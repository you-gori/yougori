//! The readiness plan: the outputs of GPU §4.15 (lines 854–860).
//!
//! For every node of the workflow's decision tree a [`PlannedNode`] gives:
//!
//! - a small set of retained-state alternatives at the boundary ([`Alternative`]);
//! - scheduled preparation and eviction actions ([`PlanAction`]);
//! - the allowed interruption point and its recovery recipes ([`InterruptionPoint`]);
//! - the peak-memory estimate with the exact assumptions that make it feasible
//!   ([`PeakEstimate`]);
//!
//! and the plan carries an ordinary online-policy fallback ([`OnlineFallback`]).
//!
//! Every action is a memory transition or a preparation step (S3.6): each maps to a
//! [`PreparationStep`] or is a release, and no type here can hold an external action or a
//! workflow grant.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::foundation::catalog::ObjectId;
use crate::foundation::ids::{Clock, Digest, MonotonicTime};
use crate::model_memory::boundaries::PreparationStep;
use crate::model_memory::residency::eviction::{
    eviction_action, Content, ContentState, CopyTier, EvictionAction, GpuCopy, ReconstructibleCopy,
    Verification, WriteBack,
};

use super::declaration::{CheckedWorkflow, ResourceKey, StageId, TreeNode, WorkflowDeclaration};
use super::memory::PeakEstimate;
use super::model::{Choice, Context, CostModel, EvictionHandling, Transition};
use super::readiness::ReadinessEstimate;
use super::recipes::{
    check_hold, HoldAuthority, ObjectHoldAuthority, PromptHolding, RecoveryRecipe,
};
use super::runtime::actions_of;
use super::search::{evaluate, search, Decision, SearchMethod};
use super::TransitionError;

/// How a missing resource becomes resident (line 857).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Materialization {
    /// A transfer from a CORE-02 catalog object.
    Load { object: ObjectId },
    /// A transfer from the plan's own written-back copy.
    RestoreCopy { tier: CopyTier },
    /// Built on the device from resident sources.
    Derive { sources: Vec<ResourceKey> },
    /// Recomputed from the exact prompt the service holds.
    Recompute { prompt: Digest, tokens: u64 },
}

impl Materialization {
    /// The S3.6 preparation step this is.
    pub fn preparation_step(&self) -> PreparationStep {
        match self {
            Self::Load { .. } | Self::RestoreCopy { .. } => PreparationStep::InboundTransfer,
            Self::Derive { .. } | Self::Recompute { .. } => PreparationStep::Reconstruct,
        }
    }
}

/// One scheduled preparation or eviction action (line 857). There is no variant for an
/// external workflow action (S3.6).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum PlanAction {
    /// Release state at the boundary, as residency's eviction rule decides.
    Evict {
        resource: ResourceKey,
        handling: EvictionHandling,
    },
    /// Keep state resident across the boundary.
    Retain { resource: ResourceKey },
    /// Make missing state resident at the boundary, before the stage's first token.
    Materialize {
        resource: ResourceKey,
        via: Materialization,
    },
    /// Prepare state during the stage for its successors.
    Prefetch {
        resource: ResourceKey,
        via: Materialization,
    },
}

impl PlanAction {
    /// The S3.6 preparation step an action is; `None` for a release. No action is or
    /// authorizes an external workflow action.
    pub fn preparation_step(&self) -> Option<PreparationStep> {
        match self {
            Self::Evict { .. } => None,
            Self::Retain { .. } => Some(PreparationStep::Reserve),
            Self::Materialize { via, .. } | Self::Prefetch { via, .. } => {
                Some(via.preparation_step())
            }
        }
    }
}

/// One retained-state alternative at a boundary (line 856).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Alternative {
    pub config: Vec<ResourceKey>,
    /// The cost to go from the chosen parent decision: readiness seconds plus charges.
    pub cost_to_go_seconds: f64,
}

/// How a resource is recovered if it is dropped at an interruption (line 858).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum RecoveryPath {
    Reload { object: ObjectId },
    RestoreWrittenBack { tier: CopyTier },
    Recompute { prompt: Digest },
}

/// An interruption point before a stage, with the recovery recipe of everything resident
/// there (line 858).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct InterruptionPoint {
    pub before_stage: StageId,
    /// Allowed when everything resident can be dropped and recovered.
    pub allowed: bool,
    pub recover: Vec<(ResourceKey, Vec<RecoveryPath>)>,
    /// State that would be lost if dropped here: dirty without a write-back tier.
    pub must_keep: Vec<ResourceKey>,
    /// Loads stop at transport-batch boundaries at most this far apart; a stage's own
    /// computation is never interrupted midway.
    pub load_cancellation_interval_seconds: f64,
}

/// The ordinary online policy the runtime falls back to (line 860; GPU-W06: the
/// demand-only policy stays a runtime rollback).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OnlineFallback {
    /// The residency retention policy that ranks victims.
    pub retention_policy: String,
    /// Demand-only: nothing is prepared speculatively.
    pub demand_only: bool,
}

/// The plan for one node of the decision tree.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PlannedNode {
    pub tree_node: usize,
    pub stage: StageId,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
    /// Resident during the stage.
    pub config: Vec<ResourceKey>,
    /// Prepared during the stage for its successors.
    pub prefetch: Vec<ResourceKey>,
    /// At the boundary before the stage, then the preparation during it.
    pub actions: Vec<PlanAction>,
    /// An estimate, never a guarantee (line 864).
    pub readiness: ReadinessEstimate,
    pub peak: PeakEstimate,
    pub alternatives: Vec<Alternative>,
    pub interruption: InterruptionPoint,
}

/// A compiled readiness plan (lines 854–860). It describes memory transitions and
/// preparation only (line 844).
#[derive(Clone, Debug, PartialEq)]
pub struct ReadinessPlan {
    pub(crate) workflow: CheckedWorkflow,
    pub(crate) tree: Vec<TreeNode>,
    pub(crate) method: SearchMethod,
    pub(crate) nodes: Vec<PlannedNode>,
    pub(crate) decisions: BTreeMap<usize, Decision>,
    pub(crate) transitions: BTreeMap<usize, (Context, Transition)>,
    pub(crate) expected_cost_seconds: f64,
    pub(crate) work_units: u64,
    pub(crate) planning_seconds: f64,
    pub(crate) compiled_at: MonotonicTime,
    pub(crate) horizon: MonotonicTime,
    pub(crate) fallback: OnlineFallback,
}

impl ReadinessPlan {
    pub fn workflow(&self) -> &CheckedWorkflow {
        &self.workflow
    }

    pub fn tree(&self) -> &[TreeNode] {
        &self.tree
    }

    pub fn method(&self) -> SearchMethod {
        self.method
    }

    /// One planned node per tree node, in tree order.
    pub fn nodes(&self) -> &[PlannedNode] {
        &self.nodes
    }

    /// The planned node of the first tree node running `stage`.
    pub fn node_for(&self, stage: &str) -> Option<&PlannedNode> {
        self.nodes.iter().find(|node| node.stage.as_str() == stage)
    }

    /// The expected cost: readiness seconds plus the declared charges, aggregated over
    /// branches.
    pub fn expected_cost_seconds(&self) -> f64 {
        self.expected_cost_seconds
    }

    pub fn work_units(&self) -> u64 {
        self.work_units
    }

    /// Work units times the measured cost of one (line 870: charge planning time).
    pub fn planning_seconds(&self) -> f64 {
        self.planning_seconds
    }

    pub fn compiled_at(&self) -> MonotonicTime {
        self.compiled_at
    }

    /// Until when every hold the plan relies on must be honoured.
    pub fn horizon(&self) -> MonotonicTime {
        self.horizon
    }

    pub fn fallback(&self) -> &OnlineFallback {
        &self.fallback
    }

    /// Every action of every node.
    pub fn actions(&self) -> impl Iterator<Item = &PlanAction> {
        self.nodes.iter().flat_map(|node| node.actions.iter())
    }
}

/// Overrides the runtime applies when it replans (line 864).
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Overrides {
    pub(crate) usable_vram_bytes: u64,
    pub(crate) duration_scale: f64,
    pub(crate) disabled: BTreeSet<(usize, usize)>,
    pub(crate) work_limit: u64,
}

impl Overrides {
    pub(crate) fn of(workflow: &CheckedWorkflow) -> Self {
        Self {
            usable_vram_bytes: workflow.usable_vram_bytes(),
            duration_scale: 1.0,
            disabled: BTreeSet::new(),
            work_limit: workflow.limits.max_work_units,
        }
    }
}

/// Compiles a readiness plan alongside `declaration` (line 844): the exact dynamic
/// program for a linear workflow, beam search for a branching one (line 862). Every hold
/// a recipe relies on must be honoured until the plan's horizon: CORE-04 leases by
/// `holds`, catalog read leases by `objects`.
pub fn compile(
    declaration: &WorkflowDeclaration,
    holds: &dyn HoldAuthority,
    objects: &dyn ObjectHoldAuthority,
    clock: &dyn Clock,
) -> Result<ReadinessPlan, TransitionError> {
    let workflow = CheckedWorkflow::check(declaration)?;
    let method = if workflow.is_linear() {
        SearchMethod::ExactDp
    } else {
        SearchMethod::Beam {
            width: workflow.limits.beam_width,
        }
    };
    compile_checked(workflow, holds, objects, clock, method)
}

/// [`compile`] with an explicit planner.
pub fn compile_with(
    declaration: &WorkflowDeclaration,
    holds: &dyn HoldAuthority,
    objects: &dyn ObjectHoldAuthority,
    clock: &dyn Clock,
    method: SearchMethod,
) -> Result<ReadinessPlan, TransitionError> {
    compile_checked(
        CheckedWorkflow::check(declaration)?,
        holds,
        objects,
        clock,
        method,
    )
}

fn compile_checked(
    workflow: CheckedWorkflow,
    holds: &dyn HoldAuthority,
    objects: &dyn ObjectHoldAuthority,
    clock: &dyn Clock,
    method: SearchMethod,
) -> Result<ReadinessPlan, TransitionError> {
    let horizon = horizon_from(&workflow, clock.now());
    for resource in &workflow.resources {
        for recipe in &resource.recipes {
            check_hold(&workflow, recipe, holds, objects, horizon).map_err(|refusal| {
                TransitionError::Recipe {
                    resource: resource.key.clone(),
                    refusal,
                }
            })?;
        }
    }
    let tree = workflow.tree.clone();
    let context = Context::initial(workflow.initial);
    let overrides = Overrides::of(&workflow);
    plan_tree(workflow, tree, context, &overrides, clock, method)
}

pub(crate) fn horizon_from(workflow: &CheckedWorkflow, now: MonotonicTime) -> MonotonicTime {
    let seconds = workflow.horizon_seconds();
    let nanos = (seconds * 1e9).min(u64::MAX as f64).max(0.0) as u64;
    now.saturating_add(std::time::Duration::from_nanos(nanos))
}

/// Plans `tree` entered from `context` under `overrides`, and assembles the outputs.
pub(crate) fn plan_tree(
    workflow: CheckedWorkflow,
    tree: Vec<TreeNode>,
    context: Context,
    overrides: &Overrides,
    clock: &dyn Clock,
    method: SearchMethod,
) -> Result<ReadinessPlan, TransitionError> {
    let compiled_at = clock.now();
    let horizon = horizon_from(&workflow, compiled_at);
    let (searched, evaluation, work_units) = {
        let mut model = CostModel::new(&workflow, &tree, clock)
            .with_usable_vram(overrides.usable_vram_bytes)
            .with_duration_scale(overrides.duration_scale)
            .with_disabled(overrides.disabled.clone())
            .with_work_limit(overrides.work_limit);
        let searched = search(&mut model, 0, context, method)?;
        let evaluation =
            evaluate(&mut model, 0, context, &searched.decisions)?.map_err(|infeasibility| {
                TransitionError::NoFeasiblePlan {
                    stage: workflow.stages[tree[0].stage].id.clone(),
                    infeasibility,
                }
            })?;
        (searched, evaluation, model.work_spent())
    };
    let mut nodes = Vec::with_capacity(tree.len());
    for (at, entry) in tree.iter().enumerate() {
        let (Some(decision), Some((entered, transition))) =
            (searched.decisions.get(&at), evaluation.transitions.get(&at))
        else {
            return Err(TransitionError::Internal {
                what: "every tree node has a decision",
            });
        };
        let stage = &workflow.stages[entry.stage];
        let actions = actions_of(
            &workflow,
            &overrides.disabled,
            transition,
            decision.prefetch,
        )?;
        let alternatives = searched
            .alternatives
            .get(&at)
            .map(|ranked| {
                ranked
                    .iter()
                    .map(|(config, cost)| Alternative {
                        config: workflow.keys(*config),
                        cost_to_go_seconds: *cost,
                    })
                    .collect()
            })
            .unwrap_or_default();
        nodes.push(PlannedNode {
            tree_node: at,
            stage: stage.id.clone(),
            parent: entry.parent,
            children: entry.children.clone(),
            config: workflow.keys(decision.config),
            prefetch: workflow.keys(decision.prefetch),
            actions,
            readiness: transition.readiness,
            peak: transition.peak.clone(),
            alternatives,
            interruption: interruption_point(&workflow, entry, entered, &overrides.disabled)?,
        });
    }
    let planning_seconds = work_units as f64 * workflow.curves.planning_seconds_per_work_unit;
    Ok(ReadinessPlan {
        tree,
        method,
        nodes,
        decisions: searched.decisions,
        transitions: evaluation.transitions,
        expected_cost_seconds: evaluation.cost_seconds,
        work_units,
        planning_seconds,
        compiled_at,
        horizon,
        fallback: OnlineFallback {
            retention_policy: "lru".to_string(),
            demand_only: true,
        },
        workflow,
    })
}

pub(crate) fn materialization(
    workflow: &CheckedWorkflow,
    resource: usize,
    choice: Choice,
) -> Result<Materialization, TransitionError> {
    let recipe = |number: usize| {
        workflow.resources[resource]
            .recipes
            .get(number)
            .ok_or(TransitionError::Internal {
                what: "recipe index out of range",
            })
    };
    Ok(match choice {
        Choice::Load { recipe: number } => match recipe(number)? {
            RecoveryRecipe::Reload { source, .. } => Materialization::Load {
                object: source.object,
            },
            _ => {
                return Err(TransitionError::Internal {
                    what: "a load uses a reload recipe",
                })
            }
        },
        Choice::Restore => Materialization::RestoreCopy {
            tier: workflow
                .budgets
                .write_back
                .ok_or(TransitionError::Internal {
                    what: "a restore needs a write-back tier",
                })?,
        },
        Choice::Derive { recipe: number } => match recipe(number)? {
            RecoveryRecipe::Derive { sources, .. } => Materialization::Derive {
                sources: sources.clone(),
            },
            _ => {
                return Err(TransitionError::Internal {
                    what: "a derive uses a derive recipe",
                })
            }
        },
        Choice::Recompute { recipe: number } => match recipe(number)? {
            RecoveryRecipe::Recompute {
                prompt: PromptHolding::Held { prefix, .. },
                ..
            } => Materialization::Recompute {
                prompt: *prefix.digest(),
                tokens: prefix.token_count(),
            },
            _ => {
                return Err(TransitionError::Internal {
                    what: "a recompute uses a held prompt",
                })
            }
        },
    })
}

/// The interruption point before a stage: for everything resident when the previous
/// stage ends, how it is recovered if dropped (line 858).
pub(crate) fn interruption_point(
    workflow: &CheckedWorkflow,
    entry: &TreeNode,
    entered: &Context,
    disabled: &BTreeSet<(usize, usize)>,
) -> Result<InterruptionPoint, TransitionError> {
    let write_back = match workflow.budgets.write_back {
        Some(_) => WriteBack::Available,
        None => WriteBack::Unavailable,
    };
    let mut recover = Vec::new();
    let mut must_keep = Vec::new();
    let superseded = entered.superseded(workflow);
    for at in entered.resident_before(workflow).iter() {
        let resource = &workflow.resources[at];
        if resource.is_session() && (Some(at) == superseded || !entry.live.contains(at)) {
            continue;
        }
        let mut paths = Vec::new();
        let (gpu, copies) = if resource.is_session() {
            (
                GpuCopy {
                    content: Content::SessionState(resource.digest),
                    state: ContentState::Dirty,
                    bytes: resource.bytes,
                },
                Vec::new(),
            )
        } else {
            let content =
                Content::Immutable(resource.content.ok_or(TransitionError::Internal {
                    what: "an immutable resource has a content key",
                })?);
            let mut copies: Vec<ReconstructibleCopy> = Vec::new();
            for (number, recipe) in resource.recipes.iter().enumerate() {
                if let RecoveryRecipe::Reload { source, .. } = recipe {
                    if !disabled.contains(&(at, number)) {
                        copies.push(source.copy);
                    }
                }
            }
            if let (true, Some(tier)) = (entered.copies.contains(at), workflow.budgets.write_back) {
                copies.push(ReconstructibleCopy {
                    tier,
                    verification: Verification::Verified { content },
                });
            }
            (
                GpuCopy {
                    content,
                    state: ContentState::Clean,
                    bytes: resource.bytes,
                },
                copies,
            )
        };
        match eviction_action(&gpu, &copies, write_back) {
            EvictionAction::Retain { .. } => {
                must_keep.push(resource.key.clone());
                continue;
            }
            EvictionAction::DropClean { .. } | EvictionAction::Recapture => {
                for (number, recipe) in resource.recipes.iter().enumerate() {
                    if let RecoveryRecipe::Reload { source, .. } = recipe {
                        if !disabled.contains(&(at, number)) {
                            paths.push(RecoveryPath::Reload {
                                object: source.object,
                            });
                        }
                    }
                }
                if paths.is_empty() {
                    if let Some(tier) = workflow.budgets.write_back {
                        paths.push(RecoveryPath::RestoreWrittenBack { tier });
                    }
                }
            }
            EvictionAction::WriteBackThenDrop { .. } => {
                if let Some(tier) = workflow.budgets.write_back {
                    paths.push(RecoveryPath::RestoreWrittenBack { tier });
                }
            }
        }
        for (number, recipe) in resource.recipes.iter().enumerate() {
            if let RecoveryRecipe::Recompute {
                prompt: PromptHolding::Held { prefix, .. },
                ..
            } = recipe
            {
                if !disabled.contains(&(at, number)) {
                    paths.push(RecoveryPath::Recompute {
                        prompt: *prefix.digest(),
                    });
                }
            }
        }
        recover.push((resource.key.clone(), paths));
    }
    Ok(InterruptionPoint {
        before_stage: workflow.stages[entry.stage].id.clone(),
        allowed: must_keep.is_empty(),
        recover,
        must_keep,
        load_cancellation_interval_seconds: workflow.curves.load_cancellation_interval_seconds,
    })
}
