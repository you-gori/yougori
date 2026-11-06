//! Runtime validation and bounded replanning (GPU §4.15, line 864).
//!
//! At every boundary [`PlanRuntime::advance`] validates the next stage's identities, the
//! available capacity, the branch decision, the holds its recipes rely on and the timing of
//! the stage that just ran. Unexpected input, external memory pressure, timing drift or a
//! lost hold invalidates the affected suffix (the subtree of the next stage) and invokes
//! bounded replanning: at most [`super::PlanLimits::max_replans`] replans, each within the
//! work bound. Correctness constraints stay hard: every directive passes the transition
//! check under the capacity observed now. Readiness times are estimates. When replanning is
//! exhausted or impossible, the runtime falls back to the ordinary online policy (line
//! 860) for the rest of the run.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::foundation::ids::{Clock, Digest};
use crate::model_memory::residency::retention::Lru;
use crate::model_memory::residency::Capacity;

use super::declaration::{CheckedWorkflow, ResourceKey, StageId, StateIdentity};
use super::memory::PeakEstimate;
use super::model::{Choice, Context, CostModel, Infeasibility, Knowledge, Transition};
use super::online::{OnlinePolicy, OrdinaryCaching};
use super::plan::{materialization, plan_tree, Overrides, PlanAction, ReadinessPlan};
use super::readiness::ReadinessEstimate;
use super::recipes::{
    failing_holds, HoldAuthority, ObjectHoldAuthority, RecipeRefusal, RecoveryRecipe,
};
use super::search::{evaluate, SearchMethod};
use super::{DeclarationError, ResourceSet, TransitionError};

/// What the runtime observes at a boundary (line 864).
pub struct BoundaryObservation<'a> {
    /// The stage the workflow takes next: the branch decision.
    pub next_stage: StageId,
    /// The identities found for the next stage's state, as presented by the runner.
    pub presented: Vec<StateIdentity>,
    /// The device budget the CORE-03 ledger grants now.
    pub usable_vram: Capacity,
    /// How long the stage that just ended took.
    pub previous_stage_seconds: Option<f64>,
    /// The authority that honours CORE-04 recipe holds.
    pub holds: &'a dyn HoldAuthority,
    /// The authority that honours catalog read leases of reload recipes.
    pub objects: &'a dyn ObjectHoldAuthority,
}

/// A deviation from the plan (line 864).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum Deviation {
    /// The presented identities are not the declared ones (unexpected input).
    UnexpectedIdentity {
        stage: StageId,
        expected: Vec<Digest>,
        presented: Vec<Digest>,
    },
    /// The workflow took a branch the plan does not have (unexpected input).
    UndeclaredBranch {
        after: Option<StageId>,
        stage: StageId,
    },
    /// The device budget fell below what the remaining plan needs.
    ExternalMemoryPressure {
        planned_peak_bytes: u64,
        usable_vram_bytes: u64,
    },
    /// A stage took longer or shorter than its estimate beyond the tolerance.
    TimingDrift {
        stage: StageId,
        expected_seconds: f64,
        observed_seconds: f64,
    },
    /// A recipe's hold is no longer honoured.
    HoldLost {
        resource: ResourceKey,
        refusal: RecipeRefusal,
    },
    /// The planned transition no longer passes the hard constraints.
    PlanInvalid { infeasibility: Infeasibility },
}

/// Why the runtime switched to the online policy (line 860).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum FallbackReason {
    /// A stage the declaration does not have.
    UnknownStage { stage: StageId },
    /// An identity the declaration does not have; the plan cannot size or rebuild it.
    UnknownIdentity { stage: StageId },
    /// Replanning reached its bound.
    ReplanLimit { replans: u32 },
    /// No plan satisfies the hard constraints from the current state.
    NoFeasiblePlan { infeasibility: Infeasibility },
    /// Replanning exceeded its work bound.
    WorkBoundExceeded { limit: u64 },
}

/// What to do at one boundary.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Directive {
    pub stage: StageId,
    /// Resident during the stage.
    pub config: Vec<ResourceKey>,
    /// To prepare during the stage.
    pub prefetch: Vec<ResourceKey>,
    pub actions: Vec<PlanAction>,
    /// An estimate, never a guarantee.
    pub readiness: ReadinessEstimate,
    pub peak: PeakEstimate,
}

/// The result of one boundary.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum BoundaryOutcome {
    /// The plan holds; follow it.
    Planned(Directive),
    /// The suffix was invalidated and replanned.
    Replanned {
        deviations: Vec<Deviation>,
        /// The invalidated suffix: stages of the previous plan's tree nodes.
        invalidated: Vec<(usize, StageId)>,
        replans: u32,
        directive: Directive,
    },
    /// The ordinary online policy applies from here. Without a directive the runtime
    /// cannot prepare anything for this stage (unknown input) and the ordinary loader
    /// serves it.
    Online {
        reason: FallbackReason,
        deviations: Vec<Deviation>,
        directive: Option<Directive>,
    },
}

/// Follows a compiled plan at runtime (line 864).
pub struct PlanRuntime {
    plan: ReadinessPlan,
    /// The tree node of the stage that ran last, in the current plan's tree.
    position: Option<usize>,
    context: Context,
    usable_vram_bytes: u64,
    duration_scale: f64,
    disabled: BTreeSet<(usize, usize)>,
    replans: u32,
    replanning_seconds: f64,
    online: Option<(FallbackReason, OrdinaryCaching<Lru>)>,
    step: u64,
}

impl PlanRuntime {
    /// Starts following `plan` from the state its workflow declares initial.
    pub fn new(plan: ReadinessPlan) -> Self {
        let usable_vram_bytes = plan.workflow.usable_vram_bytes();
        let context = Context::initial(plan.workflow.initial);
        Self {
            plan,
            position: None,
            context,
            usable_vram_bytes,
            duration_scale: 1.0,
            disabled: BTreeSet::new(),
            replans: 0,
            replanning_seconds: 0.0,
            online: None,
            step: 0,
        }
    }

    /// The plan being followed; after a replan, the plan of the suffix.
    pub fn plan(&self) -> &ReadinessPlan {
        &self.plan
    }

    pub fn replans(&self) -> u32 {
        self.replans
    }

    /// Planning time spent replanning, charged like compile time (line 870).
    pub fn replanning_seconds(&self) -> f64 {
        self.replanning_seconds
    }

    /// Whether the runtime follows the online policy.
    pub fn is_online(&self) -> bool {
        self.online.is_some()
    }

    /// The resources resident during the stage that ran last.
    pub fn resident(&self) -> Vec<ResourceKey> {
        self.plan.workflow.keys(self.context.config)
    }

    /// Validates one boundary and returns what to do (line 864).
    pub fn advance(
        &mut self,
        observation: &BoundaryObservation<'_>,
        clock: &dyn Clock,
    ) -> Result<BoundaryOutcome, TransitionError> {
        let usable =
            observation
                .usable_vram
                .physical_bytes()
                .ok_or(TransitionError::Declaration(
                    DeclarationError::VirtualCapacity,
                ))?;
        if self.online.is_some() {
            let workflow = self.plan.workflow.clone();
            let directive = self.online_directive(&workflow, observation, usable, clock)?;
            let reason = self
                .online
                .as_ref()
                .map(|(reason, _)| reason.clone())
                .ok_or(TransitionError::Internal {
                    what: "online mode has a reason",
                })?;
            return Ok(BoundaryOutcome::Online {
                reason,
                deviations: Vec::new(),
                directive,
            });
        }
        let workflow = &self.plan.workflow;
        let tree = &self.plan.tree;
        let Some(stage_at) = workflow.stage_index(&observation.next_stage) else {
            return self.go_online(
                FallbackReason::UnknownStage {
                    stage: observation.next_stage.clone(),
                },
                Vec::new(),
                None,
            );
        };
        let mut deviations = Vec::new();

        // Branch decision.
        let candidates: Vec<usize> = match self.position {
            None => vec![0],
            Some(at) => tree
                .get(at)
                .map(|entry| entry.children.clone())
                .unwrap_or_default(),
        };
        let next_node = candidates
            .into_iter()
            .find(|node| tree.get(*node).is_some_and(|entry| entry.stage == stage_at));
        if next_node.is_none() {
            deviations.push(Deviation::UndeclaredBranch {
                after: self
                    .position
                    .and_then(|at| tree.get(at))
                    .map(|entry| workflow.stages[entry.stage].id.clone()),
                stage: observation.next_stage.clone(),
            });
        }

        // Identities.
        let expected: BTreeSet<Digest> = workflow.stages[stage_at]
            .requires
            .iter()
            .map(|at| workflow.resources[at].digest)
            .collect();
        let presented: BTreeSet<Digest> = observation
            .presented
            .iter()
            .map(StateIdentity::digest)
            .collect();
        let mut substitution = None;
        if presented != expected {
            let mut set = ResourceSet::EMPTY;
            for digest in &presented {
                match workflow.resource_by_digest(digest) {
                    Some(at) => set = set.with(at),
                    None => {
                        return self.go_online(
                            FallbackReason::UnknownIdentity {
                                stage: observation.next_stage.clone(),
                            },
                            deviations,
                            None,
                        )
                    }
                }
            }
            deviations.push(Deviation::UnexpectedIdentity {
                stage: observation.next_stage.clone(),
                expected: expected.into_iter().collect(),
                presented: presented.into_iter().collect(),
            });
            substitution = Some(set);
        }

        // Capacity: the remaining planned suffix must still pass under the budget observed
        // now; the stage that just ended is history.
        if usable < self.usable_vram_bytes {
            if let Some(next) = next_node {
                let mut model = CostModel::new(workflow, tree, clock)
                    .with_usable_vram(usable)
                    .with_duration_scale(self.duration_scale)
                    .with_disabled(self.disabled.clone());
                match evaluate(
                    &mut model,
                    next,
                    self.context.at_boundary(),
                    &self.plan.decisions,
                )? {
                    Ok(_) => {}
                    Err(Infeasibility::TransitionPeak { peak_bytes, .. }) => {
                        deviations.push(Deviation::ExternalMemoryPressure {
                            planned_peak_bytes: peak_bytes,
                            usable_vram_bytes: usable,
                        })
                    }
                    Err(infeasibility) => deviations.push(Deviation::PlanInvalid { infeasibility }),
                }
            }
        }
        self.usable_vram_bytes = usable;

        // Holds.
        for ((resource, recipe), refusal) in failing_holds(
            workflow,
            observation.holds,
            observation.objects,
            self.plan.horizon,
        ) {
            if self.disabled.insert((resource, recipe)) {
                deviations.push(Deviation::HoldLost {
                    resource: workflow.resources[resource].key.clone(),
                    refusal,
                });
            }
        }

        // Timing.
        if let (Some(observed), Some(at)) = (observation.previous_stage_seconds, self.position) {
            let stage = &workflow.stages[tree[at].stage];
            let expected_seconds = stage.duration_seconds() * self.duration_scale;
            if expected_seconds > 0.0 && observed.is_finite() && observed > 0.0 {
                let error = (observed - expected_seconds).abs() / expected_seconds;
                if error > workflow.limits.timing_drift_tolerance {
                    deviations.push(Deviation::TimingDrift {
                        stage: stage.id.clone(),
                        expected_seconds,
                        observed_seconds: observed,
                    });
                    self.duration_scale *= observed / expected_seconds;
                }
            }
        }

        // Without deviations, the planned transition must still pass under what is
        // observed now.
        if deviations.is_empty() {
            if let Some(next) = next_node {
                match self.validate_planned(next, clock)? {
                    Ok((transition, prefetch)) => {
                        let directive = self.directive(next, &transition, prefetch)?;
                        self.commit(next, &transition, prefetch)?;
                        return Ok(BoundaryOutcome::Planned(directive));
                    }
                    Err(infeasibility) => {
                        deviations.push(match infeasibility {
                            Infeasibility::TransitionPeak {
                                peak_bytes,
                                usable_vram_bytes,
                                ..
                            } => Deviation::ExternalMemoryPressure {
                                planned_peak_bytes: peak_bytes,
                                usable_vram_bytes,
                            },
                            other => Deviation::PlanInvalid {
                                infeasibility: other,
                            },
                        });
                    }
                }
            }
        }
        self.replan(stage_at, next_node, substitution, deviations, clock)
    }

    /// Re-evaluates the planned transition and preparation into `next` under the observed
    /// capacity, scale and holds.
    fn validate_planned(
        &self,
        next: usize,
        clock: &dyn Clock,
    ) -> Result<Result<(Transition, ResourceSet), Infeasibility>, TransitionError> {
        let decision =
            self.plan
                .decisions
                .get(&next)
                .copied()
                .ok_or(TransitionError::Internal {
                    what: "every planned node has a decision",
                })?;
        let mut model = self.model(&self.plan.workflow, &self.plan.tree, clock);
        let context = self.context.at_boundary();
        let transition =
            match model.transition(&context, next, decision.config, Knowledge::Declared)? {
                Ok(transition) => transition,
                Err(infeasibility) => return Ok(Err(infeasibility)),
            };
        if let Err(infeasibility) =
            model.preparation_fits(next, decision.config, decision.prefetch)?
        {
            return Ok(Err(infeasibility));
        }
        Ok(Ok((transition, decision.prefetch)))
    }

    fn model<'a>(
        &self,
        workflow: &'a CheckedWorkflow,
        tree: &'a [super::declaration::TreeNode],
        clock: &'a dyn Clock,
    ) -> CostModel<'a> {
        CostModel::new(workflow, tree, clock)
            .with_usable_vram(self.usable_vram_bytes)
            .with_duration_scale(self.duration_scale)
            .with_disabled(self.disabled.clone())
    }

    fn directive(
        &self,
        node: usize,
        transition: &Transition,
        prefetch: ResourceSet,
    ) -> Result<Directive, TransitionError> {
        let workflow = &self.plan.workflow;
        let stage = self
            .plan
            .tree
            .get(node)
            .map(|entry| workflow.stages[entry.stage].id.clone())
            .ok_or(TransitionError::Internal {
                what: "tree node out of range",
            })?;
        Ok(Directive {
            stage,
            config: workflow.keys(transition.config),
            prefetch: workflow.keys(prefetch),
            actions: actions_of(workflow, &self.disabled, transition, prefetch)?,
            readiness: transition.readiness,
            peak: transition.peak.clone(),
        })
    }

    fn commit(
        &mut self,
        node: usize,
        transition: &Transition,
        prefetch: ResourceSet,
    ) -> Result<(), TransitionError> {
        let workflow = &self.plan.workflow;
        let model = CostModel::new(workflow, &self.plan.tree, &NoClock);
        self.context = model.context_after(node, transition.config, prefetch, transition.copies)?;
        self.position = Some(node);
        self.step = self.step.saturating_add(1);
        Ok(())
    }

    fn replan(
        &mut self,
        stage_at: usize,
        next_node: Option<usize>,
        substitution: Option<ResourceSet>,
        deviations: Vec<Deviation>,
        clock: &dyn Clock,
    ) -> Result<BoundaryOutcome, TransitionError> {
        let tree = &self.plan.tree;
        let suffix: Vec<usize> = match (next_node, self.position) {
            (Some(next), _) => subtree(tree, next),
            (None, Some(at)) => tree
                .get(at)
                .map(|entry| {
                    entry
                        .children
                        .iter()
                        .flat_map(|child| subtree(tree, *child))
                        .collect()
                })
                .unwrap_or_default(),
            (None, None) => subtree(tree, 0),
        };
        let invalidated: Vec<(usize, StageId)> = suffix
            .iter()
            .filter_map(|node| {
                tree.get(*node)
                    .map(|entry| (*node, self.plan.workflow.stages[entry.stage].id.clone()))
            })
            .collect();
        let limits = self.plan.workflow.limits;
        if self.replans >= limits.max_replans {
            return self.go_online(
                FallbackReason::ReplanLimit {
                    replans: self.replans,
                },
                deviations,
                None,
            );
        }
        self.replans += 1;
        let workflow = match substitution {
            Some(requires) => self.plan.workflow.with_requirement(stage_at, requires)?,
            None => self.plan.workflow.clone(),
        };
        let available = match next_node {
            Some(next) => tree
                .get(next)
                .map(|entry| entry.available)
                .unwrap_or_default(),
            None => self.available_after_position(),
        };
        let new_tree = match workflow.unroll(stage_at, available) {
            Ok(tree) => tree,
            Err(DeclarationError::SessionNotProduced { .. }) => {
                return self.go_online(
                    FallbackReason::NoFeasiblePlan {
                        infeasibility: Infeasibility::Structure {
                            reason: "the next stage consumes a session that does not exist",
                        },
                    },
                    deviations,
                    None,
                )
            }
            Err(other) => return Err(other.into()),
        };
        let linear = new_tree.iter().all(|entry| entry.children.len() <= 1);
        let method = if linear {
            SearchMethod::ExactDp
        } else {
            SearchMethod::Beam {
                width: limits.beam_width,
            }
        };
        let overrides = Overrides {
            usable_vram_bytes: self.usable_vram_bytes,
            duration_scale: self.duration_scale,
            disabled: self.disabled.clone(),
            work_limit: limits.max_work_units,
        };
        match plan_tree(
            workflow,
            new_tree,
            self.context.at_boundary(),
            &overrides,
            clock,
            method,
        ) {
            Ok(plan) => {
                self.replanning_seconds += plan.planning_seconds;
                self.plan = plan;
                self.position = None;
                let (_, transition) =
                    self.plan
                        .transitions
                        .get(&0)
                        .cloned()
                        .ok_or(TransitionError::Internal {
                            what: "a replanned root has a transition",
                        })?;
                let prefetch = self
                    .plan
                    .decisions
                    .get(&0)
                    .map(|decision| decision.prefetch)
                    .unwrap_or_default();
                let directive = self.directive(0, &transition, prefetch)?;
                self.commit(0, &transition, prefetch)?;
                Ok(BoundaryOutcome::Replanned {
                    deviations,
                    invalidated,
                    replans: self.replans,
                    directive,
                })
            }
            Err(TransitionError::NoFeasiblePlan { infeasibility, .. }) => self.go_online(
                FallbackReason::NoFeasiblePlan { infeasibility },
                deviations,
                None,
            ),
            Err(TransitionError::WorkBoundExceeded { limit }) => self.go_online(
                FallbackReason::WorkBoundExceeded { limit },
                deviations,
                None,
            ),
            Err(other) => Err(other),
        }
    }

    /// Session states that exist after the stage that ran last.
    fn available_after_position(&self) -> ResourceSet {
        let workflow = &self.plan.workflow;
        let Some(entry) = self.position.and_then(|at| self.plan.tree.get(at)) else {
            return ResourceSet::EMPTY;
        };
        let stage = &workflow.stages[entry.stage];
        let mut available = entry.available;
        if let Some(consumed) = stage.consumes {
            available = available.without(consumed);
        }
        if let Some(produced) = stage.produces {
            available = available.with(produced);
        }
        available
    }

    fn go_online(
        &mut self,
        reason: FallbackReason,
        deviations: Vec<Deviation>,
        directive: Option<Directive>,
    ) -> Result<BoundaryOutcome, TransitionError> {
        self.online = Some((reason.clone(), OrdinaryCaching::new(Lru)));
        Ok(BoundaryOutcome::Online {
            reason,
            deviations,
            directive,
        })
    }

    /// The ordinary online policy's directive for a known stage with its declared
    /// identities; `None` for anything else.
    fn online_directive(
        &mut self,
        workflow: &CheckedWorkflow,
        observation: &BoundaryObservation<'_>,
        usable: u64,
        clock: &dyn Clock,
    ) -> Result<Option<Directive>, TransitionError> {
        let Some(stage_at) = workflow.stage_index(&observation.next_stage) else {
            return Ok(None);
        };
        let expected: BTreeSet<Digest> = workflow.stages[stage_at]
            .requires
            .iter()
            .map(|at| workflow.resources[at].digest)
            .collect();
        let presented: BTreeSet<Digest> = observation
            .presented
            .iter()
            .map(StateIdentity::digest)
            .collect();
        if expected != presented {
            return Ok(None);
        }
        let available = self.available_after_position();
        let Ok(tree) = workflow.unroll(stage_at, available) else {
            return Ok(None);
        };
        self.usable_vram_bytes = usable;
        let mut model = CostModel::new(workflow, &tree, clock)
            .with_usable_vram(usable)
            .with_duration_scale(self.duration_scale)
            .with_disabled(self.disabled.clone());
        let step = self.step;
        let Some((_, policy)) = self.online.as_mut() else {
            return Ok(None);
        };
        let context = self.context.at_boundary();
        let config = match policy.configure(&mut model, &context, 0, step) {
            Ok(config) => config,
            Err(TransitionError::OnlineNoRoom { .. }) => return Ok(None),
            Err(other) => return Err(other),
        };
        let transition = match model.transition(&context, 0, config, Knowledge::Online)? {
            Ok(transition) => transition,
            Err(_) => return Ok(None),
        };
        let directive = Directive {
            stage: observation.next_stage.clone(),
            config: workflow.keys(config),
            prefetch: Vec::new(),
            actions: actions_of(workflow, &self.disabled, &transition, ResourceSet::EMPTY)?,
            readiness: transition.readiness,
            peak: transition.peak.clone(),
        };
        self.context = model.context_after(0, config, ResourceSet::EMPTY, transition.copies)?;
        self.position = None;
        self.step = self.step.saturating_add(1);
        Ok(Some(directive))
    }
}

/// A clock for building contexts, which read no time.
struct NoClock;

impl Clock for NoClock {
    fn now(&self) -> crate::foundation::ids::MonotonicTime {
        crate::foundation::ids::MonotonicTime::ZERO
    }
}

fn subtree(tree: &[super::declaration::TreeNode], root: usize) -> Vec<usize> {
    let mut order = Vec::new();
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        order.push(node);
        if let Some(entry) = tree.get(node) {
            pending.extend(entry.children.iter().rev());
        }
    }
    order
}

/// The actions of one transition plus the preparation during its stage.
pub(crate) fn actions_of(
    workflow: &CheckedWorkflow,
    disabled: &BTreeSet<(usize, usize)>,
    transition: &Transition,
    prefetch: ResourceSet,
) -> Result<Vec<PlanAction>, TransitionError> {
    let mut actions = Vec::new();
    for (resource, handling) in &transition.evictions {
        actions.push(PlanAction::Evict {
            resource: workflow.resources[*resource].key.clone(),
            handling: *handling,
        });
    }
    for resource in transition.retained.iter() {
        actions.push(PlanAction::Retain {
            resource: workflow.resources[resource].key.clone(),
        });
    }
    for (resource, choice) in &transition.demand {
        actions.push(PlanAction::Materialize {
            resource: workflow.resources[*resource].key.clone(),
            via: materialization(workflow, *resource, *choice)?,
        });
    }
    let reloads: BTreeMap<usize, usize> = prefetch
        .iter()
        .filter_map(|resource| {
            workflow.resources[resource]
                .recipes
                .iter()
                .enumerate()
                .find(|(number, recipe)| {
                    matches!(recipe, RecoveryRecipe::Reload { .. })
                        && !disabled.contains(&(resource, *number))
                })
                .map(|(number, _)| (resource, number))
        })
        .collect();
    for resource in prefetch.iter() {
        let choice = if transition.copies.contains(resource) {
            Choice::Restore
        } else {
            Choice::Load {
                recipe: *reloads.get(&resource).ok_or(TransitionError::Internal {
                    what: "prepared state has a transfer",
                })?,
            }
        };
        actions.push(PlanAction::Prefetch {
            resource: workflow.resources[resource].key.clone(),
            via: materialization(workflow, resource, choice)?,
        });
    }
    Ok(actions)
}
