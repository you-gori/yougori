//! The shared cost model of one transition between workflow stages (GPU §4.15): which
//! state is evicted and how, how missing state is materialized, the transition peak
//! through the §2.7 admission check, and the next stage's readiness through the request
//! graph. The compiled plan, the online baselines, the runtime and the fake substrate all
//! evaluate transitions here, so every policy faces the same hard constraints.

use std::collections::{BTreeSet, HashMap};
use std::fmt;

use serde::Serialize;

use crate::foundation::ids::Clock;
use crate::model_memory::residency::eviction::{
    eviction_action, Content, ContentState, EvictionAction, GpuCopy, ReconstructibleCopy,
    Verification, WriteBack,
};
use crate::model_memory::residency::retention::ObjectKind;
use crate::model_memory::residency::vram::{ImmutableKind, TransientKind};

use super::declaration::{CheckedWorkflow, TreeNode};
use super::memory::{Assumption, MemoryPlan, PeakEstimate, ProcessDemand, TransitionSlot};
use super::readiness::{stage_readiness, ReadinessEstimate, StageQuestion, Work};
use super::recipes::RecoveryRecipe;
use super::{ResourceSet, TransitionError};

/// Why one transition or decision violates a hard constraint (line 864: correctness
/// constraints remain hard).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum Infeasibility {
    /// The §2.7 inequality fails on one piece of the transition (line 862).
    TransitionPeak {
        during: TransitionSlot,
        peak_bytes: u64,
        usable_vram_bytes: u64,
        largest_term: String,
        largest_term_bytes: u64,
    },
    /// Residency's eviction rule keeps this state on the device (line 307).
    MustRetain { resource: String },
    /// No recipe can make this missing state resident.
    NoMaterialization { resource: String },
    /// Written-back copies exceed the host budget (line 851).
    HostCopyBudget {
        needed_bytes: u64,
        budget_bytes: u64,
    },
    /// Speculative preparation exceeds the maximum preparation cost (line 851).
    PreparationBudget { bytes: u64, budget_bytes: u64 },
    /// The predicted readiness misses the stage's deadline (line 851).
    DeadlineMissed {
        stage: String,
        readiness_seconds: f64,
        deadline_seconds: f64,
    },
    /// The decision is not of the required form, such as a configuration without a
    /// stage's requirement.
    Structure { reason: &'static str },
}

impl fmt::Display for Infeasibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransitionPeak {
                during,
                peak_bytes,
                usable_vram_bytes,
                largest_term,
                largest_term_bytes,
            } => write!(
                f,
                "needs {peak_bytes} bytes during {during:?} but {usable_vram_bytes} are usable; \
                 the largest term is {largest_term} at {largest_term_bytes} bytes"
            ),
            Self::MustRetain { resource } => {
                write!(f, "{resource} cannot leave the device without losing state")
            }
            Self::NoMaterialization { resource } => {
                write!(f, "no recipe can make {resource} resident")
            }
            Self::HostCopyBudget {
                needed_bytes,
                budget_bytes,
            } => write!(
                f,
                "written-back copies need {needed_bytes} bytes; the host budget is {budget_bytes}"
            ),
            Self::PreparationBudget {
                bytes,
                budget_bytes,
            } => write!(
                f,
                "preparing {bytes} bytes exceeds the maximum of {budget_bytes}"
            ),
            Self::DeadlineMissed {
                stage,
                readiness_seconds,
                deadline_seconds,
            } => write!(
                f,
                "stage {stage} would be ready after {readiness_seconds} s; the deadline is \
                 {deadline_seconds} s"
            ),
            Self::Structure { reason } => f.write_str(reason),
        }
    }
}

/// How one missing resource is materialized (line 866).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Choice {
    /// Reload through recipe `recipe` from its catalog source.
    Load { recipe: usize },
    /// Restore the plan's own written-back copy.
    Restore,
    /// Derive through recipe `recipe` from resident sources.
    Derive { recipe: usize },
    /// Recompute through recipe `recipe` from the held prompt.
    Recompute { recipe: usize },
}

/// How one resource leaves the device.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub enum EvictionHandling {
    /// Residency's clean-eviction rule decided (line 307).
    Residency(EvictionAction),
    /// A session no later stage consumes is dropped without a copy (§3.9: drop dead
    /// session KV).
    DropDeadSession,
    /// A session state its stage consumed no longer exists; the stage moved on.
    DropSupersededSession,
}

/// What a policy knows about the future.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Knowledge {
    /// The declared workflow: dead session states are known and dropped.
    Declared,
    /// Online only: every existing session state might be resumed.
    Online,
}

/// The state a transition starts from: the stage that just ran, what was resident during
/// it, what was prepared beside it and which written-back copies exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Context {
    pub(crate) parent_stage: Option<usize>,
    /// The engine context a preparing process needs during the parent stage.
    pub(crate) preparation_context_bytes: u64,
    pub(crate) config: ResourceSet,
    pub(crate) prefetch: ResourceSet,
    pub(crate) copies: ResourceSet,
    /// The parent stage and its preparation are already history (a runtime boundary):
    /// only the boundary and the next stage are checked, and preparation has finished.
    pub(crate) boundary_only: bool,
}

impl Context {
    /// The state before the first stage.
    pub(crate) fn initial(config: ResourceSet) -> Self {
        Self {
            parent_stage: None,
            preparation_context_bytes: 0,
            config,
            prefetch: ResourceSet::EMPTY,
            copies: ResourceSet::EMPTY,
            boundary_only: false,
        }
    }

    /// The same state seen from the boundary, after the parent stage ended.
    pub(crate) fn at_boundary(mut self) -> Self {
        self.boundary_only = true;
        self
    }

    pub(crate) fn produced(&self, workflow: &CheckedWorkflow) -> Option<usize> {
        self.parent_stage
            .and_then(|stage| workflow.stages.get(stage))
            .and_then(|stage| stage.produces)
    }

    pub(crate) fn superseded(&self, workflow: &CheckedWorkflow) -> Option<usize> {
        self.parent_stage
            .and_then(|stage| workflow.stages.get(stage))
            .and_then(|stage| stage.consumes)
    }

    /// Everything on the device when the parent stage ends.
    pub(crate) fn resident_before(&self, workflow: &CheckedWorkflow) -> ResourceSet {
        let mut set = self.config.union(self.prefetch);
        if let Some(produced) = self.produced(workflow) {
            set = set.with(produced);
        }
        set
    }
}

/// One evaluated transition.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Transition {
    pub(crate) config: ResourceSet,
    /// Written-back copies after the transition.
    pub(crate) copies: ResourceSet,
    /// State kept from before.
    pub(crate) retained: ResourceSet,
    pub(crate) demand: Vec<(usize, Choice)>,
    pub(crate) evictions: Vec<(usize, EvictionHandling)>,
    pub(crate) write_backs: ResourceSet,
    /// Preparation that had not finished when the stage was requested.
    pub(crate) unhidden_preparation_seconds: f64,
    pub(crate) write_back_seconds: f64,
    /// The stage's first-token readiness, everything included.
    pub(crate) readiness: ReadinessEstimate,
    pub(crate) peak: PeakEstimate,
    /// Readiness plus the retained-memory charge.
    pub(crate) cost_seconds: f64,
    pub(crate) loaded_bytes: u64,
    pub(crate) storage_read_bytes: u64,
    pub(crate) written_back_bytes: u64,
}

type ReadinessKey = (usize, u64, u64, Vec<(usize, Choice)>, u64);

/// The cost model over one workflow and one decision tree, with runtime overrides and
/// memoized evaluations.
pub(crate) struct CostModel<'a> {
    pub(crate) workflow: &'a CheckedWorkflow,
    pub(crate) tree: &'a [TreeNode],
    clock: &'a dyn Clock,
    usable_vram_bytes: u64,
    duration_scale: f64,
    disabled: BTreeSet<(usize, usize)>,
    work_spent: u64,
    work_limit: u64,
    transitions:
        HashMap<(Context, usize, ResourceSet, Knowledge), Result<Transition, Infeasibility>>,
    preparations: HashMap<(usize, ResourceSet, ResourceSet, u64), Result<(), Infeasibility>>,
    readiness: HashMap<ReadinessKey, ReadinessEstimate>,
}

impl<'a> CostModel<'a> {
    pub(crate) fn new(
        workflow: &'a CheckedWorkflow,
        tree: &'a [TreeNode],
        clock: &'a dyn Clock,
    ) -> Self {
        Self {
            workflow,
            tree,
            clock,
            usable_vram_bytes: workflow.usable_vram_bytes(),
            duration_scale: 1.0,
            disabled: BTreeSet::new(),
            work_spent: 0,
            work_limit: workflow.limits.max_work_units,
            transitions: HashMap::new(),
            preparations: HashMap::new(),
            readiness: HashMap::new(),
        }
    }

    /// The device budget observed now (external memory pressure lowers it).
    pub(crate) fn with_usable_vram(mut self, bytes: u64) -> Self {
        self.usable_vram_bytes = bytes;
        self
    }

    /// The timing-drift correction applied to every duration.
    pub(crate) fn with_duration_scale(mut self, scale: f64) -> Self {
        self.duration_scale = scale;
        self
    }

    /// Recipes whose holds were lost.
    pub(crate) fn with_disabled(mut self, disabled: BTreeSet<(usize, usize)>) -> Self {
        self.disabled = disabled;
        self
    }

    pub(crate) fn with_work_limit(mut self, limit: u64) -> Self {
        self.work_limit = limit;
        self
    }

    pub(crate) fn clock(&self) -> &'a dyn Clock {
        self.clock
    }

    pub(crate) fn work_spent(&self) -> u64 {
        self.work_spent
    }

    pub(crate) fn usable_vram_bytes(&self) -> u64 {
        self.usable_vram_bytes
    }

    pub(crate) fn duration_scale(&self) -> f64 {
        self.duration_scale
    }

    pub(crate) fn charge(&mut self) -> Result<(), TransitionError> {
        self.work_spent = self.work_spent.saturating_add(1);
        if self.work_spent > self.work_limit {
            return Err(TransitionError::WorkBoundExceeded {
                limit: self.work_limit,
            });
        }
        Ok(())
    }

    pub(crate) fn enabled(&self, resource: usize, recipe: usize) -> bool {
        !self.disabled.contains(&(resource, recipe))
    }

    fn stage_of(&self, node: usize) -> Result<usize, TransitionError> {
        self.tree
            .get(node)
            .map(|entry| entry.stage)
            .ok_or(TransitionError::Internal {
                what: "tree node out of range",
            })
    }

    /// The largest engine context among a node's children: a preparing process needs one.
    pub(crate) fn preparation_context(&self, node: usize) -> u64 {
        self.tree.get(node).map_or(0, |entry| {
            entry
                .children
                .iter()
                .filter_map(|child| self.tree.get(*child))
                .filter_map(|child| self.workflow.stages.get(child.stage))
                .map(|stage| stage.process.context_bytes)
                .max()
                .unwrap_or(0)
        })
    }

    /// The context after stage `node` ran with `config`, prepared `prefetch` and holds
    /// `copies`.
    pub(crate) fn context_after(
        &self,
        node: usize,
        config: ResourceSet,
        prefetch: ResourceSet,
        copies: ResourceSet,
    ) -> Result<Context, TransitionError> {
        Ok(Context {
            parent_stage: Some(self.stage_of(node)?),
            preparation_context_bytes: self.preparation_context(node),
            config,
            prefetch,
            copies,
            boundary_only: false,
        })
    }

    /// Whether `resource` can be prepared ahead by a transfer: immutable, with an enabled
    /// reload recipe or a written-back copy.
    pub(crate) fn prefetchable(&self, resource: usize, copies: ResourceSet) -> bool {
        let Some(entry) = self.workflow.resources.get(resource) else {
            return false;
        };
        !entry.is_session()
            && (copies.contains(resource)
                || entry.recipes.iter().enumerate().any(|(number, recipe)| {
                    matches!(recipe, RecoveryRecipe::Reload { .. })
                        && self.enabled(resource, number)
                }))
    }

    /// The scaled seconds to move `bytes` to the device.
    pub(crate) fn load_seconds(&self, bytes: u64) -> f64 {
        if bytes == 0 {
            return 0.0;
        }
        self.workflow.curves.host_to_device.seconds(bytes) * self.duration_scale
    }

    fn write_back_seconds(&self, bytes: u64) -> f64 {
        if bytes == 0 {
            return 0.0;
        }
        self.workflow.curves.device_to_host.seconds(bytes) * self.duration_scale
    }

    /// Preparation transfers run one after another on the link.
    pub(crate) fn preparation_seconds(&self, prefetch: ResourceSet) -> f64 {
        prefetch
            .iter()
            .filter_map(|at| self.workflow.resources.get(at))
            .map(|resource| self.load_seconds(resource.bytes))
            .sum()
    }

    /// Whether preparing `prefetch` during stage `node` fits: within the maximum
    /// preparation cost and, through the §2.7 check, beside the running stage (the first
    /// piece of every transition out of `node`).
    pub(crate) fn preparation_fits(
        &mut self,
        node: usize,
        config: ResourceSet,
        prefetch: ResourceSet,
    ) -> Result<Result<(), Infeasibility>, TransitionError> {
        if prefetch.is_empty() {
            return Ok(Ok(()));
        }
        self.charge()?;
        let stage_at = self.stage_of(node)?;
        let preparation_context = self.preparation_context(node);
        let key = (stage_at, config, prefetch, preparation_context);
        if let Some(found) = self.preparations.get(&key) {
            return Ok(found.clone());
        }
        let workflow = self.workflow;
        let bytes = workflow.bytes(prefetch);
        let budget = workflow.budgets.max_preparation_bytes;
        let result = if bytes > budget {
            Err(Infeasibility::PreparationBudget {
                bytes,
                budget_bytes: budget,
            })
        } else {
            let context = Context {
                parent_stage: Some(stage_at),
                preparation_context_bytes: preparation_context,
                config,
                prefetch,
                copies: ResourceSet::EMPTY,
                boundary_only: false,
            };
            let mut plan = MemoryPlan::new(workflow.trust_scope);
            self.previous_stage_pieces(&mut plan, &context, None)?;
            plan.admit(workflow, self.usable_vram_bytes)?.map(|_| ())
        };
        self.preparations.insert(key, result.clone());
        Ok(result)
    }

    /// The allocations and processes of the parent stage's piece. With `next`, the
    /// allocations extend to when the next configuration releases them.
    fn previous_stage_pieces(
        &self,
        plan: &mut MemoryPlan,
        context: &Context,
        next: Option<&NextShape>,
    ) -> Result<(), TransitionError> {
        let workflow = self.workflow;
        let before = context.config.union(context.prefetch);
        for at in before.intersection(workflow.immutables()).iter() {
            let resource = &workflow.resources[at];
            let until = match next {
                None => TransitionSlot::PreviousStage,
                Some(shape) => shape.release_slot(at),
            };
            plan.allocation(
                resource.key.as_str(),
                immutable_kind(resource.kind),
                resource.bytes,
                TransitionSlot::PreviousStage,
                until,
            )?;
        }
        if let Some(stage) = context.parent_stage.and_then(|at| workflow.stages.get(at)) {
            plan.process(ProcessDemand {
                name: format!("stage:{}", stage.id),
                from: TransitionSlot::PreviousStage,
                until: TransitionSlot::PreviousStage,
                context_bytes: stage.process.context_bytes,
                graph_pool_bytes: stage.process.graph_pool_bytes,
                kv_bytes: stage.process.kv_pool_bytes,
                maps: workflow.keys_of(stage.requires.intersection(workflow.immutables())),
                transients: vec![(
                    TransientKind::PeakWorkspace,
                    stage.process.workspace_bytes,
                    TransitionSlot::PreviousStage,
                )],
            })?;
            plan.assume(Assumption::KvPoolReserved {
                stage: stage.id.to_string(),
                bytes: stage.process.kv_pool_bytes,
            });
            if stage.consumes.is_some() || stage.produces.is_some() {
                plan.assume(Assumption::SessionInsideStagePool);
            }
        }
        if !context.prefetch.is_empty() {
            plan.process(ProcessDemand {
                name: "prepare".to_string(),
                from: TransitionSlot::PreviousStage,
                until: TransitionSlot::PreviousStage,
                context_bytes: context.preparation_context_bytes.max(1),
                graph_pool_bytes: 0,
                kv_bytes: 0,
                maps: workflow.keys_of(context.prefetch),
                transients: vec![(
                    TransientKind::Staging,
                    workflow.budgets.staging_bytes,
                    TransitionSlot::PreviousStage,
                )],
            })?;
            plan.assume(Assumption::PreparationEngineContext {
                bytes: context.preparation_context_bytes,
            });
            plan.assume(Assumption::StagingPerLoadingProcess {
                bytes: workflow.budgets.staging_bytes,
            });
        }
        if next.is_none() {
            let consumed = context.superseded(workflow);
            for at in context.config.difference(workflow.immutables()).iter() {
                if Some(at) == consumed {
                    continue;
                }
                self.holder(
                    plan,
                    at,
                    TransitionSlot::PreviousStage,
                    TransitionSlot::PreviousStage,
                )?;
            }
        }
        Ok(())
    }

    fn holder(
        &self,
        plan: &mut MemoryPlan,
        at: usize,
        from: TransitionSlot,
        until: TransitionSlot,
    ) -> Result<(), TransitionError> {
        let resource = &self.workflow.resources[at];
        plan.process(ProcessDemand {
            name: format!("hold:{}", resource.key),
            from,
            until,
            context_bytes: resource.holder_context_bytes,
            graph_pool_bytes: 0,
            kv_bytes: resource.bytes,
            maps: Vec::new(),
            transients: Vec::new(),
        })?;
        plan.assume(Assumption::SessionHolderContext {
            resource: resource.key.to_string(),
            bytes: resource.holder_context_bytes,
        });
        Ok(())
    }

    /// Evaluates the transition from `context` into tree node `child` with `config`
    /// resident during the child's stage.
    pub(crate) fn transition(
        &mut self,
        context: &Context,
        child: usize,
        config: ResourceSet,
        knowledge: Knowledge,
    ) -> Result<Result<Transition, Infeasibility>, TransitionError> {
        self.charge()?;
        let key = (*context, child, config, knowledge);
        if let Some(found) = self.transitions.get(&key) {
            return Ok(found.clone());
        }
        let result = self.compute_transition(context, child, config, knowledge)?;
        self.transitions.insert(key, result.clone());
        Ok(result)
    }

    fn compute_transition(
        &mut self,
        context: &Context,
        child: usize,
        config: ResourceSet,
        knowledge: Knowledge,
    ) -> Result<Result<Transition, Infeasibility>, TransitionError> {
        let workflow = self.workflow;
        let node = self.tree.get(child).ok_or(TransitionError::Internal {
            what: "tree node out of range",
        })?;
        let stage = workflow
            .stages
            .get(node.stage)
            .ok_or(TransitionError::Internal {
                what: "stage index out of range",
            })?;
        let required = stage.requires;
        let before = context.resident_before(workflow);
        let superseded = context.superseded(workflow);
        if !required.is_subset(config) {
            return Ok(Err(Infeasibility::Structure {
                reason: "the configuration lacks the stage's requirement",
            }));
        }
        if !workflow.is_closed(config) {
            return Ok(Err(Infeasibility::Structure {
                reason: "a resident resource lacks a prerequisite",
            }));
        }
        let sessions = config.difference(workflow.immutables());
        let allowed_sessions = match knowledge {
            Knowledge::Declared => node.available.intersection(node.live),
            Knowledge::Online => node.available,
        };
        if !sessions.is_subset(allowed_sessions) {
            return Ok(Err(Infeasibility::Structure {
                reason: "a session state does not exist here or no later stage consumes it",
            }));
        }
        let demand = config.difference(before);
        if !demand.is_subset(required) {
            return Ok(Err(Infeasibility::Structure {
                reason: "only the stage's own requirement is materialized on demand",
            }));
        }
        if context.parent_stage.is_none() && !context.prefetch.is_empty() {
            return Err(TransitionError::Internal {
                what: "nothing is prepared before the first stage",
            });
        }

        let write_back = match workflow.budgets.write_back {
            Some(_) => WriteBack::Available,
            None => WriteBack::Unavailable,
        };
        let mut copies = context.copies;
        let mut evictions = Vec::new();
        let mut write_backs = ResourceSet::EMPTY;
        for at in before.difference(config).iter() {
            let resource = &workflow.resources[at];
            let handling = if resource.is_session() {
                let live = match knowledge {
                    Knowledge::Declared => node.live.contains(at),
                    Knowledge::Online => node.available.contains(at),
                };
                if Some(at) == superseded || !node.available.contains(at) {
                    EvictionHandling::DropSupersededSession
                } else if !live {
                    EvictionHandling::DropDeadSession
                } else {
                    let gpu = GpuCopy {
                        content: Content::SessionState(resource.digest),
                        state: ContentState::Dirty,
                        bytes: resource.bytes,
                    };
                    EvictionHandling::Residency(eviction_action(&gpu, &[], write_back))
                }
            } else {
                let content =
                    Content::Immutable(resource.content.ok_or(TransitionError::Internal {
                        what: "an immutable resource has a content key",
                    })?);
                let gpu = GpuCopy {
                    content,
                    state: ContentState::Clean,
                    bytes: resource.bytes,
                };
                let held = self.verified_copies(at, content, context.copies);
                EvictionHandling::Residency(eviction_action(&gpu, &held, write_back))
            };
            match handling {
                EvictionHandling::Residency(EvictionAction::Retain { .. }) => {
                    return Ok(Err(Infeasibility::MustRetain {
                        resource: resource.key.to_string(),
                    }));
                }
                EvictionHandling::Residency(EvictionAction::WriteBackThenDrop { .. }) => {
                    write_backs = write_backs.with(at);
                    copies = copies.with(at);
                }
                _ => {}
            }
            evictions.push((at, handling));
        }
        // A copy of a session state lasts while the state exists.
        let keep = workflow.immutables().union(match knowledge {
            Knowledge::Declared => node.available.intersection(node.live),
            Knowledge::Online => node.available,
        });
        copies = copies.intersection(keep);
        let needed_bytes = workflow.bytes(copies);
        let budget_bytes = workflow.budgets.host_copy_bytes;
        if needed_bytes > budget_bytes {
            return Ok(Err(Infeasibility::HostCopyBudget {
                needed_bytes,
                budget_bytes,
            }));
        }

        let mut options: Vec<(usize, Vec<Choice>)> = Vec::new();
        for at in demand.iter() {
            let resource = &workflow.resources[at];
            let mut choices = Vec::new();
            for (number, recipe) in resource.recipes.iter().enumerate() {
                if !self.enabled(at, number) {
                    continue;
                }
                match recipe {
                    RecoveryRecipe::Reload { .. } => choices.push(Choice::Load { recipe: number }),
                    RecoveryRecipe::Derive { .. } => {
                        if workflow.recipe_sources(at, number).is_subset(before) {
                            choices.push(Choice::Derive { recipe: number });
                        }
                    }
                    RecoveryRecipe::Recompute { .. } => {
                        choices.push(Choice::Recompute { recipe: number })
                    }
                    RecoveryRecipe::Peer { .. } => {}
                }
            }
            if context.copies.contains(at) {
                choices.push(Choice::Restore);
            }
            if choices.is_empty() {
                return Ok(Err(Infeasibility::NoMaterialization {
                    resource: resource.key.to_string(),
                }));
            }
            options.push((at, choices));
        }
        let combinations = combinations(&options)?;

        let parent_duration = context
            .parent_stage
            .and_then(|at| workflow.stages.get(at))
            .map_or(0.0, |stage| stage.duration_seconds() * self.duration_scale);
        let unhidden = if context.boundary_only {
            0.0
        } else {
            (self.preparation_seconds(context.prefetch) - parent_duration).max(0.0)
        };
        let written_back_bytes = workflow.bytes(write_backs);
        let write_back_seconds = self.write_back_seconds(written_back_bytes);
        let extra_bytes = workflow.bytes(config.difference(required));
        let retained_charge = workflow.weights.retained_seconds_per_byte_second
            * extra_bytes as f64
            * stage.duration_seconds()
            * self.duration_scale;

        let mut best: Option<Transition> = None;
        let mut refusal: Option<Infeasibility> = None;
        for combination in combinations {
            let mut derive_sources = ResourceSet::EMPTY;
            let mut derive_edges = Vec::new();
            let mut works = Vec::with_capacity(combination.len());
            let mut loaded_bytes = 0u64;
            let mut storage_read_bytes = 0u64;
            for (at, choice) in &combination {
                let resource = &workflow.resources[*at];
                let work = match choice {
                    Choice::Load { .. } => {
                        loaded_bytes = loaded_bytes.saturating_add(resource.bytes);
                        storage_read_bytes = storage_read_bytes.saturating_add(resource.bytes);
                        Work::Load {
                            seconds: self.load_seconds(resource.bytes),
                        }
                    }
                    Choice::Restore => {
                        loaded_bytes = loaded_bytes.saturating_add(resource.bytes);
                        Work::Load {
                            seconds: self.load_seconds(resource.bytes),
                        }
                    }
                    Choice::Derive { recipe } | Choice::Recompute { recipe } => {
                        if let Choice::Derive { .. } = choice {
                            let sources = workflow.recipe_sources(*at, *recipe);
                            derive_sources = derive_sources.union(sources);
                            derive_edges.extend(sources.iter().map(|source| (source, *at)));
                        }
                        let seconds = resource
                            .recipes
                            .get(*recipe)
                            .map_or(0.0, RecoveryRecipe::compute_seconds);
                        Work::Compute {
                            seconds: seconds * self.duration_scale,
                        }
                    }
                };
                works.push((*at, work));
            }
            let staging = works
                .iter()
                .any(|(_, work)| matches!(work, Work::Load { .. }));
            let compute = works
                .iter()
                .any(|(_, work)| matches!(work, Work::Compute { .. }));
            let shape = NextShape {
                child_config: config,
                derive_sources,
                write_backs,
            };
            let peak = match self.transition_memory(
                context,
                stage_index(node),
                &shape,
                staging,
                compute,
            )? {
                Ok(peak) => peak,
                Err(infeasible) => {
                    refusal.get_or_insert(infeasible);
                    continue;
                }
            };
            let extra_ready = derive_sources.difference(required);
            let readiness = self
                .stage_readiness_of(
                    node.stage,
                    required.intersection(before),
                    extra_ready,
                    &combination,
                    &works,
                    &derive_edges,
                )?
                .delayed_by(unhidden + write_back_seconds);
            if let Some(deadline) = stage.deadline_seconds {
                if readiness.expected_seconds > deadline {
                    refusal.get_or_insert(Infeasibility::DeadlineMissed {
                        stage: stage.id.to_string(),
                        readiness_seconds: readiness.expected_seconds,
                        deadline_seconds: deadline,
                    });
                    continue;
                }
            }
            let cost_seconds = readiness.expected_seconds + retained_charge;
            if best
                .as_ref()
                .is_none_or(|current| cost_seconds < current.cost_seconds)
            {
                best = Some(Transition {
                    config,
                    copies,
                    retained: config.intersection(before),
                    demand: combination.clone(),
                    evictions: evictions.clone(),
                    write_backs,
                    unhidden_preparation_seconds: unhidden,
                    write_back_seconds,
                    readiness,
                    peak,
                    cost_seconds,
                    loaded_bytes,
                    storage_read_bytes,
                    written_back_bytes,
                });
            }
        }
        Ok(match best {
            Some(transition) => Ok(transition),
            None => Err(refusal.unwrap_or(Infeasibility::Structure {
                reason: "no materialization fits",
            })),
        })
    }

    /// Copies residency may drop against: verified catalog sources of enabled reload
    /// recipes and the plan's own written-back copy.
    fn verified_copies(
        &self,
        at: usize,
        content: Content,
        copies: ResourceSet,
    ) -> Vec<ReconstructibleCopy> {
        let workflow = self.workflow;
        let mut held: Vec<ReconstructibleCopy> = workflow.resources[at]
            .recipes
            .iter()
            .enumerate()
            .filter(|(number, _)| self.enabled(at, *number))
            .filter_map(|(_, recipe)| match recipe {
                RecoveryRecipe::Reload { source, .. } => Some(source.copy),
                _ => None,
            })
            .collect();
        if let (true, Some(tier)) = (copies.contains(at), workflow.budgets.write_back) {
            held.push(ReconstructibleCopy {
                tier,
                verification: Verification::Verified { content },
            });
        }
        held
    }

    fn transition_memory(
        &mut self,
        context: &Context,
        child_stage: usize,
        shape: &NextShape,
        staging: bool,
        compute: bool,
    ) -> Result<Result<PeakEstimate, Infeasibility>, TransitionError> {
        let workflow = self.workflow;
        let stage = workflow
            .stages
            .get(child_stage)
            .ok_or(TransitionError::Internal {
                what: "stage index out of range",
            })?;
        let mut plan = MemoryPlan::new(workflow.trust_scope);
        plan.assume(Assumption::EvictionsAtStageEnd);
        plan.assume(Assumption::AllocatedAtLoadStart);
        let before_prefetch = context.config.union(context.prefetch);
        if context.boundary_only {
            for at in before_prefetch.intersection(workflow.immutables()).iter() {
                let until = shape.release_slot(at);
                if until == TransitionSlot::PreviousStage {
                    continue;
                }
                let resource = &workflow.resources[at];
                plan.allocation(
                    resource.key.as_str(),
                    immutable_kind(resource.kind),
                    resource.bytes,
                    TransitionSlot::Boundary,
                    until,
                )?;
            }
        } else {
            self.previous_stage_pieces(&mut plan, context, Some(shape))?;
        }
        let produced = context.produced(workflow);
        let superseded = context.superseded(workflow);
        for at in shape
            .child_config
            .union(shape.derive_sources)
            .intersection(workflow.immutables())
            .difference(before_prefetch)
            .iter()
        {
            let resource = &workflow.resources[at];
            plan.allocation(
                resource.key.as_str(),
                immutable_kind(resource.kind),
                resource.bytes,
                TransitionSlot::Boundary,
                shape.release_slot(at),
            )?;
        }
        if !shape.derive_sources.is_empty() {
            plan.assume(Assumption::DeriveSourcesHeldUntilBuilt);
        }
        let mut transients = vec![(
            TransientKind::PeakWorkspace,
            stage.process.workspace_bytes,
            TransitionSlot::NextStage,
        )];
        if staging {
            transients.push((
                TransientKind::Staging,
                workflow.budgets.staging_bytes,
                TransitionSlot::Boundary,
            ));
            plan.assume(Assumption::StagingPerLoadingProcess {
                bytes: workflow.budgets.staging_bytes,
            });
        }
        if compute {
            transients.push((
                TransientKind::PeakWorkspace,
                stage.process.workspace_bytes,
                TransitionSlot::Boundary,
            ));
        }
        plan.process(ProcessDemand {
            name: format!("stage:{}", stage.id),
            from: TransitionSlot::Boundary,
            until: TransitionSlot::NextStage,
            context_bytes: stage.process.context_bytes,
            graph_pool_bytes: stage.process.graph_pool_bytes,
            kv_bytes: stage.process.kv_pool_bytes,
            maps: workflow.keys_of(stage.requires.intersection(workflow.immutables())),
            transients,
        })?;
        plan.assume(Assumption::KvPoolReserved {
            stage: stage.id.to_string(),
            bytes: stage.process.kv_pool_bytes,
        });
        if stage.consumes.is_some() || stage.produces.is_some() {
            plan.assume(Assumption::SessionInsideStagePool);
        }
        let sessions = context
            .resident_before(workflow)
            .union(shape.child_config)
            .difference(workflow.immutables());
        for at in sessions.iter() {
            if Some(at) == superseded {
                continue;
            }
            let into_next_pool = stage.consumes == Some(at);
            let from = if context.config.contains(at) {
                Some(TransitionSlot::PreviousStage)
            } else if Some(at) == produced && !into_next_pool {
                Some(TransitionSlot::Boundary)
            } else {
                None
            };
            let until = if shape.child_config.contains(at) {
                if into_next_pool {
                    TransitionSlot::PreviousStage
                } else {
                    TransitionSlot::NextStage
                }
            } else if shape.write_backs.contains(at) {
                TransitionSlot::Boundary
            } else {
                TransitionSlot::PreviousStage
            };
            let from = match from {
                Some(TransitionSlot::PreviousStage) if context.boundary_only => {
                    Some(TransitionSlot::Boundary)
                }
                other => other,
            };
            if let Some(from) = from {
                if from <= until {
                    self.holder(&mut plan, at, from, until)?;
                }
            }
        }
        if !shape.write_backs.is_empty() {
            plan.assume(Assumption::WriteBackBeforeNextStage);
        }
        plan.admit(workflow, self.usable_vram_bytes)
    }

    fn stage_readiness_of(
        &mut self,
        stage: usize,
        ready: ResourceSet,
        extra_ready: ResourceSet,
        combination: &[(usize, Choice)],
        works: &[(usize, Work)],
        derive_edges: &[(usize, usize)],
    ) -> Result<ReadinessEstimate, TransitionError> {
        let key = (
            stage,
            ready.bits(),
            extra_ready.bits(),
            combination.to_vec(),
            self.duration_scale.to_bits(),
        );
        if let Some(found) = self.readiness.get(&key) {
            return Ok(*found);
        }
        let question = StageQuestion {
            stage,
            ready,
            extra_ready,
            demand: works,
            derive_edges,
            scale: self.duration_scale,
        };
        let estimate = stage_readiness(self.workflow, &question, self.clock)?;
        self.readiness.insert(key, estimate);
        Ok(estimate)
    }
}

fn stage_index(node: &TreeNode) -> usize {
    node.stage
}

/// What the next configuration keeps, for allocation lifetimes.
struct NextShape {
    child_config: ResourceSet,
    derive_sources: ResourceSet,
    write_backs: ResourceSet,
}

impl NextShape {
    /// The last piece an allocation stays resident in.
    fn release_slot(&self, at: usize) -> TransitionSlot {
        if self.child_config.contains(at) {
            TransitionSlot::NextStage
        } else if self.derive_sources.contains(at) || self.write_backs.contains(at) {
            TransitionSlot::Boundary
        } else {
            TransitionSlot::PreviousStage
        }
    }
}

fn immutable_kind(kind: ObjectKind) -> ImmutableKind {
    match kind {
        ObjectKind::Adapter => ImmutableKind::Adapter,
        ObjectKind::BaseWeights
        | ObjectKind::MergedVariant
        | ObjectKind::GraphPool
        | ObjectKind::SessionKv => ImmutableKind::Weights,
    }
}

/// Every combination of one choice per missing resource, bounded.
fn combinations(
    options: &[(usize, Vec<Choice>)],
) -> Result<Vec<Vec<(usize, Choice)>>, TransitionError> {
    const LIMIT: usize = 1_024;
    let mut result: Vec<Vec<(usize, Choice)>> = vec![Vec::new()];
    for (at, choices) in options {
        let mut next = Vec::with_capacity(result.len() * choices.len());
        for prefix in &result {
            for choice in choices {
                let mut extended = prefix.clone();
                extended.push((*at, *choice));
                next.push(extended);
            }
        }
        if next.len() > LIMIT {
            return Err(TransitionError::Internal {
                what: "too many materialization combinations",
            });
        }
        result = next;
    }
    Ok(result)
}
