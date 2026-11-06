//! Online policies (GPU §4.15 lines 860 and 870).
//!
//! - Ordinary caching: demand loading with victims ranked by one of residency's retention
//!   baselines (LRU by default, GPU-W06), the online fallback of every plan.
//! - Next-model prefetch: ordinary caching that also prepares the most likely next stage's
//!   weights while the current stage runs, when they fit beside it.
//! - GPU-N1 alone: the committed bundle planner of [`crate::model_memory::bundles`]
//!   chooses what to retain or prepare at each boundary, over a horizon of the admitted
//!   request and requests forecast from online history only, with no workflow knowledge.
//!
//! Online policies know which session states exist but not which will be resumed, so
//! they write back every live-looking session they evict. Every decision passes the same
//! transition check as the compiled plan.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::foundation::ids::{DigestBuilder, ResourceId};
use crate::model_memory::bundles::experiment::forecast_controller;
use crate::model_memory::bundles::planner::plan;
use crate::model_memory::bundles::{
    Admission, Horizon, HorizonBounds, HorizonSpec, ObjectSpec, PlannerConfig, RequestSpec,
};
use crate::model_memory::graph::dag::Policy;
use crate::model_memory::graph::node::{
    CancellationBoundary, DemandSegment, DurationEstimate, NodeKind, ResourceUnit,
};
use crate::model_memory::math::calibration::ModeController;
use crate::model_memory::math::prefetch::{Objective, RawCost};
use crate::model_memory::residency::retention::{
    MarginalSavedLatency, ObjectKind, ObjectView, RetentionPolicy,
};
use crate::model_memory::residency::Capacity;

use super::declaration::Aggregation;
use super::model::{Context, CostModel, Infeasibility, Knowledge};
use super::recipes::RecoveryRecipe;
use super::{ResourceSet, TransitionError};

/// An online policy on the shared transition model.
pub(crate) trait OnlinePolicy {
    fn name(&self) -> String;

    /// Planner work units spent so far, charged as planning time (line 870).
    fn planning_work_units(&self) -> u64 {
        0
    }

    /// The configuration for tree node `node`, entered from `context`.
    fn configure(
        &mut self,
        model: &mut CostModel<'_>,
        context: &Context,
        node: usize,
        step: u64,
    ) -> Result<ResourceSet, TransitionError>;

    /// What to prepare while node `node` runs with `config`.
    fn prepare(
        &mut self,
        model: &mut CostModel<'_>,
        node: usize,
        config: ResourceSet,
        copies: ResourceSet,
        step: u64,
    ) -> Result<ResourceSet, TransitionError>;
}

#[derive(Clone, Debug, Default)]
struct History {
    last_use: BTreeMap<usize, u64>,
    uses: BTreeMap<usize, u64>,
}

impl History {
    fn touch(&mut self, at: usize, step: u64) {
        self.last_use.insert(at, step);
        *self.uses.entry(at).or_insert(0) += 1;
    }
}

/// Seconds to make `at` resident again by its cheapest enabled way.
fn reload_estimate(model: &CostModel<'_>, at: usize, copies: ResourceSet) -> f64 {
    let workflow = model.workflow;
    let resource = &workflow.resources[at];
    let mut best = f64::INFINITY;
    for (number, recipe) in resource.recipes.iter().enumerate() {
        if !model.enabled(at, number) {
            continue;
        }
        let seconds = match recipe {
            RecoveryRecipe::Reload { .. } => model.load_seconds(resource.bytes),
            RecoveryRecipe::Derive {
                compute_seconds, ..
            }
            | RecoveryRecipe::Recompute {
                compute_seconds, ..
            } => *compute_seconds * model.duration_scale(),
            RecoveryRecipe::Peer { .. } => continue,
        };
        best = best.min(seconds);
    }
    if copies.contains(at) || resource.is_session() {
        let write_back = workflow.curves.device_to_host.seconds(resource.bytes);
        best = best.min(write_back + model.load_seconds(resource.bytes));
    }
    if best.is_finite() {
        best
    } else {
        0.0
    }
}

/// The largest subset of `set` whose members' prerequisites are all members.
fn closed_subset(model: &CostModel<'_>, mut set: ResourceSet) -> ResourceSet {
    loop {
        let open: Vec<usize> = set
            .iter()
            .filter(|at| !model.workflow.resources[*at].closure.is_subset(set))
            .collect();
        if open.is_empty() {
            return set;
        }
        for at in open {
            set = set.without(at);
        }
    }
}

fn stage_id(model: &CostModel<'_>, node: usize) -> super::declaration::StageId {
    model
        .tree
        .get(node)
        .map(|entry| model.workflow.stages[entry.stage].id.clone())
        .unwrap_or_else(|| model.workflow.stages[model.workflow.root].id.clone())
}

/// Evicts victims chosen by `retention` until the transition fits (residency's policies
/// rank only the legal victims; the transition check enforces every invariant).
#[allow(clippy::too_many_arguments)]
fn make_room(
    retention: &mut dyn RetentionPolicy,
    history: &History,
    model: &mut CostModel<'_>,
    context: &Context,
    node: usize,
    mut candidate: ResourceSet,
    mut protected: ResourceSet,
    step: u64,
    policy: &str,
) -> Result<ResourceSet, TransitionError> {
    let attempts = 2 * model.workflow.resources.len() + 2;
    for _ in 0..attempts {
        let refusal = match model.transition(context, node, candidate, Knowledge::Online)? {
            Ok(_) => return Ok(candidate),
            Err(refusal) => refusal,
        };
        let no_room = |infeasibility: Infeasibility| TransitionError::OnlineNoRoom {
            policy: policy.to_string(),
            stage: stage_id(model, node),
            infeasibility,
        };
        match &refusal {
            Infeasibility::MustRetain { resource } => {
                let Some(at) = model
                    .workflow
                    .resources
                    .iter()
                    .position(|entry| entry.key.as_str() == resource)
                else {
                    return Err(no_room(refusal));
                };
                if candidate.contains(at) {
                    return Err(no_room(refusal));
                }
                candidate = candidate.union(model.workflow.resources[at].closure);
                protected = protected.union(model.workflow.resources[at].closure);
            }
            Infeasibility::TransitionPeak { .. } => {
                let workflow = model.workflow;
                let evictable: Vec<usize> = candidate
                    .difference(protected)
                    .iter()
                    .filter(|at| {
                        !candidate
                            .without(*at)
                            .iter()
                            .any(|other| workflow.resources[other].closure.contains(*at))
                    })
                    .collect();
                if evictable.is_empty() {
                    return Err(no_room(refusal));
                }
                let members: Vec<usize> = candidate.iter().collect();
                let views: Vec<ObjectView<'_>> = members
                    .iter()
                    .map(|at| ObjectView {
                        key: workflow.resources[*at].key.as_str(),
                        kind: workflow.resources[*at].kind,
                        bytes: workflow.resources[*at].bytes,
                        reload_seconds: reload_estimate(model, *at, context.copies),
                        last_use_step: history.last_use.get(at).copied().unwrap_or(0),
                        use_count: history.uses.get(at).copied().unwrap_or(0),
                        protected: protected.contains(*at),
                        evictable: evictable.contains(at),
                    })
                    .collect();
                let chosen = retention
                    .choose_victim(&views, step)
                    .and_then(|index| members.get(index).copied())
                    .filter(|at| evictable.contains(at));
                let Some(victim) = chosen else {
                    return Err(no_room(refusal));
                };
                retention.on_evict(workflow.resources[victim].key.as_str());
                candidate = candidate.without(victim);
            }
            _ => return Err(no_room(refusal)),
        }
    }
    Err(TransitionError::Internal {
        what: "an online eviction loop is bounded by the resources",
    })
}

fn record_use(
    retention: &mut dyn RetentionPolicy,
    history: &mut History,
    model: &CostModel<'_>,
    used: ResourceSet,
    copies: ResourceSet,
    step: u64,
) {
    let workflow = model.workflow;
    // Prerequisites first, as residency's cache reports them.
    let mut order: Vec<usize> = used.iter().collect();
    order.sort_by_key(|at| workflow.resources[*at].closure.len());
    for at in order {
        history.touch(at, step);
        let view = ObjectView {
            key: workflow.resources[at].key.as_str(),
            kind: workflow.resources[at].kind,
            bytes: workflow.resources[at].bytes,
            reload_seconds: reload_estimate(model, at, copies),
            last_use_step: step,
            use_count: history.uses.get(&at).copied().unwrap_or(0),
            protected: true,
            evictable: false,
        };
        retention.on_use(&view, step);
    }
}

/// The online candidate before evictions: what is resident and may stay, plus the
/// stage's requirement.
fn online_candidate(model: &CostModel<'_>, context: &Context, node: usize) -> ResourceSet {
    let workflow = model.workflow;
    let Some(entry) = model.tree.get(node) else {
        return ResourceSet::EMPTY;
    };
    let allowed = workflow.immutables().union(entry.available);
    let required = workflow.stages[entry.stage].requires;
    let kept = context.resident_before(workflow).intersection(allowed);
    closed_subset(model, kept.union(required))
}

/// Ordinary caching with one of residency's retention baselines; demand only.
pub(crate) struct OrdinaryCaching<P> {
    retention: P,
    history: History,
}

impl<P: RetentionPolicy> OrdinaryCaching<P> {
    pub(crate) fn new(retention: P) -> Self {
        Self {
            retention,
            history: History::default(),
        }
    }
}

impl<P: RetentionPolicy> OnlinePolicy for OrdinaryCaching<P> {
    fn name(&self) -> String {
        format!("ordinary-caching-{}", self.retention.name())
    }

    fn configure(
        &mut self,
        model: &mut CostModel<'_>,
        context: &Context,
        node: usize,
        step: u64,
    ) -> Result<ResourceSet, TransitionError> {
        if let Some(produced) = context.produced(model.workflow) {
            record_use(
                &mut self.retention,
                &mut self.history,
                model,
                ResourceSet::single(produced),
                context.copies,
                step.saturating_sub(1),
            );
        }
        let required = model
            .tree
            .get(node)
            .map(|entry| model.workflow.stages[entry.stage].requires)
            .unwrap_or_default();
        let candidate = online_candidate(model, context, node);
        let name = self.name();
        let config = make_room(
            &mut self.retention,
            &self.history,
            model,
            context,
            node,
            candidate,
            required,
            step,
            &name,
        )?;
        record_use(
            &mut self.retention,
            &mut self.history,
            model,
            required,
            context.copies,
            step,
        );
        Ok(config)
    }

    fn prepare(
        &mut self,
        _model: &mut CostModel<'_>,
        _node: usize,
        _config: ResourceSet,
        _copies: ResourceSet,
        _step: u64,
    ) -> Result<ResourceSet, TransitionError> {
        Ok(ResourceSet::EMPTY)
    }
}

/// Ordinary caching that prepares the most likely next stage's weights (line 870).
pub(crate) struct NextModelPrefetch<P> {
    inner: OrdinaryCaching<P>,
}

impl<P: RetentionPolicy> NextModelPrefetch<P> {
    pub(crate) fn new(retention: P) -> Self {
        Self {
            inner: OrdinaryCaching::new(retention),
        }
    }
}

impl<P: RetentionPolicy> OnlinePolicy for NextModelPrefetch<P> {
    fn name(&self) -> String {
        format!("next-model-prefetch-{}", self.inner.retention.name())
    }

    fn configure(
        &mut self,
        model: &mut CostModel<'_>,
        context: &Context,
        node: usize,
        step: u64,
    ) -> Result<ResourceSet, TransitionError> {
        self.inner.configure(model, context, node, step)
    }

    fn prepare(
        &mut self,
        model: &mut CostModel<'_>,
        node: usize,
        config: ResourceSet,
        copies: ResourceSet,
        _step: u64,
    ) -> Result<ResourceSet, TransitionError> {
        let workflow = model.workflow;
        let Some(entry) = model.tree.get(node) else {
            return Ok(ResourceSet::EMPTY);
        };
        // The most likely next stage by evidence; the first declared one without it.
        let next = match entry.aggregation {
            Aggregation::Expected => entry
                .children
                .iter()
                .zip(&entry.weights)
                .fold(None::<(usize, f64)>, |best, (child, weight)| match best {
                    Some((_, current)) if current >= *weight => best,
                    _ => Some((*child, *weight)),
                })
                .map(|(child, _)| child),
            _ => entry.children.first().copied(),
        };
        let Some(next) = next.and_then(|child| model.tree.get(child)) else {
            return Ok(ResourceSet::EMPTY);
        };
        let want = workflow.stages[next.stage]
            .requires
            .intersection(workflow.immutables())
            .difference(config);
        if want.is_empty() || !want.iter().all(|at| model.prefetchable(at, copies)) {
            return Ok(ResourceSet::EMPTY);
        }
        Ok(match model.preparation_fits(node, config, want)? {
            Ok(()) => want,
            Err(_) => ResourceSet::EMPTY,
        })
    }
}

/// GPU-N1 alone: the committed bundle planner (§4.14) over a horizon built from the
/// admitted request and requests forecast from online history, with no workflow
/// knowledge. Its planner work is charged like the compiled plan's.
pub(crate) struct BundleRetention {
    controller: ModeController,
    history: History,
    usage: MarginalSavedLatency,
    /// How often each requirement set was served: the only forecast it has.
    seen: BTreeMap<u64, u64>,
    selected: ResourceSet,
    work_units: u64,
}

/// The work budget of one bundle plan.
const BUNDLE_WORK_UNITS: u64 = 400_000;

/// Digest domain of the requests of a GPU-N1 horizon.
const HORIZON_DOMAIN: &str = "yougori/model-memory/transitions/n1-horizon/v1";

fn exact_estimate(seconds: f64) -> Result<(Duration, DurationEstimate), TransitionError> {
    let duration = Duration::try_from_secs_f64(seconds)
        .map_err(|_| TransitionError::DurationOutOfRange { seconds })?
        .max(Duration::from_nanos(1));
    Ok((duration, DurationEstimate::exact(duration)?))
}

impl BundleRetention {
    pub(crate) fn new() -> Result<Self, TransitionError> {
        Ok(Self {
            controller: forecast_controller()?,
            history: History::default(),
            usage: MarginalSavedLatency::new(8).map_err(|_| TransitionError::Internal {
                what: "a positive half-life",
            })?,
            seen: BTreeMap::new(),
            selected: ResourceSet::EMPTY,
            work_units: 0,
        })
    }

    /// The horizon at a boundary: every resident or rebuildable object the online system
    /// knows of, the admitted request of the next stage and one predicted request per
    /// requirement set served before, with its observed frequency. `None` when the room
    /// left beside the stage holds nothing.
    fn horizon(
        &self,
        model: &CostModel<'_>,
        context: &Context,
        node: usize,
    ) -> Result<Option<Horizon>, TransitionError> {
        let workflow = model.workflow;
        let Some(entry) = model.tree.get(node) else {
            return Err(TransitionError::Internal {
                what: "tree node out of range",
            });
        };
        let stage = &workflow.stages[entry.stage];
        let resident = context.resident_before(workflow);
        let allowed = workflow.immutables().union(entry.available);
        let link = ResourceId::new("transitions.h2d-link")?;
        let id = |at: usize| format!("r{at}");
        let mut objects = Vec::new();
        let mut included = ResourceSet::EMPTY;
        for at in allowed.iter() {
            let resource = &workflow.resources[at];
            let seconds = reload_estimate(model, at, context.copies);
            if !resident.contains(at) && seconds <= 0.0 {
                continue;
            }
            let (duration, load) = exact_estimate(seconds)?;
            objects.push(ObjectSpec {
                id: id(at),
                kind: match resource.kind {
                    ObjectKind::Adapter => NodeKind::Adapter,
                    ObjectKind::SessionKv => NodeKind::KvBlock,
                    ObjectKind::GraphPool => NodeKind::GraphCapture,
                    ObjectKind::BaseWeights | ObjectKind::MergedVariant => NodeKind::ArtifactExtent,
                },
                identity: resource.digest,
                trust_scope: workflow.trust_scope,
                bytes: resource.bytes,
                load,
                load_demand: vec![DemandSegment::transient(
                    link.clone(),
                    ResourceUnit::Slots,
                    1,
                    Duration::ZERO,
                    duration,
                )?],
                cancellation: CancellationBoundary::BeforeStart,
                requires: resource.closure.without(at).iter().map(id).collect(),
                resident: resident.contains(at),
                preparation: RawCost::default(),
                interference: RawCost::default(),
            });
            included = included.with(at);
        }
        if !stage.requires.is_subset(included) {
            return Ok(None);
        }
        let scale = model.duration_scale();
        let compute = exact_estimate(stage.prefill_seconds * scale)?.1;
        let request = |name: String, needs: ResourceSet, admission, arrival| RequestSpec {
            identity: DigestBuilder::new(HORIZON_DOMAIN)
                .str(&name)
                .u64(needs.bits())
                .finish(),
            id: name,
            trust_scope: workflow.trust_scope,
            weight: 1.0,
            admission,
            arrival,
            needs: needs.iter().map(id).collect(),
            compute,
            compute_demand: Vec::new(),
            cancellation: CancellationBoundary::BeforeStart,
        };
        let process = stage.process;
        let room = model
            .usable_vram_bytes()
            .saturating_sub(workflow.budgets.safety_reserve_bytes)
            .saturating_sub(process.context_bytes)
            .saturating_sub(process.graph_pool_bytes)
            .saturating_sub(process.kv_pool_bytes)
            .saturating_sub(process.workspace_bytes);
        let retention = room.saturating_sub(workflow.budgets.staging_bytes);
        if retention == 0 || workflow.bytes(stage.requires) > retention {
            return Ok(None);
        }
        let mut requests = vec![request(
            "admitted".to_string(),
            stage.requires,
            Admission::Admitted,
            Duration::ZERO,
        )];
        // The planner holds every needed object until its horizon ends, so forecasts join,
        // most frequent first, only while all their state fits the retention budget.
        let total: u64 = self.seen.values().sum();
        let after = exact_estimate(stage.duration_seconds() * scale)?.0;
        let mut forecasts: Vec<(u64, ResourceSet)> = self
            .seen
            .iter()
            .map(|(bits, count)| (*count, ResourceSet::from_bits(*bits)))
            .filter(|(_, needs)| *needs != stage.requires && needs.is_subset(included))
            .collect();
        forecasts.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.bits().cmp(&b.1.bits())));
        let mut covered = stage.requires;
        for (number, (count, needs)) in forecasts.into_iter().enumerate() {
            let union = covered.union(needs);
            if total == 0 || workflow.bytes(union) > retention {
                continue;
            }
            covered = union;
            requests.push(request(
                format!("forecast-{number}"),
                needs,
                Admission::Predicted {
                    probability: count as f64 / total as f64,
                },
                after,
            ));
        }
        let spec = HorizonSpec {
            objects,
            requests,
            memory: ResourceId::new("transitions.vram")?,
            memory_capacity: Capacity::Physical { bytes: room },
            retention_budget_bytes: retention,
            scope_budgets: Vec::new(),
            capacities: vec![(link, ResourceUnit::Slots, 1)],
            policy: Policy::new(),
            objective: Objective::new(1.0, 0.0, 0.0, 0.0).map_err(|_| {
                TransitionError::Internal {
                    what: "a valid objective",
                }
            })?,
            bounds: HorizonBounds {
                min_probability: 0.0,
                max_requests: 64,
                max_objects: 64,
            },
        };
        Ok(Some(Horizon::build(spec)?))
    }
}

impl OnlinePolicy for BundleRetention {
    fn name(&self) -> String {
        "gpu-n1-alone".to_string()
    }

    fn planning_work_units(&self) -> u64 {
        self.work_units
    }

    fn configure(
        &mut self,
        model: &mut CostModel<'_>,
        context: &Context,
        node: usize,
        step: u64,
    ) -> Result<ResourceSet, TransitionError> {
        let workflow = model.workflow;
        if let Some(produced) = context.produced(workflow) {
            record_use(
                &mut self.usage,
                &mut self.history,
                model,
                ResourceSet::single(produced),
                context.copies,
                step.saturating_sub(1),
            );
        }
        let Some(entry) = model.tree.get(node) else {
            return Err(TransitionError::Internal {
                what: "tree node out of range",
            });
        };
        let required = workflow.stages[entry.stage].requires;
        let allowed = workflow.immutables().union(entry.available);
        let mut keep = ResourceSet::EMPTY;
        if let Some(horizon) = self.horizon(model, context, node)? {
            let bundle = plan(
                &horizon,
                model.clock(),
                &self.controller,
                PlannerConfig::bundles(BUNDLE_WORK_UNITS),
            )?;
            self.work_units = self.work_units.saturating_add(bundle.work_units);
            for object in horizon.ids(bundle.selection()) {
                if let Some(at) = object
                    .strip_prefix('r')
                    .and_then(|number| number.parse::<usize>().ok())
                {
                    keep = keep.with(at);
                }
            }
        }
        self.selected = keep;
        let resident = context.resident_before(workflow).intersection(allowed);
        let candidate = closed_subset(model, resident.intersection(keep).union(required));
        let name = self.name();
        let config = make_room(
            &mut self.usage,
            &self.history,
            model,
            context,
            node,
            candidate,
            required,
            step,
            &name,
        )?;
        record_use(
            &mut self.usage,
            &mut self.history,
            model,
            required,
            context.copies,
            step,
        );
        *self.seen.entry(required.bits()).or_insert(0) += 1;
        Ok(config)
    }

    fn prepare(
        &mut self,
        model: &mut CostModel<'_>,
        node: usize,
        config: ResourceSet,
        copies: ResourceSet,
        _step: u64,
    ) -> Result<ResourceSet, TransitionError> {
        let workflow = model.workflow;
        let want: ResourceSet = self
            .selected
            .intersection(workflow.immutables())
            .difference(config)
            .iter()
            .filter(|at| model.prefetchable(*at, copies))
            .fold(ResourceSet::EMPTY, ResourceSet::with);
        if want.is_empty() {
            return Ok(ResourceSet::EMPTY);
        }
        Ok(match model.preparation_fits(node, config, want)? {
            Ok(()) => want,
            Err(_) => ResourceSet::EMPTY,
        })
    }
}
