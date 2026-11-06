//! T_r(X) from a resource-feasible schedule (GPU §4.14, lines 802–808 and step 4).
//!
//! For a selection X the whole horizon becomes one request graph
//! ([`crate::model_memory::graph`]): one load node per object, held in device memory until
//! the horizon ends and carrying its transient demand on shared links and staging pools;
//! one first-token compute per request; and one join node that every compute feeds, which
//! is the graph's single objective. Then:
//!
//! - a resident object in X is ready state ([`ReadyState`]), so it is skipped and its
//!   bytes leave the capacity given to the schedule (the T06 rule: ready state holds its
//!   memory outside the planner's capacities);
//! - an absent object in X is prepared: its load node starts now, so its preparation
//!   duration, link use and transient memory are part of the schedule;
//! - any other needed object loads on demand: it cannot start before the earliest request
//!   that still needs it arrives, which a timing node of that length enforces;
//! - each request waits for its arrival and its needs, so T_r(X) is the compute's finish
//!   minus the arrival.
//!
//! [`paths::plan`] schedules the graph with the bounded heuristic, so queues on shared
//! links, dependency barriers and capacity conflicts all shape T_r; nothing divides bytes
//! by a nominal bandwidth. A selection whose schedule the heuristic cannot certify is
//! infeasible.
//!
//! Timing nodes consume no state. The join's edges cross into its own scope under
//! allowances that name exactly each request's compute identity, and timing nodes for
//! demand loads live in the object's own scope, so no object state crosses a scope that
//! the horizon policy did not allow.

use std::time::Duration;

use crate::foundation::ids::{digest, Clock, MonotonicTime, TrustScope};
use crate::model_memory::graph::dag::{GraphBuilder, Policy, RequestGraph};
use crate::model_memory::graph::heuristic::WorkBound;
use crate::model_memory::graph::node::{
    CancellationBoundary, CompletionEvent, DemandProfile, DemandSegment, DurationEstimate,
    NodeKind, NodeSpec, ResourceUnit,
};
use crate::model_memory::graph::paths::{self, Disposition, ReadyState};
use crate::model_memory::graph::schedule::Capacities;
use crate::model_memory::graph::{NodeId, ScheduleError};
use crate::model_memory::math::prefetch::{Objective, RawCost};

use super::horizon::{Horizon, Selection};
use super::BundleError;

const ARRIVAL_DOMAIN: &str = "yougori/model-memory/bundles/arrival/v1";
const TRIGGER_DOMAIN: &str = "yougori/model-memory/bundles/demand-trigger/v1";
const JOIN_DOMAIN: &str = "yougori/model-memory/bundles/horizon-join/v1";
const JOIN_SCOPE_DOMAIN: &str = "yougori/model-memory/bundles/horizon-join-scope/v1";

/// The first work bound tried for one schedule; it doubles while the heuristic needs more.
const MIN_INITIAL_BOUND: u64 = 4096;

/// Counts planner work units against an explicit budget (GPU §4.14 step 5: a strict
/// planner-time budget). Every charge is at least the work done: a schedule that fails
/// or is cut off is charged its whole bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkMeter {
    spent: u64,
    limit: Option<u64>,
}

impl WorkMeter {
    /// A meter refusing work beyond `max_units`.
    pub fn bounded(max_units: u64) -> Self {
        Self {
            spent: 0,
            limit: Some(max_units),
        }
    }

    /// A meter without a limit, for offline references such as the exhaustive optimum.
    pub fn unbounded() -> Self {
        Self {
            spent: 0,
            limit: None,
        }
    }

    /// Units charged so far.
    pub fn spent(&self) -> u64 {
        self.spent
    }

    /// The budget; `None` without a limit.
    pub fn limit(&self) -> Option<u64> {
        self.limit
    }

    /// Units left; `u64::MAX` without a limit.
    pub fn remaining(&self) -> u64 {
        self.limit
            .map_or(u64::MAX, |limit| limit.saturating_sub(self.spent))
    }

    /// Adds `units`, or refuses with [`BundleError::BudgetExhausted`] when they would pass
    /// the limit.
    pub fn charge(&mut self, units: u64) -> Result<(), BundleError> {
        let spent = self.spent.saturating_add(units);
        if let Some(limit) = self.limit {
            if spent > limit {
                self.spent = limit;
                return Err(self.exhausted());
            }
        }
        self.spent = spent;
        Ok(())
    }

    fn exhausted(&self) -> BundleError {
        BundleError::BudgetExhausted {
            spent_units: self.spent,
            max_units: self.limit.unwrap_or(u64::MAX),
        }
    }
}

/// Why a selection is not a feasible X (GPU §4.14: physical memory, transient capacity
/// and trust constraints).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Infeasibility {
    /// X holds more than the retention budget.
    OverRetentionBudget { bytes: u64, budget_bytes: u64 },
    /// X holds more of one trust scope's objects than that scope's budget.
    OverScopeBudget {
        scope: TrustScope,
        bytes: u64,
        budget_bytes: u64,
    },
    /// An absent member of X has a reconstruction requirement outside X, so it cannot be
    /// prepared (line 830).
    NotDependencyClosed { object: String, missing: String },
    /// The bounded heuristic found no resource-feasible schedule: transient capacity is
    /// exceeded or no placement was found.
    Unschedulable(ScheduleError),
}

/// One selection scored against the horizon (GPU §4.14, lines 802–808).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Evaluation {
    pub selection: Selection,
    /// T_r(X) for each included request, in horizon order: compute finish minus arrival.
    pub completion: Vec<Duration>,
    /// When each request's compute could start, after its arrival.
    pub state_ready: Vec<Duration>,
    /// When each object becomes usable, from the decision point; zero when ready, `None`
    /// when no request needs it under X.
    pub object_ready: Vec<Option<Duration>>,
    /// sum_r w_r * (T_r(empty) - T_r(X)) in seconds, with w_r the expected weight.
    pub saved_weighted_seconds: f64,
    /// The same in objective units.
    pub benefit_score: f64,
    /// Resource consumption of preparing the absent members of X.
    pub preparation: RawCost,
    pub preparation_score: f64,
    pub interference: RawCost,
    pub interference_score: f64,
    /// benefit − preparation_cost − interference.
    pub net_score: f64,
    /// Bytes of resident members of X.
    pub retained_bytes: u64,
    /// Bytes of absent members of X.
    pub prepared_bytes: u64,
    /// Bytes every scheduled load moves: preparation and demand.
    pub loaded_bytes: u64,
    /// Work units this evaluation charged.
    pub work_units: u64,
}

/// A selection's evaluation, or why it is not feasible.
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    /// X satisfies every constraint and has this evaluation.
    Feasible(Evaluation),
    /// X violates a constraint.
    Infeasible(Infeasibility),
}

impl Outcome {
    /// The evaluation of a feasible X.
    pub fn feasible(self) -> Option<Evaluation> {
        match self {
            Self::Feasible(evaluation) => Some(evaluation),
            Self::Infeasible(_) => None,
        }
    }
}

/// The event that establishes usability for a kind of state.
fn completion_for(kind: NodeKind) -> CompletionEvent {
    match kind {
        NodeKind::ArtifactExtent => CompletionEvent::ExtentVerified,
        NodeKind::EngineInitialization => CompletionEvent::EngineReady,
        NodeKind::RankLayout => CompletionEvent::LayoutPublished,
        NodeKind::Adapter => CompletionEvent::AdapterActivated,
        NodeKind::TokenizerConfiguration => CompletionEvent::TokenizerLoaded,
        NodeKind::KvBlock => CompletionEvent::KvBlockPublished,
        NodeKind::GraphCapture => CompletionEvent::GraphKeyValidated,
        NodeKind::Communicator => CompletionEvent::CommunicatorReady,
        NodeKind::Compute => CompletionEvent::ComputeCompleted,
        NodeKind::NetworkResponse => CompletionEvent::ResponseDelivered,
    }
}

/// A score in objective units for `milliseconds`, which may be negative.
pub(crate) fn milliseconds_score(
    objective: &Objective,
    milliseconds: f64,
) -> Result<f64, BundleError> {
    let magnitude = objective.score(&RawCost {
        milliseconds: milliseconds.abs(),
        ..RawCost::default()
    })?;
    Ok(if milliseconds < 0.0 {
        -magnitude
    } else {
        magnitude
    })
}

fn add_cost(total: &mut RawCost, cost: &RawCost) {
    total.milliseconds += cost.milliseconds;
    total.bytes += cost.bytes;
    total.energy_joules += cost.energy_joules;
    total.currency_units += cost.currency_units;
}

fn name(prefix: &str, id: &str) -> Result<NodeId, BundleError> {
    Ok(NodeId::new(format!("{prefix}:{id}"))?)
}

fn exact(duration: Duration) -> Result<DurationEstimate, BundleError> {
    Ok(DurationEstimate::exact(duration)?)
}

/// Scores selections of one horizon against T_r(empty) (GPU §4.14 step 4).
pub struct Evaluator<'h> {
    horizon: &'h Horizon,
    clock: &'h dyn Clock,
    object_nodes: Vec<NodeId>,
    trigger_nodes: Vec<NodeId>,
    arrival_nodes: Vec<NodeId>,
    compute_nodes: Vec<NodeId>,
    join: NodeId,
    join_scope: TrustScope,
    policy: Policy,
    initial_bound: u64,
    empty: Evaluation,
}

impl<'h> Evaluator<'h> {
    /// Schedules the horizon with nothing retained or prepared, charging `meter`; refuses
    /// a horizon that cannot be scheduled that way.
    pub fn new(
        horizon: &'h Horizon,
        clock: &'h dyn Clock,
        meter: &mut WorkMeter,
    ) -> Result<Self, BundleError> {
        let mut object_nodes = Vec::with_capacity(horizon.objects().len());
        let mut trigger_nodes = Vec::with_capacity(horizon.objects().len());
        for object in horizon.objects() {
            object_nodes.push(name("o", &object.id)?);
            trigger_nodes.push(name("t", &object.id)?);
        }
        let mut arrival_nodes = Vec::with_capacity(horizon.request_count());
        let mut compute_nodes = Vec::with_capacity(horizon.request_count());
        let first = horizon.request(0).trust_scope;
        let join_scope = TrustScope::new(first.category, digest(JOIN_SCOPE_DOMAIN, &[]));
        let mut policy = horizon.spec().policy.clone();
        for position in 0..horizon.request_count() {
            let request = horizon.request(position);
            arrival_nodes.push(name("a", &request.id)?);
            compute_nodes.push(name("c", &request.id)?);
            if request.trust_scope != join_scope {
                policy = policy.allow(request.trust_scope, join_scope, request.identity);
            }
        }
        let mut evaluator = Self {
            horizon,
            clock,
            object_nodes,
            trigger_nodes,
            arrival_nodes,
            compute_nodes,
            join: NodeId::new("j")?,
            join_scope,
            policy,
            initial_bound: MIN_INITIAL_BOUND,
            empty: Evaluation::default(),
        };
        match evaluator.run(&Selection::new(), meter)? {
            Outcome::Feasible(empty) => {
                evaluator.initial_bound = empty.work_units.saturating_mul(2).max(MIN_INITIAL_BOUND);
                evaluator.empty = empty;
                Ok(evaluator)
            }
            Outcome::Infeasible(Infeasibility::Unschedulable(error)) => {
                Err(BundleError::EmptyHorizonUnschedulable(error))
            }
            Outcome::Infeasible(_) => Err(BundleError::InvalidValue {
                field: "horizon",
                reason: "the empty selection must be feasible",
            }),
        }
    }

    /// The horizon being scored.
    pub fn horizon(&self) -> &'h Horizon {
        self.horizon
    }

    /// The evaluation of X = empty: T_r(empty) and a net score of zero.
    pub fn empty(&self) -> &Evaluation {
        &self.empty
    }

    /// Scores `selection`, charging `meter` for the schedule.
    pub fn evaluate(
        &self,
        selection: &Selection,
        meter: &mut WorkMeter,
    ) -> Result<Outcome, BundleError> {
        self.run(selection, meter)
    }

    fn run(&self, selection: &Selection, meter: &mut WorkMeter) -> Result<Outcome, BundleError> {
        let horizon = self.horizon;
        let spec = horizon.spec();
        if let Some(object) = selection.iter().find(|&at| at >= horizon.objects().len()) {
            return Err(BundleError::Unknown {
                field: "selection",
                id: object.to_string(),
            });
        }
        let bytes = horizon.bytes(selection)?;
        if bytes > spec.retention_budget_bytes {
            return Ok(Outcome::Infeasible(Infeasibility::OverRetentionBudget {
                bytes,
                budget_bytes: spec.retention_budget_bytes,
            }));
        }
        for (scope, &budget) in horizon.scope_budgets() {
            let held = selection
                .iter()
                .filter(|&at| &horizon.object(at).trust_scope == scope)
                .map(|at| horizon.object(at).bytes)
                .fold(0u64, u64::saturating_add);
            if held > budget {
                return Ok(Outcome::Infeasible(Infeasibility::OverScopeBudget {
                    scope: *scope,
                    bytes: held,
                    budget_bytes: budget,
                }));
            }
        }
        if let Some((object, missing)) = horizon.unclosed(selection) {
            return Ok(Outcome::Infeasible(Infeasibility::NotDependencyClosed {
                object: horizon.object(object).id.clone(),
                missing: horizon.object(missing).id.clone(),
            }));
        }

        let count = horizon.objects().len();
        let ready: Vec<bool> = (0..count)
            .map(|at| selection.contains(at) && horizon.object(at).resident)
            .collect();
        let prepared: Vec<bool> = (0..count)
            .map(|at| selection.contains(at) && !horizon.object(at).resident)
            .collect();

        let mut in_graph = vec![false; count];
        let mut stack: Vec<usize> = (0..count)
            .filter(|&at| horizon.is_needed(at) || prepared[at])
            .collect();
        while let Some(at) = stack.pop() {
            if !in_graph[at] {
                in_graph[at] = true;
                stack.extend(horizon.requirements(at).iter().copied());
            }
        }

        // The earliest arrival of a request that still needs each object: ready state
        // cuts the requirement chain below it.
        let mut earliest: Vec<Option<Duration>> = vec![None; count];
        for position in 0..horizon.request_count() {
            let arrival = horizon.request(position).arrival;
            let mut seen = vec![false; count];
            let mut stack: Vec<usize> = horizon.needs(position).to_vec();
            while let Some(at) = stack.pop() {
                if seen[at] {
                    continue;
                }
                seen[at] = true;
                earliest[at] = Some(earliest[at].map_or(arrival, |known| known.min(arrival)));
                if !ready[at] {
                    stack.extend(horizon.requirements(at).iter().copied());
                }
            }
        }

        let memory = &spec.memory;
        let mut builder = GraphBuilder::new();
        let mut ready_states = Vec::new();
        let expiry = MonotonicTime::from_nanos(u64::MAX);
        for at in (0..count).filter(|&at| in_graph[at]) {
            let object = horizon.object(at);
            let mut segments = vec![DemandSegment::retained(
                memory.clone(),
                ResourceUnit::Bytes,
                object.bytes,
                Duration::ZERO,
            )?];
            segments.extend(object.load_demand.iter().cloned());
            builder = builder.node(
                NodeSpec::new(
                    self.object_nodes[at].clone(),
                    object.kind,
                    object.identity,
                    object.trust_scope,
                    object.load,
                    completion_for(object.kind),
                )
                .with_demand(DemandProfile::new(segments))
                .with_cancellation(object.cancellation),
            );
            for &requirement in horizon.requirements(at) {
                builder = builder.edge(&self.object_nodes[requirement], &self.object_nodes[at]);
            }
            if ready[at] {
                ready_states.push(ReadyState::new(object.identity, object.trust_scope, expiry));
            }
            if !selection.contains(at) {
                if let Some(arrival) = earliest[at].filter(|arrival| !arrival.is_zero()) {
                    builder = builder
                        .node(
                            NodeSpec::new(
                                self.trigger_nodes[at].clone(),
                                NodeKind::NetworkResponse,
                                digest(TRIGGER_DOMAIN, &[object.identity.as_bytes()]),
                                object.trust_scope,
                                exact(arrival)?,
                                CompletionEvent::ResponseDelivered,
                            )
                            .with_cancellation(CancellationBoundary::Anytime),
                        )
                        .edge(&self.trigger_nodes[at], &self.object_nodes[at]);
                }
            }
        }
        for position in 0..horizon.request_count() {
            let request = horizon.request(position);
            let compute = &self.compute_nodes[position];
            builder = builder.node(
                NodeSpec::new(
                    compute.clone(),
                    NodeKind::Compute,
                    request.identity,
                    request.trust_scope,
                    request.compute,
                    CompletionEvent::ComputeCompleted,
                )
                .with_demand(DemandProfile::new(request.compute_demand.clone()))
                .with_cancellation(request.cancellation),
            );
            if !request.arrival.is_zero() {
                let arrival = &self.arrival_nodes[position];
                builder = builder
                    .node(
                        NodeSpec::new(
                            arrival.clone(),
                            NodeKind::NetworkResponse,
                            digest(ARRIVAL_DOMAIN, &[request.identity.as_bytes()]),
                            request.trust_scope,
                            exact(request.arrival)?,
                            CompletionEvent::ResponseDelivered,
                        )
                        .with_cancellation(CancellationBoundary::Anytime),
                    )
                    .edge(arrival, compute);
            }
            for &need in horizon.needs(position) {
                builder = builder.edge(&self.object_nodes[need], compute);
            }
            builder = builder.edge(compute, &self.join);
        }
        builder = builder.node(
            NodeSpec::new(
                self.join.clone(),
                NodeKind::NetworkResponse,
                digest(JOIN_DOMAIN, &[]),
                self.join_scope,
                exact(Duration::from_nanos(1))?,
                CompletionEvent::FirstTokenDelivered,
            )
            .with_cancellation(CancellationBoundary::Anytime),
        );
        let graph = builder.build(self.policy.clone())?;

        let retained_bytes = (0..count)
            .filter(|&at| ready[at])
            .map(|at| horizon.object(at).bytes)
            .fold(0u64, u64::saturating_add);
        let schedule_memory = horizon
            .memory_capacity_bytes()
            .checked_sub(retained_bytes)
            .filter(|&left| left > 0)
            .ok_or(BundleError::InvalidValue {
                field: "retained bytes",
                reason: "leave no transient memory",
            })?;
        let mut capacities =
            Capacities::new().with(memory.clone(), ResourceUnit::Bytes, schedule_memory)?;
        for (resource, unit, capacity) in &spec.capacities {
            capacities = capacities.with(resource.clone(), *unit, *capacity)?;
        }

        let start = meter.spent();
        let plan = match self.schedule(&graph, &ready_states, &capacities, meter)? {
            Ok(plan) => plan,
            Err(infeasible) => return Ok(Outcome::Infeasible(infeasible)),
        };
        if !plan.rejections().is_empty() {
            return Err(BundleError::InvalidValue {
                field: "ready state",
                reason: "an advertisement for retained state was rejected",
            });
        }
        let schedule = plan.schedule();

        let mut completion = Vec::with_capacity(horizon.request_count());
        let mut state_ready = Vec::with_capacity(horizon.request_count());
        for position in 0..horizon.request_count() {
            let node =
                schedule
                    .node(&self.compute_nodes[position])
                    .ok_or(BundleError::InvalidValue {
                        field: "schedule",
                        reason: "a request compute was not scheduled",
                    })?;
            let arrival = horizon.request(position).arrival;
            completion.push(node.finish.saturating_sub(arrival));
            state_ready.push(node.start.saturating_sub(arrival));
        }
        let mut object_ready = vec![None; count];
        let mut loaded_bytes = 0u64;
        for at in 0..count {
            if ready[at] {
                object_ready[at] = Some(Duration::ZERO);
            } else if in_graph[at]
                && plan.disposition(&self.object_nodes[at]) == Some(Disposition::Missing)
            {
                object_ready[at] = schedule
                    .node(&self.object_nodes[at])
                    .map(|node| node.finish);
                loaded_bytes = loaded_bytes.saturating_add(horizon.object(at).bytes);
            }
        }

        let mut preparation = RawCost::default();
        let mut interference = RawCost::default();
        let mut prepared_bytes = 0u64;
        for at in (0..count).filter(|&at| prepared[at]) {
            let object = horizon.object(at);
            add_cost(&mut preparation, &object.preparation);
            add_cost(&mut interference, &object.interference);
            prepared_bytes = prepared_bytes.saturating_add(object.bytes);
        }

        let baseline: &[Duration] = if self.empty.completion.is_empty() {
            &completion
        } else {
            &self.empty.completion
        };
        let mut saved_nanos_weighted = 0.0;
        for (position, (before, after)) in baseline.iter().zip(&completion).enumerate() {
            let delta = before.as_nanos() as i128 - after.as_nanos() as i128;
            saved_nanos_weighted += horizon.effective_weight(position) * delta as f64;
        }
        let objective = &spec.objective;
        let benefit_score = milliseconds_score(objective, saved_nanos_weighted / 1e6)?;
        let preparation_score = objective.score(&preparation)?;
        let interference_score = objective.score(&interference)?;
        Ok(Outcome::Feasible(Evaluation {
            selection: selection.clone(),
            completion,
            state_ready,
            object_ready,
            saved_weighted_seconds: saved_nanos_weighted / 1e9,
            benefit_score,
            preparation,
            preparation_score,
            interference,
            interference_score,
            net_score: benefit_score - preparation_score - interference_score,
            retained_bytes,
            prepared_bytes,
            loaded_bytes,
            work_units: meter.spent().saturating_sub(start),
        }))
    }

    /// Runs [`paths::plan`] with a doubling work bound, charging every attempt in full.
    fn schedule(
        &self,
        graph: &RequestGraph,
        ready: &[ReadyState],
        capacities: &Capacities,
        meter: &mut WorkMeter,
    ) -> Result<Result<paths::RequestPlan, Infeasibility>, BundleError> {
        meter.charge(u64::try_from(graph.len()).unwrap_or(u64::MAX))?;
        let cap = WorkBound::for_graph(graph).max_units().max(1);
        let mut bound = self.initial_bound.min(cap);
        loop {
            let allowed = bound.min(meter.remaining());
            match paths::plan(
                graph,
                ready,
                self.clock,
                capacities,
                WorkBound::new(allowed),
            ) {
                Ok(plan) => {
                    meter.charge(plan.schedule().work_spent())?;
                    return Ok(Ok(plan));
                }
                Err(ScheduleError::WorkBoundExceeded { .. }) => {
                    meter.charge(allowed)?;
                    if allowed < bound {
                        return Err(meter.exhausted());
                    }
                    if bound >= cap {
                        return Err(BundleError::Schedule(ScheduleError::WorkBoundExceeded {
                            bound: cap,
                        }));
                    }
                    bound = bound.saturating_mul(2).min(cap);
                }
                Err(
                    error @ (ScheduleError::NoFeasiblePlacement { .. }
                    | ScheduleError::NoFeasibleSchedule),
                ) => {
                    meter.charge(allowed)?;
                    return Ok(Err(Infeasibility::Unschedulable(error)));
                }
                Err(
                    error @ (ScheduleError::NodeExceedsCapacity { .. }
                    | ScheduleError::RetainedDemandExceedsCapacity { .. }
                    | ScheduleError::CapacityExceeded { .. }),
                ) => {
                    return Ok(Err(Infeasibility::Unschedulable(error)));
                }
                Err(other) => return Err(BundleError::Schedule(other)),
            }
        }
    }
}
