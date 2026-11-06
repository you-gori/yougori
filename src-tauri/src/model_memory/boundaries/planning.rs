//! Planning one request over the T06 request graph (GPU §1, §2.3): what is ready, what
//! is missing and what is not needed, inside the request's security partition (S3.6).
//!
//! The planner takes ready state only as [`RecheckedState`], whose one constructor reads
//! a residency the T07 identity recheck accepted (line 506): an advertisement never
//! reaches the T06 graph unchecked.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::{Serialize, Serializer};

use super::declaration::{ExecutionDependencies, NodeId, SecurityPartition, StateIdentity};
use crate::foundation::ids::{Clock, Digest, DigestBuilder, MonotonicTime, TrustScope};
use crate::model_memory::graph::dag::{GraphBuilder, Policy};
use crate::model_memory::graph::heuristic::WorkBound;
use crate::model_memory::graph::node::{CompletionEvent, DurationEstimate, NodeKind, NodeSpec};
use crate::model_memory::graph::paths::{plan, Disposition, ReadyState};
use crate::model_memory::graph::schedule::Capacities;
use crate::model_memory::graph::{GraphError, NodeId as GraphNodeId, ScheduleError};
use crate::model_memory::identity::{ExecutionIdentity, RecheckedResidency};

/// Ready state for the T06 planner, made only from a residency the T07 recheck accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecheckedState(ReadyState);

impl RecheckedState {
    /// Each identity the runner holds under `residency`, in the residency's scope, until
    /// the recheck's validity ends (the earlier of the advertisement's and the grant's
    /// expiries).
    pub fn from_rechecked(
        residency: &RecheckedResidency,
        resident: &BTreeSet<StateIdentity>,
    ) -> Vec<Self> {
        resident
            .iter()
            .map(|identity| {
                Self(ReadyState::new(
                    identity.digest(),
                    residency.residency.scope,
                    residency.valid_until,
                ))
            })
            .collect()
    }

    /// The T06 ready state.
    pub fn ready_state(&self) -> &ReadyState {
        &self.0
    }
}

/// What the plan does with each declared node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencyPlan {
    /// Satisfied by ready state and skipped (§1 path 1).
    pub ready: Vec<NodeId>,
    /// To materialize, each after the missing nodes it depends on (§1 path 2).
    pub missing: Vec<NodeId>,
    /// Missing, but consumed only by ready state, so not materialized (§1 path 2).
    pub not_needed: Vec<NodeId>,
    /// Nodes ready state matched by identity but could not satisfy (expired or from a
    /// scope the policy does not allow).
    pub rejected: Vec<NodeId>,
    /// When the graph's schedule expects the first token, with links uncontended.
    pub planned_first_token_at: MonotonicTime,
    /// The scheduled work's durations added up: its makespan had nothing overlapped.
    pub planned_serial_work: Duration,
    /// When the last scheduled node finishes, measured from the plan.
    pub planned_makespan: Duration,
}

impl DependencyPlan {
    /// Work the schedule hides by overlapping it (§1 path 3): serial work less makespan.
    pub fn planned_overlap(&self) -> Duration {
        self.planned_serial_work
            .saturating_sub(self.planned_makespan)
    }
}

/// Why a declaration could not be planned. Serialized as its message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanFault {
    Graph(GraphError),
    Schedule(ScheduleError),
    /// A state node was declared with a kind of request work (compute or response).
    WorkKindAsState {
        node: NodeId,
    },
}

impl fmt::Display for PlanFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Graph(error) => error.fmt(f),
            Self::Schedule(error) => error.fmt(f),
            Self::WorkKindAsState { node } => {
                write!(f, "{node} is declared as state but is request work")
            }
        }
    }
}

impl Serialize for PlanFault {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl From<GraphError> for PlanFault {
    fn from(error: GraphError) -> Self {
        Self::Graph(error)
    }
}

impl From<ScheduleError> for PlanFault {
    fn from(error: ScheduleError) -> Self {
        Self::Schedule(error)
    }
}

/// The event that makes a node of `kind` usable (T06).
fn completion(kind: NodeKind) -> CompletionEvent {
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
        NodeKind::NetworkResponse => CompletionEvent::FirstTokenDelivered,
    }
}

fn state_name(node: NodeId) -> Result<GraphNodeId, GraphError> {
    GraphNodeId::new(format!("state-{}", node.get()))
}

fn work_identity(domain: &str, model: &ExecutionIdentity, index: u64) -> Digest {
    DigestBuilder::new(domain)
        .digest(model.digest())
        .u64(index)
        .finish()
}

/// Plans `dependencies` of `model` for a runner whose work runs in `runner_scope`: the
/// state nodes, one compute node per group in order, and the response node that delivers
/// the first token. Crossing scopes is allowed only from scopes the partition grants
/// (S3.3, S3.6).
pub fn plan_dependencies(
    model: &ExecutionIdentity,
    dependencies: &ExecutionDependencies,
    runner_scope: TrustScope,
    partition: &SecurityPartition,
    ready: &[RecheckedState],
    clock: &dyn Clock,
) -> Result<DependencyPlan, PlanFault> {
    let ready: Vec<ReadyState> = ready.iter().map(|state| state.0.clone()).collect();
    let mut builder = GraphBuilder::new();
    let mut policy = Policy::new();
    let mut allow = |producer: TrustScope, consumer: TrustScope, identity: Digest| {
        if producer != consumer && partition.allows(&producer) {
            policy = std::mem::take(&mut policy).allow(producer, consumer, identity);
        }
    };
    let mut names = BTreeMap::new();
    for node in &dependencies.nodes {
        if !node.kind.can_be_ready() {
            return Err(PlanFault::WorkKindAsState { node: node.id });
        }
        let name = state_name(node.id)?;
        builder = builder.node(NodeSpec::new(
            name.clone(),
            node.kind,
            node.identity.digest(),
            node.scope,
            DurationEstimate::exact(node.estimate)?,
            completion(node.kind),
        ));
        names.insert(name, node.id);
        for state in &ready {
            if *state.identity() == node.identity.digest() {
                allow(*state.trust_scope(), node.scope, node.identity.digest());
            }
        }
    }
    let scope_of = |id: NodeId| {
        dependencies
            .nodes
            .iter()
            .find(|node| node.id == id)
            .map(|node| (node.scope, node.identity.digest()))
    };
    for node in &dependencies.nodes {
        for input in &node.depends_on {
            builder = builder.edge(&state_name(*input)?, &state_name(node.id)?);
            if let Some((scope, identity)) = scope_of(*input) {
                allow(scope, node.scope, identity);
            }
        }
    }
    let mut previous: Option<GraphNodeId> = None;
    for (index, group) in dependencies.compute.iter().enumerate() {
        let name = GraphNodeId::new(format!("compute-{index}"))?;
        builder = builder.node(NodeSpec::new(
            name.clone(),
            NodeKind::Compute,
            work_identity(
                "yougori/model-memory/boundaries/compute/v1",
                model,
                index as u64,
            ),
            runner_scope,
            DurationEstimate::exact(group.compute)?,
            CompletionEvent::ComputeCompleted,
        ));
        for input in &group.requires {
            builder = builder.edge(&state_name(*input)?, &name);
            if let Some((scope, identity)) = scope_of(*input) {
                allow(scope, runner_scope, identity);
            }
        }
        if let Some(previous) = &previous {
            builder = builder.edge(previous, &name);
        }
        previous = Some(name);
    }
    let response = GraphNodeId::new("response")?;
    builder = builder.node(NodeSpec::new(
        response.clone(),
        NodeKind::NetworkResponse,
        work_identity("yougori/model-memory/boundaries/response/v1", model, 0),
        runner_scope,
        DurationEstimate::exact(dependencies.response)?,
        CompletionEvent::FirstTokenDelivered,
    ));
    if let Some(previous) = &previous {
        builder = builder.edge(previous, &response);
    }

    let graph = builder.build(policy)?;
    let request_plan = plan(
        &graph,
        &ready,
        clock,
        &Capacities::new(),
        WorkBound::for_graph(&graph),
    )?;
    let mut planned = DependencyPlan {
        ready: Vec::new(),
        missing: Vec::new(),
        not_needed: Vec::new(),
        rejected: Vec::new(),
        planned_first_token_at: request_plan.first_token_at(),
        planned_serial_work: request_plan.schedule().serial_work(),
        planned_makespan: request_plan.schedule().makespan(),
    };
    for name in graph.topological_order() {
        let Some(node) = names.get(name) else {
            continue;
        };
        match request_plan.disposition(name) {
            Some(Disposition::Ready) => planned.ready.push(*node),
            Some(Disposition::Missing) => planned.missing.push(*node),
            Some(Disposition::NotNeeded) | None => planned.not_needed.push(*node),
        }
    }
    let rejected: BTreeSet<NodeId> = request_plan
        .rejections()
        .iter()
        .filter_map(|(name, _)| names.get(name).copied())
        .collect();
    planned.rejected = rejected.into_iter().collect();
    Ok(planned)
}
