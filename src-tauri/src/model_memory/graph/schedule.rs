//! Fixed schedules (GPU §2.3). A schedule is the dependency DAG plus resource-conflict
//! ordering edges between nodes that contend for a capacity-limited resource. For a fixed
//! schedule, finish(v) = duration(v) + max(finish(u) for u in predecessors(v)), where
//! predecessors include the conflict edges, and the objective is the finish of the node
//! that delivers the first correct token, subject to the capacities.

use std::collections::BTreeMap;
use std::time::Duration;

use super::dag::RequestGraph;
use super::node::ResourceUnit;
use super::problem::{add, Problem};
use super::{NodeId, ResourceId, ScheduleError};

/// The capacity-limited resources a schedule must respect (GPU §2.3), each with the unit
/// its capacity and every demand on it are counted in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Capacities {
    resources: BTreeMap<ResourceId, (ResourceUnit, u64)>,
}

impl Capacities {
    /// No resources declared yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Declares `capacity` of `resource`, counted in `unit`.
    pub fn with(
        mut self,
        resource: ResourceId,
        unit: ResourceUnit,
        capacity: u64,
    ) -> Result<Self, ScheduleError> {
        if capacity == 0 {
            return Err(ScheduleError::ZeroCapacity { resource });
        }
        if self.resources.contains_key(&resource) {
            return Err(ScheduleError::DuplicateResource { resource });
        }
        self.resources.insert(resource, (unit, capacity));
        Ok(self)
    }

    /// The unit and capacity of `resource`, if declared.
    pub fn get(&self, resource: &ResourceId) -> Option<(ResourceUnit, u64)> {
        self.resources.get(resource).copied()
    }

    /// The resource's position in declaration order, its unit and its capacity.
    pub(crate) fn lookup(&self, resource: &ResourceId) -> Option<(usize, ResourceUnit, u64)> {
        let (unit, capacity) = self.resources.get(resource).copied()?;
        Some((self.resources.range(..resource).count(), unit, capacity))
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&ResourceId, ResourceUnit, u64)> {
        self.resources
            .iter()
            .map(|(id, &(unit, capacity))| (id, unit, capacity))
    }
}

/// One scheduled node: its expected start and finish, and its finish at the low and high
/// ends of every duration interval on the same fixed schedule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduledNode {
    pub node: NodeId,
    pub start: Duration,
    pub finish: Duration,
    pub finish_low: Duration,
    pub finish_high: Duration,
}

/// A fixed schedule with its finish times, checked against the capacities at the
/// expected durations (GPU §2.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluatedSchedule {
    nodes: Vec<ScheduledNode>,
    conflict_edges: Vec<(NodeId, NodeId)>,
    first_token: Duration,
    first_token_low: Duration,
    first_token_high: Duration,
    makespan: Duration,
    serial_work: Duration,
    work_spent: u64,
}

impl EvaluatedSchedule {
    pub(crate) fn from_problem(
        problem: &Problem<'_>,
        conflicts: &[(usize, usize)],
        work_spent: u64,
    ) -> Result<Self, ScheduleError> {
        let timing = problem.timing(conflicts)?;
        problem.check_capacity(&timing.start)?;
        let at = |nanos: u64| Duration::from_nanos(nanos);
        let nodes = (0..problem.len())
            .map(|node| ScheduledNode {
                node: problem.id(node).clone(),
                start: at(timing.start[node]),
                finish: at(timing.finish[node]),
                finish_low: at(timing.finish_low[node]),
                finish_high: at(timing.finish_high[node]),
            })
            .collect();
        let serial_work = problem
            .expected
            .iter()
            .try_fold(0u64, |sum, &duration| add(sum, duration))?;
        let objective = problem.objective;
        Ok(Self {
            nodes,
            conflict_edges: conflicts
                .iter()
                .map(|&(from, to)| (problem.id(from).clone(), problem.id(to).clone()))
                .collect(),
            first_token: at(timing.finish[objective]),
            first_token_low: at(timing.finish_low[objective]),
            first_token_high: at(timing.finish_high[objective]),
            makespan: at(timing.finish.iter().copied().max().unwrap_or(0)),
            serial_work: at(serial_work),
            work_spent,
        })
    }

    /// The scheduled nodes in the order they were added to the graph.
    pub fn nodes(&self) -> &[ScheduledNode] {
        &self.nodes
    }

    /// `None` for a node that is not scheduled, such as one satisfied by ready state.
    pub fn node(&self, id: &NodeId) -> Option<&ScheduledNode> {
        self.nodes.iter().find(|scheduled| &scheduled.node == id)
    }

    /// The resource-conflict ordering edges, producer of the wait first.
    pub fn conflict_edges(&self) -> &[(NodeId, NodeId)] {
        &self.conflict_edges
    }

    /// The objective: the finish of the first correct token (GPU §2.3).
    pub fn first_token(&self) -> Duration {
        self.first_token
    }

    /// The first token's finish with every duration at its low and at its high end.
    pub fn first_token_interval(&self) -> (Duration, Duration) {
        (self.first_token_low, self.first_token_high)
    }

    /// When the last scheduled node finishes.
    pub fn makespan(&self) -> Duration {
        self.makespan
    }

    /// The sum of expected durations: the makespan if nothing overlapped.
    pub fn serial_work(&self) -> Duration {
        self.serial_work
    }

    /// Work hidden by overlap: serial work minus makespan (GPU §1, path 3).
    pub fn overlap(&self) -> Duration {
        self.serial_work.saturating_sub(self.makespan)
    }

    /// Whether two scheduled nodes run at the same time; `None` if either is not
    /// scheduled.
    pub fn runs_concurrently(&self, left: &NodeId, right: &NodeId) -> Option<bool> {
        let (a, b) = (self.node(left)?, self.node(right)?);
        Some(a.start < b.finish && b.start < a.finish)
    }

    /// Work units the search spent; zero for a schedule that was only evaluated.
    pub fn work_spent(&self) -> u64 {
        self.work_spent
    }
}

/// Evaluates every node of `graph` under the given resource-conflict ordering edges
/// (GPU §2.3). Each edge must join nodes that contend for a capacity-limited resource,
/// the edges must not close a cycle, and the result must respect the capacities.
pub fn evaluate_fixed(
    graph: &RequestGraph,
    capacities: &Capacities,
    conflict_edges: &[(NodeId, NodeId)],
) -> Result<EvaluatedSchedule, ScheduleError> {
    let problem = Problem::new(graph, &vec![true; graph.len()], capacities)?;
    let local = |id: &NodeId| {
        graph
            .index_of(id)
            .ok_or_else(|| ScheduleError::UnknownNode { node: id.clone() })
    };
    let conflicts = conflict_edges
        .iter()
        .map(|(from, to)| Ok((local(from)?, local(to)?)))
        .collect::<Result<Vec<_>, ScheduleError>>()?;
    EvaluatedSchedule::from_problem(&problem, &conflicts, 0)
}
