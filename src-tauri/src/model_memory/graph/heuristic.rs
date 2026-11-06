//! The bounded production heuristic (GPU §2.3): list scheduling under resource
//! capacities, with one explicit work bound.
//!
//! Nodes are placed one at a time, in the order of a priority rule, each as soon as its
//! dependencies are placed. A node starts at the earliest of its dependency-ready time
//! and the finishes of placed nodes that contend with it at which every capacity holds.
//! Starting later than its dependencies allow adds one resource-conflict ordering edge
//! from the contending node whose finish it waits for.
//!
//! The first rule is critical-path: nodes on the first-token path come first, longest
//! remaining path first, so work off that path can never delay the objective. Memory
//! held until the request ends is never released, so a holder placed early can leave no
//! room for a later node's large transient demand. When the first rule finds no start for
//! some node, the heuristic retries once with a memory-pressure rule: the chains leading
//! to the largest transient demands go first, then the nodes holding the least memory, so
//! held memory starts after the demands it would block. The retry may put work off the
//! first-token path first; it trades latency for a feasible schedule only after the first
//! rule failed. When the retry fails too, the heuristic refuses; there is no other
//! backtracking.

use std::cmp::Reverse;

use super::dag::RequestGraph;
use super::problem::{add, Problem, Work, FOREVER};
use super::schedule::{Capacities, EvaluatedSchedule};
use super::ScheduleError;

/// An explicit upper bound on the heuristic's work units, covering both rules (GPU
/// §2.3: a bounded heuristic in production, not a solver on every request).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkBound(u64);

impl WorkBound {
    /// A bound of `max_units` work units.
    pub const fn new(max_units: u64) -> Self {
        Self(max_units)
    }

    /// A bound no graph with `nodes` scheduled nodes and `segments` demand segments in
    /// total can exceed: 9n² + S² + S + 2n·(S³ + 3S² + 4S + 2) units for both rules.
    ///
    /// The critical-path order costs at most 2n², and the memory-pressure order at most
    /// 3n² + S² + S. Each placement pass costs at most 2n² + n·(S³ + 3S² + 4S + 2): per node,
    /// selection and the blocker search cost n each, candidate collection at most S, and
    /// each of at most n candidate starts costs 1 plus a capacity probe of at most
    /// S + S_v·S·(S + 2), where S_v is the node's own segment count; candidates number at
    /// most S + 1.
    pub fn sufficient(nodes: usize, segments: usize) -> Self {
        let n = u64::try_from(nodes).unwrap_or(u64::MAX);
        let s = u64::try_from(segments).unwrap_or(u64::MAX);
        let per_node = s
            .saturating_mul(s)
            .saturating_mul(s)
            .saturating_add(s.saturating_mul(s).saturating_mul(3))
            .saturating_add(s.saturating_mul(4))
            .saturating_add(2);
        Self(
            n.saturating_mul(n)
                .saturating_mul(9)
                .saturating_add(s.saturating_mul(s))
                .saturating_add(s)
                .saturating_add(n.saturating_mul(per_node).saturating_mul(2)),
        )
    }

    /// [`Self::sufficient`] for every node and demand segment of `graph`.
    pub fn for_graph(graph: &RequestGraph) -> Self {
        let segments = graph
            .nodes()
            .iter()
            .map(|spec| spec.demand().segments().len())
            .sum();
        Self::sufficient(graph.len(), segments)
    }

    /// The bound, in work units.
    pub const fn max_units(self) -> u64 {
        self.0
    }
}

/// Schedules every node of `graph` within `bound` work units.
pub fn schedule(
    graph: &RequestGraph,
    capacities: &Capacities,
    bound: WorkBound,
) -> Result<EvaluatedSchedule, ScheduleError> {
    let problem = Problem::new(graph, &vec![true; graph.len()], capacities)?;
    run(&problem, bound)
}

pub(crate) fn run(
    problem: &Problem<'_>,
    bound: WorkBound,
) -> Result<EvaluatedSchedule, ScheduleError> {
    let mut work = Work::new(bound.max_units());
    let critical = critical_path_order(problem, &mut work)?;
    let conflicts = match place(problem, &critical, &mut work) {
        Err(ScheduleError::NoFeasiblePlacement { .. }) => {
            let pressure = memory_pressure_order(problem, &critical, &mut work)?;
            place(problem, &pressure, &mut work)?
        }
        other => other?,
    };
    EvaluatedSchedule::from_problem(problem, &conflicts, work.spent)
}

/// Places every node, taking among available nodes the one earliest in `priority`
/// (each node's position in the rule's order), and returns the conflict edges added.
fn place(
    problem: &Problem<'_>,
    priority: &[usize],
    work: &mut Work,
) -> Result<Vec<(usize, usize)>, ScheduleError> {
    let count = problem.len();
    let mut start: Vec<Option<u64>> = vec![None; count];
    let mut finish = vec![0u64; count];
    let mut waiting: Vec<usize> = problem.predecessors.iter().map(Vec::len).collect();
    let mut conflicts = Vec::new();
    for _ in 0..count {
        work.charge(count)?;
        let node = (0..count)
            .filter(|&v| start[v].is_none() && waiting[v] == 0)
            .min_by_key(|&v| priority[v])
            .ok_or(ScheduleError::NoFeasibleSchedule)?;
        let earliest = problem.predecessors[node]
            .iter()
            .map(|&p| finish[p])
            .max()
            .unwrap_or(0);
        let mut candidates = vec![earliest];
        for &resource in &problem.uses[node] {
            work.charge(problem.users[resource].len())?;
            candidates.extend(
                problem.users[resource]
                    .iter()
                    .filter(|&&other| start[other].is_some() && finish[other] > earliest)
                    .map(|&other| finish[other]),
            );
        }
        candidates.sort_unstable();
        candidates.dedup();
        work.charge(candidates.len())?;
        let mut chosen = None;
        for &at in &candidates {
            work.charge(1)?;
            if problem.fits(&start, node, at, work)? {
                chosen = Some(at);
                break;
            }
        }
        let at = chosen.ok_or_else(|| ScheduleError::NoFeasiblePlacement {
            node: problem.id(node).clone(),
        })?;
        if at > earliest {
            work.charge(count)?;
            let blocker = (0..count)
                .find(|&other| {
                    start[other].is_some() && finish[other] == at && problem.contends(other, node)
                })
                .ok_or_else(|| ScheduleError::NoFeasiblePlacement {
                    node: problem.id(node).clone(),
                })?;
            conflicts.push((blocker, node));
        }
        start[node] = Some(at);
        finish[node] = add(at, problem.expected[node])?;
        for &successor in &problem.successors[node] {
            waiting[successor] = waiting[successor].saturating_sub(1);
        }
    }
    Ok(conflicts)
}

/// Each node's position when sorted by `key`, ascending.
fn positions<K: Ord>(count: usize, key: impl Fn(usize) -> K) -> Vec<usize> {
    let mut sorted: Vec<usize> = (0..count).collect();
    sorted.sort_by_key(|&node| key(node));
    let mut position = vec![0; count];
    for (at, &node) in sorted.iter().enumerate() {
        position[node] = at;
    }
    position
}

/// The critical-path rule: first-token path first, then the longest remaining path
/// through successors on the same side of that path, then topological order.
fn critical_path_order(
    problem: &Problem<'_>,
    work: &mut Work,
) -> Result<Vec<usize>, ScheduleError> {
    let count = problem.len();
    work.charge(count.saturating_mul(count).saturating_mul(2))?;
    let mut tail = vec![0u64; count];
    for &node in problem.order.iter().rev() {
        let after = problem.successors[node]
            .iter()
            .filter(|&&successor| problem.on_path[successor] == problem.on_path[node])
            .map(|&successor| tail[successor])
            .max()
            .unwrap_or(0);
        tail[node] = add(problem.expected[node], after)?;
    }
    Ok(positions(count, |node| {
        (
            Reverse(problem.on_path[node]),
            Reverse(tail[node]),
            problem.rank[node],
        )
    }))
}

/// The memory-pressure rule. A node's pressure is the largest transient share of any
/// capacity demanded by the node or anything that depends on it, so the chain leading to
/// a large transient demand goes before holders that would leave it no room. Highest
/// pressure first, then the least memory held until the request ends (as a share of
/// capacity), then the critical-path order.
fn memory_pressure_order(
    problem: &Problem<'_>,
    critical: &[usize],
    work: &mut Work,
) -> Result<Vec<usize>, ScheduleError> {
    let count = problem.len();
    let mut held = vec![0u64; count];
    let mut transient = vec![0u64; count];
    for node in 0..count {
        let segments = &problem.segments[node];
        work.charge(
            segments
                .len()
                .saturating_mul(segments.len().saturating_add(1)),
        )?;
        for &resource in &problem.uses[node] {
            let capacity = problem.capacities[resource];
            let on = || segments.iter().filter(move |s| s.resource == resource);
            let held_quantity = on()
                .filter(|s| s.until == FOREVER)
                .fold(0u64, |sum, s| sum.saturating_add(s.quantity));
            let peak = on()
                .filter(|s| s.until != FOREVER)
                .map(|probe| {
                    on().filter(|s| {
                        s.until != FOREVER && s.from <= probe.from && probe.from < s.until
                    })
                    .fold(0u64, |sum, s| sum.saturating_add(s.quantity))
                })
                .max()
                .unwrap_or(0);
            held[node] = held[node].max(share_ppm(held_quantity, capacity));
            transient[node] = transient[node].max(share_ppm(peak, capacity));
        }
    }
    work.charge(count.saturating_mul(count).saturating_mul(3))?;
    let mut pressure = transient;
    for &node in problem.order.iter().rev() {
        for &successor in &problem.successors[node] {
            pressure[node] = pressure[node].max(pressure[successor]);
        }
    }
    Ok(positions(count, |node| {
        (Reverse(pressure[node]), held[node], critical[node])
    }))
}

/// `quantity` in parts per million of `capacity`.
fn share_ppm(quantity: u64, capacity: u64) -> u64 {
    let ppm = u128::from(quantity) * 1_000_000 / u128::from(capacity.max(1));
    u64::try_from(ppm).unwrap_or(u64::MAX)
}
