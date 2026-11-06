//! The exhaustive offline oracle for tiny graphs (GPU §2.3: "a time-indexed ILP or
//! exhaustive search is an offline oracle for tiny traces, not a solver on every
//! request"), and its comparison with the heuristic on reduced workloads.
//!
//! In a schedule every node starts either when its dependencies are ready or when a
//! contending node it waits for finishes. Listing a schedule's nodes by (start,
//! topological rank) therefore places each node at one of those candidate times after
//! the nodes before it, so a depth-first search over that canonical listing, trying every
//! available node at every feasible candidate time, visits every schedule. A branch is
//! cut only when a lower bound shows it cannot beat the best schedule found, so the
//! result is optimal: the earliest first token, then the earliest makespan.

use std::time::Duration;

use super::dag::RequestGraph;
use super::heuristic::{self, WorkBound};
use super::problem::{add, Problem, Work};
use super::schedule::{Capacities, EvaluatedSchedule};
use super::ScheduleError;

/// The largest graph the oracle accepts (GPU §2.3: tiny traces only).
pub const ORACLE_MAX_NODES: usize = 10;

/// The optimal schedule of every node in `graph`, searching at most `max_steps` work
/// units.
pub fn oracle(
    graph: &RequestGraph,
    capacities: &Capacities,
    max_steps: u64,
) -> Result<EvaluatedSchedule, ScheduleError> {
    let problem = Problem::new(graph, &vec![true; graph.len()], capacities)?;
    run(&problem, max_steps)
}

pub(crate) fn run(
    problem: &Problem<'_>,
    max_steps: u64,
) -> Result<EvaluatedSchedule, ScheduleError> {
    if problem.len() > ORACLE_MAX_NODES {
        return Err(ScheduleError::TooLargeForOracle {
            nodes: problem.len(),
            max: ORACLE_MAX_NODES,
        });
    }
    let count = problem.len();
    let mut search = Search {
        problem,
        work: Work::new(max_steps),
        start: vec![None; count],
        finish: vec![0; count],
        blocker: vec![None; count],
        waiting: problem.predecessors.iter().map(Vec::len).collect(),
        best: None,
    };
    search.descend(0, None)?;
    let best = search.best.ok_or(ScheduleError::NoFeasibleSchedule)?;
    EvaluatedSchedule::from_problem(problem, &best.conflicts, search.work.spent)
}

struct Best {
    first_token: u64,
    makespan: u64,
    conflicts: Vec<(usize, usize)>,
}

struct Search<'p, 'g> {
    problem: &'p Problem<'g>,
    work: Work,
    start: Vec<Option<u64>>,
    finish: Vec<u64>,
    blocker: Vec<Option<usize>>,
    waiting: Vec<usize>,
    best: Option<Best>,
}

impl Search<'_, '_> {
    /// Extends a canonical listing whose last node started at `last` (start, rank).
    fn descend(&mut self, placed: usize, last: Option<(u64, usize)>) -> Result<(), ScheduleError> {
        self.work.charge(1)?;
        let problem = self.problem;
        let count = problem.len();
        if placed == count {
            let first_token = self.finish[problem.objective];
            let makespan = self.finish.iter().copied().max().unwrap_or(0);
            if self
                .best
                .as_ref()
                .is_none_or(|best| (first_token, makespan) < (best.first_token, best.makespan))
            {
                self.best = Some(Best {
                    first_token,
                    makespan,
                    conflicts: (0..count)
                        .filter_map(|node| self.blocker[node].map(|from| (from, node)))
                        .collect(),
                });
            }
            return Ok(());
        }
        if let Some(best) = &self.best {
            self.work.charge(count)?;
            let floor = last.map_or(0, |(at, _)| at);
            let bounds = problem.lower_bounds(&self.start, floor)?;
            let makespan = bounds.iter().copied().max().unwrap_or(0);
            if (bounds[problem.objective], makespan) >= (best.first_token, best.makespan) {
                return Ok(());
            }
        }
        for &node in &problem.order {
            if self.start[node].is_some() || self.waiting[node] > 0 {
                continue;
            }
            let earliest = problem.predecessors[node]
                .iter()
                .map(|&p| self.finish[p])
                .max()
                .unwrap_or(0);
            let mut candidates = vec![earliest];
            for &resource in &problem.uses[node] {
                self.work.charge(problem.users[resource].len())?;
                candidates.extend(
                    problem.users[resource]
                        .iter()
                        .filter(|&&other| {
                            self.start[other].is_some() && self.finish[other] > earliest
                        })
                        .map(|&other| self.finish[other]),
                );
            }
            candidates.sort_unstable();
            candidates.dedup();
            for at in candidates {
                if last.is_some_and(|previous| (at, problem.rank[node]) <= previous) {
                    continue;
                }
                if !problem.fits(&self.start, node, at, &mut self.work)? {
                    continue;
                }
                let blocker = if at > earliest {
                    (0..count).find(|&other| {
                        self.start[other].is_some()
                            && self.finish[other] == at
                            && problem.contends(other, node)
                    })
                } else {
                    None
                };
                self.start[node] = Some(at);
                self.finish[node] = add(at, problem.expected[node])?;
                self.blocker[node] = blocker;
                for &successor in &problem.successors[node] {
                    self.waiting[successor] = self.waiting[successor].saturating_sub(1);
                }
                let outcome = self.descend(placed + 1, Some((at, problem.rank[node])));
                for &successor in &problem.successors[node] {
                    self.waiting[successor] += 1;
                }
                self.start[node] = None;
                self.finish[node] = 0;
                self.blocker[node] = None;
                outcome?;
            }
        }
        Ok(())
    }
}

/// The heuristic against the oracle on one graph (GPU §2.3: "compare the heuristic with
/// this oracle on reduced workloads").
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Comparison {
    /// `None` when the heuristic found no feasible start for some node.
    pub heuristic_first_token: Option<Duration>,
    pub oracle_first_token: Duration,
}

impl Comparison {
    /// Heuristic first token over oracle first token: 1.0 or more, `None` when the
    /// heuristic found no schedule.
    pub fn ratio(&self) -> Option<f64> {
        self.heuristic_first_token
            .map(|heuristic| heuristic.as_secs_f64() / self.oracle_first_token.as_secs_f64())
    }
}

/// Runs both on `graph`. Fails when the oracle finds no schedule or either search runs out
/// of work units.
pub fn compare(
    graph: &RequestGraph,
    capacities: &Capacities,
    heuristic_bound: WorkBound,
    oracle_steps: u64,
) -> Result<Comparison, ScheduleError> {
    let problem = Problem::new(graph, &vec![true; graph.len()], capacities)?;
    let oracle_first_token = run(&problem, oracle_steps)?.first_token();
    let heuristic_first_token = match heuristic::run(&problem, heuristic_bound) {
        Ok(schedule) => Some(schedule.first_token()),
        Err(ScheduleError::NoFeasiblePlacement { .. }) => None,
        Err(other) => return Err(other),
    };
    Ok(Comparison {
        heuristic_first_token,
        oracle_first_token,
    })
}
