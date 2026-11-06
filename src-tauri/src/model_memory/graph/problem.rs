//! The scheduled part of a request graph in the form that the evaluator, the heuristic
//! and the oracle share: nanosecond durations, demand segments resolved against the
//! declared capacities, and the contention relation between nodes.

use std::time::Duration;

use super::dag::{topological_order, RequestGraph};
use super::node::SegmentEnd;
use super::schedule::Capacities;
use super::{NodeId, ResourceId, ScheduleError};

/// The end of a segment held until the request ends: later than every finite time.
pub(crate) const FOREVER: u64 = u64::MAX;

pub(crate) fn nanos(duration: Duration) -> Result<u64, ScheduleError> {
    u64::try_from(duration.as_nanos()).map_err(|_| ScheduleError::TimeOverflow)
}

pub(crate) fn add(left: u64, right: u64) -> Result<u64, ScheduleError> {
    left.checked_add(right).ok_or(ScheduleError::TimeOverflow)
}

/// One demand segment with times in nanoseconds from the node's start.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Segment {
    pub(crate) resource: usize,
    pub(crate) quantity: u64,
    pub(crate) from: u64,
    pub(crate) until: u64,
}

impl Segment {
    /// The segment's absolute interval for a node starting at `start`.
    fn placed(&self, start: u64) -> Result<(u64, u64), ScheduleError> {
        let until = if self.until == FOREVER {
            FOREVER
        } else {
            add(start, self.until)?
        };
        Ok((add(start, self.from)?, until))
    }
}

/// Counts work units against an explicit bound.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Work {
    pub(crate) spent: u64,
    pub(crate) bound: u64,
}

impl Work {
    pub(crate) fn new(bound: u64) -> Self {
        Self { spent: 0, bound }
    }

    pub(crate) fn charge(&mut self, units: usize) -> Result<(), ScheduleError> {
        let units = u64::try_from(units).unwrap_or(u64::MAX);
        self.spent = self.spent.saturating_add(units);
        if self.spent > self.bound {
            return Err(ScheduleError::WorkBoundExceeded { bound: self.bound });
        }
        Ok(())
    }
}

/// Finish times of one fixed schedule, in nanoseconds, by local index.
#[derive(Clone, Debug)]
pub(crate) struct Timing {
    pub(crate) start: Vec<u64>,
    pub(crate) finish: Vec<u64>,
    pub(crate) finish_low: Vec<u64>,
    pub(crate) finish_high: Vec<u64>,
}

/// The nodes to schedule, with local indices in graph order.
pub(crate) struct Problem<'g> {
    pub(crate) graph: &'g RequestGraph,
    pub(crate) members: Vec<usize>,
    pub(crate) low: Vec<u64>,
    pub(crate) expected: Vec<u64>,
    pub(crate) high: Vec<u64>,
    pub(crate) predecessors: Vec<Vec<usize>>,
    pub(crate) successors: Vec<Vec<usize>>,
    pub(crate) segments: Vec<Vec<Segment>>,
    pub(crate) resources: Vec<ResourceId>,
    pub(crate) capacities: Vec<u64>,
    /// Distinct resources each node demands, ascending.
    pub(crate) uses: Vec<Vec<usize>>,
    /// Nodes demanding each resource, ascending.
    pub(crate) users: Vec<Vec<usize>>,
    pub(crate) order: Vec<usize>,
    pub(crate) rank: Vec<usize>,
    pub(crate) objective: usize,
    pub(crate) on_path: Vec<bool>,
}

impl<'g> Problem<'g> {
    /// The nodes marked in `scheduled`; the others are ready and count as finished at
    /// time zero for their consumers.
    pub(crate) fn new(
        graph: &'g RequestGraph,
        scheduled: &[bool],
        capacities: &Capacities,
    ) -> Result<Self, ScheduleError> {
        let members: Vec<usize> = (0..graph.len())
            .filter(|&at| scheduled.get(at).copied().unwrap_or(false))
            .collect();
        let mut local = vec![None; graph.len()];
        for (position, &at) in members.iter().enumerate() {
            local[at] = Some(position);
        }
        let objective =
            local[graph.objective_index()].ok_or(ScheduleError::ObjectiveNotScheduled)?;

        let resources: Vec<ResourceId> = capacities.iter().map(|(id, _, _)| id.clone()).collect();
        let limits: Vec<u64> = capacities.iter().map(|(_, _, capacity)| capacity).collect();
        let count = members.len();
        let mut problem = Self {
            graph,
            low: Vec::with_capacity(count),
            expected: Vec::with_capacity(count),
            high: Vec::with_capacity(count),
            predecessors: vec![Vec::new(); count],
            successors: vec![Vec::new(); count],
            segments: vec![Vec::new(); count],
            uses: vec![Vec::new(); count],
            users: vec![Vec::new(); resources.len()],
            order: Vec::with_capacity(count),
            rank: vec![0; count],
            on_path: members.iter().map(|&at| graph.on_path_index(at)).collect(),
            members,
            resources,
            capacities: limits,
            objective,
        };
        let mut retained = vec![0u64; problem.resources.len()];
        for position in 0..count {
            let spec = graph.spec(problem.members[position]);
            problem.low.push(nanos(spec.duration().low())?);
            problem.expected.push(nanos(spec.duration().expected())?);
            problem.high.push(nanos(spec.duration().high())?);
            for &p in graph.predecessor_indices(problem.members[position]) {
                if let Some(from) = local[p] {
                    problem.predecessors[position].push(from);
                    problem.successors[from].push(position);
                }
            }
            for segment in spec.demand().segments() {
                let (resource, unit, capacity) =
                    capacities.lookup(segment.resource()).ok_or_else(|| {
                        ScheduleError::UnknownResource {
                            node: spec.id().clone(),
                            resource: segment.resource().clone(),
                        }
                    })?;
                if unit != segment.unit() {
                    return Err(ScheduleError::UnitMismatch {
                        node: spec.id().clone(),
                        resource: segment.resource().clone(),
                        declared: unit,
                        demanded: segment.unit(),
                    });
                }
                let peak = spec.demand().peak(segment.resource()).ok_or_else(|| {
                    ScheduleError::QuantityOverflow {
                        resource: segment.resource().clone(),
                    }
                })?;
                if peak > capacity {
                    return Err(ScheduleError::NodeExceedsCapacity {
                        node: spec.id().clone(),
                        resource: segment.resource().clone(),
                        demand: peak,
                        capacity,
                    });
                }
                let until = match segment.end() {
                    SegmentEnd::AfterStart(until) => nanos(until)?,
                    SegmentEnd::RequestEnd => {
                        retained[resource] = retained[resource]
                            .checked_add(segment.quantity())
                            .ok_or_else(|| ScheduleError::QuantityOverflow {
                                resource: segment.resource().clone(),
                            })?;
                        FOREVER
                    }
                };
                problem.segments[position].push(Segment {
                    resource,
                    quantity: segment.quantity(),
                    from: nanos(segment.from())?,
                    until,
                });
                if !problem.uses[position].contains(&resource) {
                    problem.uses[position].push(resource);
                    problem.users[resource].push(position);
                }
            }
            problem.uses[position].sort_unstable();
        }
        for (resource, &held) in retained.iter().enumerate() {
            if held > problem.capacities[resource] {
                return Err(ScheduleError::RetainedDemandExceedsCapacity {
                    resource: problem.resources[resource].clone(),
                    demand: held,
                    capacity: problem.capacities[resource],
                });
            }
        }
        problem.order = graph
            .order_indices()
            .iter()
            .filter_map(|&at| local[at])
            .collect();
        for (position, &node) in problem.order.iter().enumerate() {
            problem.rank[node] = position;
        }
        Ok(problem)
    }

    pub(crate) fn len(&self) -> usize {
        self.members.len()
    }

    pub(crate) fn id(&self, node: usize) -> &NodeId {
        self.graph.spec(self.members[node]).id()
    }

    /// Whether two nodes demand a common capacity-limited resource.
    pub(crate) fn contends(&self, left: usize, right: usize) -> bool {
        let (mut i, mut j) = (0, 0);
        let (a, b) = (&self.uses[left], &self.uses[right]);
        while i < a.len() && j < b.len() {
            match a[i].cmp(&b[j]) {
                std::cmp::Ordering::Less => i += 1,
                std::cmp::Ordering::Greater => j += 1,
                std::cmp::Ordering::Equal => return true,
            }
        }
        false
    }

    /// The finish recurrence over the dependencies plus `conflicts`:
    /// finish(v) = duration(v) + max(finish(u) for u in predecessors(v)), with an empty
    /// max of zero, evaluated at the low, expected and high durations (GPU §2.3).
    pub(crate) fn timing(&self, conflicts: &[(usize, usize)]) -> Result<Timing, ScheduleError> {
        let mut predecessors = self.predecessors.clone();
        let mut successors = self.successors.clone();
        for &(from, to) in conflicts {
            if !self.contends(from, to) {
                return Err(ScheduleError::NotAConflict {
                    from: self.id(from).clone(),
                    to: self.id(to).clone(),
                });
            }
            predecessors[to].push(from);
            successors[from].push(to);
        }
        let order = topological_order(&predecessors, &successors).map_err(|cycle| {
            ScheduleError::ConflictEdgeCycle {
                nodes: cycle.iter().map(|&node| self.id(node).clone()).collect(),
            }
        })?;
        let count = self.len();
        let mut timing = Timing {
            start: vec![0; count],
            finish: vec![0; count],
            finish_low: vec![0; count],
            finish_high: vec![0; count],
        };
        for &node in &order {
            let ready = |finish: &[u64]| {
                predecessors[node]
                    .iter()
                    .map(|&p| finish[p])
                    .max()
                    .unwrap_or(0)
            };
            timing.start[node] = ready(&timing.finish);
            timing.finish[node] = add(timing.start[node], self.expected[node])?;
            timing.finish_low[node] = add(ready(&timing.finish_low), self.low[node])?;
            timing.finish_high[node] = add(ready(&timing.finish_high), self.high[node])?;
        }
        Ok(timing)
    }

    /// Sweeps every resource at the given starts and refuses the first instant where the
    /// total demand exceeds the capacity.
    pub(crate) fn check_capacity(&self, start: &[u64]) -> Result<(), ScheduleError> {
        for (resource, users) in self.users.iter().enumerate() {
            let mut events: Vec<(u64, bool, u64)> = Vec::new();
            for &node in users {
                for segment in self.segments[node]
                    .iter()
                    .filter(|s| s.resource == resource)
                {
                    let (from, until) = segment.placed(start[node])?;
                    events.push((from, true, segment.quantity));
                    events.push((until, false, segment.quantity));
                }
            }
            // Releases sort before acquisitions at the same instant: intervals are half-open.
            events.sort_unstable();
            let mut total = 0u64;
            for (at, acquire, quantity) in events {
                if !acquire {
                    total = total.saturating_sub(quantity);
                    continue;
                }
                total =
                    total
                        .checked_add(quantity)
                        .ok_or_else(|| ScheduleError::QuantityOverflow {
                            resource: self.resources[resource].clone(),
                        })?;
                if total > self.capacities[resource] {
                    return Err(ScheduleError::CapacityExceeded {
                        resource: self.resources[resource].clone(),
                        at: Duration::from_nanos(at),
                        demand: total,
                        capacity: self.capacities[resource],
                    });
                }
            }
        }
        Ok(())
    }

    /// Whether `node` starting at `at` keeps every resource within capacity, given the
    /// nodes already placed in `start`.
    pub(crate) fn fits(
        &self,
        start: &[Option<u64>],
        node: usize,
        at: u64,
        work: &mut Work,
    ) -> Result<bool, ScheduleError> {
        for &resource in &self.uses[node] {
            let mut placed: Vec<(u64, u64, u64)> = Vec::new();
            for &other in &self.users[resource] {
                work.charge(1)?;
                let Some(other_start) = start[other].filter(|_| other != node) else {
                    continue;
                };
                work.charge(self.segments[other].len())?;
                for segment in self.segments[other]
                    .iter()
                    .filter(|s| s.resource == resource)
                {
                    let (from, until) = segment.placed(other_start)?;
                    placed.push((from, until, segment.quantity));
                }
            }
            let mut own: Vec<(u64, u64, u64)> = Vec::new();
            for segment in self.segments[node]
                .iter()
                .filter(|s| s.resource == resource)
            {
                let (from, until) = segment.placed(at)?;
                own.push((from, until, segment.quantity));
            }
            for &(from, until, _) in &own {
                let mut points = vec![from];
                points.extend(
                    placed
                        .iter()
                        .chain(own.iter())
                        .map(|&(other_from, _, _)| other_from)
                        .filter(|&other_from| from < other_from && other_from < until),
                );
                for point in points {
                    work.charge(placed.len() + own.len())?;
                    let mut total = 0u64;
                    for &(a, b, quantity) in placed.iter().chain(own.iter()) {
                        if a <= point && point < b {
                            total = total.checked_add(quantity).ok_or_else(|| {
                                ScheduleError::QuantityOverflow {
                                    resource: self.resources[resource].clone(),
                                }
                            })?;
                        }
                    }
                    if total > self.capacities[resource] {
                        return Ok(false);
                    }
                }
            }
        }
        Ok(true)
    }

    /// Lower bounds on every finish when no node starts before `floor`, given the nodes
    /// already placed: the recurrence with unplaced durations at their expected values.
    pub(crate) fn lower_bounds(
        &self,
        start: &[Option<u64>],
        floor: u64,
    ) -> Result<Vec<u64>, ScheduleError> {
        let mut finish = vec![0u64; self.len()];
        for &node in &self.order {
            finish[node] = match start[node] {
                Some(at) => add(at, self.expected[node])?,
                None => {
                    let ready = self.predecessors[node]
                        .iter()
                        .map(|&p| finish[p])
                        .max()
                        .unwrap_or(0)
                        .max(floor);
                    add(ready, self.expected[node])?
                }
            };
        }
        Ok(finish)
    }
}
