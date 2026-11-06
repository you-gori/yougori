//! The exhaustive optimal schedule of a tiny trace (GPU-W06, line 1245: "Build tiny
//! offline optimal schedules"; §4.14's first prototype, line 1006: "tiny exhaustive
//! optimal solutions").
//!
//! The optimum knows the whole trace and plays by the replay's rules
//! ([`super::replay`]): the same arrivals, capacity, prerequisite closure and shared
//! bytes counted once; one loader serving demand loads in arrival order; preparation only
//! between the loader becoming free and the end of the next request's declared gap,
//! within the gap's prepared-byte budget, each prepared object's prerequisites resident
//! or prepared first; a demand load only of what the request needs; eviction at any time
//! for free (every catalog object drops clean). It chooses, for every request, which
//! objects to keep, which to prepare in the gap before it and which to load on demand,
//! minimizing the total wait.
//!
//! The search is dynamic programming over the resident set after each request and the
//! time the loader becomes free, keeping for each set only the schedules no other
//! schedule beats on both total wait and loader time (an earlier free loader never
//! lengthens a later wait or shortens a later gap). An online policy's run maps to one of
//! the schedules it searches at no lower cost: keep what the policy holds after each
//! request, prepare what the policy prepared and still holds at the next arrival, and
//! load the rest on demand, which is at most what the policy loaded. Its total wait is
//! therefore a lower bound for every policy of the replay on the same trace and budget.

use std::collections::BTreeMap;

use super::replay::{wait_percentile, EvaluationLabel, ReplayBudget};
use super::traces::{ArrivalMode, ReplayTrace, TraceKind};
use super::PredictionError;

/// The most objects any exhaustive search accepts: sets are bit masks.
pub const MAX_EXHAUSTIVE_OBJECTS: usize = 12;

/// How large a trace the exhaustive search takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExhaustiveBounds {
    /// At most [`MAX_EXHAUSTIVE_OBJECTS`].
    pub max_objects: usize,
    pub max_requests: usize,
    /// Schedules held over every request, at most.
    pub max_states: usize,
}

impl ExhaustiveBounds {
    /// The bounds of the evaluation's tiny traces.
    pub const TINY: Self = Self {
        max_objects: 8,
        max_requests: 16,
        max_states: 200_000,
    };
}

/// The optimal schedule of one tiny trace.
#[derive(Clone, Debug, PartialEq)]
pub struct OptimalSchedule {
    pub label: EvaluationLabel,
    pub kind: TraceKind,
    pub seed: u64,
    pub budget: ReplayBudget,
    pub total_wait_nanos: u64,
    /// Each request's wait on the optimal schedule, in trace order.
    pub waits: Vec<u64>,
    /// Requests served without a demand load.
    pub hits: u64,
    pub demand_load_nanos: u64,
    pub prepared_bytes: u64,
    /// Objects prepared in the gap before each request.
    pub prepared_before: Vec<Vec<String>>,
    /// Objects resident after each request is served.
    pub resident_after: Vec<Vec<String>>,
    /// Schedules the search held over every request.
    pub states: usize,
}

impl OptimalSchedule {
    /// The nearest-rank percentile of the optimal schedule's waits.
    pub fn wait_percentile(
        &self,
        quantile: crate::foundation::report::Quantile,
    ) -> Result<f64, PredictionError> {
        wait_percentile(&self.waits, quantile)
    }
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    /// Bit masks over the catalog's objects.
    set: usize,
    finish: u64,
    cost: u64,
    parent: usize,
    wait: u64,
    prepared: usize,
    demand: usize,
}

fn members(mask: usize, n: usize) -> impl Iterator<Item = usize> {
    (0..n).filter(move |bit| mask & (1usize << bit) != 0)
}

fn nanos(duration: std::time::Duration) -> Result<u64, PredictionError> {
    u64::try_from(duration.as_nanos()).map_err(|_| PredictionError::Overflow {
        field: "replay time",
    })
}

/// The optimal schedule of `trace` (see the module documentation). Refuses a trace
/// beyond `bounds` and stops when the search holds more than `bounds.max_states`.
pub fn optimal_schedule(
    trace: &ReplayTrace,
    bounds: ExhaustiveBounds,
) -> Result<OptimalSchedule, PredictionError> {
    trace.check()?;
    let n = trace.catalog.len();
    let max_objects = bounds.max_objects.min(MAX_EXHAUSTIVE_OBJECTS);
    if n > max_objects || trace.requests.len() > bounds.max_requests {
        return Err(PredictionError::TooLargeForExhaustive {
            objects: n,
            requests: trace.requests.len(),
            max_objects,
            max_requests: bounds.max_requests,
        });
    }
    let index: BTreeMap<&str, usize> = trace
        .catalog
        .iter()
        .enumerate()
        .map(|(at, object)| (object.key.as_str(), at))
        .collect();
    let mask_of = |keys: &[String]| -> Result<usize, PredictionError> {
        keys.iter().try_fold(0usize, |mask, key| {
            index
                .get(key.as_str())
                .map(|at| mask | (1usize << at))
                .ok_or_else(|| PredictionError::UnknownObject { key: key.clone() })
        })
    };
    let mut prerequisites = Vec::with_capacity(n);
    for object in &trace.catalog {
        prerequisites.push(mask_of(&object.prerequisites)?);
    }
    let sets = 1usize << n;
    let mut set_bytes = vec![0u64; sets];
    let mut set_load = vec![0u64; sets];
    for mask in 1..sets {
        let Some(lowest) = members(mask, n).next() else {
            continue;
        };
        let rest = mask & (mask - 1);
        let object = &trace.catalog[lowest];
        set_bytes[mask] = set_bytes[rest]
            .checked_add(object.bytes)
            .ok_or(PredictionError::Overflow { field: "bytes" })?;
        set_load[mask] = set_load[rest]
            .checked_add(object.load_nanos)
            .ok_or(PredictionError::Overflow { field: "load time" })?;
    }
    let closed_within =
        |inner: usize, outer: usize| members(inner, n).all(|at| prerequisites[at] & !outer == 0);
    let feasible: Vec<usize> = (0..sets)
        .filter(|mask| {
            closed_within(*mask, *mask) && set_bytes[*mask] <= trace.budget.capacity_bytes
        })
        .collect();
    let load = |mask: usize| set_load[mask];
    let bytes = |mask: usize| set_bytes[mask];

    let mut layers: Vec<Vec<Entry>> = Vec::with_capacity(trace.requests.len());
    let mut previous = vec![Entry {
        set: 0,
        finish: 0,
        cost: 0,
        parent: usize::MAX,
        wait: 0,
        prepared: 0,
        demand: 0,
    }];
    let mut states = 0usize;
    let mut open_arrival = 0u64;
    let overflow = || PredictionError::Overflow {
        field: "replay time",
    };
    for (index, request) in trace.requests.iter().enumerate() {
        let need = mask_of(&trace.closure(&request.target)?)?;
        let gap = nanos(request.gap)?;
        let declared_gap = nanos(request.declared_gap)?;
        let previous_open_arrival = open_arrival;
        open_arrival = open_arrival.checked_add(gap).ok_or_else(overflow)?;
        let mut next: BTreeMap<usize, Vec<Entry>> = BTreeMap::new();
        for (parent, entry) in previous.iter().enumerate() {
            // The replay's clock: the gap runs from the previous arrival (open) or
            // readiness (closed), and preparation must end by its declared part.
            let (arrival, gap_start) = match trace.arrivals {
                ArrivalMode::Open => (open_arrival, previous_open_arrival),
                ArrivalMode::Closed => (
                    entry.finish.checked_add(gap).ok_or_else(overflow)?,
                    entry.finish,
                ),
            };
            let window_end = gap_start.checked_add(declared_gap).ok_or_else(overflow)?;
            let window = if index == 0 {
                0
            } else {
                window_end.saturating_sub(entry.finish)
            };
            let start = arrival.max(entry.finish);
            for &set in &feasible {
                if need & !set != 0 {
                    continue;
                }
                let new = set & !entry.set;
                let forced = new & !need;
                let optional = new & need;
                if forced != 0 && window == 0 {
                    continue;
                }
                let retained = entry.set & set;
                let mut best: Option<usize> = None;
                let mut chosen = optional;
                loop {
                    let prepared = forced | chosen;
                    let valid = load(prepared) <= window
                        && bytes(prepared) <= trace.budget.max_prepared_bytes_per_gap
                        && closed_within(prepared, retained | prepared);
                    if valid {
                        let demand = optional & !chosen;
                        if best.is_none_or(|current| load(demand) < load(current)) {
                            best = Some(demand);
                        }
                    }
                    if chosen == 0 {
                        break;
                    }
                    chosen = (chosen - 1) & optional;
                }
                let Some(demand) = best else {
                    continue;
                };
                let wait = start - arrival + load(demand);
                let candidate = Entry {
                    set,
                    finish: start.checked_add(load(demand)).ok_or_else(overflow)?,
                    cost: entry
                        .cost
                        .checked_add(wait)
                        .ok_or(PredictionError::Overflow {
                            field: "total wait",
                        })?,
                    parent,
                    wait,
                    prepared: new & !demand,
                    demand,
                };
                let front = next.entry(set).or_default();
                if front
                    .iter()
                    .any(|kept| kept.cost <= candidate.cost && kept.finish <= candidate.finish)
                {
                    continue;
                }
                front.retain(|kept| {
                    !(kept.cost >= candidate.cost && kept.finish >= candidate.finish)
                });
                front.push(candidate);
            }
        }
        let layer: Vec<Entry> = next.into_values().flatten().collect();
        states = states.saturating_add(layer.len());
        if states > bounds.max_states {
            return Err(PredictionError::SearchBoundExceeded {
                states,
                max_states: bounds.max_states,
            });
        }
        if layer.is_empty() {
            return Err(PredictionError::InvalidConfig {
                field: "trace",
                reason: "no schedule serves a request",
            });
        }
        layers.push(layer.clone());
        previous = layer;
    }
    let names = |mask: usize| -> Vec<String> {
        members(mask, n)
            .map(|at| trace.catalog[at].key.clone())
            .collect()
    };
    let mut path = Vec::with_capacity(layers.len());
    let mut at = layers
        .last()
        .and_then(|last| {
            last.iter()
                .enumerate()
                .min_by(|(_, a), (_, b)| {
                    a.cost
                        .cmp(&b.cost)
                        .then(a.finish.cmp(&b.finish))
                        .then(a.set.cmp(&b.set))
                })
                .map(|(at, _)| at)
        })
        .unwrap_or(0);
    for layer in layers.iter().rev() {
        let entry = layer
            .get(at)
            .copied()
            .ok_or(PredictionError::InvalidConfig {
                field: "trace",
                reason: "the optimal schedule lost its path",
            })?;
        path.push(entry);
        at = entry.parent;
    }
    path.reverse();
    let mut schedule = OptimalSchedule {
        label: EvaluationLabel::OfflineSyntheticTraces,
        kind: trace.kind,
        seed: trace.seed,
        budget: trace.budget,
        total_wait_nanos: path.last().map_or(0, |entry| entry.cost),
        waits: path.iter().map(|entry| entry.wait).collect(),
        hits: 0,
        demand_load_nanos: 0,
        prepared_bytes: 0,
        prepared_before: Vec::with_capacity(path.len()),
        resident_after: Vec::with_capacity(path.len()),
        states,
    };
    for entry in &path {
        if entry.demand == 0 {
            schedule.hits += 1;
        }
        schedule.demand_load_nanos = schedule
            .demand_load_nanos
            .saturating_add(load(entry.demand));
        schedule.prepared_bytes = schedule
            .prepared_bytes
            .saturating_add(bytes(entry.prepared));
        schedule.prepared_before.push(names(entry.prepared));
        schedule.resident_after.push(names(entry.set));
    }
    Ok(schedule)
}
