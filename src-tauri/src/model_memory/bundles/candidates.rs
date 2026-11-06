//! Latest prerequisite branches and the bounded candidate set (GPU §4.14 steps 2–3).
//!
//! From the schedule of the current selection, each request's needs are ranked by when
//! they become usable; the ones still usable after the request arrives are its blocking
//! branches. Candidates are then:
//!
//! - single objects that can be added on their own, or else dependency-closed groups: an
//!   object plus the reconstruction requirements its preparation needs, never its
//!   descendants (line 830);
//! - concurrent blockers: for each request, the closures of its `k` latest branches for
//!   `k = 1..=B`, so objects that only pay off together are offered together;
//! - shared groups: the closure of every object several requests need that lies on a
//!   critical path, becoming usable only after one of them arrives.
//!
//! One round generates at most `2n + R·B` candidates for `n` needed objects, `R` requests
//! and `B` branches ([`candidate_bound`]), so enumeration grows linearly with model and
//! request counts.

use std::collections::BTreeSet;
use std::time::Duration;

use super::evaluate::{Evaluation, WorkMeter};
use super::horizon::{Horizon, Selection};
use super::BundleError;

/// What kinds of candidates a round may generate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateMode {
    /// Singles, closures, concurrent blockers and shared groups (the bundle method).
    Bundles,
    /// Single objects only: the individual positive-gain greedy of §4.14.
    SingleObjects,
}

/// Where a candidate came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CandidateOrigin {
    /// One object that can be added on its own.
    Single { object: usize },
    /// The object and the requirements its preparation needs.
    Closure { object: usize },
    /// The `depth` latest blocking branches of one request.
    ConcurrentBlockers { request: usize, depth: usize },
    /// The closure of an object several requests need, on a critical path.
    Shared { object: usize },
}

/// A group to add to the current selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// Objects not yet selected.
    pub group: Selection,
    pub origin: CandidateOrigin,
}

/// The most candidates one round can generate (GPU §4.14 line 836: enumeration must stay
/// bounded): `2n + R·B` with groups, `n` with single objects only. Each needed object
/// yields one single or one closure, each request at most `B` blocker prefixes, and each
/// shared object one group.
pub fn candidate_bound(
    needed_objects: usize,
    requests: usize,
    max_branches: usize,
    mode: CandidateMode,
) -> u64 {
    let n = u64::try_from(needed_objects).unwrap_or(u64::MAX);
    match mode {
        CandidateMode::SingleObjects => n,
        CandidateMode::Bundles => {
            let r = u64::try_from(requests).unwrap_or(u64::MAX);
            let b = u64::try_from(max_branches).unwrap_or(u64::MAX);
            n.saturating_mul(2).saturating_add(r.saturating_mul(b))
        }
    }
}

/// Each request's blocking branches under `current`, latest first: the needs that become
/// usable after the request arrives (GPU §4.14 step 2).
pub fn blocking_branches(horizon: &Horizon, current: &Evaluation) -> Vec<Vec<(usize, Duration)>> {
    (0..horizon.request_count())
        .map(|position| {
            let arrival = horizon.request(position).arrival;
            let mut branches: Vec<(usize, Duration)> = horizon
                .needs(position)
                .iter()
                .filter_map(|&need| {
                    current
                        .object_ready
                        .get(need)
                        .copied()
                        .flatten()
                        .filter(|ready| *ready > arrival)
                        .map(|ready| (need, ready))
                })
                .collect();
            branches.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            branches
        })
        .collect()
}

/// Generates one round of candidates on top of `selection` (GPU §4.14 step 3), charging
/// one unit plus the group size for each.
pub fn generate(
    horizon: &Horizon,
    selection: &Selection,
    current: &Evaluation,
    mode: CandidateMode,
    max_branches: usize,
    meter: &mut WorkMeter,
) -> Result<Vec<Candidate>, BundleError> {
    let needed = horizon.needed_objects();
    let mut seen: BTreeSet<Selection> = BTreeSet::new();
    let mut out = Vec::new();
    let mut push = |group: Selection,
                    origin: CandidateOrigin,
                    meter: &mut WorkMeter|
     -> Result<(), BundleError> {
        meter.charge(
            u64::try_from(group.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )?;
        if !group.is_empty() && seen.insert(group.clone()) {
            out.push(Candidate { group, origin });
        }
        Ok(())
    };

    for &object in needed.iter().filter(|&&at| !selection.contains(at)) {
        let addable = horizon.object(object).resident
            || horizon
                .requirements(object)
                .iter()
                .all(|requirement| selection.contains(*requirement));
        if addable {
            push(
                Selection::from_indices([object]),
                CandidateOrigin::Single { object },
                meter,
            )?;
        } else if mode == CandidateMode::Bundles {
            push(
                horizon.closure(object, selection),
                CandidateOrigin::Closure { object },
                meter,
            )?;
        }
    }
    if mode == CandidateMode::SingleObjects {
        return Ok(out);
    }

    meter.charge(
        (0..horizon.request_count())
            .map(|position| u64::try_from(horizon.needs(position).len()).unwrap_or(u64::MAX))
            .fold(0u64, u64::saturating_add),
    )?;
    for (request, branches) in blocking_branches(horizon, current).iter().enumerate() {
        let mut group = Selection::new();
        for (depth, &(object, _)) in branches.iter().take(max_branches).enumerate() {
            group = group.union(&horizon.closure(object, selection));
            push(
                group.clone(),
                CandidateOrigin::ConcurrentBlockers {
                    request,
                    depth: depth + 1,
                },
                meter,
            )?;
        }
    }

    let on_critical_path = |at: usize| {
        let ready = current.object_ready.get(at).copied().flatten();
        horizon
            .requesters(at)
            .iter()
            .any(|&position| ready.is_some_and(|ready| ready > horizon.request(position).arrival))
    };
    for &object in needed.iter().filter(|&&at| {
        !selection.contains(at) && horizon.requesters(at).len() >= 2 && on_critical_path(at)
    }) {
        push(
            horizon.closure(object, selection),
            CandidateOrigin::Shared { object },
            meter,
        )?;
    }
    Ok(out)
}
