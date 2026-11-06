//! GPU §1's three paths at graph level.
//!
//! 1. **Use what is ready.** A node whose exact state is advertised as ready, unexpired
//!    and in a trust scope it may consume from is skipped. Advertisements match by
//!    identity, never by name or size, and are hints with an expiry (§3.2).
//! 2. **Materialize only what is missing.** A missing node is scheduled only if the
//!    request still needs it: it is the first-token node, a sink of the graph, or a
//!    dependency of another scheduled node. Missing state needed only to produce ready
//!    state is not scheduled.
//! 3. **Overlap unavoidable work.** The scheduled nodes go to the bounded heuristic, which
//!    starts each one as early as its dependencies and the capacities allow.

use crate::foundation::ids::{Clock, Digest, MonotonicTime};

use super::dag::RequestGraph;
use super::heuristic::{self, WorkBound};
use super::problem::Problem;
use super::schedule::{Capacities, EvaluatedSchedule};
use super::{NodeId, ScheduleError, TrustScope};

/// An advertisement that some state is ready (GPU §1, path 1; §3.2): a hint with an
/// expiry, not authority to use the data, so the planner rechecks identity, trust scope
/// and expiry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadyState {
    identity: Digest,
    trust_scope: TrustScope,
    expires_at: MonotonicTime,
}

impl ReadyState {
    /// An advertisement of state with `identity` in `trust_scope`, void from `expires_at`.
    pub fn new(identity: Digest, trust_scope: TrustScope, expires_at: MonotonicTime) -> Self {
        Self {
            identity,
            trust_scope,
            expires_at,
        }
    }

    /// The identity of the advertised state; the only thing matched against nodes.
    pub const fn identity(&self) -> &Digest {
        &self.identity
    }

    /// The trust scope the advertised state lives in.
    pub fn trust_scope(&self) -> &TrustScope {
        &self.trust_scope
    }

    /// The advertisement is void at and after this time.
    pub const fn expires_at(&self) -> MonotonicTime {
        self.expires_at
    }
}

/// Why an advertisement with a node's identity did not satisfy it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadyRejection {
    /// The advertisement had expired when the plan was made.
    Expired,
    /// The state lives in another trust scope and no allowance names it.
    OtherTrustScope,
}

/// What the plan does with one node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Satisfied by ready state and skipped (path 1).
    Ready,
    /// Missing and needed, so scheduled (paths 2 and 3).
    Missing,
    /// Missing, but only ready state consumes it, so not scheduled (path 2).
    NotNeeded,
}

/// A request plan: what is reused, what is materialized, and when the first correct token
/// is expected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestPlan {
    planned_at: MonotonicTime,
    dispositions: Vec<(NodeId, Disposition)>,
    rejections: Vec<(NodeId, ReadyRejection)>,
    schedule: EvaluatedSchedule,
    first_token_at: MonotonicTime,
}

impl RequestPlan {
    /// The clock reading the plan's offsets start from.
    pub fn planned_at(&self) -> MonotonicTime {
        self.planned_at
    }

    /// When the first correct token is expected: `planned_at` plus the objective.
    pub fn first_token_at(&self) -> MonotonicTime {
        self.first_token_at
    }

    /// What the plan does with `node`; `None` for an unknown node.
    pub fn disposition(&self, node: &NodeId) -> Option<Disposition> {
        self.dispositions
            .iter()
            .find(|(id, _)| id == node)
            .map(|&(_, disposition)| disposition)
    }

    /// Nodes with the given disposition, in the order they were added to the graph.
    pub fn nodes_with(&self, disposition: Disposition) -> Vec<&NodeId> {
        self.dispositions
            .iter()
            .filter(|(_, d)| *d == disposition)
            .map(|(id, _)| id)
            .collect()
    }

    /// Advertisements that matched a node's identity but could not satisfy it.
    pub fn rejections(&self) -> &[(NodeId, ReadyRejection)] {
        &self.rejections
    }

    /// The schedule of the missing nodes.
    pub fn schedule(&self) -> &EvaluatedSchedule {
        &self.schedule
    }
}

/// Plans `graph` against the advertised `ready` state at `clock.now()` (GPU §1).
///
/// `capacities` are what this request may still use: ready state already holds its
/// memory outside them, as granted by the CORE-03 host admission ledger (§3.1), so it is
/// not counted twice.
///
/// Ready state never satisfies compute or response work: that work belongs to this one
/// request, and ready weights do not eliminate prompt computation (§1.1). An
/// advertisement claiming otherwise is refused.
pub fn plan(
    graph: &RequestGraph,
    ready: &[ReadyState],
    clock: &dyn Clock,
    capacities: &Capacities,
    bound: WorkBound,
) -> Result<RequestPlan, ScheduleError> {
    let now = clock.now();
    let mut is_ready = vec![false; graph.len()];
    let mut rejections = Vec::new();
    for (at, spec) in graph.nodes().iter().enumerate() {
        for state in ready
            .iter()
            .filter(|state| &state.identity == spec.identity())
        {
            if !spec.kind().can_be_ready() {
                return Err(ScheduleError::ReadyStateForRequestWork {
                    node: spec.id().clone(),
                    kind: spec.kind(),
                });
            }
            if state.expires_at <= now {
                rejections.push((spec.id().clone(), ReadyRejection::Expired));
            } else if !graph.policy().allows(
                &state.trust_scope,
                spec.trust_scope(),
                spec.identity(),
            ) {
                rejections.push((spec.id().clone(), ReadyRejection::OtherTrustScope));
            } else {
                is_ready[at] = true;
            }
        }
    }

    let mut disposition = vec![Disposition::NotNeeded; graph.len()];
    for &at in graph.order_indices().iter().rev() {
        disposition[at] = if is_ready[at] {
            Disposition::Ready
        } else if at == graph.objective_index()
            || graph.successor_indices(at).is_empty()
            || graph
                .successor_indices(at)
                .iter()
                .any(|&successor| disposition[successor] == Disposition::Missing)
        {
            Disposition::Missing
        } else {
            Disposition::NotNeeded
        };
    }

    let scheduled: Vec<bool> = disposition
        .iter()
        .map(|&d| d == Disposition::Missing)
        .collect();
    let problem = Problem::new(graph, &scheduled, capacities)?;
    let schedule = heuristic::run(&problem, bound)?;
    let first_token_at = now
        .checked_add(schedule.first_token())
        .ok_or(ScheduleError::TimeOverflow)?;
    Ok(RequestPlan {
        planned_at: now,
        dispositions: graph
            .nodes()
            .iter()
            .zip(disposition)
            .map(|(spec, d)| (spec.id().clone(), d))
            .collect(),
        rejections,
        schedule,
        first_token_at,
    })
}
