//! KV admission and growth (GPU-W10 line 182: "backend-supported dynamic KV growth and
//! admission limits"; acceptance: "request shape changes cannot overrun reserved
//! memory"; §2.7: reserve bounded KV growth or impose explicit limits).
//!
//! Every activation reserves its whole KV pool with its own memory, T08's KV bound. What
//! its requests may write is admitted against that pool request by request, from each
//! request's shape: its context tokens times its sequences times the model's KV bytes per
//! token. A backend whose rules say it grows its KV in increments ([`KvGrowth`]) commits
//! the pool one increment at a time, each a CORE-03 reservation carved from the
//! activation's own reservation as a child, so the ledger shows what is in use and no
//! byte is counted twice; a backend without that support holds the whole pool from the
//! start, as before. A request, or a request whose shape grows, beyond what the pool can
//! ever hold is refused; one that fits once other requests release their KV is queued; a
//! ledger refusal of an increment names the limiting resource. A lease carries the bytes
//! it was admitted for, and the runner never writes past them.
//!
//! The runner adapter declares the KV layout of its pinned backend ([`KvLayout`]); whether
//! the backend grows its pool in increments is CORE-01 `KvGrowth` evidence about the exact
//! runtime ([`super::evidenced_kv_growth`]), and without fresh evidence the pool is held
//! whole. A runner that declares no layout gets the strict bound: its pool holds one
//! request of the shape it was reserved for ([`KvSpec::bounded_by_pool`]), and it is never
//! grown.
//!
//! Requests that wait for room in the pool are served first in, first out
//! ([`super::WaitQueue`], by the request's operation): a later request is admitted only
//! from what every request waiting ahead of it leaves. Increments no lease needs any more
//! can be handed back while the generation serves, before it is reclaimed
//! ([`super::LedgerPolicyGovernor::trim_kv`]). The KV of a session that stays after its
//! lease ended, kept for a resume or because no tier could take it (T08), still needs its
//! increments: it is never trimmed until the runner dropped it
//! ([`super::ExecutionLease::keep_session`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use super::governor::CapacityRefusal;
use super::waits::{WaitDemand, WaitLimits, WaitQueue, WaitTurn, Waiter};
use crate::foundation::ids::{LeaseId, MonotonicTime, OperationId};
use crate::foundation::ledger::ReservationId;
use crate::model_memory::placement::{RequestShape, SupportedShape};

/// How many requests may wait for room in one KV pool, and how long each keeps its place.
pub const KV_WAIT_LIMITS: WaitLimits = WaitLimits::DEFAULT;

/// How a backend's KV may grow, as its rules state it: increments only where CORE-01
/// `KvGrowth` evidence shows them for the exact runtime ([`super::evidenced_kv_growth`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "growth", rename_all = "snake_case")]
pub enum KvGrowth {
    /// The backend allocates its whole KV pool when it starts.
    Fixed,
    /// The backend maps its KV pool `increment_bytes` at a time, as requests need it.
    Increments { increment_bytes: u64 },
}

/// What a runner adapter declares about a model's KV on its pinned backend: what each
/// token of each sequence takes, and how the backend fills its pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct KvLayout {
    pub bytes_per_token: u64,
    pub growth: KvGrowth,
}

/// One activation's KV: what each token of each sequence takes, the pool T08 reserved
/// with the activation, and how the backend fills it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct KvSpec {
    pub bytes_per_token: u64,
    pub pool_bytes: u64,
    pub growth: KvGrowth,
}

impl KvSpec {
    /// The pool of `pool_bytes` with the runner's declared `layout`.
    pub fn with_layout(layout: KvLayout, pool_bytes: u64) -> Self {
        Self {
            bytes_per_token: layout.bytes_per_token,
            pool_bytes,
            growth: layout.growth,
        }
    }

    /// The strict bound for a backend that declares no KV layout: the pool holds one
    /// request of `declared`, the shape it was reserved for, so each token takes the
    /// pool's share of that shape (rounded down, so that request fits), and the pool is
    /// allocated whole.
    pub fn bounded_by_pool(pool_bytes: u64, declared: &SupportedShape) -> Self {
        let tokens = declared
            .max_context_tokens
            .saturating_mul(u64::from(declared.max_batch_sequences))
            .max(1);
        Self {
            bytes_per_token: (pool_bytes / tokens).max(1),
            pool_bytes,
            growth: KvGrowth::Fixed,
        }
    }
}

/// The KV a request of `shape` writes: its context tokens for each of its sequences;
/// `None` if that does not fit in 64 bits.
pub fn kv_bytes(shape: &RequestShape, bytes_per_token: u64) -> Option<u64> {
    shape
        .context_tokens
        .checked_mul(u64::from(shape.batch_sequences))
        .and_then(|tokens| tokens.checked_mul(bytes_per_token))
}

/// Why a request's KV was not admitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kv", rename_all = "snake_case")]
pub enum KvRefusal {
    /// The request alone needs more KV than the activation's pool can ever hold: refused.
    ExceedsPool {
        requested_bytes: u64,
        pool_bytes: u64,
    },
    /// It fits the pool once other requests release theirs: it keeps its place in the
    /// pool's queue; retry then.
    AwaitingRelease {
        requested_bytes: u64,
        free_bytes: u64,
    },
    /// It fits what is free, but requests waiting ahead of it claim `claimed_bytes` of it:
    /// it keeps its place behind them (first in, first out); retry once they are served.
    QueuedBehind {
        requested_bytes: u64,
        free_bytes: u64,
        ahead: u32,
        claimed_bytes: u64,
    },
    /// It would wait, but the pool's queue already holds `waiting` requests, the most it
    /// holds.
    WaitQueueFull { waiting: u32 },
    /// The ledger refused the next increment; this names the limiting resource.
    Ledger { refusal: CapacityRefusal },
    /// The activation holds no KV pool, as a generation the governor did not activate.
    NoPool,
    /// The request's KV does not fit in 64 bits.
    Overflow,
}

impl fmt::Display for KvRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExceedsPool {
                requested_bytes,
                pool_bytes,
            } => write!(
                f,
                "the request needs {requested_bytes} bytes of KV; the model's pool holds \
                 {pool_bytes}"
            ),
            Self::AwaitingRelease {
                requested_bytes,
                free_bytes,
            } => write!(
                f,
                "the request needs {requested_bytes} bytes of KV and {free_bytes} are free; it \
                 waits until other requests release theirs"
            ),
            Self::QueuedBehind {
                requested_bytes,
                free_bytes,
                ahead,
                claimed_bytes,
            } => write!(
                f,
                "the request needs {requested_bytes} bytes of KV and {free_bytes} are free, but \
                 {ahead} requests waiting ahead of it claim {claimed_bytes}; it waits its turn"
            ),
            Self::WaitQueueFull { waiting } => write!(
                f,
                "the request would wait for KV, but {waiting} requests already wait, the most \
                 the pool's queue holds"
            ),
            Self::Ledger { refusal } => write!(f, "the KV cannot grow: {refusal}"),
            Self::NoPool => f.write_str("the generation holds no KV pool"),
            Self::Overflow => f.write_str("the request's KV does not fit in 64 bits"),
        }
    }
}

/// What admitting more KV takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum KvPlan {
    /// The committed pool has room.
    Fits,
    /// The pool must grow by these increments first.
    Grow { increments: Vec<u64> },
}

/// One activation's KV pool: the increments committed so far, each a CORE-03 reservation
/// carved from the activation's own memory, the KV each lease was admitted for, the
/// requests waiting for room, first in line first, and the increments trimmed while it
/// serves whose release is not confirmed yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct KvPool {
    spec: KvSpec,
    increments: Vec<(ReservationId, u64)>,
    leased: BTreeMap<LeaseId, u64>,
    waits: WaitQueue<OperationId>,
    releasing: Vec<(ReservationId, u64)>,
    /// The request each lease serves.
    requests: BTreeMap<LeaseId, OperationId>,
    /// Leases whose session stays with its KV once the lease ends.
    keeping: BTreeSet<LeaseId>,
    /// The KV of sessions that stayed after their lease ended, by request, until the
    /// runner dropped it.
    sessions: BTreeMap<OperationId, u64>,
}

impl KvPool {
    pub(super) fn new(spec: KvSpec) -> Self {
        Self {
            spec,
            increments: Vec::new(),
            leased: BTreeMap::new(),
            waits: WaitQueue::new(KV_WAIT_LIMITS),
            releasing: Vec::new(),
            requests: BTreeMap::new(),
            keeping: BTreeSet::new(),
            sessions: BTreeMap::new(),
        }
    }

    pub(super) fn spec(&self) -> KvSpec {
        self.spec
    }

    /// The KV the backend holds committed: the whole pool, or the increments so far.
    pub(super) fn committed_bytes(&self) -> u64 {
        match self.spec.growth {
            KvGrowth::Fixed => self.spec.pool_bytes,
            KvGrowth::Increments { .. } => self
                .increments
                .iter()
                .fold(0u64, |total, (_, bytes)| total.saturating_add(*bytes)),
        }
    }

    /// The KV admitted to leases.
    pub(super) fn leased_bytes(&self) -> u64 {
        self.leased
            .values()
            .fold(0u64, |total, bytes| total.saturating_add(*bytes))
    }

    /// The KV `lease` was admitted for.
    pub(super) fn lease_bytes(&self, lease: LeaseId) -> Option<u64> {
        self.leased.get(&lease).copied()
    }

    /// How many leases hold KV in the pool.
    pub(super) fn lease_count(&self) -> usize {
        self.leased.len()
    }

    /// The increments committed now, oldest first.
    pub(super) fn committed(&self) -> &[(ReservationId, u64)] {
        &self.increments
    }

    /// What letting `lease` hold `total` bytes of KV takes, or why it cannot: whatever it
    /// holds now counts towards `total`, so a shape that grows is judged by its whole KV.
    /// What `lease` needs beyond what it holds is served first in, first out by
    /// `request`, at `now`: a request that must wait keeps its place, and one that fits is
    /// admitted only from what the requests waiting ahead of it leave. A shrinking shape
    /// takes nothing and never waits.
    pub(super) fn plan(
        &mut self,
        lease: LeaseId,
        request: &OperationId,
        total: u64,
        now: MonotonicTime,
    ) -> Result<KvPlan, KvRefusal> {
        let pool = self.spec.pool_bytes;
        if total > pool {
            self.waits.leave(request);
            return Err(KvRefusal::ExceedsPool {
                requested_bytes: total,
                pool_bytes: pool,
            });
        }
        let held = self.lease_bytes(lease).unwrap_or(0);
        let others = self.leased_bytes().saturating_sub(held);
        let wanted = others.checked_add(total).ok_or(KvRefusal::Overflow)?;
        if total > held {
            let free = WaitDemand::bytes(pool.saturating_sub(self.leased_bytes()));
            let demand = WaitDemand::bytes(total - held);
            match self.waits.turn(request, demand, free, now) {
                WaitTurn::Admit => {}
                WaitTurn::Wait {
                    fits_now: false, ..
                } => {
                    return Err(KvRefusal::AwaitingRelease {
                        requested_bytes: total,
                        free_bytes: pool.saturating_sub(others),
                    })
                }
                WaitTurn::Wait { ahead, claimed, .. } => {
                    return Err(KvRefusal::QueuedBehind {
                        requested_bytes: total,
                        free_bytes: pool.saturating_sub(others),
                        ahead: u32::try_from(ahead).unwrap_or(u32::MAX),
                        claimed_bytes: claimed.bytes,
                    })
                }
                WaitTurn::Full { waiting } => {
                    return Err(KvRefusal::WaitQueueFull {
                        waiting: u32::try_from(waiting).unwrap_or(u32::MAX),
                    })
                }
            }
        }
        let committed = self.committed_bytes();
        if wanted <= committed {
            return Ok(KvPlan::Fits);
        }
        let KvGrowth::Increments { increment_bytes } = self.spec.growth else {
            return Ok(KvPlan::Fits);
        };
        let step = increment_bytes.max(1);
        let mut increments = Vec::new();
        let mut reach = committed;
        while reach < wanted {
            let bytes = step.min(pool.saturating_sub(reach));
            if bytes == 0 {
                break;
            }
            increments.push(bytes);
            reach = reach.saturating_add(bytes);
        }
        Ok(KvPlan::Grow { increments })
    }

    /// Records an increment the ledger granted.
    pub(super) fn grew(&mut self, reservation: ReservationId, bytes: u64) {
        self.increments.push((reservation, bytes));
    }

    /// Lets `lease` hold `total` bytes for `request`, which leaves the queue; the plan must
    /// have allowed a larger total.
    pub(super) fn admit(&mut self, lease: LeaseId, request: &OperationId, total: u64) {
        self.leased.insert(lease, total);
        self.waits.leave(request);
        // A session that stayed resumes under this lease: its KV is the lease's now.
        self.sessions.remove(request);
        self.requests.insert(lease, request.clone());
    }

    /// The session `lease` serves stays with its KV once the lease ends. Returns whether
    /// the lease holds KV here.
    pub(super) fn keep_session(&mut self, lease: LeaseId) -> bool {
        let leased = self.leased.contains_key(&lease);
        if leased {
            self.keeping.insert(lease);
        }
        leased
    }

    /// The runner dropped the KV of the session `request` kept after its lease ended.
    /// Returns its bytes, if it was kept.
    pub(super) fn forget_session(&mut self, request: &OperationId) -> Option<u64> {
        self.sessions.remove(request)
    }

    /// The KV of sessions that stayed after their lease ended, by request.
    pub(super) fn sessions(&self) -> &BTreeMap<OperationId, u64> {
        &self.sessions
    }

    /// The KV sessions kept after their lease ended.
    pub(super) fn session_bytes(&self) -> u64 {
        self.sessions
            .values()
            .fold(0u64, |total, bytes| total.saturating_add(*bytes))
    }

    /// `request` gives up its place, or was refused for good. Returns whether it waited.
    pub(super) fn leave_wait(&mut self, request: &OperationId) -> bool {
        self.waits.leave(request).is_some()
    }

    /// The requests waiting for room, first in line first, as of `now`: expired places
    /// are dropped first.
    pub(super) fn waiters(&mut self, now: MonotonicTime) -> Vec<Waiter<OperationId>> {
        self.waits.expire(now);
        self.waits.waiters().cloned().collect()
    }

    /// `lease` ended; its KV is free again, unless its session stays
    /// ([`KvPool::keep_session`]): then the session holds that KV until the runner drops it.
    pub(super) fn release(&mut self, lease: LeaseId) -> Option<u64> {
        let bytes = self.leased.remove(&lease);
        let request = self.requests.remove(&lease);
        let kept = self.keeping.remove(&lease);
        if let (true, Some(request), Some(held)) = (kept, request, bytes) {
            if held > 0 {
                self.sessions.insert(request, held);
            }
        }
        bytes
    }

    /// The increments neither a lease nor a session kept after its lease needs, newest
    /// first: handing all of them back still leaves committed at least the KV admitted to
    /// leases and the KV of those sessions, so any of them may go. None for a pool held
    /// whole.
    pub(super) fn trimmable(&self) -> Vec<(ReservationId, u64)> {
        if !matches!(self.spec.growth, KvGrowth::Increments { .. }) {
            return Vec::new();
        }
        let needed = self.leased_bytes().saturating_add(self.session_bytes());
        let mut committed = self.committed_bytes();
        let mut trimmable = Vec::new();
        for (reservation, bytes) in self.increments.iter().rev() {
            match committed.checked_sub(*bytes) {
                Some(left) if left >= needed => {
                    committed = left;
                    trimmable.push((*reservation, *bytes));
                }
                _ => break,
            }
        }
        trimmable
    }

    /// Takes the trimmable increments among `reservations` out of what is committed, so
    /// nothing is admitted on them, and keeps them as releasing until their release is
    /// confirmed. Returns those taken, newest first.
    pub(super) fn trim(
        &mut self,
        reservations: &BTreeSet<ReservationId>,
    ) -> Vec<(ReservationId, u64)> {
        let allowed: BTreeSet<ReservationId> = self
            .trimmable()
            .into_iter()
            .map(|(reservation, _)| reservation)
            .filter(|reservation| reservations.contains(reservation))
            .collect();
        let mut taken = Vec::new();
        self.increments.retain(|(reservation, bytes)| {
            let trimmed = allowed.contains(reservation);
            if trimmed {
                taken.push((*reservation, *bytes));
            }
            !trimmed
        });
        taken.reverse();
        self.releasing.extend(taken.iter().copied());
        taken
    }

    /// The trimmed increments whose release is not confirmed yet.
    pub(super) fn releasing(&self) -> &[(ReservationId, u64)] {
        &self.releasing
    }

    /// Forgets the trimmed increment `reservation` once its release is confirmed.
    pub(super) fn released(&mut self, reservation: ReservationId) -> Option<u64> {
        let index = self
            .releasing
            .iter()
            .position(|(trimmed, _)| *trimmed == reservation)?;
        Some(self.releasing.remove(index).1)
    }

    /// Every increment, committed or trimmed and still releasing, handed back when the pool
    /// ends.
    pub(super) fn take_increments(&mut self) -> Vec<(ReservationId, u64)> {
        let mut all = std::mem::take(&mut self.increments);
        all.append(&mut self.releasing);
        all
    }
}
