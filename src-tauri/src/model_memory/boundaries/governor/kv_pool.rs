//! The governor's operations on a generation's KV pool beyond admission (G06 of
//! docs/combined-plan-leftover-tasks.md: "a FIFO for KV waits" and "trimming increments
//! before reclaim"; GPU-W10 of docs/combined-gpu-memory-and-vm-sandbox-plan.md, line 1305,
//! and its acceptance, line 1310: "request shape changes cannot overrun reserved memory").
//!
//! - Waits: requests that wait for room in a pool are served first in, first out (the
//!   pool's [`WaitQueue`](super::super::WaitQueue)); [`LedgerPolicyGovernor::kv_waiters`]
//!   lists them in the order to retry, and a request that gives up leaves its place
//!   ([`LedgerPolicyGovernor::withdraw_kv_wait`]).
//! - Trimming: a backend that grows its KV in increments keeps them committed until its
//!   generation is reclaimed. [`LedgerPolicyGovernor::trim_kv`] hands back, while the
//!   generation serves, every increment no lease needs: each leaves the pool at once, so
//!   nothing is admitted on it, and starts releasing in the CORE-03 ledger, where it
//!   counts until the runner unmapped it and
//!   [`LedgerPolicyGovernor::confirm_kv_trimmed`] observed that (GPU §3.6 step 7). What
//!   leases hold always stays committed, and so does the KV of a session that stays after
//!   its lease ended, kept for a resume or because no tier could take it (T08; GPU §1
//!   step 5): the flow marks its lease ([`ExecutionLease::keep_session`]) and the session
//!   holds that KV until the runner dropped it
//!   ([`LedgerPolicyGovernor::release_session_kv`]).
//! - Before reclaim: [`KvScratch`] offers the same increments to the CORE-03 reclamation
//!   ladder as rung 2's scratch ("reclaim unused scratch"), so a foreground request that
//!   falls short inside an activation's reservation, such as an adapter carved from it,
//!   trims unused KV before any costlier rung parks a model.

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

use super::{ExecutionLease, HostLedger, LedgerPolicyGovernor, PlacementKey};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{AuthorizationEpoch, Clock, ModelActivationGeneration, OperationId};
use crate::foundation::ledger::{LedgerError, ReleaseOutcome, Requester, ReservationId};
use crate::model_memory::boundaries::kv::KvPool;
use crate::model_memory::boundaries::waits::Waiter;
use crate::model_memory::reclaim::{
    Candidate, Hold, LeasedBy, PinnedBy, ScratchSource, StopError, WorkSource,
};

/// One KV increment: a CORE-03 reservation carved from a generation's own memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct KvIncrement {
    pub reservation: ReservationId,
    pub bytes: u64,
}

impl KvIncrement {
    fn of((reservation, bytes): (ReservationId, u64)) -> Self {
        Self { reservation, bytes }
    }
}

/// Why KV was not trimmed, or a trim not confirmed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KvTrimRefusal {
    /// The generation holds no KV pool under this placement and epoch.
    NoPool,
    /// Memory is closed only as the runtime's own report or a stronger source saw it
    /// freed.
    ReleaseSourceTooWeak { source: SourceClass },
    /// The ledger refused; what was trimmed or confirmed before it stays so.
    Ledger(LedgerError),
}

impl fmt::Display for KvTrimRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPool => f.write_str("the generation holds no KV pool"),
            Self::ReleaseSourceTooWeak { source } => {
                write!(f, "a release observed by a {source} does not close memory")
            }
            Self::Ledger(error) => write!(f, "the ledger refused: {error}"),
        }
    }
}

impl std::error::Error for KvTrimRefusal {}

impl<C: Clock + Clone, P: HostLedger<C>> LedgerPolicyGovernor<C, P> {
    fn kv_pool(
        &self,
        placement: &PlacementKey,
        epoch: AuthorizationEpoch,
        generation: ModelActivationGeneration,
    ) -> Option<&KvPool> {
        self.slots
            .get(&(*placement, epoch))?
            .generations
            .get(&generation)
            .map(|entry| &entry.kv)
    }

    fn kv_pool_mut(
        &mut self,
        placement: &PlacementKey,
        epoch: AuthorizationEpoch,
        generation: ModelActivationGeneration,
    ) -> Option<&mut KvPool> {
        self.slots
            .get_mut(&(*placement, epoch))?
            .generations
            .get_mut(&generation)
            .map(|entry| &mut entry.kv)
    }

    /// The requests waiting for room in `generation`'s KV pool, first in line first: the
    /// order in which to retry them once KV is released. Places that expired are dropped.
    pub fn kv_waiters(
        &mut self,
        placement: &PlacementKey,
        epoch: AuthorizationEpoch,
        generation: ModelActivationGeneration,
    ) -> Option<Vec<Waiter<OperationId>>> {
        let now = self.clock.now();
        self.kv_pool_mut(placement, epoch, generation)
            .map(|pool| pool.waiters(now))
    }

    /// `request` gives up its place in the queue for `generation`'s KV, so those behind it
    /// move up. Returns whether it waited.
    pub fn withdraw_kv_wait(
        &mut self,
        placement: &PlacementKey,
        epoch: AuthorizationEpoch,
        generation: ModelActivationGeneration,
        request: &OperationId,
    ) -> bool {
        self.kv_pool_mut(placement, epoch, generation)
            .is_some_and(|pool| pool.leave_wait(request))
    }

    /// Marks the session `lease` serves as staying with its KV once the lease ends, when
    /// the caller set [`ExecutionLease::keep_session`].
    pub(super) fn keep_session_kv(&mut self, lease: &ExecutionLease) {
        if !lease.keep_session {
            return;
        }
        if let Some(pool) = self.kv_pool_mut(&lease.placement, lease.epoch, lease.generation) {
            pool.keep_session(lease.id());
        }
    }

    /// The KV of the sessions that stayed in `generation`'s pool after their lease ended,
    /// by the request that kept each: it is never trimmed or offered as scratch.
    pub fn kv_sessions(
        &self,
        placement: &PlacementKey,
        epoch: AuthorizationEpoch,
        generation: ModelActivationGeneration,
    ) -> Option<Vec<(OperationId, u64)>> {
        self.kv_pool(placement, epoch, generation).map(|pool| {
            pool.sessions()
                .iter()
                .map(|(request, bytes)| (request.clone(), *bytes))
                .collect()
        })
    }

    /// The runner dropped the KV of the session `request` kept after its lease ended, as
    /// after writing it back (T08): it no longer holds `generation`'s increments, which
    /// may then be trimmed. Returns its bytes, if it was kept. A session that resumes
    /// under a new lease of the same request hands its KV to that lease instead.
    pub fn release_session_kv(
        &mut self,
        placement: &PlacementKey,
        epoch: AuthorizationEpoch,
        generation: ModelActivationGeneration,
        request: &OperationId,
    ) -> Option<u64> {
        self.kv_pool_mut(placement, epoch, generation)?
            .forget_session(request)
    }

    /// A request refused for good leaves the queue it waited in.
    pub(super) fn leave_kv_wait(
        &mut self,
        (placement, epoch): (PlacementKey, AuthorizationEpoch),
        generation: ModelActivationGeneration,
        request: &OperationId,
    ) {
        if let Some(pool) = self.kv_pool_mut(&placement, epoch, generation) {
            pool.leave_wait(request);
        }
    }

    /// The increments of `generation`'s KV pool that neither a lease nor a kept session
    /// needs, newest first: what [`LedgerPolicyGovernor::trim_kv`] would hand back now.
    /// Empty for a pool held whole.
    pub fn kv_trimmable(
        &self,
        placement: &PlacementKey,
        epoch: AuthorizationEpoch,
        generation: ModelActivationGeneration,
    ) -> Option<Vec<KvIncrement>> {
        self.kv_pool(placement, epoch, generation)
            .map(|pool| pool.trimmable().into_iter().map(KvIncrement::of).collect())
    }

    /// The increments trimmed from `generation`'s KV pool whose release is not confirmed
    /// yet: they still count in the ledger.
    pub fn kv_releasing(
        &self,
        placement: &PlacementKey,
        epoch: AuthorizationEpoch,
        generation: ModelActivationGeneration,
    ) -> Option<Vec<KvIncrement>> {
        self.kv_pool(placement, epoch, generation).map(|pool| {
            pool.releasing()
                .iter()
                .copied()
                .map(KvIncrement::of)
                .collect()
        })
    }

    /// Trims `generation`'s KV pool while it serves, before it is reclaimed: hands back
    /// every increment that neither a lease nor a kept session needs, newest first. Each starts releasing in the ledger
    /// and leaves the pool, so nothing is admitted on it and a later request grows the
    /// pool again; its memory counts until the runner unmapped it and
    /// [`LedgerPolicyGovernor::confirm_kv_trimmed`] observed that. Returns what was
    /// trimmed: unmap exactly that. A ledger refusal stops the trim there, with what was
    /// trimmed before it kept.
    pub fn trim_kv(
        &mut self,
        placement: &PlacementKey,
        epoch: AuthorizationEpoch,
        generation: ModelActivationGeneration,
    ) -> Result<Vec<KvIncrement>, KvTrimRefusal> {
        let trimmable = self
            .kv_pool(placement, epoch, generation)
            .ok_or(KvTrimRefusal::NoPool)?
            .trimmable();
        let mut releasing = BTreeSet::new();
        let mut closed = BTreeSet::new();
        let mut fault = None;
        self.coordinator.capacity_mut().write_ledger(|ledger| {
            for (reservation, _) in &trimmable {
                match ledger.cancel(*reservation) {
                    Ok(ReleaseOutcome::Pending) => {
                        releasing.insert(*reservation);
                    }
                    Ok(ReleaseOutcome::Released { .. } | ReleaseOutcome::AlreadyClosed) => {
                        closed.insert(*reservation);
                    }
                    Err(error) => {
                        fault = Some(error);
                        break;
                    }
                }
            }
        });
        let all: BTreeSet<ReservationId> = releasing.union(&closed).copied().collect();
        let trimmed = match self.kv_pool_mut(placement, epoch, generation) {
            Some(pool) => {
                let taken = pool.trim(&all);
                for reservation in &closed {
                    pool.released(*reservation);
                }
                taken
            }
            None => Vec::new(),
        };
        match fault {
            Some(error) => Err(KvTrimRefusal::Ledger(error)),
            None => Ok(trimmed.into_iter().map(KvIncrement::of).collect()),
        }
    }

    /// The runner unmapped the increments trimmed from `generation`'s KV pool, as
    /// `source` observed: their release is confirmed in the ledger, and their memory
    /// returns to the generation's own reservation. The runtime's own report suffices for
    /// a child reservation (CORE-03); a weaker source is refused. Returns what was
    /// confirmed.
    pub fn confirm_kv_trimmed(
        &mut self,
        placement: &PlacementKey,
        epoch: AuthorizationEpoch,
        generation: ModelActivationGeneration,
        source: SourceClass,
    ) -> Result<Vec<KvIncrement>, KvTrimRefusal> {
        if !source.satisfies(SourceClass::GuestReport) {
            return Err(KvTrimRefusal::ReleaseSourceTooWeak { source });
        }
        let releasing: Vec<(ReservationId, u64)> = self
            .kv_pool(placement, epoch, generation)
            .map(|pool| pool.releasing().to_vec())
            .unwrap_or_default();
        let mut confirmed = Vec::new();
        let mut fault = None;
        self.coordinator.capacity_mut().write_ledger(|ledger| {
            for increment in &releasing {
                match ledger.confirm_release(increment.0, source) {
                    Ok(_) => confirmed.push(*increment),
                    Err(error) => {
                        fault = Some(error);
                        break;
                    }
                }
            }
        });
        if let Some(pool) = self.kv_pool_mut(placement, epoch, generation) {
            for (reservation, _) in &confirmed {
                pool.released(*reservation);
            }
        }
        match fault {
            Some(error) => Err(KvTrimRefusal::Ledger(error)),
            None => Ok(confirmed.into_iter().map(KvIncrement::of).collect()),
        }
    }
}

/// One KV increment the reclamation ladder may give up, with the pool it belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KvTrimWork {
    pub placement: PlacementKey,
    pub epoch: AuthorizationEpoch,
    pub generation: ModelActivationGeneration,
    pub increment: KvIncrement,
}

impl fmt::Display for KvTrimWork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KV increment {} of {} bytes of generation {}",
            self.increment.reservation, self.increment.bytes, self.generation
        )
    }
}

/// Rung 2's source over unused KV increments (GPU-W05 "reclaim unused scratch"; G06
/// "trimming increments before reclaim"): every increment that neither a lease nor a kept
/// session needs is free scratch, newest first; the others are held by those requests, or
/// pinned by the live sessions kept for a resume.
/// Stopping an increment the ledger gave up takes it out of its pool; its release waits
/// for the runner to unmap it ([`LedgerPolicyGovernor::confirm_kv_trimmed`]). Register it
/// with [`ReclaimUnusedScratch`](crate::model_memory::reclaim::ReclaimUnusedScratch)
/// acting for [`Requester::ModelPlacement`].
pub struct KvScratch<'g, C: Clock + Clone, P: HostLedger<C>> {
    governor: &'g mut LedgerPolicyGovernor<C, P>,
}

impl<'g, C: Clock + Clone, P: HostLedger<C>> KvScratch<'g, C, P> {
    /// The source over every KV pool `governor` keeps.
    pub fn new(governor: &'g mut LedgerPolicyGovernor<C, P>) -> Self {
        Self { governor }
    }
}

impl<C: Clock + Clone, P: HostLedger<C>> WorkSource for KvScratch<'_, C, P> {
    type Work = KvTrimWork;

    fn owner(&self) -> Requester {
        Requester::ModelPlacement
    }

    fn survey(&mut self) -> Vec<Candidate<KvTrimWork>> {
        let mut candidates = Vec::new();
        for (&(placement, epoch), slot) in &self.governor.slots {
            for (&generation, entry) in &slot.generations {
                let pool = &entry.kv;
                let trimmable = pool.trimmable();
                let free: BTreeSet<ReservationId> = trimmable
                    .iter()
                    .map(|(reservation, _)| *reservation)
                    .collect();
                let work = |increment| KvTrimWork {
                    placement,
                    epoch,
                    generation,
                    increment: KvIncrement::of(increment),
                };
                for (newest_first, increment) in trimmable.iter().copied().enumerate() {
                    candidates.push(Candidate {
                        work: work(increment),
                        reservations: vec![increment.0],
                        hold: Hold::Free,
                        rank: f64::from(u32::try_from(newest_first).unwrap_or(u32::MAX)),
                    });
                }
                let leases = pool.lease_count();
                // What leases do not hold, sessions kept for a resume still do.
                let hold = if leases > 0 {
                    Hold::Leased(LeasedBy::Requests { leases })
                } else {
                    Hold::Pinned(PinnedBy::LiveSession)
                };
                for increment in pool.committed().iter().copied() {
                    if free.contains(&increment.0) {
                        continue;
                    }
                    candidates.push(Candidate {
                        work: work(increment),
                        reservations: vec![increment.0],
                        hold,
                        rank: f64::from(u32::MAX),
                    });
                }
            }
        }
        candidates
    }

    fn stop(&mut self, work: &KvTrimWork) -> Result<(), StopError> {
        let pool = self
            .governor
            .kv_pool_mut(&work.placement, work.epoch, work.generation)
            .ok_or(StopError::Gone)?;
        let taken = pool.trim(&BTreeSet::from([work.increment.reservation]));
        if taken.is_empty() {
            Err(StopError::Gone)
        } else {
            Ok(())
        }
    }
}

impl<C: Clock + Clone, P: HostLedger<C>> ScratchSource for KvScratch<'_, C, P> {}

impl ExecutionLease {
    /// The session this lease serves stays with its KV once the lease ends: kept for a
    /// resume, or because no tier could take it (T08). Set it before releasing the lease;
    /// that KV is then never trimmed or offered as scratch until the runner dropped it
    /// ([`LedgerPolicyGovernor::release_session_kv`]).
    pub fn keep_session(&mut self) {
        self.keep_session = true;
    }
}
