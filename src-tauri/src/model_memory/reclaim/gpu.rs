//! GPU-resident caches for rungs 3 and 4 (GPU part §3.4 table line 539 and §3.9 lines
//! 640–644; GPU-W05: "drop low-value caches, park eligible idle models"; S03): the KV of
//! finished sessions and the weights nothing uses any more, still resident in a
//! [`GpuTier`].
//!
//! [`TierCaches`](super::TierCaches) offers the copies the representation store keeps in
//! host RAM and local storage, never what the GPU tier holds. These two sources offer what
//! the GPU tier keeps after its users are gone, each allocation through the tier, which
//! reserved it in the ledger as [`Requester::ModelPlacement`]:
//!
//! - [`FinishedSessionKv`], for rung 3 ([`DropLowValueCaches`](super::DropLowValueCaches)):
//!   the KV-cache allocations of the sessions the caller reports finished. Dead session KV
//!   is the cache of least value there is (§3.9 line 641: "drop dead session KV while
//!   retaining the base and graph"): nothing reads it again, so it is dropped without a
//!   write-back and in the order the caller lists the sessions. Register its step before
//!   the store's, so dead KV goes before any copy of value. The KV of a session the caller
//!   reports live is kept.
//! - [`IdleGpuWeights`], for rung 4
//!   ([`ParkEligibleIdleModels`](super::ParkEligibleIdleModels)): the immutable weights of
//!   the objects the caller names that no execution, captured graph or import references
//!   any more. Dropping weights means loading them again, so they are parked only as the
//!   clean-eviction rule allows (GPU-W05: "clean-drop parking only when canonical state
//!   can reconstruct exact weights"; §3.9 line 643: "park clean weights without D2H when a
//!   canonical copy exists"): when a verified copy of exactly that object in the pinned
//!   host tier or local storage rebuilds them, the cheaper rebuild first. Register its step
//!   before the steps that park models still activated, so weights no activation uses go
//!   first, and give the store's step the same GPU tier
//!   ([`TierCaches::with_gpu`](super::TierCaches::with_gpu)), so rung 3 keeps the copy that
//!   rebuilds them; stopping looks for that copy again and keeps the weights without it.
//!
//! Neither gives up an allocation that:
//!
//! - a live session may use again ([`PinnedBy::LiveSession`]);
//! - its owner protects ([`FinishedSessionKv::protect`], [`IdleGpuWeights::protect`]),
//!   such as an activation pinned by policy or a request lease the tier does not see;
//! - an execution, a captured graph or an import still references
//!   ([`LeasedBy::Referenced`]): the tier's own record of the requests, activations and
//!   loads that keep a physical allocation alive (GPU-W05 line 1056);
//! - is a shared physical extent other holders still hold ([`LeasedBy::SharedExtent`]);
//! - lies under an open transition peak, on its own reservation or on one it is carved
//!   from ([`PinnedBy::Transition`]): the overlap of a generation change may still need
//!   it, and the ledger names a peak only by its steady reservation;
//! - for weights, has no verified copy that would rebuild it
//!   ([`PinnedBy::NoCanonicalState`]).
//!
//! Each step names only as many allocations as cover what is missing (see
//! [`WorkSource`]). Stopping one checks again what holds it, then frees it through the
//! tier ([`GpuTier::free`]), which refuses while anything maps or references it, and gives
//! the reservation back through the ledger, where the ladder set it releasing. Anything
//! not freed is reported in the [`Settlement`](super::Settlement) with its
//! [`StopError`]. The memory of what was freed counts until a source with authority
//! observes it free (GPU part §3.6 step 7; S10 line 185):
//! [`confirm_freed_allocations`] confirms exactly the releases a settlement awaits, and the
//! ledger refuses a source weaker than the reservation needs: the host's own probe at host
//! level, the runtime's report within the runtime's reservation (S3.2).
//!
//! The GPU tier lists neither the allocations of a session nor what maps an allocation,
//! so the caller that allocated a session's KV names it, and a mapped allocation is
//! reported as work not stopped.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::steps::{CacheSource, ParkingSource};
use super::work::{lock, Candidate, Hold, LeasedBy, PinnedBy, Settlement, StopError, WorkSource};
use crate::foundation::catalog::Catalog;
use crate::foundation::coordination::SharedLedger;
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{Clock, OperationId};
use crate::foundation::ledger::{
    Ledger, LedgerError, ReleaseOutcome, Requester, ReservationId, ReservationState,
    MAX_NESTING_DEPTH,
};
use crate::model_memory::residency::eviction::{CopyTier, EvictionAction, NotDroppable, WriteBack};
use crate::model_memory::tiers::{
    AllocationHandle, GpuContent, GpuTier, LocalStorageTier, MutableState, ObjectCopy, ObjectRef,
    PinnedHostTier,
};

/// The KV of one session in one GPU allocation, to drop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionKv {
    /// The operation that names the session, as the flow names a served session.
    pub session: OperationId,
    pub allocation: AllocationHandle,
}

impl fmt::Display for SessionKv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KV of session {} in GPU allocation {}",
            self.session,
            self.allocation.generation()
        )
    }
}

/// The weights of one object in one GPU allocation, to drop clean.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdleWeights {
    pub object: ObjectRef,
    pub allocation: AllocationHandle,
}

impl fmt::Display for IdleWeights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "weights of {} in GPU allocation {}",
            self.object,
            self.allocation.generation()
        )
    }
}

/// What the ledger says holds an allocation's reservation: a shared extent other holders
/// still hold, or an open transition peak on the reservation or on one it is carved from.
pub(super) fn ledger_hold<C: Clock>(
    ledger: &Ledger<C>,
    reservation: ReservationId,
) -> Option<Hold> {
    if let Some(extent) = ledger.extent_of(reservation) {
        let holders = extent.holders().count();
        if holders > 0 {
            return Some(Hold::Leased(LeasedBy::SharedExtent { holders }));
        }
    }
    let mut next = Some(reservation);
    for _ in 0..=MAX_NESTING_DEPTH {
        let Some(id) = next else {
            break;
        };
        if ledger.transition_peak(id).is_some() {
            return Some(Hold::Pinned(PinnedBy::Transition));
        }
        next = ledger.reservation(id).and_then(|record| record.parent());
    }
    None
}

/// What holds a live allocation of `gpu`: its owner's protection, a reference, or the
/// ledger; `None` when nothing does.
fn allocation_hold<C: Clock>(
    gpu: &GpuTier,
    ledger: &Ledger<C>,
    protected: &BTreeMap<AllocationHandle, Hold>,
    allocation: AllocationHandle,
    reservation: ReservationId,
) -> Option<Hold> {
    if let Some(hold) = protected.get(&allocation) {
        return Some(*hold);
    }
    let references = gpu.references(allocation).unwrap_or(0);
    if references > 0 {
        return Some(Hold::Leased(LeasedBy::Referenced { references }));
    }
    ledger_hold(ledger, reservation)
}

/// Frees `allocation` through `gpu`, giving its reservation back through `ledger`.
fn free<C: Clock>(
    gpu: &mut GpuTier,
    ledger: &SharedLedger<C>,
    allocation: AllocationHandle,
) -> Result<(), StopError> {
    let mut ledger = lock(ledger);
    gpu.free(allocation, &mut ledger)
        .map(|_| ())
        .map_err(|refusal| StopError::Gpu(Box::new(refusal)))
}

/// Rung 3's source over the KV of finished sessions in one GPU tier.
pub struct FinishedSessionKv<'a, L: Clock> {
    gpu: &'a mut GpuTier,
    ledger: SharedLedger<L>,
    sessions: Vec<(OperationId, Vec<AllocationHandle>)>,
    live: BTreeSet<AllocationHandle>,
    protected: BTreeMap<AllocationHandle, Hold>,
}

impl<'a, L: Clock> FinishedSessionKv<'a, L> {
    /// The KV `gpu` holds for the sessions named next, whose allocations it reserved in
    /// `ledger`.
    pub fn new(gpu: &'a mut GpuTier, ledger: SharedLedger<L>) -> Self {
        Self {
            gpu,
            ledger,
            sessions: Vec::new(),
            live: BTreeSet::new(),
            protected: BTreeMap::new(),
        }
    }

    /// Offers the KV-cache allocations `kv` of `session`, which has finished: nothing
    /// resumes it. Sessions are offered in the order they are named.
    pub fn finished(
        mut self,
        session: OperationId,
        kv: impl IntoIterator<Item = AllocationHandle>,
    ) -> Self {
        self.sessions.push((session, kv.into_iter().collect()));
        self
    }

    /// Reports the KV-cache allocations `kv` of `session`, which is still live, as kept,
    /// even where a finished session names them too.
    pub fn live(
        mut self,
        session: OperationId,
        kv: impl IntoIterator<Item = AllocationHandle>,
    ) -> Self {
        let kv: Vec<AllocationHandle> = kv.into_iter().collect();
        self.live.extend(kv.iter().copied());
        self.sessions.push((session, kv));
        self
    }

    /// Keeps `allocation` as `hold` says: state its owner leases or pins.
    pub fn protect(mut self, allocation: AllocationHandle, hold: Hold) -> Self {
        self.protected.insert(allocation, hold);
        self
    }

    /// What holds the KV-cache allocation `allocation` now, and its reservation; `None`
    /// when the tier holds no such allocation.
    fn hold<C: Clock>(
        &self,
        ledger: &Ledger<C>,
        allocation: AllocationHandle,
    ) -> Option<(ReservationId, Hold)> {
        let content = self.gpu.content(allocation).ok()?;
        if *content != GpuContent::Mutable(MutableState::KvCache) {
            return None;
        }
        let reservation = self.gpu.reservation(allocation).ok()?;
        let hold = if self.live.contains(&allocation) {
            Hold::Pinned(PinnedBy::LiveSession)
        } else {
            allocation_hold(self.gpu, ledger, &self.protected, allocation, reservation)
                .unwrap_or(Hold::Free)
        };
        Some((reservation, hold))
    }
}

impl<L: Clock> WorkSource for FinishedSessionKv<'_, L> {
    type Work = SessionKv;

    fn owner(&self) -> Requester {
        Requester::ModelPlacement
    }

    /// Every KV-cache allocation of the sessions named, in that order, each once; an
    /// allocation that is not KV or no longer resident is left out.
    fn survey(&mut self) -> Vec<Candidate<SessionKv>> {
        let ledger = lock(&self.ledger);
        let mut seen = BTreeSet::new();
        let mut candidates = Vec::new();
        for (session, kv) in &self.sessions {
            for allocation in kv {
                if !seen.insert(*allocation) {
                    continue;
                }
                let Some((reservation, hold)) = self.hold(&ledger, *allocation) else {
                    continue;
                };
                candidates.push(Candidate {
                    work: SessionKv {
                        session: session.clone(),
                        allocation: *allocation,
                    },
                    reservations: vec![reservation],
                    hold,
                    rank: 0.0,
                });
            }
        }
        candidates
    }

    /// Frees the allocation through the tier, unless something took hold of it since the
    /// survey.
    fn stop(&mut self, work: &SessionKv) -> Result<(), StopError> {
        let hold = {
            let ledger = lock(&self.ledger);
            self.hold(&ledger, work.allocation).map(|(_, hold)| hold)
        };
        match hold {
            None => Err(StopError::Gone),
            Some(Hold::Free) => free(self.gpu, &self.ledger, work.allocation),
            Some(hold) => Err(StopError::Held { hold }),
        }
    }
}

impl<L: Clock> CacheSource for FinishedSessionKv<'_, L> {}

/// Rung 4's source over the weights in one GPU tier that nothing references.
pub struct IdleGpuWeights<'a, L: Clock> {
    gpu: &'a mut GpuTier,
    ledger: SharedLedger<L>,
    objects: Vec<ObjectRef>,
    pinned: Option<&'a PinnedHostTier>,
    local: Option<(&'a LocalStorageTier, &'a Catalog)>,
    protected: BTreeMap<AllocationHandle, Hold>,
}

impl<'a, L: Clock> IdleGpuWeights<'a, L> {
    /// The weights `gpu` holds of the objects named next, whose allocations it reserved
    /// in `ledger`. Without a copy from [`Self::with_pinned`] or [`Self::with_local`],
    /// nothing can rebuild them and nothing is offered.
    pub fn new(gpu: &'a mut GpuTier, ledger: SharedLedger<L>) -> Self {
        Self {
            gpu,
            ledger,
            objects: Vec::new(),
            pinned: None,
            local: None,
            protected: BTreeMap::new(),
        }
    }

    /// Offers the allocations that hold the weights of exactly `object`. Objects are
    /// offered in the order they are named.
    pub fn weights_of(mut self, object: ObjectRef) -> Self {
        self.objects.push(object);
        self
    }

    /// Lets the verified copies `pinned` holds rebuild weights.
    pub fn with_pinned(mut self, pinned: &'a PinnedHostTier) -> Self {
        self.pinned = Some(pinned);
        self
    }

    /// Lets the objects `local` stores, as `catalog` publishes them, rebuild weights.
    pub fn with_local(mut self, local: &'a LocalStorageTier, catalog: &'a Catalog) -> Self {
        self.local = Some((local, catalog));
        self
    }

    /// Keeps `allocation` as `hold` says: state its owner leases or pins, such as an
    /// activation pinned by policy.
    pub fn protect(mut self, allocation: AllocationHandle, hold: Hold) -> Self {
        self.protected.insert(allocation, hold);
        self
    }

    /// The tier a verified copy would rebuild `allocation` from, by the GPU tier's own
    /// clean-eviction rule, or why none would.
    fn rebuild(
        &self,
        object: &ObjectRef,
        allocation: AllocationHandle,
    ) -> Result<CopyTier, NotDroppable> {
        let mut copies: Vec<ObjectCopy> = Vec::new();
        if let Some(copy) = self.pinned.and_then(|pinned| pinned.copy_of(object)) {
            copies.push(copy);
        }
        if let Some(copy) = self
            .local
            .and_then(|(local, catalog)| local.copy_of(object, catalog))
        {
            copies.push(copy);
        }
        match self
            .gpu
            .eviction_action(allocation, &copies, WriteBack::Unavailable)
        {
            Ok(EvictionAction::DropClean { source }) => Ok(source),
            Ok(EvictionAction::Retain { because })
            | Ok(EvictionAction::WriteBackThenDrop { because, .. }) => Err(because),
            Ok(EvictionAction::Recapture) | Err(_) => Err(NotDroppable::NoVerifiedCopy),
        }
    }

    /// What holds the weights allocation `allocation` of `object` now, its reservation
    /// and the tier that would rebuild it; `None` when the tier holds no such allocation.
    fn hold<C: Clock>(
        &self,
        ledger: &Ledger<C>,
        object: &ObjectRef,
        allocation: AllocationHandle,
    ) -> Option<(ReservationId, Hold, Result<CopyTier, NotDroppable>)> {
        let content = self.gpu.content(allocation).ok()?;
        if !content.holds_weights_of(object) {
            return None;
        }
        let reservation = self.gpu.reservation(allocation).ok()?;
        let rebuild = self.rebuild(object, allocation);
        let hold = allocation_hold(self.gpu, ledger, &self.protected, allocation, reservation)
            .unwrap_or(match rebuild {
                Ok(_) => Hold::Free,
                Err(_) => Hold::Pinned(PinnedBy::NoCanonicalState),
            });
        Some((reservation, hold, rebuild))
    }
}

impl<L: Clock> WorkSource for IdleGpuWeights<'_, L> {
    type Work = IdleWeights;

    fn owner(&self) -> Requester {
        Requester::ModelPlacement
    }

    /// Every allocation holding the weights of the objects named, each once, ranked by
    /// what would rebuild it: a pinned host copy before one in local storage.
    fn survey(&mut self) -> Vec<Candidate<IdleWeights>> {
        let ledger = lock(&self.ledger);
        let mut seen = BTreeSet::new();
        let mut candidates = Vec::new();
        for object in &self.objects {
            for allocation in self.gpu.resident(object) {
                if !seen.insert(allocation) {
                    continue;
                }
                let Some((reservation, hold, rebuild)) = self.hold(&ledger, object, allocation)
                else {
                    continue;
                };
                candidates.push(Candidate {
                    work: IdleWeights {
                        object: object.clone(),
                        allocation,
                    },
                    reservations: vec![reservation],
                    hold,
                    rank: match rebuild {
                        Ok(CopyTier::PinnedHost) => 0.0,
                        Ok(_) => 1.0,
                        Err(_) => f64::INFINITY,
                    },
                });
            }
        }
        candidates
    }

    /// Frees the allocation through the tier, unless something took hold of it since the
    /// survey or no verified copy would rebuild it any more.
    fn stop(&mut self, work: &IdleWeights) -> Result<(), StopError> {
        let found = {
            let ledger = lock(&self.ledger);
            self.hold(&ledger, &work.object, work.allocation)
        };
        match found {
            None => Err(StopError::Gone),
            Some((_, _, Err(because))) => Err(StopError::Retained { because }),
            Some((_, Hold::Free, Ok(_))) => free(self.gpu, &self.ledger, work.allocation),
            Some((_, hold, Ok(_))) => Err(StopError::Held { hold }),
        }
    }
}

impl<L: Clock> ParkingSource for IdleGpuWeights<'_, L> {}

/// Confirms, as `source` observed it, the release of each reservation `settlement`
/// awaits that is still releasing, and returns the ledger's answer for each one tried.
/// Use it for the settlements of the GPU-tier steps, whose freed allocations the tier no
/// longer records, once the runtime or the host saw their memory free; never before (S10
/// line 185). The ledger refuses a source without the authority the reservation needs
/// (S3.2), and a reservation not releasing, such as one already closed, is left alone.
pub fn confirm_freed_allocations<C: Clock>(
    ledger: &mut Ledger<C>,
    settlement: &Settlement,
    source: SourceClass,
) -> Vec<(ReservationId, Result<ReleaseOutcome, LedgerError>)> {
    let releasing: Vec<ReservationId> = settlement
        .awaiting_release()
        .into_iter()
        .filter(|reservation| {
            ledger
                .reservation(*reservation)
                .is_some_and(|record| record.state() == ReservationState::Releasing)
        })
        .collect();
    releasing
        .into_iter()
        .map(|reservation| (reservation, ledger.confirm_release(reservation, source)))
        .collect()
}
