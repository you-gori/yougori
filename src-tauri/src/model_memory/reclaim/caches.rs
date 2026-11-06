//! Rung 3's source over the storage tiers (GPU part §2.7, §3.4 lines 548–552, §3.9):
//! derived representations held as caches, dropped in the representation store's own
//! order of least measured value per retained byte.
//!
//! [`TierCaches`] offers what the [`RepresentationStore`] holds: host copies in the
//! reclaimable or pinned host tier and prepared forms in local storage, each through the
//! tier that charged it to the ledger as [`Requester::ModelPlacement`]. It ranks them as
//! the store ranks its evictions: net measured value (expected saving less preparation
//! cost and retention penalty, line 550) per retained byte, least first, ties by object
//! identity. It never gives up:
//!
//! - an original, which is never evicted to meet a budget (line 552);
//! - a prepared form in local storage the catalog would not evict now: leased, needed by
//!   another object or no longer reconstructible (line 552);
//! - a canonical copy still needed: the verified copy without which weights resident on
//!   a GPU tier could no longer be dropped clean, by the GPU tier's own eviction rule
//!   (`GpuTier::eviction_action`, after `residency::eviction`, §1.1 line 307);
//! - a representation whose value cannot be measured;
//! - anything its owner protects as leased or pinned state ([`TierCaches::protect`]).
//!
//! Stopping one evicts it through its tier, which gives the reservation back through
//! the ledger, where it is already releasing, and then forgets it in the store.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::steps::CacheSource;
use super::work::{lock, Candidate, Hold, PinnedBy, StopError, WorkSource};
use crate::foundation::catalog::{Catalog, ObjectId, Scope};
use crate::foundation::coordination::SharedLedger;
use crate::foundation::ids::Clock;
use crate::foundation::ledger::{Requester, ReservationId};
use crate::model_memory::residency::eviction::{EvictionAction, WriteBack};
use crate::model_memory::tiers::{
    GpuTier, HeldRepresentation, LocalStorageTier, ModelKey, ObjectCopy, ObjectRef, PinId,
    PinnedHostTier, PlannedEviction, PoolId, ReclaimableHostTier, RepresentationKind,
    RepresentationStore, Tier,
};

/// One representation the store holds, as a cache entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheEntry {
    pub model: ModelKey,
    pub object: ObjectRef,
    pub kind: RepresentationKind,
    pub tier: Tier,
    pub bytes: u64,
}

impl fmt::Display for CacheEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} representation of {} in {} ({} bytes)",
            self.kind, self.model, self.tier, self.bytes
        )
    }
}

impl CacheEntry {
    fn held(held: HeldRepresentation) -> Self {
        Self {
            model: held.model,
            object: held.object,
            kind: held.kind,
            tier: held.tier,
            bytes: held.bytes,
        }
    }
}

/// Rung 3's source over one representation store and the tiers that hold its entries.
pub struct TierCaches<'a, L: Clock> {
    store: &'a mut RepresentationStore,
    catalog: &'a mut Catalog,
    clock: &'a dyn Clock,
    ledger: SharedLedger<L>,
    host: Option<&'a mut ReclaimableHostTier>,
    local: Option<(&'a mut LocalStorageTier, PoolId)>,
    pinned: Option<(&'a mut PinnedHostTier, BTreeMap<ObjectRef, PinId>)>,
    gpus: Vec<&'a GpuTier>,
    protected: BTreeMap<ObjectRef, Hold>,
}

impl<'a, L: Clock> TierCaches<'a, L> {
    /// The entries of `store`, whose local objects `catalog` holds, measured on `clock`
    /// and reserved in `ledger`. Entries of a tier not given are not offered.
    pub fn new(
        store: &'a mut RepresentationStore,
        catalog: &'a mut Catalog,
        clock: &'a dyn Clock,
        ledger: SharedLedger<L>,
    ) -> Self {
        Self {
            store,
            catalog,
            clock,
            ledger,
            host: None,
            local: None,
            pinned: None,
            gpus: Vec::new(),
            protected: BTreeMap::new(),
        }
    }

    /// Offers the store's host copies in the reclaimable host tier.
    pub fn with_host(mut self, host: &'a mut ReclaimableHostTier) -> Self {
        self.host = Some(host);
        self
    }

    /// Offers the store's prepared forms in `pool` of local storage.
    pub fn with_local(mut self, local: &'a mut LocalStorageTier, pool: PoolId) -> Self {
        self.local = Some((local, pool));
        self
    }

    /// Offers the store's host copies in the pinned host tier, each under the pin that
    /// holds it. The tier names a pin's reservation only by the pin.
    pub fn with_pinned(
        mut self,
        pinned: &'a mut PinnedHostTier,
        pins: BTreeMap<ObjectRef, PinId>,
    ) -> Self {
        self.pinned = Some((pinned, pins));
        self
    }

    /// Keeps every verified copy that weights resident on `gpu` need to be dropped clean.
    pub fn with_gpu(mut self, gpu: &'a GpuTier) -> Self {
        self.gpus.push(gpu);
        self
    }

    /// Keeps `object` whatever its value, as `hold` says: state its owner leases or pins.
    pub fn protect(mut self, object: ObjectRef, hold: Hold) -> Self {
        self.protected.insert(object, hold);
        self
    }

    /// The ledger reservation of the entry, through the tier that charged it.
    fn reservation_of(&self, entry: &CacheEntry) -> Option<ReservationId> {
        match entry.tier {
            Tier::ReclaimableHost => self.host.as_ref()?.reservation_of(&entry.object),
            Tier::LocalStorage => self.local.as_ref()?.0.reservation_of(entry.object.id()),
            Tier::PinnedHost => {
                let (pinned, pins) = self.pinned.as_ref()?;
                pinned.reservation(*pins.get(&entry.object)?).ok()
            }
            Tier::Gpu | Tier::AuthorizedPeer | Tier::Remote => None,
        }
    }

    /// Every copy of `object` the given tiers hold, with the tier holding it.
    fn copies_of(&self, object: &ObjectRef) -> Vec<(Tier, ObjectCopy)> {
        let mut copies = Vec::new();
        if let Some(copy) = self.host.as_ref().and_then(|host| host.copy_of(object)) {
            copies.push((Tier::ReclaimableHost, copy));
        }
        if let Some(copy) = self
            .pinned
            .as_ref()
            .and_then(|(pinned, _)| pinned.copy_of(object))
        {
            copies.push((Tier::PinnedHost, copy));
        }
        if let Some(copy) = self
            .local
            .as_ref()
            .and_then(|(local, _)| local.copy_of(object, self.catalog))
        {
            copies.push((Tier::LocalStorage, copy));
        }
        copies
    }

    /// Whether weights of `object` resident on a GPU tier can be dropped clean with the
    /// copy in `tier` and could not be without it.
    fn rebuilds_resident_weights(&self, object: &ObjectRef, tier: Tier) -> bool {
        let copies = self.copies_of(object);
        let with: Vec<ObjectCopy> = copies.iter().map(|(_, copy)| copy.clone()).collect();
        let without: Vec<ObjectCopy> = copies
            .into_iter()
            .filter(|(held_in, _)| *held_in != tier)
            .map(|(_, copy)| copy)
            .collect();
        self.gpus.iter().any(|gpu| {
            gpu.resident(object).into_iter().any(|handle| {
                let clean = |copies: &[ObjectCopy]| {
                    matches!(
                        gpu.eviction_action(handle, copies, WriteBack::Unavailable),
                        Ok(EvictionAction::DropClean { .. })
                    )
                };
                clean(&with) && !clean(&without)
            })
        })
    }

    /// Net measured value per retained byte (line 550), as the store ranks evictions;
    /// `None` when it cannot be measured.
    fn value_per_byte(&self, entry: &CacheEntry) -> Option<f64> {
        let kind = entry.kind.derived()?;
        let measured = self
            .store
            .measured_amortization(&entry.model, kind, self.clock)
            .ok()?;
        let net = measured.expected_saving_seconds().ok()? - measured.total_cost_seconds().ok()?;
        let per_byte = net / entry.bytes as f64;
        per_byte.is_finite().then_some(per_byte)
    }
}

impl<L: Clock> WorkSource for TierCaches<'_, L> {
    type Work = CacheEntry;

    fn owner(&self) -> Requester {
        Requester::ModelPlacement
    }

    fn survey(&mut self) -> Vec<Candidate<CacheEntry>> {
        let mut evictable: BTreeMap<Scope, BTreeSet<ObjectId>> = BTreeMap::new();
        let mut found: Vec<(Candidate<CacheEntry>, ObjectId)> = Vec::new();
        for held in self.store.representations() {
            let entry = CacheEntry::held(held);
            let Some(reservation) = self.reservation_of(&entry) else {
                continue;
            };
            let value = self.value_per_byte(&entry);
            let hold = if entry.kind.derived().is_none() {
                Hold::Pinned(PinnedBy::Original)
            } else if let Some(hold) = self.protected.get(&entry.object) {
                *hold
            } else if entry.tier == Tier::LocalStorage
                && !evictable
                    .entry(entry.object.scope.clone())
                    .or_insert_with(|| {
                        self.catalog
                            .eviction_candidates(&entry.object.scope)
                            .into_iter()
                            .map(|candidate| candidate.object)
                            .collect()
                    })
                    .contains(&entry.object.id())
            {
                Hold::Pinned(PinnedBy::CatalogKeeps)
            } else if self.rebuilds_resident_weights(&entry.object, entry.tier) {
                Hold::Pinned(PinnedBy::CanonicalCopyNeeded)
            } else if value.is_none() {
                Hold::Pinned(PinnedBy::Unvalued)
            } else {
                Hold::Free
            };
            let id = entry.object.id();
            found.push((
                Candidate {
                    work: entry,
                    reservations: vec![reservation],
                    hold,
                    rank: value.unwrap_or(f64::INFINITY),
                },
                id,
            ));
        }
        found.sort_by(|(left, left_id), (right, right_id)| {
            left.rank
                .total_cmp(&right.rank)
                .then_with(|| left_id.cmp(right_id))
        });
        found.into_iter().map(|(candidate, _)| candidate).collect()
    }

    /// Evicts the entry through its tier, then forgets it in the store. An original is
    /// refused.
    fn stop(&mut self, entry: &CacheEntry) -> Result<(), StopError> {
        let kind = entry.kind.derived().ok_or(StopError::Original)?;
        let eviction = PlannedEviction {
            model: entry.model.clone(),
            object: entry.object.clone(),
            kind,
            tier: entry.tier,
            bytes: entry.bytes,
        };
        {
            let mut ledger = lock(&self.ledger);
            let not_given = StopError::TierNotGiven { tier: entry.tier };
            match entry.tier {
                Tier::ReclaimableHost => {
                    let host = self.host.as_mut().ok_or(not_given)?;
                    host.evict(&eviction, &mut ledger)
                        .map_err(|refusal| StopError::Host(Box::new(refusal)))?;
                }
                Tier::PinnedHost => {
                    let (pinned, _) = self.pinned.as_mut().ok_or(not_given)?;
                    pinned
                        .evict(&eviction, &mut ledger)
                        .map_err(|refusal| StopError::Pinned(Box::new(refusal)))?;
                }
                Tier::LocalStorage => {
                    let (local, pool) = self.local.as_mut().ok_or(not_given)?;
                    local
                        .evict_cache(
                            pool,
                            self.catalog,
                            std::slice::from_ref(&eviction),
                            &mut ledger,
                        )
                        .map_err(|refusal| StopError::Local(Box::new(refusal)))?;
                }
                Tier::Gpu | Tier::AuthorizedPeer | Tier::Remote => return Err(not_given),
            }
        }
        self.store
            .forget(&eviction)
            .map(|_| ())
            .map_err(|refusal| StopError::Representation(Box::new(refusal)))
    }
}

impl<L: Clock> CacheSource for TierCaches<'_, L> {}
