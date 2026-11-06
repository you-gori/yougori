//! Reclaimable host RAM (table line 541): verified page cache and ordinary host copies,
//! under an explicit budget, with residency estimates that can go stale.
//!
//! The budget is a memory scope of T08's host check (`residency::host`), nested in host
//! RAM or the WSL VM. Every entry is charged to it in full, page cache as page cache,
//! whatever its estimated residency, until it is released, and usage observed in the
//! enclosing scopes is occupied, never free (§2.7 line 446). The entry alone is then
//! reserved as host RAM in the CORE-03 ledger through T08's ledger adapter
//! (`residency::reservation`), so the host counts it too, and it returns only through the
//! ledger.
//!
//! Reclaimable is not guaranteed resident: T08 guarantees none of it, and an estimate such
//! as mincore's is advisory. Here an estimate is used only while fresh, a stale one counts
//! as unknown, and only a fresh estimate that shows the whole entry resident lets the
//! entry serve as a source. Bytes enter only verified and through a catalog read handle
//! for exactly that object (line 546), and an entry serves only requesters in its
//! holder's tenant and trust scope (S3.3).

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::charge::{
    release, reserve_host_and_create, Charged, HostCharge, LedgerCharge, Released,
};
use super::object::{Consumer, ObjectCopy, ObjectRef};
use super::representations::{DerivedKind, PlannedEviction};
use super::source::{OfferRefusal, SourceOffer, SourcePath, TierRefusal};
use super::{instant, Tier};
use crate::foundation::catalog::{Catalog, ObjectId, ReadHandle, ReadRefusal};
use crate::foundation::ids::{Clock, MonotonicTime};
use crate::foundation::ledger::{CostPurpose, Ledger, LedgerError, ReservationId};
use crate::model_memory::math::SourceId;
use crate::model_memory::residency::eviction::{
    Content, CopyTier, ReconstructibleCopy, Verification as CopyVerification,
};
use crate::model_memory::residency::host::{
    admit_host, HostBacking, HostCopy, HostDemand, HostError, HostPlan, HostResidency, HostScope,
};
use crate::model_memory::residency::reservation::PlacementError;
use crate::model_memory::residency::Interval;

/// What an entry holds (table line 541).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostContent {
    /// Page cache over a verified file.
    VerifiedPageCache,
    /// An ordinary host copy, such as a loader's retained buffer.
    HostCopy,
}

/// Whether the bytes were verified against their content key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    Verified,
    Unverified,
}

/// One residency observation, such as from mincore: advisory, and stale after the
/// tier's maximum age.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidencyEstimate {
    pub resident_bytes: u64,
    pub observed_at: MonotonicTime,
}

/// What is known about an entry's residency now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Residency {
    /// An estimate younger than the maximum age: usable, still advisory.
    Fresh {
        resident_bytes: u64,
        age: Duration,
    },
    /// An estimate at or past the maximum age: treated as unknown.
    Stale {
        observed_at: MonotonicTime,
        age: Duration,
    },
    NeverObserved,
}

/// Why the reclaimable tier refused (table line 541).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostRefusal {
    ZeroBytes,
    /// The read handle is for another object than the one named.
    HandleMismatch {
        named: ObjectId,
        handle: ObjectId,
    },
    /// The catalog does not let the holder read the object: it is another scope's and no
    /// grant names exactly it and the holder's execution (line 546; S3.3). A read handle
    /// does not record who opened it, so the holder is checked itself.
    Unreadable(ReadRefusal),
    /// Only verified bytes enter the tier.
    Unverified {
        content: HostContent,
    },
    AlreadyHeld {
        object: ObjectRef,
    },
    /// T08's host check refused: the budget or an enclosing scope would be exceeded, or
    /// the scopes are malformed.
    Host(HostError),
    /// T08's ledger adapter would not build the entry's ledger request.
    Placement(PlacementError),
    /// The ledger refused the host RAM: the host's capacity or the tenant's budget
    /// (CORE-03).
    Ledger(LedgerError),
    NotHeld {
        object: ObjectRef,
    },
    EstimateExceedsEntry {
        resident_bytes: u64,
        entry_bytes: u64,
    },
    NoEstimate {
        object: ObjectRef,
    },
    StaleEstimate {
        object: ObjectRef,
        age: Duration,
    },
    NotFullyResident {
        object: ObjectRef,
        resident_bytes: u64,
        entry_bytes: u64,
    },
    /// The requester runs outside the holder's tenant or trust scope (S3.3).
    OutsideScope {
        requester: Box<Consumer>,
        holder: Box<Consumer>,
    },
    /// The operation is for the other kind of content.
    WrongContent {
        object: ObjectRef,
        content: HostContent,
    },
    /// The eviction belongs to another tier or names another kind.
    WrongEviction {
        tier: Tier,
        kind: DerivedKind,
    },
    /// The clock is at its last instant, so no interval starts now.
    ClockExhausted,
}

impl fmt::Display for HostRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroBytes => f.write_str("an entry has at least one byte"),
            Self::HandleMismatch { named, handle } => write!(
                f,
                "the read handle is for object {handle}, not the named object {named}"
            ),
            Self::Unreadable(refusal) => write!(f, "the holder may not read the object: {refusal}"),
            Self::Unverified { content } => {
                write!(
                    f,
                    "unverified {content:?} does not enter reclaimable host RAM"
                )
            }
            Self::AlreadyHeld { object } => write!(f, "{object} is already held"),
            Self::Host(error) => error.fmt(f),
            Self::Placement(error) => error.fmt(f),
            Self::Ledger(error) => error.fmt(f),
            Self::NotHeld { object } => write!(f, "{object} is not held"),
            Self::EstimateExceedsEntry {
                resident_bytes,
                entry_bytes,
            } => write!(
                f,
                "an estimate of {resident_bytes} resident bytes exceeds the {entry_bytes}-byte \
                 entry"
            ),
            Self::NoEstimate { object } => write!(f, "{object}'s residency was never observed"),
            Self::StaleEstimate { object, age } => write!(
                f,
                "{object}'s residency estimate is {} s old, which is stale",
                age.as_secs_f64()
            ),
            Self::NotFullyResident {
                object,
                resident_bytes,
                entry_bytes,
            } => write!(
                f,
                "only {resident_bytes} of {object}'s {entry_bytes} bytes are estimated resident"
            ),
            Self::OutsideScope { requester, holder } => write!(
                f,
                "{} may not read a host copy held by {}: sharing needs the same tenant and \
                 trust scope",
                requester.execution, holder.execution
            ),
            Self::WrongContent { object, content } => {
                write!(
                    f,
                    "{object} is {content:?}, not the content this operation is for"
                )
            }
            Self::WrongEviction { tier, kind } => {
                write!(f, "a {kind:?} eviction in {tier} is not this tier's")
            }
            Self::ClockExhausted => f.write_str("the clock is at its last instant"),
        }
    }
}

impl std::error::Error for HostRefusal {}

impl From<HostError> for HostRefusal {
    fn from(error: HostError) -> Self {
        Self::Host(error)
    }
}

impl From<LedgerError> for HostRefusal {
    fn from(error: LedgerError) -> Self {
        Self::Ledger(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HostEntry {
    holder: Consumer,
    content: HostContent,
    bytes: u64,
    estimate: Option<ResidencyEstimate>,
    reservation: ReservationId,
}

/// The host's reclaimable RAM (table line 541).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReclaimableHostTier {
    scopes: Vec<HostScope>,
    budget_scope: String,
    max_estimate_age: Duration,
    entries: BTreeMap<ObjectRef, HostEntry>,
}

impl ReclaimableHostTier {
    /// `scopes` are the T08 host scopes: host RAM, inside WSL the WSL VM, and the budget
    /// named `budget_scope`, a memory scope nested in them. An estimate is stale once it
    /// is `max_estimate_age` old.
    pub fn new(scopes: Vec<HostScope>, budget_scope: String, max_estimate_age: Duration) -> Self {
        Self {
            scopes,
            budget_scope,
            max_estimate_age,
            entries: BTreeMap::new(),
        }
    }

    /// Bytes charged to the budget: every entry in full, whatever its estimate.
    pub fn used_bytes(&self) -> u64 {
        self.entries
            .values()
            .fold(0u64, |total, entry| total.saturating_add(entry.bytes))
    }

    /// The ledger reservation holding an entry's host RAM.
    pub fn reservation_of(&self, object: &ObjectRef) -> Option<ReservationId> {
        self.entries.get(object).map(|entry| entry.reservation)
    }

    /// The T08 host plan of every entry held now, plus `adding` if given.
    pub fn host_plan(
        &self,
        adding: Option<(HostContent, u64)>,
        clock: &dyn Clock,
    ) -> Result<HostPlan, HostRefusal> {
        let during = instant(clock.now()).ok_or(HostRefusal::ClockExhausted)?;
        let mut demands = self.held(during);
        if let Some((content, bytes)) = adding {
            demands.push(self.demand(content, bytes, "new entry".to_string(), during));
        }
        Ok(self.plan(demands))
    }

    /// Admits a verified entry of `object`, which `holder` read through `handle`, and
    /// charges its true length in full: to the budget with every entry held now, then as
    /// host RAM in the ledger. The handle must be for exactly that object, and the catalog
    /// must let the holder itself read it: its own scope's, or another's under a live
    /// grant for that object and execution (line 546).
    #[allow(clippy::too_many_arguments)]
    pub fn admit<C: Clock>(
        &mut self,
        holder: &Consumer,
        object: ObjectRef,
        handle: &ReadHandle,
        catalog: &Catalog,
        content: HostContent,
        verification: Verification,
        charge: &LedgerCharge,
        ledger: &mut Ledger<C>,
        clock: &dyn Clock,
    ) -> Result<(), HostRefusal> {
        if handle.object() != object.id() {
            return Err(HostRefusal::HandleMismatch {
                named: object.id(),
                handle: handle.object(),
            });
        }
        catalog
            .object_view(&holder.scope(), &holder.execution, object.id())
            .map_err(HostRefusal::Unreadable)?;
        let bytes = handle.length_bytes();
        if bytes == 0 {
            return Err(HostRefusal::ZeroBytes);
        }
        if verification != Verification::Verified {
            return Err(HostRefusal::Unverified { content });
        }
        if self.entries.contains_key(&object) {
            return Err(HostRefusal::AlreadyHeld { object });
        }
        let during = instant(clock.now()).ok_or(HostRefusal::ClockExhausted)?;
        let new = self.demand(content, bytes, "new entry".to_string(), during);
        let mut demands = self.held(during);
        demands.push(new.clone());
        // The budget and every enclosing scope, with every entry held now.
        admit_host(&self.plan(demands))?;
        // The new entry alone becomes the ledger request.
        let reservation = reserve_host_and_create(
            ledger,
            charge,
            Charged {
                tenant: &holder.tenant,
                execution: &holder.execution,
                purpose: CostPurpose::Storage,
                parent: None,
            },
            &self.plan(vec![new]),
        )
        .map_err(|error| match error {
            HostCharge::Placement(error) => HostRefusal::Placement(error),
            HostCharge::Ledger(error) => HostRefusal::Ledger(error),
        })?;
        self.entries.insert(
            object,
            HostEntry {
                holder: holder.clone(),
                content,
                bytes,
                estimate: None,
                reservation,
            },
        );
        Ok(())
    }

    /// Records a residency estimate observed now. It changes no charge.
    pub fn observe(
        &mut self,
        object: &ObjectRef,
        resident_bytes: u64,
        clock: &dyn Clock,
    ) -> Result<(), HostRefusal> {
        let entry = self
            .entries
            .get_mut(object)
            .ok_or_else(|| HostRefusal::NotHeld {
                object: object.clone(),
            })?;
        if resident_bytes > entry.bytes {
            return Err(HostRefusal::EstimateExceedsEntry {
                resident_bytes,
                entry_bytes: entry.bytes,
            });
        }
        entry.estimate = Some(ResidencyEstimate {
            resident_bytes,
            observed_at: clock.now(),
        });
        Ok(())
    }

    /// The entry's residency now: fresh, stale or never observed.
    pub fn residency(
        &self,
        object: &ObjectRef,
        clock: &dyn Clock,
    ) -> Result<Residency, HostRefusal> {
        let entry = self.entry(object)?;
        Ok(self.residency_of(entry, clock.now()))
    }

    /// The entry as T08 sees it: reclaimable, so none of it is guaranteed resident; a
    /// fresh estimate is passed on as advisory, a stale one not at all.
    pub fn host_copy(
        &self,
        object: &ObjectRef,
        clock: &dyn Clock,
    ) -> Result<HostCopy, HostRefusal> {
        let entry = self.entry(object)?;
        let mincore_resident_bytes = match self.residency_of(entry, clock.now()) {
            Residency::Fresh { resident_bytes, .. } => Some(resident_bytes),
            Residency::Stale { .. } | Residency::NeverObserved => None,
        };
        Ok(HostCopy {
            bytes: entry.bytes,
            residency: HostResidency::Reclaimable {
                mincore_resident_bytes,
            },
        })
    }

    /// A verified copy of the object held here, in its holder's memory. T08 does not let
    /// it reconstruct a dropped GPU copy, because reclaimable memory may vanish.
    pub fn copy_of(&self, object: &ObjectRef) -> Option<ObjectCopy> {
        let entry = self.entries.get(object)?;
        Some(ObjectCopy {
            object: object.clone(),
            holder: Some(entry.holder.clone()),
            copy: ReconstructibleCopy {
                tier: CopyTier::ReclaimableHost,
                verification: CopyVerification::Verified {
                    content: Content::Immutable(object.content),
                },
            },
        })
    }

    /// Stops charging a page-cache entry, such as after dropping it, and gives its host
    /// RAM back through the ledger.
    pub fn release_page_cache<C: Clock>(
        &mut self,
        object: &ObjectRef,
        ledger: &mut Ledger<C>,
    ) -> Result<Released, HostRefusal> {
        self.remove(object, HostContent::VerifiedPageCache, ledger)
    }

    /// Carries out a planned eviction of a host copy.
    pub fn evict<C: Clock>(
        &mut self,
        eviction: &PlannedEviction,
        ledger: &mut Ledger<C>,
    ) -> Result<Released, HostRefusal> {
        if eviction.tier != Tier::ReclaimableHost || eviction.kind != DerivedKind::HostCopy {
            return Err(HostRefusal::WrongEviction {
                tier: eviction.tier,
                kind: eviction.kind,
            });
        }
        self.remove(&eviction.object, HostContent::HostCopy, ledger)
    }

    /// Offers an entry as a source to a requester in the holder's tenant and trust scope,
    /// only while a fresh estimate shows all of it resident.
    pub fn offer(
        &self,
        source: SourceId,
        object: &ObjectRef,
        requester: &Consumer,
        path: SourcePath,
        clock: &dyn Clock,
    ) -> Result<SourceOffer, OfferRefusal> {
        let refuse =
            |refusal| OfferRefusal::new(&source, Tier::ReclaimableHost, TierRefusal::Host(refusal));
        let entry = self.entry(object).map_err(refuse)?;
        if !entry.holder.shares_trust_with(requester) {
            return Err(refuse(HostRefusal::OutsideScope {
                requester: Box::new(requester.clone()),
                holder: Box::new(entry.holder.clone()),
            }));
        }
        match self.residency_of(entry, clock.now()) {
            Residency::Fresh { resident_bytes, .. } if resident_bytes == entry.bytes => {}
            Residency::Fresh { resident_bytes, .. } => {
                return Err(refuse(HostRefusal::NotFullyResident {
                    object: object.clone(),
                    resident_bytes,
                    entry_bytes: entry.bytes,
                }))
            }
            Residency::Stale { age, .. } => {
                return Err(refuse(HostRefusal::StaleEstimate {
                    object: object.clone(),
                    age,
                }))
            }
            Residency::NeverObserved => {
                return Err(refuse(HostRefusal::NoEstimate {
                    object: object.clone(),
                }))
            }
        }
        let covers_bytes = entry.bytes;
        Ok(SourceOffer::new(
            Tier::ReclaimableHost,
            source,
            object.clone(),
            requester,
            path,
            covers_bytes,
        ))
    }

    fn entry(&self, object: &ObjectRef) -> Result<&HostEntry, HostRefusal> {
        self.entries
            .get(object)
            .ok_or_else(|| HostRefusal::NotHeld {
                object: object.clone(),
            })
    }

    fn residency_of(&self, entry: &HostEntry, now: MonotonicTime) -> Residency {
        match entry.estimate {
            None => Residency::NeverObserved,
            Some(estimate) => {
                let age = now.saturating_duration_since(estimate.observed_at);
                if age < self.max_estimate_age {
                    Residency::Fresh {
                        resident_bytes: estimate.resident_bytes,
                        age,
                    }
                } else {
                    Residency::Stale {
                        observed_at: estimate.observed_at,
                        age,
                    }
                }
            }
        }
    }

    /// One entry as T08 demand on the budget: page cache as page cache, a host copy as
    /// anonymous memory.
    fn demand(
        &self,
        content: HostContent,
        bytes: u64,
        label: String,
        during: Interval,
    ) -> HostDemand {
        HostDemand {
            label,
            backing: match content {
                HostContent::VerifiedPageCache => HostBacking::PageCache,
                HostContent::HostCopy => HostBacking::Anonymous,
            },
            bytes,
            during,
            memory_scope: self.budget_scope.clone(),
            pinned_scope: None,
        }
    }

    /// The demands of every entry held now.
    fn held(&self, during: Interval) -> Vec<HostDemand> {
        self.entries
            .values()
            .enumerate()
            .map(|(index, entry)| {
                self.demand(
                    entry.content,
                    entry.bytes,
                    format!("reclaimable entry {index}"),
                    during,
                )
            })
            .collect()
    }

    fn plan(&self, demands: Vec<HostDemand>) -> HostPlan {
        HostPlan {
            scopes: self.scopes.clone(),
            demands,
        }
    }

    fn remove<C: Clock>(
        &mut self,
        object: &ObjectRef,
        content: HostContent,
        ledger: &mut Ledger<C>,
    ) -> Result<Released, HostRefusal> {
        let entry = self.entry(object)?;
        if entry.content != content {
            return Err(HostRefusal::WrongContent {
                object: object.clone(),
                content: entry.content,
            });
        }
        let released = release(ledger, entry.reservation, entry.bytes)?;
        self.entries.remove(object);
        Ok(released)
    }
}

#[cfg(test)]
mod tests;
