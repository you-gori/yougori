//! Storage tiers and representation retention: GPU §3.4 of
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md (lines 535–553), with the §1.1 rows at
//! lines 306 and 312 and the §2.7 accounting at lines 444–448.
//!
//! - [`Tier`]: the six tiers of the table at lines 537–544. Each has its own module and
//!   accounting rule: [`gpu`] counts physical allocations and references, never mapped
//!   bytes; [`pinned`] keeps a hard host-wide cap with memlock and WSL limits; [`host`]
//!   budgets reclaimable RAM whose residency estimates go stale; [`local`] charges quotas
//!   in an existing user-selected pool, a tenant's or the host's budget holder's for
//!   Yougori's own artifacts; [`peer`] checks an expiring authorization, a donor budget
//!   and topology; [`remote`] keeps resumable verified ranges under egress and access
//!   policy.
//! - [`charge`]: VRAM, host RAM, pinned host RAM and storage quota are reserved in the
//!   CORE-03 ledger (T04), the capacity authority; a tier adds only its own rule (§3.1
//!   line 491). Host and pinned RAM go through T08's ledger adapter
//!   (`model_memory::residency::reservation`), so a pin is charged as host RAM and as
//!   pinned RAM.
//! - The CORE-02 catalog (T05) is used directly. Only its importer writes committed
//!   content, and consumers reach bytes only through its read-only handles; equal content
//!   in another scope is readable only under its grant for that exact object (lines
//!   546–552). Its cache eviction, local model deletion and source-file deletion stay
//!   distinct operations of [`local::LocalStorageTier`]. [`object`] names its objects
//!   and the consumers that read them.
//! - T08's residency module checks the pinned and reclaimable tiers' host scopes, takes
//!   the GPU tier's physical allocations into the §2.7 VRAM plan, and decides clean GPU
//!   drops from the verified copies each tier reports.
//! - [`amortization`] and [`representations`]: more than one representation of a model
//!   needs an explicit space budget, a derived one is prepared only when it amortizes and
//!   kept only while its measured reuse does, and evictions are planned by measured value,
//!   never naming an original (lines 548–552).
//! - [`source`]: where bytes come from is chosen by completion time, authorization and
//!   interference (line 312), planned by T03's [`crate::model_memory::math::sources`].
//!
//! Pure, synchronous and deterministic. Time comes from [`crate::foundation::ids::Clock`].

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::MonotonicTime;
use crate::model_memory::residency::eviction::CopyTier;
use crate::model_memory::residency::Interval;

pub mod amortization;
pub mod charge;
pub mod gpu;
pub mod host;
pub mod local;
pub mod object;
pub mod peer;
pub mod pinned;
pub mod remote;
pub mod representations;
pub mod source;

#[cfg(test)]
mod fakes;

pub use amortization::{MeasuredReuse, ReuseRecord};
pub use charge::{LedgerCharge, Released};
pub use gpu::{
    AllocationHandle, GpuContent, GpuRefusal, GpuTier, MappingId, MutableState, ReferenceHolder,
};
pub use host::{
    HostContent, HostRefusal, ReclaimableHostTier, Residency, ResidencyEstimate, Verification,
};
pub use local::{
    HostBudgetHolder, LocalRefusal, LocalStorageTier, NotRecorded, PoolId, PoolPresence,
    PoolSelection, Removal, StoragePool, StorageReservation, UnreleasedReservation,
};
pub use object::{Consumer, ObjectCopy, ObjectRef};
pub use peer::{PeerAuthorization, PeerContent, PeerRefusal, PeerSource, TransferConsent};
pub use pinned::{
    CopyState, MemlockLimit, PinId, PinnedContent, PinnedHostTier, PinnedLimits, PinnedRefusal,
    WslLimit,
};
pub use remote::{
    range_digest, RangeSpec, RangeTransfer, RemoteContent, RemotePolicy, RemoteRefusal,
    RemoteSource, RANGE_DOMAIN,
};
pub use representations::{
    BudgetEnforcement, DerivedKind, HeldRepresentation, ModelKey, PlannedEviction,
    RepresentationKind, RepresentationProposal, RepresentationRefusal, RepresentationStore,
    SpaceBudget,
};
pub use source::{
    choose_source, ExcludedSource, ExclusionReason, OfferRefusal, SourceChoice, SourceChoiceError,
    SourceOffer, SourcePath, SourceRequest, TierRefusal,
};

/// The six storage tiers of GPU §3.4, in the order of the table at lines 537–544.
///
/// No tier precedes another as a source: [`source::choose_source`] decides by completion
/// time, authorization and interference (line 312).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Immutable weights and separate mutable KV, scratch and graph resources, counted as
    /// physical allocations and references, not mapped bytes ([`gpu`]).
    Gpu,
    /// Small rings and selected high-value clean representations under a hard host-wide
    /// cap, memlock and WSL limits ([`pinned`]).
    PinnedHost,
    /// Verified page cache and ordinary host copies, budgeted, with residency estimates
    /// that can go stale ([`host`]).
    ReclaimableHost,
    /// Original and prepared immutable artifacts under quotas in an existing
    /// user-selected pool ([`local`]).
    LocalStorage,
    /// Eligible immutable weights or explicitly transferable state under an expiring
    /// authorization and a donor budget, planned with its topology ([`peer`]).
    AuthorizedPeer,
    /// Original or publisher-prepared artifacts fetched in resumable verified ranges
    /// under egress and access policy ([`remote`]).
    Remote,
}

impl Tier {
    /// Every tier, in the table's order.
    pub const ALL: [Self; 6] = [
        Self::Gpu,
        Self::PinnedHost,
        Self::ReclaimableHost,
        Self::LocalStorage,
        Self::AuthorizedPeer,
        Self::Remote,
    ];

    /// The T08 copy tier (`residency::eviction`); `None` for the GPU, whose copies are the
    /// ones being evicted.
    pub const fn copy_tier(self) -> Option<CopyTier> {
        match self {
            Self::Gpu => None,
            Self::PinnedHost => Some(CopyTier::PinnedHost),
            Self::ReclaimableHost => Some(CopyTier::ReclaimableHost),
            Self::LocalStorage => Some(CopyTier::LocalStorage),
            Self::AuthorizedPeer => Some(CopyTier::AuthorizedPeer),
            Self::Remote => Some(CopyTier::RemoteSource),
        }
    }

    /// The tier's name as the table words it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Gpu => "GPU",
            Self::PinnedHost => "pinned host RAM",
            Self::ReclaimableHost => "reclaimable host RAM",
            Self::LocalStorage => "local storage",
            Self::AuthorizedPeer => "authorized peer",
            Self::Remote => "remote object/source",
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The instant `now` as a T08 interval, for checks of what is held now; `None` at the
/// clock's last instant.
fn instant(now: MonotonicTime) -> Option<Interval> {
    now.checked_add(Duration::from_nanos(1))
        .and_then(|end| Interval::new(now, end).ok())
}

/// The sum of `values`, or `None` when it does not fit in 64 bits.
fn checked_sum(values: impl IntoIterator<Item = u64>) -> Option<u64> {
    values
        .into_iter()
        .try_fold(0u64, |total, value| total.checked_add(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn six_tiers_in_the_order_of_the_table() {
        assert_eq!(
            Tier::ALL.map(Tier::name),
            [
                "GPU",
                "pinned host RAM",
                "reclaimable host RAM",
                "local storage",
                "authorized peer",
                "remote object/source",
            ]
        );
        let mut sorted = Tier::ALL;
        sorted.sort();
        assert_eq!(sorted, Tier::ALL);
        assert_eq!(
            serde_json::to_string(&Tier::AuthorizedPeer).unwrap(),
            "\"authorized_peer\""
        );
        assert_eq!(Tier::Remote.to_string(), "remote object/source");
    }

    #[test]
    fn only_pinned_host_ram_and_local_storage_guarantee_a_copy_stays() {
        // T08: only these copies can stand in for a dropped GPU copy (line 307).
        let guaranteed: Vec<Tier> = Tier::ALL
            .into_iter()
            .filter(|tier| {
                tier.copy_tier()
                    .is_some_and(CopyTier::guarantees_availability)
            })
            .collect();
        assert_eq!(guaranteed, [Tier::PinnedHost, Tier::LocalStorage]);
        assert_eq!(Tier::Gpu.copy_tier(), None);
        assert_eq!(Tier::Remote.copy_tier(), Some(CopyTier::RemoteSource));
    }

    #[test]
    fn an_instant_ends_one_nanosecond_later_and_never_overflows() {
        let now = MonotonicTime::from_nanos(5);
        let during = instant(now).unwrap();
        assert_eq!((during.start(), during.length_nanos()), (now, 1));
        assert_eq!(instant(MonotonicTime::from_nanos(u64::MAX)), None);
    }

    #[test]
    fn sums_refuse_to_overflow() {
        assert_eq!(checked_sum([1, 2, 3]), Some(6));
        assert_eq!(checked_sum([u64::MAX, 1]), None);
        assert_eq!(checked_sum([]), Some(0));
    }
}
