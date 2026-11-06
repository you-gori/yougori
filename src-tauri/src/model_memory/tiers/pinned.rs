//! Pinned host RAM (table line 540): small staging rings and selected high-value clean
//! representations, under a hard host-wide cap, memlock and WSL limits.
//!
//! Every pin is first admitted by T08's host check (`residency::host`) with every pin
//! held now as pinned demand: host RAM, inside WSL the WSL VM's memory scope, the hard
//! host-wide cap as the one root pinned-memory scope, and each execution's memlock limit
//! nested under it. Observed usage, page cache included, is occupied and never free
//! (§2.7 line 446). An unknown WSL or memlock limit is not an unlimited one, so nothing is
//! pinned until it is known. The new pin alone then goes through T08's ledger adapter
//! (`residency::reservation`), which reserves it in the CORE-03 ledger as host RAM and as
//! pinned RAM (decision T08). The ledger keeps the host's pinned RAM across every
//! runtime, and a pin returns only through it.
//!
//! Rings are small, and a representation is pinned only through a catalog read handle
//! for it, as a verified clean copy whose value satisfies the catalog's
//! [`ImportAmortization`] (line 550): that is what "selected high-value clean" asks. A pin
//! belongs to its owner's process, so it serves only requesters in the owner's tenant and
//! trust scope (S3.3).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::charge::{
    release, reserve_host_and_create, Charged, HostCharge, LedgerCharge, Released,
};
use super::object::{Consumer, ObjectCopy, ObjectRef};
use super::representations::{DerivedKind, PlannedEviction};
use super::source::{OfferRefusal, SourceOffer, SourcePath, TierRefusal};
use super::{instant, Tier};
use crate::foundation::catalog::{
    AmortizationError, Catalog, ImportAmortization, ObjectId, ReadHandle, ReadRefusal,
};
use crate::foundation::ids::{Clock, ExecutionId};
use crate::foundation::ledger::{CostPurpose, Ledger, LedgerError, ReservationId};
use crate::model_memory::math::SourceId;
use crate::model_memory::residency::eviction::{
    Content, CopyTier, ReconstructibleCopy, Verification,
};
use crate::model_memory::residency::host::{
    admit_host, HostBacking, HostDemand, HostError, HostPlan, HostScope, HostScopeKind,
    ScopeOccupancy,
};
use crate::model_memory::residency::reservation::PlacementError;
use crate::model_memory::residency::{Capacity, Interval};

/// An execution's locked-memory limit (RLIMIT_MEMLOCK).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemlockLimit {
    Bytes(u64),
    Unlimited,
    /// Not observed yet; pinning is refused.
    Unknown,
}

/// The WSL VM's memory scope, when the runtime is inside WSL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WslLimit {
    /// Not a WSL runtime: pins are charged to host RAM directly.
    NotWsl,
    /// The WSL VM's memory scope, nested in host RAM; pins are charged to it as well.
    Vm(HostScope),
    /// A WSL runtime whose limit was not observed: nothing is pinned.
    Unknown,
}

/// The tier's limits (table line 540), as T08 host scopes whose capacities come from the
/// ledger or the host's configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedLimits {
    /// Host RAM, the root memory scope, with its observed occupancy.
    pub host_ram: HostScope,
    pub wsl: WslLimit,
    /// The hard host-wide cap: the one root pinned-memory scope.
    pub host_wide_cap: HostScope,
    /// The reserve each execution's memlock scope keeps; the §2.7 inequality keeps one in
    /// every scope, so zero is refused.
    pub memlock_reserve_bytes: u64,
    /// Largest staging ring: rings are small.
    pub max_ring_bytes: u64,
}

/// Whether a host copy is identical to its verified committed object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CopyState {
    VerifiedClean,
    Unverified,
    Dirty,
}

/// What a pin holds (table line 540).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PinnedContent {
    StagingRing,
    CleanRepresentation { object: ObjectRef },
}

impl PinnedContent {
    /// Whether this is a clean representation of exactly `object`.
    pub fn represents(&self, object: &ObjectRef) -> bool {
        matches!(self, Self::CleanRepresentation { object: held } if held == object)
    }
}

/// One pin; never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PinId(u64);

/// Why the pinned tier refused (table line 540).
#[derive(Clone, Debug, PartialEq)]
pub enum PinnedRefusal {
    ZeroBytes,
    /// T08's host check refused: the hard host-wide cap, a memlock limit, the WSL VM or
    /// host RAM would be exceeded with every pin held now, or the scopes are malformed.
    Host(HostError),
    /// T08's ledger adapter would not build the pin's ledger request.
    Placement(PlacementError),
    /// The ledger refused: the host's host RAM or pinned RAM, or the tenant's budget
    /// (CORE-03).
    Ledger(LedgerError),
    /// The runtime is inside WSL and its limit is unknown.
    WslLimitUnknown,
    UnregisteredExecution {
        execution: ExecutionId,
    },
    MemlockUnknown {
        execution: ExecutionId,
    },
    /// Rings are small.
    RingTooLarge {
        max_ring_bytes: u64,
        requested_bytes: u64,
    },
    /// Only verified clean representations are pinned.
    NotClean {
        state: CopyState,
    },
    /// The read handle is for another object than the one named.
    HandleMismatch {
        named: ObjectId,
        handle: ObjectId,
    },
    /// The catalog does not let the owner read the object: it is another scope's and no
    /// grant names exactly it and the owner's execution (line 546; S3.3). A read handle
    /// does not record who opened it, so the owner is checked itself.
    Unreadable(ReadRefusal),
    Amortization(AmortizationError),
    /// The representation's value does not amortize, so it is not selected.
    NotSelected {
        benefit_seconds: f64,
        cost_seconds: f64,
    },
    AlreadyPinned {
        object: ObjectRef,
    },
    UnknownPin {
        pin: PinId,
    },
    PinsExhausted,
    /// No clean representation of the object is pinned.
    NotPinned {
        object: ObjectRef,
    },
    /// The requester runs outside the pin owner's tenant or trust scope (S3.3).
    OutsideScope {
        requester: Box<Consumer>,
        owner: Box<Consumer>,
    },
    /// The eviction belongs to another tier or names another kind.
    WrongEviction {
        tier: Tier,
        kind: DerivedKind,
    },
    /// The clock is at its last instant, so no interval starts now.
    ClockExhausted,
}

impl fmt::Display for PinnedRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroBytes => f.write_str("a pin has at least one byte"),
            Self::Host(error) => error.fmt(f),
            Self::Placement(error) => error.fmt(f),
            Self::Ledger(error) => error.fmt(f),
            Self::WslLimitUnknown => f.write_str(
                "the runtime is inside WSL and its memory limit is unknown; nothing is pinned \
                 until it is known",
            ),
            Self::UnregisteredExecution { execution } => {
                write!(f, "{execution} has no recorded memlock limit")
            }
            Self::MemlockUnknown { execution } => {
                write!(f, "{execution}'s memlock limit is unknown")
            }
            Self::RingTooLarge {
                max_ring_bytes,
                requested_bytes,
            } => write!(
                f,
                "a {requested_bytes}-byte ring exceeds the {max_ring_bytes}-byte ring limit"
            ),
            Self::NotClean { state } => {
                write!(
                    f,
                    "only verified clean copies are pinned, not {state:?} ones"
                )
            }
            Self::HandleMismatch { named, handle } => write!(
                f,
                "the read handle is for object {handle}, not the named object {named}"
            ),
            Self::Unreadable(refusal) => write!(f, "the owner may not read the object: {refusal}"),
            Self::Amortization(error) => error.fmt(f),
            Self::NotSelected {
                benefit_seconds,
                cost_seconds,
            } => write!(
                f,
                "its value ({benefit_seconds} s) does not exceed its cost ({cost_seconds} s), \
                 so it is not selected for pinning"
            ),
            Self::AlreadyPinned { object } => write!(f, "{object} is already pinned"),
            Self::UnknownPin { pin } => write!(f, "pin {} is unknown", pin.0),
            Self::PinsExhausted => f.write_str("no pin identifier is left"),
            Self::NotPinned { object } => write!(f, "{object} is not pinned"),
            Self::OutsideScope { requester, owner } => write!(
                f,
                "{} may not read memory pinned by {}: sharing needs the same tenant and \
                 trust scope",
                requester.execution, owner.execution
            ),
            Self::WrongEviction { tier, kind } => {
                write!(f, "a {kind:?} eviction in {tier} is not this tier's")
            }
            Self::ClockExhausted => f.write_str("the clock is at its last instant"),
        }
    }
}

impl std::error::Error for PinnedRefusal {}

impl From<LedgerError> for PinnedRefusal {
    fn from(error: LedgerError) -> Self {
        Self::Ledger(error)
    }
}

impl From<HostError> for PinnedRefusal {
    fn from(error: HostError) -> Self {
        Self::Host(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PinnedEntry {
    owner: Consumer,
    content: PinnedContent,
    bytes: u64,
    reservation: ReservationId,
}

/// The host's pinned RAM as this runtime uses it (table line 540).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedHostTier {
    limits: PinnedLimits,
    memlock: BTreeMap<ExecutionId, MemlockLimit>,
    entries: BTreeMap<PinId, PinnedEntry>,
    next_pin: u64,
}

impl PinnedHostTier {
    pub fn new(limits: PinnedLimits) -> Self {
        Self {
            limits,
            memlock: BTreeMap::new(),
            entries: BTreeMap::new(),
            next_pin: 0,
        }
    }

    pub fn limits(&self) -> &PinnedLimits {
        &self.limits
    }

    /// Records an execution's observed memlock limit.
    pub fn register_execution(&mut self, execution: ExecutionId, memlock: MemlockLimit) {
        self.memlock.insert(execution, memlock);
    }

    /// Bytes this tier's pins hold. The ledger's reservations, not this tally, are the
    /// host's pinned RAM.
    pub fn pinned_bytes(&self) -> u64 {
        self.entries
            .values()
            .fold(0u64, |total, entry| total.saturating_add(entry.bytes))
    }

    /// Bytes one execution's pins hold.
    pub fn pinned_bytes_of(&self, execution: &ExecutionId) -> u64 {
        self.entries
            .values()
            .filter(|entry| entry.owner.execution == *execution)
            .fold(0u64, |total, entry| total.saturating_add(entry.bytes))
    }

    /// The ledger reservation of a pin.
    pub fn reservation(&self, pin: PinId) -> Result<ReservationId, PinnedRefusal> {
        self.entries
            .get(&pin)
            .map(|entry| entry.reservation)
            .ok_or(PinnedRefusal::UnknownPin { pin })
    }

    /// The T08 host plan of every pin held now, plus `adding` if given.
    pub fn host_plan(
        &self,
        adding: Option<(&Consumer, u64)>,
        clock: &dyn Clock,
    ) -> Result<HostPlan, PinnedRefusal> {
        let during = instant(clock.now()).ok_or(PinnedRefusal::ClockExhausted)?;
        let (mut plan, mut demands) = self.held(during)?;
        if let Some((owner, bytes)) = adding {
            demands.push(plan.demand(&owner.execution, bytes, "new pin".to_string())?);
        }
        Ok(plan.with(demands))
    }

    /// Pins a staging ring no larger than the ring limit.
    pub fn pin_ring<C: Clock>(
        &mut self,
        owner: &Consumer,
        bytes: u64,
        charge: &LedgerCharge,
        ledger: &mut Ledger<C>,
        clock: &dyn Clock,
    ) -> Result<PinId, PinnedRefusal> {
        if bytes > self.limits.max_ring_bytes {
            return Err(PinnedRefusal::RingTooLarge {
                max_ring_bytes: self.limits.max_ring_bytes,
                requested_bytes: bytes,
            });
        }
        self.pin(
            owner,
            PinnedContent::StagingRing,
            bytes,
            CostPurpose::Transfer,
            charge,
            ledger,
            clock,
        )
    }

    /// Pins a verified clean copy of `object`, read by `owner` through `handle`, whose
    /// value satisfies line 550. Its size is the object's true length. The handle must be
    /// for exactly that object, and the catalog must let the owner itself read it: its own
    /// scope's, or another's under a live grant for that object and execution (line 546).
    #[allow(clippy::too_many_arguments)]
    pub fn pin_representation<C: Clock>(
        &mut self,
        owner: &Consumer,
        object: &ObjectRef,
        handle: &ReadHandle,
        catalog: &Catalog,
        state: CopyState,
        value: &ImportAmortization,
        charge: &LedgerCharge,
        ledger: &mut Ledger<C>,
        clock: &dyn Clock,
    ) -> Result<PinId, PinnedRefusal> {
        if handle.object() != object.id() {
            return Err(PinnedRefusal::HandleMismatch {
                named: object.id(),
                handle: handle.object(),
            });
        }
        catalog
            .object_view(&owner.scope(), &owner.execution, object.id())
            .map_err(PinnedRefusal::Unreadable)?;
        if state != CopyState::VerifiedClean {
            return Err(PinnedRefusal::NotClean { state });
        }
        if !value.amortizes().map_err(PinnedRefusal::Amortization)? {
            return Err(PinnedRefusal::NotSelected {
                benefit_seconds: value
                    .expected_saving_seconds()
                    .map_err(PinnedRefusal::Amortization)?,
                cost_seconds: value
                    .total_cost_seconds()
                    .map_err(PinnedRefusal::Amortization)?,
            });
        }
        if self.pin_of(object).is_some() {
            return Err(PinnedRefusal::AlreadyPinned {
                object: object.clone(),
            });
        }
        self.pin(
            owner,
            PinnedContent::CleanRepresentation {
                object: object.clone(),
            },
            handle.length_bytes(),
            CostPurpose::Storage,
            charge,
            ledger,
            clock,
        )
    }

    /// Releases a pin and gives its reservation back to the ledger.
    pub fn unpin<C: Clock>(
        &mut self,
        pin: PinId,
        ledger: &mut Ledger<C>,
    ) -> Result<Released, PinnedRefusal> {
        let entry = self
            .entries
            .get(&pin)
            .ok_or(PinnedRefusal::UnknownPin { pin })?;
        let released = release(ledger, entry.reservation, entry.bytes)?;
        self.entries.remove(&pin);
        Ok(released)
    }

    /// Carries out a planned eviction of a pinned host copy.
    pub fn evict<C: Clock>(
        &mut self,
        eviction: &PlannedEviction,
        ledger: &mut Ledger<C>,
    ) -> Result<Released, PinnedRefusal> {
        if eviction.tier != Tier::PinnedHost || eviction.kind != DerivedKind::HostCopy {
            return Err(PinnedRefusal::WrongEviction {
                tier: eviction.tier,
                kind: eviction.kind,
            });
        }
        let pin = self
            .pin_of(&eviction.object)
            .ok_or_else(|| PinnedRefusal::NotPinned {
                object: eviction.object.clone(),
            })?;
        self.unpin(pin, ledger)
    }

    /// A pinned clean copy of the object, held under the hard cap in its owner's memory:
    /// verified and reconstructing (T08 `residency::eviction`) for GPU memory of the
    /// owner's tenant and trust scope.
    pub fn copy_of(&self, object: &ObjectRef) -> Option<ObjectCopy> {
        let entry = self.pin_of(object).and_then(|pin| self.entries.get(&pin))?;
        Some(ObjectCopy {
            object: object.clone(),
            holder: Some(entry.owner.clone()),
            copy: ReconstructibleCopy {
                tier: CopyTier::PinnedHost,
                verification: Verification::Verified {
                    content: Content::Immutable(object.content),
                },
            },
        })
    }

    /// Offers a pinned clean representation as a source to a requester in the owner's
    /// tenant and trust scope.
    pub fn offer(
        &self,
        source: SourceId,
        object: &ObjectRef,
        requester: &Consumer,
        path: SourcePath,
    ) -> Result<SourceOffer, OfferRefusal> {
        let refuse =
            |refusal| OfferRefusal::new(&source, Tier::PinnedHost, TierRefusal::Pinned(refusal));
        let entry = self
            .pin_of(object)
            .and_then(|pin| self.entries.get(&pin))
            .ok_or_else(|| {
                refuse(PinnedRefusal::NotPinned {
                    object: object.clone(),
                })
            })?;
        if !entry.owner.shares_trust_with(requester) {
            return Err(refuse(PinnedRefusal::OutsideScope {
                requester: Box::new(requester.clone()),
                owner: Box::new(entry.owner.clone()),
            }));
        }
        let covers_bytes = entry.bytes;
        Ok(SourceOffer::new(
            Tier::PinnedHost,
            source,
            object.clone(),
            requester,
            path,
            covers_bytes,
        ))
    }

    fn pin_of(&self, object: &ObjectRef) -> Option<PinId> {
        self.entries
            .iter()
            .find(|(_, entry)| entry.content.represents(object))
            .map(|(pin, _)| *pin)
    }

    /// The scopes of a plan and the demands of every pin held now.
    fn held(&self, during: Interval) -> Result<(PinPlan<'_>, Vec<HostDemand>), PinnedRefusal> {
        let mut plan = PinPlan::new(self, during)?;
        let mut demands = Vec::with_capacity(self.entries.len() + 1);
        for (pin, entry) in &self.entries {
            demands.push(plan.demand(
                &entry.owner.execution,
                entry.bytes,
                format!("pin {}", pin.0),
            )?);
        }
        Ok((plan, demands))
    }

    #[allow(clippy::too_many_arguments)]
    fn pin<C: Clock>(
        &mut self,
        owner: &Consumer,
        content: PinnedContent,
        bytes: u64,
        purpose: CostPurpose,
        charge: &LedgerCharge,
        ledger: &mut Ledger<C>,
        clock: &dyn Clock,
    ) -> Result<PinId, PinnedRefusal> {
        if bytes == 0 {
            return Err(PinnedRefusal::ZeroBytes);
        }
        let during = instant(clock.now()).ok_or(PinnedRefusal::ClockExhausted)?;
        let (mut plan, mut demands) = self.held(during)?;
        let new = plan.demand(&owner.execution, bytes, "new pin".to_string())?;
        demands.push(new.clone());
        // The hard cap, memlock limits, the WSL VM and host RAM, with every pin held now.
        admit_host(&plan.with(demands))?;
        // The new pin alone becomes the ledger request.
        let request = plan.with(vec![new]);
        let pin = PinId(self.next_pin);
        let next_pin = self
            .next_pin
            .checked_add(1)
            .ok_or(PinnedRefusal::PinsExhausted)?;
        let reservation = reserve_host_and_create(
            ledger,
            charge,
            Charged {
                tenant: &owner.tenant,
                execution: &owner.execution,
                purpose,
                parent: None,
            },
            &request,
        )
        .map_err(|error| match error {
            HostCharge::Placement(error) => PinnedRefusal::Placement(error),
            HostCharge::Ledger(error) => PinnedRefusal::Ledger(error),
        })?;
        self.next_pin = next_pin;
        self.entries.insert(
            pin,
            PinnedEntry {
                owner: owner.clone(),
                content,
                bytes,
                reservation,
            },
        );
        Ok(pin)
    }
}

/// A T08 host plan of pins, built one demand at a time: host RAM, inside WSL the WSL VM,
/// the hard host-wide cap and a memlock scope under it for each execution that has a
/// limit.
struct PinPlan<'a> {
    limits: &'a PinnedLimits,
    memlock: &'a BTreeMap<ExecutionId, MemlockLimit>,
    during: Interval,
    memory_scope: String,
    scopes: Vec<HostScope>,
    /// The memlock scope made for each execution so far.
    caps: BTreeMap<ExecutionId, String>,
}

impl<'a> PinPlan<'a> {
    fn new(tier: &'a PinnedHostTier, during: Interval) -> Result<Self, PinnedRefusal> {
        let limits = &tier.limits;
        let memory_scope = match &limits.wsl {
            WslLimit::NotWsl => limits.host_ram.name.clone(),
            WslLimit::Vm(vm) => vm.name.clone(),
            WslLimit::Unknown => return Err(PinnedRefusal::WslLimitUnknown),
        };
        let mut scopes = vec![limits.host_ram.clone()];
        if let WslLimit::Vm(vm) = &limits.wsl {
            scopes.push(vm.clone());
        }
        scopes.push(limits.host_wide_cap.clone());
        Ok(Self {
            limits,
            memlock: &tier.memlock,
            during,
            memory_scope,
            scopes,
            caps: BTreeMap::new(),
        })
    }

    /// One pin of `bytes` held by `execution`: charged to the memory scope and to the
    /// execution's memlock scope, or to the hard cap alone when its memlock is unlimited.
    fn demand(
        &mut self,
        execution: &ExecutionId,
        bytes: u64,
        label: String,
    ) -> Result<HostDemand, PinnedRefusal> {
        let pinned_scope = match self.memlock.get(execution).copied() {
            None => {
                return Err(PinnedRefusal::UnregisteredExecution {
                    execution: execution.clone(),
                })
            }
            Some(MemlockLimit::Unknown) => {
                return Err(PinnedRefusal::MemlockUnknown {
                    execution: execution.clone(),
                })
            }
            Some(MemlockLimit::Unlimited) => self.limits.host_wide_cap.name.clone(),
            Some(MemlockLimit::Bytes(limit_bytes)) => match self.caps.get(execution) {
                Some(name) => name.clone(),
                None => {
                    let name = format!("memlock {execution}");
                    self.scopes.push(HostScope {
                        name: name.clone(),
                        kind: HostScopeKind::PinnedRam,
                        parent: Some(self.limits.host_wide_cap.name.clone()),
                        capacity: Capacity::Physical { bytes: limit_bytes },
                        safety_reserve_bytes: self.limits.memlock_reserve_bytes,
                        occupancy: ScopeOccupancy::default(),
                    });
                    self.caps.insert(execution.clone(), name.clone());
                    name
                }
            },
        };
        Ok(HostDemand {
            label,
            backing: HostBacking::Pinned,
            bytes,
            during: self.during,
            memory_scope: self.memory_scope.clone(),
            pinned_scope: Some(pinned_scope),
        })
    }

    fn with(&self, demands: Vec<HostDemand>) -> HostPlan {
        HostPlan {
            scopes: self.scopes.clone(),
            demands,
        }
    }
}

#[cfg(test)]
mod tests;
