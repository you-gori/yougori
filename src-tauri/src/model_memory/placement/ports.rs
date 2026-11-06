//! Ports to the authorities placement needs: reservations (CORE-03, task T04) and
//! leases and generations (CORE-04, task T09). Each trait covers only what placement
//! uses. The coordinator adapter (`coordinator_port.rs`) serves both; the ledger adapter
//! (`ledger_port.rs`) serves reservations alone; tests drive them through fakes. Model
//! identities (task T07) are used directly.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::keys::{ExtentKey, ReservationId, SlotId};
use crate::foundation::ids::{
    AuthorizationEpoch, ExecutionId, GpuAllocationGeneration, GpuDeviceKey, LeaseId,
    ModelActivationGeneration, MonotonicTime, OperationId,
};

/// Bytes a placement needs, per resource (§3.6 step 1).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceDemand {
    /// VRAM per device.
    pub vram_bytes: BTreeMap<GpuDeviceKey, u64>,
    /// Pageable host RAM.
    pub host_ram_bytes: u64,
    /// Pinned host RAM, such as staging buffers.
    pub pinned_host_bytes: u64,
}

impl ResourceDemand {
    /// Whether nothing is demanded.
    pub fn is_empty(&self) -> bool {
        self.vram_bytes.values().all(|bytes| *bytes == 0)
            && self.host_ram_bytes == 0
            && self.pinned_host_bytes == 0
    }

    /// VRAM demanded on `device`; zero when none.
    pub fn vram_bytes_on(&self, device: &GpuDeviceKey) -> u64 {
        self.vram_bytes.get(device).copied().unwrap_or(0)
    }

    /// Whether this demand is at least `other` for every resource.
    pub fn covers(&self, other: &ResourceDemand) -> bool {
        other
            .vram_bytes
            .iter()
            .all(|(device, bytes)| self.vram_bytes_on(device) >= *bytes)
            && self.host_ram_bytes >= other.host_ram_bytes
            && self.pinned_host_bytes >= other.pinned_host_bytes
    }
}

/// A resource the reservation ledger counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "resource", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ResourceKind {
    Vram { device: GpuDeviceKey },
    HostRam,
    PinnedHostRam,
}

crate::foundation::strict_serde::strict_tag!(ResourceKind, "resource");

impl fmt::Display for ResourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vram { device } => {
                let hex = device.device.to_hex();
                write!(f, "GPU memory on device {}", hex.get(..12).unwrap_or(&hex))
            }
            Self::HostRam => f.write_str("host memory"),
            Self::PinnedHostRam => f.write_str("pinned host memory"),
        }
    }
}

/// Whether a refused reservation can succeed later (CORE-03: the error says whether a
/// retry can make progress).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryOutlook {
    /// It fits once something else is released.
    FitsAfterRelease,
    /// It exceeds what the host can ever grant.
    ExceedsCapacity,
    /// The host has not observed the resource's capacity yet.
    AfterHostObservation,
    /// An owner resource-return hold denies it until the hold ends.
    AfterHoldEnds,
}

/// A capacity refusal naming the limiting resource (CORE-03).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityRefusal {
    pub resource: ResourceKind,
    pub requested_bytes: u64,
    pub available_bytes: u64,
    pub retry: RetryOutlook,
}

impl fmt::Display for CapacityRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} bytes of {} are needed but {} are available; ",
            self.requested_bytes, self.resource, self.available_bytes
        )?;
        f.write_str(match self.retry {
            RetryOutlook::FitsAfterRelease => "it fits once other work releases memory",
            RetryOutlook::ExceedsCapacity => "it exceeds what this host can provide",
            RetryOutlook::AfterHostObservation => "retry after the host has observed it",
            RetryOutlook::AfterHoldEnds => "retry after its owner has taken it back",
        })
    }
}

impl std::error::Error for CapacityRefusal {}

/// A refusal of the reservation authority that is not about capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationProblem {
    EmptyDemand,
    /// The parent the reservation is carved from is closed, releasing or unknown.
    ParentUnavailable,
    /// The parent belongs to another tenant, execution or priority.
    ParentMismatch,
    /// The parent's workload does not exist yet.
    ParentNotCreated,
    NestingTooDeep,
    /// A device is on another machine than the authority's host.
    ForeignDevice,
    /// The authority named a resource placement never asked for.
    UnexpectedResource,
    /// The predecessor of a successor reservation is not held.
    UnknownPredecessor,
    /// The parent execution holds no authority to reserve within, or its settings do not
    /// allow the activation.
    ParentNotAuthorized,
    /// Memory to acquire or reactivate within is released, promised to a successor,
    /// still waiting for a handover, or from an earlier boot or authorization epoch;
    /// reload instead.
    HoldingUnavailable,
    /// The demand cannot be met as stated, such as one with no GPU memory at all.
    InvalidDemand,
    /// The authority has issued every identifier it can.
    Exhausted,
    /// The authority refused with an error a reservation does not expect.
    Unexpected,
}

/// Why a reservation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ReservationRefusal {
    Capacity { refusal: CapacityRefusal },
    Refused { problem: ReservationProblem },
}

crate::foundation::strict_serde::strict_tag!(ReservationRefusal, "kind");

impl fmt::Display for ReservationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity { refusal } => refusal.fmt(f),
            Self::Refused { problem } => write!(f, "the reservation was refused: {problem:?}"),
        }
    }
}

impl std::error::Error for ReservationRefusal {}

/// What an activation reserves before it creates anything (§3.6 step 1): the new
/// placement's steady state plus its transition peak. Either part may be empty, as when
/// a resident placement is activated again and already holds its steady state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationRequest {
    pub slot: SlotId,
    /// The parent execution the reservation belongs to.
    pub execution: ExecutionId,
    /// The activation the reservation is for.
    pub operation: OperationId,
    /// The placement's whole steady state, every extent included.
    pub steady: ResourceDemand,
    /// Extra demand only while the activation runs; released at publication.
    pub transition_peak: ResourceDemand,
    /// The placement's own steady reservation when a resting placement is activated
    /// again within it, with `steady` empty.
    pub within: Option<ReservationId>,
    /// Resident extents of other placements this activation will acquire (§3.6 step 2),
    /// as the bytes they cover per device, by the steady reservation of the placement
    /// holding them. An authority that counts shared memory once reserves only what
    /// these do not cover; one that cannot share counts `steady` whole.
    pub acquire: BTreeMap<ReservationId, BTreeMap<GpuDeviceKey, u64>>,
    /// Every distinct immutable extent of the content with its size; `steady` includes
    /// them. An authority that holds a model's weights apart from any activation's own
    /// memory reserves each extent once, for every placement that reads it, and an
    /// activation's own reservation is then only the rest of `steady` and its transition
    /// peak (GPU part §2.7: shared weights count once).
    pub extents: BTreeMap<ExtentKey, u64>,
}

/// The reservations granted for one request; an empty part has none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationGrant {
    pub steady: Option<ReservationId>,
    pub transition_peak: Option<ReservationId>,
}

/// CORE-03 reservations (task T04) as placement uses them.
///
/// Contract: both parts of a request are granted together or not at all, a grant never
/// exceeds the parent allocation the host enforces (S3.2), and a reservation counts from
/// its grant until it is released.
pub trait ReservationPort {
    /// Reserves `request` in addition to everything already held.
    fn reserve(
        &mut self,
        request: &ReservationRequest,
    ) -> Result<ReservationGrant, ReservationRefusal>;

    /// Reserves `request` as the successor of `predecessor`, for a placement that will
    /// run only after the predecessor's placement is reclaimed (drain first). Capacity is
    /// counted as if the predecessor were already released, and the predecessor's share
    /// passes to the successor, so no other request can take it in between. Releasing the
    /// successor first gives the share back to the predecessor.
    fn reserve_successor(
        &mut self,
        predecessor: ReservationId,
        request: &ReservationRequest,
    ) -> Result<ReservationGrant, ReservationRefusal>;

    /// Releases one reservation. Idempotent: releasing twice, or an unknown reservation,
    /// changes nothing.
    fn release(&mut self, reservation: ReservationId);
}

/// What a lease is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseKind {
    /// A request admitted to the published generation.
    Serving,
    /// The one pending request explicitly assigned to a preparation generation for
    /// execute-while-load (§3.6 line 601).
    Preparation,
}

/// A lease bound to the parent execution, its authorization epoch and one activation
/// generation (S3.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRequest {
    pub slot: SlotId,
    pub kind: LeaseKind,
    pub request: OperationId,
    pub execution: ExecutionId,
    pub epoch: AuthorizationEpoch,
    pub generation: ModelActivationGeneration,
    pub expires_at: MonotonicTime,
}

/// A lease's status as the coordination module sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Active,
    Expired,
    /// The authorization it was bound to was revoked.
    Revoked,
    Released,
    Unknown,
}

impl LeaseStatus {
    /// Whether the lease still holds its generation.
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Why the coordination module refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum CoordinationRefusal {
    /// The presented authorization epoch is not the execution's current one.
    StaleAuthorization {
        presented: AuthorizationEpoch,
        current: AuthorizationEpoch,
    },
    /// The execution holds no authority.
    NotAuthorized,
    /// The requested expiry is not in the future.
    ExpiryNotInFuture,
    /// The slot's generations are exhausted; the slot must be replaced.
    GenerationsExhausted,
    /// No generation was reserved for this activation: the authority issues a generation
    /// only with its reservation.
    NoReservedGeneration,
    /// The generation is not one the authority knows.
    UnknownGeneration {
        generation: ModelActivationGeneration,
    },
    /// The generation's state does not allow the step.
    GenerationNotReady {
        generation: ModelActivationGeneration,
    },
    /// A serving lease names another generation than the one the authority serves.
    GenerationNotServing {
        requested: ModelActivationGeneration,
        serving: Option<ModelActivationGeneration>,
    },
    /// The activation waits for its predecessor's memory in a drain-first handover.
    HandoverPending {
        predecessor: ModelActivationGeneration,
    },
    /// A request is already assigned to the generation being prepared.
    PreparationAssigned,
}

crate::foundation::strict_serde::strict_tag!(CoordinationRefusal, "refusal");

/// Why a request may not publish a result yet (§3.6 line 601).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum PublicationRefusal {
    /// The lease is no longer active.
    Lease { status: LeaseStatus },
    /// The lease's generation is still being prepared.
    AwaitingPublication,
}

crate::foundation::strict_serde::strict_tag!(PublicationRefusal, "kind");

impl fmt::Display for PublicationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lease { status } => write!(f, "the lease is no longer active ({status:?})"),
            Self::AwaitingPublication => {
                f.write_str("the generation is not published yet; nothing computed for it is")
            }
        }
    }
}

impl std::error::Error for PublicationRefusal {}

impl fmt::Display for CoordinationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleAuthorization { presented, current } => write!(
                f,
                "authorization epoch {presented} is no longer valid; the current epoch is \
                 {current}"
            ),
            Self::NotAuthorized => f.write_str("the execution holds no authority"),
            Self::ExpiryNotInFuture => f.write_str("the lease would already have expired"),
            Self::GenerationsExhausted => {
                f.write_str("the slot has used every generation; replace the slot")
            }
            Self::NoReservedGeneration => {
                f.write_str("no generation was reserved for this activation")
            }
            Self::UnknownGeneration { generation } => {
                write!(f, "activation generation {generation} is unknown")
            }
            Self::GenerationNotReady { generation } => write!(
                f,
                "activation generation {generation} is not in a state that allows this"
            ),
            Self::GenerationNotServing { requested, .. } => {
                write!(
                    f,
                    "activation generation {requested} is not the serving one"
                )
            }
            Self::HandoverPending { predecessor } => write!(
                f,
                "the activation waits for the memory of activation generation {predecessor}"
            ),
            Self::PreparationAssigned => {
                f.write_str("a request is already assigned to the generation being prepared")
            }
        }
    }
}

impl std::error::Error for CoordinationRefusal {}

/// CORE-04 leases and generations (task T09) as placement uses them.
///
/// Contract: generations are allocated per slot, strictly increasing and never reissued,
/// and allocating one never changes another kind of generation or epoch (S3.1). Lease
/// release is idempotent.
pub trait CoordinationPort {
    /// A new activation generation for `slot`, newer than every one issued before (S3.1).
    fn next_activation_generation(
        &mut self,
        slot: &SlotId,
    ) -> Result<ModelActivationGeneration, CoordinationRefusal>;

    /// The GPU allocation generation for memory newly allocated on `device` by the
    /// activation in progress; activation generations do not move (S3.1).
    fn next_allocation_generation(
        &mut self,
        slot: &SlotId,
        device: &GpuDeviceKey,
    ) -> Result<GpuAllocationGeneration, CoordinationRefusal>;

    /// The GPU allocation generation of the memory `extent` is allocated in by the
    /// activation in progress: by default the activation's new allocation on the
    /// extent's device; an authority that holds weights apart names the extent's own.
    fn extent_allocation(
        &mut self,
        slot: &SlotId,
        extent: &ExtentKey,
    ) -> Result<GpuAllocationGeneration, CoordinationRefusal> {
        self.next_allocation_generation(slot, &extent.device)
    }

    /// A lease bound to the request's execution, authorization epoch and generation, or a
    /// refusal when the epoch is stale or the expiry has passed.
    fn grant_lease(
        &mut self,
        request: &LeaseRequest,
        now: MonotonicTime,
    ) -> Result<LeaseId, CoordinationRefusal>;

    /// Whether `lease` is still active at `now`.
    fn lease_status(&self, lease: LeaseId, now: MonotonicTime) -> LeaseStatus;

    /// Whether the request holding `lease` may publish a result now (§3.6 line 601): the
    /// lease is active and its generation has been published.
    fn check_result_publication(
        &self,
        lease: LeaseId,
        now: MonotonicTime,
    ) -> Result<(), PublicationRefusal>;

    /// Makes `generation` the one the authority serves, as the slot publishes it (§3.6
    /// step 5). The slot publishes only once this succeeds.
    fn publish_generation(
        &mut self,
        slot: &SlotId,
        generation: ModelActivationGeneration,
    ) -> Result<(), CoordinationRefusal>;

    /// The activation of `generation` ended without being published. Idempotent.
    fn abandon_generation(&mut self, slot: &SlotId, generation: ModelActivationGeneration);

    /// Ends `lease`. Idempotent.
    fn release_lease(&mut self, lease: LeaseId);
}

/// What one slot operation reaches the reservation and coordination authorities
/// through. One object may serve both, as the coordinator adapter does.
pub trait PlacementPorts {
    /// The reservation authority (CORE-03).
    fn reservations(&mut self) -> &mut dyn ReservationPort;

    /// The lease and generation authority (CORE-04).
    fn coordination(&mut self) -> &mut dyn CoordinationPort;
}

/// Two separate ports as one [`PlacementPorts`].
pub struct Ports<'a> {
    pub reservations: &'a mut dyn ReservationPort,
    pub coordination: &'a mut dyn CoordinationPort,
}

impl PlacementPorts for Ports<'_> {
    fn reservations(&mut self) -> &mut dyn ReservationPort {
        &mut *self.reservations
    }

    fn coordination(&mut self) -> &mut dyn CoordinationPort {
        &mut *self.coordination
    }
}
