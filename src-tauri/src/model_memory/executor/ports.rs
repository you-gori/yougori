//! The executor's ports: the catalog (T05, CORE-02), extent batching (T06, GPU §2.4),
//! the reservation ledger (T04, CORE-03), the event envelope (T10, CORE-06), the
//! evidence registry (T01, CORE-01) and GPU progress (P08, §3.10). Each covers only
//! what the executor needs. The reservation port has an adapter over the committed
//! ledger ([`super::LedgerReservations`]), the evidence port is implemented for the
//! registry itself, and the progress port has an adapter over P08's publisher
//! ([`super::PublisherProgress`]); the others are used through fakes until their
//! modules land.

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::backend::{BackendError, EventId};
use super::error::{AttemptFailure, DirectIoUnavailable, JobFailure};
use super::job::{CancelReason, DependencyId, ProgressSnapshot};
use super::model::{
    CopyApi, FlightKey, ManifestExtent, Priority, ReadMethod, SourceCandidate, Stage, TransferPath,
};
use crate::foundation::evidence::{
    EvidenceRefusal, LoaderPlan, Optimization, ProbeRegistry, Requirement, Satisfied,
};
use crate::foundation::ids::{
    Clock, ContentKey, ExecutionId, GpuDeviceKey, MonotonicTime, OperationId, TenantId,
};
use crate::foundation::ledger;
use crate::foundation::transfer::TransferRefusal;
use crate::model_memory::math::prefetch::PrefetchError;
use crate::model_memory::math::sources::{CutSpec, SourcesError};
use crate::model_memory::math::SourceId;
use crate::model_memory::progress::PublishError;

/// What the executor asks the catalog (§3.5 step 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolveRequest {
    pub execution: ExecutionId,
    pub tenant: TenantId,
    pub artifact: ContentKey,
    pub representation: ContentKey,
}

/// A verified manifest and the sources this execution may read it from (§3.5 step 1).
#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedManifest {
    /// The content key of the verified manifest.
    pub manifest: ContentKey,
    pub artifact: ContentKey,
    /// The content key of the stored object the extents are read from: a source file
    /// for raw extents, a prepared file for encoded ones.
    pub representation: ContentKey,
    /// Length of the stored object, for reads past its end (GPU-W04 tails).
    pub object_length_bytes: u64,
    pub extents: Vec<ManifestExtent>,
    /// Candidate sources in the catalog's order, with their measured profiles.
    pub sources: Vec<SourceCandidate>,
    /// Network and storage cuts the sources share (GPU §2.5).
    pub cuts: Vec<CutSpec>,
}

/// Why the catalog refused to resolve.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogRefusal {
    NotFound,
    /// The execution holds no grant for the artifact; equal bytes are not permission.
    NotAuthorized,
    /// The manifest is not verified, so nothing may be read on its strength.
    NotVerified,
}

impl fmt::Display for CatalogRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotFound => "the artifact or representation is not in the catalog",
            Self::NotAuthorized => "this execution holds no grant for the artifact",
            Self::NotVerified => "the manifest is not verified",
        })
    }
}

impl std::error::Error for CatalogRefusal {}

/// The catalog port (T05, CORE-02).
pub trait CatalogPort {
    /// Resolves the verified manifest and candidate sources of one representation for
    /// one execution.
    fn resolve(&self, request: &ResolveRequest) -> Result<ResolvedManifest, CatalogRefusal>;
}

/// One encoded extent offered for batching.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExtentSpan {
    pub index: u64,
    /// The stored extent's offset and length in the stored object.
    pub offset_bytes: u64,
    pub length_bytes: u64,
    /// What the extent needs in a decode slot: its decoded length when encoded, zero
    /// when raw.
    pub decode_bytes: u64,
}

/// Limits every transport batch must meet (§3.5 step 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BatchLimits {
    /// Reads start and end on multiples of this; a power of two.
    pub alignment_bytes: u64,
    /// One staging slot.
    pub max_read_bytes: u64,
    /// One decode slot, which holds the decoded bytes of a batch's encoded extents.
    pub max_decoded_bytes: u64,
    /// Length of the stored object; an aligned read may run past it.
    pub object_length_bytes: u64,
}

/// One transport batch (GPU §2.4 `g_t`): adjacent extents, in offset order, read as one
/// aligned range. The extents keep their identities and true lengths.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BatchPlan {
    /// Extent indices.
    pub members: Vec<u64>,
    pub read_offset_bytes: u64,
    pub read_length_bytes: u64,
}

/// The extent-batching port (T06, GPU §2.4): coalesces adjacent extents without changing
/// their identities. The executor checks every plan it returns.
pub trait BatchPort {
    /// Batches `spans`, which are sorted by offset and do not overlap.
    fn coalesce(&self, spans: &[ExtentSpan], limits: &BatchLimits) -> Vec<BatchPlan>;
}

/// A resource the ledger accounts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "resource", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ReservedResource {
    /// Memory of one GPU: destinations and device staging.
    DeviceMemory { device: GpuDeviceKey },
    /// Pinned host memory, under its host-wide cap (GPU §3.4). Pinned bytes are host RAM
    /// too, so a ledger charges them to [`ReservedResource::HostMemory`] as well
    /// (GPU §2.7).
    PinnedHostMemory,
    /// Host RAM: a pageable staging ring (GPU-W04), and every pinned byte.
    HostMemory,
}

crate::foundation::strict_serde::strict_tag!(ReservedResource, "resource");

/// What a reservation is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "purpose", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ReservationPurpose {
    /// The host staging ring.
    HostStaging,
    /// One GPU's staging pool for direct paths.
    DeviceStaging { device: GpuDeviceKey },
    /// The destination region of one operation.
    Destination { key: FlightKey },
}

crate::foundation::strict_serde::strict_tag!(ReservationPurpose, "purpose");

/// A reservation the executor asks for before anything starts (§3.5 step 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservationRequest {
    /// The executor's own operation for staging; the job's for destinations.
    pub operation: OperationId,
    /// The execution charged; `None` for the executor's own staging.
    pub execution: Option<ExecutionId>,
    pub tenant: Option<TenantId>,
    /// Foreground for staging and foreground jobs; speculative work is background work
    /// that an owner's resource-return hold may deny.
    pub priority: Priority,
    pub resource: ReservedResource,
    pub purpose: ReservationPurpose,
    pub bytes: u64,
    /// The reservation this one is carved from (CORE-03 parent and child): the
    /// placement's reservation of the destination (P04), when the job was submitted
    /// within one. `None` charges host capacity and the tenant budget.
    pub parent: Option<ledger::ReservationId>,
}

/// A granted reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReservationId(pub u64);

/// Whether retrying a refused reservation can make progress (CORE-03).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryAdvice {
    /// Capacity may free up; a later retry can succeed.
    CanProgress,
    /// The request exceeds what the resource can ever hold.
    CannotProgress,
}

/// The limit a refused reservation ran into (CORE-03).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityLimit {
    /// Physical capacity less the supervisor reserve and unmanaged use.
    PhysicalCapacity,
    /// The host has not observed the resource's capacity, so none of it is free.
    CapacityNotObserved,
    /// The host's latest observation of the resource is too old to say what is free.
    StaleHostObservation,
    /// The tenant's budget, charged separately from physical capacity.
    TenantBudget,
    /// The parent reservation the request is carved from.
    ParentReservation,
    /// An owner's resource-return hold denies background reservations.
    OwnerReturnHold,
}

/// A refused reservation, naming the limiting resource and whether a retry can make
/// progress (CORE-03).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CapacityRefusal {
    pub resource: ReservedResource,
    pub limit: CapacityLimit,
    pub requested_bytes: u64,
    pub available_bytes: u64,
    pub retry: RetryAdvice,
}

impl fmt::Display for CapacityRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} has {} bytes available under {:?} for a {}-byte request",
            self.resource, self.available_bytes, self.limit, self.requested_bytes
        )?;
        match self.retry {
            RetryAdvice::CanProgress => f.write_str("; a retry can succeed later"),
            RetryAdvice::CannotProgress => f.write_str("; the request can never fit"),
        }
    }
}

impl std::error::Error for CapacityRefusal {}

/// Why a reservation was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReservationRefusal {
    /// Not enough capacity under some limit.
    Capacity(CapacityRefusal),
    /// The ledger refused the request itself, such as a device of another host; the same
    /// request can never succeed.
    Rejected { reason: String },
}

impl fmt::Display for ReservationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity(refusal) => write!(f, "{refusal}"),
            Self::Rejected { reason } => write!(f, "the ledger rejected the request: {reason}"),
        }
    }
}

impl std::error::Error for ReservationRefusal {}

/// A reservation the ledger no longer holds open for the executor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UnknownReservation {
    pub reservation: ReservationId,
}

impl fmt::Display for UnknownReservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "reservation {} is not held", self.reservation.0)
    }
}

impl std::error::Error for UnknownReservation {}

/// The reservation ledger port (T04, CORE-03).
pub trait ReservationPort {
    /// Reserves before anything is created, or refuses naming the limiting resource.
    fn reserve(
        &mut self,
        request: &ReservationRequest,
    ) -> Result<ReservationId, ReservationRefusal>;

    /// The reserved memory is now committed: a staging pool exists, or a job's
    /// destination regions belong to its transfer. From then on the amounts count until
    /// the host observes their release, so stopping never shows false free capacity.
    fn begin_use(&mut self, reservation: ReservationId) -> Result<(), UnknownReservation>;

    /// Gives a reservation back after cancellation, failure, retirement or close. Its
    /// amounts count until the host observes their release.
    fn release(&mut self, reservation: ReservationId) -> Result<(), UnknownReservation>;

    /// A destination's bytes were delivered (§3.5 step 7) and now belong to the
    /// reservation the destination was carved from: a child of a parent reservation goes
    /// back to its parent at once, confirmed by the transfer's own report, which is enough
    /// for a child (CORE-03). A host-level reservation is released as by
    /// [`Self::release`], since the memory stays in use until the host observes otherwise.
    /// The default releases.
    fn hand_over(&mut self, reservation: ReservationId) -> Result<(), UnknownReservation> {
        self.release(reservation)
    }
}

/// The stream an event belongs to (CORE-06): each has its own retention and
/// backpressure in the event envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventStream {
    Progress,
    Metrics,
    Audit,
}

/// One measured stage of one batch or job (§3.5 step 9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StageMeasurement {
    pub stage: Stage,
    pub bytes: u64,
    pub started_at: MonotonicTime,
    pub duration: Duration,
    pub path: Option<TransferPath>,
    pub method: Option<ReadMethod>,
    /// The copy API that ran, for copies.
    pub api: Option<CopyApi>,
    pub source: Option<SourceId>,
}

/// Something the executor could not do that is not a job's failure, reported rather
/// than ignored.
#[derive(Clone, Debug, PartialEq)]
pub enum Anomaly {
    /// The ledger refused a release.
    ReleaseRefused { reservation: ReservationId },
    /// The backend refused to take back a finished event.
    EventReleaseFailed { event: EventId, error: BackendError },
    /// A peer-access query failed, so the peer was not used. No longer reported: GPU-peer
    /// reads rest on CORE-01 evidence, and the executor never queries the backend.
    PeerQueryFailed {
        from: GpuDeviceKey,
        to: GpuDeviceKey,
        error: BackendError,
    },
    /// The prefetch scheduler refused a bookkeeping step for a job.
    SchedulerRefused {
        operation: OperationId,
        error: PrefetchError,
    },
    /// The multi-source planner refused a bookkeeping step.
    PlannerRefused { error: SourcesError },
    /// The progress publisher refused an extent report for a job's operation, such as
    /// one it does not track or one outside the phases that move bytes; the transfer
    /// goes on.
    ProgressRefused {
        operation: OperationId,
        extent: u64,
        error: PublishError,
    },
}

/// What happened.
#[derive(Clone, Debug, PartialEq)]
pub enum TransferEventKind {
    /// A job was admitted, reserved and planned.
    Submitted {
        total_bytes: u64,
        new_operations: usize,
        shared_operations: usize,
    },
    StageMeasured(StageMeasurement),
    Progress(ProgressSnapshot),
    /// The dependency's whole chain completed (§3.5 step 7).
    DependencyUsable {
        dependency: DependencyId,
    },
    /// An attempt failed; the extent is retried or given up, never used.
    AttemptFailed {
        extent: u64,
        attempt: u32,
        source: Option<SourceId>,
        failure: AttemptFailure,
    },
    /// The source is no longer used for this job (§3.5).
    SourceBlacklisted {
        source: SourceId,
    },
    /// Speculative work became foreground work in place.
    Promoted,
    /// A read that asked for direct I/O was read buffered instead, for this reason
    /// (GPU-T20).
    BufferedRead {
        reason: DirectIoUnavailable,
    },
    /// The job's CORE-05 transfer from `source` refused a chunk or stopped without a
    /// revocation, such as on an exhausted budget or an expired grant: the source ends
    /// for the job (GPU-W09).
    TransferRefused {
        source: SourceId,
        refusal: TransferRefusal,
    },
    Completed,
    Failed {
        failure: JobFailure,
    },
    Cancelled {
        reason: CancelReason,
    },
    Anomaly(Anomaly),
}

impl TransferEventKind {
    /// The stream this event is carried on.
    pub fn stream(&self) -> EventStream {
        match self {
            Self::Progress(_) | Self::DependencyUsable { .. } => EventStream::Progress,
            Self::StageMeasured(_) => EventStream::Metrics,
            Self::Submitted { .. }
            | Self::AttemptFailed { .. }
            | Self::SourceBlacklisted { .. }
            | Self::Promoted
            | Self::BufferedRead { .. }
            | Self::TransferRefused { .. }
            | Self::Completed
            | Self::Failed { .. }
            | Self::Cancelled { .. }
            | Self::Anomaly(_) => EventStream::Audit,
        }
    }
}

/// One event (CORE-06): the job's operation, or the executor's own for its own events,
/// with a sequence that only grows.
#[derive(Clone, Debug, PartialEq)]
pub struct TransferEvent {
    pub sequence: u64,
    pub at: MonotonicTime,
    pub operation: OperationId,
    pub kind: TransferEventKind,
}

/// The event port (T10, CORE-06).
pub trait EventPort {
    fn emit(&mut self, event: TransferEvent);
}

/// The evidence registry gated read methods are rechecked in (T01, CORE-01; INT-06):
/// the live registry the loader plans were made with, so expiry and invalidation reach
/// every load that holds a plan.
pub trait EvidencePort {
    /// [`LoaderPlan::recheck`] of `optimization` in the registry, now.
    fn recheck(
        &self,
        plan: &LoaderPlan,
        optimization: Optimization,
    ) -> Result<Satisfied, EvidenceRefusal>;

    /// Evaluates `requirement` against the registry's evidence now (CORE-01), as GPU peer
    /// access and a runtime's compute platform are judged. The default holds no evidence.
    fn evaluate(&self, requirement: &Requirement) -> Result<Satisfied, EvidenceRefusal> {
        Err(EvidenceRefusal::Missing {
            capability: requirement.capability,
        })
    }
}

impl<C: Clock> EvidencePort for ProbeRegistry<C> {
    fn recheck(
        &self,
        plan: &LoaderPlan,
        optimization: Optimization,
    ) -> Result<Satisfied, EvidenceRefusal> {
        plan.recheck(optimization, self)
    }

    fn evaluate(&self, requirement: &Requirement) -> Result<Satisfied, EvidenceRefusal> {
        ProbeRegistry::evaluate(self, requirement)
    }
}

/// A registry shared with the evidence subsystem, which refreshes and invalidates it.
impl<C: Clock> EvidencePort for Mutex<ProbeRegistry<C>> {
    fn recheck(
        &self,
        plan: &LoaderPlan,
        optimization: Optimization,
    ) -> Result<Satisfied, EvidenceRefusal> {
        let registry = self.lock().unwrap_or_else(PoisonError::into_inner);
        plan.recheck(optimization, &*registry)
    }

    fn evaluate(&self, requirement: &Requirement) -> Result<Satisfied, EvidenceRefusal> {
        let registry = self.lock().unwrap_or_else(PoisonError::into_inner);
        registry.evaluate(requirement)
    }
}

impl<T: EvidencePort + ?Sized> EvidencePort for Arc<T> {
    fn recheck(
        &self,
        plan: &LoaderPlan,
        optimization: Optimization,
    ) -> Result<Satisfied, EvidenceRefusal> {
        (**self).recheck(plan, optimization)
    }

    fn evaluate(&self, requirement: &Requirement) -> Result<Satisfied, EvidenceRefusal> {
        (**self).evaluate(requirement)
    }
}

/// No registry: no evidence holds, so no gated method is ever used. An executor has
/// this until it is given the registry ([`super::TransferExecutor::with_evidence`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoEvidence;

impl EvidencePort for NoEvidence {
    fn recheck(
        &self,
        _plan: &LoaderPlan,
        optimization: Optimization,
    ) -> Result<Satisfied, EvidenceRefusal> {
        Err(EvidenceRefusal::Missing {
            capability: optimization.capability(),
        })
    }
}

/// Extent progress for the GPU progress publisher (P08, §3.10 line 650), per job
/// operation, which the caller tracks there before submitting the job. Each extent of a
/// batch in flight is started; it arrives when its read finished, not yet verified; it
/// is committed once verified and its copy's completion event was observed, so its
/// bytes are usable; and it is discarded when an attempt failed, to be fetched again or
/// given up, never used. Lengths are decoded bytes. Repeated reports change nothing.
pub trait ProgressPort {
    fn extent_started(
        &mut self,
        operation: &OperationId,
        index: u64,
        length_bytes: u64,
    ) -> Result<(), PublishError>;

    fn extent_arrived(
        &mut self,
        operation: &OperationId,
        index: u64,
        length_bytes: u64,
    ) -> Result<(), PublishError>;

    fn extent_committed(&mut self, operation: &OperationId, index: u64)
        -> Result<(), PublishError>;

    fn extent_discarded(&mut self, operation: &OperationId, index: u64)
        -> Result<(), PublishError>;
}
