//! The transfer executor, portable path (docs/combined-gpu-memory-and-vm-sandbox-plan.md,
//! GPU §3.5; GPU-W04).
//!
//! [`TransferExecutor`] runs the nine steps of the portable path as a state machine over
//! a [`TransferBackend`]:
//!
//! 1. resolve a verified manifest and candidate sources ([`CatalogPort`]);
//! 2. reserve the destination and bounded staging before anything starts
//!    ([`ReservationPort`]);
//! 3. coalesce the required extents into aligned batches ([`BatchPort`]);
//! 4. read with positioned reads, a memory map, an upstream loader, direct I/O
//!    ([`DirectIo`], buffered with a reason where it cannot be used) or a gated method,
//!    and label the path each read actually took ([`ReadStatus::Served`]);
//! 5. verify each stored extent as the manifest records it (a raw extent against its
//!    decoded content key, an encoded one against its encoded digest), decode it if
//!    needed and validate its decoded identity;
//! 6. copy into the destination with a real asynchronous API ([`CopyApi`]);
//! 7. record completion events, and publish a dependency only after its whole chain
//!    completed;
//! 8. recycle a staging buffer after its last consumer event, never after enqueueing;
//! 9. emit progress and measured stage durations ([`EventPort`]).
//!
//! GPUDirect Storage and GPU-peer reads skip the host ring but keep bounded device
//! staging and dependency tracking, and nothing in device staging is copied out before
//! it is verified. GPU peers are read only where CORE-01 evidence shows peer access for
//! the exact direction ([`PeerAccessPolicy`]), and CUDA read methods only while CORE-01
//! evidence shows the runtime on CUDA. Operations are shared per extent, representation
//! and destination region: one subscriber's cancellation never cancels another's work,
//! the last subscriber's cancellation permits reclamation, and promotion from speculative
//! to foreground reuses the same transfer. A failed attempt is retried a bounded number of
//! times, its source is blacklisted for the job and excluded from the live load when the
//! source is to blame, every independently verified extent is kept, and a hash mismatch
//! is a failure, never a warning followed by use. A delivered destination carved from a
//! parent reservation goes back to its parent at once ([`ReservationPort::hand_over`]).
//!
//! Source choice, source exclusion, requeueing and shared source caps across loads, and
//! prefetch admission come from the GPU cost model
//! ([`crate::model_memory::math::sources`], [`crate::model_memory::math::prefetch`]),
//! gated read methods from a backend runtime's evidence-gated plan
//! ([`crate::model_memory::backends::BackendRuntime`], [`LoaderPermissions`]), rechecked
//! in the live evidence registry at each use ([`EvidencePort`]), stored forms from the
//! sidecar manifest's codec format, dictionary and encoded digest
//! ([`crate::model_memory::manifest`]), and content and device keys from
//! [`crate::foundation::ids`]. Reservations go through a port with an adapter over the
//! host ledger ([`LedgerReservations`]); a job submitted within a placement's
//! reservation carves its destinations from it ([`TransferExecutor::submit_within`]).
//! Extent progress goes to P08's publisher through a port with an adapter
//! ([`PublisherProgress`]). A revocation reaches running jobs through
//! [`TransferExecutor::cancel_execution`] (INT-02).
//!
//! Given CORE-05 transfers ([`TransferExecutor::with_transfers`], GPU-W09), the
//! executor reads a remote store or an authorized peer only through a session of the
//! job ([`crate::foundation::transfer`]), opened from a sealed grant bound to this
//! executor, the job and the source ([`session_operation`], [`SourceGrant`],
//! [`TransferExecutor::submit_with`]), so a replayed, foreign or cross-process envelope
//! is refused; opening it reserves the grant's bytes and a network slot through
//! CORE-05's byte budget over the host ledger. Each batch is one chunk, admitted and
//! charged to every subscriber's session before it moves; every step above stays as it
//! is; an interrupted transfer resumes without moving the extents it verified again;
//! and a revocation of the transfer's authority cancels the job.
//!
//! The catalog (T05) stays a port until the manifest's artifacts are published to it;
//! extent batching (T06) and the event envelope (T10) are ports until those modules are
//! committed.

mod backend;
mod config;
mod error;
mod job;
mod ledger_adapter;
mod machine;
mod model;
mod network;
mod planning;
mod ports;
mod progress_adapter;
mod pump;
mod staging;
mod state;
mod validate;

#[cfg(test)]
mod fakes;
#[cfg(test)]
mod tests;

pub use backend::{
    BackendError, BackendErrorKind, CopyRequest, DecodeRequest, DestinationRange, EventId,
    EventStatus, ReadRequest, ReadStatus, ReadTicket, StagedRange, StagingBuffer, TransferBackend,
};
pub use config::{DeviceStagingConfig, ExecutorConfig, HostStagingConfig, HostStagingMemory};
pub use error::{
    Attempt, AttemptFailure, BatchPlanError, CancelError, CloseError, ConfigError, DependencyError,
    DirectIoUnavailable, ExecutorFault, ExtentFailure, ForgetError, JobFailure, ManifestError,
    MethodUnavailable, PlanFailure, PromoteError, RetireError, StartError, SubmitError,
    Unavailable,
};
pub use job::{
    CancelReason, DependencyId, DependencySpec, JobPriority, JobProgress, JobStatus,
    ProgressSnapshot, StageTotal, SubmitOptions, TransferRequest,
};
pub use ledger_adapter::{ledger_demand, resource_key, LedgerReservations, StagingAccount};
pub use machine::{CancelReport, ExecutorPorts, Lifecycle, RevocationReport, TransferExecutor};
pub use model::{
    AllocationKey, CopyApi, Destination, DirectIo, ExtentId, FlightKey, GatedMethod,
    LoaderPermissions, ManifestExtent, PeerAccessPolicy, Priority, ReadMethod, SourceCandidate,
    SourceKind, Stage, StagingPlace, StoredForm, TransferPath, UnsupportedApi,
};
pub use network::{
    session_operation, BindingField, SourceGrant, TransferBindingError, SESSION_DOMAIN,
};
pub use ports::{
    Anomaly, BatchLimits, BatchPlan, BatchPort, CapacityLimit, CapacityRefusal, CatalogPort,
    CatalogRefusal, EventPort, EventStream, EvidencePort, ExtentSpan, NoEvidence, ProgressPort,
    ReservationId, ReservationPort, ReservationPurpose, ReservationRefusal, ReservationRequest,
    ReservedResource, ResolveRequest, ResolvedManifest, RetryAdvice, StageMeasurement,
    TransferEvent, TransferEventKind, UnknownReservation,
};
pub use progress_adapter::PublisherProgress;
pub use pump::PumpReport;
pub use staging::StagingUsage;
pub use state::{FlightId, FlightPhase};
