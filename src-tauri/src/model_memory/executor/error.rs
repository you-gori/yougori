//! Typed refusals, failures and faults of the transfer executor (GPU §3.5).

use std::fmt;

use super::backend::{BackendError, EventId, ReadTicket, StagingBuffer};
use super::job::DependencyId;
use super::model::{AllocationKey, ReadMethod, StagingPlace, TransferPath};
use super::network::TransferBindingError;
use super::ports::{CatalogRefusal, ReservationRefusal};
use crate::foundation::ids::{AuthorizationEpoch, ContentKey, Digest, ExecutionId, OperationId};
use crate::foundation::transfer::TransferRefusal;
use crate::model_memory::backends::{ComputePlatform, PlatformRefusal};
use crate::model_memory::math::prefetch::PrefetchError;
use crate::model_memory::math::sources::SourcesError;
use crate::model_memory::math::SourceId;

/// Why a configuration was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// A staging pool needs at least one slot.
    NoSlots {
        place: StagingPlace,
    },
    /// A staging slot must hold at least one aligned unit.
    SlotSmallerThanAlignment {
        place: StagingPlace,
        slot_bytes: u64,
        alignment_bytes: u64,
    },
    /// The pool's size does not fit in 64 bits.
    PoolTooLarge {
        place: StagingPlace,
    },
    AlignmentNotPowerOfTwo {
        alignment_bytes: u64,
    },
    /// Retries are bounded, and the first try counts as one attempt.
    ZeroAttempts,
    /// The ordinary loader must be an ungated local method (GPU-W04).
    NotAnOrdinaryLocalMethod {
        method: ReadMethod,
    },
    /// The backend does not implement the ordinary loader.
    MethodNotImplemented {
        method: ReadMethod,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSlots { place } => write!(f, "the {place:?} staging pool has no slots"),
            Self::SlotSmallerThanAlignment {
                place,
                slot_bytes,
                alignment_bytes,
            } => write!(
                f,
                "{place:?} staging slots of {slot_bytes} bytes are smaller than the \
                 {alignment_bytes}-byte alignment"
            ),
            Self::PoolTooLarge { place } => {
                write!(f, "the {place:?} staging pool does not fit in 64 bits")
            }
            Self::AlignmentNotPowerOfTwo { alignment_bytes } => {
                write!(f, "the alignment {alignment_bytes} is not a power of two")
            }
            Self::ZeroAttempts => f.write_str("at least one attempt per extent is needed"),
            Self::NotAnOrdinaryLocalMethod { method } => write!(
                f,
                "{method} cannot be the ordinary loader; use positioned reads, a memory map \
                 or the upstream loader"
            ),
            Self::MethodNotImplemented { method } => {
                write!(f, "the backend does not implement {method}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Why an executor could not start.
#[derive(Clone, Debug, PartialEq)]
pub enum StartError {
    Config(ConfigError),
    /// The prefetch budget was refused (GPU §2.9).
    Prefetch(PrefetchError),
    /// Bounded staging could not be reserved, so nothing starts (§3.5 step 2).
    Reservation(ReservationRefusal),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(f, "invalid executor configuration: {error}"),
            Self::Prefetch(error) => write!(f, "invalid prefetch budget: {error}"),
            Self::Reservation(refusal) => write!(f, "staging could not be reserved: {refusal}"),
        }
    }
}

impl std::error::Error for StartError {}

/// Why the executor takes no new work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unavailable {
    Closed,
    /// A backend contract was broken; staging stays held because its use is unknown.
    Faulted {
        fault: ExecutorFault,
    },
}

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("the executor is closed"),
            Self::Faulted { fault } => write!(f, "the executor stopped after a fault: {fault}"),
        }
    }
}

impl std::error::Error for Unavailable {}

/// A broken backend contract. The executor stops: it starts nothing new and recycles no
/// staging, because it can no longer tell when a buffer is free (GPU-W04: no event reuse
/// race).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutorFault {
    /// A copy was enqueued but no completion event could be recorded after it.
    EventNotRecorded { error: BackendError },
    /// The backend returned an event that is still outstanding.
    EventReused { event: EventId },
    /// An event's state could not be read.
    EventQueryFailed { event: EventId, error: BackendError },
    /// The backend returned a ticket of a read still in flight.
    ReadTicketReused { ticket: ReadTicket },
    /// A read reported more bytes than were requested.
    ReadOverrun {
        ticket: ReadTicket,
        requested_bytes: u64,
        reported_bytes: u64,
    },
    /// Staging bookkeeping found a buffer in an impossible state.
    StagingMisuse { buffer: StagingBuffer },
    /// A read reported a path that is neither the one it was asked to take nor that
    /// path's host fallback (GPU-T21).
    PathNotRequested {
        ticket: ReadTicket,
        requested: TransferPath,
        reported: TransferPath,
    },
}

impl fmt::Display for ExecutorFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EventNotRecorded { error } => {
                write!(f, "no completion event was recorded after a copy: {error}")
            }
            Self::EventReused { event } => {
                write!(
                    f,
                    "the backend reused {event} before its completion was observed"
                )
            }
            Self::EventQueryFailed { event, error } => {
                write!(f, "{event} could not be queried: {error}")
            }
            Self::ReadTicketReused { ticket } => {
                write!(f, "the backend reused read ticket {} in flight", ticket.0)
            }
            Self::ReadOverrun {
                ticket,
                requested_bytes,
                reported_bytes,
            } => write!(
                f,
                "read {} reported {reported_bytes} bytes for a {requested_bytes}-byte request",
                ticket.0
            ),
            Self::StagingMisuse { buffer } => {
                write!(
                    f,
                    "staging slot {} of {:?} was misused",
                    buffer.slot, buffer.place
                )
            }
            Self::PathNotRequested {
                ticket,
                requested,
                reported,
            } => write!(
                f,
                "read {} asked for {requested:?} and reported {reported:?}",
                ticket.0
            ),
        }
    }
}

impl std::error::Error for ExecutorFault {}

/// Why a gated read method a request requires cannot be used (INT-06: a required
/// feature that cannot be enabled refuses the load).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MethodUnavailable {
    /// The backend does not implement it.
    NotImplemented,
    /// GPUDirect Storage needs a staging pool on the destination GPU that holds a batch.
    NoDeviceStaging,
    /// The evidence that enabled it is no longer fresh, or is from another clock
    /// session; plan the load again.
    EvidenceExpired,
    /// The registry no longer holds evidence that meets the plan's requirement, such as
    /// after a configuration change invalidated it (CORE-01), or the executor has no
    /// registry to recheck it in; plan the load again.
    EvidenceWithdrawn,
    /// The evidence gate's plan did not enable it.
    NotEnabled,
    /// A CUDA mechanism on a runtime not known to compute on CUDA (GPU §3.8); derive the
    /// permissions from the runtime's [`BackendRuntime`](crate::model_memory::backends).
    NotOnCuda { platform: ComputePlatform },
    /// A CUDA mechanism on a runtime declared on CUDA whose platform fresh CORE-01
    /// evidence does not show now (GPU §3.8): no platform policy, no or stale evidence,
    /// or evidence of another platform.
    PlatformNotShown { refusal: PlatformRefusal },
    /// Another required method would read the same bytes; one read uses one method.
    ConflictsWith { other: ReadMethod },
    /// Only local files can be read with it.
    WrongSource,
}

impl fmt::Display for MethodUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented => f.write_str("the backend does not implement it"),
            Self::NoDeviceStaging => {
                f.write_str("the destination GPU has no staging pool that holds a batch")
            }
            Self::EvidenceExpired => {
                f.write_str("the evidence that enabled it is no longer fresh; plan the load again")
            }
            Self::EvidenceWithdrawn => f.write_str(
                "the evidence registry no longer holds what enabled it; plan the load again",
            ),
            Self::NotEnabled => f.write_str("the evidence gate's plan did not enable it"),
            Self::NotOnCuda { platform } => write!(
                f,
                "it is a CUDA mechanism and the runtime computes on {platform}"
            ),
            Self::PlatformNotShown { refusal } => {
                write!(f, "it is a CUDA mechanism, and {refusal}")
            }
            Self::ConflictsWith { other } => write!(f, "{other} is required as well"),
            Self::WrongSource => f.write_str("only local files can be read with it"),
        }
    }
}

/// Why a read that asked for direct I/O was read buffered instead (GPU-T20: a supported
/// fallback with a diagnostic reason).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectIoUnavailable {
    /// The backend does not implement direct reads.
    NotImplemented,
    /// The read's offset or length is not a multiple of the direct-I/O block.
    Unaligned {
        offset_bytes: u64,
        length_bytes: u64,
        block_bytes: u64,
    },
    /// The file's filesystem refused a direct read, such as one without `O_DIRECT`; its
    /// later reads are made buffered as well.
    Refused { error: BackendError },
}

impl fmt::Display for DirectIoUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented => f.write_str("the backend does not implement direct reads"),
            Self::Unaligned {
                offset_bytes,
                length_bytes,
                block_bytes,
            } => write!(
                f,
                "the read of {length_bytes} bytes at {offset_bytes} is not aligned to the \
                 {block_bytes}-byte direct-I/O block"
            ),
            Self::Refused { error } => {
                write!(f, "the filesystem refused a direct read: {error}")
            }
        }
    }
}

impl std::error::Error for DirectIoUnavailable {}

/// Why a resolved manifest was refused before anything was reserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestError {
    WrongArtifact {
        requested: ContentKey,
        resolved: ContentKey,
    },
    WrongRepresentation {
        requested: ContentKey,
        resolved: ContentKey,
    },
    NoExtents,
    DuplicateIndex {
        index: u64,
    },
    EmptyExtent {
        index: u64,
    },
    /// An offset plus a length does not fit in 64 bits.
    Overflow {
        index: u64,
    },
    StoredOutsideObject {
        index: u64,
    },
    StoredOverlap {
        index: u64,
    },
    DecodedOverlap {
        index: u64,
    },
    /// A raw extent stores its decoded bytes, so its stored and decoded lengths are
    /// equal.
    RawLengthMismatch {
        index: u64,
    },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongArtifact { .. } => f.write_str("the catalog resolved another artifact"),
            Self::WrongRepresentation { .. } => {
                f.write_str("the catalog resolved another representation")
            }
            Self::NoExtents => f.write_str("the manifest has no extents"),
            Self::DuplicateIndex { index } => write!(f, "extent {index} appears twice"),
            Self::EmptyExtent { index } => write!(f, "extent {index} is empty"),
            Self::Overflow { index } => write!(f, "extent {index} overflows 64 bits"),
            Self::StoredOutsideObject { index } => {
                write!(f, "extent {index} lies past the end of the stored object")
            }
            Self::StoredOverlap { index } => {
                write!(f, "stored extent {index} overlaps another")
            }
            Self::DecodedOverlap { index } => {
                write!(f, "decoded extent {index} overlaps another")
            }
            Self::RawLengthMismatch { index } => {
                write!(
                    f,
                    "raw extent {index} has different stored and decoded lengths"
                )
            }
        }
    }
}

impl std::error::Error for ManifestError {}

/// Why a job's dependencies were refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DependencyError {
    NoDependencies,
    DuplicateId {
        id: DependencyId,
    },
    Empty {
        id: DependencyId,
    },
    RepeatedExtent {
        id: DependencyId,
        index: u64,
    },
    UnknownExtent {
        id: DependencyId,
        index: u64,
    },
    UnknownPrerequisite {
        id: DependencyId,
        requires: DependencyId,
    },
    /// The prerequisites form a cycle through this dependency.
    Cycle {
        id: DependencyId,
    },
}

impl fmt::Display for DependencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDependencies => f.write_str("the job names no dependencies"),
            Self::DuplicateId { id } => write!(f, "{id} appears twice"),
            Self::Empty { id } => write!(f, "{id} names no extents"),
            Self::RepeatedExtent { id, index } => write!(f, "{id} names extent {index} twice"),
            Self::UnknownExtent { id, index } => {
                write!(f, "{id} names extent {index}, which the manifest lacks")
            }
            Self::UnknownPrerequisite { id, requires } => {
                write!(f, "{id} requires {requires}, which the job lacks")
            }
            Self::Cycle { id } => write!(f, "the prerequisites of {id} form a cycle"),
        }
    }
}

impl std::error::Error for DependencyError {}

/// Why a batch plan from the extent-batching port was refused (GPU §2.4, §3.5 step 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BatchPlanError {
    Empty,
    UnknownExtent {
        index: u64,
    },
    /// An extent is in two batches, or twice in one.
    RepeatedExtent {
        index: u64,
    },
    /// Only adjacent extents coalesce, in offset order.
    NotAdjacent {
        index: u64,
    },
    /// The read range is not the members' range rounded out to the alignment, the one
    /// canonical padding rule.
    NotCanonical {
        read_offset_bytes: u64,
        read_length_bytes: u64,
        expected_offset_bytes: u64,
        expected_length_bytes: u64,
    },
    /// The read would not fit one staging slot.
    TooLarge {
        read_length_bytes: u64,
        limit_bytes: u64,
    },
    /// The decoded members would not fit one decode slot.
    DecodedTooLarge {
        decoded_bytes: u64,
        limit_bytes: u64,
    },
    /// An extent is in no batch.
    Uncovered {
        index: u64,
    },
}

impl fmt::Display for BatchPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("a batch has no extents"),
            Self::UnknownExtent { index } => write!(f, "a batch names unknown extent {index}"),
            Self::RepeatedExtent { index } => write!(f, "extent {index} is batched twice"),
            Self::NotAdjacent { index } => {
                write!(f, "extent {index} is not adjacent to the one before it")
            }
            Self::NotCanonical {
                read_offset_bytes,
                read_length_bytes,
                expected_offset_bytes,
                expected_length_bytes,
            } => write!(
                f,
                "a batch reads {read_length_bytes} bytes at {read_offset_bytes}; the aligned \
                 range is {expected_length_bytes} bytes at {expected_offset_bytes}"
            ),
            Self::TooLarge {
                read_length_bytes,
                limit_bytes,
            } => write!(
                f,
                "a {read_length_bytes}-byte batch exceeds the {limit_bytes}-byte staging slot"
            ),
            Self::DecodedTooLarge {
                decoded_bytes,
                limit_bytes,
            } => write!(
                f,
                "a batch decodes to {decoded_bytes} bytes, more than the {limit_bytes}-byte slot"
            ),
            Self::Uncovered { index } => write!(f, "extent {index} is in no batch"),
        }
    }
}

impl std::error::Error for BatchPlanError {}

/// Why extents could not be planned onto sources.
#[derive(Clone, Debug, PartialEq)]
pub enum PlanFailure {
    Batch(BatchPlanError),
    /// The multi-source planner refused (GPU §2.5).
    Sources(SourcesError),
}

impl fmt::Display for PlanFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Batch(error) => write!(f, "batching failed: {error}"),
            Self::Sources(error) => write!(f, "source planning failed: {error}"),
        }
    }
}

impl std::error::Error for PlanFailure {}

/// Why a job was refused. Nothing was reserved or started (§3.5 step 2).
#[derive(Clone, Debug, PartialEq)]
pub enum SubmitError {
    Unavailable(Unavailable),
    /// A job with this operation is still known; forget it first.
    DuplicateOperation {
        operation: OperationId,
    },
    /// The execution's authorization was revoked (INT-02); nothing more is admitted for
    /// it.
    ExecutionRevoked {
        execution: ExecutionId,
        revoked: AuthorizationEpoch,
    },
    Catalog(CatalogRefusal),
    Manifest(ManifestError),
    Dependency(DependencyError),
    /// A decoded extent would land outside the job's destination.
    DestinationOutOfBounds {
        index: u64,
    },
    /// An extent cannot fit one staging slot.
    ExtentExceedsStaging {
        index: u64,
        needed_bytes: u64,
        limit_bytes: u64,
    },
    /// A representation that decodes needs a read slot and a decode slot at once.
    StagingTooSmall {
        place: StagingPlace,
        slots: u32,
        needed_slots: u32,
    },
    /// Every source is an import-only bind or otherwise unreadable (Appendix A.3).
    NoReadableSource,
    /// The region is filled by another operation for a different key.
    DestinationConflict {
        index: u64,
    },
    /// An operation with this key expects other manifest values.
    ManifestMismatch {
        index: u64,
    },
    /// The job and the operation's subscribers share no usable source.
    NoCommonSource {
        index: u64,
    },
    /// The job and the operation's subscribers have loader plans that cannot share a
    /// read: one requires a method the other's plan did not enable.
    LoaderConflict {
        index: u64,
    },
    /// A gated method the job's loader plan requires cannot be used, so the job is
    /// refused rather than given the ordinary loader (INT-06).
    RequiredMethodUnavailable {
        method: ReadMethod,
        reason: MethodUnavailable,
    },
    /// A speculative job's value covers other bytes than the job moves.
    SpeculativeBytesMismatch {
        value_bytes: u64,
        job_bytes: u64,
    },
    /// The prefetch scheduler refused the job (GPU §2.9).
    Admission(PrefetchError),
    /// The destination could not be reserved (§3.5 step 2).
    Reservation(ReservationRefusal),
    Plan(PlanFailure),
    /// A CORE-05 grant for a network source cannot carry the job's reads (GPU-W09).
    Transfer {
        source: SourceId,
        error: TransferBindingError,
    },
}

impl fmt::Display for SubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(f, "{reason}"),
            Self::DuplicateOperation { operation } => {
                write!(f, "a job for {operation} already exists")
            }
            Self::ExecutionRevoked { execution, revoked } => write!(
                f,
                "{execution} was revoked at authorization epoch {revoked}; nothing more is \
                 admitted for it"
            ),
            Self::Catalog(refusal) => write!(f, "the catalog refused: {refusal}"),
            Self::Manifest(error) => write!(f, "the manifest was refused: {error}"),
            Self::Dependency(error) => write!(f, "the dependencies were refused: {error}"),
            Self::DestinationOutOfBounds { index } => {
                write!(f, "extent {index} would land outside the destination")
            }
            Self::ExtentExceedsStaging {
                index,
                needed_bytes,
                limit_bytes,
            } => write!(
                f,
                "extent {index} needs {needed_bytes} bytes of staging; a slot holds {limit_bytes}"
            ),
            Self::StagingTooSmall {
                place,
                slots,
                needed_slots,
            } => write!(
                f,
                "the {place:?} pool has {slots} slot(s); decoding needs {needed_slots} at once"
            ),
            Self::NoReadableSource => f.write_str(
                "no source can be read on the transfer path; an import-only bind is never a \
                 read source",
            ),
            Self::DestinationConflict { index } => write!(
                f,
                "extent {index} would fill a region another operation is filling"
            ),
            Self::ManifestMismatch { index } => write!(
                f,
                "extent {index} differs from the shared operation's manifest entry"
            ),
            Self::NoCommonSource { index } => write!(
                f,
                "extent {index} has no source both this job and the shared operation may use"
            ),
            Self::LoaderConflict { index } => write!(
                f,
                "extent {index} is shared with a job whose loader plan cannot share its read"
            ),
            Self::RequiredMethodUnavailable { method, reason } => {
                write!(
                    f,
                    "the load requires {method}, which cannot be used: {reason}"
                )
            }
            Self::SpeculativeBytesMismatch {
                value_bytes,
                job_bytes,
            } => write!(
                f,
                "the prefetch value covers {value_bytes} bytes but the job moves {job_bytes}"
            ),
            Self::Admission(error) => write!(f, "admission refused: {error}"),
            Self::Reservation(refusal) => {
                write!(f, "the destination was not reserved: {refusal}")
            }
            Self::Plan(failure) => write!(f, "{failure}"),
            Self::Transfer { source, error } => write!(f, "the grant for {source}: {error}"),
        }
    }
}

impl std::error::Error for SubmitError {}

/// Why one attempt at one extent failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttemptFailure {
    /// The read failed.
    Read {
        error: BackendError,
    },
    /// The source ended before the extent did.
    Truncated {
        needed_end_bytes: u64,
        read_end_bytes: u64,
    },
    /// The stored bytes are not the manifest's (§3.5: never a warning followed by use).
    StoredMismatch {
        expected: Digest,
        found: Digest,
    },
    /// Hashing the stored bytes failed.
    Verify {
        error: BackendError,
    },
    Decode {
        error: BackendError,
    },
    DecodedLengthMismatch {
        expected_bytes: u64,
        found_bytes: u64,
    },
    /// The decoded content key is not the manifest's.
    DecodedMismatch {
        expected: ContentKey,
        found: ContentKey,
    },
    /// Hashing the decoded bytes failed.
    Validate {
        error: BackendError,
    },
    /// The copy could not be enqueued.
    Copy {
        error: BackendError,
    },
    /// The copy's completion event reported failure.
    CopyFailed,
    /// A read method the loader plan requires cannot be used; the ordinary loader never
    /// replaces it (INT-06).
    RequiredMethodUnavailable {
        method: ReadMethod,
        reason: MethodUnavailable,
    },
    /// The transport of a CORE-05 transfer failed mid-read: its session was interrupted
    /// and resumes in a new attempt under the same envelope, so the source is not blamed
    /// (INT-08).
    TransportInterrupted {
        error: BackendError,
    },
    /// No CORE-05 session took the read's chunk, which was dropped by an interruption or
    /// delivered after its deadline: its bytes are not used.
    ChunkRefused {
        refusal: TransferRefusal,
    },
}

impl AttemptFailure {
    /// Whether the source is to blame; it is then blacklisted for the job (§3.5).
    pub fn is_source_fault(&self) -> bool {
        match self {
            Self::Read { error } => error.kind.is_source_fault(),
            Self::Truncated { .. } | Self::StoredMismatch { .. } => true,
            Self::Verify { .. }
            | Self::Decode { .. }
            | Self::DecodedLengthMismatch { .. }
            | Self::DecodedMismatch { .. }
            | Self::Validate { .. }
            | Self::Copy { .. }
            | Self::CopyFailed
            | Self::RequiredMethodUnavailable { .. }
            | Self::TransportInterrupted { .. }
            | Self::ChunkRefused { .. } => false,
        }
    }

    /// Whether no retry can succeed: a copy into a stale allocation, or a required read
    /// method that cannot be used without a new plan.
    pub fn is_permanent(&self) -> bool {
        match self {
            Self::Copy { error } => {
                error.kind == super::backend::BackendErrorKind::StaleDestination
            }
            Self::RequiredMethodUnavailable { .. } => true,
            _ => false,
        }
    }
}

impl fmt::Display for AttemptFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { error } => write!(f, "the read failed: {error}"),
            Self::Truncated {
                needed_end_bytes,
                read_end_bytes,
            } => write!(
                f,
                "the source ended at byte {read_end_bytes}, before byte {needed_end_bytes}"
            ),
            Self::StoredMismatch { expected, found } => write!(
                f,
                "hash mismatch: the stored extent hashes to {found}, not {expected}; it is \
                 not used"
            ),
            Self::Verify { error } => write!(f, "hashing the stored extent failed: {error}"),
            Self::Decode { error } => write!(f, "decoding failed: {error}"),
            Self::DecodedLengthMismatch {
                expected_bytes,
                found_bytes,
            } => write!(
                f,
                "decoding produced {found_bytes} bytes instead of {expected_bytes}"
            ),
            Self::DecodedMismatch { expected, found } => write!(
                f,
                "hash mismatch: the decoded extent hashes to {found}, not {expected}; it is \
                 not used"
            ),
            Self::Validate { error } => write!(f, "hashing the decoded extent failed: {error}"),
            Self::Copy { error } => write!(f, "the copy could not be enqueued: {error}"),
            Self::CopyFailed => f.write_str("the copy failed on the device"),
            Self::RequiredMethodUnavailable { method, reason } => {
                write!(
                    f,
                    "the load requires {method}, which cannot be used: {reason}"
                )
            }
            Self::TransportInterrupted { error } => {
                write!(f, "the transfer's transport failed and resumes: {error}")
            }
            Self::ChunkRefused { refusal } => {
                write!(f, "the transfer did not take the read: {refusal}")
            }
        }
    }
}

impl std::error::Error for AttemptFailure {}

/// One attempt at one extent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    /// 1 for the first try.
    pub number: u32,
    /// The source the bytes came from; `None` when no source was read.
    pub source: Option<SourceId>,
    pub failure: AttemptFailure,
}

/// Why an extent was given up.
#[derive(Clone, Debug, PartialEq)]
pub enum ExtentFailure {
    /// Every allowed attempt failed (§3.5: a bounded number of retries).
    RetriesExhausted { attempts: Vec<Attempt> },
    /// Every source is blacklisted for a subscriber or unusable.
    NoEligibleSource { attempts: Vec<Attempt> },
    /// The last attempt failed in a way no retry can fix.
    Permanent { attempts: Vec<Attempt> },
    /// The remaining extents could not be planned onto sources.
    Unplannable {
        failure: PlanFailure,
        attempts: Vec<Attempt>,
    },
}

impl ExtentFailure {
    /// Every attempt made, in order.
    pub fn attempts(&self) -> &[Attempt] {
        match self {
            Self::RetriesExhausted { attempts }
            | Self::NoEligibleSource { attempts }
            | Self::Permanent { attempts }
            | Self::Unplannable { attempts, .. } => attempts,
        }
    }
}

impl fmt::Display for ExtentFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RetriesExhausted { attempts } => {
                write!(f, "all {} attempts failed", attempts.len())
            }
            Self::NoEligibleSource { attempts } => write!(
                f,
                "no usable source remains after {} attempt(s)",
                attempts.len()
            ),
            Self::Permanent { .. } => f.write_str("the extent cannot be transferred"),
            Self::Unplannable { failure, .. } => write!(f, "{failure}"),
        }?;
        if let Some(last) = self.attempts().last() {
            write!(f, "; last: {}", last.failure)?;
        }
        Ok(())
    }
}

/// Why a job failed: one of its extents was given up.
#[derive(Clone, Debug, PartialEq)]
pub struct JobFailure {
    pub extent: u64,
    pub failure: ExtentFailure,
}

impl fmt::Display for JobFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "extent {} failed: {}", self.extent, self.failure)
    }
}

/// Why a job could not be cancelled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CancelError {
    Unavailable(Unavailable),
    UnknownJob { operation: OperationId },
    NotRunning { operation: OperationId },
}

impl fmt::Display for CancelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(f, "{reason}"),
            Self::UnknownJob { operation } => write!(f, "no job for {operation}"),
            Self::NotRunning { operation } => write!(f, "the job for {operation} has finished"),
        }
    }
}

impl std::error::Error for CancelError {}

/// Why a job could not be promoted.
#[derive(Clone, Debug, PartialEq)]
pub enum PromoteError {
    Unavailable(Unavailable),
    UnknownJob {
        operation: OperationId,
    },
    NotSpeculative {
        operation: OperationId,
    },
    /// Only a running job, or a finished speculative one whose bytes are unused, can be
    /// promoted.
    Finished {
        operation: OperationId,
    },
    Scheduler(PrefetchError),
}

impl fmt::Display for PromoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(f, "{reason}"),
            Self::UnknownJob { operation } => write!(f, "no job for {operation}"),
            Self::NotSpeculative { operation } => {
                write!(f, "the job for {operation} is already foreground work")
            }
            Self::Finished { operation } => {
                write!(f, "the job for {operation} failed or was cancelled")
            }
            Self::Scheduler(error) => write!(f, "the prefetch scheduler refused: {error}"),
        }
    }
}

impl std::error::Error for PromoteError {}

/// Why a job record could not be forgotten.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForgetError {
    UnknownJob { operation: OperationId },
    StillRunning { operation: OperationId },
}

impl fmt::Display for ForgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownJob { operation } => write!(f, "no job for {operation}"),
            Self::StillRunning { operation } => {
                write!(f, "the job for {operation} is running; cancel it first")
            }
        }
    }
}

impl std::error::Error for ForgetError {}

/// Why a destination allocation could not be retired.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetireError {
    Unavailable(Unavailable),
    /// A running job or unfinished operation still targets the allocation.
    InUse {
        allocation: AllocationKey,
    },
}

impl fmt::Display for RetireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(f, "{reason}"),
            Self::InUse { .. } => f.write_str(
                "the allocation still has running jobs or unfinished operations; cancel them \
                 and let them drain first",
            ),
        }
    }
}

impl std::error::Error for RetireError {}

/// Why the executor could not close.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseError {
    AlreadyClosed,
    /// Staging stays held after a fault, because its use is unknown.
    Faulted {
        fault: ExecutorFault,
    },
    /// Jobs, operations, reads or copies remain.
    Busy,
}

impl fmt::Display for CloseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyClosed => f.write_str("the executor is already closed"),
            Self::Faulted { fault } => {
                write!(f, "staging stays held after a fault: {fault}")
            }
            Self::Busy => f.write_str(
                "jobs, operations or transfers remain; finish or cancel them and retire their \
                 destinations first",
            ),
        }
    }
}

impl std::error::Error for CloseError {}
