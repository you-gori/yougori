//! GPU part §3.10: progress, persistence and recovery
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md lines 646–655, with S8 at lines
//! 137–161, GPU-W11 at lines 1141–1160 and today's progress states in Appendix A.1,
//! line 1487).
//!
//! CORE-06 (`foundation::events`) owns the §3.10 progress vocabulary: the envelope with
//! its operation, monotonic sequence, typed generations and phase; the
//! [`ProgressUpdate`](crate::foundation::events::ProgressUpdate) payload with resource,
//! completed, total and committed usable bytes, estimated remaining time with
//! confidence, queue reason and safe cancellation boundary; the coalescing progress
//! stream with its reconnect snapshot; and receiving-side reconciliation. It enforces
//! that a completed resource has every byte usable and that an ended operation has no
//! remaining time. CORE-04 (`foundation::coordination`) owns generations and leases.
//! This module keeps the MODELS parts:
//!
//! - [`estimate_remaining_time`] turns measured throughput into CORE-06's
//!   [`EtaEstimate`](crate::foundation::events::EtaEstimate) (line 648).
//! - [`ProgressPublisher`] folds extent reports into one CORE-06 progress update per
//!   operation on the hub's progress stream, never one per tensor, coalesces byte
//!   updates, and refuses GPU allocations the coordinator no longer honours (line 650).
//! - [`JobControl`] journals job intent, artifact commits, resumable verified extents
//!   and import state, never device pointers, leases or generations. Every start
//!   reconciles as after a daemon restart: the coordinator's recovery must have revived
//!   no lease and retired every earlier GPU allocation, the catalog's actual state
//!   decides what is committed, and unfinished jobs go back through the normal
//!   [`Loader`] (line 652).
//! - [`PublicProgress`] explains an event in plain language over today's five client
//!   states, without handles; stage timing exists only in [`DiagnosticProgress`]
//!   (line 654).

mod eta;
mod job;
mod journal;
mod ports;
mod public;
mod publisher;
mod recovery;

#[cfg(test)]
pub mod fakes;
#[cfg(test)]
mod plane_tests;
#[cfg(test)]
mod tests;

pub use eta::{
    estimate_remaining_time, range_confidence_percent, ThroughputSample, MIN_SEGMENTS_FOR_ESTIMATE,
};
pub use job::{
    ArtifactCommit, ImportState, JobIntent, JobKind, JobOutcome, LoadRequest, ResumePoint,
    VerifiedExtent,
};
pub use journal::{
    CorruptReason, JobRecord, Journal, JournalAction, JournalError, JournalOpened, JournalState,
    RecordRefusal, Recorded, JOURNAL_FILE_NAME, JOURNAL_FORMAT_VERSION,
};
pub use ports::{CatalogObjects, Loader, PortError, PortFailure, PortName};
pub use public::{client_state, ClientState, PublicProgress};
pub use publisher::{
    moves_bytes, DiagnosticLevel, DiagnosticProgress, ProgressPublisher, PublishError,
    PublishOutcome, PublishPolicy, PublisherStats, Stage, StageInterval, StageTiming, TrackRequest,
};
pub use recovery::{Cancellation, JobControl, JobError, RecoveryError, RecoveryReport, Submission};
