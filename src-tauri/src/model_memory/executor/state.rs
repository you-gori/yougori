//! The executor's bookkeeping: jobs, shared operations, loads and work in flight.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::backend::StagingBuffer;
use super::error::Attempt;
use super::job::{DependencyId, JobProgress, JobStatus};
use super::model::{
    AllocationKey, Destination, FlightKey, LoaderPermissions, ManifestExtent, Priority, ReadMethod,
    SourceCandidate, SourceKind, TransferPath,
};
use super::network::JobTransfer;
use super::ports::ReservationId;
use crate::foundation::ids::{ContentKey, ExecutionId, GpuDeviceKey, MonotonicTime, OperationId};
use crate::foundation::transfer::ChunkPermit;
use crate::model_memory::math::sources::{CutSpec, MultiSourceLoad};
use crate::model_memory::math::SourceId;

/// One shared operation: one extent, in one representation, into one destination region
/// (§3.5 singleflight). Subscribers come and go; the operation keeps its identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FlightId(pub(super) u64);

impl fmt::Display for FlightId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "operation {}", self.0)
    }
}

/// Where a shared operation is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlightPhase {
    /// Waiting to be planned or read.
    Queued,
    /// Its batch was dispatched to a source and waits for staging.
    Ready,
    Reading,
    /// Verified and copying; its completion event is not yet observed.
    Copying,
    /// Its completion event was observed; the region holds verified bytes.
    Delivered,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct LoadId(pub(super) u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FlightState {
    Unplanned,
    Planned { load: LoadId, batch: usize },
    Reading,
    Copying,
    Delivered,
}

pub(super) struct Flight {
    pub(super) key: FlightKey,
    pub(super) extent: ManifestExtent,
    pub(super) object_length_bytes: u64,
    pub(super) subscribers: BTreeSet<OperationId>,
    /// The destination region's reservation: held until the operation is delivered,
    /// reclaimed or given up, then returned (the ledger keeps counting it until the host
    /// observes the release).
    pub(super) reservation: Option<ReservationId>,
    pub(super) state: FlightState,
    pub(super) attempts: Vec<Attempt>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum BatchState {
    Queued,
    Ready { source: SourceId },
    Reading,
    Done,
}

pub(super) struct LoadBatch {
    pub(super) members: Vec<FlightId>,
    pub(super) read_offset_bytes: u64,
    pub(super) read_length_bytes: u64,
    pub(super) state: BatchState,
}

/// Batches of extents planned onto sources by the multi-source planner (GPU §2.5).
pub(super) struct Load {
    pub(super) plan: MultiSourceLoad,
    pub(super) batches: Vec<LoadBatch>,
    pub(super) kinds: BTreeMap<SourceId, SourceKind>,
    /// Each source's concurrency cap, which holds across every load of the executor.
    pub(super) caps: BTreeMap<SourceId, u32>,
    pub(super) artifact: ContentKey,
    /// The stored object the batches read.
    pub(super) representation: ContentKey,
    pub(super) allocation: AllocationKey,
}

pub(super) struct ReadInFlight {
    /// The chunk each subscriber's CORE-05 session admitted, for a network source.
    pub(super) permits: Vec<(OperationId, ChunkPermit)>,
    pub(super) load: LoadId,
    pub(super) batch: usize,
    pub(super) source: SourceId,
    pub(super) path: TransferPath,
    pub(super) method: ReadMethod,
    /// The destination GPU, whose copy stream records the completion events.
    pub(super) device: GpuDeviceKey,
    pub(super) read_slot: StagingBuffer,
    pub(super) decode_slot: Option<StagingBuffer>,
    pub(super) started_at: MonotonicTime,
    pub(super) members: Vec<FlightId>,
    pub(super) read_offset_bytes: u64,
    pub(super) read_length_bytes: u64,
}

pub(super) struct CopyInFlight {
    pub(super) flight: FlightId,
    pub(super) buffer: StagingBuffer,
    pub(super) source: SourceId,
    pub(super) path: TransferPath,
    pub(super) enqueued_at: MonotonicTime,
    pub(super) bytes: u64,
}

pub(super) struct DependencyState {
    pub(super) id: DependencyId,
    pub(super) extents: Vec<u64>,
    pub(super) requires: Vec<DependencyId>,
    pub(super) usable: bool,
}

pub(super) struct Job {
    /// The execution the job serves; its revocation cancels the job.
    pub(super) execution: ExecutionId,
    pub(super) priority: Priority,
    pub(super) destination: Destination,
    pub(super) loader: LoaderPermissions,
    /// Readable sources in the catalog's order.
    pub(super) sources: Vec<SourceCandidate>,
    pub(super) cuts: Vec<CutSpec>,
    /// Sources that failed this job (§3.5).
    pub(super) blacklist: BTreeSet<SourceId>,
    /// Prerequisites before dependents.
    pub(super) dependencies: Vec<DependencyState>,
    pub(super) flights: BTreeMap<u64, FlightId>,
    pub(super) committed: BTreeSet<u64>,
    pub(super) status: JobStatus,
    pub(super) progress: JobProgress,
    pub(super) progress_dirty: bool,
    /// Whether network sources are read only through the job's CORE-05 sessions.
    pub(super) sessions_required: bool,
    /// The job's CORE-05 transfers, per network source (GPU-W09).
    pub(super) transfers: BTreeMap<SourceId, JobTransfer>,
}

impl Job {
    /// Whether this job may read from `source`: it lists the source, has not blacklisted
    /// it, gets a local file when it requires a gated method, the only source such a
    /// method reads, and holds a usable CORE-05 session for a network source where
    /// sessions are required (GPU-W09).
    pub(super) fn allows(&self, source: &SourceId, kind: SourceKind) -> bool {
        !self.blacklist.contains(source)
            && (self.loader.required().is_empty() || kind == SourceKind::LocalFile)
            && self
                .sources
                .iter()
                .any(|candidate| candidate.spec.id == *source && candidate.kind == kind)
            && (!kind.is_network()
                || !self.sessions_required
                || self.transfers.get(source).is_some_and(JobTransfer::usable))
    }
}

/// Staging slots one batch holds at once: the read slot, and a decode slot when some of
/// its extents decode.
pub(super) fn slots_needed(decodes: bool) -> u32 {
    if decodes {
        2
    } else {
        1
    }
}
