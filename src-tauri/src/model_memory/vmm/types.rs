//! Identifiers and plain values of the CUDA VMM model (GPU part §3.7, Appendix E).

use std::fmt;

use serde::{Deserialize, Serialize};

use super::canonical::VerifiedCanonicalCopy;
use crate::foundation::evidence::ShareableHandle;
use crate::foundation::ids::{ContentKey, Digest};

/// An identifier that the driver, or the host that runs the processes, hands out.
macro_rules! driver_id {
    ($(#[$doc:meta])* $name:ident($inner:ty)) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub $inner);

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

driver_id!(
    /// A runner process on one host. Handles, addresses, streams and events belong to one
    /// process; a receiver of shared memory has its own reservation (Appendix E step 7).
    ProcessId(u32)
);
driver_id!(
    /// A CUDA device ordinal: "device k" of Appendix E steps 1 and 3.
    DeviceOrdinal(u32)
);
driver_id!(
    /// A physical allocation handle in one process (`CUmemGenericAllocationHandle`), from
    /// `cuMemCreate` or `cuMemImportFromShareableHandle`.
    PhysicalHandle(u64)
);
driver_id!(
    /// An exported shareable handle such as a POSIX file descriptor
    /// (`cuMemExportToShareableHandle`, Appendix E step 7).
    SharedHandle(u64)
);
driver_id!(
    /// A legacy IPC handle (`cudaIpcMemHandle_t`, Appendix E step 8).
    IpcMemHandle(u64)
);
driver_id!(
    /// A CUDA stream of one process.
    StreamId(u32)
);
driver_id!(
    /// The completion event of work enqueued on a stream.
    EventId(u64)
);

/// A device virtual address in one process (`CUdeviceptr`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VirtualAddress(pub u64);

impl VirtualAddress {
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The address `bytes` further on; `None` past the end of the address space.
    pub fn checked_add(self, bytes: u64) -> Option<Self> {
        self.0.checked_add(bytes).map(Self)
    }
}

impl fmt::Display for VirtualAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// The addresses `[start, start + length_bytes)` of one process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AddressRange {
    pub start: VirtualAddress,
    pub length_bytes: u64,
}

impl AddressRange {
    pub const fn new(start: VirtualAddress, length_bytes: u64) -> Self {
        Self {
            start,
            length_bytes,
        }
    }

    /// One past the last address; `None` when the range runs past the address space.
    pub fn end(self) -> Option<u64> {
        self.start.0.checked_add(self.length_bytes)
    }

    /// Whether `inner` lies wholly within this range.
    pub fn contains(self, inner: Self) -> bool {
        match (self.end(), inner.end()) {
            (Some(end), Some(inner_end)) => inner.start.0 >= self.start.0 && inner_end <= end,
            _ => false,
        }
    }

    /// Whether the two ranges share an address. A range that runs past the address space
    /// is taken to overlap everything.
    pub fn overlaps(self, other: Self) -> bool {
        match (self.end(), other.end()) {
            (Some(end), Some(other_end)) => self.start.0 < other_end && other.start.0 < end,
            _ => true,
        }
    }
}

impl fmt::Display for AddressRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} + {} bytes", self.start, self.length_bytes)
    }
}

/// An identifier the model hands out; it means nothing outside one [`VmmModel`].
///
/// [`VmmModel`]: super::VmmModel
macro_rules! model_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(u64);

        impl $name {
            pub(super) const fn new(value: u64) -> Self {
                Self(value)
            }

            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

model_id!(
    /// One physical allocation in the ownership ledger, tracked apart from the virtual
    /// mappings of it (§3.7).
    PhysicalId
);
model_id!(
    /// One tensor view built by offset (Appendix E step 4).
    ViewId
);
model_id!(
    /// One captured CUDA graph (§3.7).
    GraphId
);
model_id!(
    /// One workspace buffer a graph uses (§3.7: graph reuse needs compatible workspaces).
    WorkspaceId
);
model_id!(
    /// One export of a physical allocation: a shareable handle (step 7) or a legacy IPC
    /// handle (step 8).
    ExportId
);

/// The allocation properties `cuMemGetAllocationGranularity` and `cuMemCreate` are given.
///
/// Appendix E step 1 fixes `CU_MEM_ALLOCATION_TYPE_PINNED` and
/// `CU_MEM_LOCATION_TYPE_DEVICE`. The device and the requested shareable handle type vary,
/// and the reported granularity may differ with each, so granularity is probed for these
/// exact properties (§3.7: "the exact handle type and device").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AllocationProperties {
    pub device: DeviceOrdinal,
    /// The handle type the allocation can be exported as; `None` when it is never exported.
    pub requested_handle: Option<ShareableHandle>,
}

/// What enqueued work does with the addresses it touches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkKind {
    /// Populating or refilling device memory (Appendix E steps 4 and 6).
    CopyToDevice,
    /// Copying device memory to the host before a park without a verified canonical copy
    /// (step 5).
    CopyToHost,
    /// A kernel reading through a tensor view.
    Kernel,
    /// A CUDA graph replay.
    GraphReplay,
}

/// One artifact as one process holds it: a VMM reservation, a backend pool allocation or
/// a dedicated legacy allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MappingKey {
    pub process: ProcessId,
    pub artifact: Digest,
}

impl fmt::Display for MappingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "artifact {} in process {}", self.artifact, self.process)
    }
}

/// One transport batch of an immutable artifact, in artifact order (Appendix E step 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchSpec {
    pub length_bytes: u64,
    /// The digest verification must find before the batch is published (step 4).
    pub digest: Digest,
}

/// An immutable artifact split into transport batches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactLayout {
    pub artifact: Digest,
    /// The content key of the artifact's bytes, all batches in order: what a verified
    /// canonical copy must hold for a clean-drop park (Appendix E step 5).
    pub content: ContentKey,
    pub batches: Vec<BatchSpec>,
}

/// How a park keeps the artifact reconstructible (Appendix E step 5).
///
/// It authorizes dropping GPU memory, so it is never read back from JSON: a clean drop
/// carries a [`VerifiedCanonicalCopy`], which only a real check makes. A clone carries the
/// proof's clone, which never holds the original's catalog lease.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ParkSource {
    /// Clean-drop parking: a verified canonical copy of exactly the artifact's content
    /// exists, so nothing is copied back. A catalog proof stays with the artifact,
    /// holding its lease, until the artifact is refilled.
    CleanDrop { copy: VerifiedCanonicalCopy },
    /// Clean-drop parking on the catalog proof the artifact still holds from an earlier
    /// park, before it was refilled.
    HeldCopy,
    /// No verified canonical copy: every published batch is copied to the host on
    /// `stream`, and the park waits for those copies.
    CopyBack { stream: StreamId },
}

/// Where one batch is in the mapping protocol (§3.7; Appendix E steps 3–6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchState {
    /// No physical memory backs the batch: before it is first mapped, and after a park.
    Empty,
    /// Created or imported, mapped and accessible, but not populated.
    Ready,
    /// A copy into the batch is enqueued; its completion event is outstanding.
    Populating,
    /// Verification failed; the batch must be populated again before it is published.
    Rejected,
    /// Complete and verified, so work over it may run.
    Published,
}

/// Whether an artifact's memory is in use, draining for a park, or parked (Appendix E
/// steps 5 and 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    /// Batches may be mapped, populated, published and used.
    Active,
    /// A park has begun: no new work is admitted while the range becomes quiescent.
    Draining,
    /// Unmapped or dropped; physical memory is released or reported as retained.
    Parked,
}

impl fmt::Display for Lifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Active => "active",
            Self::Draining => "draining for a park",
            Self::Parked => "parked",
        })
    }
}

impl fmt::Display for BatchState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "empty",
            Self::Ready => "mapped but not populated",
            Self::Populating => "populating",
            Self::Rejected => "rejected by verification",
            Self::Published => "published",
        })
    }
}
