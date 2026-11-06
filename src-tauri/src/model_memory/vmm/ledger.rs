//! Physical allocation ownership, tracked apart from virtual mappings (GPU part §3.7;
//! Appendix E steps 3 and 5).
//!
//! Unmapping does not free physical memory: exports, imports, graph references, other
//! mappings and, for backend pools, live tensor views keep it alive. Every holder is
//! recorded per process handle, and memory is freed only when the last handle is released
//! by a deliberate call.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::types::{
    AllocationProperties, ExportId, GraphId, PhysicalHandle, ProcessId, ViewId, VirtualAddress,
};
use crate::foundation::ids::{Digest, GpuAllocationGeneration};

/// How a physical allocation was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum AllocationKind {
    /// `cuMemCreate` with these properties (Appendix E step 3).
    Vmm { properties: AllocationProperties },
    /// A dedicated `cudaMalloc` allocation (step 8).
    LegacyMalloc,
    /// One backend allocation in a private pool (step 9).
    BackendPool { expandable_segments: bool },
}

crate::foundation::strict_serde::strict_tag!(AllocationKind, "kind");

/// What a physical allocation holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "contents", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum AllocationContents {
    /// Exactly one batch of one immutable artifact, and nothing else: the only kind of
    /// allocation that may be exported (§3.7, step 7).
    Dedicated { artifact: Digest, batch: u32 },
    /// Private data, such as scratch space or several tenants' suballocations; never
    /// exported.
    Private { label: Digest },
}

crate::foundation::strict_serde::strict_tag!(AllocationContents, "contents");

/// What still holds a physical allocation through one process's handle (Appendix E step
/// 5: exports, imports and graph references count).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceCount {
    /// Mappings of the allocation in this process; for a pool or legacy allocation, its
    /// use as an artifact's current backing.
    pub mappings: u32,
    /// Tensor views bound to a pool or legacy allocation (§3.7: never free a pool while
    /// live tensors reference it).
    pub views: u32,
    /// Graphs holding the allocation.
    pub graphs: u32,
    /// Open exported shareable handles; counted for the owner only.
    pub exports: u32,
    /// Other processes' imported or opened handles; counted for the owner only.
    pub imports: u32,
}

impl ReferenceCount {
    pub fn total(self) -> u64 {
        [
            self.mappings,
            self.views,
            self.graphs,
            self.exports,
            self.imports,
        ]
        .into_iter()
        .map(u64::from)
        .sum()
    }

    pub fn is_zero(self) -> bool {
        self.total() == 0
    }
}

/// A physical allocation as the ledger records it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalInfo {
    pub kind: AllocationKind,
    pub contents: AllocationContents,
    pub size_bytes: u64,
    /// The generation of this allocation; re-creating a batch gets a new one (S3.1).
    pub generation: GpuAllocationGeneration,
    pub owner: ProcessId,
    /// True once every handle to it is released.
    pub freed: bool,
}

/// A process's handle as the driver names it, which decides how it is released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DriverHandle {
    /// Created or imported; released with `cuMemRelease`.
    Vmm(PhysicalHandle),
    /// A dedicated `cudaMalloc` allocation; released with `cudaFree`.
    Malloc(VirtualAddress),
    /// A backend pool allocation; returned to the pool.
    Pool(VirtualAddress),
    /// A consumer's opened legacy IPC mapping; closed with `cudaIpcCloseMemHandle`.
    IpcOpened(VirtualAddress),
}

/// One process's handle to a physical allocation, with everything that holds it.
#[derive(Clone, Debug)]
pub(super) struct HandleEntry {
    pub(super) driver: DriverHandle,
    pub(super) mappings: BTreeSet<VirtualAddress>,
    pub(super) views: BTreeSet<ViewId>,
    pub(super) graphs: BTreeSet<GraphId>,
    pub(super) released: bool,
}

impl HandleEntry {
    /// A handle whose memory is mapped, or in use as a backing, at `mapping`.
    pub(super) fn new(driver: DriverHandle, mapping: VirtualAddress) -> Self {
        Self {
            mappings: BTreeSet::from([mapping]),
            ..Self::unmapped(driver)
        }
    }

    pub(super) fn unmapped(driver: DriverHandle) -> Self {
        Self {
            driver,
            mappings: BTreeSet::new(),
            views: BTreeSet::new(),
            graphs: BTreeSet::new(),
            released: false,
        }
    }
}

/// One physical allocation and every handle to it.
#[derive(Clone, Debug)]
pub(super) struct PhysicalEntry {
    pub(super) kind: AllocationKind,
    pub(super) contents: AllocationContents,
    pub(super) size_bytes: u64,
    pub(super) generation: GpuAllocationGeneration,
    pub(super) owner: ProcessId,
    pub(super) handles: BTreeMap<ProcessId, HandleEntry>,
    pub(super) exports: BTreeSet<ExportId>,
    pub(super) freed: bool,
    /// The owner exited while other processes still held the allocation; their imports
    /// are no longer callable (GPU-T23).
    pub(super) orphaned_by: Option<ProcessId>,
}

fn count(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

impl PhysicalEntry {
    /// What holds the allocation through `process`'s handle. The owner's handle is also
    /// held by open exports and by every other process's handle that is not released.
    pub(super) fn references(&self, process: ProcessId) -> ReferenceCount {
        let mut references =
            self.handles
                .get(&process)
                .map_or_else(ReferenceCount::default, |handle| ReferenceCount {
                    mappings: count(handle.mappings.len()),
                    views: count(handle.views.len()),
                    graphs: count(handle.graphs.len()),
                    exports: 0,
                    imports: 0,
                });
        if process == self.owner {
            references.exports = count(self.exports.len());
            references.imports = count(
                self.handles
                    .iter()
                    .filter(|(holder, handle)| **holder != process && !handle.released)
                    .count(),
            );
        }
        references
    }

    /// Whether `process` holds a handle to the allocation that it has not released.
    pub(super) fn holds_live_handle(&self, process: ProcessId) -> bool {
        self.handles
            .get(&process)
            .is_some_and(|handle| !handle.released)
    }

    pub(super) fn info(&self) -> PhysicalInfo {
        PhysicalInfo {
            kind: self.kind,
            contents: self.contents,
            size_bytes: self.size_bytes,
            generation: self.generation,
            owner: self.owner,
            freed: self.freed,
        }
    }
}
