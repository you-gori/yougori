//! P05: the CUDA VMM and allocation lifetime model of the GPU part of
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md (§3.7 and Appendix E; context GPU-W05;
//! §1.1 rows 305 and 309).
//!
//! There is no real CUDA here. [`VmmModel`] is the governor's typed model of the
//! dedicated-allocation CUDA VMM experiment and its ordinary-allocation fallback. It
//! makes the driver calls of Appendix E through [`VmmDriver`], and [`FakeDriver`]
//! refuses any call outside Appendix E's order.
//!
//! - Evidence: allocation granularity and handle-type support come from fresh CORE-01
//!   evidence for the exact runtime, device and handle type, and are never assumed (§3.7,
//!   §1.1 row 309). The process's own driver answer at step 1 is only cross-checked
//!   against it ([`DriverGranularityReport`]).
//! - The mapping protocol: reserve once per artifact, then per batch create, map, set
//!   access and populate, and publish only after completion and verification. Parking
//!   waits for quiescence before it unmaps, and retained views are never callable while
//!   their addresses are unmapped (§3.7, steps 1–6). A clean drop skips the copy back only
//!   with a [`VerifiedCanonicalCopy`] of exactly the artifact's content, which only a
//!   CORE-02 catalog check or the residency rule of clean eviction makes (step 5). A
//!   catalog proof holds a catalog lease until the artifact is refilled.
//! - The ownership ledger: physical allocations are tracked apart from mappings. Exports,
//!   imports, graph references, other mappings and pool views hold memory, and the last
//!   reference is closed deliberately (§3.7, step 5).
//! - Sharing: only dedicated, published allocations, created for the exact handle type
//!   and sized to the reported granularity, are exported, and only within one runtime
//!   whose loader plan from the CORE-01 gate enabled that IPC family (§3.7, steps 7–8;
//!   INT-06). A released handle never blocks a new import, and once an exporter exits
//!   ([`VmmModel::process_exited`]) its imports are no longer callable (GPU-T22, GPU-T23).
//! - The fallback: one backend allocation per artifact, explicit view destruction and
//!   rebinding, no pool freed under live views, and graphs recaptured without pointer
//!   stability (§3.7, step 9).
//! - Graphs: reuse needs a matching model, kernels, shapes, arguments, addresses,
//!   workspaces and resource lifetimes; addresses alone never suffice (§3.7, §1.1 row
//!   305).
//!
//! Everything is pure, synchronous and deterministic. Time comes only from the CORE-01
//! evidence registry's clock, and work completes only when the driver says it has.

mod canonical;
mod driver;
mod error;
mod evidence;
mod fake;
mod graph;
mod ledger;
mod model;
mod sharing;
mod types;

#[cfg(test)]
mod tests;

pub use canonical::{CanonicalCopyRefusal, CanonicalSource, VerifiedCanonicalCopy};
pub use driver::{DriverCall, DriverError, OrderViolation, RecordedCall, Refusal, VmmDriver};
pub use error::{GraphMismatch, NotCallableReason, VmmError};
pub use evidence::{
    DriverGranularityReport, Granularity, GranularityRefusal, GranularityResult, ProcessContext,
};
pub use fake::{FakeDeviceSpec, FakeDriver};
pub use graph::{GraphExecutionKey, GraphResource};
pub use ledger::{AllocationContents, AllocationKind, PhysicalInfo, ReferenceCount};
pub use model::{BatchInfo, ExitReport, ParkReport, RetainedAllocation, VmmModel, VmmOrigin};
pub use types::{
    AddressRange, AllocationProperties, ArtifactLayout, BatchSpec, BatchState, DeviceOrdinal,
    EventId, ExportId, GraphId, IpcMemHandle, Lifecycle, MappingKey, ParkSource, PhysicalHandle,
    PhysicalId, ProcessId, SharedHandle, StreamId, ViewId, VirtualAddress, WorkKind, WorkspaceId,
};
