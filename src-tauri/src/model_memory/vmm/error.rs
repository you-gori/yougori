//! Typed refusals of the CUDA VMM model (GPU part §3.7, Appendix E).

use std::fmt;

use serde::Serialize;

use super::canonical::CanonicalCopyRefusal;
use super::driver::DriverError;
use super::evidence::GranularityRefusal;
use super::ledger::ReferenceCount;
use super::types::{
    BatchState, DeviceOrdinal, EventId, ExportId, GraphId, Lifecycle, MappingKey, PhysicalId,
    ProcessId, ViewId, VirtualAddress, WorkspaceId,
};
use crate::foundation::evidence::{
    EvidenceRefusal, NotEnabled, Optimization, ShareableHandle, SupportDetail,
};
use crate::foundation::ids::{ContentKey, Digest, GpuAllocationGeneration};

/// Why work over a range cannot run now (§3.7: retained tensors are never callable while
/// their addresses are unmapped; GPU-W05: no stale pointer execution).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum NotCallableReason {
    /// A park has begun, so no new work is admitted while the range drains.
    Draining,
    /// The artifact is parked: unmapped, or its allocation dropped.
    Parked,
    /// No physical memory is mapped behind this batch.
    Unmapped { batch: u32 },
    /// The batch is mapped but not published: its completion event or verification is
    /// outstanding (Appendix E step 4).
    NotPublished { batch: u32 },
    /// The view was bound to an allocation that has since been replaced; without pointer
    /// stability, views are rebuilt (§3.7).
    StaleAllocation {
        bound: GpuAllocationGeneration,
        current: Option<GpuAllocationGeneration>,
    },
    /// The process that created the imported memory exited. Recovery after an exporter's
    /// death is not defined per IPC family, so the memory is not used again: release it and
    /// import a live exporter's export (GPU-T23).
    ExporterGone { exporter: ProcessId },
}

impl fmt::Display for NotCallableReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Draining => f.write_str("the artifact is draining for a park"),
            Self::Parked => f.write_str("the artifact is parked"),
            Self::Unmapped { batch } => write!(f, "batch {batch} is not mapped"),
            Self::NotPublished { batch } => write!(
                f,
                "batch {batch} is not published: completion and verification come first"
            ),
            Self::StaleAllocation { bound, current } => match current {
                Some(current) => write!(
                    f,
                    "the view is bound to allocation generation {bound}, but the memory is now \
                     generation {current}; rebuild the view"
                ),
                None => write!(
                    f,
                    "the view is bound to allocation generation {bound}, which is gone; rebuild \
                     the view"
                ),
            },
            Self::ExporterGone { exporter } => write!(
                f,
                "process {exporter}, which exported this memory, exited; release it and import \
                 a live exporter's export"
            ),
        }
    }
}

/// Why a captured graph cannot be launched or reused (§3.7: graph reuse needs compatible
/// kernels, shapes, arguments, addresses, workspaces and resource lifetimes; §1.1 row
/// 305: addresses alone do not establish correctness).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "mismatch", rename_all = "snake_case")]
pub enum GraphMismatch {
    /// Another model: an address reservation alone never makes graphs interchangeable.
    Model,
    Kernels,
    Shapes,
    Arguments,
    /// Another list of resources.
    Resources,
    /// The resource resolves to another address now.
    Address {
        resource: usize,
        captured: VirtualAddress,
        current: VirtualAddress,
    },
    /// The memory was reallocated without pointer stability, even if the pointer value is
    /// equal; recapture the graph (§3.7).
    Reallocated {
        resource: usize,
    },
    /// The memory behind the resource was re-created at the same addresses; launching
    /// needs a successful reuse check first.
    Generation {
        resource: usize,
    },
    /// The resource is not usable now, so its lifetime does not cover a replay.
    Unavailable {
        resource: usize,
        reason: NotCallableReason,
    },
    /// The workspace was freed, reallocated or resized.
    Workspace {
        workspace: WorkspaceId,
    },
}

impl fmt::Display for GraphMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model => f.write_str(
                "the graph was captured for another model; matching addresses never make \
                 graphs interchangeable",
            ),
            Self::Kernels => f.write_str("the kernels differ"),
            Self::Shapes => f.write_str("the shapes differ"),
            Self::Arguments => f.write_str("the kernel arguments differ"),
            Self::Resources => f.write_str("the graph uses other resources"),
            Self::Address {
                resource,
                captured,
                current,
            } => write!(
                f,
                "resource {resource} was at {captured} when captured and is at {current} now"
            ),
            Self::Reallocated { resource } => write!(
                f,
                "resource {resource} was reallocated without pointer stability; recapture the \
                 graph"
            ),
            Self::Generation { resource } => write!(
                f,
                "the memory behind resource {resource} was re-created; check the graph for \
                 reuse before launching it"
            ),
            Self::Unavailable { resource, reason } => {
                write!(f, "resource {resource} is not usable: {reason}")
            }
            Self::Workspace { workspace } => {
                write!(f, "workspace {workspace} was freed, reallocated or resized")
            }
        }
    }
}

/// A refusal of the CUDA VMM model. A refused operation changes nothing, with two
/// exceptions: a [`VmmError::DigestMismatch`] rejects the batch, and a driver failure
/// partway through a park leaves the batches already unmapped unmapped.
///
/// Serialized with its own tag, so the tags of the wrapped evidence and driver errors
/// stay distinct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "vmm_error", rename_all = "snake_case")]
pub enum VmmError {
    UnknownProcess {
        process: ProcessId,
    },
    /// The process exited; nothing more is done on its behalf, and its exports and IPC
    /// handles are gone (GPU-T23).
    ProcessExited {
        process: ProcessId,
    },
    ProcessExists {
        process: ProcessId,
    },
    /// The properties name another device than the process's device k.
    WrongDevice {
        process: ProcessId,
        expected: DeviceOrdinal,
        found: DeviceOrdinal,
    },
    /// No usable granularity evidence (§3.7: probed, never assumed).
    Granularity(GranularityRefusal),
    /// The driver reported something no driver may report, such as a zero granularity.
    InvalidDriverReport {
        what: &'static str,
    },
    /// No usable CORE-01 evidence of handle-type support.
    Evidence(EvidenceRefusal),
    /// The evidence shows another handle type than the one requested (§3.7: the exact
    /// handle type).
    HandleTypeNotShown {
        requested: ShareableHandle,
        shown: SupportDetail,
    },
    EmptyLayout,
    TooManyBatches,
    EmptyBatch {
        batch: u32,
    },
    /// Every batch but the last must be a whole number of granules, so the artifact maps
    /// contiguously and views by offset stay valid.
    BatchNotAligned {
        batch: u32,
        length_bytes: u64,
        granularity_bytes: u64,
    },
    ZeroSize,
    SizeOverflow,
    /// The reservation is made once per artifact and kept for the process lifetime
    /// (Appendix E step 2).
    AlreadyPlanned {
        key: MappingKey,
    },
    UnknownArtifact {
        key: MappingKey,
    },
    UnknownBatch {
        key: MappingKey,
        batch: u32,
    },
    /// The operation does not apply to how this artifact is backed.
    WrongBacking {
        key: MappingKey,
        operation: &'static str,
    },
    NotInLifecycle {
        key: MappingKey,
        expected: Lifecycle,
        found: Lifecycle,
    },
    /// The batch is not in a state the operation accepts.
    BatchState {
        key: MappingKey,
        batch: u32,
        state: BatchState,
        operation: &'static str,
    },
    /// Publication waits for the completion event (Appendix E step 4).
    NotComplete {
        event: EventId,
    },
    /// Verification found another digest; the batch is rejected and never used.
    DigestMismatch {
        key: MappingKey,
        batch: u32,
        expected: Digest,
        found: Digest,
    },
    /// Unmapping or freeing needs every stream and graph touching the range to be
    /// quiescent (§3.7, step 5); these events are outstanding.
    NotQuiescent {
        events: Vec<EventId>,
    },
    /// Clean-drop parking needs a verified canonical copy of exactly this artifact's
    /// content.
    CanonicalCopyMismatch {
        expected: ContentKey,
        copy: ContentKey,
    },
    UnknownView {
        view: ViewId,
    },
    ViewOutOfRange {
        key: MappingKey,
        offset_bytes: u64,
        length_bytes: u64,
        artifact_bytes: u64,
    },
    NotCallable {
        key: MappingKey,
        reason: NotCallableReason,
    },
    UnknownPhysical {
        physical: PhysicalId,
    },
    NoHandle {
        physical: PhysicalId,
        process: ProcessId,
    },
    AlreadyReleased {
        physical: PhysicalId,
        process: ProcessId,
    },
    AlreadyFreed {
        physical: PhysicalId,
    },
    /// The last reference is closed only when nothing holds the allocation (step 5).
    StillReferenced {
        physical: PhysicalId,
        references: ReferenceCount,
    },
    NotOwner {
        physical: PhysicalId,
        process: ProcessId,
    },
    /// Only a dedicated allocation of one artifact batch is exported, never one that holds
    /// private data (§3.7).
    NotDedicated {
        physical: PhysicalId,
    },
    NotVmmAllocation {
        physical: PhysicalId,
    },
    /// Exports use allocations created for that handle type, sized and aligned to the
    /// granularity reported for those properties (§3.7).
    NotCreatedForHandleType {
        physical: PhysicalId,
        requested: ShareableHandle,
        created: Option<ShareableHandle>,
    },
    NotGranularityMultiple {
        size_bytes: u64,
        granularity_bytes: u64,
    },
    /// Only complete, verified memory is shared.
    NotPublished {
        physical: PhysicalId,
    },
    UnknownExport {
        export: ExportId,
    },
    ExportClosed {
        export: ExportId,
    },
    WrongExportKind {
        export: ExportId,
    },
    /// Memory is shared only within one runtime instance; the container boundary has not
    /// been probed (Appendix E step 8).
    CrossesRuntimeBoundary {
        exporter: ProcessId,
        importer: ProcessId,
    },
    /// The export is not the batch the receiver's layout expects.
    ImportMismatch {
        export: ExportId,
        key: MappingKey,
        batch: u32,
    },
    AlreadyImported {
        physical: PhysicalId,
        process: ProcessId,
    },
    SameProcess {
        process: ProcessId,
    },
    UnknownGraph {
        graph: GraphId,
    },
    EmptyGraph,
    /// The graph dropped its references; it must pass a reuse check before it launches.
    GraphDetached {
        graph: GraphId,
    },
    GraphIncompatible {
        graph: GraphId,
        mismatch: GraphMismatch,
    },
    UnknownWorkspace {
        workspace: WorkspaceId,
    },
    WorkspaceFreed {
        workspace: WorkspaceId,
    },
    /// A workspace a graph holds is neither freed nor reallocated (resource lifetimes).
    WorkspaceInUse {
        workspace: WorkspaceId,
        graphs: Vec<GraphId>,
    },
    /// No loader plan is installed for the process, so no CUDA IPC is permitted (INT-06).
    NoLoaderPlan {
        process: ProcessId,
    },
    /// The loader plan was made for another runtime or configuration than the process's.
    LoaderPlanMismatch {
        process: ProcessId,
    },
    /// The runtime profile's loader plan did not enable this optimization (INT-06); the
    /// reason is the gate's, when the plan was asked for it.
    NotPermitted {
        process: ProcessId,
        optimization: Optimization,
        reason: Option<NotEnabled>,
    },
    /// The evidence the loader plan rested on no longer holds; plan the load again.
    LoaderPlanLapsed {
        process: ProcessId,
        optimization: Optimization,
        refusal: EvidenceRefusal,
    },
    /// The artifact still holds the catalog proof of an earlier clean drop: park on it
    /// with [`ParkSource::HeldCopy`](super::ParkSource::HeldCopy) before it is refilled,
    /// or release it once it is.
    CanonicalCopyHeld {
        key: MappingKey,
    },
    /// The artifact holds no catalog proof.
    NoCanonicalCopy {
        key: MappingKey,
    },
    /// A clone of a catalog proof holds no lease, so it cannot keep the copy while the GPU
    /// copy is dropped; park with the proof the catalog check returned.
    DetachedCanonicalCopy {
        key: MappingKey,
    },
    /// The catalog proof is held until every batch is published again (Appendix E step 6).
    NotRefilled {
        key: MappingKey,
    },
    /// The catalog would not renew or release the proof's lease.
    CanonicalCopy(CanonicalCopyRefusal),
    /// A typed generation reached its last value; the subject must be replaced (S3.1).
    GenerationExhausted,
    IdsExhausted,
    Driver(DriverError),
}

impl From<DriverError> for VmmError {
    fn from(error: DriverError) -> Self {
        Self::Driver(error)
    }
}

impl From<GranularityRefusal> for VmmError {
    fn from(refusal: GranularityRefusal) -> Self {
        Self::Granularity(refusal)
    }
}

impl From<EvidenceRefusal> for VmmError {
    fn from(refusal: EvidenceRefusal) -> Self {
        Self::Evidence(refusal)
    }
}

impl fmt::Display for VmmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownProcess { process } => write!(f, "process {process} is not registered"),
            Self::ProcessExited { process } => write!(
                f,
                "process {process} exited; nothing more is done on its behalf"
            ),
            Self::ProcessExists { process } => {
                write!(f, "process {process} is already registered")
            }
            Self::WrongDevice {
                process,
                expected,
                found,
            } => write!(
                f,
                "process {process} uses device {expected}, not device {found}"
            ),
            Self::Granularity(refusal) => write!(f, "{refusal}"),
            Self::InvalidDriverReport { what } => write!(f, "the driver reported {what}"),
            Self::Evidence(refusal) => write!(f, "{refusal}"),
            Self::HandleTypeNotShown { requested, shown } => write!(
                f,
                "the evidence shows {shown:?}, not CUDA VMM sharing with {requested:?} handles"
            ),
            Self::EmptyLayout => f.write_str("the artifact has no batches"),
            Self::TooManyBatches => f.write_str("the artifact has too many batches"),
            Self::EmptyBatch { batch } => write!(f, "batch {batch} is empty"),
            Self::BatchNotAligned {
                batch,
                length_bytes,
                granularity_bytes,
            } => write!(
                f,
                "batch {batch} is {length_bytes} bytes, not a whole number of the reported \
                 {granularity_bytes}-byte granules; only the last batch may be shorter"
            ),
            Self::ZeroSize => f.write_str("a size of zero bytes"),
            Self::SizeOverflow => f.write_str("a size or address does not fit in 64 bits"),
            Self::AlreadyPlanned { key } => write!(
                f,
                "{key} already has its reservation, which is kept for the process lifetime"
            ),
            Self::UnknownArtifact { key } => write!(f, "{key} is not planned"),
            Self::UnknownBatch { key, batch } => write!(f, "{key} has no batch {batch}"),
            Self::WrongBacking { key, operation } => {
                write!(f, "cannot {operation} for {key}")
            }
            Self::NotInLifecycle {
                key,
                expected,
                found,
            } => write!(f, "{key} is {found}, not {expected}"),
            Self::BatchState {
                key,
                batch,
                state,
                operation,
            } => write!(f, "cannot {operation}: batch {batch} of {key} is {state}"),
            Self::NotComplete { event } => write!(
                f,
                "event {event} has not completed; publish only after completion"
            ),
            Self::DigestMismatch {
                key,
                batch,
                expected,
                found,
            } => write!(
                f,
                "batch {batch} of {key} verified as {found}, not {expected}; it is rejected and \
                 must be populated again"
            ),
            Self::NotQuiescent { events } => write!(
                f,
                "{} operation(s) touching the range are still running; wait for them",
                events.len()
            ),
            Self::CanonicalCopyMismatch { expected, copy } => write!(
                f,
                "the canonical copy holds content {copy}, not this artifact's content \
                 {expected}; it cannot rebuild these weights"
            ),
            Self::UnknownView { view } => write!(f, "view {view} does not exist"),
            Self::ViewOutOfRange {
                key,
                offset_bytes,
                length_bytes,
                artifact_bytes,
            } => write!(
                f,
                "a view of {length_bytes} bytes at offset {offset_bytes} does not fit in the \
                 {artifact_bytes} bytes of {key}"
            ),
            Self::NotCallable { key, reason } => {
                write!(f, "work over {key} cannot run: {reason}")
            }
            Self::UnknownPhysical { physical } => {
                write!(f, "physical allocation {physical} is unknown")
            }
            Self::NoHandle { physical, process } => write!(
                f,
                "process {process} holds no handle to physical allocation {physical}"
            ),
            Self::AlreadyReleased { physical, process } => write!(
                f,
                "process {process} already released physical allocation {physical}"
            ),
            Self::AlreadyFreed { physical } => {
                write!(f, "physical allocation {physical} is already freed")
            }
            Self::StillReferenced {
                physical,
                references,
            } => write!(
                f,
                "physical allocation {physical} is still held by {} mapping(s), {} view(s), {} \
                 graph(s), {} export(s) and {} import(s)",
                references.mappings,
                references.views,
                references.graphs,
                references.exports,
                references.imports
            ),
            Self::NotOwner { physical, process } => write!(
                f,
                "process {process} did not create physical allocation {physical}"
            ),
            Self::NotDedicated { physical } => write!(
                f,
                "physical allocation {physical} holds private data; only a dedicated allocation \
                 of one artifact batch is exported"
            ),
            Self::NotVmmAllocation { physical } => write!(
                f,
                "physical allocation {physical} is not a CUDA VMM allocation"
            ),
            Self::NotCreatedForHandleType {
                physical,
                requested,
                created,
            } => write!(
                f,
                "physical allocation {physical} was created for {created:?} handles, not \
                 {requested:?}"
            ),
            Self::NotGranularityMultiple {
                size_bytes,
                granularity_bytes,
            } => write!(
                f,
                "{size_bytes} bytes is not a multiple of the reported {granularity_bytes}-byte \
                 granularity"
            ),
            Self::NotPublished { physical } => write!(
                f,
                "physical allocation {physical} is not published; only complete, verified \
                 memory is shared"
            ),
            Self::UnknownExport { export } => write!(f, "export {export} does not exist"),
            Self::ExportClosed { export } => write!(f, "export {export} is closed"),
            Self::WrongExportKind { export } => {
                write!(f, "export {export} is of the other API family")
            }
            Self::CrossesRuntimeBoundary { exporter, importer } => write!(
                f,
                "processes {exporter} and {importer} run in different runtimes; memory is not \
                 shared across that boundary"
            ),
            Self::ImportMismatch { export, key, batch } => {
                write!(f, "export {export} is not batch {batch} of {key}")
            }
            Self::AlreadyImported { physical, process } => write!(
                f,
                "process {process} already holds physical allocation {physical}"
            ),
            Self::SameProcess { process } => {
                write!(f, "process {process} cannot import its own export")
            }
            Self::UnknownGraph { graph } => write!(f, "graph {graph} does not exist"),
            Self::EmptyGraph => f.write_str("a graph uses at least one resource"),
            Self::GraphDetached { graph } => write!(
                f,
                "graph {graph} dropped its references; check it for reuse before launching it"
            ),
            Self::GraphIncompatible { graph, mismatch } => {
                write!(f, "graph {graph} cannot be used: {mismatch}")
            }
            Self::UnknownWorkspace { workspace } => {
                write!(f, "workspace {workspace} does not exist")
            }
            Self::WorkspaceFreed { workspace } => write!(f, "workspace {workspace} is freed"),
            Self::WorkspaceInUse { workspace, graphs } => write!(
                f,
                "workspace {workspace} is held by {} graph(s)",
                graphs.len()
            ),
            Self::NoLoaderPlan { process } => write!(
                f,
                "process {process} has no loader plan, so its runtime profile permits no CUDA \
                 IPC; install the gate's plan first"
            ),
            Self::LoaderPlanMismatch { process } => write!(
                f,
                "the loader plan of process {process} was made for another runtime or \
                 configuration; plan the load again"
            ),
            Self::NotPermitted {
                process,
                optimization,
                reason,
            } => {
                write!(
                    f,
                    "the loader plan of process {process} does not enable {optimization}"
                )?;
                match reason {
                    Some(reason) => write!(f, ": {reason}"),
                    None => f.write_str(": the load never asked for it"),
                }
            }
            Self::LoaderPlanLapsed {
                process,
                optimization,
                refusal,
            } => write!(
                f,
                "the evidence that let process {process} use {optimization} no longer holds \
                 ({refusal}); plan the load again"
            ),
            Self::CanonicalCopyHeld { key } => write!(
                f,
                "{key} still holds the canonical copy of an earlier clean drop; park on that \
                 copy, or release it once the artifact is refilled"
            ),
            Self::NoCanonicalCopy { key } => write!(f, "{key} holds no canonical copy"),
            Self::DetachedCanonicalCopy { key } => write!(
                f,
                "the canonical copy offered for {key} is a clone of a catalog proof and holds no \
                 lease; park with the proof the catalog check returned"
            ),
            Self::NotRefilled { key } => write!(
                f,
                "{key} is not refilled yet, so its canonical copy is still needed"
            ),
            Self::CanonicalCopy(refusal) => write!(f, "{refusal}"),
            Self::GenerationExhausted => {
                f.write_str("the allocation generation is exhausted; replace the subject")
            }
            Self::IdsExhausted => f.write_str("the model ran out of identifiers"),
            Self::Driver(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for VmmError {}
