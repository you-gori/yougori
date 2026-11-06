//! The driver and runtime calls of Appendix E as a typed trait, with a record of each
//! call. The real calls run in the runner through `ctypes` on `libcuda.so.1`; this crate
//! only models them, and [`FakeDriver`](super::FakeDriver) enforces their order.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::types::{
    AddressRange, AllocationProperties, DeviceOrdinal, EventId, IpcMemHandle, PhysicalHandle,
    ProcessId, SharedHandle, StreamId, VirtualAddress, WorkKind,
};
use crate::foundation::evidence::ShareableHandle;

/// The calls the protocol makes, one method per driver or runtime function (Appendix E).
///
/// The model makes these calls only in Appendix E's order; a driver may refuse any other
/// order with [`DriverError::Refused`].
pub trait VmmDriver {
    /// `cuMemGetAllocationGranularity` for `properties` (step 1).
    fn allocation_granularity(
        &mut self,
        process: ProcessId,
        properties: &AllocationProperties,
    ) -> Result<u64, DriverError>;

    /// `cuMemAddressReserve` of `size_bytes`, aligned to the granularity reported for
    /// `properties` (step 2).
    fn address_reserve(
        &mut self,
        process: ProcessId,
        properties: &AllocationProperties,
        size_bytes: u64,
    ) -> Result<VirtualAddress, DriverError>;

    /// `cuMemCreate` (step 3).
    fn create(
        &mut self,
        process: ProcessId,
        properties: &AllocationProperties,
        size_bytes: u64,
    ) -> Result<PhysicalHandle, DriverError>;

    /// `cuMemMap` of the whole allocation at `range` (step 3).
    fn map(
        &mut self,
        process: ProcessId,
        range: AddressRange,
        handle: PhysicalHandle,
    ) -> Result<(), DriverError>;

    /// `cuMemSetAccess` for `device`, read-write (step 3).
    fn set_access(
        &mut self,
        process: ProcessId,
        range: AddressRange,
        device: DeviceOrdinal,
    ) -> Result<(), DriverError>;

    /// `cuMemUnmap` (step 5).
    fn unmap(&mut self, process: ProcessId, range: AddressRange) -> Result<(), DriverError>;

    /// `cuMemRelease` (step 5).
    fn release(&mut self, process: ProcessId, handle: PhysicalHandle) -> Result<(), DriverError>;

    /// `cuMemExportToShareableHandle` (step 7).
    fn export_shareable(
        &mut self,
        process: ProcessId,
        handle: PhysicalHandle,
        kind: ShareableHandle,
    ) -> Result<SharedHandle, DriverError>;

    /// `cuMemImportFromShareableHandle` (step 7).
    fn import_shareable(
        &mut self,
        process: ProcessId,
        shared: SharedHandle,
        kind: ShareableHandle,
    ) -> Result<PhysicalHandle, DriverError>;

    /// Closes an exported shareable handle, such as the file descriptor sent with
    /// `SCM_RIGHTS` (step 7).
    fn close_shared(&mut self, process: ProcessId, shared: SharedHandle)
        -> Result<(), DriverError>;

    /// `cudaMalloc` of one dedicated allocation (step 8).
    fn malloc(
        &mut self,
        process: ProcessId,
        size_bytes: u64,
    ) -> Result<VirtualAddress, DriverError>;

    /// `cudaIpcGetMemHandle` (step 8).
    fn ipc_get_mem_handle(
        &mut self,
        process: ProcessId,
        pointer: VirtualAddress,
    ) -> Result<IpcMemHandle, DriverError>;

    /// `cudaIpcOpenMemHandle` in the consumer (step 8).
    fn ipc_open_mem_handle(
        &mut self,
        process: ProcessId,
        handle: IpcMemHandle,
    ) -> Result<VirtualAddress, DriverError>;

    /// `cudaIpcCloseMemHandle` in the consumer (step 8).
    fn ipc_close_mem_handle(
        &mut self,
        process: ProcessId,
        pointer: VirtualAddress,
    ) -> Result<(), DriverError>;

    /// `cudaFree` (step 8).
    fn free(&mut self, process: ProcessId, pointer: VirtualAddress) -> Result<(), DriverError>;

    /// One backend allocation in a private pool, with `expandable_segments:True` when
    /// asked (step 9).
    fn pool_allocate(
        &mut self,
        process: ProcessId,
        size_bytes: u64,
        expandable_segments: bool,
    ) -> Result<VirtualAddress, DriverError>;

    /// Returns a backend pool allocation (step 9).
    fn pool_free(&mut self, process: ProcessId, pointer: VirtualAddress)
        -> Result<(), DriverError>;

    /// Enqueues work that touches `ranges` on `stream` and records its completion event.
    fn enqueue(
        &mut self,
        process: ProcessId,
        stream: StreamId,
        work: WorkKind,
        ranges: &[AddressRange],
    ) -> Result<EventId, DriverError>;

    /// `cuEventQuery`: whether the work behind `event` has completed. A read, so it is not
    /// recorded as a call.
    fn event_complete(&mut self, process: ProcessId, event: EventId) -> Result<bool, DriverError>;
}

/// Why a driver call failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum DriverError {
    /// The device or driver does not support the operation (`CUDA_ERROR_NOT_SUPPORTED`).
    NotSupported,
    /// Not enough device memory.
    OutOfMemory {
        requested_bytes: u64,
        available_bytes: u64,
    },
    /// Addresses or identifiers ran out.
    Exhausted,
    /// The call breaks Appendix E's order.
    Refused { violation: OrderViolation },
}

crate::foundation::strict_serde::strict_tag!(DriverError, "error");

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSupported => f.write_str("the driver does not support this operation"),
            Self::OutOfMemory {
                requested_bytes,
                available_bytes,
            } => write!(
                f,
                "the device has {available_bytes} bytes free, not the {requested_bytes} requested"
            ),
            Self::Exhausted => f.write_str("the driver ran out of addresses or identifiers"),
            Self::Refused { violation } => {
                write!(f, "the call is outside Appendix E's order: {violation}")
            }
        }
    }
}

impl std::error::Error for DriverError {}

/// A call outside Appendix E's allowed order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "violation", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum OrderViolation {
    UnknownProcess,
    /// The properties or access name a device other than the process's device k.
    WrongDevice,
    /// Step 1 must precede reserving or creating for these properties, so the reported
    /// granularity is used rather than assumed.
    GranularityNotQueried,
    ZeroSize,
    NotGranularityMultiple {
        size_bytes: u64,
        granularity_bytes: u64,
    },
    UnknownHandle,
    HandleReleased,
    /// A mapping must lie inside one reservation of the process.
    OutsideReservation,
    Misaligned {
        address: VirtualAddress,
        granularity_bytes: u64,
    },
    /// Each mapping covers one whole allocation.
    NotWholeAllocation {
        size_bytes: u64,
        allocation_bytes: u64,
    },
    AlreadyMapped,
    /// Access is set on, and unmapping removes, exactly one existing mapping.
    NotMapped,
    /// Work touched an address with no accessible memory behind it: stale pointer
    /// execution (§3.7).
    UnbackedAddress {
        address: VirtualAddress,
    },
    /// Unmapping or freeing while enqueued work touching the range is incomplete; this
    /// needs quiescence (§3.7, step 5).
    InFlight {
        events: u32,
    },
    /// Step 5 unmaps before it releases.
    ReleaseWhileMapped,
    /// Step 5 releases only when the reference count reaches zero; exports and imports
    /// count.
    ReleaseWithReferences {
        exports: u32,
        imports: u32,
    },
    /// Only an allocation created with this handle type can be exported as it.
    ExportWithoutRequestedHandleType,
    UnknownSharedHandle,
    SharedHandleClosed,
    HandleKindMismatch,
    /// Legacy IPC works only on the base of a dedicated `cudaMalloc` allocation (step 8).
    NotAMallocBase,
    /// A process never opens its own IPC handle.
    OpenInSameProcess,
    UnknownIpcHandle,
    /// The producer keeps the allocation while any consumer has it open (step 8: the
    /// lifetime is not relied on until probed).
    FreeWithOpenIpcHandles {
        opens: u32,
    },
    UnknownPointer,
    UnknownEvent,
}

crate::foundation::strict_serde::strict_tag!(OrderViolation, "violation");

impl fmt::Display for OrderViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownProcess => f.write_str("the process is unknown"),
            Self::WrongDevice => f.write_str("another device than the process's device"),
            Self::GranularityNotQueried => {
                f.write_str("the allocation granularity for these properties was not queried first")
            }
            Self::ZeroSize => f.write_str("a size of zero bytes"),
            Self::NotGranularityMultiple {
                size_bytes,
                granularity_bytes,
            } => write!(
                f,
                "{size_bytes} bytes is not a multiple of the {granularity_bytes}-byte granularity"
            ),
            Self::UnknownHandle => f.write_str("the physical handle is unknown"),
            Self::HandleReleased => f.write_str("the physical handle was already released"),
            Self::OutsideReservation => f.write_str("the range is outside every reservation"),
            Self::Misaligned {
                address,
                granularity_bytes,
            } => write!(
                f,
                "{address} is not aligned to the {granularity_bytes}-byte granularity"
            ),
            Self::NotWholeAllocation {
                size_bytes,
                allocation_bytes,
            } => write!(
                f,
                "a {size_bytes}-byte mapping of a {allocation_bytes}-byte allocation; map whole \
                 allocations"
            ),
            Self::AlreadyMapped => f.write_str("the range is already mapped"),
            Self::NotMapped => f.write_str("no mapping covers exactly this range"),
            Self::UnbackedAddress { address } => {
                write!(f, "work touched {address}, which has no accessible memory")
            }
            Self::InFlight { events } => {
                write!(
                    f,
                    "{events} enqueued operation(s) touching the range are incomplete"
                )
            }
            Self::ReleaseWhileMapped => f.write_str("the handle is still mapped"),
            Self::ReleaseWithReferences { exports, imports } => write!(
                f,
                "the allocation still has {exports} open export(s) and {imports} import(s)"
            ),
            Self::ExportWithoutRequestedHandleType => {
                f.write_str("the allocation was not created for this handle type")
            }
            Self::UnknownSharedHandle => f.write_str("the shareable handle is unknown"),
            Self::SharedHandleClosed => f.write_str("the shareable handle was closed"),
            Self::HandleKindMismatch => f.write_str("the shareable handle is of another type"),
            Self::NotAMallocBase => {
                f.write_str("the pointer is not the base of a dedicated cudaMalloc allocation")
            }
            Self::OpenInSameProcess => f.write_str("a process cannot open its own IPC handle"),
            Self::UnknownIpcHandle => f.write_str("the IPC handle is unknown"),
            Self::FreeWithOpenIpcHandles { opens } => {
                write!(f, "{opens} consumer(s) still have the allocation open")
            }
            Self::UnknownPointer => f.write_str("the pointer is unknown"),
            Self::UnknownEvent => f.write_str("the event is unknown"),
        }
    }
}

/// One driver call with its arguments, as a driver records it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "call", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum DriverCall {
    GetAllocationGranularity {
        properties: AllocationProperties,
    },
    AddressReserve {
        properties: AllocationProperties,
        size_bytes: u64,
    },
    Create {
        properties: AllocationProperties,
        size_bytes: u64,
    },
    Map {
        range: AddressRange,
        handle: PhysicalHandle,
    },
    SetAccess {
        range: AddressRange,
        device: DeviceOrdinal,
    },
    Unmap {
        range: AddressRange,
    },
    Release {
        handle: PhysicalHandle,
    },
    ExportToShareableHandle {
        handle: PhysicalHandle,
        kind: ShareableHandle,
    },
    ImportFromShareableHandle {
        shared: SharedHandle,
        kind: ShareableHandle,
    },
    CloseSharedHandle {
        shared: SharedHandle,
    },
    Malloc {
        size_bytes: u64,
    },
    IpcGetMemHandle {
        pointer: VirtualAddress,
    },
    IpcOpenMemHandle {
        handle: IpcMemHandle,
    },
    IpcCloseMemHandle {
        pointer: VirtualAddress,
    },
    Free {
        pointer: VirtualAddress,
    },
    PoolAllocate {
        size_bytes: u64,
        expandable_segments: bool,
    },
    PoolFree {
        pointer: VirtualAddress,
    },
    Enqueue {
        stream: StreamId,
        work: WorkKind,
        ranges: Vec<AddressRange>,
    },
}

crate::foundation::strict_serde::strict_tag!(DriverCall, "call");

impl DriverCall {
    /// The CUDA function the call stands for, as Appendix E names it.
    pub const fn api_name(&self) -> &'static str {
        match self {
            Self::GetAllocationGranularity { .. } => "cuMemGetAllocationGranularity",
            Self::AddressReserve { .. } => "cuMemAddressReserve",
            Self::Create { .. } => "cuMemCreate",
            Self::Map { .. } => "cuMemMap",
            Self::SetAccess { .. } => "cuMemSetAccess",
            Self::Unmap { .. } => "cuMemUnmap",
            Self::Release { .. } => "cuMemRelease",
            Self::ExportToShareableHandle { .. } => "cuMemExportToShareableHandle",
            Self::ImportFromShareableHandle { .. } => "cuMemImportFromShareableHandle",
            Self::CloseSharedHandle { .. } => "close",
            Self::Malloc { .. } => "cudaMalloc",
            Self::IpcGetMemHandle { .. } => "cudaIpcGetMemHandle",
            Self::IpcOpenMemHandle { .. } => "cudaIpcOpenMemHandle",
            Self::IpcCloseMemHandle { .. } => "cudaIpcCloseMemHandle",
            Self::Free { .. } => "cudaFree",
            Self::PoolAllocate { .. } => "backend pool allocate",
            Self::PoolFree { .. } => "backend pool free",
            Self::Enqueue { .. } => "enqueue",
        }
    }
}

/// A call one process made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedCall {
    pub process: ProcessId,
    pub call: DriverCall,
}

/// A call the driver refused, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub call: RecordedCall,
    pub error: DriverError,
}
