//! A fake driver whose allowed call order is Appendix E's (GPU part §3.7). It touches no
//! GPU: allocations, mappings and events are records, and enqueued work completes only
//! when a caller completes it, so every run is deterministic.
//!
//! It is stricter than CUDA where Appendix E is: it releases a handle only after the
//! handle is unmapped and only when no export or import still holds the allocation, and
//! it refuses to unmap or free memory that incomplete work touches.

use std::collections::BTreeMap;

use super::driver::{DriverCall, DriverError, OrderViolation, RecordedCall, Refusal, VmmDriver};
use super::types::{
    AddressRange, AllocationProperties, DeviceOrdinal, EventId, IpcMemHandle, PhysicalHandle,
    ProcessId, SharedHandle, StreamId, VirtualAddress, WorkKind,
};
use crate::foundation::evidence::ShareableHandle;

/// Where the fake places reservations; the value only keeps ranges apart.
const RESERVATION_BASE: u64 = 0x7f00_0000_0000;
/// Where the fake places `cudaMalloc`, backend pool and opened IPC pointers.
const POINTER_BASE: u64 = 0x5000_0000_0000;
/// The fake's pointer alignment for `cudaMalloc` and the backend allocator.
const POINTER_ALIGNMENT: u64 = 512;

/// What one fake device reports and holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeDeviceSpec {
    pub capacity_bytes: u64,
    /// What `cuMemGetAllocationGranularity` reports per requested handle type. A handle
    /// type that is absent is reported as not supported.
    pub granularity_bytes: BTreeMap<Option<ShareableHandle>, u64>,
}

#[derive(Debug)]
struct FakeDevice {
    spec: FakeDeviceSpec,
    used_bytes: u64,
}

#[derive(Debug)]
struct FakeReservation {
    range: AddressRange,
}

#[derive(Debug)]
struct FakeHandle {
    physical: u64,
    released: bool,
}

#[derive(Debug)]
struct FakeMapping {
    range: AddressRange,
    handle: u64,
    access: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PointerKind {
    Malloc,
    Pool,
    IpcOpened,
}

#[derive(Debug)]
struct FakePointer {
    range: AddressRange,
    physical: u64,
    kind: PointerKind,
}

#[derive(Debug)]
struct FakeProcess {
    device: DeviceOrdinal,
    queried: BTreeMap<AllocationProperties, u64>,
    reservations: Vec<FakeReservation>,
    next_reservation: u64,
    handles: BTreeMap<u64, FakeHandle>,
    mappings: BTreeMap<u64, FakeMapping>,
    pointers: BTreeMap<u64, FakePointer>,
    /// Freed pointer ranges, reused first for an allocation of exactly the same size, as
    /// an allocator may do: an equal pointer value never proves the same allocation.
    free_blocks: Vec<AddressRange>,
    next_pointer: u64,
}

#[derive(Debug)]
struct FakePhysical {
    device: DeviceOrdinal,
    size_bytes: u64,
    properties: Option<AllocationProperties>,
    owner: ProcessId,
    open_handles: u32,
    open_exports: u32,
    ipc_opens: u32,
    freed: bool,
}

#[derive(Debug)]
struct FakeShared {
    physical: u64,
    kind: ShareableHandle,
    open: bool,
    exporter: ProcessId,
}

#[derive(Debug)]
struct FakeIpc {
    physical: u64,
    producer: ProcessId,
}

#[derive(Debug)]
struct FakeEvent {
    process: ProcessId,
    ranges: Vec<AddressRange>,
    complete: bool,
}

/// The fake driver: one host with its devices and runner processes.
#[derive(Debug)]
pub struct FakeDriver {
    devices: BTreeMap<DeviceOrdinal, FakeDevice>,
    processes: BTreeMap<ProcessId, FakeProcess>,
    physical: BTreeMap<u64, FakePhysical>,
    shared: BTreeMap<u64, FakeShared>,
    ipc: BTreeMap<u64, FakeIpc>,
    events: BTreeMap<u64, FakeEvent>,
    calls: Vec<RecordedCall>,
    refusals: Vec<Refusal>,
    next_id: u64,
}

impl Default for FakeDriver {
    fn default() -> Self {
        Self::new()
    }
}

fn refused(violation: OrderViolation) -> DriverError {
    DriverError::Refused { violation }
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    if alignment == 0 {
        return None;
    }
    match value % alignment {
        0 => Some(value),
        remainder => value.checked_add(alignment - remainder),
    }
}

fn check_multiple(size_bytes: u64, granularity_bytes: u64) -> Result<(), DriverError> {
    if size_bytes == 0 {
        return Err(refused(OrderViolation::ZeroSize));
    }
    if granularity_bytes == 0 || !size_bytes.is_multiple_of(granularity_bytes) {
        return Err(refused(OrderViolation::NotGranularityMultiple {
            size_bytes,
            granularity_bytes,
        }));
    }
    Ok(())
}

fn count(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Whether every byte of `range` is accessible memory of the process: one pointer
/// allocation, or adjacent VMM mappings whose access is set.
fn covered(state: &FakeProcess, range: AddressRange) -> bool {
    let Some(end) = range.end() else {
        return false;
    };
    if state
        .pointers
        .values()
        .any(|pointer| pointer.range.contains(range))
    {
        return true;
    }
    let mut position = range.start.0;
    while position < end {
        let next = state.mappings.values().find_map(|mapping| {
            let mapping_end = mapping.range.end()?;
            (mapping.access && mapping.range.start.0 <= position && position < mapping_end)
                .then_some(mapping_end)
        });
        match next {
            Some(mapping_end) => position = mapping_end,
            None => return false,
        }
    }
    true
}

fn place_pointer(state: &mut FakeProcess, size_bytes: u64) -> Result<VirtualAddress, DriverError> {
    if let Some(position) = state
        .free_blocks
        .iter()
        .position(|block| block.length_bytes == size_bytes)
    {
        return Ok(state.free_blocks.swap_remove(position).start);
    }
    let start = align_up(state.next_pointer, POINTER_ALIGNMENT).ok_or(DriverError::Exhausted)?;
    state.next_pointer = start
        .checked_add(size_bytes)
        .ok_or(DriverError::Exhausted)?;
    Ok(VirtualAddress(start))
}

impl FakeDriver {
    pub fn new() -> Self {
        Self {
            devices: BTreeMap::new(),
            processes: BTreeMap::new(),
            physical: BTreeMap::new(),
            shared: BTreeMap::new(),
            ipc: BTreeMap::new(),
            events: BTreeMap::new(),
            calls: Vec::new(),
            refusals: Vec::new(),
            next_id: 1,
        }
    }

    /// Adds or replaces a device.
    pub fn add_device(&mut self, device: DeviceOrdinal, spec: FakeDeviceSpec) {
        self.devices.insert(
            device,
            FakeDevice {
                spec,
                used_bytes: 0,
            },
        );
    }

    /// Adds a runner process that uses `device`.
    pub fn add_process(&mut self, process: ProcessId, device: DeviceOrdinal) {
        self.processes.insert(
            process,
            FakeProcess {
                device,
                queried: BTreeMap::new(),
                reservations: Vec::new(),
                next_reservation: RESERVATION_BASE,
                handles: BTreeMap::new(),
                mappings: BTreeMap::new(),
                pointers: BTreeMap::new(),
                free_blocks: Vec::new(),
                next_pointer: POINTER_BASE,
            },
        );
    }

    /// Changes what the device reports for `handle`, as a driver update would; `None`
    /// makes the handle type unsupported. False when the device is unknown.
    pub fn set_granularity(
        &mut self,
        device: DeviceOrdinal,
        handle: Option<ShareableHandle>,
        granularity_bytes: Option<u64>,
    ) -> bool {
        let Some(device) = self.devices.get_mut(&device) else {
            return false;
        };
        match granularity_bytes {
            Some(bytes) => device.spec.granularity_bytes.insert(handle, bytes),
            None => device.spec.granularity_bytes.remove(&handle),
        };
        true
    }

    /// Completes the work behind `event`; false when the event is unknown.
    pub fn complete(&mut self, event: EventId) -> bool {
        match self.events.get_mut(&event.0) {
            Some(entry) => {
                entry.complete = true;
                true
            }
            None => false,
        }
    }

    /// Completes all enqueued work.
    pub fn complete_all(&mut self) {
        for event in self.events.values_mut() {
            event.complete = true;
        }
    }

    /// The accepted calls, in order.
    pub fn calls(&self) -> &[RecordedCall] {
        &self.calls
    }

    /// The refused calls, in order.
    pub fn refusals(&self) -> &[Refusal] {
        &self.refusals
    }

    /// Forgets the recorded calls and refusals.
    pub fn clear_log(&mut self) {
        self.calls.clear();
        self.refusals.clear();
    }

    /// Bytes of device memory held by allocations that are not freed.
    pub fn used_bytes(&self, device: DeviceOrdinal) -> u64 {
        self.devices
            .get(&device)
            .map_or(0, |device| device.used_bytes)
    }

    /// Whether `address` starts a mapping of the process.
    pub fn is_mapped(&self, process: ProcessId, address: VirtualAddress) -> bool {
        self.processes
            .get(&process)
            .is_some_and(|state| state.mappings.contains_key(&address.0))
    }

    /// The process exits or is killed: the driver drops its pending work and closes its
    /// mappings, pointers, handles and exported handles, in no particular order, and its
    /// legacy IPC handles end with it. Memory another process still holds, through an
    /// import or an opened IPC handle, stays allocated until that process lets go. Later
    /// calls by the process are refused as from an unknown process. False when the
    /// process is unknown.
    pub fn exit_process(&mut self, process: ProcessId) -> bool {
        let Some(state) = self.processes.remove(&process) else {
            return false;
        };
        self.events.retain(|_, event| event.process != process);
        self.ipc.retain(|_, ipc| ipc.producer != process);
        let mut touched = Vec::new();
        for shared in self.shared.values_mut() {
            if shared.exporter == process && shared.open {
                shared.open = false;
                if let Some(physical) = self.physical.get_mut(&shared.physical) {
                    physical.open_exports = physical.open_exports.saturating_sub(1);
                }
                touched.push(shared.physical);
            }
        }
        for handle in state.handles.values().filter(|handle| !handle.released) {
            if let Some(physical) = self.physical.get_mut(&handle.physical) {
                physical.open_handles = physical.open_handles.saturating_sub(1);
            }
            touched.push(handle.physical);
        }
        for pointer in state.pointers.values() {
            if let Some(physical) = self.physical.get_mut(&pointer.physical) {
                match pointer.kind {
                    PointerKind::IpcOpened => {
                        physical.ipc_opens = physical.ipc_opens.saturating_sub(1);
                    }
                    PointerKind::Malloc | PointerKind::Pool => {
                        physical.open_handles = physical.open_handles.saturating_sub(1);
                    }
                }
            }
            touched.push(pointer.physical);
        }
        for physical in touched {
            self.free_if_unheld(physical);
        }
        true
    }

    fn id(&mut self) -> Result<u64, DriverError> {
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or(DriverError::Exhausted)?;
        Ok(id)
    }

    fn record<T>(
        &mut self,
        process: ProcessId,
        call: DriverCall,
        result: Result<T, DriverError>,
    ) -> Result<T, DriverError> {
        let call = RecordedCall { process, call };
        match &result {
            Ok(_) => self.calls.push(call),
            Err(error) => self.refusals.push(Refusal {
                call,
                error: error.clone(),
            }),
        }
        result
    }

    fn state(&self, process: ProcessId) -> Result<&FakeProcess, DriverError> {
        self.processes
            .get(&process)
            .ok_or(refused(OrderViolation::UnknownProcess))
    }

    fn state_mut(&mut self, process: ProcessId) -> Result<&mut FakeProcess, DriverError> {
        self.processes
            .get_mut(&process)
            .ok_or(refused(OrderViolation::UnknownProcess))
    }

    fn physical_mut(&mut self, physical: u64) -> Result<&mut FakePhysical, DriverError> {
        self.physical
            .get_mut(&physical)
            .ok_or(refused(OrderViolation::UnknownHandle))
    }

    /// Incomplete events of the process whose ranges overlap `range`.
    fn in_flight(&self, process: ProcessId, range: AddressRange) -> u32 {
        count(
            self.events
                .values()
                .filter(|event| {
                    event.process == process
                        && !event.complete
                        && event.ranges.iter().any(|touched| touched.overlaps(range))
                })
                .count(),
        )
    }

    fn charge(&mut self, device: DeviceOrdinal, size_bytes: u64) -> Result<(), DriverError> {
        let device = self
            .devices
            .get_mut(&device)
            .ok_or(refused(OrderViolation::WrongDevice))?;
        let available_bytes = device.spec.capacity_bytes.saturating_sub(device.used_bytes);
        if size_bytes > available_bytes {
            return Err(DriverError::OutOfMemory {
                requested_bytes: size_bytes,
                available_bytes,
            });
        }
        device.used_bytes = device.used_bytes.saturating_add(size_bytes);
        Ok(())
    }

    fn refund(&mut self, device: DeviceOrdinal, size_bytes: u64) {
        if let Some(device) = self.devices.get_mut(&device) {
            device.used_bytes = device.used_bytes.saturating_sub(size_bytes);
        }
    }

    fn granularity_inner(
        &mut self,
        process: ProcessId,
        properties: &AllocationProperties,
    ) -> Result<u64, DriverError> {
        let device = self.state(process)?.device;
        if properties.device != device {
            return Err(refused(OrderViolation::WrongDevice));
        }
        let bytes = self
            .devices
            .get(&device)
            .and_then(|device| {
                device
                    .spec
                    .granularity_bytes
                    .get(&properties.requested_handle)
            })
            .copied()
            .ok_or(DriverError::NotSupported)?;
        self.state_mut(process)?.queried.insert(*properties, bytes);
        Ok(bytes)
    }

    fn reserve_inner(
        &mut self,
        process: ProcessId,
        properties: &AllocationProperties,
        size_bytes: u64,
    ) -> Result<VirtualAddress, DriverError> {
        let state = self.state_mut(process)?;
        let granularity_bytes = *state
            .queried
            .get(properties)
            .ok_or(refused(OrderViolation::GranularityNotQueried))?;
        check_multiple(size_bytes, granularity_bytes)?;
        let start =
            align_up(state.next_reservation, granularity_bytes).ok_or(DriverError::Exhausted)?;
        state.next_reservation = start
            .checked_add(size_bytes)
            .ok_or(DriverError::Exhausted)?;
        let start = VirtualAddress(start);
        state.reservations.push(FakeReservation {
            range: AddressRange::new(start, size_bytes),
        });
        Ok(start)
    }

    fn create_inner(
        &mut self,
        process: ProcessId,
        properties: &AllocationProperties,
        size_bytes: u64,
    ) -> Result<PhysicalHandle, DriverError> {
        let state = self.state(process)?;
        if properties.device != state.device {
            return Err(refused(OrderViolation::WrongDevice));
        }
        let granularity_bytes = *state
            .queried
            .get(properties)
            .ok_or(refused(OrderViolation::GranularityNotQueried))?;
        check_multiple(size_bytes, granularity_bytes)?;
        let physical = self.id()?;
        let handle = self.id()?;
        self.charge(properties.device, size_bytes)?;
        self.physical.insert(
            physical,
            FakePhysical {
                device: properties.device,
                size_bytes,
                properties: Some(*properties),
                owner: process,
                open_handles: 1,
                open_exports: 0,
                ipc_opens: 0,
                freed: false,
            },
        );
        self.state_mut(process)?.handles.insert(
            handle,
            FakeHandle {
                physical,
                released: false,
            },
        );
        Ok(PhysicalHandle(handle))
    }

    fn map_inner(
        &mut self,
        process: ProcessId,
        range: AddressRange,
        handle: PhysicalHandle,
    ) -> Result<(), DriverError> {
        let state = self.state(process)?;
        let entry = state
            .handles
            .get(&handle.0)
            .ok_or(refused(OrderViolation::UnknownHandle))?;
        if entry.released {
            return Err(refused(OrderViolation::HandleReleased));
        }
        let physical = self
            .physical
            .get(&entry.physical)
            .ok_or(refused(OrderViolation::UnknownHandle))?;
        let properties = physical
            .properties
            .ok_or(refused(OrderViolation::UnknownHandle))?;
        let granularity_bytes = *state
            .queried
            .get(&properties)
            .ok_or(refused(OrderViolation::GranularityNotQueried))?;
        if !state
            .reservations
            .iter()
            .any(|reservation| reservation.range.contains(range))
        {
            return Err(refused(OrderViolation::OutsideReservation));
        }
        if granularity_bytes == 0 || !range.start.0.is_multiple_of(granularity_bytes) {
            return Err(refused(OrderViolation::Misaligned {
                address: range.start,
                granularity_bytes,
            }));
        }
        if range.length_bytes != physical.size_bytes {
            return Err(refused(OrderViolation::NotWholeAllocation {
                size_bytes: range.length_bytes,
                allocation_bytes: physical.size_bytes,
            }));
        }
        if state
            .mappings
            .values()
            .any(|mapping| mapping.range.overlaps(range))
        {
            return Err(refused(OrderViolation::AlreadyMapped));
        }
        self.state_mut(process)?.mappings.insert(
            range.start.0,
            FakeMapping {
                range,
                handle: handle.0,
                access: false,
            },
        );
        Ok(())
    }

    fn set_access_inner(
        &mut self,
        process: ProcessId,
        range: AddressRange,
        device: DeviceOrdinal,
    ) -> Result<(), DriverError> {
        let state = self.state_mut(process)?;
        if device != state.device {
            return Err(refused(OrderViolation::WrongDevice));
        }
        let mapping = state
            .mappings
            .get_mut(&range.start.0)
            .filter(|mapping| mapping.range == range)
            .ok_or(refused(OrderViolation::NotMapped))?;
        mapping.access = true;
        Ok(())
    }

    fn unmap_inner(&mut self, process: ProcessId, range: AddressRange) -> Result<(), DriverError> {
        let mapped = self
            .state(process)?
            .mappings
            .get(&range.start.0)
            .is_some_and(|mapping| mapping.range == range);
        if !mapped {
            return Err(refused(OrderViolation::NotMapped));
        }
        let events = self.in_flight(process, range);
        if events > 0 {
            return Err(refused(OrderViolation::InFlight { events }));
        }
        self.state_mut(process)?.mappings.remove(&range.start.0);
        Ok(())
    }

    fn release_inner(
        &mut self,
        process: ProcessId,
        handle: PhysicalHandle,
    ) -> Result<(), DriverError> {
        let state = self.state(process)?;
        let entry = state
            .handles
            .get(&handle.0)
            .ok_or(refused(OrderViolation::UnknownHandle))?;
        if entry.released {
            return Err(refused(OrderViolation::HandleReleased));
        }
        if state
            .mappings
            .values()
            .any(|mapping| mapping.handle == handle.0)
        {
            return Err(refused(OrderViolation::ReleaseWhileMapped));
        }
        let physical_id = entry.physical;
        let physical = self.physical_mut(physical_id)?;
        if physical.owner == process {
            let imports = physical.open_handles.saturating_sub(1);
            if physical.open_exports > 0 || imports > 0 {
                return Err(refused(OrderViolation::ReleaseWithReferences {
                    exports: physical.open_exports,
                    imports,
                }));
            }
        }
        physical.open_handles = physical.open_handles.saturating_sub(1);
        let freed = (physical.open_handles == 0).then_some((physical.device, physical.size_bytes));
        if let Some((device, size_bytes)) = freed {
            physical.freed = true;
            self.refund(device, size_bytes);
        }
        if let Some(entry) = self.state_mut(process)?.handles.get_mut(&handle.0) {
            entry.released = true;
        }
        Ok(())
    }

    fn export_inner(
        &mut self,
        process: ProcessId,
        handle: PhysicalHandle,
        kind: ShareableHandle,
    ) -> Result<SharedHandle, DriverError> {
        let entry = self
            .state(process)?
            .handles
            .get(&handle.0)
            .ok_or(refused(OrderViolation::UnknownHandle))?;
        if entry.released {
            return Err(refused(OrderViolation::HandleReleased));
        }
        let physical_id = entry.physical;
        let requested = self
            .physical
            .get(&physical_id)
            .and_then(|physical| physical.properties)
            .and_then(|properties| properties.requested_handle);
        if requested != Some(kind) {
            return Err(refused(OrderViolation::ExportWithoutRequestedHandleType));
        }
        let shared = self.id()?;
        let physical = self.physical_mut(physical_id)?;
        physical.open_exports = physical.open_exports.saturating_add(1);
        self.shared.insert(
            shared,
            FakeShared {
                physical: physical_id,
                kind,
                open: true,
                exporter: process,
            },
        );
        Ok(SharedHandle(shared))
    }

    fn import_inner(
        &mut self,
        process: ProcessId,
        shared: SharedHandle,
        kind: ShareableHandle,
    ) -> Result<PhysicalHandle, DriverError> {
        let device = self.state(process)?.device;
        let entry = self
            .shared
            .get(&shared.0)
            .ok_or(refused(OrderViolation::UnknownSharedHandle))?;
        if !entry.open {
            return Err(refused(OrderViolation::SharedHandleClosed));
        }
        if entry.kind != kind {
            return Err(refused(OrderViolation::HandleKindMismatch));
        }
        let physical_id = entry.physical;
        let handle = self.id()?;
        let physical = self.physical_mut(physical_id)?;
        if physical.device != device {
            return Err(refused(OrderViolation::WrongDevice));
        }
        physical.open_handles = physical.open_handles.saturating_add(1);
        self.state_mut(process)?.handles.insert(
            handle,
            FakeHandle {
                physical: physical_id,
                released: false,
            },
        );
        Ok(PhysicalHandle(handle))
    }

    fn close_shared_inner(&mut self, shared: SharedHandle) -> Result<(), DriverError> {
        let entry = self
            .shared
            .get_mut(&shared.0)
            .ok_or(refused(OrderViolation::UnknownSharedHandle))?;
        if !entry.open {
            return Err(refused(OrderViolation::SharedHandleClosed));
        }
        entry.open = false;
        let physical_id = entry.physical;
        let physical = self.physical_mut(physical_id)?;
        physical.open_exports = physical.open_exports.saturating_sub(1);
        Ok(())
    }

    fn allocate_pointer(
        &mut self,
        process: ProcessId,
        size_bytes: u64,
        kind: PointerKind,
    ) -> Result<VirtualAddress, DriverError> {
        if size_bytes == 0 {
            return Err(refused(OrderViolation::ZeroSize));
        }
        let device = self.state(process)?.device;
        let physical = self.id()?;
        self.charge(device, size_bytes)?;
        let placed = place_pointer(self.state_mut(process)?, size_bytes);
        let address = match placed {
            Ok(address) => address,
            Err(error) => {
                self.refund(device, size_bytes);
                return Err(error);
            }
        };
        self.state_mut(process)?.pointers.insert(
            address.0,
            FakePointer {
                range: AddressRange::new(address, size_bytes),
                physical,
                kind,
            },
        );
        self.physical.insert(
            physical,
            FakePhysical {
                device,
                size_bytes,
                properties: None,
                owner: process,
                open_handles: 1,
                open_exports: 0,
                ipc_opens: 0,
                freed: false,
            },
        );
        Ok(address)
    }

    /// Frees a pointer allocation of `kind` after the checks every free shares.
    fn free_pointer(
        &mut self,
        process: ProcessId,
        pointer: VirtualAddress,
        kind: PointerKind,
    ) -> Result<(), DriverError> {
        let entry = self
            .state(process)?
            .pointers
            .get(&pointer.0)
            .filter(|entry| entry.kind == kind)
            .ok_or(refused(OrderViolation::UnknownPointer))?;
        let (range, physical_id) = (entry.range, entry.physical);
        let events = self.in_flight(process, range);
        if events > 0 {
            return Err(refused(OrderViolation::InFlight { events }));
        }
        let physical = self.physical_mut(physical_id)?;
        if physical.ipc_opens > 0 {
            return Err(refused(OrderViolation::FreeWithOpenIpcHandles {
                opens: physical.ipc_opens,
            }));
        }
        physical.freed = true;
        physical.open_handles = 0;
        let (device, size_bytes) = (physical.device, physical.size_bytes);
        self.refund(device, size_bytes);
        let state = self.state_mut(process)?;
        state.pointers.remove(&pointer.0);
        state.free_blocks.push(range);
        Ok(())
    }

    fn ipc_get_inner(
        &mut self,
        process: ProcessId,
        pointer: VirtualAddress,
    ) -> Result<IpcMemHandle, DriverError> {
        let physical = self
            .state(process)?
            .pointers
            .get(&pointer.0)
            .filter(|entry| entry.kind == PointerKind::Malloc)
            .map(|entry| entry.physical)
            .ok_or(refused(OrderViolation::NotAMallocBase))?;
        let handle = self.id()?;
        self.ipc.insert(
            handle,
            FakeIpc {
                physical,
                producer: process,
            },
        );
        Ok(IpcMemHandle(handle))
    }

    fn ipc_open_inner(
        &mut self,
        process: ProcessId,
        handle: IpcMemHandle,
    ) -> Result<VirtualAddress, DriverError> {
        let device = self.state(process)?.device;
        let entry = self
            .ipc
            .get(&handle.0)
            .ok_or(refused(OrderViolation::UnknownIpcHandle))?;
        if entry.producer == process {
            return Err(refused(OrderViolation::OpenInSameProcess));
        }
        let physical_id = entry.physical;
        let physical = self
            .physical
            .get(&physical_id)
            .filter(|physical| !physical.freed)
            .ok_or(refused(OrderViolation::UnknownIpcHandle))?;
        if physical.device != device {
            return Err(refused(OrderViolation::WrongDevice));
        }
        let size_bytes = physical.size_bytes;
        let state = self.state_mut(process)?;
        let address = place_pointer(state, size_bytes)?;
        state.pointers.insert(
            address.0,
            FakePointer {
                range: AddressRange::new(address, size_bytes),
                physical: physical_id,
                kind: PointerKind::IpcOpened,
            },
        );
        let physical = self.physical_mut(physical_id)?;
        physical.ipc_opens = physical.ipc_opens.saturating_add(1);
        Ok(address)
    }

    fn ipc_close_inner(
        &mut self,
        process: ProcessId,
        pointer: VirtualAddress,
    ) -> Result<(), DriverError> {
        let entry = self
            .state(process)?
            .pointers
            .get(&pointer.0)
            .filter(|entry| entry.kind == PointerKind::IpcOpened)
            .ok_or(refused(OrderViolation::UnknownPointer))?;
        let (range, physical_id) = (entry.range, entry.physical);
        let events = self.in_flight(process, range);
        if events > 0 {
            return Err(refused(OrderViolation::InFlight { events }));
        }
        let physical = self.physical_mut(physical_id)?;
        physical.ipc_opens = physical.ipc_opens.saturating_sub(1);
        self.free_if_unheld(physical_id);
        let state = self.state_mut(process)?;
        state.pointers.remove(&pointer.0);
        state.free_blocks.push(range);
        Ok(())
    }

    /// Frees an allocation once no handle, opened IPC mapping or export holds it, such as
    /// after its owner exited.
    fn free_if_unheld(&mut self, physical_id: u64) {
        let Some(physical) = self.physical.get_mut(&physical_id) else {
            return;
        };
        if physical.freed
            || physical.open_handles > 0
            || physical.ipc_opens > 0
            || physical.open_exports > 0
        {
            return;
        }
        physical.freed = true;
        let (device, size_bytes) = (physical.device, physical.size_bytes);
        self.refund(device, size_bytes);
    }

    fn enqueue_inner(
        &mut self,
        process: ProcessId,
        ranges: &[AddressRange],
    ) -> Result<EventId, DriverError> {
        let state = self.state(process)?;
        if ranges.is_empty() {
            return Err(refused(OrderViolation::ZeroSize));
        }
        for range in ranges {
            if range.length_bytes == 0 {
                return Err(refused(OrderViolation::ZeroSize));
            }
            if !covered(state, *range) {
                return Err(refused(OrderViolation::UnbackedAddress {
                    address: range.start,
                }));
            }
        }
        let event = self.id()?;
        self.events.insert(
            event,
            FakeEvent {
                process,
                ranges: ranges.to_vec(),
                complete: false,
            },
        );
        Ok(EventId(event))
    }
}

impl VmmDriver for FakeDriver {
    fn allocation_granularity(
        &mut self,
        process: ProcessId,
        properties: &AllocationProperties,
    ) -> Result<u64, DriverError> {
        let result = self.granularity_inner(process, properties);
        let call = DriverCall::GetAllocationGranularity {
            properties: *properties,
        };
        self.record(process, call, result)
    }

    fn address_reserve(
        &mut self,
        process: ProcessId,
        properties: &AllocationProperties,
        size_bytes: u64,
    ) -> Result<VirtualAddress, DriverError> {
        let result = self.reserve_inner(process, properties, size_bytes);
        let call = DriverCall::AddressReserve {
            properties: *properties,
            size_bytes,
        };
        self.record(process, call, result)
    }

    fn create(
        &mut self,
        process: ProcessId,
        properties: &AllocationProperties,
        size_bytes: u64,
    ) -> Result<PhysicalHandle, DriverError> {
        let result = self.create_inner(process, properties, size_bytes);
        let call = DriverCall::Create {
            properties: *properties,
            size_bytes,
        };
        self.record(process, call, result)
    }

    fn map(
        &mut self,
        process: ProcessId,
        range: AddressRange,
        handle: PhysicalHandle,
    ) -> Result<(), DriverError> {
        let result = self.map_inner(process, range, handle);
        self.record(process, DriverCall::Map { range, handle }, result)
    }

    fn set_access(
        &mut self,
        process: ProcessId,
        range: AddressRange,
        device: DeviceOrdinal,
    ) -> Result<(), DriverError> {
        let result = self.set_access_inner(process, range, device);
        self.record(process, DriverCall::SetAccess { range, device }, result)
    }

    fn unmap(&mut self, process: ProcessId, range: AddressRange) -> Result<(), DriverError> {
        let result = self.unmap_inner(process, range);
        self.record(process, DriverCall::Unmap { range }, result)
    }

    fn release(&mut self, process: ProcessId, handle: PhysicalHandle) -> Result<(), DriverError> {
        let result = self.release_inner(process, handle);
        self.record(process, DriverCall::Release { handle }, result)
    }

    fn export_shareable(
        &mut self,
        process: ProcessId,
        handle: PhysicalHandle,
        kind: ShareableHandle,
    ) -> Result<SharedHandle, DriverError> {
        let result = self.export_inner(process, handle, kind);
        let call = DriverCall::ExportToShareableHandle { handle, kind };
        self.record(process, call, result)
    }

    fn import_shareable(
        &mut self,
        process: ProcessId,
        shared: SharedHandle,
        kind: ShareableHandle,
    ) -> Result<PhysicalHandle, DriverError> {
        let result = self.import_inner(process, shared, kind);
        let call = DriverCall::ImportFromShareableHandle { shared, kind };
        self.record(process, call, result)
    }

    fn close_shared(
        &mut self,
        process: ProcessId,
        shared: SharedHandle,
    ) -> Result<(), DriverError> {
        let result = self
            .state(process)
            .map(|_| ())
            .and_then(|()| self.close_shared_inner(shared));
        self.record(process, DriverCall::CloseSharedHandle { shared }, result)
    }

    fn malloc(
        &mut self,
        process: ProcessId,
        size_bytes: u64,
    ) -> Result<VirtualAddress, DriverError> {
        let result = self.allocate_pointer(process, size_bytes, PointerKind::Malloc);
        self.record(process, DriverCall::Malloc { size_bytes }, result)
    }

    fn ipc_get_mem_handle(
        &mut self,
        process: ProcessId,
        pointer: VirtualAddress,
    ) -> Result<IpcMemHandle, DriverError> {
        let result = self.ipc_get_inner(process, pointer);
        self.record(process, DriverCall::IpcGetMemHandle { pointer }, result)
    }

    fn ipc_open_mem_handle(
        &mut self,
        process: ProcessId,
        handle: IpcMemHandle,
    ) -> Result<VirtualAddress, DriverError> {
        let result = self.ipc_open_inner(process, handle);
        self.record(process, DriverCall::IpcOpenMemHandle { handle }, result)
    }

    fn ipc_close_mem_handle(
        &mut self,
        process: ProcessId,
        pointer: VirtualAddress,
    ) -> Result<(), DriverError> {
        let result = self.ipc_close_inner(process, pointer);
        self.record(process, DriverCall::IpcCloseMemHandle { pointer }, result)
    }

    fn free(&mut self, process: ProcessId, pointer: VirtualAddress) -> Result<(), DriverError> {
        let result = self.free_pointer(process, pointer, PointerKind::Malloc);
        self.record(process, DriverCall::Free { pointer }, result)
    }

    fn pool_allocate(
        &mut self,
        process: ProcessId,
        size_bytes: u64,
        expandable_segments: bool,
    ) -> Result<VirtualAddress, DriverError> {
        let result = self.allocate_pointer(process, size_bytes, PointerKind::Pool);
        let call = DriverCall::PoolAllocate {
            size_bytes,
            expandable_segments,
        };
        self.record(process, call, result)
    }

    fn pool_free(
        &mut self,
        process: ProcessId,
        pointer: VirtualAddress,
    ) -> Result<(), DriverError> {
        let result = self.free_pointer(process, pointer, PointerKind::Pool);
        self.record(process, DriverCall::PoolFree { pointer }, result)
    }

    fn enqueue(
        &mut self,
        process: ProcessId,
        stream: StreamId,
        work: WorkKind,
        ranges: &[AddressRange],
    ) -> Result<EventId, DriverError> {
        let result = self.enqueue_inner(process, ranges);
        let call = DriverCall::Enqueue {
            stream,
            work,
            ranges: ranges.to_vec(),
        };
        self.record(process, call, result)
    }

    fn event_complete(&mut self, process: ProcessId, event: EventId) -> Result<bool, DriverError> {
        self.events
            .get(&event.0)
            .filter(|entry| entry.process == process)
            .map(|entry| entry.complete)
            .ok_or(refused(OrderViolation::UnknownEvent))
    }
}
