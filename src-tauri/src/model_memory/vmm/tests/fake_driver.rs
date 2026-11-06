//! Appendix E's call order is the fake driver's allowed order: every call out of order is
//! refused and recorded.

use super::*;

fn fake() -> FakeDriver {
    World::new().driver
}

fn refused(violation: OrderViolation) -> DriverError {
    DriverError::Refused { violation }
}

#[test]
fn reserve_and_create_need_the_granularity_query_first() {
    let mut fake = fake();
    assert_eq!(
        fake.address_reserve(P1, &private(), 4 * MIB),
        Err(refused(OrderViolation::GranularityNotQueried))
    );
    assert_eq!(
        fake.create(P1, &private(), 4 * MIB),
        Err(refused(OrderViolation::GranularityNotQueried))
    );
    assert_eq!(
        fake.allocation_granularity(P1, &private()),
        Ok(PRIVATE_GRANULE)
    );
    assert_eq!(
        fake.create(P1, &posix(), 8 * MIB),
        Err(refused(OrderViolation::GranularityNotQueried)),
        "a query for other properties does not count"
    );
    assert_eq!(
        fake.address_reserve(P1, &private(), 2 * MIB),
        Err(refused(OrderViolation::NotGranularityMultiple {
            size_bytes: 2 * MIB,
            granularity_bytes: PRIVATE_GRANULE,
        })),
        "2 MiB is not a whole granule of the reported 4 MiB"
    );
    assert_eq!(
        fake.create(P1, &private(), 0),
        Err(refused(OrderViolation::ZeroSize))
    );
    let start = fake.address_reserve(P1, &private(), 8 * MIB).unwrap();
    assert_eq!(start.get() % PRIVATE_GRANULE, 0);
    assert_eq!(fake.refusals().len(), 5);
    assert_eq!(fake.calls().len(), 2);
}

#[test]
fn unsupported_handle_types_and_other_devices_are_refused() {
    let mut fake = fake();
    let fabric = AllocationProperties {
        device: DEVICE,
        requested_handle: Some(ShareableHandle::Fabric),
    };
    assert_eq!(
        fake.allocation_granularity(P1, &fabric),
        Err(DriverError::NotSupported)
    );
    let other_device = AllocationProperties {
        device: DeviceOrdinal(1),
        requested_handle: None,
    };
    assert_eq!(
        fake.allocation_granularity(P1, &other_device),
        Err(refused(OrderViolation::WrongDevice))
    );
    assert_eq!(
        fake.allocation_granularity(ProcessId(9), &private()),
        Err(refused(OrderViolation::UnknownProcess))
    );
}

#[test]
fn mapping_follows_reserve_create_map_then_access() {
    let mut fake = fake();
    fake.allocation_granularity(P1, &private()).unwrap();
    let start = fake.address_reserve(P1, &private(), 8 * MIB).unwrap();
    let handle = fake.create(P1, &private(), 4 * MIB).unwrap();
    let first = AddressRange::new(start, 4 * MIB);
    assert_eq!(
        fake.set_access(P1, first, DEVICE),
        Err(refused(OrderViolation::NotMapped)),
        "access is set only on a mapping"
    );
    let past_end = AddressRange::new(start.checked_add(8 * MIB).unwrap(), 4 * MIB);
    assert_eq!(
        fake.map(P1, past_end, handle),
        Err(refused(OrderViolation::OutsideReservation))
    );
    let misaligned = AddressRange::new(start.checked_add(MIB).unwrap(), 4 * MIB);
    assert_eq!(
        fake.map(P1, misaligned, handle),
        Err(refused(OrderViolation::Misaligned {
            address: misaligned.start,
            granularity_bytes: PRIVATE_GRANULE,
        }))
    );
    assert_eq!(
        fake.map(P1, AddressRange::new(start, 2 * MIB), handle),
        Err(refused(OrderViolation::NotWholeAllocation {
            size_bytes: 2 * MIB,
            allocation_bytes: 4 * MIB,
        }))
    );
    assert_eq!(
        fake.map(P1, first, PhysicalHandle(999)),
        Err(refused(OrderViolation::UnknownHandle))
    );
    fake.map(P1, first, handle).unwrap();
    let other = fake.create(P1, &private(), 4 * MIB).unwrap();
    assert_eq!(
        fake.map(P1, first, other),
        Err(refused(OrderViolation::AlreadyMapped))
    );
    assert_eq!(
        fake.set_access(P1, first, DeviceOrdinal(1)),
        Err(refused(OrderViolation::WrongDevice))
    );
    fake.set_access(P1, first, DEVICE).unwrap();
    assert!(fake.is_mapped(P1, start));
    let names: Vec<_> = fake
        .calls()
        .iter()
        .map(|call| call.call.api_name())
        .collect();
    assert_eq!(
        names,
        [
            "cuMemGetAllocationGranularity",
            "cuMemAddressReserve",
            "cuMemCreate",
            "cuMemMap",
            "cuMemCreate",
            "cuMemSetAccess",
        ]
    );
}

#[test]
fn work_runs_only_over_accessible_memory() {
    let mut fake = fake();
    fake.allocation_granularity(P1, &private()).unwrap();
    let start = fake.address_reserve(P1, &private(), 8 * MIB).unwrap();
    let first = AddressRange::new(start, 4 * MIB);
    let second = AddressRange::new(start.checked_add(4 * MIB).unwrap(), 4 * MIB);
    let stale = refused(OrderViolation::UnbackedAddress { address: start });
    assert_eq!(
        fake.enqueue(P1, STREAM, WorkKind::Kernel, &[first]),
        Err(stale.clone()),
        "nothing is mapped yet"
    );
    let one = fake.create(P1, &private(), 4 * MIB).unwrap();
    fake.map(P1, first, one).unwrap();
    assert_eq!(
        fake.enqueue(P1, STREAM, WorkKind::Kernel, &[first]),
        Err(stale),
        "mapped, but access is not set"
    );
    fake.set_access(P1, first, DEVICE).unwrap();
    let event = fake
        .enqueue(P1, STREAM, WorkKind::Kernel, &[first])
        .unwrap();
    let two = fake.create(P1, &private(), 4 * MIB).unwrap();
    fake.map(P1, second, two).unwrap();
    fake.set_access(P1, second, DEVICE).unwrap();
    let spanning = AddressRange::new(start.checked_add(2 * MIB).unwrap(), 4 * MIB);
    assert!(fake
        .enqueue(P1, STREAM, WorkKind::Kernel, &[spanning])
        .is_ok());
    let beyond = AddressRange::new(start.checked_add(6 * MIB).unwrap(), 4 * MIB);
    assert!(matches!(
        fake.enqueue(P1, STREAM, WorkKind::Kernel, &[beyond]),
        Err(DriverError::Refused {
            violation: OrderViolation::UnbackedAddress { .. }
        })
    ));
    assert_eq!(fake.event_complete(P1, event), Ok(false));
    assert!(fake.complete(event));
    assert_eq!(fake.event_complete(P1, event), Ok(true));
    assert_eq!(
        fake.event_complete(P2, event),
        Err(refused(OrderViolation::UnknownEvent))
    );
    assert!(!fake.complete(EventId(12_345)));
}

#[test]
fn unmap_needs_quiescence_and_release_needs_unmap() {
    let mut fake = fake();
    fake.allocation_granularity(P1, &private()).unwrap();
    let start = fake.address_reserve(P1, &private(), 4 * MIB).unwrap();
    let range = AddressRange::new(start, 4 * MIB);
    let handle = fake.create(P1, &private(), 4 * MIB).unwrap();
    fake.map(P1, range, handle).unwrap();
    fake.set_access(P1, range, DEVICE).unwrap();
    assert_eq!(fake.used_bytes(DEVICE), 4 * MIB);
    let event = fake
        .enqueue(P1, STREAM, WorkKind::Kernel, &[range])
        .unwrap();
    assert_eq!(
        fake.unmap(P1, range),
        Err(refused(OrderViolation::InFlight { events: 1 }))
    );
    assert_eq!(
        fake.release(P1, handle),
        Err(refused(OrderViolation::ReleaseWhileMapped))
    );
    fake.complete(event);
    fake.unmap(P1, range).unwrap();
    assert_eq!(
        fake.unmap(P1, range),
        Err(refused(OrderViolation::NotMapped))
    );
    assert_eq!(fake.used_bytes(DEVICE), 4 * MIB, "unmapping frees nothing");
    fake.release(P1, handle).unwrap();
    assert_eq!(fake.used_bytes(DEVICE), 0);
    assert_eq!(
        fake.release(P1, handle),
        Err(refused(OrderViolation::HandleReleased))
    );
}

#[test]
fn release_waits_for_exports_and_imports() {
    let mut fake = fake();
    for process in [P1, P2] {
        fake.allocation_granularity(process, &posix()).unwrap();
        fake.allocation_granularity(process, &private()).unwrap();
    }
    let private_handle = fake.create(P1, &private(), 4 * MIB).unwrap();
    assert_eq!(
        fake.export_shareable(P1, private_handle, ShareableHandle::PosixFileDescriptor),
        Err(refused(OrderViolation::ExportWithoutRequestedHandleType))
    );
    let handle = fake.create(P1, &posix(), 8 * MIB).unwrap();
    let shared = fake
        .export_shareable(P1, handle, ShareableHandle::PosixFileDescriptor)
        .unwrap();
    assert_eq!(
        fake.import_shareable(P2, shared, ShareableHandle::Fabric),
        Err(refused(OrderViolation::HandleKindMismatch))
    );
    let imported = fake
        .import_shareable(P2, shared, ShareableHandle::PosixFileDescriptor)
        .unwrap();
    assert_eq!(
        fake.release(P1, handle),
        Err(refused(OrderViolation::ReleaseWithReferences {
            exports: 1,
            imports: 1,
        }))
    );
    fake.close_shared(P1, shared).unwrap();
    assert_eq!(
        fake.import_shareable(P2, shared, ShareableHandle::PosixFileDescriptor),
        Err(refused(OrderViolation::SharedHandleClosed))
    );
    assert_eq!(
        fake.release(P1, handle),
        Err(refused(OrderViolation::ReleaseWithReferences {
            exports: 0,
            imports: 1,
        }))
    );
    fake.release(P2, imported).unwrap();
    assert_eq!(
        fake.used_bytes(DEVICE),
        12 * MIB,
        "the importer's release frees nothing while the owner holds it"
    );
    fake.release(P1, handle).unwrap();
    assert_eq!(fake.used_bytes(DEVICE), 4 * MIB);
}

#[test]
fn legacy_ipc_needs_a_dedicated_malloc_and_its_consumers_closed() {
    let mut fake = fake();
    let pointer = fake.malloc(P1, 3 * MIB).unwrap();
    let pool = fake.pool_allocate(P1, MIB, true).unwrap();
    assert_eq!(
        fake.ipc_get_mem_handle(P1, pool),
        Err(refused(OrderViolation::NotAMallocBase)),
        "a pool suballocation is never shared"
    );
    assert_eq!(
        fake.ipc_get_mem_handle(P1, pointer.checked_add(512).unwrap()),
        Err(refused(OrderViolation::NotAMallocBase)),
        "an interior pointer is never shared"
    );
    let handle = fake.ipc_get_mem_handle(P1, pointer).unwrap();
    assert_eq!(
        fake.ipc_open_mem_handle(P1, handle),
        Err(refused(OrderViolation::OpenInSameProcess))
    );
    let opened = fake.ipc_open_mem_handle(P2, handle).unwrap();
    assert_eq!(
        fake.free(P1, pointer),
        Err(refused(OrderViolation::FreeWithOpenIpcHandles { opens: 1 }))
    );
    let event = fake
        .enqueue(
            P2,
            STREAM,
            WorkKind::Kernel,
            &[AddressRange::new(opened, MIB)],
        )
        .unwrap();
    assert_eq!(
        fake.ipc_close_mem_handle(P2, opened),
        Err(refused(OrderViolation::InFlight { events: 1 }))
    );
    fake.complete(event);
    fake.ipc_close_mem_handle(P2, opened).unwrap();
    fake.free(P1, pointer).unwrap();
    assert_eq!(
        fake.free(P1, pointer),
        Err(refused(OrderViolation::UnknownPointer))
    );
    fake.pool_free(P1, pool).unwrap();
    assert_eq!(fake.used_bytes(DEVICE), 0);
}

#[test]
fn a_freed_pointer_value_can_come_back() {
    let mut fake = fake();
    let first = fake.pool_allocate(P1, 4 * MIB, false).unwrap();
    fake.pool_free(P1, first).unwrap();
    let second = fake.pool_allocate(P1, 4 * MIB, false).unwrap();
    assert_eq!(
        first, second,
        "an equal pointer value never proves the same allocation"
    );
}

#[test]
fn capacity_is_enforced() {
    let mut fake = fake();
    fake.allocation_granularity(P1, &private()).unwrap();
    assert_eq!(
        fake.create(P1, &private(), 2 << 30),
        Err(DriverError::OutOfMemory {
            requested_bytes: 2 << 30,
            available_bytes: 1 << 30,
        })
    );
    assert!(fake
        .refusals()
        .iter()
        .all(|refusal| refusal.call.process == P1));
}
