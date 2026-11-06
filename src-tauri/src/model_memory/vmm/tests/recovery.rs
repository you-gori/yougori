//! GPU-T22: a receiver that let go of its handle, such as at its own park, imports a fresh
//! export of the same allocation again, while a handle it still holds blocks a second
//! import. GPU-T23: once an exporter's process exits, nothing runs over memory it
//! exported, whatever the IPC family, until the importer releases it and imports a live
//! exporter's export.

use super::*;

const POSIX: ShareableHandle = ShareableHandle::PosixFileDescriptor;
const VMM: Optimization = Optimization::CudaIpcVmmShareableHandle;
const LEGACY: Optimization = Optimization::CudaIpcLegacy;

fn exited<T>(process: ProcessId) -> Result<T, VmmError> {
    Err(VmmError::ProcessExited { process })
}

fn refused<T>(violation: OrderViolation) -> Result<T, DriverError> {
    Err(DriverError::Refused { violation })
}

/// P1 exports artifact "a" for POSIX sharing; P2 imports it, publishes it on its own
/// verification and has run a kernel through a view over it.
fn imported_world() -> (World, MappingKey, MappingKey, ExportId, ViewId) {
    let mut world = World::new();
    world.show_vmm_handles(POSIX);
    world.permit(P1, &[VMM]);
    world.permit(P2, &[VMM]);
    let key = world.load(P1, "a", &[8 * MIB], posix());
    let export = world.export(P1, world.physical_of(key, 0), POSIX).unwrap();
    world.probe(P2, posix());
    let receiver = world
        .plan(P2, &layout("a", &[8 * MIB]), posix(), VmmOrigin::Import)
        .unwrap();
    world.import(receiver, 0, export).unwrap();
    world.publish(receiver, 0, batch_digest("a", 0)).unwrap();
    let view = world.model.create_view(receiver, 0, 8 * MIB).unwrap();
    let event = world.call(view).unwrap();
    assert!(world.driver.complete(event));
    (world, key, receiver, export, view)
}

/// P1 publishes artifact "a" in a dedicated `cudaMalloc` allocation and exports it as a
/// legacy IPC handle, which P2 opened.
fn opened_world() -> (World, MappingKey, ExportId) {
    let mut world = World::new();
    world.show_legacy_ipc();
    world.permit(P1, &[LEGACY]);
    world.permit(P2, &[LEGACY]);
    let key = world
        .model
        .plan_legacy(P1, named("a"), content_of("a"), whole("a", 3 * MIB))
        .unwrap();
    world.fill(key, "a", 1);
    let export = world
        .model
        .legacy_export(&mut world.driver, &world.registry, key)
        .unwrap();
    world
        .model
        .legacy_open(&mut world.driver, &world.registry, P2, export)
        .unwrap();
    (world, key, export)
}

fn graph_key() -> GraphExecutionKey {
    GraphExecutionKey {
        model: named("a"),
        kernels: named("a/kernels"),
        shapes: named("a/shapes"),
        arguments: named("a/arguments"),
    }
}

fn whole_artifact() -> GraphResource {
    GraphResource::Artifact {
        artifact: named("a"),
        offset_bytes: 0,
        length_bytes: 8 * MIB,
    }
}

#[test]
fn a_released_handle_never_blocks_a_fresh_import() {
    let (mut world, key, receiver, export, view) = imported_world();
    let physical = world.physical_of(key, 0);
    world.model.close_export(&mut world.driver, export).unwrap();
    let report = world.park(receiver, clean_drop("a")).unwrap();
    assert_eq!(
        report.released_bytes, 0,
        "the exporter still holds the memory"
    );
    assert!(
        report.retained.is_empty(),
        "the receiver let go of its handle"
    );
    assert_eq!(world.model.references(physical, P1).unwrap().imports, 0);

    world.model.wake(receiver).unwrap();
    assert_eq!(
        world.import(receiver, 0, export),
        Err(VmmError::ExportClosed { export }),
        "the closed export stays refused"
    );
    let fresh = world.export(P1, physical, POSIX).unwrap();
    assert_eq!(
        world.import(receiver, 0, fresh),
        Ok(physical),
        "the handle released at the park does not block a fresh import"
    );
    world.publish(receiver, 0, batch_digest("a", 0)).unwrap();
    assert!(world.call(view).is_ok(), "the retained view runs again");
    assert_eq!(world.model.references(physical, P1).unwrap().imports, 1);
    assert_eq!(world.count_calls("cuMemImportFromShareableHandle"), 2);
    world.assert_no_refusals();
}

#[test]
fn a_handle_still_held_blocks_a_second_import() {
    let (mut world, key, receiver, _, view) = imported_world();
    let physical = world.physical_of(key, 0);
    let graph = world
        .model
        .capture_graph(P2, graph_key(), vec![whole_artifact()])
        .unwrap();
    let report = world.park(receiver, clean_drop("a")).unwrap();
    assert_eq!(
        report.retained,
        vec![RetainedAllocation {
            batch: 0,
            physical,
            size_bytes: 8 * MIB,
            references: ReferenceCount {
                graphs: 1,
                ..ReferenceCount::default()
            },
        }],
        "the graph keeps the receiver's handle"
    );

    world.model.wake(receiver).unwrap();
    let fresh = world.export(P1, physical, POSIX).unwrap();
    assert_eq!(
        world.import(receiver, 0, fresh),
        Err(VmmError::AlreadyImported {
            physical,
            process: P2,
        }),
        "a live handle still blocks a second import"
    );
    assert_eq!(world.count_calls("cuMemImportFromShareableHandle"), 1);

    world.model.destroy_graph(&mut world.driver, graph).unwrap();
    assert_eq!(
        world.close(P2, physical),
        Ok(0),
        "P1 still holds the memory"
    );
    assert_eq!(world.import(receiver, 0, fresh), Ok(physical));
    world.publish(receiver, 0, batch_digest("a", 0)).unwrap();
    assert!(world.call(view).is_ok());
    world.assert_no_refusals();
}

#[test]
fn a_consumer_opens_again_after_closing() {
    let (mut world, key, export) = opened_world();
    let physical = world.physical_of(key, 0);
    assert_eq!(
        world
            .model
            .legacy_open(&mut world.driver, &world.registry, P2, export),
        Err(VmmError::AlreadyImported {
            physical,
            process: P2,
        }),
        "an open mapping still blocks a second open"
    );
    world
        .model
        .legacy_close(&mut world.driver, P2, export)
        .unwrap();
    assert!(
        world
            .model
            .legacy_open(&mut world.driver, &world.registry, P2, export)
            .is_ok(),
        "a closed one does not"
    );
    assert_eq!(world.model.references(physical, P1).unwrap().imports, 1);
    assert_eq!(world.count_calls("cudaIpcOpenMemHandle"), 2);
    world.assert_no_refusals();
}

#[test]
fn an_exited_exporter_leaves_no_import_to_run() {
    let (mut world, key, receiver, export, view) = imported_world();
    let physical = world.physical_of(key, 0);
    let solo = world.load(P1, "b", &[PRIVATE_GRANULE], private());
    let graph = world
        .model
        .capture_graph(P2, graph_key(), vec![whole_artifact()])
        .unwrap();
    let event = world.call(view).unwrap();
    assert!(world.driver.complete(event));

    assert!(world.driver.exit_process(P1));
    let report = world.model.process_exited(P1).unwrap();
    assert_eq!(
        report.freed_bytes, PRIVATE_GRANULE,
        "memory nobody else held is gone"
    );
    assert_eq!(report.closed_exports, vec![export]);
    assert_eq!(
        report.orphaned,
        vec![physical],
        "the import keeps the memory, but its exporter is gone"
    );
    assert_eq!(report.dropped_artifacts.len(), 2);
    assert!(report.dropped_artifacts.contains(&key));
    assert!(report.dropped_artifacts.contains(&solo));
    assert!(world.model.has_exited(P1));
    assert!(!world.model.has_exited(P2));
    assert!(!world.model.physical(physical).unwrap().freed);
    assert_eq!(world.driver.used_bytes(DEVICE), 8 * MIB);

    let gone = Err(VmmError::NotCallable {
        key: receiver,
        reason: NotCallableReason::ExporterGone { exporter: P1 },
    });
    assert_eq!(world.call(view), gone, "the retained view no longer runs");
    assert_eq!(
        world.model.launch_graph(&mut world.driver, graph, STREAM),
        gone,
        "nor does a graph over it"
    );
    assert_eq!(
        world
            .model
            .reuse_graph(&mut world.driver, graph, graph_key(), &[whole_artifact()]),
        Err(VmmError::GraphIncompatible {
            graph,
            mismatch: GraphMismatch::Unavailable {
                resource: 0,
                reason: NotCallableReason::ExporterGone { exporter: P1 },
            },
        })
    );

    assert_eq!(world.export(P1, physical, POSIX), exited(P1));
    assert_eq!(world.close(P1, physical), exited(P1));
    assert_eq!(world.model.process_exited(P1), exited(P1));
    assert_eq!(
        world
            .model
            .probe_granularity(&mut world.driver, &world.registry, P1, posix(), HOUR),
        exited(P1)
    );
    assert_eq!(
        world.model.wake(key),
        Err(VmmError::UnknownArtifact { key }),
        "its artifacts went with it"
    );

    world.model.destroy_graph(&mut world.driver, graph).unwrap();
    let parked = world.park(receiver, clean_drop("a")).unwrap();
    assert_eq!(
        parked.released_bytes,
        8 * MIB,
        "the importer let go of the last handle"
    );
    assert!(world.model.physical(physical).unwrap().freed);
    assert_eq!(world.driver.used_bytes(DEVICE), 0);

    world.model.wake(receiver).unwrap();
    assert_eq!(
        world.import(receiver, 0, export),
        Err(VmmError::ExportClosed { export }),
        "the exit closed its exports"
    );
    world.driver.add_process(P3, DEVICE);
    world.model.register_process(context(P3, "wsl")).unwrap();
    world.permit(P3, &[VMM]);
    let live = world.load(P3, "a", &[8 * MIB], posix());
    let rebuilt = world.physical_of(live, 0);
    let fresh = world.export(P3, rebuilt, POSIX).unwrap();
    assert_eq!(world.import(receiver, 0, fresh), Ok(rebuilt));
    world.publish(receiver, 0, batch_digest("a", 0)).unwrap();
    assert!(
        world.call(view).is_ok(),
        "the view runs again over a live exporter's memory"
    );
    world.assert_no_refusals();
}

#[test]
fn an_exited_producer_admits_no_new_open() {
    let (mut world, key, export) = opened_world();
    let physical = world.physical_of(key, 0);
    world.driver.add_process(P3, DEVICE);
    world.model.register_process(context(P3, "wsl")).unwrap();
    world.permit(P3, &[LEGACY]);

    assert!(world.driver.exit_process(P1));
    assert_eq!(
        world.model.process_exited(P1),
        Ok(ExitReport {
            freed_bytes: 0,
            closed_exports: Vec::new(),
            orphaned: vec![physical],
            dropped_artifacts: vec![key],
        }),
        "a legacy IPC handle has nothing to close: it ends with its producer"
    );
    for consumer in [P2, P3] {
        assert_eq!(
            world
                .model
                .legacy_open(&mut world.driver, &world.registry, consumer, export),
            exited(P1),
            "nothing opens a dead producer's memory"
        );
    }
    assert_eq!(world.driver.used_bytes(DEVICE), 3 * MIB);
    world
        .model
        .legacy_close(&mut world.driver, P2, export)
        .unwrap();
    assert!(world.model.physical(physical).unwrap().freed);
    assert_eq!(world.driver.used_bytes(DEVICE), 0);
    world.assert_no_refusals();
}

#[test]
fn an_exited_importer_lets_the_exporter_free_its_memory() {
    let (mut world, key, receiver, export, view) = imported_world();
    let physical = world.physical_of(key, 0);
    world.model.close_export(&mut world.driver, export).unwrap();
    assert!(world.driver.exit_process(P2));
    assert_eq!(
        world.model.process_exited(P2),
        Ok(ExitReport {
            freed_bytes: 0,
            closed_exports: Vec::new(),
            orphaned: Vec::new(),
            dropped_artifacts: vec![receiver],
        })
    );
    assert_eq!(world.call(view), Err(VmmError::UnknownView { view }));
    assert_eq!(world.model.references(physical, P1).unwrap().imports, 0);
    let parked = world.park(key, clean_drop("a")).unwrap();
    assert_eq!(parked.released_bytes, 8 * MIB);
    assert!(world.model.physical(physical).unwrap().freed);
    assert_eq!(world.driver.used_bytes(DEVICE), 0);
    world.assert_no_refusals();
}

#[test]
fn an_unknown_process_cannot_exit() {
    let mut world = World::new();
    assert_eq!(
        world.model.process_exited(P3),
        Err(VmmError::UnknownProcess { process: P3 })
    );
    assert!(!world.driver.exit_process(P3));
}

#[test]
fn the_fake_driver_closes_what_an_exiting_process_held() {
    let mut fake = World::new().driver;
    for process in [P1, P2] {
        fake.allocation_granularity(process, &posix()).unwrap();
    }
    let start = fake.address_reserve(P2, &posix(), 8 * MIB).unwrap();
    let handle = fake.create(P1, &posix(), 8 * MIB).unwrap();
    let shared = fake.export_shareable(P1, handle, POSIX).unwrap();
    let imported = fake.import_shareable(P2, shared, POSIX).unwrap();
    let range = AddressRange::new(start, 8 * MIB);
    fake.map(P2, range, imported).unwrap();
    let pointer = fake.malloc(P1, 3 * MIB).unwrap();
    let ipc = fake.ipc_get_mem_handle(P1, pointer).unwrap();
    let opened = fake.ipc_open_mem_handle(P2, ipc).unwrap();
    assert_eq!(fake.used_bytes(DEVICE), 11 * MIB);

    assert!(fake.exit_process(P1));
    assert!(!fake.exit_process(P1), "a process exits once");
    assert_eq!(
        fake.allocation_granularity(P1, &posix()),
        refused(OrderViolation::UnknownProcess)
    );
    assert_eq!(
        fake.used_bytes(DEVICE),
        11 * MIB,
        "what another process holds stays allocated"
    );
    fake.add_process(P3, DEVICE);
    assert_eq!(
        fake.import_shareable(P3, shared, POSIX),
        refused(OrderViolation::SharedHandleClosed),
        "the exit closed its exported handles"
    );
    assert_eq!(
        fake.ipc_open_mem_handle(P3, ipc),
        refused(OrderViolation::UnknownIpcHandle),
        "and its IPC handles ended with it"
    );
    fake.unmap(P2, range).unwrap();
    fake.release(P2, imported).unwrap();
    assert_eq!(fake.used_bytes(DEVICE), 3 * MIB);
    fake.ipc_close_mem_handle(P2, opened).unwrap();
    assert_eq!(fake.used_bytes(DEVICE), 0);
}
