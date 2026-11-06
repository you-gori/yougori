//! Physical ownership is tracked apart from mappings; exports, imports, graph references
//! and other mappings hold memory, and the last reference is closed deliberately (§3.7;
//! Appendix E step 5).

use super::*;

fn graph_key(model: &str) -> GraphExecutionKey {
    GraphExecutionKey {
        model: named(model),
        kernels: named(&format!("{model}/kernels")),
        shapes: named(&format!("{model}/shapes")),
        arguments: named(&format!("{model}/arguments")),
    }
}

#[test]
fn unmapping_does_not_free_exported_memory() {
    let mut world = World::new();
    world.show_vmm_handles(ShareableHandle::PosixFileDescriptor);
    world.permit(P1, &[Optimization::CudaIpcVmmShareableHandle]);
    world.permit(P2, &[Optimization::CudaIpcVmmShareableHandle]);
    let key = world.load(P1, "a", &[8 * MIB], posix());
    let physical = world.physical_of(key, 0);
    let export = world
        .export(P1, physical, ShareableHandle::PosixFileDescriptor)
        .unwrap();
    assert_eq!(
        world.model.references(physical, P1),
        Some(ReferenceCount {
            mappings: 1,
            exports: 1,
            ..ReferenceCount::default()
        })
    );
    let report = world.park(key, clean_drop("a")).unwrap();
    assert_eq!(report.unmapped_bytes, 8 * MIB);
    assert_eq!(report.released_bytes, 0, "unmapping is not freeing");
    assert_eq!(
        report.retained,
        [RetainedAllocation {
            batch: 0,
            physical,
            size_bytes: 8 * MIB,
            references: ReferenceCount {
                exports: 1,
                ..ReferenceCount::default()
            },
        }]
    );
    assert_eq!(world.driver.used_bytes(DEVICE), 8 * MIB);
    assert!(!world.model.physical(physical).unwrap().freed);

    world.model.close_export(&mut world.driver, export).unwrap();
    assert_eq!(
        world.model.close_export(&mut world.driver, export),
        Err(VmmError::ExportClosed { export })
    );
    assert!(world.model.references(physical, P1).unwrap().is_zero());
    assert_eq!(
        world.driver.used_bytes(DEVICE),
        8 * MIB,
        "nothing is freed until the last reference is closed deliberately"
    );
    assert_eq!(world.close(P1, physical), Ok(8 * MIB));
    assert!(world.model.physical(physical).unwrap().freed);
    assert_eq!(world.driver.used_bytes(DEVICE), 0);
    assert_eq!(
        world.close(P1, physical),
        Err(VmmError::AlreadyFreed { physical })
    );
    world.assert_no_refusals();
}

#[test]
fn an_import_and_its_mapping_hold_the_exporters_memory() {
    let mut world = World::new();
    world.show_vmm_handles(ShareableHandle::PosixFileDescriptor);
    world.permit(P1, &[Optimization::CudaIpcVmmShareableHandle]);
    world.permit(P2, &[Optimization::CudaIpcVmmShareableHandle]);
    let key = world.load(P1, "a", &[8 * MIB], posix());
    let physical = world.physical_of(key, 0);
    let export = world
        .export(P1, physical, ShareableHandle::PosixFileDescriptor)
        .unwrap();
    world.probe(P2, posix());
    let receiver = world
        .plan(P2, &layout("a", &[8 * MIB]), posix(), VmmOrigin::Import)
        .unwrap();
    world.import(receiver, 0, export).unwrap();
    world.publish(receiver, 0, batch_digest("a", 0)).unwrap();
    world.model.close_export(&mut world.driver, export).unwrap();

    let report = world.park(key, clean_drop("a")).unwrap();
    assert_eq!(report.released_bytes, 0);
    assert_eq!(
        report.retained[0].references,
        ReferenceCount {
            imports: 1,
            ..ReferenceCount::default()
        }
    );
    assert_eq!(
        world.close(P1, physical),
        Err(VmmError::StillReferenced {
            physical,
            references: ReferenceCount {
                imports: 1,
                ..ReferenceCount::default()
            },
        })
    );
    let view = world.model.create_view(receiver, 0, 8 * MIB).unwrap();
    let event = world.call(view).unwrap();
    world.driver.complete(event);

    let receiver_report = world.park(receiver, clean_drop("a")).unwrap();
    assert_eq!(receiver_report.unmapped_bytes, 8 * MIB);
    assert_eq!(
        receiver_report.released_bytes, 0,
        "the importer's release frees nothing while the exporter holds the allocation"
    );
    assert_eq!(world.driver.used_bytes(DEVICE), 8 * MIB);
    assert_eq!(world.close(P1, physical), Ok(8 * MIB));
    assert_eq!(world.driver.used_bytes(DEVICE), 0);
    world.assert_no_refusals();
}

#[test]
fn graph_references_hold_memory_until_dropped() {
    let mut world = World::new();
    let key = world.load(P1, "a", &[4 * MIB], private());
    let physical = world.physical_of(key, 0);
    let graph = world
        .model
        .capture_graph(
            P1,
            graph_key("a"),
            vec![GraphResource::Artifact {
                artifact: named("a"),
                offset_bytes: 0,
                length_bytes: 4 * MIB,
            }],
        )
        .unwrap();
    assert_eq!(
        world.model.references(physical, P1).unwrap(),
        ReferenceCount {
            mappings: 1,
            graphs: 1,
            ..ReferenceCount::default()
        }
    );
    let report = world.park(key, clean_drop("a")).unwrap();
    assert_eq!(report.released_bytes, 0);
    assert_eq!(report.retained[0].references.graphs, 1);
    assert!(matches!(
        world.close(P1, physical),
        Err(VmmError::StillReferenced { .. })
    ));
    world.model.destroy_graph(&mut world.driver, graph).unwrap();
    assert_eq!(world.close(P1, physical), Ok(4 * MIB));
    world.assert_no_refusals();
}

#[test]
fn the_last_reference_is_closed_deliberately() {
    let mut world = World::new();
    world.probe(P1, private());
    let scratch = world
        .model
        .allocate_private(
            &mut world.driver,
            &world.registry,
            P1,
            private(),
            4 * MIB,
            named("scratch"),
        )
        .unwrap();
    assert!(world.model.references(scratch, P1).unwrap().is_zero());
    assert_eq!(
        world.driver.used_bytes(DEVICE),
        4 * MIB,
        "an unreferenced allocation stays until it is closed"
    );
    assert_eq!(
        world.close(P2, scratch),
        Err(VmmError::NoHandle {
            physical: scratch,
            process: P2,
        })
    );
    assert_eq!(world.close(P1, scratch), Ok(4 * MIB));
    assert_eq!(world.driver.used_bytes(DEVICE), 0);
    assert_eq!(
        world.model.allocate_private(
            &mut world.driver,
            &world.registry,
            P1,
            private(),
            3 * MIB,
            named("scratch"),
        ),
        Err(VmmError::NotGranularityMultiple {
            size_bytes: 3 * MIB,
            granularity_bytes: PRIVATE_GRANULE,
        })
    );

    let key = world.load(P1, "a", &[4 * MIB], private());
    let physical = world.physical_of(key, 0);
    assert_eq!(
        world.close(P1, physical),
        Err(VmmError::StillReferenced {
            physical,
            references: ReferenceCount {
                mappings: 1,
                ..ReferenceCount::default()
            },
        }),
        "mapped memory is never released"
    );
    assert_eq!(
        world.close(P1, PhysicalId::new(999)),
        Err(VmmError::UnknownPhysical {
            physical: PhysicalId::new(999)
        })
    );
    world.assert_no_refusals();
}

#[test]
fn old_memory_retained_across_a_wake_is_closed_after_the_new_memory_is_live() {
    let mut world = World::new();
    world.show_vmm_handles(ShareableHandle::PosixFileDescriptor);
    world.permit(P1, &[Optimization::CudaIpcVmmShareableHandle]);
    world.permit(P2, &[Optimization::CudaIpcVmmShareableHandle]);
    let key = world.load(P1, "a", &[8 * MIB], posix());
    let old = world.physical_of(key, 0);
    let export = world
        .export(P1, old, ShareableHandle::PosixFileDescriptor)
        .unwrap();
    world.park(key, clean_drop("a")).unwrap();
    world.model.wake(key).unwrap();
    world.fill(key, "a", 1);
    let view = world.model.create_view(key, 0, 8 * MIB).unwrap();
    let running = world.call(view).unwrap();
    assert_ne!(world.physical_of(key, 0), old);
    assert_eq!(world.driver.used_bytes(DEVICE), 16 * MIB);
    world.model.close_export(&mut world.driver, export).unwrap();
    assert_eq!(
        world.close(P1, old),
        Ok(8 * MIB),
        "work on the new memory does not hold the old allocation"
    );
    assert_eq!(world.driver.used_bytes(DEVICE), 8 * MIB);
    world.driver.complete(running);
    world.assert_no_refusals();
}
