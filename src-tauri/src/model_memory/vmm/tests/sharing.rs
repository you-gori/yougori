//! Exports use only dedicated, published allocations sized to the reported granularity,
//! never a suballocation next to private data, and never across a runtime boundary (§3.7;
//! Appendix E steps 7 and 8).

use super::*;

const POSIX: ShareableHandle = ShareableHandle::PosixFileDescriptor;

/// P1 loads "a" for POSIX file descriptor sharing; P2 plans to import it.
fn shared_world(lengths: &[u64]) -> (World, MappingKey, MappingKey) {
    let mut world = World::new();
    world.show_vmm_handles(POSIX);
    world.permit(P1, &[Optimization::CudaIpcVmmShareableHandle]);
    world.permit(P2, &[Optimization::CudaIpcVmmShareableHandle]);
    let key = world.load(P1, "a", lengths, posix());
    world.probe(P2, posix());
    let receiver = world
        .plan(P2, &layout("a", lengths), posix(), VmmOrigin::Import)
        .unwrap();
    (world, key, receiver)
}

#[test]
fn appendix_e_step_7_sequence() {
    let (mut world, key, receiver) = shared_world(&[8 * MIB, 5 * MIB]);
    let mut exports = Vec::new();
    for batch in 0..2 {
        let physical = world.physical_of(key, batch);
        exports.push(world.export(P1, physical, POSIX).unwrap());
    }
    for (batch, export) in (0..2).zip(&exports) {
        world.import(receiver, batch, *export).unwrap();
        world
            .publish(receiver, batch, batch_digest("a", batch))
            .unwrap();
    }
    for export in &exports {
        world
            .model
            .close_export(&mut world.driver, *export)
            .unwrap();
    }
    let view = world.model.create_view(receiver, 0, 13 * MIB).unwrap();
    world.call(view).unwrap();

    let exporter = world.calls_of(P1);
    assert_eq!(
        exporter[exporter.len() - 4..],
        [
            "cuMemExportToShareableHandle",
            "cuMemExportToShareableHandle",
            "close",
            "close",
        ]
    );
    let batch = [
        "cuMemImportFromShareableHandle",
        "cuMemMap",
        "cuMemSetAccess",
    ];
    let mut expected = vec!["cuMemGetAllocationGranularity", "cuMemAddressReserve"];
    expected.extend(batch.repeat(2));
    expected.push("enqueue");
    assert_eq!(world.calls_of(P2), expected);

    // Each process has its own address space, so only offsets are comparable; the
    // receiver's own cuMemAddressReserve is in its call list above.
    let own = world.model.reservation(key).unwrap();
    let theirs = world.model.reservation(receiver).unwrap();
    assert_eq!(own.length_bytes, theirs.length_bytes);
    for batch in 0..2 {
        let mine = world.model.batch(key, batch).unwrap();
        let received = world.model.batch(receiver, batch).unwrap();
        assert_eq!(
            mine.address.unwrap().get() - own.start.get(),
            received.address.unwrap().get() - theirs.start.get(),
            "the receiver maps each batch at the same offset"
        );
        assert_eq!(mine.physical, received.physical, "one physical allocation");
    }
    world.assert_no_refusals();
}

#[test]
fn only_dedicated_allocations_sized_to_the_reported_granularity_are_exported() {
    let (mut world, key, _) = shared_world(&[8 * MIB, 5 * MIB]);
    let last = world.physical_of(key, 1);
    assert_eq!(
        world.model.physical(last).unwrap().size_bytes,
        SHARED_GRANULE,
        "the 5 MiB batch is exported as its whole 8 MiB allocation, the granule reported \
         for POSIX file descriptors"
    );
    world.export(P1, last, POSIX).unwrap();

    let packed = world
        .model
        .allocate_private(
            &mut world.driver,
            &world.registry,
            P1,
            posix(),
            SHARED_GRANULE,
            named("kv cache of several tenants"),
        )
        .unwrap();
    assert_eq!(
        world.export(P1, packed, POSIX),
        Err(VmmError::NotDedicated { physical: packed }),
        "an allocation that holds private data is never exported"
    );

    let unshared = world.load(P1, "b", &[4 * MIB], private());
    let physical = world.physical_of(unshared, 0);
    assert_eq!(
        world.export(P1, physical, POSIX),
        Err(VmmError::NotCreatedForHandleType {
            physical,
            requested: POSIX,
            created: None,
        })
    );
    assert_eq!(world.count_calls("cuMemExportToShareableHandle"), 1);
    world.assert_no_refusals();
}

#[test]
fn only_published_memory_is_exported() {
    let mut world = World::new();
    world.show_vmm_handles(POSIX);
    world.permit(P1, &[Optimization::CudaIpcVmmShareableHandle]);
    world.probe(P1, posix());
    let key = world
        .plan(P1, &layout("a", &[8 * MIB]), posix(), VmmOrigin::Create)
        .unwrap();
    let physical = world.back(key, 0).unwrap();
    assert_eq!(
        world.export(P1, physical, POSIX),
        Err(VmmError::NotPublished { physical })
    );
    let event = world.populate(key, 0).unwrap();
    assert_eq!(
        world.export(P1, physical, POSIX),
        Err(VmmError::NotPublished { physical }),
        "a batch still being filled is never shared"
    );
    world.driver.complete(event);
    world.publish(key, 0, batch_digest("a", 0)).unwrap();
    assert!(world.export(P1, physical, POSIX).is_ok());
}

#[test]
fn the_receiver_verifies_and_never_populates() {
    let (mut world, key, receiver) = shared_world(&[8 * MIB]);
    let export = world.export(P1, world.physical_of(key, 0), POSIX).unwrap();
    world.import(receiver, 0, export).unwrap();
    let view = world.model.create_view(receiver, 0, 8 * MIB).unwrap();
    assert_eq!(
        world.call(view),
        Err(VmmError::NotCallable {
            key: receiver,
            reason: NotCallableReason::NotPublished { batch: 0 },
        }),
        "an imported batch is unusable until the receiver verifies it"
    );
    assert!(matches!(
        world.populate(receiver, 0),
        Err(VmmError::WrongBacking { .. })
    ));
    assert!(matches!(
        world.back(receiver, 0),
        Err(VmmError::WrongBacking { .. })
    ));
    assert!(matches!(
        world.publish(receiver, 0, named("tampered")),
        Err(VmmError::DigestMismatch { .. })
    ));
    world.publish(receiver, 0, batch_digest("a", 0)).unwrap();
    assert!(world.call(view).is_ok());
}

#[test]
fn imports_must_match_the_export() {
    let (mut world, key, receiver) = shared_world(&[8 * MIB, 8 * MIB]);
    let first = world.physical_of(key, 0);
    let export = world.export(P1, first, POSIX).unwrap();
    assert_eq!(
        world.import(receiver, 1, export),
        Err(VmmError::ImportMismatch {
            export,
            key: receiver,
            batch: 1,
        }),
        "batch 0 is not batch 1"
    );
    world.probe(P1, posix());
    let own = world
        .plan(P1, &layout("z", &[8 * MIB]), posix(), VmmOrigin::Import)
        .unwrap();
    assert_eq!(
        world.import(own, 0, export),
        Err(VmmError::SameProcess { process: P1 })
    );
    assert_eq!(
        world.export(P2, first, POSIX),
        Err(VmmError::NotOwner {
            physical: first,
            process: P2,
        })
    );
    world.model.close_export(&mut world.driver, export).unwrap();
    assert_eq!(
        world.import(receiver, 0, export),
        Err(VmmError::ExportClosed { export })
    );
    assert_eq!(
        world.import(receiver, 0, ExportId::new(999)),
        Err(VmmError::UnknownExport {
            export: ExportId::new(999)
        })
    );
    assert_eq!(world.count_calls("cuMemImportFromShareableHandle"), 0);
    world.assert_no_refusals();
}

#[test]
fn sharing_never_crosses_the_runtime_boundary() {
    let (mut world, key, _) = shared_world(&[8 * MIB]);
    let export = world.export(P1, world.physical_of(key, 0), POSIX).unwrap();
    world.add_other_runtime();
    world.probe(P3, posix());
    let outsider = world
        .plan(P3, &layout("a", &[8 * MIB]), posix(), VmmOrigin::Import)
        .unwrap();
    assert_eq!(
        world.import(outsider, 0, export),
        Err(VmmError::CrossesRuntimeBoundary {
            exporter: P1,
            importer: P3,
        })
    );
    assert_eq!(world.count_calls("cuMemImportFromShareableHandle"), 0);
}

#[test]
fn appendix_e_step_8_legacy_ipc_variant() {
    let mut world = World::new();
    world.show_legacy_ipc();
    world.permit(P1, &[Optimization::CudaIpcLegacy]);
    world.permit(P2, &[Optimization::CudaIpcLegacy]);
    let key = world
        .model
        .plan_legacy(P1, named("a"), content_of("a"), whole("a", 3 * MIB))
        .unwrap();
    world.fill(key, "a", 1);
    let physical = world.physical_of(key, 0);
    let export = world
        .model
        .legacy_export(&mut world.driver, &world.registry, key)
        .unwrap();
    assert_eq!(
        world
            .model
            .legacy_open(&mut world.driver, &world.registry, P1, export),
        Err(VmmError::SameProcess { process: P1 })
    );
    world.add_other_runtime();
    assert_eq!(
        world
            .model
            .legacy_open(&mut world.driver, &world.registry, P3, export),
        Err(VmmError::CrossesRuntimeBoundary {
            exporter: P1,
            importer: P3,
        }),
        "the container boundary is not relied on before it is probed"
    );
    world
        .model
        .legacy_open(&mut world.driver, &world.registry, P2, export)
        .unwrap();
    assert_eq!(
        world
            .model
            .legacy_open(&mut world.driver, &world.registry, P2, export),
        Err(VmmError::AlreadyImported {
            physical,
            process: P2,
        })
    );

    let report = world.park(key, clean_drop("a")).unwrap();
    assert_eq!(
        report.retained[0].references.imports, 1,
        "the producer keeps the allocation while a consumer has it open"
    );
    assert_eq!(world.count_calls("cudaFree"), 0);
    world
        .model
        .legacy_close(&mut world.driver, P2, export)
        .unwrap();
    assert_eq!(world.close(P1, physical), Ok(3 * MIB));
    assert_eq!(
        world.calls_of(P1),
        ["cudaMalloc", "enqueue", "cudaIpcGetMemHandle", "cudaFree"]
    );
    assert_eq!(
        world.calls_of(P2),
        ["cudaIpcOpenMemHandle", "cudaIpcCloseMemHandle"]
    );
    world.assert_no_refusals();
}

#[test]
fn the_two_api_families_never_stand_in_for_each_other() {
    let mut world = World::new();
    world.show_legacy_ipc();
    world.show_vmm_handles(POSIX);
    world.permit(
        P1,
        &[
            Optimization::CudaIpcLegacy,
            Optimization::CudaIpcVmmShareableHandle,
        ],
    );
    world.permit(
        P2,
        &[
            Optimization::CudaIpcLegacy,
            Optimization::CudaIpcVmmShareableHandle,
        ],
    );
    let legacy = world
        .model
        .plan_legacy(P1, named("l"), content_of("l"), whole("l", 3 * MIB))
        .unwrap();
    world.fill(legacy, "l", 1);
    let legacy_export = world
        .model
        .legacy_export(&mut world.driver, &world.registry, legacy)
        .unwrap();
    let vmm = world.load(P1, "v", &[8 * MIB], posix());
    let vmm_export = world.export(P1, world.physical_of(vmm, 0), POSIX).unwrap();
    assert_eq!(
        world
            .model
            .legacy_open(&mut world.driver, &world.registry, P2, vmm_export),
        Err(VmmError::WrongExportKind { export: vmm_export })
    );
    world.probe(P2, posix());
    let receiver = world
        .plan(P2, &layout("v", &[8 * MIB]), posix(), VmmOrigin::Import)
        .unwrap();
    assert_eq!(
        world.import(receiver, 0, legacy_export),
        Err(VmmError::WrongExportKind {
            export: legacy_export
        })
    );
    assert_eq!(
        world.export(P1, world.physical_of(legacy, 0), POSIX),
        Err(VmmError::NotVmmAllocation {
            physical: world.physical_of(legacy, 0)
        }),
        "a cudaMalloc allocation is never exported as a CUDA VMM handle"
    );
    assert!(matches!(
        world
            .model
            .legacy_export(&mut world.driver, &world.registry, vmm),
        Err(VmmError::WrongBacking { .. })
    ));
}
