//! Granularity and handle-type support come from fresh CORE-01 evidence, never from the
//! driver's or the caller's word (§3.7, §1.1 row 309, Appendix E step 1).

use super::*;
use crate::foundation::evidence::{EvidenceRefusal, Staleness};

/// The granularity refusal of `result`, if it is one.
fn granularity_refusal<T: std::fmt::Debug>(result: Result<T, VmmError>) -> GranularityRefusal {
    match result {
        Err(VmmError::Granularity(refusal)) => refusal,
        other => panic!("expected a granularity refusal, got {other:?}"),
    }
}

fn probe_result(
    world: &mut World,
    process: ProcessId,
    properties: AllocationProperties,
    fresh_for: Duration,
) -> Result<GranularityResult, VmmError> {
    world.model.probe_granularity(
        &mut world.driver,
        &world.registry,
        process,
        properties,
        fresh_for,
    )
}

#[test]
fn the_evidenced_granularity_is_used_never_2_mib() {
    let mut world = World::new();
    assert_eq!(granule(world.probe(P1, private())), PRIVATE_GRANULE);
    assert_eq!(
        world.plan(
            P1,
            &layout("a", &[2 * MIB, 2 * MIB]),
            private(),
            VmmOrigin::Create
        ),
        Err(VmmError::BatchNotAligned {
            batch: 0,
            length_bytes: 2 * MIB,
            granularity_bytes: PRIVATE_GRANULE,
        }),
        "a 2 MiB batch is not a whole granule of the evidenced 4 MiB"
    );
    let key = world
        .plan(
            P1,
            &layout("b", &[4 * MIB, 3 * MIB]),
            private(),
            VmmOrigin::Create,
        )
        .unwrap();
    assert_eq!(world.model.reservation(key).unwrap().length_bytes, 8 * MIB);
    let last = world.model.batch(key, 1).unwrap();
    assert_eq!(
        (last.offset_bytes, last.length_bytes, last.allocation_bytes),
        (4 * MIB, 3 * MIB, 4 * MIB),
        "the last batch is padded to the evidenced granule"
    );

    world.set_granule(None, Some(64 * 1024));
    assert_eq!(granule(world.probe(P1, private())), 64 * 1024);
    let key = world
        .plan(P1, &layout("c", &[3 * MIB]), private(), VmmOrigin::Create)
        .unwrap();
    assert_eq!(
        world.model.reservation(key).unwrap().length_bytes,
        3 * MIB,
        "at an evidenced 64 KiB the same 3 MiB needs no padding"
    );
    world.assert_no_refusals();
}

#[test]
fn nothing_is_asked_reserved_or_created_without_evidence() {
    let mut world = World::new();
    let missing = GranularityRefusal::Evidence {
        properties: private(),
        cause: EvidenceRefusal::Missing {
            capability: Capability::CudaVmmAllocation,
        },
    };
    assert_eq!(
        granularity_refusal(probe_result(&mut world, P1, private(), HOUR)),
        missing,
        "without evidence the driver is not even asked"
    );
    assert_eq!(
        granularity_refusal(world.plan(P1, &layout("a", &[4 * MIB]), private(), VmmOrigin::Create)),
        missing
    );
    assert_eq!(
        granularity_refusal(world.model.allocate_private(
            &mut world.driver,
            &world.registry,
            P1,
            private(),
            4 * MIB,
            named("scratch"),
        )),
        missing
    );
    assert!(world.driver.calls().is_empty(), "no driver call was made");
}

#[test]
fn the_driver_answer_is_only_cross_checked() {
    let mut world = World::new();
    world.show_allocation(P1, private(), Some(PRIVATE_GRANULE));
    world.driver.set_granularity(DEVICE, None, Some(8 * MIB));
    assert_eq!(
        granularity_refusal(probe_result(&mut world, P1, private(), HOUR)),
        GranularityRefusal::DriverContradicts {
            properties: private(),
            evidence_bytes: Some(PRIVATE_GRANULE),
            driver_bytes: Some(8 * MIB),
        },
        "the driver's word never overrides the evidence"
    );
    assert!(world.model.granularity_query(P1, private()).is_none());
    assert_eq!(
        granularity_refusal(world.plan(P1, &layout("a", &[4 * MIB]), private(), VmmOrigin::Create)),
        GranularityRefusal::NotQueried {
            properties: private()
        },
        "a contradicting answer is not kept"
    );

    world.driver.set_granularity(DEVICE, None, None);
    assert_eq!(
        granularity_refusal(probe_result(&mut world, P1, private(), HOUR)),
        GranularityRefusal::DriverContradicts {
            properties: private(),
            evidence_bytes: Some(PRIVATE_GRANULE),
            driver_bytes: None,
        }
    );
    world
        .driver
        .set_granularity(DEVICE, None, Some(PRIVATE_GRANULE));
    world.show_allocation(P1, private(), None);
    assert_eq!(
        granularity_refusal(probe_result(&mut world, P1, private(), HOUR)),
        GranularityRefusal::DriverContradicts {
            properties: private(),
            evidence_bytes: None,
            driver_bytes: Some(PRIVATE_GRANULE),
        },
        "a driver claiming support never stands in for evidence of it"
    );
    assert_eq!(world.count_calls("cuMemAddressReserve"), 0);
}

#[test]
fn granularity_evidence_answers_only_for_its_exact_subject() {
    let mut world = World::new();
    world.probe(P1, private());
    assert_eq!(
        granularity_refusal(world.plan(P1, &layout("a", &[8 * MIB]), posix(), VmmOrigin::Create)),
        GranularityRefusal::Evidence {
            properties: posix(),
            cause: EvidenceRefusal::Missing {
                capability: Capability::CudaVmmAllocation
            },
        },
        "evidence without a handle type does not answer for POSIX file descriptors"
    );
    assert_eq!(
        granularity_refusal(world.plan(P2, &layout("a", &[4 * MIB]), private(), VmmOrigin::Create)),
        GranularityRefusal::NotQueried {
            properties: private()
        },
        "the same runtime's evidence still needs this process's own step 1"
    );
    world.add_other_runtime();
    assert!(
        matches!(
            granularity_refusal(probe_result(&mut world, P3, private(), HOUR)),
            GranularityRefusal::Evidence {
                cause: EvidenceRefusal::Missing { .. },
                ..
            }
        ),
        "evidence about another runtime never applies"
    );

    let query = world.model.granularity_query(P1, private()).unwrap();
    assert_eq!(query.properties(), private());
    assert_eq!(query.source(), SourceClass::HostProbe);
    assert_eq!(query.clock(), world.registry.session());
    assert_eq!(query.fresh_for(), HOUR);
    assert_eq!(granule(query.answer()), PRIVATE_GRANULE);
}

#[test]
fn stale_or_reconfigured_evidence_is_refused() {
    let mut world = World::new();
    world.probe(P1, private());
    world
        .plan(P1, &layout("a", &[4 * MIB]), private(), VmmOrigin::Create)
        .unwrap();
    world.advance(MINUTE + Duration::from_secs(1));
    assert_eq!(
        granularity_refusal(world.plan(P1, &layout("b", &[4 * MIB]), private(), VmmOrigin::Create)),
        GranularityRefusal::Evidence {
            properties: private(),
            cause: EvidenceRefusal::Stale {
                capability: Capability::CudaVmmAllocation,
                staleness: Staleness::TooOld {
                    age: MINUTE + Duration::from_secs(1),
                    limit: MINUTE,
                },
            },
        }
    );
    world.probe(P1, private());
    world
        .plan(P1, &layout("b", &[4 * MIB]), private(), VmmOrigin::Create)
        .unwrap();

    world
        .model
        .set_configuration(P1, configuration("581.0"))
        .unwrap();
    assert!(matches!(
        granularity_refusal(world.plan(P1, &layout("c", &[4 * MIB]), private(), VmmOrigin::Create)),
        GranularityRefusal::Evidence {
            cause: EvidenceRefusal::FingerprintChanged { .. },
            ..
        }
    ));
    world.probe(P1, private());
    world
        .plan(P1, &layout("c", &[4 * MIB]), private(), VmmOrigin::Create)
        .unwrap();

    let restarted = ProbeRegistry::new(Arc::clone(&world.clock));
    assert!(
        matches!(
            granularity_refusal(world.model.plan_vmm(
                &mut world.driver,
                &restarted,
                P1,
                &layout("d", &[4 * MIB]),
                private(),
                VmmOrigin::Create,
            )),
            GranularityRefusal::Evidence {
                cause: EvidenceRefusal::Missing { .. },
                ..
            }
        ),
        "a registry made after a restart holds none of the old evidence"
    );
}

#[test]
fn the_step_one_answer_must_be_fresh_too() {
    let mut world = World::new();
    world.show_allocation(P1, private(), Some(PRIVATE_GRANULE));
    probe_result(&mut world, P1, private(), Duration::from_secs(10)).unwrap();
    world.advance(Duration::from_secs(11));
    world.show_allocation(P1, private(), Some(PRIVATE_GRANULE));
    assert_eq!(
        granularity_refusal(world.plan(P1, &layout("a", &[4 * MIB]), private(), VmmOrigin::Create)),
        GranularityRefusal::QueryStale {
            properties: private(),
            staleness: Staleness::TooOld {
                age: Duration::from_secs(11),
                limit: Duration::from_secs(10),
            },
        }
    );
    world.probe(P1, private());
    assert!(world
        .plan(P1, &layout("a", &[4 * MIB]), private(), VmmOrigin::Create)
        .is_ok());
}

#[test]
fn a_declared_or_weak_report_never_counts() {
    for (source, required) in [
        (SourceClass::Fixture, SourceClass::HostProbe),
        (SourceClass::RecordedDeclaration, SourceClass::HostProbe),
        (SourceClass::GuestReport, SourceClass::HostProbe),
    ] {
        let mut world = World::with_allocation_source(source);
        world.show_allocation(P1, private(), Some(PRIVATE_GRANULE));
        assert_eq!(
            granularity_refusal(probe_result(&mut world, P1, private(), HOUR)),
            GranularityRefusal::Evidence {
                properties: private(),
                cause: EvidenceRefusal::SourceTooWeak {
                    capability: Capability::CudaVmmAllocation,
                    observed: source,
                    required,
                },
            }
        );
    }

    let mut world = World::with_allocation_source(SourceClass::GuestReport);
    world.driver.add_process(P3, DEVICE);
    let guest_policy = ProcessContext {
        evidence_policy: EvidencePolicy {
            minimum_source: SourceClass::Fixture,
            max_age: MINUTE,
        },
        ..context(P3, "wsl")
    };
    world.model.register_process(guest_policy).unwrap();
    world.show_allocation(P3, private(), Some(PRIVATE_GRANULE));
    assert_eq!(
        probe_result(&mut world, P3, private(), HOUR).map(granule),
        Ok(PRIVATE_GRANULE),
        "a guest report meets CORE-01's floor when the policy asks no more"
    );
    let mut declared = World::with_allocation_source(SourceClass::Fixture);
    declared.driver.add_process(P3, DEVICE);
    declared
        .model
        .register_process(ProcessContext {
            evidence_policy: EvidencePolicy {
                minimum_source: SourceClass::Fixture,
                max_age: MINUTE,
            },
            ..context(P3, "wsl")
        })
        .unwrap();
    declared.show_allocation(P3, private(), Some(PRIVATE_GRANULE));
    assert!(
        matches!(
            granularity_refusal(probe_result(&mut declared, P3, private(), HOUR)),
            GranularityRefusal::Evidence {
                cause: EvidenceRefusal::SourceTooWeak {
                    required: SourceClass::GuestReport,
                    ..
                },
                ..
            }
        ),
        "a fixture never counts, whatever the policy says"
    );
    assert_eq!(
        world.model.register_process(context(P1, "wsl")),
        Err(VmmError::ProcessExists { process: P1 })
    );
}

#[test]
fn unsupported_allocation_is_reported_and_never_mapped() {
    let mut world = World::new();
    world.set_granule(None, None);
    assert_eq!(world.probe(P1, private()), GranularityResult::NotSupported);
    assert!(matches!(
        granularity_refusal(world.plan(P1, &layout("a", &[4 * MIB]), private(), VmmOrigin::Create)),
        GranularityRefusal::Evidence {
            cause: EvidenceRefusal::Unsupported { .. },
            ..
        }
    ));
    assert_eq!(world.count_calls("cuMemAddressReserve"), 0);
}

#[test]
fn a_zero_answer_or_another_device_is_refused() {
    let mut world = World::new();
    world.show_allocation(P1, private(), Some(PRIVATE_GRANULE));
    world.driver.set_granularity(DEVICE, None, Some(0));
    assert!(matches!(
        probe_result(&mut world, P1, private(), HOUR),
        Err(VmmError::InvalidDriverReport { .. })
    ));
    let other = AllocationProperties {
        device: DeviceOrdinal(1),
        requested_handle: None,
    };
    assert_eq!(
        probe_result(&mut world, P1, other, HOUR),
        Err(VmmError::WrongDevice {
            process: P1,
            expected: DEVICE,
            found: DeviceOrdinal(1),
        })
    );
    assert_eq!(
        probe_result(&mut world, ProcessId(9), private(), HOUR),
        Err(VmmError::UnknownProcess {
            process: ProcessId(9)
        })
    );
}

#[test]
fn evidence_that_contradicts_the_size_in_use_stops_mapping() {
    let mut world = World::new();
    world.probe(P1, private());
    let key = world
        .plan(
            P1,
            &layout("a", &[4 * MIB, 4 * MIB]),
            private(),
            VmmOrigin::Create,
        )
        .unwrap();
    world.back(key, 0).unwrap();
    world.set_granule(None, Some(8 * MIB));
    world.probe(P1, private());
    assert_eq!(
        world.back(key, 1),
        Err(VmmError::Granularity(GranularityRefusal::Changed {
            laid_out_bytes: 4 * MIB,
            reported_bytes: 8 * MIB,
        }))
    );
    world.show_allocation(P1, private(), Some(PRIVATE_GRANULE));
    assert!(
        matches!(
            granularity_refusal(world.back(key, 1)),
            GranularityRefusal::DriverContradicts { .. }
        ),
        "the evidence went back to 4 MiB, but the driver's last answer was 8 MiB"
    );
    world.advance(HOUR);
    assert!(matches!(
        granularity_refusal(world.back(key, 1)),
        GranularityRefusal::Evidence {
            cause: EvidenceRefusal::Stale { .. },
            ..
        }
    ));
    assert_eq!(world.count_calls("cuMemCreate"), 1);
}

#[test]
fn export_needs_fresh_evidence_for_the_exact_handle_type() {
    let mut world = World::new();
    let key = world.load(P1, "a", &[8 * MIB], posix());
    let physical = world.physical_of(key, 0);
    let posix_handle = ShareableHandle::PosixFileDescriptor;
    assert_eq!(
        world.export(P1, physical, posix_handle),
        Err(VmmError::Evidence(EvidenceRefusal::Missing {
            capability: Capability::CudaIpcVmmShareableHandle
        }))
    );

    world.show_vmm_handles(ShareableHandle::Fabric);
    assert_eq!(
        world.export(P1, physical, posix_handle),
        Err(VmmError::HandleTypeNotShown {
            requested: posix_handle,
            shown: SupportDetail::CudaIpcVmmShareableHandle {
                handle: ShareableHandle::Fabric
            },
        }),
        "evidence for another handle type never stands in"
    );

    world.show_legacy_ipc();
    let subject = Subject::Runtime(runtime("wsl"));
    world.vmm_probe.respond(
        &subject,
        Observation::unsupported(
            configuration("580.1"),
            HOUR,
            UnsupportedReason::OperationFailed,
        ),
    );
    world
        .registry
        .refresh(Capability::CudaIpcVmmShareableHandle, &subject)
        .unwrap();
    assert_eq!(
        world.export(P1, physical, posix_handle),
        Err(VmmError::Evidence(EvidenceRefusal::Unsupported {
            capability: Capability::CudaIpcVmmShareableHandle,
            reason: UnsupportedReason::OperationFailed,
        })),
        "legacy IPC evidence never enables CUDA VMM sharing"
    );

    world.show_vmm_handles(posix_handle);
    world.advance(MINUTE + Duration::from_secs(1));
    world.probe(P1, posix());
    assert!(
        matches!(
            world.export(P1, physical, posix_handle),
            Err(VmmError::Evidence(EvidenceRefusal::Stale { .. }))
        ),
        "handle-type evidence goes stale like any other"
    );

    world.show_vmm_handles(posix_handle);
    world.permit(P1, &[Optimization::CudaIpcVmmShareableHandle]);
    let export = world.export(P1, physical, posix_handle).unwrap();
    let evidence = world.model.export_evidence(export).unwrap();
    assert_eq!(evidence.source(), SourceClass::HostProbe);
    assert_eq!(
        evidence.detail(),
        &SupportDetail::CudaIpcVmmShareableHandle {
            handle: posix_handle
        }
    );
    assert_eq!(world.count_calls("cuMemExportToShareableHandle"), 1);
    world.assert_no_refusals();
}

#[test]
fn legacy_ipc_needs_its_own_evidence() {
    let mut world = World::new();
    let key = world
        .model
        .plan_legacy(P1, named("a"), content_of("a"), whole("a", 3 * MIB))
        .unwrap();
    world.fill(key, "a", 1);
    world.show_vmm_handles(ShareableHandle::PosixFileDescriptor);
    assert_eq!(
        world
            .model
            .legacy_export(&mut world.driver, &world.registry, key),
        Err(VmmError::Evidence(EvidenceRefusal::Missing {
            capability: Capability::CudaIpcLegacy
        })),
        "CUDA VMM evidence never enables legacy IPC"
    );
    world.show_legacy_ipc();
    world.permit(P1, &[Optimization::CudaIpcLegacy]);
    assert!(world
        .model
        .legacy_export(&mut world.driver, &world.registry, key)
        .is_ok());
    assert_eq!(world.count_calls("cudaIpcGetMemHandle"), 1);
}
