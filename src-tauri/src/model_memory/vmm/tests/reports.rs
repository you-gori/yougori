//! Reports and refusals serialize with distinct tags and read as plain sentences.

use super::*;
use crate::foundation::evidence::EvidenceRefusal;

#[test]
fn refusals_keep_the_tags_of_what_they_wrap() {
    let granularity = serde_json::to_value(VmmError::Granularity(GranularityRefusal::Evidence {
        properties: private(),
        cause: EvidenceRefusal::Missing {
            capability: Capability::CudaVmmAllocation,
        },
    }))
    .unwrap();
    assert_eq!(granularity["vmm_error"], "granularity");
    assert_eq!(granularity["refusal"], "evidence");
    assert_eq!(granularity["properties"]["device"], 0);
    assert_eq!(granularity["cause"]["refusal"], "missing");
    assert_eq!(granularity["cause"]["capability"], "cuda_vmm_allocation");

    let evidence = serde_json::to_value(VmmError::Evidence(EvidenceRefusal::Missing {
        capability: Capability::CudaIpcLegacy,
    }))
    .unwrap();
    assert_eq!(evidence["vmm_error"], "evidence");
    assert_eq!(evidence["refusal"], "missing");
    assert_eq!(evidence["capability"], "cuda_ipc_legacy");

    let driver = serde_json::to_value(VmmError::Driver(DriverError::Refused {
        violation: OrderViolation::ReleaseWhileMapped,
    }))
    .unwrap();
    assert_eq!(driver["vmm_error"], "driver");
    assert_eq!(driver["error"], "refused");
    assert_eq!(driver["violation"]["violation"], "release_while_mapped");

    let graph = serde_json::to_value(VmmError::GraphIncompatible {
        graph: GraphId::new(3),
        mismatch: GraphMismatch::Reallocated { resource: 0 },
    })
    .unwrap();
    assert_eq!(graph["mismatch"]["mismatch"], "reallocated");
}

#[test]
fn a_park_report_names_what_still_holds_memory() {
    let mut world = World::new();
    let key = world.load(P1, "a", &[4 * MIB], private());
    world
        .model
        .capture_graph(
            P1,
            GraphExecutionKey {
                model: named("a"),
                kernels: named("k"),
                shapes: named("s"),
                arguments: named("x"),
            },
            vec![GraphResource::Artifact {
                artifact: named("a"),
                offset_bytes: 0,
                length_bytes: 4 * MIB,
            }],
        )
        .unwrap();
    let report = world.park(key, clean_drop("a")).unwrap();
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["unmapped_bytes"], 4 * MIB);
    assert_eq!(json["released_bytes"], 0);
    assert_eq!(json["retained"][0]["references"]["graphs"], 1);
    let info = serde_json::to_value(world.model.batch(key, 0).unwrap()).unwrap();
    assert_eq!(info["state"], "empty");
    assert_eq!(info["generation"], 1);
    let query = world.model.granularity_query(P1, private()).unwrap();
    let json = serde_json::to_value(query).unwrap();
    assert_eq!(json["answer"]["result"], "reported");
    assert_eq!(json["answer"]["granularity"], PRIVATE_GRANULE);
    assert_eq!(json["source"], "host_probe");
}

#[test]
fn every_refusal_reads_as_a_sentence() {
    let key = MappingKey {
        process: P1,
        artifact: named("a"),
    };
    let physical = PhysicalId::new(1);
    let samples = [
        VmmError::Granularity(GranularityRefusal::DriverContradicts {
            properties: posix(),
            evidence_bytes: Some(8 * MIB),
            driver_bytes: None,
        }),
        VmmError::NotCallable {
            key,
            reason: NotCallableReason::ExporterGone { exporter: P1 },
        },
        VmmError::ProcessExited { process: P1 },
        VmmError::Granularity(GranularityRefusal::Changed {
            laid_out_bytes: 4 * MIB,
            reported_bytes: 8 * MIB,
        }),
        VmmError::BatchNotAligned {
            batch: 0,
            length_bytes: 2 * MIB,
            granularity_bytes: 4 * MIB,
        },
        VmmError::NotCallable {
            key,
            reason: NotCallableReason::StaleAllocation {
                bound: crate::foundation::ids::GpuAllocationGeneration::FIRST,
                current: None,
            },
        },
        VmmError::StillReferenced {
            physical,
            references: ReferenceCount {
                exports: 1,
                ..ReferenceCount::default()
            },
        },
        VmmError::NotDedicated { physical },
        VmmError::CrossesRuntimeBoundary {
            exporter: P1,
            importer: P3,
        },
        VmmError::GraphIncompatible {
            graph: GraphId::new(1),
            mismatch: GraphMismatch::Model,
        },
        VmmError::Driver(DriverError::Refused {
            violation: OrderViolation::InFlight { events: 2 },
        }),
    ];
    for refusal in samples {
        let text = refusal.to_string();
        assert!(text.len() > 20, "{text}");
        assert!(!text.ends_with('.'), "{text}");
    }
    assert!(VmmError::Granularity(GranularityRefusal::Evidence {
        properties: private(),
        cause: EvidenceRefusal::Missing {
            capability: Capability::CudaVmmAllocation,
        },
    })
    .to_string()
    .contains("never assumed"));
    assert!(VmmError::GraphIncompatible {
        graph: GraphId::new(1),
        mismatch: GraphMismatch::Model,
    }
    .to_string()
    .contains("matching addresses never make graphs interchangeable"));
}
