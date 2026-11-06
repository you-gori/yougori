use super::*;
use crate::model_memory::math::test_support::close;

const GB: f64 = 1e9;

fn id(name: &str) -> ResourceId {
    ResourceId::new(name).unwrap()
}

fn measured(bytes_per_second: f64) -> BandwidthRating {
    BandwidthRating::measured_directional(bytes_per_second).unwrap()
}

fn table(entries: &[(&str, f64)]) -> ResourceTable {
    let mut table = ResourceTable::new();
    for (name, bytes_per_second) in entries {
        table.add(id(name), measured(*bytes_per_second)).unwrap();
    }
    table
}

fn demand(bytes: u64, resources: &[&str]) -> TransferDemand {
    TransferDemand {
        bytes,
        resources: resources.iter().map(|name| id(name)).collect(),
    }
}

const FOURTEEN_GB: u64 = 14_000_000_000;

#[test]
fn fourteen_gb_needs_0_56_s_over_h2d_and_2_s_from_storage() {
    let table = table(&[("pcie0:h2d", 25.0 * GB), ("nvme0:read", 7.0 * GB)]);

    let h2d = transfer_lower_bound(&table, &[demand(FOURTEEN_GB, &["pcie0:h2d"])], 0.0).unwrap();
    assert!(close(h2d.lower_bound_seconds, 0.56, 1e-12));
    assert_eq!(h2d.binding, BindingTerm::Resource(id("pcie0:h2d")));

    let storage =
        transfer_lower_bound(&table, &[demand(FOURTEEN_GB, &["nvme0:read"])], 0.0).unwrap();
    assert!(close(storage.lower_bound_seconds, 2.0, 1e-12));

    // The same bytes read from storage and copied to the GPU: the slower resource binds.
    let both = transfer_lower_bound(
        &table,
        &[demand(FOURTEEN_GB, &["nvme0:read", "pcie0:h2d"])],
        0.0,
    )
    .unwrap();
    assert!(close(both.lower_bound_seconds, 2.0, 1e-12));
    assert_eq!(both.binding, BindingTerm::Resource(id("nvme0:read")));
    assert_eq!(both.loads.len(), 2);
}

#[test]
fn pipelining_cannot_move_the_same_bytes_in_40_ms() {
    let table = table(&[("pcie0:h2d", 25.0 * GB)]);
    let bound = transfer_lower_bound(&table, &[demand(FOURTEEN_GB, &["pcie0:h2d"])], 0.0).unwrap();
    assert_eq!(
        bound.check_claim(0.040),
        Err(BoundsError::BelowLowerBound {
            claimed_seconds: 0.040,
            lower_bound_seconds: bound.lower_bound_seconds,
        })
    );
    assert_eq!(bound.check_claim(0.56), Ok(()));
    assert!(bound.check_claim(f64::NAN).is_err());
}

#[test]
fn a_shared_resource_is_counted_once_with_the_bytes_of_every_transfer() {
    // Two GPUs load 14 GB each through one PCIe root.
    let table = table(&[
        ("gpu0:h2d", 25.0 * GB),
        ("gpu1:h2d", 25.0 * GB),
        ("pcie-root0", 25.0 * GB),
    ]);
    let bound = transfer_lower_bound(
        &table,
        &[
            demand(FOURTEEN_GB, &["gpu0:h2d", "pcie-root0"]),
            demand(FOURTEEN_GB, &["gpu1:h2d", "pcie-root0"]),
        ],
        0.0,
    )
    .unwrap();
    let root = bound
        .loads
        .iter()
        .find(|load| load.resource == id("pcie-root0"))
        .unwrap();
    assert_eq!(root.bytes, 2 * FOURTEEN_GB);
    assert!(close(bound.lower_bound_seconds, 1.12, 1e-12));
    assert_eq!(bound.binding, BindingTerm::Resource(id("pcie-root0")));

    // The root cannot be registered a second time to give each transfer its own copy.
    let mut again = table.clone();
    assert_eq!(
        again.add(id("pcie-root0"), measured(25.0 * GB)),
        Err(BoundsError::Input(InputError::Duplicate {
            field: "resources",
            name: "pcie-root0".into(),
        }))
    );
    assert_eq!(again.len(), 3);
}

#[test]
fn every_step_crossing_host_memory_adds_its_bytes() {
    // Disk read, verification, pinning and H2D all cross the host memory channels.
    let table = table(&[
        ("host-memory", 50.0 * GB),
        ("nvme0:read", 7.0 * GB),
        ("pcie0:h2d", 25.0 * GB),
    ]);
    let steps = [
        demand(FOURTEEN_GB, &["nvme0:read", "host-memory"]),
        demand(FOURTEEN_GB, &["host-memory"]),
        demand(FOURTEEN_GB, &["host-memory"]),
        demand(FOURTEEN_GB, &["host-memory", "pcie0:h2d"]),
    ];
    let bound = transfer_lower_bound(&table, &steps, 0.0).unwrap();
    let memory = bound
        .loads
        .iter()
        .find(|load| load.resource == id("host-memory"))
        .unwrap();
    assert_eq!(memory.bytes, 4 * FOURTEEN_GB);
    assert!(close(memory.seconds, 1.12, 1e-12));
    // Storage still binds here, but host memory alone already exceeds the H2D time.
    assert!(memory.seconds > 0.56);
    assert!(close(bound.lower_bound_seconds, 2.0, 1e-12));

    // One demand may not list a resource twice; two crossings are two demands.
    assert_eq!(
        transfer_lower_bound(
            &table,
            &[demand(FOURTEEN_GB, &["host-memory", "host-memory"])],
            0.0
        ),
        Err(BoundsError::Input(InputError::Duplicate {
            field: "TransferDemand.resources",
            name: "host-memory".into(),
        }))
    );
}

#[test]
fn aggregate_bidirectional_and_advertised_ratings_are_never_usable_bandwidth() {
    let aggregate = BandwidthRating::aggregate_bidirectional(64.0 * GB).unwrap();
    assert_eq!(
        aggregate.usable_bytes_per_second(),
        Err(UnusableBandwidth {
            basis: BandwidthBasis::AggregateBidirectional
        })
    );
    assert_eq!(aggregate.stated_bytes_per_second(), 64.0 * GB);
    let mut table = ResourceTable::new();
    assert_eq!(
        table.add(id("pcie0"), aggregate),
        Err(BoundsError::UnusableBandwidth {
            resource: id("pcie0"),
            basis: BandwidthBasis::AggregateBidirectional,
        })
    );
    assert_eq!(
        table.add(
            id("nic0:rx"),
            BandwidthRating::advertised(12.5 * GB).unwrap()
        ),
        Err(BoundsError::UnusableBandwidth {
            resource: id("nic0:rx"),
            basis: BandwidthBasis::Advertised,
        })
    );
    assert!(table.is_empty());
    assert_eq!(
        BandwidthRating::measured_directional(0.0),
        Err(InputError::NotPositive {
            field: "bytes_per_second"
        })
    );
}

#[test]
fn the_critical_path_binds_when_it_is_longer() {
    let table = table(&[("nvme0:read", 7.0 * GB)]);
    let bound = transfer_lower_bound(&table, &[demand(FOURTEEN_GB, &["nvme0:read"])], 3.0).unwrap();
    assert_eq!(bound.lower_bound_seconds, 3.0);
    assert_eq!(bound.binding, BindingTerm::CriticalPath);

    let idle = transfer_lower_bound(&table, &[], 0.25).unwrap();
    assert_eq!(idle.lower_bound_seconds, 0.25);
    assert!(idle.loads.is_empty());
}

#[test]
fn bound_inputs_are_validated() {
    let table = table(&[("nvme0:read", 7.0 * GB)]);
    assert_eq!(
        transfer_lower_bound(&table, &[], f64::NAN),
        Err(BoundsError::Input(InputError::NotFinite {
            field: "critical_path_minimum_seconds"
        }))
    );
    assert_eq!(
        transfer_lower_bound(&table, &[demand(1, &["nic0:rx"])], 0.0),
        Err(BoundsError::Input(InputError::Unknown {
            field: "TransferDemand.resources",
            name: "nic0:rx".into(),
        }))
    );
    assert_eq!(
        transfer_lower_bound(&table, &[demand(1, &[])], 0.0),
        Err(BoundsError::Input(InputError::Empty {
            field: "TransferDemand.resources"
        }))
    );
    assert_eq!(
        transfer_lower_bound(
            &table,
            &[
                demand(u64::MAX, &["nvme0:read"]),
                demand(1, &["nvme0:read"])
            ],
            0.0
        ),
        Err(BoundsError::Input(InputError::Overflow { field: "S_e" }))
    );
}

#[test]
fn amdahl_gives_19_63_for_a_1000x_load_that_is_95_percent_of_the_workflow() {
    let speedup = OverallSpeedup::amdahl(0.95, 1000.0).unwrap();
    assert!(close(speedup.ratio(), 19.63, 0.005));
    assert!(close(speedup.ratio(), 1.0 / (0.05 + 0.95 / 1000.0), 1e-12));
    assert_eq!(speedup.kind(), SpeedupKind::OverallWorkflow);
    assert_eq!(speedup.accelerated_fraction(), 0.95);
    assert_eq!(speedup.part_speedup(), 1000.0);

    // The untouched 5% caps the overall speedup below 20 however fast loading becomes.
    assert!(OverallSpeedup::amdahl(0.95, 1e15).unwrap().ratio() < 20.0);
    assert_eq!(OverallSpeedup::amdahl(0.0, 1000.0).unwrap().ratio(), 1.0);
    assert!(close(
        OverallSpeedup::amdahl(1.0, 1000.0).unwrap().ratio(),
        1000.0,
        1e-9
    ));
    assert!(OverallSpeedup::amdahl(1.5, 10.0).is_err());
    assert!(OverallSpeedup::amdahl(0.5, 0.0).is_err());
}

#[test]
fn readiness_dispatch_is_labelled_apart_from_generation_throughput() {
    // Hypothetical 40 s recreation versus 40 ms dispatch.
    let dispatch = ReadinessDispatchSpeedup::new(40.0, 0.040, 15_000_000_000, 41.0).unwrap();
    assert!(close(dispatch.ratio(), 1000.0, 1e-9));
    assert_eq!(dispatch.kind(), SpeedupKind::ReadinessDispatch);
    assert!(dispatch.kind().label().contains("readiness/dispatch"));
    assert!(dispatch
        .kind()
        .label()
        .contains("not generation throughput"));
    assert_eq!(dispatch.retained_memory_bytes(), 15_000_000_000);
    assert_eq!(dispatch.preparation_seconds(), 41.0);
    assert_eq!(dispatch.baseline_ready_seconds(), 40.0);
    assert_eq!(dispatch.dispatch_seconds(), 0.040);

    // The same engine generates no faster once ready.
    let generation = GenerationThroughputSpeedup::new(50.0, 50.0).unwrap();
    assert_eq!(generation.ratio(), 1.0);
    assert_eq!(generation.kind(), SpeedupKind::GenerationThroughput);
    assert_ne!(generation.kind().label(), dispatch.kind().label());
    assert_ne!(
        SpeedupKind::OverallWorkflow.label(),
        SpeedupKind::ReadinessDispatch.label()
    );

    assert!(ReadinessDispatchSpeedup::new(40.0, 0.0, 0, 0.0).is_err());
    assert!(ReadinessDispatchSpeedup::new(40.0, 0.04, 0, -1.0).is_err());
    assert!(GenerationThroughputSpeedup::new(0.0, 1.0).is_err());
}
