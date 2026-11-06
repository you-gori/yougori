use super::*;
use crate::model_memory::math::test_support::close;

const MIB: u64 = 1 << 20;
const GB: f64 = 1e9;

fn sid(name: &str) -> SourceId {
    SourceId::new(name).unwrap()
}

fn measured(bytes_per_second: f64) -> BandwidthRating {
    BandwidthRating::measured_directional(bytes_per_second).unwrap()
}

fn source(name: &str, bytes_per_second: f64, startup_seconds: f64, cuts: &[&str]) -> SourceSpec {
    SourceSpec {
        id: sid(name),
        authorization: SourceAuthorization::Authorized,
        startup_seconds,
        bandwidth: measured(bytes_per_second),
        cuts: cuts.iter().map(|cut| CutId::new(*cut).unwrap()).collect(),
        max_in_flight: 4,
        interference_seconds_per_byte: 0.0,
    }
}

fn cut(name: &str, bytes_per_second: f64) -> CutSpec {
    CutSpec {
        id: CutId::new(name).unwrap(),
        bandwidth: measured(bytes_per_second),
    }
}

const HYSTERESIS: StealPolicy = StealPolicy {
    min_gain_seconds: 0.0,
    min_gain_fraction: 0.05,
    max_moves_per_batch: 1,
    max_moves_per_rebalance: 16,
};

const NO_HYSTERESIS: StealPolicy = StealPolicy {
    min_gain_seconds: 0.0,
    min_gain_fraction: 0.0,
    max_moves_per_batch: u32::MAX,
    max_moves_per_rebalance: 64,
};

fn assert_cuts_respected(load: &MultiSourceLoad) {
    for usage in load.cut_usage() {
        assert!(
            usage.allocated_bytes_per_second <= usage.capacity_bytes_per_second * (1.0 + 1e-9),
            "{} exceeds its cut",
            usage.cut
        );
    }
}

#[test]
fn a_congested_peer_loses_to_local_nvme() {
    let sources = vec![
        source("lan-peer", 0.3 * GB, 0.050, &["nic0:rx"]),
        source("nvme0", 3.0 * GB, 0.002, &["host-storage"]),
    ];
    let cuts = vec![cut("nic0:rx", 1.25 * GB), cut("host-storage", 3.5 * GB)];
    let batches = vec![64 * MIB; 8];
    let load = MultiSourceLoad::plan(sources, cuts.clone(), &batches, HYSTERESIS).unwrap();
    assert!(load.batches_of(&sid("lan-peer")).is_empty());
    assert_eq!(load.batches_of(&sid("nvme0")).len(), 8);
    assert!(close(
        load.predicted_completion_seconds(),
        0.002 + (8 * 64 * MIB) as f64 / (3.0 * GB),
        1e-12
    ));

    // Selection follows completion time, not kind: an uncongested peer beats slow local
    // storage.
    let sources = vec![
        source("lan-peer", 1.2 * GB, 0.050, &["nic0:rx"]),
        source("sata0", 0.5 * GB, 0.002, &["host-storage"]),
    ];
    let load = MultiSourceLoad::plan(sources, cuts, &batches, HYSTERESIS).unwrap();
    assert!(load.batches_of(&sid("lan-peer")).len() > load.batches_of(&sid("sata0")).len());
}

#[test]
fn unauthorized_sources_are_never_used() {
    let mut fastest = source("unauthorized-peer", 5.0 * GB, 0.0, &[]);
    fastest.authorization = SourceAuthorization::Unauthorized;
    let sources = vec![fastest.clone(), source("nvme0", 1.0 * GB, 0.0, &[])];
    let mut load = MultiSourceLoad::plan(sources, vec![], &[16 * MIB; 16], NO_HYSTERESIS).unwrap();
    assert_eq!(load.excluded(), &[sid("unauthorized-peer")]);
    for batch in 0..16 {
        assert_eq!(load.owner(batch), Some(&sid("nvme0")));
    }
    assert_eq!(load.rate_bytes_per_second(&sid("unauthorized-peer")), None);
    assert_eq!(
        load.observe_rate(&sid("unauthorized-peer"), measured(10.0 * GB)),
        Err(SourcesError::SourceExcluded {
            source: sid("unauthorized-peer")
        })
    );
    load.observe_rate(&sid("nvme0"), measured(0.01 * GB))
        .unwrap();
    assert!(load.rebalance().steals.is_empty());
    assert!(load.batches_of(&sid("unauthorized-peer")).is_empty());

    assert_eq!(
        MultiSourceLoad::plan(vec![fastest], vec![], &[MIB], HYSTERESIS).map(|_| ()),
        Err(SourcesError::NoAuthorizedSource)
    );
}

#[test]
fn a_shared_cut_is_never_exceeded() {
    let sources = vec![
        source("peer-a", 1.0 * GB, 0.010, &["nic0:rx"]),
        source("peer-b", 1.0 * GB, 0.010, &["nic0:rx"]),
        source("sata0", 0.6 * GB, 0.002, &["host-storage"]),
    ];
    let cuts = vec![cut("nic0:rx", 1.25 * GB), cut("host-storage", 3.0 * GB)];
    let batches = vec![16 * MIB; 32];
    let mut load = MultiSourceLoad::plan(sources, cuts, &batches, HYSTERESIS).unwrap();
    assert_cuts_respected(&load);
    let nic = &load.cut_usage()[0];
    assert!(close(nic.allocated_bytes_per_second, 1.25 * GB, 1.0));
    assert!(close(
        load.rate_bytes_per_second(&sid("peer-a")).unwrap(),
        0.625 * GB,
        1.0
    ));
    assert!(close(
        load.rate_bytes_per_second(&sid("sata0")).unwrap(),
        0.6 * GB,
        1.0
    ));
    // The plan cannot beat the cut: at best 1.25 + 0.6 GB/s, never 1 + 1 + 0.6.
    let total = (32 * 16 * MIB) as f64;
    assert!(load.predicted_completion_seconds() >= total / (1.85 * GB));

    // The invariant holds through dispatch, rate changes and completion.
    load.observe_rate(&sid("peer-b"), measured(2.0 * GB))
        .unwrap();
    assert_cuts_respected(&load);
    while (0..32).any(|batch| load.status(batch) != Some(BatchStatus::Done)) {
        let started = load.dispatch();
        assert_cuts_respected(&load);
        for dispatch in started {
            load.complete(dispatch.batch).unwrap();
            assert_cuts_respected(&load);
        }
        load.rebalance();
        assert_cuts_respected(&load);
    }
}

#[test]
fn advertised_and_aggregate_figures_are_refused_rather_than_summed() {
    let mut advertised = source("peer-a", 1.0, 0.0, &["nic0:rx"]);
    advertised.bandwidth = BandwidthRating::advertised(10.0 * GB).unwrap();
    assert_eq!(
        MultiSourceLoad::plan(
            vec![advertised, source("nvme0", GB, 0.0, &[])],
            vec![cut("nic0:rx", 1.25 * GB)],
            &[MIB],
            HYSTERESIS
        )
        .map(|_| ()),
        Err(SourcesError::UnusableBandwidth {
            name: "peer-a".into(),
            basis: BandwidthBasis::Advertised
        })
    );
    let aggregate = CutSpec {
        id: CutId::new("nic0").unwrap(),
        bandwidth: BandwidthRating::aggregate_bidirectional(2.5 * GB).unwrap(),
    };
    assert_eq!(
        MultiSourceLoad::plan(
            vec![source("nvme0", GB, 0.0, &[])],
            vec![aggregate],
            &[MIB],
            HYSTERESIS
        )
        .map(|_| ()),
        Err(SourcesError::UnusableBandwidth {
            name: "nic0".into(),
            basis: BandwidthBasis::AggregateBidirectional
        })
    );
    let mut load = MultiSourceLoad::plan(
        vec![source("nvme0", GB, 0.0, &[])],
        vec![],
        &[MIB],
        HYSTERESIS,
    )
    .unwrap();
    assert!(matches!(
        load.observe_rate(
            &sid("nvme0"),
            BandwidthRating::advertised(7.0 * GB).unwrap()
        ),
        Err(SourcesError::UnusableBandwidth { .. })
    ));
}

#[test]
fn startup_costs_decide_whether_a_source_is_worth_using() {
    let sources = || {
        vec![
            source("remote-store", 2.0 * GB, 1.0, &[]),
            source("nvme0", 1.0 * GB, 0.0, &[]),
        ]
    };
    let small = MultiSourceLoad::plan(sources(), vec![], &[64 * MIB; 4], HYSTERESIS).unwrap();
    assert!(small.batches_of(&sid("remote-store")).is_empty());
    let large = MultiSourceLoad::plan(sources(), vec![], &[64 * MIB; 64], HYSTERESIS).unwrap();
    assert!(!large.batches_of(&sid("remote-store")).is_empty());
    assert!(large.predicted_completion_seconds() < (64 * 64 * MIB) as f64 / GB);
}

#[test]
fn concurrency_caps_bound_in_flight_batches_and_in_flight_batches_never_move() {
    let mut nvme = source("nvme0", 1.0 * GB, 0.0, &[]);
    nvme.max_in_flight = 2;
    let mut peer = source("peer", 1.0 * GB, 0.0, &[]);
    peer.max_in_flight = 1;
    let mut load =
        MultiSourceLoad::plan(vec![nvme, peer], vec![], &[16 * MIB; 12], HYSTERESIS).unwrap();
    let started = load.dispatch();
    assert_eq!(started.len(), 3);
    assert_eq!(load.in_flight(&sid("nvme0")), Some(2));
    assert_eq!(load.in_flight(&sid("peer")), Some(1));
    assert!(load.dispatch().is_empty());

    let in_flight: Vec<(usize, SourceId)> = started
        .iter()
        .map(|dispatch| (dispatch.batch, dispatch.source.clone()))
        .collect();
    load.observe_rate(&sid("nvme0"), measured(0.05 * GB))
        .unwrap();
    let rebalance = load.rebalance();
    assert!(rebalance.committed);
    for steal in &rebalance.steals {
        assert_eq!(load.status(steal.batch), Some(BatchStatus::Queued));
        assert!(in_flight.iter().all(|(batch, _)| *batch != steal.batch));
    }
    for (batch, owner) in &in_flight {
        assert_eq!(load.owner(*batch), Some(owner));
        assert_eq!(load.status(*batch), Some(BatchStatus::InFlight));
    }

    load.complete(started[0].batch).unwrap();
    assert_eq!(
        load.complete(started[0].batch),
        Err(SourcesError::BatchNotInFlight {
            batch: started[0].batch
        })
    );
    loop {
        for source in ["nvme0", "peer"] {
            let cap = if source == "nvme0" { 2 } else { 1 };
            assert!(load.in_flight(&sid(source)).unwrap() <= cap);
        }
        let started = load.dispatch();
        if started.is_empty() && (0..12).all(|b| load.status(b) != Some(BatchStatus::InFlight)) {
            break;
        }
        for batch in 0..12 {
            if load.status(batch) == Some(BatchStatus::InFlight) {
                load.complete(batch).unwrap();
            }
        }
    }
    assert!((0..12).all(|batch| load.status(batch) == Some(BatchStatus::Done)));
    assert_eq!(load.predicted_completion_seconds(), 0.0);
}

fn flapping_steals(policy: StealPolicy) -> usize {
    let sources = vec![source("x", GB, 0.0, &[]), source("y", GB, 0.0, &[])];
    let mut load = MultiSourceLoad::plan(sources, vec![], &[16 * MIB; 20], policy).unwrap();
    assert_eq!(load.batches_of(&sid("x")).len(), 10);
    let mut steals = 0;
    for round in 0..6 {
        let (x, y) = if round % 2 == 0 {
            (1.05, 0.95)
        } else {
            (0.95, 1.05)
        };
        load.observe_rate(&sid("x"), measured(x * GB)).unwrap();
        load.observe_rate(&sid("y"), measured(y * GB)).unwrap();
        steals += load.rebalance().steals.len();
    }
    steals
}

#[test]
fn hysteresis_prevents_flapping() {
    // Without hysteresis, small alternating changes move batches back and forth.
    assert!(flapping_steals(NO_HYSTERESIS) >= 6);
    assert_eq!(flapping_steals(HYSTERESIS), 0);
}

#[test]
fn a_large_change_moves_work_and_a_moved_batch_never_moves_again() {
    let sources = vec![source("x", GB, 0.0, &[]), source("y", GB, 0.0, &[])];
    let mut load = MultiSourceLoad::plan(sources, vec![], &[16 * MIB; 20], HYSTERESIS).unwrap();
    load.observe_rate(&sid("x"), measured(0.2 * GB)).unwrap();
    let first = load.rebalance();
    assert!(first.committed);
    assert!(first.objective_found_seconds < first.objective_before_seconds * 0.5);
    assert!(first.steals.len() >= 5);
    assert!(first
        .steals
        .iter()
        .all(|steal| steal.from == sid("x") && steal.to == sid("y")));

    load.observe_rate(&sid("x"), measured(1.0 * GB)).unwrap();
    load.observe_rate(&sid("y"), measured(0.1 * GB)).unwrap();
    let second = load.rebalance();
    assert!(second.committed);
    for moved in &first.steals {
        assert!(second.steals.iter().all(|steal| steal.batch != moved.batch));
        assert_eq!(load.owner(moved.batch), Some(&sid("y")));
    }
    assert!(second.steals.len() <= HYSTERESIS.max_moves_per_rebalance as usize);
}

#[test]
fn interference_cost_steers_work_away_from_a_donor() {
    let plan = |interference: f64| {
        let mut donor = source("donor", 2.0 * GB, 0.0, &[]);
        donor.interference_seconds_per_byte = interference;
        let sources = vec![donor, source("nvme0", 1.0 * GB, 0.0, &[])];
        MultiSourceLoad::plan(sources, vec![], &[64 * MIB; 8], HYSTERESIS).unwrap()
    };
    assert!(plan(0.0).batches_of(&sid("donor")).len() > 4);
    assert!(plan(1e-8).batches_of(&sid("donor")).is_empty());
}

#[test]
fn plan_inputs_are_validated() {
    let nvme = || source("nvme0", GB, 0.0, &[]);
    let plan = |sources: Vec<SourceSpec>, cuts: Vec<CutSpec>, batches: &[u64]| {
        MultiSourceLoad::plan(sources, cuts, batches, HYSTERESIS).map(|_| ())
    };
    assert!(plan(vec![nvme()], vec![], &[]).is_err());
    assert!(plan(vec![nvme()], vec![], &[0]).is_err());
    assert_eq!(
        plan(vec![nvme()], vec![], &[u64::MAX, 1]),
        Err(SourcesError::Input(InputError::Overflow {
            field: "batch bytes"
        }))
    );
    assert!(plan(vec![], vec![], &[MIB]).is_err());
    assert!(plan(vec![nvme(), nvme()], vec![], &[MIB]).is_err());
    assert!(plan(vec![nvme()], vec![cut("c", GB), cut("c", GB)], &[MIB]).is_err());
    assert_eq!(
        plan(vec![source("p", GB, 0.0, &["nic9"])], vec![], &[MIB]),
        Err(SourcesError::Input(InputError::Unknown {
            field: "SourceSpec.cuts",
            name: "nic9".into()
        }))
    );
    assert!(plan(
        vec![source("p", GB, 0.0, &["c", "c"])],
        vec![cut("c", GB)],
        &[MIB]
    )
    .is_err());
    let mut capless = nvme();
    capless.max_in_flight = 0;
    assert!(plan(vec![capless], vec![], &[MIB]).is_err());
    assert!(plan(vec![source("p", GB, -1.0, &[])], vec![], &[MIB]).is_err());
    let mut noisy = nvme();
    noisy.interference_seconds_per_byte = f64::NAN;
    assert!(plan(vec![noisy], vec![], &[MIB]).is_err());
    let bad_policy = StealPolicy {
        min_gain_seconds: -1.0,
        ..HYSTERESIS
    };
    assert!(MultiSourceLoad::plan(vec![nvme()], vec![], &[MIB], bad_policy).is_err());

    let mut load = MultiSourceLoad::plan(vec![nvme()], vec![], &[MIB], HYSTERESIS).unwrap();
    assert_eq!(
        load.complete(0),
        Err(SourcesError::BatchNotInFlight { batch: 0 })
    );
    assert!(load.complete(9).is_err());
    assert!(load.observe_rate(&sid("nobody"), measured(GB)).is_err());
    assert_eq!(load.owner(9), None);
}

fn three_sources() -> MultiSourceLoad {
    let sources = vec![
        source("a", GB, 0.0, &[]),
        source("b", 2.0 * GB, 0.0, &[]),
        source("c", GB, 0.0, &[]),
    ];
    MultiSourceLoad::plan(sources, vec![], &[16 * MIB; 24], HYSTERESIS).unwrap()
}

fn run_to_completion(load: &mut MultiSourceLoad, never: &SourceId) {
    loop {
        let started = load.dispatch();
        assert!(started.iter().all(|dispatch| &dispatch.source != never));
        if started.is_empty() {
            break;
        }
        for dispatch in started {
            load.complete_from(dispatch.batch, &dispatch.source)
                .unwrap();
        }
    }
}

#[test]
fn an_excluded_source_loses_its_work_and_never_receives_more() {
    let mut load = three_sources();
    let started = load.dispatch();
    let on_b: Vec<usize> = started
        .iter()
        .filter(|dispatch| dispatch.source == sid("b"))
        .map(|dispatch| dispatch.batch)
        .collect();
    assert!(on_b.len() >= 2);
    let held_by_b = load.batches_of(&sid("b"));
    // One batch finished before the source was blacklisted.
    load.complete_from(on_b[0], &sid("b")).unwrap();

    let exclusion = load.exclude_source(&sid("b")).unwrap();
    assert!(exclusion.newly_excluded);
    assert_eq!(exclusion.withdrawn, on_b[1..].to_vec());
    assert!(exclusion.stranded.is_empty());
    let unfinished: Vec<usize> = held_by_b
        .iter()
        .copied()
        .filter(|batch| *batch != on_b[0])
        .collect();
    assert_eq!(
        exclusion
            .reassigned
            .iter()
            .map(|placement| placement.batch)
            .collect::<Vec<_>>(),
        unfinished
    );
    assert!(exclusion
        .reassigned
        .iter()
        .all(|placement| placement.source != sid("b")));
    for batch in &on_b[1..] {
        assert_eq!(load.status(*batch), Some(BatchStatus::Queued));
        assert_eq!(
            load.complete(*batch),
            Err(SourcesError::BatchNotInFlight { batch: *batch })
        );
    }
    assert_eq!(load.status(on_b[0]), Some(BatchStatus::Done));
    assert_eq!(load.owner(on_b[0]), Some(&sid("b")));
    assert!(load.excluded().contains(&sid("b")));
    assert_eq!(load.rate_bytes_per_second(&sid("b")), None);
    assert_eq!(load.in_flight(&sid("b")), None);
    let excluded = Err(SourcesError::SourceExcluded { source: sid("b") });
    assert_eq!(load.observe_rate(&sid("b"), measured(10.0 * GB)), excluded);
    assert_eq!(load.complete_from(on_b[1], &sid("b")), excluded);
    assert_eq!(
        load.requeue_failed(on_b[1], &sid("b")).map(|_| ()),
        excluded
    );

    // Stealing never gives it work, however slow the others become.
    load.observe_rate(&sid("a"), measured(0.01 * GB)).unwrap();
    load.observe_rate(&sid("c"), measured(0.01 * GB)).unwrap();
    load.rebalance();
    assert_eq!(load.batches_of(&sid("b")), vec![on_b[0]]);
    for dispatch in started
        .iter()
        .filter(|dispatch| dispatch.source != sid("b"))
    {
        load.complete_from(dispatch.batch, &dispatch.source)
            .unwrap();
    }
    run_to_completion(&mut load, &sid("b"));
    assert!((0..24).all(|batch| load.status(batch) == Some(BatchStatus::Done)));

    assert_eq!(
        load.exclude_source(&sid("b")),
        Ok(SourceExclusion::default())
    );
    assert!(load.exclude_source(&sid("nobody")).is_err());
}

#[test]
fn excluding_the_last_usable_source_strands_the_unfinished_batches() {
    let mut peer = source("peer", GB, 0.0, &[]);
    peer.authorization = SourceAuthorization::Unauthorized;
    let mut load = MultiSourceLoad::plan(
        vec![source("nvme0", GB, 0.0, &[]), peer],
        vec![],
        &[MIB; 4],
        HYSTERESIS,
    )
    .unwrap();
    // A source that was never authorized is already excluded.
    assert_eq!(
        load.exclude_source(&sid("peer")),
        Ok(SourceExclusion::default())
    );
    assert_eq!(load.dispatch().len(), 4);
    load.complete_from(0, &sid("nvme0")).unwrap();

    let exclusion = load.exclude_source(&sid("nvme0")).unwrap();
    assert_eq!(exclusion.withdrawn, vec![1, 2, 3]);
    assert!(exclusion.reassigned.is_empty());
    assert_eq!(exclusion.stranded, vec![1, 2, 3]);
    assert_eq!(load.stranded(), vec![1, 2, 3]);
    assert_eq!(load.owner(1), None);
    assert_eq!(load.owner(0), Some(&sid("nvme0")));
    assert!(load.dispatch().is_empty());
    assert_eq!(load.predicted_completion_seconds(), f64::INFINITY);
    assert!(!load.rebalance().committed);
}

#[test]
fn a_failed_batch_is_queued_again_on_the_source_predicted_to_finish_it_earliest() {
    let sources = vec![source("x", GB, 0.0, &[]), source("y", GB, 0.0, &[])];
    let mut load = MultiSourceLoad::plan(sources, vec![], &[16 * MIB; 4], HYSTERESIS).unwrap();
    let started = load.dispatch();
    assert_eq!(started.len(), 4);
    let on_x: Vec<usize> = started
        .iter()
        .filter(|dispatch| dispatch.source == sid("x"))
        .map(|dispatch| dispatch.batch)
        .collect();
    assert_eq!(on_x.len(), 2);

    // A transient failure on a healthy source: it still finishes the batch earliest.
    assert_eq!(
        load.requeue_failed(on_x[0], &sid("x")),
        Ok(Placement {
            batch: on_x[0],
            source: sid("x")
        })
    );
    assert_eq!(load.status(on_x[0]), Some(BatchStatus::Queued));
    assert_eq!(load.failures(on_x[0]), Some(1));
    assert_eq!(load.in_flight(&sid("x")), Some(1));
    // Refused unless the batch is in flight on the named source.
    assert_eq!(
        load.requeue_failed(on_x[0], &sid("x")),
        Err(SourcesError::BatchNotInFlight { batch: on_x[0] })
    );
    assert_eq!(
        load.requeue_failed(on_x[1], &sid("y")),
        Err(SourcesError::BatchNotInFlight { batch: on_x[1] })
    );
    assert!(load.requeue_failed(99, &sid("x")).is_err());
    assert!(load.requeue_failed(on_x[1], &sid("nobody")).is_err());

    // A failure on a source that has become slow moves the batch to the faster one.
    load.observe_rate(&sid("x"), measured(0.1 * GB)).unwrap();
    assert_eq!(
        load.requeue_failed(on_x[1], &sid("x")),
        Ok(Placement {
            batch: on_x[1],
            source: sid("y")
        })
    );
    assert_eq!(load.owner(on_x[1]), Some(&sid("y")));
    assert!(load.dispatch().contains(&Dispatch {
        batch: on_x[1],
        source: sid("y")
    }));
    // A late report about the earlier attempt on x is refused.
    assert_eq!(
        load.complete_from(on_x[1], &sid("x")),
        Err(SourcesError::BatchNotInFlight { batch: on_x[1] })
    );
    load.complete_from(on_x[1], &sid("y")).unwrap();
    assert_eq!(load.failures(on_x[1]), Some(1));
    assert_eq!(load.failures(99), None);
    assert!(load.stranded().is_empty());
}

#[test]
fn shared_caps_hold_across_loads() {
    let peer = || source("peer", GB, 0.0, &[]);
    let mut first = MultiSourceLoad::plan(vec![peer()], vec![], &[MIB; 6], HYSTERESIS).unwrap();
    let mut second = MultiSourceLoad::plan(
        vec![peer(), source("nvme0", GB, 0.0, &[])],
        vec![],
        &[MIB; 6],
        HYSTERESIS,
    )
    .unwrap();
    assert_eq!(second.batches_of(&sid("peer")).len(), 3);
    let mut caps = SharedSourceCaps::new();
    caps.set_cap(sid("peer"), 3).unwrap();
    assert_eq!(caps.cap(&sid("peer")), Some(3));
    assert_eq!(caps.cap(&sid("nvme0")), None);
    let on_peer =
        |loads: &[&MultiSourceLoad]| SharedSourceCaps::in_flight_across(loads, &sid("peer"));

    // Earlier loads are served first, and an uncapped source is not held back.
    let started = caps.dispatch(&mut [&mut first, &mut second]);
    assert_eq!(started.len(), 6);
    assert_eq!(first.in_flight(&sid("peer")), Some(3));
    assert_eq!(second.in_flight(&sid("peer")), Some(0));
    assert_eq!(second.in_flight(&sid("nvme0")), Some(3));
    assert_eq!(on_peer(&[&first, &second]), 3);

    // Nothing more starts on the peer until one of its batches finishes.
    assert!(caps.dispatch(&mut [&mut first, &mut second]).is_empty());
    first.complete_from(0, &sid("peer")).unwrap();
    assert_eq!(
        caps.dispatch(&mut [&mut first, &mut second]),
        vec![(
            0,
            Dispatch {
                batch: 3,
                source: sid("peer")
            }
        )]
    );
    assert_eq!(on_peer(&[&first, &second]), 3);

    // A lower cap stops new dispatches until enough batches finish.
    caps.set_cap(sid("peer"), 2).unwrap();
    first.complete_from(1, &sid("peer")).unwrap();
    assert!(caps.dispatch(&mut [&mut first, &mut second]).is_empty());
    first.complete_from(2, &sid("peer")).unwrap();
    assert_eq!(caps.dispatch(&mut [&mut first, &mut second]).len(), 1);
    assert_eq!(on_peer(&[&first, &second]), 2);

    // Excluding the peer from one load releases that load's share at once.
    first.exclude_source(&sid("peer")).unwrap();
    let freed = caps.dispatch(&mut [&mut first, &mut second]);
    assert_eq!(freed.len(), 2);
    assert!(freed
        .iter()
        .all(|(position, dispatch)| *position == 1 && dispatch.source == sid("peer")));
    assert_eq!(on_peer(&[&first, &second]), 2);

    // Usage is counted from the loads passed in, so a dropped load holds nothing.
    drop(first);
    assert_eq!(on_peer(&[&second]), 2);
    // Plain dispatch ignores shared caps; only SharedSourceCaps::dispatch applies them.
    assert_eq!(second.dispatch().len(), 1);
    assert_eq!(on_peer(&[&second]), 3);

    assert_eq!(
        caps.set_cap(sid("peer"), 0),
        Err(SourcesError::Input(InputError::NotPositive {
            field: "max_in_flight"
        }))
    );
    assert_eq!(caps.remove_cap(&sid("peer")), Some(2));
    assert_eq!(caps.remove_cap(&sid("peer")), None);
}
