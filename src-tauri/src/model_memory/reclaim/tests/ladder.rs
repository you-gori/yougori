//! The ladder's rules on fake components and the real ledger: each step frees only what
//! its owner filed, the ladder stops once the shortfall is covered, an all-pinned host is
//! refused with every step's reason, parking never touches a leased model, a cache step
//! never drops an original or a needed canonical copy, and seeded repeated runs never
//! drive accounting negative or leave a release behind work still running.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use super::*;

#[test]
fn the_helper_registers_every_step_in_the_plans_order() {
    let mut ledger = ledger(100, 100);
    let mut fakes = Fakes::new();
    let mut steps = Steps::for_fakes(&fakes);
    let round = admit(&mut ledger, load("fits", 10), &mut steps, &mut fakes);
    assert_eq!(
        round.registered,
        vec![
            (ReclaimStep::CancelSpeculation, Requester::Transfer),
            (ReclaimStep::ReclaimUnusedScratch, Requester::ModelPlacement),
            (ReclaimStep::DropLowValueCaches, Requester::ModelPlacement),
            (ReclaimStep::ParkEligibleIdleModels, Requester::Coordination),
        ]
    );
    assert!(matches!(
        round.admission.admission,
        Ok(Admission::Granted(_))
    ));
    assert!(round.settlements.iter().all(Settlement::is_empty));
}

#[test]
fn each_step_frees_only_what_its_owner_filed() {
    let mut ledger = ledger(100, 100);
    let transfer = hold(&mut ledger, Requester::Transfer, "spec-a", vram(30), false);
    let ring = hold(
        &mut ledger,
        Requester::ModelPlacement,
        "ring-a",
        vram(40),
        false,
    );
    let model = hold(
        &mut ledger,
        Requester::Coordination,
        "model-a",
        vram(30),
        false,
    );
    let mut fakes = Fakes::new();
    // The speculation source also names the ring and ranks it first: it is not the
    // transfer's to give up.
    fakes.speculation.works = vec![
        work("foreign-ring", &[ring], Hold::Free, -1.0),
        work("spec-a", &[transfer], Hold::Free, 0.0),
    ];
    fakes.scratch.works = vec![work("ring-a", &[ring], Hold::Free, 0.0)];
    fakes.caches.works = vec![work("foreign-model", &[model], Hold::Free, 0.0)];
    fakes.parking.works = vec![work("model-a", &[model], Hold::Free, 0.0)];
    let mut steps = Steps::for_fakes(&fakes);

    let round = admit(&mut ledger, load("needs-60", 60), &mut steps, &mut fakes);

    assert!(matches!(
        round.admission.admission,
        Ok(Admission::Granted(_))
    ));
    let report = &round.admission.report;
    assert!(report.covered());
    assert_eq!(
        released(report, ReclaimStep::CancelSpeculation),
        (vec![transfer], vec![], 0),
        "the transfer step named only the transfer's reservation"
    );
    assert_eq!(
        released(report, ReclaimStep::ReclaimUnusedScratch),
        (vec![ring], vec![], 0)
    );
    assert_eq!(report.steps().len(), 2, "the request fit after scratch");
    assert_eq!(state(&ledger, model), Some(ReservationState::Granted));
    assert_eq!(names(&round.settlements[0].stopped), ["spec-a"]);
    assert_eq!(names(&round.settlements[1].stopped), ["ring-a"]);
    assert_eq!(fakes.speculation.stopped, ["spec-a"]);
    assert_eq!(fakes.scratch.stopped, ["ring-a"]);
    assert!(fakes.caches.stopped.is_empty() && fakes.parking.stopped.is_empty());
}

#[test]
fn a_step_refuses_a_source_of_another_owner_and_stops_nothing_through_it() {
    let mut ledger = ledger(100, 100);
    let transfer = hold(&mut ledger, Requester::Transfer, "spec-a", vram(100), false);
    let mut fakes = Fakes::new();
    fakes.speculation.works = vec![work("spec-a", &[transfer], Hold::Free, 0.0)];
    let mut steps = Steps::for_fakes(&fakes);
    let mut foreign = Fake::new(Requester::ModelPlacement, Vec::new());
    assert_eq!(
        steps.speculation.prepare(&mut foreign),
        Err(ReclaimError::OwnerMismatch {
            step: ReclaimStep::CancelSpeculation,
            acts_for: Requester::Transfer,
            source: Requester::ModelPlacement,
        })
    );
    let round = admit(&mut ledger, load("needs-50", 50), &mut steps, &mut fakes);
    assert!(matches!(
        round.admission.admission,
        Ok(Admission::Granted(_))
    ));
    // Settling the same report again through a foreign source is refused too.
    assert!(steps
        .speculation
        .settle(&round.admission.report, &mut foreign)
        .is_err());
    assert!(foreign.stopped.is_empty());
}

#[test]
fn the_ladder_stops_as_soon_as_the_shortfall_is_covered() {
    let mut ledger = ledger(100, 100);
    let first = hold(&mut ledger, Requester::Transfer, "spec-1", vram(20), false);
    let second = hold(&mut ledger, Requester::Transfer, "spec-2", vram(20), false);
    let third = hold(&mut ledger, Requester::Transfer, "spec-3", vram(20), false);
    let ring = hold(
        &mut ledger,
        Requester::ModelPlacement,
        "ring",
        vram(40),
        false,
    );
    let mut fakes = Fakes::new();
    fakes.speculation.works = vec![
        work("spec-3", &[third], Hold::Free, 0.3),
        work("spec-1", &[first], Hold::Free, 0.1),
        work("spec-2", &[second], Hold::Free, 0.2),
    ];
    fakes.scratch.works = vec![work("ring", &[ring], Hold::Free, 0.0)];
    fakes.parking.works = vec![work("ring-too", &[ring], Hold::Free, 0.0)];
    let mut steps = Steps::for_fakes(&fakes);

    let round = admit(&mut ledger, load("needs-30", 30), &mut steps, &mut fakes);

    assert!(matches!(
        round.admission.admission,
        Ok(Admission::Granted(_))
    ));
    let report = &round.admission.report;
    assert_eq!(report.steps().len(), 1, "no later rung was asked");
    // Least expected value first, and no more than covers the 30 missing.
    assert_eq!(
        released(report, ReclaimStep::CancelSpeculation),
        (vec![first, second], vec![], 0)
    );
    assert_eq!(state(&ledger, third), Some(ReservationState::Granted));
    assert_eq!(state(&ledger, ring), Some(ReservationState::Granted));
    assert_eq!(names(&round.settlements[0].stopped), ["spec-1", "spec-2"]);
    assert!(round.settlements[1..].iter().all(Settlement::is_empty));
    assert_eq!(
        fakes.stopped(),
        BTreeSet::from(["spec-1".to_string(), "spec-2".to_string()])
    );
}

#[test]
fn a_reservation_in_use_only_starts_releasing_and_the_ladder_goes_on() {
    let mut ledger = ledger(100, 100);
    let speculative = hold(&mut ledger, Requester::Transfer, "spec", vram(40), true);
    let ring = hold(
        &mut ledger,
        Requester::ModelPlacement,
        "ring",
        vram(40),
        false,
    );
    hold(&mut ledger, Requester::VmLifecycle, "vm", vram(20), true);
    let mut fakes = Fakes::new();
    fakes.speculation.works = vec![work("spec", &[speculative], Hold::Free, 0.0)];
    fakes.scratch.works = vec![work("ring", &[ring], Hold::Free, 0.0)];
    let mut steps = Steps::for_fakes(&fakes);

    let round = admit(&mut ledger, load("needs-30", 30), &mut steps, &mut fakes);

    assert!(matches!(
        round.admission.admission,
        Ok(Admission::Granted(_))
    ));
    let report = &round.admission.report;
    assert_eq!(
        released(report, ReclaimStep::CancelSpeculation),
        (vec![], vec![speculative], 0)
    );
    assert_eq!(
        released(report, ReclaimStep::ReclaimUnusedScratch),
        (vec![ring], vec![], 0)
    );
    // The job is stopped, and its memory counts until the host observes the release.
    assert_eq!(round.settlements[0].awaiting_release(), [speculative]);
    assert_eq!(fakes.speculation.stopped, ["spec"]);
    assert_eq!(
        state(&ledger, speculative),
        Some(ReservationState::Releasing)
    );
    assert_eq!(ledger.reserved(gpu()), 40 + 20 + 30);
    ledger
        .confirm_release(speculative, SourceClass::HostProbe)
        .unwrap();
    assert_eq!(ledger.reserved(gpu()), 20 + 30);
}

/// Work in use on three rungs: a prefetch, a staging ring and an idle model, 40, 30 and
/// 30 bytes of GPU 0, which they fill.
fn three_rungs_in_use() -> (Ledger<Arc<ManualClock>>, Fakes, [ReservationId; 3]) {
    let mut ledger = ledger(100, 100);
    let speculative = hold(&mut ledger, Requester::Transfer, "spec", vram(40), true);
    let ring = hold(
        &mut ledger,
        Requester::ModelPlacement,
        "ring",
        vram(30),
        true,
    );
    let model = hold(
        &mut ledger,
        Requester::Coordination,
        "model",
        vram(30),
        true,
    );
    let mut fakes = Fakes::new();
    fakes.speculation.works = vec![work("spec", &[speculative], Hold::Free, 0.0)];
    fakes.scratch.works = vec![work("ring", &[ring], Hold::Free, 0.0)];
    fakes.parking.works = vec![work("model", &[model], Hold::Free, 0.0)];
    (ledger, fakes, [speculative, ring, model])
}

#[test]
fn releases_under_way_keep_later_steps_from_stopping_more_work() {
    let (mut ledger, mut fakes, [speculative, ring, model]) = three_rungs_in_use();
    let mut steps = Steps::for_fakes(&fakes);

    let round = admit(&mut ledger, load("needs-30", 30), &mut steps, &mut fakes);

    // The cancelled prefetch will free 40 once observed: no later rung stops anything
    // for the same 30, and the request waits for that release.
    assert!(round.admission.admission.is_err());
    let report = &round.admission.report;
    assert_eq!(
        released(report, ReclaimStep::CancelSpeculation),
        (vec![], vec![speculative], 0)
    );
    for step in [
        ReclaimStep::ReclaimUnusedScratch,
        ReclaimStep::ParkEligibleIdleModels,
    ] {
        assert_eq!(released(report, step), (vec![], vec![], 0), "{step}");
    }
    assert_eq!(fakes.stopped(), BTreeSet::from(["spec".to_string()]));
    assert_eq!(state(&ledger, ring), Some(ReservationState::InUse));
    assert_eq!(state(&ledger, model), Some(ReservationState::InUse));

    // Once the host observes the release, the request fits without reclaiming.
    ledger
        .confirm_release(speculative, SourceClass::HostProbe)
        .unwrap();
    let round = admit(
        &mut ledger,
        load("needs-30-again", 30),
        &mut steps,
        &mut fakes,
    );
    assert!(matches!(
        round.admission.admission,
        Ok(Admission::Granted(_))
    ));
    assert!(round.settlements.iter().all(Settlement::is_empty));
}

#[test]
fn steps_registered_apart_share_no_releases_and_stop_more_work() {
    let (mut ledger, mut fakes, [speculative, ring, model]) = three_rungs_in_use();
    let mut steps = Steps::for_fakes(&fakes);
    steps.speculation.prepare(&mut fakes.speculation).unwrap();
    steps.scratch.prepare(&mut fakes.scratch).unwrap();
    steps.parking.prepare(&mut fakes.parking).unwrap();
    let admission = {
        let mut ladder = ReclaimLadder::new();
        ladder
            .register(
                ReclaimStep::CancelSpeculation,
                Requester::Transfer,
                &mut steps.speculation,
            )
            .register(
                ReclaimStep::ReclaimUnusedScratch,
                Requester::ModelPlacement,
                &mut steps.scratch,
            )
            .register(
                ReclaimStep::ParkEligibleIdleModels,
                Requester::Coordination,
                &mut steps.parking,
            );
        ledger.reserve_reclaiming(load("needs-30", 30), &mut ladder)
    };
    let report = &admission.report;
    assert_eq!(
        released(report, ReclaimStep::CancelSpeculation),
        (vec![], vec![speculative], 0)
    );
    assert_eq!(
        released(report, ReclaimStep::ReclaimUnusedScratch),
        (vec![], vec![ring], 0)
    );
    assert_eq!(
        released(report, ReclaimStep::ParkEligibleIdleModels),
        (vec![], vec![model], 0)
    );
}

/// Every rung holds memory, and all of it is pinned or leased.
fn all_pinned() -> (Ledger<Arc<ManualClock>>, Fakes) {
    let mut ledger = ledger(100, 100);
    let mut reserve =
        |requester, name: &str, bytes| hold(&mut ledger, requester, name, vram(bytes), true);
    let shared = reserve(Requester::Transfer, "shared-prefetch", 20);
    let ring = reserve(Requester::ModelPlacement, "busy-ring", 20);
    let original = reserve(Requester::ModelPlacement, "original", 20);
    let canonical = reserve(Requester::ModelPlacement, "canonical", 10);
    let leased = reserve(Requester::Coordination, "leased-model", 20);
    let unrebuildable = reserve(Requester::Coordination, "unrebuildable-model", 10);
    let mut fakes = Fakes::new();
    fakes.speculation.works = vec![work(
        "shared-prefetch",
        &[shared],
        Hold::Leased(LeasedBy::OtherWork { holders: 1 }),
        0.0,
    )];
    fakes.scratch.works = vec![work(
        "busy-ring",
        &[ring],
        Hold::Leased(LeasedBy::InFlight),
        0.0,
    )];
    fakes.caches.works = vec![
        work(
            "original",
            &[original],
            Hold::Pinned(PinnedBy::Original),
            0.0,
        ),
        work(
            "canonical",
            &[canonical],
            Hold::Pinned(PinnedBy::CanonicalCopyNeeded),
            0.0,
        ),
    ];
    fakes.parking.works = vec![
        work(
            "leased-model",
            &[leased],
            Hold::Leased(LeasedBy::Requests { leases: 2 }),
            0.0,
        ),
        work(
            "unrebuildable-model",
            &[unrebuildable],
            Hold::Pinned(PinnedBy::NoCanonicalState),
            0.0,
        ),
    ];
    (ledger, fakes)
}

#[test]
fn an_all_pinned_host_is_refused_with_every_steps_reason() {
    let (mut ledger, mut fakes) = all_pinned();
    let before: Vec<_> = ledger.open_reservations().cloned().collect();
    let mut steps = Steps::for_fakes(&fakes);

    let round = admit(&mut ledger, load("needs-30", 30), &mut steps, &mut fakes);

    let Err(LedgerError::Capacity(error)) = &round.admission.admission else {
        panic!("refused: {:?}", round.admission.admission);
    };
    let report = error.reclaim().expect("the ladder ran");
    assert!(!report.covered());
    let reasons: Vec<(ReclaimStep, StepOutcome)> = report
        .steps()
        .iter()
        .map(|step| (step.step, step.outcome.clone()))
        .collect();
    assert_eq!(
        reasons,
        vec![
            (
                ReclaimStep::CancelSpeculation,
                StepOutcome::Declined(DeclineReason::Held {
                    pinned: 0,
                    leased: 1
                })
            ),
            (
                ReclaimStep::ReclaimUnusedScratch,
                StepOutcome::Declined(DeclineReason::Held {
                    pinned: 0,
                    leased: 1
                })
            ),
            (
                ReclaimStep::DropLowValueCaches,
                StepOutcome::Declined(DeclineReason::Held {
                    pinned: 2,
                    leased: 0
                })
            ),
            (
                ReclaimStep::ParkEligibleIdleModels,
                StepOutcome::Declined(DeclineReason::Held {
                    pinned: 1,
                    leased: 1
                })
            ),
        ]
    );
    let message = error.to_string();
    assert!(
        message.contains("reclamation freed nothing")
            && message.contains("park eligible idle models declined, 1 pinned and 1 leased"),
        "{message}"
    );
    assert!(round.settlements.iter().all(Settlement::is_empty));
    assert!(fakes.stopped().is_empty());
    let after: Vec<_> = ledger.open_reservations().cloned().collect();
    assert_eq!(before, after, "nothing was touched");
}

#[test]
fn an_all_pinned_host_queues_a_request_that_may_wait_with_the_same_reasons() {
    let (mut ledger, mut fakes) = all_pinned();
    let mut steps = Steps::for_fakes(&fakes);
    let request = load("waits", 30).wait_up_to(Duration::from_secs(30));

    let round = admit(&mut ledger, request, &mut steps, &mut fakes);

    let Ok(Admission::Queued { waiting_for, .. }) = &round.admission.admission else {
        panic!("queued: {:?}", round.admission.admission);
    };
    let report = waiting_for.reclaim().expect("the ladder ran");
    assert_eq!(report.steps().len(), 4);
    assert!(report.steps().iter().all(|step| matches!(
        step.outcome,
        StepOutcome::Declined(DeclineReason::Held { .. })
    )));
    assert!(fakes.stopped().is_empty());
}

#[test]
fn parking_never_touches_a_leased_model() {
    let mut ledger = ledger(100, 100);
    let leased = hold(
        &mut ledger,
        Requester::Coordination,
        "leased",
        vram(50),
        true,
    );
    let idle = hold(&mut ledger, Requester::Coordination, "idle", vram(20), true);
    let unrebuildable = hold(
        &mut ledger,
        Requester::Coordination,
        "dirty",
        vram(30),
        true,
    );
    let mut fakes = Fakes::new();
    // The leased model is the cheapest and alone would cover the shortfall.
    fakes.parking.works = vec![
        work(
            "leased",
            &[leased],
            Hold::Leased(LeasedBy::Requests { leases: 1 }),
            -1.0,
        ),
        work("idle", &[idle], Hold::Free, 0.0),
        work(
            "dirty",
            &[unrebuildable],
            Hold::Pinned(PinnedBy::NoCanonicalState),
            0.0,
        ),
    ];
    let mut steps = Steps::for_fakes(&fakes);

    let round = admit(&mut ledger, load("needs-40", 40), &mut steps, &mut fakes);

    assert!(round.admission.admission.is_err(), "only 20 could go");
    let report = &round.admission.report;
    assert_eq!(
        released(report, ReclaimStep::ParkEligibleIdleModels),
        (vec![], vec![idle], 0)
    );
    assert_eq!(fakes.parking.stopped, ["idle"]);
    assert_eq!(state(&ledger, leased), Some(ReservationState::InUse));
    assert_eq!(state(&ledger, unrebuildable), Some(ReservationState::InUse));
    // Asked again, the leased model is still never given up, and the idle one, now
    // releasing, is not given up twice.
    let round = admit(
        &mut ledger,
        load("needs-40-again", 40),
        &mut steps,
        &mut fakes,
    );
    assert!(round.admission.admission.is_err());
    assert_eq!(
        round
            .admission
            .report
            .steps()
            .iter()
            .find(|step| step.step == ReclaimStep::ParkEligibleIdleModels)
            .map(|step| step.outcome.clone()),
        Some(StepOutcome::Declined(DeclineReason::Held {
            pinned: 1,
            leased: 1
        }))
    );
    assert_eq!(state(&ledger, leased), Some(ReservationState::InUse));
    assert_eq!(fakes.parking.stopped, ["idle"]);
}

#[test]
fn a_cache_step_never_drops_an_original_or_a_needed_canonical_copy() {
    let mut ledger = ledger(100, 100);
    let original = hold(
        &mut ledger,
        Requester::ModelPlacement,
        "original",
        vram(30),
        true,
    );
    let canonical = hold(
        &mut ledger,
        Requester::ModelPlacement,
        "canonical",
        vram(30),
        true,
    );
    let host_copy = hold(
        &mut ledger,
        Requester::ModelPlacement,
        "host-copy",
        vram(20),
        true,
    );
    let prepared = hold(
        &mut ledger,
        Requester::ModelPlacement,
        "prepared",
        vram(20),
        true,
    );
    let mut fakes = Fakes::new();
    // The original and the canonical copy rank lowest: value never overrides them.
    fakes.caches.works = vec![
        work(
            "original",
            &[original],
            Hold::Pinned(PinnedBy::Original),
            -9.0,
        ),
        work(
            "canonical",
            &[canonical],
            Hold::Pinned(PinnedBy::CanonicalCopyNeeded),
            -8.0,
        ),
        work("prepared", &[prepared], Hold::Free, 0.5),
        work("host-copy", &[host_copy], Hold::Free, 0.25),
    ];
    let mut steps = Steps::for_fakes(&fakes);

    let round = admit(&mut ledger, load("needs-50", 50), &mut steps, &mut fakes);

    assert!(round.admission.admission.is_err(), "only 40 could go");
    assert_eq!(
        released(&round.admission.report, ReclaimStep::DropLowValueCaches),
        (vec![], vec![host_copy, prepared], 0),
        "least value per byte first"
    );
    assert_eq!(
        names(&round.settlements[2].stopped),
        ["host-copy", "prepared"]
    );
    assert_eq!(state(&ledger, original), Some(ReservationState::InUse));
    assert_eq!(state(&ledger, canonical), Some(ReservationState::InUse));
}

#[test]
fn work_that_cannot_stop_is_reported_and_its_release_is_not_awaited() {
    let mut ledger = ledger(100, 100);
    let stuck = hold(
        &mut ledger,
        Requester::ModelPlacement,
        "stuck",
        vram(50),
        true,
    );
    let fine = hold(
        &mut ledger,
        Requester::ModelPlacement,
        "fine",
        vram(50),
        true,
    );
    let mut fakes = Fakes::new();
    fakes.scratch.works = vec![
        work("stuck", &[stuck], Hold::Free, 0.0),
        work("fine", &[fine], Hold::Free, 1.0),
    ];
    fakes.scratch.refuse.insert("stuck".to_string());
    let mut steps = Steps::for_fakes(&fakes);

    let round = admit(&mut ledger, load("needs-60", 60), &mut steps, &mut fakes);

    let scratch = &round.settlements[1];
    assert_eq!(names(&scratch.stopped), ["fine"]);
    assert_eq!(scratch.not_stopped.len(), 1);
    assert_eq!(scratch.not_stopped[0].work, "stuck");
    assert_eq!(scratch.not_stopped[0].releasing, [stuck]);
    assert_eq!(scratch.awaiting_release(), [fine]);
    // Never confirmed, the stuck work's memory stays counted.
    assert_eq!(state(&ledger, stuck), Some(ReservationState::Releasing));
    assert_eq!(ledger.reserved(gpu()), 100);
}

#[test]
fn a_step_whose_work_is_off_the_limiting_resources_says_so() {
    let mut ledger = ledger(100, 100);
    let ram = hold(
        &mut ledger,
        Requester::Transfer,
        "ram-prefetch",
        Amounts::new().with(RAM, 100),
        true,
    );
    hold(&mut ledger, Requester::VmLifecycle, "vm", vram(100), true);
    let mut fakes = Fakes::new();
    fakes.speculation.works = vec![work("ram-prefetch", &[ram], Hold::Free, 0.0)];
    let mut steps = Steps::for_fakes(&fakes);

    let round = admit(&mut ledger, load("needs-10", 10), &mut steps, &mut fakes);

    let outcomes: Vec<StepOutcome> = round
        .admission
        .report
        .steps()
        .iter()
        .map(|step| step.outcome.clone())
        .collect();
    assert_eq!(
        outcomes,
        vec![
            StepOutcome::Declined(DeclineReason::NotOnLimitingResources),
            StepOutcome::Declined(DeclineReason::NothingToReclaim),
            StepOutcome::Declined(DeclineReason::NothingToReclaim),
            StepOutcome::Declined(DeclineReason::NothingToReclaim),
        ]
    );
    assert_eq!(state(&ledger, ram), Some(ReservationState::InUse));
}

/// SplitMix64: a small deterministic generator, seeded explicitly.
struct SeededRng(u64);

impl SeededRng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }
}

const CAPACITY: u64 = 1_000;

/// No resource is granted beyond capacity, and every open record's amounts are within
/// what the ledger reports reserved.
fn assert_accounting<C: Clock>(ledger: &Ledger<C>) {
    for resource in [gpu(), RAM] {
        let reserved = ledger.reserved(resource);
        let held = ledger
            .open_reservations()
            .filter(|record| record.parent().is_none())
            .try_fold(0u64, |total, record| {
                total.checked_add(record.current().get(resource))
            })
            .expect("held amounts never overflow");
        assert_eq!(reserved, held, "{resource} is counted once per reservation");
        let available = ledger.available(resource).unwrap();
        assert_eq!(
            available.checked_add(reserved),
            Some(CAPACITY),
            "{resource}: free and reserved make up capacity"
        );
    }
}

/// Which fake the round's new work goes to.
fn owner_of(index: u64) -> Requester {
    match index {
        0 => Requester::Transfer,
        1 | 2 => Requester::ModelPlacement,
        _ => Requester::Coordination,
    }
}

/// How often each path was taken over every seeded run.
#[derive(Debug, Default)]
struct Coverage {
    returned: usize,
    releasing: usize,
    held: usize,
    stopped: usize,
    not_stopped: usize,
    kept: usize,
    queue_grants: usize,
}

#[test]
fn accounting_never_goes_negative_over_seeded_repeated_runs() {
    let mut coverage = Coverage::default();
    for seed in 1..=12u64 {
        let mut rng = SeededRng(seed);
        let clock = start();
        let mut ledger = ledger_on(Arc::clone(&clock), CAPACITY, CAPACITY);
        let mut fakes = Fakes::new();
        let mut steps = Steps::for_fakes(&fakes);
        // Work stopped but whose memory the host has not yet seen freed.
        let mut freeing: Vec<ReservationId> = Vec::new();
        // Reservations of granted requests, released later.
        let mut granted: Vec<ReservationId> = Vec::new();
        let mut stuck: BTreeSet<String> = BTreeSet::new();
        let mut next = 0u64;
        for round in 0..250u64 {
            // New work for one of the fakes, when it fits.
            for _ in 0..rng.below(3) {
                next += 1;
                let index = rng.below(4);
                let owner = owner_of(index);
                let name = format!("w{next}");
                let resource = if rng.below(4) == 0 { RAM } else { gpu() };
                let amounts = Amounts::new().with(resource, 10 + rng.below(90));
                let request = ReservationRequest::new(
                    provenance(owner, &name),
                    Priority::Foreground,
                    amounts,
                );
                let Ok(Admission::Granted(reservation)) = ledger.reserve(request) else {
                    continue;
                };
                if rng.below(3) > 0 {
                    ledger.begin_create(reservation).unwrap();
                }
                let held = match rng.below(10) {
                    0 | 1 => Hold::Pinned(PinnedBy::Policy),
                    2 | 3 => Hold::Leased(LeasedBy::InFlight),
                    _ => Hold::Free,
                };
                let fake = match index {
                    0 => &mut fakes.speculation,
                    1 => &mut fakes.scratch,
                    2 => &mut fakes.caches,
                    _ => &mut fakes.parking,
                };
                if rng.below(20) == 0 {
                    fake.refuse.insert(name.clone());
                }
                let rank = rng.below(1_000) as f64 / 100.0;
                fake.works.push(work(&name, &[reservation], held, rank));
            }
            // Sometimes time passes: unused grants lapse under the fakes.
            if rng.below(8) == 0 {
                clock.advance(Duration::from_secs(rng.below(90)));
            }
            let held_before: BTreeMap<String, Vec<ReservationId>> = [
                &fakes.speculation,
                &fakes.scratch,
                &fakes.caches,
                &fakes.parking,
            ]
            .into_iter()
            .flat_map(|fake| fake.works.iter())
            .filter(|work| !work.hold.is_free())
            .map(|work| (work.name.clone(), work.reservations.clone()))
            .collect();
            let held_states: BTreeMap<ReservationId, Option<ReservationState>> = held_before
                .values()
                .flatten()
                .map(|reservation| (*reservation, state(&ledger, *reservation)))
                .collect();

            let bytes = 10 + rng.below(400);
            let mut request = load(&format!("load-{seed}-{round}"), bytes);
            if rng.below(3) == 0 {
                request.priority = Priority::Background;
            }
            if rng.below(3) == 0 {
                request = request.wait_up_to(Duration::from_secs(30));
            }
            let outcome = admit(&mut ledger, request, &mut steps, &mut fakes);
            if let Ok(Admission::Granted(reservation)) = outcome.admission.admission {
                granted.push(reservation);
            }
            for event in ledger.drain_events() {
                if let LedgerEvent::QueueGranted { reservation, .. } = event {
                    coverage.queue_grants += 1;
                    granted.push(reservation);
                }
            }
            for step in outcome.admission.report.steps() {
                match &step.outcome {
                    StepOutcome::Released {
                        returned,
                        releasing,
                        ..
                    } => {
                        coverage.returned += returned.len();
                        coverage.releasing += releasing.len();
                    }
                    StepOutcome::Declined(DeclineReason::Held { .. }) => coverage.held += 1,
                    StepOutcome::Declined(_) | StepOutcome::NotRegistered => {}
                }
            }
            for settlement in &outcome.settlements {
                coverage.stopped += settlement.stopped.len();
                coverage.not_stopped += settlement.not_stopped.len();
                coverage.kept += settlement.kept.len();
            }

            // Pinned or leased work was never given up or stopped.
            let stopped = fakes.stopped();
            for (name, reservations) in &held_before {
                assert!(!stopped.contains(name), "seed {seed}: {name} was held");
                for reservation in reservations {
                    // An unused grant may lapse, but nothing held starts releasing.
                    let now = state(&ledger, *reservation);
                    assert!(
                        now != Some(ReservationState::Releasing) || held_states[reservation] == now,
                        "seed {seed}: held {reservation} was given up"
                    );
                }
            }
            for settlement in &outcome.settlements {
                freeing.extend(settlement.awaiting_release());
                for unstopped in &settlement.not_stopped {
                    stuck.insert(unstopped.work.clone());
                }
            }
            // Every releasing reservation belongs to work that was stopped or reported
            // as not stopped: nothing releases behind running work.
            let given_up: BTreeSet<ReservationId> = [
                &fakes.speculation,
                &fakes.scratch,
                &fakes.caches,
                &fakes.parking,
            ]
            .into_iter()
            .flat_map(|fake| fake.works.iter())
            .filter(|work| stopped.contains(&work.name) || stuck.contains(&work.name))
            .flat_map(|work| work.reservations.iter().copied())
            .collect();
            for record in ledger.open_reservations() {
                if record.state() == ReservationState::Releasing {
                    assert!(
                        given_up.contains(&record.id()),
                        "seed {seed}: {} releases behind running work",
                        record.id()
                    );
                }
            }
            assert_accounting(&ledger);

            // The host observes some stopped work's memory freed, and some granted
            // requests finish.
            if rng.below(2) == 0 {
                for reservation in freeing.drain(..) {
                    ledger
                        .confirm_release(reservation, SourceClass::HostProbe)
                        .unwrap();
                }
            }
            while !granted.is_empty() && rng.below(3) > 0 {
                let index = usize::try_from(rng.below(granted.len() as u64)).unwrap();
                let reservation = granted.swap_remove(index);
                if state(&ledger, reservation) == Some(ReservationState::Granted) {
                    ledger.begin_create(reservation).unwrap();
                }
                ledger.cancel(reservation).unwrap();
                ledger
                    .confirm_release(reservation, SourceClass::HostProbe)
                    .unwrap();
            }
            assert_accounting(&ledger);
        }
    }
    // The runs reached every path: returns at once, releases, declines for held work,
    // stops, refused stops and queue grants.
    assert!(
        coverage.returned > 0
            && coverage.releasing > 0
            && coverage.held > 0
            && coverage.stopped > 0
            && coverage.not_stopped > 0
            && coverage.queue_grants > 0,
        "{coverage:?}"
    );
}
