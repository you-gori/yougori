//! The reclamation ladder (GPU-W05): steps run in their fixed order and stop once the
//! request fits; declined steps and started releases are reported, and a release counts
//! only once observed; an all-pinned host queues or refuses with a useful reason; the
//! ledger acts only on reservations a step may give up; the ladder runs once per
//! admission and never for the queue; and seeded cancel/grant interleavings never drive
//! any amount negative.

use std::cell::RefCell;
use std::rc::Rc;

use super::*;

type CallLog = Rc<RefCell<Vec<ReclaimStep>>>;

/// A fake owner: answers every call with its script and keeps what it was told: the
/// shortfalls, how much GPU 0 memory was missing, and which of the reservations it gives up
/// the ledger would act on.
struct Owner {
    answer: ReclaimResponse,
    log: CallLog,
    told: Vec<Vec<Shortfall>>,
    missing: Vec<u64>,
    would_help: Vec<Vec<ReservationId>>,
}

impl Owner {
    fn answering(answer: ReclaimResponse, log: &CallLog) -> Self {
        Self {
            answer,
            log: Rc::clone(log),
            told: Vec::new(),
            missing: Vec::new(),
            would_help: Vec::new(),
        }
    }

    fn giving_up(reservations: &[ReservationId], log: &CallLog) -> Self {
        Self::answering(ReclaimResponse::Release(reservations.to_vec()), log)
    }

    fn declining(reason: DeclineReason, log: &CallLog) -> Self {
        Self::answering(ReclaimResponse::Decline(reason), log)
    }

    fn calls(&self) -> usize {
        self.told.len()
    }
}

impl Reclaimer for Owner {
    fn reclaim(&mut self, need: &ReclaimNeed<'_>) -> ReclaimResponse {
        self.log.borrow_mut().push(need.step());
        self.told.push(need.shortfalls().to_vec());
        self.missing.push(need.missing(vram(0)));
        let helpful = match &self.answer {
            ReclaimResponse::Release(reservations) => reservations
                .iter()
                .copied()
                .filter(|reservation| need.would_help(*reservation))
                .collect(),
            ReclaimResponse::Decline(_) => Vec::new(),
        };
        self.would_help.push(helpful);
        self.answer.clone()
    }
}

fn log() -> CallLog {
    Rc::new(RefCell::new(Vec::new()))
}

fn on_gpu0(
    requester: Requester,
    execution: &str,
    priority: Priority,
    bytes: u64,
) -> ReservationRequest {
    ReservationRequest::new(
        provenance(requester, execution, "alpha"),
        priority,
        Amounts::new().vram_bytes(gpu(0), bytes),
    )
}

/// A foreground model load of tenant beta on GPU 0.
fn demand(bytes: u64) -> ReservationRequest {
    ReservationRequest::new(
        provenance(Requester::ModelPlacement, "exe-demand", "beta"),
        Priority::Foreground,
        Amounts::new().vram_bytes(gpu(0), bytes),
    )
}

/// What holds GPU 0 in [`loaded_gpu`].
struct Held {
    /// Speculative prefetches of 2 GB and 1 GB, filed by transfers and not started.
    speculation: [ReservationId; 2],
    /// 2 GB of staging scratch reserved and not in use.
    scratch: ReservationId,
    /// A 4 GB cache in use.
    cache: ReservationId,
    /// A 12 GB idle model in use.
    idle: ReservationId,
}

/// GPU 0 (23 GB grantable) holding [`Held`] for tenant alpha: 21 GB, leaving 2 GB.
fn loaded_gpu(ledger: &mut Ledger<&ManualClock>) -> Held {
    let mut reserve = |requester, execution: &str, priority, bytes| {
        granted(ledger.reserve(on_gpu0(requester, execution, priority, bytes)))
    };
    let speculation = [
        reserve(
            Requester::Transfer,
            "exe-prefetch",
            Priority::Background,
            2 * GB,
        ),
        reserve(
            Requester::Transfer,
            "exe-prefetch",
            Priority::Background,
            GB,
        ),
    ];
    let scratch = reserve(
        Requester::ModelPlacement,
        "exe-staging",
        Priority::Foreground,
        2 * GB,
    );
    let cache = reserve(
        Requester::ModelPlacement,
        "exe-cache",
        Priority::Foreground,
        4 * GB,
    );
    let idle = reserve(
        Requester::ModelPlacement,
        "exe-idle",
        Priority::Foreground,
        12 * GB,
    );
    ledger.begin_create(cache).unwrap();
    ledger.begin_create(idle).unwrap();
    assert_eq!(ledger.available(vram(0)), Some(2 * GB));
    Held {
        speculation,
        scratch,
        cache,
        idle,
    }
}

fn outcomes(report: &LadderReport) -> Vec<(ReclaimStep, StepOutcome)> {
    report
        .steps()
        .iter()
        .map(|step| (step.step, step.outcome.clone()))
        .collect()
}

#[test]
fn the_ladder_runs_in_its_fixed_order_and_stops_once_the_request_fits() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let held = loaded_gpu(&mut ledger);
    let calls = log();
    let mut park = Owner::giving_up(&[held.idle], &calls);
    let mut caches = Owner::giving_up(&[held.cache], &calls);
    let mut scratch = Owner::giving_up(&[held.scratch], &calls);
    let mut speculation = Owner::giving_up(&held.speculation, &calls);
    let outcome = {
        let mut ladder = ReclaimLadder::new();
        // Registered out of order; they run in the ladder's order.
        ladder
            .register(
                ReclaimStep::ParkEligibleIdleModels,
                Requester::ModelPlacement,
                &mut park,
            )
            .register(
                ReclaimStep::DropLowValueCaches,
                Requester::ModelPlacement,
                &mut caches,
            )
            .register(
                ReclaimStep::ReclaimUnusedScratch,
                Requester::ModelPlacement,
                &mut scratch,
            )
            .register(
                ReclaimStep::CancelSpeculation,
                Requester::Transfer,
                &mut speculation,
            );
        assert_eq!(
            ladder.registered(),
            [
                (ReclaimStep::CancelSpeculation, Requester::Transfer),
                (ReclaimStep::ReclaimUnusedScratch, Requester::ModelPlacement),
                (ReclaimStep::DropLowValueCaches, Requester::ModelPlacement),
                (
                    ReclaimStep::ParkEligibleIdleModels,
                    Requester::ModelPlacement
                ),
            ]
        );
        // 6 GB wanted with 2 GB free: 4 GB short.
        ledger.reserve_reclaiming(demand(6 * GB), &mut ladder)
    };
    let reservation = granted(outcome.admission);
    let report = outcome.report;

    // Speculation returned 3 GB, still 1 GB short; scratch returned 2 GB and it fit, so
    // the caches and the idle model were never asked.
    assert_eq!(
        *calls.borrow(),
        [
            ReclaimStep::CancelSpeculation,
            ReclaimStep::ReclaimUnusedScratch
        ]
    );
    assert_eq!((caches.calls(), park.calls()), (0, 0));
    assert!(report.covered());
    assert_eq!(report.skipped_because(), None);
    assert_eq!(report.returned(), Amounts::new().vram_bytes(gpu(0), 5 * GB));
    assert!(report.releasing().is_empty());
    let [first, second] = report.steps() else {
        panic!("expected two steps, got {:?}", report.steps());
    };
    assert_eq!(
        (first.step, first.owner),
        (ReclaimStep::CancelSpeculation, Some(Requester::Transfer))
    );
    assert_eq!(
        first.outcome,
        StepOutcome::Released {
            returned: vec![
                ReturnedReservation {
                    reservation: held.speculation[0],
                    amounts: Amounts::new().vram_bytes(gpu(0), 2 * GB),
                },
                ReturnedReservation {
                    reservation: held.speculation[1],
                    amounts: Amounts::new().vram_bytes(gpu(0), GB),
                },
            ],
            releasing: vec![],
            refused: vec![],
        }
    );
    assert_eq!(second.step, ReclaimStep::ReclaimUnusedScratch);
    assert!(!second.outcome.freed_nothing());

    // Each step was told what was still missing, by the ledger's own accounting.
    let told = |owner: &Owner| {
        let [shortfall] = owner.told[0].as_slice() else {
            panic!("expected one shortfall, got {:?}", owner.told);
        };
        (
            shortfall.limit.clone(),
            shortfall.requested,
            shortfall.available,
        )
    };
    assert_eq!(
        told(&speculation),
        (Limit::PhysicalCapacity, 6 * GB, 2 * GB)
    );
    assert_eq!(told(&scratch), (Limit::PhysicalCapacity, 6 * GB, 5 * GB));
    assert_eq!((speculation.missing[0], scratch.missing[0]), (4 * GB, GB));
    assert_eq!(speculation.would_help[0], held.speculation);

    // The cache and the idle model keep running; nothing is counted twice.
    assert_eq!(
        ledger.reservation(held.cache).unwrap().state(),
        ReservationState::InUse
    );
    assert_eq!(ledger.reserved(vram(0)), 4 * GB + 12 * GB + 6 * GB);
    assert_eq!(ledger.available(vram(0)), Some(GB));
    assert_eq!(
        ledger.reservation(reservation).unwrap().provenance().tenant,
        tenant("beta")
    );
    for given_up in [held.speculation[0], held.speculation[1], held.scratch] {
        let record = ledger
            .closed_records()
            .iter()
            .find(|record| record.id() == given_up)
            .unwrap();
        assert_eq!(
            record.close_reason(),
            Some(CloseReason::CancelledBeforeCreate)
        );
    }
    assert_invariants(&ledger);
}

#[test]
fn a_step_gives_up_only_until_the_request_fits() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let held = loaded_gpu(&mut ledger);
    let calls = log();
    let mut speculation = Owner::giving_up(&held.speculation, &calls);
    let outcome = {
        let mut ladder = ReclaimLadder::new();
        ladder.register(
            ReclaimStep::CancelSpeculation,
            Requester::Transfer,
            &mut speculation,
        );
        // 4 GB wanted with 2 GB free: the first prefetch is enough.
        ledger.reserve_reclaiming(demand(4 * GB), &mut ladder)
    };
    granted(outcome.admission);
    assert_eq!(
        outcomes(&outcome.report),
        [(
            ReclaimStep::CancelSpeculation,
            StepOutcome::Released {
                returned: vec![ReturnedReservation {
                    reservation: held.speculation[0],
                    amounts: Amounts::new().vram_bytes(gpu(0), 2 * GB),
                }],
                releasing: vec![],
                refused: vec![RefusedNomination {
                    reservation: held.speculation[1],
                    reason: NominationRefusal::NotNeeded,
                }],
            }
        )]
    );
    // The second prefetch was left alone.
    assert_eq!(
        ledger.reservation(held.speculation[1]).unwrap().state(),
        ReservationState::Granted
    );
    assert_eq!(ledger.available(vram(0)), Some(0));
}

#[test]
fn declined_steps_are_reported_and_a_started_release_counts_only_once_observed() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let held = loaded_gpu(&mut ledger);
    let calls = log();
    let mut speculation = Owner::declining(DeclineReason::NothingToReclaim, &calls);
    let mut caches = Owner::declining(
        DeclineReason::Held {
            pinned: 1,
            leased: 0,
        },
        &calls,
    );
    let mut park = Owner::giving_up(&[held.idle], &calls);
    let mut ladder = ReclaimLadder::new();
    ladder
        .register(
            ReclaimStep::CancelSpeculation,
            Requester::Transfer,
            &mut speculation,
        )
        .register(
            ReclaimStep::DropLowValueCaches,
            Requester::ModelPlacement,
            &mut caches,
        )
        .register(
            ReclaimStep::ParkEligibleIdleModels,
            Requester::ModelPlacement,
            &mut park,
        );

    // Asked not to wait, it is refused, and the refusal lists every step tried.
    let outcome = ledger.reserve_reclaiming(demand(6 * GB), &mut ladder);
    let error = refused(outcome.admission);
    let report = outcome.report;
    assert_eq!(error.reclaim(), Some(&report));
    assert_eq!(error.queue_refusal(), Some(QueueRefusal::NotRequested));
    assert!(!report.covered());
    assert_eq!(
        outcomes(&report),
        [
            (
                ReclaimStep::CancelSpeculation,
                StepOutcome::Declined(DeclineReason::NothingToReclaim)
            ),
            (
                ReclaimStep::ReclaimUnusedScratch,
                StepOutcome::NotRegistered
            ),
            (
                ReclaimStep::DropLowValueCaches,
                StepOutcome::Declined(DeclineReason::Held {
                    pinned: 1,
                    leased: 0
                })
            ),
            (
                ReclaimStep::ParkEligibleIdleModels,
                StepOutcome::Released {
                    returned: vec![],
                    releasing: vec![held.idle],
                    refused: vec![],
                }
            ),
        ]
    );
    assert!(report
        .steps()
        .iter()
        .all(|step| step.outcome.freed_nothing()));
    assert_eq!(report.steps()[1].owner, None);
    assert_eq!(report.releasing(), [held.idle]);
    let text = error.to_string();
    for expected in [
        "fits after 4000000000 bytes is released",
        "reclamation freed nothing: cancel speculation declined, nothing to reclaim",
        "reclaim unused scratch no owner registered it",
        "drop low-value caches declined, all 1 pinned",
        "park eligible idle models 1 reservation releasing, counted until the release is \
         observed",
    ] {
        assert!(text.contains(expected), "{text}");
    }

    // Parking began, and the idle model's 12 GB still count: a promise frees nothing.
    assert_eq!(
        ledger.reservation(held.idle).unwrap().state(),
        ReservationState::Releasing
    );
    assert_eq!(ledger.available(vram(0)), Some(2 * GB));

    // Asked to wait, it is queued with the same reasons; the release is already started.
    let outcome = ledger.reserve_reclaiming(demand(6 * GB).wait_up_to(MINUTE), &mut ladder);
    let Ok(Admission::Queued {
        ticket,
        waiting_for,
        ..
    }) = outcome.admission
    else {
        panic!("expected a queue entry, got {:?}", outcome.admission);
    };
    assert_eq!(waiting_for.reclaim(), Some(&outcome.report));
    assert_eq!(outcome.report.releasing(), [held.idle]);
    drop(ladder);
    let calls_before = calls.borrow().len();

    // Once the host observes the release, the queue grants it; the ladder is not asked.
    clock.advance(SECOND);
    ledger.tick();
    assert!(ledger.drain_events().is_empty());
    ledger
        .confirm_release(held.idle, SourceClass::HostProbe)
        .unwrap();
    let events = ledger.drain_events();
    assert!(
        matches!(events.as_slice(), [LedgerEvent::QueueGranted { ticket: woken, .. }] if *woken == ticket),
        "{events:?}"
    );
    assert_eq!(calls.borrow().len(), calls_before);
    assert_eq!(
        (speculation.calls(), caches.calls(), park.calls()),
        (2, 2, 2)
    );
    assert_invariants(&ledger);
}

/// Three models in use hold all 23 GB of GPU 0 for tenant alpha.
fn all_pinned(ledger: &mut Ledger<&ManualClock>) -> [ReservationId; 3] {
    [10, 8, 5].map(|gigabytes| {
        let model = granted(ledger.reserve(on_gpu0(
            Requester::ModelPlacement,
            &format!("exe-model-{gigabytes}"),
            Priority::Foreground,
            gigabytes * GB,
        )));
        ledger.begin_create(model).unwrap();
        model
    })
}

#[test]
fn an_all_pinned_host_queues_or_refuses_with_a_useful_reason() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let models = all_pinned(&mut ledger);
    let calls = log();
    let mut speculation = Owner::declining(DeclineReason::NothingToReclaim, &calls);
    let mut scratch = Owner::declining(DeclineReason::NothingToReclaim, &calls);
    let mut caches = Owner::declining(DeclineReason::NotOnLimitingResources, &calls);
    let mut park = Owner::declining(
        DeclineReason::Held {
            pinned: 2,
            leased: 1,
        },
        &calls,
    );
    let mut ladder = ReclaimLadder::new();
    ladder
        .register(
            ReclaimStep::CancelSpeculation,
            Requester::Transfer,
            &mut speculation,
        )
        .register(
            ReclaimStep::ReclaimUnusedScratch,
            Requester::ModelPlacement,
            &mut scratch,
        )
        .register(
            ReclaimStep::DropLowValueCaches,
            Requester::ModelPlacement,
            &mut caches,
        )
        .register(
            ReclaimStep::ParkEligibleIdleModels,
            Requester::ModelPlacement,
            &mut park,
        );

    // Refused at once, naming the resource, that a release would help, and why nothing
    // was reclaimed.
    let refusal = ledger.reserve_reclaiming(demand(4 * GB), &mut ladder);
    let error = refused(refusal.admission);
    assert_eq!(error.resource(), vram(0));
    assert_eq!(
        error.limiting().prospect,
        RetryProspect::FitsAfterRelease { shortfall: 4 * GB }
    );
    assert!(error.retry_can_progress());
    assert_eq!(error.queue_refusal(), Some(QueueRefusal::NotRequested));
    assert_eq!(refusal.report.steps().len(), 4);
    assert!(refusal
        .report
        .steps()
        .iter()
        .all(|step| step.outcome.freed_nothing()));
    let text = error.to_string();
    for expected in [
        "reclamation freed nothing",
        "drop low-value caches declined, nothing it holds counts against the limiting resources",
        "park eligible idle models declined, 2 pinned and 1 leased by requests in flight",
    ] {
        assert!(text.contains(expected), "{text}");
    }

    // Queued instead, it carries the same reasons until its wait limit, and leaves with
    // them; it never loops.
    let queued_outcome = ledger.reserve_reclaiming(demand(4 * GB).wait_up_to(MINUTE), &mut ladder);
    let Ok(Admission::Queued {
        ticket,
        waiting_for,
        ..
    }) = queued_outcome.admission
    else {
        panic!("expected a queue entry, got {:?}", queued_outcome.admission);
    };
    assert_eq!(waiting_for.reclaim(), Some(&queued_outcome.report));
    drop(ladder);
    clock.advance(MINUTE + SECOND);
    ledger.tick();
    match ledger.drain_events().as_slice() {
        [LedgerEvent::QueueRefused {
            ticket: expired,
            error: LedgerError::QueueWaitExpired { waiting_for, .. },
        }] => {
            assert_eq!(*expired, ticket);
            let text = waiting_for.to_string();
            assert!(text.contains("2 pinned and 1 leased"), "{text}");
        }
        other => panic!("expected the request to reach its wait limit, got {other:?}"),
    }

    // Nothing was reclaimed: the models run on, each step was asked once per admission.
    for model in models {
        assert_eq!(
            ledger.reservation(model).unwrap().state(),
            ReservationState::InUse
        );
    }
    assert_eq!(ledger.reserved(vram(0)), 23 * GB);
    assert!(ledger.closed_records().is_empty());
    assert_eq!(
        (
            speculation.calls(),
            scratch.calls(),
            caches.calls(),
            park.calls()
        ),
        (2, 2, 2, 2)
    );
}

#[test]
fn the_ledger_acts_only_on_reservations_a_step_may_give_up() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    // A VM holds 6 GB of GPU 0 and runs a 4 GB model load inside it; a 15 GB model runs on
    // the host. 2 GB stay free.
    let vm = granted(ledger.reserve(on_gpu0(
        Requester::VmLifecycle,
        "exe-vm",
        Priority::Foreground,
        6 * GB,
    )));
    ledger.begin_create(vm).unwrap();
    let inside = granted(
        ledger.reserve(
            on_gpu0(
                Requester::ModelPlacement,
                "exe-vm",
                Priority::Foreground,
                4 * GB,
            )
            .within(vm),
        ),
    );
    let model = granted(ledger.reserve(on_gpu0(
        Requester::ModelPlacement,
        "exe-model",
        Priority::Foreground,
        15 * GB,
    )));
    ledger.begin_create(model).unwrap();
    let ram_only = granted(ledger.reserve(model_load("exe-host", "alpha", 4 * GIB, 0)));
    let gone = granted(ledger.reserve(on_gpu0(
        Requester::ModelPlacement,
        "exe-gone",
        Priority::Foreground,
        GB,
    )));
    ledger.cancel(gone).unwrap();
    let never = ReservationId::new(999);

    let calls = log();
    let mut park = Owner::giving_up(&[vm, inside, ram_only, gone, never], &calls);
    let outcome = {
        let mut ladder = ReclaimLadder::new();
        ladder.register(
            ReclaimStep::ParkEligibleIdleModels,
            Requester::ModelPlacement,
            &mut park,
        );
        ledger.reserve_reclaiming(demand(6 * GB), &mut ladder)
    };
    refused(outcome.admission);
    let refusals: Vec<_> = match &outcome.report.steps()[3].outcome {
        StepOutcome::Released {
            returned,
            releasing,
            refused,
        } => {
            assert!(returned.is_empty() && releasing.is_empty());
            refused.iter().map(|nomination| nomination.reason).collect()
        }
        other => panic!("expected nominations, got {other:?}"),
    };
    // Asking first would have told the step that the ledger acts on none of them.
    assert_eq!(park.would_help, [Vec::<ReservationId>::new()]);
    assert_eq!(
        refusals,
        [
            // Filed by VM lifecycle, not by the step's owner.
            NominationRefusal::NotOwned {
                requester: Requester::VmLifecycle
            },
            // Carved from the VM: releasing it returns nothing to the host.
            NominationRefusal::DoesNotHelp,
            // Holds host RAM, not the GPU memory the request falls short of.
            NominationRefusal::DoesNotHelp,
            NominationRefusal::AlreadyClosed,
            NominationRefusal::Unknown,
        ]
    );
    // Nothing changed.
    assert_eq!(
        ledger.reservation(vm).unwrap().state(),
        ReservationState::InUse
    );
    assert_eq!(
        ledger.reservation(inside).unwrap().state(),
        ReservationState::Granted
    );
    assert_eq!(
        ledger.reservation(ram_only).unwrap().state(),
        ReservationState::Granted
    );
    assert_eq!(ledger.available(vram(0)), Some(2 * GB));
    assert_invariants(&ledger);
}

#[test]
fn the_ladder_does_not_run_when_it_cannot_or_need_not_help() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let held = loaded_gpu(&mut ledger);
    let calls = log();
    let mut everything = Owner::giving_up(&[held.cache, held.idle, held.scratch], &calls);
    let mut ladder = ReclaimLadder::new();
    ladder.register(
        ReclaimStep::DropLowValueCaches,
        Requester::ModelPlacement,
        &mut everything,
    );

    // It fits without reclaiming.
    let fits = ledger.reserve_reclaiming(demand(GB), &mut ladder);
    granted(fits.admission);
    assert_eq!(fits.report.skipped_because(), Some(LadderSkip::NotNeeded));

    // Background requests never reclaim other work.
    let mut background = demand(6 * GB);
    background.priority = Priority::Background;
    let skipped = ledger.reserve_reclaiming(background, &mut ladder);
    let error = refused(skipped.admission);
    assert_eq!(
        skipped.report.skipped_because(),
        Some(LadderSkip::Background)
    );
    assert!(error
        .to_string()
        .contains("reclamation did not run: background requests do not reclaim other work"));

    // No release makes 30 GB fit on a 23 GB device.
    let too_large = ledger.reserve_reclaiming(demand(30 * GB), &mut ladder);
    let error = refused(too_large.admission);
    assert_eq!(error.queue_refusal(), Some(QueueRefusal::NotWaitable));
    assert_eq!(
        too_large.report.skipped_because(),
        Some(LadderSkip::NoReleaseHelps)
    );

    // An invalid request is refused as before.
    let mut empty = demand(GB);
    empty.demand = Amounts::new();
    let invalid = ledger.reserve_reclaiming(empty, &mut ladder);
    assert_eq!(invalid.admission, Err(LedgerError::EmptyDemand));
    assert_eq!(invalid.report.skipped_because(), Some(LadderSkip::Invalid));

    drop(ladder);
    assert_eq!(everything.calls(), 0);
    assert_eq!(ledger.available(vram(0)), Some(GB));
}

#[test]
fn reclaiming_behind_an_aged_request_makes_room_for_both() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    ledger.set_queue_fairness(QueueFairness {
        protect_after_wait: Some(10 * SECOND),
        ..QueueFairness::ARRIVAL_ORDER
    });
    // Prefetches of 8 GB and 4 GB and a 9 GB model hold 21 GB; 2 GB stay free.
    let speculation = [8, 4].map(|gigabytes| {
        granted(ledger.reserve(on_gpu0(
            Requester::Transfer,
            "exe-prefetch",
            Priority::Background,
            gigabytes * GB,
        )))
    });
    let model = granted(ledger.reserve(on_gpu0(
        Requester::ModelPlacement,
        "exe-model",
        Priority::Foreground,
        9 * GB,
    )));
    ledger.begin_create(model).unwrap();
    let aged = queued(
        ledger.reserve(
            on_gpu0(
                Requester::ModelPlacement,
                "exe-aged",
                Priority::Foreground,
                10 * GB,
            )
            .wait_up_to(MINUTE),
        ),
    );
    clock.advance(10 * SECOND);
    ledger.tick();
    assert!(ledger.queue_entries()[0].protected_at.is_some());

    // 2 GB is free, but the aged request keeps it: the ladder must make room for both.
    let calls = log();
    let mut owner = Owner::giving_up(&speculation, &calls);
    let outcome = {
        let mut ladder = ReclaimLadder::new();
        ladder.register(
            ReclaimStep::CancelSpeculation,
            Requester::Transfer,
            &mut owner,
        );
        ledger.reserve_reclaiming(demand(2 * GB), &mut ladder)
    };
    granted(outcome.admission);
    assert!(outcome.report.covered());
    assert_eq!(
        outcome.report.returned(),
        Amounts::new().vram_bytes(gpu(0), 12 * GB)
    );
    let [shortfall] = owner.told[0].as_slice() else {
        panic!("expected one shortfall, got {:?}", owner.told);
    };
    assert_eq!(shortfall.available, 0);
    // The queue was served once afterwards, and the aged request took what it was kept.
    let events = ledger.drain_events();
    assert!(
        matches!(events.as_slice(), [LedgerEvent::QueueGranted { ticket, .. }] if *ticket == aged),
        "{events:?}"
    );
    assert_eq!(ledger.available(vram(0)), Some(2 * GB));
    assert_eq!(owner.calls(), 1);
}

/// A small deterministic generator (SplitMix64), so every seed replays the same run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> Option<T> {
        let index = usize::try_from(self.below(items.len() as u64)).unwrap();
        items.get(index).copied()
    }
}

/// An owner that gives up an arbitrary choice of reservations, open, closed, foreign or
/// never granted, or declines.
struct Chaos(ReclaimResponse);

impl Reclaimer for Chaos {
    fn reclaim(&mut self, _: &ReclaimNeed<'_>) -> ReclaimResponse {
        self.0.clone()
    }
}

const FUZZED: [ResourceKey; 4] = [RAM, PINNED, NETWORK, ROOTS];

/// How often the seeded runs reached each path, so that a change that stops them from
/// reaching it fails instead of passing vacuously.
#[derive(Debug, Default)]
struct Coverage {
    granted_at_once: u32,
    children: u32,
    queued: u32,
    granted_from_queue: u32,
    expired: u32,
    pending_releases: u32,
    returned_by_ladder: u32,
    releasing_by_ladder: u32,
    refused_nominations: u32,
    protected: u64,
    bypasses: u64,
}

/// What the run has seen so far, for later operations to pick from.
#[derive(Default)]
struct Seen {
    reservations: Vec<ReservationId>,
    tickets: Vec<QueueTicket>,
}

impl Seen {
    /// Keeps what an admission granted or queued.
    fn admitted(&mut self, result: &Result<Admission, LedgerError>, coverage: &mut Coverage) {
        match result {
            Ok(Admission::Granted(reservation)) => {
                coverage.granted_at_once += 1;
                self.reservations.push(*reservation);
            }
            Ok(Admission::Queued { ticket, .. }) => {
                coverage.queued += 1;
                self.tickets.push(*ticket);
            }
            Err(_) => {}
        }
    }
}

fn fuzzed() -> Vec<ResourceKey> {
    let mut resources = FUZZED.to_vec();
    resources.push(vram(0));
    resources
}

fn random_request(rng: &mut Rng) -> ReservationRequest {
    let mut demand = Amounts::new();
    if rng.chance(60) {
        demand = demand.host_ram_bytes(1 + rng.below(8 * GIB));
    }
    if rng.chance(35) {
        demand = demand.pinned_host_ram_bytes(1 + rng.below(3 * GIB));
    }
    if rng.chance(50) {
        demand = demand.vram_bytes(gpu(0), 1 + rng.below(10 * GB));
    }
    if rng.chance(25) {
        demand = demand.network_slots(1);
    }
    if rng.chance(25) {
        demand = demand.burst_vm_roots(1 + rng.below(2));
    }
    if demand.is_empty() {
        demand = demand.host_ram_bytes(GIB);
    }
    let requester = rng
        .pick(&[
            Requester::VmLifecycle,
            Requester::ModelPlacement,
            Requester::Transfer,
            Requester::Coordination,
        ])
        .unwrap();
    let tenant_name = if rng.chance(50) { "alpha" } else { "beta" };
    let priority = if rng.chance(70) {
        Priority::Foreground
    } else {
        Priority::Background
    };
    let execution = format!("exe-{}", rng.below(6));
    let request = ReservationRequest::new(
        provenance(requester, &execution, tenant_name),
        priority,
        demand,
    );
    if rng.chance(50) {
        request.wait_up_to(Duration::from_secs(1 + rng.below(40)))
    } else {
        request
    }
}

fn random_fairness(rng: &mut Rng) -> QueueFairness {
    let maybe = |rng: &mut Rng, seconds: u64| {
        rng.chance(50)
            .then(|| Duration::from_secs(1 + rng.below(seconds)))
    };
    QueueFairness {
        protect_after_wait: maybe(rng, 20),
        protect_after_bypasses: rng.chance(50).then(|| u32::try_from(rng.below(4)).unwrap()),
        tenant_round_robin: rng.chance(50),
        foreground_first: rng.chance(50),
        promote_background_after: maybe(rng, 20),
    }
}

/// Recomputes every total from the open records and checks the ledger agrees: nothing
/// negative, wrapped or drifted.
fn check_accounting(ledger: &Ledger<&ManualClock>, seed: u64, step: usize) {
    let open: Vec<&ReservationRecord> = ledger.open_reservations().collect();
    let overrun = open.iter().any(|record| record.overrun());
    for resource in fuzzed() {
        let held: u128 = open
            .iter()
            .filter(|record| record.parent().is_none())
            .map(|record| u128::from(record.current().get(resource)))
            .sum();
        let at = format!("seed {seed}, step {step}, {resource}");
        assert_eq!(u128::from(ledger.reserved(resource)), held, "{at}");
        let capacity = ledger.capacity(resource).unwrap();
        let taken = held.saturating_add(u128::from(capacity.unmanaged_in_use));
        let expected = u128::from(capacity.grantable()).saturating_sub(taken);
        let available = ledger.available(resource).unwrap();
        assert_eq!(u128::from(available), expected, "{at}");
        assert!(available <= capacity.grantable(), "{at}");
        if !overrun {
            assert!(held <= u128::from(capacity.grantable()), "{at}");
        }
        for name in ["alpha", "beta"] {
            let tenant_held: u128 = open
                .iter()
                .filter(|record| {
                    record.parent().is_none() && record.provenance().tenant == tenant(name)
                })
                .map(|record| u128::from(record.current().get(resource)))
                .sum();
            assert_eq!(
                u128::from(ledger.tenant_reserved(&tenant(name), resource)),
                tenant_held,
                "{at}, {name}"
            );
        }
    }
    for record in &open {
        for (resource, amount) in record.current().iter() {
            let children: u128 = open
                .iter()
                .filter(|child| child.parent() == Some(record.id()))
                .map(|child| u128::from(child.current().get(resource)))
                .sum();
            assert!(children <= u128::from(amount), "seed {seed}, step {step}");
            assert_eq!(
                u128::from(ledger.parent_room(record.id(), resource).unwrap()),
                u128::from(amount) - children,
                "seed {seed}, step {step}"
            );
        }
    }
    let limits = ledger.config().queue;
    assert!(ledger.queue_len() <= limits.max_entries);
    let entries = ledger.queue_entries();
    for (name, stats) in ledger.queue_stats() {
        let waiting = entries.iter().filter(|entry| entry.tenant == *name).count();
        assert!(waiting <= limits.max_entries_per_tenant);
        assert_eq!(
            stats.queued,
            stats.granted + stats.refused + stats.withdrawn + waiting as u64,
            "seed {seed}, step {step}, {name}"
        );
    }
}

#[test]
fn seeded_cancel_and_grant_interleavings_never_drive_accounting_negative() {
    let mut coverage = Coverage::default();
    for seed in 1..=32u64 {
        let clock = start();
        let mut ledger = ledger_with(
            &clock,
            LedgerConfig {
                queue: QueueLimits {
                    max_entries: 6,
                    max_entries_per_tenant: 4,
                    max_wait: 30 * SECOND,
                },
                ..config()
            },
        );
        let initial: Vec<Option<u64>> = fuzzed()
            .into_iter()
            .map(|resource| ledger.available(resource))
            .collect();
        let mut rng = Rng(seed);
        let mut seen = Seen::default();
        let mut holds: Vec<HoldId> = Vec::new();
        for step in 0..300 {
            match rng.below(16) {
                0..=2 => {
                    let result = ledger.reserve(random_request(&mut rng));
                    seen.admitted(&result, &mut coverage);
                }
                3 => {
                    // A child carved from a random workload in use.
                    let parents: Vec<(ReservationId, Provenance, Priority, Amounts)> = ledger
                        .open_reservations()
                        .filter(|record| record.state() == ReservationState::InUse)
                        .map(|record| {
                            (
                                record.id(),
                                record.provenance().clone(),
                                record.priority(),
                                record.current().clone(),
                            )
                        })
                        .collect();
                    let index = usize::try_from(rng.below(parents.len() as u64)).unwrap();
                    if let Some((parent, provenance, priority, held)) = parents.get(index).cloned()
                    {
                        let mut demand = Amounts::new();
                        for (resource, amount) in held.iter() {
                            if rng.chance(70) {
                                demand = demand.with(resource, 1 + rng.below(amount));
                            }
                        }
                        if !demand.is_empty() {
                            let mut request = ReservationRequest::new(provenance, priority, demand)
                                .within(parent);
                            if rng.chance(40) {
                                request = request.wait_up_to(10 * SECOND);
                            }
                            let result = ledger.reserve(request);
                            if let Ok(Admission::Granted(_)) = result {
                                coverage.children += 1;
                            }
                            seen.admitted(&result, &mut coverage);
                        }
                    }
                }
                4 | 5 => {
                    if let Some(reservation) = rng.pick(&seen.reservations) {
                        let _ = ledger.begin_create(reservation);
                    }
                }
                6 | 7 => {
                    // Cancel, often more than once, including closed reservations.
                    if let Some(reservation) = rng.pick(&seen.reservations) {
                        for _ in 0..=rng.below(3) {
                            if ledger.cancel(reservation) == Ok(ReleaseOutcome::Pending) {
                                coverage.pending_releases += 1;
                            }
                        }
                    }
                    let never = ReservationId::new(10_000 + rng.below(100));
                    assert_eq!(
                        ledger.cancel(never),
                        Err(LedgerError::UnknownReservation { reservation: never })
                    );
                }
                8 => {
                    if let Some(ticket) = rng.pick(&seen.tickets) {
                        ledger.cancel_queued(ticket).unwrap();
                        ledger.cancel_queued(ticket).unwrap();
                    }
                }
                9 => {
                    if let Some(reservation) = rng.pick(&seen.reservations) {
                        let source = match ledger
                            .reservation(reservation)
                            .map(|record| record.parent())
                        {
                            Some(Some(_)) => SourceClass::GuestReport,
                            _ => SourceClass::HostProbe,
                        };
                        let _ = ledger.confirm_release(reservation, source);
                    }
                }
                10 => {
                    // Reconcile to a random use, above or below the reservation.
                    if let Some(reservation) = rng.pick(&seen.reservations) {
                        if let Some(record) = ledger.reservation(reservation) {
                            let source = if record.parent().is_some() {
                                SourceClass::GuestReport
                            } else {
                                SourceClass::HostProbe
                            };
                            let mut in_use = Amounts::new();
                            for (resource, amount) in record.current().iter() {
                                let most = amount.saturating_add(amount / 4).saturating_add(1);
                                in_use = in_use.with(resource, rng.below(most));
                            }
                            let _ = ledger.reconcile(reservation, observed(source, in_use));
                        }
                    }
                }
                11 => {
                    clock.advance(Duration::from_millis(rng.below(2_000)));
                    ledger.tick();
                }
                12 | 13 => {
                    // Admission with a ladder whose owners give up anything at all.
                    let mut owners: Vec<(ReclaimStep, Requester, Chaos)> = Vec::new();
                    for step in ReclaimStep::ORDER {
                        if rng.chance(60) {
                            let mut picks = Vec::new();
                            for _ in 0..rng.below(4) {
                                if let Some(reservation) = rng.pick(&seen.reservations) {
                                    picks.push(reservation);
                                }
                            }
                            picks.push(ReservationId::new(20_000 + rng.below(10)));
                            let answer = if rng.chance(25) {
                                ReclaimResponse::Decline(DeclineReason::NothingToReclaim)
                            } else {
                                ReclaimResponse::Release(picks)
                            };
                            let owner = rng
                                .pick(&[
                                    Requester::VmLifecycle,
                                    Requester::ModelPlacement,
                                    Requester::Transfer,
                                    Requester::Coordination,
                                ])
                                .unwrap();
                            owners.push((step, owner, Chaos(answer)));
                        }
                    }
                    let request = random_request(&mut rng);
                    let mut ladder = ReclaimLadder::new();
                    for (step, owner, chaos) in &mut owners {
                        ladder.register(*step, *owner, chaos);
                    }
                    let outcome = ledger.reserve_reclaiming(request, &mut ladder);
                    seen.admitted(&outcome.admission, &mut coverage);
                    let report = &outcome.report;
                    coverage.returned_by_ladder += u32::from(!report.returned().is_empty());
                    coverage.releasing_by_ladder += u32::from(!report.releasing().is_empty());
                    for step in report.steps() {
                        if let StepOutcome::Released { refused, .. } = &step.outcome {
                            coverage.refused_nominations += refused.len() as u32;
                        }
                    }
                    // A request that did not fit carries what the ladder did.
                    match &outcome.admission {
                        Err(LedgerError::Capacity(error))
                        | Ok(Admission::Queued {
                            waiting_for: error, ..
                        }) => assert_eq!(error.reclaim(), Some(&outcome.report)),
                        Ok(Admission::Granted(_)) => assert!(matches!(
                            outcome.report.skipped_because(),
                            None | Some(LadderSkip::NotNeeded)
                        )),
                        Err(_) => {}
                    }
                }
                14 => {
                    if rng.chance(50) {
                        ledger.set_queue_fairness(random_fairness(&mut rng));
                    } else {
                        let execution = ExecutionId::new(format!("exe-{}", rng.below(6))).unwrap();
                        ledger.cancel_execution(&execution);
                    }
                }
                _ => {
                    // Host pressure, or an owner resource-return hold.
                    if rng.chance(70) {
                        let resource = rng.pick(&fuzzed()).unwrap();
                        let in_use = rng.below(ledger.capacity(resource).unwrap().total / 2 + 1);
                        ledger
                            .observe_unmanaged_usage(resource, in_use, SourceClass::HostProbe)
                            .unwrap();
                    } else if let Some(hold) = holds.pop() {
                        assert_eq!(ledger.end_hold(hold), Ok(true));
                    } else {
                        let resource = rng.pick(&fuzzed()).unwrap();
                        holds.push(ledger.begin_hold(BTreeSet::from([resource])).unwrap().hold);
                    }
                }
            }
            for event in ledger.drain_events() {
                match event {
                    LedgerEvent::QueueGranted { reservation, .. } => {
                        coverage.granted_from_queue += 1;
                        seen.reservations.push(reservation);
                    }
                    LedgerEvent::QueueRefused {
                        error: LedgerError::QueueWaitExpired { .. },
                        ..
                    } => coverage.expired += 1,
                    LedgerEvent::QueueRefused { .. } | LedgerEvent::Reclaimed { .. } => {}
                }
            }
            check_accounting(&ledger, seed, step);
        }
        for stats in ledger.queue_stats().values() {
            coverage.protected += stats.protected;
            coverage.bypasses += stats.bypasses;
        }

        // Withdraw everything, cancel every reservation twice and let the host observe
        // every release: every amount returns exactly to where it started.
        for ticket in &seen.tickets {
            ledger.cancel_queued(*ticket).unwrap();
        }
        assert_eq!(ledger.queue_len(), 0);
        let roots: Vec<ReservationId> = ledger
            .open_reservations()
            .filter(|record| record.parent().is_none())
            .map(|record| record.id())
            .collect();
        for root in &roots {
            ledger.cancel(*root).unwrap();
            ledger.cancel(*root).unwrap();
        }
        for root in &roots {
            ledger
                .confirm_release(*root, SourceClass::HostProbe)
                .unwrap();
        }
        for resource in fuzzed() {
            ledger
                .observe_unmanaged_usage(resource, 0, SourceClass::HostProbe)
                .unwrap();
        }
        check_accounting(&ledger, seed, usize::MAX);
        assert_eq!(ledger.open_reservations().count(), 0, "seed {seed}");
        let after: Vec<Option<u64>> = fuzzed()
            .into_iter()
            .map(|resource| ledger.available(resource))
            .collect();
        assert_eq!(after, initial, "seed {seed}");
        for resource in fuzzed() {
            assert_eq!(ledger.reserved(resource), 0, "seed {seed}");
        }
    }
    let Coverage {
        granted_at_once,
        children,
        queued,
        granted_from_queue,
        expired,
        pending_releases,
        returned_by_ladder,
        releasing_by_ladder,
        refused_nominations,
        protected,
        bypasses,
    } = coverage;
    let reached = [
        u64::from(granted_at_once),
        u64::from(children),
        u64::from(queued),
        u64::from(granted_from_queue),
        u64::from(expired),
        u64::from(pending_releases),
        u64::from(returned_by_ladder),
        u64::from(releasing_by_ladder),
        u64::from(refused_nominations),
        protected,
        bypasses,
    ];
    assert!(reached.iter().all(|count| *count > 0), "{coverage:?}");
}
