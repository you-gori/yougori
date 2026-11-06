//! Queue fairness (GPU-W06): in arrival order a large request starves behind smaller ones;
//! aging protects it while backfill that leaves its shortfall reachable continues;
//! protection by bypass count; tenant turns; foreground before background, with promotion
//! into service or a refusal with a reason; and the records a report reads.

use std::collections::{BTreeMap, VecDeque};

use super::*;

/// The ledger of the other tests with room for 16 waiting requests, 16 of one tenant,
/// each waiting at most a minute, served under `fairness`.
fn ledger_serving(clock: &ManualClock, fairness: QueueFairness) -> Ledger<&ManualClock> {
    let mut ledger = ledger_with(
        clock,
        LedgerConfig {
            queue: QueueLimits {
                max_entries: 16,
                max_entries_per_tenant: 16,
                max_wait: MINUTE,
            },
            ..config()
        },
    );
    ledger.set_queue_fairness(fairness);
    ledger
}

fn load(execution: &str, tenant_name: &str, priority: Priority, bytes: u64) -> ReservationRequest {
    ReservationRequest::new(
        provenance(Requester::ModelPlacement, execution, tenant_name),
        priority,
        Amounts::new().vram_bytes(gpu(0), bytes),
    )
}

fn foreground(execution: &str, tenant_name: &str, bytes: u64) -> ReservationRequest {
    load(execution, tenant_name, Priority::Foreground, bytes)
}

fn aging_after(wait: Duration) -> QueueFairness {
    QueueFairness {
        protect_after_wait: Some(wait),
        ..QueueFairness::ARRIVAL_ORDER
    }
}

/// Small 2 GB loads of tenant beta that hold most of GPU 0 and churn: each second the
/// oldest finishes and a new one asks to wait up to a minute.
struct Churn {
    running: VecDeque<ReservationId>,
    waiting: Vec<QueueTicket>,
    started: u32,
    /// Every queue grant seen.
    granted: Vec<(QueueTicket, ReservationId)>,
    /// Every queue refusal seen.
    refused: Vec<(QueueTicket, LedgerError)>,
}

impl Churn {
    /// Ten loads: 20 of the 23 GB grantable, leaving 3 GB.
    fn start(ledger: &mut Ledger<&ManualClock>) -> Self {
        let mut churn = Self {
            running: VecDeque::new(),
            waiting: Vec::new(),
            started: 0,
            granted: Vec::new(),
            refused: Vec::new(),
        };
        for _ in 0..10 {
            let request = churn.next_load();
            churn.running.push_back(granted(ledger.reserve(request)));
        }
        churn
    }

    fn next_load(&mut self) -> ReservationRequest {
        self.started += 1;
        foreground(&format!("exe-small-{}", self.started), "beta", 2 * GB).wait_up_to(MINUTE)
    }

    /// One second: the oldest small load finishes, then a new one arrives. Returns the new
    /// one's admission.
    fn second(
        &mut self,
        clock: &ManualClock,
        ledger: &mut Ledger<&ManualClock>,
    ) -> Result<Admission, LedgerError> {
        clock.advance(SECOND);
        if let Some(oldest) = self.running.pop_front() {
            ledger.cancel(oldest).unwrap();
        }
        self.absorb(ledger);
        let request = self.next_load();
        let admission = ledger.reserve(request);
        match &admission {
            Ok(Admission::Granted(reservation)) => self.running.push_back(*reservation),
            Ok(Admission::Queued { ticket, .. }) => self.waiting.push(*ticket),
            Err(_) => {}
        }
        self.absorb(ledger);
        admission
    }

    /// Takes the ledger's events: small loads granted from the queue start running.
    fn absorb(&mut self, ledger: &mut Ledger<&ManualClock>) {
        for event in ledger.drain_events() {
            match event {
                LedgerEvent::QueueGranted {
                    ticket,
                    reservation,
                } => {
                    if self.waiting.contains(&ticket) {
                        self.running.push_back(reservation);
                    }
                    self.granted.push((ticket, reservation));
                }
                LedgerEvent::QueueRefused { ticket, error } => self.refused.push((ticket, error)),
                LedgerEvent::Reclaimed { .. } => {}
            }
        }
    }
}

fn record_of(ledger: &Ledger<&ManualClock>, ticket: QueueTicket) -> QueueRecord {
    ledger
        .queue_records()
        .iter()
        .find(|record| record.ticket == ticket)
        .cloned()
        .unwrap()
}

#[test]
fn in_arrival_order_a_large_request_starves_behind_smaller_ones() {
    let clock = start();
    let mut ledger = ledger_serving(&clock, QueueFairness::default());
    assert_eq!(ledger.queue_fairness(), QueueFairness::ARRIVAL_ORDER);
    let mut churn = Churn::start(&mut ledger);
    let large =
        queued(ledger.reserve(foreground("exe-large", "alpha", 10 * GB).wait_up_to(MINUTE)));

    // Every release is taken at once by the next small load, so 3 GB stay free.
    for second in 1..=61 {
        let admission = churn.second(&clock, &mut ledger);
        assert!(
            matches!(admission, Ok(Admission::Granted(_))),
            "second {second}: {admission:?}"
        );
    }

    // The large request never fit and ended at its wait limit, refused with a reason.
    assert!(churn.granted.iter().all(|(ticket, _)| *ticket != large));
    match churn.refused.as_slice() {
        [(
            ticket,
            LedgerError::QueueWaitExpired {
                waited,
                waiting_for,
                ..
            },
        )] => {
            assert_eq!(*ticket, large);
            assert_eq!(*waited, MINUTE + SECOND);
            assert_eq!(waiting_for.resource(), vram(0));
            assert!(waiting_for.kept_for().is_empty());
        }
        other => panic!("expected the large request to expire, got {other:?}"),
    }
    // Its record shows the starvation: every later load bypassed it.
    let record = record_of(&ledger, large);
    assert_eq!(record.bypassed, 60);
    assert_eq!(record.protected_at, None);
    assert_eq!(record.waited, MINUTE + SECOND);
    assert!(matches!(
        record.exit,
        QueueExit::Refused {
            error: LedgerError::QueueWaitExpired { .. }
        }
    ));
    let alpha = &ledger.queue_stats()[&tenant("alpha")];
    assert_eq!((alpha.queued, alpha.granted, alpha.refused), (1, 0, 1));
    assert_eq!(alpha.bypasses, 60);
    assert_eq!(alpha.protected, 0);
    assert_eq!(alpha.longest_wait, MINUTE + SECOND);
    assert_invariants(&ledger);
}

#[test]
fn aging_protects_a_large_request_while_backfill_that_leaves_it_reachable_continues() {
    let clock = start();
    let t0 = clock.now();
    let mut ledger = ledger_serving(&clock, aging_after(10 * SECOND));
    let mut churn = Churn::start(&mut ledger);
    let large = queued(
        ledger.reserve(
            ReservationRequest::new(
                provenance(Requester::ModelPlacement, "exe-large", "alpha"),
                Priority::Foreground,
                Amounts::new()
                    .vram_bytes(gpu(0), 10 * GB)
                    .host_ram_bytes(4 * GIB),
            )
            .wait_up_to(MINUTE),
        ),
    );

    // Until it ages, smaller loads still take every release.
    for _ in 1..10 {
        assert!(matches!(
            churn.second(&clock, &mut ledger),
            Ok(Admission::Granted(_))
        ));
    }
    let entry = &ledger.queue_entries()[0];
    assert_eq!(
        (entry.ticket, entry.bypassed, entry.protected_at),
        (large, 9, None)
    );
    assert_eq!(entry.waited, 9 * SECOND);

    // At ten seconds it is protected, and the next small load waits behind it, told why.
    let held = churn.second(&clock, &mut ledger);
    let Ok(Admission::Queued { waiting_for, .. }) = &held else {
        panic!("expected the small load to wait, got {held:?}");
    };
    let aged = QueueClaim {
        ticket: large,
        reason: ClaimReason::Aged,
    };
    assert_eq!(waiting_for.kept_for(), [aged]);
    assert_eq!(waiting_for.resource(), vram(0));
    assert!(waiting_for.retry_can_progress());
    let text = waiting_for.to_string();
    assert!(
        text.contains(&format!("capacity is kept for {large}, which aged")),
        "{text}"
    );
    let protected_at = Some(t0.saturating_add(10 * SECOND));
    assert_eq!(ledger.queue_entries()[0].protected_at, protected_at);

    // Backfill that leaves its shortfall reachable continues: host RAM it has room to
    // spare on, and another GPU.
    let ram = |execution: &str, bytes: u64| {
        ReservationRequest::new(
            provenance(Requester::VmLifecycle, execution, "beta"),
            Priority::Foreground,
            Amounts::new().host_ram_bytes(bytes),
        )
    };
    granted(ledger.reserve(ram("exe-vm", 20 * GIB)));
    // Of the 10 GiB left it keeps 4, so an 8 GiB request does not fit, and 6 GiB does.
    let error = refused(ledger.reserve(ram("exe-vm2", 8 * GIB)));
    assert_eq!(error.resource(), RAM);
    assert_eq!(error.limiting().available, 6 * GIB);
    assert_eq!(error.kept_for(), [aged]);
    assert_eq!(error.queue_refusal(), Some(QueueRefusal::NotRequested));
    granted(ledger.reserve(ram("exe-vm3", 6 * GIB)));
    assert_eq!(ledger.available(RAM), Some(4 * GIB));
    ledger
        .declare_capacity(vram(1), host_probe(16 * GB, 0))
        .unwrap();
    ledger
        .set_tenant_budget(tenant("beta"), vram(1), u64::MAX)
        .unwrap();
    granted(ledger.reserve(ReservationRequest::new(
        provenance(Requester::ModelPlacement, "exe-other-gpu", "beta"),
        Priority::Foreground,
        Amounts::new().vram_bytes(gpu(1), 8 * GB),
    )));
    assert_eq!(ledger.queue_entries()[0].bypassed, 9);

    // Releases now accumulate for it: three seconds later 11 GB are free and it is
    // granted, long before its wait limit.
    for _ in 0..3 {
        assert!(matches!(
            churn.second(&clock, &mut ledger),
            Ok(Admission::Queued { .. })
        ));
    }
    let (_, reservation) = churn
        .granted
        .iter()
        .copied()
        .find(|(ticket, _)| *ticket == large)
        .unwrap();
    let record = ledger.reservation(reservation).unwrap();
    assert_eq!(record.phase_durations(clock.now()).queued, 13 * SECOND);
    let exit = record_of(&ledger, large);
    assert_eq!(exit.exit, QueueExit::Granted { reservation });
    assert_eq!(exit.bypassed, 9);
    assert_eq!(exit.protected_at, protected_at);

    // The loads it held back are served from what is left; nothing waits past its limit.
    for _ in 0..30 {
        churn.second(&clock, &mut ledger).unwrap();
    }
    assert!(churn.refused.is_empty(), "{:?}", churn.refused);
    assert!(ledger.queue_len() <= 5);
    let alpha = &ledger.queue_stats()[&tenant("alpha")];
    assert_eq!((alpha.granted, alpha.protected, alpha.bypasses), (1, 1, 9));
    assert_invariants(&ledger);
}

#[test]
fn a_request_bypassed_too_often_is_protected_at_once() {
    let clock = start();
    let t0 = clock.now();
    let mut ledger = ledger_serving(
        &clock,
        QueueFairness {
            protect_after_bypasses: Some(3),
            ..QueueFairness::ARRIVAL_ORDER
        },
    );
    let mut churn = Churn::start(&mut ledger);
    let large =
        queued(ledger.reserve(foreground("exe-large", "alpha", 10 * GB).wait_up_to(MINUTE)));
    for _ in 0..3 {
        assert!(matches!(
            churn.second(&clock, &mut ledger),
            Ok(Admission::Granted(_))
        ));
    }
    // The third bypass protected it at once, so the fourth small load waits.
    let entry = &ledger.queue_entries()[0];
    assert_eq!(entry.ticket, large);
    assert_eq!(entry.bypassed, 3);
    assert_eq!(entry.protected_at, Some(t0.saturating_add(3 * SECOND)));
    let admission = churn.second(&clock, &mut ledger);
    let Ok(Admission::Queued { waiting_for, .. }) = admission else {
        panic!("expected the small load to wait, got {admission:?}");
    };
    assert_eq!(
        waiting_for.kept_for(),
        [QueueClaim {
            ticket: large,
            reason: ClaimReason::Aged
        }]
    );
    assert_eq!(ledger.queue_stats()[&tenant("alpha")].protected, 1);
}

/// The order in which four 5 GB requests queued on a full GPU are granted as 5 GB is
/// released at a time: three of tenant alpha, then one of beta.
fn grant_order(fairness: QueueFairness) -> Vec<String> {
    let clock = start();
    let mut ledger = ledger_serving(&clock, fairness);
    let blockers: Vec<ReservationId> = (0..4)
        .map(|index| {
            granted(ledger.reserve(foreground(&format!("exe-block{index}"), "beta", 5 * GB)))
        })
        .collect();
    granted(ledger.reserve(foreground("exe-rest", "beta", 3 * GB)));
    let mut names = BTreeMap::new();
    for (execution, tenant_name) in [
        ("exe-a1", "alpha"),
        ("exe-a2", "alpha"),
        ("exe-a3", "alpha"),
        ("exe-b1", "beta"),
    ] {
        clock.advance(SECOND);
        let ticket =
            queued(ledger.reserve(foreground(execution, tenant_name, 5 * GB).wait_up_to(MINUTE)));
        names.insert(ticket, execution.to_string());
    }
    let mut order = Vec::new();
    for blocker in blockers {
        clock.advance(SECOND);
        ledger.cancel(blocker).unwrap();
        for event in ledger.drain_events() {
            if let LedgerEvent::QueueGranted { ticket, .. } = event {
                order.push(names[&ticket].clone());
            }
        }
    }
    assert_eq!(ledger.queue_len(), 0);
    order
}

#[test]
fn tenants_take_turns_under_round_robin() {
    // Arrival order serves the tenant that queued first until it has nothing waiting.
    assert_eq!(
        grant_order(QueueFairness::ARRIVAL_ORDER),
        ["exe-a1", "exe-a2", "exe-a3", "exe-b1"]
    );
    // In turns, the tenant granted least recently goes first.
    let turns = QueueFairness {
        tenant_round_robin: true,
        ..QueueFairness::ARRIVAL_ORDER
    };
    assert_eq!(grant_order(turns), ["exe-a1", "exe-b1", "exe-a2", "exe-a3"]);
}

#[test]
fn background_work_takes_only_what_waiting_foreground_work_leaves() {
    let clock = start();
    let mut ledger = ledger_serving(
        &clock,
        QueueFairness {
            foreground_first: true,
            ..QueueFairness::ARRIVAL_ORDER
        },
    );
    granted(ledger.reserve(foreground("exe-full", "beta", 20 * GB)));
    let waiting = queued(ledger.reserve(foreground("exe-fg", "alpha", 5 * GB).wait_up_to(MINUTE)));
    // 3 GB are free, and the waiting foreground request needs them.
    let error = refused(ledger.reserve(load("exe-bg", "beta", Priority::Background, 2 * GB)));
    assert_eq!(
        error.kept_for(),
        [QueueClaim {
            ticket: waiting,
            reason: ClaimReason::Foreground
        }]
    );
    assert!(
        error.to_string().contains("a foreground request"),
        "{error}"
    );
    // Foreground work still backfills; in arrival order background work would too.
    granted(ledger.reserve(foreground("exe-fg2", "beta", 2 * GB)));
    ledger.set_queue_fairness(QueueFairness::ARRIVAL_ORDER);
    granted(ledger.reserve(load("exe-bg", "beta", Priority::Background, GB)));
}

/// A background 5 GB request waits on a full GPU while, each second, a new foreground
/// 5 GB request arrives just before 5 GB is released. Returns the background request's
/// queue record once it left the queue.
fn background_under_foreground_load(fairness: QueueFairness) -> QueueRecord {
    let clock = start();
    let mut ledger = ledger_serving(&clock, fairness);
    let mut running: VecDeque<ReservationId> = (0..4)
        .map(|index| {
            granted(ledger.reserve(foreground(&format!("exe-block{index}"), "beta", 5 * GB)))
        })
        .collect();
    granted(ledger.reserve(foreground("exe-rest", "beta", 3 * GB)));
    let background = queued(
        ledger.reserve(load("exe-bg", "alpha", Priority::Background, 5 * GB).wait_up_to(MINUTE)),
    );
    for second in 1..=70 {
        clock.advance(SECOND);
        let request = foreground(&format!("exe-fg{second}"), "beta", 5 * GB).wait_up_to(MINUTE);
        assert!(matches!(
            ledger.reserve(request),
            Ok(Admission::Queued { .. })
        ));
        let oldest = running.pop_front().unwrap();
        ledger.cancel(oldest).unwrap();
        for event in ledger.drain_events() {
            match event {
                LedgerEvent::QueueGranted { reservation, .. } => running.push_back(reservation),
                LedgerEvent::QueueRefused { ticket, .. } => assert_eq!(ticket, background),
                LedgerEvent::Reclaimed { .. } => {}
            }
        }
        if ledger.queue_position(background).is_none() {
            return record_of(&ledger, background);
        }
    }
    panic!("the background request never left the queue");
}

#[test]
fn foreground_goes_first_and_promotion_brings_background_work_into_service() {
    let t0 = start().now();
    // Foreground first alone: every release goes to the newest foreground request, and
    // the background request ends at its wait limit, refused with a reason.
    let starved = background_under_foreground_load(QueueFairness {
        foreground_first: true,
        ..QueueFairness::ARRIVAL_ORDER
    });
    assert!(matches!(
        starved.exit,
        QueueExit::Refused {
            error: LedgerError::QueueWaitExpired { .. }
        }
    ));
    assert_eq!(starved.waited, MINUTE + SECOND);
    assert_eq!(starved.promoted_at, None);
    assert_eq!(starved.priority, Priority::Background);

    // Promoted after 20 s, it is the oldest foreground request and takes the next release.
    let served = background_under_foreground_load(QueueFairness {
        foreground_first: true,
        promote_background_after: Some(20 * SECOND),
        ..QueueFairness::ARRIVAL_ORDER
    });
    assert!(matches!(served.exit, QueueExit::Granted { .. }));
    assert_eq!(served.promoted_at, Some(t0.saturating_add(20 * SECOND)));
    assert_eq!(served.waited, 20 * SECOND);
}

#[test]
fn queue_records_are_bounded_and_tenant_statistics_add_up() {
    let clock = start();
    let mut ledger = ledger_serving(&clock, QueueFairness::ARRIVAL_ORDER);
    granted(ledger.reserve(foreground("exe-full", "beta", 23 * GB)));
    let extra = 6;
    for index in 0..MAX_QUEUE_RECORDS + extra {
        let request = foreground(&format!("exe-{index}"), "alpha", GB).wait_up_to(MINUTE);
        let ticket = queued(ledger.reserve(request));
        assert_eq!(ledger.cancel_queued(ticket), Ok(true));
    }
    assert_eq!(ledger.queue_records().len(), MAX_QUEUE_RECORDS);
    assert_eq!(ledger.queue_records_dropped(), extra as u64);
    assert!(ledger
        .queue_records()
        .iter()
        .all(|record| record.exit == QueueExit::Withdrawn));

    // A revoked execution and a hold refuse waiting requests; both are recorded.
    let revoked = queued(ledger.reserve(foreground("exe-revoked", "alpha", GB).wait_up_to(MINUTE)));
    ledger.cancel_execution(&ExecutionId::new("exe-revoked").unwrap());
    let denied = queued(
        ledger.reserve(load("exe-denied", "beta", Priority::Background, GB).wait_up_to(MINUTE)),
    );
    ledger.begin_hold(BTreeSet::from([vram(0)])).unwrap();
    let waiting = queued(ledger.reserve(foreground("exe-waiting", "beta", GB).wait_up_to(MINUTE)));
    assert!(matches!(
        record_of(&ledger, revoked).exit,
        QueueExit::Refused {
            error: LedgerError::ExecutionCancelled { .. }
        }
    ));
    assert!(matches!(
        record_of(&ledger, denied).exit,
        QueueExit::Refused {
            error: LedgerError::Capacity(_)
        }
    ));

    // Every request queued is waiting, or left by exactly one way.
    for (name, stats) in ledger.queue_stats() {
        let waiting_now = ledger
            .queue_entries()
            .iter()
            .filter(|entry| entry.tenant == *name)
            .count() as u64;
        assert_eq!(
            stats.queued,
            stats.granted + stats.refused + stats.withdrawn + waiting_now,
            "{name}"
        );
    }
    let alpha = &ledger.queue_stats()[&tenant("alpha")];
    assert_eq!(alpha.withdrawn, (MAX_QUEUE_RECORDS + extra) as u64);
    assert_eq!(alpha.refused, 1);
    assert_eq!(ledger.queue_entries()[0].ticket, waiting);
    let taken = ledger.take_queue_records();
    assert_eq!(taken.len(), MAX_QUEUE_RECORDS);
    assert!(ledger.queue_records().is_empty());
}
