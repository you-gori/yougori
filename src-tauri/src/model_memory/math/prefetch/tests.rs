use std::time::Duration;

use super::*;
use crate::foundation::ids::MonotonicTime;
use crate::model_memory::math::calibration::{ModeController, ModeSignals, ModeThresholds};
use crate::model_memory::math::test_support::{close, SeededRng};

const MB: u64 = 1_000_000;
const MIB: u64 = 1 << 20;

/// 1 per millisecond, 1 per MB, 0.01 per joule, 100 per currency unit.
fn objective() -> Objective {
    Objective::new(1.0, 1e-6, 0.01, 100.0).unwrap()
}

fn ms(milliseconds: f64) -> RawCost {
    RawCost {
        milliseconds,
        ..RawCost::default()
    }
}

fn wasted(bytes: u64) -> RawCost {
    RawCost {
        bytes: bytes as f64,
        ..RawCost::default()
    }
}

fn candidate(
    name: &str,
    origin: CandidateOrigin,
    probability: f64,
    saved_ms: f64,
) -> PrefetchCandidate {
    PrefetchCandidate {
        id: CandidateId::new(name).unwrap(),
        origin,
        probability,
        bytes: 40 * MB,
        saved_if_used: ms(saved_ms),
        waste_if_unused: wasted(50 * MB),
        interference: ms(5.0),
        retention: ms(5.0),
    }
}

fn op(name: &str) -> OperationId {
    OperationId::new(name).unwrap()
}

#[test]
fn expected_value_signs() {
    let value = |p: f64| {
        expected_value(
            &candidate("c", CandidateOrigin::QueuedWork, p, 200.0),
            &objective(),
        )
        .unwrap()
    };
    // 0.9*200 - 0.1*50 - 5 - 5
    assert!(close(value(0.9).expected_value, 165.0, 1e-9));
    // 0.1*200 - 0.9*50 - 5 - 5
    assert!(close(value(0.1).expected_value, -35.0, 1e-9));
    assert!(close(value(0.0).expected_value, -60.0, 1e-9));

    // A certain use still loses when interference outweighs the saving.
    let mut noisy = candidate("noisy", CandidateOrigin::QueuedWork, 1.0, 200.0);
    noisy.interference = ms(300.0);
    let noisy = expected_value(&noisy, &objective()).unwrap();
    assert!(close(noisy.expected_value, -105.0, 1e-9));

    // Raw quantities stay beside the normalised terms.
    let mut costly = candidate("costly", CandidateOrigin::QueuedWork, 0.9, 200.0);
    costly.waste_if_unused = RawCost {
        milliseconds: 0.0,
        bytes: 50e6,
        energy_joules: 1000.0,
        currency_units: 0.05,
    };
    let costly = expected_value(&costly, &objective()).unwrap();
    assert!(close(costly.waste_score, 65.0, 1e-9));
    assert!(close(costly.expected_value, 180.0 - 6.5 - 10.0, 1e-9));
    assert_eq!(costly.raw_waste.energy_joules, 1000.0);
    assert_eq!(costly.raw_waste.currency_units, 0.05);
    assert_eq!(costly.raw_saved.milliseconds, 200.0);
    assert_eq!(costly.raw_interference.milliseconds, 5.0);
    assert_eq!(costly.raw_retention.milliseconds, 5.0);

    let mut invalid = candidate("bad", CandidateOrigin::QueuedWork, 1.5, 200.0);
    assert!(expected_value(&invalid, &objective()).is_err());
    invalid.probability = 0.5;
    invalid.retention = ms(-1.0);
    assert!(expected_value(&invalid, &objective()).is_err());
    assert!(Objective::new(-1.0, 0.0, 0.0, 0.0).is_err());
}

#[test]
fn queued_work_and_explicit_intent_rank_before_recency_and_markov() {
    let candidates = vec![
        candidate("markov", CandidateOrigin::Markov, 0.9, 600.0),
        candidate("recency", CandidateOrigin::Recency, 0.9, 400.0),
        candidate("queued", CandidateOrigin::QueuedWork, 0.9, 150.0),
        candidate("intent", CandidateOrigin::ExplicitUserIntent, 0.9, 100.0),
        candidate("unlikely", CandidateOrigin::QueuedWork, 0.05, 100.0),
    ];
    let ranked = rank_candidates(&candidates, &objective()).unwrap();
    let order: Vec<&str> = ranked
        .iter()
        .map(|value| value.candidate.as_str())
        .collect();
    assert_eq!(order, vec!["queued", "intent", "markov", "recency"]);
    assert!(ranked.iter().all(|value| value.expected_value > 0.0));

    let twice = vec![candidates[0].clone(), candidates[0].clone()];
    assert!(rank_candidates(&twice, &objective()).is_err());
}

const BUDGET: PrefetchBudget = PrefetchBudget {
    max_speculative_bytes: 100 * MB,
    capacity_bytes: 256 * MB,
    reserved_foreground_bytes: 64 * MB,
};

fn worth(bytes: u64) -> PrefetchValue {
    let mut value = expected_value(
        &candidate("c", CandidateOrigin::QueuedWork, 0.9, 200.0),
        &objective(),
    )
    .unwrap();
    value.bytes = bytes;
    value
}

#[test]
fn the_speculative_budget_and_foreground_reserve_hold() {
    let mut scheduler = PrefetchScheduler::new(BUDGET).unwrap();
    scheduler
        .start_speculative(op("s1"), &worth(40 * MB), MIB)
        .unwrap();
    scheduler
        .start_speculative(op("s2"), &worth(40 * MB), MIB)
        .unwrap();
    assert_eq!(
        scheduler.start_speculative(op("s3"), &worth(40 * MB), MIB),
        Err(PrefetchError::Refused(
            AdmissionRefusal::SpeculativeBudget {
                requested_bytes: 40 * MB,
                held_bytes: 80 * MB,
                limit_bytes: 100 * MB,
            }
        ))
    );
    scheduler.start_demand(op("d1"), 120 * MB, MIB).unwrap();
    assert_eq!(scheduler.free_bytes(), 56 * MB);
    assert_eq!(
        scheduler.start_speculative(op("s4"), &worth(10 * MB), MIB),
        Err(PrefetchError::Refused(
            AdmissionRefusal::ForegroundReserve {
                requested_bytes: 10 * MB,
                free_bytes: 56 * MB,
                reserved_bytes: 64 * MB,
            }
        ))
    );
    // Demand may use the reserve, but never more than the capacity.
    scheduler.start_demand(op("d2"), 56 * MB, MIB).unwrap();
    assert_eq!(
        scheduler.start_demand(op("d3"), 1, MIB),
        Err(PrefetchError::InsufficientCapacity {
            requested_bytes: 1,
            free_bytes: 0,
        })
    );
    let mut not_worth = worth(MB);
    not_worth.expected_value = -1.0;
    let mut roomy = PrefetchScheduler::new(BUDGET).unwrap();
    assert_eq!(
        roomy.start_speculative(op("n"), &not_worth, MIB),
        Err(PrefetchError::Refused(AdmissionRefusal::NotWorthIt {
            expected_value: -1.0
        }))
    );
    assert!(roomy.start_speculative(op("z"), &worth(0), MIB).is_err());
    assert!(roomy.start_demand(op("z"), MB, 0).is_err());
    roomy.start_demand(op("d"), MB, MIB).unwrap();
    assert_eq!(
        roomy.start_demand(op("d"), MB, MIB),
        Err(PrefetchError::DuplicateTransfer { operation: op("d") })
    );
    assert!(PrefetchScheduler::new(PrefetchBudget {
        reserved_foreground_bytes: 300 * MB,
        ..BUDGET
    })
    .is_err());
}

#[test]
fn the_budget_is_never_exceeded_under_random_operations() {
    let mut rng = SeededRng::new(29);
    let mut scheduler = PrefetchScheduler::new(BUDGET).unwrap();
    let mut names: Vec<OperationId> = Vec::new();
    for step in 0..2000 {
        let action = rng.next_u64() % 6;
        let size = (1 + rng.next_u64() % 60) * MB;
        let pick = |rng: &mut SeededRng, names: &[OperationId]| {
            (!names.is_empty())
                .then(|| names[(rng.next_u64() % names.len() as u64) as usize].clone())
        };
        let before_free = scheduler.free_bytes();
        match action {
            0 => {
                let name = op(&format!("s{step}"));
                if scheduler
                    .start_speculative(name.clone(), &worth(size), 4 * MB)
                    .is_ok()
                {
                    assert!(before_free >= size + BUDGET.reserved_foreground_bytes);
                    names.push(name);
                }
            }
            1 => {
                let name = op(&format!("d{step}"));
                if scheduler.start_demand(name.clone(), size, 4 * MB).is_ok() {
                    names.push(name);
                }
            }
            2 => {
                if let Some(name) = pick(&mut rng, &names) {
                    let remaining = scheduler
                        .transfer(&name)
                        .map_or(0, |t| t.total_bytes() - t.completed_bytes());
                    if remaining > 0 {
                        let bytes = (1 + rng.next_u64() % (12 * MB)).min(remaining);
                        let _ = scheduler.record_progress(&name, bytes);
                    }
                }
            }
            3 => {
                if let Some(name) = pick(&mut rng, &names) {
                    let _ = scheduler.request_cancel(&name);
                }
            }
            4 => {
                if let Some(name) = pick(&mut rng, &names) {
                    let _ = scheduler.promote(&name);
                }
            }
            _ => {
                if let Some(name) = pick(&mut rng, &names) {
                    let _ = scheduler.release(&name);
                }
            }
        }
        assert!(scheduler.speculative_bytes() <= BUDGET.max_speculative_bytes);
        assert!(scheduler.speculative_bytes() + scheduler.demand_bytes() <= BUDGET.capacity_bytes);
        names.retain(|name| scheduler.transfer(name).is_some());
    }
    assert!(scheduler.transfers_started() > 100);
}

#[test]
fn promotion_to_demand_reuses_the_same_transfer() {
    let mut scheduler = PrefetchScheduler::new(BUDGET).unwrap();
    scheduler
        .start_speculative(op("p"), &worth(40 * MB), 4 * MB)
        .unwrap();
    assert_eq!(
        scheduler.record_progress(&op("p"), 10 * MB),
        Ok(Progress::Running {
            completed_bytes: 10 * MB
        })
    );
    scheduler.promote(&op("p")).unwrap();
    let transfer = scheduler.transfer(&op("p")).unwrap();
    assert_eq!(transfer.class(), TransferClass::Demand);
    assert_eq!(transfer.completed_bytes(), 10 * MB);
    assert_eq!(transfer.total_bytes(), 40 * MB);
    assert_eq!(scheduler.transfers_started(), 1);
    assert_eq!(scheduler.speculative_bytes(), 0);
    assert_eq!(scheduler.demand_bytes(), 40 * MB);
    assert_eq!(
        scheduler.promote(&op("p")),
        Err(PrefetchError::NotSpeculative { operation: op("p") })
    );
    assert_eq!(
        scheduler.promote(&op("missing")),
        Err(PrefetchError::UnknownTransfer {
            operation: op("missing")
        })
    );

    // Promotion withdraws a pending cancellation, and the same transfer completes.
    scheduler
        .start_speculative(op("q"), &worth(10 * MB), 4 * MB)
        .unwrap();
    scheduler.record_progress(&op("q"), MB).unwrap();
    assert!(matches!(
        scheduler.request_cancel(&op("q")),
        Ok(CancelOutcome::Deferred { .. })
    ));
    scheduler.promote(&op("q")).unwrap();
    assert_eq!(
        scheduler.transfer(&op("q")).unwrap().state(),
        TransferState::Running
    );
    assert_eq!(
        scheduler.record_progress(&op("q"), 9 * MB),
        Ok(Progress::Complete)
    );
    assert_eq!(scheduler.transfers_started(), 2);
    scheduler.release(&op("q")).unwrap();
    assert!(scheduler.transfer(&op("q")).is_none());
}

#[test]
fn cancellation_happens_only_at_block_boundaries() {
    let mut scheduler = PrefetchScheduler::new(PrefetchBudget {
        max_speculative_bytes: 100 * MIB,
        capacity_bytes: 256 * MIB,
        reserved_foreground_bytes: 0,
    })
    .unwrap();
    scheduler
        .start_speculative(op("c"), &worth(20 * MIB), 4 * MIB)
        .unwrap();
    scheduler.record_progress(&op("c"), 6 * MIB).unwrap();
    // Mid-block: the request is deferred and nothing stops at 6 MiB.
    assert_eq!(
        scheduler.request_cancel(&op("c")),
        Ok(CancelOutcome::Deferred {
            boundary_bytes: 8 * MIB
        })
    );
    let pending = scheduler.transfer(&op("c")).unwrap();
    assert_eq!(pending.state(), TransferState::CancelRequested);
    assert_eq!(pending.completed_bytes(), 6 * MIB);
    assert_eq!(scheduler.speculative_bytes(), 20 * MIB);
    assert_eq!(
        scheduler.record_progress(&op("c"), MIB),
        Ok(Progress::Running {
            completed_bytes: 7 * MIB
        })
    );
    assert_eq!(
        scheduler.record_progress(&op("c"), 3 * MIB),
        Ok(Progress::Cancelled {
            at_bytes: 8 * MIB,
            accepted_bytes: MIB
        })
    );
    assert!(scheduler.transfer(&op("c")).is_none());
    assert_eq!(scheduler.speculative_bytes(), 0);

    // On a boundary the cancellation takes effect at once.
    scheduler
        .start_speculative(op("b"), &worth(20 * MIB), 4 * MIB)
        .unwrap();
    scheduler.record_progress(&op("b"), 8 * MIB).unwrap();
    assert_eq!(
        scheduler.request_cancel(&op("b")),
        Ok(CancelOutcome::Stopped { at_bytes: 8 * MIB })
    );

    // The end of a partial final block is a boundary too.
    scheduler
        .start_speculative(op("e"), &worth(10 * MIB), 4 * MIB)
        .unwrap();
    scheduler.record_progress(&op("e"), 9 * MIB).unwrap();
    assert_eq!(
        scheduler.request_cancel(&op("e")),
        Ok(CancelOutcome::Deferred {
            boundary_bytes: 10 * MIB
        })
    );

    scheduler.start_demand(op("f"), 4 * MIB, 4 * MIB).unwrap();
    assert_eq!(
        scheduler.record_progress(&op("f"), 4 * MIB),
        Ok(Progress::Complete)
    );
    assert_eq!(
        scheduler.request_cancel(&op("f")),
        Err(PrefetchError::AlreadyComplete { operation: op("f") })
    );
    assert!(scheduler.record_progress(&op("e"), 2 * MIB).is_err());
    assert_eq!(
        scheduler.release(&op("e")),
        Err(PrefetchError::NotComplete { operation: op("e") })
    );
}

#[test]
fn low_confidence_returns_to_demand_only_scheduling_and_back() {
    let mut controller = ModeController::new(ModeThresholds {
        enter_below_confidence: 0.5,
        exit_at_confidence: 0.7,
        enter_above_load_fraction: 0.9,
        exit_at_load_fraction: 0.7,
        enter_above_calibration_error: 0.15,
        exit_at_calibration_error: 0.05,
        recovery_dwell: Duration::from_secs(5),
    })
    .unwrap();
    let mut scheduler = PrefetchScheduler::new(BUDGET).unwrap();
    scheduler
        .start_speculative(op("mid"), &worth(20 * MB), 4 * MB)
        .unwrap();
    scheduler.record_progress(&op("mid"), 6 * MB).unwrap();
    scheduler
        .start_speculative(op("edge"), &worth(20 * MB), 4 * MB)
        .unwrap();
    scheduler.record_progress(&op("edge"), 8 * MB).unwrap();
    scheduler
        .start_demand(op("demand"), 20 * MB, 4 * MB)
        .unwrap();

    let low = ModeSignals {
        confidence: 0.3,
        load_fraction: 0.2,
        calibration_error: 0.01,
    };
    let mode = controller
        .observe(MonotonicTime::from_nanos(0), low)
        .unwrap();
    assert_eq!(mode, SchedulingMode::DemandOnly);
    let cancelled = scheduler.set_mode(mode);
    assert_eq!(
        cancelled,
        vec![
            (op("edge"), CancelOutcome::Stopped { at_bytes: 8 * MB }),
            (
                op("mid"),
                CancelOutcome::Deferred {
                    boundary_bytes: 8 * MB
                }
            ),
        ]
    );
    assert_eq!(
        scheduler.start_speculative(op("new"), &worth(MB), 4 * MB),
        Err(PrefetchError::Refused(AdmissionRefusal::DemandOnly))
    );
    scheduler
        .start_demand(op("still-served"), MB, 4 * MB)
        .unwrap();
    assert_eq!(
        scheduler.transfer(&op("demand")).unwrap().state(),
        TransferState::Running
    );

    let healthy = ModeSignals {
        confidence: 0.9,
        ..low
    };
    let seconds = |s: u64| MonotonicTime::from_nanos(s * 1_000_000_000);
    assert_eq!(
        controller.observe(seconds(1), healthy),
        Ok(SchedulingMode::DemandOnly)
    );
    let mode = controller.observe(seconds(6), healthy).unwrap();
    assert_eq!(mode, SchedulingMode::Speculative);
    assert!(scheduler.set_mode(mode).is_empty());
    scheduler
        .start_speculative(op("again"), &worth(MB), 4 * MB)
        .unwrap();
}
