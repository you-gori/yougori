//! Transition peaks (S03; GPU part §3.6 step 1): a peak is admitted against the same
//! capacity, physical, the tenant's and the parent's; a generation switch overlaps inside
//! its parent and falls back on completion or rollback, with authority once created; a
//! peak past its window falls back on its own or stays counted and stops growth; a peak
//! is bounded by the steady amounts and its window; a reconciliation ends it; and its
//! time is charged.

use super::*;

fn vram_peak(bytes: u64) -> Amounts {
    Amounts::new().vram_bytes(gpu(0), bytes)
}

fn ownership_error<T: std::fmt::Debug>(result: Result<T, LedgerError>) -> OwnershipError {
    match result {
        Err(LedgerError::Ownership(error)) => error,
        other => panic!("expected an ownership refusal, got {other:?}"),
    }
}

fn held(ledger: &Ledger<&ManualClock>, reservation: ReservationId) -> u64 {
    ledger
        .reservation(reservation)
        .unwrap()
        .current()
        .get(vram(0))
}

#[test]
fn a_transition_peak_is_admitted_against_the_same_capacity() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let steady = granted(ledger.reserve(on_gpu("exe-rt", Priority::Foreground, 10 * GB)));
    ledger.begin_create(steady).unwrap();
    granted(ledger.reserve(on_gpu("exe-other", Priority::Foreground, 8 * GB)));

    // 23 GB grantable, 18 GB held: a 6 GB overlap does not fit, and nothing changes.
    let error = match ledger.begin_transition_peak(steady, vram_peak(6 * GB), MINUTE) {
        Err(LedgerError::Capacity(error)) => error,
        other => panic!("expected a capacity error, got {other:?}"),
    };
    assert_eq!(error.resource(), vram(0));
    assert_eq!(error.limiting().limit, Limit::PhysicalCapacity);
    assert_eq!(
        error.limiting().prospect,
        RetryProspect::FitsAfterRelease { shortfall: GB }
    );
    assert_eq!(error.queue_refusal(), Some(QueueRefusal::NotRequested));
    assert_eq!(held(&ledger, steady), 10 * GB);
    assert!(ledger.transition_peak(steady).is_none());

    // 5 GB fits, at once, and nothing else is granted from the overlap.
    let deadline = ledger
        .begin_transition_peak(steady, vram_peak(5 * GB), MINUTE)
        .unwrap();
    assert_eq!(deadline, clock.now().saturating_add(MINUTE));
    assert_eq!(held(&ledger, steady), 15 * GB);
    assert_eq!(ledger.available(vram(0)), Some(0));
    let peak = ledger.transition_peak(steady).unwrap();
    assert_eq!(peak.peak(), &vram_peak(5 * GB));
    assert_eq!(peak.overdue_since(), None);
    let error = refused(ledger.reserve(on_gpu("exe-x", Priority::Foreground, GB)));
    assert_eq!(error.limiting().limit, Limit::PhysicalCapacity);
    assert_invariants(&ledger);
}

#[test]
fn a_transition_peak_is_charged_to_the_tenant_and_carved_from_the_parent() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    // The tenant's budget limits the peak as it limits any reservation.
    let steady = granted(ledger.reserve(on_gpu("exe-rt", Priority::Foreground, 10 * GB)));
    ledger
        .set_tenant_budget(tenant("alpha"), vram(0), 12 * GB)
        .unwrap();
    let error = match ledger.begin_transition_peak(steady, vram_peak(3 * GB), MINUTE) {
        Err(LedgerError::Capacity(error)) => error,
        other => panic!("expected a capacity error, got {other:?}"),
    };
    assert_eq!(
        error.limiting().limit,
        Limit::TenantBudget {
            tenant: tenant("alpha")
        }
    );
    ledger
        .set_tenant_budget(tenant("alpha"), vram(0), u64::MAX)
        .unwrap();
    ledger.cancel(steady).unwrap();

    // A child's peak comes out of its parent's room, not the host's.
    let runtime = granted(ledger.reserve(on_gpu("exe-rt", Priority::Foreground, 16 * GB)));
    ledger.begin_create(runtime).unwrap();
    let child =
        granted(ledger.reserve(on_gpu("exe-rt", Priority::Foreground, 10 * GB).within(runtime)));
    let error = match ledger.begin_transition_peak(child, vram_peak(7 * GB), MINUTE) {
        Err(LedgerError::Capacity(error)) => error,
        other => panic!("expected a capacity error, got {other:?}"),
    };
    assert_eq!(
        error.limiting().limit,
        Limit::ParentReservation { parent: runtime }
    );
    ledger
        .begin_transition_peak(child, vram_peak(6 * GB), MINUTE)
        .unwrap();
    assert_eq!(ledger.parent_room(runtime, vram(0)), Ok(0));
    assert_eq!(ledger.available(vram(0)), Some(7 * GB));
}

#[test]
fn a_generation_switch_overlaps_inside_its_parent_and_falls_back() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    // A runtime's steady size holds one 10 GB generation and 2 GB besides.
    let runtime = granted(ledger.reserve(on_gpu("exe-rt", Priority::Foreground, 12 * GB)));
    ledger.begin_create(runtime).unwrap();
    let generation = |ledger: &mut Ledger<&ManualClock>| {
        let child = granted(
            ledger.reserve(on_gpu("exe-rt", Priority::Foreground, 10 * GB).within(runtime)),
        );
        ledger.begin_create(child).unwrap();
        child
    };
    let old = generation(&mut ledger);
    let error =
        refused(ledger.reserve(on_gpu("exe-rt", Priority::Foreground, 10 * GB).within(runtime)));
    assert_eq!(
        error.limiting().limit,
        Limit::ParentReservation { parent: runtime }
    );

    // The overlap: the new generation loads while the old one serves.
    ledger
        .begin_transition_peak(runtime, vram_peak(10 * GB), MINUTE)
        .unwrap();
    let new = generation(&mut ledger);
    assert_eq!(ledger.reserved(vram(0)), 22 * GB);
    // Not before the old generation's release is observed.
    assert_eq!(
        ledger.end_transition_peak(runtime, PeakEnd::Completed, SourceClass::HostProbe),
        Err(LedgerError::BelowChildren {
            reservation: runtime,
            resource: vram(0),
            observed: 12 * GB,
            children: 20 * GB,
        })
    );
    assert_eq!(ledger.cancel(old), Ok(ReleaseOutcome::Pending));
    ledger
        .confirm_release(old, SourceClass::GuestReport)
        .unwrap();
    // The runtime exists at host level, so only a host observation ends its peak.
    assert_eq!(
        ledger.end_transition_peak(runtime, PeakEnd::Completed, SourceClass::GuestReport),
        Err(LedgerError::SourceNotAuthoritative {
            source: SourceClass::GuestReport,
            required: SourceClass::HostProbe,
        })
    );
    assert_eq!(
        ledger.end_transition_peak(runtime, PeakEnd::Completed, SourceClass::HostProbe),
        Ok(vram_peak(10 * GB))
    );
    assert_eq!(held(&ledger, runtime), 12 * GB);
    assert_eq!(ledger.available(vram(0)), Some(11 * GB));
    assert!(ledger.transition_peak(runtime).is_none());

    // Another switch rolls back: the candidate goes, the serving generation stays.
    ledger
        .begin_transition_peak(runtime, vram_peak(10 * GB), MINUTE)
        .unwrap();
    let candidate = generation(&mut ledger);
    ledger.cancel(candidate).unwrap();
    ledger
        .confirm_release(candidate, SourceClass::GuestReport)
        .unwrap();
    assert_eq!(
        ledger.end_transition_peak(runtime, PeakEnd::RolledBack, SourceClass::HostProbe),
        Ok(vram_peak(10 * GB))
    );
    assert_eq!(held(&ledger, runtime), 12 * GB);
    assert_eq!(
        ledger.reservation(new).unwrap().state(),
        ReservationState::InUse
    );
    let outcomes: Vec<PeakOutcome> = ledger
        .take_peak_records()
        .into_iter()
        .map(|record| record.outcome)
        .collect();
    assert_eq!(
        outcomes,
        vec![PeakOutcome::Completed, PeakOutcome::RolledBack]
    );
    assert_eq!(
        ownership_error(ledger.end_transition_peak(
            runtime,
            PeakEnd::Completed,
            SourceClass::HostProbe
        )),
        OwnershipError::NoPeak {
            reservation: runtime
        }
    );
    assert_invariants(&ledger);
}

#[test]
fn a_peak_past_its_window_falls_back_or_stays_counted_and_stops_growth() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    // Never created: it falls back on its own.
    let planned = granted(ledger.reserve(on_gpu("exe-a", Priority::Foreground, 6 * GB)));
    ledger
        .begin_transition_peak(planned, vram_peak(4 * GB), MINUTE)
        .unwrap();
    // Created: it stays counted.
    let serving = granted(ledger.reserve(on_gpu("exe-b", Priority::Foreground, 6 * GB)));
    ledger.begin_create(serving).unwrap();
    let deadline = ledger
        .begin_transition_peak(serving, vram_peak(4 * GB), MINUTE)
        .unwrap();
    assert_eq!(ledger.reserved(vram(0)), 20 * GB);

    clock.advance(MINUTE + SECOND);
    ledger.tick();
    assert_eq!(held(&ledger, planned), 6 * GB);
    assert_eq!(held(&ledger, serving), 10 * GB);
    assert_eq!(ledger.reserved(vram(0)), 16 * GB);
    assert_eq!(
        ledger
            .peak_records()
            .last()
            .map(|record| (record.steady, record.outcome)),
        Some((planned, PeakOutcome::Expired))
    );
    let overdue = ledger.transition_peak(serving).unwrap();
    assert_eq!(overdue.overdue_since(), Some(clock.now()));
    // Nothing more is carved from it or grown on it until its end is observed.
    let refusal =
        ownership_error(ledger.reserve(on_gpu("exe-b", Priority::Foreground, GB).within(serving)));
    assert_eq!(
        refusal,
        OwnershipError::GrowthRefused {
            reservation: serving,
            reason: GrowthRefusal::PeakOverdue { deadline },
        }
    );
    assert!(refusal.to_string().contains("transition peak"));
    assert_eq!(
        ledger.end_transition_peak(serving, PeakEnd::Completed, SourceClass::HostProbe),
        Ok(vram_peak(4 * GB))
    );
    granted(ledger.reserve(on_gpu("exe-b", Priority::Foreground, GB).within(serving)));
    assert_eq!(ledger.reserved(vram(0)), 12 * GB);
}

#[test]
fn a_peak_is_bounded_by_the_steady_amounts_and_its_window() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let steady = granted(ledger.reserve(on_gpu("exe-rt", Priority::Foreground, 10 * GB)));
    for window in [Duration::ZERO, MAX_TRANSITION_WINDOW + SECOND] {
        assert_eq!(
            ownership_error(ledger.begin_transition_peak(steady, vram_peak(GB), window)),
            OwnershipError::PeakWindow {
                window,
                max: MAX_TRANSITION_WINDOW
            }
        );
    }
    assert_eq!(
        ownership_error(ledger.begin_transition_peak(steady, vram_peak(11 * GB), MINUTE)),
        OwnershipError::PeakExceedsSteady {
            reservation: steady,
            resource: vram(0),
            peak: 11 * GB,
            steady: 10 * GB,
        }
    );
    assert_eq!(
        ownership_error(ledger.begin_transition_peak(
            steady,
            Amounts::new().host_ram_bytes(GIB),
            MINUTE
        )),
        OwnershipError::PeakExceedsSteady {
            reservation: steady,
            resource: RAM,
            peak: GIB,
            steady: 0,
        }
    );
    assert_eq!(
        ledger.begin_transition_peak(steady, Amounts::new(), MINUTE),
        Err(LedgerError::EmptyDemand)
    );
    ledger
        .begin_transition_peak(steady, vram_peak(10 * GB), MAX_TRANSITION_WINDOW)
        .unwrap();
    assert_eq!(
        ownership_error(ledger.begin_transition_peak(steady, vram_peak(GB), MINUTE)),
        OwnershipError::PeakAlreadyOpen {
            reservation: steady
        }
    );
    let other = granted(ledger.reserve(on_gpu("exe-other", Priority::Foreground, GB)));
    ledger.begin_create(other).unwrap();
    ledger.cancel(other).unwrap();
    assert_eq!(
        ledger.begin_transition_peak(other, vram_peak(GB), MINUTE),
        Err(LedgerError::ParentNotOpen { parent: other })
    );
    // Never created, so it falls back without any authority.
    assert_eq!(
        ledger.end_transition_peak(steady, PeakEnd::RolledBack, SourceClass::Fixture),
        Ok(vram_peak(10 * GB))
    );
}

#[test]
fn a_reconciliation_during_the_peak_ends_it() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let steady = granted(ledger.reserve(on_gpu("exe-rt", Priority::Foreground, 10 * GB)));
    ledger.begin_create(steady).unwrap();
    ledger
        .begin_transition_peak(steady, vram_peak(5 * GB), MINUTE)
        .unwrap();
    ledger
        .reconcile(steady, observed(SourceClass::HostProbe, vram_peak(13 * GB)))
        .unwrap();
    assert_eq!(held(&ledger, steady), 13 * GB);
    assert!(ledger.transition_peak(steady).is_none());
    assert_eq!(
        ledger.peak_records().last().map(|record| record.outcome),
        Some(PeakOutcome::Reconciled)
    );
    // A peak on a reservation that closes ends with it.
    ledger
        .begin_transition_peak(steady, vram_peak(5 * GB), MINUTE)
        .unwrap();
    ledger.cancel(steady).unwrap();
    ledger
        .confirm_release(steady, SourceClass::HostProbe)
        .unwrap();
    assert_eq!(
        ledger.peak_records().last().map(|record| record.outcome),
        Some(PeakOutcome::SteadyClosed)
    );
    assert_eq!(ledger.reserved(vram(0)), 0);
}

#[test]
fn the_time_a_peak_is_held_is_charged() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let began = clock.now();
    let steady = granted(ledger.reserve(on_gpu("exe-rt", Priority::Foreground, 10 * GB)));
    clock.advance(10 * SECOND);
    ledger
        .begin_transition_peak(steady, vram_peak(5 * GB), MINUTE)
        .unwrap();
    clock.advance(10 * SECOND);
    ledger
        .end_transition_peak(steady, PeakEnd::Completed, SourceClass::Fixture)
        .unwrap();
    clock.advance(10 * SECOND);
    let record = ledger.reservation(steady).unwrap();
    let causes: Vec<ChangeCause> = record.history().iter().map(|change| change.cause).collect();
    assert_eq!(
        causes,
        vec![
            ChangeCause::Granted,
            ChangeCause::TransitionPeakBegan,
            ChangeCause::TransitionPeakEnded
        ]
    );
    assert_eq!(
        record.held_amount_nanoseconds(vram(0), clock.now()),
        u128::from(10 * GB) * (30 * SECOND).as_nanos()
            + u128::from(5 * GB) * (10 * SECOND).as_nanos()
    );
    assert_eq!(clock.now().saturating_duration_since(began), 30 * SECOND);
}
