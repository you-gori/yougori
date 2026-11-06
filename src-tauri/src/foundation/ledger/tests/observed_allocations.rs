//! Observed allocations per owner (S03): use beyond a reservation is counted, flagged and
//! refused further growth until observed back within its entitlement; unused amounts are
//! recorded and returned only by an explicit reconciliation; an observation needs the
//! authority of a release and applies whole or not at all; a child's use beyond its
//! parent's room grows the parent only for a source with the parent's authority; and
//! closed, unknown and uncreated owners are handled.

use std::collections::BTreeMap;

use super::*;

fn gpu_bytes(bytes: u64) -> Amounts {
    Amounts::new().vram_bytes(gpu(0), bytes)
}

fn observation(source: SourceClass, usage: &[(ReservationId, u64)]) -> AllocationObservation {
    AllocationObservation {
        source,
        usage: usage
            .iter()
            .map(|(reservation, bytes)| (*reservation, gpu_bytes(*bytes)))
            .collect::<BTreeMap<_, _>>(),
    }
}

fn created(ledger: &mut Ledger<&ManualClock>, request: ReservationRequest) -> ReservationId {
    let reservation = granted(ledger.reserve(request));
    ledger.begin_create(reservation).unwrap();
    reservation
}

#[test]
fn use_beyond_a_reservation_is_counted_flagged_and_grows_no_further() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let runtime = created(&mut ledger, on_gpu("exe-rt", Priority::Foreground, 10 * GB));
    assert_eq!(ledger.available(vram(0)), Some(13 * GB));

    let report = ledger
        .observe_allocations(observation(SourceClass::HostProbe, &[(runtime, 12 * GB)]))
        .unwrap();
    assert_eq!(
        report.findings,
        vec![OwnerFinding {
            reservation: runtime,
            over: gpu_bytes(2 * GB),
            uncounted: Amounts::new(),
            under: Amounts::new(),
            grew: Vec::new(),
        }]
    );
    // Counted, never ignored: the memory in use is not free.
    let record = ledger.reservation(runtime).unwrap();
    assert_eq!(record.current(), &gpu_bytes(12 * GB));
    assert!(record.overrun());
    assert_eq!(
        record.history().last().map(|change| change.cause),
        Some(ChangeCause::OverUseCounted {
            source: SourceClass::HostProbe
        })
    );
    assert_eq!(ledger.available(vram(0)), Some(11 * GB));
    let flag = ledger.over_use(runtime).unwrap();
    assert_eq!(
        (flag.entitled.clone(), flag.excess.clone(), flag.since),
        (gpu_bytes(10 * GB), gpu_bytes(2 * GB), clock.now())
    );
    // Nothing more is carved from it or grown on it.
    let refusal = match ledger.reserve(on_gpu("exe-rt", Priority::Foreground, GB).within(runtime)) {
        Err(LedgerError::Ownership(refusal)) => refusal,
        other => panic!("expected a growth refusal, got {other:?}"),
    };
    assert_eq!(
        refusal,
        OwnershipError::GrowthRefused {
            reservation: runtime,
            reason: GrowthRefusal::OverUse {
                excess: gpu_bytes(2 * GB)
            },
        }
    );
    assert!(refusal
        .to_string()
        .contains("observed using more than it reserved"));
    assert!(matches!(
        ledger.begin_transition_peak(runtime, gpu_bytes(GB), MINUTE),
        Err(LedgerError::Ownership(OwnershipError::GrowthRefused { .. }))
    ));

    // Back within its entitlement: the flag clears; the counted amounts stay until an
    // explicit reconciliation returns them.
    clock.advance(SECOND);
    let report = ledger
        .observe_allocations(observation(SourceClass::HostProbe, &[(runtime, 9 * GB)]))
        .unwrap();
    assert_eq!(report.findings[0].under, gpu_bytes(3 * GB));
    assert!(ledger.over_use(runtime).is_none());
    assert_eq!(
        ledger.reservation(runtime).unwrap().current(),
        &gpu_bytes(12 * GB)
    );
    granted(ledger.reserve(on_gpu("exe-rt", Priority::Foreground, GB).within(runtime)));
    let outcome = ledger
        .reconcile(runtime, observed(SourceClass::HostProbe, gpu_bytes(9 * GB)))
        .unwrap();
    assert_eq!(outcome.released, gpu_bytes(3 * GB));
    assert_eq!(ledger.available(vram(0)), Some(14 * GB));
}

#[test]
fn unused_amounts_are_recorded_and_never_returned_by_an_observation() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let runtime = created(&mut ledger, on_gpu("exe-rt", Priority::Foreground, 10 * GB));
    let report = ledger
        .observe_allocations(observation(SourceClass::HostProbe, &[(runtime, 6 * GB)]))
        .unwrap();
    assert_eq!(report.findings[0].under, gpu_bytes(4 * GB));
    assert!(report.findings[0].over.is_empty());
    let under = ledger.under_use(runtime).unwrap();
    assert_eq!(
        (under.unused.clone(), under.source, under.observed_at),
        (gpu_bytes(4 * GB), SourceClass::HostProbe, clock.now())
    );
    let record = ledger.reservation(runtime).unwrap();
    assert_eq!(record.current(), &gpu_bytes(10 * GB));
    assert_eq!(record.history().len(), 1);
    assert_eq!(
        record
            .observation_from(SourceClass::HostProbe)
            .map(|seen| seen.in_use.clone()),
        Some(gpu_bytes(6 * GB))
    );
    assert_eq!(ledger.available(vram(0)), Some(13 * GB));
    assert!(ledger.over_use(runtime).is_none());
    // A later observation in full use clears the record of unused amounts.
    ledger
        .observe_allocations(observation(SourceClass::HostProbe, &[(runtime, 10 * GB)]))
        .unwrap();
    assert!(ledger.under_use(runtime).is_none());
    assert_eq!(ledger.under_uses().count(), 0);
}

#[test]
fn an_observation_needs_the_authority_of_a_release_and_applies_whole() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let runtime = created(&mut ledger, on_gpu("exe-rt", Priority::Foreground, 10 * GB));
    let child = created(
        &mut ledger,
        on_gpu("exe-rt", Priority::Foreground, 4 * GB).within(runtime),
    );
    // A runtime's report about the host-level runtime is refused, and with it the part
    // about its child: nothing changes.
    assert_eq!(
        ledger.observe_allocations(observation(
            SourceClass::GuestReport,
            &[(runtime, 12 * GB), (child, 6 * GB)]
        )),
        Err(LedgerError::SourceNotAuthoritative {
            source: SourceClass::GuestReport,
            required: SourceClass::HostProbe,
        })
    );
    assert_eq!(
        ledger.reservation(child).unwrap().current(),
        &gpu_bytes(4 * GB)
    );
    assert!(ledger.reservation(child).unwrap().observations().is_empty());
    assert_eq!(ledger.over_uses().count(), 0);
    // A fixture is never authority, even for a child.
    assert!(matches!(
        ledger.observe_allocations(observation(SourceClass::Fixture, &[(child, GB)])),
        Err(LedgerError::SourceNotAuthoritative { .. })
    ));
    // The runtime's own report about its child is enough for the child.
    let report = ledger
        .observe_allocations(observation(SourceClass::GuestReport, &[(child, 3 * GB)]))
        .unwrap();
    assert_eq!(report.findings[0].under, gpu_bytes(GB));

    // Uncreated, closed and unknown owners.
    let planned = granted(ledger.reserve(on_gpu("exe-p", Priority::Foreground, GB)));
    assert_eq!(
        ledger.observe_allocations(observation(SourceClass::HostProbe, &[(planned, GB)])),
        Err(LedgerError::InvalidTransition {
            reservation: planned,
            state: ReservationState::Granted,
            transition: Transition::Reconcile,
        })
    );
    ledger.cancel(planned).unwrap();
    let report = ledger
        .observe_allocations(observation(
            SourceClass::HostProbe,
            &[(planned, GB), (runtime, 10 * GB)],
        ))
        .unwrap();
    assert_eq!(report.closed, vec![planned]);
    assert_eq!(report.findings.len(), 1);
}

#[test]
fn a_childs_use_beyond_its_parents_room_grows_the_parent_only_with_its_authority() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let runtime = created(&mut ledger, on_gpu("exe-rt", Priority::Foreground, 10 * GB));
    let first = created(
        &mut ledger,
        on_gpu("exe-rt", Priority::Foreground, 6 * GB).within(runtime),
    );
    let second = created(
        &mut ledger,
        on_gpu("exe-rt", Priority::Foreground, 3 * GB).within(runtime),
    );
    assert_eq!(ledger.parent_room(runtime, vram(0)), Ok(GB));

    // The runtime's report: the child fills its parent's room and no more; the host-level
    // runtime is flagged, not grown, since only the host observes host capacity.
    let report = ledger
        .observe_allocations(observation(SourceClass::GuestReport, &[(first, 8 * GB)]))
        .unwrap();
    assert_eq!(
        report.findings,
        vec![OwnerFinding {
            reservation: first,
            over: gpu_bytes(2 * GB),
            uncounted: gpu_bytes(GB),
            under: Amounts::new(),
            grew: Vec::new(),
        }]
    );
    assert_eq!(
        ledger.reservation(first).unwrap().current(),
        &gpu_bytes(7 * GB)
    );
    assert_eq!(
        ledger.reservation(runtime).unwrap().current(),
        &gpu_bytes(10 * GB)
    );
    assert_eq!(ledger.available(vram(0)), Some(13 * GB));
    assert_eq!(ledger.over_use(first).unwrap().excess, gpu_bytes(2 * GB));
    assert_eq!(ledger.over_use(runtime).unwrap().excess, gpu_bytes(GB));
    assert!(matches!(
        ledger.reserve(on_gpu("exe-rt", Priority::Foreground, GB).within(second)),
        Err(LedgerError::Ownership(OwnershipError::GrowthRefused { reservation, .. }))
            if reservation == runtime
    ));

    // The host observes the same: the runtime grows, counted against the host.
    clock.advance(SECOND);
    let report = ledger
        .observe_allocations(observation(SourceClass::HostProbe, &[(first, 8 * GB)]))
        .unwrap();
    assert_eq!(report.findings[0].grew, vec![runtime]);
    assert!(report.findings[0].uncounted.is_empty());
    assert_eq!(
        ledger.reservation(first).unwrap().current(),
        &gpu_bytes(8 * GB)
    );
    assert_eq!(
        ledger.reservation(runtime).unwrap().current(),
        &gpu_bytes(11 * GB)
    );
    assert_eq!(ledger.parent_room(runtime, vram(0)), Ok(0));
    assert_eq!(ledger.available(vram(0)), Some(12 * GB));
    let flag = ledger.over_use(runtime).unwrap();
    assert_eq!(
        (flag.entitled.clone(), flag.excess.clone()),
        (gpu_bytes(10 * GB), gpu_bytes(GB))
    );
    assert_invariants(&ledger);

    // An authoritative reconciliation back within its entitlement clears the flag.
    ledger
        .reconcile(first, observed(SourceClass::HostProbe, gpu_bytes(6 * GB)))
        .unwrap();
    ledger
        .reconcile(
            runtime,
            observed(SourceClass::HostProbe, gpu_bytes(10 * GB)),
        )
        .unwrap();
    assert!(ledger.over_use(runtime).is_none());
    assert_eq!(ledger.available(vram(0)), Some(13 * GB));
    // Closing forgets what was observed.
    ledger.cancel(runtime).unwrap();
    ledger
        .confirm_release(runtime, SourceClass::HostProbe)
        .unwrap();
    assert_eq!(ledger.over_uses().count(), 0);
    assert_eq!(ledger.under_uses().count(), 0);
}
