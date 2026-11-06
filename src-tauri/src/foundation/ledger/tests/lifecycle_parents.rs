//! Lifecycle-owned parents (S03; CORE-03 parent budgets bound to CORE-04's lifecycles): a
//! draining lifecycle refuses new growth while what it holds runs; an ended or revoked one
//! releases its parents with everything carved from them, counted until observed when
//! created; ownership keeps the lifecycle's tenant and execution; a waiting owned request
//! is owned once granted and refused when its lifecycle stops; nested lifecycles end with
//! their parent's; and seeded random operations never leave a child without its parent.

use super::*;
use crate::foundation::ids::{ModelActivationGeneration, SandboxBootGeneration};

fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

fn boot(name: &str, generation: u64) -> Lifecycle {
    Lifecycle::sandbox_boot(
        tenant("alpha"),
        execution(name),
        SandboxBootGeneration::new(generation),
    )
}

fn activation(name: &str, generation: u64) -> Lifecycle {
    Lifecycle::model_activation(
        tenant("alpha"),
        execution(name),
        digest("yougori/test/model/v1", &[b"model"]),
        ModelActivationGeneration::new(generation),
    )
}

fn vm_request(name: &str, bytes: u64) -> ReservationRequest {
    ReservationRequest::new(
        provenance(Requester::VmLifecycle, name, "alpha"),
        Priority::Foreground,
        Amounts::new().host_ram_bytes(bytes),
    )
}

fn part(name: &str, bytes: u64, parent: ReservationId) -> ReservationRequest {
    ReservationRequest::new(
        provenance(Requester::ModelPlacement, name, "alpha"),
        Priority::Foreground,
        Amounts::new().host_ram_bytes(bytes),
    )
    .within(parent)
}

fn growth_refused(result: Result<Admission, LedgerError>) -> (ReservationId, GrowthRefusal) {
    match result {
        Err(LedgerError::Ownership(OwnershipError::GrowthRefused {
            reservation,
            reason,
        })) => (reservation, reason),
        other => panic!("expected a growth refusal, got {other:?}"),
    }
}

/// No open reservation outlives its parent, and nothing under a releasing parent is
/// granted or in use.
fn assert_no_orphans<C: Clock>(ledger: &Ledger<C>) {
    for record in ledger.open_reservations() {
        let Some(parent) = record.parent() else {
            continue;
        };
        let parent = ledger
            .reservation(parent)
            .unwrap_or_else(|| panic!("{} outlived its parent", record.id()));
        if parent.state() == ReservationState::Releasing {
            assert_eq!(
                record.state(),
                ReservationState::Releasing,
                "{} runs under a releasing parent",
                record.id()
            );
        }
    }
}

fn closed_reason<C: Clock>(ledger: &Ledger<C>, reservation: ReservationId) -> CloseReason {
    ledger
        .closed_records()
        .iter()
        .find(|record| record.id() == reservation)
        .and_then(ReservationRecord::close_reason)
        .unwrap()
}

#[test]
fn a_draining_lifecycle_refuses_new_growth_while_what_it_holds_runs() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let lifecycle = boot("exe-vm", 1);
    let vm = granted(ledger.reserve_owned(vm_request("exe-vm", 8 * GIB), lifecycle.clone()));
    assert_eq!(ledger.lifecycle_of(vm), Some(&lifecycle));
    assert_eq!(
        ledger.lifecycle_status(&lifecycle),
        Some(LifecycleStatus::Live)
    );
    ledger.begin_create(vm).unwrap();
    let model = granted(ledger.reserve(part("exe-vm", 4 * GIB, vm)));
    ledger.begin_create(model).unwrap();
    let waiting = queued(ledger.reserve(part("exe-vm", 6 * GIB, vm).wait_up_to(MINUTE)));
    ledger.drain_events();

    clock.advance(SECOND);
    let report = ledger.end_lifecycle(&lifecycle, LifecycleEnd::Draining);
    let draining = LifecycleStatus::Draining { since: clock.now() };
    assert_eq!(report.status, draining);
    assert_eq!(report.parents, vec![vm]);
    assert!(report.released.is_empty() && report.releasing.is_empty());

    // Nothing new is carved from the parent, or from anything carved from it.
    let (at, reason) = growth_refused(ledger.reserve(part("exe-vm", GIB, vm)));
    assert_eq!(at, vm);
    assert_eq!(
        reason,
        GrowthRefusal::LifecycleDraining {
            lifecycle: lifecycle.clone(),
            since: clock.now()
        }
    );
    assert_eq!(
        growth_refused(ledger.reserve(part("exe-vm", GIB, model))).0,
        vm
    );
    // A transition peak is growth too.
    assert!(matches!(
        ledger.begin_transition_peak(vm, Amounts::new().host_ram_bytes(GIB), MINUTE),
        Err(LedgerError::Ownership(OwnershipError::GrowthRefused { .. }))
    ));
    // The child that was waiting was refused when the queue was served.
    assert_eq!(ledger.queue_position(waiting), None);
    let events = ledger.drain_events();
    assert!(
        events.iter().any(|event| matches!(
            event,
            LedgerEvent::QueueRefused {
                ticket,
                error: LedgerError::Ownership(OwnershipError::GrowthRefused { .. }),
            } if *ticket == waiting
        )),
        "{events:?}"
    );
    assert!(ledger.drain_events().is_empty());
    // What it holds keeps running and is released the usual way.
    assert_eq!(
        ledger.reservation(model).unwrap().state(),
        ReservationState::InUse
    );
    assert_eq!(
        ledger.reservation(vm).unwrap().state(),
        ReservationState::InUse
    );
    // Nothing new binds to it.
    assert_eq!(
        ledger.reserve_owned(vm_request("exe-vm", GIB), lifecycle.clone()),
        Err(LedgerError::Ownership(OwnershipError::LifecycleNotLive {
            lifecycle: lifecycle.clone(),
            status: draining,
        }))
    );
    assert_eq!(ledger.cancel(model), Ok(ReleaseOutcome::Pending));
    ledger
        .confirm_release(model, SourceClass::GuestReport)
        .unwrap();
    assert_eq!(ledger.parent_room(vm, RAM), Ok(8 * GIB));
    assert_no_orphans(&ledger);
    assert_invariants(&ledger);
}

#[test]
fn ending_a_lifecycle_releases_its_parents_with_everything_carved_from_them() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let free = ledger.available(RAM).unwrap();
    let lifecycle = boot("exe-vm", 1);
    let vm = granted(ledger.reserve_owned(vm_request("exe-vm", 8 * GIB), lifecycle.clone()));
    ledger.begin_create(vm).unwrap();
    let running = granted(ledger.reserve(part("exe-vm", 4 * GIB, vm)));
    ledger.begin_create(running).unwrap();
    let nested = granted(ledger.reserve(part("exe-vm", GIB, running)));
    ledger.begin_create(nested).unwrap();
    let planned = granted(ledger.reserve(part("exe-vm", 2 * GIB, vm)));

    let report = ledger.end_lifecycle(&lifecycle, LifecycleEnd::Completed);
    let ended = LifecycleStatus::Ended {
        end: LifecycleEnd::Completed,
        at: clock.now(),
    };
    assert_eq!(report.status, ended);
    assert_eq!(report.parents, vec![vm]);
    assert_eq!(report.releasing, vec![vm]);
    assert!(report.released.is_empty() && report.withdrawn.is_empty());
    // The child never created closed at once; what exists is releasing, counted until
    // the host observes the release.
    assert!(ledger.reservation(planned).is_none());
    assert_eq!(
        closed_reason(&ledger, planned),
        CloseReason::ParentClosed { parent: vm }
    );
    for reservation in [vm, running, nested] {
        assert_eq!(
            ledger.reservation(reservation).unwrap().state(),
            ReservationState::Releasing
        );
    }
    assert_eq!(ledger.available(RAM), Some(free - 8 * GIB));
    assert_eq!(
        ledger.reserve(part("exe-vm", GIB, running)),
        Err(LedgerError::ParentNotOpen { parent: running })
    );
    assert_no_orphans(&ledger);

    ledger.confirm_release(vm, SourceClass::HostProbe).unwrap();
    assert!(ledger.open_reservations().next().is_none());
    assert_eq!(ledger.available(RAM), Some(free));
    for reservation in [running, nested] {
        assert!(matches!(
            closed_reason(&ledger, reservation),
            CloseReason::ParentClosed { .. }
        ));
    }
    // Ending it again changes nothing, and it stays ended.
    let again = ledger.end_lifecycle(&lifecycle, LifecycleEnd::Revoked);
    assert_eq!(again.status, ended);
    assert!(again.parents.is_empty());
    assert_eq!(ledger.lifecycle_status(&lifecycle), Some(ended));
    let late = granted(ledger.reserve(vm_request("exe-vm", GIB)));
    assert_eq!(
        ledger.bind_lifecycle(late, lifecycle.clone()),
        Err(LedgerError::Ownership(OwnershipError::LifecycleNotLive {
            lifecycle,
            status: ended,
        }))
    );
}

#[test]
fn revoking_a_lifecycle_before_creation_returns_everything_at_once() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let lifecycle = activation("exe-rt", 1);
    let parent = granted(ledger.reserve_owned(
        on_gpu("exe-rt", Priority::Foreground, 10 * GB),
        lifecycle.clone(),
    ));
    let child =
        granted(ledger.reserve(on_gpu("exe-rt", Priority::Foreground, 4 * GB).within(parent)));
    assert_eq!(ledger.available(vram(0)), Some(13 * GB));

    let report = ledger.end_lifecycle(&lifecycle, LifecycleEnd::Revoked);
    assert_eq!(report.released, vec![parent]);
    assert!(report.releasing.is_empty());
    assert_eq!(ledger.available(vram(0)), Some(23 * GB));
    assert_eq!(
        closed_reason(&ledger, parent),
        CloseReason::CancelledBeforeCreate
    );
    assert_eq!(
        closed_reason(&ledger, child),
        CloseReason::ParentClosed { parent }
    );
    assert!(ledger.lifecycle_parents(&lifecycle).is_empty());
}

#[test]
fn an_owned_parent_keeps_its_lifecycles_tenant_and_execution() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let lifecycle = boot("exe-vm", 1);
    let other_tenant = Lifecycle::sandbox_boot(
        tenant("beta"),
        execution("exe-vm"),
        SandboxBootGeneration::FIRST,
    );
    assert_eq!(
        ledger.reserve_owned(vm_request("exe-vm", GIB), other_tenant),
        Err(LedgerError::Ownership(OwnershipError::LifecycleMismatch {
            field: ParentField::Tenant
        }))
    );
    assert_eq!(
        ledger.reserve_owned(vm_request("exe-other", GIB), lifecycle.clone()),
        Err(LedgerError::Ownership(OwnershipError::LifecycleMismatch {
            field: ParentField::Execution
        }))
    );
    assert_eq!(ledger.reserved(RAM), 0);

    let vm = granted(ledger.reserve(vm_request("exe-vm", GIB)));
    ledger.bind_lifecycle(vm, lifecycle.clone()).unwrap();
    // Idempotent for its owner; another lifecycle of the same execution is refused.
    ledger.bind_lifecycle(vm, lifecycle.clone()).unwrap();
    assert_eq!(
        ledger.bind_lifecycle(vm, boot("exe-vm", 2)),
        Err(LedgerError::Ownership(OwnershipError::AlreadyOwned {
            reservation: vm,
            lifecycle: lifecycle.clone(),
        }))
    );
    // Something releasing or closed is not bound.
    ledger.begin_create(vm).unwrap();
    ledger.cancel(vm).unwrap();
    assert_eq!(
        ledger.bind_lifecycle(vm, boot("exe-vm", 3)),
        Err(LedgerError::ParentNotOpen { parent: vm })
    );
    ledger.confirm_release(vm, SourceClass::HostProbe).unwrap();
    assert_eq!(
        ledger.bind_lifecycle(vm, boot("exe-vm", 3)),
        Err(LedgerError::Closed { reservation: vm })
    );
    assert_eq!(ledger.lifecycle_of(vm), None);
    // A lifecycle that owns nothing open is forgotten while live.
    assert_eq!(ledger.lifecycle_status(&lifecycle), None);
}

#[test]
fn a_waiting_owned_request_is_owned_once_granted_and_refused_when_its_lifecycle_stops() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let blocker = granted(ledger.reserve(on_gpu("exe-other", Priority::Foreground, 20 * GB)));
    let first = activation("exe-rt", 1);
    let ticket = queued(ledger.reserve_owned(
        on_gpu("exe-rt", Priority::Foreground, 10 * GB).wait_up_to(MINUTE),
        first.clone(),
    ));
    assert_eq!(ledger.lifecycle_status(&first), Some(LifecycleStatus::Live));
    assert!(ledger.lifecycle_parents(&first).is_empty());

    // Granted when the blocker goes, and owned from that moment.
    ledger.cancel(blocker).unwrap();
    let reservation = ledger
        .open_reservations()
        .find(|record| record.ticket() == Some(ticket))
        .map(ReservationRecord::id)
        .unwrap();
    assert_eq!(ledger.lifecycle_of(reservation), Some(&first));
    assert_eq!(ledger.lifecycle_parents(&first), vec![reservation]);
    assert_eq!(
        ledger.bind_lifecycle(reservation, activation("exe-rt", 9)),
        Err(LedgerError::Ownership(OwnershipError::AlreadyOwned {
            reservation,
            lifecycle: first.clone(),
        }))
    );
    ledger.tick();
    assert_eq!(ledger.lifecycle_of(reservation), Some(&first));

    // A second generation's request waits, and is refused when that generation drains.
    let blocker = granted(ledger.reserve(on_gpu("exe-other", Priority::Foreground, 13 * GB)));
    let second = activation("exe-rt", 2);
    let waiting = queued(ledger.reserve_owned(
        on_gpu("exe-rt", Priority::Foreground, 5 * GB).wait_up_to(MINUTE),
        second.clone(),
    ));
    let report = ledger.end_lifecycle(&second, LifecycleEnd::Draining);
    assert_eq!(report.withdrawn, vec![waiting]);
    assert!(report.parents.is_empty());
    assert_eq!(ledger.queue_position(waiting), None);
    assert!(ledger.drain_events().iter().any(|event| matches!(
        event,
        LedgerEvent::QueueRefused {
            ticket,
            error: LedgerError::Ownership(OwnershipError::LifecycleNotLive { .. }),
        } if *ticket == waiting
    )));
    ledger.cancel(blocker).unwrap();
    assert_eq!(ledger.reserved(vram(0)), 10 * GB);

    // The first generation ends: its parent, never created, returns at once.
    let report = ledger.end_lifecycle(&first, LifecycleEnd::Completed);
    assert_eq!(report.released, vec![reservation]);
    assert_eq!(ledger.reserved(vram(0)), 0);
}

#[test]
fn an_activation_inside_a_boot_drains_alone_and_ends_with_the_boot() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let sandbox = boot("exe-vm", 1);
    let vm = granted(ledger.reserve_owned(vm_request("exe-vm", 8 * GIB), sandbox.clone()));
    ledger.begin_create(vm).unwrap();
    let model_lifecycle = Lifecycle::model_activation(
        tenant("alpha"),
        execution("exe-vm"),
        digest("yougori/test/model/v1", &[b"model"]),
        ModelActivationGeneration::FIRST,
    );
    let model = granted(ledger.reserve_owned(part("exe-vm", 4 * GIB, vm), model_lifecycle.clone()));
    ledger.begin_create(model).unwrap();
    let kv = granted(ledger.reserve(part("exe-vm", GIB, model)));
    ledger.begin_create(kv).unwrap();

    // The activation drains: its KV runs on, nothing new is carved from it, and the
    // boot's parent still serves other work.
    ledger.end_lifecycle(&model_lifecycle, LifecycleEnd::Draining);
    assert_eq!(
        growth_refused(ledger.reserve(part("exe-vm", GIB, model))).0,
        model
    );
    let tool = granted(ledger.reserve(part("exe-vm", GIB, vm)));

    // The boot is revoked: everything under it goes.
    let report = ledger.end_lifecycle(&sandbox, LifecycleEnd::Revoked);
    assert_eq!(report.releasing, vec![vm]);
    assert!(ledger.reservation(tool).is_none());
    for reservation in [vm, model, kv] {
        assert_eq!(
            ledger.reservation(reservation).unwrap().state(),
            ReservationState::Releasing
        );
    }
    assert_no_orphans(&ledger);
    // Ending the activation afterwards finds its parent already releasing.
    let report = ledger.end_lifecycle(&model_lifecycle, LifecycleEnd::Completed);
    assert_eq!(report.parents, vec![model]);
    assert_eq!(report.releasing, vec![model]);
    ledger.confirm_release(vm, SourceClass::HostProbe).unwrap();
    assert!(ledger.open_reservations().next().is_none());
    assert_eq!(ledger.reserved(RAM), 0);
}

/// A small deterministic generator for the seeded run.
struct Seeded(u64);

impl Seeded {
    fn next(&mut self, below: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % below
    }
}

#[test]
fn no_child_outlives_its_parent_under_seeded_random_lifecycle_operations() {
    let (mut refused_growth, mut released_parents) = (0u32, 0u32);
    for seed in 1..=24u64 {
        let clock = start();
        let mut ledger = ledger_on(&clock);
        let mut random = Seeded(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let names = ["exe-0", "exe-1", "exe-2"];
        let mut generations = [1u64; 3];
        for _ in 0..300 {
            let slot = usize::try_from(random.next(3)).unwrap();
            let lifecycle = boot(names[slot], generations[slot]);
            let open: Vec<ReservationId> = ledger.open_reservations().map(|r| r.id()).collect();
            let pick = |random: &mut Seeded| {
                (!open.is_empty()).then(|| {
                    open[usize::try_from(random.next(u64::try_from(open.len()).unwrap())).unwrap()]
                })
            };
            match random.next(7) {
                0 => {
                    let bytes = (1 + random.next(4)) * GIB;
                    let _ = ledger.reserve_owned(
                        vm_request(names[slot], bytes).wait_up_to(MINUTE),
                        lifecycle,
                    );
                }
                1 => {
                    if let Some(parent) = pick(&mut random) {
                        let name = ledger
                            .reservation(parent)
                            .unwrap()
                            .provenance()
                            .execution
                            .as_str()
                            .to_owned();
                        let bytes = (1 + random.next(3)) * GIB / 2;
                        if matches!(
                            ledger.reserve(part(&name, bytes, parent)),
                            Err(LedgerError::Ownership(OwnershipError::GrowthRefused { .. }))
                                | Err(LedgerError::ParentNotOpen { .. })
                        ) {
                            refused_growth += 1;
                        }
                    }
                }
                2 => {
                    if let Some(reservation) = pick(&mut random) {
                        let _ = ledger.begin_create(reservation);
                    }
                }
                3 => {
                    if let Some(reservation) = pick(&mut random) {
                        let _ = ledger.cancel(reservation);
                    }
                }
                4 => {
                    if let Some(reservation) = pick(&mut random) {
                        if ledger.reservation(reservation).unwrap().state()
                            == ReservationState::Releasing
                        {
                            ledger
                                .confirm_release(reservation, SourceClass::HostProbe)
                                .unwrap();
                        }
                    }
                }
                5 => {
                    let end = match random.next(3) {
                        0 => LifecycleEnd::Draining,
                        1 => LifecycleEnd::Completed,
                        _ => LifecycleEnd::Revoked,
                    };
                    let report = ledger.end_lifecycle(&lifecycle, end);
                    if end != LifecycleEnd::Draining {
                        generations[slot] += 1;
                        if !report.released.is_empty() || !report.releasing.is_empty() {
                            released_parents += 1;
                        }
                        for parent in report.parents {
                            if let Some(record) = ledger.reservation(parent) {
                                assert_eq!(record.state(), ReservationState::Releasing);
                            }
                        }
                    }
                }
                _ => clock.advance(Duration::from_secs(random.next(90))),
            }
            assert_no_orphans(&ledger);
            assert_invariants(&ledger);
            // Nothing was carved after its lifecycle stopped growing.
            for record in ledger.open_reservations() {
                let mut cursor = record.parent();
                while let Some(ancestor) = cursor {
                    if let Some(owner) = ledger.lifecycle_of(ancestor) {
                        match ledger.lifecycle_status(owner) {
                            Some(LifecycleStatus::Draining { since }) => {
                                assert!(record.granted_at() <= since)
                            }
                            Some(LifecycleStatus::Ended { at, .. }) => {
                                assert!(record.granted_at() <= at)
                            }
                            _ => {}
                        }
                    }
                    cursor = ledger.reservation(ancestor).and_then(|r| r.parent());
                }
            }
        }
    }
    // The run exercised both: growth refused under stopped lifecycles, and parents
    // released with what was carved from them.
    assert!(refused_growth > 0 && released_parents > 0);
}
