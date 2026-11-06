//! Ledger flows on a manual clock: the INT-01 race, parent/child budgets, the supervisor
//! reserve, actionable errors, the bounded queue, cancellation, reconciliation,
//! observation versus authority, stale host observations, holds, reclamation and
//! provenance.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use super::*;
use crate::foundation::evidence::{GpuDeviceSubject, HostSubject, SourceClass};
use crate::foundation::ids::{
    digest, Clock, Digest, ExecutionId, GpuDeviceKey, ManualClock, MonotonicTime, OperationId,
    TenantId,
};

const GIB: u64 = 1 << 30;
const GB: u64 = 1_000_000_000;
const SECOND: Duration = Duration::from_secs(1);
const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3_600);

const RAM: ResourceKey = ResourceKey::Host(HostResource::Ram);
const PINNED: ResourceKey = ResourceKey::Host(HostResource::PinnedRam);
const NETWORK: ResourceKey = ResourceKey::Host(HostResource::NetworkSlots);
const ROOTS: ResourceKey = ResourceKey::Host(HostResource::BurstVmRoots);
const PAGES: ResourceKey = ResourceKey::Host(HostResource::SnapshotPages);
const STORAGE: ResourceKey = ResourceKey::Host(HostResource::StorageQuota);

fn machine() -> Digest {
    digest("yougori/test/machine/v1", &[b"workstation"])
}

fn host() -> HostSubject {
    HostSubject { machine: machine() }
}

fn gpu_key(index: u8) -> GpuDeviceKey {
    GpuDeviceKey {
        machine: machine(),
        device: digest("yougori/test/gpu/v1", &[&[index]]),
    }
}

fn gpu(index: u8) -> DeviceId {
    DeviceId::from(gpu_key(index))
}

fn vram(index: u8) -> ResourceKey {
    ResourceKey::Vram(gpu(index))
}

fn tenant(name: &str) -> TenantId {
    TenantId::new(name).unwrap()
}

fn provenance(requester: Requester, execution: &str, tenant_name: &str) -> Provenance {
    Provenance {
        requester,
        execution: ExecutionId::new(execution).unwrap(),
        operation: OperationId::new(format!("op-{execution}")).unwrap(),
        tenant: tenant(tenant_name),
        purpose: CostPurpose::Compute,
        retry_number: 0,
    }
}

fn config() -> LedgerConfig {
    LedgerConfig {
        queue: QueueLimits {
            max_entries: 4,
            max_entries_per_tenant: 3,
            max_wait: MINUTE,
        },
        grant_ttl: 5 * MINUTE,
        unmanaged_usage_max_age: HOUR,
    }
}

fn host_probe(total: u64, supervisor_reserve: u64) -> CapacityDeclaration {
    CapacityDeclaration {
        total,
        supervisor_reserve,
        unmanaged_in_use: 0,
        source: SourceClass::HostProbe,
    }
}

fn ledger_on<C: Clock>(clock: C) -> Ledger<C> {
    ledger_with(clock, config())
}

/// 32 GiB host RAM with a 2 GiB supervisor reserve, 8 GiB pinned, 24 GB VRAM on GPU 0
/// with a 1 GB reserve, 4 network slots, 4 VM roots and 1M snapshot pages, all observed
/// now; tenants "alpha" and "beta" have unlimited budgets.
fn ledger_with<C: Clock>(clock: C, config: LedgerConfig) -> Ledger<C> {
    let mut ledger = Ledger::new(clock, host(), config);
    ledger
        .declare_capacity(RAM, host_probe(32 * GIB, 2 * GIB))
        .unwrap();
    ledger
        .declare_capacity(PINNED, host_probe(8 * GIB, 0))
        .unwrap();
    ledger
        .declare_capacity(vram(0), host_probe(24 * GB, GB))
        .unwrap();
    ledger.declare_capacity(NETWORK, host_probe(4, 0)).unwrap();
    ledger.declare_capacity(ROOTS, host_probe(4, 0)).unwrap();
    ledger
        .declare_capacity(PAGES, host_probe(1 << 20, 0))
        .unwrap();
    for name in ["alpha", "beta"] {
        for resource in [RAM, PINNED, vram(0), NETWORK, ROOTS, PAGES] {
            ledger
                .set_tenant_budget(tenant(name), resource, u64::MAX)
                .unwrap();
        }
    }
    ledger
}

fn start() -> ManualClock {
    ManualClock::new(MonotonicTime::from_nanos(1_000))
}

fn vm_start(execution: &str, tenant_name: &str, ram_bytes: u64) -> ReservationRequest {
    ReservationRequest::new(
        provenance(Requester::VmLifecycle, execution, tenant_name),
        Priority::Foreground,
        Amounts::new()
            .host_ram_bytes(ram_bytes)
            .burst_vm_roots(1)
            .network_slots(1),
    )
}

fn model_load(
    execution: &str,
    tenant_name: &str,
    ram_bytes: u64,
    pinned_bytes: u64,
) -> ReservationRequest {
    ReservationRequest::new(
        provenance(Requester::ModelPlacement, execution, tenant_name),
        Priority::Foreground,
        Amounts::new()
            .host_ram_bytes(ram_bytes)
            .pinned_host_ram_bytes(pinned_bytes),
    )
}

fn granted(result: Result<Admission, LedgerError>) -> ReservationId {
    match result {
        Ok(Admission::Granted(reservation)) => reservation,
        other => panic!("expected a grant, got {other:?}"),
    }
}

fn queued(result: Result<Admission, LedgerError>) -> QueueTicket {
    match result {
        Ok(Admission::Queued { ticket, .. }) => ticket,
        other => panic!("expected a queue entry, got {other:?}"),
    }
}

fn refused(result: Result<Admission, LedgerError>) -> CapacityError {
    match result {
        Err(LedgerError::Capacity(error)) => error,
        other => panic!("expected a capacity error, got {other:?}"),
    }
}

fn observed(source: SourceClass, in_use: Amounts) -> UsageObservation {
    UsageObservation { source, in_use }
}

/// Every open child fits its parent, and every host-level total stays within physical
/// capacity unless an authoritative observation found an overrun.
fn assert_invariants<C: Clock>(ledger: &Ledger<C>) {
    for record in ledger.open_reservations() {
        for (resource, _) in record.current().iter() {
            let children: u64 = ledger
                .open_reservations()
                .filter(|child| child.parent() == Some(record.id()))
                .map(|child| child.current().get(resource))
                .sum();
            assert!(
                children <= record.current().get(resource),
                "children exceed {:?}",
                record.id()
            );
        }
    }
    let overrun = ledger.open_reservations().any(|record| record.overrun());
    if !overrun {
        for resource in [RAM, PINNED, vram(0), NETWORK, ROOTS, PAGES] {
            let capacity = ledger.capacity(resource).unwrap();
            assert!(
                ledger.reserved(resource) + capacity.unmanaged_in_use <= capacity.grantable()
                    || capacity.unmanaged_in_use > 0,
                "{resource} is overcommitted"
            );
        }
    }
}

#[test]
fn int01_vm_start_and_model_load_race_never_double_grants() {
    for round in 0..64 {
        let clock = Arc::new(start());
        let ledger = Arc::new(Mutex::new(ledger_on(Arc::clone(&clock))));
        // 20 GiB + 16 GiB of host RAM cannot both fit in the 30 GiB grantable.
        let requests = [
            vm_start("exe-vm", "alpha", 20 * GIB),
            model_load("exe-model", "beta", 16 * GIB, 6 * GIB),
        ];
        let handles: Vec<_> = requests
            .into_iter()
            .map(|request| {
                let ledger = Arc::clone(&ledger);
                thread::spawn(move || ledger.lock().unwrap().reserve(request))
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        let grants = results
            .iter()
            .filter(|result| matches!(result, Ok(Admission::Granted(_))))
            .count();
        assert_eq!(grants, 1, "round {round}: {results:?}");
        let error = results
            .into_iter()
            .find(|result| result.is_err())
            .map(refused)
            .unwrap();
        assert_eq!(error.resource(), RAM);
        assert!(error.retry_can_progress());
        assert!(matches!(
            error.limiting().prospect,
            RetryProspect::FitsAfterRelease { .. }
        ));
        let ledger = ledger.lock().unwrap();
        assert!(ledger.reserved(RAM) <= 30 * GIB);
        assert_invariants(&*ledger);
    }
}

#[test]
fn int01_combined_peaks_count_overlap_once_and_grant_all_or_nothing() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let vm = granted(
        ledger.reserve(ReservationRequest::new(
            provenance(Requester::VmLifecycle, "exe-vm", "alpha"),
            Priority::Foreground,
            Amounts::new()
                .host_ram_bytes(16 * GIB)
                .pinned_host_ram_bytes(2 * GIB),
        )),
    );
    ledger.begin_create(vm).unwrap();
    assert_eq!(ledger.available(RAM), Some(14 * GIB));

    // A model load inside the VM is carved from it and adds nothing to the host totals.
    let inside =
        granted(ledger.reserve(model_load("exe-vm", "alpha", 10 * GIB, 2 * GIB).within(vm)));
    assert_eq!(ledger.available(RAM), Some(14 * GIB));
    assert_eq!(ledger.available(PINNED), Some(6 * GIB));
    assert_eq!(ledger.parent_room(vm, RAM), Ok(6 * GIB));
    assert_eq!(ledger.reservation(inside).unwrap().depth(), 1);

    // A host-side load that needs 20 GiB waits for 6 GiB; nothing is double allocated.
    let error = refused(ledger.reserve(model_load("exe-host", "beta", 20 * GIB, GIB)));
    assert_eq!(error.resource(), RAM);
    assert_eq!(error.limiting().limit, Limit::PhysicalCapacity);
    assert_eq!(
        error.limiting().prospect,
        RetryProspect::FitsAfterRelease { shortfall: 6 * GIB }
    );
    assert_eq!(error.queue_refusal(), Some(QueueRefusal::NotRequested));

    // RAM fits but pinned staging does not: nothing at all is reserved.
    let error = refused(ledger.reserve(model_load("exe-host", "beta", 4 * GIB, 7 * GIB)));
    assert_eq!(error.resource(), PINNED);
    assert_eq!(error.shortfalls().count(), 1);
    assert_eq!(ledger.available(RAM), Some(14 * GIB));
    assert_eq!(ledger.reserved(RAM), 16 * GIB);
    assert_invariants(&ledger);
}

#[test]
fn a_child_cannot_exceed_its_parent() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let parent = granted(ledger.reserve(model_load("exe-rt", "alpha", 8 * GIB, 0)));

    let error = refused(ledger.reserve(model_load("exe-rt", "alpha", 9 * GIB, 0).within(parent)));
    assert_eq!(error.limiting().limit, Limit::ParentReservation { parent });
    assert_eq!(
        error.limiting().prospect,
        RetryProspect::ExceedsLimit { limit: 8 * GIB }
    );
    assert!(!error.retry_can_progress());
    assert_eq!(error.queue_refusal(), Some(QueueRefusal::NotWaitable));

    let child = granted(ledger.reserve(model_load("exe-rt", "alpha", 5 * GIB, 0).within(parent)));
    let error = refused(ledger.reserve(model_load("exe-rt", "alpha", 4 * GIB, 0).within(parent)));
    assert_eq!(
        error.limiting().prospect,
        RetryProspect::FitsAfterRelease { shortfall: GIB }
    );
    assert!(error.retry_can_progress());

    // The parent holds no VRAM, so a child cannot hold any either.
    let vram_child = ReservationRequest::new(
        provenance(Requester::ModelPlacement, "exe-rt", "alpha"),
        Priority::Foreground,
        Amounts::new().vram_bytes(gpu(0), GB),
    )
    .within(parent);
    let error = refused(ledger.reserve(vram_child));
    assert_eq!(error.resource(), vram(0));
    assert_eq!(
        error.limiting().prospect,
        RetryProspect::ExceedsLimit { limit: 0 }
    );

    // A child keeps its parent's tenant, execution and priority.
    let other_tenant = model_load("exe-rt", "beta", GIB, 0).within(parent);
    assert_eq!(
        ledger.reserve(other_tenant),
        Err(LedgerError::ParentMismatch {
            parent,
            field: ParentField::Tenant
        })
    );
    let other_execution = model_load("exe-other", "alpha", GIB, 0).within(parent);
    assert_eq!(
        ledger.reserve(other_execution),
        Err(LedgerError::ParentMismatch {
            parent,
            field: ParentField::Execution
        })
    );
    let mut background = model_load("exe-rt", "alpha", GIB, 0).within(parent);
    background.priority = Priority::Background;
    assert_eq!(
        ledger.reserve(background),
        Err(LedgerError::ParentMismatch {
            parent,
            field: ParentField::Priority
        })
    );

    // A child's observed use cannot grow past its parent's room.
    ledger.begin_create(parent).unwrap();
    ledger.begin_create(child).unwrap();
    assert_eq!(
        ledger.reconcile(
            child,
            observed(
                SourceClass::GuestReport,
                Amounts::new().host_ram_bytes(9 * GIB)
            )
        ),
        Err(LedgerError::ExceedsParent {
            reservation: child,
            parent,
            resource: RAM,
            observed: 9 * GIB,
            room: 8 * GIB,
        })
    );

    // Nesting is bounded.
    let mut deepest = parent;
    for _ in 0..MAX_NESTING_DEPTH {
        deepest = granted(ledger.reserve(model_load("exe-rt", "alpha", 1, 0).within(deepest)));
    }
    assert_eq!(
        ledger.reserve(model_load("exe-rt", "alpha", 1, 0).within(deepest)),
        Err(LedgerError::NestingTooDeep {
            max_depth: MAX_NESTING_DEPTH
        })
    );
    assert_eq!(ledger.reserved(RAM), 8 * GIB);
    assert_invariants(&ledger);
}

#[test]
fn the_supervisor_reserve_is_never_granted() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    // 32 GiB less the 2 GiB reserve leaves 30 GiB grantable.
    let error = refused(ledger.reserve(model_load("exe-a", "alpha", 31 * GIB, 0)));
    assert_eq!(error.limiting().limit, Limit::PhysicalCapacity);
    assert_eq!(
        error.limiting().prospect,
        RetryProspect::ExceedsLimit { limit: 30 * GIB }
    );
    assert!(!error.retry_can_progress());

    granted(ledger.reserve(model_load("exe-a", "alpha", 30 * GIB, 0)));
    assert_eq!(ledger.available(RAM), Some(0));
    for name in ["alpha", "beta"] {
        let error = refused(ledger.reserve(model_load("exe-b", name, 1, 0)));
        assert_eq!(error.limiting().available, 0);
        assert_eq!(
            error.limiting().prospect,
            RetryProspect::FitsAfterRelease { shortfall: 1 }
        );
    }
    assert_eq!(ledger.reserved(RAM), 30 * GIB);
    assert_eq!(
        ledger.declare_capacity(RAM, host_probe(GIB, 2 * GIB)),
        Err(LedgerError::ReserveExceedsCapacity {
            resource: RAM,
            total: GIB,
            supervisor_reserve: 2 * GIB,
        })
    );
}

#[test]
fn capacity_errors_name_the_resource_and_whether_a_retry_helps() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let exceeds = refused(ledger.reserve(model_load("exe-a", "alpha", 40 * GIB, 0)));
    assert_eq!(exceeds.resource(), RAM);
    assert!(!exceeds.retry_can_progress());
    let text = exceeds.to_string();
    assert!(text.contains("host RAM"), "{text}");
    assert!(text.contains("a retry cannot succeed"), "{text}");

    granted(ledger.reserve(model_load("exe-a", "alpha", 28 * GIB, 0)));
    let later = refused(ledger.reserve(model_load("exe-b", "beta", 3 * GIB, 0)));
    assert_eq!(later.resource(), RAM);
    assert!(later.retry_can_progress());
    assert_eq!(later.limiting().available, 2 * GIB);
    let text = later.to_string();
    assert!(text.contains("host RAM"), "{text}");
    assert!(
        text.contains(&format!("fits after {GIB} bytes is released")),
        "{text}"
    );

    // When several resources fall short, the one no retry can fix comes first.
    let both = refused(ledger.reserve(model_load("exe-c", "beta", 3 * GIB, 9 * GIB)));
    assert_eq!(both.resource(), PINNED);
    assert!(!both.retry_can_progress());
    assert_eq!(both.shortfalls().count(), 2);
}

#[test]
fn two_14_gb_weight_sets_do_not_fit_on_a_24_gb_gpu() {
    // GPU part §2.7: even before KV and workspace, and even without a reserve.
    let clock = start();
    let mut ledger = ledger_on(&clock);
    ledger
        .declare_capacity(vram(0), host_probe(24 * GB, 0))
        .unwrap();
    let weights = |execution: &str| {
        ReservationRequest::new(
            provenance(Requester::ModelPlacement, execution, "alpha"),
            Priority::Foreground,
            Amounts::new().vram_bytes(gpu(0), 14 * GB),
        )
    };
    granted(ledger.reserve(weights("exe-first")));
    let error = refused(ledger.reserve(weights("exe-second")));
    assert_eq!(error.resource(), vram(0));
    assert_eq!(error.limiting().available, 10 * GB);
    assert_eq!(
        error.limiting().prospect,
        RetryProspect::FitsAfterRelease { shortfall: 4 * GB }
    );
}

#[test]
fn double_cancel_is_idempotent() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let before = ledger.available(RAM);

    let reservation = granted(ledger.reserve(model_load("exe-a", "alpha", 4 * GIB, 0)));
    assert_eq!(
        ledger.cancel(reservation),
        Ok(ReleaseOutcome::Released {
            amounts: Amounts::new().host_ram_bytes(4 * GIB)
        })
    );
    assert_eq!(
        ledger.cancel(reservation),
        Ok(ReleaseOutcome::AlreadyClosed)
    );
    assert_eq!(ledger.available(RAM), before);

    let created = granted(ledger.reserve(model_load("exe-b", "alpha", 4 * GIB, 0)));
    ledger.begin_create(created).unwrap();
    assert_eq!(ledger.cancel(created), Ok(ReleaseOutcome::Pending));
    assert_eq!(ledger.cancel(created), Ok(ReleaseOutcome::Pending));
    assert_eq!(ledger.available(RAM), Some(26 * GIB));
    assert_eq!(
        ledger.confirm_release(created, SourceClass::HostProbe),
        Ok(ReleaseOutcome::Released {
            amounts: Amounts::new().host_ram_bytes(4 * GIB)
        })
    );
    assert_eq!(
        ledger.confirm_release(created, SourceClass::HostProbe),
        Ok(ReleaseOutcome::AlreadyClosed)
    );
    assert_eq!(ledger.cancel(created), Ok(ReleaseOutcome::AlreadyClosed));
    assert_eq!(ledger.available(RAM), before);
    assert_eq!(ledger.closed_records().len(), 2);

    let never = ReservationId::new(99);
    assert_eq!(
        ledger.cancel(never),
        Err(LedgerError::UnknownReservation { reservation: never })
    );
}

#[test]
fn repeated_cancellation_leaves_no_drift() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let initial: Vec<_> = [RAM, PINNED, NETWORK, ROOTS]
        .into_iter()
        .map(|resource| ledger.available(resource))
        .collect();
    for round in 0..200 {
        let vm = granted(ledger.reserve(vm_start("exe-vm", "alpha", 12 * GIB)));
        let load = granted(ledger.reserve(model_load("exe-load", "beta", 8 * GIB, 4 * GIB)));
        ledger.begin_create(vm).unwrap();
        for _ in 0..3 {
            assert_eq!(
                ledger.cancel(vm),
                Ok(ReleaseOutcome::Pending),
                "round {round}"
            );
            assert!(matches!(
                ledger.cancel(load),
                Ok(ReleaseOutcome::Released { .. } | ReleaseOutcome::AlreadyClosed)
            ));
        }
        ledger.confirm_release(vm, SourceClass::HostProbe).unwrap();
        clock.advance(SECOND);
    }
    let after: Vec<_> = [RAM, PINNED, NETWORK, ROOTS]
        .into_iter()
        .map(|resource| ledger.available(resource))
        .collect();
    assert_eq!(after, initial);
    assert_eq!(ledger.open_reservations().count(), 0);
    assert_eq!(ledger.take_closed_records().len(), 400);
    assert!(ledger.closed_records().is_empty());
}

#[test]
fn cancellation_wakes_the_queue() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let holder = granted(ledger.reserve(model_load("exe-a", "alpha", 24 * GIB, 0)));
    let ticket =
        queued(ledger.reserve(model_load("exe-b", "beta", 10 * GIB, 0).wait_up_to(MINUTE)));
    assert_eq!(ledger.queue_position(ticket), Some(0));
    clock.advance(10 * SECOND);
    ledger.cancel(holder).unwrap();
    let events = ledger.drain_events();
    let [LedgerEvent::QueueGranted {
        ticket: woken,
        reservation,
    }] = events.as_slice()
    else {
        panic!("expected one grant, got {events:?}");
    };
    assert_eq!(*woken, ticket);
    let record = ledger.reservation(*reservation).unwrap();
    assert_eq!(record.ticket(), Some(ticket));
    assert_eq!(record.phase_durations(clock.now()).queued, 10 * SECOND);
    assert_eq!(ledger.queue_len(), 0);
    assert_eq!(ledger.cancel_queued(ticket), Ok(false));
}

#[test]
fn the_queue_bound_holds() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    granted(ledger.reserve(model_load("exe-full", "alpha", 30 * GIB, 0)));
    let wait = |execution: &str, tenant_name: &str| {
        model_load(execution, tenant_name, GIB, 0).wait_up_to(10 * MINUTE)
    };

    // Length: three per tenant, four in all.
    let mut tickets = Vec::new();
    for index in 0..3 {
        match ledger.reserve(wait(&format!("exe-a{index}"), "alpha")) {
            Ok(Admission::Queued {
                ticket,
                ahead,
                deadline,
                waiting_for,
            }) => {
                assert_eq!(ahead, index);
                // Asked for 10 minutes; the 1-minute limit of the ledger applies.
                assert_eq!(deadline, clock.now().saturating_add(MINUTE));
                assert_eq!(waiting_for.resource(), RAM);
                tickets.push(ticket);
            }
            other => panic!("expected a queue entry, got {other:?}"),
        }
    }
    let error = refused(ledger.reserve(wait("exe-a3", "alpha")));
    assert_eq!(
        error.queue_refusal(),
        Some(QueueRefusal::TenantFull { max_entries: 3 })
    );
    tickets.push(queued(ledger.reserve(wait("exe-b0", "beta"))));
    let error = refused(ledger.reserve(wait("exe-b1", "beta")));
    assert_eq!(
        error.queue_refusal(),
        Some(QueueRefusal::Full { max_entries: 4 })
    );
    assert_eq!(ledger.queue_len(), 4);

    // Withdrawing is idempotent; a ticket never issued is refused.
    assert_eq!(ledger.cancel_queued(tickets[3]), Ok(true));
    assert_eq!(ledger.cancel_queued(tickets[3]), Ok(false));
    let never = QueueTicket::new(77);
    assert_eq!(
        ledger.cancel_queued(never),
        Err(LedgerError::UnknownTicket { ticket: never })
    );

    // Age: past the deadline nothing is granted, even when capacity is free again.
    clock.advance(MINUTE + SECOND);
    ledger
        .declare_capacity(RAM, host_probe(64 * GIB, 2 * GIB))
        .unwrap();
    let events = ledger.drain_events();
    assert_eq!(events.len(), 3);
    for (event, ticket) in events.iter().zip(&tickets) {
        match event {
            LedgerEvent::QueueRefused {
                ticket: refused_ticket,
                error:
                    LedgerError::QueueWaitExpired {
                        waited,
                        waiting_for,
                        ..
                    },
            } => {
                assert_eq!(refused_ticket, ticket);
                assert_eq!(*waited, MINUTE + SECOND);
                assert_eq!(waiting_for.resource(), RAM);
                assert!(waiting_for.retry_can_progress());
            }
            other => panic!("expected an expiry, got {other:?}"),
        }
    }
    assert_eq!(ledger.queue_len(), 0);
    assert_eq!(ledger.reserved(RAM), 30 * GIB);
}

#[test]
fn waiting_never_queues_a_request_that_cannot_fit() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let error =
        refused(ledger.reserve(model_load("exe-a", "alpha", 31 * GIB, 0).wait_up_to(MINUTE)));
    assert_eq!(error.queue_refusal(), Some(QueueRefusal::NotWaitable));
    assert_eq!(ledger.queue_len(), 0);
    let error = refused(ledger.reserve(model_load("exe-a", "alpha", 31 * GIB, 0)));
    assert_eq!(error.queue_refusal(), Some(QueueRefusal::NotWaitable));
}

#[test]
fn partial_start_reconciliation_releases_the_unused_part() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    for index in 0..3 {
        let vm = granted(ledger.reserve(vm_start(&format!("exe-other{index}"), "beta", GIB)));
        ledger.begin_create(vm).unwrap();
    }
    let vm = granted(
        ledger.reserve(ReservationRequest::new(
            provenance(Requester::VmLifecycle, "exe-vm", "alpha"),
            Priority::Foreground,
            Amounts::new()
                .host_ram_bytes(8 * GIB)
                .burst_vm_roots(1)
                .network_slots(1)
                .snapshot_pages(1_000),
        )),
    );
    assert_eq!(ledger.available(NETWORK), Some(0));
    let next = ReservationRequest::new(
        provenance(Requester::VmLifecycle, "exe-next", "beta"),
        Priority::Foreground,
        Amounts::new().network_slots(1),
    );
    let waiting = queued(ledger.reserve(next.wait_up_to(MINUTE)));

    // Reconciling needs a started workload and a host observation.
    let in_use = Amounts::new()
        .host_ram_bytes(8 * GIB)
        .burst_vm_roots(1)
        .snapshot_pages(1_000);
    assert_eq!(
        ledger.reconcile(vm, observed(SourceClass::HostProbe, in_use.clone())),
        Err(LedgerError::InvalidTransition {
            reservation: vm,
            state: ReservationState::Granted,
            transition: Transition::Reconcile,
        })
    );
    ledger.begin_create(vm).unwrap();
    assert_eq!(
        ledger.reconcile(vm, observed(SourceClass::GuestReport, in_use.clone())),
        Err(LedgerError::SourceNotAuthoritative {
            source: SourceClass::GuestReport,
            required: SourceClass::HostProbe,
        })
    );

    // The network attach failed: the host sees no slot in use, so the slot returns.
    let outcome = ledger
        .reconcile(vm, observed(SourceClass::HostProbe, in_use.clone()))
        .unwrap();
    assert_eq!(outcome.released, Amounts::new().network_slots(1));
    assert!(outcome.overrun.is_empty());
    let record = ledger.reservation(vm).unwrap();
    assert_eq!(record.current(), &in_use);
    assert!(!record.overrun());
    assert_eq!(record.granted().get(NETWORK), 1);
    let events = ledger.drain_events();
    assert!(
        matches!(events.as_slice(), [LedgerEvent::QueueGranted { ticket, .. }] if *ticket == waiting),
        "{events:?}"
    );
    assert_eq!(ledger.available(NETWORK), Some(0));
    assert_eq!(ledger.available(ROOTS), Some(0));
    assert_invariants(&ledger);
}

#[test]
fn use_observed_above_the_reservation_is_counted_not_ignored() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let vm = granted(ledger.reserve(vm_start("exe-vm", "alpha", 8 * GIB)));
    ledger.begin_create(vm).unwrap();
    let outcome = ledger
        .reconcile(
            vm,
            observed(
                SourceClass::HostProbe,
                Amounts::new()
                    .host_ram_bytes(10 * GIB)
                    .burst_vm_roots(1)
                    .network_slots(1)
                    .pinned_host_ram_bytes(GIB),
            ),
        )
        .unwrap();
    assert_eq!(
        outcome.overrun,
        Amounts::new()
            .host_ram_bytes(2 * GIB)
            .pinned_host_ram_bytes(GIB)
    );
    assert!(outcome.released.is_empty());
    assert!(ledger.reservation(vm).unwrap().overrun());
    assert_eq!(ledger.available(RAM), Some(20 * GIB));
    assert_eq!(ledger.available(PINNED), Some(7 * GIB));
}

#[test]
fn a_parent_cannot_shrink_below_its_children() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let vm = granted(ledger.reserve(vm_start("exe-vm", "alpha", 8 * GIB)));
    ledger.begin_create(vm).unwrap();
    let load = model_load("exe-vm", "alpha", 6 * GIB, 0).within(vm);
    granted(ledger.reserve(load));
    assert_eq!(
        ledger.reconcile(
            vm,
            observed(
                SourceClass::HostProbe,
                Amounts::new().host_ram_bytes(4 * GIB)
            )
        ),
        Err(LedgerError::BelowChildren {
            reservation: vm,
            resource: RAM,
            observed: 4 * GIB,
            children: 6 * GIB,
        })
    );
    assert_eq!(ledger.reserved(RAM), 8 * GIB);
}

#[test]
fn guest_reported_free_memory_never_adds_capacity() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let vm = granted(
        ledger.reserve(ReservationRequest::new(
            provenance(Requester::VmLifecycle, "exe-vm", "alpha"),
            Priority::Foreground,
            Amounts::new()
                .host_ram_bytes(16 * GIB)
                .vram_bytes(gpu(0), 20 * GB),
        )),
    );
    ledger.begin_create(vm).unwrap();
    let ram_before = ledger.available(RAM);
    let vram_before = ledger.available(vram(0));

    // Detailed guest telemetry is recorded, and changes nothing (S3.2).
    let report = Amounts::new()
        .host_ram_bytes(2 * GIB)
        .vram_bytes(gpu(0), GB);
    ledger
        .observe_usage(vm, observed(SourceClass::GuestReport, report.clone()))
        .unwrap();
    assert_eq!(ledger.available(RAM), ram_before);
    assert_eq!(ledger.available(vram(0)), vram_before);
    let record = ledger.reservation(vm).unwrap();
    assert_eq!(
        record
            .observation_from(SourceClass::GuestReport)
            .unwrap()
            .in_use,
        report
    );
    assert_eq!(record.current().get(RAM), 16 * GIB);

    // Nor can any source short of a host probe reconcile or release host capacity.
    for source in [
        SourceClass::Fixture,
        SourceClass::RecordedDeclaration,
        SourceClass::GuestReport,
        SourceClass::ProviderApi,
    ] {
        let refusal = LedgerError::SourceNotAuthoritative {
            source,
            required: SourceClass::HostProbe,
        };
        assert_eq!(
            ledger.reconcile(vm, observed(source, report.clone())),
            Err(refusal.clone())
        );
        assert_eq!(ledger.confirm_release(vm, source), Err(refusal));
    }
    assert_eq!(ledger.available(RAM), ram_before);

    // Another tenant cannot use what the guest claims is idle.
    let other = ReservationRequest::new(
        provenance(Requester::ModelPlacement, "exe-beta", "beta"),
        Priority::Foreground,
        Amounts::new().vram_bytes(gpu(0), 10 * GB),
    );
    let error = refused(ledger.reserve(other));
    assert_eq!(error.resource(), vram(0));
    assert_eq!(error.limiting().available, 3 * GB);

    // Stopping the VM is not a release; the host's observation is.
    assert_eq!(ledger.cancel(vm), Ok(ReleaseOutcome::Pending));
    assert_eq!(ledger.available(RAM), ram_before);
    ledger.confirm_release(vm, SourceClass::HostProbe).unwrap();
    assert_eq!(ledger.available(RAM), Some(30 * GIB));
    assert_eq!(ledger.available(vram(0)), Some(23 * GB));
}

#[test]
fn an_exclusively_assigned_device_leaves_no_room_for_a_host_process() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let assigned = granted(ledger.reserve(ReservationRequest::new(
        provenance(Requester::VmLifecycle, "exe-vm", "alpha"),
        Priority::Foreground,
        Amounts::new().vram_bytes(gpu(0), 23 * GB),
    )));
    ledger.begin_create(assigned).unwrap();
    let load = |execution: &str| {
        ReservationRequest::new(
            provenance(Requester::ModelPlacement, execution, "alpha"),
            Priority::Foreground,
            Amounts::new().vram_bytes(gpu(0), 14 * GB),
        )
    };
    let error = refused(ledger.reserve(load("exe-host")));
    assert_eq!(error.resource(), vram(0));
    assert_eq!(error.limiting().limit, Limit::PhysicalCapacity);
    // Inside the owning runtime, the same load is carved from the assignment.
    granted(ledger.reserve(load("exe-vm").within(assigned)));
    assert_eq!(ledger.parent_room(assigned, vram(0)), Ok(9 * GB));
}

#[test]
fn the_tenant_budget_refuses_even_when_physical_capacity_is_free() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    ledger
        .set_tenant_budget(tenant("gamma"), RAM, 8 * GIB)
        .unwrap();
    let gamma = Limit::TenantBudget {
        tenant: tenant("gamma"),
    };

    let error = refused(ledger.reserve(model_load("exe-g", "gamma", 10 * GIB, 0)));
    assert_eq!(error.limiting().limit, gamma);
    assert_eq!(
        error.limiting().prospect,
        RetryProspect::ExceedsLimit { limit: 8 * GIB }
    );
    assert!(!error.retry_can_progress());
    assert_eq!(ledger.available(RAM), Some(30 * GIB));

    granted(ledger.reserve(model_load("exe-g", "gamma", 6 * GIB, 0)));
    let error = refused(ledger.reserve(model_load("exe-g2", "gamma", 4 * GIB, 0)));
    assert_eq!(error.limiting().limit, gamma);
    assert_eq!(
        error.limiting().prospect,
        RetryProspect::FitsAfterRelease { shortfall: 2 * GIB }
    );
    assert!(error.to_string().contains("the budget of tenant gamma"));
    assert_eq!(ledger.tenant_reserved(&tenant("gamma"), RAM), 6 * GIB);
    assert_eq!(ledger.available(RAM), Some(24 * GIB));

    // A tenant without a budget for a resource cannot reserve it.
    let error = refused(ledger.reserve(model_load("exe-d", "delta", 1, 0)));
    assert_eq!(
        error.limiting().prospect,
        RetryProspect::ExceedsLimit { limit: 0 }
    );
    // Budgets are per tenant: another tenant is unaffected.
    granted(ledger.reserve(model_load("exe-a", "alpha", 10 * GIB, 0)));
}

#[test]
fn provenance_is_recorded() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let t0 = clock.now();
    let blocker = granted(ledger.reserve(model_load("exe-block", "beta", 30 * GIB, 0)));
    let vm = granted(ledger.reserve(ReservationRequest::new(
        Provenance {
            purpose: CostPurpose::VmResources,
            ..provenance(Requester::VmLifecycle, "exe-vm", "alpha")
        },
        Priority::Foreground,
        Amounts::new().pinned_host_ram_bytes(2 * GIB),
    )));
    ledger.begin_create(vm).unwrap();
    let retry = Provenance {
        purpose: CostPurpose::Replica,
        retry_number: 2,
        operation: OperationId::new("op-load-retry-2").unwrap(),
        ..provenance(Requester::ModelPlacement, "exe-vm", "alpha")
    };
    let ticket = queued(
        ledger.reserve(
            ReservationRequest::new(
                retry.clone(),
                Priority::Foreground,
                Amounts::new().host_ram_bytes(4 * GIB),
            )
            .wait_up_to(MINUTE),
        ),
    );
    clock.advance(3 * SECOND);
    ledger.cancel(blocker).unwrap();
    let [LedgerEvent::QueueGranted {
        reservation: load, ..
    }] = ledger.drain_events()[..]
    else {
        panic!("expected the queued load to be granted");
    };
    clock.advance(2 * SECOND);
    ledger.begin_create(load).unwrap();
    clock.advance(5 * SECOND);
    ledger
        .reconcile(
            load,
            observed(
                SourceClass::HostProbe,
                Amounts::new().host_ram_bytes(3 * GIB),
            ),
        )
        .unwrap();
    clock.advance(10 * SECOND);
    assert_eq!(ledger.cancel(load), Ok(ReleaseOutcome::Pending));
    clock.advance(4 * SECOND);
    ledger
        .confirm_release(load, SourceClass::HostProbe)
        .unwrap();

    let record = ledger
        .closed_records()
        .iter()
        .find(|record| record.id() == load)
        .unwrap()
        .clone();
    assert_eq!(record.provenance(), &retry);
    assert!(record.provenance().is_retry());
    assert_eq!(record.provenance().requester, Requester::ModelPlacement);
    assert_eq!(record.provenance().tenant, tenant("alpha"));
    assert_eq!(record.parent(), None);
    assert_eq!(record.ticket(), Some(ticket));
    let at = |seconds: u64| t0.saturating_add(Duration::from_secs(seconds));
    assert_eq!(record.requested_at(), at(0));
    assert_eq!(record.granted_at(), at(3));
    assert_eq!(record.create_started_at(), Some(at(5)));
    assert_eq!(record.release_requested_at(), Some(at(20)));
    assert_eq!(record.closed_at(), Some(at(24)));
    assert_eq!(
        record.close_reason(),
        Some(CloseReason::ReleaseObserved {
            source: SourceClass::HostProbe
        })
    );
    assert_eq!(
        record.phase_durations(clock.now()),
        PhaseDurations {
            queued: 3 * SECOND,
            reserved_before_create: 2 * SECOND,
            in_use: 15 * SECOND,
            releasing: 4 * SECOND,
        }
    );
    // 4 GiB for 7 s, then 3 GiB for 14 s, in byte-nanoseconds (BENCH-08).
    let expected = u128::from(4 * GIB) * 7_000_000_000 + u128::from(3 * GIB) * 14_000_000_000;
    assert_eq!(record.held_amount_nanoseconds(RAM, clock.now()), expected);
    assert_eq!(
        record
            .history()
            .iter()
            .map(|change| change.cause)
            .collect::<Vec<_>>(),
        [
            ChangeCause::Granted,
            ChangeCause::Reconciled {
                source: SourceClass::HostProbe
            },
            ChangeCause::Closed
        ]
    );

    // A child records its parent; the record survives a JSON round trip.
    let child = granted(
        ledger.reserve(
            ReservationRequest::new(
                provenance(Requester::ModelPlacement, "exe-vm", "alpha"),
                Priority::Foreground,
                Amounts::new().pinned_host_ram_bytes(GIB),
            )
            .within(vm),
        ),
    );
    assert_eq!(ledger.reservation(child).unwrap().parent(), Some(vm));
    assert_eq!(
        ledger.reservation(vm).unwrap().provenance().purpose,
        CostPurpose::VmResources
    );
    let json = serde_json::to_value(&record).unwrap();
    assert_eq!(json["provenance"]["retry_number"], 2);
    assert_eq!(json["provenance"]["purpose"], "replica");
    assert_eq!(json["granted"][0]["resource"]["host"], "ram");
    let back: ReservationRecord = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(back, record);
    let mut extra = json;
    extra["trusted"] = true.into();
    assert!(serde_json::from_value::<ReservationRecord>(extra).is_err());
}

/// One scripted run: reservations, a queue wait, reconciliation, a hold and expiry.
fn scripted_run() -> (Vec<LedgerEvent>, String) {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let mut events = Vec::new();
    let vm = granted(ledger.reserve(vm_start("exe-vm", "alpha", 20 * GIB)));
    ledger.begin_create(vm).unwrap();
    let load = granted(ledger.reserve(model_load("exe-vm", "alpha", 8 * GIB, 0).within(vm)));
    ledger.begin_create(load).unwrap();
    queued(ledger.reserve(model_load("exe-b", "beta", 12 * GIB, 2 * GIB).wait_up_to(MINUTE)));
    queued(ledger.reserve(model_load("exe-c", "beta", 29 * GIB, 0).wait_up_to(MINUTE)));
    clock.advance(7 * SECOND);
    ledger
        .reconcile(
            vm,
            observed(
                SourceClass::HostProbe,
                Amounts::new()
                    .host_ram_bytes(16 * GIB)
                    .burst_vm_roots(1)
                    .network_slots(1),
            ),
        )
        .unwrap();
    events.extend(ledger.drain_events());
    ledger.begin_hold(BTreeSet::from([vram(0)])).unwrap();
    clock.advance(2 * MINUTE);
    ledger.tick();
    ledger.cancel_execution(&ExecutionId::new("exe-vm").unwrap());
    ledger.confirm_release(vm, SourceClass::HostProbe).unwrap();
    events.extend(ledger.drain_events());
    let records = serde_json::to_string(&ledger.take_closed_records()).unwrap();
    (events, records)
}

#[test]
fn runs_are_deterministic_with_a_manual_clock() {
    let first = scripted_run();
    assert!(!first.0.is_empty());
    for _ in 0..5 {
        assert_eq!(scripted_run(), first);
    }
}

#[test]
fn unobserved_capacity_is_never_free() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let request = ReservationRequest::new(
        provenance(Requester::ModelPlacement, "exe-a", "alpha"),
        Priority::Foreground,
        Amounts::new().vram_bytes(gpu(1), GB),
    );
    ledger
        .set_tenant_budget(tenant("alpha"), vram(1), u64::MAX)
        .unwrap();
    let error = refused(ledger.reserve(request.clone().wait_up_to(MINUTE)));
    assert_eq!(error.limiting().limit, Limit::CapacityNotObserved);
    assert_eq!(
        error.limiting().prospect,
        RetryProspect::AfterHostObservation
    );
    assert!(error.retry_can_progress());
    assert_eq!(error.queue_refusal(), Some(QueueRefusal::NotWaitable));
    assert_eq!(ledger.available(vram(1)), None);

    // A guest or provider cannot declare host capacity or host pressure.
    for source in [
        SourceClass::GuestReport,
        SourceClass::ProviderApi,
        SourceClass::Fixture,
    ] {
        let declaration = CapacityDeclaration {
            source,
            ..host_probe(24 * GB, GB)
        };
        assert_eq!(
            ledger.declare_capacity(vram(1), declaration),
            Err(LedgerError::SourceNotAuthoritative {
                source,
                required: SourceClass::HostProbe
            })
        );
        assert_eq!(
            ledger.observe_unmanaged_usage(vram(0), 0, source),
            Err(LedgerError::SourceNotAuthoritative {
                source,
                required: SourceClass::HostProbe
            })
        );
    }
    assert_eq!(
        ledger.observe_unmanaged_usage(vram(1), 0, SourceClass::HostProbe),
        Err(LedgerError::CapacityNotDeclared { resource: vram(1) })
    );
    ledger
        .declare_capacity(vram(1), host_probe(24 * GB, GB))
        .unwrap();
    granted(ledger.reserve(request));
}

#[test]
fn host_pressure_is_never_free_capacity() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    // Other processes and page cache use 10 GiB of host RAM; page cache is not free.
    ledger
        .observe_unmanaged_usage(RAM, 10 * GIB, SourceClass::HostProbe)
        .unwrap();
    assert_eq!(ledger.available(RAM), Some(20 * GIB));
    let ticket =
        queued(ledger.reserve(model_load("exe-a", "alpha", 24 * GIB, 0).wait_up_to(MINUTE)));
    // External GPU consumers hold VRAM the ledger never granted (GPU part §3.1).
    ledger
        .observe_unmanaged_usage(vram(0), 5 * GB, SourceClass::HostProbe)
        .unwrap();
    assert_eq!(ledger.available(vram(0)), Some(18 * GB));

    clock.advance(SECOND);
    ledger
        .observe_unmanaged_usage(RAM, 4 * GIB, SourceClass::HostProbe)
        .unwrap();
    let events = ledger.drain_events();
    assert!(
        matches!(events.as_slice(), [LedgerEvent::QueueGranted { ticket: woken, .. }] if *woken == ticket),
        "{events:?}"
    );
    assert_eq!(ledger.available(RAM), Some(2 * GIB));

    // Pressure that grows past the reservations refuses new work and keeps the old.
    ledger
        .observe_unmanaged_usage(RAM, 12 * GIB, SourceClass::HostProbe)
        .unwrap();
    assert_eq!(ledger.available(RAM), Some(0));
    assert_eq!(ledger.reserved(RAM), 24 * GIB);
    let error = refused(ledger.reserve(model_load("exe-b", "beta", 1, 0)));
    assert_eq!(error.limiting().limit, Limit::PhysicalCapacity);
    assert!(error.retry_can_progress());
}

#[test]
fn capacity_is_counted_once_per_host_and_device() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    // Observing the same capacity again replaces it; it never adds up.
    ledger
        .declare_capacity(RAM, host_probe(32 * GIB, 2 * GIB))
        .unwrap();
    ledger
        .declare_capacity(RAM, host_probe(32 * GIB, 2 * GIB))
        .unwrap();
    assert_eq!(ledger.available(RAM), Some(30 * GIB));

    ledger
        .declare_capacity(vram(1), host_probe(16 * GB, 0))
        .unwrap();
    ledger
        .set_tenant_budget(tenant("alpha"), vram(1), u64::MAX)
        .unwrap();
    let on = |index: u8, bytes: u64| {
        ReservationRequest::new(
            provenance(Requester::ModelPlacement, "exe-a", "alpha"),
            Priority::Foreground,
            Amounts::new().vram_bytes(gpu(index), bytes),
        )
    };
    granted(ledger.reserve(on(0, 23 * GB)));
    assert_eq!(ledger.available(vram(0)), Some(0));
    assert_eq!(ledger.available(vram(1)), Some(16 * GB));
    granted(ledger.reserve(on(1, 16 * GB)));

    // A device on another machine is not this host's capacity.
    let foreign = DeviceId::new(GpuDeviceSubject {
        machine: digest("yougori/test/machine/v1", &[b"elsewhere"]),
        device: digest("yougori/test/gpu/v1", &[&[0]]),
    });
    assert_eq!(
        ledger.declare_capacity(ResourceKey::Vram(foreign), host_probe(GB, 0)),
        Err(LedgerError::ForeignDevice { device: foreign })
    );
    let request = ReservationRequest::new(
        provenance(Requester::ModelPlacement, "exe-a", "alpha"),
        Priority::Foreground,
        Amounts::new().vram_bytes(foreign, 1),
    );
    assert_eq!(
        ledger.reserve(request),
        Err(LedgerError::ForeignDevice { device: foreign })
    );
}

fn on_gpu(execution: &str, priority: Priority, bytes: u64) -> ReservationRequest {
    ReservationRequest::new(
        provenance(Requester::ModelPlacement, execution, "alpha"),
        priority,
        Amounts::new().vram_bytes(gpu(0), bytes),
    )
}

#[test]
fn a_hold_denies_new_background_work_while_existing_work_drains() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let background = granted(ledger.reserve(on_gpu("exe-bg", Priority::Background, 20 * GB)));
    ledger.begin_create(background).unwrap();
    let waiting =
        queued(ledger.reserve(on_gpu("exe-bg2", Priority::Background, 6 * GB).wait_up_to(MINUTE)));

    let report = ledger.begin_hold(BTreeSet::from([vram(0)])).unwrap();
    assert_eq!(report.draining, [background]);
    assert_eq!(report.denied, [waiting]);
    let events = ledger.drain_events();
    match events.as_slice() {
        [LedgerEvent::QueueRefused {
            ticket,
            error: LedgerError::Capacity(error),
        }] => {
            assert_eq!(*ticket, waiting);
            assert_eq!(
                error.limiting().limit,
                Limit::OwnerReturnHold { hold: report.hold }
            );
        }
        other => panic!("expected the queued background request to be refused, got {other:?}"),
    }

    // New background work on the held device is denied, not queued.
    let error =
        refused(ledger.reserve(on_gpu("exe-bg3", Priority::Background, GB).wait_up_to(MINUTE)));
    assert_eq!(
        error.limiting().limit,
        Limit::OwnerReturnHold { hold: report.hold }
    );
    assert_eq!(error.limiting().prospect, RetryProspect::AfterHoldEnds);
    assert!(error.retry_can_progress());
    assert_eq!(error.queue_refusal(), Some(QueueRefusal::NotWaitable));
    // Foreground work and background work elsewhere continue.
    granted(ledger.reserve(on_gpu("exe-fg", Priority::Foreground, GB)));
    let mut elsewhere = model_load("exe-bg4", "alpha", GIB, 0);
    elsewhere.priority = Priority::Background;
    granted(ledger.reserve(elsewhere));

    // Stopping the background work does not return its VRAM; the observed release does.
    assert_eq!(ledger.cancel(background), Ok(ReleaseOutcome::Pending));
    assert_eq!(ledger.available(vram(0)), Some(2 * GB));
    ledger
        .confirm_release(background, SourceClass::HostProbe)
        .unwrap();
    assert_eq!(ledger.available(vram(0)), Some(22 * GB));
    let record = &ledger.closed_records()[0];
    assert!(record.release_requested_at().is_some());
    assert!(record.closed_at().is_some());

    assert_eq!(ledger.active_holds(), [report.hold]);
    assert_eq!(ledger.end_hold(report.hold), Ok(true));
    assert_eq!(ledger.end_hold(report.hold), Ok(false));
    let never = HoldId::new(9);
    assert_eq!(
        ledger.end_hold(never),
        Err(LedgerError::UnknownHold { hold: never })
    );
    granted(ledger.reserve(on_gpu("exe-bg5", Priority::Background, GB)));
}

#[test]
fn revoking_an_execution_reclaims_without_false_free_capacity() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let vm = granted(ledger.reserve(vm_start("exe-vm", "alpha", 16 * GIB)));
    ledger.begin_create(vm).unwrap();
    let load = granted(ledger.reserve(model_load("exe-vm", "alpha", 8 * GIB, 0).within(vm)));
    ledger.begin_create(load).unwrap();
    let staged = granted(ledger.reserve(model_load("exe-vm", "alpha", 0, 4 * GIB)));
    let prefetch = granted(ledger.reserve(model_load("exe-vm", "alpha", GIB, 0).within(vm)));
    let ticket =
        queued(ledger.reserve(model_load("exe-vm", "alpha", 20 * GIB, 0).wait_up_to(MINUTE)));

    let report = ledger.cancel_execution(&ExecutionId::new("exe-vm").unwrap());
    assert_eq!(report.dequeued, [ticket]);
    assert_eq!(report.released, [staged]);
    assert_eq!(report.pending, [vm]);
    assert_eq!(
        ledger.reservation(load).unwrap().state(),
        ReservationState::Releasing
    );
    assert!(ledger.reservation(prefetch).is_none());
    // The VM and the model inside it still hold their memory until the host sees it freed.
    assert_eq!(ledger.available(RAM), Some(14 * GIB));
    assert_eq!(ledger.available(PINNED), Some(8 * GIB));
    // Nothing new is carved from a releasing parent, and nothing restarts.
    assert_eq!(
        ledger.reserve(model_load("exe-vm", "alpha", GIB, 0).within(vm)),
        Err(LedgerError::ParentNotOpen { parent: vm })
    );
    assert_eq!(
        ledger.begin_create(load),
        Err(LedgerError::InvalidTransition {
            reservation: load,
            state: ReservationState::Releasing,
            transition: Transition::BeginCreate,
        })
    );
    assert!(matches!(
        ledger.drain_events().as_slice(),
        [LedgerEvent::QueueRefused {
            error: LedgerError::ExecutionCancelled { .. },
            ..
        }]
    ));

    ledger.confirm_release(vm, SourceClass::HostProbe).unwrap();
    assert_eq!(ledger.available(RAM), Some(30 * GIB));
    let reasons: Vec<_> = ledger
        .closed_records()
        .iter()
        .map(|record| (record.id(), record.close_reason()))
        .collect();
    assert!(reasons.contains(&(load, Some(CloseReason::ParentClosed { parent: vm }))));
    assert!(reasons.contains(&(prefetch, Some(CloseReason::ParentClosed { parent: vm }))));
    assert!(reasons.contains(&(staged, Some(CloseReason::CancelledBeforeCreate))));
}

#[test]
fn unused_grants_are_reclaimed() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let idle = granted(ledger.reserve(model_load("exe-idle", "alpha", 30 * GIB, 0)));
    let ticket = queued(ledger.reserve(model_load("exe-b", "beta", GIB, 0).wait_up_to(MINUTE)));
    clock.advance(5 * MINUTE);
    ledger.tick();
    assert!(
        ledger.reservation(idle).is_some(),
        "the lifetime is inclusive"
    );
    // The queued request expired first; the grant is reclaimed one second later.
    clock.advance(SECOND);
    ledger.tick();
    let events = ledger.drain_events();
    assert!(
        events.contains(&LedgerEvent::Reclaimed { reservation: idle }),
        "{events:?}"
    );
    assert!(events.iter().any(|event| matches!(
        event,
        LedgerEvent::QueueRefused { ticket: expired, error: LedgerError::QueueWaitExpired { .. } } if *expired == ticket
    )));
    assert_eq!(
        ledger.begin_create(idle),
        Err(LedgerError::Closed { reservation: idle })
    );
    assert_eq!(ledger.available(RAM), Some(30 * GIB));
    let record = &ledger.closed_records()[0];
    assert_eq!(record.close_reason(), Some(CloseReason::GrantExpired));
    assert_eq!(
        record.phase_durations(clock.now()).reserved_before_create,
        5 * MINUTE + SECOND
    );
}

#[test]
fn reserve_before_create() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let never = ReservationId::new(1);
    assert_eq!(
        ledger.begin_create(never),
        Err(LedgerError::UnknownReservation { reservation: never })
    );
    let vm = granted(ledger.reserve(vm_start("exe-vm", "alpha", GIB)));
    let load = granted(ledger.reserve(model_load("exe-vm", "alpha", GIB, 0).within(vm)));
    assert_eq!(
        ledger.begin_create(load),
        Err(LedgerError::ParentNotInUse { parent: vm })
    );
    ledger.begin_create(vm).unwrap();
    ledger.begin_create(vm).unwrap();
    ledger.begin_create(load).unwrap();
    assert_eq!(
        ledger.reservation(load).unwrap().state(),
        ReservationState::InUse
    );
    assert_eq!(
        ledger.reserve(ReservationRequest::new(
            provenance(Requester::Coordination, "exe-x", "alpha"),
            Priority::Foreground,
            Amounts::new(),
        )),
        Err(LedgerError::EmptyDemand)
    );
    let missing = ReservationId::new(500);
    assert_eq!(
        ledger.reserve(model_load("exe-vm", "alpha", 1, 0).within(missing)),
        Err(LedgerError::UnknownReservation {
            reservation: missing
        })
    );
}

#[test]
fn a_child_returns_its_amounts_to_its_parent_on_its_runtime_report() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let runtime = granted(ledger.reserve(model_load("exe-rt", "alpha", 8 * GIB, 0)));
    ledger.begin_create(runtime).unwrap();
    let first = granted(ledger.reserve(model_load("exe-rt", "alpha", 6 * GIB, 0).within(runtime)));
    ledger.begin_create(first).unwrap();
    let ticket = queued(
        ledger.reserve(
            model_load("exe-rt", "alpha", 5 * GIB, 0)
                .within(runtime)
                .wait_up_to(MINUTE),
        ),
    );
    let host_available = ledger.available(RAM);

    assert_eq!(ledger.cancel(first), Ok(ReleaseOutcome::Pending));
    // A declaration or fixture is not an observation of the release.
    for source in [SourceClass::Fixture, SourceClass::RecordedDeclaration] {
        assert_eq!(
            ledger.confirm_release(first, source),
            Err(LedgerError::SourceNotAuthoritative {
                source,
                required: SourceClass::GuestReport
            })
        );
    }
    ledger
        .confirm_release(first, SourceClass::GuestReport)
        .unwrap();
    let events = ledger.drain_events();
    assert!(
        matches!(events.as_slice(), [LedgerEvent::QueueGranted { ticket: woken, .. }] if *woken == ticket),
        "{events:?}"
    );
    // The parent's room changed; host capacity did not.
    assert_eq!(ledger.available(RAM), host_available);
    assert_eq!(ledger.parent_room(runtime, RAM), Ok(3 * GIB));
}

#[test]
fn amounts_serialize_as_a_strict_list() {
    let amounts = Amounts::new()
        .host_ram_bytes(GIB)
        .vram_bytes(gpu(0), GB)
        .network_slots(2)
        .storage_io_bytes_per_second(500)
        .storage_quota_bytes(7)
        .cpu_initialization_slots(1)
        .burst_vm_roots(1)
        .snapshot_pages(9)
        .pinned_host_ram_bytes(0);
    assert_eq!(amounts.len(), 8);
    let json = serde_json::to_value(&amounts).unwrap();
    assert_eq!(json[0]["resource"]["host"], "ram");
    assert_eq!(json[0]["amount"], GIB);
    assert_eq!(serde_json::from_value::<Amounts>(json).unwrap(), amounts);
    let zero = serde_json::json!([{ "resource": { "host": "ram" }, "amount": 0 }]);
    assert!(serde_json::from_value::<Amounts>(zero).is_err());
    let repeated = serde_json::json!([
        { "resource": { "host": "ram" }, "amount": 1 },
        { "resource": { "host": "ram" }, "amount": 2 }
    ]);
    assert!(serde_json::from_value::<Amounts>(repeated).is_err());
    let extra = serde_json::json!([{ "resource": { "host": "ram" }, "amount": 1, "free": true }]);
    assert!(serde_json::from_value::<Amounts>(extra).is_err());
    // Overflow saturates, so it can only be refused as too large.
    assert_eq!(
        Amounts::new()
            .host_ram_bytes(u64::MAX)
            .host_ram_bytes(1)
            .get(RAM),
        u64::MAX
    );
    for resource in HostResource::ALL {
        assert!(!resource.name().is_empty());
    }
    assert_eq!(vram(0).unit(), ResourceUnit::Bytes);
    assert_eq!(
        ResourceKey::Host(HostResource::StorageIo).unit(),
        ResourceUnit::BytesPerSecond
    );
    assert_eq!(PAGES.unit(), ResourceUnit::Pages);
    assert_eq!(gpu(0).subject().machine, machine());
}

#[test]
fn an_observation_flood_takes_bounded_space_and_changes_nothing() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let vm = granted(ledger.reserve(vm_start("exe-vm", "alpha", 16 * GIB)));
    ledger.begin_create(vm).unwrap();
    let available = ledger.available(RAM);
    for index in 0..10_000u64 {
        let source = if index % 2 == 0 {
            SourceClass::GuestReport
        } else {
            SourceClass::HostProbe
        };
        ledger
            .observe_usage(
                vm,
                observed(source, Amounts::new().host_ram_bytes(index + 1)),
            )
            .unwrap();
    }
    let record = ledger.reservation(vm).unwrap();
    assert_eq!(record.observations().len(), 2);
    assert_eq!(record.history().len(), 1);
    assert_eq!(ledger.available(RAM), available);
    assert_eq!(ledger.cancel(vm), Ok(ReleaseOutcome::Pending));
    ledger.confirm_release(vm, SourceClass::HostProbe).unwrap();
    assert_eq!(
        ledger.observe_usage(vm, observed(SourceClass::HostProbe, Amounts::new())),
        Err(LedgerError::Closed { reservation: vm })
    );
}

#[test]
fn vram_admission_counts_shared_weights_once_and_each_process_separately() {
    // GPU part §2.7, per device: unique_resident_weights + KV + adapters + contexts
    // + graph_pools + peak_workspaces + staging + activation_overlap + safety_reserve
    // <= usable_VRAM. The 24 GB device keeps a 1 GB safety reserve, leaving 23 GB.
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let runtime = granted(ledger.reserve(on_gpu("exe-rt", Priority::Foreground, 23 * GB)));
    ledger.begin_create(runtime).unwrap();
    let part = |bytes: u64| on_gpu("exe-rt", Priority::Foreground, bytes).within(runtime);

    // Shared weights are one reservation, however many processes map them.
    let weights = granted(ledger.reserve(part(14 * GB)));
    // Each process charges its own KV (with its bounded growth), adapters, contexts,
    // graph pools, peak workspaces, staging and activation overlap, in that order.
    let first: u64 = [3 * GB, GB / 2, GB / 2, GB / 4, GB, GB / 4, GB / 2]
        .iter()
        .sum();
    let second: u64 = [GB, 0, GB / 2, GB / 4, GB / 4, 0, 0].iter().sum();
    assert_eq!((first, second), (6 * GB, 2 * GB));
    granted(ledger.reserve(part(first)));
    granted(ledger.reserve(part(second)));

    // 14 + 6 + 2 = 22 GB of 23: a third process needing 2 GB waits for 1 GB.
    let error = refused(ledger.reserve(part(2 * GB)));
    assert_eq!(
        error.limiting().limit,
        Limit::ParentReservation { parent: runtime }
    );
    assert_eq!(
        error.limiting().prospect,
        RetryProspect::FitsAfterRelease { shortfall: GB }
    );
    granted(ledger.reserve(part(GB)));
    assert_eq!(ledger.parent_room(runtime, vram(0)), Ok(0));
    // The device is charged once, for the runtime; the safety reserve is never granted.
    assert_eq!(ledger.reserved(vram(0)), 23 * GB);
    assert_eq!(ledger.available(vram(0)), Some(0));
    assert_eq!(
        ledger.reservation(weights).unwrap().current().get(vram(0)),
        14 * GB
    );
}

#[test]
fn every_refusal_reads_as_a_sentence() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let hold = ledger.begin_hold(BTreeSet::from([vram(0)])).unwrap().hold;
    let mut request = on_gpu("exe-bg", Priority::Background, GB);
    request.demand = request.demand.vram_bytes(gpu(1), GB);
    let error = refused(ledger.reserve(request));
    // No budget on GPU 1 is a limit no retry passes, so it leads.
    assert_eq!(
        error.limiting().limit,
        Limit::TenantBudget {
            tenant: tenant("alpha")
        }
    );
    let limits: Vec<_> = error
        .shortfalls()
        .map(|shortfall| shortfall.limit.clone())
        .collect();
    assert!(limits.contains(&Limit::CapacityNotObserved));
    assert!(limits.contains(&Limit::OwnerReturnHold { hold }));
    let text = error.to_string();
    for expected in [
        "the budget of tenant alpha",
        "retry after a host probe",
        "while hold 1 returns it to its owner",
    ] {
        assert!(text.contains(expected), "{text}");
    }

    let reservation = ReservationId::new(3);
    assert_eq!(
        LedgerError::InvalidTransition {
            reservation,
            state: ReservationState::Releasing,
            transition: Transition::BeginCreate,
        }
        .to_string(),
        "reservation 3 is releasing and cannot begin creating its workload"
    );
    assert_eq!(
        LedgerError::SourceNotAuthoritative {
            source: SourceClass::GuestReport,
            required: SourceClass::HostProbe,
        }
        .to_string(),
        "a guest report is an observation, not authority; this change needs a host probe"
    );
    for error in [
        LedgerError::EmptyDemand,
        LedgerError::Closed { reservation },
        LedgerError::ParentNotOpen {
            parent: reservation,
        },
        LedgerError::ParentNotInUse {
            parent: reservation,
        },
        LedgerError::ParentMismatch {
            parent: reservation,
            field: ParentField::Execution,
        },
        LedgerError::NestingTooDeep { max_depth: 4 },
        LedgerError::ExceedsParent {
            reservation,
            parent: ReservationId::new(1),
            resource: vram(0),
            observed: 5,
            room: 4,
        },
        LedgerError::BelowChildren {
            reservation,
            resource: RAM,
            observed: 1,
            children: 2,
        },
        LedgerError::CapacityNotDeclared { resource: PAGES },
        LedgerError::ForeignDevice { device: gpu(0) },
        LedgerError::ExecutionCancelled {
            execution: ExecutionId::new("exe-1").unwrap(),
        },
        LedgerError::IdentifiersExhausted,
    ] {
        assert!(error.to_string().len() > 10, "{error:?}");
    }
}

fn lapsing_after(clock: &ManualClock, max_age: Duration) -> Ledger<&ManualClock> {
    ledger_with(
        clock,
        LedgerConfig {
            unmanaged_usage_max_age: max_age,
            ..config()
        },
    )
}

#[test]
fn a_stale_host_observation_refuses_new_grants_until_the_host_refreshes_it() {
    let clock = start();
    let observed_at = clock.now();
    let mut ledger = lapsing_after(&clock, 30 * SECOND);
    let first = granted(ledger.reserve(model_load("exe-a", "alpha", 4 * GIB, 0)));
    ledger.begin_create(first).unwrap();

    // Current up to and including the limit.
    clock.advance(30 * SECOND);
    let second = granted(ledger.reserve(model_load("exe-b", "alpha", 4 * GIB, 0)));
    assert!(ledger.stale_observations().is_empty());

    // One nanosecond later the free amount is unknown: refused, naming the resource.
    clock.advance(Duration::from_nanos(1));
    let error = refused(ledger.reserve(model_load("exe-c", "beta", GIB, 0).wait_up_to(MINUTE)));
    assert_eq!(error.resource(), RAM);
    assert_eq!(
        error.limiting().limit,
        Limit::StaleHostObservation {
            observed_at,
            age: 30 * SECOND + Duration::from_nanos(1),
            max_age: 30 * SECOND,
        }
    );
    assert_eq!(error.limiting().available, 0);
    assert_eq!(
        error.limiting().prospect,
        RetryProspect::AfterHostObservation
    );
    assert!(error.retry_can_progress());
    assert_eq!(error.queue_refusal(), Some(QueueRefusal::NotWaitable));
    let text = error.to_string();
    assert!(text.contains("host RAM"), "{text}");
    assert!(text.contains("refresh the host observation"), "{text}");
    assert_eq!(ledger.available(RAM), None);
    assert!(ledger.stale_observations().contains(&RAM));

    // Declared capacity does not lapse, and existing reservations stay and keep working.
    assert_eq!(ledger.capacity(RAM).unwrap().total, 32 * GIB);
    assert_eq!(ledger.reserved(RAM), 8 * GIB);
    ledger.begin_create(second).unwrap();
    let outcome = ledger
        .reconcile(
            first,
            observed(
                SourceClass::HostProbe,
                Amounts::new().host_ram_bytes(5 * GIB),
            ),
        )
        .unwrap();
    assert_eq!(outcome.overrun, Amounts::new().host_ram_bytes(GIB));

    // Only a host probe refreshes the observation.
    assert_eq!(
        ledger.observe_unmanaged_usage(RAM, 0, SourceClass::GuestReport),
        Err(LedgerError::SourceNotAuthoritative {
            source: SourceClass::GuestReport,
            required: SourceClass::HostProbe,
        })
    );
    assert_eq!(ledger.available(RAM), None);
    ledger
        .observe_unmanaged_usage(RAM, GIB, SourceClass::HostProbe)
        .unwrap();
    assert_eq!(ledger.available(RAM), Some(20 * GIB));
    assert!(!ledger.stale_observations().contains(&RAM));
    granted(ledger.reserve(model_load("exe-c", "beta", GIB, 0)));

    // Each resource lapses on its own: pinned RAM was not refreshed.
    let error = refused(ledger.reserve(model_load("exe-d", "beta", 0, GIB)));
    assert_eq!(error.resource(), PINNED);
    assert!(matches!(
        error.limiting().limit,
        Limit::StaleHostObservation { .. }
    ));
    // A new declaration is a host observation too.
    ledger
        .declare_capacity(PINNED, host_probe(8 * GIB, 0))
        .unwrap();
    granted(ledger.reserve(model_load("exe-d", "beta", 0, GIB)));
}

#[test]
fn a_queued_request_is_refused_once_its_host_observation_lapses() {
    let clock = start();
    let mut ledger = lapsing_after(&clock, 30 * SECOND);
    granted(ledger.reserve(model_load("exe-full", "alpha", 30 * GIB, 0)));
    let ticket = queued(ledger.reserve(model_load("exe-b", "beta", GIB, 0).wait_up_to(MINUTE)));
    clock.advance(31 * SECOND);
    ledger.tick();
    match ledger.drain_events().as_slice() {
        [LedgerEvent::QueueRefused {
            ticket: refused_ticket,
            error: LedgerError::Capacity(error),
        }] => {
            assert_eq!(*refused_ticket, ticket);
            assert!(matches!(
                error.limiting().limit,
                Limit::StaleHostObservation { .. }
            ));
            assert_eq!(error.queue_refusal(), Some(QueueRefusal::NotWaitable));
        }
        other => panic!("expected the stale observation to refuse the entry, got {other:?}"),
    }
    assert_eq!(ledger.queue_len(), 0);
}

#[test]
fn children_and_releases_proceed_while_the_host_observation_is_stale() {
    let clock = start();
    let mut ledger = lapsing_after(&clock, 30 * SECOND);
    let vm = granted(ledger.reserve(vm_start("exe-vm", "alpha", 16 * GIB)));
    ledger.begin_create(vm).unwrap();
    clock.advance(MINUTE);

    // A model load inside the VM takes nothing more from the host.
    let load = granted(ledger.reserve(model_load("exe-vm", "alpha", 8 * GIB, 0).within(vm)));
    ledger.begin_create(load).unwrap();
    // A host-level request is refused, naming every stale resource it needs.
    let error = refused(ledger.reserve(vm_start("exe-vm2", "beta", GIB)));
    let stale: Vec<_> = error
        .shortfalls()
        .map(|shortfall| shortfall.resource)
        .collect();
    assert_eq!(stale, [RAM, NETWORK, ROOTS]);
    // Cancelling and observed releases need no fresh pressure reading.
    assert_eq!(ledger.cancel(vm), Ok(ReleaseOutcome::Pending));
    ledger.confirm_release(vm, SourceClass::HostProbe).unwrap();
    assert_eq!(ledger.reserved(RAM), 0);
    assert!(ledger.reservation(load).is_none());
}

#[test]
fn vram_is_keyed_by_the_shared_gpu_device_key() {
    let key = gpu_key(0);
    let device = DeviceId::from(key);
    assert_eq!(device.key(), key);
    assert_eq!(GpuDeviceKey::from(device), key);
    assert_eq!(DeviceId::from_key(key), device);
    assert_eq!(
        (device.machine(), device.device()),
        (key.machine, key.device)
    );
    // A caller holding the evidence subject names the same device.
    let subject = GpuDeviceSubject {
        machine: key.machine,
        device: key.device,
    };
    assert_eq!(DeviceId::new(subject), device);
    assert_eq!(device.subject(), subject);
    // The ledger's device serializes exactly as the shared key does.
    let json = serde_json::to_value(key).unwrap();
    assert_eq!(serde_json::to_value(device).unwrap(), json);
    assert_eq!(serde_json::from_value::<DeviceId>(json).unwrap(), device);

    // Requests and queries name VRAM by the shared key directly.
    assert_eq!(ResourceKey::vram(key), vram(0));
    assert_eq!(
        Amounts::new().vram_bytes(key, GB),
        Amounts::new().vram_bytes(device, GB)
    );
    let clock = start();
    let mut ledger = ledger_on(&clock);
    granted(ledger.reserve(ReservationRequest::new(
        provenance(Requester::ModelPlacement, "exe-a", "alpha"),
        Priority::Foreground,
        Amounts::new().vram_bytes(key, 2 * GB),
    )));
    assert_eq!(ledger.reserved(ResourceKey::vram(key)), 2 * GB);
    assert_eq!(ledger.available(ResourceKey::vram(key)), Some(21 * GB));
}

#[test]
fn the_hosts_storage_budget_is_a_holder_apart_from_every_tenant() {
    // The owner of host storage quota (P02's integration item): the ledger charges every
    // reservation to a tenant budget, so the host's supervisor names a budget holder for
    // Yougori's own artifacts and sets its storage quota the way a tenant's is set. No
    // tenant has that budget, and the holder has no tenant's.
    let clock = start();
    let mut ledger = ledger_on(&clock);
    ledger
        .declare_capacity(STORAGE, host_probe(10 * GIB, 0))
        .unwrap();
    let host = tenant("host-budget");
    ledger
        .set_tenant_budget(host.clone(), STORAGE, 3 * GIB)
        .unwrap();
    let storage = |execution: &str, tenant_name: &str, bytes: u64| {
        ReservationRequest::new(
            Provenance {
                purpose: CostPurpose::Storage,
                ..provenance(Requester::ModelPlacement, execution, tenant_name)
            },
            Priority::Foreground,
            Amounts::new().storage_quota_bytes(bytes),
        )
    };

    // Set and spent: the host's reservation is charged to its holder and to no tenant.
    let image = granted(ledger.reserve(storage("exe-updater", "host-budget", 2 * GIB)));
    assert_eq!(ledger.tenant_budget(&host, STORAGE), 3 * GIB);
    assert_eq!(ledger.tenant_reserved(&host, STORAGE), 2 * GIB);
    for name in ["alpha", "beta"] {
        assert_eq!(ledger.tenant_budget(&tenant(name), STORAGE), 0);
        assert_eq!(ledger.tenant_reserved(&tenant(name), STORAGE), 0);
    }
    assert_eq!(ledger.reserved(STORAGE), 2 * GIB);
    let record = ledger.reservation(image).unwrap();
    assert_eq!(record.provenance().tenant, host);
    assert_eq!(record.provenance().purpose, CostPurpose::Storage);

    // A tenant cannot spend the host's budget: physical capacity is free, and alpha has
    // no storage budget of its own.
    let error = refused(ledger.reserve(storage("exe-alpha", "alpha", GIB)));
    assert_eq!(error.resource(), STORAGE);
    assert_eq!(
        error.limiting().limit,
        Limit::TenantBudget {
            tenant: tenant("alpha")
        }
    );
    assert_eq!(
        error.limiting().prospect,
        RetryProspect::ExceedsLimit { limit: 0 }
    );
    assert_eq!(ledger.available(STORAGE), Some(8 * GIB));

    // Overspend refused: the error names the storage quota and the host's holder, and
    // says what release would let it fit.
    let error = refused(ledger.reserve(storage("exe-updater-2", "host-budget", 2 * GIB)));
    assert_eq!(error.resource(), STORAGE);
    assert_eq!(
        error.limiting().limit,
        Limit::TenantBudget {
            tenant: host.clone()
        }
    );
    assert_eq!(
        error.limiting().prospect,
        RetryProspect::FitsAfterRelease { shortfall: GIB }
    );
    assert!(error.to_string().contains("storage quota"));
    assert!(error
        .to_string()
        .contains("the budget of tenant host-budget"));

    // Cancellation before creation returns it at once, and the closed record keeps the
    // host's holder as the charged party.
    assert_eq!(
        ledger.cancel(image),
        Ok(ReleaseOutcome::Released {
            amounts: Amounts::new().storage_quota_bytes(2 * GIB)
        })
    );
    assert_eq!(ledger.tenant_reserved(&host, STORAGE), 0);
    let closed = ledger
        .closed_records()
        .iter()
        .find(|record| record.id() == image)
        .unwrap();
    assert_eq!(closed.provenance().tenant, host);
    assert_eq!(
        closed.close_reason(),
        Some(CloseReason::CancelledBeforeCreate)
    );
    let again = granted(ledger.reserve(storage("exe-updater-2", "host-budget", 2 * GIB)));

    // After creation the bytes count until the host observes their release.
    ledger.begin_create(again).unwrap();
    assert_eq!(ledger.cancel(again), Ok(ReleaseOutcome::Pending));
    assert_eq!(ledger.tenant_reserved(&host, STORAGE), 2 * GIB);
    ledger
        .confirm_release(again, SourceClass::HostProbe)
        .unwrap();
    assert_eq!(ledger.tenant_reserved(&host, STORAGE), 0);
    assert_eq!(ledger.reserved(STORAGE), 0);
    assert_invariants(&ledger);
}

mod history_records;
mod lifecycle_parents;
mod load_slots;
mod observed_allocations;
mod queue_fairness;
mod reclamation;
mod shared_extents;
mod transition_peaks;
