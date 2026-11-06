use super::*;
use crate::foundation::ids::{ManualClock, MonotonicTime};

fn sample() -> HostSnapshot {
    HostSnapshot {
        host: probe::identity("1234567890abcdef1234567890abcdef").unwrap(),
        total: 32 * GIB,
        free: 20 * GIB,
        initialization_slots: 8,
        observed_at: MonotonicTime::ZERO,
    }
}

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(MonotonicTime::ZERO))
}

fn ram_request(tenant: TenantId, bytes: u64) -> ReservationRequest {
    ReservationRequest::new(
        Provenance {
            requester: Requester::Coordination,
            execution: ExecutionId::generate(),
            operation: OperationId::generate(),
            tenant,
            purpose: CostPurpose::VmResources,
            retry_number: 0,
        },
        Priority::Foreground,
        Amounts::new().host_ram_bytes(bytes),
    )
}

#[test]
fn vm_first_has_observed_ram_and_initialization_slots_without_any_gpu_or_implicit_budget() {
    let owner = Mutex::new(None);
    let clock = clock();
    let s = sample();
    let shared = publish(&owner, |host| Accounting::for_host(clock.clone(), host), &s).unwrap();
    let ledger = shared.lock().unwrap();
    assert_eq!(ledger.host(), s.host);
    assert_eq!(ledger.capacity(RAM).unwrap().total, 32 * GIB);
    assert_eq!(ledger.capacity(RAM).unwrap().unmanaged_in_use, 12 * GIB);
    assert_eq!(
        ledger.capacity(RAM).unwrap().supervisor_reserve,
        32 * GIB / 10
    );
    assert_eq!(ledger.capacity(CPU_INIT).unwrap().total, 8);
    assert_eq!(ledger.tenant_budget(&TenantId::new("vm").unwrap(), RAM), 0);
    assert!(owner.lock().unwrap().as_ref().unwrap().device.is_none());
}

#[test]
fn vm_and_model_first_share_the_ledger_and_keep_each_others_reservations_and_history() {
    for gpu_first in [false, true] {
        let clock = clock();
        let gpu = super::super::tests::sample(GIB);
        let s = sample();
        let owner = Mutex::new(if gpu_first {
            Some(Accounting::new(clock.clone(), &gpu))
        } else {
            None
        });
        let shared = publish(&owner, |host| Accounting::for_host(clock.clone(), host), &s).unwrap();
        let history = owner.lock().unwrap().as_ref().unwrap().history.clone();
        let vm = TenantId::new("vm").unwrap();
        let reservation = {
            let mut ledger = shared.lock().unwrap();
            ledger.set_tenant_budget(vm.clone(), RAM, 2 * GIB).unwrap();
            let Admission::Granted(id) = ledger.reserve(ram_request(vm.clone(), GIB)).unwrap()
            else {
                panic!("VM fits")
            };
            ledger.begin_create(id).unwrap();
            id
        };
        // GPU adoption must add a device, not replace the host owner.
        settle_on_host(
            &owner,
            || panic!("host already initialized"),
            |account| account.settle_and_reserve(&gpu, "model", Some(GIB)),
        )
        .unwrap();
        let again = publish(&owner, |_| panic!("one owner"), &s).unwrap();
        assert!(Arc::ptr_eq(&shared, &again));
        let locked = owner.lock().unwrap();
        let account = locked.as_ref().unwrap();
        assert!(Arc::ptr_eq(&history, &account.history));
        let ledger = again.lock().unwrap();
        assert_eq!(ledger.tenant_budget(&vm, RAM), 2 * GIB);
        assert!(ledger.open_reservations().any(|r| r.id() == reservation));
        assert!(ledger.reserved(ResourceKey::vram(gpu.device)) > 0);
        assert_eq!(ledger.reserved(RAM), GIB);
    }
}

#[test]
fn concurrent_vm_and_gpu_initializers_publish_one_owner() {
    let clock = clock();
    let owner = Arc::new(Mutex::new(None));
    let start = Arc::new(std::sync::Barrier::new(8));
    let mut joins = Vec::new();
    for i in 0..8 {
        let owner = owner.clone();
        let start = start.clone();
        let clock = clock.clone();
        joins.push(std::thread::spawn(move || {
            start.wait();
            if i % 2 == 0 {
                publish(&owner, |host| Accounting::for_host(clock, host), &sample()).unwrap()
            } else {
                let gpu = super::super::tests::sample(0);
                settle_on_host(
                    &owner,
                    || Accounting::new(clock, &gpu),
                    |account| account.settle_and_reserve(&gpu, "none", None),
                )
                .unwrap();
                owner.lock().unwrap().as_ref().unwrap().ledger.clone()
            }
        }));
    }
    let handles: Vec<_> = joins.into_iter().map(|j| j.join().unwrap()).collect();
    assert!(handles.iter().all(|h| Arc::ptr_eq(&handles[0], h)));
}

#[test]
fn delayed_probes_do_not_renew_their_freshness_and_failed_refresh_preserves_reservations() {
    let clock = clock();
    let owner = Mutex::new(None);
    let mut s = sample();
    clock.advance(Duration::from_secs(4));
    let shared = publish(&owner, |host| Accounting::for_host(clock.clone(), host), &s).unwrap();
    assert_eq!(
        shared.lock().unwrap().capacity(RAM).unwrap().observed_at,
        MonotonicTime::ZERO
    );
    let vm = TenantId::new("vm").unwrap();
    let id = {
        let mut ledger = shared.lock().unwrap();
        ledger.set_tenant_budget(vm.clone(), RAM, 4 * GIB).unwrap();
        let Admission::Granted(id) = ledger.reserve(ram_request(vm.clone(), GIB)).unwrap() else {
            panic!("fits")
        };
        ledger.begin_create(id).unwrap();
        id
    };
    clock.advance(Duration::from_secs(2));
    assert!(publish(&owner, |_| panic!("one owner"), &s).is_err());
    assert!(shared
        .lock()
        .unwrap()
        .reserve(ram_request(vm.clone(), GIB))
        .is_err());
    s.observed_at = clock.now();
    let refreshed = publish(&owner, |_| panic!("one owner"), &s).unwrap();
    assert!(Arc::ptr_eq(&shared, &refreshed));
    assert!(shared
        .lock()
        .unwrap()
        .open_reservations()
        .any(|r| r.id() == id));
    assert!(shared.lock().unwrap().reserve(ram_request(vm, GIB)).is_ok());
}

#[test]
fn changed_host_bad_memory_future_and_out_of_order_probes_cannot_overwrite_capacity() {
    let clock = clock();
    let owner = Mutex::new(None);
    let mut s = sample();
    clock.advance(Duration::from_secs(2));
    s.observed_at = clock.now();
    let shared = publish(&owner, |host| Accounting::for_host(clock.clone(), host), &s).unwrap();
    for kind in 0..6 {
        let mut bad = s.clone();
        match kind {
            0 => bad.host.machine = digest("another-host", &[]),
            1 => bad.total = 0,
            2 => bad.free = bad.total + 1,
            3 => bad.initialization_slots = 0,
            4 => bad.observed_at = MonotonicTime::ZERO,
            _ => bad.observed_at = clock.now().saturating_add(Duration::from_secs(1)),
        }
        assert!(publish(&owner, |_| panic!("one owner"), &bad).is_err());
        let capacity = shared.lock().unwrap().capacity(RAM).unwrap();
        assert_eq!(capacity.total, s.total);
        assert_eq!(capacity.observed_at, s.observed_at);
    }
    // Failed first initialization publishes no empty/fictional owner.
    let empty = Mutex::new(None);
    s.free = s.total + 1;
    assert!(publish(&empty, |host| Accounting::for_host(clock.clone(), host), &s).is_err());
    assert!(empty.lock().unwrap().is_none());
}

#[test]
fn observed_pressure_and_supervisor_reserve_limit_host_admission() {
    let owner = Mutex::new(None);
    let shared = publish(
        &owner,
        |host| Accounting::for_host(clock(), host),
        &sample(),
    )
    .unwrap();
    let vm = TenantId::new("vm").unwrap();
    let mut ledger = shared.lock().unwrap();
    ledger.set_tenant_budget(vm.clone(), RAM, 32 * GIB).unwrap();
    // Only 20 GiB free, and 3.2 GiB headroom is never granted.
    assert!(ledger.reserve(ram_request(vm.clone(), 17 * GIB)).is_err());
    assert!(ledger.reserve(ram_request(vm, 16 * GIB)).is_ok());
}

#[test]
fn host_only_refresh_collects_closed_records_into_the_existing_history_owner() {
    let owner = Mutex::new(None);
    let shared = publish(
        &owner,
        |host| Accounting::for_host(clock(), host),
        &sample(),
    )
    .unwrap();
    let vm = TenantId::new("vm").unwrap();
    {
        let mut ledger = shared.lock().unwrap();
        ledger.set_tenant_budget(vm.clone(), RAM, GIB).unwrap();
        let Admission::Granted(id) = ledger.reserve(ram_request(vm, GIB)).unwrap() else {
            panic!("fits")
        };
        ledger.cancel(id).unwrap();
    }
    publish(&owner, |_| panic!("one owner"), &sample()).unwrap();
    let owner = owner.lock().unwrap();
    let account = owner.as_ref().unwrap();
    assert!(account.device.is_none());
    assert!(account.history.lock().unwrap().totals().collected > 0);
}

#[test]
fn windows_reusable_memory_is_capped_by_physical_and_commit_headroom() {
    assert_eq!(windows_memory(64 * GIB, 30 * GIB, 40 * GIB).unwrap(), (64 * GIB, 30 * GIB));
    assert_eq!(windows_memory(64 * GIB, 30 * GIB, 2 * GIB).unwrap(), (64 * GIB, 2 * GIB));
    assert_eq!(windows_memory(64 * GIB, 30 * GIB, 0).unwrap(), (64 * GIB, 0));
    assert_eq!(windows_memory(64 * GIB, 0, 40 * GIB).unwrap(), (64 * GIB, 0));
    assert!(windows_memory(0, 0, GIB).is_err());
    assert!(windows_memory(64 * GIB, 65 * GIB, 80 * GIB).is_err());
}

#[test]
fn linux_keeps_its_explicit_free_page_probe() {
    let data = "MemTotal: 32000 kB\nMemFree: 1000 kB\nMemAvailable: 20000 kB\nCached: 19000 kB\n";
    assert_eq!(parse_meminfo(data).unwrap(), (32000 * 1024, 1000 * 1024));
    for text in [
        "MemTotal: 32 kB\nMemAvailable: 20 kB",
        "MemTotal: 32 kB\nMemFree: 33 kB",
        "MemTotal: 32 kB\nMemFree: 0 kB\nMemFree: 1 kB",
        "MemTotal: 32 bytes\nMemFree: 0 kB",
    ] {
        assert!(parse_meminfo(text).is_err(), "{text}");
    }
}

#[tokio::test]
async fn cancellation_does_not_start_the_host_probe() {
    let token = CancellationToken::new();
    token.cancel();
    assert!(observe(&token).await.unwrap_err().contains("cancelled"));
}

#[tokio::test]
#[ignore = "read-only Windows/Linux host capacity probe; no engine or workload"]
async fn actual_host_capacity_probe_without_a_gpu_query() {
    let sample = observe(&CancellationToken::new()).await.unwrap();
    sample.validate().unwrap();
    assert!(
        HOST_CLOCK
            .now()
            .saturating_duration_since(sample.observed_at)
            <= MAX_AGE
    );
}
