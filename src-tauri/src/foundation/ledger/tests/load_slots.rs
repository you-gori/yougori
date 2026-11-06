//! Concurrent GPU model loads (S10 line 351): load slots are counted per device, refused
//! with an actionable error naming them, queued until a load ends, never granted before
//! the host observes them, refused for another machine's device, kept apart from VRAM,
//! serialized strictly, and reserved through the coordination port like any resource.

use std::collections::BTreeMap;

use super::*;
use crate::foundation::coordination::{
    CapacityLimit, CapacityPort, CapacityRefusal, LedgerCapacity, ReservationKey,
    ReservationPriority, ReservationPurpose, ReservationRequest as PortRequest, ReserveOutcome,
    ResourceKind, RetryProspect as PortRetry,
};
use crate::foundation::ids::SandboxBootGeneration;

fn slots(device: u8) -> ResourceKey {
    ResourceKey::gpu_load_slots(gpu(device))
}

fn load(execution: &str, device: u8) -> ReservationRequest {
    ReservationRequest::new(
        provenance(Requester::ModelPlacement, execution, "alpha"),
        Priority::Foreground,
        Amounts::new()
            .gpu_load_slots(gpu(device), 1)
            .vram_bytes(gpu(device), 4 * GB),
    )
}

/// The test ledger with two load slots on GPU 0 and one on GPU 1, and budgets for them.
fn with_slots(clock: &ManualClock) -> Ledger<&ManualClock> {
    let mut ledger = ledger_on(clock);
    ledger.declare_capacity(slots(0), host_probe(2, 0)).unwrap();
    ledger
        .declare_capacity(vram(1), host_probe(24 * GB, GB))
        .unwrap();
    ledger.declare_capacity(slots(1), host_probe(1, 0)).unwrap();
    for resource in [slots(0), slots(1), vram(1)] {
        ledger
            .set_tenant_budget(tenant("alpha"), resource, u64::MAX)
            .unwrap();
    }
    ledger
}

#[test]
fn concurrent_model_loads_are_counted_per_device_and_wait_for_a_free_slot() {
    let clock = start();
    let mut ledger = with_slots(&clock);
    assert_eq!(slots(0).unit(), ResourceUnit::Slots);
    assert_eq!(slots(0).device(), Some(gpu(0)));
    let first = granted(ledger.reserve(load("exe-a", 0)));
    granted(ledger.reserve(load("exe-b", 0)));
    // The third load on GPU 0 does not fit, though VRAM does; GPU 1 is counted apart.
    let error = refused(ledger.reserve(load("exe-c", 0)));
    assert_eq!(error.resource(), slots(0));
    assert_eq!(error.limiting().limit, Limit::PhysicalCapacity);
    assert_eq!(
        error.limiting().prospect,
        RetryProspect::FitsAfterRelease { shortfall: 1 }
    );
    assert!(error.to_string().contains("model load slots on GPU"));
    assert!(error.to_string().contains("slots"));
    assert_eq!(ledger.available(vram(0)), Some(15 * GB));
    granted(ledger.reserve(load("exe-c", 1)));
    assert_eq!(ledger.available(slots(1)), Some(0));

    // A waiting load is granted once a load ends.
    let ticket = queued(ledger.reserve(load("exe-d", 0).wait_up_to(MINUTE)));
    ledger.begin_create(first).unwrap();
    ledger.cancel(first).unwrap();
    assert_eq!(ledger.queue_position(ticket), Some(0));
    ledger
        .confirm_release(first, SourceClass::HostProbe)
        .unwrap();
    assert_eq!(ledger.queue_position(ticket), None);
    assert!(ledger.drain_events().iter().any(
        |event| matches!(event, LedgerEvent::QueueGranted { ticket: woken, .. } if *woken == ticket)
    ));
    assert_eq!(ledger.reserved(slots(0)), 2);
}

#[test]
fn load_slots_need_a_host_observation_and_a_device_of_this_host() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    ledger
        .set_tenant_budget(tenant("alpha"), slots(0), u64::MAX)
        .unwrap();
    // Never observed: none is free, and only a host observation declares it.
    let error = refused(ledger.reserve(load("exe-a", 0)));
    assert_eq!(error.resource(), slots(0));
    assert_eq!(error.limiting().limit, Limit::CapacityNotObserved);
    assert_eq!(
        ledger.declare_capacity(
            slots(0),
            CapacityDeclaration {
                source: SourceClass::GuestReport,
                ..host_probe(2, 0)
            }
        ),
        Err(LedgerError::SourceNotAuthoritative {
            source: SourceClass::GuestReport,
            required: SourceClass::HostProbe,
        })
    );
    // Another machine's device is refused as its VRAM is.
    let foreign = GpuDeviceKey {
        machine: digest("yougori/test/machine/v1", &[b"elsewhere"]),
        device: digest("yougori/test/gpu/v1", &[&[0]]),
    };
    assert_eq!(
        ledger.declare_capacity(ResourceKey::gpu_load_slots(foreign), host_probe(2, 0)),
        Err(LedgerError::ForeignDevice {
            device: DeviceId::from(foreign)
        })
    );
}

#[test]
fn load_slots_serialize_as_a_strict_list() {
    let amounts = Amounts::new()
        .gpu_load_slots(gpu(0), 2)
        .vram_bytes(gpu(0), GB);
    let text = serde_json::to_string(&amounts).unwrap();
    assert!(text.contains("\"gpu_load_slots\""), "{text}");
    assert_eq!(serde_json::from_str::<Amounts>(&text).unwrap(), amounts);
    assert_eq!(amounts.get(slots(0)), 2);
    assert_eq!(amounts.get(vram(0)), GB);
}

#[test]
fn the_coordination_port_reserves_load_slots_and_names_them_when_refused() {
    let clock = start();
    let mut port = LedgerCapacity::new(with_slots(&clock));
    let request = |name: &str, boot: u64| {
        let execution = ExecutionId::new(name).unwrap();
        let purpose = ReservationPurpose::Sandbox {
            boot: SandboxBootGeneration::new(boot),
        };
        PortRequest {
            key: ReservationKey::derive(&execution, &purpose),
            tenant: tenant("alpha"),
            execution,
            purpose,
            priority: ReservationPriority::Foreground,
            parent: None,
            demand: BTreeMap::from([(ResourceKind::GpuLoadSlots { device: gpu_key(1) }, 1)]),
        }
    };
    assert_eq!(
        port.reserve(&request("exe-a", 1)),
        Ok(ReserveOutcome::Granted)
    );
    assert_eq!(port.ledger().reserved(slots(1)), 1);
    let refusal = port.reserve(&request("exe-b", 1)).unwrap_err();
    assert_eq!(
        refusal,
        CapacityRefusal::Insufficient {
            resource: ResourceKind::GpuLoadSlots { device: gpu_key(1) },
            limit: CapacityLimit::Host,
            requested: 1,
            available: 0,
            retry: PortRetry::CanProgress,
        }
    );
    assert!(refusal.to_string().contains("model load slots of GPU"));
}
