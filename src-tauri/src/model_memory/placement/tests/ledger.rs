//! Placement reservations through the committed CORE-03 ledger (task T04): child
//! reservations within the runtime's parent, the drain-first handover and releases
//! after reclamation.

use std::sync::Arc;
use std::time::Duration;

use crate::foundation::evidence::{HostSubject, SourceClass};
use crate::foundation::ids::{AuthorizationEpoch, Clock, ManualClock, MonotonicTime};
use crate::foundation::ledger::{
    self, Admission, Amounts, CapacityDeclaration, CostPurpose, HostResource, Ledger, LedgerConfig,
    Priority, Provenance, QueueLimits, Requester, ResourceKey,
};
use crate::model_memory::placement::fakes::FakeCoordination;
use crate::model_memory::placement::test_support::*;
use crate::model_memory::placement::*;

fn config() -> LedgerConfig {
    LedgerConfig {
        queue: QueueLimits {
            max_entries: 8,
            max_entries_per_tenant: 4,
            max_wait: Duration::from_secs(60),
        },
        grant_ttl: Duration::from_secs(60),
        unmanaged_usage_max_age: Duration::from_secs(24 * 3_600),
    }
}

fn vram_key() -> ResourceKey {
    ResourceKey::Vram(ledger_device(&gpu(0)))
}

struct Host {
    clock: Arc<ManualClock>,
    ledger: Ledger<Arc<ManualClock>>,
    runtime: ledger::ReservationId,
}

/// A host with `total_bytes` of VRAM and a runtime allocation of `runtime_bytes`;
/// `create_runtime` says whether the runtime's workload exists yet.
fn host(total_bytes: u64, runtime_bytes: u64, create_runtime: bool) -> Host {
    let clock = Arc::new(ManualClock::new(MonotonicTime::ZERO));
    let mut ledger = Ledger::new(
        Arc::clone(&clock),
        HostSubject { machine: machine() },
        config(),
    );
    ledger
        .declare_capacity(
            vram_key(),
            CapacityDeclaration {
                total: total_bytes,
                supervisor_reserve: 0,
                unmanaged_in_use: 0,
                source: SourceClass::HostProbe,
            },
        )
        .unwrap();
    ledger
        .set_tenant_budget(tenant(), vram_key(), total_bytes)
        .unwrap();
    let provenance = Provenance {
        requester: Requester::Coordination,
        execution: owner(),
        operation: op("runtime"),
        tenant: tenant(),
        purpose: CostPurpose::Compute,
        retry_number: 0,
    };
    let Admission::Granted(runtime) = ledger
        .reserve(ledger::ReservationRequest::new(
            provenance,
            Priority::Foreground,
            Amounts::new().vram_bytes(ledger_device(&gpu(0)), runtime_bytes),
        ))
        .unwrap()
    else {
        panic!("the runtime allocation is granted");
    };
    if create_runtime {
        ledger.begin_create(runtime).unwrap();
    }
    Host {
        clock,
        ledger,
        runtime,
    }
}

fn placement_config(parent: Option<ledger::ReservationId>) -> LedgerPlacementConfig {
    LedgerPlacementConfig {
        tenant: tenant(),
        priority: Priority::Foreground,
        parent,
        release_source: SourceClass::GuestReport,
    }
}

fn coordination() -> FakeCoordination {
    let mut coordination = FakeCoordination::new();
    coordination.authorize(&owner(), AuthorizationEpoch::FIRST);
    coordination
}

/// Steps 2–5 for a single-rank activation already begun.
fn load_and_publish<C: Clock>(
    slot: &mut PlacementSlot<C>,
    generation: crate::foundation::ids::ModelActivationGeneration,
    ports: &mut Ports<'_>,
) -> PublishReport {
    let progress = slot.prepare_extents(ports).unwrap();
    for (extent, _) in &progress.allocated {
        slot.record_extent_usable(*extent).unwrap();
    }
    slot.record_runtime_initialized().unwrap();
    slot.materialize().unwrap();
    slot.begin_activating().unwrap();
    slot.record_validation(&validation(generation, 0), ports)
        .unwrap();
    slot.record_readiness(generation, rank(0), &ready(), ports)
        .unwrap();
    slot.publish(ports).unwrap()
}

#[test]
fn placements_reserve_within_the_runtime_and_release_after_reclamation() {
    let mut host = host(24 * GB, 20 * GB, true);
    let mut state = LedgerReservations::new(placement_config(Some(host.runtime)));
    let mut coordination = coordination();
    let mut slot = PlacementSlot::new(slot_spec(), Arc::clone(&host.clock));
    let room = |host: &Host| host.ledger.parent_room(host.runtime, vram_key()).unwrap();

    // Step 1 reserves steady state and transition peak as children of the runtime.
    let first = {
        let mut port = state.port(&mut host.ledger);
        let mut ports = Ports {
            reservations: &mut port,
            coordination: &mut coordination,
        };
        slot.begin_activation(&request("model-a", &model_a(), &[]), &mut ports)
            .unwrap()
    };
    assert_eq!(room(&host), 20 * GB - 13 * GB);
    let children: Vec<_> = host
        .ledger
        .open_reservations()
        .filter(|record| record.parent() == Some(host.runtime))
        .collect();
    assert_eq!(children.len(), 2);
    assert!(children.iter().all(|record| record.provenance().requester
        == Requester::ModelPlacement
        && record.provenance().execution == owner()));

    // Publication releases the peak; the runtime's report confirms a child's release.
    let published = {
        let mut port = state.port(&mut host.ledger);
        let mut ports = Ports {
            reservations: &mut port,
            coordination: &mut coordination,
        };
        load_and_publish(&mut slot, first.generation, &mut ports)
    };
    assert_eq!(room(&host), 20 * GB - 12 * GB);

    // Two versions do not fit in the runtime: the old one drains first, and its share
    // passes to the new one instead of returning to the pool.
    let second = {
        let mut port = state.port(&mut host.ledger);
        let mut ports = Ports {
            reservations: &mut port,
            coordination: &mut coordination,
        };
        slot.begin_activation(&request("model-b", &model_b(), &[]), &mut ports)
            .unwrap()
    };
    assert_eq!(second.mode, TransitionMode::DrainFirst);
    let PauseReason::SingleGenerationCapacity { refusal } = second.pause.unwrap().reason;
    assert_eq!(refusal.resource, ResourceKind::Vram { device: gpu(0) });
    assert_eq!(refusal.retry, RetryOutlook::FitsAfterRelease);
    assert_eq!(
        room(&host),
        20 * GB - 12 * GB - GB,
        "only the new peak was added"
    );

    slot.park(published.placement).unwrap();
    {
        let mut port = state.port(&mut host.ledger);
        slot.reclaim(published.placement, &mut port).unwrap();
    }
    assert_eq!(
        room(&host),
        20 * GB - 13 * GB,
        "the old share now belongs to the new placement"
    );

    let switched = {
        let mut port = state.port(&mut host.ledger);
        let mut ports = Ports {
            reservations: &mut port,
            coordination: &mut coordination,
        };
        load_and_publish(&mut slot, second.generation, &mut ports)
    };
    assert_eq!(room(&host), 20 * GB - 12 * GB);

    // Releasing after reclamation returns everything to the runtime.
    slot.begin_draining(switched.placement).unwrap();
    slot.park(switched.placement).unwrap();
    {
        let mut port = state.port(&mut host.ledger);
        slot.reclaim(switched.placement, &mut port).unwrap();
    }
    assert_eq!(room(&host), 20 * GB);
    assert!(state.unconfirmed_releases().is_empty());
}

#[test]
fn a_host_level_release_counts_until_the_host_observes_it() {
    let mut host = host(24 * GB, 4 * GB, true);
    let mut state = LedgerReservations::new(placement_config(None));
    let mut coordination = coordination();
    let mut slot = PlacementSlot::new(slot_spec(), Arc::clone(&host.clock));
    {
        let mut port = state.port(&mut host.ledger);
        let mut ports = Ports {
            reservations: &mut port,
            coordination: &mut coordination,
        };
        let started = slot
            .begin_activation(&request("model-a", &model_a(), &[]), &mut ports)
            .unwrap();
        load_and_publish(&mut slot, started.generation, &mut ports);
    }
    // The released peak is not free until a host probe confirms it.
    assert_eq!(state.unconfirmed_releases().len(), 1);
    assert_eq!(
        host.ledger.available(vram_key()),
        Some(24 * GB - 4 * GB - 13 * GB)
    );
    assert_eq!(
        state
            .port(&mut host.ledger)
            .confirm_releases(SourceClass::GuestReport),
        0
    );
    assert_eq!(
        state
            .port(&mut host.ledger)
            .confirm_releases(SourceClass::HostProbe),
        1
    );
    assert!(state.unconfirmed_releases().is_empty());
    assert_eq!(
        host.ledger.available(vram_key()),
        Some(24 * GB - 4 * GB - 12 * GB)
    );
}

#[test]
fn a_refusal_that_is_not_about_capacity_leaves_nothing_reserved() {
    let mut host = host(24 * GB, 20 * GB, false);
    let mut state = LedgerReservations::new(placement_config(Some(host.runtime)));
    let mut coordination = coordination();
    let mut slot = PlacementSlot::new(slot_spec(), Arc::clone(&host.clock));
    let mut port = state.port(&mut host.ledger);
    let mut ports = Ports {
        reservations: &mut port,
        coordination: &mut coordination,
    };
    assert_eq!(
        slot.begin_activation(&request("model-a", &model_a(), &[]), &mut ports),
        Err(ActivationError::Reservation {
            refusal: ReservationRefusal::Refused {
                problem: ReservationProblem::ParentNotCreated
            },
            mode: TransitionMode::Initial
        })
    );
    drop(ports);
    drop(port);
    assert_eq!(
        host.ledger.parent_room(host.runtime, vram_key()),
        Ok(20 * GB)
    );
    assert!(state.unconfirmed_releases().is_empty());
    assert!(slot.placement_keys().is_empty());
}

#[test]
fn pinned_memory_is_charged_to_host_ram_as_well() {
    // 16 GB of host RAM, of which at most 8 GB may be pinned.
    let clock = Arc::new(ManualClock::new(MonotonicTime::ZERO));
    let mut ledger = Ledger::new(
        Arc::clone(&clock),
        HostSubject { machine: machine() },
        config(),
    );
    let ram = ResourceKey::Host(HostResource::Ram);
    let pinned = ResourceKey::Host(HostResource::PinnedRam);
    for (resource, total) in [(vram_key(), 24 * GB), (ram, 16 * GB), (pinned, 8 * GB)] {
        ledger
            .declare_capacity(
                resource,
                CapacityDeclaration {
                    total,
                    supervisor_reserve: 0,
                    unmanaged_in_use: 0,
                    source: SourceClass::HostProbe,
                },
            )
            .unwrap();
        ledger.set_tenant_budget(tenant(), resource, total).unwrap();
    }
    let mut state = LedgerReservations::new(LedgerPlacementConfig {
        tenant: tenant(),
        priority: Priority::Foreground,
        parent: None,
        release_source: SourceClass::HostProbe,
    });
    let mut coordination = coordination();
    let mut slot = PlacementSlot::new(slot_spec(), Arc::clone(&clock));

    // 12 GB of pageable memory and 6 GB pinned each fit their own pool, but pinned pages
    // are host RAM too: together they need 18 GB of the host's 16 GB.
    let mut too_much = request("model-a", &model_a(), &[]);
    too_much.steady.host_ram_bytes = 12 * GB;
    too_much.steady.pinned_host_bytes = 6 * GB;
    {
        let mut port = state.port(&mut ledger);
        let mut ports = Ports {
            reservations: &mut port,
            coordination: &mut coordination,
        };
        assert_eq!(
            slot.begin_activation(&too_much, &mut ports),
            Err(ActivationError::Reservation {
                refusal: ReservationRefusal::Capacity {
                    refusal: CapacityRefusal {
                        resource: ResourceKind::HostRam,
                        requested_bytes: 18 * GB,
                        available_bytes: 16 * GB,
                        retry: RetryOutlook::ExceedsCapacity,
                    }
                },
                mode: TransitionMode::Initial,
            })
        );
    }
    assert_eq!(ledger.reserved(ram), 0);
    assert_eq!(ledger.reserved(pinned), 0);
    assert!(slot.placement_keys().is_empty());

    // 8 GB pageable and 6 GB pinned fit: host RAM is charged 14 GB, the pinned pool 6 GB.
    let mut fits = request("model-a", &model_a(), &[]);
    fits.steady.host_ram_bytes = 8 * GB;
    fits.steady.pinned_host_bytes = 6 * GB;
    {
        let mut port = state.port(&mut ledger);
        let mut ports = Ports {
            reservations: &mut port,
            coordination: &mut coordination,
        };
        slot.begin_activation(&fits, &mut ports).unwrap();
    }
    assert_eq!(ledger.reserved(ram), 14 * GB);
    assert_eq!(ledger.reserved(pinned), 6 * GB);
}
