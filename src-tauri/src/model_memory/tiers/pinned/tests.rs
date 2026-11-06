use super::*;
use crate::foundation::catalog::{ObjectRole, ReadRefusal};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{ManualClock, MonotonicTime};
use crate::foundation::ledger::{Amounts, Limit, ReleaseOutcome, Requester};
use crate::model_memory::tiers::fakes::{
    charge, consumer, declare, execution, host_scope, in_vm, model, path, publish, read_handle,
    source_id, world, World, GB, GIB, MIB, PINNED, RAM,
};

/// Host RAM of 64 GiB keeping 2 GiB, and a hard host-wide cap of `cap_bytes` keeping
/// 128 MiB; memlock scopes keep 1 MiB and rings are at most 256 MiB.
fn limits(cap_bytes: u64) -> PinnedLimits {
    PinnedLimits {
        host_ram: host_scope("host-ram", HostScopeKind::HostRam, None, 64 * GIB, 2 * GIB),
        wsl: WslLimit::NotWsl,
        host_wide_cap: host_scope(
            "pinned-cap",
            HostScopeKind::PinnedRam,
            None,
            cap_bytes,
            128 * MIB,
        ),
        memlock_reserve_bytes: MIB,
        max_ring_bytes: 256 * MIB,
    }
}

/// A world whose ledger has 64 GiB of host RAM and 8 GiB of pinned RAM for alice and bob.
fn setup() -> World {
    let mut world = world(&["alice", "bob"]);
    declare(&mut world.ledger, RAM, 64 * GIB, &["alice", "bob"]);
    declare(&mut world.ledger, PINNED, 8 * GIB, &["alice", "bob"]);
    world
}

fn tier(cap_bytes: u64, executions: &[(&str, MemlockLimit)]) -> PinnedHostTier {
    let mut tier = PinnedHostTier::new(limits(cap_bytes));
    for (name, limit) in executions {
        tier.register_execution(execution(name), *limit);
    }
    tier
}

fn ring(
    pinned: &mut PinnedHostTier,
    world: &mut World,
    owner: &Consumer,
    bytes: u64,
) -> Result<PinId, PinnedRefusal> {
    pinned.pin_ring(
        owner,
        bytes,
        &charge("op-ring"),
        &mut world.ledger,
        &world.clock,
    )
}

/// The scopes the host check names as not fitting.
fn does_not_fit(refusal: PinnedRefusal) -> Vec<String> {
    match refusal {
        PinnedRefusal::Host(HostError::DoesNotFit(overcommits)) => overcommits
            .into_iter()
            .map(|overcommit| overcommit.scope)
            .collect(),
        other => panic!("expected the host check to refuse, got {other:?}"),
    }
}

/// 21 * 8 = 168 s of saving against 120 + 40 s of cost (line 550).
const WORTH: ImportAmortization = ImportAmortization {
    expected_uses: 21.0,
    per_use_saving_seconds: 8.0,
    preparation_cost_seconds: 120.0,
    retention_penalty_seconds: 40.0,
};

#[test]
fn a_pin_is_charged_to_host_ram_and_to_pinned_ram() {
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let mut pinned = tier(GIB, &[("exe-alice-1", MemlockLimit::Unlimited)]);
    let pin = ring(&mut pinned, &mut world, &alice, 64 * MIB).unwrap();
    assert_eq!(pinned.pinned_bytes(), 64 * MIB);
    assert_eq!(pinned.pinned_bytes_of(&alice.execution), 64 * MIB);
    // Decision T08: pinned pages are host RAM, and the pinned pool is a cap inside it.
    assert_eq!(world.ledger.reserved(RAM), 64 * MIB);
    assert_eq!(world.ledger.reserved(PINNED), 64 * MIB);
    assert_eq!(
        world.ledger.tenant_reserved(&alice.tenant, PINNED),
        64 * MIB
    );
    let reservation = pinned.reservation(pin).unwrap();
    let record = world.ledger.reservation(reservation).unwrap();
    assert_eq!(
        record.granted(),
        &Amounts::new()
            .host_ram_bytes(64 * MIB)
            .pinned_host_ram_bytes(64 * MIB)
    );
    assert_eq!(record.provenance().requester, Requester::ModelPlacement);
    assert_eq!(record.provenance().purpose, CostPurpose::Transfer);
    assert_eq!(record.provenance().tenant, alice.tenant);

    // Unpinned pages count until the host observes them released.
    let released = pinned.unpin(pin, &mut world.ledger).unwrap();
    assert_eq!(
        (released.bytes, released.reservation, released.outcome),
        (64 * MIB, reservation, ReleaseOutcome::Pending)
    );
    assert_eq!(pinned.pinned_bytes(), 0);
    assert_eq!(world.ledger.reserved(PINNED), 64 * MIB);
    world
        .ledger
        .confirm_release(reservation, SourceClass::HostProbe)
        .unwrap();
    assert_eq!(
        (world.ledger.reserved(RAM), world.ledger.reserved(PINNED)),
        (0, 0)
    );
    assert_eq!(
        pinned.unpin(pin, &mut world.ledger),
        Err(PinnedRefusal::UnknownPin { pin })
    );
    assert_eq!(
        pinned.reservation(pin),
        Err(PinnedRefusal::UnknownPin { pin })
    );
}

#[test]
fn the_hard_host_wide_cap_holds_across_executions() {
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let bob = consumer("bob", "exe-bob-1");
    // A 1 GiB cap keeping 128 MiB leaves 896 MiB for every runtime's pins together.
    let mut pinned = tier(
        GIB,
        &[
            ("exe-alice-1", MemlockLimit::Unlimited),
            ("exe-bob-1", MemlockLimit::Unlimited),
        ],
    );
    for _ in 0..3 {
        ring(&mut pinned, &mut world, &alice, 256 * MIB).unwrap();
    }
    let refusal = ring(&mut pinned, &mut world, &bob, 256 * MIB).unwrap_err();
    assert_eq!(does_not_fit(refusal), ["pinned-cap"]);
    assert_eq!(world.ledger.reserved(PINNED), 768 * MIB);
    assert_eq!(pinned.pinned_bytes_of(&bob.execution), 0);
    // Exactly what is left fits: 768 + 128 MiB of pins and the 128 MiB reserve make 1 GiB.
    ring(&mut pinned, &mut world, &bob, 128 * MIB).unwrap();
    assert_eq!(pinned.pinned_bytes(), 896 * MIB);
    let one_more = ring(&mut pinned, &mut world, &bob, 1).unwrap_err();
    assert_eq!(does_not_fit(one_more), ["pinned-cap"]);
    // Every pin held is pinned demand on host RAM and on the cap.
    let plan = pinned.host_plan(None, &world.clock).unwrap();
    assert_eq!(plan.demands.len(), 4);
    assert!(plan.demands.iter().all(|demand| {
        demand.backing == HostBacking::Pinned
            && demand.memory_scope == "host-ram"
            && demand.pinned_scope.as_deref() == Some("pinned-cap")
    }));
    let adding = pinned.host_plan(Some((&bob, MIB)), &world.clock).unwrap();
    assert_eq!(adding.demands.len(), 5);
    assert_eq!(adding.demands[4].label, "new pin");
}

#[test]
fn memlock_limits_nest_under_the_cap_and_must_be_known() {
    let mut world = setup();
    let first = consumer("alice", "exe-alice-1");
    let second = consumer("alice", "exe-alice-2");
    let mut pinned = tier(
        4 * GIB,
        &[
            ("exe-alice-1", MemlockLimit::Bytes(256 * MIB)),
            ("exe-alice-2", MemlockLimit::Bytes(256 * MIB)),
        ],
    );
    ring(&mut pinned, &mut world, &first, 200 * MIB).unwrap();
    // 200 + 100 MiB and the 1 MiB reserve exceed exe-alice-1's 256 MiB limit.
    let refusal = ring(&mut pinned, &mut world, &first, 100 * MIB).unwrap_err();
    assert_eq!(does_not_fit(refusal), ["memlock exe-alice-1"]);
    // Another execution has its own limit under the same cap.
    ring(&mut pinned, &mut world, &second, 100 * MIB).unwrap();
    let plan = pinned.host_plan(None, &world.clock).unwrap();
    let memlocks: Vec<(&str, Option<&str>)> = plan
        .scopes
        .iter()
        .filter(|scope| scope.name.starts_with("memlock"))
        .map(|scope| (scope.name.as_str(), scope.parent.as_deref()))
        .collect();
    assert_eq!(
        memlocks,
        [
            ("memlock exe-alice-1", Some("pinned-cap")),
            ("memlock exe-alice-2", Some("pinned-cap"))
        ]
    );
    assert_eq!(world.ledger.reserved(PINNED), 300 * MIB);

    // An unknown or unrecorded limit is not an unlimited one.
    pinned.register_execution(execution("exe-alice-3"), MemlockLimit::Unknown);
    assert_eq!(
        ring(
            &mut pinned,
            &mut world,
            &consumer("alice", "exe-alice-3"),
            MIB
        ),
        Err(PinnedRefusal::MemlockUnknown {
            execution: execution("exe-alice-3")
        })
    );
    assert_eq!(
        ring(
            &mut pinned,
            &mut world,
            &consumer("alice", "exe-alice-4"),
            MIB
        ),
        Err(PinnedRefusal::UnregisteredExecution {
            execution: execution("exe-alice-4")
        })
    );
    // Every scope keeps a reserve (§2.7), so a memlock scope without one is refused.
    let mut no_reserve = PinnedHostTier::new(PinnedLimits {
        memlock_reserve_bytes: 0,
        ..limits(4 * GIB)
    });
    no_reserve.register_execution(execution("exe-alice-1"), MemlockLimit::Bytes(256 * MIB));
    assert_eq!(
        ring(&mut no_reserve, &mut world, &first, MIB),
        Err(PinnedRefusal::Host(HostError::NoSafetyReserve {
            scope: "memlock exe-alice-1".to_string()
        }))
    );
    assert_eq!(world.ledger.reserved(PINNED), 300 * MIB);
}

#[test]
fn inside_wsl_the_vm_limit_applies_and_page_cache_is_not_free() {
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let mut unknown = PinnedHostTier::new(PinnedLimits {
        wsl: WslLimit::Unknown,
        ..limits(4 * GIB)
    });
    unknown.register_execution(alice.execution.clone(), MemlockLimit::Unlimited);
    assert_eq!(
        ring(&mut unknown, &mut world, &alice, MIB),
        Err(PinnedRefusal::WslLimitUnknown)
    );
    assert_eq!(
        unknown.host_plan(None, &world.clock),
        Err(PinnedRefusal::WslLimitUnknown)
    );

    // The WSL VM has 16 GiB keeping 1 GiB; 14 GiB is committed and 768 MiB is page cache.
    let mut vm = host_scope(
        "wsl-vm",
        HostScopeKind::WslVm,
        Some("host-ram"),
        16 * GIB,
        GIB,
    );
    vm.occupancy = ScopeOccupancy {
        committed_bytes: 14 * GIB,
        page_cache_bytes: 768 * MIB,
        unattributed_bytes: 0,
    };
    let in_wsl = |vm: &HostScope| {
        let mut tier = PinnedHostTier::new(PinnedLimits {
            wsl: WslLimit::Vm(vm.clone()),
            ..limits(4 * GIB)
        });
        tier.register_execution(alice.execution.clone(), MemlockLimit::Unlimited);
        tier
    };
    let mut pinned = in_wsl(&vm);
    // 14 GiB + 768 MiB + 256 MiB + the 1 GiB reserve make exactly 16 GiB.
    ring(&mut pinned, &mut world, &alice, 256 * MIB).unwrap();
    let refusal = ring(&mut pinned, &mut world, &alice, 1).unwrap_err();
    assert_eq!(does_not_fit(refusal), ["wsl-vm"]);
    let plan = pinned.host_plan(None, &world.clock).unwrap();
    assert_eq!(plan.demands[0].memory_scope, "wsl-vm");
    // Host RAM had room; the page cache made the difference, because it is not free.
    vm.occupancy.page_cache_bytes = 0;
    let mut without_cache = in_wsl(&vm);
    ring(&mut without_cache, &mut world, &alice, 256 * MIB).unwrap();
    ring(&mut without_cache, &mut world, &alice, 1).unwrap();
}

#[test]
fn an_address_reservation_is_no_cap() {
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let mut reserved_only = limits(4 * GIB);
    reserved_only.host_wide_cap.capacity = Capacity::VirtualReservation { bytes: 64 * GIB };
    let mut pinned = PinnedHostTier::new(reserved_only);
    pinned.register_execution(alice.execution.clone(), MemlockLimit::Unlimited);
    // §2.7: virtual address reservation does not supply physical capacity.
    assert_eq!(
        ring(&mut pinned, &mut world, &alice, MIB),
        Err(PinnedRefusal::Host(
            HostError::VirtualReservationIsNotCapacity {
                scope: "pinned-cap".to_string()
            }
        ))
    );
    assert_eq!(world.ledger.reserved(PINNED), 0);
}

#[test]
fn rings_are_small_and_every_pin_has_bytes() {
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let mut pinned = tier(4 * GIB, &[("exe-alice-1", MemlockLimit::Unlimited)]);
    assert_eq!(
        ring(&mut pinned, &mut world, &alice, 256 * MIB + 1),
        Err(PinnedRefusal::RingTooLarge {
            max_ring_bytes: 256 * MIB,
            requested_bytes: 256 * MIB + 1,
        })
    );
    assert_eq!(
        ring(&mut pinned, &mut world, &alice, 0),
        Err(PinnedRefusal::ZeroBytes)
    );
    // At the clock's last instant no interval starts, so nothing is admitted.
    let last = ManualClock::new(MonotonicTime::from_nanos(u64::MAX));
    assert_eq!(
        pinned.pin_ring(&alice, MIB, &charge("op-ring"), &mut world.ledger, &last),
        Err(PinnedRefusal::ClockExhausted)
    );
    assert_eq!(pinned.pinned_bytes(), 0);
    assert_eq!(world.ledger.reserved(PINNED), 0);
}

#[test]
fn only_selected_high_value_clean_representations_are_pinned() {
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let mut pinned = tier(4 * GIB, &[("exe-alice-1", MemlockLimit::Unlimited)]);
    let object = publish(
        &mut world.catalog,
        &alice,
        &[7; 1_000],
        ObjectRole::Original,
    );
    let other = publish(&mut world.catalog, &alice, b"other", ObjectRole::Original);
    let handle = read_handle(&mut world.catalog, &alice, &object).unwrap();
    let pin = |pinned: &mut PinnedHostTier,
               world: &mut World,
               named: &ObjectRef,
               state: CopyState,
               value: &ImportAmortization| {
        pinned.pin_representation(
            &alice,
            named,
            &handle,
            &world.catalog,
            state,
            value,
            &charge("op-pin"),
            &mut world.ledger,
            &world.clock,
        )
    };
    // The read handle, the catalog's proof of read authority, must be for that object.
    assert_eq!(
        pin(
            &mut pinned,
            &mut world,
            &other,
            CopyState::VerifiedClean,
            &WORTH
        ),
        Err(PinnedRefusal::HandleMismatch {
            named: other.id(),
            handle: object.id(),
        })
    );
    for state in [CopyState::Unverified, CopyState::Dirty] {
        assert_eq!(
            pin(&mut pinned, &mut world, &object, state, &WORTH),
            Err(PinnedRefusal::NotClean { state })
        );
    }
    // At break even, 20 * 8 = 160 is not more than 120 + 40: not selected (line 550).
    let break_even = ImportAmortization {
        expected_uses: 20.0,
        ..WORTH
    };
    assert_eq!(
        pin(
            &mut pinned,
            &mut world,
            &object,
            CopyState::VerifiedClean,
            &break_even
        ),
        Err(PinnedRefusal::NotSelected {
            benefit_seconds: 160.0,
            cost_seconds: 160.0,
        })
    );
    let not_a_number = ImportAmortization {
        per_use_saving_seconds: f64::NAN,
        ..WORTH
    };
    assert_eq!(
        pin(
            &mut pinned,
            &mut world,
            &object,
            CopyState::VerifiedClean,
            &not_a_number
        ),
        Err(PinnedRefusal::Amortization(AmortizationError::NotFinite {
            term: "per_use_saving_seconds"
        }))
    );
    assert_eq!(world.ledger.reserved(PINNED), 0);

    // 21 * 8 = 168 > 160: pinned at the object's true length, as stored data.
    let pinned_id = pin(
        &mut pinned,
        &mut world,
        &object,
        CopyState::VerifiedClean,
        &WORTH,
    )
    .unwrap();
    assert_eq!(pinned.pinned_bytes(), 1_000);
    assert_eq!(world.ledger.reserved(PINNED), 1_000);
    assert_eq!(world.ledger.reserved(RAM), 1_000);
    let record = world
        .ledger
        .reservation(pinned.reservation(pinned_id).unwrap())
        .unwrap();
    assert_eq!(record.provenance().purpose, CostPurpose::Storage);
    assert_eq!(
        pin(
            &mut pinned,
            &mut world,
            &object,
            CopyState::VerifiedClean,
            &WORTH
        ),
        Err(PinnedRefusal::AlreadyPinned {
            object: object.clone()
        })
    );
    // A pinned clean copy reconstructs a dropped GPU copy (T08) of the owner's tenant and
    // trust scope.
    let copy = pinned.copy_of(&object).unwrap();
    assert_eq!(
        (&copy.object, copy.holder.as_ref()),
        (&object, Some(&alice))
    );
    assert_eq!(copy.copy.tier, CopyTier::PinnedHost);
    assert!(copy.copy.reconstructs(&Content::Immutable(object.content)));
    assert!(copy.may_rebuild(&object, &consumer("alice", "exe-alice-2")));
    assert!(!copy.may_rebuild(&object, &in_vm("alice", "exe-alice-vm")));
    assert!(!copy.may_rebuild(&object, &consumer("bob", "exe-bob-1")));
    assert_eq!(pinned.copy_of(&other), None);
    // Bob gets no handle on Alice's object without a grant, so none of it is pinned for
    // him.
    assert!(matches!(
        read_handle(&mut world.catalog, &consumer("bob", "exe-bob-1"), &object),
        Err(ReadRefusal::NotGranted { .. })
    ));
}

#[test]
fn a_pin_serves_only_its_owners_tenant_and_trust_scope() {
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let mut pinned = tier(4 * GIB, &[("exe-alice-1", MemlockLimit::Unlimited)]);
    let object = publish(
        &mut world.catalog,
        &alice,
        &[7; 1_000],
        ObjectRole::Original,
    );
    let handle = read_handle(&mut world.catalog, &alice, &object).unwrap();
    pinned
        .pin_representation(
            &alice,
            &object,
            &handle,
            &world.catalog,
            CopyState::VerifiedClean,
            &WORTH,
            &charge("op-pin"),
            &mut world.ledger,
            &world.clock,
        )
        .unwrap();
    let route = || path(20.0 * GB, 0.0, &[]);
    let offer = pinned
        .offer(
            source_id("pinned"),
            &object,
            &consumer("alice", "exe-alice-2"),
            route(),
        )
        .unwrap();
    assert_eq!(
        (offer.tier(), offer.covers_bytes()),
        (Tier::PinnedHost, 1_000)
    );
    assert_eq!(offer.object(), &object);
    assert_eq!(offer.requester(), &consumer("alice", "exe-alice-2"));
    for stranger in [consumer("bob", "exe-bob-1"), in_vm("alice", "exe-alice-vm")] {
        let refusal = pinned
            .offer(source_id("pinned"), &object, &stranger, route())
            .unwrap_err();
        assert_eq!(refusal.tier, Tier::PinnedHost);
        assert_eq!(
            refusal.reason,
            TierRefusal::Pinned(PinnedRefusal::OutsideScope {
                requester: Box::new(stranger.clone()),
                owner: Box::new(alice.clone()),
            })
        );
    }
    let elsewhere = ObjectRef {
        content: crate::foundation::ids::ContentKey::of(b"not pinned"),
        ..object.clone()
    };
    assert_eq!(
        pinned
            .offer(source_id("pinned"), &elsewhere, &alice, route())
            .unwrap_err()
            .reason,
        TierRefusal::Pinned(PinnedRefusal::NotPinned { object: elsewhere })
    );
}

#[test]
fn the_ledger_can_refuse_what_the_host_check_allows() {
    let mut world = world(&["alice", "bob"]);
    declare(&mut world.ledger, RAM, 64 * GIB, &["alice"]);
    declare(&mut world.ledger, PINNED, 128 * MIB, &["alice"]);
    let alice = consumer("alice", "exe-alice-1");
    let mut pinned = tier(
        4 * GIB,
        &[
            ("exe-alice-1", MemlockLimit::Unlimited),
            ("exe-bob-1", MemlockLimit::Unlimited),
        ],
    );
    // T08's 4 GiB cap would allow 256 MiB, but the host's pinned RAM is 128 MiB, and the
    // ledger is the capacity authority (§3.1 line 491).
    let capacity = match ring(&mut pinned, &mut world, &alice, 256 * MIB) {
        Err(PinnedRefusal::Ledger(LedgerError::Capacity(capacity))) => capacity,
        other => panic!("expected the ledger to refuse, got {other:?}"),
    };
    assert_eq!(capacity.resource(), PINNED);
    assert_eq!(capacity.limiting().limit, Limit::PhysicalCapacity);
    assert_eq!(
        (capacity.limiting().requested, capacity.limiting().available),
        (256 * MIB, 128 * MIB)
    );
    // Granted whole or not at all: no host RAM was reserved either, and nothing is pinned.
    assert_eq!(
        (world.ledger.reserved(RAM), world.ledger.reserved(PINNED)),
        (0, 0)
    );
    assert_eq!(pinned.pinned_bytes(), 0);
    // A tenant without a budget has none (decision T04).
    match ring(&mut pinned, &mut world, &consumer("bob", "exe-bob-1"), MIB) {
        Err(PinnedRefusal::Ledger(LedgerError::Capacity(capacity))) => {
            assert!(matches!(
                capacity.limiting().limit,
                Limit::TenantBudget { .. }
            ));
        }
        other => panic!("expected the tenant budget to refuse, got {other:?}"),
    }
}

#[test]
fn evictions_take_only_pinned_host_copies() {
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let mut pinned = tier(4 * GIB, &[("exe-alice-1", MemlockLimit::Unlimited)]);
    let object = publish(
        &mut world.catalog,
        &alice,
        &[7; 1_000],
        ObjectRole::Original,
    );
    let handle = read_handle(&mut world.catalog, &alice, &object).unwrap();
    pinned
        .pin_representation(
            &alice,
            &object,
            &handle,
            &world.catalog,
            CopyState::VerifiedClean,
            &WORTH,
            &charge("op-pin"),
            &mut world.ledger,
            &world.clock,
        )
        .unwrap();
    let eviction = |object: &ObjectRef, tier, kind| PlannedEviction {
        model: model("alice", "llama-8b"),
        object: object.clone(),
        kind,
        tier,
        bytes: 1_000,
    };
    for (tier, kind) in [
        (Tier::ReclaimableHost, DerivedKind::HostCopy),
        (Tier::PinnedHost, DerivedKind::RawPrepared),
    ] {
        assert_eq!(
            pinned.evict(&eviction(&object, tier, kind), &mut world.ledger),
            Err(PinnedRefusal::WrongEviction { tier, kind })
        );
    }
    let other = crate::model_memory::tiers::fakes::weights("alice", "not pinned");
    assert_eq!(
        pinned.evict(
            &eviction(&other, Tier::PinnedHost, DerivedKind::HostCopy),
            &mut world.ledger
        ),
        Err(PinnedRefusal::NotPinned { object: other })
    );
    let released = pinned
        .evict(
            &eviction(&object, Tier::PinnedHost, DerivedKind::HostCopy),
            &mut world.ledger,
        )
        .unwrap();
    assert_eq!(
        (released.bytes, released.outcome),
        (1_000, ReleaseOutcome::Pending)
    );
    assert_eq!(pinned.copy_of(&object), None);
    assert_eq!(pinned.pinned_bytes(), 0);
}

#[test]
fn a_read_handle_never_lets_another_tenant_pin_private_weights() {
    // Review R1-c: a read handle does not record who opened it, so the tier asks the
    // catalog whether the owner itself may read the object (line 546).
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let bob = consumer("bob", "exe-bob-1");
    let mut pinned = tier(
        4 * GIB,
        &[
            ("exe-alice-1", MemlockLimit::Unlimited),
            ("exe-bob-1", MemlockLimit::Unlimited),
        ],
    );
    let private = publish(
        &mut world.catalog,
        &alice,
        &[7; 1_000],
        ObjectRole::Original,
    );
    let alices_handle = read_handle(&mut world.catalog, &alice, &private).unwrap();
    let pin = |pinned: &mut PinnedHostTier, world: &mut World, owner: &Consumer| {
        pinned.pin_representation(
            owner,
            &private,
            &alices_handle,
            &world.catalog,
            CopyState::VerifiedClean,
            &WORTH,
            &charge("op-pin"),
            &mut world.ledger,
            &world.clock,
        )
    };
    assert_eq!(
        pin(&mut pinned, &mut world, &bob),
        Err(PinnedRefusal::Unreadable(ReadRefusal::NotGranted {
            object: private.id()
        }))
    );
    assert_eq!(pinned.pinned_bytes(), 0);
    assert_eq!(world.ledger.reserved(PINNED), 0);
    // Alice may pin her own object with her own handle.
    pin(&mut pinned, &mut world, &alice).unwrap();
    assert_eq!(pinned.pinned_bytes_of(&alice.execution), 1_000);
}
