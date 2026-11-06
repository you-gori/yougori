use super::*;
use crate::foundation::catalog::{GrantRequest, ObjectRole, ReadRefusal};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::ContentKey;
use crate::foundation::ledger::{Amounts, Limit, ReleaseOutcome};
use crate::model_memory::residency::host::{HostScopeKind, ScopeOccupancy};
use crate::model_memory::tiers::fakes::{
    at_seconds, charge, consumer, declare, host_scope, in_vm, model, path, publish, read_handle,
    source_id, tenant, world, World, GB, MIB, RAM,
};

const MAX_AGE: Duration = Duration::from_secs(30);

/// Host RAM of 10,000 bytes keeping 1,000, and the reclaimable budget: a 2,600-byte
/// cgroup keeping 100 nested in it. Estimates are stale after 30 s.
fn scopes(host_page_cache_bytes: u64) -> Vec<HostScope> {
    let mut host_ram = host_scope("host-ram", HostScopeKind::HostRam, None, 10_000, 1_000);
    host_ram.occupancy = ScopeOccupancy {
        page_cache_bytes: host_page_cache_bytes,
        ..ScopeOccupancy::default()
    };
    vec![
        host_ram,
        host_scope(
            "reclaimable",
            HostScopeKind::Cgroup,
            Some("host-ram"),
            2_600,
            100,
        ),
    ]
}

fn tier(host_page_cache_bytes: u64) -> ReclaimableHostTier {
    ReclaimableHostTier::new(
        scopes(host_page_cache_bytes),
        "reclaimable".to_string(),
        MAX_AGE,
    )
}

/// A world whose ledger has 1 MiB of host RAM for alice and bob.
fn setup() -> World {
    let mut world = world(&["alice", "bob"]);
    declare(&mut world.ledger, RAM, MIB, &["alice", "bob"]);
    world
}

/// Publishes 1,000 bytes starting with `name` for `owner`.
fn object(world: &mut World, owner: &Consumer, name: &str) -> ObjectRef {
    let mut bytes = name.as_bytes().to_vec();
    bytes.resize(1_000, b'.');
    publish(&mut world.catalog, owner, &bytes, ObjectRole::Original)
}

/// `holder` reads `object` through a fresh read handle and admits it verified.
fn admit(
    cache: &mut ReclaimableHostTier,
    world: &mut World,
    holder: &Consumer,
    object: &ObjectRef,
    content: HostContent,
) -> Result<(), HostRefusal> {
    let handle = read_handle(&mut world.catalog, holder, object).unwrap();
    cache.admit(
        holder,
        object.clone(),
        &handle,
        &world.catalog,
        content,
        Verification::Verified,
        &charge("op-cache"),
        &mut world.ledger,
        &world.clock,
    )
}

/// The scopes the host check names as not fitting.
fn does_not_fit(refusal: HostRefusal) -> Vec<String> {
    match refusal {
        HostRefusal::Host(HostError::DoesNotFit(overcommits)) => overcommits
            .into_iter()
            .map(|overcommit| overcommit.scope)
            .collect(),
        other => panic!("expected the host check to refuse, got {other:?}"),
    }
}

#[test]
fn every_entry_is_charged_in_full_whatever_its_estimate() {
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let first = object(&mut world, &alice, "first");
    let second = object(&mut world, &alice, "second");
    let third = object(&mut world, &alice, "third");
    let mut cache = tier(0);
    admit(
        &mut cache,
        &mut world,
        &alice,
        &first,
        HostContent::VerifiedPageCache,
    )
    .unwrap();
    assert_eq!(cache.used_bytes(), 1_000);
    assert_eq!(world.ledger.reserved(RAM), 1_000);
    // mincore says a tenth is resident; the charge stays whole.
    cache.observe(&first, 100, &world.clock).unwrap();
    assert_eq!(cache.used_bytes(), 1_000);
    admit(
        &mut cache,
        &mut world,
        &alice,
        &second,
        HostContent::HostCopy,
    )
    .unwrap();
    // 3 × 1,000 + the 100-byte reserve exceed the 2,600-byte budget, however little of
    // the first entry is resident.
    let refusal = admit(
        &mut cache,
        &mut world,
        &alice,
        &third,
        HostContent::VerifiedPageCache,
    )
    .unwrap_err();
    assert_eq!(does_not_fit(refusal), ["reclaimable"]);
    assert_eq!(cache.used_bytes(), 2_000);
    assert_eq!(world.ledger.reserved(RAM), 2_000);
    // Each entry is host RAM in the ledger, never pinned RAM, charged to its holder.
    let record = world
        .ledger
        .reservation(cache.reservation_of(&first).unwrap())
        .unwrap();
    assert_eq!(record.granted(), &Amounts::new().host_ram_bytes(1_000));
    assert_eq!(record.provenance().purpose, CostPurpose::Storage);
    assert_eq!(record.provenance().tenant, alice.tenant);
    // Page cache is charged as page cache, a host copy as anonymous memory.
    let plan = cache.host_plan(None, &world.clock).unwrap();
    let mut backings: Vec<String> = plan
        .demands
        .iter()
        .map(|demand| format!("{:?}", demand.backing))
        .collect();
    backings.sort();
    assert_eq!(backings, ["Anonymous", "PageCache"]);
    assert!(plan
        .demands
        .iter()
        .all(|demand| demand.memory_scope == "reclaimable" && demand.pinned_scope.is_none()));
    assert_eq!(
        cache
            .host_plan(Some((HostContent::HostCopy, 1)), &world.clock)
            .unwrap()
            .demands
            .len(),
        3
    );
}

#[test]
fn observed_page_cache_and_usage_are_never_free() {
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let first = object(&mut world, &alice, "first");
    let second = object(&mut world, &alice, "second");
    // 7,500 bytes of host RAM are page cache the plan does not account for.
    let mut cache = tier(7_500);
    admit(
        &mut cache,
        &mut world,
        &alice,
        &first,
        HostContent::HostCopy,
    )
    .unwrap();
    // 2,000 + 7,500 + the 1,000-byte reserve exceed host RAM's 10,000, though the budget
    // has room.
    let refusal = admit(
        &mut cache,
        &mut world,
        &alice,
        &second,
        HostContent::HostCopy,
    )
    .unwrap_err();
    assert_eq!(does_not_fit(refusal), ["host-ram"]);
    // Counted as free, that page cache would have let the entry in.
    let mut uncounted = tier(0);
    admit(
        &mut uncounted,
        &mut world,
        &alice,
        &first,
        HostContent::HostCopy,
    )
    .unwrap();
    admit(
        &mut uncounted,
        &mut world,
        &alice,
        &second,
        HostContent::HostCopy,
    )
    .unwrap();
}

#[test]
fn residency_estimates_go_stale() {
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let reader = consumer("alice", "exe-alice-2");
    let first = object(&mut world, &alice, "first");
    let mut cache = tier(0);
    admit(
        &mut cache,
        &mut world,
        &alice,
        &first,
        HostContent::VerifiedPageCache,
    )
    .unwrap();
    let route = || path(10.0 * GB, 0.0, &[]);
    let offer = |cache: &ReclaimableHostTier, world: &World| {
        cache.offer(
            source_id("page-cache"),
            &first,
            &reader,
            route(),
            &world.clock,
        )
    };
    let refused = |cache: &ReclaimableHostTier, world: &World| match offer(cache, world) {
        Err(refusal) => refusal.reason,
        Ok(offer) => panic!("expected a refusal, got {offer:?}"),
    };
    assert_eq!(
        cache.residency(&first, &world.clock),
        Ok(Residency::NeverObserved)
    );
    assert_eq!(
        refused(&cache, &world),
        TierRefusal::Host(HostRefusal::NoEstimate {
            object: first.clone()
        })
    );
    // Reclaimable is never guaranteed resident, whatever is known (§2.7).
    let copy = cache.host_copy(&first, &world.clock).unwrap();
    assert_eq!(
        (
            copy.guaranteed_resident_bytes(),
            copy.advisory_resident_bytes()
        ),
        (0, None)
    );

    cache.observe(&first, 1_000, &world.clock).unwrap();
    world.clock.advance(Duration::from_secs(29));
    assert_eq!(
        cache.residency(&first, &world.clock),
        Ok(Residency::Fresh {
            resident_bytes: 1_000,
            age: Duration::from_secs(29),
        })
    );
    let served = offer(&cache, &world).unwrap();
    assert_eq!(served.requester(), &reader);
    assert_eq!(
        (served.tier(), served.covers_bytes()),
        (Tier::ReclaimableHost, 1_000)
    );
    let copy = cache.host_copy(&first, &world.clock).unwrap();
    assert_eq!(
        (
            copy.guaranteed_resident_bytes(),
            copy.advisory_resident_bytes()
        ),
        (0, Some(1_000))
    );

    // At the maximum age the estimate is stale: unknown, not "still resident".
    world.clock.advance(Duration::from_secs(1));
    assert_eq!(
        cache.residency(&first, &world.clock),
        Ok(Residency::Stale {
            observed_at: at_seconds(0),
            age: MAX_AGE,
        })
    );
    assert_eq!(
        refused(&cache, &world),
        TierRefusal::Host(HostRefusal::StaleEstimate {
            object: first.clone(),
            age: MAX_AGE,
        })
    );
    assert_eq!(
        cache.host_copy(&first, &world.clock).unwrap().residency,
        HostResidency::Reclaimable {
            mincore_resident_bytes: None
        }
    );

    // A fresh estimate short of the whole entry does not let it serve.
    cache.observe(&first, 999, &world.clock).unwrap();
    assert_eq!(
        refused(&cache, &world),
        TierRefusal::Host(HostRefusal::NotFullyResident {
            object: first.clone(),
            resident_bytes: 999,
            entry_bytes: 1_000,
        })
    );
    assert_eq!(
        cache.observe(&first, 1_001, &world.clock),
        Err(HostRefusal::EstimateExceedsEntry {
            resident_bytes: 1_001,
            entry_bytes: 1_000,
        })
    );
    let unheld = ObjectRef {
        content: ContentKey::of(b"never admitted"),
        ..first.clone()
    };
    assert_eq!(
        cache.observe(&unheld, 1, &world.clock),
        Err(HostRefusal::NotHeld { object: unheld })
    );
}

#[test]
fn entries_enter_verified_through_a_read_handle_for_that_object() {
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let bob = consumer("bob", "exe-bob-1");
    let first = object(&mut world, &alice, "first");
    let second = object(&mut world, &alice, "second");
    let mut cache = tier(0);
    let handle = read_handle(&mut world.catalog, &alice, &second).unwrap();
    let enter =
        |cache: &mut ReclaimableHostTier, world: &mut World, named: &ObjectRef, verification| {
            cache.admit(
                &alice,
                named.clone(),
                &handle,
                &world.catalog,
                HostContent::HostCopy,
                verification,
                &charge("op-cache"),
                &mut world.ledger,
                &world.clock,
            )
        };
    assert_eq!(
        enter(&mut cache, &mut world, &first, Verification::Verified),
        Err(HostRefusal::HandleMismatch {
            named: first.id(),
            handle: second.id(),
        })
    );
    assert_eq!(
        enter(&mut cache, &mut world, &second, Verification::Unverified),
        Err(HostRefusal::Unverified {
            content: HostContent::HostCopy
        })
    );
    enter(&mut cache, &mut world, &second, Verification::Verified).unwrap();
    assert_eq!(
        enter(&mut cache, &mut world, &second, Verification::Verified),
        Err(HostRefusal::AlreadyHeld {
            object: second.clone()
        })
    );
    // Bob gets no handle on Alice's object without a grant (line 546)...
    assert!(matches!(
        read_handle(&mut world.catalog, &bob, &first),
        Err(ReadRefusal::NotGranted { .. })
    ));
    // ...and under a grant for exactly that object his copy is charged to his own tenant.
    world
        .catalog
        .grant(
            &alice.scope(),
            GrantRequest {
                object: first.id(),
                grantee: bob.scope(),
                execution: None,
                expires_at: at_seconds(3_600),
            },
        )
        .unwrap();
    admit(&mut cache, &mut world, &bob, &first, HostContent::HostCopy).unwrap();
    assert_eq!(world.ledger.tenant_reserved(&tenant("bob"), RAM), 1_000);
    assert_eq!(world.ledger.tenant_reserved(&tenant("alice"), RAM), 1_000);
}

#[test]
fn host_copies_serve_only_their_holders_scope_and_never_rebuild_a_gpu_copy() {
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let first = object(&mut world, &alice, "first");
    let mut cache = tier(0);
    admit(
        &mut cache,
        &mut world,
        &alice,
        &first,
        HostContent::HostCopy,
    )
    .unwrap();
    cache.observe(&first, 1_000, &world.clock).unwrap();
    let route = || path(10.0 * GB, 0.0, &[]);
    for stranger in [consumer("bob", "exe-bob-1"), in_vm("alice", "exe-alice-vm")] {
        assert_eq!(
            cache
                .offer(source_id("copy"), &first, &stranger, route(), &world.clock)
                .unwrap_err()
                .reason,
            TierRefusal::Host(HostRefusal::OutsideScope {
                requester: Box::new(stranger.clone()),
                holder: Box::new(alice.clone()),
            })
        );
    }
    cache
        .offer(
            source_id("copy"),
            &first,
            &consumer("alice", "exe-alice-2"),
            route(),
            &world.clock,
        )
        .unwrap();
    // T08: reclaimable memory may vanish, so even a verified copy here forces a write-back
    // or keeps the GPU copy.
    let copy = cache.copy_of(&first).unwrap();
    assert_eq!((&copy.object, copy.holder.as_ref()), (&first, Some(&alice)));
    assert_eq!(copy.copy.tier, CopyTier::ReclaimableHost);
    assert!(!copy.copy.reconstructs(&Content::Immutable(first.content)));
}

#[test]
fn releases_and_evictions_return_host_ram_through_the_ledger() {
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let first = object(&mut world, &alice, "first");
    let second = object(&mut world, &alice, "second");
    let mut cache = tier(0);
    admit(
        &mut cache,
        &mut world,
        &alice,
        &first,
        HostContent::VerifiedPageCache,
    )
    .unwrap();
    admit(
        &mut cache,
        &mut world,
        &alice,
        &second,
        HostContent::HostCopy,
    )
    .unwrap();
    let eviction = |object: &ObjectRef, tier| PlannedEviction {
        model: model("alice", "llama-8b"),
        object: object.clone(),
        kind: DerivedKind::HostCopy,
        tier,
        bytes: 1_000,
    };
    assert_eq!(
        cache.release_page_cache(&second, &mut world.ledger),
        Err(HostRefusal::WrongContent {
            object: second.clone(),
            content: HostContent::HostCopy,
        })
    );
    assert_eq!(
        cache.evict(&eviction(&first, Tier::ReclaimableHost), &mut world.ledger),
        Err(HostRefusal::WrongContent {
            object: first.clone(),
            content: HostContent::VerifiedPageCache,
        })
    );
    assert_eq!(
        cache.evict(&eviction(&second, Tier::PinnedHost), &mut world.ledger),
        Err(HostRefusal::WrongEviction {
            tier: Tier::PinnedHost,
            kind: DerivedKind::HostCopy,
        })
    );
    let page_cache = cache.reservation_of(&first).unwrap();
    let released = cache.release_page_cache(&first, &mut world.ledger).unwrap();
    assert_eq!(
        (released.bytes, released.reservation, released.outcome),
        (1_000, page_cache, ReleaseOutcome::Pending)
    );
    assert_eq!(cache.used_bytes(), 1_000);
    // The host RAM counts until the host observes it released.
    assert_eq!(world.ledger.reserved(RAM), 2_000);
    world
        .ledger
        .confirm_release(page_cache, SourceClass::HostProbe)
        .unwrap();
    assert_eq!(world.ledger.reserved(RAM), 1_000);
    cache
        .evict(&eviction(&second, Tier::ReclaimableHost), &mut world.ledger)
        .unwrap();
    assert_eq!(cache.used_bytes(), 0);
    assert_eq!(
        cache.release_page_cache(&first, &mut world.ledger),
        Err(HostRefusal::NotHeld {
            object: first.clone()
        })
    );
}

#[test]
fn the_ledger_refuses_host_ram_beyond_the_tenant_budget() {
    let mut world = setup();
    world
        .ledger
        .set_tenant_budget(tenant("alice"), RAM, 500)
        .unwrap();
    let alice = consumer("alice", "exe-alice-1");
    let first = object(&mut world, &alice, "first");
    let mut cache = tier(0);
    match admit(
        &mut cache,
        &mut world,
        &alice,
        &first,
        HostContent::HostCopy,
    ) {
        Err(HostRefusal::Ledger(LedgerError::Capacity(capacity))) => {
            assert_eq!(capacity.resource(), RAM);
            assert_eq!(
                capacity.limiting().limit,
                Limit::TenantBudget {
                    tenant: tenant("alice")
                }
            );
            assert_eq!(capacity.limiting().available, 500);
        }
        other => panic!("expected the tenant budget to refuse, got {other:?}"),
    }
    assert_eq!(cache.used_bytes(), 0);
    assert_eq!(cache.reservation_of(&first), None);
}

#[test]
fn a_read_handle_never_lets_another_tenant_hold_private_weights() {
    // Review R1-c: a read handle does not record who opened it, so the tier asks the
    // catalog whether the holder itself may read the object (line 546).
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let bob = consumer("bob", "exe-bob-1");
    let private = object(&mut world, &alice, "private");
    let alices_handle = read_handle(&mut world.catalog, &alice, &private).unwrap();
    let mut cache = tier(0);
    let hold = |cache: &mut ReclaimableHostTier, world: &mut World, holder: &Consumer| {
        cache.admit(
            holder,
            private.clone(),
            &alices_handle,
            &world.catalog,
            HostContent::HostCopy,
            Verification::Verified,
            &charge("op-cache"),
            &mut world.ledger,
            &world.clock,
        )
    };
    assert_eq!(
        hold(&mut cache, &mut world, &bob),
        Err(HostRefusal::Unreadable(ReadRefusal::NotGranted {
            object: private.id()
        }))
    );
    assert_eq!(cache.used_bytes(), 0);
    assert_eq!(world.ledger.tenant_reserved(&tenant("bob"), RAM), 0);
    hold(&mut cache, &mut world, &alice).unwrap();
    assert_eq!(world.ledger.tenant_reserved(&tenant("alice"), RAM), 1_000);
}
