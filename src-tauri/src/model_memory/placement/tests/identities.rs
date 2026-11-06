//! Identities and generations: adapter updates (line 599), the distinct typed
//! generations of S3.1, and placement identities built by the identity layers (T07).

use std::collections::BTreeSet;

use crate::foundation::ids::{AuthorizationEpoch, GpuAllocationGeneration, MonotonicTime};
use crate::model_memory::identity::PlacementSpec;
use crate::model_memory::placement::test_support::*;
use crate::model_memory::placement::*;

#[test]
fn adapter_updates_get_their_own_identity() {
    let mut world = World::new(32 * GB);
    let first = world.activate(&request("model-a", &with_adapter("tone"), &["tone"]));
    let mut pinned = world.admission("pinned");
    pinned.adapter = Some(adapter_of("tone"));
    let pinned = world
        .slot
        .admit(&pinned, &mut world.fakes.coordination)
        .unwrap();

    let second = world.activate(&request("model-a", &with_adapter("tone-v2"), &["tone-v2"]));
    assert_ne!(adapter_of("tone"), adapter_of("tone-v2"));
    assert_ne!(
        first.placement, second.placement,
        "an adapter update is a new placement, never an in-place change"
    );
    let old = world.slot.content(first.generation).unwrap();
    let new = world.slot.published().unwrap();
    assert_eq!(old.adapters.get(&0), Some(&adapter_of("tone")));
    assert_eq!(new.adapters.get(&0), Some(&adapter_of("tone-v2")));
    assert_eq!(
        old.execution, new.execution,
        "the base execution is the same"
    );

    // The pinned request keeps the adapter it was admitted with.
    assert_eq!(
        world.slot.weight_for(&pinned, at(0, Component::Adapter(0))),
        Ok(extent("tone-weights"))
    );
    // A new request for the old adapter is refused, never served by the new one.
    let mut late = world.admission("late");
    late.adapter = Some(adapter_of("tone"));
    assert_eq!(
        world.slot.admit(&late, &mut world.fakes.coordination),
        Err(RouteRefusal::AdapterNotPublished {
            adapter: adapter_of("tone")
        })
    );
    let mut current = world.admission("current");
    current.adapter = Some(adapter_of("tone-v2"));
    world
        .slot
        .admit(&current, &mut world.fakes.coordination)
        .unwrap();

    // Reclaiming the old placement frees only the old adapter; the base stays.
    world.finish(&pinned);
    let reclaimed = world.park_and_reclaim(first.placement);
    assert_eq!(
        reclaimed
            .freed
            .iter()
            .map(|freed| freed.extent)
            .collect::<Vec<_>>(),
        vec![extent("tone-weights")]
    );
    assert_eq!(reclaimed.retained_shared.len(), 4);
}

#[test]
fn an_adapter_identity_naming_other_weights_is_refused() {
    let mut world = World::new(32 * GB);
    world.activate(&request("model-a", &with_adapter("tone"), &["tone"]));

    // New weights under the old identity would be an in-place update.
    let in_place = request("model-a", &with_adapter("tone-v2"), &["tone"]);
    assert_eq!(
        world
            .slot
            .begin_activation(&in_place, &mut world.fakes.ports()),
        Err(ActivationError::AdapterIdentityReused {
            adapter: adapter_of("tone"),
            index: 0
        })
    );

    // One identity for two different weights in one request is refused too.
    let mut parts = model_a();
    parts.push(part(Component::Adapter(0), "x-weights", GB));
    parts.push(part(Component::Adapter(1), "y-weights", GB));
    let twice = request("model-c", &parts, &["same", "same"]);
    assert_eq!(
        world
            .slot
            .begin_activation(&twice, &mut world.fakes.ports()),
        Err(ActivationError::AdapterIdentityReused {
            adapter: adapter_of("same"),
            index: 1
        })
    );
    assert_eq!(world.slot.activation(), None);
}

#[test]
fn changing_one_generation_never_refreshes_another() {
    let mut world = World::new(48 * GB);
    let first = world.activate(&request("model-a", &with_adapter("tone"), &["tone"]));
    let old = world.admit("old");
    let base: BTreeSet<GpuAllocationGeneration> = world
        .slot
        .placement(first.placement)
        .unwrap()
        .gpu
        .allocations;

    world.begin(&request("model-a", &with_adapter("tone-v2"), &["tone-v2"]));
    let progress = world.load();
    assert_eq!(
        progress.acquired.len(),
        4,
        "the base is acquired, not reallocated"
    );
    assert_eq!(progress.allocated.len(), 1);
    let (new_extent, new_allocation) = progress.allocated[0];
    assert_eq!(new_extent, extent("tone-v2-weights"));
    assert!(!base.contains(&new_allocation));
    world.validate_and_ready();
    let second = world.publish();

    // The activation generation moved; the base's allocation generations did not.
    assert!(second.generation > first.generation);
    let now_held = world
        .slot
        .placement(second.placement)
        .unwrap()
        .gpu
        .allocations;
    assert_eq!(base.intersection(&now_held).count(), 4);

    // The old request keeps its generation and epoch; nothing renewed or extended it.
    let lease = world.fakes.coordination.lease(old.lease).unwrap();
    assert_eq!(lease.request.generation, first.generation);
    assert_eq!(lease.request.epoch, AuthorizationEpoch::FIRST);
    assert_eq!(
        lease.request.expires_at,
        MonotonicTime::ZERO.saturating_add(HOUR)
    );

    // Revocation raises the authorization epoch and leaves every activation
    // generation as it was; the revoked lease ends.
    assert_eq!(
        world.fakes.coordination.revoke(&owner()),
        Some(AuthorizationEpoch::new(2))
    );
    assert_eq!(world.published_generation(), Some(second.generation));
    let ended = world.slot.reconcile_leases(&world.fakes.coordination);
    assert_eq!(
        ended
            .iter()
            .map(|lease| (lease.request.clone(), lease.status))
            .collect::<Vec<_>>(),
        vec![(op("old"), LeaseStatus::Revoked)]
    );
    // The slot stays bound to its epoch: neither the old nor the new one is admitted.
    assert_eq!(
        world
            .slot
            .admit(&world.admission("stale"), &mut world.fakes.coordination),
        Err(RouteRefusal::LeaseRefused {
            refusal: CoordinationRefusal::StaleAuthorization {
                presented: AuthorizationEpoch::FIRST,
                current: AuthorizationEpoch::new(2)
            }
        })
    );
    let mut newer = world.admission("newer");
    newer.epoch = AuthorizationEpoch::new(2);
    assert_eq!(
        world.slot.admit(&newer, &mut world.fakes.coordination),
        Err(RouteRefusal::AuthorityMismatch {
            presented: AuthorizationEpoch::new(2),
            bound: Some(AuthorizationEpoch::FIRST)
        })
    );
}

#[test]
fn placement_identities_follow_the_generation_the_leases_and_the_allocation() {
    let mut world = World::new(48 * GB);
    let first = world.activate(&request("model-a", &model_a(), &[]));
    let allocation = world
        .slot
        .placement(first.placement)
        .unwrap()
        .gpu
        .allocations
        .into_iter()
        .max()
        .unwrap();
    let expected = |activation, leases: BTreeSet<_>| {
        PlacementSpec {
            artifact: artifact_of("model-a"),
            execution: execution_of("model-a", 1),
            device: gpu(0),
            owner: tenant(),
            authority: authority(),
            activation,
            allocation,
            leases,
        }
        .identity()
    };

    let at_publish = world.slot.placement_identities(first.generation).unwrap()[&rank(0)];
    assert_eq!(at_publish, expected(first.generation, BTreeSet::new()));
    let ticket = world.admit("r1");
    let held = world.slot.placement_identities(first.generation).unwrap()[&rank(0)];
    assert_eq!(
        held,
        expected(first.generation, BTreeSet::from([ticket.lease]))
    );
    assert_ne!(held, at_publish, "current leases are part of the identity");
    world.finish(&ticket);
    assert_eq!(
        world.slot.placement_identities(first.generation).unwrap()[&rank(0)],
        at_publish
    );

    // Activating the same placement again changes only the activation generation.
    world.slot.begin_draining(first.placement).unwrap();
    world.slot.park(first.placement).unwrap();
    assert_eq!(world.slot.placement_identities(first.generation), None);
    world.begin(&reuse(request("model-a", &model_a(), &[]), first.placement));
    world.load();
    world.validate_and_ready();
    let again = world.publish();
    let reactivated = world.slot.placement_identities(again.generation).unwrap()[&rank(0)];
    assert_eq!(reactivated, expected(again.generation, BTreeSet::new()));
    assert_ne!(reactivated, at_publish);
}
