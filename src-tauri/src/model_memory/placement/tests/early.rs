//! Execute-while-load under a preparation-generation lease (§3.6 line 601) and the
//! dependency chain of §2.6.

use crate::foundation::ids::{AuthorizationEpoch, ExecutionId, MonotonicTime};
use crate::model_memory::placement::test_support::*;
use crate::model_memory::placement::*;

/// Two layers and the output head: a dense model's first token needs all three.
fn chain_model() -> Vec<Part> {
    vec![
        part(Component::Layer(0), "c-layer-0", 2 * GB),
        part(Component::Layer(1), "c-layer-1", 2 * GB),
        part(Component::OutputHead, "c-head", GB),
    ]
}

fn chain() -> Vec<WeightPosition> {
    vec![
        at(0, Component::Layer(0)),
        at(0, Component::Layer(1)),
        at(0, Component::OutputHead),
    ]
}

fn assigned(world: &World, name: &str, required: &[WeightPosition]) -> AssignedRequest {
    AssignedRequest {
        request: op(name),
        execution: owner(),
        epoch: AuthorizationEpoch::FIRST,
        required: required.iter().copied().collect(),
        lease_expires_at: world.now().saturating_add(HOUR),
    }
}

fn assign_request(
    world: &mut World,
    assigned: &AssignedRequest,
) -> Result<RequestTicket, EarlyRefusal> {
    world
        .slot
        .assign_early_request(assigned, &mut world.fakes.coordination)
}

fn assign(
    world: &mut World,
    name: &str,
    required: &[WeightPosition],
) -> Result<RequestTicket, EarlyRefusal> {
    let assigned = assigned(world, name, required);
    assign_request(world, &assigned)
}

/// Begins the chain model's activation and allocates its extents, none usable yet.
fn preparing(world: &mut World) -> ActivationStarted {
    let started = world.begin(&request("model-c", &chain_model(), &[]));
    world
        .slot
        .prepare_extents(&mut world.fakes.ports())
        .unwrap();
    started
}

/// Steps 2–5 once every extent is usable.
fn publish_prepared(world: &mut World) -> PublishReport {
    world.slot.record_runtime_initialized().unwrap();
    world.slot.materialize().unwrap();
    world.validate_and_ready();
    world.publish()
}

fn compute(world: &mut World, request: &str, position: WeightPosition) {
    world
        .slot
        .start_early_compute(&op(request), position)
        .unwrap();
    world
        .slot
        .finish_early_compute(&op(request), position)
        .unwrap();
}

#[test]
fn only_the_assigned_request_computes_while_loading() {
    let mut world = World::new(48 * GB);
    let first = world.activate(&request("model-a", &model_a(), &[]));
    let started = preparing(&mut world);
    let pending = assigned(&world, "pending", &chain());
    let ticket = assign_request(&mut world, &pending).unwrap();
    assert_eq!(ticket.kind, LeaseKind::Preparation);
    assert_eq!(ticket.generation, started.generation);
    let lease = world.fakes.coordination.lease(ticket.lease).unwrap();
    assert_eq!(lease.request.kind, LeaseKind::Preparation);
    assert_eq!(lease.request.generation, started.generation);

    let other = assigned(&world, "other", &chain());
    assert_eq!(
        assign_request(&mut world, &other),
        Err(EarlyRefusal::UnrelatedTraffic {
            assigned: op("pending"),
            offered: op("other")
        })
    );
    assert_eq!(
        assign_request(&mut world, &pending),
        Err(EarlyRefusal::AlreadyAssigned {
            assigned: op("pending")
        })
    );
    assert_eq!(
        world.slot.start_early_compute(&op("other"), chain()[0]),
        Err(EarlyRefusal::UnrelatedTraffic {
            assigned: op("pending"),
            offered: op("other")
        })
    );
    // Ordinary traffic never reaches the generation being prepared.
    assert_eq!(world.admit("ordinary").generation, first.generation);
    assert_eq!(
        world
            .slot
            .admit(&world.admission("pending"), &mut world.fakes.coordination),
        Err(RouteRefusal::DuplicateRequest {
            request: op("pending")
        })
    );
}

#[test]
fn early_computation_waits_for_each_dependency() {
    let mut world = World::new(32 * GB);
    let started = preparing(&mut world);
    assign(&mut world, "pending", &chain()).unwrap();
    let pending = op("pending");
    let [layer_0, layer_1, head] = [chain()[0], chain()[1], chain()[2]];

    // §2.6: arrivals (1, 11) and compute times (1, 10).
    world.advance(SECOND);
    world
        .slot
        .record_extent_usable(extent("c-layer-0"))
        .unwrap();
    world.slot.record_extent_usable(extent("c-head")).unwrap();
    world.slot.start_early_compute(&pending, layer_0).unwrap();
    world.advance(SECOND);
    world.slot.finish_early_compute(&pending, layer_0).unwrap();
    assert_eq!(
        world.slot.start_early_compute(&pending, layer_1),
        Err(EarlyRefusal::DependencyNotUsable { position: layer_1 }),
        "layer 1 stalls until its weights are usable"
    );
    world.advance(9 * SECOND);
    world
        .slot
        .record_extent_usable(extent("c-layer-1"))
        .unwrap();
    world.slot.start_early_compute(&pending, layer_1).unwrap();
    world.advance(10 * SECOND);
    world.slot.finish_early_compute(&pending, layer_1).unwrap();
    compute(&mut world, "pending", head);

    // The result waits for the generation's atomic public activation (step 5).
    assert_eq!(
        world
            .slot
            .release_early_result(&pending, &world.fakes.coordination),
        Err(EarlyRefusal::AwaitingPublication)
    );
    world.advance(SECOND);
    publish_prepared(&mut world);
    let result = world
        .slot
        .release_early_result(&pending, &world.fakes.coordination)
        .unwrap();
    assert_eq!(
        result.computed_until,
        MonotonicTime::ZERO.saturating_add(21 * SECOND),
        "the chain finishes at 21, not at the ideal 12"
    );
    assert_eq!(
        result.released_at,
        MonotonicTime::ZERO.saturating_add(22 * SECOND)
    );
    assert_eq!(result.generation, started.generation);
    assert_eq!(
        world
            .slot
            .release_early_result(&pending, &world.fakes.coordination),
        Err(EarlyRefusal::ResultAlreadyReleased)
    );
}

#[test]
fn no_result_before_the_whole_chain_is_usable() {
    let mut world = World::new(32 * GB);
    preparing(&mut world);
    assign(&mut world, "pending", &chain()).unwrap();
    let head = chain()[2];
    world
        .slot
        .record_extent_usable(extent("c-layer-0"))
        .unwrap();
    world
        .slot
        .record_extent_usable(extent("c-layer-1"))
        .unwrap();
    compute(&mut world, "pending", chain()[0]);
    compute(&mut world, "pending", chain()[1]);

    // Prefill can overlap loading, but the first token needs the output head too.
    assert_eq!(
        world
            .slot
            .release_early_result(&op("pending"), &world.fakes.coordination),
        Err(EarlyRefusal::ChainIncomplete {
            waiting: vec![head]
        })
    );
    assert_eq!(
        world.slot.start_early_compute(&op("pending"), head),
        Err(EarlyRefusal::DependencyNotUsable { position: head })
    );
    world.slot.record_extent_usable(extent("c-head")).unwrap();
    compute(&mut world, "pending", head);
    assert_eq!(
        world
            .slot
            .release_early_result(&op("pending"), &world.fakes.coordination),
        Err(EarlyRefusal::AwaitingPublication)
    );
    publish_prepared(&mut world);
    world
        .slot
        .release_early_result(&op("pending"), &world.fakes.coordination)
        .unwrap();
}

#[test]
fn an_exact_expert_is_never_substituted() {
    let mut world = World::new(32 * GB);
    let expert_3 = at(
        0,
        Component::Expert {
            layer: 0,
            expert: 3,
        },
    );
    let expert_5 = at(
        0,
        Component::Expert {
            layer: 0,
            expert: 5,
        },
    );
    let parts = vec![
        part(Component::Layer(0), "e-layer-0", 2 * GB),
        part(
            Component::Expert {
                layer: 0,
                expert: 3,
            },
            "e-expert-3",
            GB,
        ),
        part(
            Component::Expert {
                layer: 0,
                expert: 5,
            },
            "e-expert-5",
            GB,
        ),
        part(Component::OutputHead, "e-head", GB),
    ];
    world.begin(&request("model-e", &parts, &[]));
    world
        .slot
        .prepare_extents(&mut world.fakes.ports())
        .unwrap();
    let required = [
        at(0, Component::Layer(0)),
        expert_3,
        at(0, Component::OutputHead),
    ];
    assign(&mut world, "pending", &required).unwrap();
    for name in ["e-layer-0", "e-expert-5", "e-head"] {
        world.slot.record_extent_usable(extent(name)).unwrap();
    }
    compute(&mut world, "pending", required[0]);
    compute(&mut world, "pending", required[2]);

    assert_eq!(
        world.slot.start_early_compute(&op("pending"), expert_3),
        Err(EarlyRefusal::DependencyNotUsable { position: expert_3 }),
        "a missing expert stalls"
    );
    assert_eq!(
        world.slot.start_early_compute(&op("pending"), expert_5),
        Err(EarlyRefusal::NotRequired { position: expert_5 }),
        "another expert never stands in"
    );
    assert_eq!(
        world
            .slot
            .release_early_result(&op("pending"), &world.fakes.coordination),
        Err(EarlyRefusal::ChainIncomplete {
            waiting: vec![expert_3]
        })
    );
    world
        .slot
        .record_extent_usable(extent("e-expert-3"))
        .unwrap();
    compute(&mut world, "pending", expert_3);
    publish_prepared(&mut world);
    world
        .slot
        .release_early_result(&op("pending"), &world.fakes.coordination)
        .unwrap();
}

#[test]
fn nothing_is_released_once_the_preparation_has_ended() {
    let mut world = World::new(32 * GB);
    preparing(&mut world);
    let ticket = assign(&mut world, "pending", &chain()).unwrap();
    for name in ["c-layer-0", "c-layer-1", "c-head"] {
        world.slot.record_extent_usable(extent(name)).unwrap();
    }
    compute(&mut world, "pending", chain()[0]);

    world
        .slot
        .cancel_activation(&mut world.fakes.ports())
        .unwrap();
    assert!(
        world
            .fakes
            .coordination
            .lease(ticket.lease)
            .unwrap()
            .released,
        "the preparation lease is released with the preparation"
    );
    assert_eq!(
        world.slot.start_early_compute(&op("pending"), chain()[1]),
        Err(EarlyRefusal::PreparationEnded)
    );
    assert_eq!(
        world
            .slot
            .release_early_result(&op("pending"), &world.fakes.coordination),
        Err(EarlyRefusal::PreparationEnded)
    );
}

#[test]
fn a_revoked_preparation_lease_releases_nothing() {
    let mut world = World::new(32 * GB);
    preparing(&mut world);
    assign(&mut world, "pending", &chain()).unwrap();
    for name in ["c-layer-0", "c-layer-1", "c-head"] {
        world.slot.record_extent_usable(extent(name)).unwrap();
    }
    for position in chain() {
        compute(&mut world, "pending", position);
    }
    world.fakes.coordination.revoke(&owner());
    assert_eq!(
        world
            .slot
            .release_early_result(&op("pending"), &world.fakes.coordination),
        Err(EarlyRefusal::LeaseNotActive {
            status: LeaseStatus::Revoked
        })
    );
}

#[test]
fn the_preparation_lease_drains_with_its_generation() {
    let mut world = World::new(32 * GB);
    let started = world.begin(&request("model-c", &chain_model(), &[]));
    let progress = world
        .slot
        .prepare_extents(&mut world.fakes.ports())
        .unwrap();
    let ticket = assign(&mut world, "pending", &chain()).unwrap();
    for (extent, _) in &progress.allocated {
        world.slot.record_extent_usable(*extent).unwrap();
    }
    for position in chain() {
        compute(&mut world, "pending", position);
    }
    world.slot.record_runtime_initialized().unwrap();
    world.slot.materialize().unwrap();
    world.validate_and_ready();
    world.publish();
    assert_eq!(
        world.slot.placement(started.placement).unwrap().leases,
        1,
        "the preparation lease now drains with its generation"
    );
    world
        .slot
        .release_early_result(&op("pending"), &world.fakes.coordination)
        .unwrap();

    world.slot.begin_draining(started.placement).unwrap();
    assert_eq!(
        world.slot.park(started.placement),
        Err(SlotError::LeasesHeld {
            placement: started.placement,
            leases: 1
        })
    );
    world.finish(&ticket);
    world.slot.park(started.placement).unwrap();
}

#[test]
fn an_assignment_names_the_preparing_generation_and_the_slot_authority() {
    let mut world = World::new(32 * GB);
    let before = assigned(&world, "pending", &chain());
    assert_eq!(
        assign_request(&mut world, &before),
        Err(EarlyRefusal::NoPreparation)
    );
    preparing(&mut world);
    assert_eq!(
        assign(&mut world, "pending", &[]),
        Err(EarlyRefusal::EmptyDependencyChain)
    );
    let unknown = at(0, Component::Layer(9));
    assert_eq!(
        assign(&mut world, "pending", &[unknown]),
        Err(EarlyRefusal::UnknownPosition { position: unknown })
    );
    let mut foreign = assigned(&world, "pending", &chain());
    foreign.execution = ExecutionId::new("exe-other").unwrap();
    assert_eq!(
        assign_request(&mut world, &foreign),
        Err(EarlyRefusal::ForeignExecution { owner: owner() })
    );
    let mut newer = assigned(&world, "pending", &chain());
    newer.epoch = AuthorizationEpoch::new(2);
    assert_eq!(
        assign_request(&mut world, &newer),
        Err(EarlyRefusal::AuthorityMismatch {
            presented: AuthorizationEpoch::new(2),
            bound: Some(AuthorizationEpoch::FIRST)
        })
    );
}
