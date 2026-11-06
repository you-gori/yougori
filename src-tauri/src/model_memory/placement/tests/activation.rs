//! The seven-step activation protocol, overlap versus drain first, rollback, failures
//! and the multi-rank barrier (§3.6 lines 587–599, GPU-W05 acceptance).

use std::collections::BTreeMap;

use crate::foundation::ids::ModelActivationGeneration;
use crate::model_memory::placement::fakes::ReservationCall;
use crate::model_memory::placement::test_support::*;
use crate::model_memory::placement::*;

/// The steady reservation a placement holds.
fn steady_of(world: &World, placement: PlacementKey) -> ReservationId {
    world
        .slot
        .placement(placement)
        .unwrap()
        .steady_reservation
        .unwrap()
}

fn allocated(progress: &ExtentProgress) -> Vec<ExtentKey> {
    progress
        .allocated
        .iter()
        .map(|(extent, _)| *extent)
        .collect()
}

fn shared_with_b() -> Vec<ExtentKey> {
    vec![extent("a-embed"), extent("a-layer-0"), extent("a-head")]
}

#[test]
fn an_initial_activation_runs_the_steps_in_order() {
    let mut world = World::new(32 * GB);
    let request = request("model-a", &model_a(), &[]);

    // Step 1: a new generation, and steady state plus transition peak reserved before
    // anything is created.
    let started = world.begin(&request);
    assert_eq!(started.mode, TransitionMode::Initial);
    assert_eq!(started.generation, ModelActivationGeneration::new(1));
    assert_eq!(started.predecessor, None);
    assert_eq!(started.pause, None);
    let key = started.placement;
    assert_eq!(world.state(key), StateKind::Preparing);
    let reserved = world.fakes.reservations.requests();
    assert_eq!(reserved.len(), 1);
    assert_eq!(reserved[0].steady, vram(gpu(0), 12 * GB));
    assert_eq!(reserved[0].transition_peak, vram(gpu(0), GB));
    assert_eq!(world.vram_used(0), 13 * GB);

    // Step 2: allocate, make usable, initialize runtime state.
    let progress = world
        .slot
        .prepare_extents(&mut world.fakes.ports())
        .unwrap();
    assert!(progress.acquired.is_empty());
    assert_eq!(progress.allocated.len(), 4);
    assert_eq!(progress.not_yet_usable.len(), 4);
    assert!(matches!(
        world.slot.materialize(),
        Err(ActivationError::ExtentsNotUsable { waiting }) if waiting.len() == 4
    ));
    for extent in allocated(&progress) {
        world.slot.record_extent_usable(extent).unwrap();
    }
    assert_eq!(
        world.slot.materialize(),
        Err(ActivationError::RuntimeNotInitialized)
    );
    world.slot.record_runtime_initialized().unwrap();
    world.slot.materialize().unwrap();
    assert_eq!(world.state(key), StateKind::Materialized);
    assert_eq!(
        world.published_generation(),
        None,
        "materialized is not serving"
    );

    // Steps 3 and 4.
    world.slot.begin_activating().unwrap();
    assert_eq!(world.state(key), StateKind::Activating);
    world
        .slot
        .record_validation(&validation(started.generation, 0), &mut world.fakes.ports())
        .unwrap();
    world
        .slot
        .record_readiness(
            started.generation,
            rank(0),
            &ready(),
            &mut world.fakes.ports(),
        )
        .unwrap();

    // Step 5: publication releases the transition peak; the steady state stays.
    let report = world.publish();
    assert_eq!(report.generation, started.generation);
    assert_eq!(report.previous, None);
    assert_eq!(report.mode, TransitionMode::Initial);
    assert_eq!(report.pause, None);
    assert_eq!(world.state(key), StateKind::Serving);
    assert_eq!(world.published_generation(), Some(started.generation));
    assert_eq!(world.vram_used(0), 12 * GB);
    assert_eq!(world.slot.activation(), None);
    assert_eq!(
        world.slot.published_at(started.generation),
        Some(world.now())
    );
}

#[test]
fn steps_out_of_order_are_refused() {
    let mut world = World::new(32 * GB);
    let request = request("model-a", &model_a(), &[]);
    assert_eq!(
        world.slot.prepare_extents(&mut world.fakes.ports()),
        Err(ActivationError::NoActivation)
    );
    assert_eq!(world.slot.materialize(), Err(ActivationError::NoActivation));
    assert_eq!(
        world.slot.publish(&mut world.fakes.ports()),
        Err(ActivationError::NoActivation)
    );

    let started = world.begin(&request);
    let generation = started.generation;
    assert_eq!(
        world
            .slot
            .begin_activation(&request, &mut world.fakes.ports()),
        Err(ActivationError::ActivationInProgress { generation })
    );
    let too_early = ActivationError::OutOfOrder {
        attempted: ProtocolStep::Validate,
        missing: ProtocolStep::AcquireAndInitialize,
    };
    assert_eq!(
        world
            .slot
            .record_validation(&validation(generation, 0), &mut world.fakes.ports()),
        Err(too_early.clone())
    );
    assert_eq!(world.slot.begin_activating(), Err(too_early));
    let unvalidated = ActivationError::OutOfOrder {
        attempted: ProtocolStep::Publish,
        missing: ProtocolStep::Validate,
    };
    assert_eq!(
        world.slot.publish(&mut world.fakes.ports()),
        Err(unvalidated.clone())
    );

    world.load();
    assert_eq!(
        world.slot.publish(&mut world.fakes.ports()),
        Err(unvalidated)
    );
    world.slot.begin_activating().unwrap();
    assert_eq!(
        world.slot.publish(&mut world.fakes.ports()),
        Err(ActivationError::BarrierIncomplete {
            missing: ProtocolStep::Validate,
            waiting: vec![rank(0)]
        })
    );
    assert_eq!(
        world
            .slot
            .record_readiness(generation, rank(0), &ready(), &mut world.fakes.ports()),
        Err(ActivationError::Barrier {
            error: BarrierError::ReadinessBeforeValidation { rank: rank(0) }
        })
    );
    world
        .slot
        .record_validation(&validation(generation, 0), &mut world.fakes.ports())
        .unwrap();
    assert_eq!(
        world.slot.publish(&mut world.fakes.ports()),
        Err(ActivationError::BarrierIncomplete {
            missing: ProtocolStep::CheckReadiness,
            waiting: vec![rank(0)]
        })
    );
    world
        .slot
        .record_readiness(generation, rank(0), &ready(), &mut world.fakes.ports())
        .unwrap();
    assert_eq!(world.publish().generation, generation);
    assert_eq!(
        world.slot.prepare_extents(&mut world.fakes.ports()),
        Err(ActivationError::NoActivation)
    );
}

#[test]
fn a_reservation_refusal_names_the_resource_and_creates_nothing() {
    let mut world = World::new(8 * GB);
    let request = request("model-a", &model_a(), &[]);
    assert_eq!(
        world
            .slot
            .begin_activation(&request, &mut world.fakes.ports()),
        Err(ActivationError::Reservation {
            refusal: ReservationRefusal::Capacity {
                refusal: CapacityRefusal {
                    resource: ResourceKind::Vram { device: gpu(0) },
                    requested_bytes: 13 * GB,
                    available_bytes: 8 * GB,
                    retry: RetryOutlook::ExceedsCapacity,
                }
            },
            mode: TransitionMode::Initial,
        })
    );
    assert!(world.slot.placement_keys().is_empty());
    assert_eq!(world.slot.activation(), None);
    assert_eq!(world.fakes.reservations.held_count(), 0);

    let mut short = request.clone();
    short.steady = vram(gpu(0), 9 * GB);
    assert_eq!(
        world
            .slot
            .begin_activation(&short, &mut world.fakes.ports()),
        Err(ActivationError::InvalidRequest {
            problem: RequestProblem::UnderReserved {
                device: gpu(0),
                extent_bytes: 10 * GB,
                reserved_bytes: 9 * GB,
            }
        })
    );
    assert_eq!(
        world.fakes.reservations.requests().len(),
        1,
        "an under-reserved request never reaches the ledger"
    );
}

#[test]
fn versions_overlap_when_capacity_allows_and_switch_in_one_step() {
    let mut world = World::new(32 * GB);
    let first = world.activate(&request("model-a", &model_a(), &[]));
    assert_eq!(world.admit("before").generation, first.generation);

    let started = world.begin(&request("model-b", &model_b(), &[]));
    assert_eq!(started.mode, TransitionMode::Overlap);
    assert_eq!(started.predecessor, Some(first.placement));
    assert_eq!(started.pause, None);
    // Step 1 tells the reservation authority which resident extents it will acquire; a
    // ledger that cannot share memory still counts the steady state whole.
    let asked = world
        .fakes
        .reservations
        .requests()
        .last()
        .copied()
        .cloned()
        .unwrap();
    assert_eq!(
        asked.acquire,
        BTreeMap::from([(
            steady_of(&world, first.placement),
            BTreeMap::from([(gpu(0), 6 * GB)])
        )])
    );
    assert_eq!(asked.within, None);
    assert_eq!(world.vram_used(0), 12 * GB + 13 * GB);

    let progress = world.load();
    assert_eq!(keys(&progress.acquired), keys(&shared_with_b()));
    assert_eq!(allocated(&progress), vec![extent("b-layer-1")]);
    assert_eq!(world.admit("while-loading").generation, first.generation);
    world.validate_and_ready();
    assert_eq!(
        world.admit("while-ready").generation,
        first.generation,
        "a ready generation admits nothing before it is published"
    );

    let report = world.publish();
    assert_eq!(report.mode, TransitionMode::Overlap);
    assert_eq!(report.previous, Some(first.generation));
    assert_eq!(report.pause, None);
    assert_eq!(report.predecessor_rollback, Some(RollbackOutlook::Retained));
    assert!(report.generation > first.generation);
    assert_eq!(world.admit("after").generation, report.generation);
    assert_eq!(world.state(first.placement), StateKind::Draining);
    assert_eq!(world.state(report.placement), StateKind::Serving);
    assert!(world.slot.content(first.generation).is_some());
    assert_eq!(world.slot.placement(first.placement).unwrap().leases, 3);
}

#[test]
fn without_room_for_two_versions_the_old_drains_first_with_a_reported_pause() {
    let mut world = World::new(20 * GB);
    let first = world.activate(&request("model-a", &model_a(), &[]));
    let old_request = world.admit("before");
    world.advance(10 * SECOND);

    let started = world.begin(&request("model-b", &model_b(), &[]));
    assert_eq!(started.mode, TransitionMode::DrainFirst);
    let pause = started.pause.unwrap();
    assert_eq!(pause.started_at, world.now());
    let overlap_refusal = CapacityRefusal {
        resource: ResourceKind::Vram { device: gpu(0) },
        requested_bytes: 13 * GB,
        available_bytes: 8 * GB,
        retry: RetryOutlook::FitsAfterRelease,
    };
    assert_eq!(
        pause.reason,
        PauseReason::SingleGenerationCapacity {
            refusal: overlap_refusal
        }
    );
    assert_eq!(
        world
            .slot
            .admit(&world.admission("paused"), &mut world.fakes.coordination),
        Err(RouteRefusal::Paused {
            since: pause.started_at,
            reason: pause.reason
        })
    );
    assert_eq!(world.state(first.placement), StateKind::Draining);
    assert_eq!(
        world.vram_used(0),
        13 * GB,
        "the old share passed to the new one"
    );
    // The predecessor's memory passes whole, so none of it is also acquired.
    let successor = world
        .fakes
        .reservations
        .calls
        .iter()
        .find_map(|call| match call {
            ReservationCall::Successor { request, .. } => Some(request.clone()),
            _ => None,
        })
        .unwrap();
    assert!(successor.acquire.is_empty());

    // Shared extents are kept; new ones wait for the old placement's reclamation.
    let progress = world
        .slot
        .prepare_extents(&mut world.fakes.ports())
        .unwrap();
    assert_eq!(keys(&progress.acquired), keys(&shared_with_b()));
    assert!(progress.allocated.is_empty());
    assert_eq!(progress.waiting_for_predecessor, vec![extent("b-layer-1")]);

    world.advance(5 * SECOND);
    world.finish(&old_request);
    let reclaimed = world.park_and_reclaim(first.placement);
    assert_eq!(
        reclaimed
            .freed
            .iter()
            .map(|freed| (freed.extent, freed.bytes))
            .collect::<Vec<_>>(),
        vec![(extent("a-layer-1"), 4 * GB)]
    );
    assert_eq!(keys(&reclaimed.retained_shared), keys(&shared_with_b()));

    let progress = world.load();
    assert_eq!(allocated(&progress), vec![extent("b-layer-1")]);
    world.validate_and_ready();
    world.advance(15 * SECOND);
    let report = world.publish();
    let pause = report.pause.unwrap();
    assert_eq!(pause.ended_at, Some(world.now()));
    assert_eq!(
        pause.outcome,
        Some(PauseOutcome::Resumed {
            generation: report.generation
        })
    );
    assert_eq!(pause.duration(world.now()), 20 * SECOND);
    assert_eq!(report.previous, None);
    assert_eq!(report.predecessor, Some(first.placement));
    assert_eq!(
        report.predecessor_rollback,
        Some(RollbackOutlook::RequiresReload {
            missing_extents: 1,
            missing_bytes: 4 * GB,
            reconstructible: true
        }),
        "no instant rollback is promised after reclamation"
    );
    assert_eq!(world.slot.active_pause(), None);
    assert_eq!(world.admit("resumed").generation, report.generation);
    assert_eq!(world.vram_used(0), 12 * GB);
}

#[test]
fn a_caller_that_refuses_a_pause_gets_the_capacity_error_instead() {
    let mut world = World::new(20 * GB);
    let first = world.activate(&request("model-a", &model_a(), &[]));
    let mut overlap_only = request("model-b", &model_b(), &[]);
    overlap_only.preference = TransitionPreference::OverlapOnly;
    assert_eq!(
        world
            .slot
            .begin_activation(&overlap_only, &mut world.fakes.ports()),
        Err(ActivationError::Reservation {
            refusal: ReservationRefusal::Capacity {
                refusal: CapacityRefusal {
                    resource: ResourceKind::Vram { device: gpu(0) },
                    requested_bytes: 13 * GB,
                    available_bytes: 8 * GB,
                    retry: RetryOutlook::FitsAfterRelease,
                }
            },
            mode: TransitionMode::Overlap,
        })
    );
    assert_eq!(world.published_generation(), Some(first.generation));
    assert_eq!(world.state(first.placement), StateKind::Serving);
    assert_eq!(world.slot.active_pause(), None);
    assert_eq!(world.admit("still-served").generation, first.generation);
}

#[test]
fn rollback_is_instant_only_while_old_resources_are_retained() {
    let mut world = World::new(48 * GB);
    let first = world.activate(&request("model-a", &model_a(), &[]));
    let second = world.activate(&request("model-b", &model_b(), &[]));
    assert_eq!(second.predecessor_rollback, Some(RollbackOutlook::Retained));
    world.slot.park(first.placement).unwrap();
    assert_eq!(
        world.slot.rollback_outlook(first.placement),
        Ok(RollbackOutlook::Retained)
    );

    // Before reclamation a rollback reuses the parked placement and reloads nothing.
    let back = world.begin(&reuse(request("model-a", &model_a(), &[]), first.placement));
    assert_eq!(back.placement, first.placement);
    let asked = world
        .fakes
        .reservations
        .requests()
        .last()
        .copied()
        .cloned()
        .unwrap();
    assert_eq!(asked.within, Some(steady_of(&world, first.placement)));
    assert!(asked.steady.is_empty() && asked.acquire.is_empty());
    let progress = world.load();
    assert!(progress.acquired.is_empty() && progress.allocated.is_empty());
    world.validate_and_ready();
    let third = world.publish();
    assert!(
        third.generation > second.generation,
        "a rollback is a new generation"
    );
    assert_eq!(
        world
            .slot
            .published()
            .unwrap()
            .components
            .get(&at(0, Component::Layer(1))),
        Some(&extent("a-layer-1"))
    );

    // After reclamation the same kind of rollback has to reload what was freed.
    let reclaimed = world.park_and_reclaim(second.placement);
    assert_eq!(
        reclaimed.rollback,
        RollbackOutlook::RequiresReload {
            missing_extents: 1,
            missing_bytes: 4 * GB,
            reconstructible: true
        }
    );
    world.begin(&reuse(
        request("model-b", &model_b(), &[]),
        second.placement,
    ));
    let progress = world.load();
    assert_eq!(allocated(&progress), vec![extent("b-layer-1")]);
    assert_eq!(keys(&progress.acquired), keys(&shared_with_b()));
}

#[test]
fn a_failed_preparation_preserves_the_old_serving_generation() {
    let mut world = World::new(32 * GB);
    let first = world.activate(&request("model-a", &model_a(), &[]));
    world.admit("before");
    let started = world.begin(&request("model-b", &model_b(), &[]));
    world
        .slot
        .prepare_extents(&mut world.fakes.ports())
        .unwrap();

    let report = world
        .slot
        .record_extent_failed(extent("b-layer-1"), &mut world.fakes.ports())
        .unwrap();
    let failure = report.failure.unwrap();
    assert_eq!(failure.stage, TransientStage::Preparing);
    assert_eq!(
        failure.reason,
        FailureReason::ExtentFailed {
            extent: extent("b-layer-1")
        }
    );
    assert_eq!(world.state(started.placement), StateKind::Failed);
    assert_eq!(world.published_generation(), Some(first.generation));
    assert_eq!(world.state(first.placement), StateKind::Serving);
    assert_eq!(world.admit("after").generation, first.generation);
    assert_eq!(
        world.slot.last_failure().map(|(key, _)| *key),
        Some(started.placement)
    );
    assert_eq!(
        world.vram_used(0),
        24 * GB,
        "the peak is released; the failed placement keeps its steady share until reclaimed"
    );

    let reclaimed = world
        .slot
        .reclaim(started.placement, &mut world.fakes.reservations)
        .unwrap();
    assert_eq!(
        reclaimed
            .freed
            .iter()
            .map(|freed| freed.extent)
            .collect::<Vec<_>>(),
        vec![extent("b-layer-1")]
    );
    world.slot.retire(started.placement).unwrap();
    assert_eq!(world.vram_used(0), 12 * GB);
    assert_eq!(world.slot.last_failure(), None);
}

#[test]
fn an_extent_a_failed_preparation_left_unusable_is_never_shared() {
    let mut world = World::new(48 * GB);
    let failed = world.begin(&request("model-b", &model_b(), &[]));
    world
        .slot
        .prepare_extents(&mut world.fakes.ports())
        .unwrap();
    world.slot.record_extent_usable(extent("a-embed")).unwrap();
    world
        .slot
        .record_extent_failed(extent("b-layer-1"), &mut world.fakes.ports())
        .unwrap();

    // Model A shares the usable embedding, but not the layer and head the failed
    // preparation allocated and never verified.
    world.begin(&request("model-a", &model_a(), &[]));
    let progress = world
        .slot
        .prepare_extents(&mut world.fakes.ports())
        .unwrap();
    assert_eq!(progress.acquired, vec![extent("a-embed")]);
    assert_eq!(
        keys(&progress.waiting_for_other_holders),
        keys(&[extent("a-layer-0"), extent("a-head")])
    );
    assert_eq!(allocated(&progress), vec![extent("a-layer-1")]);
    assert!(matches!(
        world.slot.materialize(),
        Err(ActivationError::ExtentsNotUsable { .. })
    ));

    // Once the failed placement is reclaimed they are allocated afresh.
    world
        .slot
        .reclaim(failed.placement, &mut world.fakes.reservations)
        .unwrap();
    let progress = world
        .slot
        .prepare_extents(&mut world.fakes.ports())
        .unwrap();
    assert_eq!(
        keys(&allocated(&progress)),
        keys(&[extent("a-layer-0"), extent("a-head")])
    );
    assert!(progress.waiting_for_other_holders.is_empty());
}

#[test]
fn an_extent_counted_as_acquired_must_still_be_there_at_step_2() {
    let mut world = World::new(48 * GB);
    let first = world.activate(&request("model-a", &model_a(), &[]));
    world.slot.begin_draining(first.placement).unwrap();
    world.slot.park(first.placement).unwrap();

    // Nothing serves, so model B begins as an initial activation that acquires the
    // parked placement's three shared extents.
    let started = world.begin(&request("model-b", &model_b(), &[]));
    assert_eq!(started.mode, TransitionMode::Initial);
    world
        .slot
        .reclaim(first.placement, &mut world.fakes.reservations)
        .unwrap();
    // Their memory is gone, and the reservation was not made to allocate it again.
    assert!(matches!(
        world.slot.prepare_extents(&mut world.fakes.ports()),
        Err(ActivationError::PlannedExtentGone { .. })
    ));
    assert!(world.slot.placement(started.placement).unwrap().gpu.extents == 0);
}

#[test]
fn reusing_a_placement_never_grows_beyond_its_held_reservation() {
    let mut world = World::new(48 * GB);
    let first = world.activate(&request("model-a", &model_a(), &[]));
    world.slot.begin_draining(first.placement).unwrap();
    world.slot.park(first.placement).unwrap();
    let mut larger = reuse(request("model-a", &model_a(), &[]), first.placement);
    larger.steady = vram(gpu(0), 16 * GB);
    assert_eq!(
        world
            .slot
            .begin_activation(&larger, &mut world.fakes.ports()),
        Err(ActivationError::InvalidRequest {
            problem: RequestProblem::SteadyExceedsHeldReservation
        })
    );
    // After reclamation step 1 reserves the larger steady state anew.
    world
        .slot
        .reclaim(first.placement, &mut world.fakes.reservations)
        .unwrap();
    world.begin(&larger);
    assert_eq!(world.vram_used(0), 16 * GB + GB);
}

#[test]
fn a_failed_drain_first_activation_reports_the_outage() {
    let mut world = World::new(20 * GB);
    let first = world.activate(&request("model-a", &model_a(), &[]));
    let started = world.begin(&request("model-b", &model_b(), &[]));
    assert_eq!(started.mode, TransitionMode::DrainFirst);
    world.park_and_reclaim(first.placement);
    world.load();
    world.slot.begin_activating().unwrap();
    world
        .slot
        .record_validation(&validation(started.generation, 0), &mut world.fakes.ports())
        .unwrap();
    world.advance(3 * SECOND);

    let error = world
        .slot
        .record_readiness(
            started.generation,
            rank(0),
            &ReadinessReport::NotReady,
            &mut world.fakes.ports(),
        )
        .unwrap_err();
    let ActivationError::Failed { report } = error else {
        panic!("expected a failed activation, got {error:?}");
    };
    let failure = report.failure.unwrap();
    assert_eq!(failure.stage, TransientStage::Activating);
    assert_eq!(failure.reason, FailureReason::NotReady { rank: rank(0) });
    let pause = report.pause.unwrap();
    assert_eq!(pause.outcome, Some(PauseOutcome::ActivationFailed));
    assert_eq!(pause.duration(world.now()), 3 * SECOND);
    assert_eq!(
        report.predecessor_rollback,
        Some(RollbackOutlook::RequiresReload {
            missing_extents: 1,
            missing_bytes: 4 * GB,
            reconstructible: true
        })
    );
    assert_eq!(world.slot.active_pause(), None);
    assert_eq!(
        world
            .slot
            .admit(&world.admission("after"), &mut world.fakes.coordination),
        Err(RouteRefusal::NotServing)
    );
}

#[test]
fn generations_only_move_forward() {
    let mut world = World::new(32 * GB);
    let first = world.activate(&request("model-a", &model_a(), &[]));
    assert_eq!(first.generation, ModelActivationGeneration::new(1));

    let failed = world.begin(&request("model-b", &model_b(), &[]));
    let report = world
        .slot
        .cancel_activation(&mut world.fakes.ports())
        .unwrap();
    assert_eq!(
        report
            .failure
            .map(|failure| (failure.stage, failure.reason)),
        Some((TransientStage::Preparing, FailureReason::Cancelled))
    );
    world
        .slot
        .reclaim(failed.placement, &mut world.fakes.reservations)
        .unwrap();
    world.slot.retire(failed.placement).unwrap();

    let next = world.begin(&request("model-b", &model_b(), &[]));
    assert_eq!(
        next.generation,
        ModelActivationGeneration::new(3),
        "a cancelled generation is never reused"
    );
    world
        .slot
        .cancel_activation(&mut world.fakes.ports())
        .unwrap();
    world
        .slot
        .reclaim(next.placement, &mut world.fakes.reservations)
        .unwrap();

    // A coordination module that hands out an old generation is refused, and the
    // reservation made for it is released at once.
    world
        .fakes
        .coordination
        .reissue_activation_generation(slot_id(), 1);
    let held = world.fakes.reservations.held_count();
    assert_eq!(
        world.slot.begin_activation(
            &request("model-b", &model_b(), &[]),
            &mut world.fakes.ports()
        ),
        Err(ActivationError::StaleGeneration {
            generation: ModelActivationGeneration::new(1)
        })
    );
    assert_eq!(world.fakes.reservations.held_count(), held);
    assert!(world
        .fakes
        .coordination
        .abandoned
        .contains(&ModelActivationGeneration::new(1)));
    assert_eq!(world.published_generation(), Some(first.generation));
    assert_eq!(world.fakes.coordination.published, vec![first.generation]);
    assert_eq!(world.slot.activation(), None);
}

#[test]
fn a_multi_rank_activation_waits_for_every_rank() {
    let mut world = World::with_gpus(2, 32 * GB);
    let parts = vec![
        part_on(0, Component::Embedding, "m-embed", GB),
        part_on(0, Component::Layer(0), "m-layer-0", 4 * GB),
        part_on(1, Component::Layer(1), "m-layer-1", 4 * GB),
        part_on(1, Component::OutputHead, "m-head", GB),
    ];
    let started = world.begin(&request("model-m", &parts, &[]));
    let generation = started.generation;
    world.load();
    world.slot.begin_activating().unwrap();
    world
        .slot
        .record_validation(&validation(generation, 0), &mut world.fakes.ports())
        .unwrap();
    world
        .slot
        .record_readiness(generation, rank(0), &ready(), &mut world.fakes.ports())
        .unwrap();
    assert_eq!(
        world.slot.publish(&mut world.fakes.ports()),
        Err(ActivationError::BarrierIncomplete {
            missing: ProtocolStep::Validate,
            waiting: vec![rank(1)]
        }),
        "one ready rank is insufficient"
    );
    world
        .slot
        .record_validation(&validation(generation, 1), &mut world.fakes.ports())
        .unwrap();
    assert_eq!(
        world.slot.publish(&mut world.fakes.ports()),
        Err(ActivationError::BarrierIncomplete {
            missing: ProtocolStep::CheckReadiness,
            waiting: vec![rank(1)]
        })
    );
    let stale = ModelActivationGeneration::new(99);
    assert_eq!(
        world
            .slot
            .record_readiness(stale, rank(1), &ready(), &mut world.fakes.ports()),
        Err(ActivationError::Barrier {
            error: BarrierError::WrongGeneration {
                expected: generation,
                reported: stale
            }
        })
    );
    world
        .slot
        .record_readiness(generation, rank(1), &ready(), &mut world.fakes.ports())
        .unwrap();
    let report = world.publish();
    let identities = world.slot.placement_identities(report.generation).unwrap();
    assert_eq!(identities.len(), 2);
    assert_ne!(identities[&rank(0)], identities[&rank(1)]);
}

#[test]
fn a_failed_rank_check_fails_the_activation_with_stage_and_reason() {
    let mut world = World::new(32 * GB);
    let started = world.begin(&request("model-a", &model_a(), &[]));
    world.load();
    world.slot.begin_activating().unwrap();
    let unverified = ValidationReport {
        weights_verified: false,
        ..validation(started.generation, 0)
    };
    let error = world
        .slot
        .record_validation(&unverified, &mut world.fakes.ports())
        .unwrap_err();
    let ActivationError::Failed { report } = error else {
        panic!("expected a failed activation, got {error:?}");
    };
    assert_eq!(
        report
            .failure
            .map(|failure| (failure.stage, failure.reason)),
        Some((
            TransientStage::Activating,
            FailureReason::ValidationFailed {
                rank: rank(0),
                check: ValidationCheck::Weights
            }
        ))
    );
    assert_eq!(world.state(started.placement), StateKind::Failed);
    assert_eq!(world.slot.activation(), None);
    assert_eq!(world.vram_used(0), 12 * GB);
}

#[test]
fn readiness_for_less_than_the_declared_shape_fails_rather_than_shrinking_the_promise() {
    let mut world = World::new(32 * GB);
    let started = world.begin(&request("model-a", &model_a(), &[]));
    world.load();
    world.slot.begin_activating().unwrap();
    world
        .slot
        .record_validation(&validation(started.generation, 0), &mut world.fakes.ports())
        .unwrap();
    let shorter = ReadinessReport::Ready {
        supported: SupportedShape {
            max_context_tokens: 4_096,
            ..SHAPE
        },
    };
    let error = world
        .slot
        .record_readiness(
            started.generation,
            rank(0),
            &shorter,
            &mut world.fakes.ports(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        ActivationError::Failed { report }
            if report.failure.map(|failure| failure.reason)
                == Some(FailureReason::NotReady { rank: rank(0) })
    ));
    assert_eq!(world.published_generation(), None);
}

#[test]
fn cancelling_drains_an_activating_placement_and_fails_a_preparing_one() {
    let mut world = World::new(32 * GB);
    let started = world.begin(&request("model-a", &model_a(), &[]));
    world.load();
    world.slot.begin_activating().unwrap();
    let report = world
        .slot
        .cancel_activation(&mut world.fakes.ports())
        .unwrap();
    assert_eq!(report.failure, None);
    assert_eq!(report.state, StateKind::Draining, "activating → draining");
    world.slot.park(started.placement).unwrap();
    assert_eq!(
        world.vram_used(0),
        12 * GB,
        "the parked weights keep their share"
    );

    // The parked placement can be activated again, under a new generation.
    let again = world.begin(&reuse(
        request("model-a", &model_a(), &[]),
        started.placement,
    ));
    assert!(again.generation > started.generation);
    world.load();
    world.validate_and_ready();
    assert_eq!(world.publish().placement, started.placement);

    // A preparing placement has no other exit: cancelling fails it.
    let preparing = world.begin(&request("model-b", &model_b(), &[]));
    let report = world
        .slot
        .cancel_activation(&mut world.fakes.ports())
        .unwrap();
    assert_eq!(
        report
            .failure
            .map(|failure| (failure.stage, failure.reason)),
        Some((TransientStage::Preparing, FailureReason::Cancelled))
    );
    assert_eq!(world.state(preparing.placement), StateKind::Failed);
}
