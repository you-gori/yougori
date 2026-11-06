//! Independent fields (§3.6 line 585), draining and reclamation (steps 6–7), the
//! request router (line 599) and request validation.

use crate::foundation::ids::{AuthorizationEpoch, ExecutionId};
use crate::model_memory::placement::test_support::*;
use crate::model_memory::placement::*;

#[test]
fn a_request_never_mixes_generations() {
    let mut world = World::new(32 * GB);
    world.activate(&request("model-a", &model_a(), &[]));
    let old = world.admit("old");
    world.activate(&request("model-b", &model_b(), &[]));
    let new = world.admit("new");
    let layer = at(0, Component::Layer(1));

    assert_eq!(world.slot.weight_for(&old, layer), Ok(extent("a-layer-1")));
    assert_eq!(world.slot.weight_for(&new, layer), Ok(extent("b-layer-1")));
    let shared = at(0, Component::Layer(0));
    assert_eq!(
        world.slot.weight_for(&old, shared),
        world.slot.weight_for(&new, shared)
    );
    assert_eq!(
        world.slot.check_weight(&old, layer, extent("b-layer-1")),
        Err(TicketError::MixedGenerations {
            generation: old.generation,
            position: layer,
            expected: extent("a-layer-1"),
            offered: extent("b-layer-1"),
        })
    );
    assert_eq!(
        world.slot.check_weight(&new, layer, extent("a-layer-1")),
        Err(TicketError::MixedGenerations {
            generation: new.generation,
            position: layer,
            expected: extent("b-layer-1"),
            offered: extent("a-layer-1"),
        })
    );
    world
        .slot
        .check_weight(&old, layer, extent("a-layer-1"))
        .unwrap();
    let unknown = at(0, Component::Layer(7));
    assert_eq!(
        world.slot.weight_for(&old, unknown),
        Err(TicketError::UnknownPosition { position: unknown })
    );

    world.finish(&old);
    assert_eq!(
        world.slot.weight_for(&old, layer),
        Err(TicketError::UnknownTicket)
    );
    assert_eq!(
        world.slot.finish(&old, &mut world.fakes.coordination),
        Err(TicketError::UnknownTicket)
    );
}

#[test]
fn reclamation_waits_for_leases_process_references_and_completion_events() {
    let mut world = World::new(32 * GB);
    let first = world.activate(&request("model-a", &model_a(), &[]));
    let old = world.admit("old");
    let second = world.activate(&request("model-b", &model_b(), &[]));
    let key = first.placement;

    assert_eq!(
        world.slot.park(key),
        Err(SlotError::LeasesHeld {
            placement: key,
            leases: 1
        })
    );
    assert_eq!(
        world.slot.reclaim(key, &mut world.fakes.reservations),
        Err(SlotError::NotReclaimable {
            placement: key,
            state: StateKind::Draining
        })
    );
    world
        .slot
        .enqueue_work(key, CompletionEventId::new(1))
        .unwrap();
    world
        .slot
        .hold_reference(key, ReferenceId::new(7), ReferenceKind::CapturedGraph)
        .unwrap();
    world.finish(&old);
    assert!(world
        .slot
        .drain_status(key, &world.fakes.coordination)
        .unwrap()
        .is_drained());
    world.slot.park(key).unwrap();

    // A released lease is not enough: a captured graph and enqueued GPU work still use
    // the memory.
    assert_eq!(
        world.slot.reclaim(key, &mut world.fakes.reservations),
        Err(SlotError::ReclaimBlocked {
            blocked: ReclaimBlocked {
                references: vec![(ReferenceId::new(7), ReferenceKind::CapturedGraph)],
                pending_events: vec![CompletionEventId::new(1)],
            }
        })
    );
    world.slot.drop_reference(key, ReferenceId::new(7)).unwrap();
    assert!(matches!(
        world.slot.reclaim(key, &mut world.fakes.reservations),
        Err(SlotError::ReclaimBlocked { .. })
    ));
    world
        .slot
        .complete_work(key, CompletionEventId::new(1))
        .unwrap();

    let before = world.vram_used(0);
    let report = world
        .slot
        .reclaim(key, &mut world.fakes.reservations)
        .unwrap();
    assert_eq!(
        report
            .freed
            .iter()
            .map(|freed| (freed.extent, freed.bytes))
            .collect::<Vec<_>>(),
        vec![(extent("a-layer-1"), 4 * GB)]
    );
    assert_eq!(
        keys(&report.retained_shared),
        keys(&[extent("a-embed"), extent("a-layer-0"), extent("a-head")])
    );
    assert!(report.released_reservation.is_some());
    assert_eq!(world.vram_used(0), before - 12 * GB);
    assert_eq!(
        world.slot.placement(second.placement).unwrap().gpu.extents,
        4,
        "shared extents stay for the new generation"
    );
    assert_eq!(
        world.slot.enqueue_work(key, CompletionEventId::new(2)),
        Err(SlotError::NotResident { placement: key }),
        "reclaimed memory takes no new work"
    );
}

#[test]
fn expired_leases_end_with_the_drain() {
    let mut world = World::new(32 * GB);
    let first = world.activate(&request("model-a", &model_a(), &[]));
    let mut short = world.admission("short");
    short.lease_expires_at = world.now().saturating_add(10 * SECOND);
    let ticket = world
        .slot
        .admit(&short, &mut world.fakes.coordination)
        .unwrap();
    world.activate(&request("model-b", &model_b(), &[]));

    let status = world
        .slot
        .drain_status(first.placement, &world.fakes.coordination)
        .unwrap();
    assert_eq!(status.remaining_leases, 1);
    assert!(status.ended.is_empty());

    world.advance(11 * SECOND);
    let status = world
        .slot
        .drain_status(first.placement, &world.fakes.coordination)
        .unwrap();
    assert_eq!(
        status.ended,
        vec![EndedLease {
            request: op("short"),
            generation: first.generation,
            lease: ticket.lease,
            status: LeaseStatus::Expired,
        }]
    );
    assert!(status.is_drained());
    world.slot.park(first.placement).unwrap();
}

#[test]
fn a_materialized_model_is_not_ready_for_a_longer_context() {
    let mut world = World::new(32 * GB);
    world.begin(&request("model-a", &model_a(), &[]));
    world.load();
    assert_eq!(
        world
            .slot
            .admit(&world.admission("early"), &mut world.fakes.coordination),
        Err(RouteRefusal::NotServing),
        "materialized is not serving"
    );
    world.validate_and_ready();
    world.publish();

    let mut long = world.admission("long");
    long.shape.context_tokens = 32_768;
    assert_eq!(
        world.slot.admit(&long, &mut world.fakes.coordination),
        Err(RouteRefusal::NotReadyForShape {
            refusal: ShapeRefusal::ContextTooLong {
                requested_tokens: 32_768,
                supported_tokens: 8_192
            }
        })
    );
    let mut wide = world.admission("wide");
    wide.shape.batch_sequences = 8;
    assert_eq!(
        world.slot.admit(&wide, &mut world.fakes.coordination),
        Err(RouteRefusal::NotReadyForShape {
            refusal: ShapeRefusal::BatchTooLarge {
                requested_sequences: 8,
                supported_sequences: 4
            }
        })
    );
    let mut fits = world.admission("fits");
    fits.shape.context_tokens = 8_192;
    world
        .slot
        .admit(&fits, &mut world.fakes.coordination)
        .unwrap();
}

#[test]
fn a_parked_process_can_hold_no_gpu_weights() {
    let mut world = World::new(32 * GB);
    let first = world.activate(&request("model-a", &model_a(), &[]));
    world.slot.begin_draining(first.placement).unwrap();
    assert_eq!(
        world
            .slot
            .admit(&world.admission("idle"), &mut world.fakes.coordination),
        Err(RouteRefusal::NotServing)
    );
    world.park_and_reclaim(first.placement);

    let view = world.slot.placement(first.placement).unwrap();
    assert_eq!(view.state, PlacementState::Parked);
    assert_eq!(
        view.process,
        ProcessLiveness::Alive {
            instance: ProcessInstance::new(1)
        }
    );
    assert!(!view.gpu.is_resident());
    assert_eq!(view.steady_reservation, None);
    assert_eq!(
        view.artifact,
        ArtifactValidity::Verified {
            artifact: artifact_of("model-a")
        }
    );
    assert_eq!(world.vram_used(0), 0);
}

#[test]
fn a_gpu_allocation_can_outlive_its_serving_process() {
    let mut world = World::new(32 * GB);
    let first = world.activate(&request("model-a", &model_a(), &[]));
    world.slot.begin_draining(first.placement).unwrap();
    world.slot.park(first.placement).unwrap();
    let before = world.slot.placement(first.placement).unwrap().gpu;
    assert!(before.is_resident());

    world.advance(SECOND);
    assert_eq!(
        world
            .slot
            .record_process_exit(first.placement, &mut world.fakes.ports()),
        Ok(None)
    );
    let view = world.slot.placement(first.placement).unwrap();
    assert_eq!(
        view.process,
        ProcessLiveness::Exited {
            instance: ProcessInstance::new(1),
            at: world.now()
        }
    );
    assert_eq!(
        view.gpu, before,
        "process liveness and GPU residency are separate"
    );
    assert_eq!(view.state, PlacementState::Parked);
    assert_eq!(
        world.slot.rollback_outlook(first.placement),
        Ok(RollbackOutlook::RequiresProcess)
    );
    let again = reuse(request("model-a", &model_a(), &[]), first.placement);
    assert_eq!(
        world
            .slot
            .begin_activation(&again, &mut world.fakes.ports()),
        Err(ActivationError::ProcessNotAlive {
            placement: first.placement
        })
    );

    world
        .slot
        .record_process_started(first.placement, ProcessInstance::new(2))
        .unwrap();
    assert_eq!(
        world
            .slot
            .record_process_started(first.placement, ProcessInstance::new(3)),
        Err(SlotError::ProcessAlreadyAlive {
            placement: first.placement
        })
    );
    assert_eq!(
        world.slot.rollback_outlook(first.placement),
        Ok(RollbackOutlook::Retained)
    );
    world.begin(&again);
    let progress = world.load();
    assert!(
        progress.allocated.is_empty(),
        "the new process serves the allocation that outlived the old one"
    );
    world.validate_and_ready();
    world.publish();
    assert_eq!(
        world
            .slot
            .placement(first.placement)
            .unwrap()
            .gpu
            .allocations,
        before.allocations
    );
}

#[test]
fn a_process_exit_stops_admission_at_once_and_fails_a_preparation() {
    let mut world = World::new(32 * GB);
    let first = world.activate(&request("model-a", &model_a(), &[]));
    let in_flight = world.admit("in-flight");
    let failure = world
        .slot
        .record_process_exit(first.placement, &mut world.fakes.ports())
        .unwrap()
        .unwrap();
    assert_eq!(
        (failure.stage, failure.reason),
        (TransientStage::Draining, FailureReason::ProcessExited)
    );
    assert_eq!(world.state(first.placement), StateKind::Failed);
    assert_eq!(
        world
            .slot
            .admit(&world.admission("next"), &mut world.fakes.coordination),
        Err(RouteRefusal::NotServing)
    );
    assert_eq!(world.slot.last_failure(), Some(&(first.placement, failure)));
    assert_eq!(
        world
            .slot
            .reclaim(first.placement, &mut world.fakes.reservations),
        Err(SlotError::LeasesHeld {
            placement: first.placement,
            leases: 1
        })
    );
    world.finish(&in_flight);
    world
        .slot
        .reclaim(first.placement, &mut world.fakes.reservations)
        .unwrap();
    world.slot.retire(first.placement).unwrap();

    let started = world.begin(&request("model-a", &model_a(), &[]));
    let failure = world
        .slot
        .record_process_exit(started.placement, &mut world.fakes.ports())
        .unwrap()
        .unwrap();
    assert_eq!(
        (failure.stage, failure.reason),
        (TransientStage::Preparing, FailureReason::ProcessExited)
    );
    assert_eq!(world.slot.activation(), None);
}

#[test]
fn an_invalid_artifact_blocks_reloading_but_not_serving() {
    let mut world = World::new(32 * GB);
    let first = world.activate(&request("model-a", &model_a(), &[]));
    assert_eq!(
        world.slot.record_artifact_invalid(
            first.placement,
            ArtifactProblem::DigestMismatch,
            &mut world.fakes.ports()
        ),
        Ok(None)
    );
    let still = world.admit("still");
    assert_eq!(
        still.generation, first.generation,
        "weights verified when loaded keep serving"
    );
    world.slot.begin_draining(first.placement).unwrap();
    world.finish(&still);
    let reclaimed = world.park_and_reclaim(first.placement);
    assert_eq!(
        reclaimed.rollback,
        RollbackOutlook::RequiresReload {
            missing_extents: 4,
            missing_bytes: 10 * GB,
            reconstructible: false
        }
    );
    let again = reuse(request("model-a", &model_a(), &[]), first.placement);
    assert_eq!(
        world
            .slot
            .begin_activation(&again, &mut world.fakes.ports()),
        Err(ActivationError::ArtifactNotVerified)
    );
    world
        .slot
        .record_artifact_verified(first.placement)
        .unwrap();
    world.begin(&again);
    world.load();
    world.validate_and_ready();
    world.publish();

    let started = world.begin(&request("model-b", &model_b(), &[]));
    let failure = world
        .slot
        .record_artifact_invalid(
            started.placement,
            ArtifactProblem::TrustWithdrawn,
            &mut world.fakes.ports(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        (failure.stage, failure.reason),
        (TransientStage::Preparing, FailureReason::ArtifactInvalid)
    );
}

#[test]
fn retirement_requires_reclamation() {
    let mut world = World::new(32 * GB);
    let first = world.activate(&request("model-a", &model_a(), &[]));
    let key = first.placement;
    assert_eq!(
        world.slot.retire(key),
        Err(SlotError::Transition {
            transition: IllegalTransition {
                from: StateKind::Serving,
                to: StateKind::Absent
            }
        })
    );
    world.slot.begin_draining(key).unwrap();
    world.slot.park(key).unwrap();
    assert_eq!(
        world.slot.retire(key),
        Err(SlotError::NotReclaimed { placement: key })
    );
    world
        .slot
        .reclaim(key, &mut world.fakes.reservations)
        .unwrap();
    world.slot.retire(key).unwrap();
    assert_eq!(world.slot.placement(key), None);
    assert_eq!(world.fakes.reservations.held_count(), 0);
    assert_eq!(
        world.slot.retire(key),
        Err(SlotError::UnknownPlacement { placement: key })
    );
}

#[test]
fn admission_refuses_other_executions_other_epochs_and_duplicates() {
    let mut world = World::new(32 * GB);
    world.activate(&request("model-a", &model_a(), &[]));

    let mut foreign = world.admission("foreign");
    foreign.execution = ExecutionId::new("exe-other").unwrap();
    assert_eq!(
        world.slot.admit(&foreign, &mut world.fakes.coordination),
        Err(RouteRefusal::ForeignExecution { owner: owner() })
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
    world.admit("once");
    assert_eq!(
        world
            .slot
            .admit(&world.admission("once"), &mut world.fakes.coordination),
        Err(RouteRefusal::DuplicateRequest {
            request: op("once")
        })
    );
    let mut expired = world.admission("expired");
    expired.lease_expires_at = world.now();
    assert_eq!(
        world.slot.admit(&expired, &mut world.fakes.coordination),
        Err(RouteRefusal::LeaseRefused {
            refusal: CoordinationRefusal::ExpiryNotInFuture
        })
    );
}

#[test]
fn malformed_requests_are_refused_before_anything_is_reserved() {
    let mut world = World::with_gpus(2, 32 * GB);
    let base = request("model-a", &model_a(), &[]);
    let mut problem = |request: &ActivationRequest| match world
        .slot
        .begin_activation(request, &mut world.fakes.ports())
    {
        Err(ActivationError::InvalidRequest { problem }) => problem,
        other => panic!("expected an invalid request, got {other:?}"),
    };

    let mut gap = base.clone();
    gap.layout = [(rank(1), gpu(0))].into_iter().collect();
    assert_eq!(problem(&gap), RequestProblem::RanksNotContiguous);

    let mut moved = base.clone();
    moved.components[1].extent.device = gpu(1);
    assert_eq!(
        problem(&moved),
        RequestProblem::DeviceMismatch {
            position: at(0, Component::Layer(0))
        }
    );

    let mut twice = base.clone();
    twice.components.push(twice.components[0]);
    assert_eq!(
        problem(&twice),
        RequestProblem::DuplicatePosition {
            position: at(0, Component::Embedding)
        }
    );

    let mut resized = base.clone();
    resized.components.push(ExtentSpec {
        position: at(0, Component::Buffer(0)),
        extent: extent("a-embed"),
        bytes: 2 * GB,
    });
    assert_eq!(
        problem(&resized),
        RequestProblem::ExtentSizeMismatch {
            extent: extent("a-embed")
        }
    );

    let mut empty = base.clone();
    empty.components[0].bytes = 0;
    assert_eq!(
        problem(&empty),
        RequestProblem::EmptyExtent {
            position: at(0, Component::Embedding)
        }
    );

    let mut idle_rank = base.clone();
    idle_rank.layout.insert(rank(1), gpu(1));
    assert_eq!(
        problem(&idle_rank),
        RequestProblem::RankWithoutComponents { rank: rank(1) }
    );

    let mut shapeless = base.clone();
    shapeless.declared_shape.max_context_tokens = 0;
    assert_eq!(problem(&shapeless), RequestProblem::EmptyDeclaredShape);

    let mut free = base.clone();
    free.steady = ResourceDemand::default();
    assert_eq!(problem(&free), RequestProblem::NoSteadyDemand);

    let orphan = request("model-a", &with_adapter("tone"), &[]);
    assert_eq!(
        problem(&orphan),
        RequestProblem::AdapterWithoutIdentity { index: 0 }
    );
    let unused = request("model-a", &model_a(), &["tone"]);
    assert_eq!(
        problem(&unused),
        RequestProblem::IdentityWithoutAdapter { index: 0 }
    );

    let mut unverified = base.clone();
    unverified.artifact = ArtifactValidity::Unverified;
    assert_eq!(
        world
            .slot
            .begin_activation(&unverified, &mut world.fakes.ports()),
        Err(ActivationError::ArtifactNotVerified)
    );
    let mut other_artifact = base;
    other_artifact.artifact = ArtifactValidity::Verified {
        artifact: artifact_of("model-b"),
    };
    assert_eq!(
        world
            .slot
            .begin_activation(&other_artifact, &mut world.fakes.ports()),
        Err(ActivationError::ArtifactNotVerified)
    );

    assert!(world.fakes.reservations.requests().is_empty());
    assert!(world.slot.placement_keys().is_empty());
}
