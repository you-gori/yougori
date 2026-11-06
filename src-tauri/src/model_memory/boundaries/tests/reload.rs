//! Generations of one placement: weights held apart and counted once across any sequence
//! of generations (GPU §2.7), and the explicit pause for a reload when two generations
//! cannot be resident together (GPU-W05 line 110): old requests keep their leases until
//! they finish or a bounded drain deadline ends them, the old KV and contexts are freed
//! and their memory passes to the new generation, and the pause is visible with its
//! reason and an estimate. A failed preparation that overlapped leaves the old
//! generation serving; one that drained first says it did not.

use std::time::Duration;

use super::governor::{activation_request, authority, residency_of};
use super::support::*;
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{Clock, ContentKey, ModelActivationGeneration};
use crate::foundation::ledger::ReservationState;
use crate::model_memory::boundaries::fakes::RunnerCall;
use crate::model_memory::boundaries::*;
use crate::model_memory::placement::{
    ActivationError, ExtentKey, PauseReason, ReservationRefusal as SlotRefusal, ResourceKind,
    SupportedShape, TransitionMode,
};
use crate::model_memory::residency::vram::VramBreakdown;

/// What each test's new generation is checked for: a longer context than the first.
const LONGER: SupportedShape = SupportedShape {
    max_context_tokens: 8_192,
    max_batch_sequences: 1,
};

/// Own memory a longer-context generation needs beside the weights: more than the 30 GiB
/// sandbox has room for beside the serving generation, less than it has once the serving
/// generation's own memory passes over.
const LARGE_OWN_BYTES: u64 = 18 * GIB;

/// The extent key of the state named `name` on the one GPU.
fn key(name: &str) -> ExtentKey {
    ExtentKey {
        content: ContentKey::from_digest(state(name).digest()),
        device: gpu(0),
    }
}

/// VRAM holdings in use, smallest first, as [`World::holdings`] lists them.
fn in_use(bytes: &[u64]) -> Vec<(u64, ReservationState)> {
    let mut holdings: Vec<(u64, ReservationState)> = bytes
        .iter()
        .map(|bytes| (*bytes, ReservationState::InUse))
        .collect();
    holdings.sort_by_key(|(bytes, _)| *bytes);
    holdings
}

/// Model A's activation, checked for `declared`, with `own_bytes` of its own memory
/// beside its weights, consenting to `reload`.
fn generation_request(
    world: &World,
    name: &str,
    own_bytes: u64,
    declared: SupportedShape,
    reload: ReloadConsent,
) -> AdmissionRequest {
    let mut request = activation_request(world, name);
    request.activation = Some(ActivationDemand {
        device: gpu(0),
        device_bytes: MODEL_A_WEIGHTS_BYTES + own_bytes,
        peak: VramBreakdown::default(),
    });
    if let Some(spec) = request.spec.as_mut() {
        spec.declared = declared;
        spec.kv = KvSpec::bounded_by_pool(2 * GIB, &declared);
        spec.reload = reload;
    }
    request
}

fn publish(world: &mut World, pending: PendingActivation) -> ModelActivationGeneration {
    let residency = residency_of(world);
    world
        .governor
        .publish_activation(pending, residency)
        .unwrap()
}

/// Publishes model A's first generation, checked for 4,096 tokens.
fn first_generation(world: &mut World) -> ModelActivationGeneration {
    let pending = world
        .governor
        .admit(&activation_request(world, "first"))
        .unwrap()
        .activation
        .unwrap();
    publish(world, pending)
}

fn serving_lease(
    world: &mut World,
    name: &str,
    generation: ModelActivationGeneration,
) -> ExecutionLease {
    let placement = world.placement(world.scenario.model_a);
    let authority = authority(world, name);
    world
        .governor
        .lease_execution(&authority, &placement, generation, shape(1_024))
        .unwrap()
}

fn paused(refusal: AdmissionRefusal) -> ReloadStatus {
    match refusal {
        AdmissionRefusal::PausedForReload { status } => status,
        other => panic!("serving pauses for the reload, got {other:?}"),
    }
}

#[test]
fn weights_count_once_across_generations_a_b_a() {
    let mut world = World::new();
    let placement = world.placement(world.scenario.model_a);
    let epoch = world.epoch();
    let weights = |world: &World| {
        world
            .governor
            .slot_ports(&placement, epoch)
            .unwrap()
            .weights()
    };
    let shared = [key("base-0"), key("base-1"), key("layout")];

    // A: the model's weights, one holding per immutable extent, and A's own memory.
    let a = first_generation(&mut world);
    assert_eq!(world.holdings(), model_a_holdings(1));
    let held_by_a = weights(&world);
    assert_eq!(held_by_a.len(), 4);

    // B: the same base with another adapter, checked for a longer context. It acquires
    // the weights it shares with A, reserves only its own adapter and its own memory, and
    // never takes A's own memory, A's KV and contexts.
    let mut request = activation_request(&world, "b");
    let spec = request.spec.as_mut().unwrap();
    for extent in &mut spec.extents {
        if extent.identity == state("adapter-a") {
            extent.identity = state("adapter-b");
        }
    }
    spec.declared = LONGER;
    let pending = world.governor.admit(&request).unwrap().activation.unwrap();
    assert_eq!(pending.mode(), TransitionMode::Overlap);
    assert_eq!(pending.reserved().memory_bytes, MODEL_DEMAND_BYTES);
    assert_eq!(
        world.holdings(),
        in_use(&[
            128 * MIB,
            512 * MIB,
            512 * MIB,
            4 * GIB,
            4 * GIB,
            MODEL_A_OWN_BYTES,
            MODEL_A_OWN_BYTES,
        ])
    );
    let b = publish(&mut world, pending);
    let held_by_b = weights(&world);
    for extent in &shared {
        assert_eq!(held_by_b.get(extent), held_by_a.get(extent));
    }
    // Reclaiming A frees its own memory and the adapter only it read; B's weights stay.
    assert!(world
        .governor
        .confirm_released(&placement, a, SourceClass::GuestReport)
        .unwrap());
    assert_eq!(
        world.holdings(),
        in_use(&[128 * MIB, 512 * MIB, 4 * GIB, 4 * GIB, MODEL_A_OWN_BYTES])
    );
    assert!(!weights(&world).contains_key(&key("adapter-a")));

    // Back to A: the shared weights are acquired once more, never reserved again; A's
    // adapter, released with A, is reserved anew beside B's.
    let pending = world
        .governor
        .admit(&activation_request(&world, "a-again"))
        .unwrap()
        .activation
        .unwrap();
    assert_eq!(
        world.holdings(),
        in_use(&[
            128 * MIB,
            512 * MIB,
            512 * MIB,
            4 * GIB,
            4 * GIB,
            MODEL_A_OWN_BYTES,
            MODEL_A_OWN_BYTES,
        ])
    );
    publish(&mut world, pending);
    assert!(world
        .governor
        .confirm_released(&placement, b, SourceClass::GuestReport)
        .unwrap());
    assert_eq!(world.holdings(), model_a_holdings(1));
    assert_eq!(world.vram_room(), SANDBOX_VRAM_BYTES - MODEL_DEMAND_BYTES);
    let held_again = weights(&world);
    for extent in &shared {
        assert_eq!(held_again.get(extent), held_by_a.get(extent));
    }
    assert_ne!(
        held_again.get(&key("adapter-a")),
        held_by_a.get(&key("adapter-a"))
    );
}

#[test]
fn serving_pauses_for_a_reload_while_old_requests_finish() {
    let mut world = World::new();
    let placement = world.placement(world.scenario.model_a);
    let first = first_generation(&mut world);
    let old_one = serving_lease(&mut world, "old-1", first);
    let old_two = serving_lease(&mut world, "old-2", first);

    // Beside the serving generation the longer context does not fit, and without consent
    // the activation is refused: serving never pauses silently.
    let refused = world
        .governor
        .admit(&generation_request(
            &world,
            "refused",
            LARGE_OWN_BYTES,
            LONGER,
            ReloadConsent::Never,
        ))
        .unwrap_err();
    assert!(matches!(
        refused,
        AdmissionRefusal::Placement {
            error: ActivationError::Reservation {
                refusal: SlotRefusal::Capacity { .. },
                mode: TransitionMode::Overlap,
            },
        }
    ));
    assert_eq!(world.governor.reload_status(&placement), None);
    assert_eq!(world.holdings(), model_a_holdings(1));

    // With the request's consent, serving pauses: the old generation stops admitting and
    // its two requests keep their leases while they run.
    let since = world.clock.now();
    let consent = ReloadConsent::Pause {
        drain_within: Duration::from_secs(30),
    };
    let request = generation_request(&world, "longer", LARGE_OWN_BYTES, LONGER, consent);
    let status = paused(world.governor.admit(&request).unwrap_err());
    let reloading = first.next().unwrap();
    assert_eq!(status.placement, placement);
    assert_eq!((status.draining, status.reloading), (first, reloading));
    assert_eq!(
        status.phase,
        ReloadPhase::Draining {
            remaining_leases: 2
        }
    );
    let PauseReason::SingleGenerationCapacity { refusal } = status.reason;
    assert_eq!(refusal.resource, ResourceKind::Vram { device: gpu(0) });
    assert_eq!(
        (refusal.requested_bytes, refusal.available_bytes),
        (LARGE_OWN_BYTES, SANDBOX_VRAM_BYTES - MODEL_DEMAND_BYTES)
    );
    assert_eq!(status.since, since);
    assert_eq!(
        status.drain_deadline,
        since.saturating_add(Duration::from_secs(30))
    );
    // Serving resumes at the latest the reload's planned time after the deadline.
    assert_eq!(
        status.eta,
        status.drain_deadline.saturating_add(Duration::from_secs(5))
    );
    assert_eq!(status.ended_leases, 0);
    assert_eq!(world.governor.reload_status(&placement), Some(status));

    // Only the part of the new generation's own memory the old one does not hand over is
    // reserved now; the weights count once.
    let fresh = LARGE_OWN_BYTES - MODEL_A_OWN_BYTES;
    let mut held = MODEL_A_WEIGHTS.to_vec();
    held.extend([MODEL_A_OWN_BYTES, fresh]);
    assert_eq!(world.holdings(), in_use(&held));

    // New work waits with the pause's status; old requests are still honoured, and the
    // old generation's state is resident until it is reclaimed.
    let late = authority(&world, "late");
    assert!(matches!(
        world
            .governor
            .lease_execution(&late, &placement, first, shape(1_024)),
        Err(GovernorError::PausedForReload { .. })
    ));
    let mut ready = activation_request(&world, "ready-path");
    ready.activation = None;
    ready.spec = None;
    assert!(matches!(
        world.governor.admit(&ready),
        Err(AdmissionRefusal::PausedForReload { .. })
    ));
    assert_eq!(world.governor.check_execution_lease(&old_one), Ok(()));
    assert_eq!(
        world
            .governor
            .current_residency(&placement)
            .map(|current| current.generation),
        Some(first)
    );

    // The first old request completes on the old generation; the reload still waits.
    world.clock.advance(Duration::from_secs(1));
    world.governor.release_execution_lease(old_one).unwrap();
    let status = paused(world.governor.admit(&request).unwrap_err());
    assert_eq!(
        status.phase,
        ReloadPhase::Draining {
            remaining_leases: 1
        }
    );

    // The second completes; the next admission continues the reload with the generation
    // whose memory it takes.
    world.clock.advance(Duration::from_secs(1));
    assert_eq!(world.governor.check_execution_lease(&old_two), Ok(()));
    world.governor.release_execution_lease(old_two).unwrap();
    let drained_at = world.clock.now();
    let admission = world.governor.admit(&request).unwrap();
    assert_eq!(admission.handover, Some(first));
    assert_eq!(admission.covers(&request), Ok(()));
    let pending = admission.activation.unwrap();
    assert_eq!(pending.generation(), reloading);
    assert_eq!(pending.mode(), TransitionMode::DrainFirst);
    assert_eq!(
        pending.reserved().memory_bytes,
        MODEL_A_WEIGHTS_BYTES + LARGE_OWN_BYTES
    );
    let status = world.governor.reload_status(&placement).unwrap();
    assert_eq!(status.phase, ReloadPhase::HandingOver);
    assert_eq!(
        status.eta,
        drained_at.saturating_add(Duration::from_secs(5))
    );

    // The runner freed the old KV and contexts: the old placement is reclaimed, and its
    // own memory passes to the new generation without returning to the ledger.
    world
        .governor
        .hand_over(&pending, SourceClass::GuestReport)
        .unwrap();
    assert_eq!(
        world.governor.reload_status(&placement).unwrap().phase,
        ReloadPhase::Loading
    );
    assert_eq!(world.holdings(), in_use(&held));
    assert_eq!(
        world.vram_room(),
        SANDBOX_VRAM_BYTES - MODEL_A_WEIGHTS_BYTES - LARGE_OWN_BYTES
    );
    assert_eq!(
        world.governor.hand_over(&pending, SourceClass::GuestReport),
        Err(GovernorError::NoReload)
    );

    // Publication ends the pause, and the new generation serves.
    assert_eq!(publish(&mut world, pending), reloading);
    assert_eq!(world.governor.reload_status(&placement), None);
    let lease = serving_lease(&mut world, "after", reloading);
    world.governor.release_execution_lease(lease).unwrap();
    assert_eq!(world.holdings(), in_use(&held));
}

#[test]
fn a_drain_deadline_ends_the_old_leases() {
    let mut world = World::new();
    let placement = world.placement(world.scenario.model_a);
    let first = first_generation(&mut world);
    let stuck = serving_lease(&mut world, "stuck", first);

    // The placement's owner consents for every activation; a drain longer than the
    // policy allows is cut to the policy's bound.
    world
        .governor
        .allow_reload(placement, Duration::from_secs(600));
    let since = world.clock.now();
    let request = generation_request(
        &world,
        "longer",
        LARGE_OWN_BYTES,
        LONGER,
        ReloadConsent::Never,
    );
    let status = paused(world.governor.admit(&request).unwrap_err());
    assert_eq!(status.drain_deadline, since.saturating_add(MAX_DRAIN));

    // Until the deadline the stuck request keeps its lease.
    world
        .clock
        .advance(MAX_DRAIN.saturating_sub(Duration::from_secs(1)));
    let status = paused(world.governor.admit(&request).unwrap_err());
    assert_eq!(
        status.phase,
        ReloadPhase::Draining {
            remaining_leases: 1
        }
    );
    assert_eq!(world.governor.check_execution_lease(&stuck), Ok(()));

    // At the deadline its lease ends: its result is no longer honoured, and the reload
    // goes on.
    world.clock.advance(Duration::from_secs(1));
    let admission = world.governor.admit(&request).unwrap();
    assert_eq!(admission.handover, Some(first));
    let status = world.governor.reload_status(&placement).unwrap();
    assert_eq!(status.phase, ReloadPhase::HandingOver);
    assert_eq!(status.ended_leases, 1);
    assert!(matches!(
        world.governor.check_execution_lease(&stuck),
        Err(GovernorError::Lease { .. })
    ));
    // Releasing the ended lease changes nothing.
    world.governor.release_execution_lease(stuck).unwrap();
    assert_eq!(world.governor.active_leases(&placement), 0);

    let pending = admission.activation.unwrap();
    world
        .governor
        .hand_over(&pending, SourceClass::GuestReport)
        .unwrap();
    let generation = publish(&mut world, pending);
    assert_eq!(generation, first.next().unwrap());
    assert_eq!(world.governor.reload_status(&placement), None);
}

#[test]
fn a_failed_preparation_leaves_the_old_generation_serving() {
    let mut world = World::new();
    let placement = world.placement(world.scenario.model_a);
    let first = first_generation(&mut world);

    // Both generations fit: transition capacity is reserved, so the old one never stops,
    // and a failed preparation leaves it serving.
    let request = generation_request(
        &world,
        "overlapping",
        MODEL_A_OWN_BYTES,
        LONGER,
        ReloadConsent::Never,
    );
    let pending = world.governor.admit(&request).unwrap().activation.unwrap();
    assert_eq!(pending.mode(), TransitionMode::Overlap);
    let failed = pending.generation();
    let abandoned = world.governor.abandon_activation(pending).unwrap();
    assert_eq!(abandoned.mode, TransitionMode::Overlap);
    assert!(abandoned.transition_capacity_reserved);
    assert_eq!(abandoned.serving, Some(first));
    assert_eq!(abandoned.predecessor_rollback, None);
    assert_eq!(world.governor.last_abandoned(&placement), Some(&abandoned));
    let lease = serving_lease(&mut world, "still-served", first);
    world.governor.release_execution_lease(lease).unwrap();
    assert_eq!(
        world
            .governor
            .current_residency(&placement)
            .map(|current| current.generation),
        Some(first)
    );
    assert!(world
        .governor
        .confirm_released(&placement, failed, SourceClass::GuestReport)
        .unwrap());
    assert_eq!(world.holdings(), model_a_holdings(1));

    // Without room for both, the old generation drained first: a failure now says that
    // no transition capacity was reserved and nothing serves until another activation
    // succeeds.
    let consent = ReloadConsent::Pause {
        drain_within: Duration::from_secs(30),
    };
    let request = generation_request(&world, "draining", LARGE_OWN_BYTES, LONGER, consent);
    let admission = world.governor.admit(&request).unwrap();
    assert_eq!(admission.handover, Some(first));
    let pending = admission.activation.unwrap();
    assert_eq!(pending.mode(), TransitionMode::DrainFirst);
    let failed = pending.generation();
    let abandoned = world.governor.abandon_activation(pending).unwrap();
    assert_eq!(abandoned.mode, TransitionMode::DrainFirst);
    assert!(!abandoned.transition_capacity_reserved);
    assert_eq!(abandoned.serving, None);
    assert!(abandoned.predecessor_rollback.is_some());
    assert_eq!(world.governor.reload_status(&placement), None);
    let late = authority(&world, "late");
    assert_eq!(
        world
            .governor
            .lease_execution(&late, &placement, first, shape(1_024))
            .unwrap_err(),
        GovernorError::GenerationNotServing {
            requested: first,
            serving: None
        }
    );
    // Both are reclaimed once the runtime freed them, and nothing is left.
    assert!(world
        .governor
        .confirm_released(&placement, failed, SourceClass::GuestReport)
        .unwrap());
    assert!(world
        .governor
        .confirm_released(&placement, first, SourceClass::GuestReport)
        .unwrap());
    assert!(world.holdings().is_empty());
}

#[test]
fn a_reload_through_the_flow_frees_the_old_contexts_and_makes_them_again() {
    // A sandbox with room for one generation of model A only.
    let mut world = World::with_sandbox(policy(), 16 * GIB, SANDBOX_HOST_RAM_BYTES);
    let a = world.scenario.model_a;
    let placement = world.placement(a);
    let request = world.request("first", a);
    let first = world.serve(&request).unwrap().generation;
    let old = serving_lease(&mut world, "old", first);
    world.runner.hold_serving(first, op("old"));

    // A longer context needs a new generation. Without consent it is refused and the old
    // generation keeps serving.
    let mut longer = world.request("longer", a);
    longer.intent.shape = shape(8_192);
    assert!(matches!(
        world.serve(&longer).unwrap_err(),
        FlowError::Admission {
            refusal: AdmissionRefusal::Placement {
                error: ActivationError::Reservation {
                    mode: TransitionMode::Overlap,
                    ..
                },
            },
        }
    ));
    assert_eq!(world.governor.reload_status(&placement), None);

    // With consent, serving pauses while the old request runs; the API sees why and
    // until when.
    longer.intent.policy.reload = ReloadConsent::Pause {
        drain_within: Duration::from_secs(30),
    };
    let FlowError::Admission {
        refusal: AdmissionRefusal::PausedForReload { status },
    } = world.serve(&longer).unwrap_err()
    else {
        panic!("serving pauses for the reload");
    };
    assert_eq!(
        status.phase,
        ReloadPhase::Draining {
            remaining_leases: 1
        }
    );
    assert!(status.eta > world.clock.now());
    assert!(matches!(
        world.api.refusals.last(),
        Some((
            _,
            FlowError::Admission {
                refusal: AdmissionRefusal::PausedForReload { .. }
            }
        ))
    ));

    // The old request completes on the old generation, then the retried request reloads.
    assert_eq!(world.governor.check_execution_lease(&old), Ok(()));
    world.runner.finish_serving(first, &op("old"));
    world.governor.release_execution_lease(old).unwrap();
    let receipt = world.serve(&longer).unwrap();
    let second = first.next().unwrap();
    assert_eq!(receipt.generation, second);
    assert_eq!(receipt.handed_over, Some(first));
    assert!(receipt.transferred.is_empty());
    // The runner freed the old contexts, and the new generation made them again.
    let freed = world.runner.calls().iter().find_map(|call| match call {
        RunnerCall::ReleaseGeneration { generation, freed } if *generation == first => {
            Some(freed.clone())
        }
        _ => None,
    });
    let freed = freed.unwrap();
    for name in ["tokenizer", "engine", "graph"] {
        assert!(freed.contains(&state(name)));
    }
    let mut reconstructed = receipt.reconstructed.clone();
    reconstructed.sort();
    assert_eq!(reconstructed, ids(&[TOKENIZER, ENGINE, GRAPH]));
    assert!(world
        .api
        .events
        .iter()
        .any(|event| event.phase == FlowPhase::HandedOver { drained: first }));
    assert_eq!(world.runner.held_generations(&a), vec![second]);
    assert_eq!(world.governor.reload_status(&placement), None);

    // The weights counted once throughout, and only one generation's own memory is held.
    assert_eq!(world.holdings(), model_a_holdings(1));
    assert_eq!(world.vram_room(), 16 * GIB - MODEL_DEMAND_BYTES);
}
