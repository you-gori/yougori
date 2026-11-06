//! A paused reload resumes through the governor once its preconditions return (G03 of
//! docs/combined-plan-leftover-tasks.md; GPU-W05 line 110): every old lease ended, by its
//! request finishing or at the drain deadline, its staging granted, and its authority and
//! generation still current. It resumes once, without a retry; one whose authority was
//! revoked or whose generation was superseded never resumes, on the tick or on a retry, and
//! one that gets no staging by its bound ends. Every outcome says so.

use std::collections::BTreeMap;
use std::time::Duration;

use super::governor::{activation_request, authority, residency_of};
use super::support::*;
use crate::foundation::coordination::{ActivationState, RetireReason};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{Clock, ModelActivationGeneration, OperationId};
use crate::foundation::ledger::Priority;
use crate::model_memory::boundaries::*;
use crate::model_memory::placement::{ActivationError, SupportedShape, TransitionMode};
use crate::model_memory::residency::vram::VramBreakdown;

/// What the reloading generation is checked for: a longer context than the first.
pub(super) const LONGER: SupportedShape = SupportedShape {
    max_context_tokens: 8_192,
    max_batch_sequences: 1,
};

/// Own memory the longer-context generation needs beside the weights: more than fits
/// beside the serving generation, less than the sandbox has once that memory passes over.
pub(super) const LARGE_OWN_BYTES: u64 = 18 * GIB;

/// The drain the reload's request consents to.
pub(super) const DRAIN: Duration = Duration::from_secs(30);

/// Model A's longer-context activation, consenting to a pause of at most [`DRAIN`].
pub(super) fn longer_request(world: &World, name: &str) -> AdmissionRequest {
    let mut request = activation_request(world, name);
    request.activation = Some(ActivationDemand {
        device: gpu(0),
        device_bytes: MODEL_A_WEIGHTS_BYTES + LARGE_OWN_BYTES,
        peak: VramBreakdown::default(),
    });
    if let Some(spec) = request.spec.as_mut() {
        spec.declared = LONGER;
        spec.kv = KvSpec::bounded_by_pool(2 * GIB, &LONGER);
        spec.reload = ReloadConsent::Pause {
            drain_within: DRAIN,
        };
    }
    request
}

pub(super) fn publish(world: &mut World, pending: PendingActivation) -> ModelActivationGeneration {
    let residency = residency_of(world);
    world
        .governor
        .publish_activation(pending, residency)
        .unwrap()
}

/// Publishes model A's first generation.
pub(super) fn first_generation(world: &mut World) -> ModelActivationGeneration {
    let pending = world
        .governor
        .admit(&activation_request(world, "first"))
        .unwrap()
        .activation
        .unwrap();
    publish(world, pending)
}

pub(super) fn serving_lease(
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

pub(super) fn paused(refusal: AdmissionRefusal) -> ReloadStatus {
    match refusal {
        AdmissionRefusal::PausedForReload { status } => status,
        other => panic!("serving pauses for the reload, got {other:?}"),
    }
}

/// Model A serving its first generation to one old request, and the longer-context
/// reload of `request` paused for it.
pub(super) struct Paused {
    pub first: ModelActivationGeneration,
    pub old: ExecutionLease,
    pub request: AdmissionRequest,
}

pub(super) fn pause(world: &mut World, request: AdmissionRequest) -> Paused {
    let first = first_generation(world);
    let old = serving_lease(world, "old", first);
    let status = paused(world.governor.admit(&request).unwrap_err());
    assert_eq!(
        status.phase,
        ReloadPhase::Draining {
            remaining_leases: 1
        }
    );
    Paused {
        first,
        old,
        request,
    }
}

/// [`pause`] for model A's longer-context activation, `longer`.
pub(super) fn pause_longer(world: &mut World) -> Paused {
    let request = longer_request(world, "longer");
    pause(world, request)
}

/// The one outcome of a call that saw one waiting reload.
fn only(mut outcomes: Vec<ReloadResumption>) -> ReloadResumption {
    assert_eq!(outcomes.len(), 1, "one waiting reload: {outcomes:?}");
    outcomes.remove(0)
}

pub(super) fn resumed(outcome: ReloadResumption) -> (OperationId, Admission) {
    match outcome {
        ReloadResumption::Resumed {
            operation,
            admission,
        } => (operation, admission),
        other => panic!("the reload resumes, got {other:?}"),
    }
}

fn waiting(
    outcome: ReloadResumption,
) -> (
    ReloadStatus,
    Option<CapacityRefusal>,
    crate::foundation::ids::MonotonicTime,
) {
    match outcome {
        ReloadResumption::Waiting {
            status,
            capacity,
            resume_by,
        } => (status, capacity, resume_by),
        other => panic!("the reload waits, got {other:?}"),
    }
}

fn ended(outcome: ReloadResumption) -> EndedReload {
    match outcome {
        ReloadResumption::Ended(ended) => *ended,
        other => panic!("the reload ends, got {other:?}"),
    }
}

/// Pinned staging held by another placement of the sandbox, with its request.
fn competing_staging(world: &mut World, bytes: u64) -> LedgerGrant {
    let request = AdmissionRequest {
        authority: authority(world, "competitor"),
        placement: world.placement(world.scenario.model_b),
        priority: Priority::Foreground,
        activation: None,
        spec: None,
        transfer: BTreeMap::from([(extent(world.scenario.base, 1), bytes)]),
    };
    world.governor.admit(&request).unwrap().staging.unwrap()
}

#[test]
fn a_paused_reload_resumes_when_its_old_requests_finish_without_a_retry() {
    let mut world = World::new();
    let placement = world.placement(world.scenario.model_a);
    let since = world.clock.now();
    let Paused {
        first,
        old,
        request,
        ..
    } = pause_longer(&mut world);
    let reloading = first.next().unwrap();

    // While the old request runs, the reload waits, with its bound.
    let (status, capacity, resume_by) = waiting(only(world.governor.resume_reloads()));
    assert_eq!(
        status.phase,
        ReloadPhase::Draining {
            remaining_leases: 1
        }
    );
    assert_eq!(capacity, None);
    assert_eq!(resume_by, since.saturating_add(DRAIN).saturating_add(DRAIN));
    assert_eq!(world.governor.check_execution_lease(&old), Ok(()));

    // The old request finishes; nobody retries, and the governor resumes the reload with
    // the admission the retry would have received.
    world.clock.advance(Duration::from_secs(1));
    world.governor.release_execution_lease(old).unwrap();
    let (operation, admission) = resumed(only(world.governor.resume_reloads()));
    assert_eq!(operation, op("longer"));
    assert_eq!(admission.handover, Some(first));
    assert_eq!(admission.covers(&request), Ok(()));
    let pending = admission.activation.unwrap();
    assert_eq!(pending.generation(), reloading);
    assert_eq!(pending.mode(), TransitionMode::DrainFirst);
    assert_eq!(
        pending.reserved().memory_bytes,
        MODEL_A_WEIGHTS_BYTES + LARGE_OWN_BYTES
    );

    // It resumes once: the next call has nothing to resume, and a retry waits with the
    // pause's status rather than take the activation a second time.
    assert_eq!(world.governor.resume_reloads(), Vec::new());
    let status = paused(world.governor.admit(&request).unwrap_err());
    assert_eq!(status.phase, ReloadPhase::HandingOver);

    // Its caller continues it: the handover, then publication ends the pause.
    world
        .governor
        .hand_over(&pending, SourceClass::GuestReport)
        .unwrap();
    assert_eq!(publish(&mut world, pending), reloading);
    assert_eq!(world.governor.reload_status(&placement), None);
    let lease = serving_lease(&mut world, "after", reloading);
    world.governor.release_execution_lease(lease).unwrap();
    let mut held = MODEL_A_WEIGHTS.to_vec();
    held.extend([MODEL_A_OWN_BYTES, LARGE_OWN_BYTES - MODEL_A_OWN_BYTES]);
    held.sort_unstable();
    assert_eq!(
        world
            .holdings()
            .into_iter()
            .map(|(bytes, _)| bytes)
            .collect::<Vec<_>>(),
        held
    );
}

#[test]
fn a_paused_reload_resumes_at_its_drain_deadline() {
    let mut world = World::new();
    let placement = world.placement(world.scenario.model_a);
    // The placement's owner consents; the policy bounds the drain.
    world
        .governor
        .allow_reload(placement, Duration::from_secs(600));
    let mut request = longer_request(&world, "longer");
    if let Some(spec) = request.spec.as_mut() {
        spec.reload = ReloadConsent::Never;
    }
    let since = world.clock.now();
    let Paused { first, old, .. } = pause(&mut world, request);

    // Until the deadline the stuck request keeps its lease, and the reload waits.
    world
        .clock
        .advance(MAX_DRAIN.saturating_sub(Duration::from_secs(1)));
    let (status, _, resume_by) = waiting(only(world.governor.resume_reloads()));
    assert_eq!(
        status.phase,
        ReloadPhase::Draining {
            remaining_leases: 1
        }
    );
    assert_eq!(status.drain_deadline, since.saturating_add(MAX_DRAIN));
    assert_eq!(resume_by, status.drain_deadline.saturating_add(MAX_DRAIN));
    assert_eq!(world.governor.check_execution_lease(&old), Ok(()));

    // At the deadline the governor ends its lease and resumes the reload.
    world.clock.advance(Duration::from_secs(1));
    let (_, admission) = resumed(only(world.governor.resume_reloads()));
    assert_eq!(admission.handover, Some(first));
    assert!(matches!(
        world.governor.check_execution_lease(&old),
        Err(GovernorError::Lease { .. })
    ));
    let status = world.governor.reload_status(&placement).unwrap();
    assert_eq!(
        (status.phase, status.ended_leases),
        (ReloadPhase::HandingOver, 1)
    );
    world.governor.release_execution_lease(old).unwrap();
    let pending = admission.activation.unwrap();
    world
        .governor
        .hand_over(&pending, SourceClass::GuestReport)
        .unwrap();
    assert_eq!(publish(&mut world, pending), first.next().unwrap());
}

#[test]
fn a_drained_reload_waits_for_its_staging_and_resumes_when_capacity_returns() {
    // A sandbox with 3,000 bytes of host RAM: the reload's 2,000 bytes of staging fit,
    // unless another placement stages 2,000 bytes first.
    let mut world = World::with_sandbox_host_ram(policy(), 3_000);
    let placement = world.placement(world.scenario.model_a);
    let mut request = longer_request(&world, "longer");
    request.transfer = BTreeMap::from([(extent(world.scenario.base, 0), 2_000)]);
    let Paused { first, old, .. } = pause(&mut world, request.clone());
    let competitor = competing_staging(&mut world, 2_000);

    // The old request finishes, but the ledger refuses the staging: the reload waits with
    // the refusal, drained.
    world.governor.release_execution_lease(old).unwrap();
    let (status, capacity, _) = waiting(only(world.governor.resume_reloads()));
    assert_eq!(status.phase, ReloadPhase::HandingOver);
    let refusal = capacity.unwrap();
    assert_eq!(refusal.resource, HOST_RAM);
    assert_eq!(refusal.limit, LimitKind::ParentReservation);
    assert_eq!((refusal.requested, refusal.available), (2_000, 1_000));
    assert_eq!(
        world.governor.reload_status(&placement).unwrap().phase,
        ReloadPhase::HandingOver
    );

    // Capacity returns: the reload resumes with its bounded staging and its budget.
    world.governor.release(competitor).unwrap();
    let (_, admission) = resumed(only(world.governor.resume_reloads()));
    assert_eq!(admission.covers(&request), Ok(()));
    assert_eq!(admission.handover, Some(first));
    let staging = admission.staging.unwrap();
    assert_eq!(
        (staging.pinned_bytes(), staging.host_ram_bytes()),
        (2_000, 2_000)
    );
    let pending = admission.activation.unwrap();
    world
        .governor
        .hand_over(&pending, SourceClass::GuestReport)
        .unwrap();
    world.governor.release(staging).unwrap();
    assert_eq!(publish(&mut world, pending), first.next().unwrap());
}

#[test]
fn a_drained_reload_without_staging_by_its_bound_ends() {
    let mut world = World::with_sandbox_host_ram(policy(), 3_000);
    let placement = world.placement(world.scenario.model_a);
    let mut request = longer_request(&world, "longer");
    request.transfer = BTreeMap::from([(extent(world.scenario.base, 0), 2_000)]);
    let Paused { first, old, .. } = pause(&mut world, request.clone());
    let reloading = first.next().unwrap();
    let _competitor = competing_staging(&mut world, 2_000);
    world.governor.release_execution_lease(old).unwrap();
    let (_, capacity, resume_by) = waiting(only(world.governor.resume_reloads()));
    assert!(capacity.is_some());

    // Still refused at its bound: it ends, its activation abandoned and closed.
    world
        .clock
        .advance(resume_by.saturating_duration_since(world.clock.now()));
    let ended = ended(only(world.governor.resume_reloads()));
    assert_eq!(ended.end, ReloadEnd::TimedOut { resume_by });
    assert_eq!(
        (ended.placement, ended.epoch, ended.operation.clone()),
        (placement, world.epoch(), op("longer"))
    );
    assert_eq!((ended.reloading, ended.draining), (reloading, first));
    assert_eq!(ended.faults, Vec::new());
    let abandoned = ended.abandoned.unwrap();
    assert_eq!(abandoned.mode, TransitionMode::DrainFirst);
    assert!(!abandoned.transition_capacity_reserved);
    assert_eq!(abandoned.serving, None);
    assert!(abandoned.predecessor_rollback.is_some());
    assert_eq!(world.governor.last_abandoned(&placement), Some(&abandoned));
    assert_eq!(world.governor.reload_status(&placement), None);
    assert_eq!(world.governor.resume_reloads(), Vec::new());

    // Only the drained old generation is still counted, until the runtime freed it.
    assert_eq!(world.holdings(), model_a_holdings(1));
    assert!(world
        .governor
        .confirm_released(&placement, first, SourceClass::GuestReport)
        .unwrap());
    assert!(world.holdings().is_empty());
    // The placement takes new work again, without a pause.
    let admission = world
        .governor
        .admit(&activation_request(&world, "again"))
        .unwrap();
    assert_eq!(
        admission.activation.unwrap().mode(),
        TransitionMode::Initial
    );
}

#[test]
fn a_reload_whose_authority_was_revoked_never_resumes() {
    let mut world = World::new();
    let placement = world.placement(world.scenario.model_a);
    let Paused { first, old, .. } = pause_longer(&mut world);
    let reloading = first.next().unwrap();
    let revoked = world.epoch();
    world.governor.coordinator_mut().revoke(&owner()).unwrap();
    let current = world.epoch();
    // Its old request is ended by the revocation, so the drain is complete; still the
    // reload ends rather than resume.
    let _ = world.governor.release_execution_lease(old);
    let ended = ended(only(world.governor.resume_reloads()));
    assert_eq!(
        ended.end,
        ReloadEnd::AuthorityRevoked {
            error: GovernorError::StaleAuthorization {
                presented: revoked,
                current,
            },
        }
    );
    assert_eq!((ended.epoch, ended.reloading), (revoked, reloading));
    assert!(ended.abandoned.is_some());
    assert_eq!(ended.faults, Vec::new());
    assert_eq!(world.governor.resume_reloads(), Vec::new());
    assert_eq!(
        world
            .governor
            .slot(&placement, revoked)
            .unwrap()
            .activation(),
        None
    );
    let state = world
        .governor
        .coordinator()
        .model_activations(&owner(), placement.model_id())
        .and_then(|activations| activations.activation(reloading))
        .map(|activation| activation.state());
    // The coordinator reclaims it with every activation under the revoked authority.
    assert!(
        matches!(
            state,
            Some(ActivationState::Reclaiming | ActivationState::Retired { .. })
        ),
        "{state:?}"
    );
}

/// The coordinator ends the reloading generation, as a GPU return or an eviction does.
fn supersede(world: &mut World, generation: ModelActivationGeneration) {
    let model = world.placement(world.scenario.model_a).model_id();
    world
        .governor
        .coordinator_mut()
        .fail_activation(&owner(), model, generation)
        .unwrap();
}

#[test]
fn a_superseded_reload_never_resumes_on_the_tick() {
    let mut world = World::new();
    let placement = world.placement(world.scenario.model_a);
    let Paused { first, old, .. } = pause_longer(&mut world);
    let reloading = first.next().unwrap();
    supersede(&mut world, reloading);
    world.governor.release_execution_lease(old).unwrap();

    let ended = ended(only(world.governor.resume_reloads()));
    assert_eq!(
        ended.end,
        ReloadEnd::Superseded {
            state: Some(ActivationState::Retired {
                reason: RetireReason::LoadFailed
            }),
            latest: Some(reloading),
        }
    );
    assert_eq!(ended.faults, Vec::new());
    assert_eq!(world.governor.reload_status(&placement), None);
    assert_eq!(world.governor.resume_reloads(), Vec::new());
}

#[test]
fn a_superseded_reload_never_resumes_on_a_retry() {
    let mut world = World::new();
    let placement = world.placement(world.scenario.model_a);
    let Paused {
        first,
        old,
        request,
        ..
    } = pause_longer(&mut world);
    let reloading = first.next().unwrap();
    supersede(&mut world, reloading);
    world.governor.release_execution_lease(old).unwrap();

    // The retry ends the reload instead of continuing it, and is admitted as a new
    // activation: nothing serves, and the drained generation's memory still counts, so
    // the longer context does not fit.
    let refusal = world.governor.admit(&request).unwrap_err();
    assert!(
        matches!(
            refusal,
            AdmissionRefusal::Placement {
                error: ActivationError::Reservation {
                    mode: TransitionMode::Initial,
                    ..
                }
            }
        ),
        "{refusal:?}"
    );
    assert_eq!(world.governor.reload_status(&placement), None);
    let ended = ended(only(world.governor.resume_reloads()));
    assert!(matches!(ended.end, ReloadEnd::Superseded { .. }));
    assert_eq!(ended.reloading, reloading);
    assert_eq!(world.governor.resume_reloads(), Vec::new());
}
