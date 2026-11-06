//! The placement governor: a policy client of the CORE-03 ledger, never a second capacity
//! authority (line 491), driving every activation through P04's slot over the CORE-04
//! coordinator, whose generations and leases bind to the parent's authority (S3.1).

use std::collections::BTreeMap;
use std::time::Duration;

use super::support::*;
use crate::foundation::coordination::{LeaseKind, LeaseRefusal, LeaseState};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{Clock, ContentKey, ExecutionCategory, ExecutionId, TenantId};
use crate::foundation::ledger::{CostPurpose, Priority, Requester};
use crate::model_memory::boundaries::fakes::ShortGovernor;
use crate::model_memory::boundaries::*;
use crate::model_memory::graph::node::NodeKind;
use crate::model_memory::identity::{AuthorityBinding, CurrentResidency, Residency};
use crate::model_memory::placement::{
    ActivationError, Component, EarlyRefusal, ExtentKey, LeaseKind as SlotLeaseKind, Rank,
    ReservationProblem, ReservationRefusal as SlotRefusal, ResourceKind, RouteRefusal, SlotError,
    StateKind, SupportedShape, TransitionMode, WeightPosition,
};
use crate::model_memory::residency::vram::VramBreakdown;

pub(super) fn authority(world: &World, name: &str) -> RequestAuthority {
    RequestAuthority {
        execution: owner(),
        operation: op(name),
        tenant: tenant(),
        epoch: world.epoch(),
    }
}

/// Model A's activation, as the flow asks for it: its artifact as the catalog verifies
/// it, its immutable extents, `ready` or still to be made, and the request's shape.
pub(super) fn spec_of(world: &World, ready: bool) -> ActivationSpec {
    let dependencies = model_a_dependencies(&world.scenario);
    ActivationSpec {
        verified: world
            .catalog
            .representation(&dependencies.artifact, &SecurityPartition::new(scope()))
            .unwrap(),
        extents: dependencies
            .nodes
            .iter()
            .filter(|node| {
                matches!(
                    node.kind,
                    NodeKind::ArtifactExtent | NodeKind::RankLayout | NodeKind::Adapter
                )
            })
            .map(|node| ActivationExtent {
                node: node.id,
                identity: node.identity,
                device_bytes: node.device_bytes,
                ready,
                transfers: match &node.materialization {
                    Materialization::Transfer { extents } if !ready => extents.clone(),
                    _ => Vec::new(),
                },
            })
            .collect(),
        declared: DECLARED,
        kv: KvSpec::bounded_by_pool(dependencies.session_device_bytes, &DECLARED),
        reload: ReloadConsent::Never,
        reload_estimate: Duration::from_secs(5),
    }
}

/// The shape model A's activations are checked for.
pub(super) const DECLARED: SupportedShape = SupportedShape {
    max_context_tokens: 4_096,
    max_batch_sequences: 1,
};

/// An admission of model A's whole demand with every extent resident.
pub(super) fn activation_request(world: &World, name: &str) -> AdmissionRequest {
    let dependencies = model_a_dependencies(&world.scenario);
    let held: Vec<NodeId> = dependencies.nodes.iter().map(|node| node.id).collect();
    let budget = world.governor.runtime(runner_owner()).unwrap().budget;
    AdmissionRequest {
        authority: authority(world, name),
        placement: world.placement(world.scenario.model_a),
        priority: Priority::Foreground,
        activation: Some(
            activation_demand(&dependencies, &held, scope(), &budget, world.clock.now()).unwrap(),
        ),
        spec: Some(spec_of(world, true)),
        transfer: BTreeMap::new(),
    }
}

/// Where the slot reads node `id` of model A.
fn position(id: u32) -> WeightPosition {
    WeightPosition::new(Rank::new(0), Component::Layer(id))
}

pub(super) fn residency_of(world: &World) -> Residency {
    Residency {
        execution: world.scenario.model_a,
        artifact: world.scenario.base,
        owner: tenant(),
        scope: scope(),
        device: gpu(0),
        authority: AuthorityBinding::new(
            owner(),
            ExecutionCategory::VmSandbox,
            Some(world.epoch()),
        )
        .unwrap(),
    }
}

#[test]
fn the_governor_cannot_exceed_the_ledger() {
    let mut world = World::new();
    // The sandbox's reservation is the only one, and the governor counts nothing itself.
    assert_eq!(world.open_reservations(), 1);
    let view = world.governor.runtime(runner_owner()).unwrap();
    assert_eq!(view.budget.usable_bytes, SANDBOX_VRAM_BYTES);
    assert_eq!(view.execution, owner());

    // Serving A carves exactly T08's demand from the sandbox: the model's weights, one
    // holding per immutable extent held apart from any activation, and the activation's
    // own memory. Staging was returned.
    let request = world.request("a", world.scenario.model_a);
    let receipt = world.serve(&request).unwrap();
    assert_eq!(receipt.reserved_device_bytes, MODEL_DEMAND_BYTES);
    assert_eq!(world.holdings(), model_a_holdings(1));
    assert_eq!(world.children().len(), 5);
    let room = world.vram_room();
    assert_eq!(room, SANDBOX_VRAM_BYTES - MODEL_DEMAND_BYTES);

    // A demand beyond the sandbox's room is refused by the ledger in the slot's first
    // step, whatever is asked, and nothing stays reserved: another placement's weights
    // fit, its own memory is one byte short, and the weights reserved for it are
    // withdrawn.
    let mut oversize = activation_request(&world, "too-big");
    oversize.placement = world.placement(world.scenario.model_b);
    oversize.activation = Some(ActivationDemand {
        device: gpu(0),
        device_bytes: room + 1,
        peak: VramBreakdown::default(),
    });
    let refusal = world.governor.admit(&oversize).unwrap_err();
    let AdmissionRefusal::Placement {
        error:
            ActivationError::Reservation {
                refusal: SlotRefusal::Capacity { refusal },
                mode: TransitionMode::Initial,
            },
    } = refusal
    else {
        panic!("the ledger refuses, got {refusal:?}");
    };
    assert_eq!(refusal.resource, ResourceKind::Vram { device: gpu(0) });
    assert_eq!(
        (refusal.requested_bytes, refusal.available_bytes),
        (
            room + 1 - MODEL_A_WEIGHTS_BYTES,
            room - MODEL_A_WEIGHTS_BYTES
        )
    );
    assert_eq!(world.holdings(), model_a_holdings(1));

    // Staging beyond the sandbox's pinned share is refused too, and the activation begun
    // for it is abandoned and closed.
    let mut wide = World::with_policy(GovernorPolicy {
        staging_cap_bytes: 8 * GIB,
        ..policy()
    });
    let mut staged = activation_request(&wide, "staged");
    staged.transfer = BTreeMap::from([(extent(wide.scenario.base, 0), SANDBOX_PINNED_BYTES + 1)]);
    let refusal = wide.governor.admit(&staged).unwrap_err();
    let AdmissionRefusal::Capacity { refusal } = refusal else {
        panic!("the ledger refuses the staging, got {refusal:?}");
    };
    assert_eq!(refusal.resource, STAGING);
    assert_eq!(refusal.limit, LimitKind::ParentReservation);
    assert_eq!(
        (refusal.requested, refusal.available),
        (SANDBOX_PINNED_BYTES + 1, SANDBOX_PINNED_BYTES)
    );
    assert!(!refusal.retry_can_progress);
    assert!(wide.children().is_empty());
}

#[test]
fn an_under_reserving_governor_is_caught_before_anything_is_made() {
    let mut world = World::new();
    let request = world.request("short", world.scenario.model_a);
    let World {
        clock,
        catalog,
        governor,
        executor,
        runner,
        api,
        ..
    } = &mut world;
    let mut short = ShortGovernor { inner: governor };
    let error =
        serve_through(clock, catalog, &mut short, executor, runner, api, &request).unwrap_err();
    assert_eq!(
        error,
        FlowError::AdmissionShort {
            shortfall: Shortfall::Activation
        }
    );
    // An eighth less than the demand was granted, found short, abandoned and closed with
    // the staging.
    assert!(world.children().is_empty());
    assert!(world.runner.calls().is_empty());
    assert!(world.executor.submitted().is_empty());
    assert_eq!(world.api.refusals.len(), 1);
}

#[test]
fn leases_are_the_coordinators_and_bind_every_generation() {
    let mut world = World::new();
    let a = world.scenario.model_a;
    let placement = world.placement(a);
    let request = world.request("served", a);
    let receipt = world.serve(&request).unwrap();

    // The request's lease was the coordinator's model-request lease, now released.
    let records: Vec<_> = world
        .governor
        .coordinator()
        .leases()
        .filter(|record| record.lease().operation() == &op("served"))
        .collect();
    assert_eq!(records.len(), 1);
    let lease = records[0].lease();
    assert_eq!(lease.kind(), LeaseKind::ModelRequest);
    assert_eq!(lease.parent(), &owner());
    assert_eq!(lease.sandbox().authorization, world.epoch());
    let binding = lease.model().unwrap();
    assert_eq!(binding.model, placement.model_id());
    assert_eq!(binding.generations.activation, receipt.generation);
    assert!(matches!(records[0].state(), LeaseState::Released { .. }));
    assert_eq!(world.governor.active_leases(&placement), 0);

    // A lease is issued only on the serving generation, and honoured until released.
    let held = world
        .governor
        .lease_execution(
            &authority(&world, "held"),
            &placement,
            receipt.generation,
            shape(4_096),
        )
        .unwrap();
    assert_eq!(held.generation(), receipt.generation);
    assert_eq!(held.operation(), &op("held"));
    assert_eq!(held.ticket().kind, SlotLeaseKind::Serving);
    assert_eq!(held.ticket().lease, held.id());
    assert_eq!(world.governor.active_leases(&placement), 1);
    assert_eq!(world.governor.check_execution_lease(&held), Ok(()));
    let later = receipt.generation.next().unwrap();
    assert_eq!(
        world
            .governor
            .lease_execution(&authority(&world, "later"), &placement, later, shape(4_096))
            .unwrap_err(),
        GovernorError::GenerationNotServing {
            requested: later,
            serving: Some(receipt.generation)
        }
    );
    world.governor.release_execution_lease(held).unwrap();
    assert_eq!(world.governor.active_leases(&placement), 0);
}

#[test]
fn a_preparation_lease_binds_one_request_to_a_loading_generation() {
    let mut world = World::new();
    let placement = world.placement(world.scenario.model_a);
    let request = activation_request(&world, "prepared");
    let pending = world.governor.admit(&request).unwrap().activation.unwrap();
    let generation = pending.generation();

    let lease = world
        .governor
        .lease_preparation(&authority(&world, "prepared"), &pending)
        .unwrap();
    assert_eq!(lease.generation(), generation);
    assert_eq!(lease.assigned_operation(), &op("prepared"));
    assert_eq!(lease.lease().kind(), LeaseKind::Preparation);
    assert_eq!(world.governor.check_preparation_lease(&lease), Ok(()));
    assert_eq!(world.governor.active_leases(&placement), 1);

    // Line 601: one assigned request only, no result before publication, and no
    // serving lease on a generation that does not serve.
    assert_eq!(
        world
            .governor
            .lease_preparation(&authority(&world, "other"), &pending)
            .unwrap_err(),
        GovernorError::Early {
            refusal: EarlyRefusal::UnrelatedTraffic {
                assigned: op("prepared"),
                offered: op("other"),
            }
        }
    );
    assert!(matches!(
        world
            .governor
            .coordinator()
            .check_result_publication(lease.id()),
        Err(LeaseRefusal::ActivationNotServing { .. })
    ));
    assert_eq!(
        world
            .governor
            .lease_execution(
                &authority(&world, "prepared"),
                &placement,
                generation,
                shape(4_096)
            )
            .unwrap_err(),
        GovernorError::GenerationNotServing {
            requested: generation,
            serving: None
        }
    );

    // The activation is not abandoned under the request that may still compute; the
    // pending activation comes back, and abandoning works once the lease is released.
    let refused = world.governor.abandon_activation(pending).unwrap_err();
    assert_eq!(
        refused.error,
        GovernorError::PreparationInFlight { lease: lease.id() }
    );
    world.governor.release_preparation_lease(lease).unwrap();
    world.governor.abandon_activation(refused.pending).unwrap();
    assert!(world
        .governor
        .confirm_released(&placement, generation, SourceClass::GuestReport)
        .unwrap());
    assert!(world.children().is_empty());
}

#[test]
fn an_abandoned_activation_counts_until_its_release_is_confirmed() {
    let mut world = World::new();
    let placement = world.placement(world.scenario.model_a);
    let pending = world
        .governor
        .admit(&activation_request(&world, "abandoned"))
        .unwrap()
        .activation
        .unwrap();
    let generation = pending.generation();
    assert_eq!(pending.reserved().memory_bytes, MODEL_DEMAND_BYTES);
    assert_eq!(world.holdings(), model_a_holdings(1));
    let abandoned = world.governor.abandon_activation(pending).unwrap();
    // Nothing served before it, so there was nothing to preserve.
    assert_eq!(abandoned.mode, TransitionMode::Initial);
    assert_eq!(abandoned.serving, None);
    // Stopping work does not free its allocation (S10 line 185): the failed placement
    // keeps it and its weights, counted, until its release is confirmed and the slot
    // reclaims it.
    assert_eq!(world.holdings(), model_a_holdings(1));
    let slot = world.governor.slot(&placement, world.epoch()).unwrap();
    let [failed] = slot.placement_keys()[..] else {
        panic!("one placement");
    };
    assert_eq!(
        slot.placement(failed).unwrap().state.kind(),
        StateKind::Failed
    );
    // The runtime's own report closes a reservation carved from its sandbox (T04).
    assert!(world
        .governor
        .confirm_released(&placement, generation, SourceClass::GuestReport)
        .unwrap());
    assert!(world.children().is_empty());
    assert!(!world
        .governor
        .confirm_released(&placement, generation, SourceClass::GuestReport)
        .unwrap());
}

#[test]
fn publication_records_only_the_pending_activations_own_residency() {
    let mut world = World::new();
    let placement = world.placement(world.scenario.model_a);
    let pending = world
        .governor
        .admit(&activation_request(&world, "published"))
        .unwrap()
        .activation
        .unwrap();
    let generation = pending.generation();

    let mut other_model = residency_of(&world);
    other_model.execution = world.scenario.model_b;
    let refused = world
        .governor
        .publish_activation(pending, other_model)
        .unwrap_err();
    assert_eq!(refused.error, GovernorError::ResidencyMismatch);

    let mut stale = residency_of(&world);
    stale.authority =
        AuthorityBinding::new(owner(), ExecutionCategory::VmSandbox, world.epoch().next()).unwrap();
    let refused = world
        .governor
        .publish_activation(refused.pending, stale)
        .unwrap_err();
    assert_eq!(refused.error, GovernorError::ResidencyMismatch);
    assert_eq!(world.governor.current_residency(&placement), None);

    let published = world
        .governor
        .publish_activation(refused.pending, residency_of(&world))
        .unwrap();
    assert_eq!(published, generation);
    assert_eq!(
        world.governor.current_residency(&placement),
        Some(CurrentResidency {
            residency: residency_of(&world),
            generation,
        })
    );
}

#[test]
fn revocation_ends_ready_state_leases_and_new_work() {
    let mut world = World::new();
    let a = world.scenario.model_a;
    let placement = world.placement(a);
    let request = world.request("before", a);
    let receipt = world.serve(&request).unwrap();
    let held = world
        .governor
        .lease_execution(
            &authority(&world, "held"),
            &placement,
            receipt.generation,
            shape(4_096),
        )
        .unwrap();
    let revoked = world.epoch();

    world.governor.coordinator_mut().revoke(&owner()).unwrap();
    let current = world.epoch();
    assert!(current > revoked);

    // A lease from before is no longer honoured, and the residency no longer serves.
    assert!(matches!(
        world.governor.check_execution_lease(&held),
        Err(GovernorError::Lease { .. })
    ));
    assert_eq!(world.governor.current_residency(&placement), None);

    // A request under the revoked epoch finds no ready state and is refused before
    // anything is reserved.
    let mut stale = world.request("stale", a);
    stale.context.epoch = revoked;
    assert_eq!(
        world.serve(&stale).unwrap_err(),
        FlowError::Admission {
            refusal: AdmissionRefusal::Runtime {
                error: GovernorError::StaleAuthorization {
                    presented: revoked,
                    current
                }
            }
        }
    );
    assert!(world
        .api
        .phases(&op("stale"))
        .contains(&FlowPhase::Planned {
            ready_nodes: 0,
            missing_nodes: 7,
            not_needed_nodes: 0
        }));

    // Under the new epoch the revoked sandbox takes no new work either: the slot opened
    // for that epoch reserves nothing for a parent without authority.
    let fresh = world.request("fresh", a);
    assert_eq!(
        world.serve(&fresh).unwrap_err(),
        FlowError::Admission {
            refusal: AdmissionRefusal::Placement {
                error: ActivationError::Reservation {
                    refusal: SlotRefusal::Refused {
                        problem: ReservationProblem::ParentNotAuthorized
                    },
                    mode: TransitionMode::Initial,
                }
            }
        }
    );
}

#[test]
fn a_request_runs_only_under_its_runners_parent_execution_tenant_and_priority() {
    let mut world = World::new();
    let a = world.scenario.model_a;

    let mut other = world.request("other", a);
    other.context.execution = ExecutionId::new("exe-other").unwrap();
    assert_eq!(
        world.serve(&other).unwrap_err(),
        FlowError::NoCompatibleRunner {
            reasons: vec![(runner_owner(), Incompatibility::OtherExecution)]
        }
    );

    let mut foreign = world.request("foreign", a);
    foreign.context.tenant = TenantId::new("tenant-b").unwrap();
    assert_eq!(
        world.serve(&foreign).unwrap_err(),
        FlowError::Admission {
            refusal: AdmissionRefusal::Runtime {
                error: GovernorError::OtherTenant
            }
        }
    );

    let mut background = world.request("background", a);
    background.intent.priority = Priority::Background;
    assert_eq!(
        world.serve(&background).unwrap_err(),
        FlowError::Admission {
            refusal: AdmissionRefusal::Runtime {
                error: GovernorError::PriorityMismatch {
                    requested: Priority::Background,
                    runtime: Priority::Foreground
                }
            }
        }
    );

    world
        .runner
        .set_category(ExecutionCategory::SharedKernelGpuRuntime);
    let mismatched = world.request("mismatched", a);
    assert_eq!(
        world.serve(&mismatched).unwrap_err(),
        FlowError::NoCompatibleRunner {
            reasons: vec![(runner_owner(), Incompatibility::CategoryMismatch)]
        }
    );
    assert!(world.children().is_empty());
}

#[test]
fn staging_is_bounded_and_returned_after_the_last_transfer() {
    let mut world = World::new();
    let request = world.request("staged", world.scenario.model_a);
    world.serve(&request).unwrap();
    let staging: Vec<_> = world
        .governor
        .ledger()
        .closed_records()
        .iter()
        .filter(|record| record.provenance().requester == Requester::ModelPlacement)
        .collect();
    assert_eq!(staging.len(), 1);
    // Pinned pages are host RAM: the staging was charged to both (T08, P02).
    assert_eq!(staging[0].granted().get(STAGING), 5_000);
    assert_eq!(staging[0].granted().get(HOST_RAM), 5_000);
    assert_eq!(staging[0].provenance().purpose, CostPurpose::Transfer);
    assert_eq!(staging[0].provenance().operation, op("staged"));
    let phases = world.api.phases(&op("staged"));
    let at = |phase| phases.iter().position(|seen| *seen == phase).unwrap();
    assert!(at(FlowPhase::StagingReleased) < at(FlowPhase::Activated));

    // The cap bounds staging below the bytes to transfer.
    let mut capped = World::with_policy(GovernorPolicy {
        staging_cap_bytes: 3_000,
        ..policy()
    });
    let request = capped.request("capped", capped.scenario.model_a);
    capped.serve(&request).unwrap();
    let granted: Vec<u64> = capped
        .governor
        .ledger()
        .closed_records()
        .iter()
        .filter(|record| record.provenance().requester == Requester::ModelPlacement)
        .map(|record| record.granted().get(STAGING))
        .collect();
    assert_eq!(granted, vec![3_000]);

    // The policy's transfer limit refuses before anything is reserved.
    let mut limited = World::with_policy(GovernorPolicy {
        max_transfer_bytes: Some(4_000),
        ..policy()
    });
    let request = limited.request("limited", limited.scenario.model_a);
    assert_eq!(
        limited.serve(&request).unwrap_err(),
        FlowError::Admission {
            refusal: AdmissionRefusal::TransferLimit {
                requested_bytes: 5_000,
                limit_bytes: 4_000
            }
        }
    );
    assert!(limited.children().is_empty());

    // A policy with no staging admits no transfer at all.
    let mut unstaged = World::with_policy(GovernorPolicy {
        staging_cap_bytes: 0,
        ..policy()
    });
    let request = unstaged.request("unstaged", unstaged.scenario.model_a);
    assert_eq!(
        unstaged.serve(&request).unwrap_err(),
        FlowError::Admission {
            refusal: AdmissionRefusal::NoStaging
        }
    );
}

/// The review's proof reserved pinned staging that host RAM never counted. Pinned pages
/// are host RAM (§2.7 line 446; decisions T08 and P02), so the governor charges every
/// staging byte to both: a sandbox with too little host RAM gets no staging however much
/// pinned room it has, and nothing stays reserved.
#[test]
fn pinned_staging_is_charged_to_host_ram_too() {
    // While admitted, the staging reservation holds the same bytes of each.
    let mut world = World::new();
    let mut request = activation_request(&world, "staged");
    request.transfer = BTreeMap::from([(extent(world.scenario.base, 0), 2_000)]);
    let admission = world.governor.admit(&request).unwrap();
    assert_eq!(admission.covers(&request), Ok(()));
    let staging = admission.staging.as_ref().unwrap();
    assert_eq!(
        (staging.pinned_bytes(), staging.host_ram_bytes()),
        (2_000, 2_000)
    );
    let granted = world
        .governor
        .ledger()
        .reservation(staging.reservation())
        .unwrap()
        .granted()
        .clone();
    assert_eq!(
        (granted.get(STAGING), granted.get(HOST_RAM)),
        (2_000, 2_000)
    );

    // A sandbox holding 4,000 bytes of host RAM cannot stage 5,000 pinned bytes, although
    // 4 GiB of pinned RAM is free in it.
    let mut tight = World::with_sandbox_host_ram(policy(), 4_000);
    let request = tight.request("tight", tight.scenario.model_a);
    let error = tight.serve(&request).unwrap_err();
    let FlowError::Admission {
        refusal: AdmissionRefusal::Capacity { refusal },
    } = error
    else {
        panic!("the ledger refuses the staging, got {error:?}");
    };
    assert_eq!(refusal.resource, HOST_RAM);
    assert_eq!(refusal.limit, LimitKind::ParentReservation);
    assert_eq!((refusal.requested, refusal.available), (5_000, 4_000));
    // The activation begun for the request was abandoned and closed with it.
    assert!(tight.children().is_empty());
    assert!(tight.runner.calls().is_empty());
}

#[test]
fn activations_run_their_seven_steps_in_the_placements_slot() {
    let mut world = World::new();
    let a = world.scenario.model_a;
    let placement = world.placement(a);
    let request = world.request("served", a);
    let receipt = world.serve(&request).unwrap();

    // One slot for the placement under the current epoch publishes the served generation,
    // reading exactly model A's immutable extents by their state identities on the GPU.
    let slot = world.governor.slot(&placement, world.epoch()).unwrap();
    let published = slot.published().unwrap();
    assert_eq!(published.generation, receipt.generation);
    assert_eq!(published.execution, a);
    assert_eq!(published.artifact, world.scenario.base);
    let expected: BTreeMap<WeightPosition, ExtentKey> = [
        (BASE_0, "base-0"),
        (BASE_1, "base-1"),
        (ADAPTER, "adapter-a"),
        (LAYOUT, "layout"),
    ]
    .into_iter()
    .map(|(id, name)| {
        (
            position(id),
            ExtentKey {
                content: ContentKey::from_digest(state(name).digest()),
                device: gpu(0),
            },
        )
    })
    .collect();
    assert_eq!(published.components, expected);
    let [key] = slot.placement_keys()[..] else {
        panic!("one placement");
    };
    let view = slot.placement(key).unwrap();
    assert_eq!(view.state.kind(), StateKind::Serving);
    assert_eq!(view.generations, vec![receipt.generation]);
    assert_eq!(view.leases, 0);

    // Its readiness covered the request's shape, and the router admits nothing longer.
    let longer = world
        .governor
        .lease_execution(
            &authority(&world, "longer"),
            &placement,
            receipt.generation,
            shape(8_192),
        )
        .unwrap_err();
    assert!(
        matches!(
            longer,
            GovernorError::Route {
                refusal: RouteRefusal::NotReadyForShape { .. }
            }
        ),
        "{longer:?}"
    );
    assert_eq!(world.governor.active_leases(&placement), 0);
}

#[test]
fn the_assigned_request_computes_ahead_only_on_usable_extents() {
    let mut world = World::new();
    let placement = world.placement(world.scenario.model_a);
    let mut request = activation_request(&world, "early");
    request.spec = Some(spec_of(&world, false));
    let pending = world.governor.admit(&request).unwrap().activation.unwrap();
    let lease = world
        .governor
        .lease_preparation(&authority(&world, "early"), &pending)
        .unwrap();
    assert_eq!(lease.ticket().kind, SlotLeaseKind::Preparation);

    // The first base extent is reserved but not made yet: computation on it stalls.
    let base = [state("base-0")];
    assert_eq!(
        world
            .governor
            .start_compute_ahead(&lease, &base)
            .unwrap_err(),
        GovernorError::Early {
            refusal: EarlyRefusal::DependencyNotUsable {
                position: position(BASE_0)
            }
        }
    );
    // Once it is verified and copied, the assigned request computes on it; state that is
    // not an immutable extent, such as the tokenizer, constrains nothing.
    world
        .governor
        .record_usable(&pending, state("base-0"))
        .unwrap();
    let inputs = [state("tokenizer"), state("base-0")];
    world.governor.start_compute_ahead(&lease, &inputs).unwrap();
    world
        .governor
        .finish_compute_ahead(&lease, &inputs)
        .unwrap();

    // Publication waits until every extent is usable (§3.6 step 2).
    let refused = world
        .governor
        .publish_activation(pending, residency_of(&world))
        .unwrap_err();
    assert!(
        matches!(
            refused.error,
            GovernorError::Placement {
                error: ActivationError::ExtentsNotUsable { .. }
            }
        ),
        "{:?}",
        refused.error
    );
    for name in ["base-1", "adapter-a", "layout"] {
        world
            .governor
            .record_usable(&refused.pending, state(name))
            .unwrap();
    }
    let generation = world
        .governor
        .publish_activation(refused.pending, residency_of(&world))
        .unwrap();
    assert_eq!(
        world
            .governor
            .current_residency(&placement)
            .unwrap()
            .generation,
        generation
    );

    // The assignment drains with its generation, and its lease ends as any request's.
    assert_eq!(world.governor.active_leases(&placement), 1);
    world.governor.release_preparation_lease(lease).unwrap();
    assert_eq!(world.governor.active_leases(&placement), 0);
}

#[test]
fn a_new_generation_acquires_resident_extents_and_the_drained_one_is_reclaimed() {
    let mut world = World::new();
    let placement = world.placement(world.scenario.model_a);
    let first = world
        .governor
        .admit(&activation_request(&world, "first"))
        .unwrap()
        .activation
        .unwrap();
    let first_generation = world
        .governor
        .publish_activation(first, residency_of(&world))
        .unwrap();
    let room = world.vram_room();
    assert_eq!(room, SANDBOX_VRAM_BYTES - MODEL_DEMAND_BYTES);

    // Versions overlap: the second acquires the four resident extents (8 GiB + 640 MiB)
    // and reserves only the rest of its demand anew, so shared weights count once.
    let second = world
        .governor
        .admit(&activation_request(&world, "second"))
        .unwrap()
        .activation
        .unwrap();
    let weights = 8 * GIB + 640 * MIB;
    assert_eq!(world.vram_room(), room - (MODEL_DEMAND_BYTES - weights));
    let second_generation = world
        .governor
        .publish_activation(second, residency_of(&world))
        .unwrap();
    assert!(second_generation > first_generation);
    let slot = world.governor.slot(&placement, world.epoch()).unwrap();
    let [old, new] = slot.placement_keys()[..] else {
        panic!("two placements");
    };
    assert_eq!(
        slot.placement(old).unwrap().state.kind(),
        StateKind::Draining
    );

    // The drained placement is reclaimed once its release is confirmed; the extents the
    // second generation reads stay resident, and it keeps serving.
    assert!(world
        .governor
        .confirm_released(&placement, first_generation, SourceClass::GuestReport)
        .unwrap());
    let slot = world.governor.slot(&placement, world.epoch()).unwrap();
    assert!(slot.placement(old).is_none());
    assert_eq!(
        slot.placement(new).unwrap().state.kind(),
        StateKind::Serving
    );
    assert_eq!(
        world
            .governor
            .current_residency(&placement)
            .unwrap()
            .generation,
        second_generation
    );

    // A serving placement is never reclaimed, and a guest cannot be overruled by a
    // weaker source than its own report.
    assert_eq!(
        world
            .governor
            .confirm_released(&placement, second_generation, SourceClass::GuestReport)
            .unwrap_err(),
        GovernorError::Slot {
            error: SlotError::NotReclaimable {
                placement: new,
                state: StateKind::Serving
            }
        }
    );
    assert_eq!(
        world
            .governor
            .confirm_released(
                &placement,
                second_generation,
                SourceClass::RecordedDeclaration
            )
            .unwrap_err(),
        GovernorError::ReleaseSourceTooWeak {
            source: SourceClass::RecordedDeclaration
        }
    );
}
