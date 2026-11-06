//! The GPU §1 flow end to end on fakes (lines 272–295): the three paths, the event
//! sequence on a manual clock, execute-while-load, readiness for the request shape,
//! rechecked hints, the security partition, and what is kept after serving.

use std::time::Duration;

use super::support::*;
use crate::foundation::coordination::{ActivationState, LeaseKind, LeaseState, RetireReason};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{
    ContentKey, ExecutionCategory, ModelActivationGeneration, MonotonicTime, TrustScope,
};
use crate::model_memory::boundaries::fakes::{FakeModel, RunnerCall};
use crate::model_memory::boundaries::*;
use crate::model_memory::executor::SourceKind;
use crate::model_memory::graph::node::NodeKind;
use crate::model_memory::identity::{
    AdvertisementRefusal, AuthorityBinding, CurrentResidency, GrantRefusal, Residency,
};
use crate::model_memory::math::overlap::NoStall;
use crate::model_memory::placement::ShapeRefusal;
use crate::model_memory::residency::eviction::{CopyTier, EvictionAction, NotDroppable};

type Step = (FlowPhase, Option<u32>, f64);

/// Each event of one request: its phase, the node it names and its time in seconds.
fn trace(world: &World, name: &str) -> Vec<Step> {
    world
        .api
        .events
        .iter()
        .filter(|event| event.operation == op(name))
        .map(|event| {
            (
                event.phase,
                event.resource.map(NodeId::get),
                seconds(event.at),
            )
        })
        .collect()
}

fn events<'w>(world: &'w World, name: &str) -> Vec<&'w FlowEvent> {
    world
        .api
        .events
        .iter()
        .filter(|event| event.operation == op(name))
        .collect()
}

/// When `phase` happened for `node`.
fn at(trace: &[Step], phase: FlowPhase, node: u32) -> f64 {
    trace
        .iter()
        .find(|(seen, resource, _)| *seen == phase && *resource == Some(node))
        .map(|step| step.2)
        .unwrap()
}

fn close(left: f64, right: f64) -> bool {
    (left - right).abs() < 1e-9
}

fn all_close(left: &[f64], right: &[f64]) -> bool {
    left.len() == right.len() && left.iter().zip(right).all(|(l, r)| close(*l, *r))
}

/// A served session the caller will not resume, with the runner's pinned-host tier.
fn written_back() -> SessionRetention {
    SessionRetention::Released {
        action: EvictionAction::WriteBackThenDrop {
            d2h_bytes: 2 * GIB,
            because: NotDroppable::Dirty,
        },
    }
}

#[test]
fn the_end_to_end_event_sequence_on_a_manual_clock() {
    use FlowPhase::*;
    let mut world = World::new();
    let a = world.scenario.model_a;
    let request = world.request("first", a);
    let receipt = world.serve(&request).unwrap();

    // Reconstruction runs while the link streams: tokenizer, engine and layout under
    // base-0, the graph under the adapter. The link takes 2 s, 2 s and 1 s.
    assert_eq!(
        trace(&world, "first"),
        vec![
            (Requested, None, 0.0),
            (
                Planned {
                    ready_nodes: 0,
                    missing_nodes: 7,
                    not_needed_nodes: 0
                },
                None,
                0.0
            ),
            (Reserved, None, 0.0),
            (MissingState, None, 0.0),
            (TransferStarted, None, 0.0),
            (DependencyPublished, Some(TOKENIZER), 0.1),
            (DependencyPublished, Some(ENGINE), 1.6),
            (DependencyPublished, Some(LAYOUT), 1.9),
            (ExtentVerified, Some(BASE_0), 2.0),
            (DependencyPublished, Some(BASE_0), 2.0),
            (ExtentVerified, Some(BASE_1), 4.0),
            (DependencyPublished, Some(BASE_1), 4.0),
            (DependencyPublished, Some(GRAPH), 4.5),
            (ExtentVerified, Some(ADAPTER), 5.0),
            (DependencyPublished, Some(ADAPTER), 5.0),
            (StagingReleased, None, 5.0),
            (Activated, None, 5.0),
            (LeaseAcquired, None, 5.0),
            (Served, None, 5.5),
            (LeaseReleased, None, 5.5),
            (
                StateRetained {
                    kept_nodes: 7,
                    session: written_back()
                },
                None,
                5.5
            ),
        ]
    );
    let first = events(&world, "first");
    assert_eq!(
        first.iter().map(|event| event.sequence).collect::<Vec<_>>(),
        (1..=21).collect::<Vec<u64>>()
    );
    let generation = ModelActivationGeneration::FIRST;
    assert!(first
        .iter()
        .skip_while(|event| event.phase != Activated)
        .all(|event| event.generation == Some(generation)));
    // §3.10 byte fields: the transfer total, the reservation, bytes read and bytes made
    // usable (every missing node: 9 GiB + 896 MiB).
    assert_eq!(first[1].total_bytes, 5_000);
    assert_eq!(first[2].total_bytes, MODEL_DEMAND_BYTES);
    let read: Vec<u64> = first
        .iter()
        .filter(|event| event.phase == ExtentVerified)
        .map(|event| event.completed_bytes)
        .collect();
    assert_eq!(read, vec![2_000, 4_000, 5_000]);
    let published = first[14];
    assert_eq!(published.phase, DependencyPublished);
    assert_eq!(published.committed_usable_bytes, 9 * GIB + 896 * MIB);
    assert_eq!(published.total_bytes, 9 * GIB + 896 * MIB);

    assert_eq!(receipt.path, ServePath::Materialized);
    assert_eq!(receipt.generation, generation);
    assert_eq!(receipt.transferred, ids(&[BASE_0, BASE_1, ADAPTER]));
    assert_eq!(
        receipt.reconstructed,
        ids(&[TOKENIZER, ENGINE, LAYOUT, GRAPH])
    );
    assert!(receipt.not_needed.is_empty() && receipt.hint_refusals.is_empty());
    assert_eq!(receipt.reserved_device_bytes, MODEL_DEMAND_BYTES);
    assert_eq!(seconds(receipt.first_token_at), 5.5);
    assert_eq!(receipt.session, written_back());

    // The next request finds the engine ready and is served at once, its own sequence
    // starting again at 1.
    let request = world.request("second", a);
    world.serve(&request).unwrap();
    assert_eq!(
        trace(&world, "second"),
        vec![
            (Requested, None, 5.5),
            (
                Planned {
                    ready_nodes: 7,
                    missing_nodes: 0,
                    not_needed_nodes: 0
                },
                None,
                5.5
            ),
            (Reserved, None, 5.5),
            (ReadyEngine, None, 5.5),
            (LeaseAcquired, None, 5.5),
            (Served, None, 6.0),
            (LeaseReleased, None, 6.0),
            (
                StateRetained {
                    kept_nodes: 7,
                    session: written_back()
                },
                None,
                6.0
            ),
        ]
    );
    assert_eq!(events(&world, "second")[0].sequence, 1);
}

#[test]
fn the_ready_engine_path_makes_no_transfer() {
    let mut world = World::new();
    let a = world.scenario.model_a;
    let placement = world.placement(a);
    let request = world.request("first", a);
    let first = world.serve(&request).unwrap();
    let submitted = world.executor.submitted().len();
    let calls = world.runner.calls().len();
    let children = world.children();

    let request = world.request("second", a);
    let receipt = world.serve(&request).unwrap();
    assert_eq!(receipt.path, ServePath::Ready);
    assert_eq!(receipt.generation, first.generation);
    assert!(receipt.transferred.is_empty() && receipt.reconstructed.is_empty());
    assert_eq!(receipt.reserved_device_bytes, 0);
    // Nothing moved, nothing new was reserved or activated: the runner only served.
    assert_eq!(world.executor.submitted().len(), submitted);
    assert_eq!(world.children(), children);
    assert_eq!(
        world
            .governor
            .coordinator()
            .model_activations(&owner(), placement.model_id())
            .unwrap()
            .activations()
            .len(),
        1
    );
    assert_eq!(
        &world.runner.calls()[calls..],
        &[
            RunnerCall::Serve {
                operation: op("second"),
                generation: first.generation
            },
            RunnerCall::ReleaseSession {
                operation: op("second"),
                action: EvictionAction::WriteBackThenDrop {
                    d2h_bytes: 2 * GIB,
                    because: NotDroppable::Dirty
                }
            },
        ]
    );
    assert!(close(seconds(receipt.first_token_at), 6.0));
}

#[test]
fn the_missing_state_path_transfers_only_the_missing_nodes() {
    let mut world = World::new();
    let (a, b) = (world.scenario.model_a, world.scenario.model_b);
    let request = world.request("a", a);
    world.serve(&request).unwrap();
    let before = world.executor.submitted().len();

    // B shares A's base, engine, graph and rank layout. It needs only its adapter, and
    // the raw checkpoint B would build the layout from is not needed: the layout is
    // ready.
    let request = world.request("b", b);
    let receipt = world.serve(&request).unwrap();
    assert_eq!(receipt.path, ServePath::Materialized);
    assert_eq!(receipt.transferred, ids(&[ADAPTER]));
    assert!(receipt.reconstructed.is_empty());
    assert_eq!(receipt.not_needed, ids(&[RAW]));
    assert!(receipt.hint_refusals.is_empty());
    assert_eq!(
        &world.executor.submitted()[before..],
        &[extent(world.scenario.adapter_b, 0)]
    );
    assert!(!world.runner.is_resident(&state("raw")));
    assert!(world.api.phases(&op("b")).contains(&FlowPhase::Planned {
        ready_nodes: 6,
        missing_nodes: 1,
        not_needed_nodes: 1
    }));
    // One second of transfer and half a second of compute after A's 5.5 s.
    assert!(close(seconds(receipt.first_token_at), 7.0));
    // Both variants now serve, each its own first generation.
    for model in [a, b] {
        let current = world
            .governor
            .current_residency(&world.placement(model))
            .unwrap();
        assert_eq!(current.generation, ModelActivationGeneration::FIRST);
        assert_eq!(current.residency.execution, model);
    }
}

#[test]
fn unavoidable_work_overlaps_the_transfers() {
    let mut world = World::new();
    let request = world.request("overlapped", world.scenario.model_a);
    let receipt = world.serve(&request).unwrap();
    let steps = trace(&world, "overlapped");
    // Serially the request is 7.9 s of work: 5 s on the link, 2.4 s of reconstruction
    // and 0.5 s of compute. Reconstruction ran beneath the transfers, so the first token
    // came at 5.5 s.
    assert!(
        at(&steps, FlowPhase::DependencyPublished, ENGINE)
            < at(&steps, FlowPhase::ExtentVerified, BASE_0)
    );
    assert!(
        at(&steps, FlowPhase::DependencyPublished, GRAPH)
            < at(&steps, FlowPhase::ExtentVerified, ADAPTER)
    );
    assert_eq!(seconds(receipt.first_token_at), 5.5);
    // The T06 plan, with links uncontended, hid 5.1 s of its 7.95 s of serial work and
    // expected the first token at 2.85 s.
    assert_eq!(receipt.planned_overlap, ms(5_100));
    assert!(close(seconds(receipt.planned_first_token_at), 2.85));
    // The §2.6 recurrence over the measured arrivals: what execute-while-load would have
    // reached, 5.3 s, and the 2.5 s it would reach with no stall.
    let overlap = receipt.overlap.unwrap();
    assert!(all_close(&overlap.group_usable_at_seconds, &[2.0, 5.0]));
    assert!(all_close(&overlap.group_compute_seconds, &[0.2, 0.3]));
    assert!(all_close(&overlap.group_finish_seconds, &[2.2, 5.3]));
    assert!(close(overlap.ideal_finish_seconds, 2.5));
    assert!(matches!(overlap.no_stall, NoStall::Stalls { group: 2, .. }));
}

#[test]
fn execute_while_load_computes_only_under_a_preparation_lease() {
    use FlowPhase::*;
    let mut world = World::new();
    let a = world.scenario.model_a;
    let mut request = world.request("ahead", a);
    request.intent.policy.execute_while_load = true;
    let receipt = world.serve(&request).unwrap();

    // Group 0 ran as soon as base-0 was usable, under the lease of the one assigned
    // request; group 1's inputs completed with the last transfer, so it ran at serving.
    assert_eq!(receipt.computed_ahead_groups, 1);
    assert_eq!(receipt.compute_ahead_refusal, None);
    assert!(close(seconds(receipt.first_token_at), 5.3));
    let steps = trace(&world, "ahead");
    let when = |phase| {
        steps
            .iter()
            .find(|step| step.0 == phase)
            .map(|step| step.2)
            .unwrap()
    };
    assert_eq!(when(PreparationLeased), 0.0);
    assert!(close(when(ComputedAhead { group: 0 }), 2.2));
    assert!(close(when(PreparationReleased), 5.0));
    // The slot admits one lease per request: the preparation lease ends before the
    // serving lease is taken, and nothing is served before.
    let order: Vec<FlowPhase> = steps.iter().map(|step| step.0).collect();
    let index = |phase| order.iter().position(|seen| *seen == phase).unwrap();
    assert!(index(Activated) < index(PreparationReleased));
    assert!(index(PreparationReleased) < index(LeaseAcquired));
    assert!(index(LeaseAcquired) < index(Served));
    assert!(world.runner.calls().contains(&RunnerCall::ComputeAhead {
        operation: op("ahead"),
        group: 0
    }));
    // Both leases were the coordinator's, the preparation lease on the loading
    // generation, and both are released.
    let leases: Vec<(LeaseKind, ModelActivationGeneration, bool)> = world
        .governor
        .coordinator()
        .leases()
        .filter(|record| record.lease().operation() == &op("ahead"))
        .map(|record| {
            (
                record.lease().kind(),
                record.lease().model().unwrap().generations.activation,
                matches!(record.state(), LeaseState::Released { .. }),
            )
        })
        .collect();
    assert_eq!(
        leases,
        vec![
            (LeaseKind::Preparation, receipt.generation, true),
            (LeaseKind::ModelRequest, receipt.generation, true),
        ]
    );
    let overlap = receipt.overlap.unwrap();
    assert!(all_close(&overlap.group_finish_seconds, &[2.2, 5.3]));

    // A backend that cannot compute ahead is never asked to.
    let mut world = World::new();
    world.runner.set_execute_while_load(false);
    let mut request = world.request("plain", a);
    request.intent.policy.execute_while_load = true;
    let receipt = world.serve(&request).unwrap();
    assert_eq!(receipt.computed_ahead_groups, 0);
    assert!(!world.api.phases(&op("plain")).contains(&PreparationLeased));
}

#[test]
fn the_section_2_6_worked_example_runs_through_the_flow() {
    // §2.6: inputs usable at 1 s and 11 s, compute of 1 s and 10 s: the second group
    // cannot start before its input, so the first token comes at 21 s rather than 12 s.
    let mut world = World::new();
    let artifact = import(&mut world.catalog, "worked", &[1_000, 10_000]);
    for index in 0..2 {
        let bytes = world
            .catalog
            .content(&extent(artifact, index))
            .unwrap()
            .to_vec();
        world
            .executor
            .add_source(extent(artifact, index), bytes, SourceKind::LocalFile);
    }
    let model = execution_of("worked-example");
    world.runner.add_model(
        model,
        FakeModel {
            dependencies: ExecutionDependencies {
                artifact,
                nodes: vec![
                    node(
                        1,
                        NodeKind::EngineInitialization,
                        "worked-engine",
                        GIB,
                        Duration::from_nanos(1),
                        &[],
                        Materialization::Reconstruct,
                    ),
                    node(
                        2,
                        NodeKind::ArtifactExtent,
                        "worked-0",
                        GIB,
                        ms(1_000),
                        &[],
                        transfer(artifact, 0),
                    ),
                    node(
                        3,
                        NodeKind::ArtifactExtent,
                        "worked-1",
                        4 * GIB,
                        ms(10_000),
                        &[],
                        transfer(artifact, 1),
                    ),
                ],
                compute: vec![group(&[1, 2], ms(1_000)), group(&[3], ms(10_000))],
                response: ms(1),
                session_device_bytes: GIB,
                transition_peak_device_bytes: 0,
            },
            max_shape: MAX_SHAPE,
        },
    );
    let mut request = world.request("worked", model);
    request.intent.policy.execute_while_load = true;
    let receipt = world.serve(&request).unwrap();
    let overlap = receipt.overlap.unwrap();
    assert!(all_close(&overlap.group_usable_at_seconds, &[1.0, 11.0]));
    assert!(all_close(&overlap.group_compute_seconds, &[1.0, 10.0]));
    assert!(all_close(&overlap.group_finish_seconds, &[2.0, 21.0]));
    assert!(close(overlap.ideal_finish_seconds, 12.0));
    let NoStall::Stalls {
        group,
        usable_at_seconds,
        deadline_seconds,
    } = overlap.no_stall
    else {
        panic!("the second input arrives late");
    };
    assert_eq!(group, 2);
    assert!(close(usable_at_seconds, 11.0) && close(deadline_seconds, 2.0));
    assert_eq!(receipt.computed_ahead_groups, 1);
    assert!(close(seconds(receipt.first_token_at), 21.0));
}

#[test]
fn a_materialized_model_is_not_ready_for_a_longer_context() {
    let mut world = World::new();
    let a = world.scenario.model_a;
    let placement = world.placement(a);
    let request = world.request("short-context", a);
    let first = world.serve(&request).unwrap();

    // Line 585: materialized, but readiness was checked for 4,096 tokens only. A request
    // of 8,192 needs a new generation; nothing is transferred or rebuilt.
    let sandbox = |world: &World| {
        world
            .governor
            .coordinator()
            .sandbox(&owner())
            .unwrap()
            .generations()
    };
    let before = sandbox(&world);
    let mut longer = world.request("long-context", a);
    longer.intent.shape = shape(8_192);
    let receipt = world.serve(&longer).unwrap();
    let second = first.generation.next().unwrap();
    assert_eq!(receipt.path, ServePath::Materialized);
    assert_eq!(receipt.generation, second);
    assert!(receipt.transferred.is_empty() && receipt.reconstructed.is_empty());
    // S3.1: the model's activation and GPU allocation generations moved; the sandbox's
    // boot generation, policy epoch and authorization epoch did not.
    assert_eq!(sandbox(&world), before);

    // The old generation drained at once, since no request held it, and retired; its
    // memory counts until the runtime confirms the release (T09).
    let activations = world
        .governor
        .coordinator()
        .model_activations(&owner(), placement.model_id())
        .unwrap();
    assert_eq!(
        activations.activation(first.generation).unwrap().state(),
        ActivationState::Retired {
            reason: RetireReason::Replaced
        }
    );
    assert_eq!(
        activations.serving().unwrap().generations().activation,
        second
    );
    assert!(
        activations.serving().unwrap().generations().gpu_allocation
            > activations
                .activation(first.generation)
                .unwrap()
                .generations()
                .gpu_allocation
    );
    // The new generation acquired the weights of the four resident extents, held apart
    // from any activation, and reserved only its own memory, so the weights count once.
    // The old generation's own memory, its KV and contexts, stays its own and counts until
    // the old placement is reclaimed: never uncounted, never taken over.
    assert_eq!(receipt.reserved_device_bytes, MODEL_DEMAND_BYTES);
    assert_eq!(world.holdings(), model_a_holdings(2));
    assert_eq!(
        world.vram_room(),
        SANDBOX_VRAM_BYTES - MODEL_DEMAND_BYTES - MODEL_A_OWN_BYTES
    );
    // The old placement drained; its release reclaims it in the slot and frees its own
    // memory, while the weights the new generation reads stay, counted once.
    assert!(world
        .governor
        .confirm_released(&placement, first.generation, SourceClass::GuestReport)
        .unwrap());
    assert_eq!(world.holdings(), model_a_holdings(1));
    assert_eq!(world.vram_room(), SANDBOX_VRAM_BYTES - MODEL_DEMAND_BYTES);
    let slot = world.governor.slot(&placement, world.epoch()).unwrap();
    assert_eq!(slot.placement_keys().len(), 1);
    assert_eq!(slot.published().unwrap().generation, second);
    assert_eq!(
        world.runner.held_generations(&a),
        vec![first.generation, second]
    );

    // Beyond the runner's largest shape the request is refused before admission.
    let mut huge = world.request("huge", a);
    huge.intent.shape = shape(16_384);
    assert_eq!(
        world.serve(&huge).unwrap_err(),
        FlowError::NoCompatibleRunner {
            reasons: vec![(
                runner_owner(),
                Incompatibility::ShapeTooLarge {
                    refusal: ShapeRefusal::ContextTooLong {
                        requested_tokens: 16_384,
                        supported_tokens: 8_192
                    }
                }
            )]
        }
    );
}

#[test]
fn hints_are_rechecked_before_any_counts_as_ready() {
    let world_epoch_binding = |world: &World| {
        AuthorityBinding::new(owner(), ExecutionCategory::VmSandbox, Some(world.epoch())).unwrap()
    };

    // A forged advertisement: coordination never recorded it, so its state is moved
    // again even though the runner claims to hold it.
    let mut world = World::new();
    let a = world.scenario.model_a;
    let forged = CurrentResidency {
        residency: Residency {
            execution: a,
            artifact: world.scenario.base,
            owner: tenant(),
            scope: scope(),
            device: gpu(0),
            authority: world_epoch_binding(&world),
        },
        generation: ModelActivationGeneration::new(7),
    };
    world.runner.force_generation(a, &forged, MAX_SHAPE);
    for name in ["base-0", "base-1"] {
        world.runner.make_resident(state(name), 4 * GIB);
    }
    let request = world.request("forged", a);
    let receipt = world.serve(&request).unwrap();
    assert_eq!(
        receipt.hint_refusals,
        vec![HintRefusal::NoRecord { model: a }]
    );
    assert_eq!(receipt.transferred, ids(&[BASE_0, BASE_1, ADAPTER]));

    // An expired advertisement (line 506: a hint with an expiry) counts for nothing.
    let mut world = World::new();
    let request = world.request("first", a);
    world.serve(&request).unwrap();
    world.runner.set_advertisement_ttl(Duration::ZERO);
    let request = world.request("expired", a);
    let receipt = world.serve(&request).unwrap();
    let then = MonotonicTime::from_nanos(5_500_000_000);
    assert_eq!(
        receipt.hint_refusals,
        vec![HintRefusal::Recheck {
            model: a,
            refusal: AdvertisementRefusal::Expired {
                expires_at: then,
                now: then
            }
        }]
    );
    assert_eq!(receipt.path, ServePath::Materialized);
    assert_eq!(receipt.transferred, ids(&[BASE_0, BASE_1, ADAPTER]));

    // Equal storage is not permission (S3.3): without a scoped grant the resident copy
    // is not served from.
    let mut world = World::new();
    let request = world.request("first", a);
    world.serve(&request).unwrap();
    let mut ungranted = world.request("ungranted", a);
    ungranted.context.grants.clear();
    let receipt = world.serve(&ungranted).unwrap();
    assert_eq!(
        receipt.hint_refusals,
        vec![HintRefusal::Recheck {
            model: a,
            refusal: AdvertisementRefusal::Unauthorized(GrantRefusal::Missing)
        }]
    );
    assert_eq!(receipt.path, ServePath::Materialized);
}

#[test]
fn the_security_partition_is_fixed_before_scheduling() {
    let mut world = World::new();
    let a = world.scenario.model_a;
    let elsewhere = TrustScope::named(ExecutionCategory::VmSandbox, "tenant-b/sandbox");

    // A runner whose state lives outside the request's partition is never used.
    let mut request = world.request("elsewhere", a);
    request.context.partition = SecurityPartition::new(elsewhere);
    assert_eq!(
        world.serve(&request).unwrap_err(),
        FlowError::NoCompatibleRunner {
            reasons: vec![(runner_owner(), Incompatibility::OutsidePartition)]
        }
    );

    // Nor one that would need state from such a scope (S3.6).
    let cross = execution_of("cross-scope");
    let mut dependencies = model_a_dependencies(&world.scenario);
    dependencies.nodes[0].scope = elsewhere;
    world.runner.add_model(
        cross,
        FakeModel {
            dependencies,
            max_shape: MAX_SHAPE,
        },
    );
    let request = world.request("cross", cross);
    assert_eq!(
        world.serve(&request).unwrap_err(),
        FlowError::NoCompatibleRunner {
            reasons: vec![(
                runner_owner(),
                Incompatibility::DependencyOutsidePartition {
                    node: NodeId::new(TOKENIZER)
                }
            )]
        }
    );

    // The catalog hands out only artifacts the partition may read.
    let bytes = content("foreign", 0, 1_000);
    let foreign = world
        .catalog
        .import(ImportSubmission {
            scope: elsewhere,
            provenance: provenance("foreign"),
            extents: vec![ImportedExtent {
                extent: ExtentId::new(0),
                claimed_digest: ContentKey::of(&bytes),
                content: bytes,
            }],
        })
        .unwrap();
    let foreign_model = execution_of("foreign-adapter");
    let mut dependencies = model_a_dependencies(&world.scenario);
    for node in &mut dependencies.nodes {
        if node.id == NodeId::new(ADAPTER) {
            node.materialization = transfer(foreign, 0);
        }
    }
    world.runner.add_model(
        foreign_model,
        FakeModel {
            dependencies,
            max_shape: MAX_SHAPE,
        },
    );
    let request = world.request("foreign", foreign_model);
    assert_eq!(
        world.serve(&request).unwrap_err(),
        FlowError::Catalog {
            refusal: CatalogRefusal::OutsidePartition { artifact: foreign }
        }
    );
    assert!(world.children().is_empty());
}

#[test]
fn sessions_leave_only_by_the_t08_rule() {
    let mut world = World::new();
    let a = world.scenario.model_a;

    // The caller will resume: the session stays.
    let mut request = world.request("resumed", a);
    request.intent.policy.resume_session = true;
    assert_eq!(
        world.serve(&request).unwrap().session,
        SessionRetention::Kept
    );
    assert!(world.runner.has_session(&op("resumed")));

    // Not resumed, with pinned host RAM to write to: written back, then dropped.
    let request = world.request("written", a);
    assert_eq!(world.serve(&request).unwrap().session, written_back());
    assert!(!world.runner.has_session(&op("written")));
    assert_eq!(world.runner.written_back(), &[(op("written"), 2 * GIB)]);

    // Without a tier that guarantees availability, dirty KV is kept, never dropped.
    for (name, tier) in [
        ("untiered", None),
        ("reclaimable", Some(CopyTier::ReclaimableHost)),
        ("remote", Some(CopyTier::RemoteSource)),
    ] {
        world.runner.set_kv_write_back(tier);
        let request = world.request(name, a);
        assert_eq!(
            world.serve(&request).unwrap().session,
            SessionRetention::Retained {
                because: NotDroppable::Dirty
            }
        );
        assert!(world.runner.has_session(&op(name)));
    }
    // Immutable state stays resident in every case.
    for name in ["base-0", "base-1", "adapter-a", "engine", "graph", "layout"] {
        assert!(world.runner.is_resident(&state(name)), "{name}");
    }
    // A session that holds no device memory has nothing to release.
    assert_eq!(
        retain_session(
            0,
            served_session(&op("empty"), ModelActivationGeneration::FIRST),
            false,
            None
        ),
        SessionRetention::Kept
    );
}
