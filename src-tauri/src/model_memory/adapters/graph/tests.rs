use std::time::Duration;

use super::*;
use crate::foundation::ids::{AuthorizationEpoch, ManualClock};
use crate::model_memory::adapters::adapter::LayerShape;
use crate::model_memory::adapters::fakes::{
    adapter_identity, adapter_reference, base_spec, close, copy, execution, execution_identity, id,
    justified, logical, residency, token_prefix, versioned, weights_content, KvFixture, Recording,
    Restore, LIMITS,
};
use crate::model_memory::adapters::kv::KvSharing;
use crate::model_memory::residency::eviction::CopyTier;
use crate::model_memory::residency::retention::ObjectKind;

struct Fixture {
    graph: DependencyGraph,
    base: NodeId,
    adapter: NodeId,
    variant: NodeId,
    pool: NodeId,
    kv: NodeId,
}

fn chat(base: NodeId, adapter: NodeId) -> KvFixture {
    KvFixture {
        adapter: Some((adapter, adapter_identity("adapter-sql"))),
        ..KvFixture::new(base, execution_identity("base-8b"), "chat")
    }
}

fn fixture() -> Fixture {
    let mut graph = DependencyGraph::new();
    let base = graph.add_base(base_spec("base-8b", 16_000, true)).unwrap();
    let adapter = graph
        .admit_adapter(
            base,
            adapter_reference("adapter-sql", "base-8b"),
            &LIMITS,
            residency("adapter-sql", 50, true),
        )
        .unwrap();
    let variant = graph
        .materialize_merged(
            base,
            adapter,
            versioned("merge-procedure"),
            ContentKey::of(b"merged"),
            justified("base-8b", "adapter-sql", 16_000),
        )
        .unwrap();
    let pool = graph
        .add_graph_pool(GraphPoolSpec {
            execution_key: id("graphs-bs1-8"),
            bytes: 300,
            recapture_seconds: 1.5,
            prerequisites: BTreeSet::from([base]),
        })
        .unwrap();
    let kv = graph.add_session_kv(chat(base, adapter).spec()).unwrap();
    Fixture {
        graph,
        base,
        adapter,
        variant,
        pool,
        kv,
    }
}

fn grown(fixture: &KvFixture) -> KvWrite {
    let spec = fixture.spec();
    KvWrite {
        bytes: fixture.bytes,
        token_prefix: spec.stored.spec.scope.prefix,
        restore: spec.restore,
    }
}

fn lease(until_nanos: u64) -> Hold {
    Hold::Leased {
        lease: LeaseId::new(7),
        until: MonotonicTime::from_nanos(until_nanos),
    }
}

#[test]
fn only_session_kv_accepts_writes() {
    let Fixture {
        mut graph,
        base,
        adapter,
        variant,
        pool,
        kv,
    } = fixture();
    let next = KvFixture {
        tokens: 1_500,
        bytes: 1_500_000,
        ..chat(base, adapter)
    };
    for (node, kind) in [
        (base, NodeKind::Base),
        (adapter, NodeKind::Adapter),
        (variant, NodeKind::MergedVariant),
        (pool, NodeKind::GraphPool),
    ] {
        let before = graph.node(node).unwrap().clone();
        assert_eq!(
            graph.write_kv(node, grown(&next)),
            Err(GraphError::Immutable { node, kind })
        );
        assert_eq!(kind.mutability(), Mutability::Immutable);
        assert_eq!(graph.node(node).unwrap(), &before);
    }
    assert_eq!(NodeKind::SessionKv.mutability(), Mutability::Mutable);
    graph.write_kv(kv, grown(&next)).unwrap();
    let NodeData::SessionKv { stored, .. } = graph.node(kv).unwrap().data() else {
        panic!("not KV");
    };
    assert_eq!(stored.spec.scope.prefix.token_count(), 1_500);
    assert_eq!(graph.node(kv).unwrap().bytes(), 1_500_000);

    // A write whose restore requirement names another state is refused.
    let mut stale = grown(&next);
    stale.restore.requirement.state_identity = id("another state");
    assert!(matches!(
        graph.write_kv(kv, stale),
        Err(GraphError::KvStateMismatch { .. })
    ));

    graph.end_session(kv).unwrap();
    assert_eq!(
        graph.write_kv(kv, grown(&next)),
        Err(GraphError::SessionEnded { node: kv })
    );
}

#[test]
fn shared_public_prefix_kv_is_never_extended() {
    let Fixture {
        mut graph, base, ..
    } = fixture();
    let prompt = KvFixture {
        sharing: KvSharing::PublicPrefix {
            prefix: token_prefix("system prompt", 1_000),
        },
        ..KvFixture::new(base, execution_identity("base-8b"), "system prompt")
    };
    let shared = graph.add_session_kv(prompt.spec()).unwrap();
    let longer = KvFixture {
        tokens: 1_200,
        ..prompt
    };
    assert_eq!(
        graph.write_kv(shared, grown(&longer)),
        Err(GraphError::SharedKvIsReadOnly { node: shared })
    );
}

#[test]
fn bases_and_session_kv_are_accounted_apart() {
    let Fixture {
        mut graph,
        base,
        adapter,
        kv,
        ..
    } = fixture();
    let before = graph.resident_bytes().unwrap();
    assert_eq!(before, 16_000 + 50 + 16_000 + 300 + 1_000_000);
    let next = KvFixture {
        tokens: 2_000,
        bytes: 2_000_000,
        ..chat(base, adapter)
    };
    graph.write_kv(kv, grown(&next)).unwrap();
    assert_eq!(graph.resident_bytes().unwrap(), before + 1_000_000);
    assert_eq!(graph.node(base).unwrap().bytes(), 16_000);
}

#[test]
fn an_immutable_node_never_depends_on_session_kv() {
    let Fixture {
        mut graph,
        base,
        kv,
        ..
    } = fixture();
    let pool = |prerequisites| GraphPoolSpec {
        execution_key: id("graphs"),
        bytes: 10,
        recapture_seconds: 0.1,
        prerequisites,
    };
    assert_eq!(
        graph.add_graph_pool(pool(BTreeSet::from([base, kv]))),
        Err(GraphError::MutablePrerequisite { node: kv })
    );
    assert_eq!(
        graph.add_graph_pool(pool(BTreeSet::new())),
        Err(GraphError::NoPrerequisites)
    );
    assert_eq!(
        graph.add_graph_pool(pool(BTreeSet::from([NodeId(99)]))),
        Err(GraphError::UnknownNode { node: NodeId(99) })
    );
}

#[test]
fn kv_is_bound_to_the_weights_and_adapter_that_computed_it() {
    let Fixture {
        mut graph,
        base,
        adapter,
        variant,
        ..
    } = fixture();
    let count = graph.len();
    let wrong_model = KvFixture::new(base, execution_identity("base-70b"), "chat");
    assert_eq!(
        graph.add_session_kv(wrong_model.spec()),
        Err(GraphError::KvModelMismatch { node: base })
    );
    let adapter_as_weights = KvFixture::new(adapter, execution_identity("base-8b"), "chat");
    assert_eq!(
        graph.add_session_kv(adapter_as_weights.spec()),
        Err(GraphError::KvModelMismatch { node: adapter })
    );
    // The key names an adapter, but no adapter node is given, or another adapter is.
    let mut missing = chat(base, adapter).spec();
    missing.adapter = None;
    assert_eq!(
        graph.add_session_kv(missing),
        Err(GraphError::KvAdapterMismatch)
    );
    let misnamed = KvFixture {
        adapter: Some((adapter, adapter_identity("adapter-legal"))),
        ..chat(base, adapter)
    };
    assert_eq!(
        graph.add_session_kv(misnamed.spec()),
        Err(GraphError::KvAdapterMismatch)
    );
    // A merged variant already contains the adapter, which was made for the base.
    let Some((variant_identity, _)) = graph.node(variant).unwrap().data().model() else {
        panic!("a variant runs as a model");
    };
    let on_variant = KvFixture::new(variant, variant_identity, "chat");
    let with_adapter = KvFixture {
        adapter: Some((adapter, adapter_identity("adapter-sql"))),
        ..on_variant
    };
    assert_eq!(
        graph.add_session_kv(with_adapter.spec()),
        Err(GraphError::KvAdapterMismatch)
    );
    // The restore requirement must name the KV's own key.
    let mut other_state = KvFixture::new(base, execution_identity("base-8b"), "chat").spec();
    other_state.restore.requirement.state_identity = id("another state");
    assert!(matches!(
        graph.add_session_kv(other_state),
        Err(GraphError::KvStateMismatch { .. })
    ));
    assert_eq!(graph.len(), count);

    let kv = graph.add_session_kv(on_variant.spec()).unwrap();
    assert_eq!(
        graph.node(kv).unwrap().prerequisites(),
        &BTreeSet::from([variant])
    );
}

#[test]
fn release_takes_every_dependent_and_nothing_held() {
    let Fixture {
        mut graph,
        base,
        adapter,
        pool,
        kv,
        ..
    } = fixture();
    let clock = ManualClock::new(MonotonicTime::from_nanos(1_000));
    let before = graph.clone();
    assert_eq!(graph.dependents(base), BTreeSet::from([adapter, pool, kv]));
    assert_eq!(
        graph.release(&BTreeSet::from([base]), &clock),
        Err(GraphError::DependentStillResident {
            node: base,
            dependent: adapter
        })
    );
    graph.set_hold(kv, lease(2_000)).unwrap();
    let everything = BTreeSet::from([base, adapter, pool, kv]);
    assert_eq!(
        graph.release(&everything, &clock),
        Err(GraphError::Held { node: kv })
    );
    assert_eq!(graph.len(), before.len());

    // The lease expires at 2,000 ns; then the whole closure goes.
    clock.advance(Duration::from_nanos(1_000));
    assert_eq!(
        graph.release(&everything, &clock),
        Ok(16_000 + 50 + 300 + 1_000_000)
    );
    assert!(graph.node(base).is_none());
    assert_eq!(graph.len(), 1);
}

#[test]
fn weights_of_one_identity_are_resident_once() {
    let Fixture {
        mut graph, base, ..
    } = fixture();
    assert_eq!(
        graph.add_base(base_spec("base-8b", 16_000, true)),
        Err(GraphError::DuplicateWeights {
            identity: *execution_identity("base-8b").digest(),
            existing: base
        })
    );
}

#[test]
fn invalid_nodes_are_refused() {
    let mut graph = DependencyGraph::new();
    assert_eq!(
        graph.add_base(base_spec("empty", 0, true)),
        Err(GraphError::ZeroBytes)
    );
    let mut bad_layer = base_spec("bad", 10, true);
    bad_layer.layers.insert(
        "layers.1.o_proj".to_string(),
        LayerShape {
            input_features: 0,
            output_features: 4096,
        },
    );
    assert_eq!(
        graph.add_base(bad_layer),
        Err(GraphError::InvalidLayer {
            layer: "layers.1.o_proj".to_string()
        })
    );
    let mut slow = base_spec("slow", 10, true);
    slow.residency.reload_seconds = f64::NAN;
    assert!(matches!(graph.add_base(slow), Err(GraphError::Input(_))));
    let mut mismatched = base_spec("base-8b", 10, true);
    mismatched.execution = execution(&logical("base-70b"));
    assert_eq!(graph.add_base(mismatched), Err(GraphError::LogicalMismatch));
    let mut no_gpu = base_spec("base-8b", 10, true);
    no_gpu.execution.gpu_architectures.clear();
    assert!(matches!(
        graph.add_base(no_gpu),
        Err(GraphError::Identity(_))
    ));
    assert!(graph.is_empty());

    let base = graph.add_base(base_spec("base-8b", 10, true)).unwrap();
    let impossible = KvFixture {
        state: SessionState::Live {
            resume_probability: 1.5,
        },
        ..KvFixture::new(base, execution_identity("base-8b"), "chat")
    };
    assert!(matches!(
        graph.add_session_kv(impossible.spec()),
        Err(GraphError::Input(_))
    ));
    assert_eq!(
        graph.set_resume_probability(base, 0.5),
        Err(GraphError::NotSessionKv { node: base })
    );
}

#[test]
fn a_session_end_drops_its_lease_but_not_a_pin() {
    let Fixture {
        mut graph,
        base,
        kv,
        ..
    } = fixture();
    graph.set_hold(kv, lease(1_000)).unwrap();
    graph.set_resume_probability(kv, 0.9).unwrap();
    graph.end_session(kv).unwrap();
    assert_eq!(graph.node(kv).unwrap().hold(), Hold::Unheld);
    assert_eq!(
        graph.set_resume_probability(kv, 0.9),
        Err(GraphError::SessionEnded { node: kv })
    );
    graph.set_hold(base, Hold::Pinned).unwrap();
    assert_eq!(
        graph.end_session(base),
        Err(GraphError::NotSessionKv { node: base })
    );
    assert_eq!(graph.node(base).unwrap().hold(), Hold::Pinned);

    let pinned_kv = KvFixture {
        restore: Restore::Transfer,
        ..KvFixture::new(base, execution_identity("base-8b"), "pinned")
    };
    let pinned = graph.add_session_kv(pinned_kv.spec()).unwrap();
    graph.set_hold(pinned, Hold::Pinned).unwrap();
    graph.end_session(pinned).unwrap();
    assert_eq!(graph.node(pinned).unwrap().hold(), Hold::Pinned);
}

#[test]
fn requests_reach_the_retention_policy_prerequisites_first_and_once() {
    let Fixture {
        mut graph,
        base,
        adapter,
        pool,
        kv,
        ..
    } = fixture();
    let mut retention = Recording::default();
    // A request on the session also uses its adapter and base: each counts once, at
    // the new step, prerequisites first.
    assert_eq!(graph.record_request(&[kv, base], &mut retention), Ok(1));
    let used: Vec<(String, ObjectKind, u64)> = retention
        .used
        .iter()
        .map(|(view, step)| (view.key.clone(), view.kind, *step))
        .collect();
    assert_eq!(
        used,
        [
            (base.retention_key(), ObjectKind::BaseWeights, 1),
            (adapter.retention_key(), ObjectKind::Adapter, 1),
            (kv.retention_key(), ObjectKind::SessionKv, 1)
        ]
    );
    assert!(retention
        .used
        .iter()
        .all(|(view, _)| view.protected && !view.evictable));
    // Session KV costs its cheapest exact restore: 1,000 tokens at 10,000 tokens/s.
    assert!(close(retention.used[2].0.reload_seconds, 0.1));

    assert_eq!(graph.record_request(&[pool], &mut retention), Ok(2));
    assert_eq!(
        retention.used[4].0.kind,
        ObjectKind::GraphPool,
        "{:?}",
        retention.used
    );
    let node = graph.node(base).unwrap();
    assert_eq!((node.uses(), node.last_use_step()), (2, 2));
    let node = graph.node(kv).unwrap();
    assert_eq!((node.uses(), node.last_use_step()), (1, 1));
    assert_eq!(graph.step(), 2);
    // Node keys sort as node numbers do, as T08's policies expect.
    assert!(base.retention_key() < pool.retention_key());

    // A request naming a node that is not resident changes nothing.
    let before = graph.clone();
    let calls = retention.used.len();
    assert_eq!(
        graph.record_request(&[kv, NodeId(99)], &mut retention),
        Err(GraphError::UnknownNode { node: NodeId(99) })
    );
    assert_eq!(graph, before);
    assert_eq!(retention.used.len(), calls);
}

#[test]
fn node_kinds_map_to_t08_kinds_one_to_one() {
    let Fixture {
        mut graph,
        base,
        adapter,
        variant,
        pool,
        kv,
    } = fixture();
    let pairs = [
        (NodeKind::Base, ObjectKind::BaseWeights),
        (NodeKind::Adapter, ObjectKind::Adapter),
        (NodeKind::MergedVariant, ObjectKind::MergedVariant),
        (NodeKind::GraphPool, ObjectKind::GraphPool),
        (NodeKind::SessionKv, ObjectKind::SessionKv),
    ];
    for (node, object) in pairs {
        assert_eq!(node.retention_kind(), object);
    }
    let distinct: BTreeSet<ObjectKind> = pairs.iter().map(|(_, object)| *object).collect();
    assert_eq!(distinct.len(), pairs.len());
    // Merged variants and graph pools no longer reach the policies as base weights.
    let mut retention = Recording::default();
    graph
        .record_request(&[variant, pool, kv], &mut retention)
        .unwrap();
    let seen: Vec<(String, ObjectKind)> = retention
        .used
        .iter()
        .map(|(view, _)| (view.key.clone(), view.kind))
        .collect();
    assert_eq!(
        seen,
        [
            (base.retention_key(), ObjectKind::BaseWeights),
            (adapter.retention_key(), ObjectKind::Adapter),
            (variant.retention_key(), ObjectKind::MergedVariant),
            (pool.retention_key(), ObjectKind::GraphPool),
            (kv.retention_key(), ObjectKind::SessionKv),
        ]
    );
}

#[test]
fn copies_are_t08s_and_kv_is_clean_only_while_a_copy_holds_its_state() {
    let Fixture {
        mut graph,
        base,
        adapter,
        pool,
        kv,
        ..
    } = fixture();
    // Weights are immutable content, so always clean.
    let node = graph.node(base).unwrap();
    assert_eq!(
        node.gpu_copy(),
        Some(GpuCopy {
            content: weights_content("base-8b"),
            state: ContentState::Clean,
            bytes: 16_000
        })
    );
    assert_eq!(
        node.data().copies(),
        [copy(CopyTier::LocalStorage, weights_content("base-8b"))]
    );
    // A graph pool is captured again: no content and no copies.
    assert_eq!(graph.node(pool).unwrap().gpu_copy(), None);
    assert_eq!(
        graph.record_copy(pool, copy(CopyTier::PinnedHost, weights_content("base-8b"))),
        Err(GraphError::NoCopies { node: pool })
    );

    // KV computed on the GPU is dirty: no copy holds its state.
    let chat = chat(base, adapter);
    let chat_state = chat.content();
    let kv_copy = |graph: &DependencyGraph| graph.node(kv).unwrap().gpu_copy().unwrap();
    assert_eq!(
        kv_copy(&graph),
        GpuCopy {
            content: chat_state,
            state: ContentState::Dirty,
            bytes: 1_000_000
        }
    );
    // A verified copy of its exact state, in any tier, makes it clean; whether that
    // copy also spares a copy back is T08's tier rule, applied at eviction.
    graph
        .record_copy(kv, copy(CopyTier::ReclaimableHost, chat_state))
        .unwrap();
    assert_eq!(kv_copy(&graph).state, ContentState::Clean);
    // A write makes a new state that no copy holds.
    let next = KvFixture {
        tokens: 1_500,
        bytes: 1_500_000,
        ..chat
    };
    graph.write_kv(kv, grown(&next)).unwrap();
    assert_ne!(next.content(), chat_state);
    assert_eq!(
        kv_copy(&graph),
        GpuCopy {
            content: next.content(),
            state: ContentState::Dirty,
            bytes: 1_500_000
        }
    );
}

#[test]
fn invalid_restore_numbers_are_refused_on_entry() {
    let Fixture {
        mut graph,
        base,
        adapter,
        kv,
        ..
    } = fixture();
    let count = graph.len();
    // Even a recomputation that would be refused (an older epoch) must carry valid
    // numbers.
    let mut spec = KvFixture::new(base, execution_identity("base-8b"), "chat").spec();
    if let Some(recompute) = spec.restore.recompute.as_mut() {
        recompute.authorized_epoch = Some(AuthorizationEpoch::new(0));
        recompute.compute_seconds = f64::NAN;
    }
    assert_eq!(
        graph.add_session_kv(spec),
        Err(GraphError::Input(InputError::NotFinite {
            field: "KvRecompute.compute_seconds"
        }))
    );
    assert_eq!(graph.len(), count);

    let before = graph.node(kv).unwrap().clone();
    let mut write = grown(&KvFixture {
        tokens: 1_500,
        ..chat(base, adapter)
    });
    write.restore.transfer = Some(KvTransfer {
        queue_seconds: -1.0,
        transfer_seconds: 0.0,
    });
    assert_eq!(
        graph.write_kv(kv, write),
        Err(GraphError::Input(InputError::Negative {
            field: "KvTransfer.queue_seconds"
        }))
    );
    assert_eq!(graph.node(kv).unwrap(), &before);
}
