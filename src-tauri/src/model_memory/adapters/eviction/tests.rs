use std::time::Duration;

use super::*;
use crate::foundation::ids::{ContentKey, ManualClock, MonotonicTime};
use crate::model_memory::adapters::fakes::{
    adapter_identity, adapter_reference, base_spec, close, copy, execution_identity, id, justified,
    kv_cache, residency, versioned, weights_content, KvFixture, Recording, Restore, LIMITS,
};
use crate::model_memory::adapters::graph::{GraphPoolSpec, KvWrite};
use crate::model_memory::identity::{Dtype, KvRepresentation, Quantization};
use crate::model_memory::residency::eviction::{Content, ReconstructibleCopy, Verification};
use crate::model_memory::residency::retention::{
    CostPerByte, GreedyDualSize, Lru, MarginalSavedLatency,
};

const GB: u64 = 1_000_000_000;

const POLICY: EvictionPolicy = EvictionPolicy {
    min_resume_probability: 0.5,
    min_restore_seconds: 5.0,
    min_prefix_tokens: 50_000,
    copy_back_tier: Some(CopyTier::LocalStorage),
};

/// No copy back: state without a reconstructible copy stays.
const KEEP: EvictionPolicy = EvictionPolicy {
    copy_back_tier: None,
    ..POLICY
};

const LEASED: HoldReason = HoldReason::Leased {
    lease: LeaseId::new(7),
};

fn clock() -> ManualClock {
    ManualClock::new(MonotonicTime::from_nanos(1_000))
}

/// The engine serving `base-8b` in the fixtures' KV format.
fn engine() -> EngineKvProfile {
    crate::model_memory::adapters::fakes::engine(execution_identity("base-8b"))
}

fn lease(until_nanos: u64) -> Hold {
    Hold::Leased {
        lease: LeaseId::new(7),
        until: MonotonicTime::from_nanos(until_nanos),
    }
}

fn need(bytes: u64) -> EvictionRequest {
    EvictionRequest::bytes(bytes)
}

/// Plans under `policy`, choosing victims by LRU.
fn plan_with(
    graph: &DependencyGraph,
    request: &EvictionRequest,
    clock: &ManualClock,
    policy: &EvictionPolicy,
    engines: &[EngineKvProfile],
) -> EvictionOutcome {
    plan_eviction(graph, request, clock, policy, engines, &mut Lru).unwrap()
}

fn decide(
    graph: &DependencyGraph,
    needed_bytes: u64,
    clock: &ManualClock,
    engines: &[EngineKvProfile],
) -> EvictionOutcome {
    plan_with(graph, &need(needed_bytes), clock, &POLICY, engines)
}

fn released(outcome: EvictionOutcome) -> EvictionPlan {
    match outcome {
        EvictionOutcome::Release(plan) => plan,
        EvictionOutcome::Queue(reason) => panic!("queued: {reason:?}"),
    }
}

fn queued(outcome: EvictionOutcome) -> QueueReason {
    match outcome {
        EvictionOutcome::Queue(reason) => reason,
        EvictionOutcome::Release(plan) => panic!("released: {plan:?}"),
    }
}

fn add_kv(graph: &mut DependencyGraph, fixture: KvFixture) -> NodeId {
    graph.add_session_kv(fixture.spec()).unwrap()
}

fn add_base(graph: &mut DependencyGraph, name: &str, bytes: u64) -> NodeId {
    graph.add_base(base_spec(name, bytes, true)).unwrap()
}

fn add_adapter(graph: &mut DependencyGraph, base: NodeId, name: &str) -> NodeId {
    graph
        .admit_adapter(
            base,
            adapter_reference(name, "base-8b"),
            &LIMITS,
            residency(name, GB / 20, true),
        )
        .unwrap()
}

/// Records `times` requests that use `nodes`.
fn use_often(
    graph: &mut DependencyGraph,
    nodes: &[NodeId],
    times: u32,
    retention: &mut dyn RetentionPolicy,
) {
    for _ in 0..times {
        graph.record_request(nodes, retention).unwrap();
    }
}

/// The write that grows a KV fixture's prefix to `fixture`'s.
fn grown(fixture: &KvFixture) -> KvWrite {
    let spec = fixture.spec();
    KvWrite {
        bytes: fixture.bytes,
        token_prefix: spec.stored.spec.scope.prefix,
        restore: spec.restore,
    }
}

fn rule_1_with<P: RetentionPolicy + Clone>(mut retention: P) {
    let clock = clock();
    let mut graph = DependencyGraph::new();
    let base = add_base(&mut graph, "base-8b", 16 * GB);
    let idle = add_adapter(&mut graph, base, "adapter-idle");
    let busy = add_adapter(&mut graph, base, "adapter-busy");
    use_often(&mut graph, &[base], 500, &mut retention);
    use_often(&mut graph, &[busy], 500, &mut retention);
    let name = retention.name().to_string();

    let plan = released(
        plan_eviction(&graph, &need(GB / 20), &clock, &POLICY, &[], &mut retention).unwrap(),
    );
    assert_eq!(
        plan.actions,
        [EvictionAction::ParkWithoutCopyBack {
            node: idle,
            bytes: GB / 20,
            source: CopyTier::LocalStorage
        }],
        "{name}"
    );
    assert_eq!(graph.release(&plan.nodes(), &clock), Ok(GB / 20), "{name}");
    assert!(graph.node(base).is_some(), "{name}");
    assert!(graph.node(busy).is_some(), "{name}");
}

#[test]
fn rule_1_an_idle_adapter_goes_without_its_frequently_used_base() {
    rule_1_with(Lru);
    rule_1_with(CostPerByte);
    rule_1_with(MarginalSavedLatency::new(8).unwrap());
    rule_1_with(GreedyDualSize::new());
}

#[test]
fn a_base_stays_while_a_held_node_depends_on_it() {
    let clock = clock();
    let mut graph = DependencyGraph::new();
    let base = add_base(&mut graph, "base-8b", 16 * GB);
    let idle = add_adapter(&mut graph, base, "adapter-idle");
    let busy = add_adapter(&mut graph, base, "adapter-busy");
    let session = add_kv(
        &mut graph,
        KvFixture {
            adapter: Some((busy, adapter_identity("adapter-busy"))),
            ..KvFixture::new(base, execution_identity("base-8b"), "chat")
        },
    );
    graph.set_hold(session, lease(10_000)).unwrap();

    let reason = queued(decide(&graph, 17 * GB, &clock, &[engine()]));
    assert_eq!(reason.held.get(&session), Some(&LEASED));
    assert_eq!(
        reason.held.get(&base),
        Some(&HoldReason::DependentHeld { dependent: session })
    );
    assert_eq!(
        reason.held.get(&busy),
        Some(&HoldReason::DependentHeld { dependent: session })
    );
    assert_eq!(reason.held.get(&idle), None);
    assert_eq!(reason.releasable_bytes, GB / 20);
}

#[test]
fn releasing_a_base_takes_its_dependents_first() {
    let clock = clock();
    let mut graph = DependencyGraph::new();
    let base = add_base(&mut graph, "base-8b", 16 * GB);
    let adapter = add_adapter(&mut graph, base, "adapter-sql");
    let pool = graph
        .add_graph_pool(GraphPoolSpec {
            execution_key: id("graphs"),
            bytes: GB / 2,
            recapture_seconds: 1.0,
            prerequisites: BTreeSet::from([base, adapter]),
        })
        .unwrap();
    // Everything is idle; needing more than the adapter and pool frees the base too,
    // after the nodes that depend on it.
    let plan = released(decide(&graph, 16 * GB, &clock, &[]));
    assert_eq!(
        plan.actions,
        [
            EvictionAction::ReleaseGraphPool {
                node: pool,
                bytes: GB / 2
            },
            EvictionAction::ParkWithoutCopyBack {
                node: adapter,
                bytes: GB / 20,
                source: CopyTier::LocalStorage
            },
            EvictionAction::ParkWithoutCopyBack {
                node: base,
                bytes: 16 * GB,
                source: CopyTier::LocalStorage
            },
        ]
    );
    assert_eq!(plan.freed_bytes, 16 * GB + GB / 20 + GB / 2);
    assert_eq!(graph.release(&plan.nodes(), &clock), Ok(plan.freed_bytes));
    assert!(graph.is_empty());
}

#[test]
fn a_graph_pool_never_keeps_its_weights_node_resident_and_goes_with_it() {
    let clock = clock();
    let mut graph = DependencyGraph::new();
    let base = add_base(&mut graph, "base-8b", 16 * GB);
    let pool = graph
        .add_graph_pool(GraphPoolSpec {
            execution_key: id("graphs"),
            bytes: GB / 2,
            recapture_seconds: 1.0,
            prerequisites: BTreeSet::from([base]),
        })
        .unwrap();
    // The policy names the base while its pool is resident: the pool is released with
    // it, first.
    let mut first = First::default();
    let plan =
        released(plan_eviction(&graph, &need(16 * GB), &clock, &POLICY, &[], &mut first).unwrap());
    assert_eq!(
        plan.actions,
        [
            EvictionAction::ReleaseGraphPool {
                node: pool,
                bytes: GB / 2
            },
            EvictionAction::ParkWithoutCopyBack {
                node: base,
                bytes: 16 * GB,
                source: CopyTier::LocalStorage
            },
        ]
    );
    assert_eq!(first.evicted, [pool.retention_key(), base.retention_key()]);
    assert_eq!(plan.freed_bytes, 16 * GB + GB / 2);
    let mut released_graph = graph.clone();
    assert_eq!(
        released_graph.release(&plan.nodes(), &clock),
        Ok(plan.freed_bytes)
    );
    assert!(released_graph.is_empty());

    // A session does keep the base: naming the base is then refused.
    let session = add_kv(
        &mut graph,
        KvFixture::new(base, execution_identity("base-8b"), "chat"),
    );
    assert_eq!(
        plan_eviction(
            &graph,
            &need(16 * GB),
            &clock,
            &POLICY,
            &[],
            &mut First::default()
        ),
        Err(EvictionError::PolicyChoseIneligible {
            policy: "first".to_string(),
            node: Some(base)
        })
    );
    graph.end_session(session).unwrap();
    graph.release(&BTreeSet::from([session]), &clock).unwrap();

    // A pinned pool is an explicit choice, and it holds the node under it.
    graph.set_hold(pool, Hold::Pinned).unwrap();
    let reason = queued(decide(&graph, 1, &clock, &[]));
    assert_eq!(reason.held.get(&pool), Some(&HoldReason::Pinned));
    assert_eq!(
        reason.held.get(&base),
        Some(&HoldReason::DependentHeld { dependent: pool })
    );
}

#[test]
fn rule_2_dead_session_kv_goes_first_while_base_and_graph_stay() {
    let clock = clock();
    let mut graph = DependencyGraph::new();
    let base = add_base(&mut graph, "base-8b", 16 * GB);
    let pool = graph
        .add_graph_pool(GraphPoolSpec {
            execution_key: id("graphs"),
            bytes: GB / 2,
            recapture_seconds: 1.0,
            prerequisites: BTreeSet::from([base]),
        })
        .unwrap();
    let dead = add_kv(
        &mut graph,
        KvFixture {
            bytes: 2 * GB,
            restore: Restore::Lost,
            ..KvFixture::new(base, execution_identity("base-8b"), "finished chat")
        },
    );
    graph.end_session(dead).unwrap();
    let pinned_dead = add_kv(
        &mut graph,
        KvFixture {
            bytes: 2 * GB,
            ..KvFixture::new(base, execution_identity("base-8b"), "kept chat")
        },
    );
    graph.set_hold(pinned_dead, Hold::Pinned).unwrap();
    graph.end_session(pinned_dead).unwrap();
    let live = add_kv(
        &mut graph,
        KvFixture {
            bytes: 2 * GB,
            ..KvFixture::new(base, execution_identity("base-8b"), "open chat")
        },
    );
    use_often(&mut graph, &[base], 100, &mut Lru);
    use_often(&mut graph, &[live, dead], 3, &mut Lru);
    // LRU alone would take the never-used graph pool first; dead KV still goes first,
    // with no copy back and no restore path, because nothing reads it again. A pinned
    // dead session stays pinned.
    let plan = released(decide(&graph, GB, &clock, &[engine()]));
    assert_eq!(
        plan.actions,
        [EvictionAction::DropDeadKv {
            node: dead,
            bytes: 2 * GB
        }]
    );
    assert_eq!(plan.copy_back_bytes, 0);
    graph.release(&plan.nodes(), &clock).unwrap();
    for stays in [base, pool, pinned_dead, live] {
        assert!(graph.node(stays).is_some());
    }
}

/// A pinned base with a costly, long, likely-to-resume session and a short one.
fn rule_3_graph() -> (DependencyGraph, NodeId, NodeId) {
    let mut graph = DependencyGraph::new();
    let base = add_base(&mut graph, "base-8b", 16 * GB);
    graph.set_hold(base, Hold::Pinned).unwrap();
    // 100,000 tokens recompute in 10 s, above the 5 s and 50,000-token thresholds.
    let long = add_kv(
        &mut graph,
        KvFixture {
            tokens: 100_000,
            bytes: 32 * GB,
            state: SessionState::Live {
                resume_probability: 0.9,
            },
            ..KvFixture::new(base, execution_identity("base-8b"), "long contract")
        },
    );
    let short = add_kv(
        &mut graph,
        KvFixture {
            tokens: 1_000,
            bytes: GB,
            state: SessionState::Live {
                resume_probability: 0.9,
            },
            ..KvFixture::new(base, execution_identity("base-8b"), "short chat")
        },
    );
    (graph, long, short)
}

#[test]
fn rule_3_costly_long_prefix_kv_likely_to_resume_is_retained() {
    let clock = clock();
    let (graph, long, short) = rule_3_graph();
    let plan = released(decide(&graph, GB, &clock, &[engine()]));
    assert_eq!(
        plan.actions,
        [EvictionAction::CopyBackThenRelease {
            node: short,
            bytes: GB,
            to: CopyTier::LocalStorage,
            because: NotDroppable::Dirty
        }]
    );
    let reason = queued(decide(&graph, 2 * GB, &clock, &[engine()]));
    assert_eq!(reason.held.get(&long), Some(&HoldReason::LikelyToResume));
    assert_eq!(reason.releasable_bytes, GB);
}

#[test]
fn rule_3_needs_every_condition() {
    let clock = clock();
    let releases = |graph: &DependencyGraph,
                    policy: &EvictionPolicy,
                    engines: &[EngineKvProfile],
                    long: NodeId| {
        let plan = released(plan_with(graph, &need(32 * GB), &clock, policy, engines));
        assert!(plan.nodes().contains(&long), "{plan:?}");
    };

    // No resident engine can use it: an engine with another KV layout, one that does
    // not reuse prefix KV, or none at all.
    let (graph, long, _) = rule_3_graph();
    let other_layout = EngineKvProfile {
        cache: KvRepresentation::new(Dtype::BFloat16, Quantization::None, 32, versioned("paged"))
            .unwrap(),
        ..engine()
    };
    assert_ne!(other_layout.cache, kv_cache());
    let no_reuse = EngineKvProfile {
        reuses_prefix_kv: false,
        ..engine()
    };
    releases(&graph, &POLICY, &[other_layout], long);
    releases(&graph, &POLICY, &[no_reuse], long);
    releases(&graph, &POLICY, &[], long);

    // Unlikely to resume.
    let (mut graph, long, _) = rule_3_graph();
    graph.set_resume_probability(long, 0.2).unwrap();
    releases(&graph, &POLICY, &[engine()], long);

    // Cheap to restore: transferred back in 1.28 s, below 5 s.
    let mut graph = DependencyGraph::new();
    let base = add_base(&mut graph, "base-8b", 16 * GB);
    graph.set_hold(base, Hold::Pinned).unwrap();
    let copied = add_kv(
        &mut graph,
        KvFixture {
            tokens: 100_000,
            bytes: 32 * GB,
            restore: Restore::Transfer,
            state: SessionState::Live {
                resume_probability: 0.9,
            },
            ..KvFixture::new(base, execution_identity("base-8b"), "long contract")
        },
    );
    releases(&graph, &POLICY, &[engine()], copied);

    // A short prefix, even if slow to recompute (4.9999 s against a 1 s threshold).
    let mut graph = DependencyGraph::new();
    let base = add_base(&mut graph, "base-8b", 16 * GB);
    graph.set_hold(base, Hold::Pinned).unwrap();
    let short_but_slow = add_kv(
        &mut graph,
        KvFixture {
            tokens: 49_999,
            bytes: 32 * GB,
            state: SessionState::Live {
                resume_probability: 0.9,
            },
            ..KvFixture::new(base, execution_identity("base-8b"), "almost long")
        },
    );
    let policy = EvictionPolicy {
        min_restore_seconds: 1.0,
        ..POLICY
    };
    releases(&graph, &policy, &[engine()], short_but_slow);
}

#[test]
fn live_kv_without_an_exact_restore_is_required_context() {
    let clock = clock();
    let mut graph = DependencyGraph::new();
    let base = add_base(&mut graph, "base-8b", 16 * GB);
    graph.set_hold(base, Hold::Pinned).unwrap();
    let lost = add_kv(
        &mut graph,
        KvFixture {
            bytes: 4 * GB,
            restore: Restore::Lost,
            state: SessionState::Live {
                resume_probability: 0.0,
            },
            ..KvFixture::new(base, execution_identity("base-8b"), "unsaved chat")
        },
    );
    let reason = queued(decide(&graph, GB, &clock, &[engine()]));
    assert_eq!(reason.held.get(&lost), Some(&HoldReason::RequiredContext));
    assert_eq!(reason.releasable_bytes, 0);
    // Once the session ends, the same KV is dead and goes.
    graph.end_session(lost).unwrap();
    let plan = released(decide(&graph, GB, &clock, &[engine()]));
    assert_eq!(
        plan.actions,
        [EvictionAction::DropDeadKv {
            node: lost,
            bytes: 4 * GB
        }]
    );
}

#[test]
fn live_kv_is_copied_back_or_kept_never_dropped_to_be_recomputed() {
    let clock = clock();
    let mut graph = DependencyGraph::new();
    let base = add_base(&mut graph, "base-8b", 16 * GB);
    graph.set_hold(base, Hold::Pinned).unwrap();
    // An exact, authorized recomputation of 0.1 s exists, and no copy holds the state.
    let fixture = KvFixture::new(base, execution_identity("base-8b"), "chat");
    let kv = add_kv(&mut graph, fixture);
    let plan = released(decide(&graph, 1, &clock, &[]));
    assert_eq!(
        plan.actions,
        [EvictionAction::CopyBackThenRelease {
            node: kv,
            bytes: 1_000_000,
            to: CopyTier::LocalStorage,
            because: NotDroppable::Dirty
        }]
    );
    assert_eq!(plan.copy_back_bytes, 1_000_000);
    // Without a copy back it stays.
    let reason = queued(plan_with(&graph, &need(1), &clock, &KEEP, &[]));
    assert_eq!(
        reason.held.get(&kv),
        Some(&HoldReason::CannotCopyBack {
            because: NotDroppable::Dirty
        })
    );

    // A verified copy of this exact state in pinned host RAM lets it go without one.
    graph
        .record_copy(kv, copy(CopyTier::PinnedHost, fixture.content()))
        .unwrap();
    let plan = released(plan_with(&graph, &need(1), &clock, &KEEP, &[]));
    assert_eq!(
        plan.actions,
        [EvictionAction::ParkWithoutCopyBack {
            node: kv,
            bytes: 1_000_000,
            source: CopyTier::PinnedHost
        }]
    );
    assert_eq!(plan.copy_back_bytes, 0);

    // A write makes a new state, which that copy does not hold.
    let next = KvFixture {
        tokens: 1_500,
        bytes: 1_500_000,
        ..fixture
    };
    graph.write_kv(kv, grown(&next)).unwrap();
    let reason = queued(plan_with(&graph, &need(1), &clock, &KEEP, &[]));
    assert_eq!(
        reason.held.get(&kv),
        Some(&HoldReason::CannotCopyBack {
            because: NotDroppable::Dirty
        })
    );
    graph
        .record_copy(kv, copy(CopyTier::LocalStorage, next.content()))
        .unwrap();
    let plan = released(plan_with(&graph, &need(1), &clock, &KEEP, &[]));
    assert_eq!(
        plan.actions,
        [EvictionAction::ParkWithoutCopyBack {
            node: kv,
            bytes: 1_500_000,
            source: CopyTier::LocalStorage
        }]
    );
}

/// The one release of live, dirty-by-default KV whose copies `copies` makes from the
/// KV's own state.
fn kv_release(copies: impl FnOnce(Content) -> Vec<ReconstructibleCopy>) -> EvictionAction {
    let clock = clock();
    let mut graph = DependencyGraph::new();
    let base = add_base(&mut graph, "base-8b", 16 * GB);
    graph.set_hold(base, Hold::Pinned).unwrap();
    let fixture = KvFixture::new(base, execution_identity("base-8b"), "chat");
    let mut spec = fixture.spec();
    spec.copies = copies(fixture.content());
    graph.add_session_kv(spec).unwrap();
    let plan = released(decide(&graph, 1, &clock, &[]));
    match plan.actions.as_slice() {
        [action] => *action,
        _ => panic!("one release expected: {plan:?}"),
    }
}

#[test]
fn only_pinned_host_or_local_copies_of_the_exact_kv_state_spare_a_copy_back() {
    for tier in [
        CopyTier::ReclaimableHost,
        CopyTier::AuthorizedPeer,
        CopyTier::RemoteSource,
    ] {
        assert!(matches!(
            kv_release(|state| vec![copy(tier, state)]),
            EvictionAction::CopyBackThenRelease {
                because: NotDroppable::NoVerifiedCopy,
                ..
            }
        ));
    }
    // An unverified copy, or a verified copy of other content, holds nothing of this
    // state.
    let unverified = ReconstructibleCopy {
        tier: CopyTier::PinnedHost,
        verification: Verification::Unverified,
    };
    for action in [
        kv_release(|_| vec![unverified]),
        kv_release(|_| vec![copy(CopyTier::PinnedHost, weights_content("base-8b"))]),
    ] {
        assert!(matches!(
            action,
            EvictionAction::CopyBackThenRelease {
                because: NotDroppable::Dirty,
                ..
            }
        ));
    }
    for tier in [CopyTier::PinnedHost, CopyTier::LocalStorage] {
        assert!(matches!(
            kv_release(|state| vec![copy(tier, state)]),
            EvictionAction::ParkWithoutCopyBack { source, .. } if source == tier
        ));
    }
}

#[test]
fn rule_4_clean_weights_park_without_copy_back_only_against_a_canonical_copy() {
    let clock = clock();
    let mut graph = DependencyGraph::new();
    let mut base_with = |name: &str, bytes: u64, copies: Vec<ReconstructibleCopy>| {
        let mut spec = base_spec(name, bytes, false);
        spec.residency.copies = copies;
        graph.add_base(spec).unwrap()
    };
    let verified = |tier: CopyTier, name: &str| vec![copy(tier, weights_content(name))];
    let pinned = base_with("pinned", GB, verified(CopyTier::PinnedHost, "pinned"));
    let local = base_with("local", 2 * GB, verified(CopyTier::LocalStorage, "local"));
    let reclaimable = base_with(
        "reclaimable",
        GB,
        verified(CopyTier::ReclaimableHost, "reclaimable"),
    );
    let peer = base_with("peer", GB, verified(CopyTier::AuthorizedPeer, "peer"));
    let remote = base_with("remote", GB, verified(CopyTier::RemoteSource, "remote"));
    let unverified = base_with(
        "unverified",
        GB,
        vec![ReconstructibleCopy {
            tier: CopyTier::LocalStorage,
            verification: Verification::Unverified,
        }],
    );
    let stale = base_with(
        "stale",
        GB,
        verified(CopyTier::LocalStorage, "an older processed format"),
    );
    let absent = base_with("absent", GB, Vec::new());

    // Everything is idle, so LRU goes in node order.
    let plan = released(decide(&graph, 9 * GB, &clock, &[]));
    let park = |node, bytes, source| EvictionAction::ParkWithoutCopyBack {
        node,
        bytes,
        source,
    };
    let copy_back = |node| EvictionAction::CopyBackThenRelease {
        node,
        bytes: GB,
        to: CopyTier::LocalStorage,
        because: NotDroppable::NoVerifiedCopy,
    };
    assert_eq!(
        plan.actions,
        [
            park(pinned, GB, CopyTier::PinnedHost),
            park(local, 2 * GB, CopyTier::LocalStorage),
            copy_back(reclaimable),
            copy_back(peer),
            copy_back(remote),
            copy_back(unverified),
            copy_back(stale),
            copy_back(absent),
        ]
    );
    assert_eq!(plan.freed_bytes, 9 * GB);
    assert_eq!(plan.copy_back_bytes, 6 * GB);

    // Without a copy back, only the two with a canonical copy can go.
    let reason = queued(plan_with(&graph, &need(9 * GB), &clock, &KEEP, &[]));
    assert_eq!(reason.releasable_bytes, 3 * GB);
    for kept in [reclaimable, peer, remote, unverified, stale, absent] {
        assert_eq!(
            reason.held.get(&kept),
            Some(&HoldReason::CannotCopyBack {
                because: NotDroppable::NoVerifiedCopy
            })
        );
    }
}

#[test]
fn a_merged_variant_is_copied_back_until_a_copy_of_its_own_bytes_exists() {
    let clock = clock();
    let mut graph = DependencyGraph::new();
    let base = add_base(&mut graph, "base-8b", 16 * GB);
    let adapter = add_adapter(&mut graph, base, "adapter-sql");
    let merged = ContentKey::of(b"base-8b + adapter-sql, merged");
    let variant = graph
        .materialize_merged(
            base,
            adapter,
            versioned("merge-procedure"),
            merged,
            justified("base-8b", "adapter-sql", 16 * GB),
        )
        .unwrap();
    graph.set_hold(base, Hold::Pinned).unwrap();
    graph.set_hold(adapter, Hold::Pinned).unwrap();
    // The base and adapter it was merged from have copies; the variant's bytes do not.
    let plan = released(decide(&graph, GB, &clock, &[]));
    assert_eq!(
        plan.actions,
        [EvictionAction::CopyBackThenRelease {
            node: variant,
            bytes: 16 * GB,
            to: CopyTier::LocalStorage,
            because: NotDroppable::NoVerifiedCopy
        }]
    );
    graph
        .record_copy(
            variant,
            copy(CopyTier::LocalStorage, Content::Immutable(merged)),
        )
        .unwrap();
    let plan = released(decide(&graph, GB, &clock, &[]));
    assert_eq!(
        plan.actions,
        [EvictionAction::ParkWithoutCopyBack {
            node: variant,
            bytes: 16 * GB,
            source: CopyTier::LocalStorage
        }]
    );
}

#[test]
fn a_copy_back_must_land_where_it_stays_available() {
    let clock = clock();
    let mut graph = DependencyGraph::new();
    let node = graph.add_base(base_spec("base-8b", GB, false)).unwrap();
    for tier in [
        CopyTier::ReclaimableHost,
        CopyTier::AuthorizedPeer,
        CopyTier::RemoteSource,
    ] {
        let policy = EvictionPolicy {
            copy_back_tier: Some(tier),
            ..POLICY
        };
        assert_eq!(
            plan_eviction(&graph, &need(GB), &clock, &policy, &[], &mut Lru),
            Err(EvictionError::CopyBackTierNotGuaranteed { tier })
        );
    }
    let pinned = EvictionPolicy {
        copy_back_tier: Some(CopyTier::PinnedHost),
        ..POLICY
    };
    let plan = released(plan_with(&graph, &need(GB), &clock, &pinned, &[]));
    assert_eq!(
        plan.actions,
        [EvictionAction::CopyBackThenRelease {
            node,
            bytes: GB,
            to: CopyTier::PinnedHost,
            because: NotDroppable::NoVerifiedCopy
        }]
    );
}

#[test]
fn rule_5_queue_rather_than_loop_when_everything_is_leased_or_pinned() {
    let clock = clock();
    let mut retention = GreedyDualSize::new();
    let mut graph = DependencyGraph::new();
    let base = add_base(&mut graph, "base-8b", 16 * GB);
    graph.set_hold(base, Hold::Pinned).unwrap();
    let session = add_kv(
        &mut graph,
        KvFixture::new(base, execution_identity("base-8b"), "chat"),
    );
    graph.set_hold(session, lease(5_000)).unwrap();
    graph.record_request(&[session], &mut retention).unwrap();
    let graph_before = graph.clone();
    let retention_before = retention.clone();
    let mut plan = |needed_bytes| {
        plan_eviction(
            &graph,
            &need(needed_bytes),
            &clock,
            &POLICY,
            &[engine()],
            &mut retention,
        )
        .unwrap()
    };

    let first = queued(plan(1));
    assert_eq!(
        first,
        QueueReason {
            needed_bytes: 1,
            releasable_bytes: 0,
            held: BTreeMap::from([(base, HoldReason::Pinned), (session, LEASED)]),
        }
    );
    // Asking again gives the same answer and changes nothing.
    assert_eq!(queued(plan(1)), first);

    // A partial release is never started: 1 MB is releasable once the lease lapses,
    // but 2 MB are needed.
    clock.advance(Duration::from_nanos(4_000));
    assert_eq!(queued(plan(2_000_000)).releasable_bytes, 1_000_000);
    let release = released(plan(1_000_000));
    assert_eq!(
        release.actions,
        [EvictionAction::CopyBackThenRelease {
            node: session,
            bytes: 1_000_000,
            to: CopyTier::LocalStorage,
            because: NotDroppable::Dirty
        }]
    );
    assert_eq!(graph, graph_before);
    // Only the release plan advanced the policy: the session left it.
    assert_eq!(retention_before.credit(&session.retention_key()), Some(0.1));
    assert_eq!(retention.credit(&session.retention_key()), None);
    assert_eq!(
        retention.credit(&base.retention_key()),
        retention_before.credit(&base.retention_key())
    );
}

#[test]
fn the_retention_policy_advances_only_with_a_plan() {
    const GIB: u64 = 1 << 30;
    let clock = clock();
    let mut retention = GreedyDualSize::new();
    let mut graph = DependencyGraph::new();
    let a = add_base(&mut graph, "base-a", GIB);
    let b = add_base(&mut graph, "base-b", GIB);
    graph.record_request(&[a], &mut retention).unwrap();
    graph.record_request(&[b], &mut retention).unwrap();
    assert_eq!(retention.credit(&a.retention_key()), Some(2.0));
    let before = retention.clone();
    let queue = plan_eviction(&graph, &need(3 * GIB), &clock, &POLICY, &[], &mut retention);
    assert!(matches!(queue, Ok(EvictionOutcome::Queue(_))));
    assert_eq!(retention, before);

    // Equal credit per byte, so the older use goes; every unprotected resident pays
    // rent of 2 s per GiB once, and the victim leaves the policy.
    let plan =
        released(plan_eviction(&graph, &need(GIB), &clock, &POLICY, &[], &mut retention).unwrap());
    assert_eq!(plan.nodes(), BTreeSet::from([a]));
    assert_eq!(retention.credit(&a.retention_key()), None);
    assert_eq!(retention.credit(&b.retention_key()), Some(0.0));
}

#[test]
fn the_policy_sees_every_resident_once_with_its_own_bytes() {
    let clock = clock();
    let mut retention = Recording::default();
    let mut graph = DependencyGraph::new();
    let base = add_base(&mut graph, "base-8b", 16 * GB);
    let other = add_base(&mut graph, "base-3b", 4 * GB);
    graph.set_hold(other, Hold::Pinned).unwrap();
    let session = add_kv(
        &mut graph,
        KvFixture {
            tokens: 20_000,
            bytes: GB,
            ..KvFixture::new(base, execution_identity("base-8b"), "chat")
        },
    );
    graph.record_request(&[session], &mut retention).unwrap();
    let plan =
        released(plan_eviction(&graph, &need(1), &clock, &POLICY, &[], &mut retention).unwrap());
    assert_eq!(plan.nodes(), BTreeSet::from([session]));

    // One choice over every resident in key order. The base is charged its own 16 GB
    // once, not again inside the session (line 304), and is no victim while the
    // session depends on it; the pinned base is protected.
    let [views] = retention.offered.as_slice() else {
        panic!("one choice expected: {:?}", retention.offered);
    };
    let keys: Vec<String> = views.iter().map(|view| view.key.clone()).collect();
    assert_eq!(
        keys,
        [
            base.retention_key(),
            other.retention_key(),
            session.retention_key()
        ]
    );
    assert_eq!(
        (views[0].bytes, views[0].protected, views[0].evictable),
        (16 * GB, false, false)
    );
    assert_eq!(
        (views[1].bytes, views[1].protected, views[1].evictable),
        (4 * GB, true, false)
    );
    assert_eq!(
        (views[2].bytes, views[2].protected, views[2].evictable),
        (GB, false, true)
    );
    // The session's cost is its cheapest exact restore: 20,000 tokens at 10,000
    // tokens/s; the base's is its 2 s reload.
    assert!(close(views[2].reload_seconds, 2.0));
    assert!(close(views[0].reload_seconds, 2.0));
    assert_eq!((views[2].use_count, views[2].last_use_step), (1, 1));
    assert_eq!(retention.evicted, [session.retention_key()]);
}

#[test]
fn nodes_the_waiting_request_uses_are_never_released_for_it() {
    let clock = clock();
    let mut graph = DependencyGraph::new();
    let base = add_base(&mut graph, "base-8b", 16 * GB);
    let adapter = add_adapter(&mut graph, base, "adapter-sql");
    let other = add_base(&mut graph, "base-3b", 4 * GB);
    // Told nothing, LRU takes the adapter and then its base.
    let blind = released(decide(&graph, 4 * GB, &clock, &[]));
    assert_eq!(blind.nodes(), BTreeSet::from([base, adapter]));

    let request = EvictionRequest {
        needed_bytes: 4 * GB,
        uses: BTreeSet::from([adapter]),
    };
    let plan = released(plan_with(&graph, &request, &clock, &POLICY, &[]));
    assert_eq!(
        plan.actions,
        [EvictionAction::ParkWithoutCopyBack {
            node: other,
            bytes: 4 * GB,
            source: CopyTier::LocalStorage
        }]
    );
    let more = EvictionRequest {
        needed_bytes: 5 * GB,
        ..request
    };
    assert_eq!(
        queued(plan_with(&graph, &more, &clock, &POLICY, &[])).held,
        BTreeMap::from([
            (base, HoldReason::DependentHeld { dependent: adapter }),
            (adapter, HoldReason::UsedByRequest),
        ])
    );

    // A node the request uses must be resident.
    graph.release(&BTreeSet::from([other]), &clock).unwrap();
    let gone = EvictionRequest {
        needed_bytes: 1,
        uses: BTreeSet::from([other]),
    };
    assert_eq!(
        plan_eviction(&graph, &gone, &clock, &POLICY, &[], &mut Lru),
        Err(EvictionError::UnknownNode { node: other })
    );
}

/// Always names the first resident.
#[derive(Clone, Debug, Default, PartialEq)]
struct First {
    evicted: Vec<String>,
}

impl RetentionPolicy for First {
    fn name(&self) -> &str {
        "first"
    }

    fn on_use(&mut self, _object: &ObjectView<'_>, _step: u64) {}

    fn on_evict(&mut self, key: &str) {
        self.evicted.push(key.to_string());
    }

    fn choose_victim(&mut self, _residents: &[ObjectView<'_>], _step: u64) -> Option<usize> {
        Some(0)
    }
}

/// Always gives the same answer.
#[derive(Clone, Debug, PartialEq)]
struct Fixed(Option<usize>);

impl RetentionPolicy for Fixed {
    fn name(&self) -> &str {
        "fixed"
    }

    fn on_use(&mut self, _object: &ObjectView<'_>, _step: u64) {}

    fn on_evict(&mut self, _key: &str) {}

    fn choose_victim(&mut self, _residents: &[ObjectView<'_>], _step: u64) -> Option<usize> {
        self.0
    }
}

#[test]
fn a_policy_cannot_take_what_it_may_not_and_a_refusal_changes_nothing() {
    let clock = clock();
    let mut graph = DependencyGraph::new();
    let base = add_base(&mut graph, "base-8b", 16 * GB);
    add_adapter(&mut graph, base, "adapter-sql");
    let dead = add_kv(
        &mut graph,
        KvFixture::new(base, execution_identity("base-8b"), "finished chat"),
    );
    graph.end_session(dead).unwrap();
    // Dead KV goes first; the next victim the policy names is the base, which the
    // adapter still depends on.
    let mut first = First::default();
    assert_eq!(
        plan_eviction(&graph, &need(GB), &clock, &POLICY, &[], &mut first),
        Err(EvictionError::PolicyChoseIneligible {
            policy: "first".to_string(),
            node: Some(base)
        })
    );
    assert_eq!(first, First::default());
    assert_eq!(
        plan_eviction(&graph, &need(GB), &clock, &POLICY, &[], &mut Fixed(None)),
        Err(EvictionError::PolicyChoseNothing {
            policy: "fixed".to_string()
        })
    );
    assert_eq!(
        plan_eviction(
            &graph,
            &need(GB),
            &clock,
            &POLICY,
            &[],
            &mut Fixed(Some(99))
        ),
        Err(EvictionError::PolicyChoseIneligible {
            policy: "fixed".to_string(),
            node: None
        })
    );
    // When dead KV alone suffices, the policy is not asked.
    let plan =
        released(plan_eviction(&graph, &need(1), &clock, &POLICY, &[], &mut Fixed(None)).unwrap());
    assert_eq!(plan.nodes(), BTreeSet::from([dead]));
}

#[test]
fn nothing_needed_releases_nothing_and_bad_policies_are_refused() {
    let clock = clock();
    let mut graph = DependencyGraph::new();
    add_base(&mut graph, "base-8b", GB);
    let mut retention = Recording::default();
    assert_eq!(
        released(plan_eviction(&graph, &need(0), &clock, &POLICY, &[], &mut retention).unwrap()),
        EvictionPlan {
            actions: Vec::new(),
            freed_bytes: 0,
            copy_back_bytes: 0
        }
    );
    assert!(retention.offered.is_empty());
    for (policy, error) in [
        (
            EvictionPolicy {
                min_resume_probability: 1.5,
                ..POLICY
            },
            InputError::OutOfRange {
                field: "EvictionPolicy.min_resume_probability",
            },
        ),
        (
            EvictionPolicy {
                min_restore_seconds: f64::NAN,
                ..POLICY
            },
            InputError::NotFinite {
                field: "EvictionPolicy.min_restore_seconds",
            },
        ),
    ] {
        assert_eq!(
            plan_eviction(&graph, &need(1), &clock, &policy, &[], &mut Lru),
            Err(EvictionError::Input(error))
        );
    }
}

#[test]
fn refusals_explain_themselves() {
    let message = EvictionError::CopyBackTierNotGuaranteed {
        tier: CopyTier::ReclaimableHost,
    }
    .to_string();
    assert!(message.contains("ReclaimableHost") && message.contains("reconstructible"));
    assert!(EvictionError::PolicyChoseNothing {
        policy: "lru".to_string()
    }
    .to_string()
    .contains("lru"));
}
