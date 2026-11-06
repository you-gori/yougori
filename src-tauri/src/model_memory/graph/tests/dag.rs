//! GPU §2.3: the request DAG refuses cycles, unknown references, duplicates, unusable
//! completion events, cross-scope consumption without an allowance, and objectives that
//! are missing, ambiguous or computed from nothing.

use std::time::Duration;

use crate::foundation::ids::ExecutionCategory;

use super::super::dag::{GraphBuilder, Policy};
use super::super::node::{
    CancellationBoundary, CompletionEvent, DemandProfile, DemandSegment, DurationEstimate,
    NodeKind, NodeSpec, ResourceUnit,
};
use super::super::{GraphError, NodeId, ResourceId, TrustScope, MAX_NAME_LEN};
use super::support::{example, first_token, id, identity, ms, node, resource, scope};

fn chain() -> GraphBuilder {
    GraphBuilder::new()
        .node(node("weights", NodeKind::ArtifactExtent, 4))
        .node(node("prefill", NodeKind::Compute, 2))
        .node(first_token("respond", 1))
        .edge(&id("weights"), &id("prefill"))
        .edge(&id("prefill"), &id("respond"))
}

#[test]
fn names_are_checked() {
    assert_eq!(
        NodeId::new("layer-0.extent:3").unwrap().as_str(),
        "layer-0.extent:3"
    );
    assert!(matches!(
        NodeId::new(""),
        Err(GraphError::InvalidName {
            field: "NodeId",
            ..
        })
    ));
    assert!(NodeId::new("x".repeat(MAX_NAME_LEN)).is_ok());
    assert!(NodeId::new("x".repeat(MAX_NAME_LEN + 1)).is_err());
    // Resources follow the shared identifier rule of ids.rs.
    assert!(ResourceId::new("gpu0.vram").is_ok());
    assert!(ResourceId::new("pcie root").is_err());
    assert!(ResourceId::new("-pcie").is_err());
}

#[test]
fn scopes_are_equal_only_when_category_and_domain_both_are() {
    let sandbox = TrustScope::named(ExecutionCategory::VmSandbox, "tenant-a");
    let gpu_runtime = TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, "tenant-a");
    assert_ne!(sandbox, gpu_runtime);
    assert_eq!(sandbox.domain, gpu_runtime.domain);

    // The same tenant name in a labelled runtime is another scope.
    let layout = NodeSpec::new(
        id("layout"),
        NodeKind::RankLayout,
        identity("layout"),
        gpu_runtime,
        DurationEstimate::exact(ms(2)).unwrap(),
        CompletionEvent::LayoutPublished,
    );
    let across = || {
        GraphBuilder::new()
            .node(node("weights", NodeKind::ArtifactExtent, 4))
            .node(layout.clone())
            .node(NodeSpec::new(
                id("prefill"),
                NodeKind::Compute,
                identity("prefill"),
                gpu_runtime,
                DurationEstimate::exact(ms(2)).unwrap(),
                CompletionEvent::ComputeCompleted,
            ))
            .node(first_token("respond", 1))
            .edge(&id("weights"), &id("layout"))
            .edge(&id("layout"), &id("prefill"))
            .edge(&id("prefill"), &id("respond"))
    };
    let refused = across().build(Policy::new()).unwrap_err();
    assert_eq!(
        refused,
        GraphError::CrossScopeConsumption {
            producer: id("weights"),
            consumer: id("layout"),
            producer_scope: sandbox,
            consumer_scope: gpu_runtime,
        }
    );
    assert!(refused.to_string().contains("VM sandbox"));
    assert!(refused.to_string().contains("not a sandbox"));
    let allowed = Policy::new()
        .allow(sandbox, gpu_runtime, identity("weights"))
        .allow(gpu_runtime, sandbox, identity("prefill"));
    assert!(across().build(allowed).is_ok());
}

#[test]
fn a_valid_graph_keeps_its_structure() {
    let graph = example(false).build(Policy::new()).unwrap();
    assert_eq!(graph.len(), 8);
    assert!(!graph.is_empty());
    assert_eq!(graph.objective(), &id("respond"));
    assert_eq!(
        graph.predecessors(&id("prefill")).unwrap(),
        vec![&id("tok"), &id("layout"), &id("adapter")]
    );
    assert_eq!(graph.predecessors(&id("nothing")), None);
    let order: Vec<&str> = graph
        .topological_order()
        .iter()
        .map(|n| n.as_str())
        .collect();
    assert_eq!(
        order,
        ["tok", "ext1", "ext2", "init", "layout", "adapter", "prefill", "respond"]
    );
    assert!(graph.node(&id("ext2")).is_some());
}

#[test]
fn a_cycle_is_refused_and_named() {
    let refused = GraphBuilder::new()
        .node(node("a", NodeKind::ArtifactExtent, 1))
        .node(node("b", NodeKind::RankLayout, 1))
        .node(node("c", NodeKind::Compute, 1))
        .node(first_token("respond", 1))
        .edge(&id("a"), &id("b"))
        .edge(&id("b"), &id("c"))
        .edge(&id("c"), &id("a"))
        .edge(&id("c"), &id("respond"))
        .build(Policy::new());
    assert_eq!(
        refused.unwrap_err(),
        GraphError::Cycle {
            nodes: vec![id("a"), id("b"), id("c")]
        }
    );
    let self_loop = chain()
        .edge(&id("prefill"), &id("prefill"))
        .build(Policy::new());
    assert_eq!(
        self_loop.unwrap_err(),
        GraphError::Cycle {
            nodes: vec![id("prefill")]
        }
    );
}

#[test]
fn unknown_references_and_duplicates_are_refused() {
    assert_eq!(
        chain()
            .edge(&id("ghost"), &id("prefill"))
            .build(Policy::new())
            .unwrap_err(),
        GraphError::UnknownNode { node: id("ghost") }
    );
    assert_eq!(
        chain()
            .node(node("weights", NodeKind::KvBlock, 1))
            .build(Policy::new())
            .unwrap_err(),
        GraphError::DuplicateNodeId {
            node: id("weights")
        }
    );
    assert_eq!(
        chain()
            .edge(&id("weights"), &id("prefill"))
            .build(Policy::new())
            .unwrap_err(),
        GraphError::DuplicateEdge {
            from: id("weights"),
            to: id("prefill")
        }
    );
    assert_eq!(
        GraphBuilder::new().build(Policy::new()).unwrap_err(),
        GraphError::Empty
    );
}

#[test]
fn the_same_state_twice_is_refused_but_another_scope_is_other_state() {
    let twin = NodeSpec::new(
        id("weights-again"),
        NodeKind::ArtifactExtent,
        identity("weights"),
        scope("tenant-a"),
        DurationEstimate::exact(ms(4)).unwrap(),
        CompletionEvent::ExtentVerified,
    );
    assert_eq!(
        chain().node(twin.clone()).build(Policy::new()).unwrap_err(),
        GraphError::DuplicateState {
            first: id("weights"),
            second: id("weights-again")
        }
    );
    let elsewhere = NodeSpec::new(
        id("weights-b"),
        NodeKind::ArtifactExtent,
        identity("weights"),
        scope("tenant-b"),
        DurationEstimate::exact(ms(4)).unwrap(),
        CompletionEvent::ExtentVerified,
    );
    assert!(chain().node(elsewhere).build(Policy::new()).is_ok());
}

#[test]
fn a_completion_event_must_establish_usability_for_its_kind() {
    let arrived_only = NodeSpec::new(
        id("ext"),
        NodeKind::ArtifactExtent,
        identity("ext"),
        scope("tenant-a"),
        DurationEstimate::exact(ms(1)).unwrap(),
        CompletionEvent::ComputeCompleted,
    );
    assert_eq!(
        chain().node(arrived_only).build(Policy::new()).unwrap_err(),
        GraphError::CompletionEventMismatch {
            node: id("ext"),
            kind: NodeKind::ArtifactExtent,
            event: CompletionEvent::ComputeCompleted
        }
    );
}

/// `layout` in tenant-b consumes `weights` from tenant-a.
fn cross_scope() -> GraphBuilder {
    let layout = NodeSpec::new(
        id("layout"),
        NodeKind::RankLayout,
        identity("layout"),
        scope("tenant-b"),
        DurationEstimate::exact(ms(2)).unwrap(),
        CompletionEvent::LayoutPublished,
    );
    GraphBuilder::new()
        .node(node("weights", NodeKind::ArtifactExtent, 4))
        .node(layout)
        .node(node("prefill", NodeKind::Compute, 2))
        .node(first_token("respond", 1))
        .edge(&id("weights"), &id("layout"))
        .edge(&id("layout"), &id("prefill"))
        .edge(&id("prefill"), &id("respond"))
}

#[test]
fn a_node_never_consumes_another_trust_scope_without_an_allowance() {
    let violation = GraphError::CrossScopeConsumption {
        producer: id("weights"),
        consumer: id("layout"),
        producer_scope: scope("tenant-a"),
        consumer_scope: scope("tenant-b"),
    };
    assert_eq!(cross_scope().build(Policy::new()).unwrap_err(), violation);

    // An allowance for other state, or for the opposite direction, does not count.
    let other_state = Policy::new().allow(scope("tenant-a"), scope("tenant-b"), identity("other"));
    assert_eq!(cross_scope().build(other_state).unwrap_err(), violation);
    let reversed = Policy::new().allow(scope("tenant-b"), scope("tenant-a"), identity("weights"));
    assert!(matches!(
        cross_scope().build(reversed).unwrap_err(),
        GraphError::CrossScopeConsumption { .. }
    ));

    // The layout's own consumer is back in tenant-a, so it needs its own allowance too.
    let weights_only =
        Policy::new().allow(scope("tenant-a"), scope("tenant-b"), identity("weights"));
    assert_eq!(
        cross_scope().build(weights_only.clone()).unwrap_err(),
        GraphError::CrossScopeConsumption {
            producer: id("layout"),
            consumer: id("prefill"),
            producer_scope: scope("tenant-b"),
            consumer_scope: scope("tenant-a"),
        }
    );
    let both = weights_only.allow(scope("tenant-b"), scope("tenant-a"), identity("layout"));
    assert!(cross_scope().build(both).is_ok());
}

#[test]
fn exactly_one_node_delivers_the_first_token_and_it_needs_compute() {
    let no_objective = GraphBuilder::new()
        .node(node("prefill", NodeKind::Compute, 2))
        .node(node("respond", NodeKind::NetworkResponse, 1))
        .edge(&id("prefill"), &id("respond"));
    assert_eq!(
        no_objective.build(Policy::new()).unwrap_err(),
        GraphError::NoObjective
    );

    let two = chain()
        .node(first_token("respond-2", 1))
        .edge(&id("prefill"), &id("respond-2"));
    assert_eq!(
        two.build(Policy::new()).unwrap_err(),
        GraphError::AmbiguousObjective {
            first: id("respond"),
            second: id("respond-2")
        }
    );

    // Ready weights do not eliminate prompt computation (§1.1).
    let without_compute = GraphBuilder::new()
        .node(node("weights", NodeKind::ArtifactExtent, 4))
        .node(node("prefill", NodeKind::Compute, 2))
        .node(first_token("respond", 1))
        .edge(&id("weights"), &id("respond"));
    assert_eq!(
        without_compute.build(Policy::new()).unwrap_err(),
        GraphError::ObjectiveWithoutCompute {
            objective: id("respond")
        }
    );
}

#[test]
fn work_off_the_first_token_path_is_known() {
    let graph = chain()
        .node(node("decode-graph", NodeKind::GraphCapture, 9))
        .node(node("later", NodeKind::NetworkResponse, 1))
        .edge(&id("weights"), &id("decode-graph"))
        .edge(&id("decode-graph"), &id("later"))
        .edge(&id("respond"), &id("later"))
        .build(Policy::new())
        .unwrap();
    for on in ["weights", "prefill", "respond"] {
        assert!(graph.on_objective_path(&id(on)), "{on}");
    }
    for off in ["decode-graph", "later", "unknown"] {
        assert!(!graph.on_objective_path(&id(off)), "{off}");
    }
}

#[test]
fn demand_must_lie_within_the_expected_duration() {
    let late =
        DemandSegment::transient(resource("vram"), ResourceUnit::Bytes, 1, ms(1), ms(5)).unwrap();
    let spec = node("ext", NodeKind::ArtifactExtent, 4).with_demand(DemandProfile::new(vec![late]));
    assert_eq!(
        chain().node(spec).build(Policy::new()).unwrap_err(),
        GraphError::DemandOutsideDuration { node: id("ext") }
    );
}

#[test]
fn the_policy_limits_non_preemptible_stretches_at_the_high_duration() {
    let limit = Policy::new().with_max_non_preemptible(ms(10));
    // weights (4 ms), prefill (2 ms) and respond (1 ms) all fit under 10 ms.
    assert!(chain().build(limit.clone()).is_ok());

    let whole = node("load", NodeKind::ArtifactExtent, 40);
    assert_eq!(
        chain()
            .node(whole.clone())
            .build(limit.clone())
            .unwrap_err(),
        GraphError::NonPreemptibleTooLong {
            node: id("load"),
            non_preemptible: ms(40),
            limit: ms(10)
        }
    );
    let batched = whole.with_cancellation(CancellationBoundary::Boundaries {
        max_interval: ms(4),
    });
    assert!(chain().node(batched).build(limit.clone()).is_ok());

    let uncertain = NodeSpec::new(
        id("uncertain"),
        NodeKind::KvBlock,
        identity("uncertain"),
        scope("tenant-a"),
        DurationEstimate::new(ms(5), ms(8), ms(15)).unwrap(),
        CompletionEvent::KvBlockPublished,
    )
    .with_cancellation(CancellationBoundary::Boundaries {
        max_interval: ms(12),
    });
    assert_eq!(
        chain().node(uncertain).build(limit).unwrap_err(),
        GraphError::NonPreemptibleTooLong {
            node: id("uncertain"),
            non_preemptible: ms(12),
            limit: ms(10)
        }
    );
    assert_eq!(
        CancellationBoundary::Anytime.non_preemptible(Duration::MAX),
        Duration::ZERO
    );
}
