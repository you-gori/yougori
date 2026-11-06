use std::collections::BTreeSet;

use super::*;
use crate::foundation::ids::{ManualClock, MonotonicTime};
use crate::model_memory::adapters::fakes::{
    adapter_identity, adapter_reference, base_spec, execution_identity, justified, logical,
    logical_identity, residency, versioned, KvFixture, LIMITS,
};
use crate::model_memory::adapters::graph::{
    DependencyGraph, GraphError, KvWrite, NodeData, NodeId, NodeKind, WithoutMerge,
};
use crate::model_memory::identity::{
    AdaptedModel, AdapterChange, LoraRefusal, MergeScale, MergedAdapter, VersionedName,
};

/// Merging `adapter-sql` into `base-8b`: 7.8125 ms (1/128 s) saved per request; 2 s to
/// materialize plus 1 s of displaced retention value, so 3 s of cost and a break-even
/// at exactly 384 requests.
fn economics(expected_requests: u64) -> MergeEconomics {
    MergeEconomics {
        base: execution_identity("base-8b"),
        adapter: adapter_identity("adapter-sql"),
        expected_requests,
        unmerged_overhead_seconds_per_request: 0.0078125,
        materialize_seconds: 2.0,
        retention_penalty_seconds: 1.0,
        variant_bytes: 16_000_000_000,
        available_bytes: 20_000_000_000,
    }
}

#[test]
fn merging_needs_amortized_work_above_the_threshold() {
    assert_eq!(
        decide_merge(&economics(384)),
        Ok(MergeChoice::KeepUnmerged(KeepUnmerged::WorkNotAmortized {
            saving_seconds: 3.0,
            cost_seconds: 3.0,
        }))
    );
    assert_eq!(
        decide_merge(&economics(100)),
        Ok(MergeChoice::KeepUnmerged(KeepUnmerged::WorkNotAmortized {
            saving_seconds: 0.78125,
            cost_seconds: 3.0,
        }))
    );
    let Ok(MergeChoice::Merge(proof)) = decide_merge(&economics(385)) else {
        panic!("385 requests justify merging");
    };
    assert_eq!(proof.saving_seconds(), 3.0078125);
    assert_eq!(proof.cost_seconds(), 3.0);
    assert_eq!(proof.materialize_seconds(), 2.0);
    assert_eq!(proof.variant_bytes(), 16_000_000_000);
    // The proof names the merge it justifies.
    assert_eq!(
        (proof.base(), proof.adapter()),
        (
            execution_identity("base-8b"),
            adapter_identity("adapter-sql")
        )
    );
}

#[test]
fn merging_needs_the_memory_too() {
    let crowded = MergeEconomics {
        expected_requests: 1_000_000,
        available_bytes: 15_999_999_999,
        ..economics(0)
    };
    assert_eq!(
        decide_merge(&crowded),
        Ok(MergeChoice::KeepUnmerged(KeepUnmerged::DoesNotFit {
            variant_bytes: 16_000_000_000,
            available_bytes: 15_999_999_999,
        }))
    );
    let exact = MergeEconomics {
        available_bytes: 16_000_000_000,
        ..crowded
    };
    assert!(matches!(decide_merge(&exact), Ok(MergeChoice::Merge(_))));
}

#[test]
fn invalid_economics_are_refused() {
    let negative = MergeEconomics {
        unmerged_overhead_seconds_per_request: -0.001,
        ..economics(1)
    };
    assert_eq!(
        decide_merge(&negative),
        Err(InputError::Negative {
            field: "MergeEconomics.unmerged_overhead_seconds_per_request"
        })
    );
    let not_finite = MergeEconomics {
        materialize_seconds: f64::NAN,
        ..economics(1)
    };
    assert_eq!(
        decide_merge(&not_finite),
        Err(InputError::NotFinite {
            field: "MergeEconomics.materialize_seconds"
        })
    );
    let empty = MergeEconomics {
        variant_bytes: 0,
        ..economics(1)
    };
    assert_eq!(
        decide_merge(&empty),
        Err(InputError::NotPositive {
            field: "MergeEconomics.variant_bytes"
        })
    );
}

struct Merged {
    base: NodeId,
    adapter: NodeId,
    variant: NodeId,
}

/// A base, an adapter admitted for it and a merged variant of the two.
fn merged() -> (DependencyGraph, Merged) {
    let mut graph = DependencyGraph::new();
    let base = graph
        .add_base(base_spec("base-8b", 16_000_000_000, true))
        .unwrap();
    let adapter = graph
        .admit_adapter(
            base,
            adapter_reference("adapter-sql", "base-8b"),
            &LIMITS,
            residency("adapter-sql", 50_000_000, true),
        )
        .unwrap();
    let variant = graph
        .materialize_merged(
            base,
            adapter,
            versioned("merge-procedure"),
            ContentKey::of(b"base-8b + adapter-sql, merged"),
            justified("base-8b", "adapter-sql", 16_000_000_000),
        )
        .unwrap();
    (
        graph,
        Merged {
            base,
            adapter,
            variant,
        },
    )
}

#[test]
fn a_merged_variant_never_mutates_the_base() {
    let mut graph = DependencyGraph::new();
    let base = graph
        .add_base(base_spec("base-8b", 16_000_000_000, true))
        .unwrap();
    let adapter = graph
        .admit_adapter(
            base,
            adapter_reference("adapter-sql", "base-8b"),
            &LIMITS,
            residency("adapter-sql", 50_000_000, true),
        )
        .unwrap();
    let base_before = graph.node(base).unwrap().clone();
    let adapter_before = graph.node(adapter).unwrap().clone();

    let variant = graph
        .materialize_merged(
            base,
            adapter,
            versioned("merge-procedure"),
            ContentKey::of(b"base-8b + adapter-sql, merged"),
            justified("base-8b", "adapter-sql", 16_000_000_000),
        )
        .unwrap();

    // The base and adapter nodes are unchanged, and both stay usable unmerged.
    assert_eq!(graph.node(base).unwrap(), &base_before);
    assert_eq!(graph.node(adapter).unwrap(), &adapter_before);
    // The variant is a separate allocation with no dependency on the base's bytes,
    // under T07's identity for the base with the adapter merged.
    let variant_node = graph.node(variant).unwrap();
    assert_eq!(variant_node.kind(), NodeKind::MergedVariant);
    assert!(variant_node.prerequisites().is_empty());
    assert_eq!(variant_node.bytes(), 16_000_000_000);
    let NodeData::MergedVariant {
        logical: variant_logical,
        identity,
        base: from_base,
        adapter: from_adapter,
        ..
    } = variant_node.data()
    else {
        panic!("not a merged variant");
    };
    let expected = logical("base-8b").with_merged(MergedAdapter {
        adapter: adapter_identity("adapter-sql"),
        scale: MergeScale::new(2.0).unwrap(),
        procedure: versioned("merge-procedure"),
    });
    assert_eq!(variant_logical, &expected);
    assert_ne!(*identity, execution_identity("base-8b"));
    assert_eq!(
        (*from_base, *from_adapter),
        (
            execution_identity("base-8b"),
            adapter_identity("adapter-sql")
        )
    );
    assert_eq!(
        graph.resident_bytes().unwrap(),
        16_000_000_000 + 50_000_000 + 16_000_000_000
    );

    // Writing into the base is refused outright.
    let spec = KvFixture::new(base, execution_identity("base-8b"), "chat").spec();
    assert_eq!(
        graph.write_kv(
            base,
            KvWrite {
                bytes: 1,
                token_prefix: spec.stored.spec.scope.prefix,
                restore: spec.restore,
            },
        ),
        Err(GraphError::Immutable {
            node: base,
            kind: NodeKind::Base
        })
    );
    assert_eq!(graph.node(base).unwrap(), &base_before);
}

#[test]
fn add_then_subtract_never_counts_as_restoring_the_base() {
    let (mut graph, nodes) = merged();
    // T07 refuses the subtraction and names the base's identity to load instead.
    let NodeData::MergedVariant { logical, .. } = graph.node(nodes.variant).unwrap().data() else {
        panic!("not a merged variant");
    };
    assert_eq!(
        AdaptedModel::base(logical.clone()).apply(&AdapterChange::SubtractMerged(
            adapter_identity("adapter-sql")
        )),
        Err(LoraRefusal::SubtractionIsNotExactUndo {
            load_instead: logical_identity("base-8b")
        })
    );
    // The graph therefore points at the untouched base, or at its artifact once the
    // base is no longer resident.
    assert_eq!(
        graph.without_merge(nodes.variant),
        Ok(WithoutMerge::Resident(nodes.base))
    );
    let clock = ManualClock::new(MonotonicTime::ZERO);
    graph
        .release(&BTreeSet::from([nodes.base, nodes.adapter]), &clock)
        .unwrap();
    assert_eq!(
        graph.without_merge(nodes.variant),
        Ok(WithoutMerge::Load(logical_identity("base-8b")))
    );

    // Bytes offered as the base count only from a verified canonical copy of its bytes.
    let base_content = ContentKey::of(b"base-8b");
    let variant = execution_identity("base-8b + adapter-sql");
    assert_eq!(
        accept_as_base(
            &base_content,
            &WeightsOrigin::SubtractedFromVariant {
                variant,
                adapter: adapter_identity("adapter-sql"),
            },
        ),
        Err(BaseClaimRefusal::ArithmeticUndoIsNotRestore)
    );
    assert_eq!(
        accept_as_base(&base_content, &WeightsOrigin::MergedVariant { variant }),
        Err(BaseClaimRefusal::MergedVariantIsNotTheBase)
    );
    assert_eq!(
        accept_as_base(
            &base_content,
            &WeightsOrigin::VerifiedCanonical {
                content: ContentKey::of(b"base-8b, rounded")
            },
        ),
        Err(BaseClaimRefusal::ContentMismatch {
            expected: base_content,
            actual: ContentKey::of(b"base-8b, rounded"),
        })
    );
    assert_eq!(
        accept_as_base(
            &base_content,
            &WeightsOrigin::VerifiedCanonical {
                content: base_content
            },
        ),
        Ok(())
    );
    assert!(BaseClaimRefusal::ArithmeticUndoIsNotRestore
        .to_string()
        .contains("canonical base"));
}

#[test]
fn a_variant_needs_a_base_and_an_adapter_admitted_for_it() {
    let (mut graph, nodes) = merged();
    let other_base = graph.add_base(base_spec("base-70b", 1_000, true)).unwrap();
    let content = ContentKey::of(b"variant");
    assert_eq!(
        graph.materialize_merged(
            other_base,
            nodes.adapter,
            versioned("merge-procedure"),
            content,
            justified("base-8b", "adapter-sql", 1_000),
        ),
        Err(GraphError::AdapterNotForBase {
            adapter: nodes.adapter,
            base: other_base
        })
    );
    assert_eq!(
        graph.materialize_merged(
            nodes.adapter,
            nodes.adapter,
            versioned("merge-procedure"),
            content,
            justified("base-8b", "adapter-sql", 1_000),
        ),
        Err(GraphError::NotABase {
            node: nodes.adapter
        })
    );
    assert_eq!(
        graph.materialize_merged(
            nodes.base,
            nodes.base,
            versioned("merge-procedure"),
            content,
            justified("base-8b", "adapter-sql", 1_000),
        ),
        Err(GraphError::NotAnAdapter { node: nodes.base })
    );
    // The same base, adapter, scale and procedure give the same variant, resident once;
    // another procedure gives another variant.
    assert!(matches!(
        graph.materialize_merged(
            nodes.base,
            nodes.adapter,
            versioned("merge-procedure"),
            content,
            justified("base-8b", "adapter-sql", 1_000),
        ),
        Err(GraphError::DuplicateWeights { existing, .. }) if existing == nodes.variant
    ));
    assert!(graph
        .materialize_merged(
            nodes.base,
            nodes.adapter,
            VersionedName::new("merge-procedure", "2").unwrap(),
            content,
            justified("base-8b", "adapter-sql", 1_000),
        )
        .is_ok());
    assert_eq!(
        graph.without_merge(nodes.base),
        Err(GraphError::NotAVariant { node: nodes.base })
    );
}

#[test]
fn a_proof_for_another_merge_justifies_nothing() {
    let mut graph = DependencyGraph::new();
    let base = graph
        .add_base(base_spec("base-8b", 16_000_000_000, true))
        .unwrap();
    let adapter = graph
        .admit_adapter(
            base,
            adapter_reference("adapter-sql", "base-8b"),
            &LIMITS,
            residency("adapter-sql", 50_000_000, true),
        )
        .unwrap();
    let count = graph.len();
    for (proof_base, proof_adapter) in [("base-8b", "adapter-legal"), ("base-70b", "adapter-sql")] {
        assert_eq!(
            graph.materialize_merged(
                base,
                adapter,
                versioned("merge-procedure"),
                ContentKey::of(b"merged"),
                justified(proof_base, proof_adapter, 1_000),
            ),
            Err(GraphError::ProofForAnotherMerge {
                base: execution_identity(proof_base),
                adapter: adapter_identity(proof_adapter),
            })
        );
    }
    assert_eq!(graph.len(), count);
}
