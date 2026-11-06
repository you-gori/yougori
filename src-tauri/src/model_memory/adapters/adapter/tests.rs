use super::*;
use crate::model_memory::adapters::fakes::{
    adapter_reference, base_spec, layers, logical_identity, residency, LIMITS,
};
use crate::model_memory::adapters::graph::{DependencyGraph, GraphError, NodeKind};

fn shape(input_features: u64, output_features: u64) -> LayerShape {
    LayerShape {
        input_features,
        output_features,
    }
}

fn check(reference: &AdapterReference) -> Result<(), AdapterRefusal> {
    check_compatibility(&logical_identity("base-8b"), &layers(), reference, &LIMITS)
}

fn reference() -> AdapterReference {
    adapter_reference("adapter-sql", "base-8b")
}

#[test]
fn a_compatible_adapter_passes() {
    assert_eq!(check(&reference()), Ok(()));
    let mut subset = reference();
    subset.layers.remove("layers.0.v_proj");
    assert_eq!(check(&subset), Ok(()));
}

#[test]
fn another_base_identity_is_refused_even_with_identical_layers() {
    // Same layer names and shapes, another identity: names and sizes never make two
    // bases equivalent (§3.2 line 504).
    let other = adapter_reference("adapter-sql", "base-8b-other-revision");
    assert_eq!(
        check(&other),
        Err(AdapterRefusal::BaseMismatch {
            expected: logical_identity("base-8b"),
            actual: logical_identity("base-8b-other-revision"),
        })
    );
}

#[test]
fn the_layer_mapping_must_fit_the_base() {
    let mut unknown = reference();
    unknown
        .layers
        .insert("layers.0.k_proj".to_string(), shape(4096, 1024));
    assert_eq!(
        check(&unknown),
        Err(AdapterRefusal::UnknownLayer {
            layer: "layers.0.k_proj".to_string()
        })
    );

    let mut reshaped = reference();
    reshaped
        .layers
        .insert("layers.0.v_proj".to_string(), shape(4096, 4096));
    assert_eq!(
        check(&reshaped),
        Err(AdapterRefusal::ShapeMismatch {
            layer: "layers.0.v_proj".to_string(),
            base: shape(4096, 1024),
            adapter: shape(4096, 4096),
        })
    );

    let mut empty = reference();
    empty.layers.clear();
    assert_eq!(check(&empty), Err(AdapterRefusal::EmptyLayerMapping));

    let mut unnamed = reference();
    unnamed.layers.insert(String::new(), shape(1, 1));
    assert_eq!(
        check(&unnamed),
        Err(AdapterRefusal::InvalidLayerName {
            layer: String::new()
        })
    );
}

#[test]
fn the_rank_is_checked() {
    let mut zero = reference();
    zero.rank = 0;
    assert_eq!(check(&zero), Err(AdapterRefusal::ZeroRank));

    let mut high = reference();
    high.rank = 65;
    assert_eq!(
        check(&high),
        Err(AdapterRefusal::RankAboveEngineLimit {
            rank: 65,
            max_rank: 64
        })
    );
    high.rank = 64;
    assert_eq!(check(&high), Ok(()));

    let narrow_layers = LayerTable::from([("narrow".to_string(), shape(4096, 8))]);
    let narrow = AdapterReference {
        layers: narrow_layers.clone(),
        ..reference()
    };
    assert_eq!(
        check_compatibility(
            &logical_identity("base-8b"),
            &narrow_layers,
            &narrow,
            &LIMITS
        ),
        Err(AdapterRefusal::RankAboveLayer {
            layer: "narrow".to_string(),
            rank: 16
        })
    );
}

#[test]
fn a_refused_adapter_is_never_admitted() {
    let mut graph = DependencyGraph::new();
    let base = graph
        .add_base(base_spec("base-8b", 16_000_000_000, true))
        .unwrap();
    let weights = residency("adapter-sql", 50_000_000, true);
    assert_eq!(
        graph.admit_adapter(
            base,
            adapter_reference("adapter-sql", "base-70b"),
            &LIMITS,
            weights.clone()
        ),
        Err(GraphError::AdapterRefused(AdapterRefusal::BaseMismatch {
            expected: logical_identity("base-8b"),
            actual: logical_identity("base-70b"),
        }))
    );
    assert_eq!(graph.len(), 1);
    assert!(graph.dependents(base).is_empty());

    let admitted = graph
        .admit_adapter(base, reference(), &LIMITS, weights.clone())
        .unwrap();
    assert_eq!(graph.node(admitted).unwrap().kind(), NodeKind::Adapter);
    assert_eq!(
        graph.dependents(base).into_iter().collect::<Vec<_>>(),
        [admitted]
    );
    assert!(graph.node(base).unwrap().prerequisites().is_empty());

    // An adapter is admitted against a base node only.
    assert_eq!(
        graph.admit_adapter(admitted, reference(), &LIMITS, weights),
        Err(GraphError::NotABase { node: admitted })
    );
}

#[test]
fn refusals_explain_themselves() {
    let message = AdapterRefusal::RankAboveEngineLimit {
        rank: 65,
        max_rank: 64,
    }
    .to_string();
    assert!(message.contains("65") && message.contains("64"));
}
