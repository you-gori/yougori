//! The state key of lines 882–886 and line 888, manifest-derived parameter identities
//! (line 890) and the construction of immutable variants.

use std::collections::BTreeSet;

use super::*;
use crate::foundation::ids::{digest, Digest};
use crate::model_memory::adapters::adapter::{AdapterRefusal, LayerShape};
use crate::model_memory::identity::LogicalModelIdentity;
use crate::model_memory::manifest::{
    ElementType, RematerializedBuffer, TensorAlias, TensorDtype, TensorName, Token,
};
use crate::model_memory::subgraph::synthetic::{
    configuration_bytes, synthetic_manifest_with_extents, tensor_contents, SyntheticTensor,
};

fn base() -> ImmutableVariant {
    edited_base(|_| {})
}

/// Operator 1's spec for a fixed request: it has parameters and a parent.
fn base_spec() -> StateKeySpec {
    let variant = base();
    let input = ExactInput::whole(&tokens(32, 1)).unwrap();
    variant
        .state_key_specs(&input, &pinned(&variant), &mode(), 2)
        .unwrap()
        .remove(1)
}

#[test]
fn every_key_component_changes_the_key() {
    let spec = base_spec();
    let verified = family(PrototypePair::VerifiedSharedPrefix);
    let other_parent = {
        let variant = base();
        let input = ExactInput::whole(&tokens(32, 2)).unwrap();
        variant
            .state_key_specs(&input, &pinned(&variant), &mode(), 1)
            .unwrap()[0]
            .key()
    };
    let adapted = verified.b.operators()[6].adapter_effects().to_vec();
    assert!(!adapted.is_empty());
    let mut changes: Vec<(StateKeyComponent, StateKeySpec)> = Vec::new();
    let mut add = |component, edit: &dyn Fn(&mut StateKeySpec)| {
        let mut changed = spec.clone();
        edit(&mut changed);
        changes.push((component, changed));
    };
    add(StateKeyComponent::OperatorAbi, &|s| {
        s.operator.kernel = VersionedName::new("synthetic-kernels", "2").unwrap()
    });
    add(StateKeyComponent::Parameters, &|s| {
        s.parameters = base().operators()[2].parameters().to_vec()
    });
    add(StateKeyComponent::ParentStates, &|s| {
        s.parents = vec![other_parent]
    });
    add(StateKeyComponent::Inputs, &|s| {
        s.input = ExactInput::whole(&tokens(33, 1)).unwrap()
    });
    add(StateKeyComponent::AttentionSemantics, &|s| {
        s.attention.parameters = digest("yougori/test/attention/v1", &[b"sliding-4096"])
    });
    add(StateKeyComponent::PositionSemantics, &|s| {
        s.position = rope(500_000).unwrap()
    });
    add(StateKeyComponent::DtypeLayout, &|s| {
        s.output.dtype = Dtype::BFloat16
    });
    add(StateKeyComponent::AdapterEffects, &|s| {
        s.adapter_effects = adapted.clone()
    });
    add(StateKeyComponent::ExecutionProfile, &|s| {
        s.profile.math_mode = digest("yougori/test/math/v1", &[b"tf32"])
    });
    add(StateKeyComponent::RuntimeState, &|s| {
        s.runtime = BoundRuntime::Seed(7)
    });
    add(StateKeyComponent::TrustScope, &|s| {
        s.trust_scope = other_scope()
    });
    let covered: BTreeSet<StateKeyComponent> = changes.iter().map(|(c, _)| *c).collect();
    assert_eq!(covered, StateKeyComponent::ALL.into_iter().collect());
    let mut keys = BTreeSet::from([spec.key()]);
    for (component, changed) in &changes {
        assert_ne!(changed.key(), spec.key(), "{component:?}");
        assert_eq!(spec.differences(changed), vec![*component]);
        assert!(keys.insert(changed.key()), "{component:?} collided");
    }
}

#[test]
fn the_key_is_deterministic_and_its_encoding_is_pinned() {
    let spec = base_spec();
    assert_eq!(spec.key(), base_spec().key());
    assert!(spec.differences(&base_spec()).is_empty());
    assert_eq!(
        spec.key().digest().to_hex(),
        "4bcfd5a174d4d1bed76fbdbc99f13eb3809bafc2e0a765da1d6f9f0b82938577",
        "the state key encoding or its synthetic fixture changed; an encoding change needs a new STATE_KEY_DOMAIN"
    );
}

#[test]
fn seeds_and_operator_states_enter_the_key() {
    let mut seeded = base_spec();
    seeded.runtime = BoundRuntime::Seed(1);
    let mut reseeded = base_spec();
    reseeded.runtime = BoundRuntime::Seed(2);
    let mut stateful = base_spec();
    stateful.runtime = BoundRuntime::State(Digest::from_bytes([1; 32]));
    let mut restated = base_spec();
    restated.runtime = BoundRuntime::State(Digest::from_bytes([2; 32]));
    let keys: BTreeSet<_> = [&seeded, &reseeded, &stateful, &restated, &base_spec()]
        .iter()
        .map(|spec| spec.key())
        .collect();
    assert_eq!(keys.len(), 5);
}

#[test]
fn an_exact_input_binds_its_context_and_refuses_an_empty_span() {
    let a = ExactInput::new(&[1, 2], &[3, 4], None).unwrap();
    assert_eq!(a.first_position(), 2);
    assert_eq!(a.span_tokens(), 2);
    assert_ne!(a, ExactInput::new(&[9, 2], &[3, 4], None).unwrap());
    assert_ne!(a, ExactInput::new(&[1], &[2, 3, 4], None).unwrap());
    assert_ne!(
        a,
        ExactInput::new(&[1, 2], &[3, 4], Some(Digest::from_bytes([5; 32]))).unwrap()
    );
    assert_eq!(
        ExactInput::new(&[1, 2], &[], None).unwrap_err(),
        SubgraphError::EmptySpan
    );
}

#[test]
fn parameter_identities_follow_bytes_and_interpretation_not_names() {
    let reference = synthetic_manifest(&synthetic_model(REFERENCE_ROPE_THETA, &[])).unwrap();
    let revised =
        synthetic_manifest(&synthetic_model(REFERENCE_ROPE_THETA, &["head.weight"])).unwrap();
    let id = |manifest, name| ParameterIdentity::from_manifest(manifest, name).unwrap();
    assert_eq!(
        id(&reference, "layers.3.weight"),
        id(&revised, "layers.3.weight")
    );
    assert_ne!(id(&reference, "head.weight"), id(&revised, "head.weight"));
    // The same bytes at the same position under another name.
    let mut renamed = synthetic_model(REFERENCE_ROPE_THETA, &[]);
    renamed.tensors[4].name = "blocks.3.dense".to_owned();
    let renamed = synthetic_manifest(&renamed).unwrap();
    assert_eq!(
        id(&reference, "layers.3.weight"),
        id(&renamed, "blocks.3.dense")
    );
    // Equal bytes under another configuration: the tensor bytes still decide.
    let other_config = synthetic_manifest(&synthetic_model(500_000, &[])).unwrap();
    assert_eq!(
        id(&reference, "layers.0.weight"),
        id(&other_config, "layers.0.weight")
    );
    assert_eq!(
        ParameterIdentity::from_manifest(&reference, "missing.weight").unwrap_err(),
        ParameterError::Unknown {
            name: "missing.weight".to_owned()
        }
    );
}

#[test]
fn a_tensor_sharing_an_extent_with_a_changed_neighbour_loses_sharing_but_never_gains_it() {
    // 128-byte extents: layers.0 and layers.1 share one extent.
    let reference =
        synthetic_manifest_with_extents(&synthetic_model(REFERENCE_ROPE_THETA, &[]), 128).unwrap();
    let neighbour_changed = synthetic_manifest_with_extents(
        &synthetic_model(REFERENCE_ROPE_THETA, &["layers.1.weight"]),
        128,
    )
    .unwrap();
    let id = |manifest, name| ParameterIdentity::from_manifest(manifest, name).unwrap();
    // layers.0's bytes are unchanged, but its covering extent changed.
    assert_ne!(
        id(&reference, "layers.0.weight"),
        id(&neighbour_changed, "layers.0.weight")
    );
    assert_eq!(
        id(&reference, "layers.3.weight"),
        id(&neighbour_changed, "layers.3.weight")
    );
    // The extent grid and the offset inside it are part of the identity.
    let per_tensor = synthetic_manifest(&synthetic_model(REFERENCE_ROPE_THETA, &[])).unwrap();
    assert_ne!(
        id(&reference, "layers.3.weight"),
        id(&per_tensor, "layers.3.weight")
    );
}

#[test]
fn aliases_follow_their_target_and_rematerialized_buffers_bind_the_configuration() {
    let with_state = |rope_theta: u64| {
        let manifest = synthetic_manifest(&synthetic_model(rope_theta, &[])).unwrap();
        let mut manifest = manifest.into_manifest();
        manifest.tensor_index.aliases.push(TensorAlias {
            name: TensorName::new("lm_head.weight").unwrap(),
            target: TensorName::new("embed.weight").unwrap(),
        });
        manifest
            .state
            .rematerialized_buffers
            .push(RematerializedBuffer {
                name: TensorName::new("rotary.inv_freq").unwrap(),
                dtype: TensorDtype::Element(ElementType::F32),
                shape: vec![8],
                reconstruction: crate::model_memory::manifest::VersionedName {
                    name: Token::new("rope").unwrap(),
                    version: Token::new("1").unwrap(),
                },
            });
        manifest.validate().unwrap()
    };
    let reference = with_state(REFERENCE_ROPE_THETA);
    let rescaled = with_state(500_000);
    let id = |manifest, name| ParameterIdentity::from_manifest(manifest, name).unwrap();
    assert_eq!(
        id(&reference, "lm_head.weight"),
        id(&reference, "embed.weight")
    );
    assert_ne!(
        id(&reference, "rotary.inv_freq"),
        id(&reference, "embed.weight")
    );
    assert_ne!(
        id(&reference, "rotary.inv_freq"),
        id(&rescaled, "rotary.inv_freq")
    );
    assert_eq!(
        id(&reference, "embed.weight"),
        id(&rescaled, "embed.weight")
    );
}

#[test]
fn a_variant_derives_its_parameters_and_artifact_from_the_manifest() {
    let model = synthetic_model(REFERENCE_ROPE_THETA, &[]);
    let manifest = synthetic_manifest(&model).unwrap();
    let variant = base();
    assert_eq!(
        variant.artifact(),
        crate::model_memory::identity::ArtifactIdentity::from_manifest_digest(
            &manifest.digest().digest()
        )
    );
    assert_eq!(variant.operators().len(), 8);
    assert_eq!(
        variant.operators()[0].parameters(),
        &[
            ParameterIdentity::from_manifest(&manifest, "embed.weight").unwrap(),
            ParameterIdentity::from_manifest(&manifest, "layers.0.weight").unwrap(),
        ]
    );
    assert_eq!(variant.adapter(), None);
    assert_eq!(variant.identity(), base().identity());
}

#[test]
fn variant_construction_refuses_what_it_cannot_prove() {
    let model = synthetic_model(REFERENCE_ROPE_THETA, &[]);
    assert_eq!(
        custom_variant(&model, REFERENCE_ROPE_THETA, None, |d| d.operators.clear()).unwrap_err(),
        SubgraphError::NoOperators
    );
    assert_eq!(
        custom_variant(&model, REFERENCE_ROPE_THETA, None, |d| {
            d.operators[3].tensors = vec!["layers.99.weight".to_owned()]
        })
        .unwrap_err(),
        SubgraphError::Parameter(ParameterError::Unknown {
            name: "layers.99.weight".to_owned()
        })
    );
    assert_eq!(
        custom_variant(&model, REFERENCE_ROPE_THETA, None, |d| {
            d.operators[2].adaptable_layers = vec!["layers.1.proj".to_owned()]
        })
        .unwrap_err(),
        SubgraphError::DuplicateAdaptableLayer {
            layer: "layers.1.proj".to_owned()
        }
    );
    assert_eq!(
        custom_variant(
            &model,
            REFERENCE_ROPE_THETA,
            Some(&["layers.6.proj"]),
            |d| { d.operators[6].adaptable_layers.clear() }
        )
        .unwrap_err(),
        SubgraphError::AdapterLayerNotMapped {
            layer: "layers.6.proj".to_owned()
        }
    );
}

#[test]
fn an_adapter_is_admitted_only_after_the_section_3_9_compatibility_check() {
    let model = synthetic_model(REFERENCE_ROPE_THETA, &[]);
    let manifest = synthetic_manifest(&model).unwrap();
    let (logical, execution) = synthetic_identities(&model, &manifest).unwrap();
    let definition = || VariantDefinition {
        execution,
        trust_scope: scope(),
        attention: causal_attention().unwrap(),
        position: rope(REFERENCE_ROPE_THETA).unwrap(),
        profile: exact_profile().unwrap(),
        operators: architecture_operators().unwrap(),
    };
    let layers = architecture_layers();
    let other = synthetic_model(REFERENCE_ROPE_THETA, &["head.weight"]);
    let other_base: LogicalModelIdentity =
        synthetic_identities(&other, &synthetic_manifest(&other).unwrap())
            .unwrap()
            .0;
    assert_ne!(other_base, logical);
    let foreign = synthetic_adapter(other_base, &["layers.6.proj"]).unwrap();
    let admission = AdapterAdmission {
        reference: &foreign,
        base: &logical,
        base_layers: &layers,
        limits: &SYNTHETIC_ADAPTER_LIMITS,
    };
    assert!(matches!(
        ImmutableVariant::from_manifest(&manifest, definition(), Some(admission)).unwrap_err(),
        SubgraphError::Adapter(AdapterRefusal::BaseMismatch { .. })
    ));
    let mut wide = synthetic_adapter(logical, &["layers.6.proj"]).unwrap();
    wide.layers.insert(
        "layers.6.proj".to_owned(),
        LayerShape {
            input_features: 8,
            output_features: 16,
        },
    );
    let admission = AdapterAdmission {
        reference: &wide,
        base: &logical,
        base_layers: &layers,
        limits: &SYNTHETIC_ADAPTER_LIMITS,
    };
    assert!(matches!(
        ImmutableVariant::from_manifest(&manifest, definition(), Some(admission)).unwrap_err(),
        SubgraphError::Adapter(AdapterRefusal::ShapeMismatch { .. })
    ));
    let adapted = custom_variant(
        &model,
        REFERENCE_ROPE_THETA,
        Some(&["layers.6.proj"]),
        |_| {},
    )
    .unwrap();
    for (index, operator) in adapted.operators().iter().enumerate() {
        assert_eq!(operator.adapter_effects().is_empty(), index != 6, "{index}");
    }
    let effect = &adapted.operators()[6].adapter_effects()[0];
    assert_eq!(effect.rank(), 4);
    assert_eq!(effect.base(), logical);
    assert_eq!(effect.layers()[0].0, "layers.6.proj");
    assert!(adapted.adapter().is_some());
    assert_ne!(adapted.identity(), base().identity());
}

#[test]
fn synthetic_tensors_are_distinct_and_sized() {
    let a = tensor_contents("layers.1.weight", 0);
    assert_eq!(a.len(), 64);
    assert_ne!(a, tensor_contents("layers.1.weight", 1));
    assert_ne!(a, tensor_contents("layers.2.weight", 0));
    assert_ne!(configuration_bytes(1), configuration_bytes(2));
    let mut model = synthetic_model(REFERENCE_ROPE_THETA, &[]);
    model.tensors.push(SyntheticTensor {
        name: "short".to_owned(),
        bytes: vec![0; 3],
    });
    assert!(synthetic_manifest(&model).is_err());
}
