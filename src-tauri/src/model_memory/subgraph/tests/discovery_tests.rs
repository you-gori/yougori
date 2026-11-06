//! Discovery of the longest provably identical executable prefix (lines 880, 888, 890).

use super::*;
use crate::foundation::ids::digest;

fn base() -> ImmutableVariant {
    edited_base(|_| {})
}

#[test]
fn discovery_on_a_constructed_manifest_pair_stops_at_the_first_difference() {
    // Layer 3 changes; layers 4–6 and the head are byte-identical again.
    let revised = custom_variant(
        &synthetic_model(REFERENCE_ROPE_THETA, &["layers.3.weight"]),
        REFERENCE_ROPE_THETA,
        None,
        |_| {},
    )
    .unwrap();
    let a = base();
    let prefix = discover_shared_prefix(&a, &revised);
    assert_eq!(prefix.shared_operators(), 3);
    assert_eq!(
        prefix.stop(),
        &PrefixStop::Difference {
            operator: 3,
            components: vec![StateKeyComponent::Parameters]
        }
    );
    assert_eq!(prefix.branch_boundary(), Some(3));
    assert_eq!(prefix.variants(), &[a.identity(), revised.identity()]);
    // Later operators have equal parameters, yet their states differ through the parent.
    for operator in 4..8 {
        assert_eq!(
            a.operators()[operator].parameters(),
            revised.operators()[operator].parameters()
        );
    }
    let input = ExactInput::whole(&tokens(40, 2)).unwrap();
    let left = a.state_keys(&input, &pinned(&a), &mode(), 8).unwrap();
    let right = revised
        .state_keys(&input, &pinned(&revised), &mode(), 8)
        .unwrap();
    assert_eq!(left[..3], right[..3]);
    assert!(left[3..].iter().zip(&right[3..]).all(|(l, r)| l != r));
}

#[test]
fn the_verified_pair_shares_its_unchanged_block_sequence() {
    let verified = family(PrototypePair::VerifiedSharedPrefix);
    let prefix = discover_shared_prefix(&verified.a, &verified.b);
    assert_eq!(prefix.shared_operators(), 6);
    assert_eq!(
        prefix.stop(),
        &PrefixStop::Difference {
            operator: 6,
            components: vec![StateKeyComponent::AdapterEffects]
        }
    );
    let input = ExactInput::whole(&tokens(40, 2)).unwrap();
    let a = verified
        .a
        .state_keys(&input, &pinned(&verified.a), &mode(), 8)
        .unwrap();
    let b = verified
        .b
        .state_keys(&input, &pinned(&verified.b), &mode(), 8)
        .unwrap();
    assert_eq!(a[..6], b[..6]);
    assert!(a[6..].iter().zip(&b[6..]).all(|(l, r)| l != r));
    // The variants are different models: their execution identities differ.
    assert_ne!(verified.a.execution(), verified.b.execution());
}

#[test]
fn the_control_pair_differing_in_the_first_block_shares_nothing() {
    let control = family(PrototypePair::ControlFirstBlockDiffers);
    let prefix = discover_shared_prefix(&control.a, &control.b);
    assert_eq!(prefix.shared_operators(), 0);
    assert_eq!(prefix.branch_boundary(), None);
    assert_eq!(
        prefix.stop(),
        &PrefixStop::Difference {
            operator: 0,
            components: vec![StateKeyComponent::Parameters]
        }
    );
}

#[test]
fn equal_weights_under_another_positional_configuration_share_nothing() {
    let pair = family(PrototypePair::EqualWeightsDifferentPositions);
    for (left, right) in pair.a.operators().iter().zip(pair.b.operators()) {
        assert_eq!(left.parameters(), right.parameters());
    }
    let prefix = discover_shared_prefix(&pair.a, &pair.b);
    assert_eq!(prefix.shared_operators(), 0);
    assert_eq!(
        prefix.stop(),
        &PrefixStop::Difference {
            operator: 0,
            components: vec![StateKeyComponent::PositionSemantics]
        }
    );
    let input = ExactInput::whole(&tokens(40, 2)).unwrap();
    let a = pair
        .a
        .state_keys(&input, &pinned(&pair.a), &mode(), 8)
        .unwrap();
    let b = pair
        .b
        .state_keys(&input, &pinned(&pair.b), &mode(), 8)
        .unwrap();
    assert!(a.iter().zip(&b).all(|(l, r)| l != r));
}

#[test]
fn variant_wide_semantics_profile_and_scope_stop_discovery_at_the_first_operator() {
    let a = base();
    let cases: Vec<(StateKeyComponent, ImmutableVariant)> = vec![
        (
            StateKeyComponent::AttentionSemantics,
            edited_base(|d| {
                d.attention.parameters = digest("yougori/test/attention/v1", &[b"window-4096"])
            }),
        ),
        (
            StateKeyComponent::ExecutionProfile,
            edited_base(|d| {
                d.profile.kernels = VersionedName::new("synthetic-kernels", "2").unwrap()
            }),
        ),
        (
            StateKeyComponent::TrustScope,
            edited_base(|d| d.trust_scope = other_scope()),
        ),
    ];
    for (component, b) in cases {
        let prefix = discover_shared_prefix(&a, &b);
        assert_eq!(prefix.shared_operators(), 0, "{component:?}");
        assert_eq!(
            prefix.stop(),
            &PrefixStop::Difference {
                operator: 0,
                components: vec![component]
            }
        );
    }
    let mut seeded = edited_base(|d| d.operators[5].runtime = OperatorRuntime::Seeded);
    let prefix = discover_shared_prefix(&a, &seeded);
    assert_eq!(prefix.shared_operators(), 5);
    seeded = edited_base(|d| d.operators[1].output.dtype = Dtype::BFloat16);
    assert_eq!(
        discover_shared_prefix(&a, &seeded).stop(),
        &PrefixStop::Difference {
            operator: 1,
            components: vec![StateKeyComponent::DtypeLayout]
        }
    );
    let other_abi = edited_base(|d| {
        d.operators[2].abi.kernel = VersionedName::new("other-kernel", "1").unwrap()
    });
    assert_eq!(
        discover_shared_prefix(&a, &other_abi).stop(),
        &PrefixStop::Difference {
            operator: 2,
            components: vec![StateKeyComponent::OperatorAbi]
        }
    );
}

#[test]
fn identical_variants_never_branch_and_a_longer_variant_branches_at_its_end() {
    let a = base();
    let same = discover_shared_prefix(&a, &base());
    assert_eq!(same.shared_operators(), 8);
    assert_eq!(same.stop(), &PrefixStop::Identical);
    assert_eq!(same.branch_boundary(), None);
    let longer = edited_base(|d| d.operators.push(d.operators[7].clone()));
    let prefix = discover_shared_prefix(&a, &longer);
    assert_eq!(prefix.shared_operators(), 8);
    assert_eq!(prefix.stop(), &PrefixStop::EndOfVariant { operator: 8 });
    assert_eq!(prefix.branch_boundary(), Some(8));
}
