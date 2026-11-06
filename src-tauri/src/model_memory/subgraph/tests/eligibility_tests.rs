//! Each eligibility rule of lines 888–892, tried and refused.

use std::collections::BTreeMap;

use super::*;
use crate::foundation::ids::Digest;
use crate::model_memory::identity::{
    AccuracyEvaluation, Approximation, FidelityCategory, FidelityConfiguration,
};

fn base() -> ImmutableVariant {
    edited_base(|_| {})
}

#[test]
fn parameter_equality_alone_is_insufficient() {
    // The control pair differs only in the first block, so every later operator has
    // equal parameters but receives a different parent state.
    let control = family(PrototypePair::ControlFirstBlockDiffers);
    let input = ExactInput::whole(&tokens(64, 3)).unwrap();
    let a = control
        .a
        .state_key_specs(&input, &pinned(&control.a), &mode(), 8)
        .unwrap();
    let b = control
        .b
        .state_key_specs(&input, &pinned(&control.b), &mode(), 8)
        .unwrap();
    assert!(matches!(
        check_state_reuse(&a[0], &b[0], 0),
        Err(ReuseRefusal::KeyMismatch { operator: 0, ref components })
            if components == &[StateKeyComponent::Parameters]
    ));
    for operator in 1..8 {
        assert_eq!(a[operator].parameters, b[operator].parameters, "{operator}");
        assert_eq!(
            check_state_reuse(&a[operator], &b[operator], operator),
            Err(ReuseRefusal::ParentStateDiffers { operator })
        );
    }
}

#[test]
fn a_matching_fragment_under_a_different_context_is_not_the_same_input() {
    let variant = base();
    let spec = |context: &[u32], span: &[u32]| {
        let input = ExactInput::new(context, span, None).unwrap();
        variant
            .state_key_specs(&input, &pinned(&variant), &mode(), 2)
            .unwrap()
    };
    let stored = spec(&[1, 2, 3], &[40, 41, 42]);
    let other_context = spec(&[9, 2, 3], &[40, 41, 42]);
    for operator in 0..2 {
        assert_eq!(
            check_state_reuse(&stored[operator], &other_context[operator], operator),
            Err(ReuseRefusal::PrecedingContextDiffers)
        );
    }
    let other_fragment = spec(&[1, 2, 3], &[40, 41, 43]);
    assert_eq!(
        check_state_reuse(&stored[0], &other_fragment[0], 0),
        Err(ReuseRefusal::InputDiffers)
    );
    let same = spec(&[1, 2, 3], &[40, 41, 42]);
    assert_eq!(
        check_state_reuse(&stored[1], &same[1], 1),
        Ok(stored[1].key())
    );
}

#[test]
fn runtime_seeds_and_stateful_operators_enter_the_identity_or_disqualify_reuse() {
    let variant = edited_base(|d| {
        d.operators[2].runtime = OperatorRuntime::Seeded;
        d.operators[4].runtime = OperatorRuntime::Stateful;
    });
    let input = ExactInput::whole(&tokens(16, 5)).unwrap();
    let mut runtime = pinned(&variant);
    assert_eq!(
        variant
            .state_keys(&input, &runtime, &mode(), 8)
            .unwrap_err(),
        ReuseRefusal::UnboundRuntimeSeed { operator: 2 }
    );
    // Operators before the seeded one do not need it.
    assert_eq!(
        variant
            .state_keys(&input, &runtime, &mode(), 2)
            .unwrap()
            .len(),
        2
    );
    runtime.seeds.insert(2, 11);
    assert_eq!(
        variant
            .state_keys(&input, &runtime, &mode(), 8)
            .unwrap_err(),
        ReuseRefusal::UnboundOperatorState { operator: 4 }
    );
    runtime
        .operator_states
        .insert(4, Digest::from_bytes([3; 32]));
    let keys = variant.state_keys(&input, &runtime, &mode(), 8).unwrap();
    let mut reseeded = runtime.clone();
    reseeded.seeds.insert(2, 12);
    let other = variant.state_keys(&input, &reseeded, &mode(), 8).unwrap();
    assert_eq!(keys[..2], other[..2]);
    assert!(keys[2..].iter().zip(&other[2..]).all(|(a, b)| a != b));
    let mut restated = runtime.clone();
    restated
        .operator_states
        .insert(4, Digest::from_bytes([4; 32]));
    let other = variant.state_keys(&input, &restated, &mode(), 8).unwrap();
    assert_eq!(keys[..4], other[..4]);
    assert_ne!(keys[4], other[4]);
    let mut stray = runtime.clone();
    stray.seeds.insert(3, 1);
    assert_eq!(
        variant.state_keys(&input, &stray, &mode(), 8).unwrap_err(),
        ReuseRefusal::UnexpectedRuntimeBinding { operator: 3 }
    );
    let mut stray = runtime;
    stray.operator_states.insert(2, Digest::from_bytes([5; 32]));
    assert_eq!(
        variant.state_keys(&input, &stray, &mode(), 8).unwrap_err(),
        ReuseRefusal::UnexpectedRuntimeBinding { operator: 2 }
    );
}

#[test]
fn autoregressive_reuse_stops_where_token_histories_diverge() {
    let variant = base();
    let runtime = pinned(&variant);
    let stored = variant
        .boundary_history(&[1, 2, 3, 4, 5], 6, &runtime, &mode())
        .unwrap();
    let request = variant
        .boundary_history(&[1, 9, 3, 4, 5], 6, &runtime, &mode())
        .unwrap();
    assert_eq!(common_history_prefix(&stored, &request), 1);
    // The tokens match again after the divergence, but the states never do.
    assert_eq!(stored[2].token, request[2].token);
    assert!(stored[1..]
        .iter()
        .zip(&request[1..])
        .all(|(a, b)| a.state != b.state));
    assert_eq!(check_continuation(&stored, &request, 1), Ok(1));
    assert_eq!(
        check_continuation(&stored, &request, 4),
        Err(ReuseRefusal::HistoryDiverged { position: 1 })
    );
    assert_eq!(check_continuation(&stored, &stored, 5), Ok(5));
    assert_eq!(
        check_continuation(&stored, &stored, 6),
        Err(ReuseRefusal::HistoryDiverged { position: 5 })
    );
    assert_eq!(
        variant
            .boundary_history(&[1], 0, &runtime, &mode())
            .unwrap_err(),
        ReuseRefusal::NotAPlannedBoundary
    );
}

#[test]
fn autoregressive_reuse_stops_where_ancestor_states_diverge() {
    // Same tokens; the control variant's ancestors differ from the first block on.
    let control = family(PrototypePair::ControlFirstBlockDiffers);
    let history = [5, 6, 7, 8];
    let a = control
        .a
        .boundary_history(&history, 3, &pinned(&control.a), &mode())
        .unwrap();
    let b = control
        .b
        .boundary_history(&history, 3, &pinned(&control.b), &mode())
        .unwrap();
    assert_eq!(common_history_prefix(&a, &b), 0);
    assert_eq!(
        check_continuation(&a, &b, 1),
        Err(ReuseRefusal::HistoryDiverged { position: 0 })
    );
    // The verified pair shares its first six operators, so its histories at that
    // boundary are equal until the generated tokens differ.
    let verified = family(PrototypePair::VerifiedSharedPrefix);
    let a = verified
        .a
        .boundary_history(&[5, 6, 7, 8], 6, &pinned(&verified.a), &mode())
        .unwrap();
    let b = verified
        .b
        .boundary_history(&[5, 6, 7, 9], 6, &pinned(&verified.b), &mode())
        .unwrap();
    assert_eq!(common_history_prefix(&a, &b), 3);
    // At the head the adapter and the head weights already differ.
    let a = verified
        .a
        .boundary_history(&[5, 6], 8, &pinned(&verified.a), &mode())
        .unwrap();
    let b = verified
        .b
        .boundary_history(&[5, 6], 8, &pinned(&verified.b), &mode())
        .unwrap();
    assert_eq!(common_history_prefix(&a, &b), 0);
}

#[test]
fn kernel_or_batching_choices_that_break_exactness_take_the_normal_path() {
    let input = ExactInput::whole(&tokens(8, 1)).unwrap();
    let nondeterministic =
        edited_base(|d| d.profile.determinism = KernelDeterminism::NonDeterministic);
    assert_eq!(
        nondeterministic
            .state_keys(&input, &pinned(&nondeterministic), &mode(), 1)
            .unwrap_err(),
        ReuseRefusal::NondeterministicKernels
    );
    let batch_dependent = edited_base(|d| d.profile.batching = BatchDependence::BatchDependent);
    assert_eq!(
        batch_dependent
            .state_keys(&input, &pinned(&batch_dependent), &mode(), 1)
            .unwrap_err(),
        ReuseRefusal::BatchDependentKernels
    );
    let variant = base();
    let autotuned = RuntimeChoices::pinned(VersionedName::new("autotuned", "1").unwrap());
    assert_eq!(
        variant
            .state_keys(&input, &autotuned, &mode(), 1)
            .unwrap_err(),
        ReuseRefusal::KernelChoiceDiffers
    );
    assert_eq!(check_exact_execution(&variant, &pinned(&variant)), Ok(()));
    // The same refusals stop the contract, so the request runs the normal path.
    let request = request(&batch_dependent, &alice(), &tokens(8, 1));
    let boundary = boundary_for(
        &batch_dependent,
        &edited_base(|d| {
            d.profile.batching = BatchDependence::BatchDependent;
            d.operators.push(d.operators[7].clone());
        }),
        8,
    );
    assert_eq!(
        produce_state(
            &batch_dependent,
            &request,
            &boundary,
            crate::foundation::ids::ContentKey::of(b"x")
        )
        .unwrap_err(),
        ReuseRefusal::BatchDependentKernels
    );
}

#[test]
fn approximate_reuse_is_a_separate_mode_and_is_refused() {
    let approximate = ExactnessCriterion::Approximate {
        quality_contract: Digest::from_bytes([9; 32]),
    };
    assert_eq!(
        ReuseMode::new(&approximate, &FidelityConfiguration::exact_reuse()).unwrap_err(),
        ReuseRefusal::ApproximateReuseIsSeparateMode
    );
    // Even a configuration that allows approximate inference does not open it here.
    let allows_approximation = FidelityConfiguration::approximate_inference(BTreeMap::from([(
        Approximation::PrecisionReduction {
            from: Dtype::Float32,
            to: Dtype::BFloat16,
        },
        AccuracyEvaluation {
            report: Digest::from_bytes([8; 32]),
        },
    )]))
    .unwrap();
    assert_eq!(
        ReuseMode::new(&approximate, &allows_approximation).unwrap_err(),
        ReuseRefusal::ApproximateReuseIsSeparateMode
    );
    assert_eq!(
        ReuseMode::new(&ExactnessCriterion::BitIdentical, &allows_approximation)
            .unwrap()
            .category(),
        FidelityCategory::ApproximateInference
    );
    assert_eq!(
        ReuseMode::new(
            &ExactnessCriterion::BitIdentical,
            &FidelityConfiguration::lossless_representation()
        )
        .unwrap_err(),
        ReuseRefusal::FidelityForbidsReuse {
            configured: FidelityCategory::LosslessRepresentation
        }
    );
    // The contract refuses an approximate request before anything else.
    let verified = family(PrototypePair::VerifiedSharedPrefix);
    let mut approximate_request = request(&verified.a, &alice(), &tokens(8, 1));
    approximate_request.exactness = approximate;
    let boundary = boundary_for(&verified.a, &verified.b, 8);
    assert_eq!(
        produce_state(
            &verified.a,
            &approximate_request,
            &boundary,
            crate::foundation::ids::ContentKey::of(b"x")
        )
        .unwrap_err(),
        ReuseRefusal::ApproximateReuseIsSeparateMode
    );
}
