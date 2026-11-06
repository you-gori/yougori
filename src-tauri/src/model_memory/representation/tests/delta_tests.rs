//! §4.2 XOR delta versions: bit-exact reconstruction on real bytes, the depth bound,
//! required base availability, comparison with independent compression and the
//! abandonment decision.

use super::super::delta::*;
use super::*;

fn store(max_depth: u32) -> DeltaStore {
    DeltaStore::new(DeltaLimits::new(max_depth, 3).unwrap())
}

const FAST_LOCAL: ColdRecoveryCost = ColdRecoveryCost {
    read_bytes_per_second: 3.0e9,
    decode_raw_bytes_per_second: 1.0e9,
    xor_bytes_per_second: 10.0e9,
};

#[test]
fn versions_reconstruct_bit_exactly_through_a_chain() {
    let base_bytes = bf16_weights(1, 16_384, 0.02);
    let v1 = fine_tune(&base_bytes, 2, 0.01);
    let v2 = fine_tune(&v1, 3, 0.01);
    let mut deltas = store(2);
    let base = deltas.add_base(&base_bytes).unwrap();
    let k1 = deltas.add_version(Parent::Base(base), &v1).unwrap();
    let k2 = deltas.add_version(Parent::Version(k1), &v2).unwrap();
    assert_eq!(deltas.depth(&k1), Some(1));
    assert_eq!(deltas.depth(&k2), Some(2));
    assert_eq!(deltas.reconstruct(&k1).unwrap(), v1);
    assert_eq!(deltas.reconstruct(&k2).unwrap(), v2);
    assert_eq!(deltas.dependents(&base), 2);
}

#[test]
fn every_bf16_pattern_survives_a_delta_against_another_ordering() {
    let patterns = all_bf16_patterns();
    let reversed: Vec<u8> = patterns
        .chunks(2)
        .rev()
        .flat_map(|pair| [pair[0], pair[1]])
        .collect();
    let mut deltas = store(1);
    let base = deltas.add_base(&reversed).unwrap();
    let version = deltas.add_version(Parent::Base(base), &patterns).unwrap();
    assert_eq!(deltas.reconstruct(&version).unwrap(), patterns);
}

#[test]
fn the_depth_bound_is_enforced() {
    assert_eq!(DeltaLimits::new(0, 3), Err(DeltaError::ZeroDepthBound));
    let base_bytes = bf16_weights(4, 1024, 0.02);
    let v1 = fine_tune(&base_bytes, 5, 0.01);
    let v2 = fine_tune(&v1, 6, 0.01);
    let mut deltas = store(1);
    let base = deltas.add_base(&base_bytes).unwrap();
    let k1 = deltas.add_version(Parent::Base(base), &v1).unwrap();
    assert_eq!(
        deltas.add_version(Parent::Version(k1), &v2),
        Err(DeltaError::DepthExceeded {
            depth: 2,
            max_depth: 1
        })
    );
    // A delta against the base directly stays within the bound.
    assert!(deltas.add_version(Parent::Base(base), &v2).is_ok());
}

#[test]
fn reconstruction_requires_the_base() {
    let base_bytes = bf16_weights(7, 2048, 0.02);
    let v1 = fine_tune(&base_bytes, 8, 0.01);
    let v2 = fine_tune(&base_bytes, 9, 0.01);
    let mut deltas = store(2);
    let base = deltas.add_base(&base_bytes).unwrap();
    let k1 = deltas.add_version(Parent::Base(base), &v1).unwrap();
    deltas.set_base_available(&base, false).unwrap();
    assert_eq!(
        deltas.reconstruct(&k1),
        Err(DeltaError::BaseUnavailable { base })
    );
    assert_eq!(
        deltas.add_version(Parent::Base(base), &v2),
        Err(DeltaError::BaseUnavailable { base })
    );
    assert_eq!(
        deltas.add_version(Parent::Version(k1), &v2),
        Err(DeltaError::BaseUnavailable { base })
    );
    // An unavailable base makes the chain fragile: abandoned.
    match deltas.decide(&k1, &FAST_LOCAL).unwrap() {
        DeltaDecision::Abandon(reasons) => {
            assert!(reasons.contains(&AbandonReason::BaseUnavailable))
        }
        DeltaDecision::Keep => panic!("a chain without its base is fragile"),
    }
    deltas.set_base_available(&base, true).unwrap();
    assert_eq!(deltas.reconstruct(&k1).unwrap(), v1);
}

#[test]
fn a_base_with_dependents_stays_pinned_and_present() {
    let base_bytes = bf16_weights(10, 1024, 0.02);
    let v1 = fine_tune(&base_bytes, 11, 0.01);
    let mut deltas = store(1);
    let base = deltas.add_base(&base_bytes).unwrap();
    assert_eq!(deltas.is_pinned(&base), Some(true));
    let _version = deltas.add_version(Parent::Base(base), &v1).unwrap();
    assert_eq!(
        deltas.unpin_base(&base),
        Err(DeltaError::BaseHasDependents {
            base,
            dependents: 1
        })
    );
    assert_eq!(
        deltas.remove_base(&base),
        Err(DeltaError::BaseHasDependents {
            base,
            dependents: 1
        })
    );
    // A base without dependents may be unpinned, and then takes no deltas.
    let other_bytes = bf16_weights(12, 1024, 0.02);
    let other = deltas.add_base(&other_bytes).unwrap();
    deltas.unpin_base(&other).unwrap();
    assert_eq!(
        deltas.add_version(Parent::Base(other), &fine_tune(&other_bytes, 13, 0.01)),
        Err(DeltaError::BaseNotPinned { base: other })
    );
    deltas.remove_base(&other).unwrap();
    assert_eq!(
        deltas.reconstruct(&other),
        Err(DeltaError::UnknownVersion { version: other })
    );
}

#[test]
fn malformed_versions_are_refused() {
    let base_bytes = bf16_weights(14, 1024, 0.02);
    let mut deltas = store(2);
    let base = deltas.add_base(&base_bytes).unwrap();
    assert_eq!(
        deltas.add_base(&base_bytes),
        Err(DeltaError::AlreadyStored { key: base })
    );
    assert_eq!(
        deltas.add_version(Parent::Base(base), &base_bytes[..1000]),
        Err(DeltaError::LengthMismatch {
            parent_bytes: 2048,
            version_bytes: 1000
        })
    );
    let unknown = crate::foundation::ids::ContentKey::of(b"nothing");
    assert_eq!(
        deltas.add_version(Parent::Version(unknown), &base_bytes),
        Err(DeltaError::AlreadyStored { key: base })
    );
    assert_eq!(
        deltas.add_version(Parent::Version(unknown), &fine_tune(&base_bytes, 15, 0.01)),
        Err(DeltaError::UnknownVersion { version: unknown })
    );
}

#[test]
fn a_dense_fine_tune_delta_is_smaller_and_an_unrelated_one_is_not() {
    let base_bytes = bf16_weights(16, 32_768, 0.02);
    let tuned = fine_tune(&base_bytes, 17, 0.01);
    let unrelated = bf16_weights(18, 32_768, 0.02);
    let mut deltas = store(1);
    let base = deltas.add_base(&base_bytes).unwrap();
    let tuned_key = deltas.add_version(Parent::Base(base), &tuned).unwrap();
    let unrelated_key = deltas.add_version(Parent::Base(base), &unrelated).unwrap();
    let tuned_cmp = deltas.compare(&tuned_key, &FAST_LOCAL).unwrap();
    let unrelated_cmp = deltas.compare(&unrelated_key, &FAST_LOCAL).unwrap();
    // Sign and exponent rarely change under a 1% fine-tune, so the XOR is mostly zero
    // high bytes.
    assert!(tuned_cmp.delta_stored_bytes < tuned_cmp.independent_stored_bytes);
    assert!(unrelated_cmp.delta_stored_bytes >= unrelated_cmp.independent_stored_bytes);
    assert_eq!(tuned_cmp.objects_needed, 2);
    assert_eq!(tuned_cmp.version_bytes, 65_536);
}

#[test]
fn the_recovery_formula_and_the_abandonment_decision_are_computed() {
    let base_bytes = bf16_weights(19, 32_768, 0.02);
    let tuned = fine_tune(&base_bytes, 20, 0.01);
    let mut deltas = store(1);
    let base = deltas.add_base(&base_bytes).unwrap();
    let key = deltas.add_version(Parent::Base(base), &tuned).unwrap();
    let cost = ColdRecoveryCost {
        read_bytes_per_second: 1.0e6,
        decode_raw_bytes_per_second: 2.0e6,
        xor_bytes_per_second: 4.0e6,
    };
    let comparison = deltas.compare(&key, &cost).unwrap();
    let size = 65_536.0;
    let expected_delta =
        comparison.chain_read_bytes as f64 / 1.0e6 + 2.0 * size / 2.0e6 + size / 4.0e6;
    let expected_independent = comparison.independent_stored_bytes as f64 / 1.0e6 + size / 2.0e6;
    assert!((comparison.delta_recovery_seconds - expected_delta).abs() < 1e-12);
    assert!((comparison.independent_recovery_seconds - expected_independent).abs() < 1e-12);
    assert!(comparison.chain_read_bytes > comparison.delta_stored_bytes);
    // Reading the base as well makes cold recovery slower: abandoned, though smaller.
    assert_eq!(
        deltas.decide(&key, &cost).unwrap(),
        DeltaDecision::Abandon(vec![AbandonReason::SlowerColdRecovery])
    );
    // Invalid rates are refused.
    assert!(deltas
        .compare(
            &key,
            &ColdRecoveryCost {
                read_bytes_per_second: 0.0,
                ..cost
            }
        )
        .is_err());
}
