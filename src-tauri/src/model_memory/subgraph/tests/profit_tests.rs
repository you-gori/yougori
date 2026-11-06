//! The line 890 cost model on worked numbers.
//!
//! Eight operators of 2 µs per token and 8000 activation bytes per token, a request of
//! 1000 tokens: recomputation costs 8 × 2 µs × 1000 = 0.016 s and the boundary state is
//! 8,000,000 bytes. A verified copy at 25 GB/s transfer and 4 GB/s hashing costs
//! 0.00032 s + 0.002 s; with 10 µs keying the net saving for one consumer is
//! 0.016 − 0.00233 = 0.01367 s.

use super::*;
use crate::model_memory::math::InputError;

const TOKENS: u64 = 1000;

fn costs() -> Vec<OperatorCost> {
    vec![
        OperatorCost {
            compute_seconds_per_token: 2e-6,
            activation_bytes_per_token: 8_000,
            kv_bytes_per_token: 4_000,
        };
        8
    ]
}

fn verified(hash_bytes_per_second: f64) -> HandoffCosts {
    HandoffCosts {
        keying_seconds: 1e-5,
        lookup_seconds: 0.0,
        handoff: StateHandoff::Verified {
            transfer_bytes_per_second: 2.5e10,
            hash_bytes_per_second,
        },
    }
}

fn close(left: f64, right: f64) -> bool {
    (left - right).abs() < 1e-12
}

fn estimate_of(economics: &BoundaryEconomics) -> ProfitEstimate {
    estimate(economics).unwrap()
}

fn economics(boundary: usize, consumers: f64, handoff: HandoffCosts) -> BoundaryEconomics {
    BoundaryEconomics::from_costs(&costs(), boundary, TOKENS, consumers, handoff).unwrap()
}

#[test]
fn the_worked_boundary_is_profitable() {
    let economics = economics(8, 1.0, verified(4e9));
    assert!(close(economics.recompute_seconds, 0.016));
    assert_eq!(economics.activation_bytes, 8_000_000);
    let estimate = estimate(&economics).unwrap();
    assert!(close(estimate.saving_seconds, 0.016));
    assert!(close(estimate.cost_seconds, 0.00233));
    assert!(close(estimate.net_seconds, 0.01367));
    assert!(estimate.is_profitable());
}

#[test]
fn slow_hashing_makes_the_same_boundary_unprofitable() {
    // 8,000,000 bytes at 0.5 GB/s take 0.016 s, as much as recomputing.
    let estimate = estimate(&economics(8, 1.0, verified(5e8))).unwrap();
    assert!(close(estimate.cost_seconds, 0.01633));
    assert!(close(estimate.net_seconds, -0.00033));
    assert!(!estimate.is_profitable());
}

#[test]
fn a_short_shared_prefix_is_not_worth_a_verified_copy() {
    // One operator saves 0.002 s but the copy still costs 0.00233 s.
    let estimate = estimate(&economics(1, 1.0, verified(4e9))).unwrap();
    assert!(close(estimate.saving_seconds, 0.002));
    assert!(close(estimate.net_seconds, -0.00033));
    // In place, the same boundary costs only keying and lookup: 20 µs.
    let in_place = HandoffCosts {
        keying_seconds: 1e-5,
        lookup_seconds: 1e-5,
        handoff: StateHandoff::InPlace,
    };
    let in_place = estimate_of(&economics(1, 1.0, in_place));
    assert!(close(in_place.cost_seconds, 2e-5));
    assert!(close(in_place.net_seconds, 0.00198));
}

#[test]
fn expected_consumers_scale_the_saving_and_the_per_consumer_cost() {
    // 0.1 consumers: saving 0.0016 s, cost 10 µs + 0.1 × 0.00232 s.
    let estimate = estimate(&economics(8, 0.1, verified(4e9))).unwrap();
    assert!(close(estimate.saving_seconds, 0.0016));
    assert!(close(estimate.cost_seconds, 0.000242));
    assert!(estimate.is_profitable());
    // Nobody to consume the state: keying alone makes it a loss.
    let idle = estimate_of(&economics(8, 0.0, verified(4e9)));
    assert!(close(idle.net_seconds, -1e-5));
    assert!(!idle.is_profitable());
}

#[test]
fn hashing_every_operation_costs_more_than_recomputing() {
    // Eight activations of 8,000,000 bytes at 4 GB/s: 8 × 0.002 s = 0.016 s, plus 8 ×
    // 10 µs keying, against 0.016 s of recomputation.
    let estimate = hash_every_operation(&costs(), 8, TOKENS, 4e9, 1e-5).unwrap();
    assert!(close(estimate.saving_seconds, 0.016));
    assert!(close(estimate.cost_seconds, 0.01608));
    assert!(!estimate.is_profitable());
    assert_eq!(
        hash_every_operation(&costs(), 0, TOKENS, 4e9, 1e-5).unwrap_err(),
        ProfitError::BoundaryOutOfRange {
            boundary: 0,
            operators: 8
        }
    );
}

#[test]
fn caching_is_allowed_only_at_the_profitable_branch_boundary() {
    let verified_pair = family(PrototypePair::VerifiedSharedPrefix);
    let prefix = discover_shared_prefix(&verified_pair.a, &verified_pair.b);
    let in_place = HandoffCosts {
        keying_seconds: 1e-5,
        lookup_seconds: 1e-5,
        handoff: StateHandoff::InPlace,
    };
    let planned = plan_boundary(&prefix, 6, &economics(6, 1.0, in_place)).unwrap();
    assert_eq!(planned.operators(), 6);
    assert_eq!(planned.variants(), prefix.variants());
    assert!(close(planned.estimate().net_seconds, 0.012 - 2e-5));
    // Any other operator, even a profitable one inside the shared prefix, is refused.
    assert_eq!(
        plan_boundary(&prefix, 3, &economics(3, 1.0, in_place)).unwrap_err(),
        CacheRefusal::NotABranchBoundary {
            requested: 3,
            branch: 6
        }
    );
    assert_eq!(
        plan_boundary(&prefix, 6, &economics(5, 1.0, in_place)).unwrap_err(),
        CacheRefusal::EconomicsForAnotherBoundary {
            requested: 6,
            economics: 5
        }
    );
    assert!(matches!(
        plan_boundary(&prefix, 6, &economics(6, 1.0, verified(5e7))).unwrap_err(),
        CacheRefusal::Unprofitable(estimate) if estimate.net_seconds < 0.0
    ));
    let control = family(PrototypePair::ControlFirstBlockDiffers);
    let nothing = discover_shared_prefix(&control.a, &control.b);
    assert_eq!(
        plan_boundary(&nothing, 6, &economics(6, 1.0, in_place)).unwrap_err(),
        CacheRefusal::NothingShared
    );
    let same = discover_shared_prefix(&control.a, &control.a);
    assert_eq!(
        plan_boundary(&same, 8, &economics(8, 1.0, in_place)).unwrap_err(),
        CacheRefusal::NoBranch
    );
}

#[test]
fn invalid_cost_inputs_are_refused_not_clamped() {
    assert_eq!(
        BoundaryEconomics::from_costs(&costs(), 9, TOKENS, 1.0, verified(4e9)).unwrap_err(),
        ProfitError::BoundaryOutOfRange {
            boundary: 9,
            operators: 8
        }
    );
    assert_eq!(
        BoundaryEconomics::from_costs(&costs(), 0, TOKENS, 1.0, verified(4e9)).unwrap_err(),
        ProfitError::BoundaryOutOfRange {
            boundary: 0,
            operators: 8
        }
    );
    assert_eq!(
        estimate(&economics(8, -1.0, verified(4e9))).unwrap_err(),
        InputError::Negative {
            field: "expected_consumers"
        }
    );
    assert_eq!(
        estimate(&economics(8, 1.0, verified(0.0))).unwrap_err(),
        InputError::NotPositive {
            field: "hash_bytes_per_second"
        }
    );
    assert_eq!(
        estimate(&economics(8, f64::NAN, verified(4e9))).unwrap_err(),
        InputError::NotFinite {
            field: "expected_consumers"
        }
    );
    let mut huge = costs();
    huge[7].activation_bytes_per_token = u64::MAX;
    assert_eq!(
        BoundaryEconomics::from_costs(&huge, 8, TOKENS, 1.0, verified(4e9)).unwrap_err(),
        ProfitError::Input(InputError::Overflow {
            field: "activation bytes"
        })
    );
}
