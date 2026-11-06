//! §4.6 lines 713–716: `finish_at_node` on worked numbers, uncertainty and the
//! stale-report penalty.

use crate::foundation::ids::MonotonicTime;
use crate::model_memory::math::InputError;

use super::super::estimate::*;
use super::support::*;

#[test]
fn finish_at_node_adds_the_four_terms_and_their_spreads() {
    // queue 2.0 ± 0.5 + preparation 0 + compute 1.5 ± 0.2 + tail 0.05 ± 0.01.
    let estimate_at_node = finish_at_node(FinishComponents {
        queue: estimate(2.0, 0.5),
        state_preparation_critical_path: SecondsEstimate::ZERO,
        request_compute: estimate(1.5, 0.2),
        client_network_tail: estimate(0.05, 0.01),
    });
    assert_close(estimate_at_node.finish.expected_seconds(), 3.55);
    assert_close(estimate_at_node.finish.uncertainty_seconds(), 0.71);
    assert_close(estimate_at_node.finish.upper_seconds(), 4.26);
    // One second of spread costs the risk weight in seconds.
    assert_close(estimate_at_node.finish.risk_adjusted_seconds(0.5), 3.905);
}

#[test]
fn parallel_terms_take_the_later_finish_and_upper_bound() {
    let both = estimate(2.0, 0.5).alongside(estimate(2.2, 0.1));
    assert_close(both.expected_seconds(), 2.2);
    assert_close(both.upper_seconds(), 2.5);
    let serial = estimate(2.0, 0.5).then(estimate(2.2, 0.1));
    assert_close(serial.expected_seconds(), 4.2);
    assert_close(serial.uncertainty_seconds(), 0.6);
}

#[test]
fn invalid_estimates_are_refused_not_clamped() {
    assert_eq!(
        SecondsEstimate::new(-0.1, 0.0),
        Err(InputError::Negative {
            field: "expected_seconds"
        })
    );
    assert_eq!(
        SecondsEstimate::new(1.0, f64::NAN),
        Err(InputError::NotFinite {
            field: "uncertainty_seconds"
        })
    );
    assert!(StalenessPolicy::new(0.1, 0.1, 0.0).is_err());
    assert!(StalenessPolicy::new(-0.1, 0.1, 5.0).is_err());
}

#[test]
fn a_stale_report_pays_a_penalty_growing_with_its_age() {
    let policy = StalenessPolicy::new(0.1, 0.05, 5.0).unwrap();
    let penalty = stale_penalty(&policy, seconds_ago(2.0), NOW).unwrap();
    assert_close(penalty.age_seconds, 2.0);
    assert_close(penalty.penalty_seconds, 0.2);
    assert_close(penalty.added_uncertainty_seconds, 0.1);
    let fresh = stale_penalty(&policy, NOW, NOW).unwrap();
    assert_eq!(fresh.penalty_seconds, 0.0);
}

#[test]
fn a_report_at_its_maximum_age_or_from_the_future_is_never_used() {
    let policy = StalenessPolicy::new(0.1, 0.05, 5.0).unwrap();
    assert!(matches!(
        stale_penalty(&policy, seconds_ago(5.0), NOW),
        Err(StaleRefusal::TooOld { .. })
    ));
    let later = MonotonicTime::from_nanos(NOW.as_nanos() + 1);
    assert_eq!(
        stale_penalty(&policy, later, NOW),
        Err(StaleRefusal::FromTheFuture {
            observed_at: later,
            now: NOW
        })
    );
}
