use super::*;
use crate::model_memory::math::test_support::close;

#[test]
fn brier_score_and_reliability_bins() {
    let mut tracker = CalibrationTracker::new(10).unwrap();
    assert_eq!(tracker.brier_score(), None);
    assert_eq!(tracker.expected_calibration_error(), None);
    for (p, used) in [(0.9, true), (0.9, true), (0.1, false), (0.1, true)] {
        tracker.record(p, used).unwrap();
    }
    assert_eq!(tracker.count(), 4);
    // ((0.1)^2 + (0.1)^2 + (0.1)^2 + (0.9)^2) / 4
    assert!(close(tracker.brier_score().unwrap(), 0.21, 1e-12));

    let bins = tracker.reliability_bins();
    assert_eq!(bins.len(), 2);
    assert_eq!(bins[0].count, 2);
    assert!(close(bins[0].lower, 0.1, 1e-12) && close(bins[0].upper, 0.2, 1e-12));
    assert!(close(bins[0].mean_predicted, 0.1, 1e-12));
    assert_eq!(bins[0].observed_frequency, 0.5);
    assert!(close(bins[1].mean_predicted, 0.9, 1e-12));
    assert_eq!(bins[1].observed_frequency, 1.0);
    // (2/4)|0.1 - 0.5| + (2/4)|0.9 - 1.0|
    assert!(close(
        tracker.expected_calibration_error().unwrap(),
        0.25,
        1e-12
    ));

    tracker.record(1.0, true).unwrap();
    assert_eq!(
        tracker.reliability_bins().last().map(|bin| bin.count),
        Some(3)
    );
    assert!(tracker.record(1.01, true).is_err());
    assert!(tracker.record(f64::NAN, true).is_err());
    assert!(CalibrationTracker::new(0).is_err());
}

#[test]
fn a_calibrated_predictor_has_no_calibration_error() {
    let mut tracker = CalibrationTracker::new(5).unwrap();
    for index in 0..10 {
        tracker.record(0.3, index < 3).unwrap();
    }
    assert!(close(
        tracker.expected_calibration_error().unwrap(),
        0.0,
        1e-12
    ));
    assert!(close(tracker.brier_score().unwrap(), 0.21, 1e-12));
}

const THRESHOLDS: ModeThresholds = ModeThresholds {
    enter_below_confidence: 0.5,
    exit_at_confidence: 0.7,
    enter_above_load_fraction: 0.9,
    exit_at_load_fraction: 0.7,
    enter_above_calibration_error: 0.15,
    exit_at_calibration_error: 0.05,
    recovery_dwell: Duration::from_secs(5),
};

const HEALTHY: ModeSignals = ModeSignals {
    confidence: 0.9,
    load_fraction: 0.2,
    calibration_error: 0.01,
};

fn at(seconds: u64) -> MonotonicTime {
    MonotonicTime::from_nanos(seconds * 1_000_000_000)
}

#[test]
fn low_confidence_overload_or_drift_switch_to_demand_only() {
    let cases = [
        (
            ModeSignals {
                confidence: 0.4,
                ..HEALTHY
            },
            DemandOnlyReason::LowConfidence,
        ),
        (
            ModeSignals {
                load_fraction: 1.2,
                ..HEALTHY
            },
            DemandOnlyReason::Overload,
        ),
        (
            ModeSignals {
                calibration_error: 0.3,
                ..HEALTHY
            },
            DemandOnlyReason::Drift,
        ),
    ];
    for (signals, reason) in cases {
        let mut controller = ModeController::new(THRESHOLDS).unwrap();
        assert_eq!(
            controller.observe(at(0), HEALTHY),
            Ok(SchedulingMode::Speculative)
        );
        assert_eq!(
            controller.observe(at(1), signals),
            Ok(SchedulingMode::DemandOnly)
        );
        assert_eq!(controller.reason(), Some(reason));
    }
}

#[test]
fn the_fallback_returns_only_after_a_healthy_dwell_and_does_not_flap() {
    let mut controller = ModeController::new(THRESHOLDS).unwrap();
    let wobble = |confidence: f64| ModeSignals {
        confidence,
        ..HEALTHY
    };
    // Inside the band while speculative: no switch.
    assert_eq!(
        controller.observe(at(0), wobble(0.6)),
        Ok(SchedulingMode::Speculative)
    );
    assert_eq!(
        controller.observe(at(1), wobble(0.49)),
        Ok(SchedulingMode::DemandOnly)
    );
    // Oscillating around the entry threshold stays demand-only.
    for (second, confidence) in [(2, 0.55), (3, 0.49), (4, 0.69), (5, 0.51)] {
        assert_eq!(
            controller.observe(at(second), wobble(confidence)),
            Ok(SchedulingMode::DemandOnly)
        );
    }
    // Healthy from 10 s, interrupted at 12 s, healthy again from 13 s.
    assert_eq!(
        controller.observe(at(10), HEALTHY),
        Ok(SchedulingMode::DemandOnly)
    );
    assert_eq!(
        controller.observe(at(12), wobble(0.6)),
        Ok(SchedulingMode::DemandOnly)
    );
    assert_eq!(
        controller.observe(at(13), HEALTHY),
        Ok(SchedulingMode::DemandOnly)
    );
    assert_eq!(
        controller.observe(at(17), HEALTHY),
        Ok(SchedulingMode::DemandOnly)
    );
    assert_eq!(
        controller.observe(at(18), HEALTHY),
        Ok(SchedulingMode::Speculative)
    );
    assert_eq!(controller.reason(), None);
    assert_eq!(controller.mode(), SchedulingMode::Speculative);

    assert_eq!(
        controller.observe(at(17), HEALTHY),
        Err(CalibrationError::ClockWentBack)
    );
    assert!(controller.observe(at(19), wobble(1.5)).is_err());
}

#[test]
fn thresholds_must_leave_a_hysteresis_band() {
    let no_confidence_band = ModeThresholds {
        exit_at_confidence: 0.5,
        ..THRESHOLDS
    };
    assert!(ModeController::new(no_confidence_band).is_err());
    let no_load_band = ModeThresholds {
        exit_at_load_fraction: 0.9,
        ..THRESHOLDS
    };
    assert!(ModeController::new(no_load_band).is_err());
    let no_drift_band = ModeThresholds {
        exit_at_calibration_error: 0.2,
        ..THRESHOLDS
    };
    assert!(ModeController::new(no_drift_band).is_err());
    let bad_probability = ModeThresholds {
        exit_at_confidence: 1.5,
        ..THRESHOLDS
    };
    assert!(ModeController::new(bad_probability).is_err());
}
