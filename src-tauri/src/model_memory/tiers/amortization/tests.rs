use std::time::Duration;

use super::*;
use crate::foundation::catalog::AmortizationError;
use crate::model_memory::tiers::fakes::{clock_at, close};

fn terms(uses: f64, saving: f64, preparation: f64, penalty: f64) -> ImportAmortization {
    ImportAmortization {
        expected_uses: uses,
        per_use_saving_seconds: saving,
        preparation_cost_seconds: preparation,
        retention_penalty_seconds: penalty,
    }
}

/// Uses at which saving equals cost: strictly more are needed.
fn break_even_uses(terms: &ImportAmortization) -> f64 {
    terms.total_cost_seconds().unwrap() / terms.per_use_saving_seconds
}

#[test]
fn raw_prepared_worked_example() {
    // Preparing a raw representation costs 120 s of the objective, each load from it saves
    // 8 s, and keeping it over the horizon costs 40 s: (120 + 40) / 8 = 20 uses.
    let at_break_even = terms(20.0, 8.0, 120.0, 40.0);
    assert_eq!(break_even_uses(&at_break_even), 20.0);
    assert_eq!(at_break_even.expected_saving_seconds(), Ok(160.0));
    assert_eq!(at_break_even.total_cost_seconds(), Ok(160.0));
    // The inequality is strict: 20 * 8 = 160 is not more than 120 + 40.
    assert_eq!(at_break_even.amortizes(), Ok(false));
    assert_eq!(terms(21.0, 8.0, 120.0, 40.0).amortizes(), Ok(true));
}

#[test]
fn compressed_and_host_copy_worked_examples() {
    // Compressed: 300 s to prepare, 2 s saved per use, 10 s retention penalty: 155 uses
    // break even, and 156 * 2 = 312 > 310.
    assert_eq!(break_even_uses(&terms(1.0, 2.0, 300.0, 10.0)), 155.0);
    assert_eq!(terms(155.0, 2.0, 300.0, 10.0).amortizes(), Ok(false));
    assert_eq!(terms(156.0, 2.0, 300.0, 10.0).amortizes(), Ok(true));
    // A host copy costs nothing to prepare beyond the read, saves 3 s per use, and RAM
    // costs 30 s over the horizon: 10 uses break even, 11 amortize.
    assert_eq!(terms(10.0, 3.0, 0.0, 30.0).amortizes(), Ok(false));
    assert_eq!(terms(11.0, 3.0, 0.0, 30.0).amortizes(), Ok(true));
    // A use that saves nothing never amortizes, however many are expected.
    assert_eq!(terms(1e12, 0.0, 1.0, 0.0).amortizes(), Ok(false));
    assert_eq!(terms(1e12, 0.0, 0.0, 0.0).amortizes(), Ok(false));
}

#[test]
fn invalid_terms_are_refused_not_clamped() {
    assert_eq!(
        terms(f64::NAN, 1.0, 1.0, 1.0).amortizes(),
        Err(AmortizationError::NotFinite {
            term: "expected_uses"
        })
    );
    assert_eq!(
        terms(1.0, 1.0, 1.0, -0.5).amortizes(),
        Err(AmortizationError::Negative {
            term: "retention_penalty_seconds"
        })
    );
}

#[test]
fn measured_reuse_extrapolates_the_observed_rate() {
    let clock = clock_at(0);
    let mut record = ReuseRecord::new(&clock);
    // Nothing is measured before time passes, so no uses are expected.
    let none = record.measured(14_400.0, &clock).unwrap();
    assert_eq!(none.expected_uses, 0.0);
    assert_eq!(none.per_use_saving_seconds, 0.0);

    for saved_seconds in [4.0, 6.0, 5.0, 5.0, 5.0, 5.0] {
        clock.advance(Duration::from_secs(1_200));
        record.record_use(saved_seconds, &clock).unwrap();
    }
    assert_eq!(record.uses(), 6);
    assert_eq!(record.last_used_at(), Some(clock.now()));
    // Six uses in two hours, over a four-hour horizon: twelve expected, 5 s each.
    let measured = record.measured(14_400.0, &clock).unwrap();
    assert_eq!(measured.uses_observed, 6);
    assert!(close(measured.observed_seconds, 7_200.0, 1e-9));
    assert!(close(measured.expected_uses, 12.0, 1e-9));
    assert!(close(measured.per_use_saving_seconds, 5.0, 1e-12));

    // The keep rule is line 550 on the measured figures: 12 * 5 = 60 against 30 + 20,
    // then against 30 + 30.
    assert_eq!(measured.amortization(30.0, 20.0).amortizes(), Ok(true));
    assert_eq!(measured.amortization(30.0, 30.0).amortizes(), Ok(false));

    // Idle time lowers the measured rate.
    clock.advance(Duration::from_secs(7_200));
    assert!(close(
        record.measured(14_400.0, &clock).unwrap().expected_uses,
        6.0,
        1e-9
    ));

    assert_eq!(
        record.record_use(-1.0, &clock),
        Err(InputError::Negative {
            field: "saved_seconds"
        })
    );
    assert_eq!(
        record.measured(0.0, &clock),
        Err(InputError::NotPositive {
            field: "horizon_seconds"
        })
    );
    assert_eq!(record.since(), MonotonicTime::ZERO);
}
