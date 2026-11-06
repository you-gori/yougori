//! VM §2.3: statistical claims have narrow scope.
//!
//! With zero failures in N independent Bernoulli trials drawn from a fixed distribution,
//! a one-sided 95% upper bound on the failure probability is `p_upper = 1 − 0.05^(1/N)`.
//! The bound covers that distribution only: never unknown adversarial exploits, and never
//! "escape is impossible". Duplicated cases are not independent evidence, so trials are
//! counted once per case identity. `foundation::report` has no zero-failure bound (it has
//! the Wilson interval, which is two-sided and different), so it is computed here; rates
//! and their uncertainty reuse report's [`SuccessRate`] and Wilson interval.

use std::collections::BTreeMap;

use serde::Serialize;

use super::ModelError;
use crate::foundation::ids::{Digest, DigestBuilder};
use crate::foundation::report::{ConfidenceLevel, Provenance, Ratio, SuccessRate, WilsonInterval};

/// The significance of the zero-failure bound: a one-sided 95% upper bound.
pub const ZERO_FAILURE_ALPHA: f64 = 0.05;

/// Domain of [`case_identity`].
pub const CASE_IDENTITY_DOMAIN: &str = "yougori/sandbox/models/case/v1";

/// `p_upper = 1 − 0.05^(1/N)` for zero failures in `trials` independent trials (§2.3).
pub fn zero_failure_upper_bound(trials: u64) -> Result<f64, ModelError> {
    if trials == 0 {
        return Err(ModelError::NoTrials);
    }
    // 1 − e^(ln 0.05 / N), with exp_m1 for accuracy when N is large.
    Ok(-(ZERO_FAILURE_ALPHA.ln() / trials as f64).exp_m1())
}

/// The fewest independent zero-failure trials whose bound is at most `target`.
pub fn trials_for_upper_bound(target: f64) -> Result<u64, ModelError> {
    if !(target > 0.0 && target < 1.0) {
        return Err(ModelError::InvalidTarget);
    }
    let estimate = (ZERO_FAILURE_ALPHA.ln() / (-target).ln_1p()).ceil();
    let mut trials = if estimate.is_finite() && estimate >= 1.0 {
        estimate as u64
    } else {
        1
    };
    while zero_failure_upper_bound(trials)? > target {
        trials += 1;
    }
    while trials > 1 && zero_failure_upper_bound(trials - 1)? <= target {
        trials -= 1;
    }
    Ok(trials)
}

/// The identity of a test case: a digest of its canonical description, so two runs of the
/// same case share it.
pub fn case_identity(canonical: &[u8]) -> Digest {
    DigestBuilder::new(CASE_IDENTITY_DOMAIN)
        .bytes(canonical)
        .finish()
}

/// One executed test case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TrialRecord {
    pub case: Digest,
    pub failed: bool,
}

/// Trials counted once per distinct case (§2.3: duplicated cases are not independent
/// evidence). A case that failed in any run counts as failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct IndependentTrials {
    pub cases: u64,
    pub failed_cases: u64,
    pub duplicates_excluded: u64,
}

impl IndependentTrials {
    pub fn from_records(records: &[TrialRecord]) -> Self {
        let mut by_case: BTreeMap<Digest, bool> = BTreeMap::new();
        for record in records {
            *by_case.entry(record.case).or_insert(false) |= record.failed;
        }
        let cases = by_case.len() as u64;
        Self {
            cases,
            failed_cases: by_case.values().filter(|failed| **failed).count() as u64,
            duplicates_excluded: records.len() as u64 - cases,
        }
    }

    /// The zero-failure bound over the distinct cases; refused with any failure or none.
    pub fn zero_failure_bound(&self) -> Result<ZeroFailureBound, ModelError> {
        if self.failed_cases > 0 {
            return Err(ModelError::FailuresObserved {
                failures: self.failed_cases,
            });
        }
        Ok(ZeroFailureBound {
            trials: self.cases,
            upper: zero_failure_upper_bound(self.cases)?,
        })
    }

    /// Passing cases over distinct cases, as report's success rate.
    pub fn pass_rate(&self) -> Result<SuccessRate, ModelError> {
        Ok(SuccessRate::new(
            self.cases - self.failed_cases,
            self.cases,
        )?)
    }

    /// The failure proportion with its two-sided 95% Wilson interval (report's binomial
    /// interval applied to failures).
    pub fn failure_interval(&self) -> Result<WilsonInterval, ModelError> {
        Ok(SuccessRate::new(self.failed_cases, self.cases)?.wilson(ConfidenceLevel::NinetyFive))
    }
}

/// A zero-failure bound on one fixed case distribution.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct ZeroFailureBound {
    trials: u64,
    upper: f64,
}

impl ZeroFailureBound {
    pub fn trials(&self) -> u64 {
        self.trials
    }

    pub fn upper(&self) -> f64 {
        self.upper
    }

    /// Always false: the bound is about the tested distribution only (§2.3).
    pub const fn covers_unknown_adversarial_exploits(&self) -> bool {
        false
    }

    /// The bound in words, with its scope.
    pub fn statement(&self) -> String {
        format!(
            "zero failures in {} independent cases from a fixed distribution bound that \
             distribution's failure probability below {:.4}% (one-sided 95%); this does not \
             bound unknown adversarial exploits and is not a claim that escape cannot happen",
            self.trials,
            self.upper * 100.0
        )
    }
}

/// A pass rate reported beside mutation coverage, attack-case diversity and residual
/// assumptions (§2.3 line 1785).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PassRateReport {
    pass_rate: SuccessRate,
    mutation_coverage: Ratio,
    case_classes: u64,
    residual_assumptions: Vec<String>,
}

impl PassRateReport {
    /// Refuses a report without residual assumptions, with an empty mutation set, or
    /// with more case classes than cases.
    pub fn new(
        trials: &IndependentTrials,
        mutation_coverage: Ratio,
        case_classes: u64,
        residual_assumptions: Vec<String>,
    ) -> Result<Self, ModelError> {
        if residual_assumptions
            .iter()
            .all(|assumption| assumption.trim().is_empty())
        {
            return Err(ModelError::MissingResidualAssumptions);
        }
        if mutation_coverage.denominator() == 0 || case_classes == 0 || case_classes > trials.cases
        {
            return Err(ModelError::InvalidRatio);
        }
        Ok(Self {
            pass_rate: trials.pass_rate()?,
            mutation_coverage,
            case_classes,
            residual_assumptions,
        })
    }

    pub fn pass_rate(&self) -> SuccessRate {
        self.pass_rate
    }

    pub fn statement(&self) -> String {
        format!(
            "{} of {} distinct cases passed across {} case classes; {} of {} mutations \
             detected; residual assumptions: {}; zero observed failures are not escape \
             impossibility",
            self.pass_rate.successes(),
            self.pass_rate.attempts(),
            self.case_classes,
            self.mutation_coverage.numerator(),
            self.mutation_coverage.denominator(),
            self.residual_assumptions.join("; ")
        )
    }
}

/// A failure-rate measurement on one corpus, with its provenance.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FailureRateMeasurement {
    pub corpus: Digest,
    pub trials: IndependentTrials,
    pub provenance: Provenance,
}

/// The uncertainty of both sides of a risk-reduction comparison (§2.3: "needs a
/// comparable baseline and uncertainty for both measurements"). Refuses a missing
/// baseline, different corpora and anything but Yougori measurements; it computes no
/// reduction factor.
pub fn reduction_prerequisites(
    baseline: Option<&FailureRateMeasurement>,
    candidate: &FailureRateMeasurement,
) -> Result<(WilsonInterval, WilsonInterval), ModelError> {
    let baseline = baseline.ok_or(ModelError::MissingBaseline)?;
    if baseline.corpus != candidate.corpus {
        return Err(ModelError::NotComparable);
    }
    baseline.provenance.yougori_evidence()?;
    candidate.provenance.yougori_evidence()?;
    Ok((
        baseline.trials.failure_interval()?,
        candidate.trials.failure_interval()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::report::{ReportError, RunRecord, RunSubstrate, RUN_RECORD_SAMPLE_JSON};

    fn approx(actual: f64, expected: f64, tolerance: f64) {
        assert!(
            (actual - expected).abs() <= tolerance,
            "{actual} vs {expected}"
        );
    }

    fn passing(cases: u64) -> Vec<TrialRecord> {
        (0..cases)
            .map(|case| TrialRecord {
                case: case_identity(&case.to_le_bytes()),
                failed: false,
            })
            .collect()
    }

    #[test]
    fn the_zero_failure_bound_is_one_minus_alpha_to_the_one_over_n() {
        approx(zero_failure_upper_bound(1).unwrap(), 0.95, 1e-12);
        approx(
            zero_failure_upper_bound(2).unwrap(),
            1.0 - 0.05f64.sqrt(),
            1e-12,
        );
        for trials in [10u64, 100, 1_000] {
            let direct = 1.0 - 0.05f64.powf(1.0 / trials as f64);
            approx(zero_failure_upper_bound(trials).unwrap(), direct, 1e-12);
        }
        assert_eq!(zero_failure_upper_bound(0), Err(ModelError::NoTrials));
    }

    #[test]
    fn about_three_thousand_trials_bound_failure_near_a_tenth_of_a_percent() {
        let bound = zero_failure_upper_bound(3_000).unwrap();
        approx(bound, 0.000_998_08, 1e-8);
        approx(bound, 0.001, 2e-6);
        // The exact count for 0.1% is 2,995 ("approximately 3,000").
        assert_eq!(trials_for_upper_bound(0.001).unwrap(), 2_995);
        assert!(zero_failure_upper_bound(2_994).unwrap() > 0.001);
        assert_eq!(trials_for_upper_bound(0.0), Err(ModelError::InvalidTarget));
        assert_eq!(trials_for_upper_bound(1.0), Err(ModelError::InvalidTarget));
    }

    #[test]
    fn duplicated_cases_are_counted_once_before_the_bound() {
        let mut records = passing(1_000);
        let repeated = records.clone();
        records.extend(repeated.iter().cloned());
        records.extend(repeated);
        let trials = IndependentTrials::from_records(&records);
        assert_eq!(trials.cases, 1_000);
        assert_eq!(trials.duplicates_excluded, 2_000);
        let bound = trials.zero_failure_bound().unwrap();
        assert_eq!(bound.trials(), 1_000);
        // The 3,000 records do not earn the 3,000-trial bound.
        assert!(bound.upper() > zero_failure_upper_bound(3_000).unwrap());
    }

    #[test]
    fn a_failure_in_any_run_of_a_case_refuses_the_zero_failure_bound() {
        let mut records = passing(10);
        records.push(TrialRecord {
            case: records[3].case,
            failed: true,
        });
        let trials = IndependentTrials::from_records(&records);
        assert_eq!(trials.failed_cases, 1);
        assert_eq!(
            trials.zero_failure_bound(),
            Err(ModelError::FailuresObserved { failures: 1 })
        );
        assert_eq!(trials.pass_rate().unwrap().successes(), 9);
    }

    #[test]
    fn the_bound_never_covers_unknown_exploits_or_claims_impossibility() {
        let bound = IndependentTrials::from_records(&passing(3_000))
            .zero_failure_bound()
            .unwrap();
        assert!(!bound.covers_unknown_adversarial_exploits());
        let statement = bound.statement();
        assert!(statement.contains("does not bound unknown adversarial exploits"));
        assert!(!statement.contains("impossible"));
    }

    #[test]
    fn a_pass_rate_needs_coverage_diversity_and_residual_assumptions() {
        let trials = IndependentTrials::from_records(&passing(20));
        let coverage = Ratio::new(7, 9).unwrap();
        assert_eq!(
            PassRateReport::new(&trials, coverage, 4, vec![]),
            Err(ModelError::MissingResidualAssumptions)
        );
        assert_eq!(
            PassRateReport::new(&trials, Ratio::new(0, 0).unwrap(), 4, vec!["kernel".into()]),
            Err(ModelError::InvalidRatio)
        );
        let report = PassRateReport::new(
            &trials,
            coverage,
            4,
            vec!["host kernel and hypervisor are trusted".into()],
        )
        .unwrap();
        assert!(report.statement().contains("7 of 9 mutations"));
        assert!(report.statement().contains("not escape impossibility"));
    }

    #[test]
    fn a_reduction_claim_needs_a_comparable_measured_baseline() {
        let fake = {
            let mut record: RunRecord = serde_json::from_str(RUN_RECORD_SAMPLE_JSON).unwrap();
            record.substrate = RunSubstrate::FakeTimeControlled;
            Provenance::of_records(&[record]).unwrap()
        };
        let corpus = case_identity(b"corpus");
        let measurement = FailureRateMeasurement {
            corpus,
            trials: IndependentTrials::from_records(&passing(50)),
            provenance: fake,
        };
        assert_eq!(
            reduction_prerequisites(None, &measurement),
            Err(ModelError::MissingBaseline)
        );
        let other = FailureRateMeasurement {
            corpus: case_identity(b"other corpus"),
            ..measurement.clone()
        };
        assert_eq!(
            reduction_prerequisites(Some(&other), &measurement),
            Err(ModelError::NotComparable)
        );
        assert_eq!(
            reduction_prerequisites(Some(&measurement), &measurement),
            Err(ModelError::Report(ReportError::FakeSubstrateIsNotEvidence))
        );
    }
}
