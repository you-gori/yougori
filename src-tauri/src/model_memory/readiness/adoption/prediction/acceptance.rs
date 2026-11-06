//! The predeclared acceptance rule for prediction (GPU-W06 acceptance, line 1249: "mixed
//! and adversarial traces improve or match the declared baseline under equal memory
//! budgets; p95/p99, wasted bytes and prediction calibration are reported. Do not accept
//! only alternating A/B results"; G05: "do not replace the scheduler solely on
//! alternating-model demonstrations").
//!
//! [`AcceptanceRule::PREDECLARED`] was fixed before any result was computed. The
//! candidate is a prediction-assisted policy; the declared baseline is the same eviction
//! policy demand-only ([`ReplayPolicy::matched_baseline`]), the ablation that removes
//! prediction. For each trace pattern the waits of every seed are pooled, each seed one
//! independent burst, and the candidate's nearest-rank p95 and p99 must not exceed the
//! baseline's by more than the rule's tolerance. The judgement is refused (not accepted,
//! with every reason) when a required pattern is missing, only alternating traces were
//! run, a pattern has too few seeds, the runs are not matched trace for trace under equal
//! budgets, a percentile has too little resolution under `foundation::report`'s rule, or
//! a percentile regressed. Wasted bytes, total waits and calibration are reported beside
//! it. Even an acceptance is an offline result on synthetic traces
//! ([`EvaluationLabel`]), not hardware validation.

use std::collections::BTreeMap;

use super::replay::{EvaluationLabel, ReplayBudget, ReplayPolicy, ReplayReport};
use super::traces::TraceKind;
use super::PredictionError;
use crate::foundation::report::{percentile, resolution, PercentileMethod, Quantile, Resolution};

const PPM: f64 = 1e6;

/// The acceptance rule (see the module documentation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptanceRule {
    /// How much the candidate's pooled p95 may exceed the baseline's, in parts per
    /// million of the baseline's.
    pub p95_tolerance_ppm: u32,
    pub p99_tolerance_ppm: u32,
    /// Patterns that must be judged.
    pub required: &'static [TraceKind],
    /// Independent seeds per judged pattern, at least.
    pub min_seeds: usize,
    /// Whether a percentile without `foundation::report` resolution blocks acceptance.
    pub require_resolution: bool,
}

impl AcceptanceRule {
    /// The rule declared before any result: p95 and p99 within 10 % of the matched
    /// demand-only baseline on every judged pattern, mixed and adversarial traces
    /// required, at least six seeds each, resolved percentiles only.
    pub const PREDECLARED: Self = Self {
        p95_tolerance_ppm: 100_000,
        p99_tolerance_ppm: 100_000,
        required: &[TraceKind::Mixed, TraceKind::AdversarialToMarkov],
        min_seeds: 6,
        require_resolution: true,
    };
}

/// How the candidate compares on one percentile or one pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatternVerdict {
    /// Lower than the baseline (on some percentile, and no regression).
    Improves,
    /// Not lower, and within the tolerance.
    Matches,
    /// Above the baseline by more than the tolerance.
    Regresses,
}

/// One percentile of one pattern, pooled over its seeds.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct QuantileComparison {
    pub quantile: Quantile,
    pub candidate_nanos: f64,
    pub baseline_nanos: f64,
    pub resolution: Resolution,
    pub verdict: PatternVerdict,
}

/// One pattern's comparison.
#[derive(Clone, Debug, PartialEq)]
pub struct PatternComparison {
    pub kind: TraceKind,
    pub seeds: usize,
    /// Requests pooled per policy.
    pub samples: u64,
    pub p95: QuantileComparison,
    pub p99: QuantileComparison,
    pub candidate_total_wait_nanos: u64,
    pub baseline_total_wait_nanos: u64,
    pub candidate_hits: u64,
    pub baseline_hits: u64,
    pub candidate_wasted_bytes: u64,
    pub candidate_prepared_bytes: u64,
    /// The Brier score of the candidate's forecasts over every seed.
    pub candidate_brier_score: Option<f64>,
    pub verdict: PatternVerdict,
}

/// Why the candidate is not accepted.
#[derive(Clone, Debug, PartialEq)]
pub enum NotAcceptedReason {
    MissingPattern {
        kind: TraceKind,
    },
    /// Only alternating traces were judged.
    AlternatingOnly,
    TooFewSeeds {
        kind: TraceKind,
        seeds: usize,
        needed: usize,
    },
    /// A seed of the pattern ran under one policy only, or under different budgets.
    Unmatched {
        kind: TraceKind,
        seed: u64,
    },
    LowResolution {
        kind: TraceKind,
        quantile: Quantile,
    },
    Regressed {
        kind: TraceKind,
        quantile: Quantile,
        candidate_nanos: f64,
        baseline_nanos: f64,
    },
}

/// The judgement.
#[derive(Clone, Debug, PartialEq)]
pub enum Acceptance {
    Accepted,
    NotAccepted { reasons: Vec<NotAcceptedReason> },
}

/// The rule applied to one candidate and its declared baseline.
#[derive(Clone, Debug, PartialEq)]
pub struct AcceptanceReport {
    pub label: EvaluationLabel,
    pub rule: AcceptanceRule,
    pub candidate: ReplayPolicy,
    pub baseline: ReplayPolicy,
    pub patterns: Vec<PatternComparison>,
    pub acceptance: Acceptance,
}

fn compare(
    quantile: Quantile,
    candidate: &[u64],
    baseline: &[u64],
    seeds: usize,
    tolerance_ppm: u32,
) -> Result<QuantileComparison, PredictionError> {
    let pooled = |waits: &[u64]| -> Result<f64, PredictionError> {
        let mut sorted = waits.to_vec();
        sorted.sort_unstable();
        Ok(percentile(
            &sorted,
            quantile,
            PercentileMethod::NearestRank,
        )?)
    };
    let candidate_nanos = pooled(candidate)?;
    let baseline_nanos = pooled(baseline)?;
    let tolerance = baseline_nanos * f64::from(tolerance_ppm) / PPM;
    let verdict = if candidate_nanos < baseline_nanos {
        PatternVerdict::Improves
    } else if candidate_nanos <= baseline_nanos + tolerance {
        PatternVerdict::Matches
    } else {
        PatternVerdict::Regresses
    };
    let samples = u64::try_from(candidate.len().min(baseline.len())).unwrap_or(u64::MAX);
    Ok(QuantileComparison {
        quantile,
        candidate_nanos,
        baseline_nanos,
        resolution: resolution(samples, u64::try_from(seeds).unwrap_or(u64::MAX), quantile),
        verdict,
    })
}

/// Applies `rule` to the `candidate` reports against the `baseline` reports, matched by
/// trace pattern and seed. Each side must hold one policy; otherwise the judgement is
/// refused.
pub fn judge(
    rule: &AcceptanceRule,
    candidate: &[ReplayReport],
    baseline: &[ReplayReport],
) -> Result<AcceptanceReport, PredictionError> {
    let policy_of = |reports: &[ReplayReport], field| -> Result<ReplayPolicy, PredictionError> {
        let first = reports.first().ok_or(PredictionError::InvalidConfig {
            field,
            reason: "no reports",
        })?;
        if reports.iter().any(|report| report.policy != first.policy) {
            return Err(PredictionError::InvalidConfig {
                field,
                reason: "reports of more than one policy",
            });
        }
        Ok(first.policy)
    };
    let candidate_policy = policy_of(candidate, "candidate")?;
    let baseline_policy = policy_of(baseline, "baseline")?;
    if baseline_policy != candidate_policy.matched_baseline() {
        return Err(PredictionError::InvalidConfig {
            field: "baseline",
            reason: "not the candidate's declared baseline: its eviction policy demand-only",
        });
    }
    let mut reasons = Vec::new();
    type Side<'a> = BTreeMap<u64, &'a ReplayReport>;
    let mut by_kind: BTreeMap<TraceKind, (Side<'_>, Side<'_>)> = BTreeMap::new();
    for report in candidate {
        by_kind
            .entry(report.kind)
            .or_default()
            .0
            .insert(report.seed, report);
    }
    for report in baseline {
        by_kind
            .entry(report.kind)
            .or_default()
            .1
            .insert(report.seed, report);
    }
    for kind in rule.required {
        if !by_kind.contains_key(kind) {
            reasons.push(NotAcceptedReason::MissingPattern { kind: *kind });
        }
    }
    if by_kind.keys().all(|kind| *kind == TraceKind::Alternating) {
        reasons.push(NotAcceptedReason::AlternatingOnly);
    }
    let mut patterns = Vec::new();
    for (kind, (candidates, baselines)) in &by_kind {
        let mut matched = true;
        for seed in candidates.keys().chain(baselines.keys()) {
            let budgets: Option<(ReplayBudget, ReplayBudget)> = candidates
                .get(seed)
                .zip(baselines.get(seed))
                .map(|(own, other)| (own.budget, other.budget));
            if !budgets.is_some_and(|(own, other)| own == other) {
                reasons.push(NotAcceptedReason::Unmatched {
                    kind: *kind,
                    seed: *seed,
                });
                matched = false;
                break;
            }
        }
        if !matched {
            continue;
        }
        let seeds = candidates.len();
        if seeds < rule.min_seeds {
            reasons.push(NotAcceptedReason::TooFewSeeds {
                kind: *kind,
                seeds,
                needed: rule.min_seeds,
            });
        }
        let pool = |side: &Side<'_>| -> Vec<u64> {
            side.values()
                .flat_map(|report| report.metrics.waits.iter().copied())
                .collect()
        };
        let total = |side: &Side<'_>, value: fn(&ReplayReport) -> u64| -> u64 {
            side.values()
                .fold(0u64, |sum, report| sum.saturating_add(value(report)))
        };
        let (candidate_waits, baseline_waits) = (pool(candidates), pool(baselines));
        let p95 = compare(
            Quantile::P95,
            &candidate_waits,
            &baseline_waits,
            seeds,
            rule.p95_tolerance_ppm,
        )?;
        let p99 = compare(
            Quantile::P99,
            &candidate_waits,
            &baseline_waits,
            seeds,
            rule.p99_tolerance_ppm,
        )?;
        for comparison in [&p95, &p99] {
            if rule.require_resolution && comparison.resolution != Resolution::Resolved {
                reasons.push(NotAcceptedReason::LowResolution {
                    kind: *kind,
                    quantile: comparison.quantile,
                });
            }
            if comparison.verdict == PatternVerdict::Regresses {
                reasons.push(NotAcceptedReason::Regressed {
                    kind: *kind,
                    quantile: comparison.quantile,
                    candidate_nanos: comparison.candidate_nanos,
                    baseline_nanos: comparison.baseline_nanos,
                });
            }
        }
        let verdict = if [p95.verdict, p99.verdict].contains(&PatternVerdict::Regresses) {
            PatternVerdict::Regresses
        } else if [p95.verdict, p99.verdict].contains(&PatternVerdict::Improves) {
            PatternVerdict::Improves
        } else {
            PatternVerdict::Matches
        };
        let (squared_error, forecasts) =
            candidates
                .values()
                .fold((0.0, 0u64), |(sum, count), report| {
                    match &report.calibration {
                        Some(summary) => (
                            sum + summary.brier_score.unwrap_or(0.0) * summary.forecasts as f64,
                            count.saturating_add(summary.forecasts),
                        ),
                        None => (sum, count),
                    }
                });
        patterns.push(PatternComparison {
            kind: *kind,
            seeds,
            samples: u64::try_from(candidate_waits.len()).unwrap_or(u64::MAX),
            p95,
            p99,
            candidate_total_wait_nanos: total(candidates, |report| report.metrics.total_wait_nanos),
            baseline_total_wait_nanos: total(baselines, |report| report.metrics.total_wait_nanos),
            candidate_hits: total(candidates, |report| report.metrics.hits),
            baseline_hits: total(baselines, |report| report.metrics.hits),
            candidate_wasted_bytes: total(candidates, |report| report.metrics.wasted_bytes),
            candidate_prepared_bytes: total(candidates, |report| report.metrics.prepared_bytes),
            candidate_brier_score: (forecasts > 0).then(|| squared_error / forecasts as f64),
            verdict,
        });
    }
    Ok(AcceptanceReport {
        label: EvaluationLabel::OfflineSyntheticTraces,
        rule: *rule,
        candidate: candidate_policy,
        baseline: baseline_policy,
        patterns,
        acceptance: if reasons.is_empty() {
            Acceptance::Accepted
        } else {
            Acceptance::NotAccepted { reasons }
        },
    })
}
