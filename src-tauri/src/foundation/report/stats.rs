//! Statistics of the measurement contract (S8, S9, S11, S13 quality evidence): success
//! rates over every initial attempt, untrimmed conditional percentiles that are always
//! shown beside the success rate and deadline failures, the Wilson score interval, a
//! resolution rule for tail percentiles, the exact McNemar test and ratios that carry
//! their denominators.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::error::ReportError;
use super::events::{EventName, IntervalKind};
use super::ledger::{AttemptLedger, FailureCounts, RetryTally};
use super::measured::{Measured, NotMeasuredReason};
use super::text::{ClockId, Label};
use crate::foundation::ids::MonotonicTime;

/// Samples beyond a percentile that make it resolved (S8, S11: a p99 from a single
/// 100-sample burst "has weak resolution"). With 10, a p99 needs 1,000 samples.
pub const MIN_TAIL_SAMPLES: u64 = 10;

/// Independent bursts a resolved percentile needs (S8: "repeat independent bursts …
/// avoid a universal p99 claim from one run"; S11 "several independent bursts").
pub const MIN_INDEPENDENT_BURSTS: u64 = 3;

/// Relative tolerance for comparing recomputed floating-point statistics.
const FLOAT_TOLERANCE: f64 = 1e-9;

fn close(left: f64, right: f64) -> bool {
    (left - right).abs() <= FLOAT_TOLERANCE * left.abs().max(right.abs()).max(1.0)
}

/// A quotient that may be undefined; an undefined value is never written as zero or
/// infinity (S8 cost: zero completed tasks give "undefined").
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum Quotient {
    Defined { value: f64 },
    Undefined { reason: UndefinedReason },
}

crate::foundation::strict_serde::strict_tag!(Quotient, "status");

/// Why a quotient is undefined.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UndefinedReason {
    ZeroDenominator,
    NoCompletedValidTasks,
    ZeroThroughput,
    NoOutputTokens,
    NoGpuTime,
    ComponentNotMeasured,
    ZeroBaseline,
    UnboundedDivergence,
}

impl Quotient {
    /// `numerator / denominator`, undefined with `reason` when the denominator is zero.
    pub fn divide(numerator: f64, denominator: f64, reason: UndefinedReason) -> Self {
        if denominator == 0.0 {
            Self::Undefined { reason }
        } else {
            Self::Defined {
                value: numerator / denominator,
            }
        }
    }

    pub fn value(&self) -> Option<f64> {
        match self {
            Self::Defined { value } => Some(*value),
            Self::Undefined { .. } => None,
        }
    }
}

/// A ratio that keeps its numerator and denominator (S9: metrics are reported with their
/// denominators).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RatioWire")]
pub struct Ratio {
    numerator: u64,
    denominator: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RatioWire {
    numerator: u64,
    denominator: u64,
}

impl TryFrom<RatioWire> for Ratio {
    type Error = ReportError;

    fn try_from(wire: RatioWire) -> Result<Self, Self::Error> {
        Self::new(wire.numerator, wire.denominator)
    }
}

impl Ratio {
    /// Refuses a numerator larger than the denominator; a zero denominator is kept and
    /// makes the value undefined.
    pub fn new(numerator: u64, denominator: u64) -> Result<Self, ReportError> {
        if numerator > denominator {
            return Err(ReportError::InvalidRatio);
        }
        Ok(Self {
            numerator,
            denominator,
        })
    }

    pub fn numerator(&self) -> u64 {
        self.numerator
    }

    pub fn denominator(&self) -> u64 {
        self.denominator
    }

    /// Undefined, not zero, when the denominator is zero.
    pub fn value(&self) -> Quotient {
        Quotient::divide(
            self.numerator as f64,
            self.denominator as f64,
            UndefinedReason::ZeroDenominator,
        )
    }
}

/// Successes over every initial attempt (S8). Never built from zero attempts.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "SuccessRateWire")]
pub struct SuccessRate {
    successes: u64,
    attempts: u64,
    rate: f64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuccessRateWire {
    successes: u64,
    attempts: u64,
    rate: f64,
}

impl TryFrom<SuccessRateWire> for SuccessRate {
    type Error = ReportError;

    fn try_from(wire: SuccessRateWire) -> Result<Self, Self::Error> {
        let rate = Self::new(wire.successes, wire.attempts)?;
        if close(rate.rate, wire.rate) {
            Ok(rate)
        } else {
            Err(ReportError::InconsistentSummary)
        }
    }
}

impl SuccessRate {
    /// Refuses zero attempts and more successes than attempts.
    pub fn new(successes: u64, attempts: u64) -> Result<Self, ReportError> {
        if attempts == 0 {
            return Err(ReportError::NoAttempts);
        }
        if successes > attempts {
            return Err(ReportError::SuccessesExceedAttempts);
        }
        Ok(Self {
            successes,
            attempts,
            rate: successes as f64 / attempts as f64,
        })
    }

    pub fn successes(&self) -> u64 {
        self.successes
    }

    pub fn attempts(&self) -> u64 {
        self.attempts
    }

    pub fn rate(&self) -> f64 {
        self.rate
    }

    /// The Wilson score interval of this rate.
    pub fn wilson(&self, level: ConfidenceLevel) -> WilsonInterval {
        wilson_bounds(self.successes, self.attempts, level)
    }
}

/// A two-sided confidence level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceLevel {
    Ninety,
    NinetyFive,
    NinetyNine,
}

impl ConfidenceLevel {
    /// The standard normal quantile z for the level.
    pub const fn z(self) -> f64 {
        match self {
            Self::Ninety => 1.644_853_626_951_472_2,
            Self::NinetyFive => 1.959_963_984_540_054,
            Self::NinetyNine => 2.575_829_303_548_900_4,
        }
    }
}

/// The Wilson score interval for a binomial proportion (S11 BENCH-10).
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WilsonInterval {
    pub level: ConfidenceLevel,
    pub lower: f64,
    pub upper: f64,
}

/// The Wilson score interval for `successes` of `trials`:
/// (p̂ + z²/2n ± z·√(p̂(1−p̂)/n + z²/4n²)) / (1 + z²/n). The bounds are exactly 0 at no
/// successes and exactly 1 at all successes.
pub fn wilson_interval(
    successes: u64,
    trials: u64,
    level: ConfidenceLevel,
) -> Result<WilsonInterval, ReportError> {
    SuccessRate::new(successes, trials).map(|rate| rate.wilson(level))
}

fn wilson_bounds(successes: u64, trials: u64, level: ConfidenceLevel) -> WilsonInterval {
    let n = trials as f64;
    let p = successes as f64 / n;
    let z = level.z();
    let z2 = z * z;
    let denominator = 1.0 + z2 / n;
    let centre = (p + z2 / (2.0 * n)) / denominator;
    let half = z * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt() / denominator;
    let lower = if successes == 0 {
        0.0
    } else {
        (centre - half).max(0.0)
    };
    let upper = if successes == trials {
        1.0
    } else {
        (centre + half).min(1.0)
    };
    WilsonInterval {
        level,
        lower,
        upper,
    }
}

/// A percentile in basis points: 5000 is p50, 9900 is p99.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct Quantile(u16);

impl Quantile {
    /// The median.
    pub const P50: Self = Self(5000);
    /// The 95th percentile.
    pub const P95: Self = Self(9500);
    /// The 99th percentile.
    pub const P99: Self = Self(9900);

    /// The percentiles every latency summary reports (S8: p50/p95/p99).
    pub const REPORTED: [Self; 3] = [Self::P50, Self::P95, Self::P99];

    /// 1–10000 basis points.
    pub fn from_basis_points(basis_points: u16) -> Result<Self, ReportError> {
        if (1..=10_000).contains(&basis_points) {
            Ok(Self(basis_points))
        } else {
            Err(ReportError::InvalidQuantile)
        }
    }

    pub const fn basis_points(self) -> u16 {
        self.0
    }

    /// The 1-based nearest rank among `count` sorted samples: ⌈q·n⌉, at least 1.
    fn nearest_rank(self, count: u64) -> u64 {
        let product = u128::from(self.0) * u128::from(count);
        let rank = product.div_ceil(10_000);
        u64::try_from(rank).unwrap_or(count).clamp(1, count.max(1))
    }
}

impl TryFrom<u16> for Quantile {
    type Error = ReportError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::from_basis_points(value)
    }
}

impl From<Quantile> for u16 {
    fn from(quantile: Quantile) -> Self {
        quantile.0
    }
}

/// How a percentile is computed; always stated beside the value (S8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PercentileMethod {
    /// The sample at rank ⌈q·n⌉; an observed value, no interpolation.
    NearestRank,
    /// Linear interpolation between closest ranks (Hyndman–Fan type 7).
    LinearInterpolation,
}

/// The percentile `quantile` of ascending `sorted` samples, untrimmed.
pub fn percentile(
    sorted: &[u64],
    quantile: Quantile,
    method: PercentileMethod,
) -> Result<f64, ReportError> {
    if sorted.is_empty()
        || sorted
            .windows(2)
            .any(|pair| matches!(pair, [earlier, later] if earlier > later))
    {
        return Err(ReportError::InvalidDistribution);
    }
    let count = sorted.len() as u64;
    let at = |index: u64| -> Result<f64, ReportError> {
        usize::try_from(index)
            .ok()
            .and_then(|index| sorted.get(index))
            .map(|value| *value as f64)
            .ok_or(ReportError::InvalidDistribution)
    };
    match method {
        PercentileMethod::NearestRank => at(quantile.nearest_rank(count) - 1),
        PercentileMethod::LinearInterpolation => {
            let scaled = u128::from(count - 1) * u128::from(quantile.0);
            let lower =
                u64::try_from(scaled / 10_000).map_err(|_| ReportError::InvalidDistribution)?;
            let fraction = (scaled % 10_000) as f64 / 10_000.0;
            let upper = (lower + 1).min(count - 1);
            let (low, high) = (at(lower)?, at(upper)?);
            Ok(low + fraction * (high - low))
        }
    }
}

strict_tagged_enum! {
/// Whether a percentile may be claimed (S8, S11). A low-resolution value is reported but
/// cannot be claimed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution (tag = "kind", wire = ResolutionWire, wire_name = "ResolutionWire") {
    Resolved,
    LowResolution {
        tail_samples: u64,
        required_tail_samples: u64,
        bursts: u64,
        required_bursts: u64,
    },
}
}

/// The resolution rule: at least [`MIN_TAIL_SAMPLES`] samples beyond the nearest rank and
/// at least [`MIN_INDEPENDENT_BURSTS`] independent bursts.
pub fn resolution(samples: u64, bursts: u64, quantile: Quantile) -> Resolution {
    let tail_samples = samples - quantile.nearest_rank(samples).min(samples);
    if tail_samples >= MIN_TAIL_SAMPLES && bursts >= MIN_INDEPENDENT_BURSTS {
        Resolution::Resolved
    } else {
        Resolution::LowResolution {
            tail_samples,
            required_tail_samples: MIN_TAIL_SAMPLES,
            bursts,
            required_bursts: MIN_INDEPENDENT_BURSTS,
        }
    }
}

/// The spread of one percentile across independent bursts (S8 "report uncertainty").
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BurstSpread {
    pub bursts: u64,
    pub min_nanos: f64,
    pub max_nanos: f64,
}

/// One percentile of a latency summary, with its resolution and per-burst spread.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PercentileEstimate {
    pub quantile: Quantile,
    pub value_nanos: Measured<f64>,
    pub resolution: Resolution,
    pub per_burst_spread: Measured<BurstSpread>,
}

impl PercentileEstimate {
    fn compute(
        samples: &[Sample],
        quantile: Quantile,
        method: PercentileMethod,
    ) -> Result<Self, ReportError> {
        let sorted: Vec<u64> = samples.iter().map(|sample| sample.nanos).collect();
        let mut by_burst: BTreeMap<u32, Vec<u64>> = BTreeMap::new();
        for sample in samples {
            by_burst.entry(sample.burst).or_default().push(sample.nanos);
        }
        let value_nanos = if sorted.is_empty() {
            Measured::not_measured(NotMeasuredReason::NoSuccessfulRuns)
        } else {
            Measured::measured(percentile(&sorted, quantile, method)?)
        };
        let per_burst: Vec<f64> = by_burst
            .values()
            .map(|burst| percentile(burst, quantile, method))
            .collect::<Result<_, _>>()?;
        let per_burst_spread = match per_burst.len() {
            0 => Measured::not_measured(NotMeasuredReason::NoSuccessfulRuns),
            1 => Measured::not_measured(NotMeasuredReason::SingleBurst),
            bursts => Measured::measured(BurstSpread {
                bursts: bursts as u64,
                min_nanos: per_burst.iter().copied().fold(f64::INFINITY, f64::min),
                max_nanos: per_burst.iter().copied().fold(f64::NEG_INFINITY, f64::max),
            }),
        };
        Ok(Self {
            quantile,
            value_nanos,
            resolution: resolution(sorted.len() as u64, by_burst.len() as u64, quantile),
            per_burst_spread,
        })
    }

    fn matches(&self, other: &Self) -> bool {
        let values = match (self.value_nanos.value(), other.value_nanos.value()) {
            (Some(left), Some(right)) => close(*left, *right),
            (None, None) => self.value_nanos.reason() == other.value_nanos.reason(),
            _ => false,
        };
        let spreads = match (
            self.per_burst_spread.value(),
            other.per_burst_spread.value(),
        ) {
            (Some(left), Some(right)) => {
                left.bursts == right.bursts
                    && close(left.min_nanos, right.min_nanos)
                    && close(left.max_nanos, right.max_nanos)
            }
            (None, None) => self.per_burst_spread.reason() == other.per_burst_spread.reason(),
            _ => false,
        };
        self.quantile == other.quantile && self.resolution == other.resolution && values && spreads
    }
}

/// One successful initial attempt's duration and its burst.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub nanos: u64,
    pub burst: u32,
}

/// Untrimmed successful-run percentiles of one interval, always carrying the overall
/// success rate, its Wilson interval, the deadline failures and the full failure
/// taxonomy (S8). It can only be built from an [`AttemptLedger`], so it cannot exist
/// without them, and a serialized summary missing any of them is refused.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "LatencySummaryWire")]
pub struct LatencySummary {
    interval: IntervalKind,
    success_rate: SuccessRate,
    success_rate_wilson: WilsonInterval,
    deadline_failures: u64,
    failures: FailureCounts,
    retries: RetryTally,
    method: PercentileMethod,
    /// Every successful initial attempt, ascending; nothing trimmed.
    samples: Vec<Sample>,
    percentiles: Vec<PercentileEstimate>,
    /// FAST-01: the best run is a diagnostic only, never a claim.
    fastest_successful_nanos_diagnostic: Measured<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LatencySummaryWire {
    interval: IntervalKind,
    success_rate: SuccessRate,
    success_rate_wilson: WilsonInterval,
    deadline_failures: u64,
    failures: FailureCounts,
    retries: RetryTally,
    method: PercentileMethod,
    samples: Vec<Sample>,
    percentiles: Vec<PercentileEstimate>,
    fastest_successful_nanos_diagnostic: Measured<u64>,
}

impl TryFrom<LatencySummaryWire> for LatencySummary {
    type Error = ReportError;

    fn try_from(wire: LatencySummaryWire) -> Result<Self, Self::Error> {
        let rebuilt = Self::from_parts(
            wire.interval,
            wire.success_rate,
            wire.failures,
            wire.retries,
            wire.method,
            wire.samples,
        )?;
        let consistent = rebuilt.deadline_failures == wire.deadline_failures
            && rebuilt.success_rate_wilson.level == wire.success_rate_wilson.level
            && close(
                rebuilt.success_rate_wilson.lower,
                wire.success_rate_wilson.lower,
            )
            && close(
                rebuilt.success_rate_wilson.upper,
                wire.success_rate_wilson.upper,
            )
            && rebuilt.fastest_successful_nanos_diagnostic
                == wire.fastest_successful_nanos_diagnostic
            && rebuilt.percentiles.len() == wire.percentiles.len()
            && rebuilt
                .percentiles
                .iter()
                .zip(&wire.percentiles)
                .all(|(left, right)| left.matches(right));
        if consistent {
            Ok(rebuilt)
        } else {
            Err(ReportError::InconsistentSummary)
        }
    }
}

impl LatencySummary {
    /// Summarises `interval` over the ledger: the success rate and failures of every
    /// initial attempt, and untrimmed percentiles of the successful initial attempts.
    pub fn from_ledger(
        ledger: &AttemptLedger,
        interval: IntervalKind,
        method: PercentileMethod,
    ) -> Result<Self, ReportError> {
        let mut samples = Vec::new();
        for record in ledger
            .initial_attempts()
            .filter(|record| record.is_success())
        {
            samples.push(Sample {
                nanos: record.interval(interval)?.elapsed_nanos(),
                burst: record.attempt.burst,
            });
        }
        Self::from_parts(
            interval,
            ledger.success_rate()?,
            ledger.failures(),
            ledger.retry_tally(),
            method,
            samples,
        )
    }

    fn from_parts(
        interval: IntervalKind,
        success_rate: SuccessRate,
        failures: FailureCounts,
        retries: RetryTally,
        method: PercentileMethod,
        mut samples: Vec<Sample>,
    ) -> Result<Self, ReportError> {
        let accounted = success_rate.successes().checked_add(failures.total());
        if samples.len() as u64 != success_rate.successes()
            || accounted != Some(success_rate.attempts())
        {
            return Err(ReportError::InconsistentSummary);
        }
        samples.sort();
        let percentiles = Quantile::REPORTED
            .iter()
            .map(|quantile| PercentileEstimate::compute(&samples, *quantile, method))
            .collect::<Result<_, _>>()?;
        let fastest_successful_nanos_diagnostic = match samples.first() {
            Some(sample) => Measured::measured(sample.nanos),
            None => Measured::not_measured(NotMeasuredReason::NoSuccessfulRuns),
        };
        Ok(Self {
            interval,
            success_rate_wilson: success_rate.wilson(ConfidenceLevel::NinetyFive),
            success_rate,
            deadline_failures: failures.deadline_failure,
            failures,
            retries,
            method,
            samples,
            percentiles,
            fastest_successful_nanos_diagnostic,
        })
    }

    pub fn interval(&self) -> IntervalKind {
        self.interval
    }

    pub fn success_rate(&self) -> SuccessRate {
        self.success_rate
    }

    pub fn success_rate_wilson(&self) -> WilsonInterval {
        self.success_rate_wilson
    }

    pub fn deadline_failures(&self) -> u64 {
        self.deadline_failures
    }

    pub fn failures(&self) -> FailureCounts {
        self.failures
    }

    pub fn retries(&self) -> RetryTally {
        self.retries
    }

    pub fn method(&self) -> PercentileMethod {
        self.method
    }

    pub fn samples(&self) -> &[Sample] {
        &self.samples
    }

    pub fn percentiles(&self) -> &[PercentileEstimate] {
        &self.percentiles
    }

    pub fn percentile(&self, quantile: Quantile) -> Option<&PercentileEstimate> {
        self.percentiles
            .iter()
            .find(|estimate| estimate.quantile == quantile)
    }

    /// Distinct bursts among the successful samples.
    pub fn bursts(&self) -> u64 {
        self.samples
            .iter()
            .map(|sample| sample.burst)
            .collect::<BTreeSet<_>>()
            .len() as u64
    }

    /// The best run, as a diagnostic only (FAST-01); never a claim.
    pub fn fastest_successful_nanos_diagnostic(&self) -> Measured<u64> {
        self.fastest_successful_nanos_diagnostic.clone()
    }
}

/// One paired item of a reference and a candidate (S13 quality evidence layer 2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairedOutcome {
    pub item: Label,
    pub baseline_succeeded: bool,
    pub candidate_succeeded: bool,
}

/// A 2×2 table of paired binary outcomes. Read back, a table whose total does not fit in
/// 64 bits is refused; every count it sums is checked.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PairedTableWire")]
pub struct PairedTable {
    pub both_succeeded: u64,
    pub only_baseline_succeeded: u64,
    pub only_candidate_succeeded: u64,
    pub both_failed: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairedTableWire {
    both_succeeded: u64,
    only_baseline_succeeded: u64,
    only_candidate_succeeded: u64,
    both_failed: u64,
}

impl TryFrom<PairedTableWire> for PairedTable {
    type Error = ReportError;

    fn try_from(wire: PairedTableWire) -> Result<Self, Self::Error> {
        let table = Self {
            both_succeeded: wire.both_succeeded,
            only_baseline_succeeded: wire.only_baseline_succeeded,
            only_candidate_succeeded: wire.only_candidate_succeeded,
            both_failed: wire.both_failed,
        };
        table.pairs()?;
        Ok(table)
    }
}

/// The most discordant pairs the exact McNemar test sums; it takes min(b, c) + 1 steps in
/// constant memory, so the bound keeps a hostile table from taking unbounded time.
pub const MAX_EXACT_DISCORDANT_PAIRS: u64 = 10_000_000;

/// The exact McNemar test of a paired table.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McNemarResult {
    pub discordant_pairs: u64,
    pub only_baseline_succeeded: u64,
    pub only_candidate_succeeded: u64,
    pub p_value_two_sided: f64,
}

impl PairedTable {
    /// Tallies paired outcomes; each item appears once.
    pub fn from_pairs(pairs: &[PairedOutcome]) -> Result<Self, ReportError> {
        let mut seen = BTreeSet::new();
        let mut table = Self::default();
        for pair in pairs {
            if !seen.insert(&pair.item) {
                return Err(ReportError::DuplicatePairedItem);
            }
            let slot = match (pair.baseline_succeeded, pair.candidate_succeeded) {
                (true, true) => &mut table.both_succeeded,
                (true, false) => &mut table.only_baseline_succeeded,
                (false, true) => &mut table.only_candidate_succeeded,
                (false, false) => &mut table.both_failed,
            };
            *slot = slot.checked_add(1).ok_or(ReportError::CountOverflow)?;
        }
        Ok(table)
    }

    /// Every pair in the table; refused when the total does not fit in 64 bits.
    pub fn pairs(&self) -> Result<u64, ReportError> {
        [
            self.only_baseline_succeeded,
            self.only_candidate_succeeded,
            self.both_failed,
        ]
        .into_iter()
        .try_fold(self.both_succeeded, u64::checked_add)
        .ok_or(ReportError::CountOverflow)
    }

    /// The exact (binomial) McNemar test on the discordant pairs.
    pub fn mcnemar_exact(&self) -> Result<McNemarResult, ReportError> {
        Ok(McNemarResult {
            discordant_pairs: self
                .only_baseline_succeeded
                .checked_add(self.only_candidate_succeeded)
                .ok_or(ReportError::CountOverflow)?,
            only_baseline_succeeded: self.only_baseline_succeeded,
            only_candidate_succeeded: self.only_candidate_succeeded,
            p_value_two_sided: mcnemar_exact_p_value(
                self.only_baseline_succeeded,
                self.only_candidate_succeeded,
            )?,
        })
    }
}

/// A sum that carries its rounding error (Neumaier), so a long run of additions stays
/// accurate.
struct CompensatedSum {
    sum: f64,
    compensation: f64,
}

impl CompensatedSum {
    fn new(start: f64) -> Self {
        Self {
            sum: start,
            compensation: 0.0,
        }
    }

    fn add(&mut self, value: f64) {
        let total = self.sum + value;
        self.compensation += if self.sum.abs() >= value.abs() {
            (self.sum - total) + value
        } else {
            (value - total) + self.sum
        };
        self.sum = total;
    }

    fn value(&self) -> f64 {
        self.sum + self.compensation
    }
}

/// ln(eᵃ + eᵇ) without overflow.
fn log_add(a: f64, b: f64) -> f64 {
    let (high, low) = if a >= b { (a, b) } else { (b, a) };
    high + (low - high).exp().ln_1p()
}

/// Two-sided exact McNemar p-value for discordant counts `b` and `c`:
/// min(1, 2·P(X ≤ min(b, c))) with X ~ Binomial(b + c, ½); 1 with no discordant pairs.
///
/// The tail is summed in log space in constant memory. Counts whose total does not fit
/// in 64 bits, and more than [`MAX_EXACT_DISCORDANT_PAIRS`] discordant pairs, are refused.
pub fn mcnemar_exact_p_value(b: u64, c: u64) -> Result<f64, ReportError> {
    let n = b.checked_add(c).ok_or(ReportError::CountOverflow)?;
    if n == 0 {
        return Ok(1.0);
    }
    if n > MAX_EXACT_DISCORDANT_PAIRS {
        return Err(ReportError::TooManyPairsForExactTest {
            pairs: n,
            max: MAX_EXACT_DISCORDANT_PAIRS,
        });
    }
    let k = b.min(c);
    // ln P(X = i) = ln C(n, i) − n ln 2, stepped by ln((n − i + 1) / i).
    let mut log_probability = CompensatedSum::new(-(n as f64) * std::f64::consts::LN_2);
    let mut log_tail = log_probability.value();
    for i in 1..=k {
        log_probability.add(((n - i + 1) as f64 / i as f64).ln());
        log_tail = log_add(log_tail, log_probability.value());
    }
    Ok((2.0 * log_tail.exp()).min(1.0))
}

/// A window on one clock for aggregate throughput (S8 "completed output tokens per
/// second"; BENCH-01 aggregate completed throughput).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationWindow {
    pub clock: ClockId,
    pub start_nanos: MonotonicTime,
    pub end_nanos: MonotonicTime,
}

/// Output tokens of successful attempts completed inside `window`, per second of the
/// window. Failed attempts add nothing; every completion must be on the window's clock.
pub fn completed_output_tokens_per_second(
    ledger: &AttemptLedger,
    window: &ObservationWindow,
) -> Result<Quotient, ReportError> {
    let window_nanos = window
        .end_nanos
        .checked_duration_since(window.start_nanos)
        .filter(|elapsed| !elapsed.is_zero())
        .ok_or(ReportError::EmptyObservationWindow)?;
    let mut tokens = 0u64;
    for record in ledger.records().iter().filter(|record| record.is_success()) {
        let timeline = record.timeline()?;
        let completed = timeline
            .events()
            .iter()
            .find(|event| event.event.name() == EventName::RequestCompleted)
            .ok_or(ReportError::MissingEvent {
                event: EventName::RequestCompleted,
            })?;
        if completed.clock != window.clock {
            return Err(ReportError::DifferentClocks {
                interval: IntervalKind::RequestLatency,
            });
        }
        if completed.at_nanos >= window.start_nanos && completed.at_nanos <= window.end_nanos {
            tokens = tokens.saturating_add(timeline.emitted_tokens());
        }
    }
    Ok(Quotient::divide(
        tokens as f64,
        window_nanos.as_secs_f64(),
        UndefinedReason::ZeroDenominator,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::report::fixtures::{failed, label, serving_record};
    use crate::foundation::report::record::{FailureKind, RunRecord};

    fn approx(left: f64, right: f64, tolerance: f64) {
        assert!((left - right).abs() <= tolerance, "{left} != {right}");
    }

    #[test]
    fn wilson_interval_known_values() {
        let level = ConfidenceLevel::NinetyFive;
        let none = wilson_interval(0, 10, level).unwrap();
        assert_eq!(none.lower, 0.0);
        approx(none.upper, 0.277_532, 1e-6);
        let half = wilson_interval(5, 10, level).unwrap();
        approx(half.lower, 0.236_593, 1e-6);
        approx(half.upper, 0.763_407, 1e-6);
        let all = wilson_interval(10, 10, level).unwrap();
        approx(all.lower, 0.722_468, 1e-6);
        assert_eq!(all.upper, 1.0);
        assert_eq!(wilson_interval(1, 0, level), Err(ReportError::NoAttempts));
        assert_eq!(
            wilson_interval(11, 10, level),
            Err(ReportError::SuccessesExceedAttempts)
        );
        // A wider level gives a wider interval.
        let wide = wilson_interval(5, 10, ConfidenceLevel::NinetyNine).unwrap();
        assert!(wide.lower < half.lower && wide.upper > half.upper);
    }

    #[test]
    fn mcnemar_exact_known_tables() {
        let p = |b, c| mcnemar_exact_p_value(b, c).unwrap();
        // b = 1, c = 9: 2 × (C(10,0) + C(10,1)) / 2^10 = 22/1024.
        approx(p(1, 9), 0.021_484_375, 1e-12);
        approx(p(9, 1), 0.021_484_375, 1e-12);
        // b = 2, c = 8: 2 × 56/1024.
        approx(p(2, 8), 0.109_375, 1e-12);
        // b = 0, c = 6: 2/64.
        approx(p(0, 6), 0.031_25, 1e-12);
        assert_eq!(p(5, 5), 1.0);
        assert_eq!(p(0, 0), 1.0);
        // Large tables stay finite and symmetric.
        let large = p(400, 520);
        assert!(large > 0.0 && large < 0.001);
        approx(large, p(520, 400), 1e-15);
        // b = 0, c = 1000 is exactly 2 × 2^-1000.
        assert!((p(0, 1_000) / 2f64.powi(-999) - 1.0).abs() < 1e-12);
        // With n = 2k + 1, P(X ≤ k) is exactly ½: 100,001 constant-memory steps keep
        // the sum accurate.
        approx(p(100_000, 100_001), 1.0, 1e-9);

        let pairs: Vec<PairedOutcome> = (0..12)
            .map(|index| PairedOutcome {
                item: label(&format!("item-{index}")),
                baseline_succeeded: !(2..10).contains(&index),
                candidate_succeeded: index >= 1,
            })
            .collect();
        let table = PairedTable::from_pairs(&pairs).unwrap();
        assert_eq!(
            table,
            PairedTable {
                both_succeeded: 3,
                only_baseline_succeeded: 1,
                only_candidate_succeeded: 8,
                both_failed: 0,
            }
        );
        let result = table.mcnemar_exact().unwrap();
        assert_eq!(result.discordant_pairs, 9);
        assert_eq!(table.pairs(), Ok(12));
        approx(result.p_value_two_sided, 2.0 * 10.0 / 512.0, 1e-12);
        let mut duplicated = pairs.clone();
        duplicated.push(pairs[0].clone());
        assert_eq!(
            PairedTable::from_pairs(&duplicated),
            Err(ReportError::DuplicatePairedItem)
        );
    }

    #[test]
    fn a_deserialized_paired_table_cannot_overflow() {
        // Review probe a_deserialized_paired_table_overflows: a table read with
        // u64::MAX + 1 pairs was summed with unchecked additions (a debug-build panic).
        // It is now refused when read.
        let json = format!(
            r#"{{"both_succeeded":{},"only_baseline_succeeded":1,"only_candidate_succeeded":0,"both_failed":0}}"#,
            u64::MAX
        );
        let error = serde_json::from_str::<PairedTable>(&json).unwrap_err();
        assert!(error.to_string().contains("64 bits"), "{error}");
        // A table built in code is summed with checked arithmetic, never a panic.
        let table = PairedTable {
            both_succeeded: u64::MAX,
            only_baseline_succeeded: 1,
            ..PairedTable::default()
        };
        assert_eq!(table.pairs(), Err(ReportError::CountOverflow));
        let discordant = PairedTable {
            only_baseline_succeeded: u64::MAX,
            only_candidate_succeeded: 1,
            ..PairedTable::default()
        };
        assert_eq!(discordant.mcnemar_exact(), Err(ReportError::CountOverflow));
        assert_eq!(
            mcnemar_exact_p_value(u64::MAX, 1),
            Err(ReportError::CountOverflow)
        );
        // Counts that fit but would take unbounded time are refused, not summed: the sum
        // runs in constant memory over at most MAX_EXACT_DISCORDANT_PAIRS pairs.
        assert_eq!(
            mcnemar_exact_p_value(u64::MAX / 2, u64::MAX / 2),
            Err(ReportError::TooManyPairsForExactTest {
                pairs: u64::MAX - 1,
                max: MAX_EXACT_DISCORDANT_PAIRS
            })
        );
        assert_eq!(
            mcnemar_exact_p_value(1, MAX_EXACT_DISCORDANT_PAIRS),
            Err(ReportError::TooManyPairsForExactTest {
                pairs: MAX_EXACT_DISCORDANT_PAIRS + 1,
                max: MAX_EXACT_DISCORDANT_PAIRS
            })
        );
        assert_eq!(
            mcnemar_exact_p_value(3, MAX_EXACT_DISCORDANT_PAIRS - 3),
            Ok(0.0)
        );
        // A valid table reads back unchanged.
        let valid = PairedTable {
            both_succeeded: 180,
            only_baseline_succeeded: 6,
            only_candidate_succeeded: 4,
            both_failed: 10,
        };
        let read: PairedTable =
            serde_json::from_str(&serde_json::to_string(&valid).unwrap()).unwrap();
        assert_eq!(read, valid);
        assert!(serde_json::from_str::<PairedTable>(
            r#"{"both_succeeded":1,"only_baseline_succeeded":1,"only_candidate_succeeded":0,"both_failed":0,"extra":1}"#
        )
        .is_err());
    }

    #[test]
    fn percentiles_state_their_method_and_are_untrimmed() {
        let samples: Vec<u64> = (1..=10).collect();
        let nearest = PercentileMethod::NearestRank;
        assert_eq!(percentile(&samples, Quantile::P50, nearest).unwrap(), 5.0);
        assert_eq!(percentile(&samples, Quantile::P95, nearest).unwrap(), 10.0);
        assert_eq!(percentile(&samples, Quantile::P99, nearest).unwrap(), 10.0);
        let linear = PercentileMethod::LinearInterpolation;
        assert_eq!(percentile(&samples, Quantile::P50, linear).unwrap(), 5.5);
        approx(
            percentile(&samples, Quantile::P95, linear).unwrap(),
            9.55,
            1e-12,
        );
        approx(
            percentile(&samples, Quantile::P99, linear).unwrap(),
            9.91,
            1e-12,
        );
        // One extreme outlier moves the tail; nothing is trimmed.
        let mut outlier: Vec<u64> = vec![1; 99];
        outlier.push(1_000_000);
        assert_eq!(percentile(&outlier, Quantile::P99, nearest).unwrap(), 1.0);
        assert_eq!(
            percentile(
                &outlier,
                Quantile::from_basis_points(10_000).unwrap(),
                nearest
            )
            .unwrap(),
            1_000_000.0
        );
        assert_eq!(
            percentile(&[3, 1], Quantile::P50, nearest),
            Err(ReportError::InvalidDistribution)
        );
        assert_eq!(
            percentile(&[], Quantile::P50, nearest),
            Err(ReportError::InvalidDistribution)
        );
        assert_eq!(
            Quantile::from_basis_points(0),
            Err(ReportError::InvalidQuantile)
        );
        assert_eq!(
            Quantile::from_basis_points(10_001),
            Err(ReportError::InvalidQuantile)
        );
    }

    #[test]
    fn a_p99_from_one_100_sample_burst_is_low_resolution() {
        assert_eq!(
            resolution(100, 1, Quantile::P99),
            Resolution::LowResolution {
                tail_samples: 1,
                required_tail_samples: MIN_TAIL_SAMPLES,
                bursts: 1,
                required_bursts: MIN_INDEPENDENT_BURSTS,
            }
        );
        // Enough samples from one run still make no universal claim.
        assert!(matches!(
            resolution(1_000, 1, Quantile::P99),
            Resolution::LowResolution {
                tail_samples: 10,
                ..
            }
        ));
        assert_eq!(resolution(1_000, 3, Quantile::P99), Resolution::Resolved);
        assert!(matches!(
            resolution(999, 3, Quantile::P99),
            Resolution::LowResolution {
                tail_samples: 9,
                ..
            }
        ));
        assert_eq!(resolution(20, 3, Quantile::P50), Resolution::Resolved);
        assert_eq!(resolution(200, 3, Quantile::P95), Resolution::Resolved);
    }

    fn ledger_of(records: Vec<RunRecord>) -> AttemptLedger {
        AttemptLedger::from_records(records).unwrap()
    }

    #[test]
    fn a_summary_carries_the_success_rate_and_deadline_failures() {
        let mut records = Vec::new();
        for (index, millis) in [100u64, 120, 140, 160].iter().enumerate() {
            let mut record = serving_record(&format!("op-{index}"), *millis);
            record.attempt.burst = index as u32 % 2;
            records.push(record);
        }
        let mut late = serving_record("op-late", 100);
        late.outcome = failed(FailureKind::DeadlineFailure);
        late.attempt.deadline_nanos = Measured::measured(100_000_000);
        records.push(late);
        let mut rejected = serving_record("op-rejected", 100);
        rejected.outcome = failed(FailureKind::Rejected);
        rejected.events.truncate(1);
        records.push(rejected);
        let summary = LatencySummary::from_ledger(
            &ledger_of(records),
            IntervalKind::TimeToFirstToken,
            PercentileMethod::NearestRank,
        )
        .unwrap();
        assert_eq!(summary.success_rate().successes(), 4);
        assert_eq!(summary.success_rate().attempts(), 6);
        assert_eq!(summary.deadline_failures(), 1);
        assert_eq!(summary.failures().rejected, 1);
        assert_eq!(summary.samples().len(), 4);
        let p50 = summary.percentile(Quantile::P50).unwrap();
        assert_eq!(p50.value_nanos, Measured::measured(120_000_000.0));
        assert!(matches!(p50.resolution, Resolution::LowResolution { .. }));
        assert_eq!(
            p50.per_burst_spread,
            Measured::measured(BurstSpread {
                bursts: 2,
                min_nanos: 100_000_000.0,
                max_nanos: 120_000_000.0,
            })
        );
        assert_eq!(
            summary.fastest_successful_nanos_diagnostic(),
            Measured::measured(100_000_000)
        );

        let json = serde_json::to_value(&summary).unwrap();
        for field in [
            "success_rate",
            "success_rate_wilson",
            "deadline_failures",
            "failures",
            "method",
        ] {
            assert!(json.get(field).is_some(), "{field}");
            let mut stripped = json.clone();
            stripped.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<LatencySummary>(stripped).is_err(),
                "{field}"
            );
        }
        let round_trip: LatencySummary = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(round_trip, summary);
        // Trimming the tail or rewriting the rate is detected.
        let mut trimmed = json.clone();
        trimmed["samples"].as_array_mut().unwrap().pop();
        assert!(serde_json::from_value::<LatencySummary>(trimmed).is_err());
        let mut rewritten = json;
        rewritten["deadline_failures"] = 0.into();
        assert!(serde_json::from_value::<LatencySummary>(rewritten).is_err());
    }

    #[test]
    fn a_summary_with_no_successes_still_reports_the_rate() {
        let mut record = serving_record("op-1", 100);
        record.outcome = failed(FailureKind::Timeout);
        record.events.truncate(1);
        let summary = LatencySummary::from_ledger(
            &ledger_of(vec![record]),
            IntervalKind::TimeToFirstToken,
            PercentileMethod::NearestRank,
        )
        .unwrap();
        assert_eq!(summary.success_rate().rate(), 0.0);
        assert_eq!(
            summary.percentile(Quantile::P99).unwrap().value_nanos,
            Measured::not_measured(NotMeasuredReason::NoSuccessfulRuns)
        );
    }

    #[test]
    fn ratios_keep_denominators_and_undefined_is_not_zero() {
        let ratio = Ratio::new(3, 4).unwrap();
        assert_eq!(ratio.value(), Quotient::Defined { value: 0.75 });
        assert_eq!(
            Ratio::new(0, 0).unwrap().value(),
            Quotient::Undefined {
                reason: UndefinedReason::ZeroDenominator
            }
        );
        assert_eq!(Ratio::new(5, 4), Err(ReportError::InvalidRatio));
        assert!(serde_json::from_str::<Ratio>(r#"{"numerator":5,"denominator":4}"#).is_err());
        assert!(
            serde_json::from_str::<SuccessRate>(r#"{"successes":1,"attempts":0,"rate":0.0}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<SuccessRate>(r#"{"successes":1,"attempts":2,"rate":0.9}"#)
                .is_err()
        );
    }

    #[test]
    fn aggregate_throughput_counts_completed_requests_in_the_window() {
        let first = serving_record("op-1", 100);
        let mut second = serving_record("op-2", 100);
        second.outcome = failed(FailureKind::EarlyTermination);
        let ledger = ledger_of(vec![first.clone(), second]);
        let start = first.events[0].at_nanos;
        let window = ObservationWindow {
            clock: first.events[0].clock.clone(),
            start_nanos: start,
            end_nanos: start.saturating_add(std::time::Duration::from_secs(2)),
        };
        // Three tokens from the one successful request over two seconds.
        assert_eq!(
            completed_output_tokens_per_second(&ledger, &window).unwrap(),
            Quotient::Defined { value: 1.5 }
        );
        let empty = ObservationWindow {
            end_nanos: start,
            ..window
        };
        assert_eq!(
            completed_output_tokens_per_second(&ledger, &empty),
            Err(ReportError::EmptyObservationWindow)
        );
    }
}
