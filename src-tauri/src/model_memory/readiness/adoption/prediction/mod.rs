//! G05's prediction half (docs/combined-plan-leftover-tasks.md G05; GPU-W06 of
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md, line 1236: "Build tiny offline
//! optimal schedules and trace replay comparisons", acceptance at line 1249; §2.9 lines
//! 638–644: "Start with queued work and explicit user intent, then compare recency/Markov
//! models. Maintain uncertainty and calibration"; §4.1 line 841; §4.12 lines 942–948;
//! §4.14's first prototype, line 1006; the predictor gate at line 1446 and GPU-T37 at
//! line 1494).
//!
//! - [`recency`] and [`markov`]: online predictors over the request history the readiness
//!   code sees (one key per request: a [`PrepareTarget`](super::super::intent::PrepareTarget)
//!   in the governor, an object key in the replay). Each forecast is a posterior mean
//!   probability with its standard deviation and evidence, and each predictor's memory is
//!   bounded by its configuration.
//! - [`guard`]: a predictor behind its recent calibration. Forecasts are scored against
//!   what was requested; the §2.9
//!   [`ModeController`](crate::model_memory::math::calibration::ModeController) falls back
//!   to the demand-only baseline when the recent top forecast hit rate or the recent
//!   Brier score is poor (an adversarial or drifting pattern) and recovers with
//!   hysteresis. Demand-only is the default, an operator rollback is always available, and
//!   a ranking only orders the candidates it is given: the declared intent and the budget
//!   still decide what may be prepared ([`guard::rank_declared_steps`] for the
//!   [`PreparationGovernor`](super::PreparationGovernor)).
//! - [`traces`]: seeded synthetic request traces (alternating, scan, bursty, mixed and
//!   adversarial to a Markov predictor) over catalogs with a shared base.
//! - [`replay`]: the deterministic trace-replay evaluator. Every policy replays the same
//!   trace under the same [`replay::ReplayBudget`] through the residency cache: the
//!   LRU, cost-per-byte and dependency-aware baselines of
//!   [`bundles::baselines`](crate::model_memory::bundles::baselines), and the same
//!   baselines assisted by a guarded predictor that prepares within the gap a workload
//!   declares. It reports hits, reload time, wasted bytes, p50/p95/p99 wait on the replay
//!   clock and calibration.
//! - [`optimal`]: the exhaustive optimal schedule of a tiny trace under the same model and
//!   budget, the lower bound every policy is checked against.
//! - [`acceptance`]: the predeclared p95/p99 rule against the declared baseline.
//!
//! Nothing here restates a committed module: residency and eviction are
//! [`ResidencyCache`](crate::model_memory::residency::retention::ResidencyCache)'s, the
//! baselines are [`CachePolicy`](crate::model_memory::bundles::baselines::CachePolicy)'s
//! policies, expected value and ranking are
//! [`math::prefetch`](crate::model_memory::math::prefetch)'s, Brier scores and
//! reliability bins are
//! [`CalibrationTracker`](crate::model_memory::math::calibration::CalibrationTracker)'s,
//! the fallback is the §2.9 mode controller, percentiles and their resolution are
//! `foundation::report`'s, and randomness is the seeded
//! [`SeededRng`](crate::model_memory::bench::rng::SeededRng).
//!
//! Every result is an offline evaluation on synthetic traces
//! ([`replay::EvaluationLabel`]): it validates the comparison and its invariants and is
//! never hardware validation or a performance claim.

use std::fmt;

use crate::foundation::report::ReportError;
use crate::model_memory::math::calibration::CalibrationError;
use crate::model_memory::math::prefetch::PrefetchError;
use crate::model_memory::math::InputError;
use crate::model_memory::residency::retention::CacheError;

pub mod acceptance;
pub mod guard;
pub mod markov;
pub mod optimal;
pub mod recency;
pub mod replay;
pub mod traces;

#[cfg(test)]
mod tests;

pub use acceptance::{
    judge, Acceptance, AcceptanceReport, AcceptanceRule, NotAcceptedReason, PatternComparison,
    PatternVerdict,
};
pub use guard::{
    rank_declared_steps, BaselineCause, GuardConfig, GuardedPredictor, PredictorMode, Ranking,
};
pub use markov::{MarkovConfig, MarkovPredictor};
pub use optimal::{optimal_schedule, ExhaustiveBounds, OptimalSchedule};
pub use recency::{RecencyConfig, RecencyPredictor};
pub use replay::{
    replay, CalibrationSummary, EvaluationLabel, GuardTrace, Guarding, PredictorKind, ReplayBudget,
    ReplayMetrics, ReplayPolicy, ReplayReport, ReplaySettings,
};
pub use traces::{ArrivalMode, CatalogObject, ReplayTrace, TraceKind, TraceRequest, TraceSpec};

/// One forecast: the probability that the next request is `key` (GPU §2.9: "Maintain
/// uncertainty and calibration").
#[derive(Clone, Debug, PartialEq)]
pub struct Forecast<K> {
    pub key: K,
    /// Recency or Markov: §2.9's tier after queued work and explicit intent.
    pub origin: crate::model_memory::math::prefetch::CandidateOrigin,
    /// Posterior mean of the probability, in [0, 1].
    pub probability: f64,
    /// Posterior standard deviation of the probability: the uncertainty measure.
    pub std_dev: f64,
    /// Observations the estimate rests on.
    pub observations: u64,
}

impl<K> Forecast<K> {
    /// The probability `z` standard deviations below the mean, at least zero: a
    /// conservative value for decisions that must not trust thin evidence.
    pub fn lower_bound(&self, z: f64) -> f64 {
        (self.probability - z.max(0.0) * self.std_dev).clamp(0.0, 1.0)
    }
}

/// An online next-request predictor with bounded memory.
pub trait Predictor<K> {
    /// The §2.9 origin its forecasts carry.
    fn origin(&self) -> crate::model_memory::math::prefetch::CandidateOrigin;

    /// Learns that `key` was requested.
    fn observe(&mut self, key: &K);

    /// One forecast for each of `candidates`, in their order; never a key not among them.
    fn forecast(&self, candidates: &[K]) -> Vec<Forecast<K>>;

    /// Entries the predictor holds now; never more than its configuration allows.
    fn footprint(&self) -> usize;
}

impl<K, P: Predictor<K> + ?Sized> Predictor<K> for Box<P> {
    fn origin(&self) -> crate::model_memory::math::prefetch::CandidateOrigin {
        (**self).origin()
    }

    fn observe(&mut self, key: &K) {
        (**self).observe(key);
    }

    fn forecast(&self, candidates: &[K]) -> Vec<Forecast<K>> {
        (**self).forecast(candidates)
    }

    fn footprint(&self) -> usize {
        (**self).footprint()
    }
}

/// The mean and standard deviation of one category's probability under a symmetric
/// Dirichlet prior of `prior` per category over `categories` categories, after `count`
/// of `total` observations fell in it: the Beta marginal, with mean (c + a) / (n + m·a)
/// and variance p(1 − p) / (n + m·a + 1).
pub(crate) fn posterior(count: u64, total: u64, categories: usize, prior: f64) -> (f64, f64) {
    let mass = total as f64 + categories as f64 * prior;
    if mass <= 0.0 {
        return (0.0, 0.0);
    }
    let mean = ((count as f64 + prior) / mass).clamp(0.0, 1.0);
    let variance = mean * (1.0 - mean) / (mass + 1.0);
    (mean, variance.max(0.0).sqrt())
}

/// Why a predictor, trace, replay or judgement was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum PredictionError {
    /// A setting is out of range.
    InvalidConfig {
        field: &'static str,
        reason: &'static str,
    },
    /// A trace names an object its catalog does not hold, or holds it twice.
    UnknownObject {
        key: String,
    },
    DuplicateObject {
        key: String,
    },
    /// One request needs more than the budget's capacity.
    DoesNotFit {
        key: String,
        bytes: u64,
        capacity: u64,
    },
    /// The exhaustive optimum accepts only tiny traces.
    TooLargeForExhaustive {
        objects: usize,
        requests: usize,
        max_objects: usize,
        max_requests: usize,
    },
    /// The exhaustive search held more states than its bound.
    SearchBoundExceeded {
        states: usize,
        max_states: usize,
    },
    /// A time or byte count does not fit in 64 bits.
    Overflow {
        field: &'static str,
    },
    Input(InputError),
    Calibration(CalibrationError),
    Prefetch(PrefetchError),
    Cache(CacheError),
    Report(ReportError),
}

impl fmt::Display for PredictionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { field, reason } => write!(f, "{field}: {reason}"),
            Self::UnknownObject { key } => write!(f, "no object {key:?} in the catalog"),
            Self::DuplicateObject { key } => write!(f, "the catalog lists {key:?} twice"),
            Self::DoesNotFit {
                key,
                bytes,
                capacity,
            } => write!(
                f,
                "{key:?} needs {bytes} bytes, more than the capacity of {capacity}"
            ),
            Self::TooLargeForExhaustive {
                objects,
                requests,
                max_objects,
                max_requests,
            } => write!(
                f,
                "the exhaustive optimum takes at most {max_objects} objects and \
                 {max_requests} requests, not {objects} and {requests}"
            ),
            Self::SearchBoundExceeded { states, max_states } => write!(
                f,
                "the exhaustive search held {states} states, more than {max_states}"
            ),
            Self::Overflow { field } => write!(f, "{field} does not fit in 64 bits"),
            Self::Input(error) => error.fmt(f),
            Self::Calibration(error) => error.fmt(f),
            Self::Prefetch(error) => error.fmt(f),
            Self::Cache(error) => error.fmt(f),
            Self::Report(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for PredictionError {}

impl From<InputError> for PredictionError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl From<CalibrationError> for PredictionError {
    fn from(error: CalibrationError) -> Self {
        Self::Calibration(error)
    }
}

impl From<PrefetchError> for PredictionError {
    fn from(error: PrefetchError) -> Self {
        Self::Prefetch(error)
    }
}

impl From<CacheError> for PredictionError {
    fn from(error: CacheError) -> Self {
        Self::Cache(error)
    }
}

impl From<ReportError> for PredictionError {
    fn from(error: ReportError) -> Self {
        Self::Report(error)
    }
}
