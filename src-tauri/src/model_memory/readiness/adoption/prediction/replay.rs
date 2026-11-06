//! The deterministic trace-replay evaluator (GPU-W06, line 1245: "Build tiny offline
//! optimal schedules and trace replay comparisons"; acceptance at line 1249; §4.1 line
//! 841: "Measure TTFT, wasted bytes, retained memory and foreground p99"; the predictor
//! gate at line 1446: "Better latency under equal memory/traffic budget; report misses
//! and wasted work").
//!
//! Every policy replays a [`ReplayTrace`] under the trace's own [`ReplayBudget`], so
//! budgets are equal by construction, through a
//! [`ResidencyCache`] whose capacity is the budget's and whose eviction policy is one of
//! the [`CachePolicy`] baselines (LRU, cost-per-byte, and the dependency-aware marginal
//! saved latency and GreedyDual-Size, shared bases charged once). The cache keeps every
//! residency invariant.
//!
//! The replay clock: requests arrive as the trace's [`ArrivalMode`] says, each its gap
//! after the previous request's arrival (open loop) or readiness (closed loop). One
//! loader serves demand loads in arrival order. A request waits for the loader to finish
//! earlier demand loads, then for its missing objects, loaded one after another; its
//! wait is the time from arrival until everything it needs is resident. After serving a
//! request, a [`ReplayPolicy::PredictionAssisted`] policy may prepare candidates for the
//! next request while the loader is free and before the end of the next request's
//! declared gap, so a preparation never delays a request:
//!
//! 1. the guarded predictor ranks the trace's declared targets (the declared-intent gate)
//!    and is scored at the next request whether or not anything is prepared;
//! 2. while it assists, each forecast whose target is not fully resident becomes a §2.9
//!    [`PrefetchCandidate`] valued at its conservative probability
//!    ([`Forecast::lower_bound`]) by [`rank_candidates`], which keeps positive expected
//!    values only;
//! 3. in that order, a candidate is prepared when it still fits the gap's prepared-byte
//!    budget and the time left in the declared gap, through the same cache, which evicts
//!    by the same baseline. A preparation enters the cache as an ordinary load does, so
//!    the baseline sees it as a use.
//!
//! A prepared object is used when a later request needs it while it is still resident;
//! it is wasted when it is evicted first or the trace ends. Nothing is prepared after
//! the last request. The guard's load signal is zero: the gap's prepared-byte budget
//! bounds speculative work here.
//!
//! Every report carries [`EvaluationLabel::OfflineSyntheticTraces`]: an offline
//! evaluation on synthetic traces, never hardware validation.

use std::collections::BTreeMap;
use std::time::Duration;

use super::guard::{BaselineCause, GuardConfig, GuardedPredictor, PredictorMode};
use super::markov::{MarkovConfig, MarkovPredictor};
use super::recency::{RecencyConfig, RecencyPredictor};
use super::traces::{ArrivalMode, ReplayTrace, TraceKind};
use super::{Forecast, PredictionError, Predictor};
use crate::foundation::ids::{ManualClock, MonotonicTime};
use crate::foundation::report::{percentile, PercentileMethod, Quantile};
use crate::model_memory::bundles::baselines::CachePolicy;
use crate::model_memory::math::calibration::{ModeThresholds, ReliabilityBin};
use crate::model_memory::math::prefetch::{rank_candidates, Objective, PrefetchCandidate, RawCost};
use crate::model_memory::math::CandidateId;
use crate::model_memory::readiness::adoption::governor::RollbackCause;
use crate::model_memory::residency::retention::{
    AccessOutcome, CacheError, CostPerByte, GreedyDualSize, Lru, MarginalSavedLatency,
    ResidencyCache, RetentionPolicy,
};

const NANOS_PER_MILLISECOND: f64 = 1e6;

/// What every result here is (GPU §4.17 discipline; S12 G0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvaluationLabel {
    /// An offline evaluation on seeded synthetic traces: it checks the comparison and its
    /// invariants and backs no hardware, performance or release claim.
    OfflineSyntheticTraces,
}

impl EvaluationLabel {
    pub const fn describe(self) -> &'static str {
        match self {
            Self::OfflineSyntheticTraces => {
                "offline evaluation on synthetic traces; not hardware validation"
            }
        }
    }

    /// Always false: nothing here ran on hardware.
    pub const fn is_hardware_validation(self) -> bool {
        match self {
            Self::OfflineSyntheticTraces => false,
        }
    }
}

/// The budget every policy replays one trace under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayBudget {
    /// Device bytes resident at once: the cache capacity of every policy.
    pub capacity_bytes: u64,
    /// Bytes a policy may prepare in one gap between requests.
    pub max_prepared_bytes_per_gap: u64,
}

/// Which predictor assists.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PredictorKind {
    Recency(RecencyConfig),
    Markov(MarkovConfig),
}

impl PredictorKind {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Recency(_) => "recency",
            Self::Markov(_) => "markov",
        }
    }

    fn build(self) -> Result<Box<dyn Predictor<String>>, PredictionError> {
        Ok(match self {
            Self::Recency(config) => Box::new(RecencyPredictor::new(config)?),
            Self::Markov(config) => Box::new(MarkovPredictor::new(config)?),
        })
    }
}

/// Whether the guard decides when forecasts are acted on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Guarding {
    /// Forecasts are acted on only while the guard assists.
    Guarded,
    /// The ablation without the guard: every ranking is acted on, from the first.
    Unguarded,
}

/// One replayed policy.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ReplayPolicy {
    /// Demand loads only, evicting by a residency baseline.
    DemandOnly { eviction: CachePolicy },
    /// The same baseline, plus preparation ranked by a predictor.
    PredictionAssisted {
        eviction: CachePolicy,
        predictor: PredictorKind,
        guard: GuardConfig,
        guarding: Guarding,
    },
}

impl ReplayPolicy {
    pub fn eviction(&self) -> CachePolicy {
        match self {
            Self::DemandOnly { eviction } | Self::PredictionAssisted { eviction, .. } => *eviction,
        }
    }

    /// A short name for reports.
    pub fn label(&self) -> String {
        match self {
            Self::DemandOnly { eviction } => format!("demand-only/{}", eviction.label()),
            Self::PredictionAssisted {
                eviction,
                predictor,
                guarding,
                ..
            } => format!(
                "{}{}/{}",
                predictor.slug(),
                match guarding {
                    Guarding::Guarded => "",
                    Guarding::Unguarded => "-unguarded",
                },
                eviction.label()
            ),
        }
    }

    /// The demand-only run with the same eviction policy: the ablation that removes
    /// prediction, and the declared baseline of [`super::acceptance`].
    pub fn matched_baseline(&self) -> Self {
        Self::DemandOnly {
            eviction: self.eviction(),
        }
    }
}

/// The residency baselines of the evaluation: LRU and cost-per-byte (§2.7), marginal
/// saved latency and GreedyDual-Size (dependency-aware, shared bases once).
pub const BASELINES: [CachePolicy; 4] = [
    CachePolicy::Lru,
    CachePolicy::CostPerByte,
    CachePolicy::MarginalSavedLatency {
        half_life_steps: 64,
    },
    CachePolicy::GreedyDualSize,
];

/// The evaluation's recency predictor.
pub const STANDARD_RECENCY: RecencyConfig = RecencyConfig {
    depth: 8,
    window: 64,
    prior: 0.5,
};

/// The evaluation's guard: sixteen scored requests, acted on after eight; fall back below
/// a 0.3 top-forecast hit rate or above a 0.3 Brier score, recover at 0.5 and 0.2 held
/// for a minute of replay time.
pub const STANDARD_GUARD: GuardConfig = GuardConfig {
    window_steps: 16,
    min_scored_steps: 8,
    thresholds: ModeThresholds {
        enter_below_confidence: 0.3,
        exit_at_confidence: 0.5,
        enter_above_load_fraction: 1.0,
        exit_at_load_fraction: 0.9,
        enter_above_calibration_error: 0.3,
        exit_at_calibration_error: 0.2,
        recovery_dwell: Duration::from_secs(60),
    },
    calibration_bins: 10,
};

impl ReplayPolicy {
    /// The evaluation's policies: the four baselines demand-only, then guarded Markov and
    /// recency on LRU and guarded Markov on GreedyDual-Size.
    pub fn standard_set() -> Vec<Self> {
        let mut policies: Vec<Self> = BASELINES
            .iter()
            .map(|eviction| Self::DemandOnly {
                eviction: *eviction,
            })
            .collect();
        for (eviction, predictor) in [
            (
                CachePolicy::Lru,
                PredictorKind::Markov(super::traces::STANDARD_MARKOV),
            ),
            (CachePolicy::Lru, PredictorKind::Recency(STANDARD_RECENCY)),
            (
                CachePolicy::GreedyDualSize,
                PredictorKind::Markov(super::traces::STANDARD_MARKOV),
            ),
        ] {
            policies.push(Self::PredictionAssisted {
                eviction,
                predictor,
                guard: STANDARD_GUARD,
                guarding: Guarding::Guarded,
            });
        }
        policies
    }
}

/// How preparations are valued (§2.9).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ReplaySettings {
    /// The declared objective a candidate's expected value is scored in.
    pub objective: Objective,
    /// Standard deviations below the mean at which a forecast's probability is taken
    /// ([`Forecast::lower_bound`]); zero for the mean.
    pub confidence_z: f64,
}

impl ReplaySettings {
    /// One score unit per saved millisecond and per 4 MB wasted (a wasted gigabyte costs
    /// as much as 250 ms), with probabilities one standard deviation below the mean.
    pub fn standard() -> Result<Self, PredictionError> {
        Ok(Self {
            objective: Objective::new(1.0, 0.25e-6, 0.0, 0.0)?,
            confidence_z: 1.0,
        })
    }
}

/// What one replay measured.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReplayMetrics {
    pub requests: u64,
    /// Requests whose needed objects were all resident when served.
    pub hits: u64,
    /// Hits that used a prepared object.
    pub prepared_hits: u64,
    /// Load time on the request path.
    pub demand_load_nanos: u64,
    pub total_wait_nanos: u64,
    /// Each request's wait on the replay clock, in trace order.
    pub waits: Vec<u64>,
    /// Nearest-rank percentiles of `waits`.
    pub p50_wait_nanos: f64,
    pub p95_wait_nanos: f64,
    pub p99_wait_nanos: f64,
    pub demand_loaded_bytes: u64,
    pub preparations: u64,
    pub prepared_bytes: u64,
    /// Prepared bytes a later request used while they were resident.
    pub used_prepared_bytes: u64,
    /// Prepared bytes evicted before any request used them, or never used.
    pub wasted_bytes: u64,
    pub peak_resident_bytes: u64,
    /// The most bytes prepared in one gap.
    pub peak_prepared_bytes_in_gap: u64,
}

/// Calibration of every forecast scored during a replay.
#[derive(Clone, Debug, PartialEq)]
pub struct CalibrationSummary {
    pub forecasts: u64,
    pub brier_score: Option<f64>,
    pub expected_calibration_error: Option<f64>,
    pub bins: Vec<ReliabilityBin>,
}

/// What the guard did during a replay.
#[derive(Clone, Debug, PartialEq)]
pub struct GuardTrace {
    /// Gaps in which forecasts were acted on.
    pub assisting_gaps: u64,
    /// Gaps in which forecasts were only scored.
    pub shadow_gaps: u64,
    /// Times the controller fell back from assisting to demand-only.
    pub fallbacks: u64,
    /// The index of the first request at which the controller fell back.
    pub first_fallback_at: Option<usize>,
    pub final_mode: PredictorMode,
    /// The most entries the guard and its predictor held.
    pub peak_footprint: usize,
}

/// One policy's replay of one trace.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplayReport {
    pub label: EvaluationLabel,
    pub kind: TraceKind,
    pub seed: u64,
    pub policy: ReplayPolicy,
    pub budget: ReplayBudget,
    pub metrics: ReplayMetrics,
    /// For prediction-assisted policies.
    pub calibration: Option<CalibrationSummary>,
    pub guard: Option<GuardTrace>,
}

fn build_eviction(policy: CachePolicy) -> Result<Box<dyn RetentionPolicy>, PredictionError> {
    Ok(match policy {
        CachePolicy::Lru => Box::new(Lru),
        CachePolicy::CostPerByte => Box::new(CostPerByte),
        CachePolicy::MarginalSavedLatency { half_life_steps } => {
            Box::new(MarginalSavedLatency::new(half_life_steps).map_err(CacheError::Input)?)
        }
        CachePolicy::GreedyDualSize => Box::new(GreedyDualSize::new()),
    })
}

/// Nearest-rank percentiles of `waits`; zero for an empty list.
pub(crate) fn wait_percentile(waits: &[u64], quantile: Quantile) -> Result<f64, PredictionError> {
    if waits.is_empty() {
        return Ok(0.0);
    }
    let mut sorted = waits.to_vec();
    sorted.sort_unstable();
    Ok(percentile(
        &sorted,
        quantile,
        PercentileMethod::NearestRank,
    )?)
}

fn add(total: u64, value: u64, field: &'static str) -> Result<u64, PredictionError> {
    total
        .checked_add(value)
        .ok_or(PredictionError::Overflow { field })
}

fn after(at: MonotonicTime, nanos: u64) -> Result<MonotonicTime, PredictionError> {
    at.checked_add(Duration::from_nanos(nanos))
        .ok_or(PredictionError::Overflow {
            field: "replay time",
        })
}

struct Replay<'a> {
    trace: &'a ReplayTrace,
    cache: ResidencyCache<Box<dyn RetentionPolicy>>,
    clock: ManualClock,
    /// Prepared objects no request used yet, with their bytes.
    pending: BTreeMap<String, u64>,
    metrics: ReplayMetrics,
}

impl Replay<'_> {
    fn object(&self, key: &str) -> Result<(u64, u64), PredictionError> {
        self.trace
            .object(key)
            .map(|object| (object.bytes, object.load_nanos))
            .ok_or_else(|| PredictionError::UnknownObject {
                key: key.to_string(),
            })
    }

    /// The bytes and load time of what `key` still lacks.
    fn missing(&self, key: &str) -> Result<(u64, u64), PredictionError> {
        let mut bytes = 0u64;
        let mut nanos = 0u64;
        for name in self.trace.closure(key)? {
            if !self.cache.is_resident(&name) {
                let (object_bytes, object_nanos) = self.object(&name)?;
                bytes = add(bytes, object_bytes, "missing bytes")?;
                nanos = add(nanos, object_nanos, "missing load time")?;
            }
        }
        Ok((bytes, nanos))
    }

    /// The load time of what an access loaded; evicted prepared objects become waste.
    fn settle(&mut self, outcome: &AccessOutcome) -> Result<u64, PredictionError> {
        let mut nanos = 0u64;
        for name in &outcome.loaded {
            nanos = add(nanos, self.object(name)?.1, "load time")?;
        }
        for eviction in &outcome.evictions {
            if let Some(bytes) = self.pending.remove(&eviction.object) {
                self.metrics.wasted_bytes = add(self.metrics.wasted_bytes, bytes, "wasted bytes")?;
            }
        }
        self.metrics.peak_resident_bytes = self
            .metrics
            .peak_resident_bytes
            .max(self.cache.resident_bytes());
        Ok(nanos)
    }

    /// Serves one request from `start`; returns when its needs are resident.
    fn serve(
        &mut self,
        target: &str,
        start: MonotonicTime,
    ) -> Result<MonotonicTime, PredictionError> {
        self.clock.advance_to(start);
        let mut used = false;
        for name in self.trace.closure(target)? {
            if self.cache.is_resident(&name) {
                if let Some(bytes) = self.pending.remove(&name) {
                    used = true;
                    self.metrics.used_prepared_bytes =
                        add(self.metrics.used_prepared_bytes, bytes, "used bytes")?;
                }
            }
        }
        let outcome = self.cache.access(target, &self.clock)?;
        let nanos = self.settle(&outcome)?;
        if outcome.hit {
            self.metrics.hits += 1;
            if used {
                self.metrics.prepared_hits += 1;
            }
        }
        self.metrics.demand_load_nanos = add(self.metrics.demand_load_nanos, nanos, "load time")?;
        self.metrics.demand_loaded_bytes = add(
            self.metrics.demand_loaded_bytes,
            outcome.loaded_bytes,
            "loaded bytes",
        )?;
        after(start, nanos)
    }

    /// Prepares from `forecasts` between `from` and `window_end`; returns when the loader
    /// is free again.
    fn prepare(
        &mut self,
        forecasts: &[Forecast<String>],
        settings: &ReplaySettings,
        from: MonotonicTime,
        window_end: MonotonicTime,
    ) -> Result<MonotonicTime, PredictionError> {
        let mut candidates = Vec::new();
        for forecast in forecasts {
            let (bytes, nanos) = self.missing(&forecast.key)?;
            if bytes == 0 {
                continue;
            }
            candidates.push(PrefetchCandidate {
                id: CandidateId::new(forecast.key.as_str())?,
                origin: forecast.origin,
                probability: forecast.lower_bound(settings.confidence_z),
                bytes,
                saved_if_used: RawCost {
                    milliseconds: nanos as f64 / NANOS_PER_MILLISECOND,
                    ..RawCost::default()
                },
                waste_if_unused: RawCost {
                    bytes: bytes as f64,
                    ..RawCost::default()
                },
                interference: RawCost::default(),
                retention: RawCost::default(),
            });
        }
        let budget = self.trace.budget.max_prepared_bytes_per_gap;
        let mut at = from;
        let mut spent = 0u64;
        for value in rank_candidates(&candidates, &settings.objective)? {
            let key = value.candidate.as_str();
            let (bytes, nanos) = self.missing(key)?;
            if bytes == 0 || add(spent, bytes, "prepared bytes")? > budget {
                continue;
            }
            if after(at, nanos)? > window_end {
                continue;
            }
            self.clock.advance_to(at);
            let outcome = match self.cache.access(key, &self.clock) {
                Ok(outcome) => outcome,
                Err(CacheError::NoRoom { .. }) => continue,
                Err(error) => return Err(error.into()),
            };
            let loaded = self.settle(&outcome)?;
            for name in &outcome.loaded {
                let object_bytes = self.object(name)?.0;
                self.pending.insert(name.clone(), object_bytes);
            }
            spent = add(spent, outcome.loaded_bytes, "prepared bytes")?;
            self.metrics.prepared_bytes = add(
                self.metrics.prepared_bytes,
                outcome.loaded_bytes,
                "prepared bytes",
            )?;
            self.metrics.preparations += 1;
            at = after(at, loaded)?;
        }
        self.metrics.peak_prepared_bytes_in_gap =
            self.metrics.peak_prepared_bytes_in_gap.max(spent);
        Ok(at)
    }
}

/// Replays `trace` under `policy` (see the module documentation).
pub fn replay(
    trace: &ReplayTrace,
    policy: &ReplayPolicy,
    settings: &ReplaySettings,
) -> Result<ReplayReport, PredictionError> {
    trace.check()?;
    if !settings.confidence_z.is_finite() || settings.confidence_z < 0.0 {
        return Err(PredictionError::InvalidConfig {
            field: "confidence_z",
            reason: "a finite number of zero or more",
        });
    }
    let mut guard = match policy {
        ReplayPolicy::DemandOnly { .. } => None,
        ReplayPolicy::PredictionAssisted {
            predictor,
            guard,
            guarding,
            ..
        } => {
            let mut guarded = GuardedPredictor::new(predictor.build()?, *guard)?;
            guarded.enable();
            Some((guarded, *guarding))
        }
    };
    let mut state = Replay {
        trace,
        cache: ResidencyCache::new(&trace.cache_config(), build_eviction(policy.eviction())?)?,
        clock: ManualClock::new(MonotonicTime::ZERO),
        pending: BTreeMap::new(),
        metrics: ReplayMetrics::default(),
    };
    let mut log = GuardTrace {
        assisting_gaps: 0,
        shadow_gaps: 0,
        fallbacks: 0,
        first_fallback_at: None,
        final_mode: PredictorMode::Baseline {
            cause: BaselineCause::RolledBack(RollbackCause::Default),
        },
        peak_footprint: 0,
    };
    let mut loader_free = MonotonicTime::ZERO;
    let mut previous_arrival = MonotonicTime::ZERO;
    let mut previous_ready = MonotonicTime::ZERO;
    for (index, request) in trace.requests.iter().enumerate() {
        let gap_start = match trace.arrivals {
            ArrivalMode::Open => previous_arrival,
            ArrivalMode::Closed => previous_ready,
        };
        let arrival = gap_start
            .checked_add(request.gap)
            .ok_or(PredictionError::Overflow {
                field: "replay time",
            })?;
        if let Some((guarded, _)) = guard.as_mut() {
            let before = guarded.fallbacks();
            guarded.observe(&request.target, arrival, 0.0)?;
            if guarded.fallbacks() > before && log.first_fallback_at.is_none() {
                log.first_fallback_at = Some(index);
            }
        }
        let start = arrival.max(loader_free);
        let ready = state.serve(&request.target, start)?;
        let wait = u64::try_from(ready.saturating_duration_since(arrival).as_nanos())
            .map_err(|_| PredictionError::Overflow { field: "wait" })?;
        state.metrics.requests += 1;
        state.metrics.waits.push(wait);
        state.metrics.total_wait_nanos = add(state.metrics.total_wait_nanos, wait, "total wait")?;
        loader_free = ready;
        previous_arrival = arrival;
        previous_ready = ready;
        let Some((guarded, guarding)) = guard.as_mut() else {
            continue;
        };
        let ranking = guarded.rank(&trace.declared);
        log.peak_footprint = log.peak_footprint.max(guarded.footprint());
        let act = match guarding {
            Guarding::Guarded => ranking.actionable(),
            Guarding::Unguarded => ranking.forecasts.as_slice(),
        };
        let Some(next) = trace.requests.get(index + 1).filter(|_| !act.is_empty()) else {
            log.shadow_gaps += 1;
            continue;
        };
        log.assisting_gaps += 1;
        // The next request arrives no earlier than its declared gap after this one's
        // arrival (open) or readiness (closed).
        let window_end = match trace.arrivals {
            ArrivalMode::Open => arrival,
            ArrivalMode::Closed => ready,
        }
        .checked_add(next.declared_gap)
        .ok_or(PredictionError::Overflow {
            field: "replay time",
        })?;
        if ready < window_end {
            loader_free = state.prepare(act, settings, ready, window_end)?;
        }
    }
    let leftover = state
        .pending
        .values()
        .try_fold(0u64, |total, bytes| add(total, *bytes, "wasted bytes"))?;
    state.metrics.wasted_bytes = add(state.metrics.wasted_bytes, leftover, "wasted bytes")?;
    state.metrics.p50_wait_nanos = wait_percentile(&state.metrics.waits, Quantile::P50)?;
    state.metrics.p95_wait_nanos = wait_percentile(&state.metrics.waits, Quantile::P95)?;
    state.metrics.p99_wait_nanos = wait_percentile(&state.metrics.waits, Quantile::P99)?;
    let (calibration, guard_log) = match guard {
        Some((guarded, _)) => {
            let tracker = guarded.calibration();
            log.fallbacks = guarded.fallbacks();
            log.final_mode = guarded.mode();
            (
                Some(CalibrationSummary {
                    forecasts: tracker.count(),
                    brier_score: tracker.brier_score(),
                    expected_calibration_error: tracker.expected_calibration_error(),
                    bins: tracker.reliability_bins(),
                }),
                Some(log),
            )
        }
        None => (None, None),
    };
    Ok(ReplayReport {
        label: EvaluationLabel::OfflineSyntheticTraces,
        kind: trace.kind,
        seed: trace.seed,
        policy: *policy,
        budget: trace.budget,
        metrics: state.metrics,
        calibration,
        guard: guard_log,
    })
}

/// Replays every policy over every trace, trace by trace.
pub fn replay_all(
    traces: &[ReplayTrace],
    policies: &[ReplayPolicy],
    settings: &ReplaySettings,
) -> Result<Vec<ReplayReport>, PredictionError> {
    let mut reports = Vec::with_capacity(traces.len() * policies.len());
    for trace in traces {
        for policy in policies {
            reports.push(replay(trace, policy, settings)?);
        }
    }
    Ok(reports)
}
