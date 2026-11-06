//! Request preparation from known future work, prototyped on the fake runners (GPU §4.1
//! lines 663–669; §2.9 lines 463–472; GPU-W06 lines 1064–1077).
//!
//! Three policies replay the same seeded mixed traces ([`Trace`]): demand-only,
//! recency/Markov (a first-order transition model learned online), and explicit workflow
//! intent (queued work as strong intent, UI selections and hover as rate-limited weak
//! intent). Two ablations each drop one intent component, so the multi-component
//! candidate has an ablation of each (§1.1). Each episode is a fresh fake runner with the
//! previous model serving; while the tool runs, a policy may prepare the next model with
//! a bounded [`PrepareOperation`] admitted by the §2.9 expected value, speculative budget
//! and demand-only fallback; then the request arrives and is served. Every attempt is a
//! CORE-08 record of the fake substrate, measured on TTFT, wasted bytes, retained memory
//! and foreground p99, and each policy's preparations are judged by [`account`] against
//! the matched demand-only episodes.
//!
//! The fake runner cannot drop prepared state, so a preparation released before its
//! request (superseded, expired or cancelled) runs on its own disposable runner from the
//! same factory and clock: its time and bytes are measured, and its state cannot serve
//! the request. An episode whose released preparation would otherwise have served the
//! request is replayed from a copy of the policy state with that preparation moved.
//!
//! # Claim record
//!
//! 1. Contribution: prepare the next model from explicit workflow intent (queued work,
//!    rate-limited UI selections) under a deadline, cancellation and retention TTL, and
//!    keep a preparation only if its benefit survives lifecycle accounting.
//! 2. Closest prior work named by the plan: prefetch as an investment with recency/Markov
//!    prediction and a demand-only fallback (GPU §2.9), and the request-deadline
//!    hypothesis of GPU §4 over existing bulk loaders.
//! 3. Difference tested: known future work instead of statistical guessing, on the same
//!    traces, under equal speculative budgets.
//! 4. Assumptions: queued work names the model its next request needs; a request never
//!    arrives before its declared earliest time; preparation does not slow the serving
//!    model. Smallest counterexample: a workflow that reorders its queue after the
//!    preparation started, so the prepared model is never requested.
//! 5. Baseline: the stronger of demand-only and recency/Markov on the same traces.
//! 6. Result: [`PreparationExperiment::claim`]; on the fake substrate at most
//!    inconclusive, and rejected or narrowed where intent loses.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use super::claim::{CellVerdict, ClaimRecord, ClaimText, ComparisonCell, Experiment};
use super::intent::{
    account, AdmittedIntent, Arrival, CancelReason, CancellationToken, ForegroundGuard,
    IntentDecision, IntentGate, IntentSource, LifecycleAccount, LifecycleEntry, LifecyclePrices,
    PreparationVerdict, PrepareBounds, PrepareOperation, PrepareRequest, PrepareState,
    PrepareTarget, PrepareWork, WeakIntentLimits,
};
use super::measure::{interval_nanos, measure, Measurement, MixPercentile, OutsideRecords};
use super::ReadinessError;
use crate::foundation::ids::{
    Clock, ExecutionId, ManualClock, MonotonicTime, OperationId, TenantId,
};
use crate::foundation::report::{
    ArrivalMode, BenchId, EffectClass, ExperimentDesign, IntervalKind, Label, LatencyObjective,
    LoadDescription, NoncePlacement, Provenance, Quantile, RunRecord, TracePattern,
};
use crate::model_memory::bench::corpus::{Corpus, Fixture, NonceSource};
use crate::model_memory::bench::load::RunnerFactory;
use crate::model_memory::bench::profile::{RunnerMode, RunnerProfile};
use crate::model_memory::bench::rng::SeededRng;
use crate::model_memory::bench::runner::{
    FakeRunner, RequestPlan, RetryPolicy, Script, UserScript,
};
use crate::model_memory::boundaries::PreparationStep;
use crate::model_memory::math::calibration::{
    CalibrationTracker, ModeController, ModeSignals, ModeThresholds,
};
use crate::model_memory::math::prefetch::{
    expected_value, CandidateOrigin, PrefetchBudget, PrefetchCandidate, PrefetchError,
    PrefetchScheduler, RawCost,
};
use crate::model_memory::math::CandidateId;

const PPM: u64 = 1_000_000;
const NANOS_PER_SECOND: f64 = 1e9;
/// Long enough never to bind a fake request.
const GENEROUS_NANOS: u64 = 3_600 * 1_000_000_000;
/// Replays of one episode before giving up.
const MAX_PASSES: usize = 4;

/// The claim record text of this experiment (GPU §4.17).
pub const CLAIM_TEXT: ClaimText = ClaimText {
    contribution: "Prepare the next model from explicit workflow intent (queued work and \
                   rate-limited UI selections) under a deadline, cancellation token and \
                   retention TTL, keeping a preparation only if its benefit survives \
                   lifecycle accounting",
    closest_prior_work: "Prefetch as an investment with recency/Markov prediction and a \
                         demand-only fallback (GPU §2.9)",
    difference_tested: "Known future work instead of statistical guessing on the same \
                        traces and speculative budget",
    assumptions: &[
        "queued work names the model its next request needs",
        "a request never arrives before its declared earliest time",
        "preparation does not slow the serving model",
    ],
    smallest_counterexample: "a workflow that reorders its queue after preparation started, \
                              so the prepared model is never requested",
    baseline: "the stronger of demand-only and recency/Markov on the same traces",
};

/// A preparation policy (GPU §4.1), with the two ablations of workflow intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Policy {
    DemandOnly,
    RecencyMarkov,
    WorkflowIntent,
    /// Workflow intent without UI intent (ablates UI selections and hover).
    QueuedWorkOnly,
    /// Workflow intent without queued work (ablates queued work).
    UiIntentOnly,
}

impl Policy {
    pub const ALL: [Self; 5] = [
        Self::DemandOnly,
        Self::RecencyMarkov,
        Self::WorkflowIntent,
        Self::QueuedWorkOnly,
        Self::UiIntentOnly,
    ];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::DemandOnly => "demand-only",
            Self::RecencyMarkov => "recency-markov",
            Self::WorkflowIntent => "workflow-intent",
            Self::QueuedWorkOnly => "queued-work-only",
            Self::UiIntentOnly => "ui-intent-only",
        }
    }

    const fn uses(self, source: IntentSource) -> bool {
        match self {
            Self::WorkflowIntent => true,
            Self::QueuedWorkOnly => matches!(source, IntentSource::QueuedWorkflow),
            Self::UiIntentOnly => matches!(source, IntentSource::UiSelection | IntentSource::Hover),
            Self::DemandOnly | Self::RecencyMarkov => false,
        }
    }
}

/// How the traces are generated (§1.1 mixed traces, not predictable alternation).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TraceSpec {
    /// At least three models, each also in the runner profile.
    pub models: Vec<Label>,
    pub episodes: u32,
    /// The earliest a request follows the previous one (the shortest tool run).
    pub min_gap_nanos: u64,
    pub max_gap_nanos: u64,
    /// Parts per million of episodes whose next model is the current model's usual
    /// successor; the rest pick another model uniformly.
    pub usual_successor_ppm: u32,
    /// Parts per million of episodes driven by queued workflow work.
    pub workflow_ppm: u32,
    /// How often queued work names the model actually requested.
    pub workflow_accuracy_ppm: u32,
    /// Parts per million of episodes with UI selection (and hover) events.
    pub ui_ppm: u32,
    pub ui_accuracy_ppm: u32,
    /// Hover events before a UI selection, over random models.
    pub hovers: u32,
    pub hover_spacing_nanos: u64,
    /// The earliest a request follows a UI selection.
    pub min_think_nanos: u64,
    /// Requests to the same model after the switch.
    pub follow_ups: u32,
}

/// One intent signal during an episode's gap.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IntentSignal {
    pub offset_nanos: u64,
    pub source: IntentSource,
    pub model: Label,
    /// Queued work declares when its tool finishes.
    pub eta_offset_nanos: Option<u64>,
}

/// One episode: `from` serves, a tool runs for `gap_nanos`, then `next` is requested.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Episode {
    pub from: Label,
    pub next: Label,
    pub gap_nanos: u64,
    pub signals: Vec<IntentSignal>,
}

/// A seeded mixed trace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Trace {
    pub seed: u64,
    pub episodes: Vec<Episode>,
}

fn ppm(field: &'static str, value: u32) -> Result<u64, ReadinessError> {
    if u64::from(value) > PPM {
        return Err(ReadinessError::InvalidSpec {
            field,
            reason: "at most 1000000 parts per million",
        });
    }
    Ok(u64::from(value))
}

fn pick<'a>(rng: &mut SeededRng, choices: &[&'a Label]) -> Result<&'a Label, ReadinessError> {
    let index = rng.below(choices.len() as u64) as usize;
    choices
        .get(index)
        .copied()
        .ok_or(ReadinessError::InvalidSpec {
            field: "models",
            reason: "no model to choose from",
        })
}

impl Trace {
    /// Generates the trace of `spec` from `seed`: a Markov chain over the models with a
    /// usual successor, queued work that names the next model with the given accuracy,
    /// and UI episodes of rapid hovers followed by one selection.
    pub fn generate(spec: &TraceSpec, seed: u64) -> Result<Self, ReadinessError> {
        let invalid = |field, reason| ReadinessError::InvalidSpec { field, reason };
        let models = &spec.models;
        if models.len() < 3 {
            return Err(invalid("models", "at least three models"));
        }
        if models.iter().collect::<BTreeSet<_>>().len() != models.len() {
            return Err(invalid("models", "each model once"));
        }
        if spec.min_gap_nanos == 0 || spec.min_gap_nanos > spec.max_gap_nanos {
            return Err(invalid(
                "min_gap_nanos",
                "positive and at most max_gap_nanos",
            ));
        }
        let usual = ppm("usual_successor_ppm", spec.usual_successor_ppm)?;
        let workflow = ppm("workflow_ppm", spec.workflow_ppm)?;
        let workflow_accuracy = ppm("workflow_accuracy_ppm", spec.workflow_accuracy_ppm)?;
        let ui = ppm("ui_ppm", spec.ui_ppm)?;
        let ui_accuracy = ppm("ui_accuracy_ppm", spec.ui_accuracy_ppm)?;
        if workflow + ui > PPM {
            return Err(invalid(
                "ui_ppm",
                "workflow and UI episodes exceed every episode",
            ));
        }
        let selection_offset = u64::from(spec.hovers)
            .checked_mul(spec.hover_spacing_nanos)
            .ok_or(ReadinessError::Overflow)?;
        if selection_offset
            .checked_add(spec.min_think_nanos)
            .is_none_or(|earliest| earliest > spec.min_gap_nanos)
        {
            return Err(invalid(
                "min_think_nanos",
                "a selection plus the think time must fit in the shortest gap",
            ));
        }
        let mut rng = SeededRng::new(seed);
        let mut from = models[0].clone();
        let mut episodes = Vec::new();
        for _ in 0..spec.episodes {
            let position = models
                .iter()
                .position(|model| *model == from)
                .ok_or(invalid("models", "the chain left the model set"))?;
            let successor = &models[(position + 1) % models.len()];
            let others: Vec<&Label> = models.iter().filter(|model| **model != from).collect();
            let next = if rng.below(PPM) < usual {
                successor.clone()
            } else {
                pick(&mut rng, &others)?.clone()
            };
            let gap_nanos =
                spec.min_gap_nanos + rng.below(spec.max_gap_nanos - spec.min_gap_nanos + 1);
            let wrong: Vec<&Label> = models.iter().filter(|model| **model != next).collect();
            let named = |rng: &mut SeededRng, accuracy: u64| -> Result<Label, ReadinessError> {
                if rng.below(PPM) < accuracy {
                    Ok(next.clone())
                } else {
                    Ok(pick(rng, &wrong)?.clone())
                }
            };
            let kind = rng.below(PPM);
            let mut signals = Vec::new();
            if kind < workflow {
                signals.push(IntentSignal {
                    offset_nanos: 0,
                    source: IntentSource::QueuedWorkflow,
                    model: named(&mut rng, workflow_accuracy)?,
                    eta_offset_nanos: Some(gap_nanos),
                });
            } else if kind < workflow + ui {
                for hover in 0..u64::from(spec.hovers) {
                    signals.push(IntentSignal {
                        offset_nanos: hover * spec.hover_spacing_nanos,
                        source: IntentSource::Hover,
                        model: pick(&mut rng, &others)?.clone(),
                        eta_offset_nanos: None,
                    });
                }
                signals.push(IntentSignal {
                    offset_nanos: selection_offset,
                    source: IntentSource::UiSelection,
                    model: named(&mut rng, ui_accuracy)?,
                    eta_offset_nanos: None,
                });
            }
            episodes.push(Episode {
                from: from.clone(),
                next: next.clone(),
                gap_nanos,
                signals,
            });
            from = next;
        }
        Ok(Self { seed, episodes })
    }

    /// The §1.1 trace label of this trace.
    pub fn pattern(&self) -> TracePattern {
        TracePattern::Mixed { seed: self.seed }
    }
}

/// What a preparation does on the fake runner, by runner mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrepareAction {
    /// Read the weights into the host page cache (restart and verified-reload modes).
    HostCopy,
    /// Load into a process and sleep it (version-supported sleep).
    LoadAsleep,
    /// Load into a resident process (retained process).
    LoadRetained,
}

impl PrepareAction {
    pub const fn for_mode(mode: RunnerMode) -> Self {
        match mode {
            RunnerMode::RetainedProcess => Self::LoadRetained,
            RunnerMode::VersionSupportedSleep => Self::LoadAsleep,
            RunnerMode::VerifiedReload | RunnerMode::FullProcessRestart => Self::HostCopy,
        }
    }

    /// The fake's nominal durations of the work, in order.
    fn parts(self, profile: &RunnerProfile, model: &Label) -> Result<Vec<u64>, ReadinessError> {
        let timings = &profile.model(model)?.timings;
        let startup = profile.runner.engine_startup_nanos;
        Ok(match self {
            Self::HostCopy => vec![timings.host_read_nanos],
            Self::LoadAsleep => vec![
                startup,
                timings.cold_load_nanos,
                timings.graph_capture_nanos,
                timings.sleep_nanos,
            ],
            Self::LoadRetained => vec![
                startup,
                timings.cold_load_nanos,
                timings.graph_capture_nanos,
            ],
        })
    }

    /// The longest the work can take under the profile's seeded variation: each part at
    /// its largest varied value. Admission checks deadlines against this bound.
    pub fn worst_case_nanos(
        self,
        profile: &RunnerProfile,
        model: &Label,
    ) -> Result<u64, ReadinessError> {
        let spread = u128::from(profile.variation.spread_ppm());
        self.parts(profile, model)?
            .into_iter()
            .try_fold(0u64, |total, nanos| {
                let delta = u128::from(nanos) * spread / u128::from(PPM);
                let longest = u64::try_from(u128::from(nanos) + delta).ok()?;
                total.checked_add(longest)
            })
            .ok_or(ReadinessError::Overflow)
    }

    /// The request time a ready preparation saves on the nominal timings.
    pub fn saved_seconds(
        self,
        profile: &RunnerProfile,
        model: &Label,
    ) -> Result<f64, ReadinessError> {
        let timings = &profile.model(model)?.timings;
        let startup = profile.runner.engine_startup_nanos;
        let demand = startup
            .saturating_add(timings.cold_load_nanos)
            .saturating_add(timings.graph_capture_nanos);
        let saved = match self {
            Self::HostCopy => timings
                .cold_load_nanos
                .saturating_sub(timings.warm_load_nanos),
            Self::LoadAsleep => demand.saturating_sub(timings.wake_nanos),
            Self::LoadRetained => demand.saturating_sub(profile.runner.hot_dispatch_nanos),
        };
        Ok(saved as f64 / NANOS_PER_SECOND)
    }
}

/// Every parameter of the experiment.
#[derive(Clone, Debug)]
pub struct PreparationSpec {
    pub trace: TraceSpec,
    /// Independent trials, each its own trace seed and burst (§1.1).
    pub trials: u32,
    pub seed: u64,
    /// The exact identity each model label prepares.
    pub targets: BTreeMap<Label, PrepareTarget>,
    pub execution: ExecutionId,
    pub tenant: TenantId,
    pub bounds: PrepareBounds,
    pub retention_ttl: Duration,
    pub limits: WeakIntentLimits,
    pub budget: PrefetchBudget,
    pub prices: LifecyclePrices,
    pub thresholds: ModeThresholds,
    pub block_bytes: u64,
    pub max_output_tokens: u32,
    pub latency_objective: LatencyObjective,
    /// Relative foreground p99 increase tolerated.
    pub p99_tolerance: f64,
    /// Relative difference of net scores treated as a tie.
    pub tie_tolerance: f64,
    pub calibration_bins: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
enum SourceKey {
    Queued,
    Selection,
    Hover,
    Markov,
}

impl SourceKey {
    const fn of(source: IntentSource) -> Self {
        match source {
            IntentSource::QueuedWorkflow => Self::Queued,
            IntentSource::UiSelection => Self::Selection,
            IntentSource::Hover => Self::Hover,
        }
    }

    /// Beta prior (hits, misses) of each intent source: strong intent starts near 0.9,
    /// a selection at 0.5 and hover at 0.25.
    const fn prior(self) -> (f64, f64) {
        match self {
            Self::Queued => (9.0, 1.0),
            Self::Selection => (1.0, 1.0),
            Self::Hover => (1.0, 3.0),
            Self::Markov => (0.0, 0.0),
        }
    }
}

/// One policy's learned state; copied before each episode so a replay starts from it.
#[derive(Clone, Debug)]
struct PolicyState {
    policy: Policy,
    transitions: BTreeMap<Label, BTreeMap<Label, u64>>,
    outcomes: BTreeMap<SourceKey, (u64, u64)>,
    calibration: CalibrationTracker,
    mode: ModeController,
    scheduler: PrefetchScheduler,
    operations: u64,
}

impl PolicyState {
    fn new(policy: Policy, spec: &PreparationSpec) -> Result<Self, ReadinessError> {
        Ok(Self {
            policy,
            transitions: BTreeMap::new(),
            outcomes: BTreeMap::new(),
            calibration: CalibrationTracker::new(spec.calibration_bins)?,
            mode: ModeController::new(spec.thresholds)?,
            scheduler: PrefetchScheduler::new(spec.budget)?,
            operations: 0,
        })
    }

    /// The calibrated probability that an intent of `key` names the requested model.
    fn intent_probability(&self, key: SourceKey) -> f64 {
        let (hits, total) = self.outcomes.get(&key).copied().unwrap_or((0, 0));
        let (prior_hits, prior_misses) = key.prior();
        (hits as f64 + prior_hits) / (total as f64 + prior_hits + prior_misses)
    }

    /// The most likely next model after `from` with its Laplace-smoothed probability.
    fn markov_prediction(&self, from: &Label, models: &[Label]) -> Option<(Label, f64)> {
        let counts = self.transitions.get(from);
        let total: u64 = counts.map_or(0, |counts| counts.values().sum());
        let others = models.len().saturating_sub(1) as f64;
        models
            .iter()
            .filter(|model| *model != from)
            .map(|model| {
                let count = counts
                    .and_then(|counts| counts.get(model))
                    .copied()
                    .unwrap_or(0);
                (
                    model.clone(),
                    (count as f64 + 1.0) / (total as f64 + others),
                )
            })
            .fold(None, |best: Option<(Label, f64)>, (model, p)| match best {
                Some((_, best_p)) if best_p >= p => best,
                _ => Some((model, p)),
            })
    }

    fn observe(&mut self, episode: &Episode, run: &EpisodeRun) -> Result<(), ReadinessError> {
        for prediction in &run.predictions {
            self.calibration
                .record(prediction.probability, prediction.hit)?;
            if prediction.key != SourceKey::Markov {
                let entry = self.outcomes.entry(prediction.key).or_insert((0, 0));
                entry.0 += u64::from(prediction.hit);
                entry.1 += 1;
            }
        }
        *self
            .transitions
            .entry(episode.from.clone())
            .or_default()
            .entry(episode.next.clone())
            .or_insert(0) += 1;
        Ok(())
    }
}

/// One preparation of one episode, as it ran.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PrepRun {
    pub trial: u32,
    pub episode: u32,
    pub operation: OperationId,
    pub model: Label,
    #[serde(serialize_with = "super::wire::origin")]
    pub origin: CandidateOrigin,
    /// The intent source, or `None` for a recency/Markov prediction.
    pub source: Option<IntentSource>,
    pub probability: f64,
    pub used: bool,
    pub prepared_bytes: u64,
    /// Memory the prepared state held on the runner: VRAM, pinned host memory and, for a
    /// host copy, the page-cache bytes the fake does not count itself.
    pub retained_bytes: u64,
    pub ready_at: MonotonicTime,
    pub released_at: MonotonicTime,
    pub preparation_nanos: u64,
    /// Whether it ran on the episode's runner rather than a disposable one.
    pub on_episode_runner: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Prediction {
    key: SourceKey,
    probability: f64,
    hit: bool,
}

#[derive(Debug, Default)]
struct EpisodeRun {
    records: Vec<RunRecord>,
    switch_ttft_nanos: Option<u64>,
    preps: Vec<PrepRun>,
    refused: u32,
    predictions: Vec<Prediction>,
    rerun: BTreeSet<usize>,
}

struct Context<'a> {
    factory: &'a RunnerFactory,
    spec: &'a PreparationSpec,
    action: PrepareAction,
    fixture: Fixture,
    clock: Arc<ManualClock>,
    labels: BTreeMap<PrepareTarget, Label>,
}

impl Context<'_> {
    fn target(&self, model: &Label) -> Result<PrepareTarget, ReadinessError> {
        self.spec
            .targets
            .get(model)
            .copied()
            .ok_or_else(|| ReadinessError::UnknownModel {
                model: model.to_string(),
            })
    }

    fn label(&self, target: &PrepareTarget) -> Result<Label, ReadinessError> {
        self.labels
            .get(target)
            .cloned()
            .ok_or(ReadinessError::InvalidSpec {
                field: "targets",
                reason: "an admitted intent names no known model",
            })
    }

    fn advance_to(&self, at: MonotonicTime) {
        if self.clock.now() < at {
            self.clock.advance_to(at);
        }
    }
}

fn episode_stream(trial: u32, index: u32) -> u64 {
    u64::from(trial) * 1_000_000 + u64::from(index) * 100
}

/// A candidate preparation at the clock's now.
struct Candidate {
    model: Label,
    origin: CandidateOrigin,
    source: Option<IntentSource>,
    probability: f64,
    deadline: MonotonicTime,
}

struct Live {
    operation: PrepareOperation,
    run: PrepRun,
    index: usize,
}

struct Episodic<'a, 'b> {
    ctx: &'a Context<'b>,
    state: &'a mut PolicyState,
    runner: FakeRunner,
    episode: &'a Episode,
    trial: u32,
    index: u32,
    disposable: &'a BTreeSet<usize>,
    live: Vec<Live>,
    run: EpisodeRun,
}

impl Episodic<'_, '_> {
    fn try_prepare(&mut self, candidate: Candidate) -> Result<(), ReadinessError> {
        let ctx = self.ctx;
        if candidate.model == self.episode.from {
            return Ok(());
        }
        let now = ctx.clock.now();
        let active = |live: &Live| {
            matches!(
                live.operation.state(),
                PrepareState::Running { .. } | PrepareState::Ready { .. }
            )
        };
        if self
            .live
            .iter()
            .any(|live| live.run.model == candidate.model && active(live))
        {
            return Ok(());
        }
        // One live preparation per episode: a newer intent supersedes the older one.
        for live in self.live.iter_mut().filter(|live| active(live)) {
            if let PrepareState::Released { at, .. } = live
                .operation
                .cancel(CancelReason::Superseded, ctx.clock.as_ref())
            {
                live.run.released_at = at;
            }
        }
        let profile = &ctx.factory.profile;
        let bytes = profile.model(&candidate.model)?.weights_bytes;
        self.state.operations += 1;
        let operation = OperationId::new(format!(
            "op-prepare-{}-{}-{}",
            self.state.policy.slug(),
            self.trial,
            self.state.operations
        ))?;
        let hold_seconds = candidate
            .deadline
            .saturating_duration_since(now)
            .as_secs_f64();
        let value = expected_value(
            &PrefetchCandidate {
                id: CandidateId::new(operation.as_str())?,
                origin: candidate.origin,
                probability: candidate.probability,
                bytes,
                saved_if_used: RawCost {
                    milliseconds: ctx.action.saved_seconds(profile, &candidate.model)? * 1_000.0,
                    ..RawCost::default()
                },
                waste_if_unused: RawCost {
                    bytes: bytes as f64,
                    ..RawCost::default()
                },
                interference: RawCost::default(),
                retention: RawCost {
                    currency_units: bytes as f64
                        * hold_seconds
                        * ctx.spec.prices.currency_per_retained_byte_second,
                    ..RawCost::default()
                },
            },
            &ctx.spec.prices.objective,
        )?;
        let capacity = ctx.spec.budget.capacity_bytes.max(1) as f64;
        let signals = ModeSignals {
            confidence: candidate.probability,
            load_fraction: (self.state.scheduler.speculative_bytes() as f64 + bytes as f64)
                / capacity,
            calibration_error: self
                .state
                .calibration
                .expected_calibration_error()
                .unwrap_or(0.0),
        };
        let mode = self.state.mode.observe(now, signals)?;
        self.state.scheduler.set_mode(mode);
        match self.state.scheduler.start_speculative(
            operation.clone(),
            &value,
            ctx.spec.block_bytes,
        ) {
            Ok(()) => {}
            Err(PrefetchError::Refused(_)) => {
                self.run.refused += 1;
                return Ok(());
            }
            Err(other) => return Err(other.into()),
        }
        let request = PrepareRequest {
            operation: operation.clone(),
            execution: ctx.spec.execution.clone(),
            tenant: ctx.spec.tenant.clone(),
            target: ctx.target(&candidate.model)?,
            origin: candidate.origin,
            deadline: candidate.deadline,
            retention_ttl: ctx.spec.retention_ttl,
            cancellation: CancellationToken::new(),
            work: [
                PreparationStep::Reserve,
                PreparationStep::InboundTransfer,
                PreparationStep::Verify,
            ]
            .into_iter()
            .map(|step| PrepareWork::Step { step })
            .collect(),
            assigned_request: None,
        };
        let worst = Duration::from_nanos(ctx.action.worst_case_nanos(profile, &candidate.model)?);
        let mut prepared =
            match PrepareOperation::admit(request, worst, &ctx.spec.bounds, ctx.clock.as_ref()) {
                Ok(prepared) => prepared,
                Err(_) => {
                    self.state.scheduler.request_cancel(&operation)?;
                    self.run.refused += 1;
                    return Ok(());
                }
            };
        let index = self.live.len();
        let on_episode_runner = !self.disposable.contains(&index);
        let effect = if on_episode_runner {
            execute(&mut self.runner, ctx.action, &candidate.model)?
        } else {
            let stream = episode_stream(self.trial, self.index) + 1 + index as u64;
            let mut disposable = ctx.factory.fresh(stream)?;
            execute(&mut disposable, ctx.action, &candidate.model)?
        };
        prepared.complete(bytes, ctx.clock.as_ref())?;
        self.state.scheduler.record_progress(&operation, bytes)?;
        let ready_at = ctx.clock.now();
        self.live.push(Live {
            operation: prepared,
            run: PrepRun {
                trial: self.trial,
                episode: self.index,
                operation,
                model: candidate.model,
                origin: candidate.origin,
                source: candidate.source,
                probability: candidate.probability,
                used: false,
                prepared_bytes: bytes,
                retained_bytes: effect.retained_bytes,
                ready_at,
                released_at: ready_at,
                preparation_nanos: effect.nanos,
                on_episode_runner,
            },
            index,
        });
        Ok(())
    }

    fn admit_intent(
        &mut self,
        intent: AdmittedIntent,
        eta: Option<MonotonicTime>,
    ) -> Result<(), ReadinessError> {
        let ctx = self.ctx;
        let model = ctx.label(&intent.target)?;
        let key = SourceKey::of(intent.source);
        let probability = self.state.intent_probability(key);
        self.run.predictions.push(Prediction {
            key,
            probability,
            hit: model == self.episode.next,
        });
        let deadline = match eta {
            Some(eta) => eta,
            None => intent
                .observed_at
                .saturating_add(Duration::from_nanos(ctx.spec.trace.min_think_nanos)),
        };
        self.try_prepare(Candidate {
            model,
            origin: intent.source.origin(),
            source: Some(intent.source),
            probability,
            deadline,
        })
    }

    /// Admits pending weak intents whose dwell and spacing pass before `until`.
    fn drain_gate(
        &mut self,
        gate: &mut IntentGate,
        until: MonotonicTime,
    ) -> Result<(), ReadinessError> {
        loop {
            match gate.poll(self.ctx.clock.as_ref()) {
                IntentDecision::Admitted { intent } => self.admit_intent(intent, None)?,
                IntentDecision::Pending { ready_at: next }
                | IntentDecision::RateLimited { until: next }
                    if next < until =>
                {
                    self.ctx.advance_to(next);
                }
                _ => return Ok(()),
            }
        }
    }
}

struct Effect {
    nanos: u64,
    retained_bytes: u64,
}

fn execute(
    runner: &mut FakeRunner,
    action: PrepareAction,
    model: &Label,
) -> Result<Effect, ReadinessError> {
    let before = runner.snapshot();
    let weights = runner.profile().model(model)?.weights_bytes;
    let nanos = match action {
        PrepareAction::HostCopy => runner.warm_host_copy(model)?,
        PrepareAction::LoadAsleep => runner.prepare_asleep(model)?,
        PrepareAction::LoadRetained => runner.retain(model)?,
    };
    let after = runner.snapshot();
    let mut retained_bytes = after
        .vram_bytes
        .saturating_sub(before.vram_bytes)
        .saturating_add(
            after
                .pinned_host_bytes
                .saturating_sub(before.pinned_host_bytes),
        );
    if action == PrepareAction::HostCopy {
        retained_bytes = retained_bytes.saturating_add(weights);
    }
    Ok(Effect {
        nanos,
        retained_bytes,
    })
}

fn run_episode(
    ctx: &Context<'_>,
    state: &mut PolicyState,
    trial: u32,
    index: u32,
    episode: &Episode,
    disposable: &BTreeSet<usize>,
) -> Result<EpisodeRun, ReadinessError> {
    let stream = episode_stream(trial, index);
    let (runner, _start) = ctx
        .factory
        .started(stream, &episode.from, BenchId::Bench02)?;
    let gap_start = ctx.clock.now();
    let after = |nanos: u64| -> Result<MonotonicTime, ReadinessError> {
        gap_start
            .checked_add(Duration::from_nanos(nanos))
            .ok_or(ReadinessError::Overflow)
    };
    let arrival = after(episode.gap_nanos)?;
    let policy = state.policy;
    let mut work = Episodic {
        ctx,
        state,
        runner,
        episode,
        trial,
        index,
        disposable,
        live: Vec::new(),
        run: EpisodeRun::default(),
    };
    match policy {
        Policy::DemandOnly => {}
        Policy::RecencyMarkov => {
            if let Some((model, probability)) = work
                .state
                .markov_prediction(&episode.from, &ctx.spec.trace.models)
            {
                work.run.predictions.push(Prediction {
                    key: SourceKey::Markov,
                    probability,
                    hit: model == episode.next,
                });
                work.try_prepare(Candidate {
                    model,
                    origin: CandidateOrigin::Markov,
                    source: None,
                    probability,
                    deadline: after(ctx.spec.trace.min_gap_nanos)?,
                })?;
            }
        }
        Policy::WorkflowIntent | Policy::QueuedWorkOnly | Policy::UiIntentOnly => {
            let mut gate = IntentGate::new(ctx.spec.limits)?;
            for signal in episode
                .signals
                .iter()
                .filter(|signal| policy.uses(signal.source))
            {
                let at = after(signal.offset_nanos)?;
                work.drain_gate(&mut gate, at)?;
                ctx.advance_to(at);
                let target = ctx.target(&signal.model)?;
                if let IntentDecision::Admitted { intent } =
                    gate.observe(signal.source, target, ctx.clock.as_ref())
                {
                    let eta = signal.eta_offset_nanos.map(|eta| after(eta)).transpose()?;
                    work.admit_intent(intent, eta)?;
                }
            }
            work.drain_gate(&mut gate, arrival)?;
        }
    }
    if ctx.clock.now() > arrival {
        return Err(ReadinessError::PreparationOverran);
    }
    ctx.advance_to(arrival);
    let next = ctx.target(&episode.next)?;
    let mut run = std::mem::take(&mut work.run);
    for live in &mut work.live {
        let released_before = match live.operation.poll(ctx.clock.as_ref()) {
            PrepareState::Released { at, .. } => Some(at),
            _ => None,
        };
        let id = live.run.operation.clone();
        match live.operation.request_arrived(&next, ctx.clock.as_ref()) {
            Arrival::Used { .. } | Arrival::Promoted => {
                live.run.used = true;
                live.run.released_at = arrival;
                work.state.scheduler.promote(&id)?;
            }
            Arrival::NotUsed { .. } => live.run.released_at = arrival,
            Arrival::AlreadyReleased { .. } | Arrival::AlreadyConsumed => {
                if let Some(at) = released_before {
                    live.run.released_at = at;
                }
                if live.run.model == episode.next && live.run.on_episode_runner {
                    run.rerun.insert(live.index);
                }
            }
        }
        work.state.scheduler.release(&id)?;
        run.preps.push(live.run.clone());
    }
    let mut nonces = NonceSource::new(
        SeededRng::new(ctx.factory.stream_seed(stream)),
        NoncePlacement::PromptPrefix,
    );
    let mut requests = Vec::new();
    for position in 0..=ctx.spec.trace.follow_ups {
        requests.push(RequestPlan {
            variant: Label::new(if position == 0 {
                "prepare-switch"
            } else {
                "prepare-follow-up"
            })?,
            model: episode.next.clone(),
            request: nonces.render(&ctx.fixture)?,
            max_output_tokens: ctx.spec.max_output_tokens,
            deadline_nanos: GENEROUS_NANOS,
            timeout_nanos: GENEROUS_NANOS,
            gap_before_nanos: 0,
            switch_from_previous: false,
            burst: trial,
            check_response: false,
        });
    }
    let script = Script {
        bench: BenchId::Bench02,
        load: LoadDescription {
            concurrent_requests: 1,
            arrival: ArrivalMode::Sequential,
        },
        users: vec![UserScript {
            start_at: arrival,
            requests,
            retry: RetryPolicy::NONE,
        }],
        recycle_after_switches: None,
    };
    let outcome = work.runner.serve(&script)?;
    run.switch_ttft_nanos = outcome
        .records
        .iter()
        .find(|record| record.attempt.variant.as_str() == "prepare-switch")
        .filter(|record| record.is_success())
        .and_then(|record| interval_nanos(record, IntervalKind::TimeToFirstToken));
    run.records = outcome.records;
    Ok(run)
}

struct PolicyRun {
    policy: Policy,
    records: Vec<RunRecord>,
    switch_ttft: BTreeMap<(u32, u32), Option<u64>>,
    preps: Vec<PrepRun>,
    refused: u32,
    calibration: CalibrationTracker,
}

fn run_policy(
    ctx: &Context<'_>,
    policy: Policy,
    traces: &[Trace],
) -> Result<PolicyRun, ReadinessError> {
    let mut out = PolicyRun {
        policy,
        records: Vec::new(),
        switch_ttft: BTreeMap::new(),
        preps: Vec::new(),
        refused: 0,
        calibration: CalibrationTracker::new(ctx.spec.calibration_bins)?,
    };
    for (trial, trace) in (0u32..).zip(traces) {
        // Each trial learns from nothing, so trials stay independent (§1.1).
        let mut state = PolicyState::new(policy, ctx.spec)?;
        for (index, episode) in (0u32..).zip(&trace.episodes) {
            let mut disposable = BTreeSet::new();
            let mut finished = None;
            for _ in 0..MAX_PASSES {
                let mut attempt = state.clone();
                let run = run_episode(ctx, &mut attempt, trial, index, episode, &disposable)?;
                if run.rerun.is_empty() {
                    finished = Some((attempt, run));
                    break;
                }
                disposable.extend(run.rerun.iter().copied());
            }
            let (next_state, run) = finished.ok_or(ReadinessError::ReplayUnstable)?;
            state = next_state;
            state.observe(episode, &run)?;
            out.switch_ttft
                .insert((trial, index), run.switch_ttft_nanos);
            out.records.extend(run.records);
            out.preps.extend(run.preps);
            out.refused += run.refused;
            for prediction in &run.predictions {
                out.calibration
                    .record(prediction.probability, prediction.hit)?;
            }
        }
    }
    Ok(out)
}

/// One policy's measured result.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PolicyReport {
    pub policy: Policy,
    pub measurement: Measurement,
    /// Foreground p99 TTFT over every request, with its resolution; the per-case
    /// summaries in `measurement` show its composition.
    pub foreground_p99: Option<MixPercentile>,
    pub preparations: Vec<PrepRun>,
    /// Preparations refused by the expected value, the budget, the demand-only fallback
    /// or the prepare bounds.
    pub refused: u32,
    pub prepared_bytes: u64,
    pub wasted_bytes: u64,
    pub peak_retained_bytes: u64,
    pub retained_byte_seconds: f64,
    pub brier_score: Option<f64>,
    /// Lifecycle accounting against the matched demand-only episodes.
    pub lifecycle: LifecycleAccount,
}

impl PolicyReport {
    pub fn used(&self) -> usize {
        self.preparations.iter().filter(|prep| prep.used).count()
    }
}

/// The finished experiment.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PreparationExperiment {
    pub design: ExperimentDesign,
    pub traces: Vec<Trace>,
    pub reports: Vec<PolicyReport>,
    pub claim: ClaimRecord,
}

impl PreparationExperiment {
    pub fn report(&self, policy: Policy) -> Option<&PolicyReport> {
        self.reports.iter().find(|report| report.policy == policy)
    }

    /// The GPU §4.17 claim record.
    pub fn claim(&self) -> &ClaimRecord {
        &self.claim
    }
}

fn seconds_between(start: MonotonicTime, end: MonotonicTime) -> f64 {
    end.saturating_duration_since(start).as_secs_f64()
}

fn peak_retained(preps: &[PrepRun]) -> u64 {
    preps
        .iter()
        .map(|at| {
            preps
                .iter()
                .filter(|other| other.ready_at <= at.ready_at && at.ready_at < other.released_at)
                .map(|other| other.retained_bytes)
                .fold(0u64, u64::saturating_add)
        })
        .max()
        .unwrap_or(0)
}

fn report(
    spec: &PreparationSpec,
    run: PolicyRun,
    demand: &BTreeMap<(u32, u32), Option<u64>>,
    demand_measurement: Option<&Measurement>,
) -> Result<PolicyReport, ReadinessError> {
    let prepared_bytes = run
        .preps
        .iter()
        .map(|prep| prep.prepared_bytes)
        .fold(0u64, u64::saturating_add);
    let wasted_bytes = run
        .preps
        .iter()
        .filter(|prep| !prep.used)
        .map(|prep| prep.prepared_bytes)
        .fold(0u64, u64::saturating_add);
    let peak_retained_bytes = peak_retained(&run.preps);
    let measurement = measure(
        run.records,
        spec.latency_objective,
        OutsideRecords {
            transferred_bytes: prepared_bytes,
            retained_host_bytes: peak_retained_bytes,
        },
    )?;
    let mut entries = Vec::new();
    let mut charged_episodes = BTreeSet::new();
    let mut retained_byte_seconds = 0.0;
    for prep in &run.preps {
        let key = (prep.trial, prep.episode);
        let delta_seconds = match (
            demand.get(&key).copied().flatten(),
            run.switch_ttft.get(&key).copied().flatten(),
        ) {
            (Some(baseline), Some(own)) => (baseline as f64 - own as f64) / NANOS_PER_SECOND,
            _ => 0.0,
        };
        let interference_seconds = if charged_episodes.insert(key) {
            (-delta_seconds).max(0.0)
        } else {
            0.0
        };
        let held = prep.retained_bytes as f64 * seconds_between(prep.ready_at, prep.released_at);
        retained_byte_seconds += held;
        entries.push(LifecycleEntry {
            operation: prep.operation.clone(),
            origin: prep.origin,
            used: prep.used,
            saved_seconds: if prep.used {
                delta_seconds.max(0.0)
            } else {
                0.0
            },
            interference_seconds,
            wasted_bytes: if prep.used { 0 } else { prep.prepared_bytes },
            retained_byte_seconds: held,
            preparation_seconds: prep.preparation_nanos as f64 / NANOS_PER_SECOND,
        });
    }
    let p99 = |measurement: &Measurement| measurement.ttft_nanos(Quantile::P99).unwrap_or(0.0);
    let baseline = demand_measurement.unwrap_or(&measurement);
    let guard = ForegroundGuard {
        baseline_success_rate: baseline.success_rate(),
        candidate_success_rate: measurement.success_rate(),
        baseline_p99_nanos: p99(baseline),
        candidate_p99_nanos: p99(&measurement),
        p99_tolerance: spec.p99_tolerance,
    };
    let lifecycle = account(&entries, &spec.prices, &guard)?;
    Ok(PolicyReport {
        policy: run.policy,
        foreground_p99: measurement.ttft_percentile(Quantile::P99).cloned(),
        measurement,
        preparations: run.preps,
        refused: run.refused,
        prepared_bytes,
        wasted_bytes,
        peak_retained_bytes,
        retained_byte_seconds,
        brier_score: run.calibration.brier_score(),
        lifecycle,
    })
}

/// The verdict of workflow intent against demand-only: its own lifecycle account.
fn against_demand(candidate: &PolicyReport) -> CellVerdict {
    match candidate.lifecycle.verdict {
        PreparationVerdict::Succeeded => CellVerdict::Better,
        PreparationVerdict::NothingPrepared => CellVerdict::Tie,
        PreparationVerdict::Failed { .. } => CellVerdict::Worse,
    }
}

/// The verdict of workflow intent against another preparation policy: the foreground
/// must not regress against it, then net lifecycle scores are compared with a relative
/// tie band.
fn against_policy(
    candidate: &PolicyReport,
    baseline: &PolicyReport,
    spec: &PreparationSpec,
) -> CellVerdict {
    let p99 = |report: &PolicyReport| report.measurement.ttft_nanos(Quantile::P99).unwrap_or(0.0);
    let foreground_holds = candidate.measurement.success_rate()
        >= baseline.measurement.success_rate()
        && p99(candidate) <= p99(baseline) * (1.0 + spec.p99_tolerance);
    let (own, other) = (candidate.lifecycle.net_score, baseline.lifecycle.net_score);
    let band = spec.tie_tolerance * own.abs().max(other.abs());
    if !foreground_holds || own < other - band {
        CellVerdict::Worse
    } else if own > other + band {
        CellVerdict::Better
    } else {
        CellVerdict::Tie
    }
}

/// Runs the experiment on runners from `factory` (GPU §4.1). Every model of the trace
/// must be in the factory's profile and have a target; the preparation work follows the
/// profile's runner mode ([`PrepareAction::for_mode`]).
pub fn run_experiment(
    factory: &RunnerFactory,
    spec: &PreparationSpec,
) -> Result<PreparationExperiment, ReadinessError> {
    for model in &spec.trace.models {
        factory.profile.model(model)?;
        if !spec.targets.contains_key(model) {
            return Err(ReadinessError::UnknownModel {
                model: model.to_string(),
            });
        }
    }
    let labels: BTreeMap<PrepareTarget, Label> = spec
        .targets
        .iter()
        .map(|(label, target)| (*target, label.clone()))
        .collect();
    if labels.len() != spec.targets.len() {
        return Err(ReadinessError::InvalidSpec {
            field: "targets",
            reason: "two models share one target",
        });
    }
    let design = ExperimentDesign {
        effect: EffectClass::CacheOrPredictor,
        independent_trials: spec.trials,
        trace: TracePattern::Mixed { seed: spec.seed },
        components: vec![
            Label::new("queued-workflow-intent")?,
            Label::new("ui-selection-intent")?,
        ],
        ablated_components: vec![
            Label::new("queued-workflow-intent")?,
            Label::new("ui-selection-intent")?,
        ],
    };
    design.check()?;
    let traces = (0..spec.trials)
        .map(|trial| {
            Trace::generate(
                &spec.trace,
                spec.seed ^ u64::from(trial).wrapping_mul(0x9E37_79B9),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let corpus = Corpus::fast01()?;
    let fixture = corpus.get("fast01-tool-run-tests")?.clone();
    let ctx = Context {
        factory,
        spec,
        action: PrepareAction::for_mode(factory.profile.mode),
        fixture,
        clock: Arc::clone(&factory.clock),
        labels,
    };
    let mut runs = Vec::new();
    for policy in Policy::ALL {
        runs.push(run_policy(&ctx, policy, &traces)?);
    }
    let all_records: Vec<RunRecord> = runs.iter().flat_map(|run| run.records.clone()).collect();
    let provenance = Provenance::of_records(&all_records)?;
    let demand_ttft = runs
        .iter()
        .find(|run| run.policy == Policy::DemandOnly)
        .map(|run| run.switch_ttft.clone())
        .unwrap_or_default();
    let mut reports = Vec::new();
    let mut demand_measurement = None;
    for run in runs {
        let report = report(spec, run, &demand_ttft, demand_measurement.as_ref())?;
        if report.policy == Policy::DemandOnly {
            demand_measurement = Some(report.measurement.clone());
        }
        reports.push(report);
    }
    let find = |policy| {
        reports
            .iter()
            .find(|report| report.policy == policy)
            .ok_or(ReadinessError::InvalidSpec {
                field: "policies",
                reason: "a policy did not run",
            })
    };
    let intent = find(Policy::WorkflowIntent)?;
    let markov = find(Policy::RecencyMarkov)?;
    let cells = vec![
        ComparisonCell {
            label: Policy::DemandOnly.slug().to_string(),
            verdict: against_demand(intent),
        },
        ComparisonCell {
            label: Policy::RecencyMarkov.slug().to_string(),
            verdict: against_policy(intent, markov, spec),
        },
    ];
    let claim = ClaimRecord::new(
        Experiment::IntentPreparation,
        CLAIM_TEXT,
        &provenance,
        cells,
    )?;
    Ok(PreparationExperiment {
        design,
        traces,
        reports,
        claim,
    })
}

#[cfg(test)]
mod tests;
