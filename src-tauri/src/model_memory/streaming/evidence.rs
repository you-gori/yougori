//! Simulated results as CORE-08 evidence, and the GPU §4.17 claim records (lines
//! 908–915; plan S12 G0).
//!
//! Every simulated attempt becomes a [`RunRecord`] on the fake, time-controlled substrate;
//! a template on any other substrate is refused, so a simulation can never be labelled a
//! measurement. A policy's records become a [`ComparisonSide`] whose provenance
//! [`Provenance::of_records`] derives from those records — the fake substrate — and the
//! sides meet in a [`ComparisonReport`] against both required baselines (§2.1). Such a
//! report validates the comparison and backs no claim: [`ImprovementClaim`] refuses it.
//!
//! [`decide`] turns a comparison into the §4.17 result. A candidate that loses to its
//! strongest compatible baseline is rejected (or narrowed when it still beats the ordinary
//! workflow); one that misses its declared objective while gaining capacity is narrowed to
//! a capacity-only mode; anything else on fakes is at most inconclusive.
//!
//! [`ImprovementClaim`]: crate::foundation::report::ImprovementClaim

use std::time::Duration;

use crate::foundation::ids::{ManualClock, MonotonicTime, OperationId};
use crate::foundation::report::{
    percentile, AttemptIdentity, AttemptRole, Baseline, BaselineOutcome, BaselineUnavailable,
    CacheTier, ClockId, ClockReading, ColdProvenance, ComparisonReport, ComparisonSide, Direction,
    EffectClass, EventKind, EventRecorder, ExperimentDesign, FailureKind, IntervalKind, Label,
    LatencyObjective, MatchedConfiguration, Measured, ModeFidelity, ModelAtArrival, NonNegative,
    NotMeasuredReason, ObjectivePlan, ObjectiveVector, Offload, Outcome, PercentileMethod,
    PrefillMode, Provenance, Quantile, RunMeasurements, RunRecord, RunSubstrate, Scenario,
    StartState, StartTemperature, StateComparison, SuccessRate, TracePattern,
};
use crate::model_memory::bench::rng::{SeededRng, Variation};

use super::architecture::{PlannedRequest, StreamingModel};
use super::deadline::{plan_streaming, OrderPolicy, ReadCostModel, StreamingBudget};
use super::simulate::{
    co_runner, run_fake, FakeOutcome, FakeRun, FakeSubstrate, FaultPlan, InterferenceModel,
};
use super::window::{best_window, DecodeReloadCost, ExactOp, WindowProblem};
use super::StreamingError;

/// How a simulated attempt started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptStart {
    /// The model was not loaded: the load is inside the first-token clock (S8).
    DemandLoad,
    /// A co-running request on a model already serving.
    Hot,
}

/// How a simulated attempt ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptEnd {
    Succeeded,
    Cancelled,
    OutOfMemory,
}

/// One simulated attempt, ready to become a run record.
#[derive(Clone, Debug, PartialEq)]
pub struct SimulatedAttempt {
    pub variant: Label,
    pub start: AttemptStart,
    pub end: AttemptEnd,
    /// When the first-token dependencies were usable; at or before the first token.
    pub dependencies_usable_seconds: Option<f64>,
    /// Emitted tokens, the first token first.
    pub token_times_seconds: Vec<f64>,
    pub transferred_bytes: u64,
    pub peak_gpu_bytes: u64,
    pub offload: Offload,
}

impl SimulatedAttempt {
    /// A fake streaming run's attempt.
    pub fn from_fake_run(variant: Label, run: &FakeRun, peak_gpu_bytes: u64) -> Self {
        let (end, token_times_seconds) = match run.outcome {
            FakeOutcome::FirstToken { at_seconds } => (AttemptEnd::Succeeded, vec![at_seconds]),
            FakeOutcome::Cancelled { .. } => (AttemptEnd::Cancelled, Vec::new()),
            FakeOutcome::OutOfMemory { .. } => (AttemptEnd::OutOfMemory, Vec::new()),
        };
        Self {
            variant,
            start: AttemptStart::DemandLoad,
            end,
            dependencies_usable_seconds: run.dependencies_usable_seconds,
            token_times_seconds,
            transferred_bytes: run.transferred_bytes,
            peak_gpu_bytes,
            offload: Offload::NoOffload,
        }
    }
}

fn label(text: &str) -> Result<Label, StreamingError> {
    Ok(Label::new(text)?)
}

fn nanos(seconds: f64) -> Result<u64, StreamingError> {
    let seconds = super::non_negative("event time", seconds)?;
    Ok((seconds * 1e9).round() as u64)
}

/// Records one simulated attempt on the fake substrate. The template supplies the
/// matched configuration (model, precision, host, client, launch) and must itself be on
/// the fake substrate.
pub fn record_attempt(
    template: &RunRecord,
    attempt: &SimulatedAttempt,
    operation: OperationId,
    burst: u32,
) -> Result<RunRecord, StreamingError> {
    if template.substrate != RunSubstrate::FakeTimeControlled {
        return Err(StreamingError::SimulationOnRealSubstrate);
    }
    let clock = ManualClock::new(MonotonicTime::ZERO);
    let mut recorder = EventRecorder::new(
        operation.clone(),
        ClockId::new(label("fake-clock")?),
        &clock,
    );
    recorder.record(EventKind::RequestAccepted);
    recorder.record(EventKind::RequestDequeued);
    if attempt.start == AttemptStart::DemandLoad {
        recorder.record(EventKind::LoadStarted);
    }
    let succeeded = attempt.end == AttemptEnd::Succeeded;
    if succeeded {
        let first = *attempt
            .token_times_seconds
            .first()
            .ok_or(StreamingError::Invalid {
                field: "token_times_seconds",
                reason: "a successful attempt emits a token",
            })?;
        let mut stamped: Vec<(u64, EventKind)> = Vec::new();
        if attempt.start == AttemptStart::DemandLoad {
            let loaded = attempt.dependencies_usable_seconds.unwrap_or(first);
            if loaded > first {
                return Err(StreamingError::Invalid {
                    field: "dependencies_usable_seconds",
                    reason: "a first token never precedes its dependencies",
                });
            }
            stamped.push((nanos(loaded)?, EventKind::LoadCompleted));
        }
        for at in &attempt.token_times_seconds {
            stamped.push((nanos(*at)?, EventKind::TokenEmitted));
        }
        stamped.sort_by_key(|(at, _)| *at);
        let last = stamped.last().map_or(0, |(at, _)| *at);
        for (at, event) in stamped {
            clock.advance_to(MonotonicTime::from_nanos(at));
            recorder.record(event);
        }
        clock.advance_to(MonotonicTime::from_nanos(last));
        recorder.record(EventKind::RequestCompleted);
    }
    let outcome = match attempt.end {
        AttemptEnd::Succeeded => Outcome::Succeeded,
        AttemptEnd::Cancelled => Outcome::Failed {
            failure: FailureKind::EarlyTermination,
            component: label("streaming")?,
            code: label("cancelled")?,
        },
        AttemptEnd::OutOfMemory => Outcome::Failed {
            failure: FailureKind::CommandFailure,
            component: label("streaming")?,
            code: label("out-of-memory")?,
        },
    };
    let state = match attempt.start {
        AttemptStart::DemandLoad => StartState {
            temperature: StartTemperature::Warm,
            model_at_arrival: ModelAtArrival::NotLoaded,
            cache_tier: CacheTier::LocalDisk,
            prefill: PrefillMode::Fresh,
            cold_provenance: ColdProvenance::NotCold,
        },
        AttemptStart::Hot => StartState {
            temperature: StartTemperature::Hot,
            model_at_arrival: ModelAtArrival::ReadyToServe,
            cache_tier: CacheTier::GpuMemory,
            prefill: PrefillMode::Fresh,
            cold_provenance: ColdProvenance::NotCold,
        },
    };
    let record = RunRecord {
        schema_version: template.schema_version,
        attempt: AttemptIdentity {
            bench: template.attempt.bench,
            variant: attempt.variant.clone(),
            execution: template.attempt.execution.clone(),
            operation,
            role: AttemptRole::Initial,
            burst,
            deadline_nanos: not(NotMeasuredReason::NotApplicable),
        },
        scenario: Scenario::Serving,
        substrate: RunSubstrate::FakeTimeControlled,
        build: template.build.clone(),
        execution_category: template.execution_category,
        model: template.model.clone(),
        precision: template.precision.clone(),
        engine: template.engine.clone(),
        host: template.host.clone(),
        workload: template.workload.clone(),
        client: template.client.clone(),
        load: template.load.clone(),
        state: Measured::measured(state),
        launch: template.launch.clone(),
        price: not(NotMeasuredReason::NotApplicable),
        measurements: RunMeasurements {
            output_tokens: if succeeded {
                Measured::measured(attempt.token_times_seconds.len() as u64)
            } else {
                not(NotMeasuredReason::RunEndedFirst)
            },
            prefill_tokens_per_second: not(NotMeasuredReason::NotRecorded),
            aggregate_decode_tokens_per_second: not(NotMeasuredReason::NotRecorded),
            speculative: not(NotMeasuredReason::NotApplicable),
            peak_gpu_memory_bytes: Measured::measured(attempt.peak_gpu_bytes),
            retained_gpu_memory_bytes: Measured::measured(attempt.peak_gpu_bytes),
            peak_host_memory_bytes: not(NotMeasuredReason::InstrumentUnavailable),
            retained_host_memory_bytes: not(NotMeasuredReason::InstrumentUnavailable),
            peak_pinned_host_memory_bytes: not(NotMeasuredReason::InstrumentUnavailable),
            transferred_bytes: Measured::measured(attempt.transferred_bytes),
            storage_read_bytes: Measured::measured(attempt.transferred_bytes),
            energy_joules: not(NotMeasuredReason::InstrumentUnavailable),
            offload: Measured::measured(attempt.offload),
            first_run: not(NotMeasuredReason::NotApplicable),
            owner_return: not(NotMeasuredReason::NotApplicable),
            reasoning: not(NotMeasuredReason::NotApplicable),
        },
        events: recorder.into_events(),
        outcome,
    };
    record.validate()?;
    Ok(record)
}

/// An explicit "not measured" cell.
fn not<T>(reason: NotMeasuredReason) -> Measured<T> {
    Measured::not_measured(reason)
}

fn non_negative_measure(value: f64) -> Result<Measured<NonNegative>, StreamingError> {
    Ok(Measured::measured(NonNegative::new(value)?))
}

/// One side of a comparison from its records: first-token p95 (nearest rank) over the
/// successful attempts, reliability over all of them, and steady-generation throughput
/// from `throughput` records (a co-running request, or the attempts themselves when they
/// decode). Host memory, energy and cost need hardware and stay not measured.
pub fn comparison_side(
    name: Label,
    records: &[RunRecord],
    throughput: &[RunRecord],
    latency_objective: LatencyObjective,
) -> Result<ComparisonSide, StreamingError> {
    let first = records.first().ok_or(StreamingError::Invalid {
        field: "records",
        reason: "a side has at least one attempt",
    })?;
    let mut ttft: Vec<u64> = records
        .iter()
        .filter(|record| record.is_success())
        .map(|record| {
            record
                .interval(IntervalKind::TimeToFirstToken)
                .map(|i| i.elapsed_nanos())
        })
        .collect::<Result<_, _>>()?;
    ttft.sort_unstable();
    let successes = records.iter().filter(|record| record.is_success()).count() as u64;
    let rate = SuccessRate::new(successes, records.len() as u64)?;
    let time_to_first_token_nanos = if ttft.is_empty() {
        Measured::not_measured(NotMeasuredReason::NoSuccessfulRuns)
    } else {
        non_negative_measure(percentile(
            &ttft,
            Quantile::P95,
            PercentileMethod::NearestRank,
        )?)?
    };
    let mut rates = Vec::new();
    for record in throughput {
        if let ClockReading::Serving(clock) = record.clock_reading()? {
            if let Some(rate) = clock.decode_tokens_per_second.value() {
                rates.push(*rate);
            }
        }
    }
    let throughput_measure = if rates.is_empty() {
        Measured::not_measured(NotMeasuredReason::NotRecorded)
    } else {
        non_negative_measure(rates.iter().sum::<f64>() / rates.len() as f64)?
    };
    let peak = records
        .iter()
        .filter_map(|record| record.measurements.peak_gpu_memory_bytes.value().copied())
        .max()
        .unwrap_or(0);
    let moved = records
        .iter()
        .filter_map(|record| record.measurements.transferred_bytes.value().copied())
        .max()
        .unwrap_or(0);
    let mut all = records.to_vec();
    all.extend_from_slice(throughput);
    Ok(ComparisonSide {
        name,
        provenance: Provenance::of_records(&all)?,
        configuration: MatchedConfiguration::from_record(first)?,
        temperature: StartTemperature::Warm,
        fidelity: ModeFidelity::BitIdentical,
        accuracy_evaluation: not(NotMeasuredReason::NotApplicable),
        objectives: ObjectiveVector {
            time_to_first_token_quantile: Quantile::P95,
            latency_objective,
            time_to_first_token_nanos,
            throughput_under_latency_objective_tokens_per_second: throughput_measure,
            peak_gpu_memory_bytes: non_negative_measure(peak as f64)?,
            retained_gpu_memory_bytes: non_negative_measure(peak as f64)?,
            peak_host_memory_bytes: not(NotMeasuredReason::InstrumentUnavailable),
            retained_host_memory_bytes: not(NotMeasuredReason::InstrumentUnavailable),
            transferred_bytes: non_negative_measure(moved as f64)?,
            storage_read_bytes: non_negative_measure(moved as f64)?,
            preparation_cost_usd: not(NotMeasuredReason::NotApplicable),
            cost_per_completed_request_usd: not(NotMeasuredReason::NotApplicable),
            energy_per_completed_request_joules: not(NotMeasuredReason::InstrumentUnavailable),
            reliability_success_rate: non_negative_measure(rate.rate())?,
        },
    })
}

/// How a candidate stands against one baseline on the declared objective.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    Better,
    Tied,
    Worse,
}

/// The standing in a finished comparison; `None` when the baseline could not run.
pub fn standing(outcome: &BaselineOutcome) -> Option<Standing> {
    let BaselineOutcome::Compared { verdict, .. } = outcome else {
        return None;
    };
    let change = &verdict.declared;
    let tolerance = 1e-9 * change.baseline.abs().max(1.0);
    let (better, worse) = match change.objective.direction() {
        Direction::LowerIsBetter => (
            change.candidate < change.baseline - tolerance,
            change.candidate > change.baseline + tolerance,
        ),
        Direction::HigherIsBetter => (
            change.candidate > change.baseline + tolerance,
            change.candidate < change.baseline - tolerance,
        ),
    };
    Some(if better {
        Standing::Better
    } else if worse {
        Standing::Worse
    } else {
        Standing::Tied
    })
}

/// A §4.17 result (line 915), with the narrowing rule-11 and §4.10 line 758 add.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimOutcome {
    UsefulIntegration,
    SupportedOriginalContribution,
    Inconclusive,
    Rejected,
    Narrowed { scope: NarrowedScope },
}

/// What a narrowed mechanism remains good for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NarrowedScope {
    /// It gains capacity but misses the declared latency objective: a clearly labelled
    /// capacity-only option.
    CapacityOnly,
    /// It beats the ordinary workflow but loses to the strongest compatible baseline,
    /// which should be integrated instead.
    BelowStrongestBaseline,
}

/// What a decision needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimInputs {
    pub against_strongest: Option<Standing>,
    pub against_ordinary: Option<Standing>,
    /// Whether the declared objective, such as an interactive per-token latency, holds.
    pub declared_objective_met: bool,
    pub fake_substrate: bool,
    /// Whether an explicit literature and implementation comparison was made (§4.0
    /// line 659).
    pub literature_compared: bool,
}

impl ClaimInputs {
    /// The standings of a finished comparison; the fake substrate is read from every
    /// side's provenance.
    pub fn from_report(
        report: &ComparisonReport,
        declared_objective_met: bool,
        literature_compared: bool,
    ) -> Self {
        let side_fake = |outcome: &BaselineOutcome| match outcome {
            BaselineOutcome::Compared { baseline, .. } => baseline.provenance.is_fake_substrate(),
            BaselineOutcome::Unavailable { .. } => false,
        };
        Self {
            against_strongest: standing(report.strongest_upstream()),
            against_ordinary: standing(report.ordinary_workflow()),
            declared_objective_met,
            fake_substrate: report.candidate().provenance.is_fake_substrate()
                || side_fake(report.strongest_upstream())
                || side_fake(report.ordinary_workflow()),
            literature_compared,
        }
    }
}

/// The §4.17 decision (rule: on fakes, at most inconclusive; a loss even on fakes is
/// rejected or narrowed).
pub fn decide(inputs: &ClaimInputs) -> ClaimOutcome {
    if inputs.against_strongest == Some(Standing::Worse) {
        return if inputs.against_ordinary == Some(Standing::Better) {
            ClaimOutcome::Narrowed {
                scope: NarrowedScope::BelowStrongestBaseline,
            }
        } else {
            ClaimOutcome::Rejected
        };
    }
    if inputs.against_ordinary == Some(Standing::Worse) {
        return ClaimOutcome::Rejected;
    }
    if !inputs.declared_objective_met {
        return ClaimOutcome::Narrowed {
            scope: NarrowedScope::CapacityOnly,
        };
    }
    if inputs.fake_substrate {
        return ClaimOutcome::Inconclusive;
    }
    let beats_strongest = inputs.against_strongest == Some(Standing::Better);
    if beats_strongest && inputs.literature_compared {
        ClaimOutcome::SupportedOriginalContribution
    } else if beats_strongest || inputs.against_ordinary == Some(Standing::Better) {
        ClaimOutcome::UsefulIntegration
    } else {
        ClaimOutcome::Inconclusive
    }
}

/// The four experiments of this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Experiment {
    DenseDeadlineStreaming,
    MoeExplicitExperts,
    MemoryLimitedWindow,
    PerTokenStreamingDecode,
}

/// A §4.17 claim record: the six items of lines 910–915.
#[derive(Clone, Debug, PartialEq)]
pub struct ClaimRecord {
    pub experiment: Experiment,
    pub contribution: &'static str,
    pub prior_work: &'static str,
    pub difference_tested: &'static str,
    pub assumptions: &'static str,
    pub smallest_counterexample: &'static str,
    pub baseline: &'static str,
    pub outcome: ClaimOutcome,
    /// The provenance label shown with the result.
    pub provenance: String,
}

const PIPESWITCH: &str = "PipeSwitch (OSDI 2020, GPU part line 697): pipelined model \
                          transmission in execution order with grouped layers";
const OFFLOAD: &str = "the existing offload backends the plan builds on (line 768), and \
                       PipeSwitch's pipelined transfer for the double buffer";

impl Experiment {
    fn text(self) -> [&'static str; 6] {
        match self {
            Self::DenseDeadlineStreaming => [
                "order one dense decoder's transfers by each group's latest useful arrival, \
                 and let a lookahead of at most three steps choose between a coalesced \
                 contiguous read and the urgent tensor alone by the predicted first token",
                PIPESWITCH,
                "priority by slack and the bulk-versus-scattered choice when stored order \
                 differs from execution order",
                "a group is usable only when its whole read set arrived and verified; one read \
                 path serves one request at a time; groups compute in exact model order",
                "least slack alone: tensors x (deadline 10, transfer 8) and y (deadline 5, \
                 transfer 1) leave y 4 late, where earliest deadline leaves nothing late",
                "the ordinary loader, and execution-order streaming as the strongest \
                 compatible baseline, on the same fake read path",
            ],
            Self::MoeExplicitExperts => [
                "load the exact experts a request's prefill routes to first, by deadline, and \
                 every other expert afterwards",
                PIPESWITCH,
                "explicit expert dependencies in the deadline order",
                "the prefill routing is known when planning, which holds only when a recorded \
                 trace is replayed",
                "an expert the router picks that the plan did not name: the group stalls until \
                 that exact expert loads",
                "the ordinary loader and execution-order streaming of every expert",
            ],
            Self::MemoryLimitedWindow => [
                "keep only the next operations' read sets resident, load the next operation's \
                 new tensors while the current one computes, and pin a tensor across its live \
                 range when ties make that cheaper",
                OFFLOAD,
                "the simple window against an exhaustive offline oracle and against serial \
                 offload",
                "fixed exact operation order; loads for operation k+1 run during operation k; \
                 a buffer is freed only after its last consumer finished",
                "an embedding tied to the output head under a budget that cannot hold it beside \
                 two layers: the window reloads it",
                "serial offload; the ordinary loader cannot run a model larger than the device",
            ],
            Self::PerTokenStreamingDecode => [
                "none beyond capacity: a dense model larger than the device runs by streaming \
                 its non-resident weights every token",
                OFFLOAD,
                "whether the streamed bytes per token fit an interactive per-token latency",
                "every non-resident weight byte crosses the read path once per token",
                "9 GB per token over a measured 24 GB/s path takes at least 0.375 s, against a \
                 0.1 s objective",
                "none can run: the ordinary loader refuses a model larger than the device",
            ],
        }
    }

    /// The claim record with its computed decision.
    pub fn claim(self, inputs: &ClaimInputs, provenance: String) -> ClaimRecord {
        let [contribution, prior_work, difference_tested, assumptions, smallest_counterexample, baseline] =
            self.text();
        ClaimRecord {
            experiment: self,
            contribution,
            prior_work,
            difference_tested,
            assumptions,
            smallest_counterexample,
            baseline,
            outcome: decide(inputs),
            provenance,
        }
    }
}

/// Shared settings of an experiment on fakes.
#[derive(Clone, Debug, PartialEq)]
pub struct ExperimentSetup {
    /// The matched configuration, on the fake substrate.
    pub template: RunRecord,
    pub trials: u32,
    pub seed: u64,
    pub variation: Variation,
    pub latency_objective: LatencyObjective,
    pub interference: InterferenceModel,
}

/// One policy's simulated outcome, for reports beside the records.
#[derive(Clone, Debug, PartialEq)]
pub struct PolicyOutcome {
    pub name: Label,
    pub first_token_p95_seconds: Option<f64>,
    pub co_runner_lost_seconds: f64,
}

/// An experiment's records, comparison and claim record.
#[derive(Clone, Debug)]
pub struct ExperimentResult {
    pub report: ComparisonReport,
    pub claim: ClaimRecord,
    pub records: Vec<RunRecord>,
    pub policies: Vec<PolicyOutcome>,
}

fn design(setup: &ExperimentSetup, component: &str) -> Result<ExperimentDesign, StreamingError> {
    Ok(ExperimentDesign {
        effect: EffectClass::Other,
        independent_trials: setup.trials,
        trace: TracePattern::Mixed { seed: setup.seed },
        components: vec![label(component)?],
        ablated_components: Vec::new(),
    })
}

fn p95_seconds(side: &ComparisonSide) -> Option<f64> {
    side.objectives
        .time_to_first_token_nanos
        .value()
        .map(|nanos| Duration::from_nanos(nanos.get() as u64).as_secs_f64())
}

/// The co-running decode request during one trial's load (§4.4: steady-generation
/// interference), recorded as a hot serving attempt; and the progress it lost.
fn co_runner_record(
    setup: &ExperimentSetup,
    name: &str,
    trial: u32,
    busy: &[(f64, f64)],
    until_seconds: f64,
    peak_gpu_bytes: u64,
) -> Result<(Option<RunRecord>, f64), StreamingError> {
    let trace = co_runner(busy, until_seconds, &setup.interference)?;
    if trace.token_times_seconds.len() < 2 {
        return Ok((None, trace.lost_seconds));
    }
    let co = SimulatedAttempt {
        variant: label(&format!("co-{name}-trial-{trial}"))?,
        start: AttemptStart::Hot,
        end: AttemptEnd::Succeeded,
        dependencies_usable_seconds: None,
        token_times_seconds: trace.token_times_seconds,
        transferred_bytes: 0,
        peak_gpu_bytes,
        offload: Offload::NoOffload,
    };
    let record = record_attempt(
        &setup.template,
        &co,
        OperationId::new(format!("op-co-{name}-{trial}"))?,
        trial,
    )?;
    Ok((Some(record), trace.lost_seconds))
}

/// Runs one streaming policy for every trial and records attempts and co-runner traces.
fn streaming_side(
    name: &str,
    model: &StreamingModel,
    request: &PlannedRequest,
    cost: &ReadCostModel,
    budget: &StreamingBudget,
    policy: OrderPolicy,
    setup: &ExperimentSetup,
) -> Result<(ComparisonSide, Vec<RunRecord>, PolicyOutcome), StreamingError> {
    let schedule = plan_streaming(model, request, cost, budget, policy)?;
    let peak = model.total_weight_bytes()?.saturating_add(
        request
            .groups
            .iter()
            .map(|g| g.activation_bytes)
            .max()
            .unwrap_or(0),
    );
    let mut records = Vec::new();
    let mut co_records = Vec::new();
    let mut lost = 0.0;
    for trial in 0..setup.trials {
        // The same seed per trial for every policy: common random numbers.
        let substrate = FakeSubstrate {
            seed: setup.seed.wrapping_add(u64::from(trial)),
            variation: setup.variation,
        };
        let run = run_fake(request, &schedule, cost, substrate, FaultPlan::default())?;
        let variant = label(&format!("{name}-trial-{trial}"))?;
        let attempt = SimulatedAttempt::from_fake_run(variant, &run, peak);
        records.push(record_attempt(
            &setup.template,
            &attempt,
            OperationId::new(format!("op-{name}-{trial}"))?,
            trial,
        )?);
        let (co, trial_lost) = co_runner_record(
            setup,
            name,
            trial,
            &run.busy_intervals,
            run.load_complete_seconds,
            peak,
        )?;
        lost += trial_lost;
        co_records.extend(co);
    }
    let side = comparison_side(label(name)?, &records, &co_records, setup.latency_objective)?;
    let outcome = PolicyOutcome {
        name: label(name)?,
        first_token_p95_seconds: p95_seconds(&side),
        co_runner_lost_seconds: lost / f64::from(setup.trials.max(1)),
    };
    records.extend(co_records);
    Ok((side, records, outcome))
}

/// E1 or E2 on fakes: deadline order against the ordinary loader and, as the strongest
/// compatible baselines, execution-order and file-order streaming (GPU §4.4).
pub fn run_streaming_experiment(
    experiment: Experiment,
    model: &StreamingModel,
    request: &PlannedRequest,
    cost: &ReadCostModel,
    budget: &StreamingBudget,
    setup: &ExperimentSetup,
) -> Result<ExperimentResult, StreamingError> {
    let mut records = Vec::new();
    let mut policies = Vec::new();
    let mut side = |name: &str, policy| -> Result<ComparisonSide, StreamingError> {
        let (side, side_records, outcome) =
            streaming_side(name, model, request, cost, budget, policy, setup)?;
        records.extend(side_records);
        policies.push(outcome);
        Ok(side)
    };
    let candidate = side(
        "deadline-order",
        OrderPolicy::DeadlineOrder { lookahead_steps: 2 },
    )?;
    let ordinary = side("ordinary-loader", OrderPolicy::OrdinaryLoader)?;
    let execution = side("execution-order", OrderPolicy::ExecutionOrder)?;
    let file = side("file-order", OrderPolicy::FileOrder)?;
    let report = ComparisonReport::new(
        ObjectivePlan::new(crate::foundation::report::Objective::TimeToFirstToken, 0.05)?,
        StateComparison::WarmLoad,
        design(setup, "deadline-order")?,
        Vec::new(),
        candidate,
        Baseline::Measured {
            sides: vec![ordinary],
        },
        Baseline::Measured {
            sides: vec![execution, file],
        },
    )?;
    let inputs = ClaimInputs::from_report(&report, true, false);
    let claim = experiment.claim(&inputs, report.candidate().provenance.label());
    Ok(ExperimentResult {
        report,
        claim,
        records,
        policies,
    })
}

/// A window evaluation as a simulated attempt: the pass's end is its token.
fn window_attempt(
    variant: Label,
    token_times_seconds: Vec<f64>,
    dependencies_usable_seconds: f64,
    transferred_bytes: u64,
    peak_gpu_bytes: u64,
) -> SimulatedAttempt {
    SimulatedAttempt {
        variant,
        start: AttemptStart::DemandLoad,
        end: AttemptEnd::Succeeded,
        dependencies_usable_seconds: Some(dependencies_usable_seconds),
        token_times_seconds,
        transferred_bytes,
        peak_gpu_bytes,
        offload: Offload::ExplicitHostMemoryOffload,
    }
}

/// The problem with every compute duration varied by the trial's seeded spread.
fn varied(
    problem: &WindowProblem,
    rng: &mut SeededRng,
    variation: Variation,
) -> Result<Vec<ExactOp>, StreamingError> {
    problem
        .ops()
        .iter()
        .map(|op| {
            let nanos = nanos(op.compute_seconds)?;
            Ok(ExactOp {
                compute_seconds: rng.vary_nanos(nanos, variation) as f64 / 1e9,
                ..op.clone()
            })
        })
        .collect()
}

/// E3 on fakes: the best simple window against serial offload, the strongest compatible
/// baseline on a device that cannot hold the model (§4.11).
pub fn run_window_experiment(
    problem: &WindowProblem,
    tensor_bytes: &[u64],
    cost: &ReadCostModel,
    max_window_ops: usize,
    setup: &ExperimentSetup,
) -> Result<ExperimentResult, StreamingError> {
    let mut window_records = Vec::new();
    let mut serial_records = Vec::new();
    let mut window_co = Vec::new();
    let mut serial_co = Vec::new();
    let mut window_lost = 0.0;
    let mut serial_lost = 0.0;
    for trial in 0..setup.trials {
        let mut rng = SeededRng::new(setup.seed.wrapping_add(u64::from(trial)));
        let ops = varied(problem, &mut rng, setup.variation)?;
        let trial_problem =
            WindowProblem::new(tensor_bytes.to_vec(), ops, problem.budget(), *cost)?;
        let (_, _, window) = best_window(&trial_problem, max_window_ops)?;
        let serial = trial_problem.serial_offload()?;
        for (name, evaluation, out, co_out, lost) in [
            (
                "window",
                &window,
                &mut window_records,
                &mut window_co,
                &mut window_lost,
            ),
            (
                "serial-offload",
                &serial,
                &mut serial_records,
                &mut serial_co,
                &mut serial_lost,
            ),
        ] {
            let (co, trial_lost) = co_runner_record(
                setup,
                name,
                trial,
                &evaluation.busy_intervals,
                evaluation.finish_seconds,
                evaluation.peak_device_bytes,
            )?;
            co_out.extend(co);
            *lost += trial_lost;
            let last_arrival = evaluation
                .arrivals_seconds
                .iter()
                .copied()
                .fold(0.0, f64::max);
            let attempt = window_attempt(
                label(&format!("{name}-trial-{trial}"))?,
                vec![evaluation.finish_seconds],
                last_arrival.min(evaluation.finish_seconds),
                evaluation.transferred_bytes,
                evaluation.peak_device_bytes,
            );
            out.push(record_attempt(
                &setup.template,
                &attempt,
                OperationId::new(format!("op-{name}-{trial}"))?,
                trial,
            )?);
        }
    }
    let candidate = comparison_side(
        label("window")?,
        &window_records,
        &window_co,
        setup.latency_objective,
    )?;
    let serial = comparison_side(
        label("serial-offload")?,
        &serial_records,
        &serial_co,
        setup.latency_objective,
    )?;
    let trials = f64::from(setup.trials.max(1));
    let policies = vec![
        PolicyOutcome {
            name: label("window")?,
            first_token_p95_seconds: p95_seconds(&candidate),
            co_runner_lost_seconds: window_lost / trials,
        },
        PolicyOutcome {
            name: label("serial-offload")?,
            first_token_p95_seconds: p95_seconds(&serial),
            co_runner_lost_seconds: serial_lost / trials,
        },
    ];
    let report = ComparisonReport::new(
        ObjectivePlan::new(crate::foundation::report::Objective::TimeToFirstToken, 0.05)?,
        StateComparison::WarmLoad,
        design(setup, "layer-window")?,
        Vec::new(),
        candidate,
        Baseline::Unavailable {
            reason: BaselineUnavailable::NoOrdinaryWorkflowForThisPath,
            detail: label("model-larger-than-device")?,
        },
        Baseline::Measured {
            sides: vec![serial],
        },
    )?;
    let inputs = ClaimInputs::from_report(&report, true, false);
    let claim =
        Experiment::MemoryLimitedWindow.claim(&inputs, report.candidate().provenance.label());
    window_records.extend(serial_records);
    window_records.extend(window_co);
    window_records.extend(serial_co);
    Ok(ExperimentResult {
        report,
        claim,
        records: window_records,
        policies,
    })
}

/// E4 on fakes: dense decoding by per-token streaming, judged against an interactive
/// per-token objective (§4.11 line 766). `ops_per_token` operations make one token.
pub fn run_decode_experiment(
    problem: &WindowProblem,
    tensor_bytes: &[u64],
    cost: &ReadCostModel,
    ops_per_token: usize,
    reload: &DecodeReloadCost,
    objective_seconds_per_token: f64,
    setup: &ExperimentSetup,
) -> Result<ExperimentResult, StreamingError> {
    if ops_per_token == 0 || problem.ops().len() % ops_per_token != 0 {
        return Err(StreamingError::Invalid {
            field: "ops_per_token",
            reason: "the operations must be whole tokens",
        });
    }
    let mut records = Vec::new();
    let mut co_records = Vec::new();
    let mut lost = 0.0;
    let mut slowest_token = 0.0f64;
    for trial in 0..setup.trials {
        let mut rng = SeededRng::new(setup.seed.wrapping_add(u64::from(trial)));
        let ops = varied(problem, &mut rng, setup.variation)?;
        let trial_problem =
            WindowProblem::new(tensor_bytes.to_vec(), ops, problem.budget(), *cost)?;
        let (_, _, evaluation) = best_window(&trial_problem, 2)?;
        let tokens: Vec<f64> = evaluation
            .op_finish_seconds
            .iter()
            .skip(ops_per_token - 1)
            .step_by(ops_per_token)
            .copied()
            .collect();
        for pair in tokens.windows(2) {
            if let [earlier, later] = pair {
                slowest_token = slowest_token.max(later - earlier);
            }
        }
        let (co, trial_lost) = co_runner_record(
            setup,
            "streamed-decode",
            trial,
            &evaluation.busy_intervals,
            evaluation.finish_seconds,
            evaluation.peak_device_bytes,
        )?;
        co_records.extend(co);
        lost += trial_lost;
        let first_arrival = evaluation.arrivals_seconds.first().copied().unwrap_or(0.0);
        let attempt = window_attempt(
            label(&format!("streamed-decode-trial-{trial}"))?,
            tokens,
            first_arrival,
            evaluation.transferred_bytes,
            evaluation.peak_device_bytes,
        );
        records.push(record_attempt(
            &setup.template,
            &attempt,
            OperationId::new(format!("op-decode-{trial}"))?,
            trial,
        )?);
    }
    let candidate = comparison_side(
        label("streamed-decode")?,
        &records,
        &records,
        setup.latency_objective,
    )?;
    let policies = vec![PolicyOutcome {
        name: label("streamed-decode")?,
        first_token_p95_seconds: p95_seconds(&candidate),
        co_runner_lost_seconds: lost / f64::from(setup.trials.max(1)),
    }];
    let unavailable = |detail: &str| -> Result<Baseline, StreamingError> {
        Ok(Baseline::Unavailable {
            reason: BaselineUnavailable::NoOrdinaryWorkflowForThisPath,
            detail: label(detail)?,
        })
    };
    let report = ComparisonReport::new(
        ObjectivePlan::new(crate::foundation::report::Objective::TimeToFirstToken, 0.05)?,
        StateComparison::WarmLoad,
        design(setup, "per-token-streaming")?,
        Vec::new(),
        candidate,
        unavailable("model-larger-than-device")?,
        unavailable("no-compatible-backend-runs-it")?,
    )?;
    let met = reload.can_meet(objective_seconds_per_token)
        && slowest_token <= objective_seconds_per_token;
    let inputs = ClaimInputs::from_report(&report, met, false);
    let claim =
        Experiment::PerTokenStreamingDecode.claim(&inputs, report.candidate().provenance.label());
    records.extend(co_records);
    Ok(ExperimentResult {
        report,
        claim,
        records,
        policies,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::report::{BaselineRole, ImprovementClaim, ReportError};
    use crate::model_memory::math::bounds::{BandwidthRating, ResourceTable};
    use crate::model_memory::math::ResourceId;
    use crate::model_memory::residency::Capacity;
    use crate::model_memory::streaming::architecture::{
        ArchitectureFamily, ArchitectureGate, ReproducibleGain,
    };
    use crate::model_memory::streaming::moe::{routing_from_trace, RoutingTrace};
    use crate::model_memory::streaming::test_support::*;
    use crate::model_memory::streaming::window::{decode_reload_cost, WindowBudget};

    fn setup() -> ExperimentSetup {
        ExperimentSetup {
            template: fake_template(),
            trials: 5,
            seed: 7,
            variation: Variation::new(20_000).unwrap(),
            latency_objective: LatencyObjective {
                quantile: Quantile::P95,
                max_time_to_first_token_nanos: 500_000_000,
            },
            interference: InterferenceModel {
                decode_token_seconds: 0.002,
                slowdown_fraction: 0.2,
            },
        }
    }

    fn inputs(
        strongest: Option<Standing>,
        ordinary: Option<Standing>,
        met: bool,
        fake: bool,
        literature: bool,
    ) -> ClaimInputs {
        ClaimInputs {
            against_strongest: strongest,
            against_ordinary: ordinary,
            declared_objective_met: met,
            fake_substrate: fake,
            literature_compared: literature,
        }
    }

    #[test]
    fn every_decision_branch() {
        use Standing::*;
        // On fakes the best result is inconclusive, even against both baselines.
        assert_eq!(
            decide(&inputs(Some(Better), Some(Better), true, true, true)),
            ClaimOutcome::Inconclusive
        );
        // A loss to the strongest baseline, even on fakes, rejects or narrows.
        assert_eq!(
            decide(&inputs(Some(Worse), Some(Better), true, true, false)),
            ClaimOutcome::Narrowed {
                scope: NarrowedScope::BelowStrongestBaseline
            }
        );
        assert_eq!(
            decide(&inputs(Some(Worse), Some(Tied), true, true, false)),
            ClaimOutcome::Rejected
        );
        assert_eq!(
            decide(&inputs(None, Some(Worse), true, true, false)),
            ClaimOutcome::Rejected
        );
        // Capacity without the declared latency is narrowed to capacity-only.
        assert_eq!(
            decide(&inputs(None, None, false, true, false)),
            ClaimOutcome::Narrowed {
                scope: NarrowedScope::CapacityOnly
            }
        );
        // Only measured evidence and a literature comparison support originality.
        assert_eq!(
            decide(&inputs(Some(Better), Some(Better), true, false, true)),
            ClaimOutcome::SupportedOriginalContribution
        );
        assert_eq!(
            decide(&inputs(Some(Better), Some(Better), true, false, false)),
            ClaimOutcome::UsefulIntegration
        );
        assert_eq!(
            decide(&inputs(Some(Tied), Some(Better), true, false, true)),
            ClaimOutcome::UsefulIntegration
        );
        assert_eq!(
            decide(&inputs(Some(Tied), Some(Tied), true, false, true)),
            ClaimOutcome::Inconclusive
        );
    }

    #[test]
    fn claim_texts_make_no_priority_claims() {
        for experiment in [
            Experiment::DenseDeadlineStreaming,
            Experiment::MoeExplicitExperts,
            Experiment::MemoryLimitedWindow,
            Experiment::PerTokenStreamingDecode,
        ] {
            for text in experiment.text() {
                let lower = text.to_lowercase();
                for word in [
                    "unprecedented",
                    "first to ",
                    "the first ",
                    "novel",
                    "never before",
                ] {
                    assert!(!lower.contains(word), "{experiment:?}: {text}");
                }
                assert!(!text.is_empty());
            }
        }
        assert!(Experiment::DenseDeadlineStreaming.text()[1].contains("PipeSwitch"));
    }

    #[test]
    fn a_simulation_is_recorded_only_on_the_fake_substrate() {
        let mut real = fake_template();
        real.substrate = RunSubstrate::AuthorizedDisposable {
            authorization: label("disposable-test-host").unwrap(),
        };
        let attempt = window_attempt(label("x").unwrap(), vec![0.5], 0.4, 10, 10);
        assert_eq!(
            record_attempt(&real, &attempt, OperationId::new("op-x").unwrap(), 0),
            Err(StreamingError::SimulationOnRealSubstrate)
        );
        let record = record_attempt(
            &fake_template(),
            &attempt,
            OperationId::new("op-x").unwrap(),
            0,
        )
        .unwrap();
        assert!(Provenance::of_records(&[record.clone()])
            .unwrap()
            .is_fake_substrate());
        assert_eq!(
            record
                .interval(IntervalKind::TimeToFirstToken)
                .unwrap()
                .elapsed_nanos(),
            500_000_000
        );
        // A first token before its dependencies is refused.
        let early = window_attempt(label("y").unwrap(), vec![0.3], 0.4, 10, 10);
        assert!(record_attempt(
            &fake_template(),
            &early,
            OperationId::new("op-y").unwrap(),
            0
        )
        .is_err());
    }

    #[test]
    fn e1_deadline_order_against_file_order_is_recorded_and_inconclusive() {
        let model =
            StreamingModel::new(dense_spec_with(12, 8 * MIB, Layout::Lexicographic)).unwrap();
        let request = model.plan_request(shape(64), None).unwrap();
        let path = read_path(0.000_05, 6e9);
        let result = run_streaming_experiment(
            Experiment::DenseDeadlineStreaming,
            &model,
            &request,
            &path,
            &budget(64 * MIB),
            &setup(),
        )
        .unwrap();
        let ttft = |name: &str| {
            result
                .policies
                .iter()
                .find(|p| p.name.as_str() == name)
                .and_then(|p| p.first_token_p95_seconds)
                .unwrap()
        };
        assert!(ttft("deadline-order") < ttft("file-order"));
        assert!(ttft("deadline-order") < ttft("ordinary-loader"));
        // Every record is on the fake substrate, and the comparison backs no claim.
        assert!(result
            .records
            .iter()
            .all(|r| r.substrate == RunSubstrate::FakeTimeControlled));
        assert!(result.report.candidate().provenance.is_fake_substrate());
        assert_eq!(
            ImprovementClaim::from_report(&result.report, BaselineRole::OrdinaryWorkflow),
            Err(ReportError::FakeSubstrateIsNotEvidence)
        );
        assert_eq!(
            standing(result.report.ordinary_workflow()),
            Some(Standing::Better)
        );
        assert_ne!(
            standing(result.report.strongest_upstream()),
            Some(Standing::Worse)
        );
        assert_eq!(result.claim.outcome, ClaimOutcome::Inconclusive);
        assert!(result
            .claim
            .provenance
            .contains("not a Yougori measurement"));
        // A fake gain never unlocks the second architecture.
        assert!(
            ReproducibleGain::from_report(&result.report, ArchitectureFamily::DenseDecoder)
                .is_err()
        );
        // Steady-generation interference is recorded for every policy; the same bytes
        // cost the co-runner about the same progress whatever the order.
        let lost: Vec<f64> = result
            .policies
            .iter()
            .map(|p| p.co_runner_lost_seconds)
            .collect();
        assert!(lost.iter().all(|l| *l > 0.0));
        let spread = lost.iter().copied().fold(f64::MIN, f64::max)
            - lost.iter().copied().fold(f64::MAX, f64::min);
        assert!(spread < 0.1 * lost[0]);
    }

    #[test]
    fn a_measured_dense_gain_admits_the_second_architecture() {
        use crate::foundation::evidence::SourceClass;
        use crate::model_memory::streaming::architecture::{choose_loader, LoaderChoice};
        let objective = setup().latency_objective;
        // A real run in a disposable environment: the record's substrate says so.
        let measured = |name: &str, ttft: f64| -> ComparisonSide {
            let attempt = window_attempt(label(name).unwrap(), vec![ttft], ttft / 2.0, 10, 10);
            let mut record = record_attempt(
                &fake_template(),
                &attempt,
                OperationId::new(format!("op-{name}")).unwrap(),
                0,
            )
            .unwrap();
            record.substrate = RunSubstrate::AuthorizedDisposable {
                authorization: label("disposable-test-host").unwrap(),
            };
            let mut side =
                comparison_side(label(name).unwrap(), &[record], &[], objective).unwrap();
            let value = |x: f64| Measured::measured(NonNegative::new(x).unwrap());
            let objectives = &mut side.objectives;
            objectives.throughput_under_latency_objective_tokens_per_second = value(10.0);
            objectives.peak_host_memory_bytes = value(1.0);
            objectives.retained_host_memory_bytes = value(1.0);
            objectives.preparation_cost_usd = value(0.0);
            objectives.cost_per_completed_request_usd = value(0.001);
            objectives.energy_per_completed_request_joules = value(1.0);
            side
        };
        let report = ComparisonReport::new(
            ObjectivePlan::new(crate::foundation::report::Objective::TimeToFirstToken, 0.05)
                .unwrap(),
            StateComparison::WarmLoad,
            design(&setup(), "execute-while-load").unwrap(),
            Vec::new(),
            measured("streamed", 0.2),
            Baseline::Measured {
                sides: vec![measured("ordinary", 0.5)],
            },
            Baseline::Unavailable {
                reason: BaselineUnavailable::NoCompatibleUpstreamRelease,
                detail: label("none").unwrap(),
            },
        )
        .unwrap();
        let gain =
            ReproducibleGain::from_report(&report, ArchitectureFamily::DenseDecoder).unwrap();
        let world = EvidenceWorld::supported(SourceClass::GuestReport);
        assert!(matches!(
            choose_loader(
                moe_spec(2, 4, MIB),
                &ArchitectureGate::new().with_dense_gain(gain),
                &world.evidence()
            ),
            Ok(LoaderChoice::ExecuteWhileLoad { .. })
        ));
        // The gain must belong to the first architecture.
        assert!(ReproducibleGain::from_report(&report, ArchitectureFamily::MoeDecoder).is_err());
        // Measured, but not on the fake substrate: no claim record caps it at inconclusive.
        let inputs = ClaimInputs::from_report(&report, true, false);
        assert!(!inputs.fake_substrate);
        assert_eq!(decide(&inputs), ClaimOutcome::UsefulIntegration);
    }

    #[test]
    fn e2_explicit_experts_load_first_and_are_inconclusive() {
        let model = StreamingModel::new(moe_spec(4, 8, 2 * MIB)).unwrap();
        let trace = RoutingTrace::new(
            4,
            8,
            vec![(0..4)
                .map(|layer| [layer % 8, (layer + 3) % 8].into_iter().collect())
                .collect()],
        )
        .unwrap();
        let routing = routing_from_trace(&model, &trace, 0..1).unwrap();
        let request = model.plan_request(shape(16), Some(&routing)).unwrap();
        let path = read_path(0.000_05, 6e9);
        let result = run_streaming_experiment(
            Experiment::MoeExplicitExperts,
            &model,
            &request,
            &path,
            &budget(64 * MIB),
            &setup(),
        )
        .unwrap();
        let ttft = |name: &str| {
            result
                .policies
                .iter()
                .find(|p| p.name.as_str() == name)
                .and_then(|p| p.first_token_p95_seconds)
                .unwrap()
        };
        assert!(ttft("deadline-order") < ttft("execution-order"));
        assert!(ttft("deadline-order") < ttft("ordinary-loader"));
        assert_eq!(
            standing(result.report.strongest_upstream()),
            Some(Standing::Better)
        );
        assert_eq!(result.claim.outcome, ClaimOutcome::Inconclusive);
    }

    fn tied_decode_ops(layers: usize) -> Vec<ExactOp> {
        let mut ops = vec![ExactOp {
            reads: vec![0],
            compute_seconds: 0.001,
            output_activation_bytes: 0,
        }];
        for layer in 0..layers {
            ops.push(ExactOp {
                reads: vec![1 + layer],
                compute_seconds: 0.004,
                output_activation_bytes: 0,
            });
        }
        ops.push(ExactOp {
            reads: vec![0],
            compute_seconds: 0.002,
            output_activation_bytes: 0,
        });
        ops
    }

    #[test]
    fn e3_window_beats_serial_offload_and_is_inconclusive() {
        let bytes = vec![GB / 4; 6];
        let budget = WindowBudget::from_capacity(Capacity::Physical { bytes: GB }, 0).unwrap();
        let path = read_path(0.0, 25e9);
        let problem = WindowProblem::new(bytes.clone(), tied_decode_ops(5), budget, path).unwrap();
        let result = run_window_experiment(&problem, &bytes, &path, 3, &setup()).unwrap();
        assert_eq!(
            standing(result.report.strongest_upstream()),
            Some(Standing::Better)
        );
        assert!(matches!(
            result.report.ordinary_workflow(),
            BaselineOutcome::Unavailable { .. }
        ));
        assert_eq!(result.claim.outcome, ClaimOutcome::Inconclusive);
        // Both sides carry an interference result, recorded as co-runner attempts.
        assert!(result
            .policies
            .iter()
            .all(|p| p.co_runner_lost_seconds > 0.0));
        assert!(result
            .records
            .iter()
            .any(|r| r.attempt.variant.as_str().starts_with("co-window")));
    }

    #[test]
    fn e4_per_token_streaming_is_narrowed_to_capacity_only() {
        // Tied embedding/head and five layers of 1 GB on a 3 GB device at 24 GB/s.
        let bytes = vec![GB; 6];
        let budget = WindowBudget::from_capacity(Capacity::Physical { bytes: 3 * GB }, 0).unwrap();
        let path = read_path(0.0, 24e9);
        let tokens = 4;
        let per_token = tied_decode_ops(5);
        let ops: Vec<ExactOp> = (0..tokens).flat_map(|_| per_token.clone()).collect();
        let problem = WindowProblem::new(bytes.clone(), ops, budget, path).unwrap();
        let mut table = ResourceTable::new();
        let link = ResourceId::new("pcie0-h2d").unwrap();
        table
            .add(
                link.clone(),
                BandwidthRating::measured_directional(24e9).unwrap(),
            )
            .unwrap();
        let compute: f64 = per_token.iter().map(|op| op.compute_seconds).sum();
        // At most the tied tensor stays resident across tokens: 5 GB stream per token.
        let reload = decode_reload_cost(6 * GB, GB, compute, &table, &link).unwrap();
        assert!(!reload.can_meet(0.1));
        let result = run_decode_experiment(
            &problem,
            &bytes,
            &path,
            per_token.len(),
            &reload,
            0.1,
            &setup(),
        )
        .unwrap();
        assert_eq!(
            result.claim.outcome,
            ClaimOutcome::Narrowed {
                scope: NarrowedScope::CapacityOnly
            }
        );
        // The streamed decode emits every token, at no better than the bound.
        let record = &result.records[0];
        assert_eq!(
            record.measurements.output_tokens.value(),
            Some(&(tokens as u64))
        );
        let ClockReading::Serving(clock) = record.clock_reading().unwrap() else {
            panic!("a serving record");
        };
        let tokens_per_second = clock.decode_tokens_per_second.value().copied().unwrap();
        assert!(tokens_per_second <= reload.tokens_per_second_upper_bound + 1e-9);
    }
}
