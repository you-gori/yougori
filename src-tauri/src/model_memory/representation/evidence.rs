//! Simulated results as CORE-08 records (rollout decision "T12 → T02"; S12 G0).
//!
//! Every simulated trial of a §4 experiment becomes a raw [`RunRecord`] on the fake,
//! time-controlled substrate, and each experiment becomes a [`ComparisonReport`] whose
//! sides carry [`Provenance::FakeSubstrate`] (built by [`Provenance::of_records`] from
//! those records). Such a report validates the schema and the comparison discipline and
//! backs no performance, improvement or release claim. Anything that needs hardware
//! (energy, real memory peaks, decoder interference) is recorded as not measured.
//!
//! [`trial_records`] writes records under the substrate the outcomes came from, so the
//! policy shadow evaluator derives its provenance from the records of its own runs, never
//! from a provenance supplied beside them.

use std::fmt;
use std::time::Duration;

use crate::foundation::ids::{
    Clock, Digest, DigestBuilder, ExecutionCategory, ExecutionId, IdError, ManualClock,
    MonotonicTime, OperationId,
};
use crate::foundation::report::{
    ArrivalMode, AttemptIdentity, AttemptLedger, AttemptRole, Baseline, BaselineUnavailable,
    BenchId, BuildIdentity, ClientDescription, ClientPlacement, ClockId, ComparisonReport,
    ComparisonSide, CpuDescription, EffectClass, EngineIdentity, EventKind, EventRecorder,
    ExperimentDesign, GpuDescription, HostDescription, IntervalKind, Label, LatencyClaim,
    LatencyObjective, LatencySummary, LaunchDescription, LoadDescription, MatchedConfiguration,
    Measured, ModeFidelity, NonNegative, NotMeasuredReason, Objective, ObjectivePlan,
    ObjectiveVector, Outcome, PercentileMethod, Precision, Provenance, Quantile, ReportError,
    RunMeasurements, RunRecord, RunSubstrate, Scenario, SchemaVersion, StartTemperature,
    StateComparison, TracePattern,
};

/// Version label of these simulated runners.
pub const FAKE_RUNNER_VERSION: &str = "representation-fake-1";

/// Domain of the digests naming a simulated experiment's build and fixtures.
pub const EVIDENCE_DOMAIN: &str = "yougori/model-memory/representation/evidence/v1";

/// Why evidence could not be recorded.
#[derive(Clone, Debug, PartialEq)]
pub enum EvidenceError {
    Report(ReportError),
    Id(IdError),
    /// A trial's times are negative, non-finite, or end before they start.
    InvalidTrial {
        arm: String,
        index: usize,
    },
    NoTrials {
        arm: String,
    },
    /// More bursts than a record's 32-bit burst number can name.
    TooManyBursts {
        bursts: usize,
    },
}

impl From<ReportError> for EvidenceError {
    fn from(error: ReportError) -> Self {
        Self::Report(error)
    }
}

impl From<IdError> for EvidenceError {
    fn from(error: IdError) -> Self {
        Self::Id(error)
    }
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Report(error) => error.fmt(f),
            Self::Id(error) => error.fmt(f),
            Self::InvalidTrial { arm, index } => write!(f, "trial {index} of {arm} is invalid"),
            Self::NoTrials { arm } => write!(f, "{arm} has no trials"),
            Self::TooManyBursts { bursts } => write!(f, "{bursts} bursts cannot be numbered"),
        }
    }
}

impl std::error::Error for EvidenceError {}

/// One attempt, simulated or replayed: placement requested at its start, weights
/// usable, then the first token.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Trial {
    pub weights_usable_seconds: f64,
    pub first_token_seconds: f64,
    pub transferred_bytes: u64,
    pub storage_read_bytes: u64,
}

/// One side's trials, grouped into independent bursts.
#[derive(Clone, Debug, PartialEq)]
pub struct TrialArm {
    pub name: Label,
    pub bursts: Vec<Vec<Trial>>,
}

/// What an experiment's records and report share.
#[derive(Clone, Debug, PartialEq)]
pub struct FakeExperiment {
    pub bench: BenchId,
    /// Lowercase letters, digits and '-' only, so it can name operations.
    pub name: Label,
    pub temperature: StartTemperature,
    pub states: StateComparison,
    pub effect: EffectClass,
    pub trace_seed: u64,
    pub model_bytes: Digest,
    pub fixture: Digest,
    pub quantile: Quantile,
    pub max_time_to_first_token_nanos: u64,
    pub component: Label,
    pub declared: Objective,
}

/// A required upstream baseline that is unavailable, with its reason.
#[derive(Clone, Debug, PartialEq)]
pub struct UnavailableUpstream {
    pub reason: BaselineUnavailable,
    pub detail: Label,
}

fn label(value: &str) -> Result<Label, EvidenceError> {
    Ok(Label::new(value)?)
}

fn named(part: &str, experiment: &Label) -> Digest {
    DigestBuilder::new(EVIDENCE_DOMAIN)
        .str(part)
        .str(experiment.as_str())
        .finish()
}

fn nanos(seconds: f64) -> Duration {
    Duration::from_nanos((seconds * 1e9).round() as u64)
}

/// The host the records describe: the simulator for fake runs, the harness that
/// replayed a recorded run otherwise.
fn host(substrate: &RunSubstrate) -> Result<HostDescription, EvidenceError> {
    let (os, version) = match substrate {
        RunSubstrate::FakeTimeControlled => ("simulated", "fake-time-controlled"),
        RunSubstrate::AuthorizedDisposable { .. } => ("replayed", "recorded-run"),
    };
    Ok(HostDescription {
        os: label(os)?,
        os_version: label(version)?,
        cpu: CpuDescription {
            model: label(os)?,
            logical_cores: 1,
        },
        host_memory_bytes: 0,
        gpus: Measured::measured(vec![GpuDescription {
            model: label("simulated-gpu")?,
            memory_bytes: 0,
        }]),
        gpu_driver: Measured::not_measured(NotMeasuredReason::NotApplicable),
        gpu_power_clock: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
        power_source: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
        displays_on_gpu: Measured::not_measured(NotMeasuredReason::NotApplicable),
    })
}

fn measurements(trial: &Trial) -> RunMeasurements {
    RunMeasurements {
        output_tokens: Measured::measured(1),
        prefill_tokens_per_second: Measured::not_measured(NotMeasuredReason::NotApplicable),
        aggregate_decode_tokens_per_second: Measured::not_measured(
            NotMeasuredReason::NotApplicable,
        ),
        speculative: Measured::not_measured(NotMeasuredReason::NotApplicable),
        peak_gpu_memory_bytes: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
        retained_gpu_memory_bytes: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
        peak_host_memory_bytes: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
        retained_host_memory_bytes: Measured::not_measured(
            NotMeasuredReason::InstrumentUnavailable,
        ),
        peak_pinned_host_memory_bytes: Measured::not_measured(
            NotMeasuredReason::InstrumentUnavailable,
        ),
        transferred_bytes: Measured::measured(trial.transferred_bytes),
        storage_read_bytes: Measured::measured(trial.storage_read_bytes),
        energy_joules: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
        offload: Measured::not_measured(NotMeasuredReason::NotApplicable),
        first_run: Measured::not_measured(NotMeasuredReason::NotApplicable),
        owner_return: Measured::not_measured(NotMeasuredReason::NotApplicable),
        reasoning: Measured::not_measured(NotMeasuredReason::NotApplicable),
    }
}

fn valid(trial: &Trial) -> bool {
    trial.weights_usable_seconds.is_finite()
        && trial.first_token_seconds.is_finite()
        && trial.weights_usable_seconds >= 0.0
        && trial.first_token_seconds >= trial.weights_usable_seconds
}

/// The raw records of `arm` on the fake substrate (S12 G0).
pub fn fake_records(
    experiment: &FakeExperiment,
    arm: &TrialArm,
) -> Result<Vec<RunRecord>, EvidenceError> {
    trial_records(
        experiment.bench,
        &experiment.name,
        RunSubstrate::FakeTimeControlled,
        arm,
    )
}

/// The raw records of `arm` under `substrate`: one §2.1 weight-availability attempt per
/// trial, stamped by a [`ManualClock`]. The substrate is where the outcomes came from, so
/// [`Provenance::of_records`] over these records is the provenance of those outcomes.
/// `experiment` uses lowercase letters, digits and '-' only, so it can name operations.
pub fn trial_records(
    bench: BenchId,
    experiment: &Label,
    substrate: RunSubstrate,
    arm: &TrialArm,
) -> Result<Vec<RunRecord>, EvidenceError> {
    let execution = ExecutionId::new(format!("exe-{}", experiment.as_str()))?;
    let clock_id = ClockId::new(label("fake-monotonic")?);
    let mut records = Vec::new();
    let mut index = 0usize;
    for (burst, trials) in arm.bursts.iter().enumerate() {
        for trial in trials {
            if !valid(trial) {
                return Err(EvidenceError::InvalidTrial {
                    arm: arm.name.as_str().to_string(),
                    index,
                });
            }
            let operation = OperationId::new(format!(
                "op-{}-{}-{burst}-{index}",
                experiment.as_str(),
                arm.name.as_str()
            ))?;
            let burst = u32::try_from(burst).map_err(|_| EvidenceError::TooManyBursts {
                bursts: arm.bursts.len(),
            })?;
            let clock = ManualClock::new(MonotonicTime::from_nanos(1_000_000_000));
            let mut recorder = EventRecorder::new(operation.clone(), clock_id.clone(), &clock);
            recorder.record(EventKind::RequestAccepted);
            recorder.record(EventKind::PlacementRequested);
            clock.advance(nanos(trial.weights_usable_seconds));
            recorder.record(EventKind::WeightsUsable);
            let start = clock.now();
            let first_token = MonotonicTime::from_nanos(1_000_000_000)
                .saturating_add(nanos(trial.first_token_seconds));
            clock.advance(first_token.saturating_duration_since(start));
            recorder.record(EventKind::TokenEmitted);
            records.push(RunRecord {
                schema_version: SchemaVersion,
                attempt: AttemptIdentity {
                    bench,
                    variant: arm.name.clone(),
                    execution: execution.clone(),
                    operation,
                    role: AttemptRole::Initial,
                    burst,
                    deadline_nanos: Measured::not_measured(NotMeasuredReason::NotApplicable),
                },
                scenario: Scenario::Stages {
                    primary: IntervalKind::WeightAvailability,
                },
                substrate: substrate.clone(),
                build: BuildIdentity {
                    plan: named("plan", experiment),
                    runner_build: named("runner", experiment),
                    runner_version: label(FAKE_RUNNER_VERSION)?,
                },
                execution_category: ExecutionCategory::SharedKernelGpuRuntime,
                model: Measured::not_measured(NotMeasuredReason::NotApplicable),
                precision: Measured::not_measured(NotMeasuredReason::NotApplicable),
                engine: Measured::measured(EngineIdentity {
                    name: label("yougori-representation-fake")?,
                    version: label(FAKE_RUNNER_VERSION)?,
                }),
                host: host(&substrate)?,
                workload: Measured::not_measured(NotMeasuredReason::NotApplicable),
                client: ClientDescription {
                    name: label("yougori-representation-fake")?,
                    version: label(FAKE_RUNNER_VERSION)?,
                    region: label("same-host")?,
                    placement: ClientPlacement::SameHost,
                },
                load: LoadDescription {
                    concurrent_requests: 1,
                    arrival: ArrivalMode::Sequential,
                },
                state: Measured::not_measured(NotMeasuredReason::NotApplicable),
                launch: LaunchDescription {
                    image: named("image", experiment),
                    backend: label("simulated")?,
                },
                price: Measured::not_measured(NotMeasuredReason::NotApplicable),
                measurements: measurements(trial),
                events: recorder.into_events(),
                outcome: Outcome::Succeeded,
            });
            index += 1;
        }
    }
    if records.is_empty() {
        return Err(EvidenceError::NoTrials {
            arm: arm.name.as_str().to_string(),
        });
    }
    Ok(records)
}

fn mean(values: impl Iterator<Item = u64>) -> Result<Measured<NonNegative>, EvidenceError> {
    let values: Vec<u64> = values.collect();
    if values.is_empty() {
        return Ok(Measured::not_measured(NotMeasuredReason::NotRecorded));
    }
    let total: u128 = values.iter().map(|value| u128::from(*value)).sum();
    Ok(Measured::measured(NonNegative::new(
        total as f64 / values.len() as f64,
    )?))
}

/// The §1.3 objective vector of a ledger: the claimable first-token percentile, mean
/// bytes moved and read, and reliability; everything a fake cannot measure is "not
/// measured".
pub fn objectives(
    experiment: &FakeExperiment,
    ledger: &AttemptLedger,
) -> Result<ObjectiveVector, EvidenceError> {
    let summary = LatencySummary::from_ledger(
        ledger,
        IntervalKind::TimeToFirstToken,
        PercentileMethod::NearestRank,
    )?;
    let claim = LatencyClaim::from_summary(&summary, experiment.quantile)?;
    let records = ledger.records();
    Ok(ObjectiveVector {
        time_to_first_token_quantile: experiment.quantile,
        latency_objective: LatencyObjective {
            quantile: experiment.quantile,
            max_time_to_first_token_nanos: experiment.max_time_to_first_token_nanos,
        },
        time_to_first_token_nanos: Measured::measured(NonNegative::new(claim.value_nanos())?),
        throughput_under_latency_objective_tokens_per_second: Measured::not_measured(
            NotMeasuredReason::NotApplicable,
        ),
        peak_gpu_memory_bytes: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
        retained_gpu_memory_bytes: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
        peak_host_memory_bytes: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
        retained_host_memory_bytes: Measured::not_measured(
            NotMeasuredReason::InstrumentUnavailable,
        ),
        transferred_bytes: mean(
            records
                .iter()
                .filter_map(|record| record.measurements.transferred_bytes.value().copied()),
        )?,
        storage_read_bytes: mean(
            records
                .iter()
                .filter_map(|record| record.measurements.storage_read_bytes.value().copied()),
        )?,
        preparation_cost_usd: Measured::not_measured(NotMeasuredReason::NotApplicable),
        cost_per_completed_request_usd: Measured::not_measured(NotMeasuredReason::NotApplicable),
        energy_per_completed_request_joules: Measured::not_measured(
            NotMeasuredReason::InstrumentUnavailable,
        ),
        reliability_success_rate: Measured::measured(NonNegative::new(
            ledger.success_rate()?.rate(),
        )?),
    })
}

/// One fake side of a comparison, with its records' provenance.
pub fn fake_side(
    experiment: &FakeExperiment,
    arm: &TrialArm,
) -> Result<ComparisonSide, EvidenceError> {
    let records = fake_records(experiment, arm)?;
    let provenance = Provenance::of_records(&records)?;
    let ledger = AttemptLedger::from_records(records)?;
    Ok(ComparisonSide {
        name: arm.name.clone(),
        provenance,
        configuration: MatchedConfiguration {
            model_bytes: experiment.model_bytes,
            precision: Precision {
                weight_dtype: label("bf16")?,
                quantization: label("none")?,
                kv_cache_dtype: label("bf16")?,
            },
            fixture: experiment.fixture,
            max_output_tokens: 1,
            hardware: named("hardware", &experiment.name),
            client: named("client", &experiment.name),
            tool_template: Measured::not_measured(NotMeasuredReason::NotApplicable),
            execution_category: ExecutionCategory::SharedKernelGpuRuntime,
        },
        temperature: experiment.temperature,
        fidelity: ModeFidelity::BitIdentical,
        accuracy_evaluation: Measured::not_measured(NotMeasuredReason::NotApplicable),
        objectives: objectives(experiment, &ledger)?,
    })
}

/// The experiment's comparison report: the candidate against the ordinary workflow,
/// both on the fake substrate, with the unavailable upstream baseline and its reason.
pub fn fake_report(
    experiment: &FakeExperiment,
    candidate: &TrialArm,
    ordinary: &TrialArm,
    upstream: &UnavailableUpstream,
) -> Result<ComparisonReport, EvidenceError> {
    let trials =
        u32::try_from(candidate.bursts.len().min(ordinary.bursts.len())).unwrap_or(u32::MAX);
    Ok(ComparisonReport::new(
        ObjectivePlan::new(experiment.declared, 0.0)?,
        experiment.states,
        ExperimentDesign {
            effect: experiment.effect,
            independent_trials: trials,
            trace: TracePattern::Mixed {
                seed: experiment.trace_seed,
            },
            components: vec![experiment.component.clone()],
            ablated_components: Vec::new(),
        },
        Vec::new(),
        fake_side(experiment, candidate)?,
        Baseline::Measured {
            sides: vec![fake_side(experiment, ordinary)?],
        },
        Baseline::Unavailable {
            reason: upstream.reason,
            detail: upstream.detail.clone(),
        },
    )?)
}
