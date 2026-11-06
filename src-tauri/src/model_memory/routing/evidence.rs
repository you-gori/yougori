//! Fake-substrate evidence for the §4.6–§4.8 experiments.
//!
//! Every simulated request becomes a CORE-08 [`RunRecord`] on the fake, time-controlled
//! substrate (S12 G0), so its provenance is [`Provenance::FakeSubstrate`], built by
//! [`Provenance::of_records`] from the records themselves. A [`ComparisonReport`] over
//! such sides validates the schema and the comparison discipline; it backs no
//! performance, improvement or release claim. Hardware results are not measured here.

use crate::foundation::ids::{digest, ExecutionCategory, ExecutionId, MonotonicTime, OperationId};
use crate::foundation::report::{
    percentile, ArrivalMode, AttemptIdentity, AttemptLedger, AttemptRole, Baseline, BenchId,
    BuildIdentity, ClientDescription, ClientPlacement, ClockId, CommitHash, ComparisonReport,
    ComparisonSide, CpuDescription, Disclosure, EffectClass, EngineIdentity, EventKind,
    ExperimentDesign, FixtureFamily, FixtureRef, GpuDescription, HostDescription, IntervalKind,
    Label, LatencyObjective, LatencySummary, LaunchDescription, LoadDescription,
    MatchedConfiguration, Measured, ModeFidelity, ModelIdentity, ModelRevision, NonNegative,
    NonceDisclosure, NotMeasuredReason, Objective, ObjectivePlan, ObjectiveVector, Outcome,
    PercentileMethod, Precision, Provenance, Quantile, RecordedEvent, RunMeasurements, RunRecord,
    RunSubstrate, Sampling, Scenario, SchemaVersion, StartState, StartTemperature, StateComparison,
    SuccessRate, TracePattern,
};

use super::error::RoutingError;
use super::numbers::{approx_f64, count_u64, floor_u64};

/// Domain of the digests that name the simulated fleet's fixed inputs.
pub const EXPERIMENT_DIGEST_DOMAIN: &str = "yougori/routing/experiment/v1";

/// Where every trial's clock starts, in nanoseconds; times are offsets from it.
pub const TRIAL_ORIGIN_NANOS: u64 = 1_000_000_000;

/// Independent seeded trials per regime: CORE-08's minimum for a comparison (§1.1).
pub const TRIALS_PER_REGIME: u32 = crate::foundation::report::MIN_INDEPENDENT_TRIALS;

/// A demand load the request waited for.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DemandLoad {
    pub started_seconds: f64,
    pub completed_seconds: f64,
}

/// One simulated request, in seconds from its trial's start.
#[derive(Clone, Debug, PartialEq)]
pub struct SimulatedAttempt {
    pub operation: OperationId,
    pub trial: u32,
    pub input_tokens: u64,
    pub arrival_seconds: f64,
    pub demand_load: Option<DemandLoad>,
    pub service_start_seconds: f64,
    /// As the client sees it: the network tail is included.
    pub first_token_seconds: f64,
    /// As the client sees it.
    pub completion_seconds: f64,
    pub state: StartState,
    pub transferred_bytes: u64,
    pub storage_read_bytes: u64,
}

/// What every fake record of one regime shares, so the compared sides have one matched
/// configuration (S7).
#[derive(Clone, Debug, PartialEq)]
pub struct FakeRunSetup {
    /// Names the experiment, such as `gpu-4-6-joint-routing`.
    pub experiment: Label,
    /// Names the regime's trace; its digest is the fixture.
    pub trace: Label,
    pub family: FixtureFamily,
    pub max_output_tokens: u64,
    pub concurrent_requests: u32,
}

fn label(value: &str) -> Result<Label, RoutingError> {
    Ok(Label::new(value)?)
}

/// Seconds from a trial's start as a time on the record clock.
pub fn trial_time(field: &'static str, seconds: f64) -> Result<MonotonicTime, RoutingError> {
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(RoutingError::TimeOutOfRange { field });
    }
    let nanos = (seconds * 1e9).round();
    if nanos >= approx_f64(u64::MAX.saturating_sub(TRIAL_ORIGIN_NANOS)) {
        return Err(RoutingError::TimeOutOfRange { field });
    }
    TRIAL_ORIGIN_NANOS
        .checked_add(floor_u64(nanos))
        .map(MonotonicTime::from_nanos)
        .ok_or(RoutingError::TimeOutOfRange { field })
}

fn fixed(name: &str) -> crate::foundation::ids::Digest {
    digest(EXPERIMENT_DIGEST_DOMAIN, &[name.as_bytes()])
}

impl FakeRunSetup {
    /// The fake-substrate record of one simulated attempt under `policy`.
    pub fn record(
        &self,
        policy: &Label,
        attempt: &SimulatedAttempt,
    ) -> Result<RunRecord, RoutingError> {
        let clock = ClockId::new(label("simulated-monotonic")?);
        let mut stamps = vec![(
            trial_time("arrival_seconds", attempt.arrival_seconds)?,
            EventKind::RequestAccepted,
        )];
        if let Some(load) = attempt.demand_load {
            stamps.push((
                trial_time("demand_load.started_seconds", load.started_seconds)?,
                EventKind::LoadStarted,
            ));
            stamps.push((
                trial_time("demand_load.completed_seconds", load.completed_seconds)?,
                EventKind::LoadCompleted,
            ));
        }
        stamps.push((
            trial_time("service_start_seconds", attempt.service_start_seconds)?,
            EventKind::RequestDequeued,
        ));
        stamps.push((
            trial_time("first_token_seconds", attempt.first_token_seconds)?,
            EventKind::TokenEmitted,
        ));
        stamps.push((
            trial_time("completion_seconds", attempt.completion_seconds)?,
            EventKind::RequestCompleted,
        ));
        let events = stamps
            .into_iter()
            .zip(0u64..)
            .map(|((at_nanos, event), sequence)| RecordedEvent {
                operation: attempt.operation.clone(),
                clock: clock.clone(),
                sequence,
                at_nanos,
                event,
            })
            .collect();
        let record = RunRecord {
            schema_version: SchemaVersion,
            attempt: AttemptIdentity {
                bench: BenchId::Bench01,
                variant: policy.clone(),
                execution: ExecutionId::new(format!("exe-{}", self.experiment))?,
                operation: attempt.operation.clone(),
                role: AttemptRole::Initial,
                burst: attempt.trial,
                deadline_nanos: Measured::not_measured(NotMeasuredReason::NotApplicable),
            },
            scenario: Scenario::Serving,
            substrate: RunSubstrate::FakeTimeControlled,
            build: BuildIdentity {
                plan: fixed("combined-gpu-memory-and-vm-sandbox-plan"),
                runner_build: fixed("p14-routing-simulator"),
                runner_version: label("p14-sim-1")?,
            },
            execution_category: ExecutionCategory::SharedKernelGpuRuntime,
            model: Measured::measured(ModelIdentity {
                revision: ModelRevision::Commit {
                    hash: CommitHash::new("0123456789abcdef0123456789abcdef01234567")?,
                },
                licenses: vec![label("Apache-2.0")?],
                weights: fixed("simulated-weights"),
                tokenizer: fixed("simulated-tokenizer"),
                chat_template: fixed("simulated-chat-template"),
            }),
            precision: Measured::measured(Precision {
                weight_dtype: label("bf16")?,
                quantization: label("none")?,
                kv_cache_dtype: label("bf16")?,
            }),
            engine: Measured::measured(EngineIdentity {
                name: label("yougori-routing-simulator")?,
                version: label("1")?,
            }),
            host: HostDescription {
                os: label("simulated")?,
                os_version: label("1")?,
                cpu: CpuDescription {
                    model: label("simulated-cpu")?,
                    logical_cores: 8,
                },
                host_memory_bytes: 64 << 30,
                gpus: Measured::measured(vec![GpuDescription {
                    model: label("simulated-gpu")?,
                    memory_bytes: 24 << 30,
                }]),
                gpu_driver: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
                gpu_power_clock: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
                power_source: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
                displays_on_gpu: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
            },
            workload: Measured::measured(crate::foundation::report::Workload {
                fixture: FixtureRef::digesting(
                    self.trace.clone(),
                    self.trace.as_str().as_bytes(),
                    Disclosure::PermittedSynthetic,
                ),
                family: self.family,
                input_tokens: attempt.input_tokens,
                max_output_tokens: self.max_output_tokens,
                sampling: Sampling {
                    temperature: NonNegative::ZERO,
                    top_p: Measured::not_measured(NotMeasuredReason::NotApplicable),
                    top_k: Measured::not_measured(NotMeasuredReason::NotApplicable),
                    seed: Measured::measured(u64::from(attempt.trial)),
                },
                tool_schema: Measured::not_measured(NotMeasuredReason::NotApplicable),
                paired: false,
                cold_test_nonce: NonceDisclosure::NotUsed,
            }),
            client: ClientDescription {
                name: label("yougori-routing-simulator")?,
                version: label("1")?,
                region: label("simulated")?,
                placement: ClientPlacement::LocalNetwork,
            },
            load: LoadDescription {
                concurrent_requests: self.concurrent_requests,
                arrival: ArrivalMode::Sequential,
            },
            state: Measured::measured(attempt.state),
            launch: LaunchDescription {
                image: fixed("simulated-image"),
                backend: label("simulated")?,
            },
            price: Measured::not_measured(NotMeasuredReason::NotApplicable),
            measurements: RunMeasurements {
                output_tokens: Measured::not_measured(NotMeasuredReason::NotRecorded),
                prefill_tokens_per_second: Measured::not_measured(NotMeasuredReason::NotRecorded),
                aggregate_decode_tokens_per_second: Measured::not_measured(
                    NotMeasuredReason::NotRecorded,
                ),
                speculative: Measured::not_measured(NotMeasuredReason::NotApplicable),
                peak_gpu_memory_bytes: Measured::not_measured(NotMeasuredReason::NotRecorded),
                retained_gpu_memory_bytes: Measured::not_measured(NotMeasuredReason::NotRecorded),
                peak_host_memory_bytes: Measured::not_measured(NotMeasuredReason::NotRecorded),
                retained_host_memory_bytes: Measured::not_measured(NotMeasuredReason::NotRecorded),
                peak_pinned_host_memory_bytes: Measured::not_measured(
                    NotMeasuredReason::NotRecorded,
                ),
                transferred_bytes: Measured::measured(attempt.transferred_bytes),
                storage_read_bytes: Measured::measured(attempt.storage_read_bytes),
                energy_joules: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
                offload: Measured::not_measured(NotMeasuredReason::NotRecorded),
                first_run: Measured::not_measured(NotMeasuredReason::NotApplicable),
                owner_return: Measured::not_measured(NotMeasuredReason::NotApplicable),
                reasoning: Measured::not_measured(NotMeasuredReason::NotApplicable),
            },
            events,
            outcome: Outcome::Succeeded,
        };
        record.validate()?;
        Ok(record)
    }
}

/// The latency objective every simulated side is judged under: first token within
/// 60 s at the side's quantile. The same on every side, as CORE-08 requires.
pub fn latency_objective(quantile: Quantile) -> LatencyObjective {
    LatencyObjective {
        quantile,
        max_time_to_first_token_nanos: 60_000_000_000,
    }
}

/// One side of a comparison from its fake records: provenance from the records (the fake
/// substrate), the matched configuration of the first record, the time to first token at
/// `quantile` over every trial, and the transferred and read bytes per trial.
///
/// S8 keeps cold, warm and hot attempts in separate ledgers, and each ledger here holds
/// one start temperature. A routing policy decides which state each request meets, so
/// the side's objective pools the successful samples of all its ledgers, each record
/// keeping its true start state; `temperature` declares the fleet's start state.
pub fn fake_side(
    name: &str,
    records: &[RunRecord],
    temperature: StartTemperature,
    quantile: Quantile,
) -> Result<ComparisonSide, RoutingError> {
    let provenance = Provenance::of_records(records)?;
    let first = records.first().ok_or(RoutingError::Input(
        crate::model_memory::math::InputError::Empty { field: "records" },
    ))?;
    let configuration = MatchedConfiguration::from_record(first)?;
    let mut groups: std::collections::BTreeMap<Option<StartTemperature>, Vec<RunRecord>> =
        std::collections::BTreeMap::new();
    for record in records {
        groups
            .entry(record.state.value().map(|state| state.temperature))
            .or_default()
            .push(record.clone());
    }
    let mut samples = Vec::new();
    let (mut successes, mut attempts) = (0u64, 0u64);
    for group in groups.into_values() {
        let ledger = AttemptLedger::from_records(group)?;
        let summary = LatencySummary::from_ledger(
            &ledger,
            IntervalKind::TimeToFirstToken,
            PercentileMethod::NearestRank,
        )?;
        samples.extend(summary.samples().iter().map(|sample| sample.nanos));
        let rate = ledger.success_rate()?;
        successes = successes.saturating_add(rate.successes());
        attempts = attempts.saturating_add(rate.attempts());
    }
    samples.sort_unstable();
    let ttft = percentile(&samples, quantile, PercentileMethod::NearestRank)?;
    let success = SuccessRate::new(successes, attempts)?;
    let trials = records
        .iter()
        .map(|record| record.attempt.burst)
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        .max(1);
    let trials = approx_f64(count_u64(trials));
    let per_trial = |pick: fn(&RunRecord) -> u64| -> Result<Measured<NonNegative>, RoutingError> {
        let total: f64 = records.iter().map(|record| approx_f64(pick(record))).sum();
        Ok(Measured::measured(NonNegative::new(total / trials)?))
    };
    Ok(ComparisonSide {
        name: label(name)?,
        provenance,
        configuration,
        temperature,
        fidelity: ModeFidelity::BitIdentical,
        accuracy_evaluation: Measured::not_measured(NotMeasuredReason::NotApplicable),
        objectives: ObjectiveVector {
            time_to_first_token_quantile: quantile,
            latency_objective: latency_objective(quantile),
            time_to_first_token_nanos: Measured::measured(NonNegative::new(ttft)?),
            throughput_under_latency_objective_tokens_per_second: Measured::not_measured(
                NotMeasuredReason::NotRecorded,
            ),
            peak_gpu_memory_bytes: Measured::not_measured(NotMeasuredReason::NotRecorded),
            retained_gpu_memory_bytes: Measured::not_measured(NotMeasuredReason::NotRecorded),
            peak_host_memory_bytes: Measured::not_measured(NotMeasuredReason::NotRecorded),
            retained_host_memory_bytes: Measured::not_measured(NotMeasuredReason::NotRecorded),
            transferred_bytes: per_trial(|record| {
                record
                    .measurements
                    .transferred_bytes
                    .value()
                    .copied()
                    .unwrap_or(0)
            })?,
            storage_read_bytes: per_trial(|record| {
                record
                    .measurements
                    .storage_read_bytes
                    .value()
                    .copied()
                    .unwrap_or(0)
            })?,
            preparation_cost_usd: Measured::not_measured(NotMeasuredReason::NotApplicable),
            cost_per_completed_request_usd: Measured::not_measured(
                NotMeasuredReason::NotApplicable,
            ),
            energy_per_completed_request_joules: Measured::not_measured(
                NotMeasuredReason::InstrumentUnavailable,
            ),
            reliability_success_rate: Measured::measured(NonNegative::new(success.rate())?),
        },
    })
}

/// A comparison of a candidate against the ordinary workflow and the strongest
/// compatible upstream baseline (§2.1), on time to first token, with `trials`
/// independent seeded trials over a mixed trace (§1.1) and one enabled component.
pub fn fake_comparison(
    component: &str,
    states: StateComparison,
    seed: u64,
    candidate: ComparisonSide,
    ordinary_workflow: Baseline,
    strongest_upstream: Baseline,
) -> Result<ComparisonReport, RoutingError> {
    let plan = ObjectivePlan::new(Objective::TimeToFirstToken, 0.05)?;
    let design = ExperimentDesign {
        effect: EffectClass::Other,
        independent_trials: TRIALS_PER_REGIME,
        trace: TracePattern::Mixed { seed },
        components: vec![label(component)?],
        ablated_components: Vec::new(),
    };
    Ok(ComparisonReport::new(
        plan,
        states,
        design,
        Vec::new(),
        candidate,
        ordinary_workflow,
        strongest_upstream,
    )?)
}
