//! Strict runner observations adapted to CORE-08 without invented token clocks.
use crate::foundation::{
    ids::{ExecutionCategory, MonotonicTime},
    report as core,
};
use serde_json::Value;
use std::{collections::BTreeMap, fmt};

pub(crate) const MAX_COMPLETED_BYTES: usize = 16 * 1024;
const MAX_COUNTER: u64 = (1 << 53) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdapterError {
    Oversized,
    Malformed,
    UnexpectedFields,
    InvalidCounter,
    InvalidDuration,
    UnknownKind,
    UnknownOutcome,
    UnknownStage,
    InconsistentRecord,
    InvalidIdentity,
    ContextMismatch,
    InvalidReportContext,
}
impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Runner measurement rejected: {self:?}")
    }
}
impl std::error::Error for AdapterError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttemptKind {
    Load,
    Request,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RunnerOutcome {
    Ok,
    Cancelled,
    Busy,
    Invalid,
    Error,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Stage {
    Dependencies,
    Checkpoint,
    Snapshot,
    Download,
    WeightVerification,
    WeightHash,
    RuntimeArtifact,
    WeightLoad,
    AdmissionWait,
    EngineStartToReady,
    NativeReadyWait,
    RequestValidation,
    ModelWait,
    PromptPreparation,
    Generation,
    Import,
    /// A parked vLLM's `/wake_up` (G01: the retained-process wake).
    EngineWake,
    /// A woken vLLM reloading its weights from the verified files.
    WeightReload,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StageObservation {
    pub calls: u64,
    pub failed_calls: u64,
    pub elapsed_nanos: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompletedObservation {
    pub id: u64,
    pub completion_sequence: u64,
    pub kind: AttemptKind,
    pub outcome: RunnerOutcome,
    pub elapsed_nanos: u64,
    pub first_output_nanos: Option<u64>,
    pub stages: BTreeMap<Stage, StageObservation>,
    pub boundaries: Option<RequestBoundaries>,
    pub tokens: Option<TokenObservations>,
    pub demand_load: Option<DemandLoad>,
    pub backend: Option<BackendObservation>,
}

/// A completed load call observed inside this request's wait on the same runner clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DemandLoad {
    pub attempt_id: u64,
    pub started_nanos: u64,
    pub ready_nanos: u64,
    /// The load woke a sleeping engine (`runner-wake-call`) instead of loading from scratch.
    pub wake: bool,
}

/// Whose clock a [`BackendObservation`] is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BackendSource {
    /// vLLM's own per-request histograms, their growth across exactly this request: queue
    /// from arrival in the engine to first scheduling, prefill from there to the first token,
    /// decode from the first to the last token.
    VllmMetricsDelta,
    /// llama.cpp's reply timings: prompt processing and token generation.
    LlamaCppTimings,
    /// The Transformers runner's host clock: from the generate call to the first generated
    /// token it was handed (the prefill and one sampling step), then to the end.
    TransformersFirstToken,
}

/// What the backend reported of one request (G01: prefill, scheduler queue and decode),
/// in the units it reported them, never derived from the wrapper's own boundaries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BackendObservation {
    pub source: BackendSource,
    pub prompt_tokens: u64,
    /// Of the prompt, reused from a prefix cache rather than computed.
    pub cached_tokens: Option<u64>,
    pub queue_nanos: Option<u64>,
    pub prefill_nanos: u64,
    pub decode_nanos: Option<u64>,
    pub output_tokens: Option<u64>,
}

/// Tokens whose bytes were verified against a flushed client chunk. Batched
/// tokens share a timestamp; these are not GPU decode or prefill timestamps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TokenObservations {
    pub complete: bool,
    pub emitted_nanos: Vec<u64>,
    pub output_tokens: Option<u64>,
}

/// Relative to the attempt start on the Python monotonic clock. These are
/// wrapper boundaries: admission is its generation lock, not an upstream queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RequestBoundaries {
    pub accepted_nanos: u64,
    pub admitted_nanos: Option<u64>,
    pub completed_nanos: Option<u64>,
}

fn fields(value: &Value, names: &[&str]) -> Result<(), AdapterError> {
    let object = value.as_object().ok_or(AdapterError::Malformed)?;
    if object.len() != names.len() || names.iter().any(|name| !object.contains_key(*name)) {
        return Err(AdapterError::UnexpectedFields);
    }
    Ok(())
}
fn counter(value: &Value, nonzero: bool) -> Result<u64, AdapterError> {
    value
        .as_u64()
        .filter(|number| *number <= MAX_COUNTER && (!nonzero || *number > 0))
        .ok_or(AdapterError::InvalidCounter)
}

/// Python publishes milliseconds rounded to six decimal places. Convert the
/// decimal representation to integer nanoseconds, never cast a float to u64.
fn nanos(value: &Value) -> Result<u64, AdapterError> {
    let text = value
        .as_number()
        .ok_or(AdapterError::InvalidDuration)?
        .to_string();
    if text.starts_with('-') {
        return Err(AdapterError::InvalidDuration);
    }
    let (mantissa, exponent) = match text.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (
            mantissa,
            exponent
                .parse::<i32>()
                .map_err(|_| AdapterError::InvalidDuration)?,
        ),
        None => (text.as_str(), 0),
    };
    let decimals = mantissa
        .split_once('.')
        .map_or(0, |(_, fraction)| fraction.len());
    let mut digits = mantissa.replace('.', "");
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AdapterError::InvalidDuration);
    }
    let scale = exponent
        .checked_add(6)
        .and_then(|n| n.checked_sub(decimals.try_into().ok()?))
        .ok_or(AdapterError::InvalidDuration)?;
    if scale < 0 {
        let remove = scale.unsigned_abs() as usize;
        if remove > digits.len() || !digits[digits.len() - remove..].bytes().all(|b| b == b'0') {
            return Err(AdapterError::InvalidDuration);
        }
        digits.truncate(digits.len() - remove);
    }
    let number = if digits.is_empty() {
        0
    } else {
        digits
            .parse::<u64>()
            .map_err(|_| AdapterError::InvalidDuration)?
    };
    if number == 0 {
        return Ok(0);
    }
    if scale > 0 {
        number
            .checked_mul(
                10u64
                    .checked_pow(scale as u32)
                    .ok_or(AdapterError::InvalidDuration)?,
            )
            .ok_or(AdapterError::InvalidDuration)
    } else {
        Ok(number)
    }
}

fn kind(value: &Value) -> Result<AttemptKind, AdapterError> {
    match value.as_str() {
        Some("load") => Ok(AttemptKind::Load),
        Some("request") => Ok(AttemptKind::Request),
        _ => Err(AdapterError::UnknownKind),
    }
}
fn stage(name: &str) -> Result<Stage, AdapterError> {
    Ok(match name {
        "dependencies" => Stage::Dependencies,
        "checkpoint" => Stage::Checkpoint,
        "snapshot" => Stage::Snapshot,
        "download" => Stage::Download,
        "weight_verification" => Stage::WeightVerification,
        "weight_hash" => Stage::WeightHash,
        "runtime_artifact" => Stage::RuntimeArtifact,
        "weight_load" => Stage::WeightLoad,
        "admission_wait" => Stage::AdmissionWait,
        "engine_start_to_ready" => Stage::EngineStartToReady,
        "native_ready_wait" => Stage::NativeReadyWait,
        "request_validation" => Stage::RequestValidation,
        "model_wait" => Stage::ModelWait,
        "prompt_preparation" => Stage::PromptPreparation,
        "generation" => Stage::Generation,
        "import" => Stage::Import,
        "engine_wake" => Stage::EngineWake,
        "weight_reload" => Stage::WeightReload,
        _ => return Err(AdapterError::UnknownStage),
    })
}

pub(crate) fn parse_completed_bytes(bytes: &[u8]) -> Result<CompletedObservation, AdapterError> {
    if bytes.len() > MAX_COMPLETED_BYTES {
        return Err(AdapterError::Oversized);
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| AdapterError::Malformed)?;
    parse_completed(&value)
}

/// Input is already byte-bounded by the journal collector. Exact field/enum
/// checks below retain no unknown strings, nested objects, paths or secrets.
pub(crate) fn parse_completed(value: &Value) -> Result<CompletedObservation, AdapterError> {
    let mut names = vec![
        "id",
        "completionSequence",
        "kind",
        "outcome",
        "elapsedMs",
        "firstOutputMs",
        "stages",
    ];
    if value.get("boundaries").is_some() {
        names.push("boundaries");
    }
    if value.get("tokens").is_some() {
        names.push("tokens");
    }
    if value.get("demandLoad").is_some() {
        names.push("demandLoad");
    }
    if value.get("backend").is_some() {
        names.push("backend");
    }
    fields(value, &names)?;
    let demand_load = value
        .get("demandLoad")
        .map(|load| {
            fields(
                load,
                &["version", "source", "loadAttemptId", "startedMs", "readyMs"],
            )?;
            let wake = match load["source"].as_str() {
                Some("runner-load-call") => false,
                Some("runner-wake-call") => true,
                _ => return Err(AdapterError::InconsistentRecord),
            };
            if load["version"].as_u64() != Some(1) {
                return Err(AdapterError::InconsistentRecord);
            }
            Ok(DemandLoad {
                attempt_id: counter(&load["loadAttemptId"], true)?,
                started_nanos: nanos(&load["startedMs"])?,
                ready_nanos: nanos(&load["readyMs"])?,
                wake,
            })
        })
        .transpose()?;
    let backend = value
        .get("backend")
        .map(|b| {
            fields(
                b,
                &[
                    "version",
                    "source",
                    "promptTokens",
                    "cachedTokens",
                    "queueMs",
                    "prefillMs",
                    "decodeMs",
                    "outputTokens",
                ],
            )?;
            let source = match b["source"].as_str() {
                Some("vllm-metrics-delta") => BackendSource::VllmMetricsDelta,
                Some("llama-cpp-timings") => BackendSource::LlamaCppTimings,
                Some("transformers-first-token") => BackendSource::TransformersFirstToken,
                _ => return Err(AdapterError::InconsistentRecord),
            };
            if b["version"].as_u64() != Some(1) {
                return Err(AdapterError::InconsistentRecord);
            }
            let count = |name: &str| -> Result<Option<u64>, AdapterError> {
                if b[name].is_null() {
                    Ok(None)
                } else {
                    counter(&b[name], false).map(Some)
                }
            };
            let span = |name: &str| -> Result<Option<u64>, AdapterError> {
                if b[name].is_null() {
                    Ok(None)
                } else {
                    nanos(&b[name]).map(Some)
                }
            };
            Ok(BackendObservation {
                source,
                prompt_tokens: count("promptTokens")?.ok_or(AdapterError::InconsistentRecord)?,
                cached_tokens: count("cachedTokens")?,
                queue_nanos: span("queueMs")?,
                prefill_nanos: span("prefillMs")?.ok_or(AdapterError::InconsistentRecord)?,
                decode_nanos: span("decodeMs")?,
                output_tokens: count("outputTokens")?,
            })
        })
        .transpose()?;
    let tokens = value
        .get("tokens")
        .map(|t| {
            fields(
                t,
                &["version", "source", "complete", "emittedMs", "outputTokens"],
            )?;
            if t["version"].as_u64() != Some(1)
                || !matches!(
                    t["source"].as_str(),
                    Some("openai-logprobs-flush" | "transformers-streamer-flush")
                )
            {
                return Err(AdapterError::InconsistentRecord);
            }
            let times = t["emittedMs"].as_array().ok_or(AdapterError::Malformed)?;
            if times.len() > 256 {
                return Err(AdapterError::Oversized);
            }
            Ok(TokenObservations {
                complete: t["complete"].as_bool().ok_or(AdapterError::Malformed)?,
                emitted_nanos: times.iter().map(nanos).collect::<Result<_, _>>()?,
                output_tokens: if t["outputTokens"].is_null() {
                    None
                } else {
                    Some(counter(&t["outputTokens"], false)?)
                },
            })
        })
        .transpose()?;
    let boundaries = value
        .get("boundaries")
        .map(|b| {
            fields(b, &["version", "acceptedMs", "admittedMs", "completedMs"])?;
            if b["version"].as_u64() != Some(1) {
                return Err(AdapterError::InconsistentRecord);
            }
            let optional = |name: &str| -> Result<Option<u64>, AdapterError> {
                if b[name].is_null() {
                    Ok(None)
                } else {
                    nanos(&b[name]).map(Some)
                }
            };
            Ok(RequestBoundaries {
                accepted_nanos: nanos(&b["acceptedMs"])?,
                admitted_nanos: optional("admittedMs")?,
                completed_nanos: optional("completedMs")?,
            })
        })
        .transpose()?;
    let outcome = match value["outcome"].as_str() {
        Some("ok") => RunnerOutcome::Ok,
        Some("cancelled") => RunnerOutcome::Cancelled,
        Some("busy") => RunnerOutcome::Busy,
        Some("invalid") => RunnerOutcome::Invalid,
        Some("error") => RunnerOutcome::Error,
        _ => return Err(AdapterError::UnknownOutcome),
    };
    let samples = value["stages"].as_object().ok_or(AdapterError::Malformed)?;
    if samples.len() > 16 {
        return Err(AdapterError::Oversized);
    }
    let mut stages = BTreeMap::new();
    for (name, sample) in samples {
        let name = stage(name)?;
        fields(sample, &["calls", "failedCalls", "elapsedMs"])?;
        stages.insert(
            name,
            StageObservation {
                calls: counter(&sample["calls"], true)?,
                failed_calls: counter(&sample["failedCalls"], false)?,
                elapsed_nanos: nanos(&sample["elapsedMs"])?,
            },
        );
    }
    let record = CompletedObservation {
        id: counter(&value["id"], true)?,
        completion_sequence: counter(&value["completionSequence"], true)?,
        kind: kind(&value["kind"])?,
        outcome,
        elapsed_nanos: nanos(&value["elapsedMs"])?,
        first_output_nanos: if value["firstOutputMs"].is_null() {
            None
        } else {
            Some(nanos(&value["firstOutputMs"])?)
        },
        stages,
        boundaries,
        tokens,
        demand_load,
        backend,
    };
    record.validate()?;
    Ok(record)
}

impl CompletedObservation {
    fn validate(&self) -> Result<(), AdapterError> {
        if let Some(load) = &self.demand_load {
            let b = self
                .boundaries
                .as_ref()
                .ok_or(AdapterError::InconsistentRecord)?;
            if self.kind != AttemptKind::Request
                || load.attempt_id == 0
                || load.attempt_id > MAX_COUNTER
                || load.attempt_id == self.id
                || load.started_nanos < b.accepted_nanos
                || load.ready_nanos < load.started_nanos
                || load.ready_nanos > self.elapsed_nanos
                || b.admitted_nanos.is_some_and(|at| load.ready_nanos > at)
            {
                return Err(AdapterError::InconsistentRecord);
            }
        }
        if let Some(backend) = &self.backend {
            if self.kind != AttemptKind::Request
                || self.outcome != RunnerOutcome::Ok
                || backend
                    .cached_tokens
                    .is_some_and(|cached| cached > backend.prompt_tokens)
            {
                return Err(AdapterError::InconsistentRecord);
            }
        }
        if let Some(t) = &self.tokens {
            let b = self
                .boundaries
                .as_ref()
                .ok_or(AdapterError::InconsistentRecord)?;
            let admitted = b.admitted_nanos.ok_or(AdapterError::InconsistentRecord)?;
            if t.emitted_nanos.len() > 256
                || t.output_tokens.is_some_and(|n| n > MAX_COUNTER)
                || t.emitted_nanos.windows(2).any(|pair| pair[0] > pair[1])
                || t.emitted_nanos
                    .iter()
                    .any(|n| *n < admitted || *n > b.completed_nanos.unwrap_or(self.elapsed_nanos))
                || (t.complete
                    && (self.outcome != RunnerOutcome::Ok
                        || b.completed_nanos.is_none()
                        || t.emitted_nanos.is_empty()
                        || t.output_tokens != Some(t.emitted_nanos.len() as u64)))
            {
                return Err(AdapterError::InconsistentRecord);
            }
        }
        if let Some(b) = &self.boundaries {
            if self.kind != AttemptKind::Request
                || b.accepted_nanos > self.elapsed_nanos
                || b.admitted_nanos
                    .is_some_and(|n| n < b.accepted_nanos || n > self.elapsed_nanos)
                || b.completed_nanos.is_some_and(|n| {
                    self.outcome != RunnerOutcome::Ok
                        || n > self.elapsed_nanos
                        || b.admitted_nanos.is_none_or(|admitted| n < admitted)
                })
                || self.first_output_nanos.is_some_and(|n| {
                    b.admitted_nanos.is_none_or(|admitted| n < admitted)
                        || b.completed_nanos.is_some_and(|completed| n > completed)
                })
            {
                return Err(AdapterError::InconsistentRecord);
            }
        }
        if self.id == 0
            || self.id > MAX_COUNTER
            || self.completion_sequence == 0
            || self.completion_sequence > MAX_COUNTER
        {
            return Err(AdapterError::InvalidCounter);
        }
        if self
            .first_output_nanos
            .is_some_and(|first| first > self.elapsed_nanos)
            || (self.kind == AttemptKind::Load
                && (self.first_output_nanos.is_some()
                    || !matches!(self.outcome, RunnerOutcome::Ok | RunnerOutcome::Error)))
        {
            return Err(AdapterError::InconsistentRecord);
        }
        for sample in self.stages.values() {
            if sample.calls == 0
                || sample.calls > MAX_COUNTER
                || sample.failed_calls > sample.calls
                || u128::from(sample.elapsed_nanos)
                    > u128::from(self.elapsed_nanos) * u128::from(sample.calls)
            {
                return Err(AdapterError::InconsistentRecord);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ObservationIdentity {
    pub session_id: String,
    pub instance_id: String,
    pub attempt_id: u64,
}
impl ObservationIdentity {
    pub(crate) fn new(
        session_id: &str,
        instance_id: &str,
        attempt_id: u64,
    ) -> Result<Self, AdapterError> {
        let identity = Self {
            session_id: session_id.into(),
            instance_id: instance_id.into(),
            attempt_id,
        };
        identity.validate()?;
        Ok(identity)
    }
    fn validate(&self) -> Result<(), AdapterError> {
        if [&self.session_id, &self.instance_id].iter().any(|id| {
            id.len() != 32
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }) || self.attempt_id == 0
            || self.attempt_id > MAX_COUNTER
        {
            return Err(AdapterError::InvalidIdentity);
        }
        Ok(())
    }
}

/// Trusted caller-owned CORE-08 context, not supplied by a runner observation.
/// Deliberately contains no inferred cache, platform, workload or build identity.
#[derive(Clone, Debug)]
pub(crate) struct RunMetadata {
    pub attempt: core::AttemptIdentity,
    pub substrate: core::RunSubstrate,
    pub build: core::BuildIdentity,
    pub execution_category: ExecutionCategory,
    pub model: core::Measured<core::ModelIdentity>,
    pub precision: core::Measured<core::Precision>,
    pub engine: core::Measured<core::EngineIdentity>,
    pub host: core::HostDescription,
    pub workload: core::Measured<core::Workload>,
    pub client: core::ClientDescription,
    pub load: core::LoadDescription,
    pub state: core::Measured<core::StartState>,
    pub launch: core::LaunchDescription,
    pub price: core::Measured<core::PriceQuote>,
}

#[derive(Clone, Debug)]
pub(crate) struct ReportContext {
    pub identity: ObservationIdentity,
    pub expected_kind: AttemptKind,
    pub metadata: RunMetadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConversionGap {
    ExactTokenTimingUnavailable,
    QueueBoundaryUnavailable,
    RequestCompletionBoundaryUnavailable,
    ServingStartStateUnavailable,
    ServingStartStateMismatch,
    DemandWorkBoundaryUnavailable,
    InclusiveStagesNotAdditive,
    ResourceMeasurementsUnavailable,
    DenominatorRequiresSealedJournal,
}

#[derive(Clone, Debug)]
pub(crate) struct AdaptedAttempt {
    pub observation: CompletedObservation,
    pub record: Option<core::RunRecord>,
    pub gaps: Vec<ConversionGap>,
}

fn unknown_measurements() -> core::RunMeasurements {
    use core::{Measured as M, NotMeasuredReason as N};
    core::RunMeasurements {
        output_tokens: M::not_measured(N::NotRecorded),
        prefill_tokens_per_second: M::not_measured(N::UnsupportedByBackend),
        aggregate_decode_tokens_per_second: M::not_measured(N::NotRecorded),
        speculative: M::not_measured(N::NotRecorded),
        peak_gpu_memory_bytes: M::not_measured(N::NotRecorded),
        retained_gpu_memory_bytes: M::not_measured(N::NotRecorded),
        peak_host_memory_bytes: M::not_measured(N::NotRecorded),
        retained_host_memory_bytes: M::not_measured(N::NotRecorded),
        peak_pinned_host_memory_bytes: M::not_measured(N::NotRecorded),
        transferred_bytes: M::not_measured(N::NotRecorded),
        storage_read_bytes: M::not_measured(N::NotRecorded),
        energy_joules: M::not_measured(N::InstrumentUnavailable),
        offload: M::not_measured(N::NotRecorded),
        first_run: M::not_measured(N::NotApplicable),
        owner_return: M::not_measured(N::NotApplicable),
        reasoning: M::not_measured(N::NotRecorded),
    }
}

/// Produces a CORE-08 record only where the existing clock contract is met.
/// All raw successes/failures remain in the returned attempt, including gaps;
/// callers must never calculate a denominator from only `record.is_some()`.
pub(crate) fn adapt(
    record: &CompletedObservation,
    identity: &ObservationIdentity,
    context: &ReportContext,
) -> Result<AdaptedAttempt, AdapterError> {
    record.validate()?;
    identity.validate()?;
    context.identity.validate()?;
    if identity != &context.identity
        || identity.attempt_id != record.id
        || context.expected_kind != record.kind
    {
        return Err(AdapterError::ContextMismatch);
    }
    let mut adapted = AdaptedAttempt {
        observation: record.clone(),
        record: None,
        gaps: vec![
            ConversionGap::InclusiveStagesNotAdditive,
            ConversionGap::ResourceMeasurementsUnavailable,
            ConversionGap::DenominatorRequiresSealedJournal,
        ],
    };
    if record.kind == AttemptKind::Request {
        let exact_tokens = record.tokens.as_ref().is_some_and(|t| t.complete);
        if !exact_tokens {
            adapted
                .gaps
                .push(ConversionGap::ExactTokenTimingUnavailable);
        }
        if record
            .boundaries
            .as_ref()
            .is_none_or(|b| b.admitted_nanos.is_none())
        {
            adapted.gaps.push(ConversionGap::QueueBoundaryUnavailable);
        }
        if record
            .boundaries
            .as_ref()
            .is_none_or(|b| b.completed_nanos.is_none())
        {
            adapted
                .gaps
                .push(ConversionGap::RequestCompletionBoundaryUnavailable);
        }
        if !context.metadata.state.is_measured() {
            adapted
                .gaps
                .push(ConversionGap::ServingStartStateUnavailable);
        }
        let demand = matches!(&context.metadata.state,
            core::Measured::Measured { value } if value.is_demand());
        // A load from scratch belongs to a model that was not loaded on arrival, a wake to one
        // that was asleep.
        let measured_load = record.demand_load.as_ref().is_some_and(|load| {
            let arrival = if load.wake {
                core::ModelAtArrival::Asleep
            } else {
                core::ModelAtArrival::NotLoaded
            };
            matches!(&context.metadata.state,
                core::Measured::Measured { value } if value.model_at_arrival == arrival)
        });
        if record.demand_load.is_some() && context.metadata.state.is_measured() && !measured_load {
            adapted.gaps.push(ConversionGap::ServingStartStateMismatch);
            return Ok(adapted);
        }
        // Keep legacy conversion byte-for-byte stable for durable sink replay.
        // This new gap applies only to the new complete-token extension.
        if demand && exact_tokens && !measured_load {
            adapted
                .gaps
                .push(ConversionGap::DemandWorkBoundaryUnavailable);
        }
        // No inferred wake/load spans or token timings. Legacy and incomplete
        // successes remain raw; failed attempts retain their denominator entry.
        if !context.metadata.state.is_measured()
            || (record.outcome == RunnerOutcome::Ok
                && (!exact_tokens || (demand && !measured_load)))
        {
            return Ok(adapted);
        }
    }
    let metadata = &context.metadata;
    let label = |value| core::Label::new(value).expect("fixed redaction-safe measurement label");
    let outcome = match record.outcome {
        RunnerOutcome::Ok => core::Outcome::Succeeded,
        other => {
            let (failure, code) = match other {
                RunnerOutcome::Cancelled => (core::FailureKind::EarlyTermination, "cancelled"),
                RunnerOutcome::Busy => (core::FailureKind::Rejected, "busy"),
                RunnerOutcome::Invalid => (core::FailureKind::Rejected, "invalid-request"),
                _ => (core::FailureKind::CommandFailure, "runner-error"),
            };
            core::Outcome::Failed {
                failure,
                component: label("python-runner"),
                code: label(code),
            }
        }
    };
    let mut events = Vec::new();
    let scenario = if record.kind == AttemptKind::Load {
        // timed_load surrounds the load_model call; its explicit ok outcome is
        // recorded only when STATE is ready on return. This is load-call
        // activation-to-ready-return latency, not process init or exact TTFT.
        let clock = core::ClockId::new(label("runner-attempt-relative"));
        events.push(core::RecordedEvent {
            operation: metadata.attempt.operation.clone(),
            clock: clock.clone(),
            sequence: 0,
            at_nanos: MonotonicTime::from_nanos(0),
            event: core::EventKind::ActivationRequested,
        });
        if record.outcome == RunnerOutcome::Ok {
            events.push(core::RecordedEvent {
                operation: metadata.attempt.operation.clone(),
                clock,
                sequence: 1,
                at_nanos: MonotonicTime::from_nanos(record.elapsed_nanos),
                event: core::EventKind::EngineReadyForShape,
            });
        }
        core::Scenario::Stages {
            primary: core::IntervalKind::ReadyLatency,
        }
    } else {
        if let Some(b) = &record.boundaries {
            let clock = core::ClockId::new(label("runner-attempt-relative"));
            let mut observations = vec![(Some(b.accepted_nanos), core::EventKind::RequestAccepted)];
            if let Some(load) = &record.demand_load {
                let (started, ready) = if load.wake {
                    (core::EventKind::WakeStarted, core::EventKind::WakeCompleted)
                } else {
                    (core::EventKind::LoadStarted, core::EventKind::LoadCompleted)
                };
                observations.push((Some(load.started_nanos), started));
                observations.push((Some(load.ready_nanos), ready));
            }
            observations.push((b.admitted_nanos, core::EventKind::RequestDequeued));
            if let Some(t) = &record.tokens {
                if t.complete {
                    observations.extend(
                        t.emitted_nanos
                            .iter()
                            .map(|at| (Some(*at), core::EventKind::TokenEmitted)),
                    );
                }
            }
            observations.push((b.completed_nanos, core::EventKind::RequestCompleted));
            for (at, event) in observations {
                if let Some(at) = at {
                    events.push(core::RecordedEvent {
                        operation: metadata.attempt.operation.clone(),
                        clock: clock.clone(),
                        sequence: events.len() as u64,
                        at_nanos: MonotonicTime::from_nanos(at),
                        event,
                    });
                }
            }
        }
        core::Scenario::Serving
    };
    let mut measurements = unknown_measurements();
    if let Some(t) = &record.tokens {
        if t.complete {
            measurements.output_tokens = core::Measured::measured(t.emitted_nanos.len() as u64);
        }
    }
    if let Some(backend) = &record.backend {
        let (prefill, decode) = backend_rates(backend);
        if let Some(rate) = prefill {
            measurements.prefill_tokens_per_second = core::Measured::measured(rate);
        }
        if let Some(rate) = decode {
            measurements.aggregate_decode_tokens_per_second = core::Measured::measured(rate);
        }
    }
    let report = core::RunRecord {
        schema_version: core::SchemaVersion,
        attempt: metadata.attempt.clone(),
        scenario,
        substrate: metadata.substrate.clone(),
        build: metadata.build.clone(),
        execution_category: metadata.execution_category,
        model: metadata.model.clone(),
        precision: metadata.precision.clone(),
        engine: metadata.engine.clone(),
        host: metadata.host.clone(),
        workload: metadata.workload.clone(),
        client: metadata.client.clone(),
        load: metadata.load.clone(),
        state: metadata.state.clone(),
        launch: metadata.launch.clone(),
        price: metadata.price.clone(),
        measurements,
        events,
        outcome,
    };
    report
        .validate()
        .map_err(|_| AdapterError::InvalidReportContext)?;
    adapted.record = Some(report);
    Ok(adapted)
}

/// The prefill and decode rates a backend's own clock bounds (G01, FAST-01): prefill counts the
/// prompt tokens it computed (a prefix-cache hit is not prefill) over its prefill span, decode
/// the tokens produced after the first over vLLM's first-to-last span, or every generated
/// token over llama.cpp's generation span. The Transformers runner's first-token span includes
/// a sampling step and no rate is derived from it; its observation stays raw.
pub(crate) fn backend_rates(
    backend: &BackendObservation,
) -> (Option<core::NonNegative>, Option<core::NonNegative>) {
    let per_second = |tokens: u64, nanos: u64| {
        (tokens > 0 && nanos > 0)
            .then(|| core::NonNegative::new(tokens as f64 * 1e9 / nanos as f64).ok())
            .flatten()
    };
    let computed = backend
        .cached_tokens
        .map(|cached| backend.prompt_tokens - cached);
    match backend.source {
        BackendSource::TransformersFirstToken => (None, None),
        BackendSource::VllmMetricsDelta => (
            computed.and_then(|tokens| per_second(tokens, backend.prefill_nanos)),
            backend
                .output_tokens
                .zip(backend.decode_nanos)
                .and_then(|(tokens, nanos)| per_second(tokens.saturating_sub(1), nanos)),
        ),
        BackendSource::LlamaCppTimings => (
            computed.and_then(|tokens| per_second(tokens, backend.prefill_nanos)),
            backend
                .output_tokens
                .zip(backend.decode_nanos)
                .and_then(|(tokens, nanos)| per_second(tokens, nanos)),
        ),
    }
}

#[cfg(test)]
mod tests;
