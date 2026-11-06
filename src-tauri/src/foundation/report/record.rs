//! The raw run record of S8, with the FAST-01 fields of S13, redacted by construction.
//!
//! One record is one attempt: a request, a switch, a VM create, a first run, an owner
//! resource return or a stage measurement. Every S8 field is present in every record;
//! what does not apply or was not measured says so explicitly.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::bench::BenchId;
use super::cost::PriceQuote;
use super::error::ReportError;
use super::events::{
    ClockFamily, FirstRunClock, IntervalKind, MeasuredInterval, OwnerReturnClock, RecordedEvent,
    ReturnPath, ServingClock, StageReading, SwitchMode, SwitchingClock, Timeline,
    VmProvisioningClock,
};
use super::measured::{Measured, NonNegative};
use super::text::{CommitHash, Disclosure, FixtureRef, Label};
use super::SchemaVersion;
use crate::foundation::ids::{Digest, DigestBuilder, ExecutionCategory, ExecutionId, OperationId};

/// Domain of [`RunRecord::configuration_digest`].
pub const CONFIGURATION_DIGEST_DOMAIN: &str = "yougori/report/run-configuration/v1";

/// One attempt's raw record (S8 "Every raw run records …").
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRecord {
    pub schema_version: SchemaVersion,
    pub attempt: AttemptIdentity,
    pub scenario: Scenario,
    pub substrate: RunSubstrate,
    /// Plan and runner build identity.
    pub build: BuildIdentity,
    /// Kept under its VM-D4–VM-D6 label; never presented as a sandbox unless it is one.
    pub execution_category: ExecutionCategory,
    /// Model revision and licenses, weights, tokenizer and template.
    pub model: Measured<ModelIdentity>,
    /// Weight, quantization and KV dtype.
    pub precision: Measured<Precision>,
    /// Engine and version.
    pub engine: Measured<EngineIdentity>,
    /// OS, driver, GPU and memory, CPU, power and clock state.
    pub host: HostDescription,
    /// Input and output lengths, sampling and tool schema, as fixture references.
    pub workload: Measured<Workload>,
    /// Client and region.
    pub client: ClientDescription,
    /// Concurrent load.
    pub load: LoadDescription,
    /// Cache and sleep state on arrival.
    pub state: Measured<StartState>,
    /// Launch image and backend.
    pub launch: LaunchDescription,
    /// Price source and time.
    pub price: Measured<PriceQuote>,
    pub measurements: RunMeasurements,
    /// Monotonic timestamps.
    pub events: Vec<RecordedEvent>,
    pub outcome: Outcome,
}

/// Which attempt this is (S8: every initial attempt counts; a retry is a separate result
/// linked to its first attempt).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptIdentity {
    pub bench: BenchId,
    /// The case variant, such as `load-8` or `burst-100`.
    pub variant: Label,
    /// The parent execution of the benchmark run.
    pub execution: ExecutionId,
    /// This attempt; its events carry the same id.
    pub operation: OperationId,
    pub role: AttemptRole,
    /// The independent burst this attempt belongs to (S8, S11).
    pub burst: u32,
    /// The declared deadline, measured on the primary interval of the scenario.
    pub deadline_nanos: Measured<u64>,
}

strict_tagged_enum! {
/// An initial attempt, or a retry linked to its first attempt (S8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttemptRole (tag = "kind", wire = AttemptRoleWire, wire_name = "AttemptRoleWire") {
    Initial,
    Retry {
        first_attempt: OperationId,
        retry_number: u32,
    },
}
}

strict_tagged_enum! {
/// Which clock the attempt measures (S8 clocks, §2.1 stages).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scenario (tag = "clock", wire = ScenarioWire, wire_name = "ScenarioWire") {
    Serving,
    Switching {
        mode: SwitchMode,
        controlled_gap_nanos: u64,
    },
    VmProvisioning,
    FirstRun,
    OwnerResourceReturn {
        path: ReturnPath,
    },
    /// §2.1 boundaries; `primary` is the stage interval the attempt is judged by.
    Stages {
        primary: IntervalKind,
    },
}
}

impl Scenario {
    /// The interval a successful attempt must complete and its deadline applies to.
    pub const fn primary_interval(self) -> IntervalKind {
        match self {
            Self::Serving => IntervalKind::RequestLatency,
            Self::Switching { .. } => IntervalKind::SwitchLastOutputToFirstOutput,
            Self::VmProvisioning => IntervalKind::VmFirstGuestCommand,
            Self::FirstRun => IntervalKind::FirstRunToAgentTask,
            Self::OwnerResourceReturn { .. } => IntervalKind::OwnerReturnForeground,
            Self::Stages { primary } => primary,
        }
    }

    /// Every interval the deadline applies to: owner resource return checks all three
    /// of its events.
    pub fn deadline_intervals(self) -> Vec<IntervalKind> {
        match self {
            Self::OwnerResourceReturn { .. } => vec![
                IntervalKind::OwnerReturnDenial,
                IntervalKind::OwnerReturnVram,
                IntervalKind::OwnerReturnForeground,
            ],
            _ => vec![self.primary_interval()],
        }
    }
}

strict_tagged_enum! {
/// Where the attempt ran. A real run happens only in an authorized disposable
/// environment (S11: expensive VM, hardware, cloud, competitor or multi-day runs "are
/// not commands to run on the active laptop"; S13: keep the owner's active services
/// untouched). There is no variant for the owner's active machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunSubstrate (tag = "kind", wire = RunSubstrateWire, wire_name = "RunSubstrateWire") {
    /// A fake, time-controlled runner (S12 G0).
    FakeTimeControlled,
    /// A real run in a disposable environment under the named authorization.
    AuthorizedDisposable { authorization: Label },
}
}

/// Plan and runner build identity (S8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildIdentity {
    pub plan: Digest,
    pub runner_build: Digest,
    pub runner_version: Label,
}

/// Model revision and licenses, tokenizer and template (S8), and the model digest
/// (FAST-01).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelIdentity {
    pub revision: ModelRevision,
    /// SPDX identifiers or `LicenseRef-…`; at least one.
    pub licenses: Vec<Label>,
    pub weights: Digest,
    pub tokenizer: Digest,
    pub chat_template: Digest,
}

/// A model revision: a source-control commit or a named tag (S8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum ModelRevision {
    Commit { hash: CommitHash },
    Tag { name: Label },
}

crate::foundation::strict_serde::strict_tag!(ModelRevision, "kind");

/// Weight, quantization and KV dtype (S8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Precision {
    pub weight_dtype: Label,
    pub quantization: Label,
    pub kv_cache_dtype: Label,
}

/// Engine and version (S8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineIdentity {
    pub name: Label,
    pub version: Label,
}

/// OS, driver, GPU and memory, and CPU (S8), with the FAST-01 power and clock state and
/// the S7/BENCH-09 power source and monitor state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostDescription {
    pub os: Label,
    pub os_version: Label,
    pub cpu: CpuDescription,
    pub host_memory_bytes: u64,
    pub gpus: Measured<Vec<GpuDescription>>,
    pub gpu_driver: Measured<Label>,
    pub gpu_power_clock: Measured<GpuPowerClock>,
    pub power_source: Measured<PowerSource>,
    /// Displays the measured GPU drives (S7 "monitor state", BENCH-09 display load).
    pub displays_on_gpu: Measured<u32>,
}

/// The CPU (S8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpuDescription {
    pub model: Label,
    pub logical_cores: u32,
}

/// One GPU and its memory (S8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuDescription {
    pub model: Label,
    pub memory_bytes: u64,
}

/// FAST-01 "GPU power/clock state".
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuPowerClock {
    pub power_limit_watts: NonNegative,
    pub graphics_clock_mhz: u32,
    pub memory_clock_mhz: u32,
}

/// Laptop AC or battery (S7 consumer hardware, BENCH-09).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerSource {
    Ac,
    Battery,
}

/// Input and output lengths, sampling and tool schema (S8), and the FAST-01 fixture
/// family and cold-test nonce. The prompt is a fixture reference, never text.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workload {
    pub fixture: FixtureRef,
    pub family: FixtureFamily,
    pub input_tokens: u64,
    pub max_output_tokens: u64,
    pub sampling: Sampling,
    pub tool_schema: Measured<FixtureRef>,
    /// Part of a paired comparison corpus (S9, S13).
    pub paired: bool,
    pub cold_test_nonce: NonceDisclosure,
}

/// FAST-01 fixed fixtures: code, prose, long-context and tool, plus agent tasks and the
/// reasoning fixtures the FAST-05 reasoning gate needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureFamily {
    Code,
    Prose,
    LongContext,
    Tool,
    AgentTask,
    /// A question with one expected final answer (S13 line 250: a GSM8K-style set).
    /// Its attempts carry a [`ReasoningCheck`].
    Reasoning,
}

/// Sampling settings (S8).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sampling {
    pub temperature: NonNegative,
    pub top_p: Measured<NonNegative>,
    pub top_k: Measured<u32>,
    pub seed: Measured<u64>,
}

strict_tagged_enum! {
/// FAST-01: "A cold-test nonce must be disclosed and must not alter a paired task's
/// intended semantics."
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NonceDisclosure (tag = "kind", wire = NonceDisclosureWire, wire_name = "NonceDisclosureWire") {
    NotUsed,
    Disclosed {
        value: u64,
        placement: NoncePlacement,
        alters_task_semantics: bool,
    },
}
}

/// Where a cold-test nonce was placed (FAST-01).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoncePlacement {
    PromptPrefix,
    SystemPrompt,
    RequestMetadata,
}

impl Workload {
    fn check(&self) -> Result<(), ReportError> {
        if let NonceDisclosure::Disclosed {
            alters_task_semantics: true,
            ..
        } = self.cold_test_nonce
        {
            if self.paired {
                return Err(ReportError::NonceAltersPairedTask);
            }
        }
        Ok(())
    }
}

/// Client and region (S8); a remote service discloses provider region, network hops and
/// availability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientDescription {
    pub name: Label,
    pub version: Label,
    pub region: Label,
    pub placement: ClientPlacement,
}

strict_tagged_enum! {
/// Where the client ran relative to the service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientPlacement (tag = "kind", wire = ClientPlacementWire, wire_name = "ClientPlacementWire") {
    SameHost,
    LocalNetwork,
    ControlledRemote {
        provider_region: Label,
        network_hops: Measured<u32>,
        provider_availability: Measured<Label>,
    },
}
}

/// Concurrent load and arrival pattern (S8; S7 sequential, staggered and burst modes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadDescription {
    pub concurrent_requests: u32,
    pub arrival: ArrivalMode,
}

strict_tagged_enum! {
/// How attempts arrive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArrivalMode (tag = "kind", wire = ArrivalModeWire, wire_name = "ArrivalModeWire") {
    Sequential,
    Staggered { interval_nanos: u64 },
    Burst { size: u32 },
}
}

/// Cache and sleep state on arrival (S8), with the FAST-01 cache tier and prefill mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartState {
    pub temperature: StartTemperature,
    pub model_at_arrival: ModelAtArrival,
    pub cache_tier: CacheTier,
    pub prefill: PrefillMode,
    pub cold_provenance: ColdProvenance,
}

/// Cold and warm states run separately (S8) and are never compared as one another
/// (§2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartTemperature {
    Cold,
    Warm,
    Hot,
}

/// The model's state when the request arrived; anything but ready makes a demand
/// request (S8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelAtArrival {
    ReadyToServe,
    Asleep,
    NotLoaded,
}

/// FAST-01 cache tier: where reusable state was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheTier {
    NoReusableState,
    GpuMemory,
    HostMemory,
    LocalDisk,
    Peer,
}

/// FAST-01: fresh-prefill and deliberate warm-prefix tests are separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefillMode {
    Fresh,
    WarmPrefix,
}

/// How a cold state was obtained. S8: "Do not flush the user's active host cache or stop
/// their engine to manufacture a cold baseline", so those methods have no variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ColdProvenance {
    NotCold,
    /// A fresh disposable environment.
    DisposableEnvironment,
    /// The artifact had never been read on this host.
    FirstUseOfArtifact,
}

impl StartState {
    /// A demand request: the model was not ready to serve on arrival, so its first-token
    /// clock must include the wake or load (S8).
    pub fn is_demand(&self) -> bool {
        self.model_at_arrival != ModelAtArrival::ReadyToServe
    }

    /// Hot means ready to serve; cold means not loaded, nothing reusable, fresh prefill
    /// and a stated cold provenance; a warm prefix needs reusable state.
    pub fn check(&self) -> Result<(), ReportError> {
        let by_temperature = match self.temperature {
            StartTemperature::Hot => {
                self.model_at_arrival == ModelAtArrival::ReadyToServe
                    && self.cold_provenance == ColdProvenance::NotCold
            }
            StartTemperature::Warm => {
                self.model_at_arrival != ModelAtArrival::ReadyToServe
                    && self.cold_provenance == ColdProvenance::NotCold
            }
            StartTemperature::Cold => {
                self.model_at_arrival == ModelAtArrival::NotLoaded
                    && self.cold_provenance != ColdProvenance::NotCold
                    && self.cache_tier == CacheTier::NoReusableState
                    && self.prefill == PrefillMode::Fresh
            }
        };
        let prefix = !(self.prefill == PrefillMode::WarmPrefix
            && self.cache_tier == CacheTier::NoReusableState);
        if by_temperature && prefix {
            Ok(())
        } else {
            Err(ReportError::InconsistentStartState)
        }
    }

    fn matches_switch(&self, mode: SwitchMode) -> bool {
        match mode {
            SwitchMode::HotDispatch => self.temperature == StartTemperature::Hot,
            SwitchMode::Wake => self.model_at_arrival == ModelAtArrival::Asleep,
            SwitchMode::WarmReload => {
                self.temperature == StartTemperature::Warm
                    && self.model_at_arrival == ModelAtArrival::NotLoaded
            }
            SwitchMode::ColdProcessStart => self.temperature == StartTemperature::Cold,
        }
    }
}

/// Launch image and backend (S8); the image digest is the FAST-01 image digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchDescription {
    pub image: Digest,
    pub backend: Label,
}

/// FAST-01 measurements and the §1.3 memory and movement quantities, each measured or
/// explicitly not measured.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunMeasurements {
    pub output_tokens: Measured<u64>,
    pub prefill_tokens_per_second: Measured<NonNegative>,
    pub aggregate_decode_tokens_per_second: Measured<NonNegative>,
    pub speculative: Measured<SpeculativeDecoding>,
    pub peak_gpu_memory_bytes: Measured<u64>,
    pub retained_gpu_memory_bytes: Measured<u64>,
    pub peak_host_memory_bytes: Measured<u64>,
    pub retained_host_memory_bytes: Measured<u64>,
    pub peak_pinned_host_memory_bytes: Measured<u64>,
    pub transferred_bytes: Measured<u64>,
    pub storage_read_bytes: Measured<u64>,
    pub energy_joules: Measured<NonNegative>,
    pub offload: Measured<Offload>,
    pub first_run: Measured<FirstRunTally>,
    pub owner_return: Measured<OwnerReturnTally>,
    /// The reasoning check of a reasoning-family attempt; not applicable otherwise.
    pub reasoning: Measured<ReasoningCheck>,
}

/// What a reasoning gate needs from one reasoning-family attempt (S13 FAST-05: "Gate
/// load, chat, reasoning, tools, context and workload-specific speed/quality"; S13 line
/// 250 quality evidence): whether a reasoning trace was separated from the final answer,
/// and whether the final answer matched the fixture's answer key. Neither the trace nor
/// the answer is recorded as text (S8 redaction; VM §8.2: no "hidden model reasoning" in
/// logs): the answer key is a fixture reference, the trace a token count.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReasoningCheck {
    /// The expected final answer, identified by digest.
    pub answer_key: FixtureRef,
    pub trace: ReasoningTrace,
    pub final_answer: AnswerVerdict,
}

impl ReasoningCheck {
    /// A trace was present and the final answer was correct.
    pub fn passed(&self) -> bool {
        matches!(self.trace, ReasoningTrace::Present { .. })
            && self.final_answer == AnswerVerdict::Correct
    }
}

strict_tagged_enum! {
/// Whether the response carried a reasoning trace separated from its final answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReasoningTrace (tag = "kind", wire = ReasoningTraceWire, wire_name = "ReasoningTraceWire") {
    Absent,
    /// Present, with its length where the backend counts reasoning tokens.
    Present { tokens: Measured<u64> },
}
}

/// The final answer judged against the fixture's answer key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnswerVerdict {
    Correct,
    Incorrect,
    /// No final answer was emitted, such as a response cut off inside its reasoning.
    Missing,
}

/// FAST-01 "speculative accepted length/steps".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpeculativeDecoding {
    pub drafted_tokens: u64,
    pub accepted_tokens: u64,
    pub verification_steps: u64,
}

impl SpeculativeDecoding {
    /// Accepted draft tokens per verification step.
    pub fn mean_accepted_length(&self) -> Option<f64> {
        (self.verification_steps > 0)
            .then(|| self.accepted_tokens as f64 / self.verification_steps as f64)
    }
}

/// BENCH-09 fit, offload and silent spill.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Offload {
    NoOffload,
    ExplicitCpuOffload,
    ExplicitHostMemoryOffload,
    SilentSpillDetected,
}

/// S8 first run: "Include installs, downloads, sign-in when applicable, questions,
/// errors and retries"; S7 adds required actions and failed prerequisites.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstRunTally {
    pub installs: u32,
    pub downloads: u32,
    pub download_bytes: u64,
    pub sign_ins: Measured<u32>,
    pub questions: u32,
    pub required_actions: u32,
    pub errors: u32,
    pub retries: u32,
    pub failed_prerequisites: u32,
}

/// BENCH-12: abandoned and retried requests during an owner resource return.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerReturnTally {
    pub abandoned_requests: u64,
    pub retried_requests: u64,
}

impl RunMeasurements {
    fn check(&self) -> Result<(), ReportError> {
        let speculative_ok = self.speculative.value().is_none_or(|speculative| {
            speculative.accepted_tokens <= speculative.drafted_tokens
                && (speculative.drafted_tokens == 0 || speculative.verification_steps > 0)
        });
        let peak_ok =
            |peak: &Measured<u64>, retained: &Measured<u64>| match (peak.value(), retained.value())
            {
                (Some(peak), Some(retained)) => retained <= peak,
                _ => true,
            };
        // A present trace has at least one token.
        let trace_ok = self.reasoning.value().is_none_or(|check| {
            !matches!(
                check.trace,
                ReasoningTrace::Present {
                    tokens: Measured::Measured { value: 0 }
                }
            )
        });
        if speculative_ok
            && trace_ok
            && peak_ok(&self.peak_gpu_memory_bytes, &self.retained_gpu_memory_bytes)
            && peak_ok(
                &self.peak_host_memory_bytes,
                &self.retained_host_memory_bytes,
            )
        {
            Ok(())
        } else {
            Err(ReportError::InconsistentMeasurement)
        }
    }
}

strict_tagged_enum! {
/// How the attempt ended (S8 failure taxonomy).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome (tag = "result", wire = OutcomeWire, wire_name = "OutcomeWire") {
    Succeeded,
    /// Kept in the raw data and the denominator; `component` and `code` give the
    /// failure provenance (CORE-08).
    Failed {
        failure: FailureKind,
        component: Label,
        code: Label,
    },
}
}

/// S8: "A rejected request, timeout, duplicate identity, command failure or early
/// termination remains in the raw data and failure taxonomy", plus deadline failures
/// and results that completed but failed validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Rejected,
    Timeout,
    DuplicateIdentity,
    CommandFailure,
    EarlyTermination,
    DeadlineFailure,
    InvalidResult,
}

impl FailureKind {
    /// The whole failure taxonomy.
    pub const ALL: [Self; 7] = [
        Self::Rejected,
        Self::Timeout,
        Self::DuplicateIdentity,
        Self::CommandFailure,
        Self::EarlyTermination,
        Self::DeadlineFailure,
        Self::InvalidResult,
    ];
}

impl fmt::Display for FailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Rejected => "rejected",
            Self::Timeout => "timeout",
            Self::DuplicateIdentity => "duplicate identity",
            Self::CommandFailure => "command failure",
            Self::EarlyTermination => "early termination",
            Self::DeadlineFailure => "deadline failure",
            Self::InvalidResult => "invalid result",
        })
    }
}

/// The clock reading of a successful attempt.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "clock", rename_all = "snake_case")]
pub enum ClockReading {
    Serving(ServingClock),
    Switching(SwitchingClock),
    VmProvisioning(VmProvisioningClock),
    FirstRun(FirstRunClock),
    OwnerResourceReturn(OwnerReturnClock),
    Stages(StageReading),
}

impl RunRecord {
    /// Reads a record from JSON and [validates](Self::validate) it. A record of another
    /// schema version, such as one written before version 3's reasoning family, is
    /// refused with [`ReportError::UnsupportedSchemaVersion`] and never reinterpreted;
    /// text that does not parse as a record is [`ReportError::Malformed`].
    pub fn from_json(json: &str) -> Result<Self, ReportError> {
        super::check_schema_version(json)?;
        let record: Self = serde_json::from_str(json).map_err(super::malformed)?;
        record.validate()?;
        Ok(record)
    }

    /// Checks the record against S8 and FAST-01:
    ///
    /// - every event belongs to this attempt, and the timeline is consistent;
    /// - a VM provisioning attempt runs in a VM sandbox;
    /// - serving and switching attempts declare a consistent cache and sleep state, and
    ///   a switch mode matches it;
    /// - a successful attempt has its clock reading, met its deadline and, for a first
    ///   run or owner return, its tally;
    /// - a reasoning check belongs to a reasoning workload, and a successful reasoning
    ///   attempt passed it;
    /// - a disclosed nonce does not alter a paired task;
    /// - recorded token counts match the token events.
    pub fn validate(&self) -> Result<(), ReportError> {
        if self
            .events
            .iter()
            .any(|event| event.operation != self.attempt.operation)
        {
            return Err(ReportError::EventFromAnotherRun);
        }
        let timeline = Timeline::new(&self.events)?;
        if let AttemptRole::Retry {
            first_attempt,
            retry_number,
        } = &self.attempt.role
        {
            if *retry_number == 0 || *first_attempt == self.attempt.operation {
                return Err(ReportError::InvalidRetry);
            }
        }
        if let Some(model) = self.model.value() {
            if model.licenses.is_empty() {
                return Err(ReportError::MissingLicense);
            }
        }
        if let Some(state) = self.state.value() {
            state.check()?;
        }
        if let Some(workload) = self.workload.value() {
            workload.check()?;
        }
        self.measurements.check()?;
        self.check_scenario()?;
        // A reasoning check belongs to a reasoning workload, and a successful reasoning
        // attempt showed a trace and a correct final answer (FAST-05 reasoning gate).
        let reasoning_workload = self
            .workload
            .value()
            .is_some_and(|workload| workload.family == FixtureFamily::Reasoning);
        if self.measurements.reasoning.is_measured() && !reasoning_workload {
            return Err(ReportError::ReasoningCheckMismatch);
        }
        if reasoning_workload
            && self.is_success()
            && !self
                .measurements
                .reasoning
                .value()
                .is_some_and(ReasoningCheck::passed)
        {
            return Err(ReportError::ReasoningNotPassed);
        }
        let token_events = timeline.emitted_tokens();
        if let Some(recorded) = self.measurements.output_tokens.value() {
            if token_events > 0 && *recorded != token_events {
                return Err(ReportError::TokenCountMismatch {
                    recorded: *recorded,
                    events: token_events,
                });
            }
        }
        if self.is_success() {
            self.clock_reading_on(&timeline)?;
            for interval in self.scenario.deadline_intervals() {
                let measured = timeline.interval(interval)?;
                if let Some(deadline) = self.attempt.deadline_nanos.value() {
                    if measured.elapsed_nanos() > *deadline {
                        return Err(ReportError::SuccessAfterDeadline { interval });
                    }
                }
            }
            let tally_missing = match self.scenario {
                Scenario::FirstRun => !self.measurements.first_run.is_measured(),
                Scenario::OwnerResourceReturn { .. } => {
                    !self.measurements.owner_return.is_measured()
                }
                _ => false,
            };
            if tally_missing {
                return Err(ReportError::MissingScenarioMeasurement);
            }
        }
        if self.failure() == Some(FailureKind::DeadlineFailure) {
            // A deadline failure needs a declared deadline that the attempt missed.
            let deadline = self
                .attempt
                .deadline_nanos
                .value()
                .ok_or(ReportError::InconsistentDeadline)?;
            let met = self
                .scenario
                .deadline_intervals()
                .into_iter()
                .all(|interval| {
                    timeline
                        .interval(interval)
                        .is_ok_and(|measured| measured.elapsed_nanos() <= *deadline)
                });
            if met {
                return Err(ReportError::InconsistentDeadline);
            }
        }
        Ok(())
    }

    fn check_scenario(&self) -> Result<(), ReportError> {
        match self.scenario {
            Scenario::VmProvisioning if !self.execution_category.is_vm_sandbox() => {
                Err(ReportError::ScenarioCategoryMismatch)
            }
            Scenario::Serving => self.start_state().map(|_| ()),
            Scenario::Switching { mode, .. } => {
                if self.start_state()?.matches_switch(mode) {
                    Ok(())
                } else {
                    Err(ReportError::InconsistentStartState)
                }
            }
            Scenario::Stages { primary } if primary.family() != ClockFamily::Stage => {
                Err(ReportError::InvalidStagePrimary)
            }
            _ => Ok(()),
        }
    }

    fn start_state(&self) -> Result<&StartState, ReportError> {
        self.state.value().ok_or(ReportError::MissingStartState)
    }

    /// The validated events of this attempt.
    pub fn timeline(&self) -> Result<Timeline<'_>, ReportError> {
        Timeline::new(&self.events)
    }

    /// Measures `kind` from this attempt's events.
    pub fn interval(&self, kind: IntervalKind) -> Result<MeasuredInterval, ReportError> {
        self.timeline()?.interval(kind)
    }

    /// The scenario's clock (S8) or stage reading (§2.1).
    pub fn clock_reading(&self) -> Result<ClockReading, ReportError> {
        self.clock_reading_on(&self.timeline()?)
    }

    fn clock_reading_on(&self, timeline: &Timeline<'_>) -> Result<ClockReading, ReportError> {
        Ok(match self.scenario {
            Scenario::Serving => {
                ClockReading::Serving(timeline.serving(self.start_state()?.is_demand())?)
            }
            Scenario::Switching {
                mode,
                controlled_gap_nanos,
            } => ClockReading::Switching(timeline.switching(
                mode,
                controlled_gap_nanos,
                self.start_state()?.is_demand(),
            )?),
            Scenario::VmProvisioning => ClockReading::VmProvisioning(timeline.vm_provisioning()?),
            Scenario::FirstRun => ClockReading::FirstRun(timeline.first_run()?),
            Scenario::OwnerResourceReturn { path } => {
                ClockReading::OwnerResourceReturn(timeline.owner_return(path)?)
            }
            Scenario::Stages { .. } => ClockReading::Stages(timeline.stages()?),
        })
    }

    pub fn is_success(&self) -> bool {
        matches!(self.outcome, Outcome::Succeeded)
    }

    pub fn failure(&self) -> Option<FailureKind> {
        match &self.outcome {
            Outcome::Succeeded => None,
            Outcome::Failed { failure, .. } => Some(*failure),
        }
    }

    pub fn is_initial(&self) -> bool {
        matches!(self.attempt.role, AttemptRole::Initial)
    }

    /// The user-facing execution label (VM-D4–VM-D6, S12).
    pub fn category_label(&self) -> &'static str {
        self.execution_category.label()
    }

    /// Every fixture the record references.
    pub fn fixtures(&self) -> Vec<&FixtureRef> {
        let workload = self.workload.value();
        workload
            .map(|workload| &workload.fixture)
            .into_iter()
            .chain(workload.and_then(|workload| workload.tool_schema.value()))
            .chain(
                self.measurements
                    .reasoning
                    .value()
                    .map(|check| &check.answer_key),
            )
            .collect()
    }

    /// The most restrictive disclosure among the record's fixtures.
    pub fn disclosure(&self) -> Disclosure {
        self.fixtures()
            .iter()
            .map(|fixture| fixture.disclosure)
            .min()
            .unwrap_or(Disclosure::PermittedSynthetic)
    }

    /// Public artifacts use permitted synthetic or approved fixtures only (S8).
    pub fn check_publishable(&self) -> Result<(), ReportError> {
        match self
            .fixtures()
            .into_iter()
            .find(|fixture| !fixture.disclosure.is_publishable())
        {
            Some(fixture) => Err(ReportError::NotPublishable {
                fixture: fixture.id.clone(),
            }),
            None => Ok(()),
        }
    }

    /// A digest of everything that configures the attempt (BENCH-13 "configuration
    /// hashes"): build, category, model, precision, engine, host, workload, client,
    /// load, state and launch.
    pub fn configuration_digest(&self) -> Result<Digest, ReportError> {
        let parts = [
            serde_json::to_vec(&self.build),
            serde_json::to_vec(&self.execution_category),
            serde_json::to_vec(&self.model),
            serde_json::to_vec(&self.precision),
            serde_json::to_vec(&self.engine),
            serde_json::to_vec(&self.host),
            serde_json::to_vec(&self.workload),
            serde_json::to_vec(&self.client),
            serde_json::to_vec(&self.load),
            serde_json::to_vec(&self.state),
            serde_json::to_vec(&self.launch),
        ];
        parts
            .into_iter()
            .try_fold(
                DigestBuilder::new(CONFIGURATION_DIGEST_DOMAIN),
                |builder, part| part.map(|bytes| builder.bytes(&bytes)),
            )
            .map(DigestBuilder::finish)
            .map_err(|_| ReportError::Encoding)
    }
}

/// §2.1 switch overhead: extra latency versus an already-ready execution of the same
/// request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SwitchOverhead {
    /// B accepted to first B token in the switch.
    pub switched_nanos: u64,
    /// Accepted to first token of the same request on a hot, ready engine.
    pub ready_nanos: u64,
    /// May be negative within measurement noise; never clamped.
    pub overhead_nanos: i64,
}

/// Computes §2.1 switch overhead. `switched` is a successful switching attempt and
/// `ready` a successful hot serving attempt with the same request fixture.
pub fn switch_overhead(
    switched: &RunRecord,
    ready: &RunRecord,
) -> Result<SwitchOverhead, ReportError> {
    let switched_reading = match switched.clock_reading()? {
        ClockReading::Switching(clock) if switched.is_success() => clock,
        _ => return Err(ReportError::NotSameRequest),
    };
    let ready_hot = ready
        .state
        .value()
        .is_some_and(|state| state.temperature == StartTemperature::Hot);
    let ready_reading = match ready.clock_reading()? {
        ClockReading::Serving(clock) if ready.is_success() && ready_hot => clock,
        _ => return Err(ReportError::NotSameRequest),
    };
    let same_request = match (switched.workload.value(), ready.workload.value()) {
        (Some(left), Some(right)) => left.fixture.digest == right.fixture.digest,
        _ => false,
    };
    if !same_request {
        return Err(ReportError::NotSameRequest);
    }
    let switched_nanos = switched_reading.request.time_to_first_token.elapsed_nanos();
    let ready_nanos = ready_reading.time_to_first_token.elapsed_nanos();
    let overhead_nanos = i64::try_from(i128::from(switched_nanos) - i128::from(ready_nanos))
        .map_err(|_| ReportError::DurationOverflow)?;
    Ok(SwitchOverhead {
        switched_nanos,
        ready_nanos,
        overhead_nanos,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::{ExecutionCategory, MonotonicTime, SandboxBootGeneration};
    use crate::foundation::report::events::EventKind;
    use crate::foundation::report::fixtures::{
        events, failed, label, op, reasoning_record, serving_record, vm_record, warm_switch_record,
    };
    use crate::foundation::report::measured::NotMeasuredReason;

    #[test]
    fn a_valid_serving_record_reads_its_clock() {
        let record = serving_record("op-1", 120);
        record.validate().unwrap();
        match record.clock_reading().unwrap() {
            ClockReading::Serving(clock) => {
                assert_eq!(clock.time_to_first_token.elapsed_nanos(), 120_000_000)
            }
            other => panic!("unexpected reading {other:?}"),
        }
        assert_eq!(
            record.category_label(),
            "GPU runtime (shared kernel), not a sandbox"
        );
    }

    #[test]
    fn missing_fields_are_refused_and_not_measured_is_explicit() {
        let record = serving_record("op-1", 120);
        let mut json = serde_json::to_value(&record).unwrap();
        json["measurements"]
            .as_object_mut()
            .unwrap()
            .remove("energy_joules");
        assert!(serde_json::from_value::<RunRecord>(json).is_err());

        let mut zero = serde_json::to_value(&record).unwrap();
        zero["measurements"]["energy_joules"] = serde_json::json!(0);
        assert!(serde_json::from_value::<RunRecord>(zero).is_err());

        assert_eq!(
            record.measurements.energy_joules,
            Measured::not_measured(NotMeasuredReason::InstrumentUnavailable)
        );
    }

    #[test]
    fn no_field_accepts_a_raw_prompt_credential_or_path() {
        let record = serving_record("op-1", 120);
        let json = serde_json::to_value(&record).unwrap();
        // An extra free-text field is refused anywhere in the record, including beside
        // the tag of a variant without data.
        for pointer in [
            "",
            "/attempt",
            "/attempt/role",
            "/scenario",
            "/substrate",
            "/workload/value",
            "/workload/value/cold_test_nonce",
            "/host",
            "/host/gpu_driver",
            "/client",
            "/client/placement",
            "/load/arrival",
            "/measurements",
            "/measurements/energy_joules",
            "/events/0",
            "/events/0/event",
            "/outcome",
        ] {
            let mut tampered = json.clone();
            tampered
                .pointer_mut(pointer)
                .and_then(|value| value.as_object_mut())
                .unwrap()
                .insert("prompt".into(), "Tell me the admin password".into());
            assert!(
                serde_json::from_value::<RunRecord>(tampered).is_err(),
                "{pointer}"
            );
        }
        // Text fields refuse prompts, credentials and paths.
        for (pointer, value) in [
            ("/engine/value/version", "Write a poem about the sea"),
            (
                "/host/gpu_driver/value",
                "C:\\Windows\\System32\\nvapi64.dll",
            ),
            ("/client/name", "hf_AbCdEfGhIjKlMnOpQrStUvWxYz012345"),
            (
                "/workload/value/fixture/id",
                "/home/argon/prompts/secret.txt",
            ),
            ("/launch/backend", "sk-proj-abcdefghijklmnop1234"),
        ] {
            let mut tampered = json.clone();
            *tampered.pointer_mut(pointer).unwrap() = value.into();
            assert!(
                serde_json::from_value::<RunRecord>(tampered).is_err(),
                "{pointer}"
            );
        }
    }

    #[test]
    fn a_vm_create_is_measured_only_in_a_vm_sandbox() {
        let record = vm_record("op-1", 800);
        record.validate().unwrap();
        let mut labelled = record.clone();
        labelled.execution_category = ExecutionCategory::ProviderContainerRuntime;
        assert_eq!(
            labelled.validate(),
            Err(ReportError::ScenarioCategoryMismatch)
        );
    }

    #[test]
    fn an_acknowledged_vm_is_not_a_successful_create() {
        let mut record = vm_record("op-1", 800);
        record
            .events
            .retain(|event| !matches!(event.event, EventKind::GuestCommandSucceeded { .. }));
        assert!(matches!(
            record.validate(),
            Err(ReportError::MissingEvent { .. })
        ));
        record.outcome = failed(FailureKind::Timeout);
        record.validate().unwrap();
    }

    #[test]
    fn a_success_after_its_deadline_is_refused() {
        let mut record = serving_record("op-1", 120);
        record.attempt.deadline_nanos = Measured::measured(100_000_000);
        assert_eq!(
            record.validate(),
            Err(ReportError::SuccessAfterDeadline {
                interval: IntervalKind::RequestLatency
            })
        );
        record.outcome = failed(FailureKind::DeadlineFailure);
        record.validate().unwrap();
        // A deadline failure needs a deadline, and one that was actually missed.
        record.attempt.deadline_nanos = Measured::measured(500_000_000);
        assert_eq!(record.validate(), Err(ReportError::InconsistentDeadline));
        record.attempt.deadline_nanos = Measured::not_measured(NotMeasuredReason::NotApplicable);
        assert_eq!(record.validate(), Err(ReportError::InconsistentDeadline));
    }

    #[test]
    fn states_must_be_consistent_and_cold_cannot_be_manufactured() {
        let mut record = serving_record("op-1", 120);
        if let Measured::Measured { value } = &mut record.state {
            value.temperature = StartTemperature::Cold;
        }
        assert_eq!(record.validate(), Err(ReportError::InconsistentStartState));
        let json = serde_json::to_string(&ColdProvenance::DisposableEnvironment).unwrap();
        assert_eq!(json, "\"disposable_environment\"");
        for forbidden in ["\"flushed_user_host_cache\"", "\"stopped_user_engine\""] {
            assert!(serde_json::from_str::<ColdProvenance>(forbidden).is_err());
        }
        // A real run on the owner's active machine has no representation.
        assert!(
            serde_json::from_str::<RunSubstrate>(r#"{"kind":"active_owner_machine"}"#).is_err()
        );
    }

    #[test]
    fn a_disclosed_nonce_must_not_alter_a_paired_task() {
        let mut record = serving_record("op-1", 120);
        if let Measured::Measured { value } = &mut record.workload {
            value.paired = true;
            value.cold_test_nonce = NonceDisclosure::Disclosed {
                value: 7,
                placement: NoncePlacement::RequestMetadata,
                alters_task_semantics: true,
            };
        }
        assert_eq!(record.validate(), Err(ReportError::NonceAltersPairedTask));
    }

    #[test]
    fn token_counts_must_match_the_token_events() {
        let mut record = serving_record("op-1", 120);
        record.measurements.output_tokens = Measured::measured(99);
        assert_eq!(
            record.validate(),
            Err(ReportError::TokenCountMismatch {
                recorded: 99,
                events: 3
            })
        );
    }

    #[test]
    fn events_from_another_attempt_are_refused() {
        let mut record = serving_record("op-1", 120);
        record.events[0].operation = op("op-2");
        assert_eq!(record.validate(), Err(ReportError::EventFromAnotherRun));
    }

    #[test]
    fn a_retry_must_name_another_first_attempt() {
        let mut record = serving_record("op-1", 120);
        record.attempt.role = AttemptRole::Retry {
            first_attempt: op("op-1"),
            retry_number: 1,
        };
        assert_eq!(record.validate(), Err(ReportError::InvalidRetry));
        record.attempt.role = AttemptRole::Retry {
            first_attempt: op("op-0"),
            retry_number: 0,
        };
        assert_eq!(record.validate(), Err(ReportError::InvalidRetry));
    }

    #[test]
    fn switch_overhead_compares_the_same_request_on_a_ready_engine() {
        let switched = warm_switch_record("op-s", 250, 900);
        switched.validate().unwrap();
        let ready = serving_record("op-r", 120);
        let overhead = switch_overhead(&switched, &ready).unwrap();
        assert_eq!(overhead.ready_nanos, 120_000_000);
        assert_eq!(
            overhead.overhead_nanos,
            overhead.switched_nanos as i64 - 120_000_000
        );
        let mut other_request = ready.clone();
        if let Measured::Measured { value } = &mut other_request.workload {
            value.fixture.id = label("another-prompt");
            value.fixture.digest = crate::foundation::ids::digest("yougori/test/v1", &[b"x"]);
        }
        assert_eq!(
            switch_overhead(&switched, &other_request),
            Err(ReportError::NotSameRequest)
        );
    }

    #[test]
    fn configuration_digests_ignore_outcomes_but_not_configuration() {
        let first = serving_record("op-1", 120);
        let mut second = serving_record("op-2", 140);
        second.outcome = failed(FailureKind::Timeout);
        assert_eq!(
            first.configuration_digest().unwrap(),
            second.configuration_digest().unwrap()
        );
        second.load.concurrent_requests = 32;
        assert_ne!(
            first.configuration_digest().unwrap(),
            second.configuration_digest().unwrap()
        );
    }

    #[test]
    fn a_reasoning_attempt_records_its_trace_and_final_answer() {
        // The reasoning fixture family marks a reasoning test; its check is what the
        // FAST-05 reasoning gate needs: a trace, and a final answer matching the
        // fixture's answer key.
        let record = reasoning_record("op-reasoning", 300);
        record.validate().unwrap();
        let check = record.measurements.reasoning.value().unwrap();
        assert!(check.passed());
        // The answer key is one of the record's fixtures, for disclosure and BENCH-13.
        assert!(record
            .fixtures()
            .iter()
            .any(|fixture| fixture.id.as_str() == "gsm8k-style-answer-7"));
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["workload"]["value"]["family"], "reasoning");
        assert_eq!(
            serde_json::from_value::<RunRecord>(json.clone()).unwrap(),
            record
        );

        // A successful attempt needs a trace and a correct answer; anything else is an
        // invalid result, which stays in the raw data.
        let with_check = |trace: ReasoningTrace, final_answer: AnswerVerdict| {
            let mut changed = record.clone();
            if let Measured::Measured { value } = &mut changed.measurements.reasoning {
                value.trace = trace;
                value.final_answer = final_answer;
            }
            changed
        };
        let present = || ReasoningTrace::Present {
            tokens: Measured::measured(120),
        };
        for mut refused in [
            with_check(present(), AnswerVerdict::Incorrect),
            with_check(present(), AnswerVerdict::Missing),
            with_check(ReasoningTrace::Absent, AnswerVerdict::Correct),
        ] {
            assert_eq!(refused.validate(), Err(ReportError::ReasoningNotPassed));
            assert_eq!(
                RunRecord::from_json(&serde_json::to_string(&refused).unwrap()),
                Err(ReportError::ReasoningNotPassed)
            );
            refused.outcome = failed(FailureKind::InvalidResult);
            refused.validate().unwrap();
        }
        let mut unchecked = record.clone();
        unchecked.measurements.reasoning = Measured::not_measured(NotMeasuredReason::NotRecorded);
        assert_eq!(unchecked.validate(), Err(ReportError::ReasoningNotPassed));
        // A trace counted as present has at least one token.
        let empty_trace = with_check(
            ReasoningTrace::Present {
                tokens: Measured::measured(0),
            },
            AnswerVerdict::Correct,
        );
        assert_eq!(
            empty_trace.validate(),
            Err(ReportError::InconsistentMeasurement)
        );
        // A check belongs only to a reasoning workload.
        let mut misplaced = serving_record("op-chat", 120);
        misplaced.measurements.reasoning = record.measurements.reasoning.clone();
        assert_eq!(
            misplaced.validate(),
            Err(ReportError::ReasoningCheckMismatch)
        );
        // Its answer key still counts for disclosure, even without a workload.
        let mut orphan = misplaced.clone();
        orphan.workload = Measured::not_measured(NotMeasuredReason::NotApplicable);
        assert_eq!(orphan.fixtures(), vec![&check.answer_key]);

        // Neither the answer nor the trace can be recorded as text (S8 redaction).
        for pointer in [
            "/measurements/reasoning/value",
            "/measurements/reasoning/value/trace",
            "/measurements/reasoning/value/answer_key",
        ] {
            let mut tampered = json.clone();
            tampered
                .pointer_mut(pointer)
                .and_then(|value| value.as_object_mut())
                .unwrap()
                .insert("text".into(), "The answer is 42 because".into());
            assert!(
                serde_json::from_value::<RunRecord>(tampered).is_err(),
                "{pointer}"
            );
        }
        // A private answer key keeps the record out of public artifacts.
        let mut private = record.clone();
        if let Measured::Measured { value } = &mut private.measurements.reasoning {
            value.answer_key.disclosure = Disclosure::Private;
        }
        assert_eq!(
            private.check_publishable(),
            Err(ReportError::NotPublishable {
                fixture: label("gsm8k-style-answer-7")
            })
        );
    }

    #[test]
    fn publication_needs_publishable_fixtures() {
        let mut record = serving_record("op-1", 120);
        record.check_publishable().unwrap();
        if let Measured::Measured { value } = &mut record.workload {
            value.fixture.disclosure = Disclosure::Private;
        }
        assert_eq!(record.disclosure(), Disclosure::Private);
        assert_eq!(
            record.check_publishable(),
            Err(ReportError::NotPublishable {
                fixture: label("code-fixture-1")
            })
        );
    }

    #[test]
    fn helper_events_are_on_one_clock() {
        let built = events(
            "op-9",
            vec![
                (
                    0,
                    EventKind::VmCreateInitiated {
                        guest: ExecutionId::new("exe-1").unwrap(),
                        boot: SandboxBootGeneration::FIRST,
                    },
                ),
                (5, EventKind::VmApiAcknowledged),
            ],
        );
        assert!(built.iter().all(|event| event.clock == built[0].clock));
        assert!(built[1].at_nanos > MonotonicTime::ZERO);
    }
}
