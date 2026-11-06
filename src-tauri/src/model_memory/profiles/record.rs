//! FAST-05 evidence-bound serving profiles (S13 line 245; line 252).
//!
//! A validated profile holds the exact checkpoint and tokenizer, the image digest, the
//! launch, configuration and resource limits, the GPU and topology, the driver and
//! backend, the proof date, the workload, the raw report identity, the prerequisites and
//! the withdrawal state. It is the record format for the existing model catalog and
//! capability contract, not a second catalog service. Its proof is the CORE-08 raw
//! records of a Yougori measurement of exactly this profile, and the raw report identity,
//! the gates and the measured speed are derived from them. A changed image, model,
//! launcher, parser, hardware class or resource contract invalidates the proof. A profile
//! that fails reproducibly is withdrawn, and its evidence history is kept.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use super::drafting::{DraftMethod, DraftingMatrix};
use super::formats::{check_kv_qualification, kv_fidelity, KvFormatQualification, KvFormatRefusal};
use super::guard::admit_technique;
use super::selection::RequestMix;
use super::settings::{EngineRef, HardwareClass, ServingSettings, SettingsError};
use crate::foundation::evidence::{AdmittedRuntime, BackendRelease};
use crate::foundation::ids::{Digest, DigestBuilder, ExecutionCategory, OperationId};
use crate::foundation::report::{
    AttemptRole, ClockReading, FixtureFamily, IntervalKind, Provenance, ReportError, RunRecord,
    Scenario,
};
use crate::model_memory::backends::{BackendRuntime, ExperimentApproval, TechniqueRefusal};
use crate::model_memory::identity::{
    ExecutionIdentity, ExecutionSpec, FidelityCategory, FidelityRefusal, IdentityError,
    KvRepresentation, LogicalModelIdentity, LogicalModelSpec, SourceIdentity,
};

const RECORD_DOMAIN: &str = "yougori/model_memory/profiles/record/v2";
const WORKLOAD_DOMAIN: &str = "yougori/model_memory/profiles/workload/v1";

/// Distinct failure reports after which a profile is reproducibly failing and withdrawn
/// (FAST-05): a failure and its reproduction.
pub const REPRODUCED_FAILURE_REPORTS: usize = 2;

/// Identity of one validated profile: a digest of everything it binds and proves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProfileId(Digest);

impl ProfileId {
    pub const fn digest(self) -> Digest {
        self.0
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// The resources a profile was proven under (FAST-05 "resource limits", "resource
/// contract").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceContract {
    pub gpu_memory_bytes_per_device: u64,
    pub host_memory_bytes: u64,
    pub pinned_host_bytes: u64,
    pub cpu_millicores: u32,
}

/// The parsers tool calls and reasoning output go through (FAST-05 "parser").
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Parsers {
    pub tool_call: Option<String>,
    pub reasoning: Option<String>,
}

/// The exact model a profile serves, through the identity layers of GPU §3.2 (T07;
/// FAST-05 "exact checkpoint/tokenizer"). The source is the checkpoint; the logical model
/// adds dtype and quantization, tokenizer and generation configuration; the execution
/// adds runner and version, kernel layout, GPU architectures, rank topology and compile
/// configuration. Built only from consistent specs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelBinding {
    logical: LogicalModelSpec,
    execution: ExecutionSpec,
    logical_identity: LogicalModelIdentity,
    execution_identity: ExecutionIdentity,
}

impl ModelBinding {
    /// Binds `execution` to `logical`; refused when the execution is for another logical
    /// model or has no identity.
    pub fn new(
        logical: LogicalModelSpec,
        execution: ExecutionSpec,
    ) -> Result<Self, ModelBindingError> {
        let logical_identity = logical.identity();
        if execution.logical != logical_identity {
            return Err(ModelBindingError::ExecutionForOtherModel);
        }
        let execution_identity = execution
            .identity()
            .map_err(|error| ModelBindingError::Execution { error })?;
        Ok(Self {
            logical,
            execution,
            logical_identity,
            execution_identity,
        })
    }

    /// The checkpoint.
    pub fn source(&self) -> SourceIdentity {
        self.logical.source
    }

    pub fn logical(&self) -> LogicalModelIdentity {
        self.logical_identity
    }

    pub fn execution(&self) -> ExecutionIdentity {
        self.execution_identity
    }

    pub fn logical_spec(&self) -> &LogicalModelSpec {
        &self.logical
    }

    pub fn execution_spec(&self) -> &ExecutionSpec {
        &self.execution
    }
}

/// Why a model binding was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModelBindingError {
    /// The execution spec names another logical model.
    ExecutionForOtherModel,
    Execution {
        error: IdentityError,
    },
}

/// Everything whose change invalidates a profile's proof (FAST-05).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileBinding {
    pub model: ModelBinding,
    /// Backend release and image digest.
    pub engine: EngineRef,
    /// Identity of the launcher: the runner adapter and the launch arguments it writes.
    pub launcher: Digest,
    pub parsers: Parsers,
    pub hardware: HardwareClass,
    pub driver: String,
    pub resources: ResourceContract,
}

impl ProfileBinding {
    /// What changed from this binding to `current`; empty when the proof still applies.
    pub fn invalidations(&self, current: &Self) -> Vec<Invalidation> {
        [
            (
                self.model.source() != current.model.source(),
                Invalidation::Source,
            ),
            (
                self.model.logical() != current.model.logical(),
                Invalidation::LogicalModel,
            ),
            (
                self.model.execution() != current.model.execution(),
                Invalidation::Execution,
            ),
            (
                self.engine.image != current.engine.image,
                Invalidation::Image,
            ),
            (
                self.engine.release != current.engine.release,
                Invalidation::Backend,
            ),
            (self.launcher != current.launcher, Invalidation::Launcher),
            (self.parsers != current.parsers, Invalidation::Parser),
            (
                self.hardware.identity() != current.hardware.identity(),
                Invalidation::HardwareClass,
            ),
            (self.driver != current.driver, Invalidation::Driver),
            (
                self.resources != current.resources,
                Invalidation::ResourceContract,
            ),
        ]
        .into_iter()
        .filter_map(|(changed, invalidation)| changed.then_some(invalidation))
        .collect()
    }

    fn feed(&self, builder: DigestBuilder) -> DigestBuilder {
        let builder = builder
            .digest(self.model.source().digest())
            .digest(self.model.logical().digest())
            .digest(self.model.execution().digest());
        let builder = self.engine.feed(builder).digest(&self.launcher);
        let builder = feed_optional(builder, self.parsers.tool_call.as_deref());
        feed_optional(builder, self.parsers.reasoning.as_deref())
            .digest(&self.hardware.identity())
            .str(&self.driver)
            .u64(self.resources.gpu_memory_bytes_per_device)
            .u64(self.resources.host_memory_bytes)
            .u64(self.resources.pinned_host_bytes)
            .u64(u64::from(self.resources.cpu_millicores))
    }
}

/// A change that invalidates a profile's proof (FAST-05: a changed image, model,
/// launcher, parser, hardware class or resource contract; also the driver and backend
/// the record holds). A model change shows in every identity layer built on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Invalidation {
    /// The checkpoint (T07 source identity).
    Source,
    /// Dtype or quantization, tokenizer, generation configuration, adapters or code
    /// policy (T07 logical model identity).
    LogicalModel,
    /// Runner, kernel layout, GPU architectures, rank topology, processed weights or
    /// compile configuration (T07 execution identity).
    Execution,
    Image,
    Backend,
    Launcher,
    Parser,
    HardwareClass,
    Driver,
    ResourceContract,
}

strict_tagged_enum! {
/// The outcome of one gate, with the CORE-08 raw report it rests on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateResult (tag = "gate", wire = GateResultWire, wire_name = "GateResultWire") {
    Passed { report: Digest },
    Failed { report: Digest },
    /// The profile does not offer this capability, and says so.
    NotApplicable,
    /// Not measured, which never passes.
    NotMeasured,
}
}

impl GateResult {
    const fn passed(self) -> bool {
        matches!(self, Self::Passed { .. })
    }

    fn feed(self, builder: DigestBuilder) -> DigestBuilder {
        match self {
            Self::Passed { report } => builder.str("passed").digest(&report),
            Self::Failed { report } => builder.str("failed").digest(&report),
            Self::NotApplicable => builder.str("not_applicable"),
            Self::NotMeasured => builder.str("not_measured"),
        }
    }
}

/// The gates FAST-05 names besides the workload's own: load, chat, reasoning, tools and
/// context. Derived from the proof, never written by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ProfileGates {
    pub load: GateResult,
    pub chat: GateResult,
    pub reasoning: GateResult,
    pub tools: GateResult,
    pub context: GateResult,
}

/// Which gate refused a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateName {
    Load,
    Chat,
    Reasoning,
    Tools,
    Context,
    WorkloadQuality,
}

/// The workload a profile was proven on and its own speed and quality gate, derived from
/// the proof's serving attempts (FAST-05: workload-specific speed/quality; a fixed 15
/// tok/s floor is not a universal rule).
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct WorkloadGate {
    /// Identity of the workload: the fixtures and load of every initial serving attempt.
    pub workload: Digest,
    /// The most concurrent requests an initial serving attempt ran with.
    pub concurrent_requests: u32,
    /// The per-user speed this workload declares it needs.
    pub minimum_per_user_tokens_per_second: f64,
    /// The slowest per-user decode speed of a successful initial serving attempt; `None`
    /// when there was none or one was not measured, which never passes.
    pub measured_per_user_tokens_per_second: Option<f64>,
    /// Passed when every initial serving attempt succeeded.
    pub quality: GateResult,
}

strict_tagged_enum! {
/// Where a profile was qualified (S13 line 252: only on an authorized disposable GPU
/// machine or provider allocation, keeping the owner's active services untouched).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QualificationHost (tag = "host", wire = QualificationHostWire, wire_name = "QualificationHostWire") {
    DisposableMachine { authorization: Digest },
    ProviderAllocation { authorization: Digest },
    /// The owner's own machine with its active services; never qualifies a profile.
    OwnerMachine,
}
}

strict_tagged_enum! {
/// The cleanup after a qualification run (S13 line 252: record its cleanup).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cleanup (tag = "cleanup", wire = CleanupWire, wire_name = "CleanupWire") {
    Completed { report: Digest },
    Incomplete { report: Digest },
    NotRecorded,
}
}

/// The qualification run behind a profile, with the execution category it actually ran
/// in (S13 line 252).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Qualification {
    pub host: QualificationHost,
    pub execution_category: ExecutionCategory,
    pub cleanup: Cleanup,
}

strict_tagged_enum! {
/// A license or trust review of imported recipe data (FAST-05).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Review (tag = "review", wire = ReviewWire, wire_name = "ReviewWire") {
    Approved { report: Digest },
    Pending,
    Rejected { report: Digest },
}
}

strict_tagged_enum! {
/// Where a profile's recipe came from (FAST-05: an external catalog import needs license
/// and trust review).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin (tag = "origin", wire = OriginWire, wire_name = "OriginWire") {
    /// Written and qualified here.
    Qualified,
    Imported { source: String, license: Review, trust: Review },
}
}

strict_tagged_enum! {
/// A condition a profile needs before it can run; checked, never applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prerequisite (tag = "prerequisite", wire = PrerequisiteWire, wire_name = "PrerequisiteWire") {
    /// Peer copies between every pair of GPUs were measured to work.
    PeerAccessVerified,
    PinnedHostMemory { bytes: u64 },
    ManagedDiskSpace { bytes: u64 },
}
}

impl Prerequisite {
    pub fn met_by(&self, facts: &PrerequisiteFacts) -> bool {
        match self {
            Self::PeerAccessVerified => facts.peer_access_verified,
            Self::PinnedHostMemory { bytes } => facts.pinned_host_bytes >= *bytes,
            Self::ManagedDiskSpace { bytes } => facts.managed_disk_bytes >= *bytes,
        }
    }

    fn feed(&self, builder: DigestBuilder) -> DigestBuilder {
        match self {
            Self::PeerAccessVerified => builder.str("peer_access_verified"),
            Self::PinnedHostMemory { bytes } => builder.str("pinned_host_memory").u64(*bytes),
            Self::ManagedDiskSpace { bytes } => builder.str("managed_disk_space").u64(*bytes),
        }
    }
}

/// What is currently available, established elsewhere by evidence and reservations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrerequisiteFacts {
    pub peer_access_verified: bool,
    pub pinned_host_bytes: u64,
    pub managed_disk_bytes: u64,
}

/// The CORE-08 raw records of the run that qualified a profile (FAST-05 "raw report
/// identity"). Only a Yougori measurement qualifies: every record ran in an authorized
/// disposable environment, so a run on the fake time-controlled substrate is refused (S12
/// G0; the T02 follow-up), and so is a proof without records. Built only by
/// [`ProfileProof::new`].
#[derive(Clone, Debug, PartialEq)]
pub struct ProfileProof {
    records: Vec<RunRecord>,
    evidence: Digest,
}

impl ProfileProof {
    /// Accepts `records` when each is a valid raw record (S8), no attempt is recorded
    /// twice, each retry follows an initial attempt of the proof that has not succeeded,
    /// and their provenance is a Yougori measurement.
    pub fn new(records: Vec<RunRecord>) -> Result<Self, ReportError> {
        let mut recorded: BTreeMap<&OperationId, &RunRecord> = BTreeMap::new();
        let mut succeeded: BTreeSet<&OperationId> = BTreeSet::new();
        for record in &records {
            record.validate()?;
            let chain = match &record.attempt.role {
                AttemptRole::Initial => &record.attempt.operation,
                AttemptRole::Retry { first_attempt, .. } => {
                    let first = recorded
                        .get(first_attempt)
                        .ok_or(ReportError::UnknownFirstAttempt)?;
                    if !first.is_initial() {
                        return Err(ReportError::RetryOfRetry);
                    }
                    if succeeded.contains(first_attempt) {
                        return Err(ReportError::RetryAfterSuccess);
                    }
                    first_attempt
                }
            };
            if recorded.insert(&record.attempt.operation, record).is_some() {
                return Err(ReportError::DuplicateAttempt);
            }
            if record.is_success() {
                succeeded.insert(chain);
            }
        }
        let evidence = Provenance::of_records(&records)?.yougori_evidence()?;
        Ok(Self { records, evidence })
    }

    /// The raw report identity: the CORE-08 evidence digest of every record.
    pub fn evidence(&self) -> Digest {
        self.evidence
    }

    pub fn records(&self) -> &[RunRecord] {
        &self.records
    }

    /// Initial attempts only: a retry is a result of its own and never rewrites a failed
    /// first attempt (S8).
    fn initial_attempts(&self) -> impl Iterator<Item = &RunRecord> + '_ {
        self.records.iter().filter(|record| record.is_initial())
    }
}

/// What a profile offers besides loading and serving its context, each of which then
/// needs its gate to pass (FAST-05: gate load, chat, reasoning, tools and context). A
/// capability that is not offered must have no attempts in the proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferedCapabilities {
    pub chat: bool,
    pub reasoning: bool,
    pub tools: bool,
}

/// What every record of a proof must share, measured, with the profile it backs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofField {
    /// The execution category the qualification ran in.
    ExecutionCategory,
    /// The engine image digest.
    Image,
    /// The backend name and release.
    Engine,
    Driver,
    /// The hardware class's GPU count and memory per GPU.
    Gpus,
    /// The logical model's tokenizer digest.
    Tokenizer,
    /// The settings' KV cache dtype, by its T07 tag.
    KvCacheDtype,
}

/// A profile as submitted for validation.
#[derive(Clone, Debug, PartialEq)]
pub struct ProfileDraft {
    pub binding: ProfileBinding,
    /// Launch and configuration.
    pub settings: ServingSettings,
    pub qualification: Qualification,
    pub proof_date: NaiveDate,
    /// The qualification run's raw records. The raw report identity, every gate and the
    /// measured speed are derived from them.
    pub proof: ProfileProof,
    /// What the profile offers besides loading and its context.
    pub offers: OfferedCapabilities,
    /// The per-user decode speed the workload declares it needs.
    pub minimum_per_user_tokens_per_second: f64,
    pub prerequisites: Vec<Prerequisite>,
    pub origin: Origin,
}

/// Qualifications a draft's settings are checked against.
#[derive(Clone, Copy, Debug)]
pub struct Qualifications<'a> {
    /// Line 248 checks for a lossy KV format.
    pub kv_formats: &'a [KvFormatQualification],
    /// The pinned FAST-04 matrix for a drafting setting.
    pub drafting: &'a DraftingMatrix,
}

/// Whether a profile can still be selected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProfileState {
    Active,
    /// Withdrawn after these failure reports; never selected again.
    Withdrawn {
        reports: Vec<Digest>,
    },
}

/// A kind of failure a profile was reported for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Startup,
    Capacity,
    ToolSemantics,
    Security,
    Quality,
    Speed,
}

/// One entry of a profile's evidence history; entries are only ever appended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "entry", rename_all = "snake_case")]
pub enum HistoryEntry {
    Validated {
        proof_date: NaiveDate,
        raw_report: Digest,
    },
    FailureReported {
        report: Digest,
        kind: FailureKind,
    },
    Withdrawn {
        reports: Vec<Digest>,
    },
}

/// The user-facing capability record of a profile (line 250: bit-identical modes are
/// kept apart from lossy capacity modes, as T07's lossless-representation and
/// approximate-inference categories).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileCapabilities {
    pub kv_cache: KvRepresentation,
    pub fidelity: FidelityCategory,
    pub context_tokens: u32,
    pub max_num_seqs: u32,
    pub chat: bool,
    pub reasoning: bool,
    pub tool_calls: bool,
    pub drafting: Option<DraftMethod>,
}

/// Why a draft was not validated.
#[derive(Clone, Debug, PartialEq)]
pub enum RecordRefusal {
    Settings {
        error: SettingsError,
    },
    TensorParallelNotHardware {
        tensor_parallel_size: u32,
        gpu_count: u32,
    },
    /// The execution identity's runner is not the bound engine's release.
    RunnerNotEngine,
    /// The execution identity's rank topology is not the settings' tensor-parallel size.
    RankTopologyNotSettings {
        rank_topology: u32,
        tensor_parallel_size: u32,
    },
    /// The NCCL choice was made from another topology than the hardware class's.
    NcclForOtherTopology,
    /// Profiles are never qualified on the owner's active machine (S13 line 252).
    OwnerMachine,
    /// The qualification's cleanup is not recorded as completed.
    CleanupNotCompleted {
        cleanup: Cleanup,
    },
    /// Imported recipe data without approved license and trust reviews.
    ImportNotReviewed,
    /// The proof could not be read as CORE-08 evidence. Boxed to keep the refusal small.
    Proof {
        error: Box<ReportError>,
    },
    /// A proof record is about another profile, or does not measure what the profile
    /// binds.
    ProofNotAboutProfile {
        operation: OperationId,
        field: ProofField,
    },
    GateNotPassed {
        gate: GateName,
        result: GateResult,
    },
    /// A capability the profile does not offer has attempts in the proof.
    NotOfferedButMeasured {
        gate: GateName,
    },
    /// Tools are offered without a tool-call parser.
    ToolsWithoutParser,
    /// A tool-call parser is configured and tools are not offered.
    ParserWithoutToolGate,
    /// Reasoning is offered without a reasoning parser to separate its trace.
    ReasoningWithoutParser,
    /// A reasoning parser is configured and reasoning is not offered.
    ParserWithoutReasoningGate,
    /// The workload's declared minimum is negative or not a number.
    WorkloadThresholdInvalid,
    WorkloadNotMeasured,
    /// No serving attempt ran with as many concurrent requests as the profile allows, so
    /// its per-user speed at that concurrency is unproven.
    ConcurrencyNotMeasured {
        max_num_seqs: u32,
        measured: u32,
    },
    WorkloadBelowDeclaredMinimum {
        measured_per_user_tokens_per_second: f64,
        minimum_per_user_tokens_per_second: f64,
    },
    /// A lossy KV representation without its line 248 qualification.
    KvFormat {
        refusal: KvFormatRefusal,
    },
    /// Drafting outside the pinned FAST-04 matrix.
    DraftingNotPinned,
}

impl fmt::Display for RecordRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Settings { error } => write!(f, "{error}"),
            Self::TensorParallelNotHardware {
                tensor_parallel_size,
                gpu_count,
            } => write!(
                f,
                "the profile uses {tensor_parallel_size} GPUs and its hardware class has \
                 {gpu_count}"
            ),
            Self::RunnerNotEngine => f.write_str(
                "the execution identity was built for another runner than the bound engine",
            ),
            Self::RankTopologyNotSettings {
                rank_topology,
                tensor_parallel_size,
            } => write!(
                f,
                "the execution identity has {rank_topology} tensor-parallel ranks and the \
                 settings {tensor_parallel_size}"
            ),
            Self::NcclForOtherTopology => {
                f.write_str("the NCCL choice was made from another peer topology")
            }
            Self::OwnerMachine => f.write_str(
                "profiles are qualified only on an authorized disposable machine or provider \
                 allocation, never on the owner's active machine",
            ),
            Self::CleanupNotCompleted { .. } => {
                f.write_str("the qualification run's cleanup is not recorded as completed")
            }
            Self::ImportNotReviewed => {
                f.write_str("imported recipe data needs approved license and trust reviews first")
            }
            Self::Proof { error } => {
                write!(f, "the proof is not usable CORE-08 evidence: {error}")
            }
            Self::ProofNotAboutProfile { operation, field } => write!(
                f,
                "the proof's attempt {operation} does not measure this profile's {field:?}; a \
                 proof backs only the profile it ran"
            ),
            Self::GateNotPassed { gate, result } => {
                write!(f, "the {gate:?} gate did not pass: {result:?}")
            }
            Self::NotOfferedButMeasured { gate } => write!(
                f,
                "the profile does not offer {gate:?}, and its proof has attempts for it"
            ),
            Self::ToolsWithoutParser => {
                f.write_str("tool calls are offered without a tool-call parser to bind them to")
            }
            Self::ParserWithoutToolGate => {
                f.write_str("a tool-call parser is configured but tool calls are not offered")
            }
            Self::ReasoningWithoutParser => {
                f.write_str("reasoning is offered without a reasoning parser to separate its trace")
            }
            Self::ParserWithoutReasoningGate => {
                f.write_str("a reasoning parser is configured but reasoning is not offered")
            }
            Self::WorkloadThresholdInvalid => {
                f.write_str("the workload's declared minimum speed is not a valid number")
            }
            Self::WorkloadNotMeasured => f.write_str("the workload's speed was not measured"),
            Self::ConcurrencyNotMeasured {
                max_num_seqs,
                measured,
            } => write!(
                f,
                "the profile serves {max_num_seqs} sequences at once and its proof ran at most \
                 {measured} concurrent requests"
            ),
            Self::WorkloadBelowDeclaredMinimum {
                measured_per_user_tokens_per_second,
                minimum_per_user_tokens_per_second,
            } => write!(
                f,
                "the workload measured {measured_per_user_tokens_per_second} tokens/s per user, \
                 below its declared {minimum_per_user_tokens_per_second}"
            ),
            Self::KvFormat { refusal } => write!(f, "{refusal}"),
            Self::DraftingNotPinned => {
                f.write_str("drafting is outside the pinned engine, model and method matrix")
            }
        }
    }
}

impl std::error::Error for RecordRefusal {}

/// Why a profile cannot serve a request now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unusable {
    Withdrawn,
    Invalidated {
        changes: Vec<Invalidation>,
    },
    /// Proven in another execution category than the admitted runtime's; a profile never
    /// carries a category across (S13 line 252).
    OtherCategory {
        recorded: ExecutionCategory,
        current: ExecutionCategory,
    },
    /// The admitted runtime runs another backend release than the binding in force.
    RuntimeForOtherEngine {
        runtime: BackendRelease,
        engine: BackendRelease,
    },
    /// The backend runtime is not the admitted runtime.
    BackendForOtherRuntime,
    /// The profile's graph mode or concurrency needs a backend technique the gate did not
    /// admit for this runtime (GPU part §3.8).
    TechniqueNotAdmitted {
        refusal: TechniqueRefusal,
    },
    ContextTooShort {
        context_tokens: u32,
        needed_tokens: u32,
    },
    TooFewSequences {
        max_num_seqs: u32,
        needed: u32,
    },
    NoToolCalls,
    /// The request's fidelity configuration does not allow the profile's KV
    /// representation (T07, §1.3).
    Fidelity {
        refusal: FidelityRefusal,
    },
    PrerequisiteUnmet {
        prerequisite: Prerequisite,
    },
}

/// What a profile must meet to serve a request now.
#[derive(Clone, Copy, Debug)]
pub struct ProfileNeeds<'a> {
    /// The binding in force now.
    pub current: &'a ProfileBinding,
    /// The runtime the request admitted on CORE-01 evidence of its category (INT-07).
    pub runtime: &'a AdmittedRuntime,
    /// The same runtime as the backend gate knows it (GPU part §3.8).
    pub backend: &'a BackendRuntime,
    /// Approved later experiments, each for one exact release.
    pub approvals: &'a [ExperimentApproval],
    pub mix: &'a RequestMix,
    pub facts: &'a PrerequisiteFacts,
}

/// A publication authorization; validation alone never publishes (FAST-05: publication
/// needs separate authorization).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationAuthorization {
    pub authorization: Digest,
}

/// Why a profile cannot be published.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationRefusal {
    NotAuthorized,
    Withdrawn,
}

/// A validated FAST-05 profile. Only [`ServingProfileRecord::validate`] makes one; the
/// state changes only by withdrawal, and history only grows.
#[derive(Clone, Debug, PartialEq)]
pub struct ServingProfileRecord {
    id: ProfileId,
    draft: ProfileDraft,
    gates: ProfileGates,
    workload: WorkloadGate,
    state: ProfileState,
    history: Vec<HistoryEntry>,
}

impl ServingProfileRecord {
    /// Validates `draft` as a profile.
    ///
    /// The settings must run on the hardware class and match the execution identity's
    /// runner and rank topology; the qualification must have run on an authorized
    /// disposable machine or provider allocation with its cleanup completed; imported
    /// recipe data needs approved license and trust reviews. Every proof record must
    /// measure this profile's execution category, image, engine release, driver, GPUs,
    /// tokenizer and KV dtype. The gates come from the proof: load and context must pass,
    /// and so must each offered capability, while one not offered has no attempts; tools
    /// are offered exactly when a tool-call parser is configured, and reasoning exactly
    /// when a reasoning parser is. The workload's slowest per-user speed, measured at the
    /// profile's concurrency, must reach its declared minimum, and every serving attempt
    /// must have succeeded. A lossy KV format needs its line 248 qualification and
    /// drafting its pinned matrix row.
    pub fn validate(
        draft: ProfileDraft,
        qualifications: Qualifications<'_>,
    ) -> Result<Self, RecordRefusal> {
        check_settings(&draft, qualifications)?;
        check_qualification(&draft)?;
        check_proof_binding(&draft)?;
        let gates = derive_gates(&draft)?;
        let workload = derive_workload(&draft)?;
        check_workload(&workload, draft.settings.max_num_seqs)?;
        let id = ProfileId(
            feed_record(&draft, &gates, &workload, DigestBuilder::new(RECORD_DOMAIN)).finish(),
        );
        let history = vec![HistoryEntry::Validated {
            proof_date: draft.proof_date,
            raw_report: draft.proof.evidence(),
        }];
        Ok(Self {
            id,
            draft,
            gates,
            workload,
            state: ProfileState::Active,
            history,
        })
    }

    pub fn id(&self) -> ProfileId {
        self.id
    }

    pub fn binding(&self) -> &ProfileBinding {
        &self.draft.binding
    }

    pub fn settings(&self) -> &ServingSettings {
        &self.draft.settings
    }

    pub fn qualification(&self) -> &Qualification {
        &self.draft.qualification
    }

    /// The category the profile was proven in.
    pub fn execution_category(&self) -> ExecutionCategory {
        self.draft.qualification.execution_category
    }

    pub fn proof_date(&self) -> NaiveDate {
        self.draft.proof_date
    }

    /// The raw report identity: the CORE-08 evidence digest of the proof.
    pub fn raw_report(&self) -> Digest {
        self.draft.proof.evidence()
    }

    pub fn proof(&self) -> &ProfileProof {
        &self.draft.proof
    }

    pub fn offers(&self) -> OfferedCapabilities {
        self.draft.offers
    }

    /// The gates, as derived from the proof.
    pub fn gates(&self) -> &ProfileGates {
        &self.gates
    }

    /// The workload and its speed and quality, as derived from the proof.
    pub fn workload(&self) -> &WorkloadGate {
        &self.workload
    }

    pub fn prerequisites(&self) -> &[Prerequisite] {
        &self.draft.prerequisites
    }

    pub fn origin(&self) -> &Origin {
        &self.draft.origin
    }

    pub fn state(&self) -> &ProfileState {
        &self.state
    }

    pub fn is_withdrawn(&self) -> bool {
        matches!(self.state, ProfileState::Withdrawn { .. })
    }

    /// The evidence history, oldest first.
    pub fn history(&self) -> &[HistoryEntry] {
        &self.history
    }

    pub fn capabilities(&self) -> ProfileCapabilities {
        let settings = &self.draft.settings;
        let gates = &self.gates;
        ProfileCapabilities {
            kv_cache: settings.kv_cache.clone(),
            fidelity: kv_fidelity(self.draft.binding.model.logical_spec(), &settings.kv_cache),
            context_tokens: settings.context_tokens,
            max_num_seqs: settings.max_num_seqs,
            chat: gates.chat.passed(),
            reasoning: gates.reasoning.passed(),
            tool_calls: gates.tools.passed(),
            drafting: settings.drafting.as_ref().map(|drafting| drafting.method),
        }
    }

    /// What changed since the proof; empty when it still applies.
    pub fn invalidations(&self, current: &ProfileBinding) -> Vec<Invalidation> {
        self.draft.binding.invalidations(current)
    }

    /// Whether the profile can serve `needs` now: not withdrawn, its proof still valid,
    /// proven in the category of the admitted runtime, which runs the bound engine and is
    /// the backend gate's runtime, with every technique its settings need admitted by that
    /// gate, meeting the request mix without less context, fewer sequences or missing
    /// tools, with a KV representation the request's fidelity configuration allows, and
    /// with every prerequisite met.
    pub fn usable_for(&self, needs: &ProfileNeeds<'_>) -> Result<(), Unusable> {
        if self.is_withdrawn() {
            return Err(Unusable::Withdrawn);
        }
        let changes = self.invalidations(needs.current);
        if !changes.is_empty() {
            return Err(Unusable::Invalidated { changes });
        }
        let recorded = self.execution_category();
        let current = needs.runtime.category();
        if recorded != current {
            return Err(Unusable::OtherCategory { recorded, current });
        }
        let runtime = &needs.runtime.runtime().release;
        if *runtime != needs.current.engine.release {
            return Err(Unusable::RuntimeForOtherEngine {
                runtime: runtime.clone(),
                engine: needs.current.engine.release.clone(),
            });
        }
        if needs.backend.plan().runtime() != needs.runtime.runtime() {
            return Err(Unusable::BackendForOtherRuntime);
        }
        for technique in self.draft.settings.techniques() {
            admit_technique(needs.backend, technique, needs.approvals)
                .map_err(|refusal| Unusable::TechniqueNotAdmitted { refusal })?;
        }
        let capabilities = self.capabilities();
        if capabilities.context_tokens < needs.mix.max_request_tokens {
            return Err(Unusable::ContextTooShort {
                context_tokens: capabilities.context_tokens,
                needed_tokens: needs.mix.max_request_tokens,
            });
        }
        if capabilities.max_num_seqs < needs.mix.concurrent_sequences {
            return Err(Unusable::TooFewSequences {
                max_num_seqs: capabilities.max_num_seqs,
                needed: needs.mix.concurrent_sequences,
            });
        }
        if needs.mix.tool_calls && !capabilities.tool_calls {
            return Err(Unusable::NoToolCalls);
        }
        needs
            .mix
            .fidelity
            .check_kv_representation(
                self.draft.binding.model.logical_spec(),
                &self.draft.settings.kv_cache,
            )
            .map_err(|refusal| Unusable::Fidelity { refusal })?;
        if let Some(prerequisite) = self
            .draft
            .prerequisites
            .iter()
            .find(|prerequisite| !prerequisite.met_by(needs.facts))
        {
            return Err(Unusable::PrerequisiteUnmet {
                prerequisite: *prerequisite,
            });
        }
        Ok(())
    }

    /// Publication needs its own authorization and a profile that is not withdrawn.
    pub fn check_publication(
        &self,
        authorization: Option<&PublicationAuthorization>,
    ) -> Result<(), PublicationRefusal> {
        if self.is_withdrawn() {
            return Err(PublicationRefusal::Withdrawn);
        }
        authorization
            .map(|_| ())
            .ok_or(PublicationRefusal::NotAuthorized)
    }

    /// Appends a failure report; the second distinct report withdraws the profile. A
    /// report already recorded changes nothing.
    fn record_failure(&mut self, report: Digest, kind: FailureKind) {
        let mut reports: BTreeSet<Digest> = self.failure_reports().collect();
        if !reports.insert(report) {
            return;
        }
        self.history
            .push(HistoryEntry::FailureReported { report, kind });
        if !self.is_withdrawn() && reports.len() >= REPRODUCED_FAILURE_REPORTS {
            let reports: Vec<Digest> = self.failure_reports().collect();
            self.history.push(HistoryEntry::Withdrawn {
                reports: reports.clone(),
            });
            self.state = ProfileState::Withdrawn { reports };
        }
    }

    fn failure_reports(&self) -> impl Iterator<Item = Digest> + '_ {
        self.history.iter().filter_map(|entry| match entry {
            HistoryEntry::FailureReported { report, .. } => Some(*report),
            HistoryEntry::Validated { .. } | HistoryEntry::Withdrawn { .. } => None,
        })
    }
}

fn check_settings(
    draft: &ProfileDraft,
    qualifications: Qualifications<'_>,
) -> Result<(), RecordRefusal> {
    let settings = &draft.settings;
    let binding = &draft.binding;
    settings
        .check()
        .map_err(|error| RecordRefusal::Settings { error })?;
    if settings.tensor_parallel_size != binding.hardware.gpu_count {
        return Err(RecordRefusal::TensorParallelNotHardware {
            tensor_parallel_size: settings.tensor_parallel_size,
            gpu_count: binding.hardware.gpu_count,
        });
    }
    // The choice carries the measured topology it was made from, so this compares the
    // topology itself, by identity, with the hardware class's.
    if settings
        .nccl
        .as_ref()
        .is_some_and(|choice| choice.topology().identity() != binding.hardware.topology)
    {
        return Err(RecordRefusal::NcclForOtherTopology);
    }
    let execution = binding.model.execution_spec();
    if execution.runner.name.as_str() != binding.engine.release.backend.tag()
        || execution.runner.version.as_str() != binding.engine.release.version.as_str()
    {
        return Err(RecordRefusal::RunnerNotEngine);
    }
    let rank_topology = execution.topology.tensor_parallel_size();
    if rank_topology != settings.tensor_parallel_size {
        return Err(RecordRefusal::RankTopologyNotSettings {
            rank_topology,
            tensor_parallel_size: settings.tensor_parallel_size,
        });
    }
    if kv_fidelity(binding.model.logical_spec(), &settings.kv_cache)
        != FidelityCategory::LosslessRepresentation
    {
        check_kv_qualification(
            &binding.model.logical(),
            &binding.engine,
            &settings.kv_cache,
            qualifications.kv_formats,
        )
        .map_err(|refusal| RecordRefusal::KvFormat { refusal })?;
    }
    if let Some(drafting) = &settings.drafting {
        let pinned = qualifications
            .drafting
            .row(
                &binding.engine,
                &binding.model.logical(),
                drafting.method,
                drafting.drafter.as_ref(),
            )
            .is_some_and(|row| drafting.speculative_tokens <= row.max_speculative_tokens);
        if !pinned {
            return Err(RecordRefusal::DraftingNotPinned);
        }
    }
    Ok(())
}

fn check_qualification(draft: &ProfileDraft) -> Result<(), RecordRefusal> {
    if draft.qualification.host == QualificationHost::OwnerMachine {
        return Err(RecordRefusal::OwnerMachine);
    }
    if !matches!(draft.qualification.cleanup, Cleanup::Completed { .. }) {
        return Err(RecordRefusal::CleanupNotCompleted {
            cleanup: draft.qualification.cleanup,
        });
    }
    if let Origin::Imported { license, trust, .. } = &draft.origin {
        let approved = |review: &Review| matches!(review, Review::Approved { .. });
        if !approved(license) || !approved(trust) {
            return Err(RecordRefusal::ImportNotReviewed);
        }
    }
    Ok(())
}

fn proof_error(error: ReportError) -> RecordRefusal {
    RecordRefusal::Proof {
        error: Box::new(error),
    }
}

/// Every proof record must measure what this profile binds: its execution category,
/// image, backend release, driver, GPU count and memory, tokenizer and KV dtype. Card
/// names are not compared: CORE-08 labels them in its own vocabulary.
fn check_proof_binding(draft: &ProfileDraft) -> Result<(), RecordRefusal> {
    let binding = &draft.binding;
    let release = &binding.engine.release;
    let hardware = &binding.hardware;
    let tokenizer = &binding.model.logical_spec().tokenizer;
    let kv_dtype = draft.settings.kv_cache.dtype().tag();
    for record in draft.proof.records() {
        let checks = [
            (
                ProofField::ExecutionCategory,
                record.execution_category == draft.qualification.execution_category,
            ),
            (
                ProofField::Image,
                record.launch.image == binding.engine.image,
            ),
            (
                ProofField::Engine,
                record.engine.value().is_some_and(|engine| {
                    engine.name.as_str() == release.backend.tag()
                        && engine.version.as_str() == release.version.as_str()
                }),
            ),
            (
                ProofField::Driver,
                record
                    .host
                    .gpu_driver
                    .value()
                    .is_some_and(|driver| driver.as_str() == binding.driver),
            ),
            (
                ProofField::Gpus,
                record.host.gpus.value().is_some_and(|gpus| {
                    usize::try_from(hardware.gpu_count).is_ok_and(|count| count == gpus.len())
                        && gpus
                            .iter()
                            .all(|gpu| gpu.memory_bytes == hardware.memory_bytes_per_gpu)
                }),
            ),
            (
                ProofField::Tokenizer,
                record
                    .model
                    .value()
                    .is_some_and(|model| model.tokenizer == *tokenizer),
            ),
            (
                ProofField::KvCacheDtype,
                record
                    .precision
                    .value()
                    .is_some_and(|precision| precision.kv_cache_dtype.as_str() == kv_dtype),
            ),
        ];
        if let Some((field, _)) = checks.into_iter().find(|(_, measured)| !measured) {
            return Err(RecordRefusal::ProofNotAboutProfile {
                operation: record.attempt.operation.clone(),
                field,
            });
        }
    }
    Ok(())
}

/// The fixture family of a serving attempt.
fn serving_family(record: &RunRecord) -> Option<FixtureFamily> {
    if record.scenario == Scenario::Serving {
        record.workload.value().map(|workload| workload.family)
    } else {
        None
    }
}

/// Whether an initial attempt is evidence for `gate`: the §2.1 ready-latency stage for
/// load; prose and code requests for chat; reasoning requests for reasoning; tool requests
/// with their tool schema for tools; long-context requests for context; every serving
/// request for the workload's quality.
fn backs_gate(record: &RunRecord, gate: GateName) -> bool {
    let family = serving_family(record);
    match gate {
        GateName::Load => matches!(
            record.scenario,
            Scenario::Stages {
                primary: IntervalKind::ReadyLatency
            }
        ),
        GateName::Chat => matches!(family, Some(FixtureFamily::Prose | FixtureFamily::Code)),
        GateName::Reasoning => family == Some(FixtureFamily::Reasoning),
        GateName::Tools => {
            family == Some(FixtureFamily::Tool)
                && record
                    .workload
                    .value()
                    .is_some_and(|workload| workload.tool_schema.is_measured())
        }
        GateName::Context => family == Some(FixtureFamily::LongContext),
        GateName::WorkloadQuality => record.scenario == Scenario::Serving,
    }
}

/// Whether a request's input and output budget fill `context_tokens`.
fn fills_context(record: &RunRecord, context_tokens: u64) -> bool {
    record.workload.value().is_some_and(|workload| {
        workload
            .input_tokens
            .saturating_add(workload.max_output_tokens)
            >= context_tokens
    })
}

/// The gate over `attempts`, citing the CORE-08 evidence of exactly those attempts:
/// failed when one did not succeed, passed when all did and the gate was `exercised`,
/// and not measured without attempts or when it was not exercised.
fn gate_result(attempts: &[&RunRecord], exercised: bool) -> Result<GateResult, RecordRefusal> {
    if attempts.is_empty() {
        return Ok(GateResult::NotMeasured);
    }
    let records: Vec<RunRecord> = attempts.iter().map(|record| (*record).clone()).collect();
    let report = Provenance::of_records(&records)
        .and_then(|provenance| provenance.yougori_evidence())
        .map_err(proof_error)?;
    Ok(if !records.iter().all(RunRecord::is_success) {
        GateResult::Failed { report }
    } else if exercised {
        GateResult::Passed { report }
    } else {
        GateResult::NotMeasured
    })
}

/// The five gates, from the proof's initial attempts. Tools are offered exactly when a
/// tool-call parser is configured, and reasoning exactly when a reasoning parser is, the
/// parser that separates the trace a reasoning request is checked for. A capability that
/// is not offered is not applicable and has no attempts; load, context and every offered
/// capability must pass, and context only counts as exercised when a request fills the
/// configured context.
fn derive_gates(draft: &ProfileDraft) -> Result<ProfileGates, RecordRefusal> {
    let offers = draft.offers;
    let parsers = &draft.binding.parsers;
    match (offers.tools, parsers.tool_call.is_some()) {
        (true, false) => return Err(RecordRefusal::ToolsWithoutParser),
        (false, true) => return Err(RecordRefusal::ParserWithoutToolGate),
        _ => {}
    }
    match (offers.reasoning, parsers.reasoning.is_some()) {
        (true, false) => return Err(RecordRefusal::ReasoningWithoutParser),
        (false, true) => return Err(RecordRefusal::ParserWithoutReasoningGate),
        _ => {}
    }
    let context_tokens = u64::from(draft.settings.context_tokens);
    let gate = |name: GateName, offered: bool| -> Result<GateResult, RecordRefusal> {
        let attempts: Vec<&RunRecord> = draft
            .proof
            .initial_attempts()
            .filter(|record| backs_gate(record, name))
            .collect();
        if !offered {
            return if attempts.is_empty() {
                Ok(GateResult::NotApplicable)
            } else {
                Err(RecordRefusal::NotOfferedButMeasured { gate: name })
            };
        }
        let exercised = name != GateName::Context
            || attempts
                .iter()
                .any(|record| fills_context(record, context_tokens));
        match gate_result(&attempts, exercised)? {
            passed @ GateResult::Passed { .. } => Ok(passed),
            result => Err(RecordRefusal::GateNotPassed { gate: name, result }),
        }
    };
    Ok(ProfileGates {
        load: gate(GateName::Load, true)?,
        chat: gate(GateName::Chat, offers.chat)?,
        reasoning: gate(GateName::Reasoning, offers.reasoning)?,
        tools: gate(GateName::Tools, offers.tools)?,
        context: gate(GateName::Context, true)?,
    })
}

/// The workload, its highest concurrency, its slowest per-user speed and its quality,
/// from the proof's initial serving attempts.
fn derive_workload(draft: &ProfileDraft) -> Result<WorkloadGate, RecordRefusal> {
    let serving: Vec<&RunRecord> = draft
        .proof
        .initial_attempts()
        .filter(|record| backs_gate(record, GateName::WorkloadQuality))
        .collect();
    Ok(WorkloadGate {
        workload: workload_identity(&serving)?,
        concurrent_requests: serving
            .iter()
            .map(|record| record.load.concurrent_requests)
            .max()
            .unwrap_or(0),
        minimum_per_user_tokens_per_second: draft.minimum_per_user_tokens_per_second,
        measured_per_user_tokens_per_second: slowest_per_user_speed(&serving)?,
        quality: gate_result(&serving, true)?,
    })
}

/// The digest of the fixtures and load of each serving attempt, in a fixed order and each
/// once, so the order of the records does not matter.
fn workload_identity(serving: &[&RunRecord]) -> Result<Digest, RecordRefusal> {
    let mut parts = serving
        .iter()
        .map(|record| serde_json::to_vec(&(&record.workload, &record.load)))
        .collect::<Result<Vec<Vec<u8>>, _>>()
        .map_err(|_| proof_error(ReportError::Encoding))?;
    parts.sort();
    parts.dedup();
    let builder =
        DigestBuilder::new(WORKLOAD_DOMAIN).u64(u64::try_from(parts.len()).unwrap_or(u64::MAX));
    Ok(parts
        .iter()
        .fold(builder, |builder, part| builder.bytes(part))
        .finish())
}

/// The slowest per-user decode speed among the successful attempts (S8: speeds come from
/// successful initial attempts), or `None` when there is none or one was not measured.
fn slowest_per_user_speed(serving: &[&RunRecord]) -> Result<Option<f64>, RecordRefusal> {
    let mut slowest: Option<f64> = None;
    for record in serving.iter().filter(|record| record.is_success()) {
        let speed = match record.clock_reading().map_err(proof_error)? {
            ClockReading::Serving(clock) => clock.decode_tokens_per_second.value().copied(),
            _ => None,
        };
        match speed {
            Some(speed) if speed.is_finite() && speed >= 0.0 => {
                slowest = Some(slowest.map_or(speed, |current| current.min(speed)));
            }
            _ => return Ok(None),
        }
    }
    Ok(slowest)
}

fn check_workload(workload: &WorkloadGate, max_num_seqs: u32) -> Result<(), RecordRefusal> {
    let minimum = workload.minimum_per_user_tokens_per_second;
    if !minimum.is_finite() || minimum < 0.0 {
        return Err(RecordRefusal::WorkloadThresholdInvalid);
    }
    let measured = workload
        .measured_per_user_tokens_per_second
        .ok_or(RecordRefusal::WorkloadNotMeasured)?;
    if workload.concurrent_requests < max_num_seqs {
        return Err(RecordRefusal::ConcurrencyNotMeasured {
            max_num_seqs,
            measured: workload.concurrent_requests,
        });
    }
    if measured < minimum {
        return Err(RecordRefusal::WorkloadBelowDeclaredMinimum {
            measured_per_user_tokens_per_second: measured,
            minimum_per_user_tokens_per_second: minimum,
        });
    }
    if !workload.quality.passed() {
        return Err(RecordRefusal::GateNotPassed {
            gate: GateName::WorkloadQuality,
            result: workload.quality,
        });
    }
    Ok(())
}

fn feed_optional(builder: DigestBuilder, text: Option<&str>) -> DigestBuilder {
    match text {
        Some(text) => builder.str("some").str(text),
        None => builder.str("none"),
    }
}

fn category_tag(category: ExecutionCategory) -> &'static str {
    match category {
        ExecutionCategory::VmSandbox => "vm_sandbox",
        ExecutionCategory::SharedKernelGpuRuntime => "shared_kernel_gpu_runtime",
        ExecutionCategory::ProviderContainerRuntime => "provider_container_runtime",
        ExecutionCategory::HostProcessModelRuntime => "host_process_model_runtime",
    }
}

fn feed_review(builder: DigestBuilder, review: &Review) -> DigestBuilder {
    match review {
        Review::Approved { report } => builder.str("approved").digest(report),
        Review::Pending => builder.str("pending"),
        Review::Rejected { report } => builder.str("rejected").digest(report),
    }
}

fn feed_record(
    draft: &ProfileDraft,
    gates: &ProfileGates,
    workload: &WorkloadGate,
    builder: DigestBuilder,
) -> DigestBuilder {
    let builder = draft.settings.feed(draft.binding.feed(builder));
    let qualification = &draft.qualification;
    let builder = match qualification.host {
        QualificationHost::DisposableMachine { authorization } => {
            builder.str("disposable_machine").digest(&authorization)
        }
        QualificationHost::ProviderAllocation { authorization } => {
            builder.str("provider_allocation").digest(&authorization)
        }
        QualificationHost::OwnerMachine => builder.str("owner_machine"),
    }
    .str(category_tag(qualification.execution_category));
    let builder = match qualification.cleanup {
        Cleanup::Completed { report } => builder.str("cleanup_completed").digest(&report),
        Cleanup::Incomplete { report } => builder.str("cleanup_incomplete").digest(&report),
        Cleanup::NotRecorded => builder.str("cleanup_not_recorded"),
    }
    .str(&draft.proof_date.to_string())
    .digest(&draft.proof.evidence());
    let offers = draft.offers;
    let builder = [offers.chat, offers.reasoning, offers.tools]
        .into_iter()
        .fold(builder, |builder, offered| {
            builder.str(if offered { "offered" } else { "not_offered" })
        });
    let builder = [
        gates.load,
        gates.chat,
        gates.reasoning,
        gates.tools,
        gates.context,
    ]
    .into_iter()
    .fold(builder, |builder, gate| gate.feed(builder));
    let builder = builder
        .digest(&workload.workload)
        .u64(u64::from(workload.concurrent_requests))
        .u64(workload.minimum_per_user_tokens_per_second.to_bits());
    let builder = match workload.measured_per_user_tokens_per_second {
        Some(measured) => builder.str("measured").u64(measured.to_bits()),
        None => builder.str("not_measured"),
    };
    let builder = workload
        .quality
        .feed(builder)
        .u64(u64::try_from(draft.prerequisites.len()).unwrap_or(u64::MAX));
    let builder = draft
        .prerequisites
        .iter()
        .fold(builder, |builder, prerequisite| prerequisite.feed(builder));
    match &draft.origin {
        Origin::Qualified => builder.str("qualified"),
        Origin::Imported {
            source,
            license,
            trust,
        } => feed_review(
            feed_review(builder.str("imported").str(source), license),
            trust,
        ),
    }
}

/// Validated profiles by identity: the in-memory form of the records the existing
/// catalog keeps (FAST-05: no second catalog service).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProfileRecords {
    records: BTreeMap<ProfileId, ServingProfileRecord>,
}

/// Why a record operation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum RecordsError {
    AlreadyRecorded {
        id: ProfileId,
    },
    /// A withdrawn profile is never recorded again; a fixed profile needs new proof and
    /// so a new identity.
    Withdrawn {
        id: ProfileId,
    },
    Unknown {
        id: ProfileId,
    },
}

/// Why a template could not select a profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileSelectionError {
    Unknown {
        id: ProfileId,
    },
    /// The reason is boxed to keep the error small.
    Unusable {
        id: ProfileId,
        reason: Box<Unusable>,
    },
}

impl ProfileRecords {
    pub fn new() -> Self {
        Self::default()
    }

    /// Keeps a validated record.
    pub fn add(&mut self, record: ServingProfileRecord) -> Result<ProfileId, RecordsError> {
        let id = record.id();
        match self.records.get(&id) {
            Some(existing) if existing.is_withdrawn() => Err(RecordsError::Withdrawn { id }),
            Some(_) => Err(RecordsError::AlreadyRecorded { id }),
            None => {
                self.records.insert(id, record);
                Ok(id)
            }
        }
    }

    pub fn get(&self, id: &ProfileId) -> Option<&ServingProfileRecord> {
        self.records.get(id)
    }

    /// Every record, withdrawn ones included, by identity.
    pub fn iter(&self) -> impl Iterator<Item = &ServingProfileRecord> {
        self.records.values()
    }

    /// Records a failure report against a profile and returns its state; the second
    /// distinct report withdraws it (FAST-05).
    pub fn report_failure(
        &mut self,
        id: &ProfileId,
        report: Digest,
        kind: FailureKind,
    ) -> Result<&ProfileState, RecordsError> {
        let record = self
            .records
            .get_mut(id)
            .ok_or(RecordsError::Unknown { id: *id })?;
        record.record_failure(report, kind);
        Ok(record.state())
    }

    /// A template's choice of profile `id`, when it can serve `needs` now (FAST-05:
    /// user-authored templates may select a supported profile).
    pub fn select(
        &self,
        id: &ProfileId,
        needs: &ProfileNeeds<'_>,
    ) -> Result<&ServingProfileRecord, ProfileSelectionError> {
        let record = self
            .records
            .get(id)
            .ok_or(ProfileSelectionError::Unknown { id: *id })?;
        record.usable_for(needs).map(|()| record).map_err(|reason| {
            ProfileSelectionError::Unusable {
                id: *id,
                reason: Box::new(reason),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::evidence::Backend;
    use crate::foundation::report::{
        AnswerVerdict, GpuDescription, Measured, NotMeasuredReason, Precision, ReasoningTrace,
        RunSubstrate,
    };
    use crate::model_memory::backends::Technique;
    use crate::model_memory::identity::{
        Approximation, Quantization, RankTopology, SourceSpec, VersionedName,
    };
    use crate::model_memory::profiles::drafting::{DraftingCompatibility, DraftingSetting};
    use crate::model_memory::profiles::formats::CheckResult;
    use crate::model_memory::profiles::settings::{CommunicationScope, NcclChoice, PeerAccess};
    use crate::model_memory::profiles::testkit::{
        admitted, admitted_runtime, allowing, approval, approvals, backend_for, binding, checked,
        context_attempt, d, draft, engine, execution_spec_for, failed, fp4_kv, fp8_kv,
        load_attempt, logical, logical_spec, mix, model_binding, paced, proof, proof_in, proof_of,
        proof_with, qualification, qualification_attempts, reasoning_attempt, retry_of, runtime,
        serving_attempt, single_gpu, source_spec, tag, two_gpu_topology, two_gpus, validate,
        workload_of, GIB,
    };

    /// The CORE-08 evidence of exactly `records`, as a gate cites it.
    fn evidence_of(records: &[RunRecord]) -> Digest {
        Provenance::of_records(records)
            .unwrap()
            .yougori_evidence()
            .unwrap()
    }

    /// The draft with its proof replaced by `records`.
    fn proven_by(records: Vec<RunRecord>) -> ProfileDraft {
        ProfileDraft {
            proof: proof_of(records),
            ..draft()
        }
    }

    fn refusal(draft: ProfileDraft) -> RecordRefusal {
        match validate(draft) {
            Err(refusal) => refusal,
            Ok(record) => panic!("expected a refusal, got {:?}", record.id()),
        }
    }

    fn facts() -> PrerequisiteFacts {
        PrerequisiteFacts {
            peer_access_verified: true,
            pinned_host_bytes: 8 * GIB,
            managed_disk_bytes: 100 * GIB,
        }
    }

    /// The binding in force, the admitted shared-kernel runtime and its backend gate with
    /// CUDA graphs and concurrency approved, a request mix and the available prerequisites.
    struct Context {
        current: ProfileBinding,
        runtime: AdmittedRuntime,
        backend: BackendRuntime,
        approvals: Vec<ExperimentApproval>,
        mix: RequestMix,
        facts: PrerequisiteFacts,
    }

    impl Context {
        fn new(mix: RequestMix) -> Self {
            Self::on(ExecutionCategory::SharedKernelGpuRuntime, mix)
        }

        fn on(category: ExecutionCategory, mix: RequestMix) -> Self {
            Self {
                current: binding(),
                runtime: admitted(category),
                backend: backend_for(runtime(category)),
                approvals: approvals(),
                mix,
                facts: facts(),
            }
        }

        fn needs(&self) -> ProfileNeeds<'_> {
            ProfileNeeds {
                current: &self.current,
                runtime: &self.runtime,
                backend: &self.backend,
                approvals: &self.approvals,
                mix: &self.mix,
                facts: &self.facts,
            }
        }
    }

    fn proof_date() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, 27).unwrap()
    }

    fn versioned(name: &str, version: &str) -> VersionedName {
        VersionedName::new(name, version).unwrap()
    }

    /// The binding with its model rebuilt from `logical` and an execution for it.
    fn with_model(
        logical: LogicalModelSpec,
        execution: impl FnOnce(&mut ExecutionSpec),
    ) -> ProfileBinding {
        let mut spec = execution_spec_for(logical.identity());
        execution(&mut spec);
        ProfileBinding {
            model: ModelBinding::new(logical, spec).unwrap(),
            ..binding()
        }
    }

    #[test]
    fn a_validated_record_holds_every_fast05_field() {
        let record = validate(draft()).unwrap();
        let model = &record.binding().model;
        assert_eq!(model.source(), source_spec().identity().unwrap());
        assert_eq!(model.logical(), logical());
        assert_eq!(
            model.execution(),
            execution_spec_for(logical()).identity().unwrap()
        );
        assert_eq!(model.logical_spec().tokenizer, d("tokenizer"));
        assert_eq!(record.binding().engine, engine());
        assert_eq!(record.binding().launcher, d("launcher"));
        assert_eq!(
            record.binding().parsers.tool_call.as_deref(),
            Some("hermes")
        );
        assert_eq!(record.binding().hardware, single_gpu());
        assert_eq!(record.binding().driver, "580.95.05");
        assert_eq!(
            record.binding().resources.gpu_memory_bytes_per_device,
            22 * GIB
        );
        assert_eq!(record.settings().max_num_seqs, 4);
        assert_eq!(record.proof_date(), proof_date());
        // The raw report identity is the CORE-08 evidence of the qualification run.
        assert_eq!(record.raw_report(), evidence_of(&qualification_attempts()));
        assert_eq!(record.proof(), &proof());
        // The workload and its speed come from the run's serving attempts.
        let workload = record.workload();
        assert_eq!(workload.concurrent_requests, 4);
        assert_eq!(workload.minimum_per_user_tokens_per_second, 10.0);
        assert_eq!(workload.measured_per_user_tokens_per_second, Some(12.5));
        assert!(record.prerequisites().is_empty());
        assert_eq!(record.state(), &ProfileState::Active);
        assert_eq!(
            record.execution_category(),
            ExecutionCategory::SharedKernelGpuRuntime
        );
        assert_eq!(
            record.history(),
            &[HistoryEntry::Validated {
                proof_date: proof_date(),
                raw_report: evidence_of(&qualification_attempts()),
            }]
        );
        // The identity is the content's: the same draft gives the same one.
        assert_eq!(validate(draft()).unwrap().id(), record.id());
        let mut later = draft();
        later.proof_date = NaiveDate::from_ymd_opt(2026, 10, 28).unwrap();
        assert_ne!(validate(later).unwrap().id(), record.id());
    }

    #[test]
    fn each_change_kind_invalidates_a_profile() {
        let record = validate(draft()).unwrap();
        let mut records = ProfileRecords::new();
        let id = records.add(record.clone()).unwrap();
        let context = Context::new(mix(8_192, 1));
        assert!(record.invalidations(&context.current).is_empty());
        assert!(records.select(&id, &context.needs()).is_ok());

        let other_source = SourceSpec {
            configuration: d("other configuration"),
            ..source_spec()
        }
        .identity()
        .unwrap();
        let changes: Vec<(Vec<Invalidation>, ProfileBinding)> = vec![
            // A new checkpoint changes every identity layer built on it.
            (
                vec![
                    Invalidation::Source,
                    Invalidation::LogicalModel,
                    Invalidation::Execution,
                ],
                with_model(
                    LogicalModelSpec {
                        source: other_source,
                        ..logical_spec()
                    },
                    |_| {},
                ),
            ),
            (
                vec![Invalidation::LogicalModel, Invalidation::Execution],
                with_model(
                    LogicalModelSpec {
                        tokenizer: d("new tokenizer"),
                        ..logical_spec()
                    },
                    |_| {},
                ),
            ),
            (
                vec![Invalidation::Execution],
                with_model(logical_spec(), |execution| {
                    execution.kernel_layout = versioned("flash-attn", "2.8.0")
                }),
            ),
            (vec![Invalidation::Image], {
                let mut changed = binding();
                changed.engine.image = d("new image");
                changed
            }),
            (vec![Invalidation::Backend], {
                let mut changed = binding();
                changed.engine.release = BackendRelease::new(Backend::Vllm, "0.31.0").unwrap();
                changed
            }),
            (vec![Invalidation::Launcher], {
                let mut changed = binding();
                changed.launcher = d("new launcher");
                changed
            }),
            (vec![Invalidation::Parser], {
                let mut changed = binding();
                changed.parsers.tool_call = Some("qwen3_coder".to_owned());
                changed
            }),
            (vec![Invalidation::HardwareClass], {
                let mut changed = binding();
                changed.hardware.memory_bytes_per_gpu = 16 * GIB;
                changed
            }),
            (vec![Invalidation::Driver], {
                let mut changed = binding();
                changed.driver = "575.64".to_owned();
                changed
            }),
            (vec![Invalidation::ResourceContract], {
                let mut changed = binding();
                changed.resources.pinned_host_bytes = 2 * GIB;
                changed
            }),
        ];
        for (kinds, changed) in changes {
            assert_eq!(record.invalidations(&changed), kinds);
            let mut context = Context::new(mix(8_192, 1));
            context.current = changed;
            assert_eq!(
                records.select(&id, &context.needs()),
                Err(ProfileSelectionError::Unusable {
                    id,
                    reason: Box::new(Unusable::Invalidated {
                        changes: kinds.clone()
                    })
                }),
                "{kinds:?}"
            );
        }
    }

    #[test]
    fn the_same_card_name_on_another_topology_invalidates() {
        let record = validate(draft()).unwrap();
        let mut two = binding();
        two.hardware = two_gpus(&two_gpu_topology(PeerAccess::Verified));
        assert_eq!(two.hardware.gpu_name, record.binding().hardware.gpu_name);
        assert_eq!(
            record.invalidations(&two),
            vec![Invalidation::HardwareClass]
        );
    }

    #[test]
    fn the_model_binding_is_consistent() {
        let other = LogicalModelSpec {
            tokenizer: d("other tokenizer"),
            ..logical_spec()
        };
        assert_eq!(
            ModelBinding::new(other, execution_spec_for(logical())),
            Err(ModelBindingError::ExecutionForOtherModel)
        );
        let mut no_architecture = execution_spec_for(logical());
        no_architecture.gpu_architectures.clear();
        assert!(matches!(
            ModelBinding::new(logical_spec(), no_architecture),
            Err(ModelBindingError::Execution { .. })
        ));
        assert_eq!(model_binding().source(), logical_spec().source);
    }

    #[test]
    fn the_execution_identity_must_match_the_engine_and_settings() {
        let mut other_runner = draft();
        other_runner.binding = with_model(logical_spec(), |execution| {
            execution.runner = versioned("vllm", "0.31.0")
        });
        assert_eq!(
            validate(other_runner).map(|record| record.id()),
            Err(RecordRefusal::RunnerNotEngine)
        );
        let mut two_ranks = draft();
        two_ranks.binding = with_model(logical_spec(), |execution| {
            execution.topology = RankTopology::new(2, 1, 1).unwrap()
        });
        assert_eq!(
            validate(two_ranks).map(|record| record.id()),
            Err(RecordRefusal::RankTopologyNotSettings {
                rank_topology: 2,
                tensor_parallel_size: 1
            })
        );
    }

    #[test]
    fn a_reproducibly_failing_profile_is_withdrawn_and_its_history_kept() {
        let mut records = ProfileRecords::new();
        let id = records.add(validate(draft()).unwrap()).unwrap();
        assert_eq!(
            records.report_failure(&id, d("failure 1"), FailureKind::Startup),
            Ok(&ProfileState::Active)
        );
        // The same report again is not a reproduction.
        assert_eq!(
            records.report_failure(&id, d("failure 1"), FailureKind::Startup),
            Ok(&ProfileState::Active)
        );
        let withdrawn = ProfileState::Withdrawn {
            reports: vec![d("failure 1"), d("failure 2")],
        };
        assert_eq!(
            records.report_failure(&id, d("failure 2"), FailureKind::Startup),
            Ok(&withdrawn)
        );
        // Later reports are still kept, and the profile stays withdrawn.
        assert_eq!(
            records.report_failure(&id, d("failure 3"), FailureKind::Quality),
            Ok(&withdrawn)
        );
        assert_eq!(
            records.get(&id).unwrap().history(),
            &[
                HistoryEntry::Validated {
                    proof_date: proof_date(),
                    raw_report: evidence_of(&qualification_attempts()),
                },
                HistoryEntry::FailureReported {
                    report: d("failure 1"),
                    kind: FailureKind::Startup
                },
                HistoryEntry::FailureReported {
                    report: d("failure 2"),
                    kind: FailureKind::Startup
                },
                HistoryEntry::Withdrawn {
                    reports: vec![d("failure 1"), d("failure 2")]
                },
                HistoryEntry::FailureReported {
                    report: d("failure 3"),
                    kind: FailureKind::Quality
                },
            ]
        );
        // Recording the same profile again cannot revive it.
        assert_eq!(
            records.add(validate(draft()).unwrap()),
            Err(RecordsError::Withdrawn { id })
        );
        assert_eq!(
            records.report_failure(&ProfileId(d("unknown")), d("x"), FailureKind::Speed),
            Err(RecordsError::Unknown {
                id: ProfileId(d("unknown"))
            })
        );
    }

    #[test]
    fn a_withdrawn_profile_is_never_selected() {
        let mut records = ProfileRecords::new();
        let id = records.add(validate(draft()).unwrap()).unwrap();
        let context = Context::new(mix(8_192, 1));
        assert!(records.select(&id, &context.needs()).is_ok());
        records
            .report_failure(&id, d("failure 1"), FailureKind::Capacity)
            .unwrap();
        records
            .report_failure(&id, d("failure 2"), FailureKind::Security)
            .unwrap();
        assert_eq!(
            records.select(&id, &context.needs()),
            Err(ProfileSelectionError::Unusable {
                id,
                reason: Box::new(Unusable::Withdrawn)
            })
        );
        assert_eq!(
            records
                .get(&id)
                .unwrap()
                .check_publication(Some(&PublicationAuthorization {
                    authorization: d("publish")
                })),
            Err(PublicationRefusal::Withdrawn)
        );
        assert_eq!(
            records.select(&ProfileId(d("unknown")), &context.needs()),
            Err(ProfileSelectionError::Unknown {
                id: ProfileId(d("unknown"))
            })
        );
    }

    #[test]
    fn selection_meets_the_request_without_downgrading_it() {
        let mut records = ProfileRecords::new();
        let id = records.add(validate(draft()).unwrap()).unwrap();
        let select = |mix: RequestMix| {
            let context = Context::new(mix);
            records
                .select(&id, &context.needs())
                .map(|record| record.id())
        };
        assert_eq!(select(mix(16_384, 4)), Ok(id));
        assert_eq!(
            select(mix(16_385, 1)),
            Err(ProfileSelectionError::Unusable {
                id,
                reason: Box::new(Unusable::ContextTooShort {
                    context_tokens: 16_384,
                    needed_tokens: 16_385
                })
            })
        );
        assert_eq!(
            select(mix(1_024, 5)),
            Err(ProfileSelectionError::Unusable {
                id,
                reason: Box::new(Unusable::TooFewSequences {
                    max_num_seqs: 4,
                    needed: 5
                })
            })
        );
        let mut tools = mix(1_024, 1);
        tools.tool_calls = true;
        assert_eq!(select(tools.clone()), Ok(id));

        let mut no_tools = proven_by(vec![
            load_attempt("op-load"),
            serving_attempt("op-chat", FixtureFamily::Code),
            context_attempt("op-context"),
        ]);
        no_tools.offers.tools = false;
        no_tools.binding.parsers.tool_call = None;
        let no_tools = validate(no_tools).unwrap();
        assert_eq!(no_tools.gates().tools, GateResult::NotApplicable);
        assert!(!no_tools.capabilities().tool_calls);
        let mut context = Context::new(tools);
        context.current.parsers.tool_call = None;
        assert_eq!(
            no_tools.usable_for(&context.needs()),
            Err(Unusable::NoToolCalls)
        );
    }

    #[test]
    fn a_profile_never_crosses_its_execution_category() {
        let record = validate(draft()).unwrap();
        // Proven in the shared-kernel runtime: never used for a VM sandbox or a provider
        // container, even when the request admitted those.
        for category in [
            ExecutionCategory::VmSandbox,
            ExecutionCategory::ProviderContainerRuntime,
        ] {
            let context = Context::on(category, mix(1_024, 1));
            assert_eq!(
                record.usable_for(&context.needs()),
                Err(Unusable::OtherCategory {
                    recorded: ExecutionCategory::SharedKernelGpuRuntime,
                    current: category
                })
            );
        }
    }

    #[test]
    fn the_admitted_runtime_must_run_the_bound_engine() {
        let record = validate(draft()).unwrap();
        let mut upgraded = runtime(ExecutionCategory::SharedKernelGpuRuntime);
        upgraded.release = BackendRelease::new(Backend::Vllm, "0.31.0").unwrap();
        let mut context = Context::new(mix(1_024, 1));
        context.runtime = admitted_runtime(upgraded.clone());
        context.backend = backend_for(upgraded);
        assert_eq!(
            record.usable_for(&context.needs()),
            Err(Unusable::RuntimeForOtherEngine {
                runtime: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
                engine: engine().release,
            })
        );
    }

    #[test]
    fn a_profile_beyond_todays_flags_needs_the_backend_gate() {
        // The profile captures CUDA graphs and runs 4 sequences: both are later
        // experiments of the vLLM retained-process row.
        let record = validate(draft()).unwrap();
        assert_eq!(
            record.settings().techniques(),
            vec![Technique::CudaGraphs, Technique::Concurrency]
        );
        for (approved, missing) in [
            (Technique::Concurrency, Technique::CudaGraphs),
            (Technique::CudaGraphs, Technique::Concurrency),
        ] {
            let mut context = Context::new(mix(1_024, 1));
            context.approvals = vec![approval(approved)];
            assert_eq!(
                record.usable_for(&context.needs()),
                Err(Unusable::TechniqueNotAdmitted {
                    refusal: TechniqueRefusal::ExperimentNotApproved {
                        technique: missing,
                        release: engine().release,
                    }
                })
            );
        }
        // Today's eager, single-sequence settings need no approval.
        let mut today = draft();
        today.settings.graph_mode = super::super::settings::GraphMode::Eager;
        today.settings.max_num_seqs = 1;
        let today = validate(today).unwrap();
        assert!(today.settings().techniques().is_empty());
        let mut context = Context::new(mix(1_024, 1));
        context.approvals.clear();
        assert_eq!(today.usable_for(&context.needs()), Ok(()));
        // The gate must describe the admitted runtime.
        let mut elsewhere = Context::new(mix(1_024, 1));
        elsewhere.backend = backend_for(runtime(ExecutionCategory::ProviderContainerRuntime));
        assert_eq!(
            record.usable_for(&elsewhere.needs()),
            Err(Unusable::BackendForOtherRuntime)
        );
    }

    #[test]
    fn prerequisites_are_checked_never_applied() {
        let mut with_prerequisites = draft();
        with_prerequisites.prerequisites = vec![
            Prerequisite::PinnedHostMemory { bytes: 4 * GIB },
            Prerequisite::ManagedDiskSpace { bytes: 200 * GIB },
        ];
        let record = validate(with_prerequisites).unwrap();
        let mut context = Context::new(mix(1_024, 1));
        assert_eq!(
            record.usable_for(&context.needs()),
            Err(Unusable::PrerequisiteUnmet {
                prerequisite: Prerequisite::ManagedDiskSpace { bytes: 200 * GIB }
            })
        );
        context.facts.managed_disk_bytes = 200 * GIB;
        assert_eq!(record.usable_for(&context.needs()), Ok(()));
        assert!(
            !Prerequisite::PeerAccessVerified.met_by(&PrerequisiteFacts {
                peer_access_verified: false,
                ..facts()
            })
        );
        assert!(Prerequisite::PeerAccessVerified.met_by(&facts()));
    }

    #[test]
    fn the_proof_must_be_a_yougori_measurement() {
        // A fake time-controlled run proves the contract, never a profile (S12 G0), and
        // one fake attempt among real ones makes the whole run fake.
        let fake: Vec<RunRecord> = qualification_attempts()
            .into_iter()
            .map(|mut record| {
                record.substrate = RunSubstrate::FakeTimeControlled;
                record
            })
            .collect();
        assert_eq!(
            ProfileProof::new(fake),
            Err(ReportError::FakeSubstrateIsNotEvidence)
        );
        let mut mixed = qualification_attempts();
        mixed[1].substrate = RunSubstrate::FakeTimeControlled;
        assert_eq!(
            ProfileProof::new(mixed),
            Err(ReportError::FakeSubstrateIsNotEvidence)
        );
        // Nothing proves nothing.
        assert_eq!(ProfileProof::new(Vec::new()), Err(ReportError::NoAttempts));
        // Every record must be a valid raw record: three tokens are not four.
        let mut miscounted = qualification_attempts();
        miscounted[1].measurements.output_tokens = Measured::measured(4);
        assert!(matches!(
            ProfileProof::new(miscounted),
            Err(ReportError::TokenCountMismatch { .. })
        ));
        // An attempt is recorded once, and a retry follows a failed first attempt.
        let mut repeated = qualification_attempts();
        repeated.push(serving_attempt("op-chat", FixtureFamily::Prose));
        assert_eq!(
            ProfileProof::new(repeated),
            Err(ReportError::DuplicateAttempt)
        );
        let chat = serving_attempt("op-chat", FixtureFamily::Code);
        let mut after_success = qualification_attempts();
        after_success.push(retry_of(&chat, "op-chat-retry"));
        assert_eq!(
            ProfileProof::new(after_success),
            Err(ReportError::RetryAfterSuccess)
        );
        assert_eq!(
            ProfileProof::new(vec![retry_of(&chat, "op-chat-retry")]),
            Err(ReportError::UnknownFirstAttempt)
        );
    }

    #[test]
    fn the_proof_must_measure_this_profile() {
        let not_about = |change: fn(&mut RunRecord)| {
            let mut records = qualification_attempts();
            change(&mut records[2]);
            refusal(proven_by(records))
        };
        let about = |field| RecordRefusal::ProofNotAboutProfile {
            operation: OperationId::new("op-tools").unwrap(),
            field,
        };
        assert_eq!(
            not_about(
                |record| record.execution_category = ExecutionCategory::ProviderContainerRuntime
            ),
            about(ProofField::ExecutionCategory)
        );
        assert_eq!(
            not_about(|record| record.launch.image = d("other image")),
            about(ProofField::Image)
        );
        assert_eq!(
            not_about(|record| {
                if let Measured::Measured { value } = &mut record.engine {
                    value.version = tag("0.31.0");
                }
            }),
            about(ProofField::Engine)
        );
        assert_eq!(
            not_about(|record| record.host.gpu_driver = Measured::measured(tag("575.64"))),
            about(ProofField::Driver)
        );
        // What the record does not measure cannot back the profile either.
        assert_eq!(
            not_about(|record| record.host.gpu_driver =
                Measured::not_measured(NotMeasuredReason::InstrumentUnavailable)),
            about(ProofField::Driver)
        );
        assert_eq!(
            not_about(|record| {
                if let Measured::Measured { value } = &mut record.host.gpus {
                    value.push(GpuDescription {
                        model: tag("nvidia-geforce-rtx-4090"),
                        memory_bytes: 24 * GIB,
                    });
                }
            }),
            about(ProofField::Gpus)
        );
        assert_eq!(
            not_about(|record| {
                if let Measured::Measured { value } = &mut record.host.gpus {
                    value[0].memory_bytes = 16 * GIB;
                }
            }),
            about(ProofField::Gpus)
        );
        assert_eq!(
            not_about(|record| {
                if let Measured::Measured { value } = &mut record.model {
                    value.tokenizer = d("other tokenizer");
                }
            }),
            about(ProofField::Tokenizer)
        );
        // A run with FP8 KV does not prove a BF16 KV profile.
        assert_eq!(
            not_about(|record| record.precision = Measured::measured(Precision {
                weight_dtype: tag("bf16"),
                quantization: tag("none"),
                kv_cache_dtype: tag("f8e4m3"),
            })),
            about(ProofField::KvCacheDtype)
        );
    }

    #[test]
    fn gates_are_derived_from_the_proof() {
        let record = validate(draft()).unwrap();
        let attempts = qualification_attempts();
        let gates = record.gates();
        // Each gate cites the CORE-08 evidence of exactly its own attempts.
        assert_eq!(
            gates.load,
            GateResult::Passed {
                report: evidence_of(&attempts[0..1])
            }
        );
        assert_eq!(
            gates.chat,
            GateResult::Passed {
                report: evidence_of(&attempts[1..2])
            }
        );
        assert_eq!(gates.reasoning, GateResult::NotApplicable);
        assert_eq!(
            gates.tools,
            GateResult::Passed {
                report: evidence_of(&attempts[2..3])
            }
        );
        assert_eq!(
            gates.context,
            GateResult::Passed {
                report: evidence_of(&attempts[3..4])
            }
        );
        assert_eq!(
            record.workload().quality,
            GateResult::Passed {
                report: evidence_of(&attempts[1..4])
            }
        );
        let capabilities = record.capabilities();
        assert!(capabilities.chat && capabilities.tool_calls && !capabilities.reasoning);
    }

    #[test]
    fn every_offered_gate_must_pass_on_the_proof() {
        // Without the ready-latency stage, loading is not measured.
        assert_eq!(
            refusal(proven_by(qualification_attempts().split_off(1))),
            RecordRefusal::GateNotPassed {
                gate: GateName::Load,
                result: GateResult::NotMeasured
            }
        );
        // A failed long-context request fails the context gate.
        let mut attempts = qualification_attempts();
        attempts[3] = failed(context_attempt("op-context"));
        let report = evidence_of(&attempts[3..4]);
        assert_eq!(
            refusal(proven_by(attempts)),
            RecordRefusal::GateNotPassed {
                gate: GateName::Context,
                result: GateResult::Failed { report }
            }
        );
        // One that does not fill the 16,384-token context leaves the context unproven.
        let mut short = qualification_attempts();
        workload_of(&mut short[3]).input_tokens = 8_000;
        assert_eq!(
            refusal(proven_by(short)),
            RecordRefusal::GateNotPassed {
                gate: GateName::Context,
                result: GateResult::NotMeasured
            }
        );
        // Offered chat needs chat requests.
        let mut no_chat = qualification_attempts();
        no_chat.remove(1);
        assert_eq!(
            refusal(proven_by(no_chat)),
            RecordRefusal::GateNotPassed {
                gate: GateName::Chat,
                result: GateResult::NotMeasured
            }
        );
        // Offered reasoning needs reasoning requests.
        let mut reasoning = draft();
        reasoning.offers.reasoning = true;
        reasoning.binding.parsers.reasoning = Some("kolibri1".to_owned());
        assert_eq!(
            refusal(reasoning),
            RecordRefusal::GateNotPassed {
                gate: GateName::Reasoning,
                result: GateResult::NotMeasured
            }
        );
        // A tool request without its tool schema proves nothing about tools.
        let mut schemaless = qualification_attempts();
        schemaless[2] = serving_attempt("op-tools", FixtureFamily::Tool);
        assert_eq!(
            refusal(proven_by(schemaless)),
            RecordRefusal::GateNotPassed {
                gate: GateName::Tools,
                result: GateResult::NotMeasured
            }
        );
        // A successful retry never rewrites a failed first attempt (S8).
        let mut retried = qualification_attempts();
        retried[1] = failed(serving_attempt("op-chat", FixtureFamily::Code));
        let first = retried[1].clone();
        retried.push(retry_of(&first, "op-chat-retry"));
        let report = evidence_of(&retried[1..2]);
        assert_eq!(
            refusal(proven_by(retried)),
            RecordRefusal::GateNotPassed {
                gate: GateName::Chat,
                result: GateResult::Failed { report }
            }
        );
    }

    #[test]
    fn what_is_not_offered_has_no_attempts() {
        // Tools are offered exactly when a tool-call parser is configured.
        let mut no_parser = draft();
        no_parser.binding.parsers.tool_call = None;
        assert_eq!(refusal(no_parser), RecordRefusal::ToolsWithoutParser);
        let mut parser_only = draft();
        parser_only.offers.tools = false;
        assert_eq!(refusal(parser_only), RecordRefusal::ParserWithoutToolGate);
        // Declaring a capability absent cannot hide its attempts.
        let mut hidden = draft();
        hidden.offers.tools = false;
        hidden.binding.parsers.tool_call = None;
        assert_eq!(
            refusal(hidden),
            RecordRefusal::NotOfferedButMeasured {
                gate: GateName::Tools
            }
        );
        let mut no_chat = draft();
        no_chat.offers.chat = false;
        assert_eq!(
            refusal(no_chat),
            RecordRefusal::NotOfferedButMeasured {
                gate: GateName::Chat
            }
        );
        // Without chat requests, chat may be declared absent.
        let mut without_chat = qualification_attempts();
        without_chat.remove(1);
        let mut absent = proven_by(without_chat);
        absent.offers.chat = false;
        let record = validate(absent).unwrap();
        assert_eq!(record.gates().chat, GateResult::NotApplicable);
        assert!(!record.capabilities().chat);
    }

    /// The draft offering reasoning through the kolibri1 reasoning parser, proven by the
    /// qualification run and `reasoning` requests.
    fn reasoning_draft(reasoning: Vec<RunRecord>) -> ProfileDraft {
        let mut attempts = qualification_attempts();
        attempts.extend(reasoning);
        let mut draft = proven_by(attempts);
        draft.offers.reasoning = true;
        draft.binding.parsers.reasoning = Some("kolibri1".to_owned());
        draft
    }

    /// A reasoning request whose check found `trace` and `final_answer`, recorded as failed.
    fn failed_reasoning(
        operation: &str,
        trace: ReasoningTrace,
        final_answer: AnswerVerdict,
    ) -> RunRecord {
        failed(checked(
            serving_attempt(operation, FixtureFamily::Reasoning),
            trace,
            final_answer,
        ))
    }

    fn trace() -> ReasoningTrace {
        ReasoningTrace::Present {
            tokens: Measured::measured(40),
        }
    }

    #[test]
    fn reasoning_requests_prove_offered_reasoning() {
        // A reasoning request showed a trace and a correct final answer: reasoning passes,
        // citing exactly that request.
        let reasoning = reasoning_attempt("op-reasoning");
        let record = validate(reasoning_draft(vec![reasoning.clone()])).unwrap();
        assert_eq!(
            record.gates().reasoning,
            GateResult::Passed {
                report: evidence_of(&[reasoning])
            }
        );
        assert!(record.capabilities().reasoning);
        // Reasoning is offered exactly when a reasoning parser separates its trace.
        let mut unparsed = reasoning_draft(vec![reasoning_attempt("op-reasoning")]);
        unparsed.binding.parsers.reasoning = None;
        assert_eq!(refusal(unparsed), RecordRefusal::ReasoningWithoutParser);
        let mut parser_only = draft();
        parser_only.binding.parsers.reasoning = Some("kolibri1".to_owned());
        assert_eq!(
            refusal(parser_only),
            RecordRefusal::ParserWithoutReasoningGate
        );
        // Declaring reasoning absent cannot hide reasoning requests.
        let mut hidden = reasoning_draft(vec![reasoning_attempt("op-reasoning")]);
        hidden.offers.reasoning = false;
        hidden.binding.parsers.reasoning = None;
        assert_eq!(
            refusal(hidden),
            RecordRefusal::NotOfferedButMeasured {
                gate: GateName::Reasoning
            }
        );
    }

    #[test]
    fn a_failed_or_unanswered_reasoning_request_refuses_then_withdraws() {
        // A reasoning request that failed with a wrong final answer fails the gate.
        let wrong = failed_reasoning("op-reasoning", trace(), AnswerVerdict::Incorrect);
        assert_eq!(
            refusal(reasoning_draft(vec![wrong.clone()])),
            RecordRefusal::GateNotPassed {
                gate: GateName::Reasoning,
                result: GateResult::Failed {
                    report: evidence_of(&[wrong])
                }
            }
        );
        // So does one cut off inside its reasoning, with no final answer.
        let unanswered = failed_reasoning("op-reasoning", trace(), AnswerVerdict::Missing);
        assert_eq!(
            refusal(reasoning_draft(vec![unanswered.clone()])),
            RecordRefusal::GateNotPassed {
                gate: GateName::Reasoning,
                result: GateResult::Failed {
                    report: evidence_of(&[unanswered])
                }
            }
        );
        // Recorded as a success, a missing answer or a missing trace is no valid raw
        // record, so it cannot be part of a proof at all.
        for (trace, final_answer) in [
            (trace(), AnswerVerdict::Missing),
            (ReasoningTrace::Absent, AnswerVerdict::Correct),
        ] {
            let mut attempts = qualification_attempts();
            attempts.push(checked(
                serving_attempt("op-reasoning", FixtureFamily::Reasoning),
                trace,
                final_answer,
            ));
            assert_eq!(
                ProfileProof::new(attempts),
                Err(ReportError::ReasoningNotPassed)
            );
        }
        // Once validated, two distinct failed reasoning runs withdraw the profile, each
        // reported by its own CORE-08 evidence.
        let mut records = ProfileRecords::new();
        let id = records
            .add(validate(reasoning_draft(vec![reasoning_attempt("op-reasoning")])).unwrap())
            .unwrap();
        let run = |operation: &str| {
            evidence_of(&[failed_reasoning(operation, trace(), AnswerVerdict::Missing)])
        };
        assert_eq!(
            records.report_failure(&id, run("op-served-1"), FailureKind::Quality),
            Ok(&ProfileState::Active)
        );
        assert_eq!(
            records.report_failure(&id, run("op-served-2"), FailureKind::Quality),
            Ok(&ProfileState::Withdrawn {
                reports: vec![run("op-served-1"), run("op-served-2")]
            })
        );
    }

    #[test]
    fn speed_and_quality_come_from_the_workloads_attempts() {
        // 12.5 tokens/s per user passes a workload that declares 10 and fails one that
        // declares 25. No fixed 15 tokens/s floor applies to either.
        let mut fast = draft();
        fast.minimum_per_user_tokens_per_second = 25.0;
        assert_eq!(
            refusal(fast),
            RecordRefusal::WorkloadBelowDeclaredMinimum {
                measured_per_user_tokens_per_second: 12.5,
                minimum_per_user_tokens_per_second: 25.0
            }
        );
        // The slowest request counts: tokens 100 ms apart decode at 10 tokens/s.
        let mut attempts = qualification_attempts();
        attempts[1] = paced(attempts[1].clone(), 3, 100);
        let mut slowest = proven_by(attempts);
        slowest.minimum_per_user_tokens_per_second = 11.0;
        assert_eq!(
            refusal(slowest),
            RecordRefusal::WorkloadBelowDeclaredMinimum {
                measured_per_user_tokens_per_second: 10.0,
                minimum_per_user_tokens_per_second: 11.0
            }
        );
        // One token has no measurable decode speed, so no speed is claimed.
        let mut attempts = qualification_attempts();
        attempts[1] = paced(attempts[1].clone(), 1, 80);
        assert_eq!(
            refusal(proven_by(attempts)),
            RecordRefusal::WorkloadNotMeasured
        );
        // The speed must be measured at the profile's four concurrent sequences.
        let single = ProfileDraft {
            proof: proof_with(|record| record.load.concurrent_requests = 1),
            ..draft()
        };
        assert_eq!(
            refusal(single),
            RecordRefusal::ConcurrencyNotMeasured {
                max_num_seqs: 4,
                measured: 1
            }
        );
        let mut undeclared = draft();
        undeclared.minimum_per_user_tokens_per_second = f64::NAN;
        assert_eq!(refusal(undeclared), RecordRefusal::WorkloadThresholdInvalid);
        // A failed agent task fails the workload's quality, which cites every request.
        let mut attempts = qualification_attempts();
        attempts.push(failed(serving_attempt("op-task", FixtureFamily::AgentTask)));
        let report = evidence_of(&attempts[1..]);
        assert_eq!(
            refusal(proven_by(attempts)),
            RecordRefusal::GateNotPassed {
                gate: GateName::WorkloadQuality,
                result: GateResult::Failed { report }
            }
        );
        // One hardware class is enough; there is no three-class rule.
        assert!(validate(draft()).is_ok());
    }

    #[test]
    fn the_workload_is_identified_by_its_requests() {
        let base = validate(draft()).unwrap().workload().workload;
        // The order of the records does not matter.
        let mut reordered = qualification_attempts();
        reordered.reverse();
        assert_eq!(
            validate(proven_by(reordered)).unwrap().workload().workload,
            base
        );
        // Another request or another load does.
        let mut longer = qualification_attempts();
        workload_of(&mut longer[1]).input_tokens = 1_024;
        assert_ne!(
            validate(proven_by(longer)).unwrap().workload().workload,
            base
        );
        let wider = ProfileDraft {
            proof: proof_with(|record| record.load.concurrent_requests = 8),
            ..draft()
        };
        assert_ne!(validate(wider).unwrap().workload().workload, base);
    }

    #[test]
    fn qualification_runs_only_on_authorized_disposable_hosts() {
        let mut owner = draft();
        owner.qualification.host = QualificationHost::OwnerMachine;
        assert_eq!(
            validate(owner).map(|record| record.id()),
            Err(RecordRefusal::OwnerMachine)
        );
        let mut provider = draft();
        provider.qualification.host = QualificationHost::ProviderAllocation {
            authorization: d("pod"),
        };
        provider.qualification.execution_category = ExecutionCategory::ProviderContainerRuntime;
        // The proof must have run in that category too.
        assert_eq!(
            refusal(provider.clone()),
            RecordRefusal::ProofNotAboutProfile {
                operation: OperationId::new("op-load").unwrap(),
                field: ProofField::ExecutionCategory
            }
        );
        provider.proof = proof_in(ExecutionCategory::ProviderContainerRuntime);
        assert_eq!(
            validate(provider).unwrap().execution_category(),
            ExecutionCategory::ProviderContainerRuntime
        );
        for cleanup in [
            Cleanup::NotRecorded,
            Cleanup::Incomplete {
                report: d("leftover"),
            },
        ] {
            let mut unclean = draft();
            unclean.qualification.cleanup = cleanup;
            assert_eq!(
                validate(unclean).map(|record| record.id()),
                Err(RecordRefusal::CleanupNotCompleted { cleanup })
            );
        }
    }

    #[test]
    fn imports_need_license_and_trust_review() {
        let approved = Review::Approved {
            report: d("review"),
        };
        for (license, trust) in [
            (Review::Pending, approved),
            (approved, Review::Rejected { report: d("no") }),
        ] {
            let mut imported = draft();
            imported.origin = Origin::Imported {
                source: "local-ai-registry".to_owned(),
                license,
                trust,
            };
            assert_eq!(
                validate(imported).map(|record| record.id()),
                Err(RecordRefusal::ImportNotReviewed)
            );
        }
        let mut reviewed = draft();
        reviewed.origin = Origin::Imported {
            source: "local-ai-registry".to_owned(),
            license: approved,
            trust: approved,
        };
        assert!(validate(reviewed).is_ok());
    }

    #[test]
    fn publication_needs_separate_authorization() {
        let record = validate(draft()).unwrap();
        assert_eq!(
            record.check_publication(None),
            Err(PublicationRefusal::NotAuthorized)
        );
        assert_eq!(
            record.check_publication(Some(&PublicationAuthorization {
                authorization: d("release action")
            })),
            Ok(())
        );
    }

    #[test]
    fn lossy_profiles_are_labelled_and_qualified_per_model() {
        let mut fp8 = draft();
        fp8.settings.kv_cache = fp8_kv();
        assert_eq!(
            validate(fp8.clone()).map(|record| record.id()),
            Err(RecordRefusal::KvFormat {
                refusal: KvFormatRefusal::NotQualified {
                    kv: Box::new(fp8_kv())
                }
            })
        );
        let kv_formats = [qualification(fp8_kv())];
        let matrix = DraftingMatrix::default();
        let qualified = |draft: ProfileDraft| {
            ServingProfileRecord::validate(
                draft,
                Qualifications {
                    kv_formats: &kv_formats,
                    drafting: &matrix,
                },
            )
        };
        // Qualified for this model, but proven with BF16 KV: the proof is of another profile.
        assert_eq!(
            qualified(fp8.clone()).map(|record| record.id()),
            Err(RecordRefusal::ProofNotAboutProfile {
                operation: OperationId::new("op-load").unwrap(),
                field: ProofField::KvCacheDtype
            })
        );
        fp8.proof = proof_with(|record| {
            record.precision = Measured::measured(Precision {
                weight_dtype: tag("bf16"),
                quantization: tag("none"),
                kv_cache_dtype: tag("f8e4m3"),
            })
        });
        let lossy = qualified(fp8).unwrap();
        let exact = validate(draft()).unwrap();
        assert_eq!(
            lossy.capabilities().fidelity,
            FidelityCategory::ApproximateInference
        );
        assert_eq!(
            exact.capabilities().fidelity,
            FidelityCategory::LosslessRepresentation
        );
        assert_ne!(lossy.id(), exact.id());
        // A lossy profile serves only requests whose fidelity configuration lists it.
        let mut context = Context::new(mix(1_024, 1));
        let Quantization::Scheme(scheme) = fp8_kv().quantization().clone() else {
            panic!("FP8 KV carries its scheme");
        };
        assert_eq!(
            lossy.usable_for(&context.needs()),
            Err(Unusable::Fidelity {
                refusal: FidelityRefusal::NotExplicitlyConfigured {
                    approximation: Approximation::Quantization(scheme)
                }
            })
        );
        context.mix.fidelity = allowing(&fp8_kv());
        assert_eq!(lossy.usable_for(&context.needs()), Ok(()));

        let mut fp4 = draft();
        fp4.settings.kv_cache = fp4_kv();
        let mut unsupported = qualification(fp4_kv());
        unsupported.per_model_support = CheckResult::NotChecked;
        let kv_formats = [unsupported];
        assert!(matches!(
            ServingProfileRecord::validate(
                fp4,
                Qualifications {
                    kv_formats: &kv_formats,
                    drafting: &matrix,
                },
            ),
            Err(RecordRefusal::KvFormat {
                refusal: KvFormatRefusal::CheckNotPassed { .. }
            })
        ));
    }

    #[test]
    fn drafting_profiles_need_the_pinned_matrix() {
        let mut drafted = draft();
        drafted.settings.drafting = Some(DraftingSetting {
            method: DraftMethod::Mtp,
            drafter: None,
            speculative_tokens: 2,
        });
        assert_eq!(
            validate(drafted.clone()).map(|record| record.id()),
            Err(RecordRefusal::DraftingNotPinned)
        );
        let matrix = DraftingMatrix::new(vec![DraftingCompatibility {
            engine: engine(),
            model: logical(),
            method: DraftMethod::Mtp,
            drafter: None,
            promises_greedy_exactness: true,
            max_speculative_tokens: 2,
        }])
        .unwrap();
        let pinned = Qualifications {
            kv_formats: &[],
            drafting: &matrix,
        };
        let record = ServingProfileRecord::validate(drafted.clone(), pinned).unwrap();
        assert_eq!(record.capabilities().drafting, Some(DraftMethod::Mtp));
        if let Some(setting) = drafted.settings.drafting.as_mut() {
            setting.speculative_tokens = 3;
        }
        assert_eq!(
            ServingProfileRecord::validate(drafted, pinned).map(|record| record.id()),
            Err(RecordRefusal::DraftingNotPinned)
        );
    }

    #[test]
    fn settings_must_match_the_hardware_class() {
        let mut two = draft();
        two.settings.tensor_parallel_size = 2;
        two.settings.nccl = Some(
            NcclChoice::from_topology(
                &two_gpu_topology(PeerAccess::Verified),
                CommunicationScope::EngineProcess,
            )
            .unwrap(),
        );
        assert_eq!(
            validate(two.clone()).map(|record| record.id()),
            Err(RecordRefusal::TensorParallelNotHardware {
                tensor_parallel_size: 2,
                gpu_count: 1
            })
        );
        two.binding.hardware = two_gpus(&two_gpu_topology(PeerAccess::Unavailable));
        assert_eq!(
            validate(two.clone()).map(|record| record.id()),
            Err(RecordRefusal::NcclForOtherTopology)
        );
        two.binding.hardware = two_gpus(&two_gpu_topology(PeerAccess::Verified));
        assert_eq!(
            validate(two.clone()).map(|record| record.id()),
            Err(RecordRefusal::RankTopologyNotSettings {
                rank_topology: 1,
                tensor_parallel_size: 2
            })
        );
        let hardware = two.binding.hardware.clone();
        two.binding = ProfileBinding {
            hardware,
            ..with_model(logical_spec(), |execution| {
                execution.topology = RankTopology::new(2, 1, 1).unwrap()
            })
        };
        // The proof ran on one GPU, not on this two-GPU hardware class.
        assert_eq!(
            validate(two.clone()).map(|record| record.id()),
            Err(RecordRefusal::ProofNotAboutProfile {
                operation: OperationId::new("op-load").unwrap(),
                field: ProofField::Gpus
            })
        );
        two.proof = proof_with(|record| {
            if let Measured::Measured { value } = &mut record.host.gpus {
                value.push(value[0].clone());
            }
        });
        assert!(validate(two).is_ok());
    }

    #[test]
    fn strict_inputs_refuse_unknown_fields() {
        assert!(serde_json::from_str::<GateResult>(r#"{"gate":"not_applicable"}"#).is_ok());
        assert!(
            serde_json::from_str::<GateResult>(r#"{"gate":"not_applicable","report":"00"}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<QualificationHost>(r#"{"host":"owner_machine","why":1}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<Origin>(r#"{"origin":"qualified","source":"x"}"#).is_err());
        assert!(serde_json::from_str::<Prerequisite>(
            r#"{"prerequisite":"peer_access_verified","bytes":1}"#
        )
        .is_err());
        assert!(serde_json::from_str::<Cleanup>(r#"{"cleanup":"not_recorded","x":0}"#).is_err());
        assert!(serde_json::from_str::<Review>(r#"{"review":"pending","by":"x"}"#).is_err());
        assert_eq!(
            serde_json::to_string(&GateResult::NotMeasured).unwrap(),
            r#"{"gate":"not_measured"}"#
        );
    }
}
