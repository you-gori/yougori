//! Builders shared by this module's tests.

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU32, NonZeroU64};
use std::sync::Arc;
use std::time::Duration;

use chrono::NaiveDate;

use super::drafting::DraftingMatrix;
use super::formats::{CheckResult, KvFormatQualification};
use super::guard::AuthorityRecord;
use super::record::{
    Cleanup, ModelBinding, OfferedCapabilities, Origin, Parsers, ProfileBinding, ProfileDraft,
    ProfileProof, Qualification, QualificationHost, Qualifications, RecordRefusal,
    ResourceContract, ServingProfileRecord,
};
use super::selection::{
    CheckpointCompatibility, KvCacheSupport, ProfiledFootprint, RequestMix, ToolCalls,
};
use super::settings::{
    ComputeCapability, EngineRef, GraphMode, HardwareClass, MemoryFraction, PeerAccess, PeerLink,
    PeerPath, PeerTopology, ServingSettings,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    AdmittedRuntime, Backend, BackendModeRules, BackendRelease, Capability, ClockSession,
    ConfigurationFingerprint, GpuDeviceSubject, LoaderGate, LoaderRequest, Observation,
    ProbeRegistry, RuntimeOffer, RuntimeProfile, RuntimeRequirement, RuntimeSettings,
    RuntimeSubject, SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{
    digest, ContentKey, Digest, ExecutionCategory, ExecutionId, ManualClock, MonotonicTime,
    OperationId,
};
use crate::foundation::report::{
    AnswerVerdict, ArrivalMode, AttemptIdentity, AttemptRole, BenchId, BuildIdentity, CacheTier,
    ClientDescription, ClientPlacement, ClockId, ColdProvenance, CommitHash, CpuDescription,
    Disclosure, EngineIdentity, EventKind, EventRecorder, FailureKind as RunFailure, FixtureFamily,
    FixtureRef, GpuDescription, HostDescription, IntervalKind, Label as ReportLabel,
    LaunchDescription, LoadDescription, Measured, ModelAtArrival, ModelIdentity, ModelRevision,
    NonNegative, NonceDisclosure, NotMeasuredReason, Offload, Outcome, PowerSource, Precision,
    PrefillMode, ReasoningCheck, ReasoningTrace, RecordedEvent, RunMeasurements, RunRecord,
    RunSubstrate, Sampling, Scenario, SchemaVersion, StartState, StartTemperature, Workload,
};
use crate::model_memory::backends::{
    BackendRuntime, ComputePlatform, ExperimentApproval, PinnedCapabilities, QueriedCapabilities,
    Technique,
};
use crate::model_memory::identity::{
    AccuracyEvaluation, AdapterRecipe, Approximation, CodePolicy, CommitId, CompileConfiguration,
    Dtype, ExecutionSpec, FidelityConfiguration, ImmutableRevision, KvRepresentation, Label,
    LogicalModelIdentity, LogicalModelSpec, Quantization, QuantizationScheme, RankTopology,
    RelativePath, SourceFile, SourceLocation, SourceSpec, VersionedName,
};

pub const GIB: u64 = 1 << 30;
pub const HOUR: Duration = Duration::from_secs(3600);

pub fn d(label: &str) -> Digest {
    digest("yougori/test/profiles/v1", &[label.as_bytes()])
}

fn label(value: &str) -> Label {
    Label::new(value).unwrap()
}

fn versioned(name: &str, version: &str) -> VersionedName {
    VersionedName::new(name, version).unwrap()
}

/// A BF16 checkpoint at a pinned commit.
pub fn source_spec() -> SourceSpec {
    SourceSpec {
        location: SourceLocation::Repository {
            host: label("huggingface.co"),
            repository: label("example-org/example-8b"),
        },
        revision: ImmutableRevision::Commit(
            CommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap(),
        ),
        files: vec![
            SourceFile {
                path: RelativePath::new("model.safetensors").unwrap(),
                length_bytes: 16 * GIB,
                content: ContentKey::of(b"weights"),
            },
            SourceFile {
                path: RelativePath::new("tokenizer.json").unwrap(),
                length_bytes: 9_000_000,
                content: ContentKey::of(b"tokenizer"),
            },
        ],
        configuration: d("model configuration"),
        published_dtype: Dtype::BFloat16,
        license: label("apache-2.0"),
        provenance: None,
    }
}

/// The checkpoint served in BF16, unquantized, with its own tokenizer.
pub fn logical_spec() -> LogicalModelSpec {
    LogicalModelSpec {
        source: source_spec().identity().unwrap(),
        dtype: Dtype::BFloat16,
        quantization: Quantization::None,
        tokenizer: d("tokenizer"),
        generation_config: d("generation config"),
        adapters: AdapterRecipe::None,
        code_policy: CodePolicy::BuiltInOnly,
    }
}

pub fn logical() -> LogicalModelIdentity {
    logical_spec().identity()
}

/// `logical` on vLLM 0.29.0, one rank, eager, for sm_89.
pub fn execution_spec_for(logical: LogicalModelIdentity) -> ExecutionSpec {
    ExecutionSpec {
        logical,
        runner: versioned("vllm", "0.29.0"),
        architecture_adapter: versioned("llama", "1"),
        kernel_layout: versioned("flash-attn", "2.7.4"),
        gpu_architectures: BTreeSet::from([label("sm_89")]),
        topology: RankTopology::SINGLE,
        processed_weights: versioned("vllm-bf16", "1"),
        compile: CompileConfiguration::Eager,
    }
}

pub fn model_binding() -> ModelBinding {
    ModelBinding::new(logical_spec(), execution_spec_for(logical())).unwrap()
}

pub fn engine() -> EngineRef {
    EngineRef {
        release: BackendRelease::new(Backend::Vllm, "0.29.0").unwrap(),
        image: d("vllm image"),
    }
}

/// KV in `dtype`, quantized by `quantization`, 16 tokens per block in vLLM's paged layout.
pub fn kv(dtype: Dtype, quantization: Quantization) -> KvRepresentation {
    KvRepresentation::new(dtype, quantization, 16, versioned("vllm-paged", "0.29.0")).unwrap()
}

/// KV in the model's own BF16.
pub fn model_kv() -> KvRepresentation {
    kv(Dtype::BFloat16, Quantization::None)
}

fn kv_scheme(name: &str, bits: u8) -> QuantizationScheme {
    QuantizationScheme::new(versioned(name, "1"), bits, None, d(name)).unwrap()
}

pub fn fp8_kv() -> KvRepresentation {
    kv(
        Dtype::Float8E4M3,
        Quantization::Scheme(kv_scheme("fp8-e4m3-kv", 8)),
    )
}

pub fn fp4_kv() -> KvRepresentation {
    kv(
        Dtype::Float4E2M1,
        Quantization::Scheme(kv_scheme("nvfp4-kv", 4)),
    )
}

pub fn lossless() -> FidelityConfiguration {
    FidelityConfiguration::lossless_representation()
}

/// A configuration that allows exactly the quantization of `kv`, with its accuracy
/// evaluation.
pub fn allowing(kv: &KvRepresentation) -> FidelityConfiguration {
    let Quantization::Scheme(scheme) = kv.quantization().clone() else {
        panic!("only a quantized KV representation has a scheme to allow");
    };
    FidelityConfiguration::approximate_inference(BTreeMap::from([(
        Approximation::Quantization(scheme),
        AccuracyEvaluation {
            report: d("accuracy evaluation"),
        },
    )]))
    .unwrap()
}

pub fn session() -> ClockSession {
    ClockSession::from_uuid(uuid::Uuid::from_u128(1))
}

pub fn configuration() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_digest(d("configuration"))
}

pub fn device(index: u32) -> GpuDeviceSubject {
    GpuDeviceSubject {
        machine: d("machine"),
        device: d(&format!("gpu {index}")),
    }
}

pub fn single_gpu() -> HardwareClass {
    HardwareClass {
        gpu_name: "NVIDIA GeForce RTX 4090".to_owned(),
        gpu_count: 1,
        memory_bytes_per_gpu: 24 * GIB,
        compute_capability: ComputeCapability { major: 8, minor: 9 },
        topology: PeerTopology::single().identity(),
    }
}

pub fn two_gpu_topology(access: PeerAccess) -> PeerTopology {
    PeerTopology {
        device_count: 2,
        paths: vec![
            PeerPath {
                from: 0,
                to: 1,
                link: PeerLink::PcieHostBridge,
                access,
            },
            PeerPath {
                from: 1,
                to: 0,
                link: PeerLink::PcieHostBridge,
                access,
            },
        ],
    }
}

/// Two of the same card as [`single_gpu`], connected as `topology` says.
pub fn two_gpus(topology: &PeerTopology) -> HardwareClass {
    HardwareClass {
        gpu_count: 2,
        topology: topology.identity(),
        ..single_gpu()
    }
}

/// A probe's observation that a serving fact holds with `detail`, under the test
/// configuration, fresh for an hour.
pub fn measured(detail: SupportDetail) -> Observation {
    Observation::supported(configuration(), HOUR, detail)
}

/// What a probe of `capability` from `source` observes on `subject`.
#[derive(Clone)]
pub struct Script {
    pub capability: Capability,
    pub source: SourceClass,
    pub subject: Subject,
    pub observation: Observation,
}

/// Checkpoint compatibility of [`logical`] on [`engine`] and `hardware`, naming `record`.
pub fn compatibility_script(hardware: &HardwareClass, record: Digest) -> Script {
    Script {
        capability: Capability::CheckpointCompatibility,
        source: SourceClass::HostProbe,
        subject: Subject::ModelCheckpoint(CheckpointCompatibility::subject(
            &logical(),
            &engine(),
            hardware,
        )),
        observation: measured(SupportDetail::CheckpointCompatibility { record }),
    }
}

/// The host's measurement of `device`'s free and total memory.
pub fn free_memory_script(device: GpuDeviceSubject, free_bytes: u64, total_bytes: u64) -> Script {
    Script {
        capability: Capability::GpuFreeMemory,
        source: SourceClass::HostProbe,
        subject: Subject::GpuDevice(device),
        observation: measured(SupportDetail::GpuMemory {
            free_bytes,
            total_bytes: NonZeroU64::new(total_bytes).unwrap(),
        }),
    }
}

/// The measured peer topology of `runtime`'s GPUs.
pub fn topology_script(runtime: RuntimeSubject, topology: &PeerTopology) -> Script {
    Script {
        capability: Capability::PeerTopology,
        source: SourceClass::HostProbe,
        subject: Subject::Runtime(runtime),
        observation: measured(SupportDetail::PeerTopology {
            device_count: NonZeroU32::new(topology.device_count).unwrap(),
            paths: topology.paths.clone(),
        }),
    }
}

/// A CORE-01 registry on `clock` holding every script, observed now. Each capability and
/// source has its own probe, which observes only its scripted subjects.
pub fn registry_with(
    clock: Arc<ManualClock>,
    scripts: &[Script],
) -> ProbeRegistry<Arc<ManualClock>> {
    let mut probes: BTreeMap<(Capability, SourceClass), FakeProbe> = BTreeMap::new();
    for script in scripts {
        probes
            .entry((script.capability, script.source))
            .or_insert_with(|| FakeProbe::new(script.capability, script.source).scripted_only())
            .respond(&script.subject, script.observation.clone());
    }
    let mut registry = ProbeRegistry::new(clock);
    for probe in probes.into_values() {
        registry.register(Box::new(probe)).unwrap();
    }
    for script in scripts {
        registry
            .refresh(script.capability, &script.subject)
            .unwrap();
    }
    registry
}

/// 32,768 positions; measured footprints of 18 GiB (piecewise graphs, 8,192 tokens),
/// 17 GiB (piecewise, 2,048) and 15 GiB (eager, 2,048); KV of 128 KiB per token in BF16
/// and 64 KiB in FP8; tool calls through the hermes parser.
pub fn compatibility() -> CheckpointCompatibility {
    CheckpointCompatibility {
        max_position_tokens: 32_768,
        footprints: vec![
            ProfiledFootprint {
                graph_mode: GraphMode::PiecewiseCudaGraphs,
                max_num_batched_tokens: 8_192,
                non_kv_bytes_per_device: 18 * GIB,
            },
            ProfiledFootprint {
                graph_mode: GraphMode::PiecewiseCudaGraphs,
                max_num_batched_tokens: 2_048,
                non_kv_bytes_per_device: 17 * GIB,
            },
            ProfiledFootprint {
                graph_mode: GraphMode::Eager,
                max_num_batched_tokens: 2_048,
                non_kv_bytes_per_device: 15 * GIB,
            },
        ],
        kv_caches: vec![
            KvCacheSupport {
                representation: model_kv(),
                bytes_per_token_per_device: 128 * 1024,
            },
            KvCacheSupport {
                representation: fp8_kv(),
                bytes_per_token_per_device: 64 * 1024,
            },
        ],
        tool_calls: ToolCalls::Preserved {
            parser: "hermes".to_owned(),
        },
    }
}

/// A mix without tools under a lossless configuration.
pub fn mix(max_request_tokens: u32, concurrent_sequences: u32) -> RequestMix {
    RequestMix {
        max_request_tokens,
        concurrent_sequences,
        tool_calls: false,
        fidelity: lossless(),
    }
}

/// Every line 248 check passed for `kv` with [`logical`] on [`engine`].
pub fn qualification(kv: KvRepresentation) -> KvFormatQualification {
    let passed = CheckResult::Passed {
        report: d("line 248 report"),
    };
    KvFormatQualification {
        model: logical(),
        engine: engine(),
        kv,
        per_model_support: passed,
        numerical_behavior: passed,
        cache_format: passed,
        rollback: passed,
    }
}

/// Eager, one sequence, 2,048 batched tokens, BF16 KV, 32,768 tokens, one GPU at 0.90.
pub fn settings() -> ServingSettings {
    ServingSettings {
        graph_mode: GraphMode::Eager,
        max_num_seqs: 1,
        max_num_batched_tokens: 2_048,
        kv_cache: model_kv(),
        context_tokens: 32_768,
        tensor_parallel_size: 1,
        gpu_memory: MemoryFraction::new(900).unwrap(),
        nccl: None,
        drafting: None,
    }
}

pub fn binding() -> ProfileBinding {
    ProfileBinding {
        model: model_binding(),
        engine: engine(),
        launcher: d("launcher"),
        parsers: Parsers {
            tool_call: Some("hermes".to_owned()),
            reasoning: None,
        },
        hardware: single_gpu(),
        driver: "580.95.05".to_owned(),
        resources: ResourceContract {
            gpu_memory_bytes_per_device: 22 * GIB,
            host_memory_bytes: 32 * GIB,
            pinned_host_bytes: 4 * GIB,
            cpu_millicores: 8_000,
        },
    }
}

/// A CORE-08 label.
pub fn tag(value: &str) -> ReportLabel {
    ReportLabel::new(value).unwrap()
}

/// One request on a manual clock: accepted, dequeued 5 ms later, then `tokens` tokens,
/// the first 100 ms after dequeue and each next one `gap_millis` later.
fn request_events(operation: &OperationId, tokens: u32, gap_millis: u64) -> Vec<RecordedEvent> {
    let clock = ManualClock::new(MonotonicTime::from_nanos(5_000_000_000));
    let mut recorder = EventRecorder::new(
        operation.clone(),
        ClockId::new(tag("host-monotonic")),
        &clock,
    );
    recorder.record(EventKind::RequestAccepted);
    clock.advance(Duration::from_millis(5));
    recorder.record(EventKind::RequestDequeued);
    for token in 0..tokens {
        let after = if token == 0 { 100 } else { gap_millis };
        clock.advance(Duration::from_millis(after));
        recorder.record(EventKind::TokenEmitted);
    }
    clock.advance(Duration::from_millis(1));
    recorder.record(EventKind::RequestCompleted);
    recorder.into_events()
}

fn not_measured<T>(reason: NotMeasuredReason) -> Measured<T> {
    Measured::not_measured(reason)
}

/// A successful attempt of [`draft`]'s qualification run on an authorized disposable
/// machine: in the shared-kernel runtime, with [`engine`]'s release and image, driver
/// 580.95.05, one 24 GiB GPU, [`logical_spec`]'s tokenizer and BF16 KV, with four
/// concurrent requests. It has no events or workload yet.
fn attempt(operation: &str, scenario: Scenario, state: StartState) -> RunRecord {
    RunRecord {
        schema_version: SchemaVersion,
        attempt: AttemptIdentity {
            bench: BenchId::Bench01,
            variant: tag("profile-qualification"),
            execution: ExecutionId::new("exe-qualification-1").unwrap(),
            operation: OperationId::new(operation).unwrap(),
            role: AttemptRole::Initial,
            burst: 0,
            deadline_nanos: not_measured(NotMeasuredReason::NotApplicable),
        },
        scenario,
        substrate: RunSubstrate::AuthorizedDisposable {
            authorization: tag("qualification-run-1"),
        },
        build: BuildIdentity {
            plan: d("plan"),
            runner_build: d("runner build"),
            runner_version: tag("1.0.0"),
        },
        execution_category: ExecutionCategory::SharedKernelGpuRuntime,
        model: Measured::measured(ModelIdentity {
            revision: ModelRevision::Commit {
                hash: CommitHash::new("0123456789abcdef0123456789abcdef01234567").unwrap(),
            },
            licenses: vec![tag("Apache-2.0")],
            weights: d("weights"),
            tokenizer: d("tokenizer"),
            chat_template: d("chat template"),
        }),
        precision: Measured::measured(Precision {
            weight_dtype: tag("bf16"),
            quantization: tag("none"),
            kv_cache_dtype: tag("bf16"),
        }),
        engine: Measured::measured(EngineIdentity {
            name: tag("vllm"),
            version: tag("0.29.0"),
        }),
        host: HostDescription {
            os: tag("linux"),
            os_version: tag("6.8.0"),
            cpu: CpuDescription {
                model: tag("amd-epyc-9354"),
                logical_cores: 32,
            },
            host_memory_bytes: 64 * GIB,
            gpus: Measured::measured(vec![GpuDescription {
                model: tag("nvidia-geforce-rtx-4090"),
                memory_bytes: 24 * GIB,
            }]),
            gpu_driver: Measured::measured(tag("580.95.05")),
            gpu_power_clock: not_measured(NotMeasuredReason::InstrumentUnavailable),
            power_source: Measured::measured(PowerSource::Ac),
            displays_on_gpu: Measured::measured(0),
        },
        workload: not_measured(NotMeasuredReason::NotApplicable),
        client: ClientDescription {
            name: tag("yougori-bench-client"),
            version: tag("1.0.0"),
            region: tag("local"),
            placement: ClientPlacement::SameHost,
        },
        load: LoadDescription {
            concurrent_requests: 4,
            arrival: ArrivalMode::Burst { size: 4 },
        },
        state: Measured::measured(state),
        launch: LaunchDescription {
            image: d("vllm image"),
            backend: tag("cuda"),
        },
        price: not_measured(NotMeasuredReason::NotApplicable),
        measurements: RunMeasurements {
            output_tokens: not_measured(NotMeasuredReason::NotApplicable),
            prefill_tokens_per_second: not_measured(NotMeasuredReason::NotRecorded),
            aggregate_decode_tokens_per_second: not_measured(NotMeasuredReason::NotRecorded),
            speculative: not_measured(NotMeasuredReason::NotApplicable),
            peak_gpu_memory_bytes: not_measured(NotMeasuredReason::NotRecorded),
            retained_gpu_memory_bytes: not_measured(NotMeasuredReason::NotRecorded),
            peak_host_memory_bytes: not_measured(NotMeasuredReason::NotRecorded),
            retained_host_memory_bytes: not_measured(NotMeasuredReason::NotRecorded),
            peak_pinned_host_memory_bytes: not_measured(NotMeasuredReason::NotRecorded),
            transferred_bytes: not_measured(NotMeasuredReason::NotRecorded),
            storage_read_bytes: not_measured(NotMeasuredReason::NotRecorded),
            energy_joules: not_measured(NotMeasuredReason::InstrumentUnavailable),
            offload: Measured::measured(Offload::NoOffload),
            first_run: not_measured(NotMeasuredReason::NotApplicable),
            owner_return: not_measured(NotMeasuredReason::NotApplicable),
            reasoning: not_measured(NotMeasuredReason::NotApplicable),
        },
        events: Vec::new(),
        outcome: Outcome::Succeeded,
    }
}

/// `record` emitting `tokens` tokens `gap_millis` apart: three tokens 80 ms apart decode
/// at 12.5 tokens/s per user.
pub fn paced(mut record: RunRecord, tokens: u32, gap_millis: u64) -> RunRecord {
    record.events = request_events(&record.attempt.operation, tokens, gap_millis);
    record.measurements.output_tokens = Measured::measured(u64::from(tokens));
    record
}

/// A successful hot request of `family`: 512 tokens in, at most 128 out, three tokens
/// out 80 ms apart.
pub fn serving_attempt(operation: &str, family: FixtureFamily) -> RunRecord {
    let state = StartState {
        temperature: StartTemperature::Hot,
        model_at_arrival: ModelAtArrival::ReadyToServe,
        cache_tier: CacheTier::NoReusableState,
        prefill: PrefillMode::Fresh,
        cold_provenance: ColdProvenance::NotCold,
    };
    let mut record = attempt(operation, Scenario::Serving, state);
    record.workload = Measured::measured(Workload {
        fixture: FixtureRef::new(
            tag(&format!("{operation}-fixture")),
            d(operation),
            Disclosure::PermittedSynthetic,
        ),
        family,
        input_tokens: 512,
        max_output_tokens: 128,
        sampling: Sampling {
            temperature: NonNegative::ZERO,
            top_p: not_measured(NotMeasuredReason::NotApplicable),
            top_k: not_measured(NotMeasuredReason::NotApplicable),
            seed: Measured::measured(7),
        },
        tool_schema: not_measured(NotMeasuredReason::NotApplicable),
        paired: false,
        cold_test_nonce: NonceDisclosure::NotUsed,
    });
    paced(record, 3, 80)
}

/// The workload of a serving attempt, to change it.
pub fn workload_of(record: &mut RunRecord) -> &mut Workload {
    match &mut record.workload {
        Measured::Measured { value } => value,
        Measured::NotMeasured { .. } => panic!("only a serving attempt has a workload"),
    }
}

/// A successful tool request with its tool schema.
pub fn tool_attempt(operation: &str) -> RunRecord {
    let mut record = serving_attempt(operation, FixtureFamily::Tool);
    workload_of(&mut record).tool_schema = Measured::measured(FixtureRef::new(
        tag("tool-schema"),
        d("tool schema"),
        Disclosure::PermittedSynthetic,
    ));
    record
}

/// A successful reasoning request: its trace was separated from a final answer that
/// matched the fixture's answer key.
pub fn reasoning_attempt(operation: &str) -> RunRecord {
    checked(
        serving_attempt(operation, FixtureFamily::Reasoning),
        ReasoningTrace::Present {
            tokens: Measured::measured(40),
        },
        AnswerVerdict::Correct,
    )
}

/// `record` with a reasoning check of `trace` and `final_answer`.
pub fn checked(
    mut record: RunRecord,
    trace: ReasoningTrace,
    final_answer: AnswerVerdict,
) -> RunRecord {
    record.measurements.reasoning = Measured::measured(ReasoningCheck {
        answer_key: FixtureRef::new(
            tag("answer-key"),
            d("answer key"),
            Disclosure::PermittedSynthetic,
        ),
        trace,
        final_answer,
    });
    record
}

/// A successful long-context request whose input and output budget fill 16,384 tokens.
pub fn context_attempt(operation: &str) -> RunRecord {
    let mut record = serving_attempt(operation, FixtureFamily::LongContext);
    workload_of(&mut record).input_tokens = 16_384 - 128;
    record
}

/// The §2.1 ready-latency stage from a cold disposable machine: ready 40 s after
/// activation was requested.
pub fn load_attempt(operation: &str) -> RunRecord {
    let state = StartState {
        temperature: StartTemperature::Cold,
        model_at_arrival: ModelAtArrival::NotLoaded,
        cache_tier: CacheTier::NoReusableState,
        prefill: PrefillMode::Fresh,
        cold_provenance: ColdProvenance::DisposableEnvironment,
    };
    let scenario = Scenario::Stages {
        primary: IntervalKind::ReadyLatency,
    };
    let mut record = attempt(operation, scenario, state);
    let clock = ManualClock::new(MonotonicTime::from_nanos(5_000_000_000));
    let mut recorder = EventRecorder::new(
        record.attempt.operation.clone(),
        ClockId::new(tag("host-monotonic")),
        &clock,
    );
    recorder.record(EventKind::ActivationRequested);
    clock.advance(Duration::from_secs(40));
    recorder.record(EventKind::EngineReadyForShape);
    record.events = recorder.into_events();
    record
}

/// `record` failed: it completed, and its result failed validation.
pub fn failed(mut record: RunRecord) -> RunRecord {
    record.outcome = Outcome::Failed {
        failure: RunFailure::InvalidResult,
        component: tag("validator"),
        code: tag("fixture-mismatch"),
    };
    record
}

/// A successful first retry of the serving attempt `first`.
pub fn retry_of(first: &RunRecord, operation: &str) -> RunRecord {
    let mut retry = first.clone();
    retry.attempt.operation = OperationId::new(operation).unwrap();
    retry.attempt.role = AttemptRole::Retry {
        first_attempt: first.attempt.operation.clone(),
        retry_number: 1,
    };
    retry.outcome = Outcome::Succeeded;
    paced(retry, 3, 80)
}

/// The qualification run of [`draft`]: the ready-latency stage, a code request, a tool
/// request and a long-context request filling its context.
pub fn qualification_attempts() -> Vec<RunRecord> {
    vec![
        load_attempt("op-load"),
        serving_attempt("op-chat", FixtureFamily::Code),
        tool_attempt("op-tools"),
        context_attempt("op-context"),
    ]
}

pub fn proof_of(records: Vec<RunRecord>) -> ProfileProof {
    ProfileProof::new(records).unwrap()
}

/// The qualification run as [`draft`]'s proof.
pub fn proof() -> ProfileProof {
    proof_of(qualification_attempts())
}

/// The qualification run with every attempt changed by `change`.
pub fn proof_with(change: impl Fn(&mut RunRecord)) -> ProfileProof {
    let mut records = qualification_attempts();
    records.iter_mut().for_each(change);
    proof_of(records)
}

/// The qualification run in `category`.
pub fn proof_in(category: ExecutionCategory) -> ProfileProof {
    proof_with(|record| record.execution_category = category)
}

/// A profile proven on 27 October 2026 in the shared-kernel runtime: piecewise graphs,
/// 4 sequences, 8,192 batched tokens and 16,384 tokens of context, offering chat and
/// tools and not reasoning, at 12.5 tokens/s per user against a declared 10.
pub fn draft() -> ProfileDraft {
    ProfileDraft {
        binding: binding(),
        settings: ServingSettings {
            graph_mode: GraphMode::PiecewiseCudaGraphs,
            max_num_seqs: 4,
            max_num_batched_tokens: 8_192,
            context_tokens: 16_384,
            ..settings()
        },
        qualification: Qualification {
            host: QualificationHost::DisposableMachine {
                authorization: d("authorization"),
            },
            execution_category: ExecutionCategory::SharedKernelGpuRuntime,
            cleanup: Cleanup::Completed {
                report: d("cleanup"),
            },
        },
        proof_date: NaiveDate::from_ymd_opt(2026, 10, 27).unwrap(),
        proof: proof(),
        offers: OfferedCapabilities {
            chat: true,
            reasoning: false,
            tools: true,
        },
        minimum_per_user_tokens_per_second: 10.0,
        prerequisites: Vec::new(),
        origin: Origin::Qualified,
    }
}

/// Validates against no KV qualifications and an empty drafting matrix.
pub fn validate(draft: ProfileDraft) -> Result<ServingProfileRecord, RecordRefusal> {
    let matrix = DraftingMatrix::default();
    ServingProfileRecord::validate(
        draft,
        Qualifications {
            kv_formats: &[],
            drafting: &matrix,
        },
    )
}

/// The runtime of `category` that runs [`engine`]'s release.
pub fn runtime(category: ExecutionCategory) -> RuntimeSubject {
    RuntimeSubject {
        category,
        release: engine().release,
        instance: d(category.label()),
    }
}

pub fn start_clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(MonotonicTime::from_nanos(30_000_000_000)))
}

/// A registry on `clock` whose host probe has confirmed the category of each runtime.
pub fn registry_on(
    clock: Arc<ManualClock>,
    runtimes: &[RuntimeSubject],
) -> ProbeRegistry<Arc<ManualClock>> {
    let probe = FakeProbe::runtime_category(SourceClass::HostProbe);
    for runtime in runtimes {
        probe.respond(
            &Subject::Runtime(runtime.clone()),
            Observation::supported(
                configuration(),
                HOUR,
                SupportDetail::RuntimeCategory {
                    category: runtime.category,
                },
            ),
        );
    }
    let mut registry = ProbeRegistry::new(clock);
    registry.register(Box::new(probe)).unwrap();
    for runtime in runtimes {
        registry
            .refresh(
                Capability::RuntimeCategory,
                &Subject::Runtime(runtime.clone()),
            )
            .unwrap();
    }
    registry
}

/// `runtime`, offered with host evidence of its category.
pub fn offer_for(runtime: RuntimeSubject) -> RuntimeOffer {
    let registry = registry_on(start_clock(), std::slice::from_ref(&runtime));
    RuntimeOffer::observe(&registry, runtime, HOUR, configuration()).unwrap()
}

pub fn offer(category: ExecutionCategory) -> RuntimeOffer {
    offer_for(runtime(category))
}

/// `runtime`, admitted by a request that allows exactly its category.
pub fn admitted_runtime(runtime: RuntimeSubject) -> AdmittedRuntime {
    let requirement = if runtime.category.is_vm_sandbox() {
        RuntimeRequirement::VmSandbox
    } else {
        RuntimeRequirement::explicit([runtime.category]).unwrap()
    };
    requirement.admit(&offer_for(runtime)).unwrap()
}

pub fn admitted(category: ExecutionCategory) -> AdmittedRuntime {
    admitted_runtime(runtime(category))
}

/// `runtime` as the backend gate knows it: on CUDA, with the ordinary loader the gate
/// planned and the pinned release's queried capabilities (no sleep levels or features).
pub fn backend_for(runtime: RuntimeSubject) -> BackendRuntime {
    let registry = registry_on(start_clock(), &[]);
    let profile = RuntimeProfile {
        runtime,
        configuration: configuration(),
        permitted: BTreeMap::new(),
    };
    let plan = LoaderGate::recorded()
        .plan(&profile, &LoaderRequest::default(), &registry)
        .unwrap();
    let rules = BackendModeRules::recorded();
    let pinned = PinnedCapabilities::new(
        QueriedCapabilities {
            release: profile.runtime.release.clone(),
            source: SourceClass::HostProbe,
            sleep_levels: BTreeMap::new(),
            features: BTreeSet::new(),
        },
        &rules,
    )
    .unwrap();
    BackendRuntime::new(&profile, ComputePlatform::Cuda, &plan, &rules, pinned).unwrap()
}

/// The shared-kernel runtime's backend gate.
pub fn backend_runtime() -> BackendRuntime {
    backend_for(runtime(ExecutionCategory::SharedKernelGpuRuntime))
}

/// An approval of `technique` on [`engine`]'s release.
pub fn approval(technique: Technique) -> ExperimentApproval {
    ExperimentApproval {
        technique,
        release: engine().release,
        record: d("experiment plan"),
    }
}

/// Approvals of CUDA graphs and concurrency on [`engine`]'s release.
pub fn approvals() -> Vec<ExperimentApproval> {
    vec![
        approval(Technique::CudaGraphs),
        approval(Technique::Concurrency),
    ]
}

/// A request that allows the shared-kernel GPU runtime only.
pub fn labelled_requirement() -> RuntimeRequirement {
    RuntimeRequirement::explicit([ExecutionCategory::SharedKernelGpuRuntime]).unwrap()
}

/// The parent execution the fake authority record holds settings under.
pub fn parent_execution() -> ExecutionId {
    ExecutionId::new("exe-parent-1").unwrap()
}

/// The coordination authority's record, as a fake: the settings it authorizes for one
/// model under one parent execution.
pub struct FakeAuthority {
    pub execution: ExecutionId,
    pub model: Digest,
    pub settings: RuntimeSettings,
}

impl FakeAuthority {
    /// `settings`, authorized for `d("model")` under [`parent_execution`].
    pub fn of(settings: RuntimeSettings) -> Self {
        Self {
            execution: parent_execution(),
            model: d("model"),
            settings,
        }
    }
}

/// The fake authority holds no settings for that model under that parent.
#[derive(Debug, PartialEq, Eq)]
pub struct NotAuthorized;

impl AuthorityRecord for FakeAuthority {
    type Model = Digest;
    type Refusal = NotAuthorized;

    fn authorized_settings(
        &self,
        execution: &ExecutionId,
        model: &Digest,
    ) -> Result<RuntimeSettings, NotAuthorized> {
        if *execution == self.execution && *model == self.model {
            Ok(self.settings.clone())
        } else {
            Err(NotAuthorized)
        }
    }
}
