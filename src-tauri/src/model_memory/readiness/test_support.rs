//! Shared test values: exact model identities, a four-model fake runner profile, and a
//! backend runtime assembled through evidence's own gate from fake guest-report probes.
//! The numbers are illustrative parameters of a fake, not measurements of any engine.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    self, Backend, BackendModeRule, BackendModeRules, BackendRelease, Capability,
    ConfigurationFingerprint, EvidencePolicy, LoaderGate, LoaderRequest, ModePair, Necessity,
    Observation, Optimization, ProbeRegistry, RuntimeProfile, RuntimeSubject, ShareableHandle,
    SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{
    digest, ContentKey, ExecutionCategory, ExecutionId, ManualClock, MonotonicTime,
};
use crate::foundation::report::Label;
use crate::model_memory::backends::{
    BackendRuntime, ComputePlatform, KvRetention, LevelSemantics, PinnedCapabilities,
    PinnedFeature, QueriedCapabilities, SleepLevel, WeightRetention, VLLM_0_31_0_SLEEP_DOC,
};
use crate::model_memory::bench::load::RunnerFactory;
use crate::model_memory::bench::profile::{
    FakeHost, ModelSpec, ModelTimings, ProcessFootprint, RunnerMode, RunnerProfile, RunnerTimings,
    ServingCosts,
};
use crate::model_memory::bench::resources::ResourceSnapshot;
use crate::model_memory::bench::rng::Variation;
use crate::model_memory::identity::{
    AdapterRecipe, CodePolicy, CompileConfiguration, Dtype, ExecutionIdentity, ExecutionSpec,
    ImmutableRevision, Label as IdentityLabel, LogicalModelSpec, Quantization, RankTopology,
    RelativePath, SourceFile, SourceLocation, SourceSpec, VersionedName,
};
use crate::model_memory::readiness::intent::PrepareTarget;
use crate::model_memory::residency::eviction::Content;
use crate::model_memory::residency::eviction::{CopyTier, ReconstructibleCopy, Verification};

pub(crate) const SECOND: u64 = 1_000_000_000;
pub(crate) const MILLIS: u64 = 1_000_000;
pub(crate) const GB: u64 = 1_000_000_000;

pub(crate) fn at(seconds: u64) -> MonotonicTime {
    MonotonicTime::from_nanos(seconds * SECOND)
}

pub(crate) fn label(value: &str) -> Label {
    Label::new(value).unwrap()
}

/// The exact execution identity of a fake model named `name`.
pub(crate) fn execution_identity(name: &str) -> ExecutionIdentity {
    let text = |value: &str| IdentityLabel::new(value).unwrap();
    let source = SourceSpec {
        location: SourceLocation::Local { name: text(name) },
        revision: ImmutableRevision::FileDigests,
        files: vec![SourceFile {
            path: RelativePath::new("model.safetensors").unwrap(),
            length_bytes: 1,
            content: ContentKey::of(name.as_bytes()),
        }],
        configuration: digest("yougori/test/readiness/config/v1", &[name.as_bytes()]),
        published_dtype: Dtype::BFloat16,
        license: text("apache-2.0"),
        provenance: None,
    }
    .identity()
    .unwrap();
    let logical = LogicalModelSpec {
        source,
        dtype: Dtype::BFloat16,
        quantization: Quantization::None,
        tokenizer: digest("yougori/test/readiness/tokenizer/v1", &[name.as_bytes()]),
        generation_config: digest("yougori/test/readiness/generation/v1", &[b"default"]),
        adapters: AdapterRecipe::None,
        code_policy: CodePolicy::BuiltInOnly,
    }
    .identity();
    ExecutionSpec {
        logical,
        runner: VersionedName::new("vllm", "0.31.0").unwrap(),
        architecture_adapter: VersionedName::new("llama", "1").unwrap(),
        kernel_layout: VersionedName::new("default", "1").unwrap(),
        gpu_architectures: BTreeSet::from([text("sm_90")]),
        topology: RankTopology::SINGLE,
        processed_weights: VersionedName::new("bf16", "1").unwrap(),
        compile: CompileConfiguration::Eager,
    }
    .identity()
    .unwrap()
}

pub(crate) fn target(name: &str) -> PrepareTarget {
    PrepareTarget {
        model: execution_identity(name),
        adapter: None,
    }
}

/// The content of model `name`'s weights.
pub(crate) fn weights(name: &str) -> ContentKey {
    ContentKey::of(format!("weights of {name}").as_bytes())
}

/// A copy of `content` in `tier`, verified for exactly that content.
pub(crate) fn verified(tier: CopyTier, content: ContentKey) -> ReconstructibleCopy {
    ReconstructibleCopy {
        tier,
        verification: Verification::Verified {
            content: Content::Immutable(content),
        },
    }
}

fn model(name: &str, weights_bytes: u64, timings: [u64; 7]) -> ModelSpec {
    let [cold, warm, read, sleep, wake, unload, capture] = timings;
    ModelSpec {
        name: label(name),
        weights_bytes,
        kv_bytes_per_token: 131_072,
        layer_groups: 4,
        cuda_graphs: 8,
        communicators: 1,
        weight_allocations: 4,
        weight_dtype: label("bf16"),
        quantization: label("none"),
        kv_cache_dtype: label("bf16"),
        timings: ModelTimings {
            cold_load_nanos: cold * MILLIS,
            warm_load_nanos: warm * MILLIS,
            host_read_nanos: read * MILLIS,
            sleep_nanos: sleep * MILLIS,
            wake_nanos: wake * MILLIS,
            unload_nanos: unload * MILLIS,
            graph_capture_nanos: capture * MILLIS,
        },
    }
}

/// Four models on a 24 GB GPU with 7 GB/s storage, 100 GB/s host memory channels and
/// 25 GB/s each way over PCIe; every duration is above its GPU §2.2 bound, with no
/// variation, leak or corruption.
pub(crate) fn profile(mode: RunnerMode) -> RunnerProfile {
    RunnerProfile {
        mode,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        category: ExecutionCategory::SharedKernelGpuRuntime,
        models: vec![
            model("model-a", 8 * GB, [1_500, 400, 1_200, 350, 350, 50, 300]),
            model("model-b", 6 * GB, [1_000, 300, 900, 250, 250, 40, 250]),
            model("model-c", 4 * GB, [800, 250, 650, 200, 200, 30, 200]),
            model("model-d", 7 * GB, [1_300, 350, 1_050, 300, 300, 45, 280]),
        ],
        runner: RunnerTimings {
            engine_startup_nanos: 2_000 * MILLIS,
            process_exit_nanos: 100 * MILLIS,
            hot_dispatch_nanos: 2 * MILLIS,
        },
        footprint: ProcessFootprint {
            context_vram_bytes: GB / 2,
            rss_bytes: 2 * GB,
            file_descriptors: 64,
            kv_pool_allocations: 1,
        },
        serving: ServingCosts {
            max_num_seqs: 16,
            max_queue_depth: 256,
            prefill_nanos_per_token: 20_000,
            decode_step_base_nanos: 10 * MILLIS,
            decode_step_per_sequence_nanos: 200_000,
            decode_nanos_per_kibitoken_context: 50_000,
            prefix_caching: true,
        },
        host: FakeHost {
            vram_capacity_bytes: 24 * GB,
            pinned_host_capacity_bytes: 32 * GB,
            host_memory_bytes: 64 * GB,
            storage_read_bytes_per_second: 7e9,
            host_memory_bytes_per_second: 100e9,
            host_to_device_bytes_per_second: 25e9,
            device_to_host_bytes_per_second: 25e9,
        },
        leak_per_switch: ResourceSnapshot::ZERO,
        corrupt_state_after_switches: None,
        execute_while_load: false,
        deterministic_outputs: true,
        variation: Variation::NONE,
    }
}

/// A factory over `profile` on a manual clock that starts at 1 s.
pub(crate) fn factory(profile: RunnerProfile, seed: u64) -> RunnerFactory {
    RunnerFactory {
        profile,
        rules: BackendModeRules::recorded(),
        clock: Arc::new(ManualClock::new(MonotonicTime::from_nanos(SECOND))),
        seed,
        execution: ExecutionId::new("exe-readiness-p12").unwrap(),
    }
}

/// vLLM's two documented levels as a queried answer: level 1 offloads the weights and
/// discards KV, level 2 discards both.
pub(crate) fn documented_vllm_levels() -> BTreeMap<SleepLevel, LevelSemantics> {
    BTreeMap::from([
        (
            SleepLevel::new(1),
            LevelSemantics {
                weights: WeightRetention::OffloadedToHost,
                kv_cache: KvRetention::Discarded,
            },
        ),
        (
            SleepLevel::new(2),
            LevelSemantics {
                weights: WeightRetention::Discarded,
                kv_cache: KvRetention::Discarded,
            },
        ),
    ])
}

/// A runtime with the registry its loader plan was made with.
pub(crate) struct Loaded {
    pub(crate) runtime: BackendRuntime,
    pub(crate) registry: ProbeRegistry<Arc<ManualClock>>,
}

/// A hypothetical rule table in which vLLM 0.31.0 also supports sleep weight discard,
/// tested together with sleep weight offload. No release records discard today; tests
/// that need the clean-drop sleep route use this table, and say so.
pub(crate) fn discard_rules() -> BackendModeRules {
    BackendModeRules::new([BackendModeRule {
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        supported: BTreeSet::from([
            Optimization::ZeroCopyPreload,
            Optimization::SleepWeightOffload,
            Optimization::SleepWeightDiscard,
        ]),
        tested_together: BTreeSet::from([ModePair::new(
            Optimization::SleepWeightOffload,
            Optimization::SleepWeightDiscard,
        )
        .unwrap()]),
        conflicts: Vec::new(),
    }])
    .unwrap()
}

/// The support detail CORE-01 requires of each optimization; exhaustive, so a new
/// optimization must be given its own detail here.
fn detail(optimization: Optimization, release: &BackendRelease) -> SupportDetail {
    match optimization {
        Optimization::CudaIpcLegacy => SupportDetail::CudaIpcLegacy,
        Optimization::CudaIpcVmmShareableHandle => SupportDetail::CudaIpcVmmShareableHandle {
            handle: ShareableHandle::PosixFileDescriptor,
        },
        Optimization::IoUring | Optimization::GpuDirectStorage | Optimization::CudaCheckpoint => {
            SupportDetail::Plain
        }
        Optimization::ZeroCopyPreload
        | Optimization::SleepWeightOffload
        | Optimization::SleepWeightDiscard => SupportDetail::BackendMode {
            release: release.clone(),
        },
        Optimization::ExecuteWhileLoad => SupportDetail::ExecuteWhileLoad,
    }
}

/// A runtime of `release` under `rules` whose profile permits `modes`, which fake
/// guest-report probes report supported, and whose pinned release reports `levels` and
/// `features`.
pub(crate) fn runtime(
    release: BackendRelease,
    rules: BackendModeRules,
    modes: &[Optimization],
    levels: BTreeMap<SleepLevel, LevelSemantics>,
    features: &[PinnedFeature],
) -> Loaded {
    const FRESH_FOR: Duration = Duration::from_secs(600);
    let subject = RuntimeSubject {
        category: ExecutionCategory::SharedKernelGpuRuntime,
        release: release.clone(),
        instance: digest("yougori/test/readiness/instance/v1", &[b"instance"]),
    };
    let configuration = ConfigurationFingerprint::from_settings([("launch", "test")]).unwrap();
    let profile = RuntimeProfile {
        runtime: subject.clone(),
        configuration: configuration.clone(),
        permitted: modes
            .iter()
            .map(|&optimization| {
                (
                    optimization,
                    EvidencePolicy {
                        minimum_source: SourceClass::GuestReport,
                        max_age: FRESH_FOR,
                    },
                )
            })
            .collect(),
    };
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1)));
    let mut registry = ProbeRegistry::new(Arc::clone(&clock));
    for &optimization in modes {
        let probe = Arc::new(FakeProbe::guest_report(optimization.capability()));
        probe.respond(
            &Subject::Runtime(subject.clone()),
            Observation::supported(
                configuration.clone(),
                FRESH_FOR,
                detail(optimization, &release),
            ),
        );
        registry.register(Box::new(Arc::clone(&probe))).unwrap();
        registry
            .refresh(
                optimization.capability(),
                &Subject::Runtime(subject.clone()),
            )
            .unwrap();
    }
    // P06 integration: the runtime's CUDA platform is CORE-01 evidence, not a declaration.
    let platform = Arc::new(FakeProbe::guest_report(Capability::ComputePlatform));
    platform.respond(
        &Subject::Runtime(subject.clone()),
        Observation::supported(
            configuration.clone(),
            FRESH_FOR,
            SupportDetail::ComputePlatform {
                platform: evidence::ComputePlatform::Cuda,
            },
        ),
    );
    registry.register(Box::new(Arc::clone(&platform))).unwrap();
    registry
        .refresh(
            Capability::ComputePlatform,
            &Subject::Runtime(subject.clone()),
        )
        .unwrap();
    let request = LoaderRequest {
        optimizations: modes
            .iter()
            .map(|&optimization| (optimization, Necessity::Optional))
            .collect(),
    };
    let plan = LoaderGate::new(rules.clone())
        .plan(&profile, &request, &registry)
        .unwrap();
    let pinned = PinnedCapabilities::new(
        QueriedCapabilities {
            release,
            source: SourceClass::GuestReport,
            sleep_levels: levels,
            features: features.iter().copied().collect(),
        },
        &rules,
    )
    .unwrap();
    let mut runtime = BackendRuntime::new(&profile, ComputePlatform::Cuda, &plan, &rules, pinned)
        .unwrap()
        .with_platform_policy(EvidencePolicy {
            minimum_source: SourceClass::GuestReport,
            max_age: FRESH_FOR,
        });
    // A rule table that records discard-mode sleep cites the sleep documentation.
    if rules
        .check_mode(runtime.release(), Optimization::SleepWeightDiscard)
        .is_ok()
    {
        runtime = runtime.cite_discard_sleep(VLLM_0_31_0_SLEEP_DOC).unwrap();
    }
    Loaded { runtime, registry }
}

/// vLLM 0.31.0 under [`discard_rules`] with sleep weight offload and discard enabled and
/// both documented levels.
pub(crate) fn vllm_with_sleep() -> Loaded {
    runtime(
        BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        discard_rules(),
        &[
            Optimization::SleepWeightOffload,
            Optimization::SleepWeightDiscard,
        ],
        documented_vllm_levels(),
        &[PinnedFeature::StagedWake],
    )
}

/// vLLM 0.31.0 under the recorded rules, which do not record sleep weight discard: only
/// sleep weight offload is enabled.
pub(crate) fn vllm_recorded() -> Loaded {
    runtime(
        BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        BackendModeRules::recorded(),
        &[Optimization::SleepWeightOffload],
        documented_vllm_levels(),
        &[PinnedFeature::StagedWake],
    )
}
