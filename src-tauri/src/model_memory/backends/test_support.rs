//! Fixtures for this module's tests: fake guest-report probes on a manual clock, loader
//! plans made by evidence's own gate, compute-platform evidence, and queried
//! capabilities.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use super::capabilities::{
    KvRetention, LevelSemantics, PinnedCapabilities, QueriedCapabilities, SleepLevel,
    WeightRetention,
};
use super::declarations::{ComputePlatform, PinnedFeature, Technique};
use super::runtime::{
    AdmittedTechnique, BackendRuntime, ExperimentApproval, RuntimeRefusal, SleepPlan, SleepRefusal,
    TechniqueRefusal, VLLM_0_31_0_SLEEP_DOC,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    self, Backend, BackendModeRule, BackendModeRules, BackendRelease, Capability,
    ConfigurationFingerprint, EvidencePolicy, LoaderGate, LoaderPlan, LoaderRequest, ModePair,
    Necessity, Observation, Optimization, ProbeRegistry, RuntimeProfile, RuntimeSubject,
    ShareableHandle, SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{digest, ContentKey, ExecutionCategory, ManualClock, MonotonicTime};
use crate::model_memory::residency::eviction::{
    Content, CopyTier, ReconstructibleCopy, Verification,
};

/// How long fake observations stay fresh, and the evidence policy's maximum age.
const FRESH_FOR: Duration = Duration::from_secs(600);

/// How long compute-platform observations stay fresh, and the platform policy's maximum
/// age: longer than the modes', so a mode's evidence can lapse while the platform's holds.
pub(super) const PLATFORM_FRESH_FOR: Duration = Duration::from_secs(3_600);

/// A probe registry on a shared manual clock.
pub(super) type Registry = ProbeRegistry<Arc<ManualClock>>;

pub(super) fn release(backend: Backend, version: &str) -> BackendRelease {
    BackendRelease::new(backend, version).unwrap()
}

/// The vLLM release model_server.py pins today (GPU part §1.2; Appendix A.1).
pub(super) fn vllm_0_29_0() -> BackendRelease {
    release(Backend::Vllm, "0.29.0")
}

/// The upgrade candidate whose preload daemon is documented (GPU part §1.2).
pub(super) fn vllm_0_31_0() -> BackendRelease {
    release(Backend::Vllm, "0.31.0")
}

/// The pinned llama.cpp build (Appendix A.1).
pub(super) fn llama_cpp() -> BackendRelease {
    release(Backend::LlamaCpp, "b11425")
}

/// The Transformers version model_server.py pins.
pub(super) fn transformers() -> BackendRelease {
    release(Backend::Transformers, "5.18.0")
}

/// The content of the weights that tests put to sleep.
pub(super) fn weights() -> Content {
    Content::Immutable(ContentKey::of(b"weights"))
}

/// A copy of `weights()` in local storage, verified for exactly that content: one that
/// reconstructs them.
pub(super) fn local_copy() -> ReconstructibleCopy {
    ReconstructibleCopy {
        tier: CopyTier::LocalStorage,
        verification: Verification::Verified { content: weights() },
    }
}

pub(super) fn runtime_subject(release: &BackendRelease, instance: &str) -> RuntimeSubject {
    RuntimeSubject {
        category: ExecutionCategory::SharedKernelGpuRuntime,
        release: release.clone(),
        instance: digest("yougori/test/instance/v1", &[instance.as_bytes()]),
    }
}

pub(super) fn configuration() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("launch", "test")]).unwrap()
}

/// The platform policy of test runtimes: a guest report at most an hour old.
pub(super) fn platform_policy() -> EvidencePolicy {
    EvidencePolicy {
        minimum_source: SourceClass::GuestReport,
        max_age: PLATFORM_FRESH_FOR,
    }
}

/// What a fake probe of a runtime on `platform` observes; nothing on an unknown platform.
pub(super) fn observed(platform: ComputePlatform) -> Option<evidence::ComputePlatform> {
    match platform {
        ComputePlatform::Cuda => Some(evidence::ComputePlatform::Cuda),
        ComputePlatform::Metal => Some(evidence::ComputePlatform::Metal),
        ComputePlatform::Cpu => Some(evidence::ComputePlatform::Cpu),
        ComputePlatform::Other => None,
    }
}

/// `release`'s own rule table recording discard-mode sleep beside offloading and
/// zero-copy preload, the two sleep modes tested together (the recorded preload conflict
/// is merged in by evidence).
pub(super) fn discard_sleep_rules(release: &BackendRelease) -> BackendModeRules {
    BackendModeRules::new([BackendModeRule {
        release: release.clone(),
        supported: [
            Optimization::ZeroCopyPreload,
            Optimization::SleepWeightOffload,
            Optimization::SleepWeightDiscard,
        ]
        .into(),
        tested_together: [ModePair::new(
            Optimization::SleepWeightOffload,
            Optimization::SleepWeightDiscard,
        )
        .unwrap()]
        .into(),
        conflicts: Vec::new(),
    }])
    .unwrap()
}

/// A profile for `runtime` that permits `permitted` on guest-report evidence.
pub(super) fn profile(runtime: &RuntimeSubject, permitted: &[Optimization]) -> RuntimeProfile {
    RuntimeProfile {
        runtime: runtime.clone(),
        configuration: configuration(),
        permitted: permitted
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
    }
}

/// The detail a supported observation of `optimization` carries on `release`; every
/// optimization is named, so one evidence adds gets a detail here before tests use it.
fn detail(optimization: Optimization, release: &BackendRelease) -> SupportDetail {
    match optimization {
        Optimization::CudaIpcLegacy => SupportDetail::CudaIpcLegacy,
        Optimization::CudaIpcVmmShareableHandle => SupportDetail::CudaIpcVmmShareableHandle {
            handle: ShareableHandle::PosixFileDescriptor,
        },
        Optimization::ZeroCopyPreload
        | Optimization::SleepWeightOffload
        | Optimization::SleepWeightDiscard => SupportDetail::BackendMode {
            release: release.clone(),
        },
        Optimization::ExecuteWhileLoad => SupportDetail::ExecuteWhileLoad,
        Optimization::GpuDirectStorage | Optimization::CudaCheckpoint | Optimization::IoUring => {
            SupportDetail::Plain
        }
    }
}

/// Evidence, from fake guest-report probes, that each of `supported` works on each of
/// `runtimes` under the test configuration, and that each computes on CUDA, with the
/// registry's clock.
pub(super) fn evidence(
    runtimes: &[&RuntimeSubject],
    supported: &[Optimization],
) -> (Registry, Arc<ManualClock>) {
    evidence_on(runtimes, supported, Some(evidence::ComputePlatform::Cuda))
}

/// [`evidence`], with each runtime observed computing on `platform`, or no
/// compute-platform evidence at all for `None`.
pub(super) fn evidence_on(
    runtimes: &[&RuntimeSubject],
    supported: &[Optimization],
    platform: Option<evidence::ComputePlatform>,
) -> (Registry, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1)));
    let mut registry = ProbeRegistry::new(Arc::clone(&clock));
    if let Some(platform) = platform {
        let probe = Arc::new(FakeProbe::guest_report(Capability::ComputePlatform));
        for runtime in runtimes {
            probe.respond(
                &Subject::Runtime((*runtime).clone()),
                Observation::supported(
                    configuration(),
                    PLATFORM_FRESH_FOR,
                    SupportDetail::ComputePlatform { platform },
                ),
            );
        }
        registry.register(Box::new(Arc::clone(&probe))).unwrap();
        for runtime in runtimes {
            registry
                .refresh(
                    Capability::ComputePlatform,
                    &Subject::Runtime((*runtime).clone()),
                )
                .unwrap();
        }
    }
    for &optimization in supported {
        let probe = Arc::new(FakeProbe::guest_report(optimization.capability()));
        for runtime in runtimes {
            probe.respond(
                &Subject::Runtime((*runtime).clone()),
                Observation::supported(
                    configuration(),
                    FRESH_FOR,
                    detail(optimization, &runtime.release),
                ),
            );
        }
        registry.register(Box::new(Arc::clone(&probe))).unwrap();
        for runtime in runtimes {
            registry
                .refresh(
                    optimization.capability(),
                    &Subject::Runtime((*runtime).clone()),
                )
                .unwrap();
        }
    }
    (registry, clock)
}

/// The gate's plan for `profile`, with every `requested` optimization optional.
pub(super) fn loader_plan(
    gate: &LoaderGate,
    profile: &RuntimeProfile,
    registry: &Registry,
    requested: &[Optimization],
) -> LoaderPlan {
    let request = LoaderRequest {
        optimizations: requested
            .iter()
            .map(|&optimization| (optimization, Necessity::Optional))
            .collect(),
    };
    gate.plan(profile, &request, registry).unwrap()
}

/// vLLM's two levels as its unversioned sleep documentation describes them: level 1
/// offloads the weights to host memory and discards the KV cache, level 2 discards both.
/// Tests use them as a queried answer; the module itself records no semantics.
pub(super) fn documented_vllm_levels() -> BTreeMap<SleepLevel, LevelSemantics> {
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

/// A guest-report answer from `release`.
pub(super) fn answer(
    release: BackendRelease,
    levels: BTreeMap<SleepLevel, LevelSemantics>,
    features: &[PinnedFeature],
) -> QueriedCapabilities {
    QueriedCapabilities {
        release,
        source: SourceClass::GuestReport,
        sleep_levels: levels,
        features: features.iter().copied().collect(),
    }
}

/// Capabilities accepted under the recorded mode rules.
pub(super) fn pinned(
    release: BackendRelease,
    levels: BTreeMap<SleepLevel, LevelSemantics>,
    features: &[PinnedFeature],
) -> PinnedCapabilities {
    PinnedCapabilities::new(
        answer(release, levels, features),
        &BackendModeRules::recorded(),
    )
    .unwrap()
}

/// One runtime under test. The profile permits `modes`, the fakes report them supported
/// and the load asks for each as optional; the pinned release reports `levels` (by
/// default vLLM's documented ones where the rules record sleep for the release) and
/// `features`. The runtime has the test platform policy, and a fake probe observes it on
/// its platform.
pub(super) struct Fixture {
    release: BackendRelease,
    instance: &'static str,
    platform: ComputePlatform,
    modes: Vec<Optimization>,
    levels: Option<BTreeMap<SleepLevel, LevelSemantics>>,
    features: Vec<PinnedFeature>,
    rules: BackendModeRules,
    citation: Option<&'static str>,
}

impl Fixture {
    pub(super) fn new(release: BackendRelease) -> Self {
        Self {
            release,
            instance: "instance",
            platform: ComputePlatform::Cuda,
            modes: Vec::new(),
            levels: None,
            features: Vec::new(),
            rules: BackendModeRules::recorded(),
            citation: None,
        }
    }

    /// vLLM 0.31.0 with both sleep modes, on its own rule table that records discarding,
    /// cited to the sleep documentation.
    pub(super) fn discarding() -> Self {
        let release = vllm_0_31_0();
        Self::new(release.clone())
            .rules(discard_sleep_rules(&release))
            .modes(&[
                Optimization::SleepWeightOffload,
                Optimization::SleepWeightDiscard,
            ])
            .cite(VLLM_0_31_0_SLEEP_DOC)
    }

    /// Names the runtime instance, so two fixtures are two runtimes.
    pub(super) fn instance(mut self, instance: &'static str) -> Self {
        self.instance = instance;
        self
    }

    pub(super) fn on(mut self, platform: ComputePlatform) -> Self {
        self.platform = platform;
        self
    }

    pub(super) fn modes(mut self, modes: &[Optimization]) -> Self {
        self.modes = modes.to_vec();
        self
    }

    pub(super) fn levels(mut self, levels: BTreeMap<SleepLevel, LevelSemantics>) -> Self {
        self.levels = Some(levels);
        self
    }

    pub(super) fn features(mut self, features: &[PinnedFeature]) -> Self {
        self.features = features.to_vec();
        self
    }

    pub(super) fn rules(mut self, rules: BackendModeRules) -> Self {
        self.rules = rules;
        self
    }

    /// Cites `source` for the rule table's discard-mode sleep.
    pub(super) fn cite(mut self, source: &'static str) -> Self {
        self.citation = Some(source);
        self
    }

    /// The gate's plan for this runtime.
    pub(super) fn plan(&self) -> LoaderPlan {
        self.prepare().1
    }

    pub(super) fn pinned(&self) -> PinnedCapabilities {
        let levels = match &self.levels {
            Some(levels) => levels.clone(),
            None if self
                .rules
                .check_mode(&self.release, Optimization::SleepWeightOffload)
                .is_ok() =>
            {
                documented_vllm_levels()
            }
            None => BTreeMap::new(),
        };
        PinnedCapabilities::new(
            answer(self.release.clone(), levels, &self.features),
            &self.rules,
        )
        .unwrap()
    }

    /// The runtime, with the registry and clock its plan was made with.
    pub(super) fn build(&self) -> Result<Loaded, RuntimeRefusal> {
        let (profile, plan, registry, clock) = self.prepare();
        let mut runtime =
            BackendRuntime::new(&profile, self.platform, &plan, &self.rules, self.pinned())?
                .with_platform_policy(platform_policy());
        if let Some(source) = self.citation {
            runtime = runtime.cite_discard_sleep(source)?;
        }
        Ok(Loaded {
            runtime,
            registry,
            clock,
        })
    }

    /// The runtime with neither a platform policy nor a citation: its platform is only
    /// declared.
    pub(super) fn declared(&self) -> Result<Loaded, RuntimeRefusal> {
        let (profile, plan, registry, clock) = self.prepare();
        let runtime =
            BackendRuntime::new(&profile, self.platform, &plan, &self.rules, self.pinned())?;
        Ok(Loaded {
            runtime,
            registry,
            clock,
        })
    }

    fn prepare(&self) -> (RuntimeProfile, LoaderPlan, Registry, Arc<ManualClock>) {
        let subject = runtime_subject(&self.release, self.instance);
        let profile = profile(&subject, &self.modes);
        let (registry, clock) = evidence_on(&[&subject], &self.modes, observed(self.platform));
        let plan = loader_plan(
            &LoaderGate::new(self.rules.clone()),
            &profile,
            &registry,
            &self.modes,
        );
        (profile, plan, registry, clock)
    }
}

/// A runtime with the registry and clock its plan was made with.
pub(super) struct Loaded {
    pub(super) runtime: BackendRuntime,
    pub(super) registry: Registry,
    pub(super) clock: Arc<ManualClock>,
}

impl Loaded {
    /// Plans sleep at `level` for `weights()`, against the plan's own registry.
    pub(super) fn sleep(
        &self,
        level: u8,
        copy: Option<ReconstructibleCopy>,
    ) -> Result<SleepPlan, SleepRefusal> {
        self.runtime
            .plan_sleep(SleepLevel::new(level), weights(), copy, &self.registry)
    }

    /// Admits `technique`, rechecking its evidence against the plan's own registry.
    pub(super) fn admit_rechecked(
        &self,
        technique: Technique,
        approvals: &[ExperimentApproval],
    ) -> Result<AdmittedTechnique, TechniqueRefusal> {
        self.runtime
            .admit_with_evidence(technique, approvals, &self.registry)
    }
}

impl fmt::Debug for Loaded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Loaded")
            .field("runtime", &self.runtime)
            .finish_non_exhaustive()
    }
}

impl Deref for Loaded {
    type Target = BackendRuntime;

    fn deref(&self) -> &BackendRuntime {
        &self.runtime
    }
}
