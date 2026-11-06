//! The test world: a VM sandbox launched by the CORE-04 coordinator over the CORE-03
//! ledger, the governor over both, a catalog holding one base and three small artifacts,
//! one runner serving two adapter variants of the base, a transfer executor on one link
//! of 1,000 bytes of extent content per second and an API sink, all on one manual clock.
//!
//! Model A is the base with adapter A; model B is the same base with adapter B, and B
//! builds the shared rank layout from a raw checkpoint that A never needed.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use crate::foundation::coordination::{
    BootRequest, CapacityPort, Coordinator, LaunchOutcome, LaunchPlan, LedgerCapacity, ObservedVm,
    PerimeterId, PortFailure, PortOperation, Readiness, ReadinessReport, ReservationPriority,
    ResourceKind, RestoredVmReport, SandboxPort, SettingsGrant, SnapshotId, SnapshotManifest,
    VmInstanceId,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    AdmittedRuntime, ArtifactVerification, Backend, BackendRelease, Capability,
    ConfigurationFingerprint, HostSubject, Observation, ProbeRegistry,
    Residency as RuntimeResidency, RuntimeOffer, RuntimeRequirement, RuntimeSettings,
    RuntimeSubject, SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Clock, ContentKey, Digest, ExecutionCategory, ExecutionId,
    GpuDeviceKey, ManualClock, MonotonicTime, OperationId, PolicyEpoch, SandboxBootGeneration,
    TenantId, TrustScope,
};
use crate::foundation::ledger::{
    CapacityDeclaration, Ledger, LedgerConfig, Priority, QueueLimits, ReservationState,
};
use crate::model_memory::boundaries::fakes::{
    FakeApi, FakeCatalog, FakeExecutor, FakeModel, FakeRunner,
};
use crate::model_memory::boundaries::*;
use crate::model_memory::executor::SourceKind;
use crate::model_memory::graph::node::NodeKind;
use crate::model_memory::identity::fakes::GrantCatalog;
use crate::model_memory::identity::{
    AdapterRecipe, ArtifactIdentity, CodePolicy, CommitId, CompileConfiguration, Dtype,
    ExecutionIdentity, ExecutionSpec, GrantTerms, GrantedUse, ImmutableRevision, Label,
    LogicalModelSpec, Quantization, RankTopology, RelativePath, ScopedGrant, SourceFile,
    SourceIdentity, SourceLocation, SourceSpec, VersionedName,
};
use crate::model_memory::placement::{RequestShape, SupportedShape};

pub(super) const GIB: u64 = 1 << 30;
pub(super) const MIB: u64 = 1 << 20;
pub(super) const HOUR: Duration = Duration::from_secs(3_600);
/// The one transfer link moves 1,000 bytes of extent content per second.
pub(super) const LINK_BYTES_PER_SECOND: u64 = 1_000;
/// The sandbox owns 30 GiB of a 32 GiB GPU, 16 GiB of 64 GiB host RAM and 4 GiB of
/// 8 GiB pinned host RAM.
pub(super) const SANDBOX_VRAM_BYTES: u64 = 30 * GIB;
pub(super) const SANDBOX_HOST_RAM_BYTES: u64 = 16 * GIB;
pub(super) const SANDBOX_PINNED_BYTES: u64 = 4 * GIB;
pub(super) const SAFETY_RESERVE_BYTES: u64 = GIB;
/// The longest drain before a reload the governor's policy allows.
pub(super) const MAX_DRAIN: Duration = Duration::from_secs(120);
/// The largest shape the runner can be ready for with either model.
pub(super) const MAX_SHAPE: SupportedShape = SupportedShape {
    max_context_tokens: 8_192,
    max_batch_sequences: 4,
};
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

/// Node numbers shared by both models' declarations.
pub(super) const TOKENIZER: u32 = 1;
pub(super) const ENGINE: u32 = 2;
pub(super) const BASE_0: u32 = 3;
pub(super) const BASE_1: u32 = 4;
pub(super) const ADAPTER: u32 = 5;
pub(super) const GRAPH: u32 = 6;
pub(super) const LAYOUT: u32 = 7;
pub(super) const RAW: u32 = 8;

/// Model A's §2.7 demand: weights 8 GiB + 128 MiB (two base extents and the rank
/// layout), adapter 512 MiB, context 1 GiB, graph pool 256 MiB, KV 2 GiB and a 1 GiB
/// transition peak.
pub(super) const MODEL_DEMAND_BYTES: u64 = 12 * GIB + 896 * MIB;

/// Model A's immutable extents, the model's weights, each held apart from any activation
/// (GPU §2.7: shared weights count once): the rank layout, the adapter and the two base
/// extents.
pub(super) const MODEL_A_WEIGHTS: [u64; 4] = [128 * MIB, 512 * MIB, 4 * GIB, 4 * GIB];

/// Model A's weights together.
pub(super) const MODEL_A_WEIGHTS_BYTES: u64 = 8 * GIB + 640 * MIB;

/// What one activation of model A holds of its own beside the weights: context 1 GiB,
/// graph pool 256 MiB, KV 2 GiB and the 1 GiB transition peak.
pub(super) const MODEL_A_OWN_BYTES: u64 = MODEL_DEMAND_BYTES - MODEL_A_WEIGHTS_BYTES;

/// Model A's GPU holdings in use with `activations` of its own memory beside its weights,
/// smallest first, as [`World::holdings`] lists them.
pub(super) fn model_a_holdings(activations: usize) -> Vec<(u64, ReservationState)> {
    let mut holdings: Vec<(u64, ReservationState)> = MODEL_A_WEIGHTS
        .iter()
        .copied()
        .chain(std::iter::repeat_n(MODEL_A_OWN_BYTES, activations))
        .map(|bytes| (bytes, ReservationState::InUse))
        .collect();
    holdings.sort_by_key(|(bytes, _)| *bytes);
    holdings
}

pub(super) fn ms(millis: u64) -> Duration {
    Duration::from_millis(millis)
}

pub(super) fn seconds(at: MonotonicTime) -> f64 {
    at.as_nanos() as f64 / 1e9
}

pub(super) fn machine() -> Digest {
    digest("yougori/test/machine/v1", &[b"workstation"])
}

pub(super) fn gpu(index: u8) -> GpuDeviceKey {
    GpuDeviceKey {
        machine: machine(),
        device: digest("yougori/test/device/v1", &[&[index]]),
    }
}

pub(super) fn owner() -> ExecutionId {
    ExecutionId::new("exe-owner").unwrap()
}

pub(super) fn tenant() -> TenantId {
    TenantId::new("tenant-a").unwrap()
}

pub(super) fn op(name: &str) -> OperationId {
    OperationId::new(name).unwrap()
}

/// The sandbox's trust scope, where the runner's state lives.
pub(super) fn scope() -> TrustScope {
    TrustScope::named(ExecutionCategory::VmSandbox, "tenant-a/sandbox")
}

pub(super) fn runner_owner() -> PlacementOwner {
    PlacementOwner {
        device: gpu(0),
        instance: 1,
    }
}

pub(super) fn state(name: &str) -> StateIdentity {
    StateIdentity::from_digest(digest(
        "yougori/test/boundaries/state/v1",
        &[name.as_bytes()],
    ))
}

pub(super) fn shape(context_tokens: u64) -> RequestShape {
    RequestShape {
        context_tokens,
        batch_sequences: 1,
    }
}

/// A VM backend that boots at once and is always ready, observed by the host.
struct ReadyVms;

impl SandboxPort for ReadyVms {
    fn prepare_perimeter(&mut self, request: &BootRequest) -> Result<PerimeterId, PortFailure> {
        Ok(PerimeterId::new(digest(
            "yougori/test/perimeter/v1",
            &[request.execution.as_str().as_bytes()],
        )))
    }

    fn create_vm(
        &mut self,
        request: &BootRequest,
        _perimeter: &PerimeterId,
    ) -> Result<VmInstanceId, PortFailure> {
        Ok(VmInstanceId::new(digest(
            "yougori/test/vm/v1",
            &[request.execution.as_str().as_bytes()],
        )))
    }

    fn restore_vm(
        &mut self,
        _request: &BootRequest,
        _perimeter: &PerimeterId,
        _snapshot: &SnapshotManifest,
    ) -> Result<VmInstanceId, PortFailure> {
        Err(PortFailure {
            operation: PortOperation::RestoreVm,
            detail: "this backend does not restore".to_owned(),
        })
    }

    fn observe_readiness(
        &mut self,
        _vm: &VmInstanceId,
        _boot: SandboxBootGeneration,
    ) -> ReadinessReport {
        ReadinessReport {
            source: SourceClass::HostProbe,
            readiness: Readiness::Ready,
        }
    }

    fn inspect_restored_vm(
        &mut self,
        vm: &VmInstanceId,
        boot: SandboxBootGeneration,
    ) -> RestoredVmReport {
        RestoredVmReport {
            vm: *vm,
            boot,
            snapshot: SnapshotId::new(digest("yougori/test/snapshot/v1", &[b"none"])),
            guest_identity: digest("yougori/test/guest/v1", &[b"none"]),
            actions: BTreeSet::new(),
            attached_volumes: BTreeSet::new(),
            policy: PolicyEpoch::FIRST,
            image_profile: digest("yougori/test/image/v1", &[b"none"]),
            presented_epochs: BTreeSet::new(),
            source: SourceClass::HostProbe,
        }
    }

    fn terminate_vm(&mut self, _vm: &VmInstanceId) -> Result<(), PortFailure> {
        Ok(())
    }

    fn teardown_perimeter(&mut self, _perimeter: &PerimeterId) -> Result<(), PortFailure> {
        Ok(())
    }

    fn list_vms(&mut self) -> Result<Vec<ObservedVm>, PortFailure> {
        Ok(Vec::new())
    }
}

pub(super) type Host = Coordinator<Arc<ManualClock>, LedgerCapacity<Arc<ManualClock>>>;

/// The host's one ledger: a 32 GiB GPU, 64 GiB of host RAM and 8 GiB of pinned host RAM,
/// all of it in the tenant's budget.
pub(super) fn host_ledger(clock: &Arc<ManualClock>) -> Ledger<Arc<ManualClock>> {
    let mut ledger = Ledger::new(
        Arc::clone(clock),
        HostSubject { machine: machine() },
        LedgerConfig {
            queue: QueueLimits {
                max_entries: 8,
                max_entries_per_tenant: 4,
                max_wait: Duration::from_secs(60),
            },
            grant_ttl: Duration::from_secs(60),
            unmanaged_usage_max_age: Duration::from_secs(24 * 3_600),
        },
    );
    for (resource, total) in [
        (vram_key(gpu(0)), 32 * GIB),
        (HOST_RAM, 64 * GIB),
        (STAGING, 8 * GIB),
    ] {
        ledger
            .declare_capacity(
                resource,
                CapacityDeclaration {
                    total,
                    supervisor_reserve: 0,
                    unmanaged_in_use: 0,
                    source: SourceClass::HostProbe,
                },
            )
            .unwrap();
        ledger.set_tenant_budget(tenant(), resource, total).unwrap();
    }
    ledger
}

/// A registry that observed the VM runtime, and that runtime admitted as a VM sandbox.
pub(super) fn vm_runtime(
    clock: &Arc<ManualClock>,
) -> (ProbeRegistry<Arc<ManualClock>>, AdmittedRuntime) {
    let mut registry = ProbeRegistry::new(Arc::clone(clock));
    let probe = Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe));
    registry.register(Box::new(Arc::clone(&probe))).unwrap();
    let runtime = RuntimeSubject {
        category: ExecutionCategory::VmSandbox,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance: digest("yougori/test/instance/v1", &[b"vm-host"]),
    };
    let configuration =
        ConfigurationFingerprint::from_digest(digest("yougori/test/configuration/v1", &[b"vm"]));
    let subject = Subject::Runtime(runtime.clone());
    probe.respond(
        &subject,
        Observation::supported(
            configuration,
            HOUR,
            SupportDetail::RuntimeCategory {
                category: ExecutionCategory::VmSandbox,
            },
        ),
    );
    registry
        .refresh(Capability::RuntimeCategory, &subject)
        .unwrap();
    let offer = RuntimeOffer::observe(&registry, runtime, HOUR, configuration).unwrap();
    let admitted = RuntimeRequirement::VmSandbox.admit(&offer).unwrap();
    (registry, admitted)
}

/// Launches and starts the VM sandbox of `owner()` on `host`, holding its share of the
/// GPU, `host_ram_bytes` of host RAM and its share of pinned host RAM, its authority
/// granting its models `grant`; the runtime settings that authority allows.
pub(super) fn launch_sandbox<P: CapacityPort>(
    host: &mut Coordinator<Arc<ManualClock>, P>,
    registry: &ProbeRegistry<Arc<ManualClock>>,
    admitted: AdmittedRuntime,
    host_ram_bytes: u64,
    grant: SettingsGrant,
) -> RuntimeSettings {
    launch_sized_sandbox(
        host,
        registry,
        admitted,
        SANDBOX_VRAM_BYTES,
        host_ram_bytes,
        grant,
    )
}

/// [`launch_sandbox`] with `vram_bytes` of the GPU.
pub(super) fn launch_sized_sandbox<P: CapacityPort>(
    host: &mut Coordinator<Arc<ManualClock>, P>,
    registry: &ProbeRegistry<Arc<ManualClock>>,
    admitted: AdmittedRuntime,
    vram_bytes: u64,
    host_ram_bytes: u64,
    grant: SettingsGrant,
) -> RuntimeSettings {
    let plan = LaunchPlan {
        execution: owner(),
        tenant: tenant(),
        runtime: admitted,
        demand: BTreeMap::from([
            (ResourceKind::GpuMemoryBytes { device: gpu(0) }, vram_bytes),
            (ResourceKind::HostMemoryBytes, host_ram_bytes),
            (ResourceKind::PinnedHostMemoryBytes, SANDBOX_PINNED_BYTES),
        ]),
        priority: ReservationPriority::Foreground,
        authority_lifetime: 10 * HOUR,
        readiness_max_age: Duration::from_secs(5),
        runtime_evidence_max_age: HOUR,
    };
    let LaunchOutcome::AuthorityActive {
        grant: authority, ..
    } = host
        .launch_with(plan, grant, &mut ReadyVms, registry)
        .unwrap()
    else {
        panic!("the sandbox launches");
    };
    host.start_running(&owner()).unwrap();
    RuntimeSettings {
        execution_category: ExecutionCategory::VmSandbox,
        network: BTreeSet::new(),
        authority,
        artifact_verification: ArtifactVerification::Verified {
            artifacts: BTreeSet::new(),
        },
        loader: BTreeSet::new(),
        batch_size: NonZeroU32::new(8).unwrap(),
        residency: RuntimeResidency::Device,
    }
}

/// A launched, running VM sandbox of `owner()` with `vram_bytes` of the GPU and
/// `host_ram_bytes` of host RAM on a coordinator that owns the host's ledger, and the
/// runtime settings its authority allows.
pub(super) fn launch_sized(
    clock: &Arc<ManualClock>,
    vram_bytes: u64,
    host_ram_bytes: u64,
) -> (Host, RuntimeSettings) {
    let (registry, admitted) = vm_runtime(clock);
    let mut host = Coordinator::new(
        Arc::clone(clock),
        registry.session(),
        LedgerCapacity::new(host_ledger(clock)),
    );
    let settings = launch_sized_sandbox(
        &mut host,
        &registry,
        admitted,
        vram_bytes,
        host_ram_bytes,
        SettingsGrant::default(),
    );
    (host, settings)
}

fn label(value: &str) -> Label {
    Label::new(value).unwrap()
}

fn versioned(name: &str, version: &str) -> VersionedName {
    VersionedName::new(name, version).unwrap()
}

fn source_of(name: &str) -> SourceIdentity {
    SourceSpec {
        location: SourceLocation::Repository {
            host: label("huggingface.co"),
            repository: label(&format!("example-org/{name}")),
        },
        revision: ImmutableRevision::Commit(CommitId::new(COMMIT).unwrap()),
        files: vec![SourceFile {
            path: RelativePath::new("model.safetensors").unwrap(),
            length_bytes: 1_000,
            content: ContentKey::of(name.as_bytes()),
        }],
        configuration: digest("yougori/test/configuration/v1", &[name.as_bytes()]),
        published_dtype: Dtype::BFloat16,
        license: label("apache-2.0"),
        provenance: None,
    }
    .identity()
    .unwrap()
}

/// The T07 execution identity of `model` on one rank.
pub(super) fn execution_of(model: &str) -> ExecutionIdentity {
    let logical = LogicalModelSpec {
        source: source_of(model),
        dtype: Dtype::BFloat16,
        quantization: Quantization::None,
        tokenizer: digest("yougori/test/tokenizer/v1", &[model.as_bytes()]),
        generation_config: digest("yougori/test/generation/v1", &[model.as_bytes()]),
        adapters: AdapterRecipe::None,
        code_policy: CodePolicy::BuiltInOnly,
    }
    .identity();
    ExecutionSpec {
        logical,
        runner: versioned("vllm", "0.31.0"),
        architecture_adapter: versioned("llama", "1"),
        kernel_layout: versioned("flash-attn", "2.7.4"),
        gpu_architectures: BTreeSet::from([label("sm_90a")]),
        topology: RankTopology::new(1, 1, 1).unwrap(),
        processed_weights: versioned("vllm-bf16", "1"),
        compile: CompileConfiguration::Eager,
    }
    .identity()
    .unwrap()
}

/// Deterministic content of one extent; distinct for every name and extent.
pub(super) fn content(name: &str, extent: u32, length: usize) -> Vec<u8> {
    format!("{name}/{extent}/")
        .into_bytes()
        .into_iter()
        .cycle()
        .take(length)
        .collect()
}

pub(super) fn provenance(name: &str) -> Provenance {
    Provenance {
        source: digest("yougori/test/source/v1", &[name.as_bytes()]),
        revision: digest("yougori/test/revision/v1", &[COMMIT.as_bytes()]),
        license: Some(digest("yougori/test/license/v1", &[b"apache-2.0"])),
    }
}

/// Imports an artifact of extents with these lengths into the sandbox's scope.
pub(super) fn import(catalog: &mut FakeCatalog, name: &str, lengths: &[usize]) -> ArtifactIdentity {
    catalog
        .import(ImportSubmission {
            scope: scope(),
            provenance: provenance(name),
            extents: lengths
                .iter()
                .zip(0u32..)
                .map(|(length, index)| {
                    let bytes = content(name, index, *length);
                    ImportedExtent {
                        extent: ExtentId::new(index),
                        claimed_digest: ContentKey::of(&bytes),
                        content: bytes,
                    }
                })
                .collect(),
        })
        .unwrap()
}

pub(super) fn extent(artifact: ArtifactIdentity, index: u32) -> ExtentRef {
    ExtentRef {
        artifact,
        extent: ExtentId::new(index),
    }
}

pub(super) fn transfer(artifact: ArtifactIdentity, index: u32) -> Materialization {
    Materialization::Transfer {
        extents: vec![extent(artifact, index)],
    }
}

pub(super) fn node(
    id: u32,
    kind: NodeKind,
    name: &str,
    device_bytes: u64,
    estimate: Duration,
    depends_on: &[u32],
    materialization: Materialization,
) -> DependencyNode {
    DependencyNode {
        id: NodeId::new(id),
        kind,
        identity: state(name),
        scope: scope(),
        device_bytes,
        estimate,
        depends_on: depends_on.iter().map(|id| NodeId::new(*id)).collect(),
        materialization,
    }
}

pub(super) fn group(requires: &[u32], compute: Duration) -> ComputeGroup {
    ComputeGroup {
        requires: requires.iter().map(|id| NodeId::new(*id)).collect(),
        compute,
    }
}

pub(super) fn ids(values: &[u32]) -> Vec<NodeId> {
    values.iter().map(|id| NodeId::new(*id)).collect()
}

/// The artifacts and the two models of the world.
#[derive(Clone, Copy, Debug)]
pub(super) struct Scenario {
    pub base: ArtifactIdentity,
    pub adapter_a: ArtifactIdentity,
    pub adapter_b: ArtifactIdentity,
    pub raw: ArtifactIdentity,
    pub model_a: ExecutionIdentity,
    pub model_b: ExecutionIdentity,
}

/// The state both variants share: tokenizer, engine, two base extents and the graph.
fn shared_nodes(scenario: &Scenario) -> Vec<DependencyNode> {
    vec![
        node(
            TOKENIZER,
            NodeKind::TokenizerConfiguration,
            "tokenizer",
            0,
            ms(100),
            &[],
            Materialization::Reconstruct,
        ),
        node(
            ENGINE,
            NodeKind::EngineInitialization,
            "engine",
            GIB,
            ms(1_500),
            &[],
            Materialization::Reconstruct,
        ),
        node(
            BASE_0,
            NodeKind::ArtifactExtent,
            "base-0",
            4 * GIB,
            ms(2_000),
            &[],
            transfer(scenario.base, 0),
        ),
        node(
            BASE_1,
            NodeKind::ArtifactExtent,
            "base-1",
            4 * GIB,
            ms(2_000),
            &[],
            transfer(scenario.base, 1),
        ),
        node(
            GRAPH,
            NodeKind::GraphCapture,
            "graph",
            256 * MIB,
            ms(500),
            &[ENGINE, BASE_0, BASE_1],
            Materialization::Reconstruct,
        ),
    ]
}

fn computation() -> Vec<ComputeGroup> {
    vec![
        group(&[TOKENIZER, ENGINE, BASE_0, LAYOUT], ms(200)),
        group(&[BASE_1, ADAPTER, GRAPH], ms(300)),
    ]
}

/// Model A: the base with adapter A; the runner builds the rank layout itself.
pub(super) fn model_a_dependencies(scenario: &Scenario) -> ExecutionDependencies {
    let mut nodes = shared_nodes(scenario);
    nodes.push(node(
        ADAPTER,
        NodeKind::Adapter,
        "adapter-a",
        512 * MIB,
        ms(1_000),
        &[],
        transfer(scenario.adapter_a, 0),
    ));
    nodes.push(node(
        LAYOUT,
        NodeKind::RankLayout,
        "layout",
        128 * MIB,
        ms(300),
        &[],
        Materialization::Reconstruct,
    ));
    ExecutionDependencies {
        artifact: scenario.base,
        nodes,
        compute: computation(),
        response: ms(50),
        session_device_bytes: 2 * GIB,
        transition_peak_device_bytes: GIB,
    }
}

/// Model B: the base with adapter B; the same rank layout is built from a raw checkpoint.
pub(super) fn model_b_dependencies(scenario: &Scenario) -> ExecutionDependencies {
    let mut nodes = shared_nodes(scenario);
    nodes.push(node(
        ADAPTER,
        NodeKind::Adapter,
        "adapter-b",
        512 * MIB,
        ms(1_000),
        &[],
        transfer(scenario.adapter_b, 0),
    ));
    nodes.push(node(
        LAYOUT,
        NodeKind::RankLayout,
        "layout",
        128 * MIB,
        ms(300),
        &[RAW],
        Materialization::Reconstruct,
    ));
    nodes.push(node(
        RAW,
        NodeKind::ArtifactExtent,
        "raw",
        GIB,
        ms(1_000),
        &[],
        transfer(scenario.raw, 0),
    ));
    ExecutionDependencies {
        artifact: scenario.base,
        nodes,
        compute: computation(),
        response: ms(50),
        session_device_bytes: 2 * GIB,
        transition_peak_device_bytes: GIB,
    }
}

pub(super) fn policy() -> GovernorPolicy {
    GovernorPolicy {
        lease_duration: HOUR,
        cancel_within: Duration::from_secs(5),
        staging_cap_bytes: GIB,
        max_transfer_bytes: None,
        safety_reserve_bytes: SAFETY_RESERVE_BYTES,
        max_drain: MAX_DRAIN,
    }
}

/// Runs one request through the flow with the given governor, the runner admitted by
/// this build's native ABI.
pub(super) fn serve_through(
    clock: &ManualClock,
    catalog: &FakeCatalog,
    governor: &mut dyn PlacementGovernor,
    executor: &mut FakeExecutor,
    runner: &mut FakeRunner,
    api: &mut FakeApi,
    request: &ExactRequest,
) -> Result<ServeReceipt, FlowError> {
    let checked = NativeAbi::current()
        .admit(runner)
        .expect("the fake runner's native ABI is this build's");
    let mut boundaries = Boundaries {
        catalog,
        governor,
        executor,
        runners: vec![checked],
        api,
    };
    serve(clock, &mut boundaries, request)
}

pub(super) struct World {
    pub clock: Arc<ManualClock>,
    pub governor: LedgerPolicyGovernor<Arc<ManualClock>>,
    pub catalog: FakeCatalog,
    pub executor: FakeExecutor,
    pub runner: FakeRunner,
    pub api: FakeApi,
    pub scenario: Scenario,
    /// The CORE-02 catalog the sandbox owner's scoped grants are checked against.
    pub grants: GrantCatalog,
}

impl World {
    pub(super) fn new() -> Self {
        Self::with_policy(policy())
    }

    pub(super) fn with_policy(policy: GovernorPolicy) -> Self {
        Self::with_sandbox_host_ram(policy, SANDBOX_HOST_RAM_BYTES)
    }

    /// A world whose sandbox holds `host_ram_bytes` of host RAM.
    pub(super) fn with_sandbox_host_ram(policy: GovernorPolicy, host_ram_bytes: u64) -> Self {
        Self::with_sandbox(policy, SANDBOX_VRAM_BYTES, host_ram_bytes)
    }

    /// A world whose sandbox holds `vram_bytes` of the GPU and `host_ram_bytes` of host
    /// RAM.
    pub(super) fn with_sandbox(
        policy: GovernorPolicy,
        vram_bytes: u64,
        host_ram_bytes: u64,
    ) -> Self {
        let clock = Arc::new(ManualClock::new(MonotonicTime::ZERO));
        let grants = GrantCatalog::open(Arc::clone(&clock) as Arc<dyn Clock>, &[tenant()]);
        let (host, settings) = launch_sized(&clock, vram_bytes, host_ram_bytes);
        let mut governor = LedgerPolicyGovernor::new(host, Arc::clone(&clock), policy);
        governor.attach_runtime(
            runner_owner(),
            RuntimeBinding {
                execution: owner(),
                settings,
            },
        );
        let mut catalog = FakeCatalog::new();
        let scenario = Scenario {
            base: import(&mut catalog, "base", &[2_000, 2_000]),
            adapter_a: import(&mut catalog, "adapter-a", &[1_000]),
            adapter_b: import(&mut catalog, "adapter-b", &[1_000]),
            raw: import(&mut catalog, "raw", &[1_000]),
            model_a: execution_of("chat-a"),
            model_b: execution_of("chat-b"),
        };
        let mut executor = FakeExecutor::new(Arc::clone(&clock), LINK_BYTES_PER_SECOND);
        for (extent, bytes) in catalog.contents() {
            executor.add_source(*extent, bytes.clone(), SourceKind::LocalFile);
        }
        let mut runner = FakeRunner::new(
            Arc::clone(&clock),
            runner_owner(),
            scope(),
            ExecutionCategory::VmSandbox,
        );
        runner.add_model(
            scenario.model_a,
            FakeModel {
                dependencies: model_a_dependencies(&scenario),
                max_shape: MAX_SHAPE,
            },
        );
        runner.add_model(
            scenario.model_b,
            FakeModel {
                dependencies: model_b_dependencies(&scenario),
                max_shape: MAX_SHAPE,
            },
        );
        Self {
            clock,
            governor,
            catalog,
            executor,
            runner,
            api: FakeApi::default(),
            scenario,
            grants,
        }
    }

    /// The sandbox's current authorization epoch.
    pub(super) fn epoch(&self) -> AuthorizationEpoch {
        self.governor
            .coordinator()
            .sandbox(&owner())
            .map(|sandbox| sandbox.generations().authorization)
            .unwrap()
    }

    /// A self-grant to serve from resident state of `artifact` in the sandbox (S3.3: equal
    /// storage is never permission, even for the owner).
    pub(super) fn grant(&self, artifact: ArtifactIdentity) -> ScopedGrant {
        self.grants.scoped_grant(
            &owner(),
            GrantTerms {
                grantor: tenant(),
                grantee: tenant(),
                artifact,
                scope: scope(),
                uses: BTreeSet::from([GrantedUse::Serve]),
                expires_at: MonotonicTime::ZERO.saturating_add(10 * HOUR),
            },
        )
    }

    pub(super) fn request(&self, name: &str, model: ExecutionIdentity) -> ExactRequest {
        request_for(
            self.epoch(),
            name,
            model,
            vec![self.grant(self.scenario.base)],
        )
    }

    pub(super) fn serve(&mut self, request: &ExactRequest) -> Result<ServeReceipt, FlowError> {
        serve_through(
            &self.clock,
            &self.catalog,
            &mut self.governor,
            &mut self.executor,
            &mut self.runner,
            &mut self.api,
            request,
        )
    }

    pub(super) fn placement(&self, model: ExecutionIdentity) -> PlacementKey {
        placement_of(model)
    }

    /// The ledger reservation of the sandbox.
    pub(super) fn sandbox_reservation(&self) -> crate::foundation::ledger::ReservationId {
        let key = self
            .governor
            .coordinator()
            .sandbox(&owner())
            .and_then(|sandbox| sandbox.reservation())
            .unwrap();
        self.governor
            .coordinator()
            .capacity()
            .record(&key)
            .unwrap()
            .id()
    }

    /// Open reservations carved from the sandbox: each with its VRAM and pinned bytes,
    /// in the order granted.
    pub(super) fn children(&self) -> Vec<(u64, u64, ReservationState)> {
        let parent = self.sandbox_reservation();
        self.governor
            .ledger()
            .open_reservations()
            .filter(|record| record.parent() == Some(parent))
            .map(|record| {
                (
                    record.granted().get(vram_key(gpu(0))),
                    record.granted().get(STAGING),
                    record.state(),
                )
            })
            .collect()
    }

    /// The VRAM and state of every open reservation carved from the sandbox that holds
    /// VRAM, smallest first.
    pub(super) fn holdings(&self) -> Vec<(u64, ReservationState)> {
        let mut holdings: Vec<(u64, ReservationState)> = self
            .children()
            .into_iter()
            .filter(|(vram, _, _)| *vram > 0)
            .map(|(vram, _, state)| (vram, state))
            .collect();
        holdings.sort_by_key(|(bytes, _)| *bytes);
        holdings
    }

    /// VRAM the sandbox has not carved into children.
    pub(super) fn vram_room(&self) -> u64 {
        self.governor
            .ledger()
            .parent_room(self.sandbox_reservation(), vram_key(gpu(0)))
            .unwrap()
    }

    pub(super) fn open_reservations(&self) -> usize {
        self.governor.ledger().open_reservations().count()
    }
}

/// The placement of `model` in the one runner.
pub(super) fn placement_of(model: ExecutionIdentity) -> PlacementKey {
    PlacementKey {
        owner: runner_owner(),
        model,
    }
}

/// A request named `name` for `model` under `epoch`, in the sandbox's partition.
pub(super) fn request_for(
    epoch: AuthorizationEpoch,
    name: &str,
    model: ExecutionIdentity,
    grants: Vec<ScopedGrant>,
) -> ExactRequest {
    ExactRequest {
        context: RequestContext {
            execution: owner(),
            operation: op(name),
            tenant: tenant(),
            epoch,
            partition: SecurityPartition::new(scope()),
            grants,
        },
        intent: Intent {
            model,
            shape: shape(4_096),
            priority: Priority::Foreground,
            policy: RequestPolicy::default(),
        },
        payload: RequestPayload::new(format!("the prompt of {name}").into_bytes()),
    }
}
