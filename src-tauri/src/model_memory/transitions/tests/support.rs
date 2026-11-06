//! Test world: typed identities, fake holds, declaration builders and the hand-worked
//! A→B→A workflow. Sizes use decimal gigabytes, as the plan writes them.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::{Arc, MutexGuard};
use std::time::Duration;

use crate::foundation::catalog::{
    ArtifactClass, Catalog, LeaseId as CatalogLeaseId, ObjectId, ReadRefusal, Scope,
};
use crate::foundation::coordination::{LeaseKind, LeaseRefusal};
use crate::foundation::ids::{
    digest, AuthorizationEpoch, ContentKey, ExecutionCategory, ExecutionId, GpuDeviceKey, LeaseId,
    ManualClock, MonotonicTime, TenantId, TrustScope,
};
use crate::foundation::report::{RunRecord, RUN_RECORD_SAMPLE_JSON};
use crate::model_memory::identity::fakes::GrantCatalog;
use crate::model_memory::identity::{
    AdapterIdentity, AdapterRecipe, AdapterSpec, ArtifactIdentity, AuthorityBinding, CodePolicy,
    CommitId, CompileConfiguration, Dtype, ExecutionIdentity, ExecutionSpec, ImmutableRevision,
    KvRepresentation, Label, LogicalModelSpec, PositionalEncoding, Quantization, RankTopology,
    RelativePath, SessionSpec, SourceFile, SourceIdentity, SourceLocation, SourceSpec, TokenPrefix,
    TokenState, VersionedName,
};
use crate::model_memory::residency::eviction::{
    Content, CopyTier, ReconstructibleCopy, Verification,
};
use crate::model_memory::residency::Capacity;
use crate::model_memory::transitions::*;

pub(super) const GB: u64 = 1_000_000_000;
pub(super) const MB: u64 = 1_000_000;
/// How long fixture catalog leases last: past every test's horizon.
pub(super) const OBJECT_LEASE: Duration = Duration::from_secs(3_600);
/// The service lease every held prompt names.
pub(super) const SERVICE_LEASE: u64 = 2;
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

pub(super) fn close(left: f64, right: f64) -> bool {
    (left - right).abs() <= 1e-9 * left.abs().max(right.abs()).max(1.0)
}

pub(super) fn execution_id() -> ExecutionId {
    ExecutionId::new("exe-workflow-1").unwrap()
}

pub(super) fn tenant() -> TenantId {
    TenantId::new("tenant-1").unwrap()
}

pub(super) fn scope() -> TrustScope {
    TrustScope::named(ExecutionCategory::VmSandbox, "tenant-1/runtime-1")
}

pub(super) fn device() -> GpuDeviceKey {
    GpuDeviceKey {
        machine: digest("yougori/test/transitions/machine/v1", &[b"host-1"]),
        device: digest("yougori/test/transitions/device/v1", &[b"gpu-0"]),
    }
}

pub(super) fn key(name: &str) -> ResourceKey {
    ResourceKey::new(name).unwrap()
}

pub(super) fn stage_id(name: &str) -> StageId {
    StageId::new(name).unwrap()
}

pub(super) fn clock() -> ManualClock {
    ManualClock::new(MonotonicTime::from_nanos(1_000_000_000))
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

/// The execution identity of model `name` on one rank.
pub(super) fn execution_of(name: &str) -> ExecutionIdentity {
    let logical = LogicalModelSpec {
        source: source_of(name),
        dtype: Dtype::BFloat16,
        quantization: Quantization::None,
        tokenizer: digest("yougori/test/tokenizer/v1", &[name.as_bytes()]),
        generation_config: digest("yougori/test/generation/v1", &[name.as_bytes()]),
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

pub(super) fn artifact_of(name: &str) -> ArtifactIdentity {
    ArtifactIdentity::from_manifest_digest(&digest("yougori/test/manifest/v1", &[name.as_bytes()]))
}

pub(super) fn adapter_of(name: &str) -> AdapterIdentity {
    AdapterSpec {
        source: source_of(name),
        method: versioned("lora", "1"),
        dtype: Dtype::BFloat16,
    }
    .identity()
}

/// A session state of `base` (with an optional adapter) after `tokens`.
pub(super) fn session_spec(base: &str, adapter: Option<&str>, tokens: &[u32]) -> SessionSpec {
    SessionSpec {
        execution: execution_of(base),
        state: TokenState::Prefix(TokenPrefix::from_token_ids(tokens)),
        adapter: adapter.map(adapter_of),
        positional_encoding: PositionalEncoding {
            scheme: versioned("rope", "1"),
            parameters: digest("yougori/test/rope/v1", &[b"10000"]),
        },
        kv: KvRepresentation::new(
            Dtype::BFloat16,
            Quantization::None,
            16,
            versioned("paged", "1"),
        )
        .unwrap(),
        tenant: tenant(),
        authority: AuthorityBinding::new(
            execution_id(),
            ExecutionCategory::VmSandbox,
            Some(AuthorizationEpoch::FIRST),
        )
        .unwrap(),
    }
}

/// The verified local-storage catalog source of `name`'s bytes.
pub(super) fn catalog_source(name: &str) -> CatalogSource {
    let content = ContentKey::of(name.as_bytes());
    let scope = Scope::tenant(tenant());
    CatalogSource {
        object: ObjectId::new(&scope, ArtifactClass::ModelWeights, content),
        scope,
        class: ArtifactClass::ModelWeights,
        content,
        copy: ReconstructibleCopy {
            tier: CopyTier::LocalStorage,
            verification: Verification::Verified {
                content: Content::Immutable(content),
            },
        },
    }
}

/// The workflow execution's hold on `name`'s catalog object.
pub(super) fn object_hold(name: &str) -> ObjectHold {
    ObjectHold {
        reader: Scope::tenant(tenant()),
        execution: execution_id(),
        lease: objects().lease(name),
    }
}

/// A reload of `name` from its catalog object, held by a catalog read lease.
pub(super) fn reload(name: &str) -> RecoveryRecipe {
    RecoveryRecipe::Reload {
        source: catalog_source(name),
        hold: object_hold(name),
    }
}

/// This thread's CORE-02 catalog in a temporary directory, where every reload's object is
/// published and leased to the workflow's execution for [`OBJECT_LEASE`].
pub(super) struct ObjectCatalog {
    grants: GrantCatalog,
    leases: RefCell<BTreeMap<String, CatalogLeaseId>>,
}

thread_local! {
    static OBJECTS: RefCell<Option<Rc<ObjectCatalog>>> = const { RefCell::new(None) };
}

/// This thread's fixture catalog, opened on first use. Its clock starts where [`clock`]
/// does.
pub(super) fn objects() -> Rc<ObjectCatalog> {
    OBJECTS.with(|cell| {
        Rc::clone(cell.borrow_mut().get_or_insert_with(|| {
            Rc::new(ObjectCatalog {
                grants: GrantCatalog::open(Arc::new(clock()), &[tenant()]),
                leases: RefCell::new(BTreeMap::new()),
            })
        }))
    })
}

impl ObjectCatalog {
    /// The workflow execution's lease on `name`'s bytes, published if need be.
    pub(super) fn lease(&self, name: &str) -> CatalogLeaseId {
        if let Some(lease) = self.leases.borrow().get(name) {
            return *lease;
        }
        let object = self.publish(name);
        let lease = self
            .catalog()
            .acquire_lease(
                &Scope::tenant(tenant()),
                &execution_id(),
                object,
                OBJECT_LEASE,
            )
            .unwrap();
        self.leases.borrow_mut().insert(name.to_string(), lease);
        lease
    }

    /// Publishes `name`'s bytes as the tenant's model weights.
    pub(super) fn publish(&self, name: &str) -> ObjectId {
        let object = self.grants.publish(&tenant(), name.as_bytes());
        assert_eq!(object, catalog_source(name).object);
        object
    }

    pub(super) fn catalog(&self) -> MutexGuard<'_, Catalog> {
        self.grants.lock()
    }

    /// Releases every lease handed out so far, as when holds are lost.
    pub(super) fn release_all(&self) {
        let leases: Vec<CatalogLeaseId> = self.leases.borrow_mut().values().copied().collect();
        self.leases.borrow_mut().clear();
        let mut catalog = self.catalog();
        for lease in leases {
            catalog
                .release_lease(&Scope::tenant(tenant()), &execution_id(), lease)
                .unwrap();
        }
    }
}

/// Base weights `name` reloadable from the catalog.
pub(super) fn base(name: &str, bytes: u64) -> ResourceDeclaration {
    ResourceDeclaration {
        key: key(name),
        identity: StateIdentity::Base {
            execution: execution_of(name),
            artifact: artifact_of(name),
        },
        content: Some(ContentKey::of(name.as_bytes())),
        device_bytes: bytes,
        prerequisites: Vec::new(),
        recipes: vec![reload(name)],
        holder_context_bytes: 0,
    }
}

/// Adapter `name` on base `base_name`, reloadable from the catalog.
pub(super) fn adapter(name: &str, base_name: &str, bytes: u64) -> ResourceDeclaration {
    ResourceDeclaration {
        key: key(name),
        identity: StateIdentity::Adapter {
            adapter: adapter_of(name),
            base: execution_of(base_name),
        },
        content: Some(ContentKey::of(name.as_bytes())),
        device_bytes: bytes,
        prerequisites: vec![key(base_name)],
        recipes: vec![reload(name)],
        holder_context_bytes: 0,
    }
}

/// A merged variant `name` with the given recipes.
pub(super) fn merged(name: &str, bytes: u64, recipes: Vec<RecoveryRecipe>) -> ResourceDeclaration {
    ResourceDeclaration {
        key: key(name),
        identity: StateIdentity::Merged {
            execution: execution_of(name),
            artifact: artifact_of(name),
        },
        content: Some(ContentKey::of(name.as_bytes())),
        device_bytes: bytes,
        prerequisites: Vec::new(),
        recipes,
        holder_context_bytes: 0,
    }
}

/// Session state `name` of `base_name` after `tokens`, held between stages by an engine
/// with a 0.5 GB context.
pub(super) fn session(
    name: &str,
    base_name: &str,
    tokens: &[u32],
    bytes: u64,
    recipes: Vec<RecoveryRecipe>,
) -> ResourceDeclaration {
    ResourceDeclaration {
        key: key(name),
        identity: StateIdentity::Session {
            spec: session_spec(base_name, None, tokens),
        },
        content: None,
        device_bytes: bytes,
        prerequisites: vec![key(base_name)],
        recipes,
        holder_context_bytes: GB / 2,
    }
}

/// A recompute recipe from the held prompt `tokens`.
pub(super) fn recompute(tokens: &[u32], seconds: f64) -> RecoveryRecipe {
    RecoveryRecipe::Recompute {
        prompt: PromptHolding::Held {
            prefix: TokenPrefix::from_token_ids(tokens),
            lease: LeaseId::new(SERVICE_LEASE),
        },
        compute_seconds: seconds,
    }
}

/// A stage: 0.5 GB context, a 2 GB KV pool, 0.5 GB workspace, 0.5 s prefill, 4.5 s
/// decode, 10 ms to deliver the first token.
pub(super) fn stage(id: &str, requires: &[&str]) -> StageDeclaration {
    StageDeclaration {
        id: stage_id(id),
        requires: requires.iter().map(|name| key(name)).collect(),
        produces: None,
        process: StageProcess {
            context_bytes: GB / 2,
            graph_pool_bytes: 0,
            kv_pool_bytes: 2 * GB,
            workspace_bytes: GB / 2,
        },
        prefill_seconds: 0.5,
        decode_seconds: 4.5,
        response_seconds: 0.01,
        readiness_deadline_seconds: None,
        external_actions: Vec::new(),
    }
}

pub(super) fn edge(from: &str, to: &str, weight: BranchWeight) -> WorkflowEdge {
    WorkflowEdge {
        from: stage_id(from),
        to: stage_id(to),
        weight,
    }
}

pub(super) fn chain(stages: &[&str]) -> Vec<WorkflowEdge> {
    stages
        .windows(2)
        .map(|pair| edge(pair[0], pair[1], BranchWeight::Unknown))
        .collect()
}

pub(super) fn evidence(taken: u64, observed: u64) -> BranchWeight {
    BranchWeight::Evidence { taken, observed }
}

/// 24 GB usable with a 1 GB safety reserve, 0.5 GB staging, a 64 GB pinned host copy
/// budget and 16 GB of preparation; host-to-device and back at 2 GB/s; no charges.
pub(super) fn declaration(
    resources: Vec<ResourceDeclaration>,
    stages: Vec<StageDeclaration>,
    edges: Vec<WorkflowEdge>,
) -> WorkflowDeclaration {
    let root = stages[0].id.clone();
    WorkflowDeclaration {
        execution: execution_id(),
        tenant: tenant(),
        trust_scope: scope(),
        resources,
        stages,
        edges,
        root,
        initial: Vec::new(),
        budgets: Budgets {
            device: device(),
            usable_vram: Capacity::Physical { bytes: 24 * GB },
            safety_reserve_bytes: GB,
            staging_bytes: GB / 2,
            host_copy_bytes: 64 * GB,
            write_back: Some(CopyTier::PinnedHost),
            max_preparation_bytes: 16 * GB,
        },
        curves: MeasuredCurves {
            host_to_device: LoadCurve {
                fixed_seconds: 0.0,
                bytes_per_second: 2.0 * GB as f64,
            },
            device_to_host: LoadCurve {
                fixed_seconds: 0.0,
                bytes_per_second: 2.0 * GB as f64,
            },
            relative_spread: 0.1,
            planning_seconds_per_work_unit: 1e-6,
            load_cancellation_interval_seconds: 0.25,
            evidence: digest("yougori/test/curves/v1", &[b"fake-runs"]),
        },
        weights: CostWeights {
            retained_seconds_per_byte_second: 0.0,
            preparation_seconds_per_byte: 0.0,
        },
        limits: PlanLimits::default(),
    }
}

/// The hand-worked A→B→A workflow: A is 9 GB, B 7 GB, and B's stage reserves a 6.5 GB KV
/// pool, so A cannot stay beside it.
pub(super) fn aba() -> WorkflowDeclaration {
    let mut b_stage = stage("s2", &["model-b"]);
    b_stage.process.kv_pool_bytes = 6_500 * MB;
    declaration(
        vec![base("model-a", 9 * GB), base("model-b", 7 * GB)],
        vec![
            stage("s1", &["model-a"]),
            b_stage,
            stage("s3", &["model-a"]),
        ],
        chain(&["s1", "s2", "s3"]),
    )
}

/// Holds by lease number, revocable during a test.
pub(super) struct FakeHolds {
    leases: RefCell<BTreeMap<LeaseId, Result<HeldLease, LeaseRefusal>>>,
}

impl FakeHolds {
    /// The service lease, honoured far beyond any horizon; catalog holds go to this
    /// thread's fixture catalog.
    pub(super) fn honoured() -> Self {
        let holds = Self {
            leases: RefCell::new(BTreeMap::new()),
        };
        holds.grant(SERVICE_LEASE, LeaseKind::Service, u64::MAX / 2);
        holds
    }

    pub(super) fn grant(&self, lease: u64, kind: LeaseKind, expires_at_nanos: u64) {
        self.leases.borrow_mut().insert(
            LeaseId::new(lease),
            Ok(HeldLease {
                kind,
                parent: execution_id(),
                expires_at: MonotonicTime::from_nanos(expires_at_nanos),
            }),
        );
    }

    pub(super) fn set(&self, lease: u64, held: Result<HeldLease, LeaseRefusal>) {
        self.leases.borrow_mut().insert(LeaseId::new(lease), held);
    }

    pub(super) fn revoke(&self, lease: u64) {
        self.set(
            lease,
            Err(LeaseRefusal::RevokedAuthorization {
                bound: AuthorizationEpoch::FIRST,
                current: AuthorizationEpoch::new(2),
            }),
        );
    }
}

impl ObjectHoldAuthority for FakeHolds {
    fn object_hold(&self, hold: &ObjectHold) -> Result<HeldObject, ReadRefusal> {
        objects().catalog().object_hold(hold)
    }
}

impl HoldAuthority for FakeHolds {
    fn hold(&self, lease: LeaseId) -> Result<HeldLease, LeaseRefusal> {
        self.leases
            .borrow()
            .get(&lease)
            .cloned()
            .unwrap_or(Err(LeaseRefusal::UnknownLease { lease }))
    }
}

/// CORE-08's golden record, the template of every fake-substrate record.
pub(super) fn template() -> RunRecord {
    serde_json::from_str(RUN_RECORD_SAMPLE_JSON).unwrap()
}
