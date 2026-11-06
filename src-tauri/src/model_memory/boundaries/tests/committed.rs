//! A world over the committed modules: the CORE-02 catalog with P01's importer behind the
//! catalog store, the host's one CORE-03 ledger shared by the coordinator and P03's
//! reservations, the governor driving P04 slots, and P03's portable path behind the
//! executor boundary. Only P03's native backend, batching and event ports, P01's extent
//! planner, the runner and the API sink are fakes.
//!
//! The model is a small Hugging Face style folder (configuration, tokenizer and one
//! safetensors file of two tensors) imported with integrity extents of 16 bytes; its one
//! weights node transfers every extent of the safetensors file.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;
use tempfile::TempDir;

use super::support::*;
use crate::foundation::catalog::{
    self as objects, ArtifactClass, ArtifactVerifier, CatalogConfig, ContentDescriptor,
    ImportManifest, ImportSource, ImportStart, ImportStatus, ObjectBytes, ObjectMetadata,
    ObjectRole, PublisherId, Scope, TrustClaim, TrustPolicy, Uninterrupted, VerifierRegistry,
    VerifierRejection,
};
use crate::foundation::coordination::{Coordinator, LedgerCapacity, SettingsGrant, SharedLedger};
use crate::foundation::evidence::{Backend, BackendRelease};
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Clock, ContentKey, ExecutionCategory, ExecutionId, ManualClock,
    MonotonicTime, TenantId,
};
use crate::foundation::ledger::{HostResource, Ledger, ResourceKey};
use crate::model_memory::boundaries::fakes::{
    BytesBackend, Coalescer, EventLog, FakeApi, FakeModel, FakeRunner, FixedExtents,
};
use crate::model_memory::boundaries::*;
use crate::model_memory::executor::{
    ExecutorConfig, ExecutorPorts, HostStagingConfig, HostStagingMemory, LedgerReservations,
    ReadMethod, SourceCandidate, SourceKind, StagingAccount,
};
use crate::model_memory::graph::node::NodeKind;
use crate::model_memory::identity::{self as layers, ArtifactIdentity, ExecutionIdentity};
use crate::model_memory::manifest as mf;
use crate::model_memory::math::bounds::BandwidthRating;
use crate::model_memory::math::prefetch::PrefetchBudget;
use crate::model_memory::math::sources::{SourceAuthorization, SourceSpec, StealPolicy};
use crate::model_memory::math::SourceId;

/// Integrity-extent size of the import.
pub(super) const EXTENT_BYTES: u64 = 16;
/// Read alignment and staging slot size of the executor.
pub(super) const ALIGN: u64 = 16;
pub(super) const SLOT: u64 = 64;

/// Node numbers of the committed model's declaration.
pub(super) const WEIGHTS: u32 = 3;
pub(super) const CONTEXT: u32 = 9;

pub(super) type Clocked = Arc<ManualClock>;
pub(super) type SharedHost = Coordinator<Clocked, LedgerCapacity<Clocked, SharedLedger<Clocked>>>;
pub(super) type SharedGovernor =
    LedgerPolicyGovernor<Clocked, LedgerCapacity<Clocked, SharedLedger<Clocked>>>;

/// The tenant's catalog scope, which holds its models.
pub(super) fn owner_scope() -> Scope {
    Scope::tenant(tenant())
}

/// The execution the catalog store reads sidecars as.
pub(super) fn reader() -> ExecutionId {
    ExecutionId::new("exe-catalog-reader").unwrap()
}

/// The one local source the catalog offers P03.
pub(super) fn local() -> SourceId {
    SourceId::new("local-catalog").unwrap()
}

pub(super) fn local_candidate() -> SourceCandidate {
    SourceCandidate {
        kind: SourceKind::LocalFile,
        spec: SourceSpec {
            id: local(),
            authorization: SourceAuthorization::Authorized,
            startup_seconds: 0.0,
            bandwidth: BandwidthRating::measured_directional(1e9).unwrap(),
            cuts: vec![],
            max_in_flight: 4,
            interference_seconds_per_byte: 0.0,
        },
    }
}

/// Accepts the structure of every original model file; trusts user selections only.
struct WeightsVerifier;

impl ArtifactVerifier for WeightsVerifier {
    fn class(&self) -> ArtifactClass {
        ArtifactClass::ModelWeights
    }

    fn authenticate(
        &self,
        _content: &ContentDescriptor,
        _publisher: &PublisherId,
        _attestation: &[u8],
    ) -> Result<(), VerifierRejection> {
        Err(VerifierRejection::AttestationInvalid)
    }

    fn validate(
        &self,
        _content: &ContentDescriptor,
        _bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        Ok(())
    }
}

/// Bytes in memory as a catalog import source.
struct Bytes {
    identity: objects::SourceIdentity,
    bytes: Vec<u8>,
}

impl ImportSource for Bytes {
    fn identity(&self) -> objects::SourceIdentity {
        self.identity
    }

    fn length_bytes(&mut self) -> Result<u64, objects::SourceError> {
        Ok(self.bytes.len() as u64)
    }

    fn read_at(
        &mut self,
        offset_bytes: u64,
        buffer: &mut [u8],
    ) -> Result<usize, objects::SourceError> {
        let rest = self.bytes.get(offset_bytes as usize..).unwrap_or_default();
        let read = rest.len().min(buffer.len());
        buffer[..read].copy_from_slice(&rest[..read]);
        Ok(read)
    }
}

/// A safetensors file holding `tensors` in order, its header padded to eight bytes.
fn safetensors(tensors: &[(&str, &str, &[u64], &[u8])]) -> Vec<u8> {
    let mut header = serde_json::Map::new();
    header.insert("__metadata__".to_owned(), json!({ "format": "pt" }));
    let mut data = Vec::new();
    for (name, dtype, shape, bytes) in tensors {
        let begin = data.len();
        data.extend_from_slice(bytes);
        header.insert(
            (*name).to_owned(),
            json!({ "dtype": dtype, "shape": shape, "data_offsets": [begin, data.len()] }),
        );
    }
    let mut encoded = serde_json::to_vec(&header).unwrap();
    while !encoded.len().is_multiple_of(8) {
        encoded.push(b' ');
    }
    let mut file = (encoded.len() as u64).to_le_bytes().to_vec();
    file.extend_from_slice(&encoded);
    file.extend_from_slice(&data);
    file
}

/// A model folder in a temporary directory, with its listing.
pub(super) struct ModelFolder {
    dir: TempDir,
    pub files: BTreeMap<String, Vec<u8>>,
    pub listing: mf::SourceListing,
}

impl ModelFolder {
    /// Configuration, tokenizer and one safetensors file with two tensors.
    pub(super) fn small() -> Self {
        let embed: Vec<u8> = (0..16u32)
            .flat_map(|value| (value as f32).to_le_bytes())
            .collect();
        let norm: Vec<u8> = (0..8u8).map(|value| value.wrapping_mul(29)).collect();
        let weights = safetensors(&[
            ("model.embed_tokens.weight", "F32", &[4, 4], &embed),
            ("model.norm.weight", "BF16", &[4], &norm),
        ]);
        let files: Vec<(&str, Vec<u8>, mf::FileRole)> = vec![
            (
                "config.json",
                br#"{"architectures":["LlamaForCausalLM"],"hidden_size":4}"#.to_vec(),
                mf::FileRole::Configuration,
            ),
            (
                "tokenizer.json",
                br#"{"model":{"type":"BPE","vocab":{}}}"#.to_vec(),
                mf::FileRole::Tokenizer,
            ),
            (
                "model.safetensors",
                weights,
                mf::FileRole::Weights {
                    format: mf::WeightFormat::Safetensors,
                    rank: None,
                },
            ),
        ];
        let dir = tempfile::tempdir().unwrap();
        let mut contents = BTreeMap::new();
        let mut listed = Vec::new();
        for (path, bytes, role) in files {
            std::fs::write(dir.path().join(path), &bytes).unwrap();
            listed.push(mf::ListedFile {
                path: mf::RelativePath::new(path).unwrap(),
                length_bytes: bytes.len() as u64,
                content: ContentKey::of(&bytes),
                role,
            });
            contents.insert(path.to_owned(), bytes);
        }
        let listing = mf::SourceListing {
            origin: mf::SourceOrigin::LocalFolder,
            revision: mf::SourceListing::content_revision(&listed),
            files: listed,
        };
        Self {
            dir,
            files: contents,
            listing,
        }
    }

    pub(super) fn weights(&self) -> &[u8] {
        &self.files["model.safetensors"]
    }

    pub(super) fn source(&self) -> mf::DirectorySource {
        mf::DirectorySource::new(self.dir.path())
    }
}

/// A catalog in a temporary directory behind the store, reading the tenant's scope as
/// the sandbox's trust scope; the other tenant may store models too.
pub(super) fn open_store(clock: &Clocked) -> (TempDir, ModelStore<FixedExtents>) {
    let dir = tempfile::tempdir().unwrap();
    let other = Scope::tenant(TenantId::new("tenant-b").unwrap());
    let config = CatalogConfig::new(Duration::from_secs(3_600))
        .with_quota(owner_scope(), 1 << 30)
        .with_quota(other, 1 << 30)
        .with_trust(
            ArtifactClass::ModelWeights,
            TrustPolicy::new().accept_user_selected(),
        )
        .with_trust(
            ArtifactClass::ModelSidecar,
            TrustPolicy::new().accept_user_selected(),
        );
    let mut verifiers = VerifierRegistry::new();
    verifiers.register(Box::new(WeightsVerifier)).unwrap();
    let (catalog, _report) = mf::CatalogArtifacts::open(
        dir.path(),
        config,
        verifiers,
        Arc::clone(clock) as Arc<dyn Clock>,
        mf::ImportLimits::DEFAULT.max_sidecar_bytes,
    )
    .unwrap();
    let importer = mf::Importer::new(
        catalog,
        mf::IdentityLayers,
        FixedExtents,
        mf::ImportLimits::DEFAULT,
    );
    let store = ModelStore::new(
        importer,
        vec![CatalogScope {
            trust: scope(),
            owner: owner_scope(),
        }],
        reader(),
    );
    (dir, store)
}

/// Publishes every file of `folder` as an original of `scope`, as the per-source import
/// paths of Appendix C would.
pub(super) fn publish_originals(
    store: &ModelStore<FixedExtents>,
    folder: &ModelFolder,
    scope: &Scope,
) {
    let mut catalog = store.importer().catalog().catalog();
    for (path, bytes) in &folder.files {
        let manifest = ImportManifest::describe(bytes, NonZeroU64::new(64).unwrap());
        let identity = objects::SourceIdentity::describe("test-original", path);
        let request = objects::ImportRequest {
            operation: op("import-original"),
            execution: owner(),
            scope: scope.clone(),
            class: ArtifactClass::ModelWeights,
            role: ObjectRole::Original,
            manifest,
            trust: TrustClaim::UserSelected,
            depends_on: BTreeSet::new(),
            metadata: ObjectMetadata::new(),
        };
        let ImportStart::Started(ticket) = catalog.begin_import(request, identity).unwrap() else {
            panic!("the original was not started");
        };
        let status = catalog
            .drive_import(
                &ticket,
                &mut Bytes {
                    identity,
                    bytes: bytes.clone(),
                },
                &mut Uninterrupted,
            )
            .unwrap();
        assert!(matches!(status, ImportStatus::Published { .. }));
        catalog.cancel_import(ticket);
    }
}

fn token(text: &str) -> mf::Token {
    mf::Token::new(text).unwrap()
}

/// The identity-layer inputs of the import that the files do not carry.
pub(super) fn layer_context() -> mf::LayerContext {
    mf::LayerContext {
        location: layers::SourceLocation::Local {
            name: layers::Label::new("tiny-llama").unwrap(),
        },
        license: layers::Label::new("apache-2.0").unwrap(),
        provenance: None,
        published_dtype: layers::Dtype::Float32,
        quantization: layers::Quantization::None,
        generation_config: digest("yougori/test/generation/v1", &[b"chat-template"]),
        adapters: layers::AdapterRecipe::None,
        code_policy: layers::CodePolicy::BuiltInOnly,
        gpu_architectures: BTreeSet::from([layers::Label::new("sm_89").unwrap()]),
        processed_weights: layers::VersionedName::new("original", "1").unwrap(),
        compile: layers::CompileConfiguration::Eager,
    }
}

/// P01's request to import `folder` into `scope`, keyed by `key`.
pub(super) fn import_request(
    folder: &ModelFolder,
    scope: &Scope,
    key: mf::ImportKey,
) -> mf::ImportRequest<mf::LayerContext, mf::CatalogContext> {
    mf::ImportRequest {
        key,
        listing: folder.listing.clone(),
        description: mf::ArtifactDescription {
            bounds: mf::ManifestBounds::DEFAULT,
            compute_dtype: mf::ElementType::Bf16,
            quantization: mf::Quantization::None,
            adapters: Vec::new(),
            execution_abi: mf::ExecutionAbi {
                runner: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
                architecture_adapter: mf::VersionedName {
                    name: token("LlamaForCausalLM"),
                    version: token("1"),
                },
                layout: token("original"),
                kernels: Vec::new(),
                hardware: mf::HardwareRestriction::Unrestricted,
            },
            distribution: mf::Distribution::SINGLE,
            integrity_extent_bytes: EXTENT_BYTES,
        },
        state: mf::StateGroup::default(),
        aliases: Vec::new(),
        owners: Vec::new(),
        identity: layer_context(),
        catalog: mf::CatalogContext {
            scope: scope.clone(),
            execution: owner(),
            operation: op("import-model"),
            trust: TrustClaim::UserSelected,
            dependencies: BTreeMap::new(),
        },
    }
}

/// The import key the identity layers derive for `folder`, as the importer names it when
/// it is given another: its source identity first, then its execution identity.
pub(super) fn derived_key(
    store: &ModelStore<FixedExtents>,
    folder: &ModelFolder,
    scope: &Scope,
) -> mf::ImportKey {
    let probe = digest("yougori/test/probe/v1", &[b"key"]);
    let mut key = mf::ImportKey {
        source: mf::SourceIdentity(probe),
        execution: mf::ExecutionIdentity(probe),
    };
    for _ in 0..2 {
        let outcome = store.importer().import(
            &import_request(folder, scope, key),
            &folder.source(),
            &mf::CancellationToken::new(),
        );
        match outcome {
            Err(mf::ImportError::SourceIdentityMismatch { found, .. }) => key.source = found,
            Err(mf::ImportError::ExecutionIdentityMismatch { found, .. }) => key.execution = found,
            other => panic!("the probe import did not name an identity: {other:?}"),
        }
    }
    key
}

/// Publishes `folder`'s originals in `scope` and imports it through the store.
pub(super) fn import_model(
    store: &mut ModelStore<FixedExtents>,
    folder: &ModelFolder,
) -> ArtifactIdentity {
    publish_originals(store, folder, &owner_scope());
    let key = derived_key(store, folder, &owner_scope());
    store
        .import(ModelImport {
            request: import_request(folder, &owner_scope(), key),
            source: &folder.source(),
            cancel: mf::CancellationToken::new(),
        })
        .unwrap()
}

/// The committed model's declaration: tokenizer, engine and graph rebuilt by the runner,
/// and one weights node made of every extent of the safetensors file.
pub(super) fn committed_dependencies(
    artifact: ArtifactIdentity,
    representation: &VerifiedRepresentation,
    weights: ContentKey,
) -> ExecutionDependencies {
    let extents: Vec<ExtentRef> = representation
        .extents()
        .iter()
        .filter(|descriptor| {
            descriptor
                .stored
                .is_some_and(|stored| stored.representation == weights)
        })
        .map(|descriptor| ExtentRef {
            artifact,
            extent: descriptor.extent,
        })
        .collect();
    ExecutionDependencies {
        artifact,
        nodes: vec![
            node(
                TOKENIZER,
                NodeKind::TokenizerConfiguration,
                "committed-tokenizer",
                0,
                ms(100),
                &[],
                Materialization::Reconstruct,
            ),
            node(
                ENGINE,
                NodeKind::EngineInitialization,
                "committed-engine",
                GIB,
                ms(1_500),
                &[],
                Materialization::Reconstruct,
            ),
            node(
                WEIGHTS,
                NodeKind::ArtifactExtent,
                "committed-weights",
                4 * GIB,
                ms(2_000),
                &[],
                Materialization::Transfer { extents },
            ),
            node(
                CONTEXT,
                NodeKind::GraphCapture,
                "committed-graph",
                256 * MIB,
                ms(500),
                &[ENGINE, WEIGHTS],
                Materialization::Reconstruct,
            ),
        ],
        compute: vec![
            group(&[TOKENIZER, ENGINE, WEIGHTS], ms(200)),
            group(&[CONTEXT], ms(100)),
        ],
        response: ms(50),
        session_device_bytes: 2 * GIB,
        transition_peak_device_bytes: GIB,
    }
}

/// The executor's own account for its staging ring, outside any sandbox.
pub(super) fn staging_account() -> StagingAccount {
    StagingAccount {
        execution: ExecutionId::new("exe-transfer").unwrap(),
        tenant: TenantId::new("host-transfer").unwrap(),
    }
}

pub(super) fn executor_config() -> ExecutorConfig {
    ExecutorConfig {
        operation: op("transfer-executor"),
        host_staging: HostStagingConfig {
            memory: HostStagingMemory::Pinned,
            slots: 4,
            slot_bytes: SLOT,
        },
        device_staging: BTreeMap::new(),
        alignment_bytes: ALIGN,
        max_attempts: 2,
        local_read_method: ReadMethod::PositionedRead,
        steal_policy: StealPolicy {
            min_gain_seconds: 1.0,
            min_gain_fraction: 0.5,
            max_moves_per_batch: 1,
            max_moves_per_rebalance: 1,
        },
        prefetch_budget: PrefetchBudget {
            max_speculative_bytes: 4_096,
            capacity_bytes: MIB,
            reserved_foreground_bytes: 1_024,
        },
    }
}

/// The world over the committed modules.
pub(super) struct Committed {
    pub clock: Clocked,
    pub store: Arc<ModelStore<FixedExtents>>,
    pub folder: ModelFolder,
    pub artifact: ArtifactIdentity,
    pub representation: VerifiedRepresentation,
    pub ledger: SharedLedger<Clocked>,
    pub governor: SharedGovernor,
    pub executor: PortableExecutor<Clocked>,
    pub backend: BytesBackend,
    pub events: EventLog,
    pub runner: FakeRunner,
    pub api: FakeApi,
    pub model: ExecutionIdentity,
    _catalog: TempDir,
}

impl Committed {
    pub(super) fn new() -> Self {
        let clock = Arc::new(ManualClock::new(MonotonicTime::ZERO));
        let (catalog_dir, mut store) = open_store(&clock);
        let folder = ModelFolder::small();
        let artifact = import_model(&mut store, &folder);
        let representation = store
            .representation(&artifact, &SecurityPartition::new(scope()))
            .unwrap();

        // The host's one ledger, also charged by the executor's own staging ring.
        let mut host_ledger = host_ledger(&clock);
        let account = staging_account();
        for resource in [
            ResourceKey::Host(HostResource::Ram),
            ResourceKey::Host(HostResource::PinnedRam),
        ] {
            host_ledger
                .set_tenant_budget(account.tenant.clone(), resource, MIB)
                .unwrap();
        }
        let ledger: SharedLedger<Clocked> = Arc::new(Mutex::new(host_ledger));
        let (registry, admitted) = vm_runtime(&clock);
        let mut host: SharedHost = Coordinator::new(
            Arc::clone(&clock),
            registry.session(),
            LedgerCapacity::shared(Arc::clone(&ledger)),
        );
        // The launch grants the sandbox's models exactly the store's verified artifacts.
        let settings = launch_sandbox(
            &mut host,
            &registry,
            admitted,
            SANDBOX_HOST_RAM_BYTES,
            SettingsGrant {
                network: BTreeSet::new(),
                verified_artifacts: representation.verified_artifacts(),
            },
        );
        let mut governor = LedgerPolicyGovernor::new(host, Arc::clone(&clock), policy());
        governor.attach_runtime(
            runner_owner(),
            RuntimeBinding {
                execution: owner(),
                settings,
            },
        );

        let store = Arc::new(store);
        let backend = BytesBackend::new();
        for bytes in folder.files.values() {
            backend
                .state()
                .objects
                .insert((local(), ContentKey::of(bytes)), bytes.clone());
        }
        let events = EventLog::default();
        let executor = PortableExecutor::start(
            executor_config(),
            Arc::clone(&clock),
            ExecutorPorts {
                backend: Box::new(backend.clone()),
                catalog: Box::new(StoreManifests::new(
                    Arc::clone(&store),
                    vec![local_candidate()],
                )),
                batches: Box::new(Coalescer),
                reservations: Box::new(LedgerReservations::new(Arc::clone(&ledger), account)),
                events: Box::new(events.clone()),
            },
            BTreeMap::from([(local(), SourceKind::LocalFile)]),
        )
        .unwrap();

        let model = execution_of("committed");
        let mut runner = FakeRunner::new(
            Arc::clone(&clock),
            runner_owner(),
            scope(),
            ExecutionCategory::VmSandbox,
        );
        runner.add_model(
            model,
            FakeModel {
                dependencies: committed_dependencies(
                    artifact,
                    &representation,
                    ContentKey::of(folder.weights()),
                ),
                max_shape: MAX_SHAPE,
            },
        );
        Self {
            clock,
            store,
            folder,
            artifact,
            representation,
            ledger,
            governor,
            executor,
            backend,
            events,
            runner,
            api: FakeApi::default(),
            model,
            _catalog: catalog_dir,
        }
    }

    pub(super) fn epoch(&self) -> AuthorizationEpoch {
        self.governor
            .coordinator()
            .sandbox(&owner())
            .map(|sandbox| sandbox.generations().authorization)
            .unwrap()
    }

    pub(super) fn request(&self, name: &str) -> ExactRequest {
        request_for(self.epoch(), name, self.model, Vec::new())
    }

    /// Runs one request through the flow over the committed boundaries.
    pub(super) fn serve(&mut self, request: &ExactRequest) -> Result<ServeReceipt, FlowError> {
        let checked = NativeAbi::current()
            .admit(&mut self.runner)
            .expect("the fake runner's native ABI is this build's");
        let mut boundaries = Boundaries {
            catalog: &*self.store,
            governor: &mut self.governor,
            executor: &mut self.executor,
            runners: vec![checked],
            api: &mut self.api,
        };
        serve(&*self.clock, &mut boundaries, request)
    }

    /// Runs `read` on the host's one ledger.
    pub(super) fn ledger<R>(&self, read: impl FnOnce(&Ledger<Clocked>) -> R) -> R {
        read(&self.ledger.lock().unwrap())
    }
}
