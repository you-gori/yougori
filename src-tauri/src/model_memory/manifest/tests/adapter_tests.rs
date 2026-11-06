//! The adapters over the committed catalog (T05) and identity layers (T07): a real
//! catalog in a temporary directory, and identities built by hand through the layers.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use super::super::*;
use super::fakes::{FakeCatalog, FakeIdentities, FixedExtents};
use super::{
    description, pattern, safetensors_bytes, small_model, token, ModelFixture, SAFETENSORS_WEIGHTS,
};
use crate::foundation::catalog::{
    self as objects, ArtifactClass, ArtifactVerifier, CatalogConfig, ContentDescriptor,
    FailureReason, ImportManifest, ImportSource, ImportStart, ImportStatus, ObjectBytes, ObjectId,
    ObjectMetadata, ObjectRole, ObjectStatus, PublisherId, RootKind, Scope, TrustClaim,
    TrustPolicy, Uninterrupted, VerifierRegistry, VerifierRejection,
};
use crate::foundation::ids::{
    digest, Digest, DigestBuilder, ExecutionId, ManualClock, MonotonicTime, OperationId, TenantId,
};
use crate::model_memory::identity as layers;

/// Integrity-extent size of these imports.
const G: u64 = 16;

/// Accepts the structure of every original model file; trusts only user selections.
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
        let rest = &self.bytes[offset_bytes as usize..];
        let read = rest.len().min(buffer.len());
        buffer[..read].copy_from_slice(&rest[..read]);
        Ok(read)
    }
}

/// A catalog in a temporary directory with one tenant scope.
struct CatalogFixture {
    _dir: tempfile::TempDir,
    adapter: CatalogArtifacts,
    scope: Scope,
    execution: ExecutionId,
}

fn open_catalog() -> CatalogFixture {
    let dir = tempfile::tempdir().unwrap();
    let scope = Scope::tenant(TenantId::new("tenant-a").unwrap());
    let config = CatalogConfig::new(Duration::from_secs(3_600))
        .with_quota(scope.clone(), 1 << 30)
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
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1)));
    let (adapter, _report) = CatalogArtifacts::open(
        dir.path(),
        config,
        verifiers,
        clock,
        ImportLimits::DEFAULT.max_sidecar_bytes,
    )
    .unwrap();
    CatalogFixture {
        _dir: dir,
        adapter,
        scope,
        execution: ExecutionId::new("exe-test").unwrap(),
    }
}

impl CatalogFixture {
    fn context(&self) -> CatalogContext {
        CatalogContext {
            scope: self.scope.clone(),
            execution: self.execution.clone(),
            operation: OperationId::new("op-sidecar").unwrap(),
            trust: TrustClaim::UserSelected,
            dependencies: BTreeMap::new(),
        }
    }

    /// Publishes every file of `model` as an original of the scope, as the per-source
    /// import paths of Appendix C would.
    fn publish_originals(&self, model: &ModelFixture) -> BTreeSet<ObjectId> {
        let mut catalog = self.adapter.catalog();
        model
            .files
            .iter()
            .map(|(path, bytes)| {
                let manifest = ImportManifest::describe(bytes, NonZeroU64::new(64).unwrap());
                let object = ObjectId::new(
                    &self.scope,
                    ArtifactClass::ModelWeights,
                    manifest.content_key,
                );
                let identity = objects::SourceIdentity::describe("test-original", path);
                let request = objects::ImportRequest {
                    operation: OperationId::new("op-original").unwrap(),
                    execution: self.execution.clone(),
                    scope: self.scope.clone(),
                    class: ArtifactClass::ModelWeights,
                    role: ObjectRole::Original,
                    manifest,
                    trust: TrustClaim::UserSelected,
                    depends_on: BTreeSet::new(),
                    metadata: ObjectMetadata::new(),
                };
                let ImportStart::Started(ticket) = catalog.begin_import(request, identity).unwrap()
                else {
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
                object
            })
            .collect()
    }
}

/// Delegates to the catalog adapter and cancels the import after one named call.
struct CancelAfter {
    inner: CatalogArtifacts,
    call: &'static str,
    token: CancellationToken,
}

impl CancelAfter {
    fn after<T>(&self, call: &'static str, result: T) -> T {
        if call == self.call {
            self.token.cancel();
        }
        result
    }
}

impl ArtifactCatalog for CancelAfter {
    type Context = CatalogContext;

    fn published(
        &self,
        key: &ImportKey,
        context: &CatalogContext,
    ) -> Result<Option<PublishedArtifact>, CatalogError> {
        self.after("published", self.inner.published(key, context))
    }

    fn begin_staging(
        &self,
        key: &ImportKey,
        reserved_bytes: u64,
        context: &CatalogContext,
    ) -> Result<StagingId, CatalogError> {
        self.after(
            "begin_staging",
            self.inner.begin_staging(key, reserved_bytes, context),
        )
    }

    fn write_staged(
        &self,
        staging: StagingId,
        sidecar: &[u8],
        artifact: &PublishedArtifact,
    ) -> Result<(), CatalogError> {
        self.after(
            "write_staged",
            self.inner.write_staged(staging, sidecar, artifact),
        )
    }

    fn read_staged(&self, staging: StagingId, max_bytes: u64) -> Result<Vec<u8>, CatalogError> {
        self.after("read_staged", self.inner.read_staged(staging, max_bytes))
    }

    fn commit(&self, staging: StagingId) -> Result<(), CatalogError> {
        self.after("commit", self.inner.commit(staging))
    }

    fn publish(&self, staging: StagingId) -> Result<PublishedArtifact, CatalogError> {
        self.after("publish", self.inner.publish(staging))
    }

    fn discard(&self, staging: StagingId) -> Result<(), CatalogError> {
        self.inner.discard(staging)
    }
}

/// The scope's sidecar objects, published or quarantined.
fn sidecars(adapter: &CatalogArtifacts, scope: &Scope) -> Vec<ObjectId> {
    let catalog = adapter.catalog();
    catalog
        .objects(scope)
        .into_iter()
        .filter(|object| {
            catalog
                .private_metadata(scope, *object)
                .is_ok_and(|private| private.class == ArtifactClass::ModelSidecar)
        })
        .collect()
}

#[test]
fn the_catalog_adapter_publishes_a_sidecar_prepared_from_published_originals() {
    let model = small_model();
    let fixture = open_catalog();
    let originals = fixture.publish_originals(&model);
    let (context, scope, execution) = (
        fixture.context(),
        fixture.scope.clone(),
        fixture.execution.clone(),
    );
    let importer = Importer::new(
        fixture.adapter,
        FakeIdentities,
        FixedExtents,
        ImportLimits::DEFAULT,
    );
    let request = model.request_with(description(Distribution::SINGLE, G), (), context);
    let Ok(ImportOutcome::Published(published)) =
        importer.import(&request, &model.source(), &CancellationToken::new())
    else {
        panic!("the import did not publish");
    };
    {
        let mut catalog = importer.catalog().catalog();
        let name = root_name(&request.key).unwrap();
        let root = catalog
            .roots(&scope)
            .into_iter()
            .find(|root| root.name == name)
            .unwrap();
        assert_eq!(root.kind, RootKind::LocalModel);
        let objects: Vec<ObjectId> = root.objects.iter().copied().collect();
        let [object] = objects.as_slice() else {
            panic!("the root holds {objects:?}");
        };
        let object = *object;
        assert_eq!(catalog.status(&scope, object), ObjectStatus::Published);
        let private = catalog.private_metadata(&scope, object).unwrap();
        assert_eq!(private.class, ArtifactClass::ModelSidecar);
        // Derived from the originals, and needing them: they stay reachable with it.
        assert_eq!(private.depends_on, originals);
        assert_eq!(
            private.role,
            ObjectRole::Prepared {
                derived_from: originals
            }
        );
        assert_eq!(private.source, catalog_source(&request.key));
        assert_eq!(
            private.metadata.labels[MANIFEST_LABEL],
            published.manifest.digest().to_hex()
        );
        assert_eq!(
            private.metadata.labels[ARTIFACT_LABEL],
            published.artifact.0.to_hex()
        );
        assert_eq!(
            private.metadata.labels[SCHEMA_LABEL],
            MANIFEST_SCHEMA_VERSION.to_string()
        );
        let lease = catalog
            .acquire_lease(&scope, &execution, object, Duration::from_secs(5))
            .unwrap();
        let bytes = catalog
            .open_read(&scope, &execution, lease)
            .unwrap()
            .read_all()
            .unwrap();
        assert_eq!(
            ValidatedManifest::from_sidecar_bytes(&bytes)
                .unwrap()
                .digest(),
            published.manifest
        );
        catalog.release_lease(&scope, &execution, lease).unwrap();
    }
    // The root finds it again: a repeated import reads nothing and stores nothing.
    assert_eq!(
        importer.import(&request, &model.source(), &CancellationToken::new()),
        Ok(ImportOutcome::AlreadyPublished(published))
    );
    assert_eq!(sidecars(importer.catalog(), &scope).len(), 1);
}

#[test]
fn the_catalog_adapter_refuses_sidecars_over_files_outside_the_catalog() {
    let model = small_model();
    let fixture = open_catalog();
    let context = fixture.context();
    let scope = fixture.scope.clone();
    let importer = Importer::new(
        fixture.adapter,
        FakeIdentities,
        FixedExtents,
        ImportLimits::DEFAULT,
    );
    let request = model.request_with(description(Distribution::SINGLE, G), (), context);
    let error = importer
        .import(&request, &model.source(), &CancellationToken::new())
        .unwrap_err();
    assert!(
        matches!(
            &error,
            ImportError::Catalog {
                step: ImportStep::Index,
                error: CatalogError::Refused { detail },
            } if detail.contains("not a published object of this scope")
        ),
        "{error:?}"
    );
    assert!(sidecars(importer.catalog(), &scope).is_empty());
    assert!(importer.catalog().catalog().roots(&scope).is_empty());
}

#[test]
fn a_cancelled_catalog_import_publishes_nothing() {
    let model = small_model();
    for (call, step) in [
        ("write_staged", ImportStep::ReadBack),
        ("read_staged", ImportStep::Commit),
        ("commit", ImportStep::Publish),
    ] {
        let fixture = open_catalog();
        fixture.publish_originals(&model);
        let context = fixture.context();
        let scope = fixture.scope.clone();
        let token = CancellationToken::new();
        let importer = Importer::new(
            CancelAfter {
                inner: fixture.adapter,
                call,
                token: token.clone(),
            },
            FakeIdentities,
            FixedExtents,
            ImportLimits::DEFAULT,
        );
        let request = model.request_with(description(Distribution::SINGLE, G), (), context.clone());
        assert_eq!(
            importer.import(&request, &model.source(), &token),
            Err(ImportError::Cancelled { step }),
            "cancelled after {call}"
        );
        let adapter = &importer.catalog().inner;
        assert!(sidecars(adapter, &scope).is_empty(), "{call}");
        assert_eq!(adapter.published(&request.key, &context), Ok(None));
        let catalog = adapter.catalog();
        assert!(catalog.roots(&scope).is_empty());
        assert!(catalog
            .failures_in(&scope)
            .any(|record| record.reason == FailureReason::Cancelled
                && record.class == ArtifactClass::ModelSidecar));
    }
}

#[test]
fn the_sidecar_verifier_refuses_what_is_not_a_validated_sidecar() {
    let model = small_model();
    let fixture = open_catalog();
    let originals = fixture.publish_originals(&model);
    let garbage = b"this is not a sidecar".to_vec();
    let mut catalog = fixture.adapter.catalog();
    let identity = objects::SourceIdentity::describe("test-sidecar", "garbage");
    let request = objects::ImportRequest {
        operation: OperationId::new("op-garbage").unwrap(),
        execution: fixture.execution.clone(),
        scope: fixture.scope.clone(),
        class: ArtifactClass::ModelSidecar,
        role: ObjectRole::Prepared {
            derived_from: originals,
        },
        manifest: ImportManifest::describe(&garbage, NonZeroU64::new(64).unwrap()),
        trust: TrustClaim::UserSelected,
        depends_on: BTreeSet::new(),
        metadata: ObjectMetadata::new(),
    };
    let ImportStart::Started(ticket) = catalog.begin_import(request, identity).unwrap() else {
        panic!("the import was not started");
    };
    let status = catalog
        .drive_import(
            &ticket,
            &mut Bytes {
                identity,
                bytes: garbage,
            },
            &mut Uninterrupted,
        )
        .unwrap();
    assert!(
        matches!(
            &status,
            ImportStatus::Failed { failure }
                if matches!(failure.reason, FailureReason::VerifierRejected { .. })
        ),
        "{status:?}"
    );
    // Publisher attestations over sidecars are never authenticated here.
    let verifier = SidecarVerifier::new(ReadBackChannel::new(), 1 << 20);
    let descriptor = ContentDescriptor {
        scope: fixture.scope.clone(),
        class: ArtifactClass::ModelSidecar,
        content_key: ContentKey::of(b"x"),
        length_bytes: 1,
        manifest_digest: digest("yougori/test/manifest/v1", &[b"x"]),
    };
    assert_eq!(
        verifier.authenticate(
            &descriptor,
            &PublisherId::from_key_fingerprint(digest("yougori/test/key/v1", &[b"k"])),
            b"signature"
        ),
        Err(VerifierRejection::AttestationInvalid)
    );
}

/// The sidecar the importer writes for `model` with integrity extents of
/// `integrity_extent_bytes`, and its record, built over the fake ports.
fn sidecar_of(model: &ModelFixture, integrity_extent_bytes: u64) -> (Vec<u8>, PublishedArtifact) {
    let importer = Importer::new(
        FakeCatalog::default(),
        FakeIdentities,
        FixedExtents,
        ImportLimits::DEFAULT,
    );
    let request = model.request(description(Distribution::SINGLE, integrity_extent_bytes));
    let Ok(ImportOutcome::Published(record)) =
        importer.import(&request, &model.source(), &CancellationToken::new())
    else {
        panic!("the fake import did not publish");
    };
    let state = importer.catalog().state();
    let staged = state.staged.values().next().unwrap();
    (staged.bytes.clone(), record)
}

/// Publishes `sidecar` over `originals` with `labels`, as an earlier build would have,
/// and points the local-model root of `key` at it.
fn plant_sidecar(
    adapter: &CatalogArtifacts,
    fixture: (&Scope, &ExecutionId),
    key: &ImportKey,
    originals: &BTreeSet<ObjectId>,
    sidecar: &[u8],
    labels: ObjectMetadata,
) -> ObjectId {
    let (scope, execution) = fixture;
    let mut catalog = adapter.catalog();
    let manifest =
        ImportManifest::describe(sidecar, NonZeroU64::new(SIDECAR_EXTENT_BYTES).unwrap());
    let object = ObjectId::new(scope, ArtifactClass::ModelSidecar, manifest.content_key);
    let identity =
        objects::SourceIdentity::describe("an-earlier-build", &manifest.content_key.to_string());
    let request = objects::ImportRequest {
        operation: OperationId::new("op-earlier").unwrap(),
        execution: execution.clone(),
        scope: scope.clone(),
        class: ArtifactClass::ModelSidecar,
        role: ObjectRole::Prepared {
            derived_from: originals.clone(),
        },
        manifest,
        trust: TrustClaim::UserSelected,
        depends_on: originals.clone(),
        metadata: labels,
    };
    let ImportStart::Started(ticket) = catalog.begin_import(request, identity).unwrap() else {
        panic!("the earlier sidecar was not started");
    };
    let status = catalog
        .drive_import(
            &ticket,
            &mut Bytes {
                identity,
                bytes: sidecar.to_vec(),
            },
            &mut Uninterrupted,
        )
        .unwrap();
    assert!(
        matches!(status, ImportStatus::Published { .. }),
        "{status:?}"
    );
    catalog.cancel_import(ticket);
    catalog
        .set_root(
            scope,
            RootKind::LocalModel,
            root_name(key).unwrap(),
            BTreeSet::from([object]),
        )
        .unwrap();
    object
}

/// The bytes of `object`, read under a short lease.
fn read_object(
    adapter: &CatalogArtifacts,
    scope: &Scope,
    execution: &ExecutionId,
    object: ObjectId,
) -> Vec<u8> {
    let mut catalog = adapter.catalog();
    let lease = catalog
        .acquire_lease(scope, execution, object, Duration::from_secs(5))
        .unwrap();
    let bytes = catalog
        .open_read(scope, execution, lease)
        .unwrap()
        .read_all()
        .unwrap();
    catalog.release_lease(scope, execution, lease).unwrap();
    bytes
}

#[test]
fn a_sidecar_of_an_earlier_schema_is_imported_again_and_never_rewritten() {
    let model = small_model();
    let fixture = open_catalog();
    let originals = fixture.publish_originals(&model);
    let context = fixture.context();
    let (scope, execution) = (fixture.scope.clone(), fixture.execution.clone());
    let request = model.request_with(description(Distribution::SINGLE, G), (), context.clone());
    let labels = |record: &PublishedArtifact| {
        ObjectMetadata::new()
            .with_label(MANIFEST_LABEL, record.manifest.digest().to_hex())
            .with_label(ARTIFACT_LABEL, record.artifact.0.to_hex())
    };
    let importer = Importer::new(
        fixture.adapter,
        FakeIdentities,
        FixedExtents,
        ImportLimits::DEFAULT,
    );
    let adapter = importer.catalog();
    let plant = |sidecar: &[u8], labels: ObjectMetadata| {
        plant_sidecar(
            adapter,
            (&scope, &execution),
            &request.key,
            &originals,
            sidecar,
            labels,
        )
    };

    // A sidecar labelled with a later schema is refused, never replaced.
    let (later_bytes, later) = sidecar_of(&model, 8 * G);
    plant(
        &later_bytes,
        labels(&later).with_label(SCHEMA_LABEL, (MANIFEST_SCHEMA_VERSION + 1).to_string()),
    );
    assert!(matches!(
        adapter.published(&request.key, &context),
        Err(CatalogError::Refused { .. })
    ));
    assert!(matches!(
        importer.import(&request, &model.source(), &CancellationToken::new()),
        Err(ImportError::Catalog {
            step: ImportStep::VerifySource,
            ..
        })
    ));

    // Labelled with an earlier schema, or published before the label existed, it is not
    // reused. Their bytes stand in for an earlier build's, which this build cannot read.
    let (labelled_bytes, labelled) = sidecar_of(&model, 4 * G);
    plant(
        &labelled_bytes,
        labels(&labelled).with_label(SCHEMA_LABEL, "2"),
    );
    assert_eq!(adapter.published(&request.key, &context), Ok(None));
    let (earlier_bytes, earlier_record) = sidecar_of(&model, 2 * G);
    let earlier = plant(&earlier_bytes, labels(&earlier_record));
    assert_eq!(adapter.published(&request.key, &context), Ok(None));

    // The next import publishes a new sidecar and points the key's root at it.
    let Ok(ImportOutcome::Published(published)) =
        importer.import(&request, &model.source(), &CancellationToken::new())
    else {
        panic!("the import did not publish again");
    };
    assert_ne!(published.manifest, earlier_record.manifest);
    {
        let catalog = adapter.catalog();
        let name = root_name(&request.key).unwrap();
        let root = catalog
            .roots(&scope)
            .into_iter()
            .find(|root| root.name == name)
            .unwrap();
        assert_eq!(root.objects.len(), 1);
        assert!(!root.objects.contains(&earlier));
        // The earlier object is left as it was: published, labelled and unchanged.
        assert_eq!(catalog.status(&scope, earlier), ObjectStatus::Published);
        let private = catalog.private_metadata(&scope, earlier).unwrap();
        assert_eq!(private.metadata, labels(&earlier_record));
    }
    assert_eq!(
        read_object(adapter, &scope, &execution, earlier),
        earlier_bytes
    );
    assert_eq!(sidecars(adapter, &scope).len(), 4);
    // The new sidecar carries this build's schema and is reused from now on.
    assert_eq!(
        adapter.published(&request.key, &context),
        Ok(Some(published))
    );
    assert_eq!(
        importer.import(&request, &model.source(), &CancellationToken::new()),
        Ok(ImportOutcome::AlreadyPublished(published))
    );
}

#[test]
fn the_sidecar_verifier_refuses_a_sidecar_of_an_earlier_schema() {
    let (sidecar, _) = sidecar_of(&small_model(), G);
    let body = &sidecar[..sidecar.len() - SIDECAR_DIGEST_BYTES];
    let mut earlier = body.to_vec();
    earlier[8..10].copy_from_slice(&2u16.to_be_bytes());
    let digest = DigestBuilder::new(MANIFEST_DOMAIN).bytes(&earlier).finish();
    earlier.extend_from_slice(digest.as_bytes());
    assert_eq!(
        ValidatedManifest::from_sidecar_bytes(&earlier),
        Err(ManifestError::NeedsReimport { schema_version: 2 })
    );
    let fixture = open_catalog();
    let originals = fixture.publish_originals(&small_model());
    let mut catalog = fixture.adapter.catalog();
    let identity = objects::SourceIdentity::describe("test-sidecar", "schema-2");
    let request = objects::ImportRequest {
        operation: OperationId::new("op-earlier").unwrap(),
        execution: fixture.execution.clone(),
        scope: fixture.scope.clone(),
        class: ArtifactClass::ModelSidecar,
        role: ObjectRole::Prepared {
            derived_from: originals,
        },
        manifest: ImportManifest::describe(&earlier, NonZeroU64::new(64).unwrap()),
        trust: TrustClaim::UserSelected,
        depends_on: BTreeSet::new(),
        metadata: ObjectMetadata::new(),
    };
    let ImportStart::Started(ticket) = catalog.begin_import(request, identity).unwrap() else {
        panic!("the import was not started");
    };
    let status = catalog
        .drive_import(
            &ticket,
            &mut Bytes {
                identity,
                bytes: earlier,
            },
            &mut Uninterrupted,
        )
        .unwrap();
    assert!(
        matches!(
            &status,
            ImportStatus::Failed { failure }
                if matches!(&failure.reason, FailureReason::VerifierRejected { .. })
        ),
        "{status:?}"
    );
}

pub(super) fn layer_context() -> LayerContext {
    LayerContext {
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

/// The configuration or tokenizer digest of one file of `role`, derived as the manifest
/// derives it.
fn role_digest(domain: &str, file: &str, model: &ModelFixture) -> Digest {
    DigestBuilder::new(domain)
        .u64(1)
        .str(file)
        .digest(ContentKey::of(&model.files[file]).digest())
        .u64(0)
        .finish()
}

/// The source and execution identity of `small_model` built by hand through the layers,
/// for an execution ABI of `abi` with the quantization `context` names.
pub(super) fn layered_identities(
    model: &ModelFixture,
    context: &LayerContext,
    abi: &ExecutionAbi,
) -> (layers::SourceIdentity, layers::ExecutionIdentity) {
    let source = layers::SourceSpec {
        location: context.location.clone(),
        revision: layers::ImmutableRevision::FileDigests,
        files: model
            .listing
            .files
            .iter()
            .map(|file| layers::SourceFile {
                path: layers::RelativePath::new(file.path.as_str()).unwrap(),
                length_bytes: file.length_bytes,
                content: file.content,
            })
            .collect(),
        configuration: role_digest(CONFIGURATION_DOMAIN, "config.json", model),
        published_dtype: context.published_dtype,
        license: context.license.clone(),
        provenance: context.provenance,
    }
    .identity()
    .unwrap();
    let logical = layers::LogicalModelSpec {
        source,
        dtype: layers::Dtype::BFloat16,
        quantization: context.quantization.clone(),
        tokenizer: role_digest(TOKENIZER_DOMAIN, "tokenizer.json", model),
        generation_config: context.generation_config,
        adapters: layers::AdapterRecipe::None,
        code_policy: layers::CodePolicy::BuiltInOnly,
    }
    .identity();
    let execution = layers::ExecutionSpec {
        logical,
        runner: layers::VersionedName::new("vllm", "0.31.0").unwrap(),
        architecture_adapter: layers::VersionedName::new("LlamaForCausalLM", "1").unwrap(),
        kernel_layout: kernel_layout(abi).unwrap(),
        gpu_architectures: context.gpu_architectures.clone(),
        topology: layers::RankTopology::SINGLE,
        processed_weights: context.processed_weights.clone(),
        compile: layers::CompileConfiguration::Eager,
    }
    .identity()
    .unwrap();
    (source, execution)
}

#[test]
fn the_identity_adapter_keys_imports_by_the_identity_layers() {
    let model = small_model();
    let context = layer_context();
    let (source, execution) = layered_identities(&model, &context, &super::abi());
    let mut request = model.request_with(description(Distribution::SINGLE, G), context, ());
    request.key = IdentityLayers::import_key(&source, &execution);
    let importer = Importer::new(
        FakeCatalog::default(),
        IdentityLayers,
        FixedExtents,
        ImportLimits::DEFAULT,
    );
    let Ok(ImportOutcome::Published(published)) =
        importer.import(&request, &model.source(), &CancellationToken::new())
    else {
        panic!("the import did not publish");
    };
    let artifact = layers::ArtifactIdentity::from_manifest_digest(&published.manifest.digest());
    assert_eq!(published.artifact, ArtifactIdentity(*artifact.digest()));
    assert_ne!(published.artifact.0, published.manifest.digest());

    // Every identity input the request carries is bound: another licence is another
    // source, so the listed files are not the requested source.
    let mut relicensed = request.clone();
    relicensed.identity.license = layers::Label::new("mit").unwrap();
    assert!(matches!(
        Importer::new(
            FakeCatalog::default(),
            IdentityLayers,
            FixedExtents,
            ImportLimits::DEFAULT
        )
        .import(&relicensed, &model.source(), &CancellationToken::new()),
        Err(ImportError::SourceIdentityMismatch { .. })
    ));
    // Other kernels are another execution: the kernel layout is the manifest's own.
    let mut rekernelled = request.clone();
    rekernelled.description.execution_abi.kernels = vec![token("exllama_v2_gemm")];
    assert!(matches!(
        Importer::new(
            FakeCatalog::default(),
            IdentityLayers,
            FixedExtents,
            ImportLimits::DEFAULT
        )
        .import(&rekernelled, &model.source(), &CancellationToken::new()),
        Err(ImportError::ExecutionIdentityMismatch { .. })
    ));
}

#[test]
fn the_identity_adapter_refuses_inputs_the_manifest_contradicts() {
    let model = small_model();
    let context = layer_context();
    let importer = Importer::new(
        FakeCatalog::default(),
        FakeIdentities,
        FixedExtents,
        ImportLimits::DEFAULT,
    );
    let request = model.request(description(Distribution::SINGLE, G));
    assert!(importer
        .import(&request, &model.source(), &CancellationToken::new())
        .is_ok());
    let staged = {
        let state = importer.catalog().state();
        ValidatedManifest::from_sidecar_bytes(&state.staged.values().next().unwrap().bytes).unwrap()
    };
    let (source, _) = layered_identities(&model, &context, &super::abi());
    let source = SourceIdentity(*source.digest());
    let identities = IdentityLayers;
    assert!(identities
        .execution_identity(&source, &staged, &context)
        .is_ok());
    let refused = |context: &LayerContext| identities.execution_identity(&source, &staged, context);

    assert_eq!(
        identities.execution_identity(
            &SourceIdentity(digest("yougori/test/other/v1", &[b"x"])),
            &staged,
            &context
        ),
        Err(IdentityError::Inconsistent {
            field: "source identity"
        })
    );
    let mut quantized = context.clone();
    quantized.quantization = layers::Quantization::Scheme(
        layers::QuantizationScheme::new(
            layers::VersionedName::new("awq", "1").unwrap(),
            4,
            Some(128),
            digest("yougori/test/scales/v1", &[b"s"]),
        )
        .unwrap(),
    );
    assert_eq!(
        refused(&quantized),
        Err(IdentityError::Inconsistent {
            field: "quantization"
        })
    );
    let adapter = layers::AdapterSpec {
        source: layers::SourceSpec {
            location: context.location.clone(),
            revision: layers::ImmutableRevision::FileDigests,
            files: vec![layers::SourceFile {
                path: layers::RelativePath::new("adapter.safetensors").unwrap(),
                length_bytes: 1,
                content: ContentKey::of(b"a"),
            }],
            configuration: digest("yougori/test/adapter-config/v1", &[b"r8"]),
            published_dtype: layers::Dtype::BFloat16,
            license: context.license.clone(),
            provenance: None,
        }
        .identity()
        .unwrap(),
        method: layers::VersionedName::new("lora", "1").unwrap(),
        dtype: layers::Dtype::BFloat16,
    }
    .identity();
    let mut merged = context.clone();
    merged.adapters = layers::AdapterRecipe::Merged(
        layers::MergedAdapters::new(vec![layers::MergedAdapter {
            adapter,
            scale: layers::MergeScale::new(1.0).unwrap(),
            procedure: layers::VersionedName::new("merge", "1").unwrap(),
        }])
        .unwrap(),
    );
    assert_eq!(
        refused(&merged),
        Err(IdentityError::Inconsistent { field: "adapters" })
    );
    let mut processed = context.clone();
    processed.processed_weights = layers::VersionedName::new("marlin", "1").unwrap();
    assert_eq!(
        refused(&processed),
        Err(IdentityError::Inconsistent {
            field: "processed-weight layout"
        })
    );
    let mut remote = context.clone();
    remote.location = layers::SourceLocation::Repository {
        host: layers::Label::new(HUGGING_FACE_HOST).unwrap(),
        repository: layers::Label::new("example/tiny-llama").unwrap(),
    };
    assert_eq!(
        refused(&remote),
        Err(IdentityError::Inconsistent {
            field: "source location"
        })
    );
    let mut no_gpu = context.clone();
    no_gpu.gpu_architectures.clear();
    assert!(matches!(
        refused(&no_gpu),
        Err(IdentityError::Refused { .. })
    ));

    // A restricted execution ABI admits only the GPU architectures it names.
    let mut restricted = staged.manifest().clone();
    restricted.execution_abi.hardware =
        HardwareRestriction::ComputeCapabilities(vec![ComputeCapability { major: 8, minor: 9 }]);
    let logical = layers::LogicalModelSpec {
        source: layers::SourceSpec {
            location: context.location.clone(),
            revision: layers::ImmutableRevision::FileDigests,
            files: vec![layers::SourceFile {
                path: layers::RelativePath::new("x").unwrap(),
                length_bytes: 1,
                content: ContentKey::of(b"x"),
            }],
            configuration: digest("yougori/test/config/v1", &[b"c"]),
            published_dtype: layers::Dtype::Float32,
            license: context.license.clone(),
            provenance: None,
        }
        .identity()
        .unwrap(),
        dtype: layers::Dtype::BFloat16,
        quantization: layers::Quantization::None,
        tokenizer: digest("yougori/test/tokenizer/v1", &[b"t"]),
        generation_config: context.generation_config,
        adapters: layers::AdapterRecipe::None,
        code_policy: layers::CodePolicy::BuiltInOnly,
    }
    .identity();
    assert!(IdentityLayers::execution_spec(logical, &restricted, &context).is_ok());
    let mut hopper = context.clone();
    hopper.gpu_architectures = BTreeSet::from([layers::Label::new("sm_90a").unwrap()]);
    assert_eq!(
        IdentityLayers::execution_spec(logical, &restricted, &hopper).map(|_| ()),
        Err(IdentityError::Inconsistent {
            field: "GPU architectures"
        })
    );
    // A compute dtype the layers cannot name is refused, not guessed.
    let mut boolean = staged.manifest().clone();
    boolean.semantics.compute_dtype = ElementType::Bool;
    let layer_source = IdentityLayers::manifest_source_spec(staged.manifest(), &context)
        .unwrap()
        .identity()
        .unwrap();
    assert_eq!(
        IdentityLayers::logical_spec(layer_source, &boolean, &context).map(|_| ()),
        Err(IdentityError::Incomplete {
            field: "compute dtype"
        })
    );
}

#[test]
fn a_repository_source_needs_a_commit_in_the_identity_layers() {
    let model = small_model();
    let mut context = layer_context();
    context.location = layers::SourceLocation::Repository {
        host: layers::Label::new(HUGGING_FACE_HOST).unwrap(),
        repository: layers::Label::new("example/tiny-llama").unwrap(),
    };
    let mut listing = model.listing.clone();
    listing.origin = SourceOrigin::HuggingFace {
        repository: token("example/tiny-llama"),
    };
    let configuration = digest("yougori/test/config/v1", &[b"c"]);
    assert!(matches!(
        IdentityLayers.source_identity(&listing, &configuration, &context),
        Err(IdentityError::Refused { .. })
    ));
    listing.revision = SourceRevision::GitCommit(
        GitCommit::from_hex("0123456789abcdef0123456789abcdef01234567").unwrap(),
    );
    assert!(IdentityLayers
        .source_identity(&listing, &configuration, &context)
        .is_ok());
    listing.origin = SourceOrigin::LocalFolder;
    assert_eq!(
        IdentityLayers.source_identity(&listing, &configuration, &context),
        Err(IdentityError::Inconsistent {
            field: "source location"
        })
    );
}

#[test]
fn gpu_architectures_and_dtypes_map_onto_the_identity_layers() {
    for (label, major, minor) in [
        ("sm_89", 8, 9),
        ("sm_90a", 9, 0),
        ("sm_120", 12, 0),
        ("sm_100f", 10, 0),
    ] {
        assert_eq!(
            compute_capability(label),
            Some(ComputeCapability { major, minor }),
            "{label}"
        );
    }
    for label in ["sm_8", "gfx90a", "sm_", "sm_9x0", "90"] {
        assert_eq!(compute_capability(label), None, "{label}");
    }
    assert_eq!(
        layer_dtype(ElementType::Bf16),
        Some(layers::Dtype::BFloat16)
    );
    assert_eq!(
        layer_dtype(ElementType::F4),
        Some(layers::Dtype::Float4E2M1)
    );
    assert_eq!(layer_dtype(ElementType::U8), Some(layers::Dtype::UInt8));
    assert_eq!(layer_dtype(ElementType::I32), None);
    assert_eq!(layer_dtype(ElementType::F8E8m0), None);
}

#[test]
fn both_adapters_import_a_model_end_to_end() {
    let model = small_model();
    let fixture = open_catalog();
    fixture.publish_originals(&model);
    let catalog_context = fixture.context();
    let scope = fixture.scope.clone();
    let layer_context = layer_context();
    let (source, execution) = layered_identities(&model, &layer_context, &super::abi());
    let mut request = model.request_with(
        description(Distribution::SINGLE, G),
        layer_context,
        catalog_context.clone(),
    );
    request.key = IdentityLayers::import_key(&source, &execution);
    let importer = Importer::new(
        fixture.adapter,
        IdentityLayers,
        FixedExtents,
        ImportLimits::DEFAULT,
    );
    let Ok(ImportOutcome::Published(published)) =
        importer.import(&request, &model.source(), &CancellationToken::new())
    else {
        panic!("the import did not publish");
    };
    let artifact = layers::ArtifactIdentity::from_manifest_digest(&published.manifest.digest());
    assert_eq!(published.artifact, ArtifactIdentity(*artifact.digest()));
    assert_eq!(
        importer.catalog().published(&request.key, &catalog_context),
        Ok(Some(published))
    );
    assert_eq!(sidecars(importer.catalog(), &scope).len(), 1);
}

/// A small model whose configuration and weights differ by `seed`, so its source, import
/// key and sidecar differ from every other seed's.
fn model_variant(seed: u8) -> ModelFixture {
    let weights = safetensors_bytes(&[(
        "model.embed_tokens.weight",
        ElementType::U8,
        &[16],
        &pattern(16, seed),
    )]);
    ModelFixture::new(&[
        (
            "config.json",
            format!(r#"{{"variant":{seed}}}"#).into_bytes(),
            FileRole::Configuration,
        ),
        ("model.safetensors", weights, SAFETENSORS_WEIGHTS),
    ])
}

#[test]
fn concurrent_catalog_imports_of_different_keys_all_publish() {
    let fixture = open_catalog();
    let models: Vec<ModelFixture> = (0..8).map(model_variant).collect();
    for model in &models {
        fixture.publish_originals(model);
    }
    let context = fixture.context();
    let scope = fixture.scope.clone();
    let importer = Arc::new(Importer::new(
        fixture.adapter,
        FakeIdentities,
        FixedExtents,
        ImportLimits::DEFAULT,
    ));
    let threads: Vec<_> = models
        .iter()
        .map(|model| {
            let importer = Arc::clone(&importer);
            let request =
                model.request_with(description(Distribution::SINGLE, G), (), context.clone());
            let source = model.source();
            std::thread::spawn(move || {
                importer.import(&request, &source, &CancellationToken::new())
            })
        })
        .collect();
    for thread in threads {
        let outcome = thread.join().unwrap();
        assert!(
            matches!(outcome, Ok(ImportOutcome::Published(_))),
            "{outcome:?}"
        );
    }
    assert_eq!(sidecars(importer.catalog(), &scope).len(), models.len());
}
