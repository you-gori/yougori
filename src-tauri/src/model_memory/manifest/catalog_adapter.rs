//! Adapter of the catalog port over the committed immutable object catalog (T05,
//! `foundation::catalog`; S2 CORE-02; GPU part §3.3–§3.4).
//!
//! A sidecar is published as one catalog object of class [`ArtifactClass::ModelSidecar`],
//! prepared from the model's source files, which must already be published originals of
//! class [`ArtifactClass::ModelWeights`] in the same scope, named by their whole-file
//! content keys. The catalog runs its own six-stage protocol for that object, and the
//! adapter advances it one port call at a time by interrupting it before the next stage:
//!
//! - `write_staged`: source verification, temporary representation and complete index;
//! - `read_staged`: read-back validation of the staged object (every extent, the content
//!   key and the [`SidecarVerifier`], which decodes and validates the staged sidecar and
//!   hands back the bytes it read);
//! - `commit`: durable commit; the object stays unpublished;
//! - `publish`: catalog publication, then a local-model root named by the import key,
//!   which keeps the sidecar reachable and finds it again.
//!
//! Each published sidecar carries its manifest schema version as a private label. A
//! sidecar published under an earlier schema, or before the label existed, is not reused:
//! the next import of its key publishes a new sidecar and points the root at it, and the
//! old object is never rewritten (GPU-W08 codec versions; GPU-W03 migration).
//!
//! `discard` cancels the catalog import: nothing is published, and the catalog keeps the
//! verified staging for a resume or collects it after its grace period.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::num::NonZeroU64;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crate::foundation::catalog::{
    ArtifactClass, ArtifactVerifier, CacheEviction, CancelOutcome, Catalog, CatalogConfig,
    Checkpoint, ContentDescriptor, FailureReason, ImportControl, ImportManifest, ImportRefusal,
    ImportRequest as ObjectImport, ImportSource, ImportStage, ImportStart, ImportStatus,
    ImportTicket, ObjectBytes, ObjectId, ObjectMetadata, ObjectRole, ObjectStatus, OpenReport,
    Proceed, PublisherId, RootKind, RootName, Scope, SourceError as ObjectSourceError,
    SourceIdentity as ObjectSource, TrustClaim, Uninterrupted, VerifierRegistry, VerifierRejection,
};
use crate::foundation::ids::{Clock, ContentKey, Digest, DigestBuilder, ExecutionId, OperationId};

use super::digests::ManifestDigest;
use super::groups::{DependencyRoot, FIRST_MANIFEST_SCHEMA_VERSION, MANIFEST_SCHEMA_VERSION};
use super::importer::ImportLimits;
use super::ports::{
    ArtifactCatalog, ArtifactIdentity, CatalogError, ImportKey, PublishedArtifact, StagingId,
};
use super::validate::ValidatedManifest;

/// Domain of the catalog source identity of an import key's sidecar.
pub const CATALOG_SOURCE_DOMAIN: &str = "yougori/model-memory/manifest/catalog-source/v1";
/// Domain of the root name that keeps an import key's sidecar reachable.
pub const CATALOG_ROOT_DOMAIN: &str = "yougori/model-memory/manifest/catalog-root/v1";
/// Private label holding the sidecar's manifest digest.
pub const MANIFEST_LABEL: &str = "yougori.model-memory.manifest";
/// Private label holding the sidecar's artifact identity.
pub const ARTIFACT_LABEL: &str = "yougori.model-memory.artifact";
/// Private label holding the sidecar's manifest schema version, in decimal.
pub const SCHEMA_LABEL: &str = "yougori.model-memory.schema";
/// Extent size of a sidecar object in the catalog.
pub const SIDECAR_EXTENT_BYTES: u64 = 1 << 20;
/// How long the read back of an already published sidecar holds its lease.
const READ_BACK_LEASE: Duration = Duration::from_secs(60);

/// The catalog inputs of one import that its key does not carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogContext {
    /// The scope that will own the sidecar; the source files are its published originals.
    pub scope: Scope,
    /// The parent execution importing, part of the catalog's single-flight key.
    pub execution: ExecutionId,
    pub operation: OperationId,
    /// Why the sidecar is trusted under the catalog's `ModelSidecar` policy.
    pub trust: TrustClaim,
    /// The catalog object of every dependency root the manifest records (§3.3 lifecycle).
    pub dependencies: BTreeMap<DependencyRoot, ObjectId>,
}

fn refused(detail: impl fmt::Display) -> CatalogError {
    CatalogError::Refused {
        detail: detail.to_string(),
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Hands the bytes the [`SidecarVerifier`] validated during the catalog's read-back to the
/// adapter that asked for them. It accepts only the content key it was armed with, so
/// verifications at other times, such as reopening the catalog, leave nothing behind. The
/// adapter arms, drives and takes while holding the catalog lock, under which alone the
/// verifier runs, so concurrent imports never see each other's read-back.
#[derive(Clone, Debug, Default)]
pub struct ReadBackChannel(Arc<Mutex<ReadBackSlot>>);

#[derive(Debug, Default)]
struct ReadBackSlot {
    armed: Option<ContentKey>,
    bytes: Option<Vec<u8>>,
}

impl ReadBackChannel {
    pub fn new() -> Self {
        Self::default()
    }

    fn arm(&self, content: ContentKey) {
        *lock(&self.0) = ReadBackSlot {
            armed: Some(content),
            bytes: None,
        };
    }

    fn deliver(&self, content: &ContentKey, bytes: Vec<u8>) {
        let mut slot = lock(&self.0);
        if slot.armed.as_ref() == Some(content) {
            slot.bytes = Some(bytes);
        }
    }

    fn take(&self) -> Option<Vec<u8>> {
        std::mem::take(&mut *lock(&self.0)).bytes
    }
}

/// The responsible verifier of [`ArtifactClass::ModelSidecar`] (INT-09): a sidecar's
/// structure is valid only if it decodes to a validated manifest (§3.3). Publisher
/// attestations over sidecars are not authenticated here, so a publisher claim is refused;
/// sidecars built by the importer are imported under a user selection.
#[derive(Debug)]
pub struct SidecarVerifier {
    read_back: ReadBackChannel,
    max_sidecar_bytes: u64,
}

impl SidecarVerifier {
    /// Reads sidecars of at most `max_sidecar_bytes`, capped at the importer's ceiling
    /// ([`ImportLimits::CEILING`]), since it holds a whole sidecar in memory.
    pub fn new(read_back: ReadBackChannel, max_sidecar_bytes: u64) -> Self {
        Self {
            read_back,
            max_sidecar_bytes: max_sidecar_bytes.min(ImportLimits::CEILING.max_sidecar_bytes),
        }
    }
}

impl ArtifactVerifier for SidecarVerifier {
    fn class(&self) -> ArtifactClass {
        ArtifactClass::ModelSidecar
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
        content: &ContentDescriptor,
        bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        let length_bytes = bytes.length_bytes();
        if length_bytes > self.max_sidecar_bytes {
            return Err(VerifierRejection::CorruptStructure {
                detail: format!("{length_bytes} bytes exceed the sidecar bound"),
            });
        }
        let length = usize::try_from(length_bytes).map_err(|_| VerifierRejection::Unreadable {
            detail: "the sidecar does not fit in memory".to_owned(),
        })?;
        let mut sidecar = vec![0u8; length];
        bytes
            .read_exact_at(0, &mut sidecar)
            .map_err(|error| VerifierRejection::Unreadable {
                detail: error.to_string(),
            })?;
        ValidatedManifest::from_sidecar_bytes(&sidecar).map_err(|error| {
            VerifierRejection::CorruptStructure {
                detail: error.to_string(),
            }
        })?;
        self.read_back.deliver(&content.content_key, sidecar);
        Ok(())
    }
}

/// The sidecar bytes as the catalog's import source.
struct SidecarSource {
    identity: ObjectSource,
    bytes: Vec<u8>,
}

impl ImportSource for SidecarSource {
    fn identity(&self) -> ObjectSource {
        self.identity
    }

    fn length_bytes(&mut self) -> Result<u64, ObjectSourceError> {
        Ok(self.bytes.len() as u64)
    }

    fn read_at(
        &mut self,
        offset_bytes: u64,
        buffer: &mut [u8],
    ) -> Result<usize, ObjectSourceError> {
        let rest = usize::try_from(offset_bytes)
            .ok()
            .and_then(|start| self.bytes.get(start..))
            .unwrap_or(&[]);
        let read = rest.len().min(buffer.len());
        match (buffer.get_mut(..read), rest.get(..read)) {
            (Some(target), Some(data)) => {
                target.copy_from_slice(data);
                Ok(read)
            }
            _ => Err(ObjectSourceError {
                detail: "the read left the sidecar".to_owned(),
            }),
        }
    }
}

/// Lets the catalog run up to, and not into, one stage.
struct StopBefore(ImportStage);

impl ImportControl for StopBefore {
    fn proceed(&mut self, at: Checkpoint) -> Proceed {
        if at == (Checkpoint::Stage { stage: self.0 }) {
            Proceed::Interrupt
        } else {
            Proceed::Continue
        }
    }
}

/// Accepts a drive that stopped exactly where it was told to.
fn paused_before(status: ImportStatus, stage: ImportStage) -> Result<(), CatalogError> {
    let expected = FailureReason::Interrupted {
        at: Checkpoint::Stage { stage },
    };
    match status {
        ImportStatus::Pending {
            last_failure: Some(record),
            ..
        } if record.reason == expected => Ok(()),
        ImportStatus::Pending { last_failure, .. } => Err(refused(last_failure.map_or_else(
            || "the catalog import paused".to_owned(),
            |record| format!("{} during {:?}", record.reason.code(), record.stage),
        ))),
        ImportStatus::Failed { failure } => Err(refused(format!(
            "{} during {:?}",
            failure.reason.code(),
            failure.stage
        ))),
        ImportStatus::Published { .. } => {
            Err(refused("the catalog published before it was asked to"))
        }
    }
}

/// The catalog source identity of an import key's sidecar.
pub fn catalog_source(key: &ImportKey) -> ObjectSource {
    ObjectSource::from_digest(
        DigestBuilder::new(CATALOG_SOURCE_DOMAIN)
            .digest(&key.source.0)
            .digest(&key.execution.0)
            .finish(),
    )
}

/// The name of the local-model root that keeps an import key's sidecar reachable.
pub fn root_name(key: &ImportKey) -> Result<RootName, CatalogError> {
    let digest = DigestBuilder::new(CATALOG_ROOT_DOMAIN)
        .digest(&key.source.0)
        .digest(&key.execution.0)
        .finish();
    RootName::new(format!("model-sidecar-{}", digest.to_hex())).map_err(refused)
}

fn labels(artifact: &PublishedArtifact) -> ObjectMetadata {
    ObjectMetadata::new()
        .with_label(MANIFEST_LABEL, artifact.manifest.digest().to_hex())
        .with_label(ARTIFACT_LABEL, artifact.artifact.0.to_hex())
        .with_label(SCHEMA_LABEL, MANIFEST_SCHEMA_VERSION.to_string())
}

/// Whether a published sidecar was written under this build's manifest schema. One
/// without the label, or labelled with an earlier schema, needs a re-import; a later or
/// unknown label is refused rather than replaced.
fn current_schema(metadata: &ObjectMetadata) -> Result<bool, CatalogError> {
    let Some(label) = metadata.labels.get(SCHEMA_LABEL) else {
        return Ok(false);
    };
    if *label == MANIFEST_SCHEMA_VERSION.to_string() {
        return Ok(true);
    }
    if (FIRST_MANIFEST_SCHEMA_VERSION..MANIFEST_SCHEMA_VERSION)
        .any(|earlier| *label == earlier.to_string())
    {
        return Ok(false);
    }
    Err(refused(format!(
        "the sidecar's manifest schema {label:?} is not one this build reads or replaces"
    )))
}

fn record_from_labels(
    key: &ImportKey,
    metadata: &ObjectMetadata,
) -> Result<PublishedArtifact, CatalogError> {
    let digest = |label: &str| {
        metadata
            .labels
            .get(label)
            .and_then(|hex| Digest::from_hex(hex).ok())
            .ok_or_else(|| refused(format!("the sidecar has no valid {label} label")))
    };
    Ok(PublishedArtifact {
        key: *key,
        manifest: ManifestDigest::from_digest(digest(MANIFEST_LABEL)?),
        artifact: ArtifactIdentity(digest(ARTIFACT_LABEL)?),
    })
}

/// One temporary area of the port.
struct Staged {
    key: ImportKey,
    context: CatalogContext,
    reserved_bytes: u64,
    stage: Stage,
}

enum Stage {
    Open,
    /// A catalog import of the sidecar, driven one stage at a time.
    Importing {
        ticket: ImportTicket,
        source: SidecarSource,
        content: ContentKey,
        object: ObjectId,
        record: PublishedArtifact,
    },
    /// The same sidecar is already published in the scope.
    Present {
        object: ObjectId,
        record: PublishedArtifact,
    },
}

/// The catalog port over the committed catalog.
pub struct CatalogArtifacts {
    catalog: Mutex<Catalog>,
    read_back: ReadBackChannel,
    extent_bytes: NonZeroU64,
    staged: Mutex<BTreeMap<StagingId, Staged>>,
    next_staging: AtomicU64,
    /// The cache evictions a sidecar's staging made room with, by importing execution, until
    /// [`Self::take_evictions`].
    evictions: Mutex<BTreeMap<ExecutionId, Vec<CacheEviction>>>,
}

impl fmt::Debug for CatalogArtifacts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CatalogArtifacts")
            .field("catalog", &*lock(&self.catalog))
            .finish_non_exhaustive()
    }
}

impl CatalogArtifacts {
    /// Opens the catalog in `root` with a [`SidecarVerifier`] added to `verifiers`.
    pub fn open(
        root: impl AsRef<Path>,
        config: CatalogConfig,
        mut verifiers: VerifierRegistry,
        clock: Arc<dyn Clock>,
        max_sidecar_bytes: u64,
    ) -> Result<(Self, OpenReport), CatalogError> {
        let read_back = ReadBackChannel::new();
        verifiers
            .register(Box::new(SidecarVerifier::new(
                read_back.clone(),
                max_sidecar_bytes,
            )))
            .map_err(refused)?;
        let (catalog, report) = Catalog::open(root, config, verifiers, clock).map_err(refused)?;
        Ok((Self::new(catalog, read_back), report))
    }

    /// Wraps a catalog whose `ModelSidecar` verifier is a [`SidecarVerifier`] given
    /// `read_back`.
    pub fn new(catalog: Catalog, read_back: ReadBackChannel) -> Self {
        Self {
            catalog: Mutex::new(catalog),
            read_back,
            extent_bytes: NonZeroU64::new(SIDECAR_EXTENT_BYTES).unwrap_or(NonZeroU64::MIN),
            staged: Mutex::new(BTreeMap::new()),
            next_staging: AtomicU64::new(1),
            evictions: Mutex::new(BTreeMap::new()),
        }
    }

    /// The cache evictions the sidecar staging of `execution`'s imports made room with, in
    /// order; taken once.
    pub fn take_evictions(&self, execution: &ExecutionId) -> Vec<CacheEviction> {
        lock(&self.evictions).remove(execution).unwrap_or_default()
    }

    /// The catalog, for roots, reads, eviction and garbage collection.
    pub fn catalog(&self) -> MutexGuard<'_, Catalog> {
        lock(&self.catalog)
    }

    fn take(&self, staging: StagingId) -> Result<Staged, CatalogError> {
        lock(&self.staged)
            .remove(&staging)
            .ok_or(CatalogError::UnknownStaging)
    }

    fn put(&self, staging: StagingId, staged: Staged) {
        lock(&self.staged).insert(staging, staged);
    }

    /// Runs `step` on the temporary area, which stays open for later calls and discard.
    fn with_staged<T>(
        &self,
        staging: StagingId,
        step: impl FnOnce(&mut Staged) -> Result<T, CatalogError>,
    ) -> Result<T, CatalogError> {
        let mut staged = self.take(staging)?;
        let result = step(&mut staged);
        self.put(staging, staged);
        result
    }

    fn stage(
        &self,
        staged: &mut Staged,
        sidecar: &[u8],
        artifact: &PublishedArtifact,
    ) -> Result<(), CatalogError> {
        if !matches!(staged.stage, Stage::Open) {
            return Err(refused("the temporary area was already written"));
        }
        let length_bytes = sidecar.len() as u64;
        if length_bytes > staged.reserved_bytes {
            return Err(CatalogError::ReservationExceeded {
                reserved_bytes: staged.reserved_bytes,
                requested_bytes: length_bytes,
            });
        }
        let manifest = ValidatedManifest::from_sidecar_bytes(sidecar).map_err(refused)?;
        if manifest.digest() != artifact.manifest || artifact.key != staged.key {
            return Err(refused("the record does not describe this sidecar"));
        }
        let context = &staged.context;
        let scope = &context.scope;
        let derived_from: BTreeSet<ObjectId> = manifest
            .manifest()
            .provenance
            .files
            .iter()
            .map(|file| ObjectId::new(scope, ArtifactClass::ModelWeights, file.content))
            .collect();
        // Raw extents are read from the originals, so the sidecar needs them as well as
        // being derived from them: they stay reachable for as long as it does.
        let mut depends_on = manifest
            .manifest()
            .lifecycle
            .dependency_roots
            .iter()
            .map(|root| {
                context.dependencies.get(root).copied().ok_or_else(|| {
                    refused(format!("dependency root {root:?} has no catalog object"))
                })
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        depends_on.extend(derived_from.iter().copied());
        let declaration = ImportManifest::describe(sidecar, self.extent_bytes);
        let content = declaration.content_key;
        let object = ObjectId::new(scope, ArtifactClass::ModelSidecar, content);
        let mut source = SidecarSource {
            identity: catalog_source(&staged.key),
            bytes: sidecar.to_vec(),
        };
        let request = ObjectImport {
            operation: context.operation.clone(),
            execution: context.execution.clone(),
            scope: scope.clone(),
            class: ArtifactClass::ModelSidecar,
            role: ObjectRole::Prepared { derived_from },
            manifest: declaration,
            trust: context.trust.clone(),
            depends_on,
            metadata: labels(artifact),
        };
        let mut catalog = lock(&self.catalog);
        // A sidecar the scope's budget cannot take evicts the least recently used prepared
        // representations as far as it needs (never an original), then is admitted once more.
        let started = match catalog.begin_import(request.clone(), source.identity) {
            Err(ImportRefusal::Quota { refusal }) if refusal.evictable_shortfall().is_some() => {
                let needed = refusal.evictable_shortfall().unwrap_or_default();
                let eviction = catalog
                    .evict_for_import(scope, needed)
                    .map_err(|refusal| refused(format!("no room for the sidecar: {refusal}")))?;
                lock(&self.evictions)
                    .entry(context.execution.clone())
                    .or_default()
                    .push(eviction);
                catalog.begin_import(request, source.identity)
            }
            other => other,
        };
        match started.map_err(refused)? {
            ImportStart::Started(ticket) | ImportStart::Attached(ticket) => {
                let status = catalog.drive_import(
                    &ticket,
                    &mut source,
                    &mut StopBefore(ImportStage::ReadBackValidation),
                );
                staged.stage = Stage::Importing {
                    ticket,
                    source,
                    content,
                    object,
                    record: *artifact,
                };
                paused_before(status.map_err(refused)?, ImportStage::ReadBackValidation)
            }
            ImportStart::AlreadyPublished(object) => {
                staged.stage = Stage::Present {
                    object,
                    record: *artifact,
                };
                Ok(())
            }
        }
    }

    /// Reads a published sidecar under a short lease.
    fn read_published(
        &self,
        context: &CatalogContext,
        object: ObjectId,
    ) -> Result<Vec<u8>, CatalogError> {
        let mut catalog = lock(&self.catalog);
        let lease = catalog
            .acquire_lease(&context.scope, &context.execution, object, READ_BACK_LEASE)
            .map_err(refused)?;
        let bytes = catalog
            .open_read(&context.scope, &context.execution, lease)
            .map_err(refused)
            .and_then(|mut handle| handle.read_all().map_err(refused));
        let released = catalog
            .release_lease(&context.scope, &context.execution, lease)
            .map_err(refused);
        let bytes = bytes?;
        released?;
        Ok(bytes)
    }
}

impl ArtifactCatalog for CatalogArtifacts {
    type Context = CatalogContext;

    fn published(
        &self,
        key: &ImportKey,
        context: &CatalogContext,
    ) -> Result<Option<PublishedArtifact>, CatalogError> {
        let name = root_name(key)?;
        let catalog = lock(&self.catalog);
        let Some(root) = catalog
            .roots(&context.scope)
            .into_iter()
            .find(|root| root.kind == RootKind::LocalModel && root.name == name)
        else {
            return Ok(None);
        };
        let objects: Vec<ObjectId> = root.objects.into_iter().collect();
        let [object] = objects.as_slice() else {
            return Err(refused(
                "the import key's root does not hold exactly one sidecar",
            ));
        };
        if catalog.status(&context.scope, *object) != ObjectStatus::Published {
            return Ok(None);
        }
        let private = catalog
            .private_metadata(&context.scope, *object)
            .map_err(refused)?;
        if private.class != ArtifactClass::ModelSidecar {
            return Err(refused("the import key's root does not hold a sidecar"));
        }
        if !current_schema(&private.metadata)? {
            return Ok(None);
        }
        record_from_labels(key, &private.metadata).map(Some)
    }

    /// The catalog reserves the sidecar's exact length against the scope's quota when
    /// it is staged; until then the reservation is the bound `write_staged` enforces.
    fn begin_staging(
        &self,
        key: &ImportKey,
        reserved_bytes: u64,
        context: &CatalogContext,
    ) -> Result<StagingId, CatalogError> {
        let staging = StagingId(self.next_staging.fetch_add(1, Ordering::SeqCst));
        self.put(
            staging,
            Staged {
                key: *key,
                context: context.clone(),
                reserved_bytes,
                stage: Stage::Open,
            },
        );
        Ok(staging)
    }

    fn write_staged(
        &self,
        staging: StagingId,
        sidecar: &[u8],
        artifact: &PublishedArtifact,
    ) -> Result<(), CatalogError> {
        self.with_staged(staging, |staged| self.stage(staged, sidecar, artifact))
    }

    fn read_staged(&self, staging: StagingId, max_bytes: u64) -> Result<Vec<u8>, CatalogError> {
        let bytes = self.with_staged(staging, |staged| match &mut staged.stage {
            Stage::Importing {
                ticket,
                source,
                content,
                ..
            } => {
                // The verifier runs only while the catalog is locked, so holding the lock
                // from arming to taking keeps every other import's read-back out.
                let (status, bytes) = {
                    let mut catalog = lock(&self.catalog);
                    self.read_back.arm(*content);
                    let status = catalog.drive_import(
                        ticket,
                        source,
                        &mut StopBefore(ImportStage::DurableCommit),
                    );
                    (status, self.read_back.take())
                };
                paused_before(status.map_err(refused)?, ImportStage::DurableCommit)?;
                bytes.ok_or_else(|| refused("the sidecar verifier did not report the staged bytes"))
            }
            Stage::Present { object, .. } => self.read_published(&staged.context, *object),
            Stage::Open => Err(refused("nothing was staged")),
        })?;
        if bytes.len() as u64 > max_bytes {
            return Err(CatalogError::ReservationExceeded {
                reserved_bytes: max_bytes,
                requested_bytes: bytes.len() as u64,
            });
        }
        Ok(bytes)
    }

    fn commit(&self, staging: StagingId) -> Result<(), CatalogError> {
        self.with_staged(staging, |staged| match &mut staged.stage {
            Stage::Importing { ticket, source, .. } => {
                let status = lock(&self.catalog).drive_import(
                    ticket,
                    source,
                    &mut StopBefore(ImportStage::CatalogPublication),
                );
                paused_before(status.map_err(refused)?, ImportStage::CatalogPublication)
            }
            Stage::Present { .. } => Ok(()),
            Stage::Open => Err(refused("nothing was staged")),
        })
    }

    fn publish(&self, staging: StagingId) -> Result<PublishedArtifact, CatalogError> {
        let staged = self.take(staging)?;
        let (object, record) = match staged.stage {
            Stage::Importing {
                ticket,
                mut source,
                content,
                object,
                record,
            } => {
                let status =
                    lock(&self.catalog).drive_import(&ticket, &mut source, &mut Uninterrupted);
                match status {
                    Ok(ImportStatus::Published {
                        object: published, ..
                    }) if published == object => {
                        lock(&self.catalog).cancel_import(ticket);
                        (object, record)
                    }
                    other => {
                        self.put(
                            staging,
                            Staged {
                                stage: Stage::Importing {
                                    ticket,
                                    source,
                                    content,
                                    object,
                                    record,
                                },
                                ..staged
                            },
                        );
                        return Err(match other {
                            Ok(status) => paused_before(status, ImportStage::CatalogPublication)
                                .err()
                                .unwrap_or_else(|| refused("the catalog published another object")),
                            Err(error) => refused(error),
                        });
                    }
                }
            }
            Stage::Present { object, record } => (object, record),
            Stage::Open => {
                self.put(staging, staged);
                return Err(refused("nothing was staged"));
            }
        };
        let name = root_name(&record.key)?;
        lock(&self.catalog)
            .set_root(
                &staged.context.scope,
                RootKind::LocalModel,
                name,
                BTreeSet::from([object]),
            )
            .map_err(refused)?;
        Ok(record)
    }

    fn discard(&self, staging: StagingId) -> Result<(), CatalogError> {
        match self.take(staging)?.stage {
            Stage::Importing { ticket, .. } => match lock(&self.catalog).cancel_import(ticket) {
                CancelOutcome::UnknownTicket => Err(CatalogError::UnknownStaging),
                CancelOutcome::Cancelled
                | CancelOutcome::Continuing { .. }
                | CancelOutcome::Finished(_) => Ok(()),
            },
            Stage::Open | Stage::Present { .. } => Ok(()),
        }
    }
}
