//! The catalog store: boundary 1 over the CORE-02 object catalog (T05) and P01's sidecar
//! importer (GPU §3.3–§3.4, line 306; S3.3; INT-05, INT-09).
//!
//! A model is imported by P01's [`Importer`] over the catalog adapter
//! [`CatalogArtifacts`] and the identity layers [`IdentityLayers`]. Its source files are
//! already published originals of class `ModelWeights` in a tenant's scope; the importer
//! verifies them, builds the sidecar manifest and publishes it as one `ModelSidecar`
//! object under a local-model root, so the importer stays the only writer.
//!
//! The store reads an artifact back as the owner of the scope that holds it, under a
//! short catalog lease, validates the sidecar and recomputes the artifact identity from
//! its manifest digest: the sidecar's label only says where to look, never what to trust.
//! A scope is read only when the request's partition allows the trust scope bound to it
//! (S3.6), and another scope's equal content is never permission (S3.3).
//!
//! Names stay those of the modules that own them. An extent is named by its decoded
//! content key ([`ContentKey`]); where it is stored, by the sidecar's content key, the
//! source file's content key, its index in the manifest and its offset in the file
//! ([`StoredExtent`]), which are exactly what the transfer executor (P03) resolves and
//! reads; and the representation's verified artifacts, by the digests of the catalog
//! objects ([`ObjectId`]) it was read from, as the catalog's
//! [`artifact_verification`](crate::foundation::catalog::Catalog::artifact_verification)
//! and the coordinator's settings grant name them. [`StoreManifests`] serves the same
//! sidecars to P03 as its catalog port, read as the requesting tenant's own.
//!
//! Encoded extents of prepared files are listed without a stored location, since the
//! manifest names a prepared file by path and not by content key.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use super::catalog::{
    ArtifactCatalog, ArtifactImporter, CatalogRefusal, ExtentDescriptor, ExtentId, ImportRefusal,
    Provenance, StoredExtent, VerifiedRepresentation,
};
use super::declaration::SecurityPartition;
use crate::foundation::catalog::{ArtifactClass, ObjectId, ObjectStatus, ReadRefusal, Scope};
use crate::foundation::ids::{ContentKey, Digest, DigestBuilder, ExecutionId, TrustScope};
use crate::model_memory::executor::{
    CatalogPort, CatalogRefusal as ManifestRefusal, ManifestExtent, ResolveRequest,
    ResolvedManifest, SourceCandidate, StoredForm,
};
use crate::model_memory::identity::ArtifactIdentity;
use crate::model_memory::manifest::{
    CancellationToken, CatalogArtifacts, CatalogContext, ExtentEncoding, ExtentPlanner,
    IdentityLayers, ImportOutcome, ImportRequest, Importer, LayerContext, SourceFiles,
    SourceOrigin, SourceRevision, ValidatedManifest, ARTIFACT_LABEL,
};

/// How long a read back of a sidecar holds its catalog lease.
const READ_LEASE: Duration = Duration::from_secs(60);

/// Digest domain of a source origin in a representation's provenance.
pub const ORIGIN_DOMAIN: &str = "yougori/model-memory/boundaries/source-origin/v1";

/// Digest domain of a commit revision in a representation's provenance.
pub const REVISION_DOMAIN: &str = "yougori/model-memory/boundaries/source-revision/v1";

/// A catalog scope the store reads, and the trust scope its state lives in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogScope {
    pub trust: TrustScope,
    pub owner: Scope,
}

/// One model import: P01's request and the source its files are read from.
pub struct ModelImport<'s> {
    pub request: ImportRequest<LayerContext, CatalogContext>,
    pub source: &'s dyn SourceFiles,
    pub cancel: CancellationToken,
}

/// Why a sidecar could not be read back.
enum ReadFailure {
    NotGranted,
    NotPublished,
    Other(String),
}

impl ReadFailure {
    fn reason(&self) -> String {
        match self {
            Self::NotGranted => "the reader holds no grant for the sidecar".to_owned(),
            Self::NotPublished => "the sidecar is not published".to_owned(),
            Self::Other(reason) => reason.clone(),
        }
    }
}

/// Boundary 1 over the CORE-02 catalog and P01's importer.
pub struct ModelStore<E> {
    importer: Importer<CatalogArtifacts, IdentityLayers, E>,
    scopes: Vec<CatalogScope>,
    reader: ExecutionId,
}

impl<E: ExtentPlanner> ModelStore<E> {
    /// A store over `importer`'s catalog that reads the artifacts of `scopes`, as
    /// `reader`.
    pub fn new(
        importer: Importer<CatalogArtifacts, IdentityLayers, E>,
        scopes: Vec<CatalogScope>,
        reader: ExecutionId,
    ) -> Self {
        Self {
            importer,
            scopes,
            reader,
        }
    }

    /// The importer, for its catalog: originals, roots, grants and garbage collection.
    pub fn importer(&self) -> &Importer<CatalogArtifacts, IdentityLayers, E> {
        &self.importer
    }

    pub fn scopes(&self) -> &[CatalogScope] {
        &self.scopes
    }

    /// The published sidecar objects of `owner` that name `artifact`.
    fn sidecars(&self, owner: &Scope, artifact: &ArtifactIdentity) -> Vec<ObjectId> {
        let hex = artifact.digest().to_hex();
        let catalog = self.importer.catalog().catalog();
        catalog
            .objects(owner)
            .into_iter()
            .filter(|object| catalog.status(owner, *object) == ObjectStatus::Published)
            .filter(|object| {
                catalog
                    .private_metadata(owner, *object)
                    .is_ok_and(|private| {
                        private.class == ArtifactClass::ModelSidecar
                            && private.metadata.labels.get(ARTIFACT_LABEL) == Some(&hex)
                    })
            })
            .collect()
    }

    /// An object's bytes, read as `reader` of `scope` by `execution` under a short lease.
    fn read(
        &self,
        scope: &Scope,
        execution: &ExecutionId,
        object: ObjectId,
    ) -> Result<Vec<u8>, ReadFailure> {
        let refused = |refusal: ReadRefusal| match refusal {
            ReadRefusal::NotGranted { .. } => ReadFailure::NotGranted,
            ReadRefusal::NotPublished { .. } => ReadFailure::NotPublished,
            other => ReadFailure::Other(other.to_string()),
        };
        let mut catalog = self.importer.catalog().catalog();
        let lease = catalog
            .acquire_lease(scope, execution, object, READ_LEASE)
            .map_err(refused)?;
        let bytes = catalog
            .open_read(scope, execution, lease)
            .map_err(refused)
            .and_then(|mut handle| {
                handle
                    .read_all()
                    .map_err(|error| ReadFailure::Other(error.to_string()))
            });
        let released = catalog
            .release_lease(scope, execution, lease)
            .map_err(refused);
        let bytes = bytes?;
        released?;
        Ok(bytes)
    }

    /// The representation of `artifact` from its sidecar `object` in `scope`.
    fn read_representation(
        &self,
        scope: &CatalogScope,
        object: ObjectId,
        artifact: &ArtifactIdentity,
    ) -> Result<VerifiedRepresentation, CatalogRefusal> {
        let unreadable = |reason: String| CatalogRefusal::Unreadable {
            artifact: *artifact,
            reason,
        };
        let bytes = self
            .read(&scope.owner, &self.reader, object)
            .map_err(|failure| unreadable(failure.reason()))?;
        let sidecar = ContentKey::of(&bytes);
        if ObjectId::new(&scope.owner, ArtifactClass::ModelSidecar, sidecar) != object {
            return Err(unreadable(
                "the bytes read are not the sidecar object's content".to_owned(),
            ));
        }
        let manifest = ValidatedManifest::from_sidecar_bytes(&bytes)
            .map_err(|error| unreadable(error.to_string()))?;
        let identity = ArtifactIdentity::from_manifest_digest(&manifest.digest().digest());
        if identity != *artifact {
            return Err(unreadable(
                "the sidecar describes another artifact".to_owned(),
            ));
        }
        let body = manifest.manifest();
        let files = &body.provenance.files;
        let mut extents = Vec::with_capacity(body.extents.extents.len());
        for (index, extent) in body.extents.extents.iter().enumerate() {
            let number = u32::try_from(index)
                .map_err(|_| unreadable("the manifest has too many extents".to_owned()))?;
            let file = files
                .get(extent.file.index())
                .ok_or_else(|| unreadable("an extent names no source file".to_owned()))?;
            let stored = match extent.encoding {
                ExtentEncoding::Raw => Some(StoredExtent {
                    artifact: sidecar,
                    representation: file.content,
                    index: index as u64,
                    offset_bytes: extent.logical_offset_bytes,
                }),
                ExtentEncoding::Encoded(_) => None,
            };
            extents.push(ExtentDescriptor {
                extent: ExtentId::new(number),
                digest: extent.content_key,
                length_bytes: extent.true_length_bytes,
                stored,
            });
        }
        let objects: BTreeSet<ObjectId> =
            std::iter::once(object)
                .chain(files.iter().map(|file| {
                    ObjectId::new(&scope.owner, ArtifactClass::ModelWeights, file.content)
                }))
                .collect();
        let provenance = Provenance {
            source: origin_digest(&body.provenance.origin),
            revision: revision_digest(&body.provenance.revision),
            license: None,
        };
        Ok(VerifiedRepresentation::from_catalog(
            identity,
            scope.trust,
            provenance,
            extents,
            objects,
        ))
    }
}

/// The digest of a source origin: its kind and its name.
fn origin_digest(origin: &SourceOrigin) -> Digest {
    let builder = DigestBuilder::new(ORIGIN_DOMAIN);
    match origin {
        SourceOrigin::HuggingFace { repository } => {
            builder.str("hugging_face").str(repository.as_str())
        }
        SourceOrigin::Registry { model } => builder.str("registry").str(model.as_str()),
        SourceOrigin::LocalFolder => builder.str("local_folder"),
        SourceOrigin::Publisher { publisher } => builder.str("publisher").str(publisher.as_str()),
    }
    .finish()
}

/// The digest of an immutable revision: a commit's, or the content listing's own.
fn revision_digest(revision: &SourceRevision) -> Digest {
    match revision {
        SourceRevision::GitCommit(commit) => DigestBuilder::new(REVISION_DOMAIN)
            .str("git_commit")
            .bytes(commit.as_bytes())
            .finish(),
        SourceRevision::ContentListing(listing) => *listing,
    }
}

impl<E: ExtentPlanner> ArtifactCatalog for ModelStore<E> {
    fn representation(
        &self,
        artifact: &ArtifactIdentity,
        partition: &SecurityPartition,
    ) -> Result<VerifiedRepresentation, CatalogRefusal> {
        let mut outside = false;
        for scope in &self.scopes {
            let Some(object) = self.sidecars(&scope.owner, artifact).first().copied() else {
                continue;
            };
            if !partition.allows(&scope.trust) {
                outside = true;
                continue;
            }
            return self.read_representation(scope, object, artifact);
        }
        Err(if outside {
            CatalogRefusal::OutsidePartition {
                artifact: *artifact,
            }
        } else {
            CatalogRefusal::UnknownArtifact {
                artifact: *artifact,
            }
        })
    }
}

impl<'s, E: ExtentPlanner> ArtifactImporter<ModelImport<'s>> for ModelStore<E> {
    /// Runs P01's import protocol into a scope the store reads; a repeated import of the
    /// same key publishes nothing new.
    fn import(&mut self, submission: ModelImport<'s>) -> Result<ArtifactIdentity, ImportRefusal> {
        let scope = &submission.request.catalog.scope;
        if !self.scopes.iter().any(|bound| bound.owner == *scope) {
            return Err(ImportRefusal::Rejected {
                reason: format!("the store reads no artifacts of {scope}"),
            });
        }
        let outcome = self
            .importer
            .import(&submission.request, submission.source, &submission.cancel)
            .map_err(|error| ImportRefusal::Rejected {
                reason: error.to_string(),
            })?;
        let (ImportOutcome::Published(published) | ImportOutcome::AlreadyPublished(published)) =
            outcome;
        Ok(ArtifactIdentity::from_manifest_digest(
            &published.manifest.digest(),
        ))
    }
}

/// P03's catalog port over the store: the verified manifest of one source file of a
/// sidecar-backed artifact, and the sources it may be read from. The artifact is named by
/// its sidecar's content key and read as the requesting tenant's own; another tenant's
/// equal content is never found (S3.3).
pub struct StoreManifests<E> {
    store: Arc<ModelStore<E>>,
    sources: Vec<SourceCandidate>,
}

impl<E> StoreManifests<E> {
    /// Resolves from `store`, offering `sources`, in the catalog's order of preference.
    pub fn new(store: Arc<ModelStore<E>>, sources: Vec<SourceCandidate>) -> Self {
        Self { store, sources }
    }
}

impl<E: ExtentPlanner> CatalogPort for StoreManifests<E> {
    fn resolve(&self, request: &ResolveRequest) -> Result<ResolvedManifest, ManifestRefusal> {
        let owner = Scope::tenant(request.tenant.clone());
        if !self.store.scopes.iter().any(|scope| scope.owner == owner) {
            return Err(ManifestRefusal::NotFound);
        }
        let object = ObjectId::new(&owner, ArtifactClass::ModelSidecar, request.artifact);
        let bytes = self
            .store
            .read(&owner, &request.execution, object)
            .map_err(|failure| match failure {
                ReadFailure::NotGranted => ManifestRefusal::NotAuthorized,
                ReadFailure::NotPublished => ManifestRefusal::NotFound,
                ReadFailure::Other(_) => ManifestRefusal::NotVerified,
            })?;
        if ContentKey::of(&bytes) != request.artifact {
            return Err(ManifestRefusal::NotVerified);
        }
        let manifest = ValidatedManifest::from_sidecar_bytes(&bytes)
            .map_err(|_| ManifestRefusal::NotVerified)?;
        let body = manifest.manifest();
        let (file_index, file) = body
            .provenance
            .files
            .iter()
            .enumerate()
            .find(|(_, file)| file.content == request.representation)
            .ok_or(ManifestRefusal::NotFound)?;
        let extents = body
            .extents
            .extents
            .iter()
            .enumerate()
            .filter(|(_, extent)| {
                extent.file.index() == file_index && matches!(extent.encoding, ExtentEncoding::Raw)
            })
            .map(|(index, extent)| ManifestExtent {
                index: index as u64,
                stored_offset_bytes: extent.logical_offset_bytes,
                stored_length_bytes: extent.true_length_bytes,
                stored: StoredForm::Raw,
                decoded_offset_bytes: extent.logical_offset_bytes,
                decoded_length_bytes: extent.true_length_bytes,
                decoded_key: extent.content_key,
            })
            .collect();
        Ok(ResolvedManifest {
            manifest: request.artifact,
            artifact: request.artifact,
            representation: request.representation,
            object_length_bytes: file.length_bytes,
            extents,
            sources: self.sources.clone(),
            cuts: Vec::new(),
        })
    }
}
