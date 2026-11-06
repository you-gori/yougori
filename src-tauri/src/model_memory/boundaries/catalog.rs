//! Boundary 1 of GPU §3.1: the artifact catalog and importer.
//!
//! Responsibility: verified immutable representations and provenance. Must not own:
//! requests, credentials in artifacts, GPU scheduling. Both traits take only artifact
//! identities, a security partition or an import submission, and return only verified
//! representations; no request, device, lease or priority type reaches them. Provenance
//! is typed digests only, so an artifact has no field that could carry a credential.
//! Consumers get read-only representations; only an importer publishes (line 306).
//!
//! Model extents are named by the shared [`ContentKey`] that transfer orders verify. The
//! CORE-02 object catalog (T05) names an object by its [`ObjectId`] (scope, class and
//! content key) and checks stored extents against its own extent digests; P01's sidecar
//! manifest binds each model extent to its decoded content key and to the source file it
//! is stored in. [`ModelStore`](super::ModelStore) implements both traits over the
//! catalog and P01's importer, and names a stored extent by those same keys
//! ([`StoredExtent`]): the sidecar's content key for the artifact and the source file's
//! for the stored object, which are what the transfer executor (P03) resolves and reads.
//! Verified artifacts are named as the catalog and the coordinator name them: the digest
//! of each catalog object the representation was read from
//! ([`VerifiedRepresentation::verified_artifacts`]). [`verify_submission`] is the
//! verification of a submission of raw extents, which no catalog object holds.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::declaration::SecurityPartition;
use crate::foundation::catalog::ObjectId;
use crate::foundation::ids::{ContentKey, Digest, DigestBuilder, TrustScope};
use crate::model_memory::identity::ArtifactIdentity;

/// One extent of an artifact, numbered within it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExtentId(u32);

impl ExtentId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// One extent of one exact artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ExtentRef {
    pub artifact: ArtifactIdentity,
    pub extent: ExtentId,
}

/// Where a catalog stores an extent, in the names the catalog (CORE-02), the sidecar
/// manifest (P01) and the transfer executor (P03) share: the content key of the artifact's
/// sidecar, the content key of the stored object its bytes are read from, its index in the
/// artifact's manifest and its offset in the stored object's decoded bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct StoredExtent {
    pub artifact: ContentKey,
    pub representation: ContentKey,
    pub index: u64,
    pub offset_bytes: u64,
}

/// An extent's verified content key and true length, and where it is stored when a
/// catalog object holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ExtentDescriptor {
    pub extent: ExtentId,
    pub digest: ContentKey,
    pub length_bytes: u64,
    /// `None` when no catalog object holds the extent in a form a transfer can read, as
    /// for a submission of raw extents or an encoded extent of a prepared file.
    pub stored: Option<StoredExtent>,
}

/// The artifact identity (T07 layer 4) of a set of extents, from a digest bound to every
/// extent's number, length and content key in order. The digest stands in for the P01
/// manifest digest in the verification of raw extents.
fn manifest_identity(extents: &[ExtentDescriptor]) -> ArtifactIdentity {
    let builder = extents.iter().fold(
        DigestBuilder::new("yougori/model-memory/boundaries/manifest/v1").u64(extents.len() as u64),
        |builder, extent| {
            builder
                .u64(u64::from(extent.extent.get()))
                .u64(extent.length_bytes)
                .digest(extent.digest.digest())
        },
    );
    ArtifactIdentity::from_manifest_digest(&builder.finish())
}

/// Where an artifact came from (GPU §3.2 item 1): typed digests only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Provenance {
    /// The repository or local source.
    pub source: Digest,
    /// The immutable revision.
    pub revision: Digest,
    /// The licence, when the representation records one. A P01 sidecar does not: the
    /// licence is bound into the T07 source identity its import was keyed by.
    pub license: Option<Digest>,
}

/// A verified, immutable artifact representation. It is made only by
/// [`verify_submission`] or by the catalog store from a sidecar it read back from the
/// catalog and validated, so every value has passed verification; nothing mutates it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VerifiedRepresentation {
    artifact: ArtifactIdentity,
    scope: TrustScope,
    provenance: Provenance,
    extents: Vec<ExtentDescriptor>,
    objects: BTreeSet<ObjectId>,
}

impl VerifiedRepresentation {
    /// A representation the catalog store read from `objects` and validated; extents in
    /// ascending order of their numbers.
    pub(super) fn from_catalog(
        artifact: ArtifactIdentity,
        scope: TrustScope,
        provenance: Provenance,
        extents: Vec<ExtentDescriptor>,
        objects: BTreeSet<ObjectId>,
    ) -> Self {
        Self {
            artifact,
            scope,
            provenance,
            extents,
            objects,
        }
    }

    pub fn artifact(&self) -> ArtifactIdentity {
        self.artifact
    }

    pub fn scope(&self) -> TrustScope {
        self.scope
    }

    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    /// Extents in ascending order of their numbers.
    pub fn extents(&self) -> &[ExtentDescriptor] {
        &self.extents
    }

    pub fn extent(&self, extent: ExtentId) -> Option<&ExtentDescriptor> {
        self.extents
            .binary_search_by_key(&extent, |descriptor| descriptor.extent)
            .ok()
            .and_then(|index| self.extents.get(index))
    }

    /// The catalog objects the representation was read from: its sidecar and the source
    /// files it indexes. Empty for a representation no catalog object holds.
    pub fn objects(&self) -> &BTreeSet<ObjectId> {
        &self.objects
    }

    /// The representation's verified artifacts as the catalog's
    /// [`artifact_verification`](crate::foundation::catalog::Catalog::artifact_verification)
    /// and the coordinator's settings grant and model-cache check name them: the digest of
    /// each catalog object it was read from.
    pub fn verified_artifacts(&self) -> BTreeSet<Digest> {
        self.objects.iter().map(|object| object.digest()).collect()
    }
}

/// Why the catalog refused a read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum CatalogRefusal {
    UnknownArtifact {
        artifact: ArtifactIdentity,
    },
    /// The artifact exists only in scopes the partition holds no grant for (S3.3).
    OutsidePartition {
        artifact: ArtifactIdentity,
    },
    UnknownExtent {
        extent: ExtentRef,
    },
    /// The catalog holds the artifact but could not read it back or validate it; nothing
    /// of it is used.
    Unreadable {
        artifact: ArtifactIdentity,
        reason: String,
    },
}

impl fmt::Display for CatalogRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownArtifact { .. } => f.write_str("the catalog has no such artifact"),
            Self::OutsidePartition { .. } => {
                f.write_str("the artifact is outside the request's security partition")
            }
            Self::UnknownExtent { .. } => f.write_str("the artifact has no such extent"),
            Self::Unreadable { reason, .. } => {
                write!(f, "the artifact could not be read back: {reason}")
            }
        }
    }
}

/// Read side of the catalog: what consumers see.
pub trait ArtifactCatalog {
    /// The verified representation of an exact artifact, if the partition may read it.
    fn representation(
        &self,
        artifact: &ArtifactIdentity,
        partition: &SecurityPartition,
    ) -> Result<VerifiedRepresentation, CatalogRefusal>;
}

/// One extent offered for import, with the content key its source claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedExtent {
    pub extent: ExtentId,
    pub claimed_digest: ContentKey,
    pub content: Vec<u8>,
}

/// Everything an import of raw extents publishes: content, scope and provenance, and
/// nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportSubmission {
    pub scope: TrustScope,
    pub provenance: Provenance,
    pub extents: Vec<ImportedExtent>,
}

/// Why an import was refused; nothing is published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum ImportRefusal {
    NoExtents,
    DuplicateExtent {
        extent: ExtentId,
    },
    EmptyExtent {
        extent: ExtentId,
    },
    /// The content does not match its claimed key; it is never published.
    DigestMismatch {
        extent: ExtentId,
        claimed: ContentKey,
        actual: ContentKey,
    },
    /// The dedicated importer refused or stopped, in its own words.
    Rejected {
        reason: String,
    },
}

impl fmt::Display for ImportRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoExtents => f.write_str("the import has no extents"),
            Self::DuplicateExtent { extent } => write!(f, "extent {} appears twice", extent.0),
            Self::EmptyExtent { extent } => write!(f, "extent {} is empty", extent.0),
            Self::DigestMismatch { extent, .. } => {
                write!(f, "extent {} does not match its digest", extent.0)
            }
            Self::Rejected { reason } => write!(f, "the importer refused: {reason}"),
        }
    }
}

/// Write side of the catalog: the dedicated importer, the only writer (line 306). `S` is
/// what one import reads from: raw extents by default, or a model's source files for the
/// catalog store's P01 importer.
pub trait ArtifactImporter<S = ImportSubmission> {
    /// Verifies and publishes atomically: either every extent is published or none is.
    fn import(&mut self, submission: S) -> Result<ArtifactIdentity, ImportRefusal>;
}

/// The verification of a submission of raw extents before publishing: each extent is
/// non-empty, numbered once and matches its claimed content key. No catalog object holds
/// the result.
pub fn verify_submission(
    submission: &ImportSubmission,
) -> Result<VerifiedRepresentation, ImportRefusal> {
    if submission.extents.is_empty() {
        return Err(ImportRefusal::NoExtents);
    }
    let mut seen = BTreeSet::new();
    let mut extents = Vec::with_capacity(submission.extents.len());
    for imported in &submission.extents {
        if !seen.insert(imported.extent) {
            return Err(ImportRefusal::DuplicateExtent {
                extent: imported.extent,
            });
        }
        if imported.content.is_empty() {
            return Err(ImportRefusal::EmptyExtent {
                extent: imported.extent,
            });
        }
        let actual = ContentKey::of(&imported.content);
        if actual != imported.claimed_digest {
            return Err(ImportRefusal::DigestMismatch {
                extent: imported.extent,
                claimed: imported.claimed_digest,
                actual,
            });
        }
        extents.push(ExtentDescriptor {
            extent: imported.extent,
            digest: actual,
            length_bytes: imported.content.len() as u64,
            stored: None,
        });
    }
    extents.sort_by_key(|descriptor| descriptor.extent);
    Ok(VerifiedRepresentation {
        artifact: manifest_identity(&extents),
        scope: submission.scope,
        provenance: submission.provenance,
        extents,
        objects: BTreeSet::new(),
    })
}
