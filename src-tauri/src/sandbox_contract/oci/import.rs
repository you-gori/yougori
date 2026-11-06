//! The importer: from a pinned image reference to published catalog objects (VM-W33;
//! §5.3; §8.3 line 2278; VM-P37; VM-CP-30).
//!
//! [`OciImporter::import`] fetches each blob from a [`BlobSource`] within its declared
//! size, verifies it against its descriptor before parsing it, parses the documents
//! strictly, selects the platform exactly, reads every layer and builds the tree. Only
//! when the whole image passed does it publish anything: each layer envelope as an
//! original and the tree envelope as a representation prepared from the layers, all of
//! class [`ArtifactClass::OciLayer`] in the request's scope, so a refused image leaves no
//! object behind. The scope's remaining quota is checked for all new objects first; a
//! failure inside the catalog after the first object was published (a storage error)
//! can still leave earlier layers published and unreferenced, since the catalog has no
//! multi-object transaction. Tier 0 keeps the verified blobs in memory until publication,
//! bounded by `max_image_compressed_bytes`.
//!
//! Publication goes through [`Catalog::begin_import`] every time, also when the object is
//! already there: the catalog re-checks the claim against the class's current trust policy
//! through [`OciVerifier`](super::OciVerifier), so a cache hit is held to the same policy as
//! the first download. Objects are identified per scope (S3.3), so importing the same
//! digests into another scope makes that scope's own objects under its own claim and
//! quota and never yields the first scope's objects; reading those needs the owner's
//! grant (see [`OverlayRegistry`](super::OverlayRegistry)).
//!
//! The importer writes only catalog staging under its own [`ExecutionId`], separate from
//! every consumer sandbox and from tenant data: it takes no file grant, volume or tenant
//! object, and nothing here creates files outside the catalog or starts a process.
//!
//! The import has three phases, so the layers can be read where §5.2 asks, inside a VM
//! (M15): [`OciImporter::prepare`] fetches and verifies every blob and parses only the
//! image's documents and provenance; the layers are then read, by
//! [`OciImporter::read_in_process`] (Tier 0 and tests) or by an importer VM whose tree
//! [`OciImporter::tree_from_body`] checks again with this module's own rules; and
//! [`OciImporter::publish_read`] publishes. [`OciImporter::import`] is the three in one.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use super::config::{parse_config, ConfigRefusal, ImageConfigRecord};
use super::digest::{BlobReference, BlobRefusal, MediaType, OciDigest, VerifiedBlob};
use super::document::{parse_index, parse_manifest, select_platform, DocumentRefusal, Platform};
use super::envelope::{layer_envelope, tree_envelope, Envelope, EnvelopeRefusal, TreeHeader};
use super::layer::{read_layer, ImageBudget, LayerRefusal, StreamRefusal};
use super::limits::{len_u64, ImportLimits, LimitsProblem};
use super::overlay::ImageObjects;
use super::tree::{TreeBuilder, TreeIndex, TreeRefusal, TreeSummary};
use super::verifier::{
    check_signature, OciAttestation, OciVerifier, PublisherSignatures, SignatureRefusal,
};
use crate::foundation::catalog::{
    ArtifactClass, Catalog, FailureRecord, ImportError, ImportManifest, ImportRefusal,
    ImportRequest, ImportSource, ImportStart, ImportStatus, ObjectId, ObjectMetadata, ObjectRole,
    PublisherId, Scope, SourceError, SourceIdentity, TrustClaim, Uninterrupted,
};
use crate::foundation::ids::{DigestBuilder, ExecutionId, OperationId};
use crate::sandbox_contract::files::{
    check_inspection, ArtifactOrigin, ImportInspection, InspectionMethod, InspectionRefusal,
};

/// Domain of the catalog source identities of OCI objects.
const SOURCE_DOMAIN: &str = "yougori/oci/source/v1";

/// Why a blob source could not deliver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobSourceError {
    pub detail: String,
}

impl fmt::Display for BlobSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

/// Where blobs come from, by digest. An implementation must not return more than
/// `max_bytes`; the importer checks the length and digest of whatever it returns.
pub trait BlobSource {
    fn read_blob(&mut self, digest: &OciDigest, max_bytes: u64)
        -> Result<Vec<u8>, BlobSourceError>;
}

/// An in-memory blob store, as a registry download or a local layout would supply.
#[derive(Clone, Debug, Default)]
pub struct MemoryBlobs {
    blobs: BTreeMap<OciDigest, Vec<u8>>,
}

impl MemoryBlobs {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores `bytes` under their own digest and returns it.
    pub fn insert(&mut self, bytes: Vec<u8>) -> OciDigest {
        let digest = OciDigest::of(&bytes);
        self.blobs.insert(digest, bytes);
        digest
    }

    /// Stores `bytes` under `digest` whatever they hash to, as a corrupt or hostile store
    /// would.
    pub fn insert_as(&mut self, digest: OciDigest, bytes: Vec<u8>) {
        self.blobs.insert(digest, bytes);
    }
}

impl BlobSource for MemoryBlobs {
    fn read_blob(
        &mut self,
        digest: &OciDigest,
        max_bytes: u64,
    ) -> Result<Vec<u8>, BlobSourceError> {
        let bytes = self.blobs.get(digest).ok_or_else(|| BlobSourceError {
            detail: format!("no blob {digest}"),
        })?;
        let length = usize::try_from(max_bytes)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        Ok(bytes.get(..length).unwrap_or(&[]).to_vec())
    }
}

/// What a request offers as the reason to trust the image. Only the catalog decides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OciTrust {
    /// Only the digests: integrity, never trust, so it is refused (§5.3).
    ChecksumOnly,
    /// A publisher's signature over the image manifest digest.
    Publisher {
        publisher: PublisherId,
        signature: Vec<u8>,
    },
    /// The importing tenant chose this image for its own scope.
    UserSelected,
}

/// One import as its caller declares it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OciImportRequest {
    pub operation: OperationId,
    /// The importer's own execution; its staging is separate from every consumer.
    pub importer: ExecutionId,
    /// The scope that will own the objects.
    pub scope: Scope,
    /// The pinned root: an image index or an image manifest, by digest and size.
    pub root: BlobReference,
    pub platform: Platform,
    pub trust: OciTrust,
    /// Where this parser runs. A host process or a host mount is refused (§5.2 line
    /// 2073); Tier 0 cannot check the declaration.
    pub inspection: InspectionMethod,
}

/// Which blob a fetch was for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobAt {
    Root,
    Manifest,
    Config,
    Layer { index: usize },
}

/// Which catalog object a publication was for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogStep {
    Layer { index: usize },
    Tree,
}

/// Why provenance was refused before any layer was read. The catalog decides trust; these
/// are early refusals that agree with it, never grants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProvenanceRefusal {
    /// A digest is never trust (§5.3).
    ChecksumIsNotTrust,
    /// The catalog's policy for OCI layers does not trust this publisher.
    PublisherNotTrusted { publisher: PublisherId },
    /// The signature does not verify for the claimed publisher over this manifest.
    SignatureRejected { refusal: SignatureRefusal },
}

/// Why an import failed. Nothing is published unless every layer and the tree passed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OciImportError {
    Limits {
        problem: LimitsProblem,
    },
    Inspection {
        refusal: InspectionRefusal,
    },
    Source {
        at: BlobAt,
        error: BlobSourceError,
    },
    Blob {
        at: BlobAt,
        refusal: BlobRefusal,
    },
    /// The root reference is neither an index nor a manifest.
    RootMediaType {
        media_type: MediaType,
    },
    Document {
        refusal: DocumentRefusal,
    },
    Config {
        refusal: ConfigRefusal,
    },
    Provenance {
        refusal: ProvenanceRefusal,
    },
    Layer {
        index: usize,
        refusal: LayerRefusal,
    },
    Tree {
        refusal: TreeRefusal,
    },
    Envelope {
        refusal: EnvelopeRefusal,
    },
    /// The scope's remaining quota cannot hold the image's new objects; nothing was
    /// published.
    QuotaShort {
        needed_bytes: u64,
        available_bytes: u64,
    },
    /// The catalog refused the object before writing anything (trust, quota, bounds).
    Catalog {
        step: CatalogStep,
        refusal: ImportRefusal,
    },
    /// The catalog's import ended without publishing, for example when the verifier's
    /// read-back rejected it.
    CatalogFailed {
        step: CatalogStep,
        failure: FailureRecord,
    },
    /// The catalog paused the import; nothing was published.
    CatalogPending {
        step: CatalogStep,
        last_failure: Option<FailureRecord>,
    },
    CatalogApi {
        step: CatalogStep,
        error: ImportError,
    },
}

impl fmt::Display for OciImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limits { problem } => problem.fmt(f),
            Self::Inspection { refusal } => refusal.fmt(f),
            Self::Source { at, error } => write!(f, "{at:?}: {error}"),
            Self::Blob { at, refusal } => write!(f, "{at:?}: {refusal}"),
            Self::RootMediaType { media_type } => {
                write!(f, "the root is {media_type}, not an index or manifest")
            }
            Self::Document { refusal } => refusal.fmt(f),
            Self::Config { refusal } => refusal.fmt(f),
            Self::Provenance { refusal } => write!(f, "provenance refused: {refusal:?}"),
            Self::Layer { index, refusal } => write!(f, "layer {index}: {refusal}"),
            Self::Tree { refusal } => refusal.fmt(f),
            Self::Envelope { refusal } => refusal.fmt(f),
            Self::QuotaShort {
                needed_bytes,
                available_bytes,
            } => write!(
                f,
                "{needed_bytes} bytes needed; the quota has {available_bytes} left"
            ),
            Self::Catalog { step, refusal } => write!(f, "{step:?}: {refusal}"),
            Self::CatalogFailed { step, failure } => {
                write!(
                    f,
                    "{step:?}: the catalog import failed: {:?}",
                    failure.reason
                )
            }
            Self::CatalogPending { step, .. } => write!(f, "{step:?}: the catalog import paused"),
            Self::CatalogApi { step, error } => write!(f, "{step:?}: {error}"),
        }
    }
}

impl std::error::Error for OciImportError {}

/// One published layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedLayer {
    pub object: ObjectId,
    pub reference: BlobReference,
    pub diff_id: OciDigest,
    pub compressed_bytes: u64,
    pub expanded_bytes: u64,
    /// The object was already published in this scope; the claim was re-checked.
    pub cache_hit: bool,
}

/// The published tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedTree {
    pub object: ObjectId,
    pub summary: TreeSummary,
    pub cache_hit: bool,
}

/// An imported image: its objects in one scope and its config as data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedImage {
    pub scope: Scope,
    pub importer: ExecutionId,
    pub manifest: OciDigest,
    pub config: ImageConfigRecord,
    pub layers: Vec<ImportedLayer>,
    pub tree: ImportedTree,
}

impl ImportedImage {
    /// The read-only bases an overlay is built on.
    pub fn objects(&self) -> ImageObjects {
        ImageObjects {
            owner: self.scope.clone(),
            importer: self.importer.clone(),
            tree: self.tree.object,
            layers: self.layers.iter().map(|layer| layer.object).collect(),
        }
    }
}

/// An envelope as a catalog import source.
struct EnvelopeSource<'a> {
    identity: SourceIdentity,
    bytes: &'a [u8],
}

impl ImportSource for EnvelopeSource<'_> {
    fn identity(&self) -> SourceIdentity {
        self.identity
    }

    fn length_bytes(&mut self) -> Result<u64, SourceError> {
        Ok(len_u64(self.bytes.len()))
    }

    fn read_at(&mut self, offset_bytes: u64, buffer: &mut [u8]) -> Result<usize, SourceError> {
        let start = usize::try_from(offset_bytes).map_err(|_| SourceError {
            detail: "offset out of range".into(),
        })?;
        let rest = self.bytes.get(start..).unwrap_or(&[]);
        let count = rest.len().min(buffer.len());
        if let (Some(target), Some(source)) = (buffer.get_mut(..count), rest.get(..count)) {
            target.copy_from_slice(source);
        }
        Ok(count)
    }
}

/// The OCI importer (VM-W33).
#[derive(Clone)]
pub struct OciImporter {
    limits: ImportLimits,
    signatures: Arc<dyn PublisherSignatures>,
}

impl fmt::Debug for OciImporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OciImporter")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

struct Image {
    manifest_bytes: Vec<u8>,
    manifest_digest: OciDigest,
    config_bytes: Vec<u8>,
    config_digest: OciDigest,
    config: ImageConfigRecord,
}

/// An image fetched and verified, its documents parsed and its provenance checked; its layer
/// blobs are verified against their descriptors and not read yet (module docs).
pub struct PreparedImage {
    image: Image,
    request: OciImportRequest,
    /// Each layer's verified blob and the diff_id the config names for it.
    layers: Vec<(VerifiedBlob, OciDigest)>,
}

impl fmt::Debug for PreparedImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedImage")
            .field("manifest", &self.image.manifest_digest)
            .field("layers", &self.layers.len())
            .finish_non_exhaustive()
    }
}

impl PreparedImage {
    /// The image manifest's digest.
    pub fn manifest(&self) -> OciDigest {
        self.image.manifest_digest
    }

    /// The image config's digest.
    pub fn config_digest(&self) -> OciDigest {
        self.image.config_digest
    }

    /// The image config, as data.
    pub fn config(&self) -> &ImageConfigRecord {
        &self.image.config
    }

    /// Each layer's verified blob and its diff_id, in order.
    pub fn layers(&self) -> impl Iterator<Item = (&VerifiedBlob, &OciDigest)> {
        self.layers.iter().map(|(blob, diff_id)| (blob, diff_id))
    }
}

/// What reading an image's layers came to: the tree and each layer's expanded size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadLayers {
    manifest: OciDigest,
    tree: TreeIndex,
    expanded_bytes: Vec<u64>,
}

impl ReadLayers {
    pub fn tree(&self) -> &TreeIndex {
        &self.tree
    }

    pub fn expanded_bytes(&self) -> &[u64] {
        &self.expanded_bytes
    }
}

struct Publication<'a> {
    request: &'a OciImportRequest,
    image: &'a Image,
}

/// One object ready to publish: its envelope, declaration, source and private labels.
struct Planned {
    envelope: Envelope,
    manifest: ImportManifest,
    source: SourceIdentity,
    step: CatalogStep,
    metadata: ObjectMetadata,
}

/// Refuses before anything is published when the scope's remaining quota cannot hold
/// every object not already published there, so a short quota never leaves part of an
/// image behind. The catalog still reserves each object itself.
fn check_quota<'a>(
    catalog: &Catalog,
    scope: &Scope,
    planned: impl Iterator<Item = &'a Planned>,
) -> Result<(), OciImportError> {
    let mut seen = BTreeSet::new();
    let mut needed_bytes = 0u64;
    for plan in planned {
        let key = plan.manifest.content_key;
        if seen.insert(key) && catalog.find(scope, ArtifactClass::OciLayer, key).is_none() {
            needed_bytes = needed_bytes.saturating_add(plan.manifest.true_length_bytes);
        }
    }
    let usage = catalog.quota_usage(scope);
    let available_bytes = usage
        .limit_bytes
        .map_or(0, |limit| limit.saturating_sub(usage.charged_bytes()));
    if needed_bytes > available_bytes {
        return Err(OciImportError::QuotaShort {
            needed_bytes,
            available_bytes,
        });
    }
    Ok(())
}

impl OciImporter {
    /// Local owner-selected images when no publisher roots are configured. This port
    /// never authenticates a publisher; the catalog must still allow UserSelected.
    pub fn local_owner(limits: ImportLimits) -> Result<Self, LimitsProblem> {
        struct NoPublisher;
        impl PublisherSignatures for NoPublisher {
            fn verify(
                &self,
                _: &PublisherId,
                _: &crate::foundation::ids::Digest,
                _: &[u8],
            ) -> Result<(), SignatureRefusal> {
                Err(SignatureRefusal::UnknownPublisher)
            }
        }
        Self::new(limits, Arc::new(NoPublisher))
    }

    /// An importer under `limits`, which must be enforceable, verifying publisher
    /// signatures through `signatures`.
    pub fn new(
        limits: ImportLimits,
        signatures: Arc<dyn PublisherSignatures>,
    ) -> Result<Self, LimitsProblem> {
        limits.validate()?;
        Ok(Self { limits, signatures })
    }

    /// The limits every import is held to.
    pub fn limits(&self) -> &ImportLimits {
        &self.limits
    }

    /// The catalog verifier for this importer's objects, to register when the catalog is
    /// opened; it shares the importer's limits and signature port, and reads layer
    /// envelopes' tar streams in this process (Tier 0 and the tests).
    pub fn verifier(&self) -> OciVerifier {
        OciVerifier::with_checked_limits(Arc::clone(&self.signatures), self.limits)
    }

    /// The catalog verifier the engine registers: like [`Self::verifier`], but it checks a
    /// layer envelope by its blob's digest and size and never parses the tar stream on the
    /// host (§5.2): the layers were read inside the importer VM, and every consumer VM checks
    /// each file and the diff_id as it materializes them.
    pub fn boundary_verifier(&self) -> OciVerifier {
        OciVerifier::with_checked_limits(Arc::clone(&self.signatures), self.limits)
            .without_host_layer_parsing()
    }

    fn fetch(
        &self,
        blobs: &mut dyn BlobSource,
        at: BlobAt,
        reference: BlobReference,
        limit_bytes: u64,
    ) -> Result<VerifiedBlob, OciImportError> {
        if reference.size_bytes > limit_bytes {
            return Err(OciImportError::Blob {
                at,
                refusal: BlobRefusal::DeclaredTooLarge {
                    size_bytes: reference.size_bytes,
                    limit_bytes,
                },
            });
        }
        let bytes = blobs
            .read_blob(&reference.digest, reference.size_bytes)
            .map_err(|error| OciImportError::Source { at, error })?;
        VerifiedBlob::verify(reference, bytes)
            .map_err(|refusal| OciImportError::Blob { at, refusal })
    }

    /// Imports the image `request` pins into `catalog` (VM-W33): [`Self::prepare`], the
    /// layers read here ([`Self::read_in_process`]) and [`Self::publish_read`].
    pub fn import(
        &self,
        catalog: &mut Catalog,
        blobs: &mut dyn BlobSource,
        request: &OciImportRequest,
    ) -> Result<ImportedImage, OciImportError> {
        let prepared = self.prepare(catalog, blobs, request)?;
        let read = self.read_in_process(&prepared)?;
        self.publish_read(catalog, request, prepared, read)
    }

    /// Fetches and verifies every blob of the image `request` pins, parses its documents
    /// and checks its provenance against `catalog`'s policy; reads no layer.
    pub fn prepare(
        &self,
        catalog: &Catalog,
        blobs: &mut dyn BlobSource,
        request: &OciImportRequest,
    ) -> Result<PreparedImage, OciImportError> {
        check_inspection(&ImportInspection {
            origin: ArtifactOrigin::TrustedImporter,
            filesystem_image: false,
            method: request.inspection,
        })
        .map_err(|refusal| OciImportError::Inspection { refusal })?;
        let document = |refusal| OciImportError::Document { refusal };
        let manifest_blob = match request.root.media_type {
            MediaType::ImageIndex | MediaType::DockerIndex => {
                let root = self.fetch(
                    blobs,
                    BlobAt::Root,
                    request.root,
                    self.limits.max_document_bytes,
                )?;
                let index = parse_index(&root, &self.limits).map_err(document)?;
                let chosen = select_platform(&index, &request.platform).map_err(document)?;
                self.fetch(
                    blobs,
                    BlobAt::Manifest,
                    chosen.reference(),
                    self.limits.max_document_bytes,
                )?
            }
            MediaType::ImageManifest | MediaType::DockerManifest => self.fetch(
                blobs,
                BlobAt::Root,
                request.root,
                self.limits.max_document_bytes,
            )?,
            media_type => return Err(OciImportError::RootMediaType { media_type }),
        };
        let manifest = parse_manifest(&manifest_blob, &self.limits).map_err(document)?;
        let config_blob = self.fetch(
            blobs,
            BlobAt::Config,
            manifest.config.reference(),
            self.limits.max_document_bytes,
        )?;
        let config = parse_config(
            &config_blob,
            manifest.layers.len(),
            &request.platform,
            &self.limits,
        )
        .map_err(|refusal| OciImportError::Config { refusal })?;
        let image = Image {
            manifest_digest: manifest_blob.reference().digest,
            manifest_bytes: manifest_blob.bytes().to_vec(),
            config_digest: config_blob.reference().digest,
            config_bytes: config_blob.bytes().to_vec(),
            config,
        };
        self.check_provenance(catalog, request, &image)?;

        let mut remaining_compressed_bytes = self.limits.max_image_compressed_bytes;
        let mut layers = Vec::with_capacity(manifest.layers.len());
        for (index, (descriptor, diff_id)) in manifest
            .layers
            .iter()
            .zip(&image.config.diff_ids)
            .enumerate()
        {
            let limit_bytes = self.limits.max_layer_compressed_bytes;
            if descriptor.size_bytes > remaining_compressed_bytes
                && descriptor.size_bytes <= limit_bytes
            {
                return Err(OciImportError::Layer {
                    index,
                    refusal: LayerRefusal::Stream {
                        refusal: StreamRefusal::ImageCompressedTooLarge {
                            total_bytes: descriptor.size_bytes,
                            limit_bytes: remaining_compressed_bytes,
                        },
                    },
                });
            }
            let blob = self.fetch(
                blobs,
                BlobAt::Layer { index },
                descriptor.reference(),
                limit_bytes,
            )?;
            remaining_compressed_bytes =
                remaining_compressed_bytes.saturating_sub(descriptor.size_bytes);
            layers.push((blob, *diff_id));
        }
        Ok(PreparedImage {
            image,
            layers,
            request: request.clone(),
        })
    }

    /// Reads `prepared`'s layers in this process and builds the tree: Tier 0 and the tests,
    /// and the reference the importer VM's tree is held to. The engine reads layers only
    /// inside a VM (§5.2).
    pub fn read_in_process(&self, prepared: &PreparedImage) -> Result<ReadLayers, OciImportError> {
        let mut budget = ImageBudget::new(&self.limits);
        let mut tree = TreeBuilder::new(&self.limits);
        let mut expanded_bytes = Vec::with_capacity(prepared.layers.len());
        for (index, (blob, diff_id)) in prepared.layers.iter().enumerate() {
            let report = read_layer(blob, diff_id, &self.limits, &mut budget)
                .map_err(|refusal| OciImportError::Layer { index, refusal })?;
            tree.apply(&report)
                .map_err(|refusal| OciImportError::Tree { refusal })?;
            expanded_bytes.push(report.expanded_bytes);
        }
        let tree = tree
            .finish()
            .map_err(|refusal| OciImportError::Tree { refusal })?;
        Ok(ReadLayers {
            manifest: prepared.manifest(),
            tree,
            expanded_bytes,
        })
    }

    /// Takes the tree an importer VM computed from `prepared`'s layers (`body`, the tree
    /// index body, and each layer's expanded size as the VM reported it) and checks it again
    /// with this module's own rules: strict JSON, every name, parent, link and bound
    /// ([`TreeIndex`]'s whole-tree checks), no setuid or setgid bit, and expanded sizes
    /// within the limits. The bytes the tree names are checked by every consumer VM as it
    /// materializes the image.
    pub fn tree_from_body(
        &self,
        prepared: &PreparedImage,
        body: &[u8],
        expanded_bytes: Vec<u64>,
    ) -> Result<ReadLayers, OciImportError> {
        let layers = u32::try_from(prepared.layers.len()).map_err(|_| OciImportError::Tree {
            refusal: TreeRefusal::TooManyLayers,
        })?;
        if len_u64(body.len()) > self.limits.max_tree_object_bytes {
            return Err(OciImportError::Tree {
                refusal: TreeRefusal::Malformed {
                    detail: format!(
                        "a {}-byte tree; at most {}",
                        body.len(),
                        self.limits.max_tree_object_bytes
                    ),
                },
            });
        }
        let tree = TreeIndex::from_body(body, layers, &self.limits)
            .map_err(|refusal| OciImportError::Tree { refusal })?;
        if let Some(entry) = tree.entries.iter().find(|entry| {
            matches!(
                entry.node,
                super::tree::TreeNode::Directory { mode, .. } | super::tree::TreeNode::File { mode, .. }
                    if mode & 0o6000 != 0 || mode & !0o7777 != 0
            )
        }) {
            return Err(OciImportError::Tree {
                refusal: TreeRefusal::Malformed {
                    detail: format!("{} has privileged or unsupported mode bits", entry.name),
                },
            });
        }
        let total = expanded_bytes
            .iter()
            .try_fold(0u64, |sum, bytes| sum.checked_add(*bytes));
        if expanded_bytes.len() != prepared.layers.len()
            || expanded_bytes
                .iter()
                .any(|bytes| *bytes > self.limits.max_layer_expanded_bytes)
            || total.is_none_or(|total| total > self.limits.max_image_expanded_bytes)
            || expanded_bytes
                .iter()
                .zip(&prepared.layers)
                .any(|(expanded, (blob, _))| {
                    *expanded > len_u64(blob.bytes().len()).saturating_mul(self.limits.max_ratio)
                })
        {
            return Err(OciImportError::Tree {
                refusal: TreeRefusal::Malformed {
                    detail: "the layers' expanded sizes are not within the limits".to_owned(),
                },
            });
        }
        for entry in &tree.entries {
            if let super::tree::TreeNode::File { content, .. } = &entry.node {
                let extent = expanded_bytes[content.layer as usize];
                if content.data_offset_bytes > extent
                    || content.size_bytes > extent - content.data_offset_bytes
                {
                    return Err(OciImportError::Tree {
                        refusal: TreeRefusal::Malformed {
                            detail: format!("{} exceeds its layer's expanded extent", entry.name),
                        },
                    });
                }
            }
        }
        Ok(ReadLayers {
            manifest: prepared.manifest(),
            tree,
            expanded_bytes,
        })
    }

    /// Publishes `prepared` with the layers `read` came to into `catalog`, as `request`
    /// declares: each layer envelope as an original, then the tree as a representation
    /// prepared from them; the scope's quota is checked for all of them first.
    pub fn publish_read(
        &self,
        catalog: &mut Catalog,
        request: &OciImportRequest,
        prepared: PreparedImage,
        read: ReadLayers,
    ) -> Result<ImportedImage, OciImportError> {
        if prepared.request != *request || prepared.manifest() != read.manifest {
            return Err(OciImportError::Tree {
                refusal: TreeRefusal::Malformed {
                    detail: "the prepared image, request and parsed tree do not belong to the same import".into(),
                },
            });
        }
        let PreparedImage { image, layers, .. } = prepared;
        let ReadLayers {
            tree,
            expanded_bytes,
            ..
        } = read;
        let publication = Publication {
            request,
            image: &image,
        };
        let mut planned = Vec::with_capacity(layers.len());
        for (index, (blob, diff_id)) in layers.iter().enumerate() {
            let envelope = layer_envelope(blob, *diff_id)
                .map_err(|refusal| OciImportError::Envelope { refusal })?;
            let reference = blob.reference();
            planned.push(
                self.plan(
                    envelope,
                    DigestBuilder::new(SOURCE_DOMAIN)
                        .str("layer")
                        .str(reference.media_type.as_str())
                        .bytes(reference.digest.as_bytes())
                        .bytes(diff_id.as_bytes()),
                    CatalogStep::Layer { index },
                    ObjectMetadata::new()
                        .with_label("oci.kind", "layer")
                        .with_label("oci.digest", reference.digest.to_string())
                        .with_label("oci.diff_id", diff_id.to_string())
                        .with_label("oci.media_type", reference.media_type.as_str()),
                ),
            );
        }
        let header = TreeHeader {
            manifest: image.manifest_digest,
            config: image.config_digest,
            layers: layers
                .iter()
                .map(|(blob, _)| blob.reference().digest)
                .collect(),
            diff_ids: image.config.diff_ids.clone(),
        };
        let tree_plan = self.plan(
            tree_envelope(&header, &tree)
                .map_err(|refusal| OciImportError::Envelope { refusal })?,
            DigestBuilder::new(SOURCE_DOMAIN)
                .str("tree")
                .bytes(image.manifest_digest.as_bytes()),
            CatalogStep::Tree,
            ObjectMetadata::new()
                .with_label("oci.kind", "tree")
                .with_label("oci.manifest", image.manifest_digest.to_string()),
        );
        check_quota(catalog, &request.scope, planned.iter().chain([&tree_plan]))?;

        let mut imported = Vec::with_capacity(layers.len());
        for ((plan, (blob, diff_id)), expanded) in planned.iter().zip(&layers).zip(&expanded_bytes)
        {
            let (object, cache_hit) =
                self.publish(catalog, &publication, plan, ObjectRole::Original)?;
            imported.push(ImportedLayer {
                object,
                reference: *blob.reference(),
                diff_id: *diff_id,
                compressed_bytes: len_u64(blob.bytes().len()),
                expanded_bytes: *expanded,
                cache_hit,
            });
        }
        let derived_from: BTreeSet<ObjectId> = imported.iter().map(|layer| layer.object).collect();
        let (object, cache_hit) = self.publish(
            catalog,
            &publication,
            &tree_plan,
            ObjectRole::Prepared { derived_from },
        )?;
        Ok(ImportedImage {
            scope: request.scope.clone(),
            importer: request.importer.clone(),
            manifest: image.manifest_digest,
            config: image.config,
            layers: imported,
            tree: ImportedTree {
                object,
                summary: tree.summary,
                cache_hit,
            },
        })
    }

    fn plan(
        &self,
        envelope: Envelope,
        source: DigestBuilder,
        step: CatalogStep,
        metadata: ObjectMetadata,
    ) -> Planned {
        Planned {
            manifest: envelope.import_manifest(self.limits.extent_bytes),
            envelope,
            source: SourceIdentity::from_digest(source.finish()),
            step,
            metadata,
        }
    }

    /// Early refusals that agree with the catalog's decision: a checksum is not trust, the
    /// class policy must trust the publisher, and the signature must verify. Passing these
    /// grants nothing; the catalog decides at publication.
    fn check_provenance(
        &self,
        catalog: &Catalog,
        request: &OciImportRequest,
        image: &Image,
    ) -> Result<(), OciImportError> {
        let refuse = |refusal| Err(OciImportError::Provenance { refusal });
        match &request.trust {
            OciTrust::ChecksumOnly => refuse(ProvenanceRefusal::ChecksumIsNotTrust),
            OciTrust::UserSelected => Ok(()),
            OciTrust::Publisher {
                publisher,
                signature,
            } => {
                let trusted = catalog
                    .config()
                    .trust
                    .get(&ArtifactClass::OciLayer)
                    .is_some_and(|policy| policy.trusts(publisher));
                if !trusted {
                    return refuse(ProvenanceRefusal::PublisherNotTrusted {
                        publisher: *publisher,
                    });
                }
                check_signature(
                    self.signatures.as_ref(),
                    publisher,
                    &image.manifest_digest,
                    signature,
                )
                .or_else(|refusal| refuse(ProvenanceRefusal::SignatureRejected { refusal }))
            }
        }
    }

    fn publish(
        &self,
        catalog: &mut Catalog,
        publication: &Publication<'_>,
        plan: &Planned,
        role: ObjectRole,
    ) -> Result<(ObjectId, bool), OciImportError> {
        let request = publication.request;
        let step = plan.step;
        let trust = match &request.trust {
            OciTrust::ChecksumOnly => TrustClaim::ChecksumOnly,
            OciTrust::UserSelected => TrustClaim::UserSelected,
            OciTrust::Publisher {
                publisher,
                signature,
            } => TrustClaim::Publisher {
                publisher: *publisher,
                attestation: OciAttestation {
                    manifest: publication.image.manifest_bytes.clone(),
                    config: publication.image.config_bytes.clone(),
                    signature: signature.clone(),
                    prefix: plan.envelope.prefix().to_vec(),
                    import_manifest: plan.manifest.clone(),
                }
                .encode(),
            },
        };
        let mut source = EnvelopeSource {
            identity: plan.source,
            bytes: &plan.envelope.bytes,
        };
        let start = catalog
            .begin_import(
                ImportRequest {
                    operation: request.operation.clone(),
                    execution: request.importer.clone(),
                    scope: request.scope.clone(),
                    class: ArtifactClass::OciLayer,
                    role,
                    manifest: plan.manifest.clone(),
                    trust,
                    depends_on: BTreeSet::new(),
                    metadata: plan.metadata.clone(),
                },
                source.identity,
            )
            .map_err(|refusal| OciImportError::Catalog { step, refusal })?;
        let ticket = match start {
            ImportStart::AlreadyPublished(object) => return Ok((object, true)),
            ImportStart::Started(ticket) | ImportStart::Attached(ticket) => ticket,
        };
        let outcome = match catalog.drive_import(&ticket, &mut source, &mut Uninterrupted) {
            Ok(ImportStatus::Published { object, .. }) => Ok((object, false)),
            Ok(ImportStatus::Failed { failure }) => {
                Err(OciImportError::CatalogFailed { step, failure })
            }
            Ok(ImportStatus::Pending { last_failure, .. }) => {
                Err(OciImportError::CatalogPending { step, last_failure })
            }
            Err(error) => Err(OciImportError::CatalogApi { step, error }),
        };
        catalog.cancel_import(ticket);
        outcome
    }
}
