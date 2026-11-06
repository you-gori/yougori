//! The model-file import entry over the engine's catalog (S02, "connect model files ... to
//! the existing scoped catalog ... Preserve originals"; GPU-W03: "Integrate CORE-02
//! publication, interrupted-import recovery, quotas and lease-aware garbage collection";
//! G04/S02 in docs/combined-plan-remaining-only.md §8: "Exercise interrupted publication,
//! quota/disk-full, alternate-source and lease-aware cleanup paths while retaining
//! original files"; Appendix C, local folders).
//!
//! [`ModelFiles::import`] takes one model folder the tenant chose and its listing (every
//! file with its length, content key and role) and:
//!
//! 1. **verifies every file before publishing any**: one read of each file checks its
//!    length and content key against the listing and builds the catalog declaration of its
//!    extents, unless the caller declared the file already while reading it for its content
//!    key ([`ModelFileImport::declared`]: the import's identity and declarations are
//!    established before the import, and nothing is read twice before the copy). A file
//!    already published in the tenant's scope is not read again ("Repeated imports do not
//!    multiply disk usage");
//! 2. **publishes each file as an original** of class `ModelWeights` through the catalog's
//!    importer, reading the file again only through positioned reads of a read-only handle:
//!    as the tenant's own selection (`TrustClaim::UserSelected`), or under a publisher's
//!    key when the caller carries that file's publisher claim ([`ModelFileImport::claims`],
//!    checked by the class's signed verifier under the trust roots in force; a wrong
//!    signature publishes nothing). The catalog re-checks every extent and the content key,
//!    commits its own copy read-only and publishes it atomically; an interrupted copy
//!    resumes from its verified extents. A file the scope's budget cannot take evicts the
//!    least recently used prepared representations the catalog allows evicting, only as
//!    many as the file needs (`Catalog::evict_for_import`), then is admitted again once; a user's
//!    original is never evicted for a budget;
//! 3. **leases** every original for the importing execution, then runs the manifest
//!    [`Importer`] over the catalog adapter [`CatalogArtifacts`], reading the published
//!    copies under those leases rather than the folder, so the sidecar indexes exactly the
//!    bytes the catalog holds; the adapter publishes it as a `ModelSidecar` prepared from
//!    the originals under a local-model root;
//! 4. **leases** the sidecar too and returns every lease to the caller.
//!
//! The user's files are opened for reading only and never written, moved or deleted. The
//! catalog's copy of each costs its size once per tenant scope. Copying a file holds the
//! catalog lock for the whole copy, so other catalog calls wait for it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::MutexGuard;
use std::time::Duration;

use crate::foundation::catalog::{
    ArtifactClass, CacheEviction, Catalog, Checkpoint, ContentDescriptor, FailureRecord,
    ImportControl, ImportError as ObjectImportError, ImportManifest, ImportRefusal,
    ImportRequest as ObjectImport, ImportSource, ImportStart, ImportStatus, LeaseId,
    ManifestBuilder, ObjectBytes, ObjectId, ObjectMetadata, ObjectRole, Proceed, PublisherId,
    ReadHandle, ReadRefusal, RootKind, Scope, SourceError as ObjectSourceError,
    SourceIdentity as ObjectSource, TrustClaim, VerifierRejection,
};
use crate::foundation::catalog_service::CatalogHolder;
use crate::foundation::ids::{Digest, DigestBuilder, ExecutionId};
use crate::foundation::signing::StructureValidator;
use crate::model_memory::identity as layers;
use crate::model_memory::manifest::{
    root_name, ArtifactDescription, ArtifactIdentity, CancellationToken, CatalogArtifacts,
    CatalogContext, DirectorySource, Distribution, ElementType, ExecutionAbi, ExecutionIdentity,
    ExtentPlanError, ExtentPlanner, ExtentSpan, HardwareRestriction, IdentityError,
    ImportError as SidecarError, ImportKey, ImportLimits, ImportOutcome, ImportRequest, Importer,
    ListedFile, ManifestDigest, ModelIdentities, PublishedArtifact, Quantization, ReadBackChannel,
    RelativePath, SourceError, SourceFiles, SourceIdentity, SourceListing, SourceOrigin,
    SourceRevision, ValidatedManifest,
};

/// Extent size of an original model file in the catalog: the unit an interrupted copy
/// resumes from.
pub(crate) const ORIGINAL_EXTENT_BYTES: NonZeroU64 = match NonZeroU64::new(8 << 20) {
    Some(bytes) => bytes,
    None => NonZeroU64::MIN,
};

/// The catalog source kind of an original model file; its locator is the content key and
/// true length, so imports of the same bytes from any folder of the tenant share one
/// flight.
pub(crate) const ORIGINAL_SOURCE_KIND: &str = "model-file-content";

/// How a request waits for another request's flight over the same sidecar: polled this
/// often, and rejoined at most this many times (another request may start a new flight
/// between the end of one and this request's turn).
const FLIGHT_POLL: Duration = Duration::from_millis(20);
const MAX_FLIGHT_WAITS: u32 = 8;

/// The structure check of `ModelWeights` originals: none. A model folder's files are
/// weights, configuration, tokenizer and other files, which the catalog stores as the
/// bytes their content keys name. The sidecar importer's bounded indexers parse every
/// weights header, and refuse a malformed one, before a sidecar over the files is
/// published.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ModelFileBytes;

impl StructureValidator for ModelFileBytes {
    fn validate(
        &self,
        _content: &ContentDescriptor,
        _bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        Ok(())
    }
}

/// Integrity extents of the size the artifact description requests, the last keeping
/// its true length (§2.4 g_h): the plain tiling the T06 granularity port refines later.
/// The importer checks every plan before using it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct TiledExtents;

impl ExtentPlanner for TiledExtents {
    fn integrity_extents(
        &self,
        logical_length_bytes: u64,
        integrity_extent_bytes: u64,
    ) -> Result<Vec<ExtentSpan>, ExtentPlanError> {
        if integrity_extent_bytes == 0 {
            return Err(ExtentPlanError::Refused);
        }
        let mut spans = Vec::new();
        let mut offset_bytes = 0u64;
        while offset_bytes < logical_length_bytes {
            let true_length_bytes = integrity_extent_bytes.min(logical_length_bytes - offset_bytes);
            spans.push(ExtentSpan {
                offset_bytes,
                true_length_bytes,
            });
            offset_bytes = offset_bytes.saturating_add(true_length_bytes);
        }
        Ok(spans)
    }
}

/// Domain of [`FolderIdentities`]' source identity.
pub(crate) const FOLDER_SOURCE_DOMAIN: &str = "yougori/catalog-service/folder-source/v1";
/// Domain of [`FolderIdentities`]' execution identity.
pub(crate) const FOLDER_EXECUTION_DOMAIN: &str = "yougori/catalog-service/folder-execution/v1";

/// The identity port of the owner's own model folders (G04/S02): the import key is
/// computable from the listing and the artifact description alone, before any file is
/// read, so the runner keys the import up front and a repeated import of the same folder
/// finds its sidecar without reading the folder again.
///
/// The source identity binds the listing's origin and its revision, which for a folder
/// is the content revision over every file's path, length and content key (so any changed
/// byte is another source). The execution identity binds the source and the parts of the
/// description the sidecar records: the execution ABI (runner release, architecture
/// adapter, layout, kernels, hardware), the compute dtype, the exact quantization and the
/// rank layout. The artifact identity is the identity layers' (`model_memory::identity`),
/// from the manifest digest.
///
/// The committed identity layers' adapter (`IdentityLayers`) binds the same inputs plus
/// the licence, code policy, GPU architectures and generation configuration, but derives
/// the configuration and tokenizer digests inside the importer, so its key cannot be
/// built before the import reads every file; the runner has no principled source for
/// those extra inputs for a folder either. Moving the engine to the layers' key is a
/// follow-up that needs the manifest module to derive the key from a listing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FolderIdentities;

impl FolderIdentities {
    /// The source identity of `listing`: its origin and revision.
    pub(crate) fn source_of(listing: &SourceListing) -> SourceIdentity {
        let builder = DigestBuilder::new(FOLDER_SOURCE_DOMAIN);
        let builder = match &listing.origin {
            SourceOrigin::LocalFolder => builder.str("local_folder"),
            SourceOrigin::HuggingFace { repository } => {
                builder.str("hugging_face").str(repository.as_str())
            }
            SourceOrigin::Registry { model } => builder.str("registry").str(model.as_str()),
            SourceOrigin::Publisher { publisher } => {
                builder.str("publisher").str(publisher.as_str())
            }
        };
        let builder = match &listing.revision {
            SourceRevision::GitCommit(commit) => builder.str("commit").str(&commit.to_hex()),
            SourceRevision::ContentListing(digest) => builder.str("content").digest(digest),
        };
        SourceIdentity(builder.finish())
    }

    /// The execution identity of `description` over `source`.
    pub(crate) fn execution_of(
        source: &SourceIdentity,
        description: &ArtifactDescription,
    ) -> ExecutionIdentity {
        execution_digest(
            source,
            &description.execution_abi,
            description.compute_dtype,
            &description.quantization,
            &description.distribution,
        )
    }

    /// The import key of `listing` built for `description`: the key the importer derives
    /// for the same inputs.
    pub(crate) fn import_key(
        listing: &SourceListing,
        description: &ArtifactDescription,
    ) -> ImportKey {
        let source = Self::source_of(listing);
        ImportKey {
            execution: Self::execution_of(&source, description),
            source,
        }
    }
}

/// The execution identity's digest; the builder sorts kernels, parameters and
/// capabilities, so they are sorted here too.
fn execution_digest(
    source: &SourceIdentity,
    abi: &ExecutionAbi,
    compute_dtype: ElementType,
    quantization: &Quantization,
    distribution: &Distribution,
) -> ExecutionIdentity {
    let mut kernels: Vec<&str> = abi.kernels.iter().map(|kernel| kernel.as_str()).collect();
    kernels.sort_unstable();
    let builder = DigestBuilder::new(FOLDER_EXECUTION_DOMAIN)
        .digest(&source.0)
        .str(abi.runner.backend.tag())
        .str(abi.runner.version.as_str())
        .str(abi.architecture_adapter.name.as_str())
        .str(abi.architecture_adapter.version.as_str())
        .str(abi.layout.as_str())
        .u64(kernels.len() as u64);
    let builder = kernels
        .iter()
        .fold(builder, |builder, kernel| builder.str(kernel));
    let builder = match &abi.hardware {
        HardwareRestriction::Unrestricted => builder.str("unrestricted"),
        HardwareRestriction::ComputeCapabilities(capabilities) => {
            let mut sorted = capabilities.clone();
            sorted.sort();
            sorted.iter().fold(
                builder.str("compute_capabilities").u64(sorted.len() as u64),
                |builder, capability| {
                    builder
                        .u64(u64::from(capability.major))
                        .u64(u64::from(capability.minor))
                },
            )
        }
    };
    let builder = builder.str(compute_dtype.safetensors_name());
    let builder = match quantization {
        Quantization::None => builder.str("none"),
        Quantization::Method { method, parameters } => {
            let mut sorted: Vec<(&str, &str)> = parameters
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect();
            sorted.sort_unstable();
            sorted.iter().fold(
                builder
                    .str("method")
                    .str(method.as_str())
                    .u64(sorted.len() as u64),
                |builder, (key, value)| builder.str(key).str(value),
            )
        }
    };
    ExecutionIdentity(
        builder
            .u64(u64::from(distribution.tensor_parallel_size))
            .u64(u64::from(distribution.pipeline_parallel_size))
            .u64(u64::from(distribution.expert_parallel_size))
            .u64(u64::from(distribution.expert_count))
            .finish(),
    )
}

impl ModelIdentities for FolderIdentities {
    type Context = ();

    fn source_identity(
        &self,
        listing: &SourceListing,
        _configuration: &Digest,
        _context: &(),
    ) -> Result<SourceIdentity, IdentityError> {
        Ok(Self::source_of(listing))
    }

    fn execution_identity(
        &self,
        source: &SourceIdentity,
        manifest: &ValidatedManifest,
        _context: &(),
    ) -> Result<ExecutionIdentity, IdentityError> {
        let manifest = manifest.manifest();
        Ok(execution_digest(
            source,
            &manifest.execution_abi,
            manifest.semantics.compute_dtype,
            &manifest.semantics.quantization,
            &manifest.distribution,
        ))
    }

    fn artifact_identity(&self, manifest: &ManifestDigest) -> ArtifactIdentity {
        let identity = layers::ArtifactIdentity::from_manifest_digest(&manifest.digest());
        ArtifactIdentity(*identity.digest())
    }
}

/// One model folder to import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ModelFileImport<C> {
    /// The model folder the tenant chose. Its files are opened for reading only.
    pub folder: PathBuf,
    /// The sidecar import: its key, the folder's listing (every file with its length,
    /// content key and role), the description and the catalog context (tenant scope,
    /// importing execution, operation, and the sidecar's trust claim).
    pub request: ImportRequest<C, CatalogContext>,
    /// How long the execution's leases on the published objects last; renew them
    /// through the catalog.
    pub lease: Duration,
    /// The catalog declarations the caller built while reading the files for their content
    /// keys. A declaration whose content key and length are the listing's stands in for
    /// the import's own verifying read of that file; any other is ignored.
    pub declared: BTreeMap<RelativePath, ImportManifest>,
    /// Per-file publisher claims. A listed file named here is published under that
    /// publisher's key (`TrustClaim::Publisher`), the rest as the tenant's own selection.
    pub claims: BTreeMap<RelativePath, PublisherClaim>,
}

/// A publisher's attestation of one file: its signature over the file's content statement
/// (`content_statement` of the publisher, the `ModelWeights` class, the content key and
/// the length), as `yougori-sign` writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PublisherClaim {
    pub publisher: PublisherId,
    pub attestation: Vec<u8>,
}

/// One listed file as published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ImportedOriginal {
    pub path: RelativePath,
    pub object: ObjectId,
    /// This import copied the file; `false` when the tenant's scope already held it.
    pub copied: bool,
}

/// A lease the importing execution holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HeldLease {
    pub object: ObjectId,
    pub lease: LeaseId,
}

/// A model folder published in the catalog, held under the importing execution's leases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ImportedModel {
    pub scope: Scope,
    pub execution: ExecutionId,
    pub artifact: PublishedArtifact,
    /// The sidecar was already published for the import key; nothing was indexed again.
    pub reused: bool,
    pub sidecar: ObjectId,
    /// Every listed file, in path order.
    pub originals: Vec<ImportedOriginal>,
    /// One lease per distinct object: the sidecar first, then the originals.
    pub leases: Vec<HeldLease>,
    /// The cache evictions this import made room with, in order.
    pub evictions: Vec<CacheEviction>,
}

/// Why a model folder was not imported. Nothing is published for a file that failed
/// verification; an interrupted copy keeps its verified extents for a retry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ModelFileRefusal {
    /// The engine has no catalog open.
    NotOpened {
        detail: String,
    },
    /// The listing is out of the importer's bounds; nothing was read.
    Listing(SourceError),
    /// A file does not match its listing (missing, not a regular file, another length,
    /// another content key, changed while read) or could not be read. Nothing was
    /// published for any file.
    Source(SourceError),
    Cancelled {
        path: Option<RelativePath>,
    },
    /// The catalog refused a file before writing anything: the scope's quota, the
    /// class's trust policy or the declaration's bounds.
    Admission {
        path: RelativePath,
        refusal: Box<ImportRefusal>,
    },
    /// The scope's budget cannot take the file and the eviction that would make room was
    /// refused; nothing was evicted or written.
    Eviction {
        path: RelativePath,
        detail: String,
    },
    /// The copy stopped before publication; its verified extents stay staged and a retry
    /// resumes from them.
    Interrupted {
        path: RelativePath,
        failure: Option<Box<FailureRecord>>,
    },
    /// The copy failed and its staging was discarded.
    Failed {
        path: RelativePath,
        failure: Box<FailureRecord>,
    },
    Catalog {
        path: RelativePath,
        error: ObjectImportError,
    },
    /// The sidecar import over the published originals failed; nothing of it is visible.
    Sidecar(Box<SidecarError>),
    /// The sidecar was published but its local-model root does not hold it alone.
    SidecarMissing {
        detail: String,
    },
    Lease {
        object: ObjectId,
        refusal: ReadRefusal,
    },
}

impl fmt::Display for ModelFileRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotOpened { detail } => write!(f, "the engine has no catalog open: {detail}"),
            Self::Listing(error) | Self::Source(error) => error.fmt(f),
            Self::Cancelled { path: None } => f.write_str("the model import was cancelled"),
            Self::Cancelled { path: Some(path) } => {
                write!(f, "the model import was cancelled while copying {path}")
            }
            Self::Admission { path, refusal } => {
                write!(f, "the catalog refused {path}: {refusal}")
            }
            Self::Eviction { path, detail } => {
                write!(
                    f,
                    "no room for {path} and the cache eviction was refused: {detail}"
                )
            }
            Self::Interrupted { path, failure } => match failure {
                Some(failure) => write!(
                    f,
                    "copying {path} stopped ({}); a retry resumes from its verified extents",
                    failure.reason.code()
                ),
                None => write!(
                    f,
                    "copying {path} stopped; a retry resumes from its verified extents"
                ),
            },
            Self::Failed { path, failure } => {
                write!(f, "copying {path} failed: {}", failure.reason.code())
            }
            Self::Catalog { path, error } => write!(f, "copying {path}: {error}"),
            Self::Sidecar(error) => write!(f, "indexing the model failed: {error}"),
            Self::SidecarMissing { detail } => {
                write!(f, "the model's sidecar is missing: {detail}")
            }
            Self::Lease { object, refusal } => write!(f, "no lease on {object}: {refusal}"),
        }
    }
}

impl std::error::Error for ModelFileRefusal {}

/// Interrupts a catalog import once the caller cancels.
struct Cancellation<'a>(&'a CancellationToken);

impl ImportControl for Cancellation<'_> {
    fn proceed(&mut self, _at: Checkpoint) -> Proceed {
        if self.0.is_cancelled() {
            Proceed::Interrupt
        } else {
            Proceed::Continue
        }
    }
}

fn io_error(path: &RelativePath, error: &io::Error) -> SourceError {
    SourceError::Io {
        path: path.clone(),
        kind: error.kind(),
    }
}

/// The catalog source of an original: named by its content and length, not its folder.
fn original_source(listed: &ListedFile) -> ObjectSource {
    ObjectSource::describe(
        ORIGINAL_SOURCE_KIND,
        &format!("{}:{}", listed.content, listed.length_bytes),
    )
}

/// One original as the catalog's import source: positioned reads through a read-only
/// handle on the user's file.
struct OriginalFile {
    file: File,
    identity: ObjectSource,
}

impl OriginalFile {
    /// Opens `path` under `folder` for reading, after the folder's own checks (no
    /// symlink on the path, a regular file).
    fn open(
        folder: &DirectorySource,
        path: &RelativePath,
        identity: ObjectSource,
    ) -> Result<Self, SourceError> {
        drop(folder.open(path)?);
        let full = path
            .components()
            .fold(folder.root().to_path_buf(), |full, part| full.join(part));
        let file = File::open(&full).map_err(|error| io_error(path, &error))?;
        Ok(Self { file, identity })
    }
}

fn source_error(error: io::Error) -> ObjectSourceError {
    ObjectSourceError {
        detail: error.to_string(),
    }
}

impl ImportSource for OriginalFile {
    fn identity(&self) -> ObjectSource {
        self.identity
    }

    fn length_bytes(&mut self) -> Result<u64, ObjectSourceError> {
        self.file
            .metadata()
            .map(|metadata| metadata.len())
            .map_err(source_error)
    }

    fn read_at(
        &mut self,
        offset_bytes: u64,
        buffer: &mut [u8],
    ) -> Result<usize, ObjectSourceError> {
        self.file
            .seek(SeekFrom::Start(offset_bytes))
            .map_err(source_error)?;
        loop {
            match self.file.read(buffer) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                result => return result.map_err(source_error),
            }
        }
    }
}

/// Reads one published copy sequentially through its read-only handle, which checks the
/// lease on every read.
struct CopyReader {
    handle: ReadHandle,
    position_bytes: u64,
}

impl Read for CopyReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self
            .handle
            .length_bytes()
            .saturating_sub(self.position_bytes);
        let length = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let Some(window) = buffer.get_mut(..length).filter(|window| !window.is_empty()) else {
            return Ok(0);
        };
        self.handle
            .read_exact_at(self.position_bytes, window)
            .map_err(|error| io::Error::other(error.to_string()))?;
        self.position_bytes = self.position_bytes.saturating_add(length as u64);
        Ok(length)
    }
}

/// The published copies of a model's files as the sidecar importer's source, each read
/// under the importing execution's lease.
struct CatalogCopies<'a> {
    holder: &'a dyn CatalogHolder,
    scope: &'a Scope,
    execution: &'a ExecutionId,
    leases: BTreeMap<RelativePath, LeaseId>,
}

impl SourceFiles for CatalogCopies<'_> {
    fn open(&self, path: &RelativePath) -> Result<(Box<dyn Read + '_>, u64), SourceError> {
        let lease = self
            .leases
            .get(path)
            .ok_or_else(|| SourceError::MissingFile { path: path.clone() })?;
        let handle = self
            .holder
            .catalog()
            .open_read(self.scope, self.execution, *lease)
            .map_err(|_| SourceError::Io {
                path: path.clone(),
                kind: io::ErrorKind::PermissionDenied,
            })?;
        let length_bytes = handle.length_bytes();
        Ok((
            Box::new(CopyReader {
                handle,
                position_bytes: 0,
            }),
            length_bytes,
        ))
    }
}

/// One listed file the tenant's scope does not hold yet, verified and declared.
struct Declared<'r> {
    listed: &'r ListedFile,
    manifest: ImportManifest,
}

/// The engine's model-file importer over its catalog: the manifest [`Importer`] over the
/// catalog adapter [`CatalogArtifacts`], which holds the catalog. See the module
/// documentation.
pub(crate) struct ModelFiles<I, E> {
    importer: Importer<CatalogArtifacts, I, E>,
}

impl<I, E> CatalogHolder for ModelFiles<I, E>
where
    I: ModelIdentities + Send + Sync,
    E: ExtentPlanner + Send + Sync,
{
    fn catalog(&self) -> MutexGuard<'_, Catalog> {
        self.importer.catalog().catalog()
    }
}

impl<I, E> ModelFiles<I, E>
where
    I: ModelIdentities + Send + Sync,
    E: ExtentPlanner + Send + Sync,
{
    /// The importer over `catalog`, whose `ModelSidecar` verifier is a
    /// [`SidecarVerifier`](crate::model_memory::manifest::SidecarVerifier) given
    /// `read_back`.
    pub(crate) fn new(
        catalog: Catalog,
        read_back: ReadBackChannel,
        identities: I,
        extents: E,
        limits: ImportLimits,
    ) -> Self {
        Self {
            importer: Importer::new(
                CatalogArtifacts::new(catalog, read_back),
                identities,
                extents,
                limits,
            ),
        }
    }

    /// Imports one model folder; see the module documentation. On success the importing
    /// execution holds a lease on the sidecar and on every original.
    pub(crate) fn import(
        &self,
        request: &ModelFileImport<I::Context>,
        cancel: &CancellationToken,
    ) -> Result<ImportedModel, ModelFileRefusal> {
        let sidecar = &request.request;
        let context = &sidecar.catalog;
        self.check_bounds(&sidecar.listing)?;
        let folder = DirectorySource::new(&request.folder);
        let files = sidecar.listing.sorted_files();

        // 1. Every file the scope does not hold yet is verified before any is published.
        let mut held = BTreeMap::new();
        let mut declared = Vec::new();
        for listed in files.iter().copied() {
            if cancel.is_cancelled() {
                return Err(ModelFileRefusal::Cancelled { path: None });
            }
            let found =
                self.catalog()
                    .find(&context.scope, ArtifactClass::ModelWeights, listed.content);
            match found {
                Some(object) => {
                    held.insert(listed.content, object);
                }
                None => {
                    let manifest = match request.declared.get(&listed.path) {
                        Some(manifest)
                            if manifest.content_key == listed.content
                                && manifest.true_length_bytes == listed.length_bytes =>
                        {
                            manifest.clone()
                        }
                        _ => self.declare(&folder, listed, cancel)?,
                    };
                    declared.push(Declared { listed, manifest });
                }
            }
        }

        // 2. Each is published as the tenant's original, or under its publisher's key.
        let mut copied = BTreeSet::new();
        let mut evictions = Vec::new();
        for file in declared {
            if held.contains_key(&file.listed.content) {
                // The same bytes listed under another path: published once.
                continue;
            }
            let content = file.listed.content;
            let claim = request.claims.get(&file.listed.path);
            let (object, fresh, evicted) =
                self.publish_original(context, &folder, file, claim, cancel)?;
            if fresh {
                copied.insert(object);
            }
            evictions.extend(evicted);
            held.insert(content, object);
        }
        let originals: Vec<ImportedOriginal> = files
            .iter()
            .filter_map(|listed| {
                held.get(&listed.content).map(|object| ImportedOriginal {
                    path: listed.path.clone(),
                    object: *object,
                    copied: copied.contains(object),
                })
            })
            .collect();

        // 3. The originals are leased, and the sidecar is indexed from their copies.
        let mut leases = Vec::new();
        let outcome = self
            .lease_new(
                context,
                request.lease,
                originals.iter().map(|original| original.object),
                &mut leases,
            )
            .and_then(|()| {
                let by_object: BTreeMap<ObjectId, LeaseId> = leases
                    .iter()
                    .map(|held| (held.object, held.lease))
                    .collect();
                let copies = CatalogCopies {
                    holder: self,
                    scope: &context.scope,
                    execution: &context.execution,
                    leases: originals
                        .iter()
                        .filter_map(|original| {
                            by_object
                                .get(&original.object)
                                .map(|lease| (original.path.clone(), *lease))
                        })
                        .collect(),
                };
                let indexed = self.index_once(sidecar, &copies, cancel);
                // What the sidecar's own publication evicted to fit the budget, with the
                // originals' evictions.
                evictions.extend(self.importer.catalog().take_evictions(&context.execution));
                indexed
            })
            .and_then(|outcome| {
                let (artifact, reused) = match outcome {
                    ImportOutcome::Published(artifact) => (artifact, false),
                    ImportOutcome::AlreadyPublished(artifact) => (artifact, true),
                };
                let object = self.sidecar_object(&context.scope, &artifact)?;
                // 4. The sidecar is leased first among the leases returned.
                let mut sidecar_lease = Vec::new();
                self.lease_new(context, request.lease, [object], &mut sidecar_lease)?;
                sidecar_lease.append(&mut leases);
                leases = sidecar_lease;
                Ok((artifact, reused, object))
            });
        match outcome {
            Ok((artifact, reused, sidecar)) => Ok(ImportedModel {
                scope: context.scope.clone(),
                execution: context.execution.clone(),
                artifact,
                reused,
                sidecar,
                originals,
                leases,
                evictions,
            }),
            Err(refusal) => {
                self.release_all(&context.scope, &context.execution, &leases);
                Err(refusal)
            }
        }
    }

    /// Indexes the sidecar from `copies`, single flight across requests: while another
    /// request of the same model is indexing it, this one waits for that flight to end
    /// (bounded by the caller's cancellation) and then takes its result, which is the
    /// published sidecar.
    fn index_once(
        &self,
        sidecar: &ImportRequest<I::Context, CatalogContext>,
        copies: &CatalogCopies<'_>,
        cancel: &CancellationToken,
    ) -> Result<ImportOutcome, ModelFileRefusal> {
        let mut waited = 0u32;
        loop {
            match self.importer.import(sidecar, copies, cancel) {
                Err(SidecarError::InFlight { key }) if waited < MAX_FLIGHT_WAITS => {
                    waited += 1;
                    while self.importer.in_flight(&key) {
                        if cancel.is_cancelled() {
                            return Err(ModelFileRefusal::Cancelled { path: None });
                        }
                        std::thread::sleep(FLIGHT_POLL);
                    }
                }
                other => return other.map_err(|error| ModelFileRefusal::Sidecar(Box::new(error))),
            }
        }
    }

    /// Ends every lease of `imported`. Every lease is released even after a refusal; the
    /// first refusal is returned.
    pub(crate) fn release(&self, imported: &ImportedModel) -> Result<(), ModelFileRefusal> {
        let mut catalog = self.catalog();
        let mut first = None;
        for held in &imported.leases {
            if let Err(refusal) =
                catalog.release_lease(&imported.scope, &imported.execution, held.lease)
            {
                first.get_or_insert(ModelFileRefusal::Lease {
                    object: held.object,
                    refusal,
                });
            }
        }
        first.map_or(Ok(()), Err)
    }

    /// The listing's bounds, checked before any file is opened.
    fn check_bounds(&self, listing: &SourceListing) -> Result<(), ModelFileRefusal> {
        let limits = self.importer.limits();
        let count = listing.files.len() as u64;
        if count > limits.max_source_files {
            return Err(ModelFileRefusal::Listing(SourceError::TooManyFiles {
                count,
                max: limits.max_source_files,
            }));
        }
        let total_bytes = listing
            .files
            .iter()
            .try_fold(0u64, |total, file| total.checked_add(file.length_bytes));
        if total_bytes.is_none_or(|total| total > limits.max_source_bytes) {
            return Err(ModelFileRefusal::Listing(SourceError::TooManyBytes {
                max_bytes: limits.max_source_bytes,
            }));
        }
        Ok(())
    }

    /// One read of `listed`: its length and content key are checked against the listing,
    /// and its extents are declared for the catalog.
    fn declare(
        &self,
        folder: &DirectorySource,
        listed: &ListedFile,
        cancel: &CancellationToken,
    ) -> Result<ImportManifest, ModelFileRefusal> {
        let path = &listed.path;
        let source = |error| ModelFileRefusal::Source(error);
        let (mut reader, found_bytes) = folder.open(path).map_err(source)?;
        if found_bytes != listed.length_bytes {
            return Err(source(SourceError::LengthMismatch {
                path: path.clone(),
                listed_bytes: listed.length_bytes,
                found_bytes,
            }));
        }
        let changed = || source(SourceError::Changed { path: path.clone() });
        let mut builder = ManifestBuilder::new(listed.length_bytes, ORIGINAL_EXTENT_BYTES);
        let mut chunk = vec![0u8; self.importer.limits().read_chunk_bytes.max(1)];
        loop {
            if cancel.is_cancelled() {
                return Err(ModelFileRefusal::Cancelled {
                    path: Some(path.clone()),
                });
            }
            let read = match reader.read(&mut chunk) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result.map_err(|error| source(io_error(path, &error)))?,
            };
            if read == 0 {
                break;
            }
            let bytes = chunk.get(..read).ok_or_else(changed)?;
            builder.update(bytes).map_err(|_| changed())?;
        }
        let manifest = builder.finish().map_err(|_| changed())?;
        if manifest.content_key != listed.content {
            return Err(source(SourceError::DigestMismatch { path: path.clone() }));
        }
        Ok(manifest)
    }

    /// Publishes one verified file as the tenant's original, or under `claim`'s publisher;
    /// `true` when this import copied it, with the cache eviction that made room, if one did.
    fn publish_original(
        &self,
        context: &CatalogContext,
        folder: &DirectorySource,
        file: Declared<'_>,
        claim: Option<&PublisherClaim>,
        cancel: &CancellationToken,
    ) -> Result<(ObjectId, bool, Option<CacheEviction>), ModelFileRefusal> {
        let path = file.listed.path.clone();
        let identity = original_source(file.listed);
        let mut source =
            OriginalFile::open(folder, &path, identity).map_err(ModelFileRefusal::Source)?;
        let trust = match claim {
            Some(claim) => TrustClaim::Publisher {
                publisher: claim.publisher,
                attestation: claim.attestation.clone(),
            },
            None => TrustClaim::UserSelected,
        };
        let request = ObjectImport {
            operation: context.operation.clone(),
            execution: context.execution.clone(),
            scope: context.scope.clone(),
            class: ArtifactClass::ModelWeights,
            role: ObjectRole::Original,
            manifest: file.manifest,
            trust,
            depends_on: BTreeSet::new(),
            metadata: ObjectMetadata::new(),
        };
        let mut catalog = self.catalog();
        let mut evicted = None;
        let start = match catalog.begin_import(request.clone(), identity) {
            Err(ImportRefusal::Quota { refusal }) if refusal.evictable_shortfall().is_some() => {
                let needed = refusal.evictable_shortfall().unwrap_or_default();
                let eviction =
                    catalog
                        .evict_for_import(&context.scope, needed)
                        .map_err(|refusal| ModelFileRefusal::Eviction {
                            path: path.clone(),
                            detail: refusal.to_string(),
                        })?;
                evicted = Some(eviction);
                catalog.begin_import(request, identity)
            }
            other => other,
        };
        let ticket = match start {
            Err(refusal) => {
                return Err(ModelFileRefusal::Admission {
                    path,
                    refusal: Box::new(refusal),
                })
            }
            Ok(ImportStart::AlreadyPublished(object)) => return Ok((object, false, evicted)),
            Ok(ImportStart::Started(ticket) | ImportStart::Attached(ticket)) => ticket,
        };
        let status = catalog.drive_import(&ticket, &mut source, &mut Cancellation(cancel));
        // Detached either way: a finished import is done, and an unfinished one keeps its
        // verified extents staged for a retry until collected.
        catalog.cancel_import(ticket);
        match status {
            Ok(ImportStatus::Published { object, .. }) => Ok((object, true, evicted)),
            Ok(ImportStatus::Pending { .. }) if cancel.is_cancelled() => {
                Err(ModelFileRefusal::Cancelled { path: Some(path) })
            }
            Ok(ImportStatus::Pending { last_failure, .. }) => Err(ModelFileRefusal::Interrupted {
                path,
                failure: last_failure.map(Box::new),
            }),
            Ok(ImportStatus::Failed { failure }) => Err(ModelFileRefusal::Failed {
                path,
                failure: Box::new(failure),
            }),
            Err(error) => Err(ModelFileRefusal::Catalog { path, error }),
        }
    }

    /// The sidecar the adapter published for `artifact`'s key: the one object of its
    /// local-model root.
    fn sidecar_object(
        &self,
        scope: &Scope,
        artifact: &PublishedArtifact,
    ) -> Result<ObjectId, ModelFileRefusal> {
        let name = root_name(&artifact.key).map_err(|error| ModelFileRefusal::SidecarMissing {
            detail: error.to_string(),
        })?;
        let objects: Vec<ObjectId> = self
            .catalog()
            .roots(scope)
            .into_iter()
            .find(|root| root.kind == RootKind::LocalModel && root.name == name)
            .map(|root| root.objects.into_iter().collect())
            .unwrap_or_default();
        match objects.as_slice() {
            [object] => Ok(*object),
            _ => Err(ModelFileRefusal::SidecarMissing {
                detail: format!(
                    "the local-model root {name} holds {} objects",
                    objects.len()
                ),
            }),
        }
    }

    /// Takes a lease on each object not leased in `leases` yet and appends it.
    fn lease_new(
        &self,
        context: &CatalogContext,
        duration: Duration,
        objects: impl IntoIterator<Item = ObjectId>,
        leases: &mut Vec<HeldLease>,
    ) -> Result<(), ModelFileRefusal> {
        let mut catalog = self.catalog();
        for object in objects {
            if leases.iter().any(|held| held.object == object) {
                continue;
            }
            let lease = catalog
                .acquire_lease(&context.scope, &context.execution, object, duration)
                .map_err(|refusal| ModelFileRefusal::Lease { object, refusal })?;
            leases.push(HeldLease { object, lease });
        }
        Ok(())
    }

    /// Ends the leases a failed import took. A lease this import just took can only
    /// already be gone, so a refusal here changes nothing and is not reported.
    fn release_all(&self, scope: &Scope, execution: &ExecutionId, leases: &[HeldLease]) {
        let mut catalog = self.catalog();
        for held in leases {
            let _already_ended = catalog.release_lease(scope, execution, held.lease);
        }
    }
}
