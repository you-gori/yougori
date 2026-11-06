//! The model importer protocol (GPU part §3.3, plan line 533; GPU-W03; Appendix C):
//! bounded source verification → temporary representation → complete index/proofs →
//! read-back validation → durable commit → catalog publication.
//!
//! Every source file is read exactly once, in step 1: one pass verifies its length and
//! content key and, from the same bytes, indexes its header and hashes its integrity
//! extents. Step 3 completes the index and proofs from that pass without reading a source
//! again, and step 4 reads back the staged sidecar and validates it against the index and
//! proofs built in step 3.
//!
//! Imports are single-flight per source and execution identity: a second import of a key
//! in flight is refused with [`ImportError::InFlight`], and an import of a key already
//! published reuses it. Cancellation is checked before every step and during every file
//! read; a cancelled or failed import discards its temporary area and never publishes.
//! The importer reads sources only through the [`SourceFiles`] it is given and never
//! converts, copies or deletes the original files (§3.4; the packaged `.ywi` format is a
//! gated non-goal).

use std::collections::BTreeSet;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::builder::{
    ArtifactDescription, EncodingInput, ExtentInput, ManifestBuilder, SourceFileInput, TensorInput,
};
use super::derive;
use super::groups::{
    ConverterIdentity, FileFormat, FileRole, SourceFile, StateGroup, TensorAlias, TensorOwner,
};
use super::index::{IndexError, IndexerBounds};
use super::ports::{
    check_extent_plan, ArtifactCatalog, CatalogError, ExecutionIdentity, ExtentPlanError,
    ExtentPlanner, ExtentSpan, IdentityError, ImportKey, ModelIdentities, PublishedArtifact,
    SourceIdentity, StagingId,
};
use super::source::{
    check_listing, scan_file, FileScan, ListedFile, ListingLimits, ScanError, SourceError,
    SourceFiles, SourceListing,
};
use super::types::{RelativePath, TensorName, Token};
use super::validate::{ManifestError, ValidatedManifest};

/// Name of this module's sidecar indexer (§3.3 provenance: converter identity).
pub const SIDECAR_CONVERTER_NAME: &str = "yougori-sidecar-indexer";
/// Version of the sidecar indexer; it changes whenever the index it writes would. Version
/// 3 writes manifest schema 3, which lists codec formats in the schema group.
pub const SIDECAR_CONVERTER_VERSION: &str = "3";

/// The converter identity recorded in every manifest the importer writes.
pub fn sidecar_converter() -> Result<ConverterIdentity, ManifestError> {
    let token = |text: &str, field| {
        Token::new(text).map_err(|error| ManifestError::InvalidName { field, error })
    };
    Ok(ConverterIdentity {
        name: token(SIDECAR_CONVERTER_NAME, "converter name")?,
        version: token(SIDECAR_CONVERTER_VERSION, "converter version")?,
    })
}

/// A cancellation flag shared between an import and whoever may cancel it.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// One import: what to read and what to build it for. `identity` and `catalog` are the
/// per-import inputs of the two ports (for the committed adapters, a
/// [`LayerContext`](super::LayerContext) and a [`CatalogContext`](super::CatalogContext)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportRequest<I = (), C = ()> {
    pub key: ImportKey,
    pub listing: SourceListing,
    pub description: ArtifactDescription,
    pub state: StateGroup,
    pub aliases: Vec<TensorAlias>,
    /// Ownership beyond each file's rank, such as which rank holds an expert's tensors.
    pub owners: Vec<(TensorName, TensorOwner)>,
    pub identity: I,
    pub catalog: C,
}

/// Limits of one importer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportLimits {
    pub max_source_files: u64,
    pub max_source_bytes: u64,
    /// The disk reservation for the temporary representation, and the largest sidecar.
    pub max_sidecar_bytes: u64,
    pub read_chunk_bytes: usize,
    pub indexer: IndexerBounds,
}

impl ImportLimits {
    pub const DEFAULT: Self = Self {
        max_source_files: 4_096,
        max_source_bytes: 16 << 40,
        max_sidecar_bytes: 1 << 30,
        read_chunk_bytes: 1 << 20,
        indexer: IndexerBounds::DEFAULT,
    };

    /// The largest limits an importer accepts: the manifest ceilings for files and bytes,
    /// an 8 GiB sidecar held in memory, 64 MiB reads and the indexer ceiling.
    pub const CEILING: Self = Self {
        max_source_files: 65_536,
        max_source_bytes: 1 << 50,
        max_sidecar_bytes: 1 << 33,
        read_chunk_bytes: 1 << 26,
        indexer: IndexerBounds::CEILING,
    };

    /// Refuses a limit above `ceiling`, the indexer's bounds included.
    pub fn check_within(&self, ceiling: &Self) -> Result<(), ImportError> {
        let (own, bounds) = (&self.indexer, &ceiling.indexer);
        let pairs: [(&'static str, u64, u64); 11] = [
            (
                "max_source_files",
                self.max_source_files,
                ceiling.max_source_files,
            ),
            (
                "max_source_bytes",
                self.max_source_bytes,
                ceiling.max_source_bytes,
            ),
            (
                "max_sidecar_bytes",
                self.max_sidecar_bytes,
                ceiling.max_sidecar_bytes,
            ),
            (
                "read_chunk_bytes",
                self.read_chunk_bytes as u64,
                ceiling.read_chunk_bytes as u64,
            ),
            (
                "indexer.max_header_bytes",
                own.max_header_bytes,
                bounds.max_header_bytes,
            ),
            ("indexer.max_tensors", own.max_tensors, bounds.max_tensors),
            (
                "indexer.max_dimensions",
                own.max_dimensions,
                bounds.max_dimensions,
            ),
            (
                "indexer.max_name_bytes",
                own.max_name_bytes,
                bounds.max_name_bytes,
            ),
            (
                "indexer.max_metadata_entries",
                own.max_metadata_entries,
                bounds.max_metadata_entries,
            ),
            (
                "indexer.max_array_elements",
                own.max_array_elements,
                bounds.max_array_elements,
            ),
            (
                "indexer.max_string_bytes",
                own.max_string_bytes,
                bounds.max_string_bytes,
            ),
        ];
        match pairs
            .into_iter()
            .find(|(_, declared, ceiling)| declared > ceiling)
        {
            Some((limit, declared, ceiling)) => Err(ImportError::LimitAboveCeiling {
                limit,
                declared,
                ceiling,
            }),
            None => Ok(()),
        }
    }
}

impl Default for ImportLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The protocol's steps, in order (§3.3, plan line 533).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ImportStep {
    VerifySource,
    StageRepresentation,
    Index,
    ReadBack,
    Commit,
    Publish,
}

impl fmt::Display for ImportStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::VerifySource => "source verification",
            Self::StageRepresentation => "temporary representation",
            Self::Index => "index and proofs",
            Self::ReadBack => "read-back validation",
            Self::Commit => "durable commit",
            Self::Publish => "catalog publication",
        })
    }
}

/// How an import ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportOutcome {
    Published(PublishedArtifact),
    /// The key was already published; nothing was read or stored.
    AlreadyPublished(PublishedArtifact),
}

/// Why an import stopped. Nothing is published after any of these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportError {
    /// The importer's limits are above [`ImportLimits::CEILING`]; nothing was read.
    LimitAboveCeiling {
        limit: &'static str,
        declared: u64,
        ceiling: u64,
    },
    /// An import of this source and execution identity is already running.
    InFlight {
        key: ImportKey,
    },
    Cancelled {
        step: ImportStep,
    },
    Source(SourceError),
    Index {
        path: RelativePath,
        error: IndexError,
    },
    Manifest(ManifestError),
    Extents(ExtentPlanError),
    Identity(IdentityError),
    SourceIdentityMismatch {
        expected: SourceIdentity,
        found: SourceIdentity,
    },
    ExecutionIdentityMismatch {
        expected: ExecutionIdentity,
        found: ExecutionIdentity,
    },
    Catalog {
        step: ImportStep,
        error: CatalogError,
    },
    SidecarTooLarge {
        length_bytes: u64,
        max_bytes: u64,
    },
    /// The staged sidecar did not read back as written, or does not agree with the index
    /// and proofs it was built from.
    ReadBackMismatch,
    /// Discarding the temporary area also failed; it stays unpublished and unreachable.
    CleanupFailed {
        original: Box<ImportError>,
        cleanup: CatalogError,
    },
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitAboveCeiling {
                limit,
                declared,
                ceiling,
            } => write!(
                f,
                "import limit {limit} {declared} is above the ceiling {ceiling}"
            ),
            Self::InFlight { .. } => {
                f.write_str("this model is already being imported for this runtime")
            }
            Self::Cancelled { step } => write!(f, "the import was cancelled during {step}"),
            Self::Source(error) => write!(f, "{error}"),
            Self::Index { path, error } => write!(f, "{path}: {error}"),
            Self::Manifest(error) => write!(f, "{error}"),
            Self::Extents(error) => write!(f, "{error}"),
            Self::Identity(error) => write!(f, "{error}"),
            Self::SourceIdentityMismatch { .. } => {
                f.write_str("the listed files are not the requested source")
            }
            Self::ExecutionIdentityMismatch { .. } => {
                f.write_str("the indexed model is not the requested execution identity")
            }
            Self::Catalog { step, error } => write!(f, "{step}: {error}"),
            Self::SidecarTooLarge {
                length_bytes,
                max_bytes,
            } => write!(
                f,
                "the {length_bytes}-byte sidecar exceeds its {max_bytes}-byte reservation"
            ),
            Self::ReadBackMismatch => f.write_str(
                "the staged sidecar did not read back as the index and proofs it was built from",
            ),
            Self::CleanupFailed { original, cleanup } => {
                write!(
                    f,
                    "{original}; discarding the temporary area also failed: {cleanup}"
                )
            }
        }
    }
}

impl std::error::Error for ImportError {}

impl From<ManifestError> for ImportError {
    fn from(error: ManifestError) -> Self {
        Self::Manifest(error)
    }
}

fn scan_error(error: ScanError, step: ImportStep) -> ImportError {
    match error {
        ScanError::Source(error) => ImportError::Source(error),
        ScanError::Index { path, error } => ImportError::Index { path, error },
        ScanError::Cancelled => ImportError::Cancelled { step },
    }
}

fn checkpoint(cancel: &CancellationToken, step: ImportStep) -> Result<(), ImportError> {
    if cancel.is_cancelled() {
        return Err(ImportError::Cancelled { step });
    }
    Ok(())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Holds a key's flight until the import ends, however it ends.
struct Flight<'a> {
    flights: &'a Mutex<BTreeSet<ImportKey>>,
    key: ImportKey,
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        lock(self.flights).remove(&self.key);
    }
}

/// One file after its pass: what was listed, its extent plan and what the pass found.
struct ScannedFile<'r> {
    listed: &'r ListedFile,
    spans: Vec<ExtentSpan>,
    scan: FileScan,
}

impl ScannedFile<'_> {
    fn source_file(&self) -> SourceFile {
        SourceFile {
            path: self.listed.path.clone(),
            length_bytes: self.listed.length_bytes,
            content: self.scan.content,
            role: self.listed.role,
            format: self
                .scan
                .index
                .as_ref()
                .map_or(FileFormat::Opaque, |index| index.format),
        }
    }
}

/// Step 4: the staged bytes must be the bytes written, decode to a manifest that validates
/// (which recomputes every extent-tree root from the staged extents), and agree with the
/// index and proofs built in step 3: the same canonical digest, tensor index, extent table,
/// tree roots and decoded content identity.
fn validate_read_back(
    built: &ValidatedManifest,
    written: &[u8],
    read_back: &[u8],
) -> Result<(), ImportError> {
    if read_back != written {
        return Err(ImportError::ReadBackMismatch);
    }
    let staged = ValidatedManifest::from_sidecar_bytes(read_back)?;
    let (staged_manifest, built_manifest) = (staged.manifest(), built.manifest());
    if staged.digest() != built.digest()
        || staged_manifest.tensor_index != built_manifest.tensor_index
        || staged_manifest.extents != built_manifest.extents
        || staged_manifest.integrity != built_manifest.integrity
    {
        return Err(ImportError::ReadBackMismatch);
    }
    Ok(())
}

/// Runs imports over the catalog, identity and extent ports.
pub struct Importer<C, I, E> {
    catalog: C,
    identities: I,
    extents: E,
    limits: ImportLimits,
    flights: Mutex<BTreeSet<ImportKey>>,
}

impl<C, I, E> Importer<C, I, E>
where
    C: ArtifactCatalog,
    I: ModelIdentities,
    E: ExtentPlanner,
{
    pub fn new(catalog: C, identities: I, extents: E, limits: ImportLimits) -> Self {
        Self {
            catalog,
            identities,
            extents,
            limits,
            flights: Mutex::new(BTreeSet::new()),
        }
    }

    pub fn catalog(&self) -> &C {
        &self.catalog
    }

    pub fn identities(&self) -> &I {
        &self.identities
    }

    pub fn limits(&self) -> &ImportLimits {
        &self.limits
    }

    /// Whether an import of `key` is running now.
    pub fn in_flight(&self, key: &ImportKey) -> bool {
        lock(&self.flights).contains(key)
    }

    fn enter(&self, key: ImportKey) -> Result<Flight<'_>, ImportError> {
        if !lock(&self.flights).insert(key) {
            return Err(ImportError::InFlight { key });
        }
        Ok(Flight {
            flights: &self.flights,
            key,
        })
    }

    /// Runs the protocol for `request`, reading its files from `source`.
    pub fn import(
        &self,
        request: &ImportRequest<I::Context, C::Context>,
        source: &dyn SourceFiles,
        cancel: &CancellationToken,
    ) -> Result<ImportOutcome, ImportError> {
        self.limits.check_within(&ImportLimits::CEILING)?;
        let _flight = self.enter(request.key)?;
        if let Some(published) = self
            .catalog
            .published(&request.key, &request.catalog)
            .map_err(|error| ImportError::Catalog {
                step: ImportStep::VerifySource,
                error,
            })?
        {
            return Ok(ImportOutcome::AlreadyPublished(published));
        }

        // 1. Bounded source verification: the listing's bounds, then the one pass over
        //    every file, which also yields the index and proofs.
        checkpoint(cancel, ImportStep::VerifySource)?;
        let listing_limits = ListingLimits {
            max_files: self.limits.max_source_files,
            max_bytes: self.limits.max_source_bytes,
        };
        check_listing(&request.listing, &listing_limits).map_err(ImportError::Source)?;
        let scanned = self.scan_sources(request, source, cancel)?;
        let files: Vec<SourceFile> = scanned.iter().map(ScannedFile::source_file).collect();
        if !derive::has_configuration(&files) {
            return Err(ImportError::Manifest(ManifestError::MissingConfiguration));
        }
        let found = self
            .identities
            .source_identity(
                &request.listing,
                &derive::configuration_digest(&files),
                &request.identity,
            )
            .map_err(ImportError::Identity)?;
        if found != request.key.source {
            return Err(ImportError::SourceIdentityMismatch {
                expected: request.key.source,
                found,
            });
        }

        // 2. Temporary representation, under a bounded disk reservation.
        checkpoint(cancel, ImportStep::StageRepresentation)?;
        let staging = self
            .catalog
            .begin_staging(
                &request.key,
                self.limits.max_sidecar_bytes,
                &request.catalog,
            )
            .map_err(|error| ImportError::Catalog {
                step: ImportStep::StageRepresentation,
                error,
            })?;
        match self.complete(request, scanned, staging, cancel) {
            Ok(published) => Ok(ImportOutcome::Published(published)),
            Err(error) => match self.catalog.discard(staging) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(ImportError::CleanupFailed {
                    original: Box::new(error),
                    cleanup,
                }),
            },
        }
    }

    /// The one pass over every listed file, in path order.
    fn scan_sources<'r>(
        &self,
        request: &'r ImportRequest<I::Context, C::Context>,
        source: &dyn SourceFiles,
        cancel: &CancellationToken,
    ) -> Result<Vec<ScannedFile<'r>>, ImportError> {
        let description = &request.description;
        let mut scanned = Vec::with_capacity(request.listing.files.len());
        for listed in request.listing.sorted_files() {
            checkpoint(cancel, ImportStep::VerifySource)?;
            let spans = self
                .extents
                .integrity_extents(listed.length_bytes, description.integrity_extent_bytes)
                .map_err(ImportError::Extents)?;
            check_extent_plan(
                &spans,
                listed.length_bytes,
                description.bounds.max_extent_bytes,
            )
            .map_err(ImportError::Extents)?;
            let scan = scan_file(
                source,
                listed,
                &spans,
                &self.limits.indexer,
                self.limits.read_chunk_bytes,
                cancel,
            )
            .map_err(|error| scan_error(error, ImportStep::VerifySource))?;
            scanned.push(ScannedFile {
                listed,
                spans,
                scan,
            });
        }
        Ok(scanned)
    }

    /// Steps 3–6, inside the temporary area. Any error leaves nothing published.
    fn complete(
        &self,
        request: &ImportRequest<I::Context, C::Context>,
        scanned: Vec<ScannedFile<'_>>,
        staging: StagingId,
        cancel: &CancellationToken,
    ) -> Result<PublishedArtifact, ImportError> {
        let catalog_error =
            |step: ImportStep| move |error: CatalogError| ImportError::Catalog { step, error };

        // 3. Complete index and proofs, from the pass; no source is read again.
        checkpoint(cancel, ImportStep::Index)?;
        let manifest = assemble(request, scanned)?;
        let execution = self
            .identities
            .execution_identity(&request.key.source, &manifest, &request.identity)
            .map_err(ImportError::Identity)?;
        if execution != request.key.execution {
            return Err(ImportError::ExecutionIdentityMismatch {
                expected: request.key.execution,
                found: execution,
            });
        }
        let artifact = PublishedArtifact {
            key: request.key,
            manifest: manifest.digest(),
            artifact: self.identities.artifact_identity(&manifest.digest()),
        };
        let sidecar = manifest.sidecar_bytes();
        let sidecar_bytes = sidecar.len() as u64;
        if sidecar_bytes > self.limits.max_sidecar_bytes {
            return Err(ImportError::SidecarTooLarge {
                length_bytes: sidecar_bytes,
                max_bytes: self.limits.max_sidecar_bytes,
            });
        }
        self.catalog
            .write_staged(staging, &sidecar, &artifact)
            .map_err(catalog_error(ImportStep::Index))?;

        // 4. Read-back validation of the staged sidecar against the index and proofs.
        checkpoint(cancel, ImportStep::ReadBack)?;
        let read_back = self
            .catalog
            .read_staged(staging, sidecar_bytes)
            .map_err(catalog_error(ImportStep::ReadBack))?;
        validate_read_back(&manifest, &sidecar, &read_back)?;

        // 5. Durable commit, still unpublished.
        checkpoint(cancel, ImportStep::Commit)?;
        self.catalog
            .commit(staging)
            .map_err(catalog_error(ImportStep::Commit))?;

        // 6. Catalog publication.
        checkpoint(cancel, ImportStep::Publish)?;
        self.catalog
            .publish(staging)
            .map_err(catalog_error(ImportStep::Publish))
    }
}

/// Builds the validated manifest from the pass over every file.
fn assemble<I, C>(
    request: &ImportRequest<I, C>,
    scanned: Vec<ScannedFile<'_>>,
) -> Result<ValidatedManifest, ImportError> {
    let mut builder = ManifestBuilder::new(
        request.listing.origin.clone(),
        sidecar_converter()?,
        request.description.clone(),
    );
    builder.set_revision(request.listing.revision);
    for file in scanned {
        let listed = file.listed;
        builder.add_source_file(SourceFileInput {
            path: listed.path.clone(),
            length_bytes: listed.length_bytes,
            content: file.scan.content,
            role: listed.role,
            format: file
                .scan
                .index
                .as_ref()
                .map_or(FileFormat::Opaque, |index| index.format),
        })?;
        let owner = match listed.role {
            FileRole::Weights {
                rank: Some(rank), ..
            } => TensorOwner::Rank(rank),
            _ => TensorOwner::Replicated,
        };
        for tensor in file
            .scan
            .index
            .map(|index| index.tensors)
            .unwrap_or_default()
        {
            builder.add_tensor(TensorInput {
                name: tensor.name,
                file: listed.path.clone(),
                offset_bytes: tensor.offset_bytes,
                true_length_bytes: tensor.true_length_bytes,
                dtype: tensor.dtype,
                shape: tensor.shape,
                layout: tensor.layout,
                owner,
            })?;
        }
        for (span, content_key) in file.spans.iter().zip(file.scan.content_keys) {
            builder.add_extent(ExtentInput {
                file: listed.path.clone(),
                logical_offset_bytes: span.offset_bytes,
                true_length_bytes: span.true_length_bytes,
                content_key,
                encoding: EncodingInput::Raw,
            });
        }
    }
    for (name, owner) in &request.owners {
        builder.set_owner(name, *owner)?;
    }
    for alias in &request.aliases {
        builder.add_alias(alias.clone())?;
    }
    for name in &request.state.persistent_buffers {
        builder.add_persistent_buffer(name.clone())?;
    }
    for buffer in &request.state.rematerialized_buffers {
        builder.add_rematerialized_buffer(buffer.clone())?;
    }
    Ok(builder.finish()?)
}
