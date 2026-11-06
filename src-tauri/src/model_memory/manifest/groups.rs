//! The versioned sidecar manifest: the ten field groups of GPU part §3.3 (plan lines
//! 514–527). A [`Manifest`] is plain data; only [`Manifest::validate`] turns it into a
//! [`ValidatedManifest`](super::ValidatedManifest) that can be encoded or used.

use crate::foundation::evidence::BackendRelease;
use crate::foundation::ids::Digest;

use super::codec::CodecFormat;
use super::digests::{ContentKey, DictionaryId, EncodedDigest, ManifestDigest};
use super::types::{
    ElementType, GitCommit, RelativePath, TensorDtype, TensorLayout, TensorName, Token,
    MAX_TENSOR_NAME_BYTES,
};
use super::validate::ManifestError;

/// First eight bytes of every encoded manifest (§3.3 schema: magic).
pub const MANIFEST_MAGIC: [u8; 8] = *b"YGMANFST";
/// Manifest schema version this build writes and reads (§3.3 schema: version). Version 3
/// binds every encoded extent's codec format (codec version and frame parameters,
/// GPU-W08) and lists those formats in the schema group; version 2 bound each source file
/// by the content key of the whole file. A sidecar of an earlier version is refused with
/// [`ManifestError::NeedsReimport`] and never migrated or rewritten in place.
pub const MANIFEST_SCHEMA_VERSION: u16 = 3;
/// The first manifest schema version ever written. Versions from here up to the current
/// one need a re-import; any other version is unknown.
pub const FIRST_MANIFEST_SCHEMA_VERSION: u16 = 1;
/// Canonical encoding version this build writes and reads (§3.3 schema: canonical
/// serialization version).
pub const CANONICAL_ENCODING_VERSION: u16 = 1;
/// Most entries in a short list: kernels, quantization parameters, adapters, compute
/// capabilities and dependency roots.
pub const MAX_LIST_ENTRIES: u32 = 4_096;

/// Byte order of the canonical encoding's integers (§3.3 schema: byte order). Tensor
/// bytes keep their file format's own order (little-endian for safetensors and GGUF).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteOrder {
    BigEndian,
}

/// Limits a manifest declares and every reader enforces before allocating (§3.3 schema:
/// bounds; "validate ... before allocating").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestBounds {
    /// Source files plus prepared representation files.
    pub max_files: u32,
    /// Tensors, and separately aliases and state buffers.
    pub max_tensors: u32,
    pub max_extents: u32,
    pub max_name_bytes: u32,
    pub max_dimensions: u32,
    pub max_ranks: u32,
    /// Largest decoded extent: the per-extent decompression bound.
    pub max_extent_bytes: u64,
    /// Largest total of decoded bytes across all source files.
    pub max_total_bytes: u64,
}

impl ManifestBounds {
    /// The bounds a new manifest declares unless its importer chooses others.
    pub const DEFAULT: Self = Self {
        max_files: 4_096,
        max_tensors: 1 << 20,
        max_extents: 1 << 24,
        max_name_bytes: 512,
        max_dimensions: 16,
        max_ranks: 1_024,
        max_extent_bytes: 64 << 20,
        max_total_bytes: 16 << 40,
    };

    /// The largest bounds this reader accepts a manifest declaring.
    pub const CEILING: Self = Self {
        max_files: 65_536,
        max_tensors: 1 << 22,
        max_extents: 1 << 26,
        max_name_bytes: MAX_TENSOR_NAME_BYTES as u32,
        max_dimensions: 64,
        max_ranks: 65_536,
        max_extent_bytes: 256 << 20,
        max_total_bytes: 1 << 50,
    };

    /// Refuses a declared bound above `ceiling`.
    pub fn check_within(&self, ceiling: &Self) -> Result<(), ManifestError> {
        let pairs: [(&'static str, u64, u64); 8] = [
            ("max_files", self.max_files.into(), ceiling.max_files.into()),
            (
                "max_tensors",
                self.max_tensors.into(),
                ceiling.max_tensors.into(),
            ),
            (
                "max_extents",
                self.max_extents.into(),
                ceiling.max_extents.into(),
            ),
            (
                "max_name_bytes",
                self.max_name_bytes.into(),
                ceiling.max_name_bytes.into(),
            ),
            (
                "max_dimensions",
                self.max_dimensions.into(),
                ceiling.max_dimensions.into(),
            ),
            ("max_ranks", self.max_ranks.into(), ceiling.max_ranks.into()),
            (
                "max_extent_bytes",
                self.max_extent_bytes,
                ceiling.max_extent_bytes,
            ),
            (
                "max_total_bytes",
                self.max_total_bytes,
                ceiling.max_total_bytes,
            ),
        ];
        match pairs
            .into_iter()
            .find(|(_, declared, ceiling)| declared > ceiling)
        {
            Some((bound, declared, ceiling)) => Err(ManifestError::BoundsAboveCeiling {
                bound,
                declared,
                ceiling,
            }),
            None => Ok(()),
        }
    }
}

impl Default for ManifestBounds {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Schema group: the magic ([`MANIFEST_MAGIC`], fixed), versions, byte order and bounds.
/// Its canonical encoding also lists the codec format of every encoded extent, derived
/// from the extents group, so a reader refuses an unknown codec or codec version before it
/// reads or allocates anything else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchemaGroup {
    pub schema_version: u16,
    pub encoding_version: u16,
    pub byte_order: ByteOrder,
    pub bounds: ManifestBounds,
}

impl SchemaGroup {
    /// The schema this build writes, with `bounds`.
    pub const fn current(bounds: ManifestBounds) -> Self {
        Self {
            schema_version: MANIFEST_SCHEMA_VERSION,
            encoding_version: CANONICAL_ENCODING_VERSION,
            byte_order: ByteOrder::BigEndian,
            bounds,
        }
    }
}

/// Where a source comes from (§3.2 source identity: repository or local source). A local
/// folder's location is private and is not recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceOrigin {
    HuggingFace { repository: Token },
    Registry { model: Token },
    LocalFolder,
    Publisher { publisher: Token },
}

/// The immutable revision of a source (§3.3 provenance). A movable name such as a branch
/// is unrepresentable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceRevision {
    GitCommit(GitCommit),
    /// For sources without a commit, such as a local folder: the digest of the file
    /// listing (paths, lengths and file digests), so the revision is the content.
    ContentListing(Digest),
}

/// The container format of a weights file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WeightFormat {
    Safetensors,
    Gguf,
}

/// What a source file is for. The importer is told; it never guesses from a file name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileRole {
    /// Tensor weights. `rank` names the one rank a processed-rank file belongs to; `None`
    /// is an unsharded file every rank may read.
    Weights {
        format: WeightFormat,
        rank: Option<u32>,
    },
    Configuration,
    Tokenizer,
    Other,
}

/// What the indexer found in a source file's header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileFormat {
    /// An 8-byte little-endian header length, the JSON header, then the data buffer.
    Safetensors { header_length_bytes: u64 },
    /// A GGUF header; tensor offsets are relative to the aligned data section.
    Gguf {
        version: u32,
        alignment_bytes: u64,
        data_offset_bytes: u64,
        metadata_digest: Digest,
    },
    /// A file without a tensor index, such as a configuration or tokenizer file.
    Opaque,
}

impl FileFormat {
    /// Where tensor data may start in the file; `None` when the header does not fit in
    /// 64 bits.
    pub fn data_offset_bytes(&self) -> Option<u64> {
        match self {
            Self::Safetensors {
                header_length_bytes,
            } => header_length_bytes.checked_add(8),
            Self::Gguf {
                data_offset_bytes, ..
            } => Some(*data_offset_bytes),
            Self::Opaque => Some(0),
        }
    }
}

/// One source file (§3.3 provenance: source file digests). `content` is the shared content
/// key of the whole file: the key the catalog names its object by and the source identity
/// binds (T05, T07).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceFile {
    pub path: RelativePath,
    pub length_bytes: u64,
    pub content: ContentKey,
    pub role: FileRole,
    pub format: FileFormat,
}

/// The program and version that produced a representation (§3.3 provenance: converter
/// identity).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConverterIdentity {
    pub name: Token,
    pub version: Token,
}

/// Provenance group: immutable source revision, source file digests and converter
/// identity. Files are in path order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provenance {
    pub origin: SourceOrigin,
    pub revision: SourceRevision,
    pub files: Vec<SourceFile>,
    pub converter: ConverterIdentity,
}

/// Exact quantization parameters (§3.3 semantics). Parameters are in key order, each key
/// once, compared exactly as written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Quantization {
    None,
    Method {
        method: Token,
        parameters: Vec<(Token, Token)>,
    },
}

/// Semantics group: configuration and tokenizer digests, dtype, exact quantization and
/// adapters. The two digests are derived from the source files and checked by validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Semantics {
    pub configuration_digest: Digest,
    pub tokenizer_digest: Digest,
    pub compute_dtype: ElementType,
    pub quantization: Quantization,
    /// Adapter identities in application order; each is also a dependency root.
    pub adapters: Vec<Digest>,
}

/// A name with an exact version, such as an architecture adapter.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VersionedName {
    pub name: Token,
    pub version: Token,
}

/// A CUDA compute capability such as 8.9.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ComputeCapability {
    pub major: u8,
    pub minor: u8,
}

/// Hardware an execution representation is restricted to (§3.3 execution ABI).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HardwareRestriction {
    Unrestricted,
    /// Only these compute capabilities, in ascending order.
    ComputeCapabilities(Vec<ComputeCapability>),
}

/// Execution ABI group: runner and adapter versions, layout and kernel identifiers, and
/// hardware restrictions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionAbi {
    pub runner: BackendRelease,
    pub architecture_adapter: VersionedName,
    /// Processed-weight layout identifier; `original` for unprocessed checkpoints.
    pub layout: Token,
    /// Kernel identifiers in ascending order.
    pub kernels: Vec<Token>,
    pub hardware: HardwareRestriction,
}

/// Distribution group: the TP/PP/EP layout; tensor and expert ownership is on each
/// [`TensorEntry`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Distribution {
    pub tensor_parallel_size: u32,
    pub pipeline_parallel_size: u32,
    pub expert_parallel_size: u32,
    /// Number of experts; 0 for a dense model.
    pub expert_count: u32,
}

impl Distribution {
    /// One rank, no experts.
    pub const SINGLE: Self = Self {
        tensor_parallel_size: 1,
        pipeline_parallel_size: 1,
        expert_parallel_size: 1,
        expert_count: 0,
    };

    /// Ranks of one replica: tensor-parallel times pipeline-parallel size.
    pub fn rank_count(&self) -> Option<u32> {
        self.tensor_parallel_size
            .checked_mul(self.pipeline_parallel_size)
    }
}

/// Which rank holds a tensor (§3.3 distribution: expert/tensor ownership).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TensorOwner {
    /// Every rank reads it.
    Replicated,
    /// One rank's shard.
    Rank(u32),
    /// One expert's weights on the rank that owns them.
    Expert { expert: u32, rank: u32 },
}

impl TensorOwner {
    /// The rank this tensor is pinned to, if any.
    pub fn rank(&self) -> Option<u32> {
        match self {
            Self::Replicated => None,
            Self::Rank(rank) | Self::Expert { rank, .. } => Some(*rank),
        }
    }
}

/// Index of a file in [`Provenance::files`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceFileId(pub u32);

impl SourceFileId {
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// One tensor (§3.3 tensor index: name, shape, layout, dtype, offset, true length).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TensorEntry {
    pub name: TensorName,
    pub file: SourceFileId,
    /// Offset from the start of the file, not from its data section.
    pub offset_bytes: u64,
    pub true_length_bytes: u64,
    pub dtype: TensorDtype,
    /// Dimensions in the layout's order.
    pub shape: Vec<u64>,
    pub layout: TensorLayout,
    pub owner: TensorOwner,
}

/// A tied tensor: `name` reads the bytes of `target` (§3.3 tensor index: aliases/ties).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TensorAlias {
    pub name: TensorName,
    pub target: TensorName,
}

/// Tensor index group. Tensors and aliases are in name order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TensorIndex {
    pub tensors: Vec<TensorEntry>,
    pub aliases: Vec<TensorAlias>,
}

/// A buffer that is not stored but rebuilt at load, such as rotary frequencies, with the
/// identity of the code that rebuilds it (§3.3 state: reconstruction adapter identity).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RematerializedBuffer {
    pub name: TensorName,
    pub dtype: TensorDtype,
    pub shape: Vec<u64>,
    pub reconstruction: VersionedName,
}

/// State group: persistent buffers stored in the files and rematerialized buffers, each
/// in name order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateGroup {
    pub persistent_buffers: Vec<TensorName>,
    pub rematerialized_buffers: Vec<RematerializedBuffer>,
}

/// Index of a file in [`ExtentGroup::prepared_files`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PreparedFileId(pub u32);

impl PreparedFileId {
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// A representation file the artifact owns, holding encoded extents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedFile {
    pub path: RelativePath,
    pub length_bytes: u64,
}

/// Where an encoded extent's bytes are stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodedLocation {
    pub file: PreparedFileId,
    pub offset_bytes: u64,
    pub length_bytes: u64,
}

/// An encoded representation of one extent with its own digest and its codec format and
/// dictionary identity (§3.3 extents and integrity; GPU-W08 codec versions).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodedRepresentation {
    /// The codec, its version and the frame parameters a decoder must agree on.
    pub format: CodecFormat,
    pub dictionary: Option<DictionaryId>,
    pub location: EncodedLocation,
    pub digest: EncodedDigest,
}

/// How an extent is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtentEncoding {
    /// The decoded bytes, in place in the source file.
    Raw,
    Encoded(EncodedRepresentation),
}

/// One integrity extent (§2.4 g_h; §3.3 extents: logical offset, true length, decoded
/// digest, encoded location, codec format and dictionary). A raw extent has no codec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    pub file: SourceFileId,
    pub logical_offset_bytes: u64,
    pub true_length_bytes: u64,
    pub content_key: ContentKey,
    pub encoding: ExtentEncoding,
}

impl Extent {
    /// End of the extent in the file's logical bytes; `None` on overflow.
    pub fn end_bytes(&self) -> Option<u64> {
        self.logical_offset_bytes
            .checked_add(self.true_length_bytes)
    }
}

/// Extents group: granularities, prepared files and the extents of every source file in
/// (file, offset) order, tiling each file's logical bytes exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtentGroup {
    /// The integrity-extent size g_h the extents were planned with (§2.4).
    pub integrity_extent_bytes: u64,
    /// The codec block size g_c, present exactly when some extent is encoded.
    pub codec_block_bytes: Option<u64>,
    /// In path order.
    pub prepared_files: Vec<PreparedFile>,
    pub extents: Vec<Extent>,
}

/// Integrity group: per-file extent-tree roots and the decoded content identity. The
/// manifest digest itself follows the encoded body (see
/// [`ValidatedManifest::digest`](super::ValidatedManifest::digest)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegrityGroup {
    /// One root per source file, in file order, over leaves binding offset, true length,
    /// content key, codec format, dictionary, encoded location and encoded digest.
    pub extent_roots: Vec<Digest>,
    /// Digest of every file's path, length and decoded content keys, independent of how
    /// the extents are encoded.
    pub decoded_content_identity: Digest,
}

/// Something an artifact keeps reachable (§3.3 lifecycle: dependency roots).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DependencyRoot {
    Artifact(ManifestDigest),
    Adapter(Digest),
    Dictionary(DictionaryId),
}

/// Storage accounting (§3.3 lifecycle; §3.4 "never delete a user's original"): source
/// bytes are referenced, never owned, so evicting the artifact never deletes originals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageAccounting {
    pub referenced_source_bytes: u64,
    pub owned_representation_bytes: u64,
}

/// What a schema migration must do with this artifact (§3.3 lifecycle; GPU-W03: migrate
/// without rewriting or deleting original model files).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationRequirement {
    /// Rebuild the sidecar from the sources; nothing else is stored.
    ReindexFromSources,
    /// Rebuild the prepared files and the sidecar from the sources.
    RebuildPreparedFromSources,
}

/// Lifecycle group: dependency roots (in order), storage accounting and migration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lifecycle {
    pub dependency_roots: Vec<DependencyRoot>,
    pub storage: StorageAccounting,
    pub migration: MigrationRequirement,
}

/// A versioned sidecar manifest: the ten field groups of §3.3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub schema: SchemaGroup,
    pub provenance: Provenance,
    pub semantics: Semantics,
    pub execution_abi: ExecutionAbi,
    pub distribution: Distribution,
    pub tensor_index: TensorIndex,
    pub state: StateGroup,
    pub extents: ExtentGroup,
    pub integrity: IntegrityGroup,
    pub lifecycle: Lifecycle,
}
