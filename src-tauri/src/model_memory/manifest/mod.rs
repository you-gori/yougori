//! Sidecar manifest and model importer (docs/combined-gpu-memory-and-vm-sandbox-plan.md,
//! GPU part §3.3; GPU-W03; Appendix C).
//!
//! A [`Manifest`] is a versioned sidecar index over existing safetensors and GGUF files
//! with the ten field groups of §3.3: schema, provenance, semantics, execution ABI,
//! distribution, tensor index, state, extents, integrity and lifecycle. It has exactly
//! one canonical encoding, and its [`ManifestDigest`] is the artifact identity (§3.2
//! layer 4). Decoded content keys hash a domain, the true length and the decoded bytes;
//! the manifest binds offsets, tensor interpretation and order to those keys, and the
//! per-file extent trees bind codecs and encoded digests, so a changed shape, offset or
//! codec changes the digest even when the payload is identical.
//!
//! Every encoded extent names a [`CodecFormat`]: its codec, the [`CodecVersion`] of the
//! codec's stream format and the frame parameters a decoder must agree on (GPU-W08). The
//! format is bound into the extent's encoded digest, its leaf and the canonical encoding,
//! whose schema group lists every format first, so a reader refuses an unknown codec or
//! version before allocating. A decoder declares the versions it decodes, and an extent
//! of any other version is refused. A sidecar of an earlier manifest schema is refused
//! with [`ManifestError::NeedsReimport`]; it is never migrated or rewritten in place.
//!
//! Only a [`ValidatedManifest`] can be encoded, read back, planned for a rank or used to
//! verify extent bytes. Validation (overflow, duplicate names, overlapping ranges, rank
//! coverage, missing files, decompression bounds, derived digests and tree roots) runs
//! before any allocation that depends on the manifest.
//!
//! The bounded indexers ([`index_safetensors`], [`index_gguf`]) read only the headers of
//! existing files and refuse malformed input. The [`Importer`] runs the §3.3 protocol:
//! bounded source verification, temporary representation, complete index and proofs,
//! read-back validation, durable commit and catalog publication. It is single-flight per
//! source and execution identity, and a cancelled import never publishes.
//!
//! Every source file is read once: one pass verifies it and, from the same bytes, indexes
//! its header and hashes its extents. Read-back validation reads the staged sidecar and
//! checks it against that index and those proofs.
//!
//! The catalog (T05), identity layers (T07) and extent granularities (T06) are reached
//! through the traits in [`ports`]. The catalog and identity ports have adapters over the
//! committed modules ([`CatalogArtifacts`], [`IdentityLayers`]); the extent port waits for
//! T06. Not built: the packaged `.ywi` representation ([`PACKAGED_FORMAT`]).

mod builder;
mod canonical;
mod catalog_adapter;
mod codec;
mod derive;
mod digests;
mod gguf;
mod groups;
mod identity_adapter;
mod importer;
mod index;
pub mod ports;
mod safetensors;
mod source;
mod tree;
mod types;
mod validate;

#[cfg(test)]
mod tests;

pub use builder::{
    ArtifactDescription, EncodingInput, ExtentInput, ManifestBuilder, SourceFileInput, TensorInput,
};
pub use canonical::SIDECAR_DIGEST_BYTES;
pub use catalog_adapter::{
    catalog_source, root_name, CatalogArtifacts, CatalogContext, ReadBackChannel, SidecarVerifier,
    ARTIFACT_LABEL, CATALOG_ROOT_DOMAIN, CATALOG_SOURCE_DOMAIN, MANIFEST_LABEL, SCHEMA_LABEL,
    SIDECAR_EXTENT_BYTES,
};
pub use codec::{
    zstd_window_ceiling_bytes, BoundedOutput, Codec, CodecFormat, CodecVersion, DecodeError,
    ExtentDecoder, ZstdFrameParameters, ZSTD_MIN_WINDOW_BYTES,
};
pub use derive::listing_digest;
pub use digests::{
    ContentKey, DictionaryId, EncodedDigest, ManifestDigest, CONFIGURATION_DOMAIN,
    DECODED_CONTENT_DOMAIN, DICTIONARY_DOMAIN, ENCODED_DOMAIN, EXTENT_LEAF_DOMAIN,
    GGUF_METADATA_DOMAIN, MANIFEST_DOMAIN, SOURCE_LISTING_DOMAIN, TOKENIZER_DOMAIN,
    TREE_EMPTY_DOMAIN, TREE_NODE_DOMAIN,
};
pub use gguf::{
    index_gguf, GGUF_DEFAULT_ALIGNMENT_BYTES, GGUF_MAGIC, GGUF_MAX_DIMENSIONS, GGUF_MAX_KEY_BYTES,
    GGUF_MAX_TENSOR_NAME_BYTES,
};
pub use groups::{
    ByteOrder, ComputeCapability, ConverterIdentity, DependencyRoot, Distribution, EncodedLocation,
    EncodedRepresentation, ExecutionAbi, Extent, ExtentEncoding, ExtentGroup, FileFormat, FileRole,
    HardwareRestriction, IntegrityGroup, Lifecycle, Manifest, ManifestBounds, MigrationRequirement,
    PreparedFile, PreparedFileId, Provenance, Quantization, RematerializedBuffer, SchemaGroup,
    Semantics, SourceFile, SourceFileId, SourceOrigin, SourceRevision, StateGroup,
    StorageAccounting, TensorAlias, TensorEntry, TensorIndex, TensorOwner, VersionedName,
    WeightFormat, CANONICAL_ENCODING_VERSION, FIRST_MANIFEST_SCHEMA_VERSION, MANIFEST_MAGIC,
    MANIFEST_SCHEMA_VERSION, MAX_LIST_ENTRIES,
};
pub use identity_adapter::{
    compute_capability, kernel_layout, layer_dtype, quantization_parameters_digest, IdentityLayers,
    LayerContext, HUGGING_FACE_HOST, KERNEL_SET_DOMAIN, KERNEL_SET_NAME,
    QUANTIZATION_PARAMETERS_DOMAIN,
};
pub use importer::{
    sidecar_converter, CancellationToken, ImportError, ImportLimits, ImportOutcome, ImportRequest,
    ImportStep, Importer, SIDECAR_CONVERTER_NAME, SIDECAR_CONVERTER_VERSION,
};
pub use index::{index_weights, IndexError, IndexedFile, IndexedTensor, IndexerBounds};
pub use ports::{
    check_extent_plan, ArtifactCatalog, ArtifactIdentity, CatalogError, ExecutionIdentity,
    ExtentPlanError, ExtentPlanner, ExtentSpan, IdentityError, ImportKey, ModelIdentities,
    PublishedArtifact, SourceIdentity, StagingId,
};
pub use safetensors::{index_safetensors, SAFETENSORS_PREFIX_BYTES};
pub use source::{DirectorySource, ListedFile, SourceError, SourceFiles, SourceListing};
pub use tree::{extent_leaf, inclusion_path, tree_root, verify_inclusion};
pub use types::{
    element_count, tensor_bytes, ElementType, GgmlType, GitCommit, NameError, RelativePath,
    ShapeError, TensorDtype, TensorLayout, TensorName, Token, MAX_PATH_BYTES,
    MAX_PATH_COMPONENT_BYTES, MAX_TENSOR_NAME_BYTES, MAX_TOKEN_BYTES,
};
pub use validate::{
    ExtentError, ExtentProof, ManifestError, RankPlan, RankRefusal, ValidatedManifest,
};

/// A representation the plan names but builds only once a measured gate is met.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatedNonGoal {
    pub name: &'static str,
    pub clause: &'static str,
    pub gate: &'static str,
}

/// The packaged `.ywi` representation is not built (§3.3, plan line 512): it is
/// introduced only if measured gains justify conversion, duplication and maintenance.
/// Until then every artifact is a sidecar over the original files, which the importer
/// never converts, copies or deletes.
pub const PACKAGED_FORMAT: GatedNonGoal = GatedNonGoal {
    name: ".ywi packaged representation",
    clause: "GPU part §3.3 (plan line 512)",
    gate: "measured gains justify conversion, duplication and maintenance",
};
