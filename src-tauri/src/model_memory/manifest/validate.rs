//! Validation before any allocation (GPU part §3.3: "Validate overflow, duplicate names,
//! overlapping ranges, rank coverage, missing files and decompression bounds before
//! allocating"; "Authenticate the manifest and its referenced trees").
//!
//! [`ValidatedManifest`] is the only form that can be encoded, decoded, planned for a
//! rank or used to verify extent bytes, so every size a loader allocates from has passed
//! these checks first.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::Range;

use crate::foundation::ids::Digest;

use super::canonical::{
    check_schema_version, codec_formats, decode_body, encode_body, split_sidecar,
};
use super::codec::{
    zstd_window_ceiling_bytes, BoundedOutput, Codec, CodecFormat, CodecVersion, DecodeError,
    ExtentDecoder,
};
use super::derive;
use super::digests::{ContentKey, DictionaryId, EncodedDigest, ManifestDigest};
use super::groups::{
    DependencyRoot, Distribution, EncodedRepresentation, Extent, ExtentEncoding, FileFormat,
    FileRole, HardwareRestriction, Manifest, ManifestBounds, Quantization, SchemaGroup, SourceFile,
    SourceFileId, SourceRevision, TensorEntry, TensorOwner, WeightFormat,
    CANONICAL_ENCODING_VERSION, MAX_LIST_ENTRIES,
};
use super::tree::{extent_leaf, inclusion_path, verify_inclusion};
use super::types::{
    tensor_bytes, NameError, RelativePath, ShapeError, TensorDtype, TensorLayout, TensorName,
};

/// Why a manifest was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestError {
    BadMagic,
    UnsupportedSchemaVersion {
        found: u16,
    },
    /// The sidecar was written under an earlier schema of this format. It is never
    /// migrated or rewritten in place: the model is imported again from its sources, and
    /// the old sidecar is left as it is.
    NeedsReimport {
        schema_version: u16,
    },
    UnsupportedEncodingVersion {
        found: u16,
    },
    UnsupportedByteOrder {
        code: u8,
    },
    Truncated,
    TrailingBytes,
    UnknownTag {
        field: &'static str,
        tag: u8,
    },
    UnknownGgmlType {
        id: u32,
    },
    /// The codec table names a codec this build does not know.
    UnknownCodec {
        code: u8,
    },
    /// The codec table names a version of a known codec that this build does not know.
    UnknownCodecVersion {
        codec: Codec,
        version: u16,
    },
    /// An encoded extent names a codec table entry that does not exist.
    MissingCodecFormat {
        index: u32,
    },
    UnknownRunner,
    InvalidRunnerVersion,
    InvalidName {
        field: &'static str,
        error: NameError,
    },
    InvalidUtf8 {
        field: &'static str,
    },
    /// The digest after the body is not the body's digest.
    DigestMismatch,
    BoundsAboveCeiling {
        bound: &'static str,
        declared: u64,
        ceiling: u64,
    },
    BoundExceeded {
        bound: &'static str,
        found: u64,
        max: u64,
    },
    Overflow {
        field: &'static str,
    },
    NotCanonical {
        collection: &'static str,
    },
    DuplicateName {
        name: String,
    },
    /// Two files share a path, or paths equal up to ASCII case.
    DuplicateFile {
        path: RelativePath,
    },
    /// A reference to a source file the manifest does not list.
    MissingFile {
        file: u32,
    },
    MissingPreparedFile {
        file: u32,
    },
    /// A path the builder was given for a tensor or extent but not as a file.
    UnknownFilePath {
        path: RelativePath,
    },
    MissingTensor {
        name: TensorName,
    },
    MissingAliasTarget {
        alias: TensorName,
    },
    MissingDependencyRoot {
        root: DependencyRoot,
    },
    /// Neither a configuration file nor GGUF metadata configures the model.
    MissingConfiguration,
    /// A file's role, format and header disagree, or a tensor sits in a file without a
    /// tensor index.
    FormatMismatch {
        path: RelativePath,
    },
    EmptyHardwareRestriction,
    TensorShape {
        name: TensorName,
        error: ShapeError,
    },
    TensorLength {
        name: TensorName,
        declared_bytes: u64,
        expected_bytes: u64,
    },
    TensorOutOfBounds {
        name: TensorName,
    },
    TensorMisaligned {
        name: TensorName,
        alignment_bytes: u64,
    },
    OverlappingRanges {
        ranges: &'static str,
        file: u32,
        offset_bytes: u64,
    },
    InvalidParallelLayout,
    RankOutOfRange {
        rank: u32,
        rank_count: u32,
    },
    /// A sharded artifact with no tensor for this rank (rank coverage).
    MissingRank {
        rank: u32,
    },
    ExpertOutOfRange {
        expert: u32,
        expert_count: u32,
    },
    MissingExpert {
        expert: u32,
    },
    /// Under expert parallelism an expert lives on one rank.
    ExpertSplitAcrossRanks {
        expert: u32,
    },
    /// A tensor in a processed-rank file owned by another rank.
    OwnerOffFileRank {
        name: TensorName,
    },
    InvalidGranularity,
    EmptyExtent {
        file: u32,
        offset_bytes: u64,
    },
    ExtentGap {
        file: u32,
        offset_bytes: u64,
    },
    ExtentCoverage {
        file: u32,
        covered_bytes: u64,
        length_bytes: u64,
    },
    /// An encoded extent declares more decoded bytes than the per-extent bound.
    DecompressionBound {
        declared_bytes: u64,
        max_bytes: u64,
    },
    CodecBlockMismatch,
    /// A codec format's window bound is zero or above what its codec block size allows
    /// ([`zstd_window_ceiling_bytes`]).
    InvalidWindowBound {
        declared_bytes: u64,
        max_bytes: u64,
    },
    /// A codec format names a dictionary id but its extent declares no dictionary.
    UndeclaredDictionary {
        dictionary_id: u32,
    },
    EncodedOutOfBounds {
        file: u32,
    },
    /// A prepared file is not tiled exactly by encoded extents.
    PreparedCoverage {
        file: u32,
    },
    DerivedMismatch {
        field: &'static str,
    },
    TreeRootMismatch {
        file: u32,
    },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => f.write_str("this is not a Yougori manifest"),
            Self::UnsupportedSchemaVersion { found } => {
                write!(f, "manifest schema version {found} is not supported")
            }
            Self::NeedsReimport { schema_version } => write!(
                f,
                "manifest schema version {schema_version} is no longer read: import the model \
                 again from its sources"
            ),
            Self::UnsupportedEncodingVersion { found } => {
                write!(f, "canonical encoding version {found} is not supported")
            }
            Self::UnsupportedByteOrder { code } => write!(f, "byte order {code} is not supported"),
            Self::Truncated => f.write_str("the manifest ends early"),
            Self::TrailingBytes => f.write_str("the manifest has bytes after its last field"),
            Self::UnknownTag { field, tag } => write!(f, "{field} has unknown tag {tag}"),
            Self::UnknownGgmlType { id } => write!(f, "ggml type {id} is not supported"),
            Self::UnknownCodec { code } => write!(f, "codec {code} is not known"),
            Self::UnknownCodecVersion { codec, version } => {
                write!(f, "{codec} version {version} is not known")
            }
            Self::MissingCodecFormat { index } => {
                write!(
                    f,
                    "an extent names codec format {index}, which is not listed"
                )
            }
            Self::UnknownRunner => f.write_str("the runner is not a known backend"),
            Self::InvalidRunnerVersion => f.write_str("the runner version is not valid"),
            Self::InvalidName { field, error } => write!(f, "{field}: {error}"),
            Self::InvalidUtf8 { field } => write!(f, "{field} is not UTF-8"),
            Self::DigestMismatch => f.write_str("the manifest digest does not match its body"),
            Self::BoundsAboveCeiling {
                bound,
                declared,
                ceiling,
            } => write!(
                f,
                "{bound} {declared} is above this reader's ceiling {ceiling}"
            ),
            Self::BoundExceeded { bound, found, max } => {
                write!(f, "{found} exceeds {bound} {max}")
            }
            Self::Overflow { field } => write!(f, "{field} overflows 64 bits"),
            Self::NotCanonical { collection } => {
                write!(f, "{collection} are not in canonical order")
            }
            Self::DuplicateName { name } => write!(f, "{name:?} appears twice"),
            Self::DuplicateFile { path } => write!(f, "file {path} appears twice"),
            Self::MissingFile { file } => write!(f, "source file {file} is not listed"),
            Self::MissingPreparedFile { file } => write!(f, "prepared file {file} is not listed"),
            Self::UnknownFilePath { path } => write!(f, "file {path} was not added"),
            Self::MissingTensor { name } => write!(f, "tensor {name} is not in the index"),
            Self::MissingAliasTarget { alias } => {
                write!(f, "alias {alias} names a tensor that is not in the index")
            }
            Self::MissingDependencyRoot { root } => {
                write!(f, "dependency root {root:?} is not recorded")
            }
            Self::MissingConfiguration => {
                f.write_str("no configuration file or GGUF metadata configures the model")
            }
            Self::FormatMismatch { path } => {
                write!(f, "file {path}: its role, format and header disagree")
            }
            Self::EmptyHardwareRestriction => {
                f.write_str("a hardware restriction must name at least one compute capability")
            }
            Self::TensorShape { name, error } => write!(f, "tensor {name}: {error}"),
            Self::TensorLength {
                name,
                declared_bytes,
                expected_bytes,
            } => write!(
                f,
                "tensor {name} declares {declared_bytes} bytes but its shape needs \
                 {expected_bytes}"
            ),
            Self::TensorOutOfBounds { name } => {
                write!(f, "tensor {name} lies outside its file's data")
            }
            Self::TensorMisaligned {
                name,
                alignment_bytes,
            } => write!(f, "tensor {name} is not aligned to {alignment_bytes} bytes"),
            Self::OverlappingRanges {
                ranges,
                file,
                offset_bytes,
            } => write!(f, "{ranges} overlap in file {file} at byte {offset_bytes}"),
            Self::InvalidParallelLayout => f.write_str("the parallel layout is not valid"),
            Self::RankOutOfRange { rank, rank_count } => {
                write!(f, "rank {rank} is outside the {rank_count} ranks")
            }
            Self::MissingRank { rank } => write!(f, "no tensor is assigned to rank {rank}"),
            Self::ExpertOutOfRange {
                expert,
                expert_count,
            } => write!(f, "expert {expert} is outside the {expert_count} experts"),
            Self::MissingExpert { expert } => write!(f, "no tensor is assigned to expert {expert}"),
            Self::ExpertSplitAcrossRanks { expert } => {
                write!(f, "expert {expert} is split across ranks")
            }
            Self::OwnerOffFileRank { name } => {
                write!(f, "tensor {name} is owned by a rank other than its file's")
            }
            Self::InvalidGranularity => f.write_str("an extent granularity is out of bounds"),
            Self::EmptyExtent { file, offset_bytes } => {
                write!(f, "file {file} has an empty extent at byte {offset_bytes}")
            }
            Self::ExtentGap { file, offset_bytes } => {
                write!(f, "file {file} has no extent at byte {offset_bytes}")
            }
            Self::ExtentCoverage {
                file,
                covered_bytes,
                length_bytes,
            } => write!(
                f,
                "extents of file {file} cover {covered_bytes} of its {length_bytes} bytes"
            ),
            Self::DecompressionBound {
                declared_bytes,
                max_bytes,
            } => write!(
                f,
                "an encoded extent declares {declared_bytes} decoded bytes, above the \
                 {max_bytes}-byte bound"
            ),
            Self::CodecBlockMismatch => {
                f.write_str("the codec block size and the encoded extents disagree")
            }
            Self::InvalidWindowBound {
                declared_bytes,
                max_bytes,
            } => write!(
                f,
                "a codec format's window bound of {declared_bytes} bytes is not between 1 and \
                 {max_bytes} bytes"
            ),
            Self::UndeclaredDictionary { dictionary_id } => write!(
                f,
                "a codec format names dictionary id {dictionary_id} for an extent without a \
                 dictionary"
            ),
            Self::EncodedOutOfBounds { file } => {
                write!(f, "an encoded extent lies outside prepared file {file}")
            }
            Self::PreparedCoverage { file } => {
                write!(f, "prepared file {file} has bytes no extent accounts for")
            }
            Self::DerivedMismatch { field } => {
                write!(f, "the {field} does not match the manifest's content")
            }
            Self::TreeRootMismatch { file } => {
                write!(
                    f,
                    "the extent tree root of file {file} does not match its extents"
                )
            }
        }
    }
}

impl std::error::Error for ManifestError {}

/// Why bytes read for an extent were refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtentError {
    NoSuchExtent,
    StoredLength {
        expected_bytes: u64,
        found_bytes: u64,
    },
    DictionaryMissing,
    UnexpectedDictionary,
    DictionaryMismatch,
    /// Checked before any decoding: a hash mismatch is never decoded or used.
    EncodedDigestMismatch,
    /// No decoder of the extent's codec was supplied.
    DecoderUnavailable {
        codec: Codec,
    },
    /// Decoders of the extent's codec were supplied, but none declares its version.
    DecoderVersionMismatch {
        version: CodecVersion,
    },
    Decode(DecodeError),
    DecodedLength {
        expected_bytes: u64,
        found_bytes: u64,
    },
    ContentKeyMismatch,
}

impl fmt::Display for ExtentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSuchExtent => f.write_str("the manifest has no such extent"),
            Self::StoredLength {
                expected_bytes,
                found_bytes,
            } => write!(
                f,
                "expected {expected_bytes} stored bytes, found {found_bytes}"
            ),
            Self::DictionaryMissing => f.write_str("the extent's dictionary was not supplied"),
            Self::UnexpectedDictionary => f.write_str("the extent uses no dictionary"),
            Self::DictionaryMismatch => f.write_str("the dictionary is not the declared one"),
            Self::EncodedDigestMismatch => {
                f.write_str("the encoded bytes do not match their digest")
            }
            Self::DecoderUnavailable { codec } => write!(f, "no {codec} decoder is available"),
            Self::DecoderVersionMismatch { version } => {
                write!(f, "no decoder supplied decodes {version}")
            }
            Self::Decode(error) => write!(f, "{error}"),
            Self::DecodedLength {
                expected_bytes,
                found_bytes,
            } => write!(f, "decoded {found_bytes} bytes, expected {expected_bytes}"),
            Self::ContentKeyMismatch => {
                f.write_str("the decoded bytes do not match their content key")
            }
        }
    }
}

impl std::error::Error for ExtentError {}

/// Why a rank plan was refused (GPU-W03: "wrong rank ... rejected before execution").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RankRefusal {
    /// Processed-rank files fit only the layout they were produced for.
    LayoutMismatch {
        manifest: Distribution,
        requested: Distribution,
    },
    RankOutOfRange {
        rank: u32,
        rank_count: u32,
    },
}

impl fmt::Display for RankRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LayoutMismatch { .. } => {
                f.write_str("the artifact was prepared for a different rank layout")
            }
            Self::RankOutOfRange { rank, rank_count } => {
                write!(
                    f,
                    "rank {rank} is outside the artifact's {rank_count} ranks"
                )
            }
        }
    }
}

impl std::error::Error for RankRefusal {}

/// What one rank loads: its tensors and the integrity extents holding them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RankPlan {
    pub rank: u32,
    /// The rank's own tensors and every replicated tensor, in name order.
    pub tensors: Vec<TensorName>,
    pub tensor_bytes: u64,
    /// Indices into the extent list, ascending: the scatter/gather map from these tensors
    /// to integrity extents.
    pub extents: Vec<usize>,
}

/// An inclusion proof of one extent in its file's extent tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtentProof {
    pub file: SourceFileId,
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub path: Vec<Digest>,
}

impl ExtentProof {
    /// Whether this proves `extent` is in the tree with `root`.
    pub fn verify(&self, root: &Digest, extent: &Extent) -> bool {
        extent.file == self.file
            && verify_inclusion(
                root,
                &extent_leaf(extent),
                self.leaf_index,
                self.leaf_count,
                &self.path,
            )
    }
}

/// A manifest that passed every check, with its canonical body and digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedManifest {
    manifest: Manifest,
    body: Vec<u8>,
    digest: ManifestDigest,
}

impl Manifest {
    /// Checks every rule of §3.3 and fixes the canonical encoding and digest.
    pub fn validate(self) -> Result<ValidatedManifest, ManifestError> {
        check_schema(&self.schema)?;
        let bounds = self.schema.bounds;
        check_provenance(&self, &bounds)?;
        let rank_count = check_distribution(&self, &bounds)?;
        check_semantics(&self)?;
        check_execution_abi(&self)?;
        check_tensor_index(&self, &bounds, rank_count)?;
        check_state(&self, &bounds)?;
        check_extents(&self, &bounds)?;
        check_integrity(&self)?;
        check_lifecycle(&self)?;
        let body = encode_body(&self);
        let digest = ManifestDigest::of_body(&body);
        Ok(ValidatedManifest {
            manifest: self,
            body,
            digest,
        })
    }
}

impl ValidatedManifest {
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn into_manifest(self) -> Manifest {
        self.manifest
    }

    /// The artifact identity (§3.2 layer 4).
    pub fn digest(&self) -> ManifestDigest {
        self.digest
    }

    /// The sidecar: the canonical body followed by its manifest digest.
    pub fn sidecar_bytes(&self) -> Vec<u8> {
        let mut sidecar = Vec::with_capacity(self.body.len() + 32);
        sidecar.extend_from_slice(&self.body);
        sidecar.extend_from_slice(self.digest.digest().as_bytes());
        sidecar
    }

    /// Reads a sidecar under this build's [`ManifestBounds::CEILING`].
    pub fn from_sidecar_bytes(sidecar: &[u8]) -> Result<Self, ManifestError> {
        Self::from_sidecar_bytes_within(sidecar, &ManifestBounds::CEILING)
    }

    /// Reads a sidecar: the digest is checked first, then the body is decoded under the
    /// bounds it declares (at most `ceiling`), validated, and required to be the one
    /// canonical encoding.
    pub fn from_sidecar_bytes_within(
        sidecar: &[u8],
        ceiling: &ManifestBounds,
    ) -> Result<Self, ManifestError> {
        let (body, trailer) = split_sidecar(sidecar)?;
        if ManifestDigest::of_body(body).digest() != trailer {
            return Err(ManifestError::DigestMismatch);
        }
        let validated = decode_body(body, ceiling)?.validate()?;
        if validated.body != body {
            return Err(ManifestError::NotCanonical {
                collection: "encodings",
            });
        }
        Ok(validated)
    }

    /// The tensor named `name`, following an alias to its target.
    pub fn tensor(&self, name: &str) -> Option<&TensorEntry> {
        let index = &self.manifest.tensor_index;
        let find = |name: &str| {
            index
                .tensors
                .binary_search_by(|tensor| tensor.name.as_str().cmp(name))
                .ok()
                .and_then(|position| index.tensors.get(position))
        };
        find(name).or_else(|| {
            index
                .aliases
                .binary_search_by(|alias| alias.name.as_str().cmp(name))
                .ok()
                .and_then(|position| index.aliases.get(position))
                .and_then(|alias| find(alias.target.as_str()))
        })
    }

    /// The root of `file`'s extent tree.
    pub fn extent_root(&self, file: SourceFileId) -> Option<Digest> {
        self.manifest
            .integrity
            .extent_roots
            .get(file.index())
            .copied()
    }

    fn file_range(&self, file: SourceFileId) -> Range<usize> {
        let extents = &self.manifest.extents.extents;
        extents.partition_point(|extent| extent.file < file)
            ..extents.partition_point(|extent| extent.file <= file)
    }

    /// Indices of the extents of `file` overlapping `[offset, offset + length)`.
    pub fn extents_covering(
        &self,
        file: SourceFileId,
        offset_bytes: u64,
        length_bytes: u64,
    ) -> Range<usize> {
        let range = self.file_range(file);
        let extents = self
            .manifest
            .extents
            .extents
            .get(range.clone())
            .unwrap_or(&[]);
        let end_bytes = offset_bytes.saturating_add(length_bytes);
        if length_bytes == 0 {
            return range.start..range.start;
        }
        let first = extents
            .partition_point(|extent| extent.end_bytes().unwrap_or(u64::MAX) <= offset_bytes);
        let last = extents.partition_point(|extent| extent.logical_offset_bytes < end_bytes);
        (range.start + first)..(range.start + last.max(first))
    }

    /// What `rank` of `layout` loads. Refused unless `layout` is the artifact's own and the
    /// rank exists, so a wrong rank never reaches execution.
    pub fn rank_plan(&self, layout: &Distribution, rank: u32) -> Result<RankPlan, RankRefusal> {
        let distribution = self.manifest.distribution;
        if *layout != distribution {
            return Err(RankRefusal::LayoutMismatch {
                manifest: distribution,
                requested: *layout,
            });
        }
        let rank_count = distribution.rank_count().unwrap_or(0);
        if rank >= rank_count {
            return Err(RankRefusal::RankOutOfRange { rank, rank_count });
        }
        let mut tensors = Vec::new();
        let mut bytes = 0u64;
        let mut extents = BTreeSet::new();
        for tensor in &self.manifest.tensor_index.tensors {
            if tensor.owner.rank().is_some_and(|owner| owner != rank) {
                continue;
            }
            tensors.push(tensor.name.clone());
            bytes = bytes.saturating_add(tensor.true_length_bytes);
            extents.extend(self.extents_covering(
                tensor.file,
                tensor.offset_bytes,
                tensor.true_length_bytes,
            ));
        }
        Ok(RankPlan {
            rank,
            tensors,
            tensor_bytes: bytes,
            extents: extents.into_iter().collect(),
        })
    }

    /// An inclusion proof of extent `extent_index` in its file's tree.
    pub fn extent_proof(&self, extent_index: usize) -> Option<ExtentProof> {
        let all = &self.manifest.extents.extents;
        let extent = all.get(extent_index)?;
        let range = self.file_range(extent.file);
        let leaves: Vec<Digest> = all.get(range.clone())?.iter().map(extent_leaf).collect();
        let local = extent_index.checked_sub(range.start)?;
        Some(ExtentProof {
            file: extent.file,
            leaf_index: local as u64,
            leaf_count: leaves.len() as u64,
            path: inclusion_path(&leaves, local),
        })
    }

    /// The distinct codec formats of the encoded extents, in canonical order: the codec
    /// table of the encoding, and what a loader needs decoders for.
    pub fn codec_formats(&self) -> Vec<CodecFormat> {
        codec_formats(&self.manifest.extents)
    }

    /// Refuses `decoders` unless, for every codec format of the manifest, one of them
    /// decodes its codec and declares its version, so a loader can refuse before it
    /// reads any extent.
    pub fn check_decoders(&self, decoders: &[&dyn ExtentDecoder]) -> Result<(), ExtentError> {
        self.codec_formats()
            .iter()
            .try_for_each(|format| select_decoder(decoders, format).map(|_| ()))
    }

    /// Verifies bytes read for extent `extent_index` and returns its decoded bytes.
    ///
    /// Encoded bytes are checked against their encoded digest, which binds the codec
    /// format, before any decoding, and the dictionary against its identity. The decoder
    /// must decode the extent's codec and declare its version; it is given the declared
    /// format and writes into a buffer of exactly the declared true length, which
    /// validation already held to the per-extent bound.
    pub fn verify_extent(
        &self,
        extent_index: usize,
        stored: &[u8],
        dictionary: Option<&[u8]>,
        decoders: &[&dyn ExtentDecoder],
    ) -> Result<Vec<u8>, ExtentError> {
        let extent = self
            .manifest
            .extents
            .extents
            .get(extent_index)
            .ok_or(ExtentError::NoSuchExtent)?;
        let decoded = match extent.encoding {
            ExtentEncoding::Raw => {
                if stored.len() as u64 != extent.true_length_bytes {
                    return Err(ExtentError::StoredLength {
                        expected_bytes: extent.true_length_bytes,
                        found_bytes: stored.len() as u64,
                    });
                }
                if dictionary.is_some() {
                    return Err(ExtentError::UnexpectedDictionary);
                }
                stored.to_vec()
            }
            ExtentEncoding::Encoded(encoded) => {
                if stored.len() as u64 != encoded.location.length_bytes {
                    return Err(ExtentError::StoredLength {
                        expected_bytes: encoded.location.length_bytes,
                        found_bytes: stored.len() as u64,
                    });
                }
                let dictionary = match (encoded.dictionary, dictionary) {
                    (None, None) => None,
                    (None, Some(_)) => return Err(ExtentError::UnexpectedDictionary),
                    (Some(_), None) => return Err(ExtentError::DictionaryMissing),
                    (Some(declared), Some(bytes)) => {
                        if DictionaryId::of(bytes) != declared {
                            return Err(ExtentError::DictionaryMismatch);
                        }
                        Some(bytes)
                    }
                };
                if EncodedDigest::of(encoded.format, encoded.dictionary, stored) != encoded.digest {
                    return Err(ExtentError::EncodedDigestMismatch);
                }
                let decoder = select_decoder(decoders, &encoded.format)?;
                let limit_bytes = usize::try_from(extent.true_length_bytes).map_err(|_| {
                    ExtentError::Decode(DecodeError::BoundExceeded {
                        limit_bytes: extent.true_length_bytes,
                    })
                })?;
                let mut output = BoundedOutput::with_limit(limit_bytes);
                decoder
                    .decode(&encoded.format, stored, dictionary, &mut output)
                    .map_err(ExtentError::Decode)?;
                if output.written_bytes() != limit_bytes {
                    return Err(ExtentError::DecodedLength {
                        expected_bytes: extent.true_length_bytes,
                        found_bytes: output.written_bytes() as u64,
                    });
                }
                output.into_bytes()
            }
        };
        if ContentKey::of(&decoded) != extent.content_key {
            return Err(ExtentError::ContentKeyMismatch);
        }
        Ok(decoded)
    }
}

/// The first of `decoders` that decodes the format's codec and declares its version
/// (GPU-W08). Nothing is allocated before this choice.
fn select_decoder<'d>(
    decoders: &[&'d dyn ExtentDecoder],
    format: &CodecFormat,
) -> Result<&'d dyn ExtentDecoder, ExtentError> {
    let codec = format.codec();
    let version = format.version();
    let mut of_codec = decoders
        .iter()
        .copied()
        .filter(|decoder| decoder.codec() == codec)
        .peekable();
    if of_codec.peek().is_none() {
        return Err(ExtentError::DecoderUnavailable { codec });
    }
    of_codec
        .find(|decoder| decoder.versions().contains(&version))
        .ok_or(ExtentError::DecoderVersionMismatch { version })
}

fn check_count(
    count: usize,
    max: impl Into<u64>,
    bound: &'static str,
) -> Result<(), ManifestError> {
    let max = max.into();
    let found = count as u64;
    if found > max {
        return Err(ManifestError::BoundExceeded { bound, found, max });
    }
    Ok(())
}

/// Refuses a collection that is not strictly increasing; equal neighbours are duplicates.
fn check_order<T: Ord>(
    items: impl IntoIterator<Item = T>,
    collection: &'static str,
    duplicate: impl Fn(&T) -> ManifestError,
) -> Result<(), ManifestError> {
    let mut previous: Option<T> = None;
    for item in items {
        if let Some(previous) = &previous {
            match previous.cmp(&item) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => return Err(duplicate(&item)),
                std::cmp::Ordering::Greater => {
                    return Err(ManifestError::NotCanonical { collection })
                }
            }
        }
        previous = Some(item);
    }
    Ok(())
}

fn duplicate_name<T: fmt::Display>(name: &T) -> ManifestError {
    ManifestError::DuplicateName {
        name: name.to_string(),
    }
}

fn check_name(name: &TensorName, bounds: &ManifestBounds) -> Result<(), ManifestError> {
    check_count(name.as_str().len(), bounds.max_name_bytes, "max_name_bytes")
}

fn check_schema(schema: &SchemaGroup) -> Result<(), ManifestError> {
    check_schema_version(schema.schema_version)?;
    if schema.encoding_version != CANONICAL_ENCODING_VERSION {
        return Err(ManifestError::UnsupportedEncodingVersion {
            found: schema.encoding_version,
        });
    }
    schema.bounds.check_within(&ManifestBounds::CEILING)
}

fn check_provenance(manifest: &Manifest, bounds: &ManifestBounds) -> Result<(), ManifestError> {
    let files = &manifest.provenance.files;
    let prepared = &manifest.extents.prepared_files;
    check_count(files.len() + prepared.len(), bounds.max_files, "max_files")?;
    check_order(
        files.iter().map(|file| &file.path),
        "source files",
        |path| ManifestError::DuplicateFile {
            path: (*path).clone(),
        },
    )?;
    let mut folded = BTreeSet::new();
    for path in files
        .iter()
        .map(|file| &file.path)
        .chain(prepared.iter().map(|file| &file.path))
    {
        if !folded.insert(path.folded()) {
            return Err(ManifestError::DuplicateFile { path: path.clone() });
        }
    }
    let total_bytes = files
        .iter()
        .try_fold(0u64, |total, file| total.checked_add(file.length_bytes))
        .ok_or(ManifestError::Overflow {
            field: "source bytes",
        })?;
    if total_bytes > bounds.max_total_bytes {
        return Err(ManifestError::BoundExceeded {
            bound: "max_total_bytes",
            found: total_bytes,
            max: bounds.max_total_bytes,
        });
    }
    if let SourceRevision::ContentListing(listing) = manifest.provenance.revision {
        if listing != derive::source_listing_digest(files) {
            return Err(ManifestError::DerivedMismatch {
                field: "content listing revision",
            });
        }
    }
    files.iter().try_for_each(check_file_format)
}

fn check_file_format(file: &SourceFile) -> Result<(), ManifestError> {
    let mismatch = || ManifestError::FormatMismatch {
        path: file.path.clone(),
    };
    match (file.role, file.format) {
        (
            FileRole::Weights {
                format: WeightFormat::Safetensors,
                ..
            },
            FileFormat::Safetensors {
                header_length_bytes,
            },
        ) => {
            if header_length_bytes
                .checked_add(8)
                .is_none_or(|end| end > file.length_bytes)
            {
                return Err(mismatch());
            }
        }
        (
            FileRole::Weights {
                format: WeightFormat::Gguf,
                ..
            },
            FileFormat::Gguf {
                version,
                alignment_bytes,
                data_offset_bytes,
                ..
            },
        ) => {
            if !matches!(version, 2 | 3)
                || !alignment_bytes.is_power_of_two()
                || data_offset_bytes % alignment_bytes != 0
            {
                return Err(mismatch());
            }
        }
        (FileRole::Configuration | FileRole::Tokenizer | FileRole::Other, FileFormat::Opaque) => {}
        _ => return Err(mismatch()),
    }
    Ok(())
}

fn check_distribution(manifest: &Manifest, bounds: &ManifestBounds) -> Result<u32, ManifestError> {
    let distribution = &manifest.distribution;
    if distribution.tensor_parallel_size == 0
        || distribution.pipeline_parallel_size == 0
        || distribution.expert_parallel_size == 0
    {
        return Err(ManifestError::InvalidParallelLayout);
    }
    let rank_count = distribution.rank_count().ok_or(ManifestError::Overflow {
        field: "rank count",
    })?;
    if rank_count > bounds.max_ranks {
        return Err(ManifestError::BoundExceeded {
            bound: "max_ranks",
            found: rank_count.into(),
            max: bounds.max_ranks.into(),
        });
    }
    if rank_count % distribution.expert_parallel_size != 0
        || (distribution.expert_parallel_size > 1 && distribution.expert_count == 0)
    {
        return Err(ManifestError::InvalidParallelLayout);
    }
    for file in &manifest.provenance.files {
        if let FileRole::Weights {
            rank: Some(rank), ..
        } = file.role
        {
            if rank >= rank_count {
                return Err(ManifestError::RankOutOfRange { rank, rank_count });
            }
        }
    }
    Ok(rank_count)
}

fn check_semantics(manifest: &Manifest) -> Result<(), ManifestError> {
    let files = &manifest.provenance.files;
    let semantics = &manifest.semantics;
    if !derive::has_configuration(files) {
        return Err(ManifestError::MissingConfiguration);
    }
    if semantics.configuration_digest != derive::configuration_digest(files) {
        return Err(ManifestError::DerivedMismatch {
            field: "configuration digest",
        });
    }
    if semantics.tokenizer_digest != derive::tokenizer_digest(files) {
        return Err(ManifestError::DerivedMismatch {
            field: "tokenizer digest",
        });
    }
    if let Quantization::Method { parameters, .. } = &semantics.quantization {
        check_count(
            parameters.len(),
            MAX_LIST_ENTRIES,
            "quantization parameters",
        )?;
        check_order(
            parameters.iter().map(|(key, _)| key),
            "quantization parameters",
            duplicate_name,
        )?;
    }
    check_count(semantics.adapters.len(), MAX_LIST_ENTRIES, "adapters")?;
    let mut seen = BTreeSet::new();
    for adapter in &semantics.adapters {
        if !seen.insert(adapter) {
            return Err(duplicate_name(adapter));
        }
    }
    Ok(())
}

fn check_execution_abi(manifest: &Manifest) -> Result<(), ManifestError> {
    let abi = &manifest.execution_abi;
    check_count(abi.kernels.len(), MAX_LIST_ENTRIES, "kernels")?;
    check_order(abi.kernels.iter(), "kernels", duplicate_name)?;
    if let HardwareRestriction::ComputeCapabilities(capabilities) = &abi.hardware {
        if capabilities.is_empty() {
            return Err(ManifestError::EmptyHardwareRestriction);
        }
        check_count(capabilities.len(), MAX_LIST_ENTRIES, "compute capabilities")?;
        check_order(capabilities.iter(), "compute capabilities", |capability| {
            ManifestError::DuplicateName {
                name: format!("{}.{}", capability.major, capability.minor),
            }
        })?;
    }
    Ok(())
}

fn expected_layout(file: &SourceFile) -> Result<TensorLayout, ManifestError> {
    match file.format {
        FileFormat::Safetensors { .. } => Ok(TensorLayout::RowMajor),
        FileFormat::Gguf { .. } => Ok(TensorLayout::GgmlInnermostFirst),
        FileFormat::Opaque => Err(ManifestError::FormatMismatch {
            path: file.path.clone(),
        }),
    }
}

fn check_tensor(
    tensor: &TensorEntry,
    file: &SourceFile,
    bounds: &ManifestBounds,
) -> Result<u64, ManifestError> {
    check_name(&tensor.name, bounds)?;
    check_count(tensor.shape.len(), bounds.max_dimensions, "max_dimensions")?;
    if tensor.layout != expected_layout(file)? {
        return Err(ManifestError::TensorShape {
            name: tensor.name.clone(),
            error: ShapeError::LayoutMismatch,
        });
    }
    let expected_bytes =
        tensor_bytes(tensor.dtype, tensor.layout, &tensor.shape).map_err(|error| {
            ManifestError::TensorShape {
                name: tensor.name.clone(),
                error,
            }
        })?;
    if expected_bytes != tensor.true_length_bytes {
        return Err(ManifestError::TensorLength {
            name: tensor.name.clone(),
            declared_bytes: tensor.true_length_bytes,
            expected_bytes,
        });
    }
    let end_bytes = tensor
        .offset_bytes
        .checked_add(tensor.true_length_bytes)
        .ok_or(ManifestError::Overflow {
            field: "tensor range",
        })?;
    let data_offset_bytes = file
        .format
        .data_offset_bytes()
        .ok_or(ManifestError::Overflow {
            field: "data offset",
        })?;
    if tensor.offset_bytes < data_offset_bytes || end_bytes > file.length_bytes {
        return Err(ManifestError::TensorOutOfBounds {
            name: tensor.name.clone(),
        });
    }
    if let FileFormat::Gguf {
        alignment_bytes, ..
    } = file.format
    {
        let relative_bytes = tensor.offset_bytes - data_offset_bytes;
        if !relative_bytes.is_multiple_of(alignment_bytes) {
            return Err(ManifestError::TensorMisaligned {
                name: tensor.name.clone(),
                alignment_bytes,
            });
        }
    }
    if let FileRole::Weights {
        rank: Some(file_rank),
        ..
    } = file.role
    {
        if tensor.owner.rank() != Some(file_rank) {
            return Err(ManifestError::OwnerOffFileRank {
                name: tensor.name.clone(),
            });
        }
    }
    Ok(end_bytes)
}

fn check_tensor_index(
    manifest: &Manifest,
    bounds: &ManifestBounds,
    rank_count: u32,
) -> Result<(), ManifestError> {
    let index = &manifest.tensor_index;
    let files = &manifest.provenance.files;
    let distribution = &manifest.distribution;
    check_count(index.tensors.len(), bounds.max_tensors, "max_tensors")?;
    check_count(index.aliases.len(), bounds.max_tensors, "aliases")?;
    check_order(
        index.tensors.iter().map(|tensor| &tensor.name),
        "tensors",
        duplicate_name,
    )?;
    check_order(
        index.aliases.iter().map(|alias| &alias.name),
        "aliases",
        duplicate_name,
    )?;

    let mut ranges: BTreeMap<u32, Vec<(u64, u64)>> = BTreeMap::new();
    let mut rank_owned = vec![false; rank_count as usize];
    let mut any_pinned = false;
    let mut expert_ranks: BTreeMap<u32, u32> = BTreeMap::new();
    for tensor in &index.tensors {
        let file = files
            .get(tensor.file.index())
            .ok_or(ManifestError::MissingFile {
                file: tensor.file.0,
            })?;
        let end_bytes = check_tensor(tensor, file, bounds)?;
        if tensor.true_length_bytes > 0 {
            ranges
                .entry(tensor.file.0)
                .or_default()
                .push((tensor.offset_bytes, end_bytes));
        }
        let Some(rank) = tensor.owner.rank() else {
            continue;
        };
        any_pinned = true;
        *rank_owned
            .get_mut(rank as usize)
            .ok_or(ManifestError::RankOutOfRange { rank, rank_count })? = true;
        if let TensorOwner::Expert { expert, rank } = tensor.owner {
            if expert >= distribution.expert_count {
                return Err(ManifestError::ExpertOutOfRange {
                    expert,
                    expert_count: distribution.expert_count,
                });
            }
            let first_rank = *expert_ranks.entry(expert).or_insert(rank);
            if first_rank != rank && distribution.expert_parallel_size > 1 {
                return Err(ManifestError::ExpertSplitAcrossRanks { expert });
            }
        }
    }
    for (file, mut list) in ranges {
        list.sort_unstable();
        for pair in list.windows(2) {
            if let [(_, first_end), (second_start, _)] = pair {
                if second_start < first_end {
                    return Err(ManifestError::OverlappingRanges {
                        ranges: "tensors",
                        file,
                        offset_bytes: *second_start,
                    });
                }
            }
        }
    }
    if any_pinned {
        if let Some(rank) = rank_owned.iter().position(|owned| !owned) {
            return Err(ManifestError::MissingRank { rank: rank as u32 });
        }
    }
    if let Some(expert) =
        (0..distribution.expert_count).find(|expert| !expert_ranks.contains_key(expert))
    {
        return Err(ManifestError::MissingExpert { expert });
    }
    for alias in &index.aliases {
        check_name(&alias.name, bounds)?;
        check_name(&alias.target, bounds)?;
        if has_tensor(manifest, &alias.name) {
            return Err(duplicate_name(&alias.name));
        }
        if !has_tensor(manifest, &alias.target) {
            return Err(ManifestError::MissingAliasTarget {
                alias: alias.name.clone(),
            });
        }
    }
    Ok(())
}

fn has_tensor(manifest: &Manifest, name: &TensorName) -> bool {
    manifest
        .tensor_index
        .tensors
        .binary_search_by(|tensor| tensor.name.cmp(name))
        .is_ok()
}

fn has_alias(manifest: &Manifest, name: &TensorName) -> bool {
    manifest
        .tensor_index
        .aliases
        .binary_search_by(|alias| alias.name.cmp(name))
        .is_ok()
}

fn check_state(manifest: &Manifest, bounds: &ManifestBounds) -> Result<(), ManifestError> {
    let state = &manifest.state;
    check_count(
        state.persistent_buffers.len(),
        bounds.max_tensors,
        "persistent buffers",
    )?;
    check_count(
        state.rematerialized_buffers.len(),
        bounds.max_tensors,
        "rematerialized buffers",
    )?;
    check_order(
        state.persistent_buffers.iter(),
        "persistent buffers",
        duplicate_name,
    )?;
    check_order(
        state
            .rematerialized_buffers
            .iter()
            .map(|buffer| &buffer.name),
        "rematerialized buffers",
        duplicate_name,
    )?;
    for name in &state.persistent_buffers {
        check_name(name, bounds)?;
        if !has_tensor(manifest, name) && !has_alias(manifest, name) {
            return Err(ManifestError::MissingTensor { name: name.clone() });
        }
    }
    for buffer in &state.rematerialized_buffers {
        check_name(&buffer.name, bounds)?;
        check_count(buffer.shape.len(), bounds.max_dimensions, "max_dimensions")?;
        if has_tensor(manifest, &buffer.name)
            || has_alias(manifest, &buffer.name)
            || state.persistent_buffers.binary_search(&buffer.name).is_ok()
        {
            return Err(duplicate_name(&buffer.name));
        }
        let layout = match buffer.dtype {
            TensorDtype::Element(_) => TensorLayout::RowMajor,
            TensorDtype::Ggml(_) => TensorLayout::GgmlInnermostFirst,
        };
        tensor_bytes(buffer.dtype, layout, &buffer.shape).map_err(|error| {
            ManifestError::TensorShape {
                name: buffer.name.clone(),
                error,
            }
        })?;
    }
    Ok(())
}

fn check_extent_bounds(
    extent: &Extent,
    manifest: &Manifest,
    bounds: &ManifestBounds,
    encoded_ranges: &mut BTreeMap<u32, Vec<(u64, u64)>>,
) -> Result<u64, ManifestError> {
    let group = &manifest.extents;
    if extent.true_length_bytes == 0 {
        return Err(ManifestError::EmptyExtent {
            file: extent.file.0,
            offset_bytes: extent.logical_offset_bytes,
        });
    }
    let end_bytes = extent.end_bytes().ok_or(ManifestError::Overflow {
        field: "extent range",
    })?;
    match extent.encoding {
        ExtentEncoding::Raw => {
            if extent.true_length_bytes > bounds.max_extent_bytes {
                return Err(ManifestError::BoundExceeded {
                    bound: "max_extent_bytes",
                    found: extent.true_length_bytes,
                    max: bounds.max_extent_bytes,
                });
            }
        }
        ExtentEncoding::Encoded(encoded) => {
            if extent.true_length_bytes > bounds.max_extent_bytes {
                return Err(ManifestError::DecompressionBound {
                    declared_bytes: extent.true_length_bytes,
                    max_bytes: bounds.max_extent_bytes,
                });
            }
            let block_bytes = match group.codec_block_bytes {
                Some(block_bytes) if extent.true_length_bytes <= block_bytes => block_bytes,
                _ => return Err(ManifestError::CodecBlockMismatch),
            };
            check_codec_format(&encoded, block_bytes)?;
            let file = encoded.location.file;
            let prepared = group
                .prepared_files
                .get(file.index())
                .ok_or(ManifestError::MissingPreparedFile { file: file.0 })?;
            let encoded_end = encoded
                .location
                .offset_bytes
                .checked_add(encoded.location.length_bytes)
                .ok_or(ManifestError::Overflow {
                    field: "encoded range",
                })?;
            if encoded.location.length_bytes == 0 || encoded_end > prepared.length_bytes {
                return Err(ManifestError::EncodedOutOfBounds { file: file.0 });
            }
            encoded_ranges
                .entry(file.0)
                .or_default()
                .push((encoded.location.offset_bytes, encoded_end));
        }
    }
    Ok(end_bytes)
}

/// The parameters of an encoded extent's codec format, before any decoder sees them: a
/// window bound a block of `codec_block_bytes` can use, and a dictionary id only with a
/// dictionary.
fn check_codec_format(
    encoded: &EncodedRepresentation,
    codec_block_bytes: u64,
) -> Result<(), ManifestError> {
    match encoded.format {
        CodecFormat::ZstdRfc8878(frame) => {
            let max_bytes = zstd_window_ceiling_bytes(codec_block_bytes);
            if frame.max_window_bytes == 0 || frame.max_window_bytes > max_bytes {
                return Err(ManifestError::InvalidWindowBound {
                    declared_bytes: frame.max_window_bytes,
                    max_bytes,
                });
            }
            if frame.dictionary_id != 0 && encoded.dictionary.is_none() {
                return Err(ManifestError::UndeclaredDictionary {
                    dictionary_id: frame.dictionary_id,
                });
            }
        }
    }
    Ok(())
}

fn check_file_covered(
    files: &[SourceFile],
    file: u32,
    covered_bytes: u64,
) -> Result<(), ManifestError> {
    let length_bytes = files
        .get(file as usize)
        .map_or(0, |source| source.length_bytes);
    if covered_bytes != length_bytes {
        return Err(ManifestError::ExtentCoverage {
            file,
            covered_bytes,
            length_bytes,
        });
    }
    Ok(())
}

fn check_extents(manifest: &Manifest, bounds: &ManifestBounds) -> Result<(), ManifestError> {
    let group = &manifest.extents;
    let files = &manifest.provenance.files;
    if group.integrity_extent_bytes == 0 || group.integrity_extent_bytes > bounds.max_extent_bytes {
        return Err(ManifestError::InvalidGranularity);
    }
    let any_encoded = group
        .extents
        .iter()
        .any(|extent| matches!(extent.encoding, ExtentEncoding::Encoded(_)));
    match group.codec_block_bytes {
        None if any_encoded => return Err(ManifestError::CodecBlockMismatch),
        Some(_) if !any_encoded => return Err(ManifestError::CodecBlockMismatch),
        Some(block_bytes) if block_bytes == 0 || block_bytes > bounds.max_extent_bytes => {
            return Err(ManifestError::InvalidGranularity)
        }
        _ => {}
    }
    check_order(
        group.prepared_files.iter().map(|file| &file.path),
        "prepared files",
        |path| ManifestError::DuplicateFile {
            path: (*path).clone(),
        },
    )?;
    check_count(group.extents.len(), bounds.max_extents, "max_extents")?;

    let mut encoded_ranges: BTreeMap<u32, Vec<(u64, u64)>> = BTreeMap::new();
    let mut current: Option<(u32, u64)> = None;
    for extent in &group.extents {
        let file = extent.file.0;
        if files.get(extent.file.index()).is_none() {
            return Err(ManifestError::MissingFile { file });
        }
        let end_bytes = check_extent_bounds(extent, manifest, bounds, &mut encoded_ranges)?;
        match current {
            Some((previous, _)) if file < previous => {
                return Err(ManifestError::NotCanonical {
                    collection: "extents",
                })
            }
            Some((previous, next_offset)) if file == previous => {
                if extent.logical_offset_bytes < next_offset {
                    return Err(ManifestError::OverlappingRanges {
                        ranges: "extents",
                        file,
                        offset_bytes: extent.logical_offset_bytes,
                    });
                }
                if extent.logical_offset_bytes > next_offset {
                    return Err(ManifestError::ExtentGap {
                        file,
                        offset_bytes: next_offset,
                    });
                }
            }
            _ => {
                let first_unchecked = match current {
                    Some((previous, covered_bytes)) => {
                        check_file_covered(files, previous, covered_bytes)?;
                        previous + 1
                    }
                    None => 0,
                };
                for skipped in first_unchecked..file {
                    check_file_covered(files, skipped, 0)?;
                }
                if extent.logical_offset_bytes != 0 {
                    return Err(ManifestError::ExtentGap {
                        file,
                        offset_bytes: 0,
                    });
                }
            }
        }
        current = Some((file, end_bytes));
    }
    let first_unchecked = match current {
        Some((previous, covered_bytes)) => {
            check_file_covered(files, previous, covered_bytes)?;
            previous + 1
        }
        None => 0,
    };
    for remaining in first_unchecked..files.len() as u32 {
        check_file_covered(files, remaining, 0)?;
    }

    for (index, prepared) in group.prepared_files.iter().enumerate() {
        let file = index as u32;
        let mut ranges = encoded_ranges.remove(&file).unwrap_or_default();
        ranges.sort_unstable();
        let mut covered_bytes = 0u64;
        for (start, end) in ranges {
            if start < covered_bytes {
                return Err(ManifestError::OverlappingRanges {
                    ranges: "encoded extents",
                    file,
                    offset_bytes: start,
                });
            }
            if start > covered_bytes {
                return Err(ManifestError::PreparedCoverage { file });
            }
            covered_bytes = end;
        }
        if covered_bytes != prepared.length_bytes {
            return Err(ManifestError::PreparedCoverage { file });
        }
    }
    Ok(())
}

fn check_integrity(manifest: &Manifest) -> Result<(), ManifestError> {
    let files = &manifest.provenance.files;
    let extents = &manifest.extents.extents;
    let integrity = &manifest.integrity;
    if integrity.extent_roots.len() != files.len() {
        return Err(ManifestError::DerivedMismatch {
            field: "extent roots",
        });
    }
    let computed = derive::extent_roots(files.len(), extents);
    if let Some(file) = integrity
        .extent_roots
        .iter()
        .zip(&computed)
        .position(|(declared, computed)| declared != computed)
    {
        return Err(ManifestError::TreeRootMismatch { file: file as u32 });
    }
    if integrity.decoded_content_identity != derive::decoded_content_identity(files, extents) {
        return Err(ManifestError::DerivedMismatch {
            field: "decoded content identity",
        });
    }
    Ok(())
}

fn check_lifecycle(manifest: &Manifest) -> Result<(), ManifestError> {
    let lifecycle = &manifest.lifecycle;
    let roots = &lifecycle.dependency_roots;
    check_count(roots.len(), MAX_LIST_ENTRIES, "dependency roots")?;
    check_order(roots.iter(), "dependency roots", |root| {
        ManifestError::DuplicateName {
            name: format!("{root:?}"),
        }
    })?;
    for required in derive::required_roots(&manifest.semantics.adapters, &manifest.extents.extents)
    {
        if roots.binary_search(&required).is_err() {
            return Err(ManifestError::MissingDependencyRoot { root: required });
        }
    }
    let storage = derive::storage(&manifest.provenance.files, &manifest.extents.prepared_files)
        .ok_or(ManifestError::Overflow { field: "storage" })?;
    if storage != lifecycle.storage {
        return Err(ManifestError::DerivedMismatch {
            field: "storage accounting",
        });
    }
    if derive::migration(&manifest.extents.prepared_files) != lifecycle.migration {
        return Err(ManifestError::DerivedMismatch {
            field: "migration requirement",
        });
    }
    Ok(())
}
