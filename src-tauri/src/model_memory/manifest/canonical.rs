//! The canonical encoding (GPU part §3.3: "Use domain-separated hashes and canonical
//! encodings"; schema group: magic, versions, byte order and bounds).
//!
//! Layout: [`MANIFEST_MAGIC`], the schema group, then the other nine groups in the order
//! of the §3.3 table. Integers are big-endian; strings and lists carry a u64 length; enums
//! are one tag byte; optional values carry a 0/1 byte. Validation fixes the order of every
//! collection, so one manifest has exactly one encoding. The sidecar is the body followed
//! by its 32-byte manifest digest.
//!
//! The schema group ends with the codec table: every distinct codec format of the encoded
//! extents in ascending order, each a codec code, a version number and that version's
//! frame parameters (GPU-W08). An encoded extent names its format by table index; a raw
//! extent has none. The table precedes every other group, so an unknown codec or codec
//! version is refused before anything is allocated.
//!
//! The decoder checks every length and count against the declared bounds and the bytes
//! remaining before it reads, and never preallocates from an untrusted count. A schema
//! version older than this build's is refused with [`ManifestError::NeedsReimport`] right
//! after the magic, before anything else is read.

use std::collections::BTreeSet;

use crate::foundation::evidence::{Backend, BackendRelease, BackendVersion, MAX_VERSION_LEN};
use crate::foundation::ids::Digest;

use super::codec::{Codec, CodecFormat, CodecVersion, ZstdFrameParameters};
use super::digests::{ContentKey, DictionaryId, EncodedDigest, ManifestDigest};
use super::groups::{
    ByteOrder, ComputeCapability, ConverterIdentity, DependencyRoot, Distribution, EncodedLocation,
    EncodedRepresentation, ExecutionAbi, Extent, ExtentEncoding, ExtentGroup, FileFormat, FileRole,
    HardwareRestriction, IntegrityGroup, Lifecycle, Manifest, ManifestBounds, MigrationRequirement,
    PreparedFile, PreparedFileId, Provenance, Quantization, RematerializedBuffer, SchemaGroup,
    Semantics, SourceFile, SourceFileId, SourceOrigin, SourceRevision, StateGroup,
    StorageAccounting, TensorAlias, TensorEntry, TensorIndex, TensorOwner, VersionedName,
    WeightFormat, CANONICAL_ENCODING_VERSION, FIRST_MANIFEST_SCHEMA_VERSION, MANIFEST_MAGIC,
    MANIFEST_SCHEMA_VERSION, MAX_LIST_ENTRIES,
};
use super::types::{
    ElementType, GgmlType, GitCommit, RelativePath, TensorDtype, TensorLayout, TensorName, Token,
    MAX_PATH_BYTES, MAX_TOKEN_BYTES,
};
use super::validate::ManifestError;

/// Bytes of the manifest digest that ends every sidecar.
pub const SIDECAR_DIGEST_BYTES: usize = 32;

/// The backends a manifest may name, by their stable tags.
const BACKENDS: [Backend; 3] = [Backend::Vllm, Backend::LlamaCpp, Backend::Transformers];

#[derive(Default)]
struct Writer {
    out: Vec<u8>,
}

impl Writer {
    fn raw(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
    }

    fn u8(&mut self, value: u8) {
        self.out.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.raw(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.raw(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.raw(&value.to_be_bytes());
    }

    fn len(&mut self, len: usize) {
        self.u64(len as u64);
    }

    fn str(&mut self, value: &str) {
        self.len(value.len());
        self.raw(value.as_bytes());
    }

    fn digest(&mut self, value: &Digest) {
        self.raw(value.as_bytes());
    }

    fn option_u32(&mut self, value: Option<u32>) {
        match value {
            None => self.u8(0),
            Some(value) => {
                self.u8(1);
                self.u32(value);
            }
        }
    }

    fn option_u64(&mut self, value: Option<u64>) {
        match value {
            None => self.u8(0),
            Some(value) => {
                self.u8(1);
                self.u64(value);
            }
        }
    }

    fn option_digest(&mut self, value: Option<Digest>) {
        match value {
            None => self.u8(0),
            Some(value) => {
                self.u8(1);
                self.digest(&value);
            }
        }
    }
}

/// The distinct codec formats of a group's encoded extents in ascending order: the codec
/// table of the canonical encoding.
pub(super) fn codec_formats(group: &ExtentGroup) -> Vec<CodecFormat> {
    group
        .extents
        .iter()
        .filter_map(|extent| match extent.encoding {
            ExtentEncoding::Raw => None,
            ExtentEncoding::Encoded(encoded) => Some(encoded.format),
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// The canonical body of `manifest`, without the trailing digest.
pub(super) fn encode_body(manifest: &Manifest) -> Vec<u8> {
    let formats = codec_formats(&manifest.extents);
    let mut writer = Writer::default();
    writer.raw(&MANIFEST_MAGIC);
    write_schema(&mut writer, &manifest.schema);
    write_codec_formats(&mut writer, &formats);
    write_provenance(&mut writer, &manifest.provenance);
    write_semantics(&mut writer, &manifest.semantics);
    write_execution_abi(&mut writer, &manifest.execution_abi);
    write_distribution(&mut writer, &manifest.distribution);
    write_tensor_index(&mut writer, &manifest.tensor_index);
    write_state(&mut writer, &manifest.state);
    write_extents(&mut writer, &manifest.extents, &formats);
    write_integrity(&mut writer, &manifest.integrity);
    write_lifecycle(&mut writer, &manifest.lifecycle);
    writer.out
}

fn write_schema(w: &mut Writer, schema: &SchemaGroup) {
    w.u16(schema.schema_version);
    w.u16(schema.encoding_version);
    w.u8(match schema.byte_order {
        ByteOrder::BigEndian => 1,
    });
    let bounds = &schema.bounds;
    w.u32(bounds.max_files);
    w.u32(bounds.max_tensors);
    w.u32(bounds.max_extents);
    w.u32(bounds.max_name_bytes);
    w.u32(bounds.max_dimensions);
    w.u32(bounds.max_ranks);
    w.u64(bounds.max_extent_bytes);
    w.u64(bounds.max_total_bytes);
}

fn write_codec_formats(w: &mut Writer, formats: &[CodecFormat]) {
    w.len(formats.len());
    for format in formats {
        w.u8(format.codec().code());
        w.u16(format.version().number());
        match format {
            CodecFormat::ZstdRfc8878(frame) => {
                w.u32(frame.dictionary_id);
                w.u8(frame.content_checksum.into());
                w.u64(frame.max_window_bytes);
            }
        }
    }
}

/// The table index of `format`; the table holds the format of every encoded extent.
fn format_index(formats: &[CodecFormat], format: &CodecFormat) -> u32 {
    match formats.binary_search(format) {
        Ok(index) | Err(index) => u32::try_from(index).unwrap_or(u32::MAX),
    }
}

fn weight_format_code(format: WeightFormat) -> u8 {
    match format {
        WeightFormat::Safetensors => 1,
        WeightFormat::Gguf => 2,
    }
}

fn write_provenance(w: &mut Writer, provenance: &Provenance) {
    match &provenance.origin {
        SourceOrigin::HuggingFace { repository } => {
            w.u8(1);
            w.str(repository.as_str());
        }
        SourceOrigin::Registry { model } => {
            w.u8(2);
            w.str(model.as_str());
        }
        SourceOrigin::LocalFolder => w.u8(3),
        SourceOrigin::Publisher { publisher } => {
            w.u8(4);
            w.str(publisher.as_str());
        }
    }
    match provenance.revision {
        SourceRevision::GitCommit(commit) => {
            w.u8(1);
            w.raw(commit.as_bytes());
        }
        SourceRevision::ContentListing(listing) => {
            w.u8(2);
            w.digest(&listing);
        }
    }
    w.len(provenance.files.len());
    for file in &provenance.files {
        w.str(file.path.as_str());
        w.u64(file.length_bytes);
        w.digest(file.content.digest());
        match file.role {
            FileRole::Weights { format, rank } => {
                w.u8(1);
                w.u8(weight_format_code(format));
                w.option_u32(rank);
            }
            FileRole::Configuration => w.u8(2),
            FileRole::Tokenizer => w.u8(3),
            FileRole::Other => w.u8(4),
        }
        match file.format {
            FileFormat::Safetensors {
                header_length_bytes,
            } => {
                w.u8(1);
                w.u64(header_length_bytes);
            }
            FileFormat::Gguf {
                version,
                alignment_bytes,
                data_offset_bytes,
                metadata_digest,
            } => {
                w.u8(2);
                w.u32(version);
                w.u64(alignment_bytes);
                w.u64(data_offset_bytes);
                w.digest(&metadata_digest);
            }
            FileFormat::Opaque => w.u8(3),
        }
    }
    w.str(provenance.converter.name.as_str());
    w.str(provenance.converter.version.as_str());
}

fn write_semantics(w: &mut Writer, semantics: &Semantics) {
    w.digest(&semantics.configuration_digest);
    w.digest(&semantics.tokenizer_digest);
    w.u8(semantics.compute_dtype.code());
    match &semantics.quantization {
        Quantization::None => w.u8(1),
        Quantization::Method { method, parameters } => {
            w.u8(2);
            w.str(method.as_str());
            w.len(parameters.len());
            for (key, value) in parameters {
                w.str(key.as_str());
                w.str(value.as_str());
            }
        }
    }
    w.len(semantics.adapters.len());
    for adapter in &semantics.adapters {
        w.digest(adapter);
    }
}

fn write_versioned(w: &mut Writer, versioned: &VersionedName) {
    w.str(versioned.name.as_str());
    w.str(versioned.version.as_str());
}

fn write_execution_abi(w: &mut Writer, abi: &ExecutionAbi) {
    w.str(abi.runner.backend.tag());
    w.str(abi.runner.version.as_str());
    write_versioned(w, &abi.architecture_adapter);
    w.str(abi.layout.as_str());
    w.len(abi.kernels.len());
    for kernel in &abi.kernels {
        w.str(kernel.as_str());
    }
    match &abi.hardware {
        HardwareRestriction::Unrestricted => w.u8(1),
        HardwareRestriction::ComputeCapabilities(capabilities) => {
            w.u8(2);
            w.len(capabilities.len());
            for capability in capabilities {
                w.u8(capability.major);
                w.u8(capability.minor);
            }
        }
    }
}

fn write_distribution(w: &mut Writer, distribution: &Distribution) {
    w.u32(distribution.tensor_parallel_size);
    w.u32(distribution.pipeline_parallel_size);
    w.u32(distribution.expert_parallel_size);
    w.u32(distribution.expert_count);
}

fn write_dtype(w: &mut Writer, dtype: TensorDtype) {
    match dtype {
        TensorDtype::Element(element) => {
            w.u8(1);
            w.u8(element.code());
        }
        TensorDtype::Ggml(ggml) => {
            w.u8(2);
            w.u32(ggml.id());
        }
    }
}

fn write_shape(w: &mut Writer, shape: &[u64]) {
    w.len(shape.len());
    for dimension in shape {
        w.u64(*dimension);
    }
}

fn write_tensor_index(w: &mut Writer, index: &TensorIndex) {
    w.len(index.tensors.len());
    for tensor in &index.tensors {
        w.str(tensor.name.as_str());
        w.u32(tensor.file.0);
        w.u64(tensor.offset_bytes);
        w.u64(tensor.true_length_bytes);
        write_dtype(w, tensor.dtype);
        write_shape(w, &tensor.shape);
        w.u8(match tensor.layout {
            TensorLayout::RowMajor => 1,
            TensorLayout::GgmlInnermostFirst => 2,
        });
        match tensor.owner {
            TensorOwner::Replicated => w.u8(1),
            TensorOwner::Rank(rank) => {
                w.u8(2);
                w.u32(rank);
            }
            TensorOwner::Expert { expert, rank } => {
                w.u8(3);
                w.u32(expert);
                w.u32(rank);
            }
        }
    }
    w.len(index.aliases.len());
    for alias in &index.aliases {
        w.str(alias.name.as_str());
        w.str(alias.target.as_str());
    }
}

fn write_state(w: &mut Writer, state: &StateGroup) {
    w.len(state.persistent_buffers.len());
    for name in &state.persistent_buffers {
        w.str(name.as_str());
    }
    w.len(state.rematerialized_buffers.len());
    for buffer in &state.rematerialized_buffers {
        w.str(buffer.name.as_str());
        write_dtype(w, buffer.dtype);
        write_shape(w, &buffer.shape);
        write_versioned(w, &buffer.reconstruction);
    }
}

fn write_extents(w: &mut Writer, group: &ExtentGroup, formats: &[CodecFormat]) {
    w.u64(group.integrity_extent_bytes);
    w.option_u64(group.codec_block_bytes);
    w.len(group.prepared_files.len());
    for file in &group.prepared_files {
        w.str(file.path.as_str());
        w.u64(file.length_bytes);
    }
    w.len(group.extents.len());
    for extent in &group.extents {
        w.u32(extent.file.0);
        w.u64(extent.logical_offset_bytes);
        w.u64(extent.true_length_bytes);
        w.digest(extent.content_key.digest());
        match extent.encoding {
            ExtentEncoding::Raw => w.u8(1),
            ExtentEncoding::Encoded(encoded) => {
                w.u8(2);
                w.u32(format_index(formats, &encoded.format));
                w.option_digest(encoded.dictionary.map(|dictionary| dictionary.digest()));
                w.u32(encoded.location.file.0);
                w.u64(encoded.location.offset_bytes);
                w.u64(encoded.location.length_bytes);
                w.digest(&encoded.digest.digest());
            }
        }
    }
}

fn write_integrity(w: &mut Writer, integrity: &IntegrityGroup) {
    w.len(integrity.extent_roots.len());
    for root in &integrity.extent_roots {
        w.digest(root);
    }
    w.digest(&integrity.decoded_content_identity);
}

fn write_lifecycle(w: &mut Writer, lifecycle: &Lifecycle) {
    w.len(lifecycle.dependency_roots.len());
    for root in &lifecycle.dependency_roots {
        match root {
            DependencyRoot::Artifact(manifest) => {
                w.u8(1);
                w.digest(&manifest.digest());
            }
            DependencyRoot::Adapter(adapter) => {
                w.u8(2);
                w.digest(adapter);
            }
            DependencyRoot::Dictionary(dictionary) => {
                w.u8(3);
                w.digest(&dictionary.digest());
            }
        }
    }
    w.u64(lifecycle.storage.referenced_source_bytes);
    w.u64(lifecycle.storage.owned_representation_bytes);
    w.u8(match lifecycle.migration {
        MigrationRequirement::ReindexFromSources => 1,
        MigrationRequirement::RebuildPreparedFromSources => 2,
    });
}

/// Splits a sidecar into its body and the manifest digest that ends it.
pub(super) fn split_sidecar(sidecar: &[u8]) -> Result<(&[u8], Digest), ManifestError> {
    let body_bytes = sidecar
        .len()
        .checked_sub(SIDECAR_DIGEST_BYTES)
        .ok_or(ManifestError::Truncated)?;
    let (body, trailer) = sidecar
        .split_at_checked(body_bytes)
        .ok_or(ManifestError::Truncated)?;
    let trailer =
        <[u8; SIDECAR_DIGEST_BYTES]>::try_from(trailer).map_err(|_| ManifestError::Truncated)?;
    Ok((body, Digest::from_bytes(trailer)))
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], ManifestError> {
        let (head, tail) = self
            .rest
            .split_at_checked(len)
            .ok_or(ManifestError::Truncated)?;
        self.rest = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ManifestError> {
        <[u8; N]>::try_from(self.take(N)?).map_err(|_| ManifestError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, ManifestError> {
        let [byte] = self.array::<1>()?;
        Ok(byte)
    }

    fn u16(&mut self) -> Result<u16, ManifestError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ManifestError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ManifestError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn digest(&mut self) -> Result<Digest, ManifestError> {
        Ok(Digest::from_bytes(self.array()?))
    }

    /// A u64 length or count, refused above `max` before anything is read or allocated.
    fn len(&mut self, max: u64, bound: &'static str) -> Result<usize, ManifestError> {
        let found = self.u64()?;
        if found > max {
            return Err(ManifestError::BoundExceeded { bound, found, max });
        }
        usize::try_from(found).map_err(|_| ManifestError::Overflow { field: bound })
    }

    fn string(&mut self, max_bytes: u64, field: &'static str) -> Result<String, ManifestError> {
        let len = self.len(max_bytes, field)?;
        let bytes = self.take(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| ManifestError::InvalidUtf8 { field })
    }

    fn token(&mut self, field: &'static str) -> Result<Token, ManifestError> {
        Token::new(self.string(MAX_TOKEN_BYTES as u64, field)?)
            .map_err(|error| ManifestError::InvalidName { field, error })
    }

    fn path(&mut self, field: &'static str) -> Result<RelativePath, ManifestError> {
        RelativePath::new(self.string(MAX_PATH_BYTES as u64, field)?)
            .map_err(|error| ManifestError::InvalidName { field, error })
    }

    fn tensor_name(
        &mut self,
        bounds: &ManifestBounds,
        field: &'static str,
    ) -> Result<TensorName, ManifestError> {
        TensorName::new(self.string(bounds.max_name_bytes.into(), field)?)
            .map_err(|error| ManifestError::InvalidName { field, error })
    }

    fn present(&mut self, field: &'static str) -> Result<bool, ManifestError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            tag => Err(ManifestError::UnknownTag { field, tag }),
        }
    }

    fn option_u32(&mut self, field: &'static str) -> Result<Option<u32>, ManifestError> {
        Ok(if self.present(field)? {
            Some(self.u32()?)
        } else {
            None
        })
    }

    fn option_u64(&mut self, field: &'static str) -> Result<Option<u64>, ManifestError> {
        Ok(if self.present(field)? {
            Some(self.u64()?)
        } else {
            None
        })
    }

    fn option_digest(&mut self, field: &'static str) -> Result<Option<Digest>, ManifestError> {
        Ok(if self.present(field)? {
            Some(self.digest()?)
        } else {
            None
        })
    }
}

/// Decodes a canonical body. `ceiling` caps the bounds the body may declare; the declared
/// bounds then cap every count and length that follows.
pub(super) fn decode_body(
    body: &[u8],
    ceiling: &ManifestBounds,
) -> Result<Manifest, ManifestError> {
    let mut r = Reader { rest: body };
    if r.take(MANIFEST_MAGIC.len())? != MANIFEST_MAGIC {
        return Err(ManifestError::BadMagic);
    }
    let schema = read_schema(&mut r, ceiling)?;
    let bounds = schema.bounds;
    let formats = read_codec_formats(&mut r, &bounds)?;
    let provenance = read_provenance(&mut r, &bounds)?;
    let semantics = read_semantics(&mut r)?;
    let execution_abi = read_execution_abi(&mut r)?;
    let distribution = Distribution {
        tensor_parallel_size: r.u32()?,
        pipeline_parallel_size: r.u32()?,
        expert_parallel_size: r.u32()?,
        expert_count: r.u32()?,
    };
    let tensor_index = read_tensor_index(&mut r, &bounds)?;
    let state = read_state(&mut r, &bounds)?;
    let extents = read_extents(&mut r, &bounds, &formats)?;
    let integrity = read_integrity(&mut r, &bounds)?;
    let lifecycle = read_lifecycle(&mut r)?;
    if !r.rest.is_empty() {
        return Err(ManifestError::TrailingBytes);
    }
    Ok(Manifest {
        schema,
        provenance,
        semantics,
        execution_abi,
        distribution,
        tensor_index,
        state,
        extents,
        integrity,
        lifecycle,
    })
}

/// Refuses any schema version but this build's: an earlier one needs a re-import, any
/// other is unknown.
pub(super) fn check_schema_version(schema_version: u16) -> Result<(), ManifestError> {
    if schema_version == MANIFEST_SCHEMA_VERSION {
        Ok(())
    } else if (FIRST_MANIFEST_SCHEMA_VERSION..MANIFEST_SCHEMA_VERSION).contains(&schema_version) {
        Err(ManifestError::NeedsReimport { schema_version })
    } else {
        Err(ManifestError::UnsupportedSchemaVersion {
            found: schema_version,
        })
    }
}

fn read_schema(r: &mut Reader<'_>, ceiling: &ManifestBounds) -> Result<SchemaGroup, ManifestError> {
    let schema_version = r.u16()?;
    check_schema_version(schema_version)?;
    let encoding_version = r.u16()?;
    if encoding_version != CANONICAL_ENCODING_VERSION {
        return Err(ManifestError::UnsupportedEncodingVersion {
            found: encoding_version,
        });
    }
    let byte_order = match r.u8()? {
        1 => ByteOrder::BigEndian,
        code => return Err(ManifestError::UnsupportedByteOrder { code }),
    };
    let bounds = ManifestBounds {
        max_files: r.u32()?,
        max_tensors: r.u32()?,
        max_extents: r.u32()?,
        max_name_bytes: r.u32()?,
        max_dimensions: r.u32()?,
        max_ranks: r.u32()?,
        max_extent_bytes: r.u64()?,
        max_total_bytes: r.u64()?,
    };
    bounds.check_within(ceiling)?;
    Ok(SchemaGroup {
        schema_version,
        encoding_version,
        byte_order,
        bounds,
    })
}

/// One codec table entry. Nothing is allocated: an unknown codec or version is refused as
/// soon as its code is read, never guessed.
fn read_codec_format(r: &mut Reader<'_>) -> Result<CodecFormat, ManifestError> {
    let code = r.u8()?;
    let codec = Codec::from_code(code).ok_or(ManifestError::UnknownCodec { code })?;
    let number = r.u16()?;
    let version =
        CodecVersion::from_number(codec, number).ok_or(ManifestError::UnknownCodecVersion {
            codec,
            version: number,
        })?;
    Ok(match version {
        CodecVersion::ZstdRfc8878 => CodecFormat::ZstdRfc8878(ZstdFrameParameters {
            dictionary_id: r.u32()?,
            content_checksum: r.present("content checksum flag")?,
            max_window_bytes: r.u64()?,
        }),
    })
}

/// The codec table. Every entry is read and checked once before the table is allocated,
/// so an unknown codec or version anywhere in it is refused first; the entries must be
/// strictly ascending.
fn read_codec_formats(
    r: &mut Reader<'_>,
    bounds: &ManifestBounds,
) -> Result<Vec<CodecFormat>, ManifestError> {
    let count = r.len(bounds.max_extents.into(), "max_extents")?;
    let mut probe = Reader { rest: r.rest };
    let mut previous: Option<CodecFormat> = None;
    for _ in 0..count {
        let format = read_codec_format(&mut probe)?;
        if previous.is_some_and(|previous| previous >= format) {
            return Err(ManifestError::NotCanonical {
                collection: "codec formats",
            });
        }
        previous = Some(format);
    }
    let mut formats = Vec::new();
    for _ in 0..count {
        formats.push(read_codec_format(r)?);
    }
    Ok(formats)
}

fn read_provenance(
    r: &mut Reader<'_>,
    bounds: &ManifestBounds,
) -> Result<Provenance, ManifestError> {
    let origin = match r.u8()? {
        1 => SourceOrigin::HuggingFace {
            repository: r.token("repository")?,
        },
        2 => SourceOrigin::Registry {
            model: r.token("registry model")?,
        },
        3 => SourceOrigin::LocalFolder,
        4 => SourceOrigin::Publisher {
            publisher: r.token("publisher")?,
        },
        tag => {
            return Err(ManifestError::UnknownTag {
                field: "origin",
                tag,
            })
        }
    };
    let revision = match r.u8()? {
        1 => SourceRevision::GitCommit(GitCommit::from_bytes(r.array()?)),
        2 => SourceRevision::ContentListing(r.digest()?),
        tag => {
            return Err(ManifestError::UnknownTag {
                field: "revision",
                tag,
            })
        }
    };
    let count = r.len(bounds.max_files.into(), "max_files")?;
    let mut files = Vec::new();
    for _ in 0..count {
        let path = r.path("source file path")?;
        let length_bytes = r.u64()?;
        let content = ContentKey::from_digest(r.digest()?);
        let role = match r.u8()? {
            1 => {
                let format = match r.u8()? {
                    1 => WeightFormat::Safetensors,
                    2 => WeightFormat::Gguf,
                    tag => {
                        return Err(ManifestError::UnknownTag {
                            field: "weight format",
                            tag,
                        })
                    }
                };
                FileRole::Weights {
                    format,
                    rank: r.option_u32("file rank")?,
                }
            }
            2 => FileRole::Configuration,
            3 => FileRole::Tokenizer,
            4 => FileRole::Other,
            tag => {
                return Err(ManifestError::UnknownTag {
                    field: "file role",
                    tag,
                })
            }
        };
        let format = match r.u8()? {
            1 => FileFormat::Safetensors {
                header_length_bytes: r.u64()?,
            },
            2 => FileFormat::Gguf {
                version: r.u32()?,
                alignment_bytes: r.u64()?,
                data_offset_bytes: r.u64()?,
                metadata_digest: r.digest()?,
            },
            3 => FileFormat::Opaque,
            tag => {
                return Err(ManifestError::UnknownTag {
                    field: "file format",
                    tag,
                })
            }
        };
        files.push(SourceFile {
            path,
            length_bytes,
            content,
            role,
            format,
        });
    }
    let converter = ConverterIdentity {
        name: r.token("converter name")?,
        version: r.token("converter version")?,
    };
    Ok(Provenance {
        origin,
        revision,
        files,
        converter,
    })
}

fn read_element(r: &mut Reader<'_>, field: &'static str) -> Result<ElementType, ManifestError> {
    let code = r.u8()?;
    ElementType::from_code(code).ok_or(ManifestError::UnknownTag { field, tag: code })
}

fn read_semantics(r: &mut Reader<'_>) -> Result<Semantics, ManifestError> {
    let configuration_digest = r.digest()?;
    let tokenizer_digest = r.digest()?;
    let compute_dtype = read_element(r, "compute dtype")?;
    let quantization = match r.u8()? {
        1 => Quantization::None,
        2 => {
            let method = r.token("quantization method")?;
            let count = r.len(MAX_LIST_ENTRIES.into(), "quantization parameters")?;
            let mut parameters = Vec::new();
            for _ in 0..count {
                parameters.push((
                    r.token("quantization parameter")?,
                    r.token("quantization value")?,
                ));
            }
            Quantization::Method { method, parameters }
        }
        tag => {
            return Err(ManifestError::UnknownTag {
                field: "quantization",
                tag,
            })
        }
    };
    let count = r.len(MAX_LIST_ENTRIES.into(), "adapters")?;
    let mut adapters = Vec::new();
    for _ in 0..count {
        adapters.push(r.digest()?);
    }
    Ok(Semantics {
        configuration_digest,
        tokenizer_digest,
        compute_dtype,
        quantization,
        adapters,
    })
}

fn read_versioned(
    r: &mut Reader<'_>,
    name_field: &'static str,
    version_field: &'static str,
) -> Result<VersionedName, ManifestError> {
    Ok(VersionedName {
        name: r.token(name_field)?,
        version: r.token(version_field)?,
    })
}

fn read_execution_abi(r: &mut Reader<'_>) -> Result<ExecutionAbi, ManifestError> {
    let tag = r.string(MAX_TOKEN_BYTES as u64, "runner")?;
    let backend = BACKENDS
        .into_iter()
        .find(|backend| backend.tag() == tag)
        .ok_or(ManifestError::UnknownRunner)?;
    let version = BackendVersion::new(r.string(MAX_VERSION_LEN as u64, "runner version")?)
        .map_err(|_| ManifestError::InvalidRunnerVersion)?;
    let architecture_adapter = read_versioned(r, "architecture adapter", "adapter version")?;
    let layout = r.token("layout")?;
    let count = r.len(MAX_LIST_ENTRIES.into(), "kernels")?;
    let mut kernels = Vec::new();
    for _ in 0..count {
        kernels.push(r.token("kernel")?);
    }
    let hardware = match r.u8()? {
        1 => HardwareRestriction::Unrestricted,
        2 => {
            let count = r.len(MAX_LIST_ENTRIES.into(), "compute capabilities")?;
            let mut capabilities = Vec::new();
            for _ in 0..count {
                capabilities.push(ComputeCapability {
                    major: r.u8()?,
                    minor: r.u8()?,
                });
            }
            HardwareRestriction::ComputeCapabilities(capabilities)
        }
        tag => {
            return Err(ManifestError::UnknownTag {
                field: "hardware restriction",
                tag,
            })
        }
    };
    Ok(ExecutionAbi {
        runner: BackendRelease { backend, version },
        architecture_adapter,
        layout,
        kernels,
        hardware,
    })
}

fn read_dtype(r: &mut Reader<'_>) -> Result<TensorDtype, ManifestError> {
    match r.u8()? {
        1 => Ok(TensorDtype::Element(read_element(r, "element type")?)),
        2 => {
            let id = r.u32()?;
            GgmlType::from_id(id)
                .map(TensorDtype::Ggml)
                .ok_or(ManifestError::UnknownGgmlType { id })
        }
        tag => Err(ManifestError::UnknownTag {
            field: "dtype",
            tag,
        }),
    }
}

fn read_shape(r: &mut Reader<'_>, bounds: &ManifestBounds) -> Result<Vec<u64>, ManifestError> {
    let count = r.len(bounds.max_dimensions.into(), "max_dimensions")?;
    let mut shape = Vec::new();
    for _ in 0..count {
        shape.push(r.u64()?);
    }
    Ok(shape)
}

fn read_tensor_index(
    r: &mut Reader<'_>,
    bounds: &ManifestBounds,
) -> Result<TensorIndex, ManifestError> {
    let count = r.len(bounds.max_tensors.into(), "max_tensors")?;
    let mut tensors = Vec::new();
    for _ in 0..count {
        let name = r.tensor_name(bounds, "tensor name")?;
        let file = SourceFileId(r.u32()?);
        let offset_bytes = r.u64()?;
        let true_length_bytes = r.u64()?;
        let dtype = read_dtype(r)?;
        let shape = read_shape(r, bounds)?;
        let layout = match r.u8()? {
            1 => TensorLayout::RowMajor,
            2 => TensorLayout::GgmlInnermostFirst,
            tag => {
                return Err(ManifestError::UnknownTag {
                    field: "layout",
                    tag,
                })
            }
        };
        let owner = match r.u8()? {
            1 => TensorOwner::Replicated,
            2 => TensorOwner::Rank(r.u32()?),
            3 => TensorOwner::Expert {
                expert: r.u32()?,
                rank: r.u32()?,
            },
            tag => {
                return Err(ManifestError::UnknownTag {
                    field: "owner",
                    tag,
                })
            }
        };
        tensors.push(TensorEntry {
            name,
            file,
            offset_bytes,
            true_length_bytes,
            dtype,
            shape,
            layout,
            owner,
        });
    }
    let count = r.len(bounds.max_tensors.into(), "aliases")?;
    let mut aliases = Vec::new();
    for _ in 0..count {
        aliases.push(TensorAlias {
            name: r.tensor_name(bounds, "alias name")?,
            target: r.tensor_name(bounds, "alias target")?,
        });
    }
    Ok(TensorIndex { tensors, aliases })
}

fn read_state(r: &mut Reader<'_>, bounds: &ManifestBounds) -> Result<StateGroup, ManifestError> {
    let count = r.len(bounds.max_tensors.into(), "persistent buffers")?;
    let mut persistent_buffers = Vec::new();
    for _ in 0..count {
        persistent_buffers.push(r.tensor_name(bounds, "persistent buffer")?);
    }
    let count = r.len(bounds.max_tensors.into(), "rematerialized buffers")?;
    let mut rematerialized_buffers = Vec::new();
    for _ in 0..count {
        rematerialized_buffers.push(RematerializedBuffer {
            name: r.tensor_name(bounds, "rematerialized buffer")?,
            dtype: read_dtype(r)?,
            shape: read_shape(r, bounds)?,
            reconstruction: read_versioned(r, "reconstruction adapter", "adapter version")?,
        });
    }
    Ok(StateGroup {
        persistent_buffers,
        rematerialized_buffers,
    })
}

fn read_extents(
    r: &mut Reader<'_>,
    bounds: &ManifestBounds,
    formats: &[CodecFormat],
) -> Result<ExtentGroup, ManifestError> {
    let integrity_extent_bytes = r.u64()?;
    let codec_block_bytes = r.option_u64("codec block size")?;
    let count = r.len(bounds.max_files.into(), "max_files")?;
    let mut prepared_files = Vec::new();
    for _ in 0..count {
        prepared_files.push(PreparedFile {
            path: r.path("prepared file path")?,
            length_bytes: r.u64()?,
        });
    }
    let count = r.len(bounds.max_extents.into(), "max_extents")?;
    let mut extents = Vec::new();
    let mut named = vec![false; formats.len()];
    for _ in 0..count {
        let file = SourceFileId(r.u32()?);
        let logical_offset_bytes = r.u64()?;
        let true_length_bytes = r.u64()?;
        let content_key = ContentKey::from_digest(r.digest()?);
        let encoding = match r.u8()? {
            1 => ExtentEncoding::Raw,
            2 => {
                let index = r.u32()?;
                let format = *formats
                    .get(index as usize)
                    .ok_or(ManifestError::MissingCodecFormat { index })?;
                if let Some(named) = named.get_mut(index as usize) {
                    *named = true;
                }
                let dictionary = r
                    .option_digest("dictionary")?
                    .map(DictionaryId::from_digest);
                let location = EncodedLocation {
                    file: PreparedFileId(r.u32()?),
                    offset_bytes: r.u64()?,
                    length_bytes: r.u64()?,
                };
                let digest = EncodedDigest::from_digest(r.digest()?);
                ExtentEncoding::Encoded(EncodedRepresentation {
                    format,
                    dictionary,
                    location,
                    digest,
                })
            }
            tag => {
                return Err(ManifestError::UnknownTag {
                    field: "extent encoding",
                    tag,
                })
            }
        };
        extents.push(Extent {
            file,
            logical_offset_bytes,
            true_length_bytes,
            content_key,
            encoding,
        });
    }
    // A table entry no extent names would give the same manifest a second encoding.
    if named.contains(&false) {
        return Err(ManifestError::NotCanonical {
            collection: "codec formats",
        });
    }
    Ok(ExtentGroup {
        integrity_extent_bytes,
        codec_block_bytes,
        prepared_files,
        extents,
    })
}

fn read_integrity(
    r: &mut Reader<'_>,
    bounds: &ManifestBounds,
) -> Result<IntegrityGroup, ManifestError> {
    let count = r.len(bounds.max_files.into(), "extent roots")?;
    let mut extent_roots = Vec::new();
    for _ in 0..count {
        extent_roots.push(r.digest()?);
    }
    Ok(IntegrityGroup {
        extent_roots,
        decoded_content_identity: r.digest()?,
    })
}

fn read_lifecycle(r: &mut Reader<'_>) -> Result<Lifecycle, ManifestError> {
    let count = r.len(MAX_LIST_ENTRIES.into(), "dependency roots")?;
    let mut dependency_roots = Vec::new();
    for _ in 0..count {
        dependency_roots.push(match r.u8()? {
            1 => DependencyRoot::Artifact(ManifestDigest::from_digest(r.digest()?)),
            2 => DependencyRoot::Adapter(r.digest()?),
            3 => DependencyRoot::Dictionary(DictionaryId::from_digest(r.digest()?)),
            tag => {
                return Err(ManifestError::UnknownTag {
                    field: "dependency root",
                    tag,
                })
            }
        });
    }
    let storage = StorageAccounting {
        referenced_source_bytes: r.u64()?,
        owned_representation_bytes: r.u64()?,
    };
    let migration = match r.u8()? {
        1 => MigrationRequirement::ReindexFromSources,
        2 => MigrationRequirement::RebuildPreparedFromSources,
        tag => {
            return Err(ManifestError::UnknownTag {
                field: "migration",
                tag,
            })
        }
    };
    Ok(Lifecycle {
        dependency_roots,
        storage,
        migration,
    })
}
