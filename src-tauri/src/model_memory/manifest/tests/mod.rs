//! Tests of the sidecar manifest, the bounded indexers and the importer protocol, on
//! synthetic files in temporary directories, fakes of the T05, T06 and T07 ports, and
//! the adapters over the committed catalog (T05) and identity layers (T07).

mod adapter_tests;
mod codec_version_tests;
mod fakes;
mod gguf_tests;
mod importer_tests;
mod manifest_tests;
mod review_tests;
mod safetensors_tests;
mod types_tests;

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::json;
use tempfile::TempDir;

use self::fakes::FakeIdentities;
use super::*;
use crate::foundation::evidence::{Backend, BackendRelease};

pub(super) fn token(text: &str) -> Token {
    Token::new(text).unwrap()
}

pub(super) fn path(text: &str) -> RelativePath {
    RelativePath::new(text).unwrap()
}

pub(super) fn name(text: &str) -> TensorName {
    TensorName::new(text).unwrap()
}

pub(super) fn abi() -> ExecutionAbi {
    ExecutionAbi {
        runner: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        architecture_adapter: VersionedName {
            name: token("LlamaForCausalLM"),
            version: token("1"),
        },
        layout: token("original"),
        kernels: Vec::new(),
        hardware: HardwareRestriction::Unrestricted,
    }
}

pub(super) fn description(
    distribution: Distribution,
    integrity_extent_bytes: u64,
) -> ArtifactDescription {
    ArtifactDescription {
        bounds: ManifestBounds::DEFAULT,
        compute_dtype: ElementType::Bf16,
        quantization: Quantization::None,
        adapters: Vec::new(),
        execution_abi: abi(),
        distribution,
        integrity_extent_bytes,
    }
}

pub(super) fn tensor_parallel(size: u32) -> Distribution {
    Distribution {
        tensor_parallel_size: size,
        ..Distribution::SINGLE
    }
}

/// Little-endian bytes of `values`.
pub(super) fn f32_bytes(values: &[f32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

/// Bytes `0, 1, 2, ...` offset by `seed`, as a recognisable payload.
pub(super) fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| (index as u8).wrapping_add(seed))
        .collect()
}

/// A safetensors file from a header JSON and a data buffer: the header is padded with
/// spaces to a multiple of eight bytes, as the reference writer does.
pub(super) fn raw_safetensors(header_json: &[u8], data: &[u8]) -> Vec<u8> {
    let mut header = header_json.to_vec();
    while !header.len().is_multiple_of(8) {
        header.push(b' ');
    }
    let mut file = (header.len() as u64).to_le_bytes().to_vec();
    file.extend_from_slice(&header);
    file.extend_from_slice(data);
    file
}

/// A well-formed safetensors file holding `tensors` in order.
pub(super) fn safetensors_bytes(tensors: &[(&str, ElementType, &[u64], &[u8])]) -> Vec<u8> {
    let mut header = serde_json::Map::new();
    header.insert("__metadata__".to_owned(), json!({ "format": "pt" }));
    let mut data = Vec::new();
    for (tensor, dtype, shape, bytes) in tensors {
        let begin = data.len();
        data.extend_from_slice(bytes);
        header.insert(
            (*tensor).to_owned(),
            json!({
                "dtype": dtype.safetensors_name(),
                "shape": shape,
                "data_offsets": [begin, data.len()],
            }),
        );
    }
    raw_safetensors(&serde_json::to_vec(&header).unwrap(), &data)
}

/// The data buffer's start in a safetensors file.
pub(super) fn safetensors_data_start(file: &[u8]) -> u64 {
    8 + u64::from_le_bytes(file[..8].try_into().unwrap())
}

fn gguf_string(out: &mut Vec<u8>, text: &[u8]) {
    out.extend_from_slice(&(text.len() as u64).to_le_bytes());
    out.extend_from_slice(text);
}

/// A tensor of a synthetic GGUF file. `offset` overrides the contiguous offset.
#[derive(Clone)]
pub(super) struct GgufTensor {
    pub name: String,
    pub dims: Vec<u64>,
    pub ggml_type: u32,
    pub data: Vec<u8>,
    pub offset: Option<u64>,
}

/// A synthetic GGUF file, written little-endian as ggml writes it.
#[derive(Clone)]
pub(super) struct GgufFile {
    pub magic: [u8; 4],
    pub version: u32,
    pub alignment: u64,
    pub metadata: Vec<(Vec<u8>, u32, Vec<u8>)>,
    pub tensors: Vec<GgufTensor>,
    pub trailing: Vec<u8>,
}

impl GgufFile {
    pub fn new() -> Self {
        Self {
            magic: *b"GGUF",
            version: 3,
            alignment: 32,
            metadata: Vec::new(),
            tensors: Vec::new(),
            trailing: Vec::new(),
        }
    }

    pub fn raw_kv(mut self, key: &str, value_type: u32, value: Vec<u8>) -> Self {
        self.metadata
            .push((key.as_bytes().to_vec(), value_type, value));
        self
    }

    pub fn kv_string(self, key: &str, value: &str) -> Self {
        let mut bytes = Vec::new();
        gguf_string(&mut bytes, value.as_bytes());
        self.raw_kv(key, 8, bytes)
    }

    pub fn kv_u32(self, key: &str, value: u32) -> Self {
        self.raw_kv(key, 4, value.to_le_bytes().to_vec())
    }

    pub fn kv_alignment(mut self, alignment: u32) -> Self {
        self.alignment = alignment.into();
        self.kv_u32("general.alignment", alignment)
    }

    pub fn kv_strings(self, key: &str, values: &[&str]) -> Self {
        let mut bytes = 8u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&(values.len() as u64).to_le_bytes());
        for value in values {
            gguf_string(&mut bytes, value.as_bytes());
        }
        self.raw_kv(key, 9, bytes)
    }

    pub fn kv_f32s(self, key: &str, values: &[f32]) -> Self {
        let mut bytes = 6u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&(values.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&f32_bytes(values));
        self.raw_kv(key, 9, bytes)
    }

    pub fn tensor(mut self, name: &str, dims: &[u64], ggml_type: u32, data: Vec<u8>) -> Self {
        self.tensors.push(GgufTensor {
            name: name.to_owned(),
            dims: dims.to_vec(),
            ggml_type,
            data,
            offset: None,
        });
        self
    }

    fn padded(&self, len: u64) -> u64 {
        len.div_ceil(self.alignment) * self.alignment
    }

    /// The file's bytes and the start of its data section.
    pub fn build(&self) -> (Vec<u8>, u64) {
        let mut out = self.magic.to_vec();
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&(self.tensors.len() as u64).to_le_bytes());
        out.extend_from_slice(&(self.metadata.len() as u64).to_le_bytes());
        for (key, value_type, value) in &self.metadata {
            gguf_string(&mut out, key);
            out.extend_from_slice(&value_type.to_le_bytes());
            out.extend_from_slice(value);
        }
        let mut offset = 0u64;
        for tensor in &self.tensors {
            gguf_string(&mut out, tensor.name.as_bytes());
            out.extend_from_slice(&(tensor.dims.len() as u32).to_le_bytes());
            for dimension in &tensor.dims {
                out.extend_from_slice(&dimension.to_le_bytes());
            }
            out.extend_from_slice(&tensor.ggml_type.to_le_bytes());
            out.extend_from_slice(&tensor.offset.unwrap_or(offset).to_le_bytes());
            offset += self.padded(tensor.data.len() as u64);
        }
        let data_start = self.padded(out.len() as u64);
        out.resize(data_start as usize, 0);
        for tensor in &self.tensors {
            out.extend_from_slice(&tensor.data);
            let end = data_start + self.padded(out.len() as u64 - data_start);
            out.resize(end as usize, 0);
        }
        out.extend_from_slice(&self.trailing);
        (out, data_start)
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.build().0
    }
}

/// A model folder in a temporary directory with its listing.
pub(super) struct ModelFixture {
    pub dir: TempDir,
    pub files: BTreeMap<String, Vec<u8>>,
    pub listing: SourceListing,
}

impl ModelFixture {
    /// Writes `files` (path, bytes, role) under a new temporary directory.
    pub fn new(files: &[(&str, Vec<u8>, FileRole)]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut contents = BTreeMap::new();
        let mut listed = Vec::new();
        for (file, bytes, role) in files {
            let full = dir.path().join(file);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(&full, bytes).unwrap();
            contents.insert((*file).to_owned(), bytes.clone());
            listed.push(listed_file(file, bytes, *role));
        }
        let listing = SourceListing {
            origin: SourceOrigin::LocalFolder,
            revision: SourceListing::content_revision(&listed),
            files: listed,
        };
        Self {
            dir,
            files: contents,
            listing,
        }
    }

    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    /// The model folder as the importer's source.
    pub fn source(&self) -> DirectorySource {
        DirectorySource::new(self.root())
    }

    /// A request for `description` with port contexts, keyed by the fake identities.
    pub fn request_with<I, C>(
        &self,
        description: ArtifactDescription,
        identity: I,
        catalog: C,
    ) -> ImportRequest<I, C> {
        let source = FakeIdentities::source_for(&self.listing);
        let execution = FakeIdentities::execution_for(
            &source,
            &description.execution_abi,
            &description.distribution,
        );
        ImportRequest {
            key: ImportKey { source, execution },
            listing: self.listing.clone(),
            description,
            state: StateGroup::default(),
            aliases: Vec::new(),
            owners: Vec::new(),
            identity,
            catalog,
        }
    }

    /// A request for `description` over the fake ports.
    pub fn request(&self, description: ArtifactDescription) -> ImportRequest {
        self.request_with(description, (), ())
    }
}

pub(super) fn listed_file(file: &str, bytes: &[u8], role: FileRole) -> ListedFile {
    ListedFile {
        path: path(file),
        length_bytes: bytes.len() as u64,
        content: ContentKey::of(bytes),
        role,
    }
}

pub(super) const SAFETENSORS_WEIGHTS: FileRole = FileRole::Weights {
    format: WeightFormat::Safetensors,
    rank: None,
};

pub(super) const GGUF_WEIGHTS: FileRole = FileRole::Weights {
    format: WeightFormat::Gguf,
    rank: None,
};

/// The codec format the encoded test extents declare: zstd frames of 64-byte codec blocks
/// without a dictionary id or checksum, so at most a 1 KiB window.
pub(super) const ZSTD_FORMAT: CodecFormat = CodecFormat::ZstdRfc8878(ZstdFrameParameters {
    dictionary_id: 0,
    content_checksum: false,
    max_window_bytes: 1 << 10,
});

/// A small Hugging Face style model: configuration, tokenizer and one safetensors file
/// with two tensors.
pub(super) fn small_model() -> ModelFixture {
    let embed = f32_bytes(&(0..16).map(|value| value as f32).collect::<Vec<_>>());
    let norm = pattern(8, 7);
    let weights = safetensors_bytes(&[
        (
            "model.embed_tokens.weight",
            ElementType::F32,
            &[4, 4],
            &embed,
        ),
        ("model.norm.weight", ElementType::Bf16, &[4], &norm),
    ]);
    ModelFixture::new(&[
        (
            "config.json",
            br#"{"architectures":["LlamaForCausalLM"],"hidden_size":4}"#.to_vec(),
            FileRole::Configuration,
        ),
        (
            "tokenizer.json",
            br#"{"model":{"type":"BPE","vocab":{}}}"#.to_vec(),
            FileRole::Tokenizer,
        ),
        ("model.safetensors", weights, SAFETENSORS_WEIGHTS),
    ])
}
