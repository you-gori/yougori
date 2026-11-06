//! Tests of the representation module on real byte buffers: synthetic BF16 weights from
//! a seeded generator, manifests built with the committed builder, and fakes of stored
//! and resident bytes.

mod claims_tests;
mod codec_tests;
mod delta_tests;
mod differential_tests;
mod entropy_tests;
mod experiments;
mod policy_tests;
mod selection_tests;

use std::collections::BTreeMap;

use crate::foundation::evidence::{Backend, BackendRelease};
use crate::foundation::ids::{
    digest, ContentKey, Digest, ExecutionCategory, GpuDeviceKey, ManualClock, MonotonicTime,
    TrustScope,
};
use crate::model_memory::bench::rng::SeededRng;
use crate::model_memory::manifest::{
    sidecar_converter, ArtifactDescription, DictionaryId, Distribution, ElementType, EncodingInput,
    ExecutionAbi, ExtentDecoder, ExtentEncoding, ExtentInput, FileFormat, FileRole,
    HardwareRestriction, ManifestBounds, ManifestBuilder, Quantization, RelativePath,
    SourceFileInput, SourceOrigin, TensorAlias, TensorDtype, TensorInput, TensorLayout, TensorName,
    TensorOwner, Token, ValidatedManifest, VersionedName, WeightFormat,
};

use super::codec::{prepare_file, EscapePolicy, ZstdDecoder};
use super::differential::{
    Consumer, ResidentBytes, ResidentExtent, ResidentRead, SourceBytes, StoredExtents,
};

/// Integrity-extent and codec-block size of the test artifacts.
pub(super) const G: u64 = 256;

/// Safetensors header length that puts tensor data at offset 256, a multiple of `G`.
pub(super) const ALIGNED_HEADER: u64 = 248;

pub(super) fn path(text: &str) -> RelativePath {
    RelativePath::new(text).unwrap()
}

pub(super) fn tensor_name(text: &str) -> TensorName {
    TensorName::new(text).unwrap()
}

fn token(text: &str) -> Token {
    Token::new(text).unwrap()
}

fn abi() -> ExecutionAbi {
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

fn description(adapters: Vec<Digest>) -> ArtifactDescription {
    ArtifactDescription {
        bounds: ManifestBounds::DEFAULT,
        compute_dtype: ElementType::Bf16,
        quantization: Quantization::None,
        adapters,
        execution_abi: abi(),
        distribution: Distribution::SINGLE,
        integrity_extent_bytes: G,
    }
}

/// The top 16 bits of an f32: its BF16 truncation.
pub(super) fn bf16_bits(value: f32) -> u16 {
    (value.to_bits() >> 16) as u16
}

pub(super) fn bf16_value(bits: u16) -> f32 {
    f32::from_bits(u32::from(bits) << 16)
}

/// `count` BF16 weights near a normal distribution of standard deviation `scale`.
pub(super) fn bf16_weights(seed: u64, count: usize, scale: f32) -> Vec<u8> {
    let mut rng = SeededRng::new(seed);
    (0..count)
        .flat_map(|_| {
            // Irwin-Hall: the sum of 12 uniforms minus 6 is close to a standard normal.
            let sum: f32 = (0..12)
                .map(|_| rng.below(1 << 24) as f32 / (1u32 << 24) as f32)
                .sum();
            bf16_bits((sum - 6.0) * scale).to_le_bytes()
        })
        .collect()
}

/// A dense fine-tune: every value scaled by a small seeded factor, and nudged by one
/// mantissa step when the factor left it unchanged, so virtually every byte changes.
pub(super) fn fine_tune(base: &[u8], seed: u64, relative: f32) -> Vec<u8> {
    let mut rng = SeededRng::new(seed);
    base.chunks(2)
        .flat_map(|pair| {
            let bits = u16::from_le_bytes([pair[0], pair[1]]);
            let factor = 1.0 + relative * (rng.below(2001) as f32 / 1000.0 - 1.0);
            let mut tuned = bf16_bits(bf16_value(bits) * factor);
            if tuned == bits {
                tuned ^= 1;
            }
            tuned.to_le_bytes()
        })
        .collect()
}

/// Seeded bytes with no structure, standing in for already-quantized blocks.
pub(super) fn random_bytes(seed: u64, count: usize) -> Vec<u8> {
    let mut rng = SeededRng::new(seed);
    (0..count).map(|_| rng.below(256) as u8).collect()
}

/// Every BF16 bit pattern once, little-endian: 131,072 bytes.
pub(super) fn all_bf16_patterns() -> Vec<u8> {
    (0..=u16::MAX).flat_map(u16::to_le_bytes).collect()
}

/// How a test artifact stores its weight files.
#[derive(Clone, Copy, Debug)]
pub(super) enum Storage {
    Raw,
    Zstd(EscapePolicy),
}

pub(super) const ZSTD: Storage = Storage::Zstd(EscapePolicy {
    level: 3,
    metadata_bytes_per_encoded_block: 0,
});

/// One safetensors file of BF16 tensors.
#[derive(Clone, Debug)]
pub(super) struct WeightFile {
    pub path: &'static str,
    pub header_length_bytes: u64,
    pub tensors: Vec<(&'static str, Vec<u8>)>,
}

impl WeightFile {
    pub(super) fn aligned(path: &'static str, tensors: Vec<(&'static str, Vec<u8>)>) -> Self {
        Self {
            path,
            header_length_bytes: ALIGNED_HEADER,
            tensors,
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut bytes = self.header_length_bytes.to_le_bytes().to_vec();
        bytes.extend(std::iter::repeat_n(b' ', self.header_length_bytes as usize));
        for (_, data) in &self.tensors {
            bytes.extend_from_slice(data);
        }
        bytes
    }
}

/// A test artifact: config.json, weight files, aliases and adapters.
#[derive(Clone, Debug)]
pub(super) struct ModelSpec {
    pub files: Vec<WeightFile>,
    pub aliases: Vec<(&'static str, &'static str)>,
    pub adapters: Vec<Digest>,
    pub storage: Storage,
}

impl ModelSpec {
    pub(super) fn single(tensors: Vec<(&'static str, Vec<u8>)>) -> Self {
        Self {
            files: vec![WeightFile::aligned("model.safetensors", tensors)],
            aliases: Vec::new(),
            adapters: Vec::new(),
            storage: Storage::Raw,
        }
    }
}

/// A built artifact with its source files and prepared files.
pub(super) struct Model {
    pub manifest: ValidatedManifest,
    pub files: BTreeMap<RelativePath, Vec<u8>>,
    pub prepared: BTreeMap<RelativePath, Vec<u8>>,
}

const CONFIG: &[u8] = b"{\"architectures\":[\"LlamaForCausalLM\"],\"model_type\":\"llama\"}";

fn add_raw_extents(builder: &mut ManifestBuilder, file: &str, bytes: &[u8]) {
    for (index, chunk) in bytes.chunks(G as usize).enumerate() {
        builder.add_extent(ExtentInput {
            file: path(file),
            logical_offset_bytes: index as u64 * G,
            true_length_bytes: chunk.len() as u64,
            content_key: ContentKey::of(chunk),
            encoding: EncodingInput::Raw,
        });
    }
}

pub(super) fn build_model(spec: &ModelSpec) -> Model {
    let mut builder = ManifestBuilder::new(
        SourceOrigin::LocalFolder,
        sidecar_converter().unwrap(),
        description(spec.adapters.clone()),
    );
    let mut files = BTreeMap::new();
    let mut prepared = BTreeMap::new();
    builder
        .add_source_file(SourceFileInput {
            path: path("config.json"),
            length_bytes: CONFIG.len() as u64,
            content: ContentKey::of(CONFIG),
            role: FileRole::Configuration,
            format: FileFormat::Opaque,
        })
        .unwrap();
    add_raw_extents(&mut builder, "config.json", CONFIG);
    files.insert(path("config.json"), CONFIG.to_vec());
    for weight in &spec.files {
        let bytes = weight.bytes();
        builder
            .add_source_file(SourceFileInput {
                path: path(weight.path),
                length_bytes: bytes.len() as u64,
                content: ContentKey::of(&bytes),
                role: FileRole::Weights {
                    format: WeightFormat::Safetensors,
                    rank: None,
                },
                format: FileFormat::Safetensors {
                    header_length_bytes: weight.header_length_bytes,
                },
            })
            .unwrap();
        let mut offset = 8 + weight.header_length_bytes;
        for (name, data) in &weight.tensors {
            let dtype = TensorDtype::Element(ElementType::Bf16);
            builder
                .add_tensor(TensorInput {
                    name: tensor_name(name),
                    file: path(weight.path),
                    offset_bytes: offset,
                    true_length_bytes: data.len() as u64,
                    dtype,
                    shape: vec![data.len() as u64 / 2],
                    layout: TensorLayout::RowMajor,
                    owner: TensorOwner::Replicated,
                })
                .unwrap();
            offset += data.len() as u64;
        }
        match spec.storage {
            Storage::Raw => add_raw_extents(&mut builder, weight.path, &bytes),
            Storage::Zstd(policy) => {
                let prepared_path = path(&format!("prepared/{}.zst", weight.path));
                let file =
                    prepare_file(&path(weight.path), &bytes, G, &prepared_path, &policy).unwrap();
                for extent in file.extents {
                    builder.add_extent(extent);
                }
                if let Some(block) = file.codec_block_bytes {
                    builder.set_codec_block_bytes(block);
                }
                if let Some((prepared_path, data)) = file.prepared {
                    builder
                        .add_prepared_file(prepared_path.clone(), data.len() as u64)
                        .unwrap();
                    prepared.insert(prepared_path, data);
                }
            }
        }
        files.insert(path(weight.path), bytes);
    }
    for (alias, target) in &spec.aliases {
        builder
            .add_alias(TensorAlias {
                name: tensor_name(alias),
                target: tensor_name(target),
            })
            .unwrap();
    }
    Model {
        manifest: builder.finish().unwrap(),
        files,
        prepared,
    }
}

impl StoredExtents for Model {
    fn stored(&self, extent_index: usize) -> Option<Vec<u8>> {
        let manifest = self.manifest.manifest();
        let extent = manifest.extents.extents.get(extent_index)?;
        let (bytes, offset, length) = match &extent.encoding {
            ExtentEncoding::Raw => {
                let file = manifest.provenance.files.get(extent.file.index())?;
                (
                    self.files.get(&file.path)?,
                    extent.logical_offset_bytes,
                    extent.true_length_bytes,
                )
            }
            ExtentEncoding::Encoded(encoded) => {
                let file = manifest
                    .extents
                    .prepared_files
                    .get(encoded.location.file.index())?;
                (
                    self.prepared.get(&file.path)?,
                    encoded.location.offset_bytes,
                    encoded.location.length_bytes,
                )
            }
        };
        bytes
            .get(offset as usize..(offset + length) as usize)
            .map(<[u8]>::to_vec)
    }

    fn dictionary(&self, _dictionary: &DictionaryId) -> Option<Vec<u8>> {
        None
    }
}

impl SourceBytes for Model {
    fn file(&self, path: &RelativePath) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }
}

impl Model {
    /// Every decoded extent of the artifact, verified.
    pub(super) fn decoded_extents(&self) -> BTreeMap<ContentKey, Vec<u8>> {
        let decoder = ZstdDecoder;
        let decoders: [&dyn ExtentDecoder; 1] = [&decoder];
        (0..self.manifest.manifest().extents.extents.len())
            .map(|index| {
                let stored = self.stored(index).unwrap();
                let decoded = self
                    .manifest
                    .verify_extent(index, &stored, None, &decoders)
                    .unwrap();
                (ContentKey::of(&decoded), decoded)
            })
            .collect()
    }

    pub(super) fn tensor_source_bytes(&self, name: &str) -> Vec<u8> {
        let tensor = self.manifest.tensor(name).unwrap();
        let file = &self.manifest.manifest().provenance.files[tensor.file.index()];
        let bytes = &self.files[&file.path];
        let start = tensor.offset_bytes as usize;
        bytes[start..start + tensor.true_length_bytes as usize].to_vec()
    }
}

/// Resident decoded bytes by content key, trust scope and device.
#[derive(Default)]
pub(super) struct Residents(pub BTreeMap<(ContentKey, TrustScope, GpuDeviceKey), Vec<u8>>);

impl Residents {
    /// The copy of `key` held for [`consumer`].
    pub(super) fn consumer_copy(&mut self, key: &ContentKey) -> Option<&mut Vec<u8>> {
        let at = consumer();
        self.0.get_mut(&(*key, at.scope, at.device))
    }

    pub(super) fn remove_consumer_copy(&mut self, key: &ContentKey) -> Option<Vec<u8>> {
        let at = consumer();
        self.0.remove(&(*key, at.scope, at.device))
    }
}

impl ResidentBytes for Residents {
    /// Serves exactly the named copy, as a correct port does.
    fn resident(&self, resident: &ResidentExtent) -> Option<ResidentRead> {
        self.0
            .get(&(resident.key, resident.scope, resident.device))
            .map(|bytes| ResidentRead {
                scope: resident.scope,
                device: resident.device,
                bytes: bytes.clone(),
            })
    }
}

pub(super) fn tenant_scope(name: &str) -> TrustScope {
    TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, name)
}

pub(super) fn device(name: &str) -> GpuDeviceKey {
    GpuDeviceKey {
        machine: digest("yougori/test/machine/v1", &[b"host-1"]),
        device: digest("yougori/test/device/v1", &[name.as_bytes()]),
    }
}

pub(super) fn consumer() -> Consumer {
    Consumer {
        scope: tenant_scope("tenant-a"),
        device: device("gpu-0"),
    }
}

pub(super) fn clock() -> ManualClock {
    ManualClock::new(MonotonicTime::from_nanos(1_000))
}

pub(super) const EXPIRES: MonotonicTime = MonotonicTime::from_nanos(1_000_000);

/// Everything `model` holds, resident for [`consumer`] until [`EXPIRES`].
pub(super) fn resident_model(model: &Model) -> (Vec<ResidentExtent>, Residents) {
    let decoded = model.decoded_extents();
    let advertised = decoded
        .iter()
        .map(|(key, bytes)| ResidentExtent {
            key: *key,
            true_length_bytes: bytes.len() as u64,
            scope: consumer().scope,
            device: consumer().device,
            expires_at: EXPIRES,
        })
        .collect();
    let at = consumer();
    let copies = decoded
        .into_iter()
        .map(|(key, bytes)| ((key, at.scope, at.device), bytes))
        .collect();
    (advertised, Residents(copies))
}
