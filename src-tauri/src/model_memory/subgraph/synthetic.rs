//! Synthetic model families for the fake substrate (GPU §4.16 line 898).
//!
//! Each synthetic model is a validated sidecar manifest over two in-memory files, a
//! configuration and a weights file, with one 64-byte F32 tensor per extent so that a
//! changed tensor changes exactly its own parameter identity. The architecture is an
//! input block (token embedding and layer 0), [`DECODER_LAYERS`] decoder layers and a
//! task head. Nothing here reads or writes a file.

use std::collections::BTreeSet;
use std::fmt;

use crate::foundation::evidence::{Backend, BackendRelease, VersionError};
use crate::foundation::ids::{digest, ContentKey, Digest, TrustScope};
use crate::model_memory::adapters::adapter::{
    AdapterLimits, AdapterReference, LayerShape, LayerTable,
};
use crate::model_memory::identity::{
    self, AdapterRecipe, AdapterSpec, CodePolicy, CompileConfiguration, Dtype, ExecutionIdentity,
    ExecutionSpec, IdentityError, ImmutableRevision, LogicalModelIdentity, LogicalModelSpec,
    MergeScale, PositionalEncoding, RankTopology, SourceFile, SourceIdentity, SourceLocation,
    SourceSpec, VersionedName,
};
use crate::model_memory::manifest::{
    self, sidecar_converter, tensor_bytes, ArtifactDescription, Distribution, ElementType,
    EncodingInput, ExecutionAbi, ExtentInput, FileFormat, FileRole, HardwareRestriction,
    ManifestBounds, ManifestBuilder, ManifestError, NameError, RelativePath, SourceFileInput,
    SourceOrigin, TensorDtype, TensorInput, TensorLayout, TensorName, TensorOwner, Token,
    ValidatedManifest, WeightFormat,
};

use super::profit::{HandoffCosts, OperatorCost, StateHandoff};
use super::variant::{
    AdapterAdmission, AttentionSemantics, BatchDependence, ExecutionProfile, ImmutableVariant,
    KernelDeterminism, OperatorAbi, OperatorDefinition, OperatorRuntime, SubgraphError,
    TensorFormat, VariantDefinition,
};

/// Decoder layers after the input block.
pub const DECODER_LAYERS: usize = 6;
/// Operators of the synthetic architecture: input block, decoder layers, task head.
pub const SYNTHETIC_OPERATORS: usize = DECODER_LAYERS + 2;
/// Bytes of every synthetic tensor (F32, 16 elements) and of every integrity extent.
pub const SYNTHETIC_TENSOR_BYTES: u64 = 64;
/// Bytes before the first tensor of the weights file: the 8-byte length and a 56-byte
/// header, as a safetensors file lays them out.
pub const SYNTHETIC_HEADER_BYTES: u64 = 64;
/// Domain of synthetic tensor contents.
pub const SYNTHETIC_TENSOR_DOMAIN: &str = "yougori/model-memory/subgraph/synthetic-tensor/v1";
/// Rotary base of the synthetic reference model.
pub const REFERENCE_ROPE_THETA: u64 = 10_000;

/// One tensor of a synthetic model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntheticTensor {
    pub name: String,
    /// Exactly [`SYNTHETIC_TENSOR_BYTES`] bytes.
    pub bytes: Vec<u8>,
}

/// A synthetic model: its configuration bytes and its tensors in file order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntheticModel {
    pub configuration: Vec<u8>,
    pub tensors: Vec<SyntheticTensor>,
}

/// Why a synthetic model or family could not be built.
#[derive(Clone, Debug, PartialEq)]
pub enum SyntheticError {
    TensorSize { name: String },
    Manifest(ManifestError),
    Name(NameError),
    Identity(IdentityError),
    Version(VersionError),
    Subgraph(SubgraphError),
}

impl fmt::Display for SyntheticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TensorSize { name } => write!(
                f,
                "synthetic tensor {name:?} is not {SYNTHETIC_TENSOR_BYTES} bytes"
            ),
            Self::Manifest(error) => write!(f, "{error}"),
            Self::Name(error) => write!(f, "{error:?}"),
            Self::Identity(error) => write!(f, "{error:?}"),
            Self::Version(error) => write!(f, "{error}"),
            Self::Subgraph(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for SyntheticError {}

impl From<ManifestError> for SyntheticError {
    fn from(error: ManifestError) -> Self {
        Self::Manifest(error)
    }
}

impl From<NameError> for SyntheticError {
    fn from(error: NameError) -> Self {
        Self::Name(error)
    }
}

impl From<IdentityError> for SyntheticError {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

impl From<VersionError> for SyntheticError {
    fn from(error: VersionError) -> Self {
        Self::Version(error)
    }
}

impl From<SubgraphError> for SyntheticError {
    fn from(error: SubgraphError) -> Self {
        Self::Subgraph(error)
    }
}

/// The 64 bytes of a synthetic tensor: two chained digests of its name and revision, so
/// equal names and revisions give equal bytes and anything else differs.
pub fn tensor_contents(name: &str, revision: u8) -> Vec<u8> {
    let first = digest(SYNTHETIC_TENSOR_DOMAIN, &[name.as_bytes(), &[revision]]);
    let second = digest(SYNTHETIC_TENSOR_DOMAIN, &[first.as_bytes()]);
    let mut bytes = first.as_bytes().to_vec();
    bytes.extend_from_slice(second.as_bytes());
    bytes
}

/// The configuration file of a synthetic model with rotary base `rope_theta`.
pub fn configuration_bytes(rope_theta: u64) -> Vec<u8> {
    format!("{{\"architecture\":\"synthetic\",\"rope_theta\":{rope_theta}}}").into_bytes()
}

/// The weights file: a fixed header region, then every tensor in order.
pub fn weights_file(model: &SyntheticModel) -> Result<Vec<u8>, SyntheticError> {
    let mut file: Vec<u8> = (0..SYNTHETIC_HEADER_BYTES)
        .map(|index| index as u8)
        .collect();
    for tensor in &model.tensors {
        if tensor.bytes.len() as u64 != SYNTHETIC_TENSOR_BYTES {
            return Err(SyntheticError::TensorSize {
                name: tensor.name.clone(),
            });
        }
        file.extend_from_slice(&tensor.bytes);
    }
    Ok(file)
}

fn add_file(
    builder: &mut ManifestBuilder,
    path: &str,
    bytes: &[u8],
    role: FileRole,
    format: FileFormat,
    extent_bytes: u64,
) -> Result<(), SyntheticError> {
    builder.add_source_file(SourceFileInput {
        path: RelativePath::new(path)?,
        length_bytes: bytes.len() as u64,
        content: ContentKey::of(bytes),
        role,
        format,
    })?;
    let chunk_bytes = usize::try_from(extent_bytes).unwrap_or(usize::MAX).max(1);
    for (index, chunk) in bytes.chunks(chunk_bytes).enumerate() {
        builder.add_extent(ExtentInput {
            file: RelativePath::new(path)?,
            logical_offset_bytes: (index as u64).saturating_mul(extent_bytes),
            true_length_bytes: chunk.len() as u64,
            content_key: ContentKey::of(chunk),
            encoding: EncodingInput::Raw,
        });
    }
    Ok(())
}

/// The validated manifest of a synthetic model, built in memory, with one integrity
/// extent per tensor.
pub fn synthetic_manifest(model: &SyntheticModel) -> Result<ValidatedManifest, SyntheticError> {
    synthetic_manifest_with_extents(model, SYNTHETIC_TENSOR_BYTES)
}

/// [`synthetic_manifest`] with integrity extents of `extent_bytes`.
pub fn synthetic_manifest_with_extents(
    model: &SyntheticModel,
    extent_bytes: u64,
) -> Result<ValidatedManifest, SyntheticError> {
    let token = |text: &str| Token::new(text);
    let description = ArtifactDescription {
        bounds: ManifestBounds::DEFAULT,
        compute_dtype: ElementType::F32,
        quantization: manifest::Quantization::None,
        adapters: Vec::new(),
        execution_abi: ExecutionAbi {
            runner: BackendRelease::new(Backend::Transformers, "4.57.0")?,
            architecture_adapter: manifest::VersionedName {
                name: token("synthetic")?,
                version: token("1")?,
            },
            layout: token("original")?,
            kernels: Vec::new(),
            hardware: HardwareRestriction::Unrestricted,
        },
        distribution: Distribution::SINGLE,
        integrity_extent_bytes: extent_bytes,
    };
    let mut builder =
        ManifestBuilder::new(SourceOrigin::LocalFolder, sidecar_converter()?, description);
    add_file(
        &mut builder,
        "config.json",
        &model.configuration,
        FileRole::Configuration,
        FileFormat::Opaque,
        extent_bytes,
    )?;
    add_file(
        &mut builder,
        "model.safetensors",
        &weights_file(model)?,
        FileRole::Weights {
            format: WeightFormat::Safetensors,
            rank: None,
        },
        FileFormat::Safetensors {
            header_length_bytes: SYNTHETIC_HEADER_BYTES - 8,
        },
        extent_bytes,
    )?;
    let dtype = TensorDtype::Element(ElementType::F32);
    let shape = [SYNTHETIC_TENSOR_BYTES / 4];
    let true_length_bytes = tensor_bytes(dtype, TensorLayout::RowMajor, &shape).map_err(|_| {
        SyntheticError::TensorSize {
            name: "shape".to_owned(),
        }
    })?;
    for (index, tensor) in model.tensors.iter().enumerate() {
        builder.add_tensor(TensorInput {
            name: TensorName::new(tensor.name.clone())?,
            file: RelativePath::new("model.safetensors")?,
            offset_bytes: SYNTHETIC_HEADER_BYTES + index as u64 * SYNTHETIC_TENSOR_BYTES,
            true_length_bytes,
            dtype,
            shape: shape.to_vec(),
            layout: TensorLayout::RowMajor,
            owner: TensorOwner::Replicated,
        })?;
    }
    Ok(builder.finish()?)
}

/// Tensor names of the synthetic architecture in file order.
pub fn architecture_tensors() -> Vec<String> {
    let mut names = vec!["embed.weight".to_owned()];
    names.extend((0..=DECODER_LAYERS).map(|layer| format!("layers.{layer}.weight")));
    names.push("head.weight".to_owned());
    names
}

/// A synthetic model whose tensors are all at revision 0 except those in `revised`, at
/// revision 1.
pub fn synthetic_model(rope_theta: u64, revised: &[&str]) -> SyntheticModel {
    SyntheticModel {
        configuration: configuration_bytes(rope_theta),
        tensors: architecture_tensors()
            .into_iter()
            .map(|name| {
                let revision = u8::from(revised.contains(&name.as_str()));
                SyntheticTensor {
                    bytes: tensor_contents(&name, revision),
                    name,
                }
            })
            .collect(),
    }
}

fn versioned(name: &str, version: &str) -> Result<VersionedName, SyntheticError> {
    Ok(VersionedName::new(name, version)?)
}

/// The positional encoding of a synthetic model: RoPE with base `rope_theta`.
pub fn rope(rope_theta: u64) -> Result<PositionalEncoding, SyntheticError> {
    Ok(PositionalEncoding {
        scheme: versioned("rope", "1")?,
        parameters: digest(
            "yougori/model-memory/subgraph/synthetic-rope/v1",
            &[&rope_theta.to_be_bytes()],
        ),
    })
}

/// The deterministic, batch-invariant profile of the synthetic kernels.
pub fn exact_profile() -> Result<ExecutionProfile, SyntheticError> {
    Ok(ExecutionProfile {
        kernels: versioned("synthetic-kernels", "1")?,
        determinism: KernelDeterminism::Deterministic,
        batching: BatchDependence::BatchInvariant,
        math_mode: digest(
            "yougori/model-memory/subgraph/math-mode/v1",
            &[b"ieee-strict"],
        ),
    })
}

/// Causal attention over the whole context.
pub fn causal_attention() -> Result<AttentionSemantics, SyntheticError> {
    Ok(AttentionSemantics {
        scheme: versioned("causal", "1")?,
        parameters: digest(
            "yougori/model-memory/subgraph/attention/v1",
            &[b"full-context"],
        ),
    })
}

/// The operator definitions of the synthetic architecture.
pub fn architecture_operators() -> Result<Vec<OperatorDefinition>, SyntheticError> {
    let output = TensorFormat {
        dtype: Dtype::Float32,
        layout: versioned("contiguous", "1")?,
    };
    let kernel = versioned("synthetic-kernels", "1")?;
    let operator =
        |kind: &str, tensors: Vec<String>, layers: Vec<String>| -> Result<_, SyntheticError> {
            Ok(OperatorDefinition {
                abi: OperatorAbi {
                    operator: versioned(kind, "1")?,
                    kernel: kernel.clone(),
                },
                tensors,
                adaptable_layers: layers,
                output: output.clone(),
                runtime: OperatorRuntime::Stateless,
            })
        };
    let mut operators = vec![operator(
        "input_block",
        vec!["embed.weight".to_owned(), "layers.0.weight".to_owned()],
        vec!["layers.0.proj".to_owned()],
    )?];
    for layer in 1..=DECODER_LAYERS {
        operators.push(operator(
            "decoder_layer",
            vec![format!("layers.{layer}.weight")],
            vec![format!("layers.{layer}.proj")],
        )?);
    }
    operators.push(operator(
        "task_head",
        vec!["head.weight".to_owned()],
        Vec::new(),
    )?);
    Ok(operators)
}

/// The base's adaptable layers and their shapes (§3.9 line 632).
pub fn architecture_layers() -> LayerTable {
    (0..=DECODER_LAYERS)
        .map(|layer| {
            (
                format!("layers.{layer}.proj"),
                LayerShape {
                    input_features: 16,
                    output_features: 16,
                },
            )
        })
        .collect()
}

fn local_source(
    name: &str,
    files: &[(&str, &[u8])],
    configuration: Digest,
) -> Result<SourceIdentity, SyntheticError> {
    Ok(SourceSpec {
        location: SourceLocation::Local {
            name: identity::Label::new(name)?,
        },
        revision: ImmutableRevision::FileDigests,
        files: files
            .iter()
            .map(|(path, bytes)| {
                Ok(SourceFile {
                    path: identity::RelativePath::new(*path)?,
                    length_bytes: bytes.len() as u64,
                    content: ContentKey::of(bytes),
                })
            })
            .collect::<Result<Vec<_>, IdentityError>>()?,
        configuration,
        published_dtype: Dtype::Float32,
        license: identity::Label::new("LicenseRef-synthetic")?,
        provenance: None,
    }
    .identity()?)
}

/// T07's logical and execution identities of a synthetic model.
pub fn synthetic_identities(
    model: &SyntheticModel,
    manifest: &ValidatedManifest,
) -> Result<(LogicalModelIdentity, ExecutionIdentity), SyntheticError> {
    let weights = weights_file(model)?;
    let source = local_source(
        "synthetic-family",
        &[
            ("config.json", &model.configuration),
            ("model.safetensors", &weights),
        ],
        manifest.manifest().semantics.configuration_digest,
    )?;
    let logical = LogicalModelSpec {
        source,
        dtype: Dtype::Float32,
        quantization: identity::Quantization::None,
        tokenizer: digest(
            "yougori/model-memory/subgraph/tokenizer/v1",
            &[b"synthetic"],
        ),
        generation_config: digest("yougori/model-memory/subgraph/generation/v1", &[b"greedy"]),
        adapters: AdapterRecipe::None,
        code_policy: CodePolicy::BuiltInOnly,
    }
    .identity();
    let execution = ExecutionSpec {
        logical,
        runner: versioned("yougori-fake-subgraph", "1")?,
        architecture_adapter: versioned("synthetic", "1")?,
        kernel_layout: versioned("synthetic-kernels", "1")?,
        gpu_architectures: BTreeSet::from([identity::Label::new("fake-gpu")?]),
        topology: RankTopology::SINGLE,
        processed_weights: versioned("original", "1")?,
        compile: CompileConfiguration::Eager,
    }
    .identity()?;
    Ok((logical, execution))
}

/// A LoRA adapter for `base` targeting `layers` of the synthetic architecture.
pub fn synthetic_adapter(
    base: LogicalModelIdentity,
    layers: &[&str],
) -> Result<AdapterReference, SyntheticError> {
    let table = architecture_layers();
    let source = local_source(
        "synthetic-adapter",
        &[("adapter.safetensors", b"synthetic adapter weights")],
        digest(
            "yougori/model-memory/subgraph/adapter-config/v1",
            &[b"rank-4"],
        ),
    )?;
    let adapter = AdapterSpec {
        source,
        method: versioned("lora", "1")?,
        dtype: Dtype::Float32,
    }
    .identity();
    Ok(AdapterReference {
        adapter,
        base,
        layers: layers
            .iter()
            .filter_map(|layer| table.get(*layer).map(|shape| ((*layer).to_owned(), *shape)))
            .collect(),
        rank: 4,
        scale: MergeScale::new(1.0)?,
    })
}

/// Adapter ranks the synthetic engine accepts.
pub const SYNTHETIC_ADAPTER_LIMITS: AdapterLimits = AdapterLimits { max_rank: 16 };

/// A variant over a synthetic model in `scope`, with an optional unmerged adapter on the
/// listed layers.
pub fn synthetic_variant(
    model: &SyntheticModel,
    rope_theta: u64,
    scope: TrustScope,
    adapter_layers: Option<&[&str]>,
) -> Result<ImmutableVariant, SyntheticError> {
    let manifest = synthetic_manifest(model)?;
    let (logical, execution) = synthetic_identities(model, &manifest)?;
    let definition = VariantDefinition {
        execution,
        trust_scope: scope,
        attention: causal_attention()?,
        position: rope(rope_theta)?,
        profile: exact_profile()?,
        operators: architecture_operators()?,
    };
    let reference = adapter_layers
        .map(|layers| synthetic_adapter(logical, layers))
        .transpose()?;
    let layers = architecture_layers();
    let admission = reference.as_ref().map(|reference| AdapterAdmission {
        reference,
        base: &logical,
        base_layers: &layers,
        limits: &SYNTHETIC_ADAPTER_LIMITS,
    });
    Ok(ImmutableVariant::from_manifest(
        &manifest, definition, admission,
    )?)
}

/// The fake cost of each synthetic operator: 2 µs per token for the input block and
/// each decoder layer, 1 µs for the head; 8000 activation bytes and, except for the
/// head, 4000 KV bytes per token.
pub fn synthetic_costs() -> Vec<OperatorCost> {
    (0..SYNTHETIC_OPERATORS)
        .map(|index| {
            let head = index + 1 == SYNTHETIC_OPERATORS;
            OperatorCost {
                compute_seconds_per_token: if head { 1e-6 } else { 2e-6 },
                activation_bytes_per_token: 8_000,
                kv_bytes_per_token: if head { 0 } else { 4_000 },
            }
        })
        .collect()
}

/// In-place handoff with 10 µs keying and 10 µs lookup.
pub const SYNTHETIC_HANDOFF: HandoffCosts = HandoffCosts {
    keying_seconds: 1e-5,
    lookup_seconds: 1e-5,
    handoff: StateHandoff::InPlace,
};

/// The three pairs of the first prototype (line 898).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrototypePair {
    /// B keeps the input block and decoder layers 1–5, adds an unmerged adapter on layer
    /// 6 and replaces the task head.
    VerifiedSharedPrefix,
    /// B differs from A in the first block only.
    ControlFirstBlockDiffers,
    /// B has A's weights under another rotary base.
    EqualWeightsDifferentPositions,
}

impl PrototypePair {
    pub const ALL: [Self; 3] = [
        Self::VerifiedSharedPrefix,
        Self::ControlFirstBlockDiffers,
        Self::EqualWeightsDifferentPositions,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::VerifiedSharedPrefix => "verified-shared-prefix",
            Self::ControlFirstBlockDiffers => "control-first-block-differs",
            Self::EqualWeightsDifferentPositions => "equal-weights-different-positions",
        }
    }
}

/// Two variants of one family with their fake costs.
#[derive(Clone, Debug, PartialEq)]
pub struct PrototypeFamily {
    pub pair: PrototypePair,
    pub a: ImmutableVariant,
    pub b: ImmutableVariant,
    /// Per operator; both variants have the synthetic architecture.
    pub costs: Vec<OperatorCost>,
    pub handoff: HandoffCosts,
}

/// The family of `pair` in `scope`.
pub fn prototype_family(
    pair: PrototypePair,
    scope: TrustScope,
) -> Result<PrototypeFamily, SyntheticError> {
    let a = synthetic_variant(
        &synthetic_model(REFERENCE_ROPE_THETA, &[]),
        REFERENCE_ROPE_THETA,
        scope,
        None,
    )?;
    let b = match pair {
        PrototypePair::VerifiedSharedPrefix => synthetic_variant(
            &synthetic_model(REFERENCE_ROPE_THETA, &["head.weight"]),
            REFERENCE_ROPE_THETA,
            scope,
            Some(&["layers.6.proj"]),
        )?,
        PrototypePair::ControlFirstBlockDiffers => synthetic_variant(
            &synthetic_model(REFERENCE_ROPE_THETA, &["layers.0.weight"]),
            REFERENCE_ROPE_THETA,
            scope,
            None,
        )?,
        PrototypePair::EqualWeightsDifferentPositions => {
            let theta = 500_000;
            synthetic_variant(&synthetic_model(theta, &[]), theta, scope, None)?
        }
    };
    Ok(PrototypeFamily {
        pair,
        a,
        b,
        costs: synthetic_costs(),
        handoff: SYNTHETIC_HANDOFF,
    })
}
