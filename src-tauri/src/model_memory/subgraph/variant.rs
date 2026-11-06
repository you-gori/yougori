//! Immutable model variants as chains of executable operators (GPU §4.16 lines 880–890).
//!
//! A variant is built only from a validated manifest: every parameter identity comes from
//! that manifest, and the artifact identity is derived from its digest, never supplied.
//! An unmerged adapter passes the §3.9 compatibility check (line 632) before it becomes
//! the adapter effect of the operators whose layers it targets. Attention and position
//! semantics and the deterministic execution profile are properties of the whole variant
//! and enter every operator's state key, so a change in any of them changes the key of
//! the very first operator.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::foundation::ids::{Digest, TrustScope};
use crate::model_memory::adapters::adapter::{
    check_compatibility, AdapterLimits, AdapterReference, AdapterRefusal, LayerShape, LayerTable,
};
use crate::model_memory::identity::{
    AdapterIdentity, ArtifactIdentity, Dtype, ExecutionIdentity, LogicalModelIdentity, MergeScale,
    PositionalEncoding, VersionedName,
};
use crate::model_memory::manifest::ValidatedManifest;

use super::canon::Canon;
use super::parameters::{ParameterError, ParameterIdentity};

/// Domain of [`VariantIdentity`].
pub const VARIANT_DOMAIN: &str = "yougori/model-memory/subgraph/variant/v1";

/// The operator and the kernel ABI it runs with (line 884 "operator/kernel ABI").
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OperatorAbi {
    /// What the operator computes, such as one decoder layer of an architecture adapter.
    pub operator: VersionedName,
    /// The kernel implementation and its ABI version.
    pub kernel: VersionedName,
}

impl OperatorAbi {
    pub(super) fn write(&self, canon: Canon) -> Canon {
        canon.versioned(&self.operator).versioned(&self.kernel)
    }
}

/// Attention semantics (line 885): masking, windows, sink tokens and every runtime
/// attention option, as a scheme and the digest of its exact parameters.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AttentionSemantics {
    pub scheme: VersionedName,
    pub parameters: Digest,
}

impl AttentionSemantics {
    pub(super) fn write(&self, canon: Canon) -> Canon {
        canon.versioned(&self.scheme).digest(&self.parameters)
    }
}

/// The dtype and layout of an operator's output state (line 885 "dtype/layout").
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TensorFormat {
    pub dtype: Dtype,
    pub layout: VersionedName,
}

impl TensorFormat {
    pub(super) fn write(&self, canon: Canon) -> Canon {
        canon.dtype(self.dtype).versioned(&self.layout)
    }
}

/// Whether an operator draws random numbers or carries state across calls (line 888:
/// "Runtime seeds and stateful operators either enter the identity or disqualify
/// reuse"). A seeded or stateful operator needs its seed or state bound per request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OperatorRuntime {
    Stateless,
    Seeded,
    Stateful,
}

impl OperatorRuntime {
    pub(super) fn tag(self) -> &'static str {
        match self {
            Self::Stateless => "stateless",
            Self::Seeded => "seeded",
            Self::Stateful => "stateful",
        }
    }
}

/// Whether the kernels give the same bits on every run (line 892).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KernelDeterminism {
    Deterministic,
    /// Atomics, autotuning or another run-to-run variation; never exact.
    NonDeterministic,
}

/// Whether a request's result depends on what it is batched with (line 892).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BatchDependence {
    BatchInvariant,
    /// Split reductions or tiling chosen by batch shape; never exact across batches.
    BatchDependent,
}

/// The deterministic execution profile (line 886): the kernel set, its determinism and
/// batch dependence, and the digest of the math mode (TF32, fast-math and similar
/// switches).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExecutionProfile {
    pub kernels: VersionedName,
    pub determinism: KernelDeterminism,
    pub batching: BatchDependence,
    pub math_mode: Digest,
}

impl ExecutionProfile {
    pub(super) fn write(&self, canon: Canon) -> Canon {
        canon
            .versioned(&self.kernels)
            .tag(match self.determinism {
                KernelDeterminism::Deterministic => "deterministic",
                KernelDeterminism::NonDeterministic => "non_deterministic",
            })
            .tag(match self.batching {
                BatchDependence::BatchInvariant => "batch_invariant",
                BatchDependence::BatchDependent => "batch_dependent",
            })
            .digest(&self.math_mode)
    }
}

/// What an unmerged adapter changes in one operator (line 886 "adapter effects"): the
/// adapter, the base it was checked against, its rank and scale, and the operator's
/// layers it targets with their shapes. Built only by [`ImmutableVariant::from_manifest`]
/// after the §3.9 compatibility check.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AdapterEffect {
    adapter: AdapterIdentity,
    base: LogicalModelIdentity,
    rank: u32,
    scale: MergeScale,
    layers: Vec<(String, LayerShape)>,
}

impl AdapterEffect {
    pub fn adapter(&self) -> AdapterIdentity {
        self.adapter
    }

    pub fn base(&self) -> LogicalModelIdentity {
        self.base
    }

    pub fn rank(&self) -> u32 {
        self.rank
    }

    pub fn scale(&self) -> MergeScale {
        self.scale
    }

    /// The targeted layers of this operator, in name order.
    pub fn layers(&self) -> &[(String, LayerShape)] {
        &self.layers
    }

    pub(super) fn write(&self, canon: Canon) -> Canon {
        let canon = canon
            .digest(self.adapter.digest())
            .digest(self.base.digest())
            .u64(self.rank.into())
            .u64(self.scale.get().to_bits())
            .count(self.layers.len());
        self.layers.iter().fold(canon, |canon, (layer, shape)| {
            canon
                .text(layer)
                .u64(shape.input_features)
                .u64(shape.output_features)
        })
    }
}

/// One operator as declared for [`ImmutableVariant::from_manifest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorDefinition {
    pub abi: OperatorAbi,
    /// Manifest names of the operator's parameters in slot order; aliases and
    /// rematerialized buffers are accepted.
    pub tensors: Vec<String>,
    /// Names of the adaptable layers inside this operator, as adapter layer mappings
    /// name them (§3.9 line 632). Each name belongs to one operator.
    pub adaptable_layers: Vec<String>,
    pub output: TensorFormat,
    pub runtime: OperatorRuntime,
}

/// A variant as declared for [`ImmutableVariant::from_manifest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariantDefinition {
    /// T07's execution identity of the variant's weights as executed.
    pub execution: ExecutionIdentity,
    /// The trust and runtime domain the variant runs in (S3.3).
    pub trust_scope: TrustScope,
    pub attention: AttentionSemantics,
    pub position: PositionalEncoding,
    pub profile: ExecutionProfile,
    /// In execution order; the first consumes the request input.
    pub operators: Vec<OperatorDefinition>,
}

/// An unmerged adapter with what the §3.9 compatibility check needs (line 632).
#[derive(Clone, Copy, Debug)]
pub struct AdapterAdmission<'a> {
    pub reference: &'a AdapterReference,
    /// The logical base the adapter is attached to.
    pub base: &'a LogicalModelIdentity,
    /// The base's adaptable layers and their shapes.
    pub base_layers: &'a LayerTable,
    pub limits: &'a AdapterLimits,
}

/// Why a variant could not be built.
#[derive(Clone, Debug, PartialEq)]
pub enum SubgraphError {
    /// A variant needs at least one operator.
    NoOperators,
    /// An exact input covers at least one token.
    EmptySpan,
    Parameter(ParameterError),
    /// The §3.9 compatibility check refused the adapter (line 632).
    Adapter(AdapterRefusal),
    /// The adapter targets a layer that no operator declares.
    AdapterLayerNotMapped {
        layer: String,
    },
    /// Two operators declare the same adaptable layer.
    DuplicateAdaptableLayer {
        layer: String,
    },
}

impl fmt::Display for SubgraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoOperators => f.write_str("a variant needs at least one operator"),
            Self::EmptySpan => f.write_str("an exact input covers at least one token"),
            Self::Parameter(error) => error.fmt(f),
            Self::Adapter(refusal) => write!(f, "the adapter was refused: {refusal}"),
            Self::AdapterLayerNotMapped { layer } => {
                write!(
                    f,
                    "the adapter targets layer {layer:?}, which no operator declares"
                )
            }
            Self::DuplicateAdaptableLayer { layer } => {
                write!(f, "two operators declare adaptable layer {layer:?}")
            }
        }
    }
}

impl std::error::Error for SubgraphError {}

impl From<ParameterError> for SubgraphError {
    fn from(error: ParameterError) -> Self {
        Self::Parameter(error)
    }
}

/// One operator of an [`ImmutableVariant`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operator {
    abi: OperatorAbi,
    parameters: Vec<ParameterIdentity>,
    output: TensorFormat,
    adapter_effects: Vec<AdapterEffect>,
    runtime: OperatorRuntime,
}

impl Operator {
    pub fn abi(&self) -> &OperatorAbi {
        &self.abi
    }

    /// Manifest-derived parameter identities in slot order.
    pub fn parameters(&self) -> &[ParameterIdentity] {
        &self.parameters
    }

    pub fn output(&self) -> &TensorFormat {
        &self.output
    }

    pub fn adapter_effects(&self) -> &[AdapterEffect] {
        &self.adapter_effects
    }

    pub fn runtime(&self) -> OperatorRuntime {
        self.runtime
    }

    fn write(&self, canon: Canon) -> Canon {
        let canon = self.abi.write(canon).count(self.parameters.len());
        let canon = self
            .parameters
            .iter()
            .fold(canon, |canon, parameter| canon.digest(parameter.digest()));
        let canon = self.output.write(canon).count(self.adapter_effects.len());
        self.adapter_effects
            .iter()
            .fold(canon, |canon, effect| effect.write(canon))
            .tag(self.runtime.tag())
    }
}

/// The identity of an immutable variant: every field of it, including the unmerged
/// adapter, which the execution identity alone does not cover. Built only by
/// [`ImmutableVariant::identity`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VariantIdentity(Digest);

impl VariantIdentity {
    pub const fn digest(&self) -> &Digest {
        &self.0
    }
}

impl fmt::Debug for VariantIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VariantIdentity({})", self.0.to_hex())
    }
}

/// An immutable model variant (line 880): manifest-derived operators, the semantics and
/// profile bound into every state key, and the trust scope it runs in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImmutableVariant {
    execution: ExecutionIdentity,
    artifact: ArtifactIdentity,
    adapter: Option<AdapterIdentity>,
    trust_scope: TrustScope,
    attention: AttentionSemantics,
    position: PositionalEncoding,
    profile: ExecutionProfile,
    operators: Vec<Operator>,
}

impl ImmutableVariant {
    /// Builds a variant over `manifest`: every parameter identity is derived from it and
    /// the artifact identity is its digest under T07's artifact domain. An unmerged
    /// adapter must pass the §3.9 compatibility check (line 632) and every layer it
    /// targets must belong to exactly one operator.
    pub fn from_manifest(
        manifest: &ValidatedManifest,
        definition: VariantDefinition,
        adapter: Option<AdapterAdmission<'_>>,
    ) -> Result<Self, SubgraphError> {
        if definition.operators.is_empty() {
            return Err(SubgraphError::NoOperators);
        }
        let mut owners: BTreeMap<&str, usize> = BTreeMap::new();
        for (index, operator) in definition.operators.iter().enumerate() {
            for layer in &operator.adaptable_layers {
                if owners.insert(layer.as_str(), index).is_some() {
                    return Err(SubgraphError::DuplicateAdaptableLayer {
                        layer: layer.clone(),
                    });
                }
            }
        }
        if let Some(admission) = adapter {
            check_compatibility(
                admission.base,
                admission.base_layers,
                admission.reference,
                admission.limits,
            )
            .map_err(SubgraphError::Adapter)?;
            if let Some(layer) = admission
                .reference
                .layers
                .keys()
                .find(|layer| !owners.contains_key(layer.as_str()))
            {
                return Err(SubgraphError::AdapterLayerNotMapped {
                    layer: layer.clone(),
                });
            }
        }
        let operators = definition
            .operators
            .into_iter()
            .map(|operator| -> Result<Operator, SubgraphError> {
                let parameters = operator
                    .tensors
                    .iter()
                    .map(|name| ParameterIdentity::from_manifest(manifest, name))
                    .collect::<Result<Vec<_>, _>>()?;
                let adapter_effects = adapter
                    .and_then(|admission| effect_on(admission, &operator.adaptable_layers))
                    .into_iter()
                    .collect();
                Ok(Operator {
                    abi: operator.abi,
                    parameters,
                    output: operator.output,
                    adapter_effects,
                    runtime: operator.runtime,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            execution: definition.execution,
            artifact: ArtifactIdentity::from_manifest_digest(&manifest.digest().digest()),
            adapter: adapter.map(|admission| admission.reference.adapter),
            trust_scope: definition.trust_scope,
            attention: definition.attention,
            position: definition.position,
            profile: definition.profile,
            operators,
        })
    }

    pub fn execution(&self) -> ExecutionIdentity {
        self.execution
    }

    pub fn artifact(&self) -> ArtifactIdentity {
        self.artifact
    }

    /// The unmerged adapter, which is part of the full model identity (§3.9).
    pub fn adapter(&self) -> Option<AdapterIdentity> {
        self.adapter
    }

    pub fn trust_scope(&self) -> &TrustScope {
        &self.trust_scope
    }

    pub fn attention(&self) -> &AttentionSemantics {
        &self.attention
    }

    pub fn position(&self) -> &PositionalEncoding {
        &self.position
    }

    pub fn profile(&self) -> &ExecutionProfile {
        &self.profile
    }

    pub fn operators(&self) -> &[Operator] {
        &self.operators
    }

    /// The digest of every field of the variant under [`VARIANT_DOMAIN`].
    pub fn identity(&self) -> VariantIdentity {
        let canon = Canon::new(VARIANT_DOMAIN)
            .digest(self.execution.digest())
            .digest(self.artifact.digest())
            .optional_digest(self.adapter.as_ref().map(AdapterIdentity::digest))
            .scope(&self.trust_scope);
        let canon = self.attention.write(canon).positional(&self.position);
        let canon = self.profile.write(canon).count(self.operators.len());
        VariantIdentity(
            self.operators
                .iter()
                .fold(canon, |canon, operator| operator.write(canon))
                .finish(),
        )
    }
}

/// The admitted adapter's effect on an operator with `layers`, if it targets any.
fn effect_on(admission: AdapterAdmission<'_>, layers: &[String]) -> Option<AdapterEffect> {
    let targeted: BTreeSet<&String> = layers.iter().collect();
    let effect_layers: Vec<(String, LayerShape)> = admission
        .reference
        .layers
        .iter()
        .filter(|(layer, _)| targeted.contains(layer))
        .map(|(layer, shape)| (layer.clone(), *shape))
        .collect();
    (!effect_layers.is_empty()).then(|| AdapterEffect {
        adapter: admission.reference.adapter,
        base: admission.reference.base,
        rank: admission.reference.rank,
        scale: admission.reference.scale,
        layers: effect_layers,
    })
}
