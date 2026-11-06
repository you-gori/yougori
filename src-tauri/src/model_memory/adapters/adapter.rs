//! Adapters reference a base identity, layer mapping, rank and scale, and are checked
//! for compatibility before admission (GPU §3.9 line 632).
//!
//! Identities are T07's ([`crate::model_memory::identity`]): an adapter is named by its
//! [`AdapterIdentity`] and refers to the [`LogicalModelIdentity`] it was made for. Only
//! identities establish compatibility; equal model names or file sizes never do (§3.2
//! line 504). [`super::graph::DependencyGraph::admit_adapter`] runs
//! [`check_compatibility`] against the resident base before the adapter becomes a node.

use std::collections::BTreeMap;
use std::fmt;

use crate::model_memory::identity::{AdapterIdentity, LogicalModelIdentity, MergeScale};

/// Longest accepted layer name.
pub const MAX_LAYER_NAME_LEN: usize = 256;

/// The input and output features of one adaptable projection (line 632).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LayerShape {
    pub input_features: u64,
    pub output_features: u64,
}

/// Adaptable layers by name, such as `model.layers.0.self_attn.q_proj`, with their
/// shapes. A base declares its own; an adapter's layer mapping names the layers it
/// targets and the shapes it was trained for (line 632).
pub type LayerTable = BTreeMap<String, LayerShape>;

/// What an adapter references (line 632).
#[derive(Clone, Debug, PartialEq)]
pub struct AdapterReference {
    /// T07's identity of the adapter's canonical weights.
    pub adapter: AdapterIdentity,
    /// The logical base the adapter was made for: its weights, dtype, quantization and
    /// tokenizer.
    pub base: LogicalModelIdentity,
    /// The layer mapping: each base layer the adapter targets, with its expected shape.
    pub layers: LayerTable,
    /// Rank of the low-rank update.
    pub rank: u32,
    /// Scale applied to the update; T07 keeps it finite and non-zero.
    pub scale: MergeScale,
}

/// What the serving engine supports for adapters (line 632).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdapterLimits {
    /// Largest adapter rank the engine's batched adapter kernels accept.
    pub max_rank: u32,
}

/// Why an adapter was refused before admission (line 632).
#[derive(Clone, Debug, PartialEq)]
pub enum AdapterRefusal {
    /// The adapter was made for another base identity.
    BaseMismatch {
        expected: LogicalModelIdentity,
        actual: LogicalModelIdentity,
    },
    EmptyLayerMapping,
    /// A layer name is empty, too long or contains a control character.
    InvalidLayerName {
        layer: String,
    },
    /// The base has no layer of this name.
    UnknownLayer {
        layer: String,
    },
    /// The base layer has another shape than the adapter expects.
    ShapeMismatch {
        layer: String,
        base: LayerShape,
        adapter: LayerShape,
    },
    ZeroRank,
    RankAboveEngineLimit {
        rank: u32,
        max_rank: u32,
    },
    /// The rank exceeds the smaller dimension of a target layer.
    RankAboveLayer {
        layer: String,
        rank: u32,
    },
}

impl fmt::Display for AdapterRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BaseMismatch { expected, actual } => write!(
                f,
                "the adapter was made for base {actual}, not the resident base {expected}"
            ),
            Self::EmptyLayerMapping => f.write_str("the adapter maps no layers"),
            Self::InvalidLayerName { layer } => write!(f, "invalid layer name {layer:?}"),
            Self::UnknownLayer { layer } => write!(f, "the base has no layer {layer:?}"),
            Self::ShapeMismatch {
                layer,
                base,
                adapter,
            } => write!(
                f,
                "layer {layer:?} is {}x{} in the base but {}x{} in the adapter",
                base.input_features,
                base.output_features,
                adapter.input_features,
                adapter.output_features
            ),
            Self::ZeroRank => f.write_str("the adapter rank is zero"),
            Self::RankAboveEngineLimit { rank, max_rank } => write!(
                f,
                "adapter rank {rank} is above the engine's limit of {max_rank}"
            ),
            Self::RankAboveLayer { layer, rank } => {
                write!(
                    f,
                    "adapter rank {rank} is above the dimensions of {layer:?}"
                )
            }
        }
    }
}

impl std::error::Error for AdapterRefusal {}

/// True for a usable layer name: 1–256 characters without control characters.
pub(crate) fn is_layer_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= MAX_LAYER_NAME_LEN
        && !name.chars().any(char::is_control)
}

/// Checks an adapter against a resident base before admission (line 632): the base
/// identity, the engine's rank limit, then every mapped layer's name, shape and rank
/// bound. The scale was checked when its [`MergeScale`] was made.
pub fn check_compatibility(
    base: &LogicalModelIdentity,
    base_layers: &LayerTable,
    reference: &AdapterReference,
    limits: &AdapterLimits,
) -> Result<(), AdapterRefusal> {
    if reference.base != *base {
        return Err(AdapterRefusal::BaseMismatch {
            expected: *base,
            actual: reference.base,
        });
    }
    if reference.rank == 0 {
        return Err(AdapterRefusal::ZeroRank);
    }
    if reference.rank > limits.max_rank {
        return Err(AdapterRefusal::RankAboveEngineLimit {
            rank: reference.rank,
            max_rank: limits.max_rank,
        });
    }
    if reference.layers.is_empty() {
        return Err(AdapterRefusal::EmptyLayerMapping);
    }
    for (layer, shape) in &reference.layers {
        if !is_layer_name(layer) {
            return Err(AdapterRefusal::InvalidLayerName {
                layer: layer.clone(),
            });
        }
        let base_shape = base_layers
            .get(layer)
            .ok_or_else(|| AdapterRefusal::UnknownLayer {
                layer: layer.clone(),
            })?;
        if base_shape != shape {
            return Err(AdapterRefusal::ShapeMismatch {
                layer: layer.clone(),
                base: *base_shape,
                adapter: *shape,
            });
        }
        let smaller_dimension = shape.input_features.min(shape.output_features);
        if u64::from(reference.rank) > smaller_dimension {
            return Err(AdapterRefusal::RankAboveLayer {
                layer: layer.clone(),
                rank: reference.rank,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
