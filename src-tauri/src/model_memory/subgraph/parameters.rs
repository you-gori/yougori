//! Exact parameter identities derived from a validated manifest (GPU §4.16 line 890: "Use
//! manifest-derived parameter identities"; §3.3 lines 529–531).
//!
//! A tensor's identity binds its interpretation (dtype, shape, layout, true length, rank
//! ownership and the manifest's exact quantization) and its bytes, through the decoded
//! content keys of the integrity extents that cover it and the tensor's offset inside the
//! first of them. Equal identities therefore mean equal bytes read the same way. The
//! converse does not hold: a tensor that shares an extent with a changed neighbour, or
//! sits at another offset relative to the extent grid, gets a different identity. That
//! loses sharing but never invents it. Tensor names are not bound: a name never makes two
//! parameters equal (§3.2 line 504), and the operator ABI fixes each parameter's role.

use std::fmt;

use crate::foundation::ids::Digest;
use crate::model_memory::manifest::{
    quantization_parameters_digest, RematerializedBuffer, TensorDtype, TensorEntry, TensorLayout,
    TensorOwner, ValidatedManifest,
};

use super::canon::Canon;

/// Domain of [`ParameterIdentity`].
pub const PARAMETER_DOMAIN: &str = "yougori/model-memory/subgraph/parameter/v1";

/// The exact identity of one parameter tensor or rematerialized buffer (line 884
/// "exact parameter identities"). Built only by [`ParameterIdentity::from_manifest`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParameterIdentity(Digest);

/// Why a parameter identity could not be derived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParameterError {
    /// The manifest has no tensor, alias or rematerialized buffer of this name.
    Unknown { name: String },
    /// The manifest's extents do not cover the tensor's bytes contiguously.
    NotCovered { name: String },
}

impl fmt::Display for ParameterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown { name } => write!(f, "the manifest has no parameter {name:?}"),
            Self::NotCovered { name } => {
                write!(f, "the manifest's extents do not cover parameter {name:?}")
            }
        }
    }
}

impl std::error::Error for ParameterError {}

impl ParameterIdentity {
    /// The identity of the tensor named `name` (following an alias to its target), or of
    /// the rematerialized buffer of that name. A rematerialized buffer is rebuilt from
    /// the model configuration, so its identity binds the configuration digest and the
    /// reconstruction code's identity.
    pub fn from_manifest(manifest: &ValidatedManifest, name: &str) -> Result<Self, ParameterError> {
        if let Some(tensor) = manifest.tensor(name) {
            return from_tensor(manifest, tensor, name);
        }
        manifest
            .manifest()
            .state
            .rematerialized_buffers
            .iter()
            .find(|buffer| buffer.name.as_str() == name)
            .map(|buffer| from_rematerialized(manifest, buffer))
            .ok_or_else(|| ParameterError::Unknown {
                name: name.to_owned(),
            })
    }

    pub const fn digest(&self) -> &Digest {
        &self.0
    }
}

impl fmt::Debug for ParameterIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ParameterIdentity({})", self.0.to_hex())
    }
}

impl fmt::Display for ParameterIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_hex())
    }
}

fn dtype_part(canon: Canon, dtype: TensorDtype) -> Canon {
    match dtype {
        TensorDtype::Element(element) => canon.tag("element").text(element.safetensors_name()),
        TensorDtype::Ggml(ggml) => canon.tag("ggml").u64(ggml.id().into()),
    }
}

fn shape_part(canon: Canon, shape: &[u64]) -> Canon {
    shape
        .iter()
        .fold(canon.count(shape.len()), |canon, dimension| {
            canon.u64(*dimension)
        })
}

fn from_tensor(
    manifest: &ValidatedManifest,
    tensor: &TensorEntry,
    name: &str,
) -> Result<ParameterIdentity, ParameterError> {
    let not_covered = || ParameterError::NotCovered {
        name: name.to_owned(),
    };
    let end_bytes = tensor
        .offset_bytes
        .checked_add(tensor.true_length_bytes)
        .ok_or_else(not_covered)?;
    let range =
        manifest.extents_covering(tensor.file, tensor.offset_bytes, tensor.true_length_bytes);
    let extents = manifest
        .manifest()
        .extents
        .extents
        .get(range)
        .ok_or_else(not_covered)?;
    let offset_in_first_bytes = match extents.first() {
        None if tensor.true_length_bytes == 0 => 0,
        None => return Err(not_covered()),
        Some(first) => {
            let mut next_bytes = first.logical_offset_bytes;
            for extent in extents {
                if extent.file != tensor.file || extent.logical_offset_bytes != next_bytes {
                    return Err(not_covered());
                }
                next_bytes = extent.end_bytes().ok_or_else(not_covered)?;
            }
            if first.logical_offset_bytes > tensor.offset_bytes || next_bytes < end_bytes {
                return Err(not_covered());
            }
            tensor.offset_bytes - first.logical_offset_bytes
        }
    };
    let canon = dtype_part(Canon::new(PARAMETER_DOMAIN).tag("tensor"), tensor.dtype);
    let canon = shape_part(canon, &tensor.shape)
        .tag(match tensor.layout {
            TensorLayout::RowMajor => "row_major",
            TensorLayout::GgmlInnermostFirst => "ggml_innermost_first",
        })
        .u64(tensor.true_length_bytes);
    let canon = match tensor.owner {
        TensorOwner::Replicated => canon.tag("replicated"),
        TensorOwner::Rank(rank) => canon.tag("rank").u64(rank.into()),
        TensorOwner::Expert { expert, rank } => {
            canon.tag("expert").u64(expert.into()).u64(rank.into())
        }
    };
    let quantization = quantization_parameters_digest(&manifest.manifest().semantics.quantization);
    let canon = canon
        .optional_digest(quantization.as_ref())
        .u64(offset_in_first_bytes)
        .count(extents.len());
    Ok(ParameterIdentity(
        extents
            .iter()
            .fold(canon, |canon, extent| {
                canon
                    .u64(extent.true_length_bytes)
                    .digest(extent.content_key.digest())
            })
            .finish(),
    ))
}

fn from_rematerialized(
    manifest: &ValidatedManifest,
    buffer: &RematerializedBuffer,
) -> ParameterIdentity {
    let canon = dtype_part(
        Canon::new(PARAMETER_DOMAIN).tag("rematerialized"),
        buffer.dtype,
    );
    ParameterIdentity(
        shape_part(canon, &buffer.shape)
            .text(buffer.reconstruction.name.as_str())
            .text(buffer.reconstruction.version.as_str())
            .digest(&manifest.manifest().semantics.configuration_digest)
            .finish(),
    )
}
