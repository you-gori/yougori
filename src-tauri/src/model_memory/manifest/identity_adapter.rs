//! Adapter of the identity port over the committed identity layers (T07,
//! `model_memory::identity`; GPU part §3.2).
//!
//! The listing and the manifest supply what they record: files with their whole-file
//! content keys, the immutable revision, the configuration and tokenizer digests, the
//! dtype, the exact quantization, the runner, architecture adapter and kernel identifiers,
//! and the rank topology. A [`LayerContext`] supplies the inputs they do not record, such
//! as the licence or the GPU architectures an execution is built for. Where both name a
//! field they must agree, or the identity is refused, so an import is never keyed by an
//! identity its manifest does not describe, and two manifests that differ in quantization
//! parameters or kernels never share an execution identity (§3.2 items 2–3; line 504).
//! The artifact identity is built by `ArtifactIdentity::from_manifest_digest`.

use std::collections::BTreeSet;

use crate::foundation::ids::{Digest, DigestBuilder};
use crate::model_memory::identity as layers;

use super::digests::ManifestDigest;
use super::groups::{
    ComputeCapability, ExecutionAbi, HardwareRestriction, Manifest, Quantization, SourceOrigin,
    SourceRevision,
};
use super::ports::{
    ArtifactIdentity, ExecutionIdentity, IdentityError, ImportKey, ModelIdentities, SourceIdentity,
};
use super::source::SourceListing;
use super::types::{ElementType, RelativePath, Token};
use super::validate::ValidatedManifest;

/// The host of Hugging Face repositories in a source location.
pub const HUGGING_FACE_HOST: &str = "huggingface.co";
/// Domain of [`quantization_parameters_digest`]: the method, then every parameter.
pub const QUANTIZATION_PARAMETERS_DOMAIN: &str =
    "yougori/model-memory/manifest/quantization-parameters/v1";
/// Domain of the digest [`kernel_layout`] names a manifest's kernel identifiers by.
pub const KERNEL_SET_DOMAIN: &str = "yougori/model-memory/manifest/kernel-set/v1";
/// Name of the kernel layout [`kernel_layout`] derives from a manifest.
pub const KERNEL_SET_NAME: &str = "kernel-set";

/// The identity-layer inputs of one import that its listing and manifest do not record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerContext {
    /// Must match the listing's origin: a local folder is a local source, and any other
    /// origin is a repository of the same name (on [`HUGGING_FACE_HOST`] for Hugging Face).
    pub location: layers::SourceLocation,
    pub license: layers::Label,
    pub provenance: Option<Digest>,
    pub published_dtype: layers::Dtype,
    /// Must be quantized exactly when the manifest is. A scheme's method name is the
    /// manifest's method, its parameters digest is [`quantization_parameters_digest`] of
    /// the manifest's quantization, and its weight bits and group size equal the
    /// manifest's `bits` and `group_size` parameters wherever those are integers.
    pub quantization: layers::Quantization,
    pub generation_config: Digest,
    /// Must merge exactly the manifest's adapters, in order.
    pub adapters: layers::AdapterRecipe,
    pub code_policy: layers::CodePolicy,
    /// Each must fit the manifest's hardware restriction.
    pub gpu_architectures: BTreeSet<layers::Label>,
    /// Its name must be the manifest's processed-weight layout.
    pub processed_weights: layers::VersionedName,
    pub compile: layers::CompileConfiguration,
}

/// The identity port over the committed identity layers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IdentityLayers;

fn refused(error: layers::IdentityError) -> IdentityError {
    IdentityError::Refused {
        detail: error.to_string(),
    }
}

fn label(text: &str) -> Result<layers::Label, IdentityError> {
    layers::Label::new(text).map_err(refused)
}

fn versioned(name: &str, version: &str) -> Result<layers::VersionedName, IdentityError> {
    layers::VersionedName::new(name, version).map_err(refused)
}

/// The digest of a manifest's exact quantization (§3.3 semantics: "exact quantization
/// parameters"): the method and every parameter in key order; `None` when unquantized.
/// The identity layers' scheme for a quantized manifest carries it as its parameters
/// digest, so two parameter sets never share a logical identity.
pub fn quantization_parameters_digest(quantization: &Quantization) -> Option<Digest> {
    let Quantization::Method { method, parameters } = quantization else {
        return None;
    };
    let mut sorted: Vec<&(Token, Token)> = parameters.iter().collect();
    sorted.sort();
    let builder = DigestBuilder::new(QUANTIZATION_PARAMETERS_DOMAIN)
        .str(method.as_str())
        .u64(sorted.len() as u64);
    Some(
        sorted
            .iter()
            .fold(builder, |builder, (key, value)| {
                builder.str(key.as_str()).str(value.as_str())
            })
            .finish(),
    )
}

/// The kernel layout of an execution ABI (§3.2 item 3: kernel/layout version):
/// [`KERNEL_SET_NAME`] at the digest of its kernel identifiers in order, so two kernel
/// sets never share an execution identity. It is derived, never taken from a caller.
pub fn kernel_layout(abi: &ExecutionAbi) -> Result<layers::VersionedName, IdentityError> {
    let mut kernels: Vec<&Token> = abi.kernels.iter().collect();
    kernels.sort();
    let builder = DigestBuilder::new(KERNEL_SET_DOMAIN).u64(kernels.len() as u64);
    let digest = kernels
        .iter()
        .fold(builder, |builder, kernel| builder.str(kernel.as_str()))
        .finish();
    versioned(KERNEL_SET_NAME, &digest.to_hex())
}

/// Refuses a context quantization that is not the manifest's exact one.
fn check_quantization(
    manifest: &Quantization,
    context: &layers::Quantization,
) -> Result<(), IdentityError> {
    let inconsistent = |field| Err(IdentityError::Inconsistent { field });
    let (Quantization::Method { method, parameters }, layers::Quantization::Scheme(scheme)) =
        (manifest, context)
    else {
        return match (manifest, context) {
            (Quantization::None, layers::Quantization::None) => Ok(()),
            _ => inconsistent("quantization"),
        };
    };
    if scheme.method().name.as_str() != method.as_str() {
        return inconsistent("quantization method");
    }
    if quantization_parameters_digest(manifest).as_ref() != Some(scheme.parameters()) {
        return inconsistent("quantization parameters");
    }
    for (key, value) in parameters {
        let (agrees, field) = match key.as_str() {
            "bits" => (
                match value.as_str().parse::<u8>() {
                    Ok(bits) => bits == scheme.weight_bits(),
                    Err(_) => true,
                },
                "quantization bits",
            ),
            "group_size" => (
                match value.as_str().parse::<u32>() {
                    Ok(group) => Some(group) == scheme.group_size(),
                    Err(_) => true,
                },
                "quantization group size",
            ),
            _ => (true, ""),
        };
        if !agrees {
            return inconsistent(field);
        }
    }
    Ok(())
}

/// The identity layers' dtype of a compute element type; `None` where they have none.
pub fn layer_dtype(element: ElementType) -> Option<layers::Dtype> {
    match element {
        ElementType::F64 => Some(layers::Dtype::Float64),
        ElementType::F32 => Some(layers::Dtype::Float32),
        ElementType::F16 => Some(layers::Dtype::Float16),
        ElementType::Bf16 => Some(layers::Dtype::BFloat16),
        ElementType::F8E4m3 => Some(layers::Dtype::Float8E4M3),
        ElementType::F8E5m2 => Some(layers::Dtype::Float8E5M2),
        ElementType::F4 => Some(layers::Dtype::Float4E2M1),
        ElementType::I8 => Some(layers::Dtype::Int8),
        ElementType::U8 => Some(layers::Dtype::UInt8),
        ElementType::Bool
        | ElementType::F8E8m0
        | ElementType::I16
        | ElementType::U16
        | ElementType::I32
        | ElementType::U32
        | ElementType::I64
        | ElementType::U64
        | ElementType::F6E2m3
        | ElementType::F6E3m2 => None,
    }
}

/// The compute capability a GPU architecture label such as `sm_90a` names: the digits
/// after `sm_`, the last of them the minor version, with an optional letter suffix.
pub fn compute_capability(architecture: &str) -> Option<ComputeCapability> {
    let digits = architecture
        .strip_prefix("sm_")?
        .trim_end_matches(|character: char| character.is_ascii_lowercase());
    if digits.len() < 2 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let (major, minor) = digits.split_at(digits.len() - 1);
    Some(ComputeCapability {
        major: major.parse().ok()?,
        minor: minor.parse().ok()?,
    })
}

fn check_location(
    origin: &SourceOrigin,
    location: &layers::SourceLocation,
) -> Result<(), IdentityError> {
    let agrees = match (origin, location) {
        (SourceOrigin::LocalFolder, layers::SourceLocation::Local { .. }) => true,
        (
            SourceOrigin::HuggingFace { repository: name },
            layers::SourceLocation::Repository { host, repository },
        ) => host.as_str() == HUGGING_FACE_HOST && repository.as_str() == name.as_str(),
        (
            SourceOrigin::Registry { model: name } | SourceOrigin::Publisher { publisher: name },
            layers::SourceLocation::Repository { repository, .. },
        ) => repository.as_str() == name.as_str(),
        _ => false,
    };
    if agrees {
        Ok(())
    } else {
        Err(IdentityError::Inconsistent {
            field: "source location",
        })
    }
}

fn layer_revision(revision: &SourceRevision) -> Result<layers::ImmutableRevision, IdentityError> {
    match revision {
        SourceRevision::GitCommit(commit) => Ok(layers::ImmutableRevision::Commit(
            layers::CommitId::new(&commit.to_hex()).map_err(refused)?,
        )),
        SourceRevision::ContentListing(_) => Ok(layers::ImmutableRevision::FileDigests),
    }
}

fn layer_file(
    path: &RelativePath,
    length_bytes: u64,
    content: crate::foundation::ids::ContentKey,
) -> Result<layers::SourceFile, IdentityError> {
    Ok(layers::SourceFile {
        path: layers::RelativePath::new(path.as_str()).map_err(refused)?,
        length_bytes,
        content,
    })
}

impl IdentityLayers {
    /// The source spec of a verified listing whose configuration digests to
    /// `configuration` (§3.2 item 1).
    pub fn listing_source_spec(
        listing: &SourceListing,
        configuration: &Digest,
        context: &LayerContext,
    ) -> Result<layers::SourceSpec, IdentityError> {
        check_location(&listing.origin, &context.location)?;
        Ok(layers::SourceSpec {
            location: context.location.clone(),
            revision: layer_revision(&listing.revision)?,
            files: listing
                .files
                .iter()
                .map(|file| layer_file(&file.path, file.length_bytes, file.content))
                .collect::<Result<_, _>>()?,
            configuration: *configuration,
            published_dtype: context.published_dtype,
            license: context.license.clone(),
            provenance: context.provenance,
        })
    }

    /// The source spec a manifest records (§3.2 item 1).
    pub fn manifest_source_spec(
        manifest: &Manifest,
        context: &LayerContext,
    ) -> Result<layers::SourceSpec, IdentityError> {
        let provenance = &manifest.provenance;
        check_location(&provenance.origin, &context.location)?;
        Ok(layers::SourceSpec {
            location: context.location.clone(),
            revision: layer_revision(&provenance.revision)?,
            files: provenance
                .files
                .iter()
                .map(|file| layer_file(&file.path, file.length_bytes, file.content))
                .collect::<Result<_, _>>()?,
            configuration: manifest.semantics.configuration_digest,
            published_dtype: context.published_dtype,
            license: context.license.clone(),
            provenance: context.provenance,
        })
    }

    /// The logical model spec of a manifest over `source` (§3.2 item 2).
    pub fn logical_spec(
        source: layers::SourceIdentity,
        manifest: &Manifest,
        context: &LayerContext,
    ) -> Result<layers::LogicalModelSpec, IdentityError> {
        let semantics = &manifest.semantics;
        let dtype = layer_dtype(semantics.compute_dtype).ok_or(IdentityError::Incomplete {
            field: "compute dtype",
        })?;
        check_quantization(&semantics.quantization, &context.quantization)?;
        let merged: Vec<Digest> = match &context.adapters {
            layers::AdapterRecipe::None => Vec::new(),
            layers::AdapterRecipe::Merged(merged) => merged
                .adapters()
                .iter()
                .map(|adapter| *adapter.adapter.digest())
                .collect(),
        };
        if merged != semantics.adapters {
            return Err(IdentityError::Inconsistent { field: "adapters" });
        }
        Ok(layers::LogicalModelSpec {
            source,
            dtype,
            quantization: context.quantization.clone(),
            tokenizer: semantics.tokenizer_digest,
            generation_config: context.generation_config,
            adapters: context.adapters.clone(),
            code_policy: context.code_policy.clone(),
        })
    }

    /// The execution spec of a manifest over `logical` (§3.2 item 3).
    pub fn execution_spec(
        logical: layers::LogicalModelIdentity,
        manifest: &Manifest,
        context: &LayerContext,
    ) -> Result<layers::ExecutionSpec, IdentityError> {
        let abi = &manifest.execution_abi;
        if context.processed_weights.name.as_str() != abi.layout.as_str() {
            return Err(IdentityError::Inconsistent {
                field: "processed-weight layout",
            });
        }
        if let HardwareRestriction::ComputeCapabilities(allowed) = &abi.hardware {
            let fits = context.gpu_architectures.iter().all(|architecture| {
                compute_capability(architecture.as_str())
                    .is_some_and(|capability| allowed.contains(&capability))
            });
            if !fits {
                return Err(IdentityError::Inconsistent {
                    field: "GPU architectures",
                });
            }
        }
        let distribution = &manifest.distribution;
        Ok(layers::ExecutionSpec {
            logical,
            runner: versioned(abi.runner.backend.tag(), abi.runner.version.as_str())?,
            architecture_adapter: layers::VersionedName {
                name: label(abi.architecture_adapter.name.as_str())?,
                version: label(abi.architecture_adapter.version.as_str())?,
            },
            kernel_layout: kernel_layout(abi)?,
            gpu_architectures: context.gpu_architectures.clone(),
            topology: layers::RankTopology::new(
                distribution.tensor_parallel_size,
                distribution.pipeline_parallel_size,
                distribution.expert_parallel_size,
            )
            .map_err(refused)?,
            processed_weights: context.processed_weights.clone(),
            compile: context.compile.clone(),
        })
    }

    /// The import key of a source and execution identity built by the identity layers.
    pub fn import_key(
        source: &layers::SourceIdentity,
        execution: &layers::ExecutionIdentity,
    ) -> ImportKey {
        ImportKey {
            source: SourceIdentity(*source.digest()),
            execution: ExecutionIdentity(*execution.digest()),
        }
    }
}

impl ModelIdentities for IdentityLayers {
    type Context = LayerContext;

    fn source_identity(
        &self,
        listing: &SourceListing,
        configuration: &Digest,
        context: &LayerContext,
    ) -> Result<SourceIdentity, IdentityError> {
        let identity = Self::listing_source_spec(listing, configuration, context)?
            .identity()
            .map_err(refused)?;
        Ok(SourceIdentity(*identity.digest()))
    }

    fn execution_identity(
        &self,
        source: &SourceIdentity,
        manifest: &ValidatedManifest,
        context: &LayerContext,
    ) -> Result<ExecutionIdentity, IdentityError> {
        let manifest = manifest.manifest();
        let recorded = Self::manifest_source_spec(manifest, context)?
            .identity()
            .map_err(refused)?;
        if *recorded.digest() != source.0 {
            return Err(IdentityError::Inconsistent {
                field: "source identity",
            });
        }
        let logical = Self::logical_spec(recorded, manifest, context)?.identity();
        let execution = Self::execution_spec(logical, manifest, context)?
            .identity()
            .map_err(refused)?;
        Ok(ExecutionIdentity(*execution.digest()))
    }

    fn artifact_identity(&self, manifest: &ManifestDigest) -> ArtifactIdentity {
        let identity = layers::ArtifactIdentity::from_manifest_digest(&manifest.digest());
        ArtifactIdentity(*identity.digest())
    }
}
