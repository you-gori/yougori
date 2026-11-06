//! The six identity layers of §3.2.
//!
//! Each layer is a spec of typed fields and an identity: the digest of the spec's
//! canonical encoding under the layer's own domain. A layer binds the layer below it by
//! that layer's identity, so a change below changes every layer built on it.

use std::collections::BTreeSet;

use crate::foundation::ids::{
    ContentKey, Digest, GpuAllocationGeneration, GpuDeviceKey, LeaseId, ModelActivationGeneration,
    TenantId,
};

use super::adapter::{AdapterIdentity, AdapterRecipe, MergedAdapter, MergedAdapters};
use super::encoding::{
    identity_type, Encode, Encoding, ARTIFACT_DOMAIN, EXECUTION_DOMAIN, LOGICAL_DOMAIN,
    PLACEMENT_DOMAIN, SESSION_DOMAIN, SOURCE_DOMAIN,
};
use super::error::IdentityError;
use super::fields::{
    AuthorityBinding, CommitId, Dtype, KvRepresentation, Label, PositionalEncoding, Quantization,
    RelativePath, TokenPrefix, VersionedName,
};

identity_type!(
    /// §3.2 item 1: repository or local source, immutable revision, file digests, model
    /// configuration and licence/provenance. Built only by [`SourceSpec::identity`].
    SourceIdentity
);

identity_type!(
    /// §3.2 item 2: the source plus exact dtype/quantization, tokenizer,
    /// generation-relevant configuration, adapter recipe and code policy. Built only by
    /// [`LogicalModelSpec::identity`].
    LogicalModelIdentity
);

identity_type!(
    /// §3.2 item 3: the logical model plus runner/version, architecture adapter,
    /// kernel/layout version, GPU architecture constraints, rank topology,
    /// processed-weight format and compile configuration. One logical model may have
    /// several. Built only by [`ExecutionSpec::identity`].
    ExecutionIdentity
);

identity_type!(
    /// §3.2 item 4: binds the canonical manifest digest (§3.3). Built only by
    /// [`ArtifactIdentity::from_manifest_digest`].
    ArtifactIdentity
);

identity_type!(
    /// §3.2 item 5: artifact and execution identity, device, owner, the S3.1 authority
    /// binding, activation and allocation generations and the current leases. Built only
    /// by [`PlacementSpec::identity`].
    PlacementIdentity
);

identity_type!(
    /// §3.2 item 6: execution identity, token prefix/state, adapter, positional
    /// encoding, KV representation, tenant and the S3.1 authority binding. Built only by
    /// [`SessionSpec::identity`].
    SessionIdentity
);

/// Where a source comes from (§3.2 item 1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SourceLocation {
    /// A repository on a model hub or Git host, such as `huggingface.co` and `org/name`.
    Repository { host: Label, repository: Label },
    /// A source imported from this machine, under the name it was imported as.
    Local { name: Label },
}

/// The immutable revision of a source (§3.2 item 1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ImmutableRevision {
    Commit(CommitId),
    /// A local source without version control, whose file digests are its revision.
    FileDigests,
}

/// One file of a source: path, true length and the content key of its bytes (§3.2 item
/// 1 "file digests").
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SourceFile {
    pub path: RelativePath,
    pub length_bytes: u64,
    pub content: ContentKey,
}

/// The typed inputs of a [`SourceIdentity`] (§3.2 item 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceSpec {
    pub location: SourceLocation,
    pub revision: ImmutableRevision,
    /// In any order; the encoding sorts them by path, and a path may appear once.
    pub files: Vec<SourceFile>,
    /// Digest of the model configuration.
    pub configuration: Digest,
    /// The dtype the weights are published in, from the model configuration. A logical
    /// model in another dtype is checked against it (§1.3).
    pub published_dtype: Dtype,
    /// SPDX identifier, or the licence name as published.
    pub license: Label,
    /// Digest of a provenance statement such as a signed attestation, when one exists.
    pub provenance: Option<Digest>,
}

impl SourceSpec {
    /// §3.2 item 1. Refuses a repository without a commit, and an empty or duplicated
    /// file list.
    pub fn identity(&self) -> Result<SourceIdentity, IdentityError> {
        Ok(SourceIdentity(self.canonical()?.finish(SOURCE_DOMAIN)))
    }

    /// The sum of the file lengths, or `None` when it overflows 64 bits. Equal sizes
    /// never make two sources the same (line 504).
    pub fn total_length_bytes(&self) -> Option<u64> {
        self.files
            .iter()
            .try_fold(0u64, |total, file| total.checked_add(file.length_bytes))
    }

    pub(crate) fn canonical(&self) -> Result<Encoding, IdentityError> {
        if matches!(self.location, SourceLocation::Repository { .. })
            && self.revision == ImmutableRevision::FileDigests
        {
            return Err(IdentityError::RepositoryNeedsCommit);
        }
        let files = sorted_unique_files(&self.files)?;
        let mut out = Encoding::new();
        match &self.location {
            SourceLocation::Repository { host, repository } => {
                out.tag("repository").item(host).item(repository);
            }
            SourceLocation::Local { name } => {
                out.tag("local").item(name);
            }
        }
        match &self.revision {
            ImmutableRevision::Commit(commit) => {
                out.tag("commit").item(commit);
            }
            ImmutableRevision::FileDigests => {
                out.tag("file_digests");
            }
        }
        out.count(files.len());
        for file in files {
            out.item(&file.path)
                .u64(file.length_bytes)
                .item(&file.content);
        }
        out.item(&self.configuration)
            .item(&self.published_dtype)
            .item(&self.license)
            .option(self.provenance.as_ref());
        Ok(out)
    }
}

fn sorted_unique_files(files: &[SourceFile]) -> Result<Vec<&SourceFile>, IdentityError> {
    if files.is_empty() {
        return Err(IdentityError::NoSourceFiles);
    }
    let mut sorted: Vec<&SourceFile> = files.iter().collect();
    sorted.sort_by(|left, right| left.path.cmp(&right.path));
    let duplicate = sorted.windows(2).find_map(|pair| match pair {
        [left, right] if left.path == right.path => Some(left.path.as_str().to_owned()),
        _ => None,
    });
    match duplicate {
        Some(path) => Err(IdentityError::DuplicateSourceFile { path }),
        None => Ok(sorted),
    }
}

/// Whether code shipped with a source may run, and which code (§3.2 item 2 "code
/// policy").
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CodePolicy {
    /// Only the runner's own model code runs.
    BuiltInOnly,
    /// The source's own model code runs, pinned by digest.
    PinnedRemoteCode { code: Digest },
}

impl Encode for CodePolicy {
    fn encode(&self, out: &mut Encoding) {
        match self {
            Self::BuiltInOnly => {
                out.tag("built_in_only");
            }
            Self::PinnedRemoteCode { code } => {
                out.tag("pinned_remote_code").item(code);
            }
        }
    }
}

/// The typed inputs of a [`LogicalModelIdentity`] (§3.2 item 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalModelSpec {
    pub source: SourceIdentity,
    pub dtype: Dtype,
    pub quantization: Quantization,
    /// Digest of the tokenizer: vocabulary, merges, normalisation and special tokens.
    pub tokenizer: Digest,
    /// Digest of the generation-relevant configuration, such as the chat template and
    /// stop tokens.
    pub generation_config: Digest,
    /// Adapters merged into the weights. Unmerged adapters belong to sessions.
    pub adapters: AdapterRecipe,
    pub code_policy: CodePolicy,
}

impl LogicalModelSpec {
    /// §3.2 item 2.
    pub fn identity(&self) -> LogicalModelIdentity {
        LogicalModelIdentity(self.canonical().finish(LOGICAL_DOMAIN))
    }

    /// A separate merged variant: this spec with `adapter` merged after any adapters
    /// already merged (§1.1, line 308). `self` stays as it is, so the base remains an
    /// immutable identity of its own; the variant's identity differs from it.
    pub fn with_merged(&self, adapter: MergedAdapter) -> Self {
        let adapters = match &self.adapters {
            AdapterRecipe::None => MergedAdapters::single(adapter),
            AdapterRecipe::Merged(merged) => merged.then(adapter),
        };
        Self {
            adapters: AdapterRecipe::Merged(adapters),
            ..self.clone()
        }
    }

    pub(crate) fn canonical(&self) -> Encoding {
        let mut out = Encoding::new();
        out.item(&self.source)
            .item(&self.dtype)
            .item(&self.quantization)
            .item(&self.tokenizer)
            .item(&self.generation_config)
            .item(&self.adapters)
            .item(&self.code_policy);
        out
    }
}

/// Tensor-, pipeline- and expert-parallel sizes (§3.2 item 3 "rank topology"). Each is
/// at least 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RankTopology {
    tensor_parallel_size: u32,
    pipeline_parallel_size: u32,
    expert_parallel_size: u32,
}

impl RankTopology {
    /// One rank.
    pub const SINGLE: Self = Self {
        tensor_parallel_size: 1,
        pipeline_parallel_size: 1,
        expert_parallel_size: 1,
    };

    /// Refuses a zero size in any dimension.
    pub fn new(
        tensor_parallel_size: u32,
        pipeline_parallel_size: u32,
        expert_parallel_size: u32,
    ) -> Result<Self, IdentityError> {
        for (dimension, size) in [
            ("tensor_parallel_size", tensor_parallel_size),
            ("pipeline_parallel_size", pipeline_parallel_size),
            ("expert_parallel_size", expert_parallel_size),
        ] {
            if size == 0 {
                return Err(IdentityError::ZeroParallelism { dimension });
            }
        }
        Ok(Self {
            tensor_parallel_size,
            pipeline_parallel_size,
            expert_parallel_size,
        })
    }

    pub fn tensor_parallel_size(&self) -> u32 {
        self.tensor_parallel_size
    }

    pub fn pipeline_parallel_size(&self) -> u32 {
        self.pipeline_parallel_size
    }

    pub fn expert_parallel_size(&self) -> u32 {
        self.expert_parallel_size
    }
}

impl Encode for RankTopology {
    fn encode(&self, out: &mut Encoding) {
        out.u64(self.tensor_parallel_size.into())
            .u64(self.pipeline_parallel_size.into())
            .u64(self.expert_parallel_size.into());
    }
}

/// How the model is compiled for execution (§3.2 item 3 "relevant compile
/// configuration").
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CompileConfiguration {
    Eager,
    Compiled { configuration: Digest },
}

impl Encode for CompileConfiguration {
    fn encode(&self, out: &mut Encoding) {
        match self {
            Self::Eager => {
                out.tag("eager");
            }
            Self::Compiled { configuration } => {
                out.tag("compiled").item(configuration);
            }
        }
    }
}

/// The typed inputs of an [`ExecutionIdentity`] (§3.2 item 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionSpec {
    pub logical: LogicalModelIdentity,
    pub runner: VersionedName,
    pub architecture_adapter: VersionedName,
    pub kernel_layout: VersionedName,
    /// GPU architectures the kernels and processed weights are built for, such as
    /// `sm_90a`. A set: order carries no meaning. At least one.
    pub gpu_architectures: BTreeSet<Label>,
    pub topology: RankTopology,
    pub processed_weights: VersionedName,
    pub compile: CompileConfiguration,
}

impl ExecutionSpec {
    /// §3.2 item 3. Refuses an empty set of GPU architectures.
    pub fn identity(&self) -> Result<ExecutionIdentity, IdentityError> {
        Ok(ExecutionIdentity(
            self.canonical()?.finish(EXECUTION_DOMAIN),
        ))
    }

    pub(crate) fn canonical(&self) -> Result<Encoding, IdentityError> {
        if self.gpu_architectures.is_empty() {
            return Err(IdentityError::NoGpuArchitecture);
        }
        let mut out = Encoding::new();
        out.item(&self.logical)
            .item(&self.runner)
            .item(&self.architecture_adapter)
            .item(&self.kernel_layout)
            .list(&self.gpu_architectures)
            .item(&self.topology)
            .item(&self.processed_weights)
            .item(&self.compile);
        Ok(out)
    }
}

impl ArtifactIdentity {
    /// §3.2 item 4. The manifest (§3.3) is built later; its canonical digest is taken as
    /// given and bound under the artifact domain, so the identity differs from the bare
    /// manifest digest and from every other layer.
    pub fn from_manifest_digest(manifest: &Digest) -> Self {
        Self(artifact_encoding(manifest).finish(ARTIFACT_DOMAIN))
    }
}

pub(crate) fn artifact_encoding(manifest: &Digest) -> Encoding {
    let mut out = Encoding::new();
    out.item(manifest);
    out
}

/// The typed inputs of a [`PlacementIdentity`] (§3.2 item 5, S3.1).
///
/// The activation and allocation generations are distinct fields: moving one leaves the
/// other as it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementSpec {
    pub artifact: ArtifactIdentity,
    pub execution: ExecutionIdentity,
    pub device: GpuDeviceKey,
    pub owner: TenantId,
    pub authority: AuthorityBinding,
    pub activation: ModelActivationGeneration,
    pub allocation: GpuAllocationGeneration,
    /// The execution leases that currently hold the placement, as issued by the
    /// coordination authority. A set: order carries no meaning.
    pub leases: BTreeSet<LeaseId>,
}

impl PlacementSpec {
    /// §3.2 item 5 and S3.1.
    pub fn identity(&self) -> PlacementIdentity {
        PlacementIdentity(self.canonical().finish(PLACEMENT_DOMAIN))
    }

    /// The same placement after a new model activation. Only the activation generation
    /// changes, and only forward (S3.1); the allocation generation, leases and authority
    /// stay as they are.
    pub fn with_activation(&self, next: ModelActivationGeneration) -> Result<Self, IdentityError> {
        if next <= self.activation {
            return Err(IdentityError::GenerationNotAfter {
                field: "model activation",
                current: self.activation.get(),
                proposed: next.get(),
            });
        }
        Ok(Self {
            activation: next,
            ..self.clone()
        })
    }

    /// The same placement after a new GPU allocation. Only the allocation generation
    /// changes, and only forward (S3.1); the activation generation stays as it is.
    pub fn with_allocation(&self, next: GpuAllocationGeneration) -> Result<Self, IdentityError> {
        if next <= self.allocation {
            return Err(IdentityError::GenerationNotAfter {
                field: "GPU allocation",
                current: self.allocation.get(),
                proposed: next.get(),
            });
        }
        Ok(Self {
            allocation: next,
            ..self.clone()
        })
    }

    pub(crate) fn canonical(&self) -> Encoding {
        let mut out = Encoding::new();
        out.item(&self.artifact)
            .item(&self.execution)
            .item(&self.device)
            .item(&self.owner)
            .item(&self.authority)
            .item(&self.activation)
            .item(&self.allocation)
            .list(&self.leases);
        out
    }
}

/// What a session has consumed (§3.2 item 6 "token prefix/state").
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TokenState {
    /// The exact tokens so far, for attention models.
    Prefix(TokenPrefix),
    /// A recurrent state digest and how many tokens produced it.
    Recurrent { state: Digest, tokens_consumed: u64 },
}

impl Encode for TokenState {
    fn encode(&self, out: &mut Encoding) {
        match self {
            Self::Prefix(prefix) => {
                out.tag("prefix").item(prefix);
            }
            Self::Recurrent {
                state,
                tokens_consumed,
            } => {
                out.tag("recurrent").item(state).u64(*tokens_consumed);
            }
        }
    }
}

/// The typed inputs of a [`SessionIdentity`] (§3.2 item 6, S3.1).
///
/// A session binds the execution identity, not a placement, so a new activation or
/// allocation of the model neither changes the session nor resets its authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSpec {
    pub execution: ExecutionIdentity,
    pub state: TokenState,
    /// The unmerged adapter applied to the immutable base, if any (§1.1, line 308).
    pub adapter: Option<AdapterIdentity>,
    pub positional_encoding: PositionalEncoding,
    pub kv: KvRepresentation,
    pub tenant: TenantId,
    pub authority: AuthorityBinding,
}

impl SessionSpec {
    /// §3.2 item 6 and S3.1.
    pub fn identity(&self) -> SessionIdentity {
        SessionIdentity(self.canonical().finish(SESSION_DOMAIN))
    }

    pub(crate) fn canonical(&self) -> Encoding {
        let mut out = Encoding::new();
        out.item(&self.execution)
            .item(&self.state)
            .option(self.adapter.as_ref())
            .item(&self.positional_encoding)
            .item(&self.kv)
            .item(&self.tenant)
            .item(&self.authority);
        out
    }
}
