//! Synthetic identities of the simulated fleet used by the §4.6–§4.8 experiments: one
//! published model, its single-GPU and two-stage pipeline executions, resident claims,
//! grants and a session. Every digest is named under [`EXPERIMENT_DIGEST_DOMAIN`]; none
//! stands for a real artifact, machine or measurement. Grants stand on a real CORE-02
//! catalog and KV-scope enforcement on CORE-01 evidence, both supplied by the caller in a
//! [`FleetAuthority`]; nothing here opens a catalog or a registry.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use crate::foundation::catalog::{Catalog, ObjectId};

use crate::foundation::ids::{
    digest, AuthorizationEpoch, ContentKey, Digest, ExecutionCategory, ExecutionId, GpuDeviceKey,
    ModelActivationGeneration, MonotonicTime, TenantId, TrustScope,
};
use crate::model_memory::identity::{
    AdapterRecipe, ArtifactIdentity, AuthorityBinding, CodePolicy, CommitId, CompileConfiguration,
    CurrentResidency, Dtype, ExecutionIdentity, ExecutionSpec, GrantTerms, GrantedUse,
    ImmutableRevision, KvAuthority, KvPosition, KvRepresentation, KvScopeSpec, Label,
    LogicalModelSpec, PositionalEncoding, Quantization, RankTopology, RelativePath, Residency,
    ResidentAdvertisement, ScopeEnforcement, ScopedGrant, SourceFile, SourceLocation, SourceSpec,
    TokenPrefix, VersionedName,
};
use crate::model_memory::math::recompute::KvRequirement;

use super::error::RoutingError;
use super::evidence::EXPERIMENT_DIGEST_DOMAIN;
use super::joint::{RequestedModel, ResidentClaim, SessionState};

/// A digest named under [`EXPERIMENT_DIGEST_DOMAIN`].
pub fn named(name: &str) -> Digest {
    digest(EXPERIMENT_DIGEST_DOMAIN, &[name.as_bytes()])
}

/// A device key from a machine name and a device name.
pub fn device(machine: &str, device: &str) -> GpuDeviceKey {
    GpuDeviceKey {
        machine: named(&format!("machine:{machine}")),
        device: named(&format!("device:{machine}:{device}")),
    }
}

/// What the fleet's grants and KV-scope evidence stand on (S3.3, FAST-03): the CORE-02
/// catalog holding the tenant's artifact object, the execution the catalog lets read it,
/// and CORE-01 evidence that the KV backend enforces the reuse scope.
#[derive(Clone)]
pub struct FleetAuthority {
    pub catalog: Arc<Mutex<Catalog>>,
    /// The artifact's object in the tenant's catalog scope.
    pub object: ObjectId,
    /// The execution the catalog lets read the object.
    pub execution: ExecutionId,
    pub kv_enforcement: ScopeEnforcement,
}

/// The identities shared by every simulated runner.
#[derive(Clone, Debug, PartialEq)]
pub struct SyntheticFleet {
    pub tenant: TenantId,
    pub parent: ExecutionId,
    pub category: ExecutionCategory,
    pub epoch: AuthorizationEpoch,
    pub authority: AuthorityBinding,
    pub artifact: ArtifactIdentity,
    pub logical: LogicalModelSpec,
    /// The model on one GPU.
    pub single: ExecutionSpec,
    /// The same logical model as a two-stage pipeline (§4.8).
    pub pipeline: ExecutionSpec,
    /// A different logical model, never a substitute for the requested one.
    pub other: ExecutionSpec,
}

fn versioned(name: &str, version: &str) -> Result<VersionedName, RoutingError> {
    Ok(VersionedName::new(name, version)?)
}

fn label(value: &str) -> Result<Label, RoutingError> {
    Ok(Label::new(value)?)
}

fn logical_spec(repository: &str, weights_bytes: u64) -> Result<LogicalModelSpec, RoutingError> {
    let source = SourceSpec {
        location: SourceLocation::Repository {
            host: label("huggingface.co")?,
            repository: label(repository)?,
        },
        revision: ImmutableRevision::Commit(CommitId::new(
            "0123456789abcdef0123456789abcdef01234567",
        )?),
        files: vec![
            SourceFile {
                path: RelativePath::new("config.json")?,
                length_bytes: 700,
                content: ContentKey::of(format!("{repository}/config").as_bytes()),
            },
            SourceFile {
                path: RelativePath::new("model.safetensors")?,
                length_bytes: weights_bytes,
                content: ContentKey::of(format!("{repository}/weights").as_bytes()),
            },
        ],
        configuration: named(&format!("{repository}/configuration")),
        published_dtype: Dtype::BFloat16,
        license: label("apache-2.0")?,
        provenance: None,
    }
    .identity()?;
    Ok(LogicalModelSpec {
        source,
        dtype: Dtype::BFloat16,
        quantization: Quantization::None,
        tokenizer: named(&format!("{repository}/tokenizer")),
        generation_config: named(&format!("{repository}/generation")),
        adapters: AdapterRecipe::None,
        code_policy: CodePolicy::BuiltInOnly,
    })
}

fn execution_spec(
    logical: &LogicalModelSpec,
    topology: RankTopology,
) -> Result<ExecutionSpec, RoutingError> {
    Ok(ExecutionSpec {
        logical: logical.identity(),
        runner: versioned("vllm", "0.31.0")?,
        architecture_adapter: versioned("llama", "1")?,
        kernel_layout: versioned("flash-attn", "2.7.4")?,
        gpu_architectures: BTreeSet::from([label("sm_89")?]),
        topology,
        processed_weights: versioned("vllm-bf16", "1")?,
        compile: CompileConfiguration::Eager,
    })
}

impl SyntheticFleet {
    /// A 14 GB model (`example-org/example-7b`) for one tenant in the shared-kernel GPU
    /// runtime under authorization epoch 1, and a larger model it never stands in for.
    pub fn new() -> Result<Self, RoutingError> {
        let category = ExecutionCategory::SharedKernelGpuRuntime;
        let epoch = AuthorizationEpoch::FIRST;
        let parent = ExecutionId::new("exe-routing-fleet")?;
        let logical = logical_spec("example-org/example-7b", 14_000_000_000)?;
        let other_logical = logical_spec("example-org/example-70b", 140_000_000_000)?;
        Ok(Self {
            tenant: TenantId::new("tenant-routing")?,
            authority: AuthorityBinding::new(parent.clone(), category, Some(epoch))?,
            parent,
            category,
            epoch,
            artifact: ArtifactIdentity::from_manifest_digest(&named("example-7b/manifest")),
            single: execution_spec(&logical, RankTopology::SINGLE)?,
            pipeline: execution_spec(&logical, RankTopology::new(1, 2, 1)?)?,
            other: execution_spec(&other_logical, RankTopology::SINGLE)?,
            logical,
        })
    }

    pub fn single_execution(&self) -> Result<ExecutionIdentity, RoutingError> {
        Ok(self.single.identity()?)
    }

    pub fn pipeline_execution(&self) -> Result<ExecutionIdentity, RoutingError> {
        Ok(self.pipeline.identity()?)
    }

    /// The exact single-GPU execution only.
    pub fn requested_single(&self) -> Result<RequestedModel, RoutingError> {
        RequestedModel::exact(&self.single)
    }

    /// The single-GPU execution or the two-stage pipeline of the same logical model.
    pub fn requested_single_or_pipeline(&self) -> Result<RequestedModel, RoutingError> {
        RequestedModel::with_executions(
            self.logical.identity(),
            &[self.single.clone(), self.pipeline.clone()],
        )
    }

    /// The trust scope of the runtime on `machine`.
    pub fn scope(&self, machine: &str) -> TrustScope {
        TrustScope::named(self.category, &format!("fleet:{machine}"))
    }

    pub fn residency(
        &self,
        device: GpuDeviceKey,
        scope: TrustScope,
        execution: ExecutionIdentity,
    ) -> Residency {
        Residency {
            execution,
            artifact: self.artifact,
            owner: self.tenant.clone(),
            scope,
            device,
            authority: self.authority.clone(),
        }
    }

    /// A grant from the tenant to itself for `uses` within `scope` until `expires_at`,
    /// checked through the authority's catalog (S3.3: the owner needs a grant too).
    pub fn grant(
        &self,
        authority: &FleetAuthority,
        scope: TrustScope,
        uses: &[GrantedUse],
        expires_at: MonotonicTime,
    ) -> Result<ScopedGrant, RoutingError> {
        Ok(ScopedGrant::from_catalog(
            &authority.catalog,
            authority.object,
            authority.execution.clone(),
            GrantTerms {
                grantor: self.tenant.clone(),
                grantee: self.tenant.clone(),
                artifact: self.artifact,
                scope,
                uses: uses.iter().copied().collect(),
                expires_at,
            },
        )?)
    }

    /// A resident claim for `execution` on `device`, advertised at activation
    /// `generation` until `expires_at`, with a serve grant in its scope.
    pub fn resident_claim(
        &self,
        authority: &FleetAuthority,
        device: GpuDeviceKey,
        scope: TrustScope,
        execution: ExecutionIdentity,
        generation: ModelActivationGeneration,
        expires_at: MonotonicTime,
    ) -> Result<ResidentClaim, RoutingError> {
        let residency = self.residency(device, scope, execution);
        Ok(ResidentClaim {
            advertisement: ResidentAdvertisement {
                residency: residency.clone(),
                generation,
                expires_at,
            },
            current: CurrentResidency {
                residency,
                generation,
            },
            grant: Some(self.grant(authority, scope, &[GrantedUse::Serve], expires_at)?),
        })
    }

    /// A session of `context_tokens` on `home`, holding `kv_bytes_per_token` bytes of KV
    /// per token, scoped to the single-GPU execution.
    pub fn session(
        &self,
        home: GpuDeviceKey,
        context_tokens: u32,
        kv_bytes_per_token: u64,
    ) -> Result<SessionState, RoutingError> {
        let tokens: Vec<u32> = (0..context_tokens).map(|index| index % 32_000).collect();
        let prefix = TokenPrefix::from_token_ids(&tokens);
        let scope = KvScopeSpec {
            model: self.single_execution()?,
            tokenizer: self.logical.tokenizer,
            adapter: None,
            prefix: prefix.clone(),
            position: KvPosition {
                encoding: PositionalEncoding {
                    scheme: versioned("rope", "1")?,
                    parameters: named("rope-theta-500000"),
                },
                first_position: 0,
            },
            cache: KvRepresentation::new(
                Dtype::BFloat16,
                Quantization::None,
                16,
                versioned("paged", "1")?,
            )?,
            authority: KvAuthority {
                tenant: self.tenant.clone(),
                session: self.authority.clone(),
            },
        };
        let requirement = KvRequirement {
            state_identity: *scope.key().digest(),
            prefix_identity: *prefix.digest(),
            current_epoch: self.epoch,
        };
        Ok(SessionState {
            home,
            scope,
            requirement,
            kv_bytes: u64::from(context_tokens).saturating_mul(kv_bytes_per_token),
            context_tokens: u64::from(context_tokens),
        })
    }
}
