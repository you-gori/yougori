//! Test fixtures over T07's identities and T08's copies and retention policies.

use std::collections::BTreeSet;
use std::time::Duration;

use crate::foundation::ids::{
    digest, AuthorizationEpoch, ContentKey, Digest, ExecutionCategory, ExecutionId, MonotonicTime,
    TenantId, TrustScope,
};
use crate::model_memory::identity::{
    AdapterIdentity, AdapterRecipe, AdapterSpec, AuthorityBinding, CodePolicy,
    CompileConfiguration, Dtype, ExecutionIdentity, ExecutionSpec, ImmutableRevision, KvAuthority,
    KvPosition, KvRepresentation, KvScopeSpec, Label, LogicalModelIdentity, LogicalModelSpec,
    MergeScale, PositionalEncoding, Quantization, RankTopology, RelativePath, ScopeEnforcement,
    SourceFile, SourceIdentity, SourceLocation, SourceSpec, TokenPrefix, VersionedName,
};
use crate::model_memory::math::recompute::{KvRecompute, KvRequirement, KvTransfer};
use crate::model_memory::residency::eviction::{
    Content, CopyTier, ReconstructibleCopy, Verification,
};
use crate::model_memory::residency::retention::{Lru, ObjectKind, ObjectView, RetentionPolicy};

use super::adapter::{AdapterLimits, AdapterReference, LayerShape, LayerTable};
use super::graph::{
    BaseSpec, KvRestorePaths, NodeId, SessionKvSpec, SessionState, WeightsResidency,
};
use super::kv::{
    kv_state_key, EngineKvProfile, KvRequest, KvReuseSpec, KvSharing, RankPosition, StoredKv,
};
use super::merge::{decide_merge, MergeChoice, MergeEconomics, MergeJustified};

pub(crate) const LIMITS: AdapterLimits = AdapterLimits { max_rank: 64 };

/// A test digest named by `name`.
pub(crate) fn id(name: &str) -> Digest {
    digest("yougori/test/adapters/name/v1", &[name.as_bytes()])
}

pub(crate) fn tenant(name: &str) -> TenantId {
    TenantId::new(name).unwrap()
}

pub(crate) fn versioned(name: &str) -> VersionedName {
    VersionedName::new(name, "1").unwrap()
}

/// The VM sandbox trust scope the fixtures run in.
pub(crate) fn trust() -> TrustScope {
    TrustScope::named(ExecutionCategory::VmSandbox, "models")
}

/// A moment inside the freshness of [`verified`]'s evidence.
pub(crate) const NOW: MonotonicTime = MonotonicTime::from_nanos(1_000_000_000);

/// A backend verified to enforce the KV scope (FAST-03), on evidence a CORE-01 registry
/// evaluated at 0 ns and fresh for an hour.
pub(crate) fn verified() -> ScopeEnforcement {
    crate::model_memory::identity::fakes::scope_enforcement(
        MonotonicTime::ZERO,
        Duration::from_secs(3_600),
    )
}

/// A local source whose only file holds `name`.
pub(crate) fn source(name: &str) -> SourceIdentity {
    SourceSpec {
        location: SourceLocation::Local {
            name: Label::new(name).unwrap(),
        },
        revision: ImmutableRevision::FileDigests,
        files: vec![SourceFile {
            path: RelativePath::new("model.safetensors").unwrap(),
            length_bytes: 1_024,
            content: ContentKey::of(name.as_bytes()),
        }],
        configuration: id("configuration"),
        published_dtype: Dtype::BFloat16,
        license: Label::new("apache-2.0").unwrap(),
        provenance: None,
    }
    .identity()
    .unwrap()
}

pub(crate) fn logical(name: &str) -> LogicalModelSpec {
    LogicalModelSpec {
        source: source(name),
        dtype: Dtype::BFloat16,
        quantization: Quantization::None,
        tokenizer: id("tokenizer"),
        generation_config: id("generation"),
        adapters: AdapterRecipe::None,
        code_policy: CodePolicy::BuiltInOnly,
    }
}

pub(crate) fn execution(logical: &LogicalModelSpec) -> ExecutionSpec {
    ExecutionSpec {
        logical: logical.identity(),
        runner: versioned("vllm"),
        architecture_adapter: versioned("llama"),
        kernel_layout: versioned("flash-attention"),
        gpu_architectures: BTreeSet::from([Label::new("sm_90a").unwrap()]),
        topology: RankTopology::SINGLE,
        processed_weights: versioned("bf16-dense"),
        compile: CompileConfiguration::Eager,
    }
}

pub(crate) fn logical_identity(name: &str) -> LogicalModelIdentity {
    logical(name).identity()
}

pub(crate) fn execution_identity(name: &str) -> ExecutionIdentity {
    execution(&logical(name)).identity().unwrap()
}

pub(crate) fn adapter_identity(name: &str) -> AdapterIdentity {
    AdapterSpec {
        source: source(name),
        method: versioned("lora"),
        dtype: Dtype::BFloat16,
    }
    .identity()
}

pub(crate) fn layers() -> LayerTable {
    let shape = |input_features, output_features| LayerShape {
        input_features,
        output_features,
    };
    LayerTable::from([
        ("layers.0.q_proj".to_string(), shape(4096, 4096)),
        ("layers.0.v_proj".to_string(), shape(4096, 1024)),
    ])
}

/// A copy in `tier` verified to hold `content`.
pub(crate) fn copy(tier: CopyTier, content: Content) -> ReconstructibleCopy {
    ReconstructibleCopy {
        tier,
        verification: Verification::Verified { content },
    }
}

/// The content key of weights named `name`.
pub(crate) fn weights_content(name: &str) -> Content {
    Content::Immutable(ContentKey::of(name.as_bytes()))
}

/// Weights keyed by `name`, reloaded in 2 s, with a verified local-storage copy of the
/// same bytes or no copy at all.
pub(crate) fn residency(name: &str, bytes: u64, verified: bool) -> WeightsResidency {
    WeightsResidency {
        content: ContentKey::of(name.as_bytes()),
        bytes,
        copies: if verified {
            vec![copy(CopyTier::LocalStorage, weights_content(name))]
        } else {
            Vec::new()
        },
        reload_seconds: 2.0,
    }
}

pub(crate) fn base_spec(name: &str, bytes: u64, verified: bool) -> BaseSpec {
    let logical = logical(name);
    BaseSpec {
        execution: execution(&logical),
        logical,
        layers: layers(),
        residency: residency(name, bytes, verified),
    }
}

/// Adapter `name` made for base `base` at rank 16 and scale 2.
pub(crate) fn adapter_reference(name: &str, base: &str) -> AdapterReference {
    AdapterReference {
        adapter: adapter_identity(name),
        base: logical_identity(base),
        layers: layers(),
        rank: 16,
        scale: MergeScale::new(2.0).unwrap(),
    }
}

/// A proof that merging adapter `adapter` into base `base` is justified, for a variant
/// of `variant_bytes` materialized in 2 s.
pub(crate) fn justified(base: &str, adapter: &str, variant_bytes: u64) -> MergeJustified {
    let choice = decide_merge(&MergeEconomics {
        base: execution_identity(base),
        adapter: adapter_identity(adapter),
        expected_requests: 1_000_000,
        unmerged_overhead_seconds_per_request: 0.01,
        materialize_seconds: 2.0,
        retention_penalty_seconds: 0.0,
        variant_bytes,
        available_bytes: variant_bytes,
    })
    .unwrap();
    match choice {
        MergeChoice::Merge(justified) => justified,
        MergeChoice::KeepUnmerged(reason) => panic!("merging was not justified: {reason:?}"),
    }
}

/// `tokens` token IDs derived from `name`, so equal names and counts give equal
/// prefixes.
pub(crate) fn token_prefix(name: &str, tokens: u64) -> TokenPrefix {
    let seed = name.bytes().fold(7u32, |hash, byte| {
        hash.wrapping_mul(31).wrapping_add(u32::from(byte))
    });
    let ids: Vec<u32> = (0..tokens)
        .map(|position| seed.wrapping_add(position as u32))
        .collect();
    TokenPrefix::from_token_ids(&ids)
}

/// Tenant `name`'s session under `epoch`, in a VM sandbox.
pub(crate) fn authority(name: &str, epoch: u64) -> KvAuthority {
    KvAuthority {
        tenant: tenant(name),
        session: AuthorityBinding::new(
            ExecutionId::new(format!("exe-{name}")).unwrap(),
            ExecutionCategory::VmSandbox,
            Some(AuthorizationEpoch::new(epoch)),
        )
        .unwrap(),
    }
}

pub(crate) fn rope() -> PositionalEncoding {
    PositionalEncoding {
        scheme: versioned("rope"),
        parameters: id("theta 1e6"),
    }
}

pub(crate) fn kv_cache() -> KvRepresentation {
    KvRepresentation::new(Dtype::BFloat16, Quantization::None, 16, versioned("paged")).unwrap()
}

/// KV computed by `model` (and `adapter`) over `tokens` tokens of `prefix`, owned by
/// tenant `owner` under epoch 1.
pub(crate) fn kv_spec(
    model: ExecutionIdentity,
    adapter: Option<AdapterIdentity>,
    tokens: u64,
    prefix: &str,
    owner: &str,
) -> KvReuseSpec {
    KvReuseSpec {
        scope: KvScopeSpec {
            model,
            tokenizer: id("tokenizer"),
            adapter,
            prefix: token_prefix(prefix, tokens),
            position: KvPosition {
                encoding: rope(),
                first_position: 0,
            },
            cache: kv_cache(),
            authority: authority(owner, 1),
        },
        attention_semantics: id("causal"),
        rank: RankPosition::new(0, 1).unwrap(),
    }
}

/// A request for `spec` from the fixtures' trust scope.
pub(crate) fn request(spec: KvReuseSpec) -> KvRequest {
    KvRequest {
        spec,
        trust_scope: trust(),
    }
}

/// The engine serving `model` in the fixtures' KV format, verified to enforce scope.
pub(crate) fn engine(model: ExecutionIdentity) -> EngineKvProfile {
    EngineKvProfile {
        model,
        tokenizer: id("tokenizer"),
        positional_encoding: rope(),
        cache: kv_cache(),
        attention_semantics: id("causal"),
        rank: RankPosition::new(0, 1).unwrap(),
        reuses_prefix_kv: true,
        enforcement: verified(),
    }
}

/// How a KV fixture's state could come back after release (§2.8).
#[derive(Clone, Copy, Debug)]
pub(crate) enum Restore {
    /// Transferred back from a reconstructible copy at 25 GB/s.
    Transfer,
    /// The original prefix, recomputed exactly at 10,000 tokens/s.
    Recompute,
    /// Neither: the KV is required context.
    Lost,
}

/// Session KV of tenant `acme` under epoch 1.
#[derive(Clone, Copy, Debug)]
pub(crate) struct KvFixture {
    pub weights: NodeId,
    pub model: ExecutionIdentity,
    pub adapter: Option<(NodeId, AdapterIdentity)>,
    pub prefix: &'static str,
    pub tokens: u64,
    pub bytes: u64,
    pub state: SessionState,
    pub restore: Restore,
    pub sharing: KvSharing,
    /// A verified copy of this exact state in that tier, if any.
    pub copy: Option<CopyTier>,
}

impl KvFixture {
    pub(crate) fn new(weights: NodeId, model: ExecutionIdentity, prefix: &'static str) -> Self {
        Self {
            weights,
            model,
            adapter: None,
            prefix,
            tokens: 1_000,
            bytes: 1_000_000,
            state: SessionState::Live {
                resume_probability: 0.5,
            },
            restore: Restore::Recompute,
            sharing: KvSharing::TenantScoped,
            copy: None,
        }
    }

    pub(crate) fn stored(&self) -> StoredKv {
        StoredKv {
            spec: kv_spec(
                self.model,
                self.adapter.map(|(_, identity)| identity),
                self.tokens,
                self.prefix,
                "acme",
            ),
            trust_scope: trust(),
            sharing: self.sharing,
        }
    }

    /// The T08 content of this exact state.
    pub(crate) fn content(&self) -> Content {
        Content::SessionState(kv_state_key(&self.stored()))
    }

    pub(crate) fn spec(&self) -> SessionKvSpec {
        let stored = self.stored();
        let state_identity = kv_state_key(&stored);
        let requirement = KvRequirement {
            state_identity,
            prefix_identity: *stored.spec.scope.prefix.digest(),
            current_epoch: AuthorizationEpoch::new(1),
        };
        let transfer = matches!(self.restore, Restore::Transfer).then_some(KvTransfer {
            queue_seconds: 0.0,
            transfer_seconds: self.bytes as f64 / 25e9,
        });
        let recompute = matches!(self.restore, Restore::Recompute).then_some(KvRecompute {
            held_prefix: Some(requirement.prefix_identity),
            produces_state: state_identity,
            authorized_epoch: Some(AuthorizationEpoch::new(1)),
            queue_seconds: 0.0,
            compute_seconds: self.tokens as f64 / 10_000.0,
        });
        SessionKvSpec {
            copies: self
                .copy
                .map(|tier| copy(tier, self.content()))
                .into_iter()
                .collect(),
            stored,
            bytes: self.bytes,
            weights: self.weights,
            adapter: self.adapter.map(|(node, _)| node),
            state: self.state,
            restore: KvRestorePaths {
                requirement,
                transfer,
                recompute,
            },
        }
    }
}

/// One [`ObjectView`] as a policy saw it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SeenView {
    pub key: String,
    pub kind: ObjectKind,
    pub bytes: u64,
    pub reload_seconds: f64,
    pub last_use_step: u64,
    pub use_count: u64,
    pub protected: bool,
    pub evictable: bool,
}

impl SeenView {
    fn of(view: &ObjectView<'_>) -> Self {
        Self {
            key: view.key.to_string(),
            kind: view.kind,
            bytes: view.bytes,
            reload_seconds: view.reload_seconds,
            last_use_step: view.last_use_step,
            use_count: view.use_count,
            protected: view.protected,
            evictable: view.evictable,
        }
    }
}

/// A T08 retention policy that records everything it is told and chooses as [`Lru`].
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Recording {
    /// `on_use` calls: the view and the step.
    pub used: Vec<(SeenView, u64)>,
    pub evicted: Vec<String>,
    /// The residents of every `choose_victim` call.
    pub offered: Vec<Vec<SeenView>>,
}

impl RetentionPolicy for Recording {
    fn name(&self) -> &str {
        "recording"
    }

    fn on_use(&mut self, object: &ObjectView<'_>, step: u64) {
        self.used.push((SeenView::of(object), step));
    }

    fn on_evict(&mut self, key: &str) {
        self.evicted.push(key.to_string());
    }

    fn choose_victim(&mut self, residents: &[ObjectView<'_>], step: u64) -> Option<usize> {
        self.offered
            .push(residents.iter().map(SeenView::of).collect());
        Lru.choose_victim(residents, step)
    }
}

/// True when `actual` is within 1e-9 of `expected`.
pub(crate) fn close(actual: f64, expected: f64) -> bool {
    (actual - expected).abs() <= 1e-9
}
