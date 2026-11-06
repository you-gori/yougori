//! Fixtures and a seeded generator for the identity tests.

use std::collections::BTreeSet;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use crate::foundation::ids::{
    digest, AuthorizationEpoch, Clock, ContentKey, Digest, ExecutionCategory, ExecutionId,
    GpuAllocationGeneration, GpuDeviceKey, LeaseId, ManualClock, ModelActivationGeneration,
    MonotonicTime, TenantId,
};

use super::super::fakes::{scope_enforcement, GrantCatalog};
use super::super::*;

pub(crate) const HOUR: Duration = Duration::from_secs(3_600);

/// Scope enforcement shown by registry evidence observed at 0 ns and fresh for an hour.
pub(crate) fn enforced() -> ScopeEnforcement {
    scope_enforcement(at(0), HOUR)
}

/// A manual clock and a catalog on it in which tenants a, b and c publish and grant.
pub(crate) struct World {
    pub(crate) clock: Arc<ManualClock>,
    pub(crate) grants: GrantCatalog,
}

impl World {
    pub(crate) fn at(nanos: u64) -> Self {
        let clock = Arc::new(ManualClock::new(at(nanos)));
        let grants = GrantCatalog::open(
            Arc::clone(&clock) as Arc<dyn Clock>,
            &[tenant("tenant-a"), tenant("tenant-b"), tenant("tenant-c")],
        );
        Self { clock, grants }
    }

    /// A scoped grant for `terms`, checked through the catalog for the grantee's
    /// execution, with a catalog grant that only the terms bound.
    pub(crate) fn grant(&self, terms: GrantTerms) -> ScopedGrant {
        let execution = grantee_execution(&terms.grantee);
        self.grants.scoped_grant(&execution, terms)
    }
}

/// The execution a grantee reads under in these tests.
pub(crate) fn grantee_execution(grantee: &TenantId) -> ExecutionId {
    exe(&format!("exe-{}", grantee.as_str()))
}

/// Terms from `grantor` to `grantee` for the fixture artifact.
pub(crate) fn terms(
    grantor: &str,
    grantee: &str,
    scope: TrustScope,
    uses: &[GrantedUse],
    expires_at: u64,
) -> GrantTerms {
    GrantTerms {
        grantor: tenant(grantor),
        grantee: tenant(grantee),
        artifact: artifact(),
        scope,
        uses: uses.iter().copied().collect(),
        expires_at: at(expires_at),
    }
}

pub(crate) const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
pub(crate) const OTHER_COMMIT: &str = "89abcdef0123456789abcdef0123456789abcdef";

/// A fixture digest named by `name`.
pub(crate) fn d(name: &str) -> Digest {
    digest("yougori/test/identity-fixture/v1", &[name.as_bytes()])
}

pub(crate) fn label(value: &str) -> Label {
    Label::new(value).unwrap()
}

pub(crate) fn versioned(name: &str, version: &str) -> VersionedName {
    VersionedName::new(name, version).unwrap()
}

pub(crate) fn tenant(value: &str) -> TenantId {
    TenantId::new(value).unwrap()
}

pub(crate) fn exe(value: &str) -> ExecutionId {
    ExecutionId::new(value).unwrap()
}

pub(crate) fn lease(id: u64) -> LeaseId {
    LeaseId::new(id)
}

pub(crate) fn at(nanos: u64) -> MonotonicTime {
    MonotonicTime::from_nanos(nanos)
}

pub(crate) fn file(path: &str, length_bytes: u64, content: &str) -> SourceFile {
    SourceFile {
        path: RelativePath::new(path).unwrap(),
        length_bytes,
        content: ContentKey::of(content.as_bytes()),
    }
}

pub(crate) fn source_spec() -> SourceSpec {
    SourceSpec {
        location: SourceLocation::Repository {
            host: label("huggingface.co"),
            repository: label("example-org/example-8b"),
        },
        revision: ImmutableRevision::Commit(CommitId::new(COMMIT).unwrap()),
        files: vec![
            file("config.json", 700, "config.json"),
            file("model-00001-of-00002.safetensors", 4_900_000_000, "shard-1"),
            file("model-00002-of-00002.safetensors", 1_100_000_000, "shard-2"),
            file("tokenizer.json", 9_000_000, "tokenizer.json"),
        ],
        configuration: d("configuration"),
        published_dtype: Dtype::BFloat16,
        license: label("apache-2.0"),
        provenance: Some(d("attestation")),
    }
}

pub(crate) fn source() -> SourceIdentity {
    source_spec().identity().unwrap()
}

pub(crate) fn awq() -> QuantizationScheme {
    QuantizationScheme::new(versioned("awq", "0.2"), 4, Some(128), d("awq-scales")).unwrap()
}

pub(crate) fn logical_spec() -> LogicalModelSpec {
    LogicalModelSpec {
        source: source(),
        dtype: Dtype::BFloat16,
        quantization: Quantization::None,
        tokenizer: d("tokenizer"),
        generation_config: d("generation-config"),
        adapters: AdapterRecipe::None,
        code_policy: CodePolicy::BuiltInOnly,
    }
}

pub(crate) fn logical() -> LogicalModelIdentity {
    logical_spec().identity()
}

pub(crate) fn execution_spec() -> ExecutionSpec {
    ExecutionSpec {
        logical: logical(),
        runner: versioned("vllm", "0.29.0"),
        architecture_adapter: versioned("llama", "1"),
        kernel_layout: versioned("flash-attn", "2.7.4"),
        gpu_architectures: BTreeSet::from([label("sm_90a")]),
        topology: RankTopology::SINGLE,
        processed_weights: versioned("vllm-bf16", "1"),
        compile: CompileConfiguration::Eager,
    }
}

pub(crate) fn execution() -> ExecutionIdentity {
    execution_spec().identity().unwrap()
}

pub(crate) fn artifact() -> ArtifactIdentity {
    ArtifactIdentity::from_manifest_digest(&d("manifest"))
}

pub(crate) fn vm_binding(parent: &str, epoch: u64) -> AuthorityBinding {
    AuthorityBinding::new(
        exe(parent),
        ExecutionCategory::VmSandbox,
        Some(AuthorizationEpoch::new(epoch)),
    )
    .unwrap()
}

/// A device key from fixture digests of a machine name and a device name.
pub(crate) fn gpu(machine: &str, device: &str) -> GpuDeviceKey {
    GpuDeviceKey {
        machine: d(machine),
        device: d(device),
    }
}

pub(crate) fn placement_spec() -> PlacementSpec {
    PlacementSpec {
        artifact: artifact(),
        execution: execution(),
        device: gpu("host-a", "GPU-0"),
        owner: tenant("tenant-a"),
        authority: vm_binding("exe-parent", 3),
        activation: ModelActivationGeneration::new(5),
        allocation: GpuAllocationGeneration::new(9),
        leases: BTreeSet::from([lease(1), lease(2)]),
    }
}

pub(crate) fn rope() -> PositionalEncoding {
    PositionalEncoding {
        scheme: versioned("rope", "1"),
        parameters: d("rope-theta-500000"),
    }
}

pub(crate) fn kv_representation() -> KvRepresentation {
    KvRepresentation::new(
        Dtype::BFloat16,
        Quantization::None,
        16,
        versioned("paged", "1"),
    )
    .unwrap()
}

pub(crate) fn adapter_source(name: &str) -> SourceIdentity {
    SourceSpec {
        location: SourceLocation::Repository {
            host: label("huggingface.co"),
            repository: label(name),
        },
        files: vec![
            file("adapter_config.json", 600, &format!("{name}/config")),
            file(
                "adapter_model.safetensors",
                80_000_000,
                &format!("{name}/weights"),
            ),
        ],
        configuration: d(&format!("{name}/configuration")),
        ..source_spec()
    }
    .identity()
    .unwrap()
}

pub(crate) fn adapter_spec(name: &str) -> AdapterSpec {
    AdapterSpec {
        source: adapter_source(name),
        method: versioned("lora", "1"),
        dtype: Dtype::BFloat16,
    }
}

pub(crate) fn adapter(name: &str) -> AdapterIdentity {
    adapter_spec(name).identity()
}

pub(crate) fn merged(name: &str, scale: f64) -> MergedAdapter {
    MergedAdapter {
        adapter: adapter(name),
        scale: MergeScale::new(scale).unwrap(),
        procedure: versioned("peft-merge-fp32", "0.13"),
    }
}

pub(crate) fn session_spec() -> SessionSpec {
    SessionSpec {
        execution: execution(),
        state: TokenState::Prefix(TokenPrefix::from_token_ids(&[128_000, 9906, 11, 1917])),
        adapter: Some(adapter("org/support-lora")),
        positional_encoding: rope(),
        kv: kv_representation(),
        tenant: tenant("tenant-a"),
        authority: vm_binding("exe-session", 3),
    }
}

pub(crate) fn kv_scope_spec() -> KvScopeSpec {
    KvScopeSpec {
        model: execution(),
        tokenizer: d("tokenizer"),
        adapter: Some(adapter("org/support-lora")),
        prefix: TokenPrefix::from_token_ids(&[128_000, 9906, 11, 1917]),
        position: KvPosition {
            encoding: rope(),
            first_position: 0,
        },
        cache: kv_representation(),
        authority: KvAuthority {
            tenant: tenant("tenant-a"),
            session: vm_binding("exe-session", 3),
        },
    }
}

pub(crate) fn graph_resource(role: &str, kind: GraphResourceKind, address: u64) -> GraphResource {
    GraphResource {
        role: label(role),
        kind,
        content: d(role),
        allocation: GpuAllocationGeneration::new(9),
        device_address: address,
        length_bytes: 1 << 20,
        layout: label("bf16[4096]"),
    }
}

pub(crate) fn graph_spec() -> GraphCaptureSpec {
    GraphCaptureSpec {
        execution: execution(),
        device: gpu("host-a", "GPU-0"),
        shape: CaptureShape {
            sequences: 8,
            tokens: 8,
        },
        resources: vec![
            graph_resource("weights", GraphResourceKind::Weights, 0x7f00_0000_0000),
            graph_resource("kv_cache", GraphResourceKind::KvCache, 0x7f10_0000_0000),
            graph_resource("workspace", GraphResourceKind::Workspace, 0x7f20_0000_0000),
            graph_resource("input_ids", GraphResourceKind::Input, 0x7f30_0000_0000),
            graph_resource("logits", GraphResourceKind::Output, 0x7f40_0000_0000),
        ],
    }
}

/// Asserts that every named digest differs from every other.
pub(crate) fn assert_all_distinct<T: PartialEq + Debug>(cases: &[(&str, T)]) {
    for (index, (left_name, left)) in cases.iter().enumerate() {
        for (right_name, right) in &cases[index + 1..] {
            assert_ne!(
                left, right,
                "{left_name} and {right_name} share an identity"
            );
        }
    }
}

/// SplitMix64: a small seeded generator, so every shuffled test is reproducible.
pub(crate) struct SplitMix64(u64);

impl SplitMix64 {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A value in `0..bound`; `bound` is above zero.
    pub(crate) fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }

    pub(crate) fn shuffle<T>(&mut self, items: &mut [T]) {
        for index in (1..items.len()).rev() {
            let other = self.below(index as u64 + 1) as usize;
            items.swap(index, other);
        }
    }
}
