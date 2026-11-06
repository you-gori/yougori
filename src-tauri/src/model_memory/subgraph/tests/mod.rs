//! Tests of GPU-N3 (GPU §4.16–§4.17) on synthetic manifests and the fake substrate.

mod contract_tests;
mod decision_tests;
mod discovery_tests;
mod eligibility_tests;
mod key_tests;
mod profit_tests;
mod prototype_tests;
mod rng_tests;

use crate::foundation::ids::{
    AuthorizationEpoch, ExecutionCategory, ExecutionId, TenantId, TrustScope,
};
use crate::model_memory::identity::{
    AuthorityBinding, Dtype, FidelityConfiguration, KvRepresentation, Quantization, SessionSpec,
    TokenPrefix, TokenState, VersionedName,
};

use super::synthetic::{
    architecture_layers, architecture_operators, causal_attention, exact_profile, prototype_family,
    rope, synthetic_adapter, synthetic_identities, synthetic_manifest, synthetic_model,
    PrototypeFamily, PrototypePair, SyntheticModel, REFERENCE_ROPE_THETA, SYNTHETIC_ADAPTER_LIMITS,
};
use super::*;

pub(super) fn scope() -> TrustScope {
    TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, "p11-scope")
}

pub(super) fn other_scope() -> TrustScope {
    TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, "p11-other-scope")
}

pub(super) fn family(pair: PrototypePair) -> PrototypeFamily {
    prototype_family(pair, scope()).unwrap()
}

/// A variant over `model` with its definition edited by `edit` before it is built.
pub(super) fn custom_variant(
    model: &SyntheticModel,
    rope_theta: u64,
    adapter_layers: Option<&[&str]>,
    edit: impl FnOnce(&mut VariantDefinition),
) -> Result<ImmutableVariant, SubgraphError> {
    let manifest = synthetic_manifest(model).unwrap();
    let (logical, execution) = synthetic_identities(model, &manifest).unwrap();
    let mut definition = VariantDefinition {
        execution,
        trust_scope: scope(),
        attention: causal_attention().unwrap(),
        position: rope(rope_theta).unwrap(),
        profile: exact_profile().unwrap(),
        operators: architecture_operators().unwrap(),
    };
    edit(&mut definition);
    let reference = adapter_layers.map(|layers| synthetic_adapter(logical, layers).unwrap());
    let layers = architecture_layers();
    let admission = reference.as_ref().map(|reference| AdapterAdmission {
        reference,
        base: &logical,
        base_layers: &layers,
        limits: &SYNTHETIC_ADAPTER_LIMITS,
    });
    ImmutableVariant::from_manifest(&manifest, definition, admission)
}

/// The reference variant A, edited.
pub(super) fn edited_base(edit: impl FnOnce(&mut VariantDefinition)) -> ImmutableVariant {
    custom_variant(
        &synthetic_model(REFERENCE_ROPE_THETA, &[]),
        REFERENCE_ROPE_THETA,
        None,
        edit,
    )
    .unwrap()
}

/// A tenant and the authority its requests run under.
pub(super) struct Who {
    pub tenant: TenantId,
    pub authority: AuthorityBinding,
}

pub(super) fn who(tenant: &str, parent: &str, epoch: u64) -> Who {
    Who {
        tenant: TenantId::new(tenant).unwrap(),
        authority: AuthorityBinding::new(
            ExecutionId::new(parent).unwrap(),
            ExecutionCategory::SharedKernelGpuRuntime,
            Some(AuthorizationEpoch::new(epoch)),
        )
        .unwrap(),
    }
}

pub(super) fn alice() -> Who {
    who("tenant-alice", "parent-alice", 1)
}

pub(super) fn bob() -> Who {
    who("tenant-bob", "parent-bob", 1)
}

pub(super) fn tokens(count: u32, seed: u32) -> Vec<u32> {
    (0..count).map(|index| index * 7 + seed).collect()
}

/// A bit-identical request for `variant` with a session of that variant.
pub(super) fn request(variant: &ImmutableVariant, who: &Who, tokens: &[u32]) -> SubgraphRequest {
    SubgraphRequest {
        input: ExactInput::whole(tokens).unwrap(),
        runtime: RuntimeChoices::pinned(variant.profile().kernels.clone()),
        exactness: ExactnessCriterion::BitIdentical,
        fidelity: FidelityConfiguration::exact_reuse(),
        tenant: who.tenant.clone(),
        authority: who.authority.clone(),
        trust_scope: *variant.trust_scope(),
        session: SessionSpec {
            execution: variant.execution(),
            state: TokenState::Prefix(TokenPrefix::from_token_ids(tokens)),
            adapter: variant.adapter(),
            positional_encoding: variant.position().clone(),
            kv: KvRepresentation::new(
                Dtype::Float32,
                Quantization::None,
                16,
                VersionedName::new("paged", "1").unwrap(),
            )
            .unwrap(),
            tenant: who.tenant.clone(),
            authority: who.authority.clone(),
        },
    }
}

pub(super) fn mode() -> ReuseMode {
    ReuseMode::new(
        &ExactnessCriterion::BitIdentical,
        &FidelityConfiguration::exact_reuse(),
    )
    .unwrap()
}

pub(super) fn pinned(variant: &ImmutableVariant) -> RuntimeChoices {
    RuntimeChoices::pinned(variant.profile().kernels.clone())
}

/// In-place handoff economics for one consumer at the family's branch boundary.
pub(super) fn boundary_for(
    a: &ImmutableVariant,
    b: &ImmutableVariant,
    tokens: u64,
) -> ProfitableBoundary {
    let prefix = discover_shared_prefix(a, b);
    let boundary = prefix.branch_boundary().unwrap();
    let economics = BoundaryEconomics::from_costs(
        &super::synthetic::synthetic_costs()
            .into_iter()
            .chain(std::iter::repeat(super::synthetic::synthetic_costs()[0]).take(4))
            .collect::<Vec<_>>(),
        boundary,
        tokens,
        1.0,
        super::synthetic::SYNTHETIC_HANDOFF,
    )
    .unwrap();
    plan_boundary(&prefix, boundary, &economics).unwrap()
}
