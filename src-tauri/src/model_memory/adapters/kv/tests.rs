use super::*;
use crate::foundation::coordination::RevocationNotice;
use crate::foundation::ids::{AuthorizationEpoch, ExecutionCategory};
use crate::model_memory::adapters::fakes::{
    adapter_identity, authority, engine, execution_identity, id, kv_cache, kv_spec, request, rope,
    token_prefix, trust, verified, versioned, NOW,
};
use crate::model_memory::identity::{
    Dtype, KvPosition, KvScopeComponent, Quantization, RevokedAuthorities,
};

fn stored() -> StoredKv {
    StoredKv {
        spec: kv_spec(
            execution_identity("base-8b"),
            Some(adapter_identity("adapter-sql")),
            32_000,
            "contract",
            "acme",
        ),
        trust_scope: trust(),
        sharing: KvSharing::TenantScoped,
    }
}

/// Nothing revoked.
fn standing() -> RevokedAuthorities {
    RevokedAuthorities::new()
}

fn reuse(stored: &StoredKv, wanted: KvReuseSpec) -> Result<KvReuseGrant, KvReuseRefusal> {
    check_kv_reuse(
        stored,
        &request(wanted),
        &PublicPrefixSharing::none(),
        &standing(),
        &verified(),
        NOW,
    )
}

fn by_t07(refusal: identity::KvReuseRefusal) -> KvReuseRefusal {
    KvReuseRefusal::Scope(refusal)
}

fn scope_mismatch(components: Vec<KvScopeComponent>) -> KvReuseRefusal {
    by_t07(identity::KvReuseRefusal::ScopeMismatch { components })
}

/// `scope` configured as public under acme's session authority at epoch 1.
fn allowed(scope: PublicPrefixScope) -> PublicPrefixSharing {
    let mut sharing = PublicPrefixSharing::none();
    sharing.allow(scope, authority("acme", 1).session);
    sharing
}

/// The coordinator's notice that `name`'s sandbox was revoked at epoch `epoch`.
fn revocation(name: &str, epoch: u64) -> RevocationNotice {
    RevocationNotice {
        execution: authority(name, epoch).session.parent().clone(),
        revoked: AuthorizationEpoch::new(epoch),
        current: AuthorizationEpoch::new(epoch + 1),
        at: NOW,
    }
}

#[test]
fn identical_kv_in_the_same_session_is_granted_under_t07s_key() {
    let stored = stored();
    let grant = reuse(&stored, stored.spec.clone()).unwrap();
    assert_eq!(grant.key(), kv_state_key(&stored));
    // The key is built over T07's scope key, so another session's authority changes it.
    let mut other_session = stored.clone();
    other_session.spec.scope.authority = authority("acme", 2);
    assert_ne!(kv_state_key(&other_session), grant.key());
}

#[test]
fn a_mismatch_in_any_key_component_refuses_reuse() {
    let stored = stored();
    let base = stored.spec.clone();
    let with = |change: &dyn Fn(&mut KvReuseSpec)| {
        let mut spec = base.clone();
        change(&mut spec);
        spec
    };
    let cases: Vec<(KvReuseSpec, KvReuseRefusal)> = vec![
        (
            with(&|spec| spec.scope.model = execution_identity("base-8b-instruct")),
            scope_mismatch(vec![KvScopeComponent::Model]),
        ),
        (
            with(&|spec| spec.scope.tokenizer = id("tokenizer-v2")),
            scope_mismatch(vec![KvScopeComponent::Tokenizer]),
        ),
        (
            with(&|spec| spec.scope.adapter = None),
            scope_mismatch(vec![KvScopeComponent::Adapter]),
        ),
        (
            with(&|spec| spec.scope.adapter = Some(adapter_identity("adapter-legal"))),
            scope_mismatch(vec![KvScopeComponent::Adapter]),
        ),
        (
            with(&|spec| spec.scope.prefix = token_prefix("contract", 31_999)),
            scope_mismatch(vec![KvScopeComponent::Prefix]),
        ),
        (
            with(&|spec| spec.scope.prefix = token_prefix("another contract", 32_000)),
            scope_mismatch(vec![KvScopeComponent::Prefix]),
        ),
        (
            with(&|spec| {
                spec.scope.position = KvPosition {
                    encoding: rope(),
                    first_position: 1,
                }
            }),
            scope_mismatch(vec![KvScopeComponent::Position]),
        ),
        (
            with(&|spec| spec.scope.position.encoding.parameters = id("theta 5e5")),
            scope_mismatch(vec![KvScopeComponent::Position]),
        ),
        (
            with(&|spec| {
                spec.scope.cache = KvRepresentation::new(
                    Dtype::Float8E4M3,
                    Quantization::None,
                    16,
                    versioned("paged"),
                )
                .unwrap()
            }),
            scope_mismatch(vec![KvScopeComponent::CacheRepresentation]),
        ),
        (
            with(&|spec| {
                spec.scope.cache = KvRepresentation::new(
                    Dtype::BFloat16,
                    Quantization::None,
                    32,
                    versioned("paged"),
                )
                .unwrap()
            }),
            scope_mismatch(vec![KvScopeComponent::CacheRepresentation]),
        ),
        (
            with(&|spec| spec.attention_semantics = id("sliding window 4096")),
            KvReuseRefusal::AttentionSemanticsMismatch,
        ),
        (
            with(&|spec| spec.rank = RankPosition::new(1, 2).unwrap()),
            KvReuseRefusal::RankMismatch,
        ),
    ];
    for (wanted, refusal) in cases {
        assert_eq!(reuse(&stored, wanted.clone()), Err(refusal));
        let changed = StoredKv {
            spec: wanted,
            ..stored.clone()
        };
        assert_ne!(kv_state_key(&changed), kv_state_key(&stored));
    }
    assert_eq!(base.scope.cache, kv_cache());
}

#[test]
fn cross_tenant_kv_is_refused() {
    let stored = stored();
    let mut globex = stored.spec.clone();
    globex.scope.authority = authority("globex", 1);
    let refused = Err(scope_mismatch(vec![
        KvScopeComponent::Tenant,
        KvScopeComponent::SessionAuthority,
    ]));
    assert_eq!(reuse(&stored, globex.clone()), refused);
    // Listing the same prefix as public does not widen a tenant-scoped entry.
    let sharing = allowed(PublicPrefixScope {
        prefix: stored.spec.scope.prefix,
        trust_scope: trust(),
    });
    assert_eq!(
        check_kv_reuse(
            &stored,
            &request(globex),
            &sharing,
            &standing(),
            &verified(),
            NOW
        ),
        refused
    );
}

#[test]
fn another_trust_scope_or_a_raised_epoch_is_refused() {
    let stored = stored();
    for trust_scope in [
        TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, "models"),
        TrustScope::named(ExecutionCategory::VmSandbox, "other models"),
    ] {
        let elsewhere = KvRequest {
            spec: stored.spec.clone(),
            trust_scope,
        };
        assert_eq!(
            check_kv_reuse(
                &stored,
                &elsewhere,
                &PublicPrefixSharing::none(),
                &standing(),
                &verified(),
                NOW
            ),
            Err(by_t07(identity::KvReuseRefusal::OtherTrustScope))
        );
    }
    let mut revoked = stored.spec.clone();
    revoked.scope.authority = authority("acme", 2);
    assert_eq!(
        reuse(&stored, revoked),
        Err(scope_mismatch(vec![KvScopeComponent::SessionAuthority]))
    );
}

#[test]
fn reuse_needs_a_backend_that_enforces_the_scope() {
    let stored = stored();
    let refused = Err(by_t07(identity::KvReuseRefusal::BackendDoesNotEnforceScope));
    assert_eq!(
        check_kv_reuse(
            &stored,
            &request(stored.spec.clone()),
            &PublicPrefixSharing::none(),
            &standing(),
            &ScopeEnforcement::NotVerified,
            NOW,
        ),
        refused
    );
    let prompt = kv_spec(
        execution_identity("base-8b"),
        None,
        512,
        "system prompt",
        "acme",
    );
    let public = StoredKv {
        sharing: KvSharing::PublicPrefix {
            prefix: prompt.scope.prefix,
        },
        spec: prompt.clone(),
        trust_scope: trust(),
    };
    let sharing = allowed(PublicPrefixScope {
        prefix: prompt.scope.prefix,
        trust_scope: trust(),
    });
    assert_eq!(
        check_kv_reuse(
            &public,
            &request(prompt.clone()),
            &sharing,
            &standing(),
            &ScopeEnforcement::NotVerified,
            NOW
        ),
        refused
    );
    // The evidence is fresh for an hour from 0 ns, and not a nanosecond longer.
    let fresh_until = MonotonicTime::ZERO.saturating_add(std::time::Duration::from_secs(3_600));
    let at = |now| {
        check_kv_reuse(
            &public,
            &request(prompt.clone()),
            &sharing,
            &standing(),
            &verified(),
            now,
        )
    };
    assert!(at(fresh_until).is_ok());
    let late = MonotonicTime::from_nanos(fresh_until.as_nanos() + 1);
    assert_eq!(
        at(late),
        Err(by_t07(identity::KvReuseRefusal::EnforcementEvidenceStale {
            fresh_until,
            now: late,
        }))
    );
}

#[test]
fn public_prefix_sharing_needs_explicit_configuration() {
    let prompt = kv_spec(
        execution_identity("base-8b"),
        None,
        512,
        "system prompt",
        "acme",
    );
    let prefix = prompt.scope.prefix;
    let public = StoredKv {
        spec: prompt.clone(),
        trust_scope: trust(),
        sharing: KvSharing::PublicPrefix { prefix },
    };
    let mut globex = prompt.clone();
    globex.scope.authority = authority("globex", 7);
    let check = |sharing: &PublicPrefixSharing, wanted: &KvRequest| {
        check_kv_reuse(&public, wanted, sharing, &standing(), &verified(), NOW)
    };
    let not_configured = Err(by_t07(identity::KvReuseRefusal::PublicPrefixNotConfigured));
    assert_eq!(
        check(&PublicPrefixSharing::none(), &request(globex.clone())),
        not_configured
    );
    let elsewhere = allowed(PublicPrefixScope {
        prefix,
        trust_scope: TrustScope::named(ExecutionCategory::VmSandbox, "other models"),
    });
    assert_eq!(check(&elsewhere, &request(globex.clone())), not_configured);

    let sharing = allowed(PublicPrefixScope {
        prefix,
        trust_scope: trust(),
    });
    let grant = check(&sharing, &request(globex.clone())).unwrap();
    assert_eq!(grant.key(), kv_state_key(&public));
    assert!(check(&sharing, &request(prompt.clone())).is_ok());

    let outsider = KvRequest {
        spec: globex.clone(),
        trust_scope: TrustScope::named(ExecutionCategory::ProviderContainerRuntime, "models"),
    };
    assert_eq!(
        check(&sharing, &outsider),
        Err(by_t07(identity::KvReuseRefusal::OtherTrustScope))
    );
    // Components other than the tenant and session authority still have to match.
    let mut other_model = globex.clone();
    other_model.scope.model = execution_identity("base-70b");
    assert_eq!(
        check(&sharing, &request(other_model)),
        Err(scope_mismatch(vec![KvScopeComponent::Model]))
    );

    // An entry that holds more than the configured prefix may carry tenant state.
    let longer = kv_spec(
        execution_identity("base-8b"),
        None,
        900,
        "system prompt",
        "acme",
    );
    let extended = StoredKv {
        spec: longer.clone(),
        trust_scope: trust(),
        sharing: KvSharing::PublicPrefix { prefix },
    };
    let mut wanted = longer;
    wanted.scope.authority = authority("globex", 7);
    assert_eq!(
        check_kv_reuse(
            &extended,
            &request(wanted),
            &sharing,
            &standing(),
            &verified(),
            NOW
        ),
        Err(by_t07(identity::KvReuseRefusal::BeyondPublicPrefix))
    );
}

#[test]
fn a_revoked_authority_ends_public_prefix_sharing_at_once() {
    // Acme's sandbox publishes its system prompt; globex reuses it until acme's sandbox is
    // revoked, whose allowance and KV then stop at the next check.
    let prompt = kv_spec(
        execution_identity("base-8b"),
        None,
        512,
        "system prompt",
        "acme",
    );
    let prefix = prompt.scope.prefix;
    let public = StoredKv {
        spec: prompt.clone(),
        trust_scope: trust(),
        sharing: KvSharing::PublicPrefix { prefix },
    };
    let mut globex = prompt;
    globex.scope.authority = authority("globex", 7);
    let mut sharing = PublicPrefixSharing::none();
    let scope = PublicPrefixScope {
        prefix,
        trust_scope: trust(),
    };
    sharing.allow(scope, authority("acme", 1).session);
    let mut revocations = RevokedAuthorities::new();
    let check = |sharing: &PublicPrefixSharing, revocations: &RevokedAuthorities| {
        check_kv_reuse(
            &public,
            &request(globex.clone()),
            sharing,
            revocations,
            &verified(),
            NOW,
        )
    };
    assert!(check(&sharing, &revocations).is_ok());

    // The coordinator revokes acme's sandbox: its KV is never reused again.
    revocations.record(&revocation("acme", 1));
    assert_eq!(
        check(&sharing, &revocations),
        Err(by_t07(identity::KvReuseRefusal::ProducerRevoked))
    );

    // KV made by a standing sandbox under an allowance whose only authority was revoked.
    let initech_made = StoredKv {
        spec: KvReuseSpec {
            scope: KvScopeSpec {
                authority: authority("initech", 3),
                ..public.spec.scope.clone()
            },
            ..public.spec.clone()
        },
        ..public.clone()
    };
    let wanted = request(globex.clone());
    let reuse_initech = |sharing: &PublicPrefixSharing, revocations: &RevokedAuthorities| {
        check_kv_reuse(
            &initech_made,
            &wanted,
            sharing,
            revocations,
            &verified(),
            NOW,
        )
    };
    assert_eq!(
        reuse_initech(&sharing, &revocations),
        Err(by_t07(identity::KvReuseRefusal::PublicPrefixRevoked))
    );
    // Initech allowing the prefix under its own standing sandbox makes it public again.
    sharing.allow(scope, authority("initech", 3).session);
    assert!(reuse_initech(&sharing, &revocations).is_ok());

    // A revoked requester is granted nothing.
    revocations.record(&revocation("globex", 7));
    assert_eq!(
        reuse_initech(&sharing, &revocations),
        Err(by_t07(identity::KvReuseRefusal::RequesterRevoked))
    );
}

#[test]
fn state_keys_bind_trust_scope_and_sharing() {
    let prompt = kv_spec(
        execution_identity("base-8b"),
        None,
        512,
        "system prompt",
        "acme",
    );
    let tenant_scoped = StoredKv {
        spec: prompt.clone(),
        trust_scope: trust(),
        sharing: KvSharing::TenantScoped,
    };
    let public = StoredKv {
        sharing: KvSharing::PublicPrefix {
            prefix: prompt.scope.prefix,
        },
        ..tenant_scoped.clone()
    };
    let elsewhere = StoredKv {
        trust_scope: TrustScope::named(ExecutionCategory::HostProcessModelRuntime, "models"),
        ..tenant_scoped.clone()
    };
    let globex_public = StoredKv {
        spec: KvReuseSpec {
            scope: KvScopeSpec {
                authority: authority("globex", 1),
                ..prompt.scope.clone()
            },
            ..prompt.clone()
        },
        ..public.clone()
    };
    assert_eq!(
        kv_state_key(&tenant_scoped),
        kv_state_key(&tenant_scoped.clone())
    );
    assert_ne!(kv_state_key(&tenant_scoped), kv_state_key(&public));
    assert_ne!(kv_state_key(&tenant_scoped), kv_state_key(&elsewhere));
    // Two tenants' copies of one public prefix share T07's reuse key but stay two states.
    assert_eq!(
        public.reuse_scope().key(),
        globex_public.reuse_scope().key()
    );
    assert_ne!(kv_state_key(&public), kv_state_key(&globex_public));
    assert_eq!(KV_STATE_DOMAIN, "yougori/model-memory/adapters/kv-state/v2");
}

#[test]
fn a_rank_lies_inside_its_topology() {
    assert_eq!(RankPosition::new(2, 2), None);
    assert_eq!(RankPosition::new(0, 0), None);
    let rank = RankPosition::new(1, 2).unwrap();
    assert_eq!((rank.index(), rank.world_size()), (1, 2));
}

#[test]
fn an_engine_can_use_only_kv_it_matches() {
    let kv = stored().spec;
    let engine = engine(execution_identity("base-8b"));
    assert!(engine.can_use(&kv));
    let changed = [
        EngineKvProfile {
            reuses_prefix_kv: false,
            ..engine.clone()
        },
        EngineKvProfile {
            enforcement: ScopeEnforcement::NotVerified,
            ..engine.clone()
        },
        EngineKvProfile {
            model: execution_identity("base-70b"),
            ..engine.clone()
        },
        EngineKvProfile {
            tokenizer: id("tokenizer-v2"),
            ..engine.clone()
        },
        EngineKvProfile {
            positional_encoding: PositionalEncoding {
                scheme: versioned("yarn"),
                parameters: id("factor 4"),
            },
            ..engine.clone()
        },
        EngineKvProfile {
            cache: KvRepresentation::new(
                Dtype::Float8E5M2,
                Quantization::None,
                16,
                versioned("paged"),
            )
            .unwrap(),
            ..engine.clone()
        },
        EngineKvProfile {
            attention_semantics: id("sliding window 4096"),
            ..engine.clone()
        },
        EngineKvProfile {
            rank: RankPosition::new(1, 2).unwrap(),
            ..engine.clone()
        },
    ];
    for other in changed {
        assert!(!other.can_use(&kv), "{other:?}");
    }
}

#[test]
fn refusals_explain_themselves() {
    assert!(by_t07(identity::KvReuseRefusal::OtherTrustScope)
        .to_string()
        .contains("trust scope"));
    assert!(KvReuseRefusal::RankMismatch.to_string().contains("rank"));
    assert!(scope_mismatch(vec![KvScopeComponent::Tenant])
        .to_string()
        .contains("Tenant"));
}
