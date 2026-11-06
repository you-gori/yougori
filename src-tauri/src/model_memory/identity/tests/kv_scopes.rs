//! FAST-03 (line 243): reusable KV blocks bind the exact model, tokenizer, adapter,
//! prefix, position, cache representation and tenant/session authority; reuse across
//! requests needs every component to match and CORE-01 evidence, still fresh, that the
//! backend enforces the scope. Section 3.9 line 636: sessions stay tenant-scoped unless a
//! public prefix is explicitly configured, and KV never crosses a trust scope.

use std::collections::BTreeSet;
use std::time::Duration;

use crate::foundation::coordination::RevocationNotice;
use crate::foundation::ids::{AuthorizationEpoch, ExecutionCategory, MonotonicTime};

use super::super::fakes::scope_enforcement;
use super::super::*;
use super::support::*;

fn mutations() -> Vec<(&'static str, KvScopeComponent, KvScopeSpec)> {
    let base = kv_scope_spec();
    let authority = |tenant_name: &str, session: AuthorityBinding| KvAuthority {
        tenant: tenant(tenant_name),
        session,
    };
    let fp8 = QuantizationScheme::new(versioned("fp8-kv", "1"), 8, None, d("kv-scales")).unwrap();
    vec![
        (
            "model",
            KvScopeComponent::Model,
            KvScopeSpec {
                model: ExecutionSpec {
                    runner: versioned("vllm", "0.31.0"),
                    ..execution_spec()
                }
                .identity()
                .unwrap(),
                ..base.clone()
            },
        ),
        (
            "tokenizer",
            KvScopeComponent::Tokenizer,
            KvScopeSpec {
                tokenizer: d("other-tokenizer"),
                ..base.clone()
            },
        ),
        (
            "no adapter",
            KvScopeComponent::Adapter,
            KvScopeSpec {
                adapter: None,
                ..base.clone()
            },
        ),
        (
            "other adapter",
            KvScopeComponent::Adapter,
            KvScopeSpec {
                adapter: Some(adapter("org/other-lora")),
                ..base.clone()
            },
        ),
        (
            "prefix",
            KvScopeComponent::Prefix,
            KvScopeSpec {
                prefix: TokenPrefix::from_token_ids(&[128_000, 9906, 11, 1918]),
                ..base.clone()
            },
        ),
        (
            "shorter prefix",
            KvScopeComponent::Prefix,
            KvScopeSpec {
                prefix: TokenPrefix::from_token_ids(&[128_000, 9906, 11]),
                ..base.clone()
            },
        ),
        (
            "first position",
            KvScopeComponent::Position,
            KvScopeSpec {
                position: KvPosition {
                    first_position: 4,
                    ..base.position.clone()
                },
                ..base.clone()
            },
        ),
        (
            "positional encoding",
            KvScopeComponent::Position,
            KvScopeSpec {
                position: KvPosition {
                    encoding: PositionalEncoding {
                        parameters: d("rope-yarn-factor-4"),
                        ..rope()
                    },
                    first_position: 0,
                },
                ..base.clone()
            },
        ),
        (
            "cache dtype",
            KvScopeComponent::CacheRepresentation,
            KvScopeSpec {
                cache: KvRepresentation::new(
                    Dtype::Float8E4M3,
                    Quantization::Scheme(fp8),
                    16,
                    versioned("paged", "1"),
                )
                .unwrap(),
                ..base.clone()
            },
        ),
        (
            "cache block",
            KvScopeComponent::CacheRepresentation,
            KvScopeSpec {
                cache: KvRepresentation::new(
                    Dtype::BFloat16,
                    Quantization::None,
                    32,
                    versioned("paged", "1"),
                )
                .unwrap(),
                ..base.clone()
            },
        ),
        (
            "tenant",
            KvScopeComponent::Tenant,
            KvScopeSpec {
                authority: authority("tenant-b", vm_binding("exe-session", 3)),
                ..base.clone()
            },
        ),
        (
            "session parent",
            KvScopeComponent::SessionAuthority,
            KvScopeSpec {
                authority: authority("tenant-a", vm_binding("exe-other-session", 3)),
                ..base.clone()
            },
        ),
        (
            "authorization epoch",
            KvScopeComponent::SessionAuthority,
            KvScopeSpec {
                authority: authority("tenant-a", vm_binding("exe-session", 4)),
                ..base.clone()
            },
        ),
        (
            "runtime category",
            KvScopeComponent::SessionAuthority,
            KvScopeSpec {
                authority: authority(
                    "tenant-a",
                    AuthorityBinding::new(
                        exe("exe-session"),
                        ExecutionCategory::HostProcessModelRuntime,
                        Some(AuthorizationEpoch::new(3)),
                    )
                    .unwrap(),
                ),
                ..base
            },
        ),
    ]
}

#[test]
fn kv_reuse_needs_every_component_to_match() {
    let stored = kv_scope_spec();
    let mut covered = BTreeSet::new();
    let mut keys = vec![("stored", stored.key())];
    for (name, component, request) in mutations() {
        assert_eq!(
            check_kv_reuse(&stored, &request, &enforced()),
            Err(KvReuseRefusal::ScopeMismatch {
                components: vec![component],
            }),
            "{name}"
        );
        assert_eq!(stored.mismatches(&request), vec![component], "{name}");
        covered.insert(component);
        keys.push((name, request.key()));
    }
    assert_eq!(
        covered,
        KvScopeComponent::ALL.into_iter().collect::<BTreeSet<_>>(),
        "every FAST-03 component is exercised"
    );
    assert_all_distinct(&keys);
}

#[test]
fn kv_reuse_matches_when_every_component_matches() {
    let stored = kv_scope_spec();
    assert_eq!(
        check_kv_reuse(&stored, &kv_scope_spec(), &enforced()),
        Ok(stored.key())
    );
    assert!(stored.mismatches(&kv_scope_spec()).is_empty());
}

#[test]
fn kv_reuse_needs_a_backend_that_enforces_the_scope() {
    // Even an exact match stays disabled when the backend cannot enforce the scope.
    assert_eq!(
        check_kv_reuse(
            &kv_scope_spec(),
            &kv_scope_spec(),
            &ScopeEnforcement::NotVerified
        ),
        Err(KvReuseRefusal::BackendDoesNotEnforceScope)
    );
}

#[test]
fn cross_tenant_kv_reuse_is_refused() {
    let other_tenant = KvScopeSpec {
        authority: KvAuthority {
            tenant: tenant("tenant-b"),
            session: vm_binding("exe-tenant-b-session", 3),
        },
        ..kv_scope_spec()
    };
    assert_eq!(
        check_kv_reuse(&kv_scope_spec(), &other_tenant, &enforced()),
        Err(KvReuseRefusal::ScopeMismatch {
            components: vec![KvScopeComponent::Tenant, KvScopeComponent::SessionAuthority],
        })
    );
}

#[test]
fn every_mismatch_is_reported() {
    let everything_else = KvScopeSpec {
        model: ExecutionSpec {
            runner: versioned("sglang", "0.4.0"),
            ..execution_spec()
        }
        .identity()
        .unwrap(),
        tokenizer: d("other-tokenizer"),
        adapter: None,
        prefix: TokenPrefix::from_token_ids(&[1]),
        position: KvPosition {
            encoding: rope(),
            first_position: 9,
        },
        cache: KvRepresentation::new(
            Dtype::Float16,
            Quantization::None,
            16,
            versioned("paged", "1"),
        )
        .unwrap(),
        authority: KvAuthority {
            tenant: tenant("tenant-z"),
            session: vm_binding("exe-z", 1),
        },
    };
    assert_eq!(
        kv_scope_spec().mismatches(&everything_else),
        KvScopeComponent::ALL.to_vec()
    );
}

#[test]
fn scope_enforcement_is_registry_evidence_that_stays_fresh_only_so_long() {
    let enforcement = scope_enforcement(at(1_000), Duration::from_nanos(500));
    assert!(enforcement.is_verified());
    let ScopeEnforcement::Verified { evidence } = &enforcement else {
        panic!("the registry's evaluation verifies the scope");
    };
    assert_eq!(evidence.observed_at(), at(1_000));
    assert_eq!(evidence.fresh_until(), at(1_500));
    assert_eq!(enforcement.fresh_at(at(1_500)), Ok(evidence));
    assert_eq!(
        enforcement.fresh_at(at(1_501)),
        Err(KvReuseRefusal::EnforcementEvidenceStale {
            fresh_until: at(1_500),
            now: at(1_501),
        })
    );
    assert!(!ScopeEnforcement::NotVerified.is_verified());
    assert_eq!(
        ScopeEnforcement::NotVerified.fresh_at(at(0)),
        Err(KvReuseRefusal::BackendDoesNotEnforceScope)
    );
}

fn vm(name: &str) -> TrustScope {
    TrustScope::named(ExecutionCategory::VmSandbox, name)
}

fn public_prefix() -> TokenPrefix {
    kv_scope_spec().prefix
}

/// Tenant A's block of the fixture prefix in VM 1, shared as `sharing`.
fn stored_in(sharing: KvSharing) -> KvReuseScope {
    KvReuseScope {
        spec: kv_scope_spec(),
        trust_scope: vm("vm-1"),
        sharing,
    }
}

fn public_block() -> KvReuseScope {
    stored_in(KvSharing::PublicPrefix {
        prefix: public_prefix(),
    })
}

/// The same KV, asked for by tenant B's session in VM 1.
fn tenant_b_request() -> KvReuseRequest {
    KvReuseRequest {
        spec: KvScopeSpec {
            authority: KvAuthority {
                tenant: tenant("tenant-b"),
                session: vm_binding("exe-tenant-b-session", 3),
            },
            ..kv_scope_spec()
        },
        trust_scope: vm("vm-1"),
    }
}

fn own_request() -> KvReuseRequest {
    KvReuseRequest {
        spec: kv_scope_spec(),
        trust_scope: vm("vm-1"),
    }
}

/// The session authority of tenant A's block, which also allows its prefix.
fn tenant_a_session() -> AuthorityBinding {
    vm_binding("exe-session", 3)
}

/// Tenant A's prefix allowed as public in VM 1 under tenant A's session authority.
fn configured() -> PublicPrefixSharing {
    let mut sharing = PublicPrefixSharing::none();
    sharing.allow(
        PublicPrefixScope {
            prefix: public_prefix(),
            trust_scope: vm("vm-1"),
        },
        tenant_a_session(),
    );
    sharing
}

/// The check with nothing revoked.
fn check(
    stored: &KvReuseScope,
    request: &KvReuseRequest,
    sharing: &PublicPrefixSharing,
    enforcement: &ScopeEnforcement,
    now: MonotonicTime,
) -> Result<KvReuseKey, KvReuseRefusal> {
    check_scoped_kv_reuse(
        stored,
        request,
        sharing,
        &RevokedAuthorities::new(),
        enforcement,
        now,
    )
}

#[test]
fn kv_stays_tenant_scoped_unless_a_public_prefix_is_configured() {
    let now = at(100);
    let tenant_scoped = stored_in(KvSharing::TenantScoped);
    assert_eq!(
        check(
            &tenant_scoped,
            &own_request(),
            &configured(),
            &enforced(),
            now
        ),
        Ok(tenant_scoped.key())
    );
    // Configuring the prefix as public does not open a tenant-scoped block.
    assert_eq!(
        check(
            &tenant_scoped,
            &tenant_b_request(),
            &configured(),
            &enforced(),
            now
        ),
        Err(KvReuseRefusal::ScopeMismatch {
            components: vec![KvScopeComponent::Tenant, KvScopeComponent::SessionAuthority],
        })
    );
    // A public-prefix block serves another tenant only while the prefix is configured.
    assert_eq!(
        check(
            &public_block(),
            &tenant_b_request(),
            &PublicPrefixSharing::none(),
            &enforced(),
            now
        ),
        Err(KvReuseRefusal::PublicPrefixNotConfigured)
    );
    assert_eq!(
        check(
            &public_block(),
            &tenant_b_request(),
            &configured(),
            &enforced(),
            now
        ),
        Ok(public_block().key())
    );
}

#[test]
fn a_revoked_public_prefix_is_refused_at_the_next_check() {
    let mut sharing = configured();
    let scope = PublicPrefixScope {
        prefix: public_prefix(),
        trust_scope: vm("vm-1"),
    };
    assert!(sharing.allows(&scope, &RevokedAuthorities::new()));
    assert!(sharing.revoke(&scope));
    assert!(!sharing.revoke(&scope), "revoked once");
    assert!(!sharing.allows(&scope, &RevokedAuthorities::new()));
    assert!(!sharing.is_configured(&scope));
    assert_eq!(
        check(
            &public_block(),
            &tenant_b_request(),
            &sharing,
            &enforced(),
            at(100)
        ),
        Err(KvReuseRefusal::PublicPrefixNotConfigured)
    );
}

#[test]
fn a_public_prefix_is_configured_per_trust_scope() {
    let mut elsewhere = PublicPrefixSharing::none();
    elsewhere.allow(
        PublicPrefixScope {
            prefix: public_prefix(),
            trust_scope: vm("vm-2"),
        },
        tenant_a_session(),
    );
    assert_eq!(
        check(
            &public_block(),
            &tenant_b_request(),
            &elsewhere,
            &enforced(),
            at(100)
        ),
        Err(KvReuseRefusal::PublicPrefixNotConfigured)
    );
}

#[test]
fn kv_never_crosses_a_trust_scope_even_when_public() {
    for stored in [stored_in(KvSharing::TenantScoped), public_block()] {
        for request in [own_request(), tenant_b_request()] {
            let other_vm = KvReuseRequest {
                trust_scope: vm("vm-2"),
                ..request
            };
            assert_eq!(
                check(&stored, &other_vm, &configured(), &enforced(), at(100)),
                Err(KvReuseRefusal::OtherTrustScope)
            );
        }
    }
}

#[test]
fn a_public_block_holds_nothing_beyond_its_prefix() {
    // The block covers more tokens than the configured public prefix.
    let longer = TokenPrefix::from_token_ids(&[128_000, 9906, 11, 1917, 42]);
    let beyond = KvReuseScope {
        spec: KvScopeSpec {
            prefix: longer,
            ..kv_scope_spec()
        },
        ..public_block()
    };
    let request = KvReuseRequest {
        spec: KvScopeSpec {
            prefix: longer,
            ..tenant_b_request().spec
        },
        ..tenant_b_request()
    };
    assert_eq!(
        check(&beyond, &request, &configured(), &enforced(), at(100)),
        Err(KvReuseRefusal::BeyondPublicPrefix)
    );
}

#[test]
fn a_public_block_still_needs_every_other_component_to_match() {
    for (name, component, spec) in mutations() {
        if component.is_authority() {
            continue;
        }
        let request = KvReuseRequest {
            spec: KvScopeSpec {
                authority: tenant_b_request().spec.authority,
                ..spec
            },
            trust_scope: vm("vm-1"),
        };
        assert_eq!(
            check(
                &public_block(),
                &request,
                &configured(),
                &enforced(),
                at(100)
            ),
            Err(KvReuseRefusal::ScopeMismatch {
                components: vec![component],
            }),
            "{name}"
        );
    }
    assert_eq!(
        KvScopeComponent::ALL
            .into_iter()
            .filter(|component| component.is_authority())
            .collect::<Vec<_>>(),
        vec![KvScopeComponent::Tenant, KvScopeComponent::SessionAuthority]
    );
}

#[test]
fn shared_reuse_needs_fresh_scope_enforcement() {
    for stored in [stored_in(KvSharing::TenantScoped), public_block()] {
        assert_eq!(
            check(
                &stored,
                &own_request(),
                &configured(),
                &ScopeEnforcement::NotVerified,
                at(100)
            ),
            Err(KvReuseRefusal::BackendDoesNotEnforceScope)
        );
        let short = scope_enforcement(at(0), Duration::from_nanos(100));
        assert!(check(&stored, &own_request(), &configured(), &short, at(100)).is_ok());
        assert_eq!(
            check(&stored, &own_request(), &configured(), &short, at(101)),
            Err(KvReuseRefusal::EnforcementEvidenceStale {
                fresh_until: at(100),
                now: at(101),
            })
        );
    }
}

#[test]
fn reuse_keys_separate_sharing_trust_scope_and_tenant_scoped_authority() {
    let tenant_scoped = stored_in(KvSharing::TenantScoped);
    let tenant_b_block = KvReuseScope {
        spec: tenant_b_request().spec,
        ..tenant_scoped.clone()
    };
    let tenant_b_public = KvReuseScope {
        spec: tenant_b_request().spec,
        ..public_block()
    };
    assert_eq!(
        public_block().key(),
        tenant_b_public.key(),
        "tenants sharing one public block share its key"
    );
    assert_all_distinct(&[
        ("tenant scoped", tenant_scoped.key()),
        ("tenant b's block", tenant_b_block.key()),
        ("public", public_block().key()),
        (
            "public in vm 2",
            KvReuseScope {
                trust_scope: vm("vm-2"),
                ..public_block()
            }
            .key(),
        ),
        (
            "tenant scoped in vm 2",
            KvReuseScope {
                trust_scope: vm("vm-2"),
                ..tenant_scoped.clone()
            }
            .key(),
        ),
    ]);
    // The reuse key lives in its own domain, apart from the FAST-03 scope key.
    assert_ne!(tenant_scoped.key().digest(), kv_scope_spec().key().digest());
}

/// The coordinator's notice that `parent`'s authority was revoked at `epoch`.
fn notice(parent: &str, epoch: u64) -> RevocationNotice {
    RevocationNotice {
        execution: exe(parent),
        revoked: AuthorizationEpoch::new(epoch),
        current: AuthorizationEpoch::new(epoch + 1),
        at: at(50),
    }
}

/// Tenant C's block of the same public prefix, made by a session that stands.
fn tenant_c_block() -> KvReuseScope {
    KvReuseScope {
        spec: KvScopeSpec {
            authority: KvAuthority {
                tenant: tenant("tenant-c"),
                session: vm_binding("exe-tenant-c-session", 3),
            },
            ..kv_scope_spec()
        },
        ..public_block()
    }
}

#[test]
fn a_public_prefix_allowance_ends_when_its_authority_is_revoked() {
    let sharing = configured();
    let mut revocations = RevokedAuthorities::new();
    let reuse = |stored: &KvReuseScope, revocations: &RevokedAuthorities| {
        check_scoped_kv_reuse(
            stored,
            &tenant_b_request(),
            &sharing,
            revocations,
            &enforced(),
            at(100),
        )
    };
    assert_eq!(
        reuse(&tenant_c_block(), &revocations),
        Ok(tenant_c_block().key())
    );
    // Revoking another execution, or tenant A's parent at an older epoch, changes nothing.
    revocations.record(&notice("exe-unrelated", 9));
    revocations.record(&notice("exe-session", 2));
    assert!(reuse(&tenant_c_block(), &revocations).is_ok());

    // The coordinator revokes tenant A's sandbox at the allowance's epoch: at once, the
    // prefix is no longer public, though it stays configured.
    revocations.record(&notice("exe-session", 3));
    assert_eq!(
        reuse(&tenant_c_block(), &revocations),
        Err(KvReuseRefusal::PublicPrefixRevoked)
    );
    let scope = PublicPrefixScope {
        prefix: public_prefix(),
        trust_scope: vm("vm-1"),
    };
    assert!(sharing.is_configured(&scope));
    assert!(!sharing.allows(&scope, &revocations));
    // And nothing tenant A's revoked session made is reused.
    assert_eq!(
        reuse(&public_block(), &revocations),
        Err(KvReuseRefusal::ProducerRevoked)
    );

    // An allowance under another standing authority keeps the prefix public.
    let mut also = sharing.clone();
    also.allow(scope, vm_binding("exe-tenant-c-session", 3));
    assert!(also.allows(&scope, &revocations));
    assert!(check_scoped_kv_reuse(
        &tenant_c_block(),
        &tenant_b_request(),
        &also,
        &revocations,
        &enforced(),
        at(100)
    )
    .is_ok());
}

#[test]
fn a_revoked_requester_or_producer_reuses_nothing() {
    let own = stored_in(KvSharing::TenantScoped);
    let mut revocations = RevokedAuthorities::new();
    revocations.record(&notice("exe-session", 3));
    // Tenant-scoped KV: the session asking is the session that made it, now revoked.
    assert_eq!(
        check_scoped_kv_reuse(
            &own,
            &own_request(),
            &PublicPrefixSharing::none(),
            &revocations,
            &enforced(),
            at(100)
        ),
        Err(KvReuseRefusal::RequesterRevoked)
    );
    // A revoked tenant B asks for a public block made by a standing tenant C.
    let mut revoked_b = RevokedAuthorities::new();
    revoked_b.record(&notice("exe-tenant-b-session", 3));
    assert_eq!(
        check_scoped_kv_reuse(
            &tenant_c_block(),
            &tenant_b_request(),
            &configured(),
            &revoked_b,
            &enforced(),
            at(100)
        ),
        Err(KvReuseRefusal::RequesterRevoked)
    );
    // Revocation is checked after the trust scope and before the backend's evidence.
    let elsewhere = KvReuseRequest {
        trust_scope: vm("vm-2"),
        ..own_request()
    };
    assert_eq!(
        check_scoped_kv_reuse(
            &own,
            &elsewhere,
            &PublicPrefixSharing::none(),
            &revocations,
            &ScopeEnforcement::NotVerified,
            at(100)
        ),
        Err(KvReuseRefusal::OtherTrustScope)
    );
    assert_eq!(
        check_scoped_kv_reuse(
            &own,
            &own_request(),
            &PublicPrefixSharing::none(),
            &revocations,
            &ScopeEnforcement::NotVerified,
            at(100)
        ),
        Err(KvReuseRefusal::RequesterRevoked)
    );
}

#[test]
fn revoked_authorities_follow_the_coordinators_notices() {
    let mut revocations = RevokedAuthorities::new();
    let binding = |parent: &str, epoch: u64| vm_binding(parent, epoch);
    assert!(!revocations.is_revoked(&binding("exe-a", 1)));
    revocations.record(&notice("exe-a", 4));
    assert_eq!(
        revocations.revoked_epoch(&exe("exe-a")),
        Some(AuthorizationEpoch::new(4))
    );
    // Every epoch up to the revoked one is revoked; the epoch now in force is not.
    for epoch in 1..=4 {
        assert!(revocations.is_revoked(&binding("exe-a", epoch)), "{epoch}");
    }
    assert!(!revocations.is_revoked(&binding("exe-a", 5)));
    assert!(!revocations.is_revoked(&binding("exe-b", 1)));
    // A later notice never un-revokes, and an older one changes nothing.
    revocations.record(&notice("exe-a", 2));
    assert_eq!(
        revocations.revoked_epoch(&exe("exe-a")),
        Some(AuthorizationEpoch::new(4))
    );
    revocations.record(&notice("exe-a", 6));
    assert!(revocations.is_revoked(&binding("exe-a", 5)));
    // A binding without an epoch is revoked with its parent.
    let labelled = AuthorityBinding::new(
        exe("exe-a"),
        ExecutionCategory::SharedKernelGpuRuntime,
        None,
    )
    .unwrap();
    assert!(revocations.is_revoked(&labelled));
    let unrelated = AuthorityBinding::new(
        exe("exe-c"),
        ExecutionCategory::SharedKernelGpuRuntime,
        None,
    )
    .unwrap();
    assert!(!revocations.is_revoked(&unrelated));
}

#[test]
fn new_reuse_refusals_explain_themselves() {
    for (refusal, words) in [
        (KvReuseRefusal::PublicPrefixRevoked, "revoked"),
        (KvReuseRefusal::ProducerRevoked, "revoked"),
        (KvReuseRefusal::RequesterRevoked, "revoked"),
    ] {
        assert!(refusal.to_string().contains(words), "{refusal:?}");
    }
}
