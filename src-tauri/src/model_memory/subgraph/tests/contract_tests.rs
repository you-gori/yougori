//! The shared-subgraph state contract (line 894): authorization within a trust scope
//! through T07's scoped grants (S3.3), the §3.9 checks it cannot bypass, and the refusal
//! to relabel incompatible state as reusable.

use std::collections::BTreeSet;
use std::time::Duration;

use super::*;
use crate::foundation::ids::{
    ContentKey, Digest, ManualClock, MonotonicTime, TenantId, TrustScope,
};
use crate::model_memory::adapters::kv::{
    check_kv_reuse, KvRequest, KvReuseRefusal, KvReuseSpec, KvSharing, PublicPrefixSharing,
    RankPosition, StoredKv,
};
use crate::model_memory::identity::fakes::{checked_grant, scope_enforcement};
use crate::model_memory::identity::RevokedAuthorities;
use crate::model_memory::identity::{
    self, GrantRefusal, GrantTerms, GrantedUse, KvAuthority, KvPosition, KvScopeComponent,
    KvScopeSpec, ScopedGrant,
};

const ACTIVATION: &[u8] = b"boundary activation";

struct Setup {
    a: ImmutableVariant,
    b: ImmutableVariant,
    state: SubgraphState,
    tokens: Vec<u32>,
}

/// Alice's state of variant A at the verified pair's branch boundary.
fn setup() -> Setup {
    let verified = family(PrototypePair::VerifiedSharedPrefix);
    let tokens = tokens(48, 4);
    let boundary = boundary_for(&verified.a, &verified.b, 48);
    let state = produce_state(
        &verified.a,
        &request(&verified.a, &alice(), &tokens),
        &boundary,
        ContentKey::of(ACTIVATION),
    )
    .unwrap();
    Setup {
        a: verified.a,
        b: verified.b,
        state,
        tokens,
    }
}

fn clock() -> ManualClock {
    ManualClock::new(MonotonicTime::from_nanos(1_000))
}

fn grant(to: &Who, artifact_of: &ImmutableVariant, uses: &[GrantedUse]) -> ScopedGrant {
    grant_in(&alice(), to, artifact_of, uses, scope())
}

/// A grant from `from` to `to`'s parent execution in `trust_scope`, checked through a
/// catalog.
fn grant_in(
    from: &Who,
    to: &Who,
    artifact_of: &ImmutableVariant,
    uses: &[GrantedUse],
    trust_scope: TrustScope,
) -> ScopedGrant {
    checked_grant(
        to.authority.parent(),
        GrantTerms {
            grantor: from.tenant.clone(),
            grantee: to.tenant.clone(),
            artifact: artifact_of.artifact(),
            scope: trust_scope,
            uses: uses.iter().copied().collect::<BTreeSet<_>>(),
            expires_at: MonotonicTime::from_nanos(10_000),
        },
    )
}

#[test]
fn the_producing_authority_reuses_the_shared_prefix() {
    let setup = setup();
    assert_eq!(setup.state.operators(), 6);
    assert_eq!(setup.state.owner(), &alice().tenant);
    assert_eq!(setup.state.producer(), setup.a.identity());
    let reuse = reuse_state(
        &setup.state,
        &setup.b,
        &request(&setup.b, &alice(), &setup.tokens),
        None,
        &clock(),
    )
    .unwrap();
    assert_eq!(reuse.operators(), 6);
    assert_eq!(reuse.valid_until(), None);
    assert_eq!(Some(reuse.boundary_key()), setup.state.boundary_key());
    assert_eq!(reuse.verify_received(&ContentKey::of(ACTIVATION)), Ok(()));
    assert_eq!(
        reuse.verify_received(&ContentKey::of(b"tampered")),
        Err(ReuseRefusal::ActivationMismatch)
    );
    // Another input never matches the stored keys.
    assert_eq!(
        reuse_state(
            &setup.state,
            &setup.b,
            &request(&setup.b, &alice(), &tokens(48, 5)),
            None,
            &clock()
        )
        .unwrap_err(),
        ReuseRefusal::InputDiffers
    );
}

#[test]
fn cross_scope_reuse_is_refused_with_or_without_a_grant() {
    let setup = setup();
    let elsewhere = custom_variant(
        &synthetic_model(REFERENCE_ROPE_THETA, &["head.weight"]),
        REFERENCE_ROPE_THETA,
        Some(&["layers.6.proj"]),
        |d| d.trust_scope = other_scope(),
    )
    .unwrap();
    let mut wants = request(&elsewhere, &alice(), &setup.tokens);
    let cross = grant_in(
        &alice(),
        &alice(),
        &setup.a,
        &[GrantedUse::ShareIntermediateState],
        other_scope(),
    );
    for presented in [None, Some(&cross)] {
        assert_eq!(
            reuse_state(&setup.state, &elsewhere, &wants, presented, &clock()).unwrap_err(),
            ReuseRefusal::DifferentTrustScope
        );
    }
    // A request claiming the producer's scope for a variant that runs elsewhere.
    wants.trust_scope = scope();
    assert_eq!(
        reuse_state(&setup.state, &elsewhere, &wants, None, &clock()).unwrap_err(),
        ReuseRefusal::DifferentTrustScope
    );
}

#[test]
fn another_tenant_in_the_same_scope_needs_the_owners_scoped_grant() {
    let setup = setup();
    let wants = request(&setup.b, &bob(), &setup.tokens);
    assert_eq!(
        reuse_state(&setup.state, &setup.b, &wants, None, &clock()).unwrap_err(),
        ReuseRefusal::Unauthorized(GrantRefusal::Missing)
    );
    let valid = grant(&bob(), &setup.a, &[GrantedUse::ShareIntermediateState]);
    let reuse = reuse_state(&setup.state, &setup.b, &wants, Some(&valid), &clock()).unwrap();
    assert_eq!(reuse.valid_until(), Some(MonotonicTime::from_nanos(10_000)));
    assert_eq!(
        reuse_state(
            &setup.state,
            &setup.b,
            &wants,
            Some(&grant(
                &bob(),
                &setup.a,
                &[GrantedUse::Serve, GrantedUse::Transfer]
            )),
            &clock()
        )
        .unwrap_err(),
        ReuseRefusal::Unauthorized(GrantRefusal::UseNotGranted {
            requested: GrantedUse::ShareIntermediateState
        })
    );
    // Sharing the artifact's device memory or storage is not sharing intermediate state.
    assert_eq!(
        reuse_state(
            &setup.state,
            &setup.b,
            &wants,
            Some(&grant(
                &bob(),
                &setup.a,
                &[
                    GrantedUse::ShareDeviceMemory,
                    GrantedUse::ShareImmutableStorage
                ]
            )),
            &clock()
        )
        .unwrap_err(),
        ReuseRefusal::Unauthorized(GrantRefusal::UseNotGranted {
            requested: GrantedUse::ShareIntermediateState
        })
    );
    assert_eq!(
        reuse_state(
            &setup.state,
            &setup.b,
            &wants,
            Some(&grant(
                &bob(),
                &setup.b,
                &[GrantedUse::ShareIntermediateState]
            )),
            &clock()
        )
        .unwrap_err(),
        ReuseRefusal::Unauthorized(GrantRefusal::ForAnotherArtifact)
    );
    let from_bob = grant_in(
        &bob(),
        &bob(),
        &setup.a,
        &[GrantedUse::ShareIntermediateState],
        scope(),
    );
    assert_eq!(
        reuse_state(&setup.state, &setup.b, &wants, Some(&from_bob), &clock()).unwrap_err(),
        ReuseRefusal::Unauthorized(GrantRefusal::NotFromOwner)
    );
    let late = clock();
    late.advance(Duration::from_nanos(9_000));
    assert!(matches!(
        reuse_state(&setup.state, &setup.b, &wants, Some(&valid), &late).unwrap_err(),
        ReuseRefusal::Unauthorized(GrantRefusal::Expired { .. })
    ));
}

#[test]
fn the_same_tenant_under_another_parent_execution_needs_a_grant_too() {
    let setup = setup();
    let other_parent = who("tenant-alice", "parent-alice-2", 1);
    let wants = request(&setup.b, &other_parent, &setup.tokens);
    assert_eq!(
        reuse_state(&setup.state, &setup.b, &wants, None, &clock()).unwrap_err(),
        ReuseRefusal::Unauthorized(GrantRefusal::Missing)
    );
    let own = grant(
        &other_parent,
        &setup.a,
        &[GrantedUse::ShareIntermediateState],
    );
    assert!(reuse_state(&setup.state, &setup.b, &wants, Some(&own), &clock()).is_ok());
}

#[test]
fn state_from_an_older_authorization_epoch_is_never_honoured_again() {
    let setup = setup();
    let revoked = who("tenant-alice", "parent-alice", 2);
    let wants = request(&setup.b, &revoked, &setup.tokens);
    let own = grant(&revoked, &setup.a, &[GrantedUse::ShareIntermediateState]);
    for presented in [None, Some(&own)] {
        assert_eq!(
            reuse_state(&setup.state, &setup.b, &wants, presented, &clock()).unwrap_err(),
            ReuseRefusal::AuthorityChanged
        );
    }
}

#[test]
fn the_section_3_9_session_checks_cannot_be_bypassed() {
    let setup = setup();
    let base_request = request(&setup.b, &alice(), &setup.tokens);
    let mut cases: Vec<(SessionComponent, SubgraphRequest)> = Vec::new();
    let mut wrong_execution = base_request.clone();
    wrong_execution.session.execution = setup.a.execution();
    cases.push((SessionComponent::Execution, wrong_execution));
    let mut no_adapter = base_request.clone();
    no_adapter.session.adapter = None;
    cases.push((SessionComponent::Adapter, no_adapter));
    let mut other_position = base_request.clone();
    other_position.session.positional_encoding = rope(500_000).unwrap();
    cases.push((SessionComponent::PositionalEncoding, other_position));
    let mut other_tenant = base_request.clone();
    other_tenant.session.tenant = TenantId::new("tenant-mallory").unwrap();
    cases.push((SessionComponent::Tenant, other_tenant));
    let mut other_authority = base_request.clone();
    other_authority.session.authority = bob().authority;
    cases.push((SessionComponent::Authority, other_authority));
    for (component, wants) in cases {
        assert_eq!(
            check_session(&setup.b, &wants),
            Err(ReuseRefusal::SessionMismatch { component })
        );
        assert_eq!(
            reuse_state(&setup.state, &setup.b, &wants, None, &clock()).unwrap_err(),
            ReuseRefusal::SessionMismatch { component }
        );
    }
    // Producing state for the wrong session is refused just the same.
    let boundary = boundary_for(&setup.a, &setup.b, 48);
    let mut wrong = request(&setup.a, &alice(), &setup.tokens);
    wrong.session.execution = setup.b.execution();
    assert_eq!(
        produce_state(&setup.a, &wrong, &boundary, ContentKey::of(ACTIVATION)).unwrap_err(),
        ReuseRefusal::SessionMismatch {
            component: SessionComponent::Execution
        }
    );
}

fn kv_spec(variant: &ImmutableVariant, tokens: &[u32]) -> KvReuseSpec {
    let session = request(variant, &alice(), tokens).session;
    KvReuseSpec {
        scope: KvScopeSpec {
            model: variant.execution(),
            tokenizer: Digest::from_bytes([2; 32]),
            adapter: variant.adapter(),
            prefix: identity::TokenPrefix::from_token_ids(tokens),
            position: KvPosition {
                encoding: variant.position().clone(),
                first_position: 0,
            },
            cache: session.kv,
            authority: KvAuthority {
                tenant: session.tenant,
                session: session.authority,
            },
        },
        attention_semantics: variant.attention().parameters,
        rank: RankPosition::new(0, 1).unwrap(),
    }
}

#[test]
fn a_verified_shared_prefix_never_makes_the_other_variants_kv_reusable() {
    let setup = setup();
    // The shared prefix is verified for this input ...
    assert!(reuse_state(
        &setup.state,
        &setup.b,
        &request(&setup.b, &alice(), &setup.tokens),
        None,
        &clock()
    )
    .is_ok());
    // ... yet A's whole KV cache stays unusable for B under the §3.9 check.
    let stored = StoredKv {
        spec: kv_spec(&setup.a, &setup.tokens),
        trust_scope: scope(),
        sharing: KvSharing::TenantScoped,
    };
    let wants = KvRequest {
        spec: kv_spec(&setup.b, &setup.tokens),
        trust_scope: scope(),
    };
    let refusal = check_kv_reuse(
        &stored,
        &wants,
        &PublicPrefixSharing::none(),
        &RevokedAuthorities::new(),
        &scope_enforcement(MonotonicTime::ZERO, Duration::from_secs(3_600)),
        MonotonicTime::ZERO,
    )
    .unwrap_err();
    match refusal {
        KvReuseRefusal::Scope(identity::KvReuseRefusal::ScopeMismatch { components }) => {
            assert!(components.contains(&KvScopeComponent::Model));
            assert!(components.contains(&KvScopeComponent::Adapter));
        }
        other => panic!("unexpected refusal {other:?}"),
    }
}

#[test]
fn a_state_claiming_more_than_the_provable_prefix_is_refused_whole() {
    let setup = setup();
    // A longer sibling of A lets A's whole operator chain be planned as a boundary.
    let longer = edited_base(|d| d.operators.push(d.operators[7].clone()));
    let whole = boundary_for(&setup.a, &longer, 48);
    assert_eq!(whole.operators(), 8);
    let entire = produce_state(
        &setup.a,
        &request(&setup.a, &alice(), &setup.tokens),
        &whole,
        ContentKey::of(ACTIVATION),
    )
    .unwrap();
    assert_eq!(entire.operators(), 8);
    let refusal = reuse_state(
        &entire,
        &setup.b,
        &request(&setup.b, &alice(), &setup.tokens),
        None,
        &clock(),
    )
    .unwrap_err();
    assert_eq!(
        refusal,
        ReuseRefusal::ClaimsBeyondSharedPrefix {
            claimed: 8,
            provable: 6,
            first_mismatch: Box::new(ReuseRefusal::KeyMismatch {
                operator: 6,
                components: vec![StateKeyComponent::AdapterEffects],
            }),
        }
    );
    // Nothing is provable for the control variant: the first operator's refusal.
    let control = family(PrototypePair::ControlFirstBlockDiffers);
    assert_eq!(
        reuse_state(
            &setup.state,
            &control.b,
            &request(&control.b, &alice(), &setup.tokens),
            None,
            &clock()
        )
        .unwrap_err(),
        ReuseRefusal::KeyMismatch {
            operator: 0,
            components: vec![StateKeyComponent::Parameters],
        }
    );
    // A consumer shorter than the state cannot take it either.
    let shorter = edited_base(|d| {
        d.operators.truncate(4);
    });
    assert!(matches!(
        reuse_state(
            &entire,
            &shorter,
            &request(&shorter, &alice(), &setup.tokens),
            None,
            &clock()
        )
        .unwrap_err(),
        ReuseRefusal::ClaimsBeyondSharedPrefix {
            claimed: 8,
            provable: 4,
            ..
        }
    ));
}

#[test]
fn state_is_produced_only_at_a_boundary_planned_for_the_variant() {
    let setup = setup();
    let control = family(PrototypePair::ControlFirstBlockDiffers);
    let longer = edited_base(|d| d.operators.push(d.operators[7].clone()));
    let foreign = boundary_for(&setup.a, &longer, 48);
    assert_eq!(
        produce_state(
            &control.b,
            &request(&control.b, &alice(), &setup.tokens),
            &foreign,
            ContentKey::of(ACTIVATION)
        )
        .unwrap_err(),
        ReuseRefusal::NotAPlannedBoundary
    );
    let boundary = boundary_for(&setup.a, &setup.b, 48);
    let mut elsewhere = request(&setup.a, &alice(), &setup.tokens);
    elsewhere.trust_scope = other_scope();
    assert_eq!(
        produce_state(&setup.a, &elsewhere, &boundary, ContentKey::of(ACTIVATION)).unwrap_err(),
        ReuseRefusal::DifferentTrustScope
    );
    // B's own state at the same boundary carries the same keys as A's.
    let from_b = produce_state(
        &setup.b,
        &request(&setup.b, &alice(), &setup.tokens),
        &boundary,
        ContentKey::of(ACTIVATION),
    )
    .unwrap();
    assert_eq!(from_b.keys(), setup.state.keys());
    assert_ne!(from_b.producer(), setup.state.producer());
}
