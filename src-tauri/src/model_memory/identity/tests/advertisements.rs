//! Line 506: a resident advertisement is a hint with an expiry and generation, not
//! authority to read the data; compatibility and authorization are rechecked before
//! serving or transferring, and nothing made under an older authority binding passes
//! (S3.1). Authorization stands on a live catalog grant (INT-05), and only a passing
//! recheck makes a [`RecheckedResidency`].

use crate::foundation::catalog::ReadRefusal;
use crate::foundation::ids::{
    AuthorizationEpoch, ExecutionCategory, ManualClock, ModelActivationGeneration, MonotonicTime,
};

use super::super::*;
use super::support::*;

fn vm_scope(name: &str) -> TrustScope {
    TrustScope::named(ExecutionCategory::VmSandbox, name)
}

fn residency() -> Residency {
    Residency {
        execution: execution(),
        artifact: artifact(),
        owner: tenant("tenant-a"),
        scope: vm_scope("vm-1"),
        device: gpu("host-a", "GPU-0"),
        authority: vm_binding("exe-parent", 3),
    }
}

fn advertisement(generation: u64, expires_at: u64) -> ResidentAdvertisement {
    ResidentAdvertisement {
        residency: residency(),
        generation: ModelActivationGeneration::new(generation),
        expires_at: at(expires_at),
    }
}

fn current(generation: u64) -> CurrentResidency {
    CurrentResidency {
        residency: residency(),
        generation: ModelActivationGeneration::new(generation),
    }
}

fn serve_request() -> AdvertisementRequest {
    AdvertisementRequest {
        requester: tenant("tenant-b"),
        required: execution(),
        purpose: AdvertisementPurpose::Serve,
    }
}

fn serve_terms() -> GrantTerms {
    terms(
        "tenant-a",
        "tenant-b",
        vm_scope("vm-1"),
        &[GrantedUse::Serve],
        500,
    )
}

impl World {
    /// A grant from tenant A to tenant B's execution, checked through the catalog.
    fn b_grant(&self, uses: &[GrantedUse], scope: TrustScope, expires_at: u64) -> ScopedGrant {
        self.grant(terms("tenant-a", "tenant-b", scope, uses, expires_at))
    }

    fn serve_grant(&self) -> ScopedGrant {
        self.grant(serve_terms())
    }
}

#[test]
fn a_fresh_compatible_authorized_advertisement_may_be_used_until_the_earlier_expiry() {
    let world = World::at(100);
    let clock = &*world.clock;
    let rechecked = advertisement(5, 1_000)
        .recheck(
            &current(5),
            &serve_request(),
            Some(&world.serve_grant()),
            clock,
        )
        .unwrap();
    assert_eq!(rechecked.residency, residency());
    assert_eq!(rechecked.generation, ModelActivationGeneration::new(5));
    assert_eq!(rechecked.valid_until, at(500), "the grant expires first");
    assert_eq!(
        rechecked.facts(),
        &RecheckedFacts {
            residency: residency(),
            generation: ModelActivationGeneration::new(5),
            valid_until: at(500),
        }
    );
    assert_eq!(rechecked.clone().into_facts(), *rechecked.facts());

    let long_grant = world.b_grant(&[GrantedUse::Serve], vm_scope("vm-1"), 5_000);
    let rechecked = advertisement(5, 1_000)
        .recheck(&current(5), &serve_request(), Some(&long_grant), clock)
        .unwrap();
    assert_eq!(
        rechecked.valid_until,
        at(1_000),
        "the advertisement expires first"
    );
}

#[test]
fn an_expired_advertisement_is_rejected() {
    let world = World::at(999);
    let clock = &*world.clock;
    let long_grant = world.b_grant(&[GrantedUse::Serve], vm_scope("vm-1"), 5_000);
    let advert = advertisement(5, 1_000);
    assert!(advert
        .recheck(&current(5), &serve_request(), Some(&long_grant), clock)
        .is_ok());
    clock.advance_to(at(1_000));
    assert_eq!(
        advert.recheck(&current(5), &serve_request(), Some(&long_grant), clock),
        Err(AdvertisementRefusal::Expired {
            expires_at: at(1_000),
            now: at(1_000),
        })
    );
}

#[test]
fn an_older_generation_advertisement_is_rejected() {
    let world = World::at(100);
    let clock = &*world.clock;
    assert_eq!(
        advertisement(4, 1_000).recheck(
            &current(5),
            &serve_request(),
            Some(&world.serve_grant()),
            clock
        ),
        Err(AdvertisementRefusal::OlderGeneration {
            advertised: ModelActivationGeneration::new(4),
            current: ModelActivationGeneration::new(5),
        })
    );
}

#[test]
fn an_advertisement_ahead_of_the_authority_is_rejected() {
    let world = World::at(100);
    let clock = &*world.clock;
    assert_eq!(
        advertisement(6, 1_000).recheck(
            &current(5),
            &serve_request(),
            Some(&world.serve_grant()),
            clock
        ),
        Err(AdvertisementRefusal::AheadOfAuthority {
            advertised: ModelActivationGeneration::new(6),
            current: ModelActivationGeneration::new(5),
        })
    );
}

#[test]
fn an_advertisement_that_disagrees_with_the_authority_is_rejected() {
    let world = World::at(100);
    let clock = &*world.clock;
    let claims = [
        Residency {
            device: gpu("host-a", "GPU-1"),
            ..residency()
        },
        Residency {
            owner: tenant("tenant-c"),
            ..residency()
        },
        Residency {
            artifact: ArtifactIdentity::from_manifest_digest(&d("other-manifest")),
            ..residency()
        },
        Residency {
            scope: vm_scope("vm-2"),
            ..residency()
        },
    ];
    for claim in claims {
        let advert = ResidentAdvertisement {
            residency: claim,
            ..advertisement(5, 1_000)
        };
        assert_eq!(
            advert.recheck(
                &current(5),
                &serve_request(),
                Some(&world.serve_grant()),
                clock
            ),
            Err(AdvertisementRefusal::DisagreesWithAuthority)
        );
    }
}

#[test]
fn compatibility_is_rechecked_by_execution_identity() {
    let world = World::at(100);
    let clock = &*world.clock;
    // Same runner name, another kernel layout: a different execution identity.
    let other = ExecutionSpec {
        kernel_layout: versioned("flash-attn", "3.0.0"),
        ..execution_spec()
    }
    .identity()
    .unwrap();
    let request = AdvertisementRequest {
        required: other,
        ..serve_request()
    };
    assert_eq!(
        advertisement(5, 1_000).recheck(&current(5), &request, Some(&world.serve_grant()), clock),
        Err(AdvertisementRefusal::Incompatible)
    );
}

#[test]
fn an_advertisement_is_never_authority() {
    let world = World::at(100);
    let clock = &*world.clock;
    let advert = advertisement(5, 1_000);
    let refusal = |grant: Option<&ScopedGrant>| match advert.recheck(
        &current(5),
        &serve_request(),
        grant,
        clock,
    ) {
        Err(AdvertisementRefusal::Unauthorized(refusal)) => refusal,
        other => panic!("expected an authorization refusal, got {other:?}"),
    };
    assert_eq!(refusal(None), GrantRefusal::Missing);
    assert_eq!(
        refusal(Some(&world.grant(GrantTerms {
            grantor: tenant("tenant-c"),
            ..serve_terms()
        }))),
        GrantRefusal::NotFromOwner
    );
    assert_eq!(
        refusal(Some(&world.grant(GrantTerms {
            grantee: tenant("tenant-c"),
            ..serve_terms()
        }))),
        GrantRefusal::ForAnotherTenant
    );
    assert_eq!(
        refusal(Some(&world.grant(GrantTerms {
            artifact: ArtifactIdentity::from_manifest_digest(&d("other-manifest")),
            ..serve_terms()
        }))),
        GrantRefusal::ForAnotherArtifact
    );
    assert_eq!(
        refusal(Some(&world.grant(GrantTerms {
            scope: vm_scope("vm-2"),
            ..serve_terms()
        }))),
        GrantRefusal::ForAnotherScope
    );
    assert_eq!(
        refusal(Some(&world.b_grant(
            &[GrantedUse::Transfer],
            vm_scope("vm-1"),
            500
        ))),
        GrantRefusal::UseNotGranted {
            requested: GrantedUse::Serve
        }
    );
    assert_eq!(
        refusal(Some(&world.b_grant(
            &[GrantedUse::Serve],
            vm_scope("vm-1"),
            100
        ))),
        GrantRefusal::Expired {
            expires_at: at(100),
            now: at(100),
        }
    );
}

#[test]
fn a_transfer_needs_a_transfer_grant_for_the_recipient_scope() {
    let world = World::at(100);
    let clock = &*world.clock;
    let request = AdvertisementRequest {
        purpose: AdvertisementPurpose::Transfer {
            recipient: vm_scope("vm-2"),
        },
        ..serve_request()
    };
    let advert = advertisement(5, 1_000);
    let to_recipient = world.b_grant(&[GrantedUse::Transfer], vm_scope("vm-2"), 800);
    assert_eq!(
        advert
            .recheck(&current(5), &request, Some(&to_recipient), clock)
            .map(|rechecked| rechecked.valid_until),
        Ok(at(800))
    );
    let to_source_scope = world.b_grant(&[GrantedUse::Transfer], vm_scope("vm-1"), 800);
    assert_eq!(
        advert.recheck(&current(5), &request, Some(&to_source_scope), clock),
        Err(AdvertisementRefusal::Unauthorized(
            GrantRefusal::ForAnotherScope
        ))
    );
    let serve_only = world.b_grant(&[GrantedUse::Serve], vm_scope("vm-2"), 800);
    assert_eq!(
        advert.recheck(&current(5), &request, Some(&serve_only), clock),
        Err(AdvertisementRefusal::Unauthorized(
            GrantRefusal::UseNotGranted {
                requested: GrantedUse::Transfer
            }
        ))
    );
}

#[test]
fn expiry_is_checked_before_anything_else() {
    // An expired, stale, incompatible and unauthorized advertisement reports expiry.
    let clock = ManualClock::new(MonotonicTime::from_nanos(2_000));
    let request = AdvertisementRequest {
        required: ExecutionSpec {
            runner: versioned("sglang", "0.4.0"),
            ..execution_spec()
        }
        .identity()
        .unwrap(),
        ..serve_request()
    };
    assert_eq!(
        advertisement(4, 1_000).recheck(&current(5), &request, None, &clock),
        Err(AdvertisementRefusal::Expired {
            expires_at: at(1_000),
            now: at(2_000),
        })
    );
}

#[test]
fn an_advertisement_from_before_a_revocation_is_rejected() {
    let world = World::at(100);
    let clock = &*world.clock;
    // Issued under epoch 3. A revocation has since raised the record to epoch 4 while the
    // activation generation stayed at 5.
    let revoked = CurrentResidency {
        residency: Residency {
            authority: vm_binding("exe-parent", 4),
            ..residency()
        },
        ..current(5)
    };
    assert_eq!(
        advertisement(5, 1_000).recheck(
            &revoked,
            &serve_request(),
            Some(&world.serve_grant()),
            clock
        ),
        Err(AdvertisementRefusal::AuthorityChanged {
            advertised_epoch: Some(AuthorizationEpoch::new(3)),
            current_epoch: Some(AuthorizationEpoch::new(4)),
        })
    );

    // Another parent execution under the same epoch is refused the same way.
    let reparented = CurrentResidency {
        residency: Residency {
            authority: vm_binding("exe-other-parent", 3),
            ..residency()
        },
        ..current(5)
    };
    assert_eq!(
        advertisement(5, 1_000).recheck(
            &reparented,
            &serve_request(),
            Some(&world.serve_grant()),
            clock
        ),
        Err(AdvertisementRefusal::AuthorityChanged {
            advertised_epoch: Some(AuthorizationEpoch::new(3)),
            current_epoch: Some(AuthorizationEpoch::new(3)),
        })
    );

    // An advertisement made under the current binding is usable again.
    let readvertised = ResidentAdvertisement {
        residency: revoked.residency.clone(),
        ..advertisement(5, 1_000)
    };
    assert!(readvertised
        .recheck(
            &revoked,
            &serve_request(),
            Some(&world.serve_grant()),
            clock
        )
        .is_ok());
}

#[test]
fn a_recheck_after_the_owner_revokes_the_catalog_grant_is_refused() {
    let world = World::at(100);
    let clock = &*world.clock;
    let (owner, grantee) = (tenant("tenant-a"), tenant("tenant-b"));
    let object = world.grants.publish_artifact(&owner, &artifact());
    let catalog_grant = world.grants.grant(
        &owner,
        object,
        &grantee,
        &grantee_execution(&grantee),
        at(5_000),
    );
    let grant = ScopedGrant::from_catalog(
        world.grants.catalog(),
        object,
        grantee_execution(&grantee),
        serve_terms(),
    )
    .unwrap();
    let advert = advertisement(5, 1_000);
    assert!(advert
        .recheck(&current(5), &serve_request(), Some(&grant), clock)
        .is_ok());

    world.grants.revoke(&owner, catalog_grant);
    assert_eq!(
        advert.recheck(&current(5), &serve_request(), Some(&grant), clock),
        Err(AdvertisementRefusal::Unauthorized(
            GrantRefusal::CatalogRefused(ReadRefusal::NotGranted { object })
        ))
    );
}
