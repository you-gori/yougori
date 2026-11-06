//! Line 504 and S3.3: the same weights may have several execution representations;
//! identical representations share physical storage only within one authorized trust
//! scope; storage equality is not permission; device memory never crosses a VM boundary.
//! INT-05: a scoped grant stands on a live catalog grant, so the owner's revocation, the
//! catalog grant's expiry or a quarantine ends sharing at the next decision.

use std::sync::Arc;
use std::thread;

use crate::foundation::catalog::{
    ArtifactClass, GrantId, ObjectId, ReadRefusal, Scope, TrustPolicy,
};
use crate::foundation::ids::{ContentKey, ExecutionCategory, ManualClock};

use super::super::*;
use super::support::*;

fn scope(category: ExecutionCategory, name: &str) -> TrustScope {
    TrustScope::named(category, name)
}

fn vm(name: &str) -> TrustScope {
    scope(ExecutionCategory::VmSandbox, name)
}

fn stored() -> StoredRepresentation {
    StoredRepresentation {
        execution: execution(),
        artifact: artifact(),
        owner: tenant("tenant-a"),
        scope: vm("vm-1"),
    }
}

fn request(tenant_name: &str, medium: SharingMedium) -> ShareRequest {
    ShareRequest {
        execution: execution(),
        tenant: tenant(tenant_name),
        scope: vm("vm-1"),
        medium,
    }
}

fn grant_terms(grantee: &str, uses: &[GrantedUse]) -> GrantTerms {
    terms("tenant-a", grantee, vm("vm-1"), uses, 1_000)
}

fn storage_terms() -> GrantTerms {
    grant_terms("tenant-b", &[GrantedUse::ShareImmutableStorage])
}

impl World {
    fn decide(
        &self,
        request: &ShareRequest,
        grant: Option<&ScopedGrant>,
    ) -> Result<SharingApproval, SharingRefusal> {
        decide_storage_sharing(&stored(), request, grant, &*self.clock)
    }

    /// The fixture artifact published by tenant A and granted to tenant B's execution
    /// until `catalog_expires_at`, with the scoped grant checked against it.
    fn granted_storage(&self, catalog_expires_at: u64) -> (ScopedGrant, GrantId) {
        let owner = tenant("tenant-a");
        let grantee = tenant("tenant-b");
        let object = self.grants.publish_artifact(&owner, &artifact());
        let catalog_grant = self.grants.grant(
            &owner,
            object,
            &grantee,
            &grantee_execution(&grantee),
            at(catalog_expires_at),
        );
        let scoped = ScopedGrant::from_catalog(
            self.grants.catalog(),
            object,
            grantee_execution(&grantee),
            storage_terms(),
        )
        .unwrap();
        (scoped, catalog_grant)
    }
}

#[test]
fn the_same_weights_have_several_execution_representations() {
    let eager = execution_spec();
    let compiled = ExecutionSpec {
        kernel_layout: versioned("flash-attn", "3.0.0"),
        processed_weights: versioned("vllm-fp8-repacked", "1"),
        compile: CompileConfiguration::Compiled {
            configuration: d("torch-compile"),
        },
        ..execution_spec()
    };
    assert_eq!(eager.logical, compiled.logical, "one logical model");
    let eager_identity = eager.identity().unwrap();
    let compiled_identity = compiled.identity().unwrap();
    assert_ne!(eager_identity, compiled_identity, "two representations");

    // Different representations of the same weights never share storage as if equal.
    let world = World::at(10);
    let request = ShareRequest {
        execution: compiled_identity,
        ..request("tenant-b", SharingMedium::ImmutableStorage)
    };
    assert_eq!(
        world.decide(&request, Some(&world.grant(storage_terms()))),
        Err(SharingRefusal::DifferentExecutionRepresentation)
    );
}

#[test]
fn identical_representations_share_within_one_scope_under_a_grant() {
    let world = World::at(10);
    let approval = world
        .decide(
            &request("tenant-b", SharingMedium::ImmutableStorage),
            Some(&world.grant(storage_terms())),
        )
        .unwrap();
    assert_eq!(
        approval,
        SharingApproval {
            artifact: artifact(),
            scope: vm("vm-1"),
            medium: SharingMedium::ImmutableStorage,
            valid_until: at(1_000),
        }
    );
}

#[test]
fn cross_tenant_storage_sharing_is_refused_without_a_grant() {
    let world = World::at(10);
    let decide = |grant: Option<&ScopedGrant>| {
        world.decide(&request("tenant-b", SharingMedium::ImmutableStorage), grant)
    };
    let refused = |refusal| Err(SharingRefusal::Unauthorized(refusal));
    assert_eq!(decide(None), refused(GrantRefusal::Missing));
    assert_eq!(
        decide(Some(&world.grant(grant_terms(
            "tenant-c",
            &[GrantedUse::ShareImmutableStorage]
        )))),
        refused(GrantRefusal::ForAnotherTenant)
    );
    // Tenant B's own object of the same artifact grants B nothing of A's storage.
    assert_eq!(
        decide(Some(&world.grant(GrantTerms {
            grantor: tenant("tenant-b"),
            ..storage_terms()
        }))),
        refused(GrantRefusal::NotFromOwner),
        "a tenant cannot grant itself another tenant's storage"
    );
    assert_eq!(
        decide(Some(&world.grant(GrantTerms {
            artifact: ArtifactIdentity::from_manifest_digest(&d("other-manifest")),
            ..storage_terms()
        }))),
        refused(GrantRefusal::ForAnotherArtifact)
    );
    assert_eq!(
        decide(Some(&world.grant(GrantTerms {
            scope: vm("vm-2"),
            ..storage_terms()
        }))),
        refused(GrantRefusal::ForAnotherScope)
    );
    assert_eq!(
        decide(Some(&world.grant(grant_terms(
            "tenant-b",
            &[GrantedUse::Serve, GrantedUse::Transfer]
        )))),
        refused(GrantRefusal::UseNotGranted {
            requested: GrantedUse::ShareImmutableStorage
        })
    );
    let grant = world.grant(storage_terms());
    world.clock.advance_to(at(1_000));
    assert_eq!(
        decide(Some(&grant)),
        refused(GrantRefusal::Expired {
            expires_at: at(1_000),
            now: at(1_000),
        })
    );
}

#[test]
fn a_revoked_catalog_grant_ends_sharing_at_once() {
    let world = World::at(10);
    let (scoped, catalog_grant) = world.granted_storage(5_000);
    let share = request("tenant-b", SharingMedium::ImmutableStorage);
    assert!(world.decide(&share, Some(&scoped)).is_ok());

    world.grants.revoke(&tenant("tenant-a"), catalog_grant);
    let not_granted = GrantRefusal::CatalogRefused(ReadRefusal::NotGranted {
        object: scoped.object(),
    });
    assert_eq!(
        world.decide(&share, Some(&scoped)),
        Err(SharingRefusal::Unauthorized(not_granted.clone())),
        "a grant checked before the revocation stops at the next decision"
    );
    assert_eq!(
        ScopedGrant::from_catalog(
            world.grants.catalog(),
            scoped.object(),
            scoped.execution().clone(),
            storage_terms(),
        ),
        Err(not_granted),
        "and no new scoped grant can be made"
    );
}

#[test]
fn the_catalog_grants_own_expiry_ends_sharing_before_longer_terms() {
    let world = World::at(10);
    let (scoped, _) = world.granted_storage(500);
    let share = request("tenant-b", SharingMedium::ImmutableStorage);
    world.clock.advance_to(at(499));
    assert_eq!(
        world
            .decide(&share, Some(&scoped))
            .map(|approval| approval.valid_until),
        Ok(at(1_000)),
        "the terms are the bound while the catalog grant lives"
    );
    world.clock.advance_to(at(500));
    assert_eq!(
        world.decide(&share, Some(&scoped)),
        Err(SharingRefusal::Unauthorized(GrantRefusal::CatalogRefused(
            ReadRefusal::NotGranted {
                object: scoped.object()
            }
        )))
    );
}

#[test]
fn a_scoped_grant_is_made_only_from_a_live_catalog_grant() {
    let world = World::at(10);
    let (owner, grantee) = (tenant("tenant-a"), tenant("tenant-b"));
    let object = world.grants.publish_artifact(&owner, &artifact());
    let from_catalog = |object, execution: &str, terms| {
        ScopedGrant::from_catalog(world.grants.catalog(), object, exe(execution), terms)
    };
    let not_granted = |object| {
        Err(GrantRefusal::CatalogRefused(ReadRefusal::NotGranted {
            object,
        }))
    };

    // The owner granted nothing yet.
    assert_eq!(
        from_catalog(object, "exe-tenant-b", storage_terms()),
        not_granted(object)
    );
    // A catalog grant narrowed to one execution covers no other.
    world
        .grants
        .grant(&owner, object, &grantee, &exe("exe-tenant-b"), at(5_000));
    assert_eq!(
        from_catalog(object, "exe-tenant-b-other", storage_terms()),
        not_granted(object)
    );
    let scoped = from_catalog(object, "exe-tenant-b", storage_terms()).unwrap();
    assert_eq!(scoped.object(), object);
    assert_eq!(scoped.execution(), &exe("exe-tenant-b"));
    assert_eq!(scoped.terms(), &storage_terms());
    assert_eq!(scoped.grantor, owner, "the terms read through the grant");

    // An object that is not the grantor's is refused even when its owner granted it.
    let third = tenant("tenant-c");
    let others = world.grants.publish(&third, b"tenant c's weights");
    world
        .grants
        .grant(&third, others, &grantee, &exe("exe-tenant-b"), at(5_000));
    assert_eq!(
        from_catalog(others, "exe-tenant-b", storage_terms()),
        Err(GrantRefusal::NotFromOwner)
    );

    // An object the catalog never published backs nothing.
    let unknown = ObjectId::new(
        &Scope::tenant(owner.clone()),
        ArtifactClass::ModelWeights,
        ContentKey::of(b"never imported"),
    );
    assert_eq!(
        from_catalog(unknown, "exe-tenant-b", storage_terms()),
        not_granted(unknown)
    );
}

#[test]
fn a_quarantined_object_backs_no_grant() {
    let world = World::at(10);
    let (scoped, _) = world.granted_storage(5_000);
    let share = request("tenant-b", SharingMedium::ImmutableStorage);
    assert!(world.decide(&share, Some(&scoped)).is_ok());

    // Withdrawing trust in user-selected weights quarantines the object (INT-09).
    world
        .grants
        .lock()
        .set_trust_policy(ArtifactClass::ModelWeights, TrustPolicy::new());
    assert_eq!(
        world.decide(&share, Some(&scoped)),
        Err(SharingRefusal::Unauthorized(GrantRefusal::CatalogRefused(
            ReadRefusal::Quarantined {
                object: scoped.object()
            }
        )))
    );
}

#[test]
fn a_catalog_that_cannot_be_read_backs_no_grant() {
    let world = World::at(10);
    let grant = world.grant(storage_terms());
    let catalog = Arc::clone(world.grants.catalog());
    let poisoned = thread::spawn(move || {
        let _held = catalog.lock();
        panic!("a panic while the catalog is locked poisons it");
    })
    .join();
    assert!(poisoned.is_err());
    assert_eq!(
        world.decide(
            &request("tenant-b", SharingMedium::ImmutableStorage),
            Some(&grant)
        ),
        Err(SharingRefusal::Unauthorized(
            GrantRefusal::CatalogUnavailable
        ))
    );
}

#[test]
fn the_owner_shares_its_own_storage_only_under_a_grant_too() {
    let world = World::at(10);
    let own = request("tenant-a", SharingMedium::ImmutableStorage);
    assert_eq!(
        world.decide(&own, None),
        Err(SharingRefusal::Unauthorized(GrantRefusal::Missing))
    );
    // The catalog's ownership stands in for a grant to the owning scope.
    let self_grant = world.grant(grant_terms(
        "tenant-a",
        &[GrantedUse::ShareImmutableStorage],
    ));
    assert!(world.decide(&own, Some(&self_grant)).is_ok());
}

#[test]
fn storage_is_shared_only_within_one_trust_scope() {
    let world = World::at(10);
    let elsewhere = ShareRequest {
        scope: vm("vm-2"),
        ..request("tenant-b", SharingMedium::ImmutableStorage)
    };
    let grant_there = world.grant(GrantTerms {
        scope: vm("vm-2"),
        ..storage_terms()
    });
    assert_eq!(
        world.decide(&elsewhere, Some(&grant_there)),
        Err(SharingRefusal::DifferentTrustScope)
    );
}

#[test]
fn device_memory_never_crosses_a_vm_boundary() {
    let world = World::at(10);
    let device_terms = grant_terms("tenant-b", &[GrantedUse::ShareDeviceMemory]);
    for other in [
        vm("vm-2"),
        scope(ExecutionCategory::SharedKernelGpuRuntime, "wsl-cuda"),
        scope(ExecutionCategory::HostProcessModelRuntime, "vm-1"),
    ] {
        let crossing = ShareRequest {
            scope: other,
            ..request("tenant-b", SharingMedium::DeviceMemory)
        };
        let grant_there = world.grant(GrantTerms {
            scope: other,
            ..device_terms.clone()
        });
        assert_eq!(
            world.decide(&crossing, Some(&grant_there)),
            Err(SharingRefusal::CrossVmDeviceMemory)
        );
    }

    // Within one VM, device memory needs a grant that names it explicitly.
    let inside = request("tenant-b", SharingMedium::DeviceMemory);
    assert_eq!(
        world.decide(&inside, Some(&world.grant(storage_terms()))),
        Err(SharingRefusal::Unauthorized(GrantRefusal::UseNotGranted {
            requested: GrantedUse::ShareDeviceMemory
        }))
    );
    assert!(world
        .decide(&inside, Some(&world.grant(device_terms)))
        .is_ok());
}

#[test]
fn device_memory_between_two_labelled_runtimes_needs_one_scope() {
    let clock = ManualClock::new(at(10));
    let shared = scope(ExecutionCategory::SharedKernelGpuRuntime, "wsl-cuda");
    let stored_here = StoredRepresentation {
        scope: shared,
        ..stored()
    };
    let crossing = ShareRequest {
        scope: scope(ExecutionCategory::ProviderContainerRuntime, "pod-1"),
        ..request("tenant-b", SharingMedium::DeviceMemory)
    };
    assert_eq!(
        decide_storage_sharing(&stored_here, &crossing, None, &clock),
        Err(SharingRefusal::DifferentTrustScope)
    );
}

#[test]
fn scoped_grants_compare_by_terms_object_execution_and_catalog() {
    let world = World::at(10);
    let first = world.grant(storage_terms());
    let again = world.grant(storage_terms());
    assert_eq!(
        first, again,
        "the same terms on the same object and catalog"
    );
    assert_ne!(
        first,
        world.grant(GrantTerms {
            expires_at: at(900),
            ..storage_terms()
        })
    );
    let elsewhere = World::at(10);
    assert_ne!(
        first,
        elsewhere.grant(storage_terms()),
        "another catalog is another grant"
    );
    let shown = format!("{first:?}");
    assert!(shown.contains("ScopedGrant") && shown.contains("terms"));

    fn send_and_sync<T: Send + Sync>() {}
    send_and_sync::<ScopedGrant>();
}

#[test]
fn intermediate_state_needs_its_own_grant_use() {
    // A shared subgraph's state (line 894) is not the artifact's device memory.
    let world = World::at(10);
    let stored = stored();
    let grantee = tenant("tenant-b");
    let need = |granted_use| GrantNeed {
        owner: &stored.owner,
        grantee: &grantee,
        artifact: &stored.artifact,
        scope: &stored.scope,
        granted_use,
    };
    let device = world.grant(grant_terms("tenant-b", &[GrantedUse::ShareDeviceMemory]));
    let state = world.grant(grant_terms(
        "tenant-b",
        &[GrantedUse::ShareIntermediateState],
    ));
    let now = at(10);
    assert_eq!(
        check_grant(
            Some(&device),
            &need(GrantedUse::ShareIntermediateState),
            now
        ),
        Err(GrantRefusal::UseNotGranted {
            requested: GrantedUse::ShareIntermediateState
        })
    );
    assert_eq!(
        check_grant(Some(&state), &need(GrantedUse::ShareDeviceMemory), now),
        Err(GrantRefusal::UseNotGranted {
            requested: GrantedUse::ShareDeviceMemory
        })
    );
    assert_eq!(
        check_grant(Some(&state), &need(GrantedUse::ShareIntermediateState), now),
        Ok(at(1_000))
    );
}
