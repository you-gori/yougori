//! Line 866: recovery recipes never promise reconstruction from a peer that can
//! disappear or from a prompt the service no longer holds, and indispensable
//! reconstruction dependencies are held by explicit leases.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use super::support::*;
use crate::foundation::catalog::{
    ArtifactClass, LeaseId as CatalogLeaseId, ObjectId, ReadRefusal, Scope, TrustPolicy,
};
use crate::foundation::coordination::{
    BootRequest, CancelCause, Coordinator, LaunchOutcome, LaunchPlan, LeaseKind, LeaseRefusal,
    LeaseTerms, LedgerCapacity, ObservedVm, PerimeterId, PortFailure, PortOperation, Readiness,
    ReadinessReport, ReservationPriority, ResourceKind, RestoredVmReport, SandboxPort, SnapshotId,
    SnapshotManifest, VmInstanceId,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Backend, BackendRelease, Capability, ConfigurationFingerprint, HostSubject, Observation,
    ProbeRegistry, RuntimeOffer, RuntimeRequirement, RuntimeSubject, SourceClass, Subject,
    SupportDetail,
};
use crate::foundation::ids::{
    digest, ContentKey, ExecutionCategory, ExecutionId, LeaseId, ManualClock, MonotonicTime,
    OperationId, PolicyEpoch, SandboxBootGeneration, TenantId,
};
use crate::foundation::ledger::{CapacityDeclaration, Ledger, LedgerConfig, QueueLimits};
use crate::model_memory::boundaries::{vram_key, HOST_RAM, STAGING};
use crate::model_memory::identity::fakes::GrantCatalog;
use crate::model_memory::identity::TokenPrefix;
use crate::model_memory::residency::eviction::{
    Content, CopyTier, ReconstructibleCopy, Verification,
};
use crate::model_memory::transitions::*;

fn recipe_refusal(declaration: &WorkflowDeclaration) -> RecipeRefusal {
    match CheckedWorkflow::check(declaration) {
        Err(TransitionError::Recipe { refusal, .. }) => refusal,
        other => panic!("expected a recipe refusal, got {other:?}"),
    }
}

fn compile_refusal(declaration: &WorkflowDeclaration, holds: &FakeHolds) -> RecipeRefusal {
    match compile(declaration, holds, holds, &clock()) {
        Err(TransitionError::Recipe { refusal, .. }) => refusal,
        other => panic!("expected a recipe refusal, got {other:?}"),
    }
}

/// s1 on A produces a session that s2 on A resumes; the session has `recipe`.
fn with_session_recipe(recipe: RecoveryRecipe) -> WorkflowDeclaration {
    let mut first = stage("s1", &["model-a"]);
    first.produces = Some(key("session-1"));
    declaration(
        vec![
            base("model-a", 4 * GB),
            session("session-1", "model-a", &[1, 2, 3], GB, vec![recipe]),
        ],
        vec![first, stage("s2", &["model-a", "session-1"])],
        chain(&["s1", "s2"]),
    )
}

fn with_base_recipe(recipe: RecoveryRecipe) -> WorkflowDeclaration {
    let mut declared = aba();
    declared.resources[1].recipes = vec![recipe];
    declared
}

#[test]
fn a_recipe_naming_a_peer_is_refused() {
    let peer = digest("yougori/test/peer/v1", &[b"neighbour"]);
    assert_eq!(
        recipe_refusal(&with_base_recipe(RecoveryRecipe::Peer { peer })),
        RecipeRefusal::PeerCanDisappear { peer }
    );
    // A verified copy on a peer, in reclaimable host RAM or at the remote source is no
    // promise either (residency's availability rule).
    for tier in [
        CopyTier::AuthorizedPeer,
        CopyTier::ReclaimableHost,
        CopyTier::RemoteSource,
    ] {
        let mut source = catalog_source("model-b");
        source.copy.tier = tier;
        let recipe = RecoveryRecipe::Reload {
            source,
            hold: object_hold("model-b"),
        };
        assert_eq!(
            recipe_refusal(&with_base_recipe(recipe)),
            RecipeRefusal::SourceNotGuaranteed { tier }
        );
    }
    let mut unverified = catalog_source("model-b");
    unverified.copy = ReconstructibleCopy {
        tier: CopyTier::LocalStorage,
        verification: Verification::Unverified,
    };
    assert_eq!(
        recipe_refusal(&with_base_recipe(RecoveryRecipe::Reload {
            source: unverified,
            hold: object_hold("model-b"),
        })),
        RecipeRefusal::SourceNotGuaranteed {
            tier: CopyTier::LocalStorage
        }
    );
}

#[test]
fn a_recipe_relying_on_a_prompt_the_service_does_not_hold_is_refused() {
    let not_held = RecoveryRecipe::Recompute {
        prompt: PromptHolding::NotHeld {
            prefix: TokenPrefix::from_token_ids(&[1, 2, 3]),
        },
        compute_seconds: 1.0,
    };
    assert_eq!(
        recipe_refusal(&with_session_recipe(not_held)),
        RecipeRefusal::PromptNotHeld
    );
    // Holding some other prompt is not holding this session's.
    assert_eq!(
        recipe_refusal(&with_session_recipe(recompute(&[1, 2, 4], 1.0))),
        RecipeRefusal::PromptMismatch
    );
    assert!(CheckedWorkflow::check(&with_session_recipe(recompute(&[1, 2, 3], 1.0))).is_ok());
}

#[test]
fn a_catalog_source_must_be_this_tenants_exact_object() {
    let mut other_scope = catalog_source("model-b");
    other_scope.scope = Scope::tenant(TenantId::new("tenant-2").unwrap());
    other_scope.object = ObjectId::new(
        &other_scope.scope,
        ArtifactClass::ModelWeights,
        other_scope.content,
    );
    assert_eq!(
        recipe_refusal(&with_base_recipe(RecoveryRecipe::Reload {
            source: other_scope,
            hold: object_hold("model-b"),
        })),
        RecipeRefusal::SourceOutsideScope
    );
    let mut mismatched = catalog_source("model-b");
    mismatched.object = catalog_source("model-a").object;
    assert_eq!(
        recipe_refusal(&with_base_recipe(RecoveryRecipe::Reload {
            source: mismatched,
            hold: object_hold("model-b"),
        })),
        RecipeRefusal::SourceIdentityMismatch
    );
    // Another model's bytes are not this resource's content.
    assert_eq!(
        recipe_refusal(&with_base_recipe(reload("model-a"))),
        RecipeRefusal::SourceContentMismatch
    );
    let mut sidecar = catalog_source("model-b");
    sidecar.class = ArtifactClass::ModelSidecar;
    sidecar.object = ObjectId::new(&sidecar.scope, sidecar.class, sidecar.content);
    assert_eq!(
        recipe_refusal(&with_base_recipe(RecoveryRecipe::Reload {
            source: sidecar,
            hold: object_hold("model-b"),
        })),
        RecipeRefusal::WrongArtifactClass {
            class: ArtifactClass::ModelSidecar
        }
    );
    // Reloading session state from a catalog object is refused: sessions are not
    // immutable artifacts.
    let mut session_reload = with_session_recipe(recompute(&[1, 2, 3], 1.0));
    let content = ContentKey::of(b"session");
    let scope = Scope::tenant(tenant());
    session_reload.resources[1].recipes = vec![RecoveryRecipe::Reload {
        source: CatalogSource {
            object: ObjectId::new(&scope, ArtifactClass::ModelWeights, content),
            scope,
            class: ArtifactClass::ModelWeights,
            content,
            copy: ReconstructibleCopy {
                tier: CopyTier::LocalStorage,
                verification: Verification::Verified {
                    content: Content::Immutable(content),
                },
            },
        },
        hold: object_hold("model-b"),
    }];
    assert!(matches!(
        recipe_refusal(&session_reload),
        RecipeRefusal::WrongKind { .. }
    ));
}

#[test]
fn only_a_merged_variant_is_derived_and_only_from_its_base_and_adapter() {
    let derive = |sources: &[&str]| RecoveryRecipe::Derive {
        sources: sources.iter().map(|name| key(name)).collect(),
        compute_seconds: 1.0,
    };
    let mut on_base = aba();
    on_base.resources[1].recipes = vec![derive(&["model-a"])];
    assert!(matches!(
        recipe_refusal(&on_base),
        RecipeRefusal::WrongKind { .. }
    ));
    let workflow = |recipe: RecoveryRecipe| {
        declaration(
            vec![
                base("model-a", 4 * GB),
                base("model-b", 4 * GB),
                adapter("adapter-x", "model-a", GB),
                merged("merged-ax", 4 * GB, vec![recipe]),
            ],
            vec![stage("s1", &["adapter-x"]), stage("s2", &["merged-ax"])],
            chain(&["s1", "s2"]),
        )
    };
    assert!(CheckedWorkflow::check(&workflow(derive(&["model-a", "adapter-x"]))).is_ok());
    assert!(matches!(
        recipe_refusal(&workflow(derive(&["model-b", "adapter-x"]))),
        RecipeRefusal::InvalidSource { .. }
    ));
    assert!(matches!(
        recipe_refusal(&workflow(derive(&["model-a", "model-b"]))),
        RecipeRefusal::InvalidSource { .. }
    ));
    assert!(matches!(
        recipe_refusal(&workflow(derive(&["missing"]))),
        RecipeRefusal::UnknownSource { .. }
    ));
}

#[test]
fn a_recomputes_prompt_is_held_by_a_core04_service_lease() {
    // The prompt a recompute relies on is held by a service lease of this workflow's
    // parent execution, honoured until the plan's horizon.
    let resumed = || with_session_recipe(recompute(&[1, 2, 3], 1.0));
    let unknown = FakeHolds::honoured();
    unknown.set(
        SERVICE_LEASE,
        Err(LeaseRefusal::UnknownLease {
            lease: LeaseId::new(SERVICE_LEASE),
        }),
    );
    assert!(matches!(
        compile_refusal(&resumed(), &unknown),
        RecipeRefusal::HoldNotHonoured { .. }
    ));

    let revoked = FakeHolds::honoured();
    revoked.revoke(SERVICE_LEASE);
    assert!(matches!(
        compile_refusal(&resumed(), &revoked),
        RecipeRefusal::HoldNotHonoured {
            refusal: LeaseRefusal::RevokedAuthorization { .. },
            ..
        }
    ));

    let wrong_kind = FakeHolds::honoured();
    wrong_kind.grant(SERVICE_LEASE, LeaseKind::Transfer, u64::MAX / 2);
    assert_eq!(
        compile_refusal(&resumed(), &wrong_kind),
        RecipeRefusal::WrongLeaseKind {
            lease: LeaseId::new(SERVICE_LEASE),
            expected: LeaseKind::Service,
            found: LeaseKind::Transfer,
        }
    );

    let foreign = FakeHolds::honoured();
    foreign.set(
        SERVICE_LEASE,
        Ok(HeldLease {
            kind: LeaseKind::Service,
            parent: ExecutionId::new("exe-other").unwrap(),
            expires_at: MonotonicTime::from_nanos(u64::MAX / 2),
        }),
    );
    assert_eq!(
        compile_refusal(&resumed(), &foreign),
        RecipeRefusal::ForeignLease {
            lease: LeaseId::new(SERVICE_LEASE)
        }
    );

    // A lease that ends before the plan's horizon is refused: renewal is never assumed.
    let short = FakeHolds::honoured();
    short.grant(SERVICE_LEASE, LeaseKind::Service, 2_000_000_000);
    assert!(matches!(
        compile_refusal(&resumed(), &short),
        RecipeRefusal::HoldEndsTooEarly { .. }
    ));
}

/// A catalog of its own, so a test controls every lease.
fn own_catalog() -> GrantCatalog {
    GrantCatalog::open(Arc::new(clock()), &[tenant()])
}

/// Publishes `name`'s bytes in `catalog` and leases them to `execution` for `duration`.
fn lease_in(
    catalog: &GrantCatalog,
    name: &str,
    execution: &ExecutionId,
    duration: Duration,
) -> CatalogLeaseId {
    let object = catalog.publish(&tenant(), name.as_bytes());
    catalog
        .lock()
        .acquire_lease(&Scope::tenant(tenant()), execution, object, duration)
        .unwrap()
}

/// The hand-worked A→B→A with each model's reload held by `holds[model]`.
fn aba_held_by(hold_a: ObjectHold, hold_b: ObjectHold) -> WorkflowDeclaration {
    let mut declared = aba();
    declared.resources[0].recipes = vec![RecoveryRecipe::Reload {
        source: catalog_source("model-a"),
        hold: hold_a,
    }];
    declared.resources[1].recipes = vec![RecoveryRecipe::Reload {
        source: catalog_source("model-b"),
        hold: hold_b,
    }];
    declared
}

fn held(lease: CatalogLeaseId) -> ObjectHold {
    ObjectHold {
        reader: Scope::tenant(tenant()),
        execution: execution_id(),
        lease,
    }
}

fn catalog_refusal(declaration: &WorkflowDeclaration, catalog: &GrantCatalog) -> RecipeRefusal {
    match compile(
        declaration,
        &FakeHolds::honoured(),
        &*catalog.lock(),
        &clock(),
    ) {
        Err(TransitionError::Recipe { refusal, .. }) => refusal,
        other => panic!("expected a recipe refusal, got {other:?}"),
    }
}

#[test]
fn a_reload_is_held_by_a_catalog_read_lease_on_its_exact_object() {
    // A lease that outlives the horizon is honoured.
    let catalog = own_catalog();
    let a = lease_in(&catalog, "model-a", &execution_id(), OBJECT_LEASE);
    let b = lease_in(&catalog, "model-b", &execution_id(), OBJECT_LEASE);
    let plan = compile(
        &aba_held_by(held(a), held(b)),
        &FakeHolds::honoured(),
        &*catalog.lock(),
        &clock(),
    )
    .unwrap();
    let expires_at = catalog
        .lock()
        .lease_expires_at(&Scope::tenant(tenant()), &execution_id(), b)
        .unwrap();
    assert!(plan.horizon() <= expires_at);

    // A lease on another object holds nothing for this recipe.
    assert_eq!(
        catalog_refusal(&aba_held_by(held(a), held(a)), &catalog),
        RecipeRefusal::ObjectHoldOnAnotherObject {
            held: catalog_source("model-a").object,
            source: catalog_source("model-b").object,
        }
    );
}

#[test]
fn a_catalog_lease_that_expires_inside_the_horizon_is_refused() {
    let catalog = own_catalog();
    let a = lease_in(&catalog, "model-a", &execution_id(), OBJECT_LEASE);
    let b = lease_in(&catalog, "model-b", &execution_id(), Duration::from_secs(2));
    assert!(matches!(
        catalog_refusal(&aba_held_by(held(a), held(b)), &catalog),
        RecipeRefusal::ObjectHoldEndsTooEarly { expires_at, needed_until }
            if expires_at == MonotonicTime::from_nanos(3_000_000_000) && needed_until > expires_at
    ));
}

#[test]
fn another_readers_catalog_lease_is_refused() {
    let catalog = own_catalog();
    let a = lease_in(&catalog, "model-a", &execution_id(), OBJECT_LEASE);
    let other = ExecutionId::new("exe-other").unwrap();
    let b = lease_in(&catalog, "model-b", &other, OBJECT_LEASE);
    // Presented as this workflow's, the catalog refuses it as it would refuse a read.
    assert_eq!(
        catalog_refusal(&aba_held_by(held(a), held(b)), &catalog),
        RecipeRefusal::ObjectHoldNotHonoured {
            refusal: ReadRefusal::LeaseNotHeld
        }
    );
    // Declared under the other execution, the hold is refused before any catalog check.
    let foreign = ObjectHold {
        reader: Scope::tenant(tenant()),
        execution: other,
        lease: b,
    };
    assert_eq!(
        recipe_refusal(&aba_held_by(held(a), foreign)),
        RecipeRefusal::ForeignObjectHold
    );
}

#[test]
fn a_released_catalog_lease_is_refused() {
    let catalog = own_catalog();
    let a = lease_in(&catalog, "model-a", &execution_id(), OBJECT_LEASE);
    let b = lease_in(&catalog, "model-b", &execution_id(), OBJECT_LEASE);
    catalog
        .lock()
        .release_lease(&Scope::tenant(tenant()), &execution_id(), b)
        .unwrap();
    assert!(matches!(
        catalog_refusal(&aba_held_by(held(a), held(b)), &catalog),
        RecipeRefusal::ObjectHoldNotHonoured {
            refusal: ReadRefusal::UnknownLease | ReadRefusal::LeaseReleased
        }
    ));
}

#[test]
fn a_catalog_object_made_unreadable_is_refused() {
    // Withdrawing trust in user-selected weights quarantines the objects (INT-09); a
    // quarantined object cannot back a reload.
    let catalog = own_catalog();
    let a = lease_in(&catalog, "model-a", &execution_id(), OBJECT_LEASE);
    let b = lease_in(&catalog, "model-b", &execution_id(), OBJECT_LEASE);
    let revision = catalog
        .lock()
        .set_trust_policy(ArtifactClass::ModelWeights, TrustPolicy::new());
    assert!(revision
        .quarantined
        .contains(&catalog_source("model-b").object));
    // The quarantine revokes the leases on the object, so the catalog no longer knows them.
    assert!(matches!(
        catalog_refusal(&aba_held_by(held(a), held(b)), &catalog),
        RecipeRefusal::ObjectHoldNotHonoured {
            refusal: ReadRefusal::UnknownLease
                | ReadRefusal::LeaseRevoked
                | ReadRefusal::Quarantined { .. }
        }
    ));
}

#[test]
fn interruption_points_name_a_recovery_recipe_for_everything_resident() {
    let plan = compile(
        &with_session_recipe(recompute(&[1, 2, 3], 1.0)),
        &FakeHolds::honoured(),
        &FakeHolds::honoured(),
        &clock(),
    )
    .unwrap();
    // Before s2: base A (reload from the catalog) and the live session (written back
    // and restored, or recomputed from the held prompt).
    let point = &plan.nodes()[1].interruption;
    assert!(point.allowed);
    assert!(point.must_keep.is_empty());
    let recover: BTreeMap<_, _> = point.recover.iter().cloned().collect();
    assert_eq!(
        recover[&key("model-a")],
        vec![RecoveryPath::Reload {
            object: catalog_source("model-a").object
        }]
    );
    assert_eq!(
        recover[&key("session-1")],
        vec![
            RecoveryPath::RestoreWrittenBack {
                tier: CopyTier::PinnedHost
            },
            RecoveryPath::Recompute {
                prompt: *TokenPrefix::from_token_ids(&[1, 2, 3]).digest()
            }
        ]
    );
    assert!(close(point.load_cancellation_interval_seconds, 0.25));

    // Without a write-back tier the session would be lost if dropped: not allowed there.
    let mut no_write_back = with_session_recipe(recompute(&[1, 2, 3], 1.0));
    no_write_back.budgets.write_back = None;
    let plan = compile(
        &no_write_back,
        &FakeHolds::honoured(),
        &FakeHolds::honoured(),
        &clock(),
    )
    .unwrap();
    let point = &plan.nodes()[1].interruption;
    assert!(!point.allowed);
    assert_eq!(point.must_keep, vec![key("session-1")]);
}

/// A VM backend that boots at once and is always ready, observed by the host.
struct ReadyVms;

impl SandboxPort for ReadyVms {
    fn prepare_perimeter(&mut self, request: &BootRequest) -> Result<PerimeterId, PortFailure> {
        Ok(PerimeterId::new(digest(
            "yougori/test/perimeter/v1",
            &[request.execution.as_str().as_bytes()],
        )))
    }

    fn create_vm(
        &mut self,
        request: &BootRequest,
        _perimeter: &PerimeterId,
    ) -> Result<VmInstanceId, PortFailure> {
        Ok(VmInstanceId::new(digest(
            "yougori/test/vm/v1",
            &[request.execution.as_str().as_bytes()],
        )))
    }

    fn restore_vm(
        &mut self,
        _request: &BootRequest,
        _perimeter: &PerimeterId,
        _snapshot: &SnapshotManifest,
    ) -> Result<VmInstanceId, PortFailure> {
        Err(PortFailure {
            operation: PortOperation::RestoreVm,
            detail: "this backend does not restore".to_owned(),
        })
    }

    fn observe_readiness(
        &mut self,
        _vm: &VmInstanceId,
        _boot: SandboxBootGeneration,
    ) -> ReadinessReport {
        ReadinessReport {
            source: SourceClass::HostProbe,
            readiness: Readiness::Ready,
        }
    }

    fn inspect_restored_vm(
        &mut self,
        vm: &VmInstanceId,
        boot: SandboxBootGeneration,
    ) -> RestoredVmReport {
        RestoredVmReport {
            vm: *vm,
            boot,
            snapshot: SnapshotId::new(digest("yougori/test/snapshot/v1", &[b"none"])),
            guest_identity: digest("yougori/test/guest/v1", &[b"none"]),
            actions: BTreeSet::new(),
            attached_volumes: BTreeSet::new(),
            policy: PolicyEpoch::FIRST,
            image_profile: digest("yougori/test/image/v1", &[b"none"]),
            presented_epochs: BTreeSet::new(),
            source: SourceClass::HostProbe,
        }
    }

    fn terminate_vm(&mut self, _vm: &VmInstanceId) -> Result<(), PortFailure> {
        Ok(())
    }

    fn teardown_perimeter(&mut self, _perimeter: &PerimeterId) -> Result<(), PortFailure> {
        Ok(())
    }

    fn list_vms(&mut self) -> Result<Vec<ObservedVm>, PortFailure> {
        Ok(Vec::new())
    }
}

type Host = Coordinator<Arc<ManualClock>, LedgerCapacity<Arc<ManualClock>>>;

const HOUR: Duration = Duration::from_secs(3_600);

/// A running VM sandbox of the workflow's parent execution under the CORE-04 coordinator.
fn launched(clock: &Arc<ManualClock>) -> Host {
    let mut ledger = Ledger::new(
        Arc::clone(clock),
        HostSubject {
            machine: device().machine,
        },
        LedgerConfig {
            queue: QueueLimits {
                max_entries: 8,
                max_entries_per_tenant: 4,
                max_wait: Duration::from_secs(60),
            },
            grant_ttl: Duration::from_secs(60),
            unmanaged_usage_max_age: Duration::from_secs(24 * 3_600),
        },
    );
    for (resource, total) in [
        (vram_key(device()), 32 * GB),
        (HOST_RAM, 64 * GB),
        (STAGING, 8 * GB),
    ] {
        ledger
            .declare_capacity(
                resource,
                CapacityDeclaration {
                    total,
                    supervisor_reserve: 0,
                    unmanaged_in_use: 0,
                    source: SourceClass::HostProbe,
                },
            )
            .unwrap();
        ledger.set_tenant_budget(tenant(), resource, total).unwrap();
    }
    let mut registry = ProbeRegistry::new(Arc::clone(clock));
    let probe = Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe));
    registry.register(Box::new(Arc::clone(&probe))).unwrap();
    let runtime = RuntimeSubject {
        category: ExecutionCategory::VmSandbox,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance: digest("yougori/test/instance/v1", &[b"vm-host"]),
    };
    let configuration =
        ConfigurationFingerprint::from_digest(digest("yougori/test/configuration/v1", &[b"vm"]));
    let subject = Subject::Runtime(runtime.clone());
    probe.respond(
        &subject,
        Observation::supported(
            configuration,
            HOUR,
            SupportDetail::RuntimeCategory {
                category: ExecutionCategory::VmSandbox,
            },
        ),
    );
    registry
        .refresh(Capability::RuntimeCategory, &subject)
        .unwrap();
    let offer = RuntimeOffer::observe(&registry, runtime, HOUR, configuration).unwrap();
    let admitted = RuntimeRequirement::VmSandbox.admit(&offer).unwrap();
    let mut host = Coordinator::new(
        Arc::clone(clock),
        registry.session(),
        LedgerCapacity::new(ledger),
    );
    let plan = LaunchPlan {
        execution: execution_id(),
        tenant: tenant(),
        runtime: admitted,
        demand: BTreeMap::from([
            (ResourceKind::GpuMemoryBytes { device: device() }, 24 * GB),
            (ResourceKind::HostMemoryBytes, 16 * GB),
            (ResourceKind::PinnedHostMemoryBytes, 4 * GB),
        ]),
        priority: ReservationPriority::Foreground,
        authority_lifetime: 10 * HOUR,
        readiness_max_age: Duration::from_secs(5),
        runtime_evidence_max_age: HOUR,
    };
    let outcome = host.launch(plan, &mut ReadyVms, &registry).unwrap();
    assert!(matches!(outcome, LaunchOutcome::AuthorityActive { .. }));
    host.start_running(&execution_id()).unwrap();
    host
}

#[test]
fn the_core04_coordinator_holds_the_reconstruction_dependencies() {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000_000)));
    let mut host = launched(&clock);
    let terms = LeaseTerms {
        term: 2 * HOUR,
        max_lifetime: 2 * HOUR,
        cancel_within: Duration::from_secs(1),
    };
    let service = host
        .start_child_work(
            &execution_id(),
            OperationId::new("op-prompt-hold").unwrap(),
            LeaseKind::Service,
            terms,
        )
        .unwrap();
    let declared = with_session_recipe(RecoveryRecipe::Recompute {
        prompt: PromptHolding::Held {
            prefix: TokenPrefix::from_token_ids(&[1, 2, 3]),
            lease: service.id(),
        },
        compute_seconds: 1.0,
    });
    let objects = FakeHolds::honoured();
    let plan = compile(&declared, &host, &objects, clock.as_ref()).unwrap();
    assert!(plan.horizon() <= service.expires_at());

    // Revoking the parent's authority cancels the lease: no recipe may rely on it.
    host.revoke(&execution_id()).unwrap();
    match compile(&declared, &host, &objects, clock.as_ref()) {
        Err(TransitionError::Recipe {
            refusal:
                RecipeRefusal::HoldNotHonoured {
                    refusal: LeaseRefusal::Cancelled { cause },
                    ..
                },
            ..
        }) => assert_eq!(cause, CancelCause::Revocation),
        other => panic!("expected a refused hold, got {other:?}"),
    }
}
