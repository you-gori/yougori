//! CORE-04 grant records as shown: read from the real coordinator, with grants held,
//! revoked in this run and tombstoned before a recovery; a grant held only while its
//! authority stands in force, also when a stored document is shown again; and every
//! record refused when it is edited into something the coordinator did not record. The
//! capacity and VM ports are stand-ins that grant every reservation and boot every VM
//! ready.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde_json::{json, Value};

use super::*;
use crate::foundation::coordination::{
    network_grant_id, BootRequest, CapacityPort, CapacityRefusal, Coordinator,
    ExecutionCancellation, LabelledAuthorization, LaunchOutcome, LaunchPlan, Lease, LeaseKind,
    LeaseTerms, ObservedVm, PerimeterId, PortFailure, PortOperation, Readiness as PortReadiness,
    ReadinessReport, ReconcileReport, ReleaseOutcome, ReservationKey, ReservationPriority,
    ReservationRequest, ReserveOutcome, ResourceKind, RestoredVmReport, ReturnHold, SandboxPort,
    SettingsGrant, SnapshotManifest, VmInstanceId,
};
use crate::foundation::evidence::{ClockSession, NetworkGrant, RuntimeRequirement};
use crate::foundation::ids::{ExecutionId, GrantId, OperationId, SandboxBootGeneration, TenantId};
use crate::foundation::product::fixtures::GOLDEN_FIXTURES;
use crate::foundation::product::{
    read_view, AuthorityStanding, ExecutionGrants, GrantError, GrantScope, GrantShown, GrantStatus,
    ProductView, Read, ReadPurpose, ShownAt, ViewSubject, ViewSubjectKind,
};

/// A capacity port that grants every reservation; these tests are about grants.
struct Ample;

impl CapacityPort for Ample {
    fn reserve(&mut self, _: &ReservationRequest) -> Result<ReserveOutcome, CapacityRefusal> {
        Ok(ReserveOutcome::Granted)
    }

    fn begin_create(&mut self, _: &ReservationKey) -> Result<(), CapacityRefusal> {
        Ok(())
    }

    fn release(&mut self, _: &ReservationKey) -> Result<ReleaseOutcome, CapacityRefusal> {
        Ok(ReleaseOutcome::Released)
    }

    fn confirm_release(
        &mut self,
        _: &ReservationKey,
        _: SourceClass,
    ) -> Result<ReleaseOutcome, CapacityRefusal> {
        Ok(ReleaseOutcome::Released)
    }

    fn cancel_execution(
        &mut self,
        _: &ExecutionId,
    ) -> Result<ExecutionCancellation, CapacityRefusal> {
        Ok(ExecutionCancellation::default())
    }

    fn reconcile(
        &mut self,
        _: &ExecutionId,
        expected: &BTreeSet<ReservationKey>,
    ) -> Result<ReconcileReport, CapacityRefusal> {
        Ok(ReconcileReport {
            confirmed: expected.clone(),
            ..ReconcileReport::default()
        })
    }

    fn begin_hold(&mut self, _: &BTreeSet<ResourceKind>) -> Result<ReturnHold, CapacityRefusal> {
        Ok(ReturnHold::new(1))
    }

    fn end_hold(&mut self, _: ReturnHold) -> Result<(), CapacityRefusal> {
        Ok(())
    }
}

/// A VM port whose VMs boot ready, and which lists none after a restart.
struct Vms;

impl SandboxPort for Vms {
    fn prepare_perimeter(&mut self, request: &BootRequest) -> Result<PerimeterId, PortFailure> {
        Ok(PerimeterId::new(digest(
            "yougori/test/product/perimeter/v1",
            &[request.execution.as_str().as_bytes()],
        )))
    }

    fn create_vm(
        &mut self,
        request: &BootRequest,
        _: &PerimeterId,
    ) -> Result<VmInstanceId, PortFailure> {
        Ok(VmInstanceId::new(digest(
            "yougori/test/product/vm/v1",
            &[request.execution.as_str().as_bytes()],
        )))
    }

    fn restore_vm(
        &mut self,
        _: &BootRequest,
        _: &PerimeterId,
        _: &SnapshotManifest,
    ) -> Result<VmInstanceId, PortFailure> {
        Err(PortFailure {
            operation: PortOperation::RestoreVm,
            detail: "this test port restores nothing".to_owned(),
        })
    }

    fn observe_readiness(&mut self, _: &VmInstanceId, _: SandboxBootGeneration) -> ReadinessReport {
        ReadinessReport {
            source: SourceClass::HostProbe,
            readiness: PortReadiness::Ready,
        }
    }

    fn inspect_restored_vm(
        &mut self,
        _: &VmInstanceId,
        _: SandboxBootGeneration,
    ) -> RestoredVmReport {
        unreachable!("this test port restores nothing")
    }

    fn terminate_vm(&mut self, _: &VmInstanceId) -> Result<(), PortFailure> {
        Ok(())
    }

    fn teardown_perimeter(&mut self, _: &PerimeterId) -> Result<(), PortFailure> {
        Ok(())
    }

    fn list_vms(&mut self) -> Result<Vec<ObservedVm>, PortFailure> {
        Ok(Vec::new())
    }
}

type World = Coordinator<Arc<ManualClock>, Ample>;

/// The clock session the grants fixture names, so it does not depend on a random one.
const FIXED_SESSION: &str = "01234567-89ab-4cde-8f01-23456789abcd";

/// A coordinator on the registry's own clock and clock session.
fn coordinator(probes: &Probes) -> World {
    Coordinator::new(Arc::clone(&probes.clock), probes.registry.session(), Ample)
}

fn execution() -> ExecutionId {
    ExecutionId::new("exe-coder").unwrap()
}

fn tenant() -> TenantId {
    TenantId::new("tenant-a").unwrap()
}

fn route(name: &str) -> NetworkGrant {
    NetworkGrant::NamedRoute {
        route: digest("yougori/test/product/route/v1", &[name.as_bytes()]),
    }
}

fn issued(name: &str) -> GrantId {
    GrantId::from_digest(digest("yougori/test/product/grant/v1", &[name.as_bytes()]))
}

fn settings(network: &[NetworkGrant]) -> SettingsGrant {
    SettingsGrant {
        network: network.iter().copied().collect(),
        verified_artifacts: BTreeSet::new(),
    }
}

/// Launches the VM sandbox with authority for an hour, its models granted `network`.
fn launch(world: &mut World, probes: &mut Probes, network: &[NetworkGrant]) {
    let offer = probes.offer(ExecutionCategory::VmSandbox);
    let plan = LaunchPlan {
        execution: execution(),
        tenant: tenant(),
        runtime: RuntimeRequirement::VmSandbox.admit(&offer).unwrap(),
        demand: BTreeMap::new(),
        priority: ReservationPriority::Foreground,
        authority_lifetime: HOUR,
        readiness_max_age: HOUR,
        runtime_evidence_max_age: HOUR,
    };
    let outcome = world
        .launch_with(plan, settings(network), &mut Vms, &probes.registry)
        .unwrap();
    assert!(
        matches!(outcome, LaunchOutcome::AuthorityActive { .. }),
        "{outcome:?}"
    );
}

/// Authorizes the shared-kernel GPU runtime for an hour, its models granted `network`.
fn authorize(world: &mut World, probes: &mut Probes, network: &[NetworkGrant]) {
    let offer = probes.offer(ExecutionCategory::SharedKernelGpuRuntime);
    let admitted = RuntimeRequirement::explicit([ExecutionCategory::SharedKernelGpuRuntime])
        .unwrap()
        .admit(&offer)
        .unwrap();
    world
        .authorize_labelled(
            LabelledAuthorization {
                execution: execution(),
                tenant: tenant(),
                runtime: admitted,
                authority_lifetime: HOUR,
                runtime_evidence_max_age: HOUR,
                settings: settings(network),
            },
            &probes.registry,
        )
        .unwrap();
}

/// Child work of the sandbox under `grants`.
fn work(world: &mut World, operation: &str, grants: &[GrantId]) -> Lease {
    world
        .start_granted_work(
            &execution(),
            OperationId::new(operation).unwrap(),
            LeaseKind::ChildWork,
            LeaseTerms {
                term: Duration::from_secs(600),
                max_lifetime: HOUR,
                cancel_within: Duration::from_secs(5),
            },
            grants.iter().copied().collect(),
        )
        .unwrap()
}

/// A VM sandbox whose models may use the mirror and telemetry routes, with child work
/// under a delegation and under the telemetry route, after the telemetry route and a grant
/// it never held were revoked. The coordinator and its registry.
fn sandbox() -> (World, Probes) {
    let mut probes = Probes::new(SourceClass::HostProbe);
    let mut world = coordinator(&probes);
    launch(
        &mut world,
        &mut probes,
        &[route("mirror"), route("telemetry")],
    );
    work(&mut world, "op-build", &[issued("delegation")]);
    let telemetry = network_grant_id(&route("telemetry"));
    work(&mut world, "op-report", &[telemetry]);
    probes.advance(Duration::from_secs(1));
    world.revoke_grant(&execution(), telemetry).unwrap();
    world
        .revoke_grant(&execution(), issued("never-held"))
        .unwrap();
    probes.advance(Duration::from_secs(1));
    (world, probes)
}

/// A labelled runtime that revoked its old mirror route, restarted, and was authorized
/// again with the old and a new mirror route. The coordinator and the registry after the
/// restart.
fn restarted() -> (World, Probes) {
    let mut before = Probes::new(SourceClass::HostProbe);
    let mut world = coordinator(&before);
    authorize(&mut world, &mut before, &[route("old-mirror")]);
    world
        .revoke_grant(&execution(), network_grant_id(&route("old-mirror")))
        .unwrap();
    let persisted = world.persist();

    let mut after = Probes::new(SourceClass::HostProbe);
    let (mut world, _) = World::recover(
        persisted,
        Arc::clone(&after.clock),
        after.registry.session(),
        Ample,
        &mut Vms,
    )
    .unwrap();
    authorize(
        &mut world,
        &mut after,
        &[route("old-mirror"), route("mirror")],
    );
    (world, after)
}

fn shown(grants: &ExecutionGrants, grant: GrantId) -> &GrantShown {
    grants.grant(grant).unwrap()
}

#[test]
fn a_sandboxs_held_and_revoked_grants_are_shown_as_the_coordinator_records_them() {
    let (world, probes) = sandbox();
    let grants = ExecutionGrants::of(&world, &execution(), probes.now()).unwrap();
    assert_eq!(grants.standing(), AuthorityStanding::InForce);
    assert_eq!(grants.grants().len(), 4);
    assert!(grants
        .grants()
        .windows(2)
        .all(|pair| pair[0].grant() < pair[1].grant()));

    let mirror = shown(&grants, network_grant_id(&route("mirror")));
    assert_eq!(
        mirror.scope(),
        GrantScope::Network {
            network: route("mirror")
        }
    );
    assert_eq!(mirror.status(), GrantStatus::Held);
    assert!(mirror
        .text()
        .as_str()
        .contains("not that anything enforces it"));

    let delegation = shown(&grants, issued("delegation"));
    assert_eq!(delegation.scope(), GrantScope::Issued);
    assert_eq!(delegation.status(), GrantStatus::Held);
    assert_eq!(delegation.leases(), 1);

    // Revoked in this run: what it cancelled, with the bound the holder stops by; the
    // epoch and the other grants stay.
    let telemetry = shown(&grants, network_grant_id(&route("telemetry")));
    assert_eq!(
        telemetry.scope(),
        GrantScope::Network {
            network: route("telemetry")
        }
    );
    let GrantStatus::Revoked {
        at,
        cancelled_leases,
        stop_by,
        activations,
    } = telemetry.status()
    else {
        panic!("revoked in this run: {telemetry}");
    };
    assert_eq!((cancelled_leases, activations), (1, 0));
    assert_eq!(stop_by, Some(at.saturating_add(Duration::from_secs(5))));
    assert_eq!(telemetry.leases(), 0);
    assert_eq!(
        grants.epoch(),
        world
            .sandbox(&execution())
            .unwrap()
            .generations()
            .authorization
    );

    // A grant the sandbox never held is tombstoned all the same; its scope is unknown.
    let never = shown(&grants, issued("never-held"));
    assert_eq!(never.scope(), GrantScope::Unrecorded);
    assert!(matches!(
        never.status(),
        GrantStatus::Revoked {
            cancelled_leases: 0,
            stop_by: None,
            ..
        }
    ));

    assert_eq!(round_trip(&grants), grants);
    assert!(ExecutionGrants::of(
        &world,
        &ExecutionId::new("exe-other").unwrap(),
        probes.now()
    )
    .is_none());
}

#[test]
fn a_grant_revoked_before_a_restart_is_shown_tombstoned_and_never_granted_again() {
    let (world, probes) = restarted();
    let grants = ExecutionGrants::of(&world, &execution(), probes.now()).unwrap();
    assert_eq!(grants.standing(), AuthorityStanding::InForce);
    assert_eq!(grants.grants().len(), 2);
    assert_eq!(
        shown(&grants, network_grant_id(&route("mirror"))).status(),
        GrantStatus::Held
    );
    let old = shown(&grants, network_grant_id(&route("old-mirror")));
    assert_eq!(old.scope(), GrantScope::Unrecorded);
    assert_eq!(old.status(), GrantStatus::Tombstoned);
    assert!(old.text().as_str().contains("never granted again"), "{old}");
    assert_eq!(round_trip(&grants), grants);

    // Revoking the whole authority advances the epoch: every grant under it lapses.
    let mut world = world;
    world.revoke_labelled(&execution()).unwrap();
    let revoked = ExecutionGrants::of(&world, &execution(), probes.now()).unwrap();
    assert_eq!(revoked.standing(), AuthorityStanding::Revoked);
    let mirror = shown(&revoked, network_grant_id(&route("mirror")));
    assert_eq!(mirror.status(), GrantStatus::Lapsed);
    assert!(mirror.text().as_str().contains("was revoked"), "{mirror}");
    assert_eq!(
        shown(&revoked, network_grant_id(&route("old-mirror"))).status(),
        GrantStatus::Tombstoned
    );
}

#[test]
fn a_grant_is_held_only_while_its_authority_stands_in_force() {
    let (world, probes) = sandbox();
    let in_force = ExecutionGrants::of(&world, &execution(), probes.now()).unwrap();
    let mut view = ProductView::new(
        ViewSubject::new(ViewSubjectKind::Sandbox, "coder").unwrap(),
        ShownAt::of(probes.now(), config()),
    );
    view.grants = Some(in_force.clone());
    let stored = view.to_json().unwrap();
    let Read::Current(read) = read_view(&stored, ReadPurpose::Act).unwrap() else {
        panic!("current");
    };
    assert_eq!(read, view);
    let held = |grants: &ExecutionGrants| {
        grants
            .grants()
            .iter()
            .filter(|grant| grant.status() == GrantStatus::Held)
            .count()
    };
    assert_eq!(held(&in_force), 2);

    // Shown again after the authority expired, or on another clock: nothing is held, and
    // the revocations stay as recorded.
    probes.advance(HOUR);
    for (again, standing) in [
        (
            view.as_of(probes.now(), config()),
            AuthorityStanding::Expired,
        ),
        (
            view.as_of(Probes::new(SourceClass::HostProbe).now(), config()),
            AuthorityStanding::OtherClock,
        ),
    ] {
        let grants = again.grants.as_ref().unwrap();
        assert_eq!(grants.standing(), standing);
        assert_eq!(held(grants), 0);
        let delegation = grants.grant(issued("delegation")).unwrap();
        assert_eq!(delegation.status(), GrantStatus::Lapsed);
        assert!(
            delegation.text().as_str().contains("not held"),
            "{delegation}"
        );
        assert_eq!(
            grants
                .grants()
                .iter()
                .filter(|grant| grant.status().is_revoked())
                .count(),
            2
        );
        assert!(read_view(&again.to_json().unwrap(), ReadPurpose::Act).is_ok());
    }
    let expired = ExecutionGrants::of(&world, &execution(), probes.now()).unwrap();
    assert_eq!(expired.standing(), AuthorityStanding::Expired);
    assert_eq!(held(&expired), 0);
}

#[test]
fn grant_records_edited_into_something_the_coordinator_did_not_record_are_refused() {
    let (world, probes) = sandbox();
    let grants = ExecutionGrants::of(&world, &execution(), probes.now()).unwrap();
    let json = serde_json::to_value(&grants).unwrap();
    let index = |grant: GrantId| {
        grants
            .grants()
            .iter()
            .position(|shown| shown.grant() == grant)
            .unwrap()
    };
    let edit = |change: &dyn Fn(&mut Value)| {
        let mut edited = json.clone();
        change(&mut edited);
        refused::<ExecutionGrants>(edited)
    };
    let mirror = index(network_grant_id(&route("mirror")));
    let delegation = index(issued("delegation"));
    let telemetry = index(network_grant_id(&route("telemetry")));

    let error = edit(&|json| json["grants"][mirror]["scope"]["network"] = json!(route("other")));
    assert!(
        error.contains("not the identity of its network grant"),
        "{error}"
    );
    let error = edit(&|json| json["grants"][mirror]["status"] = json!({"status": "lapsed"}));
    assert!(
        error.contains("lapsed while the authority is in force"),
        "{error}"
    );
    let error = edit(&|json| json["standing"] = json!("expired"));
    assert!(
        error.contains("held while the authority is not in force"),
        "{error}"
    );
    let error = edit(&|json| json["standing"] = json!("revoked"));
    assert!(error.contains("records contradict"), "{error}");
    let error = edit(&|json| json["grants"][mirror]["text"] = json!("certified route"));
    assert!(error.contains("not its own"), "{error}");
    let error = edit(&|json| json["grants"][telemetry]["leases"] = json!(2));
    assert!(error.contains("no lease in force"), "{error}");
    let error = edit(&|json| json["grants"][delegation]["scope"] = json!({"scope": "unrecorded"}));
    assert!(error.contains("not revoked"), "{error}");
    let error = edit(&|json| {
        json["grants"][telemetry]["status"]
            .as_object_mut()
            .unwrap()
            .remove("stop_by");
    });
    assert!(error.contains("stop bound"), "{error}");
    let error = edit(&|json| json["grants"].as_array_mut().unwrap().swap(0, 1));
    assert!(error.contains("identity order"), "{error}");
    let error = edit(&|json| json["epoch"] = json!(0));
    assert!(error.contains("later epoch"), "{error}");
    let error = edit(&|json| json["grants"][mirror]["enforced"] = json!(true));
    assert!(error.contains("unknown field"), "{error}");
    let error = edit(&|json| json["grants"][mirror]["status"] = json!({"status": "held", "x": 1}));
    assert!(error.contains("unknown field"), "{error}");

    // The standing is where the authority stood when the document was shown.
    let mut view = ProductView::new(
        ViewSubject::new(ViewSubjectKind::Sandbox, "coder").unwrap(),
        ShownAt::of(probes.now(), config()),
    );
    view.grants = Some(grants.clone());
    assert_eq!(view.check(), Ok(()));
    view.shown_at.clock = ClockSession::from_uuid(uuid::Uuid::from_u128(7));
    let error = view.check().unwrap_err().to_string();
    assert!(error.contains("stood OtherClock"), "{error}");
    assert!(matches!(
        grants.check(&view.shown_at),
        Err(GrantError::Standing { .. })
    ));
}

/// The grants fixture: the sandbox's grants, on the fixed clock session.
fn execution_grants() -> Value {
    let (world, probes) = sandbox();
    let mut view = ProductView::new(
        ViewSubject::new(ViewSubjectKind::Sandbox, "coder").unwrap(),
        ShownAt::of(probes.now(), config()),
    );
    view.grants = ExecutionGrants::of(&world, &execution(), probes.now());
    let mut json = serde_json::to_value(&view).unwrap();
    json["shown_at"]["clock"] = json!(FIXED_SESSION);
    json["grants"]["authority"]["clock"] = json!(FIXED_SESSION);
    json
}

#[test]
fn the_grants_fixture_is_what_the_coordinator_records() {
    let fixture = GOLDEN_FIXTURES
        .iter()
        .find(|fixture| fixture.name == "execution_grants")
        .unwrap();
    assert_eq!(fixture.version, 2);
    let expected: Value = serde_json::from_str(fixture.json).unwrap();
    assert_eq!(execution_grants(), expected);
    let Read::Current(read) = read_view(fixture.json, ReadPurpose::Act).unwrap() else {
        panic!("current");
    };
    assert_eq!(read.to_json_pretty().unwrap() + "\n", fixture.json);
    let grants = read.grants.as_ref().unwrap();
    assert_eq!(grants.standing(), AuthorityStanding::InForce);
    let statuses: Vec<GrantStatus> = grants.grants().iter().map(GrantShown::status).collect();
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == GrantStatus::Held)
            .count(),
        2
    );
    assert_eq!(
        statuses.iter().filter(|status| status.is_revoked()).count(),
        2
    );
}
