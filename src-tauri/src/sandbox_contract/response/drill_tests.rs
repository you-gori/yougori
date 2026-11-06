//! Drills on fakes (Tier 0): VM-W43's acceptance items, VM-P24 isolation, stop, cleanup and
//! restart drills, the VM-P14 and VM-CP-14 response-side records, consistency with V05's
//! VM-D10 responses for both classes, audit overload during emergency revocation, and a
//! V09 canary hit as a signal. The coordinator, ledger port, backend, journal and hub are
//! the committed CORE-04 and CORE-06 code over in-memory fakes; no VM exists.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::emergency::DeferredRecord;
use super::fakes::*;
use super::tests::every_input;
use super::timeline::EventSource;
use super::*;
use crate::foundation::coordination::{
    LeaseKind, MilestoneSource, RevocationEvents, RevocationMilestone, RevocationStatus,
    SandboxRecovery, SandboxState, VmInstanceId,
};
use crate::foundation::events::{
    AuditEntry, AuditFailurePolicy, AuditRefusal, Durability, EventContext, EventSequence,
    GrantRevocation, LogConfig, LogError, MetricDraft, MetricValue, Phase, ProducerId, RecordError,
    RedactionPolicy, Revocation, RevocationAdmission, RevocationLog, RevocationReason,
    RevocationRecord, StoreRefusal, Takeover,
};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Clock, ManualClock, OperationId, SandboxBootGeneration,
};
use crate::sandbox_contract::canaries::{
    self, CanaryKind, CanaryRegistry, CanarySeed, HitMeaning, HoneyportPool, ObservedContent,
    PlacementLocation, PlacementRequest, PlantOrigin, PlantingRequest, SandboxBinding,
};
use crate::sandbox_contract::effects::{IssuerId, SandboxRef};
use crate::sandbox_contract::files::{
    CleanupPlan, CleanupRefusal, CleanupTarget, ManagedObjectKind, ManagedObjects, ManagedRootId,
    ObservedIdentities, SandboxClass, ViolationAction, ViolationOutcome,
};

fn operation(name: &str) -> OperationId {
    OperationId::new(name).unwrap()
}

/// The CORE-06 plane, the coordinator's durable revocation stream and the deferred audit
/// queue of one host.
struct Plane {
    hub: crate::foundation::events::EventHub<Arc<ManualClock>>,
    issuer: crate::foundation::events::RevocationIssuer,
    journal: Journal,
    authority: crate::foundation::events::AuditAppendAuthority,
    store: MemoryAuditStore,
    spool: MemorySpool,
    deferred: DeferredAudit,
    /// Declared before its directory, so it is released before the directory goes.
    log: RevocationLog,
    directory: tempfile::TempDir,
}

impl Plane {
    fn new(clock: &Arc<ManualClock>, spool_records: usize, policy: AuditFailurePolicy) -> Self {
        Self::with_log(
            clock,
            spool_records,
            policy,
            REVOCATIONS_OWNER,
            revocation_log_config(),
        )
    }

    /// A plane whose durable revocation stream, on a fresh temporary directory, is owned by
    /// `owner` with `config`.
    fn with_log(
        clock: &Arc<ManualClock>,
        spool_records: usize,
        policy: AuditFailurePolicy,
        owner: &str,
        config: LogConfig,
    ) -> Self {
        let (hub, issuer) = hub(clock);
        let (journal, authority, store, spool) = journal(clock, spool_records, policy);
        let directory = tempfile::tempdir().unwrap();
        let (log, _) = open_revocation_log(directory.path(), owner, config);
        Self {
            hub,
            issuer,
            journal,
            authority,
            store,
            spool,
            deferred: DeferredAudit::new(4).unwrap(),
            log,
            directory,
        }
    }

    fn execute(&mut self, world: &mut World, target: &TargetResponse) -> TargetExecution {
        let mut events = RevocationEvents {
            hub: &mut self.hub,
            issuer: &mut self.issuer,
            journal: &mut self.journal,
            authority: &mut self.authority,
        };
        execute_target(
            &mut world.coordinator,
            &mut world.port,
            &mut events,
            &mut self.log,
            &mut self.deferred,
            target,
            operation("op-response"),
        )
        .unwrap()
    }

    fn revoke(
        &mut self,
        world: &mut World,
        of: &crate::foundation::ids::ExecutionId,
    ) -> EmergencyReceipt {
        let mut events = RevocationEvents {
            hub: &mut self.hub,
            issuer: &mut self.issuer,
            journal: &mut self.journal,
            authority: &mut self.authority,
        };
        emergency_revoke(
            &mut world.coordinator,
            &mut events,
            &mut self.log,
            &mut self.deferred,
            of,
            operation("op-emergency"),
        )
        .unwrap()
    }
}

fn responder_for(world: &World, sandboxes: &[(&str, SandboxClass)]) -> Responder<Arc<ManualClock>> {
    let mut responder = Responder::new(Arc::clone(&world.clock), policies(), bounds());
    for (name, class) in sandboxes {
        responder
            .register_sandbox(execution(name), *class, BTreeSet::new())
            .unwrap();
    }
    responder
}

// ---------------------------------------------------------------------------------------
// VM-D10 through V05, for both classes

#[test]
fn a_task_sandbox_stops_on_a_clear_violation_through_v05() {
    let mut world = World::new();
    let a = execution("exe-a");
    world.launch(&a);
    let mut plane = Plane::new(&world.clock, 4, AuditFailurePolicy::DenyHighImpact);
    let mut responder = responder_for(&world, &[("exe-a", SandboxClass::Task)]);
    let record = responded(
        responder
            .respond_to(&fresh_host_assessment(
                "exe-a",
                ViolationKind::CredentialReplay,
                &world.clock,
            ))
            .unwrap(),
    );
    let target = record.observed().unwrap();
    assert_eq!(target.class_response, Some(ViolationAction::Stop));
    let mut host = FakeSandboxHost::new("exe-a", SandboxClass::Task);
    let before = host.user_data.clone();
    let executed = plane.execute(&mut world, target);
    host.apply(target);
    let receipt = executed.revocation.unwrap();
    assert_eq!(receipt.recorded, Ok(EventSequence::FIRST));
    assert_eq!(
        receipt.audit,
        RevocationAudit::Written {
            durability: Durability::Durable
        }
    );
    assert_eq!(receipt.leases_bounded_until, None);
    assert_eq!(receipt.high_impact, HighImpactGate::Admitted);
    assert_eq!(receipt.lane, Ok(RevocationAdmission::Queued));
    assert!(matches!(
        executed.class_response,
        Some(ViolationOutcome::Stopping {
            status: RevocationStatus::Completed { .. },
            ..
        })
    ));
    assert_eq!(
        executed.runtime_actions,
        [ResponseAction::DenyNewHighImpact, ResponseAction::Isolate]
    );
    assert_eq!(world.port.terminated.len(), 1);
    assert!(world.port.running.is_empty());
    assert!(!world.has_authority(&a));
    assert_eq!(host.user_data, before);
    assert!(!host.vm_running);
}

#[test]
fn a_service_sandbox_locks_down_with_a_one_click_stop_through_v05() {
    let mut world = World::new();
    let s = execution("exe-s");
    world.launch(&s);
    let mut plane = Plane::new(&world.clock, 4, AuditFailurePolicy::DenyHighImpact);
    let mut responder = responder_for(&world, &[("exe-s", SandboxClass::Service)]);
    let record = responded(
        responder
            .respond_to(&fresh_host_assessment(
                "exe-s",
                ViolationKind::LaunchArtifactIntegrity,
                &world.clock,
            ))
            .unwrap(),
    );
    let target = record.observed().unwrap();
    assert_eq!(target.class_response, Some(ViolationAction::LockDown));
    assert!(target.preserves.contains(&Preserved::VmState));
    let mut host = FakeSandboxHost::new("exe-s", SandboxClass::Service);
    let before = host.user_data.clone();
    let executed = plane.execute(&mut world, target);
    host.apply(target);
    let stop = match executed.class_response {
        Some(ViolationOutcome::LockedDown { notice, stop }) => {
            assert!(notice.current > notice.revoked);
            stop
        }
        other => panic!("{other:?}"),
    };
    // Locked down: the VM is kept, without authority, until the user's one click.
    assert_eq!(world.port.running.len(), 1);
    assert!(world.port.terminated.is_empty());
    assert!(!world.has_authority(&s));
    assert!(host.locked_down && host.vm_running);
    let status = stop.stop(&mut world.coordinator, &mut world.port).unwrap();
    assert!(
        matches!(status, RevocationStatus::Completed { .. }),
        "{status:?}"
    );
    assert_eq!(world.port.terminated.len(), 1);
    assert_eq!(host.user_data, before);
}

#[test]
fn every_stop_matches_v05s_class_response_for_both_classes() {
    for kind in StopPolicy::default_triggers() {
        for class in [SandboxClass::Task, SandboxClass::Service] {
            let mut world = World::new();
            let a = execution("exe-a");
            world.launch(&a);
            let mut plane = Plane::new(&world.clock, 4, AuditFailurePolicy::DenyHighImpact);
            let mut responder = responder_for(&world, &[("exe-a", class)]);
            let record = responded(
                responder
                    .respond_to(&fresh_host_assessment("exe-a", kind, &world.clock))
                    .unwrap(),
            );
            let target = record.observed().unwrap();
            assert_eq!(
                target.class_response,
                Some(ViolationAction::for_class(class))
            );
            let executed = plane.execute(&mut world, target);
            match (class, executed.class_response) {
                (SandboxClass::Task, Some(ViolationOutcome::Stopping { .. }))
                | (SandboxClass::Service, Some(ViolationOutcome::LockedDown { .. })) => {}
                (class, other) => panic!("{kind:?} {class:?}: {other:?}"),
            }
            assert!(!world.has_authority(&a));
        }
    }
}

// ---------------------------------------------------------------------------------------
// False positives do not erase user work (VM-W43 acceptance)

fn target_of(decision: &Decision) -> TargetResponse {
    TargetResponse {
        sandbox: execution("exe-a"),
        sandbox_class: decision.input.sandbox_class,
        role: TargetRole::Observed,
        actions: decision.actions.clone(),
        new_actions: decision.actions.clone(),
        class_response: decision.class_response,
        notification: None,
        preserves: decision.preserves.clone(),
    }
}

#[test]
fn no_decision_changes_user_data_identities() {
    let policies = policies();
    for input in every_input() {
        let decision = decide(&policies, &input);
        let mut host = FakeSandboxHost::new("exe-a", input.sandbox_class);
        let before = host.user_data.clone();
        host.apply(&target_of(&decision));
        assert_eq!(host.user_data, before, "{input:?}");
        // Isolation and lockdown keep the VM; only a task stop ends it.
        assert_eq!(
            host.vm_running,
            decision.preserves.contains(&Preserved::VmState)
        );
    }
}

#[test]
fn response_cleanup_removes_only_the_stopped_vms_process_perimeter_and_sockets() {
    let root = ManagedRootId::from_host(digest("yougori/test/root/v1", &[b"sandboxes"]));
    let root_identity = digest("yougori/test/root-identity/v1", &[b"sandboxes"]);
    let mut objects = ManagedObjects::new();
    objects.register_root(root, root_identity);
    let kinds = [
        ManagedObjectKind::Overlay,
        ManagedObjectKind::ScratchDirectory,
        ManagedObjectKind::Socket,
        ManagedObjectKind::Perimeter,
        ManagedObjectKind::Snapshot,
        ManagedObjectKind::VmProcess,
        ManagedObjectKind::UserSourceData,
    ];
    let mut observed = ObservedIdentities {
        roots: BTreeMap::from([(root, root_identity)]),
        ..ObservedIdentities::default()
    };
    let mut handles = Vec::new();
    for kind in kinds {
        let object = digest("yougori/test/object/v1", &[format!("{kind:?}").as_bytes()]);
        observed.objects_present.insert(object);
        handles.push((
            kind,
            object,
            objects.register_object(root, kind, object, None).unwrap(),
        ));
    }
    for (kind, object, handle) in handles {
        let result = plan_response_cleanup(&objects, &CleanupTarget::Object { handle }, &observed);
        match kind {
            ManagedObjectKind::Socket
            | ManagedObjectKind::Perimeter
            | ManagedObjectKind::VmProcess => {
                assert!(
                    matches!(result, Ok(CleanupPlan::Delete { .. })),
                    "{kind:?}: {result:?}"
                );
            }
            ManagedObjectKind::UserSourceData => assert_eq!(
                result,
                Err(ResponseCleanupRefusal::Unsafe {
                    cleanup: CleanupRefusal::PreservesUserData { object }
                })
            ),
            _ => assert_eq!(
                result,
                Err(ResponseCleanupRefusal::PreservedForRecovery { object, kind })
            ),
        }
    }
    assert_eq!(
        plan_response_cleanup(&objects, &CleanupTarget::StoredPid { pid: 4242 }, &observed),
        Err(ResponseCleanupRefusal::Unsafe {
            cleanup: CleanupRefusal::UnverifiedPid { pid: 4242 }
        }),
        "a stored PID never names a process to terminate (§6.4)"
    );
    assert_eq!(
        plan_response_cleanup(
            &objects,
            &CleanupTarget::GuestPath {
                path: "../../home".into()
            },
            &observed
        ),
        Err(ResponseCleanupRefusal::Unsafe {
            cleanup: CleanupRefusal::GuestPathNeverAccepted
        })
    );
}

// ---------------------------------------------------------------------------------------
// VM-P24 drills: isolation, stop, cleanup and restart preserve user data and never revive
// authority

#[test]
fn isolation_drill_is_reversible_and_never_revives_authority() {
    let mut world = World::new();
    let s = execution("exe-s");
    world.launch(&s);
    let mut plane = Plane::new(&world.clock, 4, AuditFailurePolicy::DenyHighImpact);
    let mut responder = responder_for(&world, &[("exe-s", SandboxClass::Service)]);
    let mut monitor = ResourceMonitor::new(
        host_session(),
        &uncertain(),
        BTreeMap::from([(
            MonitoredResource::PacketsPerSecond,
            SustainedWindow {
                high_mark: 1_000,
                low_mark: 500,
                sustain_seconds: 30,
                clear_seconds: 60,
                max_sample_gap_seconds: 10,
            },
        )]),
        16,
    )
    .unwrap();
    let mut sandbox_host = FakeSandboxHost::new("exe-s", SandboxClass::Service);
    let before = sandbox_host.user_data.clone();
    let epoch = world.epoch(&s);

    // A sustained packet flood isolates; authority is untouched.
    let mut trigger = None;
    for _ in 0..4 {
        let flood = sample(
            "exe-s",
            MonitoredResource::PacketsPerSecond,
            host(HostObserver::Perimeter),
            5_000,
            world.clock.now(),
        );
        if let ResourceObservation::Triggered { assessment, .. } =
            monitor.observe(&flood, world.clock.as_ref()).unwrap()
        {
            trigger = Some(assessment);
        }
        world.clock.advance(10 * SECOND);
    }
    let record = responded(responder.respond_to(&trigger.unwrap()).unwrap());
    let target = record.observed().unwrap();
    assert_eq!(
        target.actions,
        [ResponseAction::NotifyUser, ResponseAction::Isolate].into()
    );
    let executed = plane.execute(&mut world, target);
    sandbox_host.apply(target);
    assert_eq!(executed.revocation, None);
    assert_eq!(executed.runtime_actions, [ResponseAction::Isolate]);
    assert!(sandbox_host.network_cut && sandbox_host.channels_cut && sandbox_host.vm_running);
    assert!(world.has_authority(&s));
    assert_eq!(world.epoch(&s), epoch);

    // The user releases it: channels come back, authority neither grows nor changes.
    responder.release_isolation(&s).unwrap();
    sandbox_host.release_isolation();
    assert!(!sandbox_host.network_cut);
    assert_eq!(world.epoch(&s), epoch);

    // A canary hit isolates and revokes; releasing isolation then revives nothing.
    let record = responded(
        responder
            .respond_to(&fresh_host_assessment(
                "exe-s",
                ViolationKind::CanaryUse,
                &world.clock,
            ))
            .unwrap(),
    );
    let target = record.observed().unwrap();
    let executed = plane.execute(&mut world, target);
    sandbox_host.apply(target);
    let revoked_epoch = world.epoch(&s);
    assert!(revoked_epoch > epoch);
    assert_eq!(
        executed.class_response, None,
        "a canary hit alone never stops"
    );
    assert!(!world.has_authority(&s));
    let release = responder.release_isolation(&s).unwrap();
    sandbox_host.release_isolation();
    assert!(release.still_applied.contains(&ResponseAction::Revoke));
    assert!(!world.has_authority(&s));
    assert_eq!(world.epoch(&s), revoked_epoch);
    assert_eq!(sandbox_host.user_data, before);
}

#[test]
fn stop_cleanup_and_restart_drill_preserves_user_data_and_never_revives_authority() {
    let mut world = World::new();
    let a = execution("exe-a");
    world.launch(&a);
    let lease = world
        .coordinator
        .start_child_work(&a, operation("op-build"), LeaseKind::ChildWork, terms())
        .unwrap();
    let mut plane = Plane::new(&world.clock, 4, AuditFailurePolicy::DenyHighImpact);
    let mut responder = responder_for(&world, &[("exe-a", SandboxClass::Task)]);
    let mut host = FakeSandboxHost::new("exe-a", SandboxClass::Task);
    let before = host.user_data.clone();

    let record = responded(
        responder
            .respond_to(&fresh_host_assessment(
                "exe-a",
                ViolationKind::CapabilityReplay,
                &world.clock,
            ))
            .unwrap(),
    );
    let target = record.observed().unwrap();
    let executed = plane.execute(&mut world, target);
    host.apply(target);
    let receipt = executed.revocation.unwrap();
    assert_eq!(
        receipt.leases_bounded_until,
        Some(at(START_SECONDS + 5)),
        "the build may act until its declared cancel bound, no longer"
    );
    let notice = receipt.notice;
    let mut timeline = RevocationTimeline::begin(&notice, Some(record.id));
    // The build's lease holds the stop until its declared 5 s bound.
    assert!(matches!(
        executed.class_response,
        Some(ViolationOutcome::Stopping {
            status: RevocationStatus::WaitingForLeases { .. },
            ..
        })
    ));
    world.clock.advance(SECOND);
    // The coordinator's own check refuses new child work and records the first denied
    // authorization; the timeline takes it from CORE-04, not from a hand-made record.
    assert!(!world.has_authority(&a));
    world.clock.advance(SECOND);
    // The host observes every eligible release channel closed.
    world
        .coordinator
        .acknowledge_revocation(
            &a,
            RevocationMilestone::AllChannelsClosed,
            SourceClass::HostProbe,
        )
        .unwrap();
    world.clock.advance(3 * SECOND);
    let status = world
        .coordinator
        .advance_revocation(&a, &mut world.port)
        .unwrap();
    assert!(
        matches!(status, RevocationStatus::Completed { .. }),
        "{status:?}"
    );
    assert_eq!(
        timeline
            .observe_operation(world.coordinator.revocation(&a).unwrap())
            .unwrap(),
        [
            RevocationEventKind::FirstDeniedAuthorization,
            RevocationEventKind::ChannelClosure,
            RevocationEventKind::VmStop,
            RevocationEventKind::CleanupCompletion
        ]
    );
    assert_eq!(
        timeline.source(RevocationEventKind::FirstDeniedAuthorization),
        Some(EventSource::Coordination {
            milestone: RevocationMilestone::FirstDeniedAuthorization,
            established_by: MilestoneSource::Coordinator,
        })
    );
    assert_eq!(
        timeline.source(RevocationEventKind::ChannelClosure),
        Some(EventSource::Coordination {
            milestone: RevocationMilestone::AllChannelsClosed,
            established_by: MilestoneSource::Acknowledged {
                source: SourceClass::HostProbe
            },
        })
    );
    assert_eq!(
        timeline.source(RevocationEventKind::DurableEpochAdvance),
        Some(EventSource::Notice)
    );
    assert!(world.coordinator.check_lease(lease.id()).is_err());

    // Five separate events, each at its own time after the decision.
    let after: Vec<u64> = timeline
        .entries()
        .iter()
        .map(|entry| match entry.status {
            TimelineStatus::Observed {
                after_decision_nanos,
                ..
            } => after_decision_nanos / 1_000_000_000,
            TimelineStatus::NotObserved => panic!("{entry:?}"),
        })
        .collect();
    assert_eq!(after, [0, 1, 2, 5, 5]);
    assert_eq!(
        timeline.vm_stop_within_target(),
        Some(false),
        "5 s against a 2 s target, this run"
    );

    // Restart: a new sandbox gets the preserved data and its own authority; the old
    // sandbox, its epoch and its lease stay dead.
    let a2 = execution("exe-a-restart");
    world.launch(&a2);
    let mut restarted = FakeSandboxHost::new("exe-a-restart", SandboxClass::Task);
    restarted.user_data = host.user_data.clone();
    responder
        .register_sandbox(a2.clone(), SandboxClass::Task, BTreeSet::new())
        .unwrap();
    assert!(world.has_authority(&a2));
    assert!(!world.has_authority(&a));
    assert!(world.coordinator.check_lease(lease.id()).is_err());
    assert_eq!(world.epoch(&a), notice.current);
    assert!(responder
        .applied(&a)
        .unwrap()
        .contains(&ResponseAction::Stop));
    assert_eq!(responder.applied(&a2), Some(&BTreeSet::new()));
    assert_eq!(restarted.user_data, before);
    assert_eq!(host.user_data, before);
}

// ---------------------------------------------------------------------------------------
// Audit overload cannot block emergency revocation (VM-W43 acceptance; §8.2)

#[test]
fn audit_overload_cannot_block_emergency_revocation() {
    let mut world = World::new();
    let (a, b) = (execution("exe-a"), execution("exe-b"));
    world.launch(&a);
    world.launch(&b);
    let mut plane = Plane::new(&world.clock, 2, AuditFailurePolicy::SpoolHighImpact);
    // A metrics flood on the hub, and storage that is full.
    let mut metrics = plane
        .hub
        .register_metrics(
            ProducerId::new("monitor").unwrap(),
            SourceClass::HostProbe,
            RedactionPolicy::metadata_only(),
            None,
        )
        .unwrap();
    for count in 0..500 {
        plane
            .hub
            .emit_metric(
                &mut metrics,
                EventContext::new(operation("op-metrics"), Phase::Running),
                MetricDraft::new("cpu_millicores", MetricValue::Counter { count }),
            )
            .unwrap();
    }
    *plane.store.refuse.borrow_mut() = Some(StoreRefusal::Full);
    // An ordinary record takes the last ordinary spool slot.
    let mut gate = EmissionGate::new(limit(10, SECOND));
    let signal = host_violation("exe-a", ViolationKind::PerimeterRule, world.clock.now());
    assert!(matches!(
        record_signal(&mut plane.journal, &mut plane.authority, &mut gate, &signal, operation("op-signal"), world.clock.as_ref()),
        SignalAudit::Recorded(receipt) if matches!(receipt.durability, Durability::Spooled { .. })
    ));

    // The first revocation takes the reserved slot; the second finds the spool full.
    let first = plane.revoke(&mut world, &a);
    assert_eq!(
        first.audit,
        RevocationAudit::Written {
            durability: Durability::Spooled { spooled_records: 2 }
        }
    );
    let second = plane.revoke(&mut world, &b);
    match &second.audit {
        RevocationAudit::Deferred { deferral, refusal } => {
            assert_eq!(*deferral, Deferral::Queued);
            assert!(matches!(
                refusal,
                AuditRefusal::FailClosed { kept: None, .. }
            ));
        }
        other => panic!("{other:?}"),
    }
    // Both revocations are in force, both reached the priority lane first, and audit
    // overload never reached the durable revocation stream.
    assert!(!world.has_authority(&a));
    assert!(!world.has_authority(&b));
    assert_eq!(second.lane, Ok(RevocationAdmission::Queued));
    assert_eq!(first.recorded, Ok(EventSequence::FIRST));
    assert_eq!(second.recorded, Ok(EventSequence::new(2).unwrap()));
    let delivery = plane.hub.drain(8);
    let revoked: Vec<_> = delivery
        .revocations
        .notices
        .iter()
        .map(|notice| (notice.payload().execution.clone(), notice.payload().reason))
        .collect();
    assert_eq!(
        revoked,
        [
            (a.clone(), RevocationReason::SecurityEvent),
            (b.clone(), RevocationReason::SecurityEvent)
        ]
    );
    assert!(delivery.metrics.events.len() <= 8);
    // New high-impact operations are denied while audit is degraded.
    assert_eq!(
        second.high_impact,
        HighImpactGate::Denied {
            reason: HighImpactDenial::RevocationRecordsDeferred {
                pending: 1,
                overflowed: 0
            }
        }
    );
    assert!(!second.high_impact.admits());
    assert!(plane
        .journal
        .admit_high_impact(
            &mut plane.authority,
            EventContext::new(operation("op-publish"), Phase::Requested),
            Vec::new()
        )
        .is_err());

    // Storage recovers: the spooled records go first, then the deferred one is written.
    *plane.store.refuse.borrow_mut() = None;
    plane.journal.flush();
    let flush = plane.deferred.flush(
        &mut plane.journal,
        &mut plane.authority,
        &operation("op-flush"),
    );
    assert_eq!(
        (flush.written, flush.remaining, flush.refusal),
        (1, 0, None)
    );
    assert_eq!(plane.store.revocations(), 2);
    assert_eq!(
        HighImpactGate::judge(plane.journal.health(), &plane.deferred),
        HighImpactGate::Admitted
    );
    assert!(plane.spool.records.borrow().is_empty());
}

#[test]
fn a_failing_store_and_spool_never_undo_a_revocation() {
    let mut world = World::new();
    let a = execution("exe-a");
    world.launch(&a);
    let mut plane = Plane::new(&world.clock, 2, AuditFailurePolicy::DenyHighImpact);
    *plane.store.refuse.borrow_mut() = Some(StoreRefusal::Failed);
    *plane.spool.refuse.borrow_mut() = true;
    let receipt = plane.revoke(&mut world, &a);
    assert!(
        matches!(receipt.audit, RevocationAudit::KeptByJournal { .. }),
        "{:?}",
        receipt.audit
    );
    assert!(
        plane.deferred.is_empty(),
        "the journal keeps the record itself"
    );
    assert!(!world.has_authority(&a));
    assert!(matches!(
        receipt.high_impact,
        HighImpactGate::Denied {
            reason: HighImpactDenial::AuditFailClosed { .. }
        }
    ));
    *plane.store.refuse.borrow_mut() = None;
    *plane.spool.refuse.borrow_mut() = false;
    plane.journal.flush();
    assert_eq!(plane.store.revocations(), 1);
}

#[test]
fn the_deferred_queue_is_bounded_and_records_its_overflow() {
    assert_eq!(DeferredAudit::new(0), Err(DeferredProblem::ZeroCapacity));
    let revocation = |name: &str, epoch: u64| Revocation {
        execution: execution(name),
        epoch: AuthorizationEpoch::new(epoch),
        reason: RevocationReason::SecurityEvent,
    };
    let mut deferred = DeferredAudit::new(1).unwrap();
    assert_eq!(deferred.defer(revocation("exe-a", 2)), Deferral::Queued);
    assert_eq!(deferred.defer(revocation("exe-a", 3)), Deferral::Raised);
    assert_eq!(
        deferred.defer(revocation("exe-a", 1)),
        Deferral::AlreadyCovered
    );
    assert_eq!(deferred.defer(revocation("exe-b", 2)), Deferral::Overflowed);
    assert_eq!((deferred.len(), deferred.overflowed()), (1, 1));
    assert_eq!(
        deferred.pending().next().unwrap().epoch(),
        AuthorizationEpoch::new(3)
    );

    let clock = Arc::new(clock());
    let (mut working, mut authority, store, _) =
        journal(&clock, 4, AuditFailurePolicy::DenyHighImpact);
    let flush = deferred.flush(&mut working, &mut authority, &operation("op-flush"));
    assert_eq!(
        (
            flush.written,
            flush.remaining,
            flush.overflow_recorded,
            flush.refusal
        ),
        (1, 0, Some(1), None)
    );
    assert_eq!(deferred.overflowed(), 0);
    let records = store.records.borrow();
    assert!(matches!(
        records[0].event().payload(),
        AuditEntry::Revocation { .. }
    ));
    match records[1].event().payload() {
        AuditEntry::HostFact { fields, .. } => {
            assert!(fields.get("records").is_some());
        }
        other => panic!("{other:?}"),
    }
    drop(records);

    // A journal that keeps the refused record takes it over from the queue.
    let (mut failing, mut authority, store, spool) =
        journal(&clock, 4, AuditFailurePolicy::DenyHighImpact);
    *store.refuse.borrow_mut() = Some(StoreRefusal::Slow);
    *spool.refuse.borrow_mut() = true;
    let mut deferred = DeferredAudit::new(2).unwrap();
    deferred.defer(revocation("exe-a", 2));
    let flush = deferred.flush(&mut failing, &mut authority, &operation("op-flush"));
    assert_eq!(flush.remaining, 0);
    assert!(matches!(
        flush.refusal,
        Some(AuditRefusal::FailClosed { kept: Some(_), .. })
    ));
}

#[test]
fn detection_signals_are_recorded_within_their_emission_bound() {
    let clock = Arc::new(clock());
    let (mut journal, mut authority, store, _) =
        journal(&clock, 4, AuditFailurePolicy::DenyHighImpact);
    let mut gate = EmissionGate::new(limit(2, SECOND));
    let mut recorded = 0;
    for step in 0..5u64 {
        let signal = host_violation("exe-a", ViolationKind::PerimeterRule, clock.now());
        match record_signal(
            &mut journal,
            &mut authority,
            &mut gate,
            &signal,
            operation("op-signal"),
            clock.as_ref(),
        ) {
            SignalAudit::Recorded(_) => recorded += 1,
            SignalAudit::HeldBack { held_back, .. } => assert_eq!(held_back, step - 1),
            SignalAudit::Refused(refusal) => panic!("{refusal:?}"),
        }
    }
    assert_eq!(recorded, 2);
    for record in store.records.borrow().iter() {
        assert!(matches!(
            record.event().payload(),
            AuditEntry::HostFact {
                fact: crate::foundation::events::HostFact::DetectionSignal,
                ..
            }
        ));
    }
}

// ---------------------------------------------------------------------------------------
// VM-P14 and VM-CP-14: five separate events and a target reported as a target

#[test]
fn the_timeline_keeps_five_separate_events_and_refuses_inference() {
    let mut world = World::new();
    let s = execution("exe-s");
    world.launch(&s);
    let mut plane = Plane::new(&world.clock, 4, AuditFailurePolicy::DenyHighImpact);
    let notice = plane.revoke(&mut world, &s).notice;
    let mut timeline = RevocationTimeline::begin(&notice, None);
    assert_eq!(timeline.execution(), &s);
    assert_eq!(
        timeline.record(RevocationEventKind::DurableEpochAdvance, world.clock.now()),
        Err(TimelineRefusal::DecisionIsFixed)
    );
    let earlier = at(START_SECONDS - 1);
    assert_eq!(
        timeline.record(RevocationEventKind::ChannelClosure, earlier),
        Err(TimelineRefusal::BeforeDecision {
            event: RevocationEventKind::ChannelClosure,
            at: earlier,
            decided_at: notice.at
        })
    );
    assert_eq!(
        timeline.record(RevocationEventKind::CleanupCompletion, world.clock.now()),
        Err(TimelineRefusal::CleanupBeforeStop)
    );
    // CORE-04's sockets-closed acknowledgment is not channel closure.
    world
        .coordinator
        .acknowledge_revocation(
            &s,
            RevocationMilestone::SocketsClosed,
            SourceClass::HostProbe,
        )
        .unwrap();
    assert!(timeline
        .observe_operation(world.coordinator.revocation(&s).unwrap())
        .unwrap()
        .is_empty());
    assert_eq!(timeline.source(RevocationEventKind::ChannelClosure), None);
    let first = world.clock.now();
    timeline
        .record(RevocationEventKind::FirstDeniedAuthorization, first)
        .unwrap();
    assert_eq!(
        timeline.source(RevocationEventKind::FirstDeniedAuthorization),
        Some(EventSource::Recorded)
    );
    world.clock.advance(SECOND);
    assert_eq!(
        timeline.record(
            RevocationEventKind::FirstDeniedAuthorization,
            world.clock.now()
        ),
        Err(TimelineRefusal::AlreadyRecorded {
            event: RevocationEventKind::FirstDeniedAuthorization,
            first
        })
    );
    let entries = timeline.entries();
    assert_eq!(entries.map(|entry| entry.event), RevocationEventKind::ALL);
    assert!(matches!(
        entries[0].status,
        TimelineStatus::Observed {
            after_decision_nanos: 0,
            ..
        }
    ));
    assert!(matches!(entries[1].status, TimelineStatus::Observed { .. }));
    for entry in &entries[2..] {
        assert_eq!(entry.status, TimelineStatus::NotObserved, "{entry:?}");
    }
    assert_eq!(timeline.vm_stop_within_target(), None);
    let json = serde_json::to_value(entries).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 5);
    assert_eq!(json[0]["status"]["source"]["source"], "notice");
    assert_eq!(json[1]["status"]["source"]["source"], "recorded");

    // All channels closed, acknowledged later, is taken as channel closure; the first
    // denial already recorded by hand stands.
    world.clock.advance(SECOND);
    world
        .coordinator
        .acknowledge_revocation(
            &s,
            RevocationMilestone::AllChannelsClosed,
            SourceClass::HostProbe,
        )
        .unwrap();
    assert_eq!(
        timeline
            .observe_operation(world.coordinator.revocation(&s).unwrap())
            .unwrap(),
        [RevocationEventKind::ChannelClosure]
    );
    assert_eq!(
        timeline.source(RevocationEventKind::FirstDeniedAuthorization),
        Some(EventSource::Recorded)
    );
    let restored: [TimelineEntry; 5] =
        serde_json::from_value(serde_json::to_value(timeline.entries()).unwrap()).unwrap();
    assert_eq!(restored, timeline.entries());

    // Another sandbox's revocation never feeds this timeline.
    let other = execution("exe-other");
    world.launch(&other);
    plane.revoke(&mut world, &other);
    assert_eq!(
        timeline.observe_operation(world.coordinator.revocation(&other).unwrap()),
        Err(TimelineRefusal::OtherRevocation)
    );

    // All five at one instant stay five events; a stop within 2 s met the target this run.
    let mut world = World::new();
    let a = execution("exe-a");
    world.launch(&a);
    let mut plane = Plane::new(&world.clock, 4, AuditFailurePolicy::DenyHighImpact);
    let mut responder = responder_for(&world, &[("exe-a", SandboxClass::Task)]);
    let record = responded(
        responder
            .respond_to(&fresh_host_assessment(
                "exe-a",
                ViolationKind::PerimeterRule,
                &world.clock,
            ))
            .unwrap(),
    );
    let executed = plane.execute(&mut world, record.observed().unwrap());
    let mut timeline =
        RevocationTimeline::begin(&executed.revocation.unwrap().notice, Some(record.id));
    timeline
        .record(
            RevocationEventKind::FirstDeniedAuthorization,
            world.clock.now(),
        )
        .unwrap();
    timeline
        .record(RevocationEventKind::ChannelClosure, world.clock.now())
        .unwrap();
    timeline
        .observe_operation(world.coordinator.revocation(&a).unwrap())
        .unwrap();
    assert!(timeline
        .entries()
        .iter()
        .all(|entry| matches!(entry.status, TimelineStatus::Observed { .. })));
    assert_eq!(timeline.decision(), Some(record.id));
    assert_eq!(timeline.vm_stop_within_target(), Some(true));
}

#[test]
fn the_stop_figure_is_an_engineering_target_never_a_guarantee() {
    assert_eq!(VM_STOP_TARGET.within_seconds, 2);
    assert_eq!(VM_STOP_TARGET.event, RevocationEventKind::VmStop);
    assert_eq!(VM_STOP_TARGET.label, TargetLabel::EngineeringTarget);
    let json = serde_json::to_value(VM_STOP_TARGET).unwrap();
    assert_eq!(json["label"], serde_json::json!("engineering_target"));
    assert_eq!(
        serde_json::from_value::<VmStopTarget>(json.clone()).unwrap(),
        VM_STOP_TARGET
    );
    assert!(serde_json::from_value::<TargetLabel>(serde_json::json!("guarantee")).is_err());
    let mut claimed = json;
    claimed["guaranteed"] = serde_json::json!(true);
    assert!(serde_json::from_value::<VmStopTarget>(claimed).is_err());
}

// ---------------------------------------------------------------------------------------
// A canary hit is a signal, never proof (§8.2 line 2274; V09)

fn binding(name: &str) -> SandboxBinding {
    SandboxBinding {
        sandbox: SandboxRef {
            issuer: IssuerId::new(digest("yougori/test/issuer/v1", &[b"host-1"])),
            execution: execution(name),
        },
        instance: VmInstanceId::new(digest("yougori/test/instance/v1", &[name.as_bytes()])),
        boot: SandboxBootGeneration::new(1),
    }
}

#[test]
fn a_canary_hit_is_one_signal_and_never_proof() {
    let now = clock();
    let planted = binding("exe-a");
    let mut registry = CanaryRegistry::new(&CanarySeed::from_bytes([7; 32]), HoneyportPool::none());
    let plan = registry
        .plan(PlantingRequest {
            binding: planted.clone(),
            origin: PlantOrigin::FreshBoot,
            placements: vec![PlacementRequest {
                kind: CanaryKind::FakeCredential,
                location: PlacementLocation::home(".config/legacy-deploy/token").unwrap(),
            }],
        })
        .unwrap();
    let value = plan.instructions()[0]
        .value()
        .expose_for_planting()
        .to_owned();
    let bytes = format!("POST /deploy\r\nAuthorization: Bearer {value}\r\n").into_bytes();
    let observation = canaries::Observation::host_observed(
        planted.clone(),
        now.now(),
        ObservedContent::OutboundBytes(bytes.clone()),
    )
    .unwrap();
    let report = registry.match_observation(&observation, &now);
    assert_eq!(report.hits.len(), 1);
    let hit = &report.hits[0];
    assert_eq!(hit.meaning(), HitMeaning::SignalNotProof);
    assert!(matches!(
        hit.audit_draft(),
        crate::foundation::events::AuditDraft::HostFact {
            fact: crate::foundation::events::HostFact::DetectionSignal,
            ..
        }
    ));

    let signal = MonitoringSignal::from_canary_hit(hit, host_session());
    assert_eq!(signal.class(), violation(ViolationKind::CanaryUse));
    assert_eq!(signal.source(), host(HostObserver::Perimeter));
    assert_eq!(signal.subject(), hit.canary().digest());
    assert_eq!(signal.sandbox(), &execution("exe-a"));
    let mut responder = Responder::new(&now, policies(), bounds());
    responder
        .register_sandbox(execution("exe-a"), SandboxClass::Task, BTreeSet::new())
        .unwrap();
    let assessment = assess_violation(&[signal], &uncertain(), &now, host_session()).unwrap();
    let record = responded(responder.respond(&assessment).unwrap());
    assert!(!record.decision.actions.contains(&ResponseAction::Stop));
    assert!(record.decision.actions.contains(&ResponseAction::Revoke));
    assert_eq!(
        record.decision.reason,
        DecisionReason::KnownViolation {
            kind: ViolationKind::CanaryUse,
            observer: HostObserver::Perimeter,
            meaning: Some(HitMeaning::SignalNotProof)
        }
    );

    // The same canary reported by the guest stays a guest report.
    let reported =
        canaries::Observation::guest_reported(planted, ObservedContent::OutboundBytes(bytes))
            .unwrap();
    let report = registry.match_observation(&reported, &now);
    let guest = MonitoringSignal::from_canary_hit(&report.hits[0], host_session());
    assert_eq!(guest.source(), SignalSource::GuestReported);
    assert_eq!(guest.observed_at(), now.now());
    let decision = decide(
        &policies(),
        &DecisionInput {
            class: guest.class(),
            source: guest.source(),
            freshness: guest.freshness(now.now(), host_session(), 30 * SECOND),
            sandbox_class: SandboxClass::Service,
        },
    );
    assert_eq!(
        decision.actions,
        [
            ResponseAction::NotifyUser,
            ResponseAction::RequestHostCorroboration
        ]
        .into()
    );
}

// ---------------------------------------------------------------------------------------
// VM-W43 reach: a bystander loses the violated grant through CORE-04, nothing else

#[test]
fn a_bystander_loses_only_the_violated_grant_through_core_04() {
    let mut world = World::new();
    let a = execution("exe-a");
    let b = execution("exe-b");
    world.launch(&a);
    world.launch(&b);
    let shared = grant("deploy-credential");
    let other = grant("registry-route");
    let shared_lease = world
        .coordinator
        .start_granted_work(
            &b,
            operation("op-deploy"),
            LeaseKind::ChildWork,
            terms(),
            BTreeSet::from([shared]),
        )
        .unwrap();
    let other_lease = world
        .coordinator
        .start_granted_work(
            &b,
            operation("op-pull"),
            LeaseKind::ChildWork,
            terms(),
            BTreeSet::from([other]),
        )
        .unwrap();
    let epoch_before = world.epoch(&b);
    let mut plane = Plane::new(&world.clock, 4, AuditFailurePolicy::DenyHighImpact);
    let mut responder = Responder::new(Arc::clone(&world.clock), policies(), bounds());
    responder
        .register_sandbox(a.clone(), SandboxClass::Task, BTreeSet::from([shared]))
        .unwrap();
    responder
        .register_sandbox(
            b.clone(),
            SandboxClass::Service,
            BTreeSet::from([shared, other]),
        )
        .unwrap();
    let record = responded(
        responder
            .respond_to(&fresh_host_assessment_with_grant(
                "exe-a",
                ViolationKind::CredentialReplay,
                shared,
                &world.clock,
            ))
            .unwrap(),
    );
    assert_eq!(record.targets.len(), 2);

    // The violator gets its whole policy-defined response.
    let violator = plane.execute(&mut world, &record.targets[0]);
    assert!(violator.revocation.is_some());
    assert!(violator.grant_revocation.is_none());
    assert!(!world.has_authority(&a));

    // The bystander loses the grant: a tombstone, its epoch unchanged.
    let bystander = plane.execute(&mut world, &record.targets[1]);
    assert!(bystander.revocation.is_none());
    assert_eq!(bystander.class_response, None);
    let receipt = bystander.grant_revocation.unwrap();
    assert_eq!(receipt.revoked.execution, b);
    assert_eq!(receipt.revoked.grant, shared);
    assert_eq!(receipt.revoked.epoch, epoch_before);
    assert!(matches!(receipt.audit, RevocationAudit::Written { .. }));
    assert!(receipt.lane.is_ok());
    assert_eq!(receipt.high_impact, HighImpactGate::Admitted);
    let cancelled: Vec<_> = receipt
        .revoked
        .cancellations
        .iter()
        .map(|cancellation| cancellation.lease)
        .collect();
    assert_eq!(cancelled, [shared_lease.id()]);
    assert_eq!(
        receipt.leases_bounded_until,
        receipt
            .revoked
            .cancellations
            .first()
            .map(|cancellation| cancellation.bound_at)
    );
    assert_eq!(world.epoch(&b), epoch_before);
    assert!(world.coordinator.grant_revoked(&b, shared));
    assert!(!world.coordinator.grant_revoked(&b, other));
    assert!(world.coordinator.check_lease(other_lease.id()).is_ok());
    assert!(
        world.has_authority(&b),
        "the bystander keeps its other authority"
    );
    assert!(world
        .coordinator
        .start_granted_work(
            &b,
            operation("op-deploy-again"),
            LeaseKind::ChildWork,
            terms(),
            BTreeSet::from([shared]),
        )
        .is_err());
    assert_eq!(
        plane.store.revocations(),
        1,
        "one whole revocation, the violator's"
    );
    let grant_records = plane
        .store
        .records
        .borrow()
        .iter()
        .filter(|record| {
            matches!(
                record.event().payload(),
                AuditEntry::GrantRevocation { revocation } if revocation.grant == shared
            )
        })
        .count();
    assert_eq!(grant_records, 1);
}

#[test]
fn a_grant_revocation_that_names_no_grant_revokes_the_whole_sandbox() {
    let mut world = World::new();
    let a = execution("exe-a");
    world.launch(&a);
    let epoch_before = world.epoch(&a);
    let mut plane = Plane::new(&world.clock, 4, AuditFailurePolicy::DenyHighImpact);
    let mut responder = responder_for(&world, &[("exe-a", SandboxClass::Task)]);
    let record = responded(
        responder
            .respond_to(&fresh_host_assessment(
                "exe-a",
                ViolationKind::PerimeterRule,
                &world.clock,
            ))
            .unwrap(),
    );
    // A target built by hand that asks for a grant revocation without naming a grant.
    let mut target = record.observed().unwrap().clone();
    target.actions = BTreeSet::from([ResponseAction::RevokeGrant]);
    target.new_actions = target.actions.clone();
    let executed = plane.execute(&mut world, &target);
    assert!(executed.grant_revocation.is_none());
    let receipt = executed.revocation.unwrap();
    assert!(receipt.notice.current > epoch_before, "it fails closed");
    assert!(!world.has_authority(&a));
}

#[test]
fn deferred_grant_records_are_kept_once_and_written_as_grant_revocations() {
    let grant_record = |name: &str, held: &str| GrantRevocation {
        execution: execution(name),
        grant: grant(held),
        epoch: AuthorizationEpoch::new(1),
        reason: RevocationReason::SecurityEvent,
    };
    let mut deferred = DeferredAudit::new(3).unwrap();
    assert_eq!(
        deferred.defer_grant(grant_record("exe-b", "g1")),
        Deferral::Queued
    );
    assert_eq!(
        deferred.defer_grant(grant_record("exe-b", "g1")),
        Deferral::AlreadyCovered
    );
    assert_eq!(
        deferred.defer_grant(grant_record("exe-b", "g2")),
        Deferral::Queued
    );
    // A whole revocation of the same sandbox is its own record.
    assert_eq!(
        deferred.defer(Revocation {
            execution: execution("exe-b"),
            epoch: AuthorizationEpoch::new(2),
            reason: RevocationReason::SecurityEvent,
        }),
        Deferral::Queued
    );
    assert_eq!(
        deferred.defer_grant(grant_record("exe-c", "g1")),
        Deferral::Overflowed
    );
    assert!(matches!(
        deferred.pending().next(),
        Some(DeferredRecord::Grant(record)) if record.grant == grant("g1")
    ));

    let clock = Arc::new(clock());
    let (mut working, mut authority, store, _) =
        journal(&clock, 4, AuditFailurePolicy::DenyHighImpact);
    let flush = deferred.flush(&mut working, &mut authority, &operation("op-flush"));
    assert_eq!(
        (flush.written, flush.remaining, flush.overflow_recorded),
        (3, 0, Some(1))
    );
    let records = store.records.borrow();
    let kinds: Vec<&str> = records
        .iter()
        .map(|record| match record.event().payload() {
            AuditEntry::GrantRevocation { .. } => "grant",
            AuditEntry::Revocation { .. } => "revocation",
            AuditEntry::HostFact { .. } => "overflow",
            _ => "other",
        })
        .collect();
    assert_eq!(kinds, ["grant", "grant", "revocation", "overflow"]);
}

// ---------------------------------------------------------------------------------------
// Emergency revocations on the coordinator's durable revocation stream (S06; §8.2 audit
// failure policy; VM-W43)

/// Releases `plane`'s durable revocation stream as a stopping engine does, and takes it
/// again on the same directory as the next run does.
fn restart_log(plane: Plane) -> (RevocationLog, tempfile::TempDir) {
    let Plane { log, directory, .. } = plane;
    log.close().unwrap();
    let (log, report) =
        open_revocation_log(directory.path(), REVOCATIONS_OWNER, revocation_log_config());
    assert!(matches!(report.takeover, Takeover::Released { .. }));
    (log, directory)
}

/// A stream whose segments cannot hold one record: storage refuses every record.
fn too_small() -> LogConfig {
    LogConfig {
        segment_bytes: 64,
        ..revocation_log_config()
    }
}

/// A violator and a bystander that share `shared`, with a response to the violator's
/// credential replay that reaches the bystander.
fn shared_grant_response(world: &mut World, shared: GrantRef) -> ResponseRecord {
    let (a, b) = (execution("exe-a"), execution("exe-b"));
    world.launch(&a);
    world.launch(&b);
    let mut responder = Responder::new(Arc::clone(&world.clock), policies(), bounds());
    responder
        .register_sandbox(a, SandboxClass::Task, BTreeSet::from([shared]))
        .unwrap();
    responder
        .register_sandbox(b, SandboxClass::Service, BTreeSet::from([shared]))
        .unwrap();
    let record = responded(
        responder
            .respond_to(&fresh_host_assessment_with_grant(
                "exe-a",
                ViolationKind::CredentialReplay,
                shared,
                &world.clock,
            ))
            .unwrap(),
    );
    assert_eq!(record.targets.len(), 2);
    record
}

/// The restart of S06 for an emergency revocation: the revocation is on the durable stream,
/// read back under its operation, and after a restart before the next persisted state the
/// replay from the stored cursor ends the sandbox the recovered state would have kept.
#[test]
fn an_emergency_revocation_is_on_the_durable_stream_and_a_restart_still_ends_the_sandbox() {
    let mut world = World::new();
    let a = execution("exe-a");
    world.launch(&a);
    let mut plane = Plane::new(&world.clock, 4, AuditFailurePolicy::DenyHighImpact);
    // The state is persisted, with the stream's cursor, before the revocation.
    let mut persisted = world.coordinator.persist();
    world.coordinator.confirm_persisted(&persisted);
    let stored = plane.log.log().end();

    let receipt = plane.revoke(&mut world, &a);
    assert_eq!(receipt.recorded, Ok(EventSequence::FIRST));
    assert_eq!(receipt.lane, Ok(RevocationAdmission::Queued));
    assert_eq!(
        receipt.audit,
        RevocationAudit::Written {
            durability: Durability::Durable
        }
    );
    assert_eq!(receipt.high_impact, HighImpactGate::Admitted);
    assert_eq!(plane.deferred.unrecorded_len(), 0);
    assert!(!world.has_authority(&a));

    // Read back: one record under the operation, the lane's revocation with the epoch now
    // in force.
    let correlated = plane
        .log
        .log()
        .correlate(&operation("op-emergency"))
        .unwrap();
    assert_eq!(correlated.records.len(), 1);
    let (sequence, record) = &correlated.records[0];
    assert_eq!(*sequence, EventSequence::FIRST);
    let RevocationRecord::Execution(envelope) = record else {
        panic!("{record:?}");
    };
    let delivery = plane.hub.drain(8);
    assert_eq!(delivery.revocations.notices.len(), 1);
    assert_eq!(
        envelope.payload(),
        delivery.revocations.notices[0].payload()
    );
    assert_eq!(
        envelope.payload(),
        &Revocation {
            execution: a.clone(),
            epoch: receipt.notice.current,
            reason: RevocationReason::SecurityEvent,
        }
    );
    assert_eq!(
        envelope.generations().authorization,
        Some(receipt.notice.current)
    );
    assert_eq!(envelope.phase(), Phase::Revoked);

    // The engine stops before it persists again. The next run replays the stream from the
    // stored cursor: the persisted state predates the revocation.
    let (log, _directory) = restart_log(plane);
    let replay = log.replay(&stored).unwrap();
    assert_eq!(replay.records, 1);
    assert!(replay.is_complete());
    let rebuilt = persisted.adopt_revocations(&replay);
    assert_eq!(rebuilt.unpersisted.keys().collect::<Vec<_>>(), [&a]);
    assert_eq!(
        rebuilt.unpersisted[&a].payload().epoch,
        receipt.notice.current
    );

    // Recovery keeps the live VM without authority; the revocation on the stream ends it.
    let (mut coordinator, report) = crate::foundation::coordination::Coordinator::recover(
        persisted,
        Arc::clone(&world.clock),
        session(3),
        GrantAll,
        &mut world.port,
    )
    .unwrap();
    assert!(matches!(
        report.sandboxes.get(&a),
        Some(SandboxRecovery::VmKeptWithoutAuthority { .. })
    ));
    let completed = coordinator.complete_revocations(&rebuilt, &mut world.port);
    assert!(matches!(completed.get(&a), Some(Ok(_))), "{completed:?}");
    assert_eq!(
        coordinator.sandbox(&a).unwrap().state(),
        SandboxState::Stopped
    );
    assert_eq!(world.port.terminated.len(), 1);
}

/// The restart of S06 for a shared grant: the bystander's tombstone is on the durable
/// stream beside the violator's revocation, and a restart before the next persisted state
/// restores the tombstone the state lacks.
#[test]
fn a_shared_grant_revocation_is_on_the_durable_stream_and_its_tombstone_survives_a_restart() {
    let mut world = World::new();
    let shared = grant("deploy-credential");
    let record = shared_grant_response(&mut world, shared);
    let (a, b) = (execution("exe-a"), execution("exe-b"));
    let mut plane = Plane::new(&world.clock, 4, AuditFailurePolicy::DenyHighImpact);
    let mut persisted = world.coordinator.persist();
    world.coordinator.confirm_persisted(&persisted);
    let stored = plane.log.log().end();

    let violator = plane.execute(&mut world, &record.targets[0]);
    let bystander = plane.execute(&mut world, &record.targets[1]);
    assert_eq!(
        violator.revocation.unwrap().recorded,
        Ok(EventSequence::FIRST)
    );
    let receipt = bystander.grant_revocation.unwrap();
    assert_eq!(receipt.recorded, Ok(EventSequence::new(2).unwrap()));
    assert_eq!(receipt.high_impact, HighImpactGate::Admitted);
    assert!(world.coordinator.grant_revoked(&b, shared));

    // Read back: the tombstone, at the epoch the bystander keeps, and the violator's
    // revocation, both under the response's operation.
    let replay = plane.log.replay(&plane.log.log().start()).unwrap();
    assert_eq!(
        replay.tombstones(),
        BTreeMap::from([(b.clone(), BTreeSet::from([shared]))])
    );
    let tombstone = &replay.grants[&b][&shared];
    assert_eq!(tombstone.payload().epoch, receipt.revoked.epoch);
    assert_eq!(tombstone.payload().epoch, world.epoch(&b));
    assert_eq!(tombstone.operation(), &operation("op-response"));
    assert_eq!(replay.executions.keys().collect::<Vec<_>>(), [&a]);

    // A restart before the next persisted state: the state lacks the tombstone, and the
    // replay from the stored cursor restores it.
    let (log, _directory) = restart_log(plane);
    let replay = log.replay(&stored).unwrap();
    assert_eq!(persisted.revoked_grants.get(&b), None);
    let rebuilt = persisted.adopt_revocations(&replay);
    assert_eq!(
        rebuilt.tombstones_restored,
        BTreeMap::from([(b.clone(), BTreeSet::from([shared]))])
    );
    assert_eq!(
        persisted.revoked_grants.get(&b),
        Some(&BTreeSet::from([shared]))
    );
    // The bystander's epoch never advanced, so only the violator's sandbox is to end.
    assert_eq!(rebuilt.unpersisted.keys().collect::<Vec<_>>(), [&a]);
}

/// A stream owned under the lane issuer's own name refuses the record. The revocation is
/// in force, on the lane and in audit all the same; the receipt names the refusal, and new
/// high-impact operations are denied until the revocation is on a stream of its own owner.
#[test]
fn a_refused_durable_record_never_undoes_a_revocation_and_denies_high_impact_until_recorded() {
    let mut world = World::new();
    let (a, b) = (execution("exe-a"), execution("exe-b"));
    world.launch(&a);
    world.launch(&b);
    let mut plane = Plane::with_log(
        &world.clock,
        4,
        AuditFailurePolicy::DenyHighImpact,
        ISSUER,
        revocation_log_config(),
    );
    let refusal = RecordError::SharedProducer {
        producer: ProducerId::new(ISSUER).unwrap(),
    };

    let first = plane.revoke(&mut world, &a);
    assert_eq!(first.recorded, Err(refusal.clone()));
    assert_eq!(plane.log.log().last(), None);
    // Never undone, never delayed: CORE-04 holds it, the lane carried it, audit wrote it.
    assert!(!world.has_authority(&a));
    assert!(first.notice.current > first.notice.revoked);
    assert_eq!(first.lane, Ok(RevocationAdmission::Queued));
    assert_eq!(
        first.audit,
        RevocationAudit::Written {
            durability: Durability::Durable
        }
    );
    assert_eq!(plane.store.revocations(), 1);
    // Never silent: it waits to be recorded, and new high-impact operations are denied.
    assert_eq!(
        first.high_impact,
        HighImpactGate::Denied {
            reason: HighImpactDenial::RevocationsNotDurable { unrecorded: 1 }
        }
    );
    assert!(!first.high_impact.admits());
    assert!(plane.deferred.is_empty(), "no audit record waits");
    assert_eq!(
        plane.deferred.unrecorded().cloned().collect::<Vec<_>>(),
        [UnrecordedRevocation {
            record: DeferredRecord::Revocation(Revocation {
                execution: a.clone(),
                epoch: first.notice.current,
                reason: RevocationReason::SecurityEvent,
            }),
            operation: operation("op-emergency"),
            at: first.notice.at,
            refusal: refusal.clone(),
        }]
    );

    // The same revocation again waits once; another sandbox's waits beside it.
    let again = plane.revoke(&mut world, &a);
    assert_eq!(again.notice.current, first.notice.current);
    assert_eq!(plane.deferred.unrecorded_len(), 1);
    let second = plane.revoke(&mut world, &b);
    assert_eq!(second.recorded, Err(refusal.clone()));
    assert_eq!(
        second.high_impact,
        HighImpactGate::Denied {
            reason: HighImpactDenial::RevocationsNotDurable { unrecorded: 2 }
        }
    );

    // A retry on the same stream is refused the same way and records nothing.
    let retry = plane
        .deferred
        .record_unrecorded(&mut plane.log, &plane.issuer);
    assert_eq!(
        retry,
        UnrecordedRetry {
            recorded: Vec::new(),
            remaining: 2,
            refusal: Some(refusal),
        }
    );
    assert_eq!(plane.log.log().last(), None);

    // A stream of its own owner takes both, oldest first, each under the operation, time
    // and epoch it was published with; then the gate admits again.
    let directory = tempfile::tempdir().unwrap();
    let (mut own, _) =
        open_revocation_log(directory.path(), REVOCATIONS_OWNER, revocation_log_config());
    let retry = plane.deferred.record_unrecorded(&mut own, &plane.issuer);
    assert_eq!(
        retry,
        UnrecordedRetry {
            recorded: vec![EventSequence::FIRST, EventSequence::new(2).unwrap()],
            remaining: 0,
            refusal: None,
        }
    );
    assert_eq!(plane.deferred.unrecorded_len(), 0);
    assert_eq!(
        HighImpactGate::judge(plane.journal.health(), &plane.deferred),
        HighImpactGate::Admitted
    );
    let replay = own.replay(&own.log().start()).unwrap();
    assert_eq!(replay.records, 2);
    let kept = &replay.executions[&a];
    assert_eq!(kept.payload().epoch, first.notice.current);
    assert_eq!(kept.operation(), &operation("op-emergency"));
    assert_eq!(kept.emitted_at(), first.notice.at);
    assert_eq!(kept.generations().authorization, Some(first.notice.current));
    assert_eq!(kept.phase(), Phase::Revoked);
    assert_eq!(replay.executions[&b].payload().epoch, second.notice.current);
}

/// Storage that cannot take a record refuses the bystander's tombstone and the violator's
/// revocation. Both hold in CORE-04 all the same, the bystander keeps its other authority,
/// and both are recorded once the stream, taken again, has room.
#[test]
fn a_full_durable_stream_refuses_the_records_and_the_grant_stays_revoked() {
    let mut world = World::new();
    let shared = grant("deploy-credential");
    let record = shared_grant_response(&mut world, shared);
    let (a, b) = (execution("exe-a"), execution("exe-b"));
    let mut plane = Plane::with_log(
        &world.clock,
        4,
        AuditFailurePolicy::DenyHighImpact,
        REVOCATIONS_OWNER,
        too_small(),
    );

    let violator = plane.execute(&mut world, &record.targets[0]);
    let bystander = plane.execute(&mut world, &record.targets[1]);
    let revoked = violator.revocation.unwrap();
    assert!(matches!(
        revoked.recorded,
        Err(RecordError::Log(LogError::TooLarge { limit: 64, .. }))
    ));
    let receipt = bystander.grant_revocation.unwrap();
    assert!(
        matches!(
            receipt.recorded,
            Err(RecordError::Log(LogError::TooLarge { limit: 64, .. }))
        ),
        "{:?}",
        receipt.recorded
    );
    assert_eq!(plane.log.log().last(), None);
    // In force all the same: the tombstone holds, the bystander keeps its epoch and its
    // other authority, the violator has none; the lane and audit took both.
    assert!(world.coordinator.grant_revoked(&b, shared));
    assert_eq!(world.epoch(&b), receipt.revoked.epoch);
    assert!(world.has_authority(&b));
    assert!(!world.has_authority(&a));
    assert!(receipt.lane.is_ok());
    assert!(matches!(receipt.audit, RevocationAudit::Written { .. }));
    assert_eq!(
        receipt.high_impact,
        HighImpactGate::Denied {
            reason: HighImpactDenial::RevocationsNotDurable { unrecorded: 2 }
        }
    );
    let waiting: Vec<_> = plane
        .deferred
        .unrecorded()
        .map(|waiting| &waiting.record)
        .cloned()
        .collect();
    assert!(matches!(
        waiting.as_slice(),
        [DeferredRecord::Revocation(revocation), DeferredRecord::Grant(tombstone)]
            if revocation.execution == a && tombstone.execution == b && tombstone.grant == shared
    ));

    // The stream is taken again with segments that hold a record, and the waiting
    // revocations are recorded on it.
    let Plane {
        log,
        directory,
        mut deferred,
        issuer,
        journal,
        ..
    } = plane;
    log.close().unwrap();
    let (mut log, _) =
        open_revocation_log(directory.path(), REVOCATIONS_OWNER, revocation_log_config());
    let retry = deferred.record_unrecorded(&mut log, &issuer);
    assert_eq!(
        (retry.recorded.len(), retry.remaining, retry.refusal),
        (2, 0, None)
    );
    assert_eq!(
        HighImpactGate::judge(journal.health(), &deferred),
        HighImpactGate::Admitted
    );
    let replay = log.replay(&log.log().start()).unwrap();
    assert_eq!(
        replay.tombstones(),
        BTreeMap::from([(b.clone(), BTreeSet::from([shared]))])
    );
    assert_eq!(
        replay.grants[&b][&shared].operation(),
        &operation("op-response")
    );
    assert_eq!(
        replay.executions[&a].payload().epoch,
        revoked.notice.current
    );
}
