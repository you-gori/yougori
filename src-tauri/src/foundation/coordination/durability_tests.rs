//! Scenario tests of durable lifecycle authority on fakes (docs/combined-plan-remaining-only.md
//! §8, S04 / M13 / M17; VM part §6.2–§6.4; VM-W29, VM-W26): scoped identities, stale
//! watchers, a restored older state against the durable floor and the revocation stream,
//! retirement as tombstone compaction, a reused PID, partitions and clock rollback, partial
//! cleanup with a failed supervisor, and revocation through its reserved slot under
//! overload. Time comes from a clock the tests set, backward included.

use std::collections::BTreeSet;
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::fakes::{FakeLedger, FakeSandbox};
use super::*;
use crate::foundation::events::{
    DurableStreamId, EventContext, EventSequence, Generations, GrantRevocation, LogConfig, Phase,
    ProducerId, RevocationLog, RevocationReason,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    AdmittedRuntime, ArtifactVerification, AuthorityGrant, Backend, BackendRelease, Capability,
    ClockSession, ConfigurationFingerprint, NetworkGrant, Observation, ProbeRegistry, Residency,
    RuntimeOffer, RuntimeRequirement, RuntimeSettings, RuntimeSubject, SourceClass, Subject,
    SupportDetail,
};
use crate::foundation::ids::{
    digest, Clock, Digest, ExecutionCategory, ExecutionId, GpuDeviceKey, Incarnation,
    MonotonicTime, OperationId, SandboxBootGeneration, TenantId,
};

const SECOND: Duration = Duration::from_secs(1);
const HOUR: Duration = Duration::from_secs(3600);
const GIB: u64 = 1 << 30;

/// A clock a test can set anywhere, backward included.
#[derive(Debug, Default)]
struct SettableClock(AtomicU64);

impl SettableClock {
    fn set(&self, to: MonotonicTime) {
        self.0.store(to.as_nanos(), Ordering::SeqCst);
    }

    fn advance(&self, by: Duration) {
        let by = u64::try_from(by.as_nanos()).unwrap();
        self.0.fetch_add(by, Ordering::SeqCst);
    }
}

impl Clock for SettableClock {
    fn now(&self) -> MonotonicTime {
        MonotonicTime::from_nanos(self.0.load(Ordering::SeqCst))
    }
}

type TestClock = Arc<SettableClock>;
type TestCoordinator = Coordinator<TestClock, FakeLedger>;

fn at(seconds: u64) -> MonotonicTime {
    MonotonicTime::from_nanos(seconds * 1_000_000_000)
}

fn session(number: u128) -> ClockSession {
    ClockSession::from_uuid(uuid::Uuid::from_u128(number))
}

fn named(domain: &str, name: &str) -> Digest {
    digest(domain, &[name.as_bytes()])
}

fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

fn operation(name: &str) -> OperationId {
    OperationId::new(name).unwrap()
}

fn tenant() -> TenantId {
    TenantId::new("tenant-a").unwrap()
}

fn grant_id(name: &str) -> GrantId {
    GrantId::from_digest(named("yougori/test/grant/v1", name))
}

/// The coordination authority under test: issuer `coordinator` on host `host-a`.
fn issuer() -> AuthorityIssuer {
    AuthorityIssuer {
        host: HostId::named("host-a"),
        issuer: IssuerId::named("coordinator"),
    }
}

fn configuration() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_digest(named("yougori/test/configuration/v1", "launch"))
}

fn device() -> GpuDeviceKey {
    GpuDeviceKey {
        machine: named("yougori/test/machine/v1", "host"),
        device: named("yougori/test/device/v1", "gpu0"),
    }
}

fn vm_runtime() -> RuntimeSubject {
    RuntimeSubject {
        category: ExecutionCategory::VmSandbox,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance: named("yougori/test/instance/v1", "vm-host-1"),
    }
}

fn route(name: &str) -> NetworkGrant {
    NetworkGrant::NamedRoute {
        route: named("yougori/test/route/v1", name),
    }
}

fn artifact() -> Digest {
    named("yougori/test/artifact/v1", "weights")
}

fn settings_grant() -> SettingsGrant {
    SettingsGrant {
        network: BTreeSet::from([route("model-download")]),
        verified_artifacts: BTreeSet::from([artifact()]),
    }
}

fn model_settings(grant: AuthorityGrant) -> RuntimeSettings {
    RuntimeSettings {
        execution_category: ExecutionCategory::VmSandbox,
        network: BTreeSet::from([route("model-download")]),
        authority: grant,
        artifact_verification: ArtifactVerification::Verified {
            artifacts: BTreeSet::from([artifact()]),
        },
        loader: BTreeSet::new(),
        batch_size: NonZeroU32::new(8).unwrap(),
        residency: Residency::Device,
    }
}

fn demand() -> std::collections::BTreeMap<ResourceKind, u64> {
    std::collections::BTreeMap::from([
        (ResourceKind::HostMemoryBytes, 16 * GIB),
        (ResourceKind::GpuMemoryBytes { device: device() }, 24 * GIB),
        (ResourceKind::CpuInitializationSlots, 4),
    ])
}

fn host_ledger() -> FakeLedger {
    FakeLedger::new([
        (ResourceKind::HostMemoryBytes, 64 * GIB),
        (ResourceKind::GpuMemoryBytes { device: device() }, 48 * GIB),
        (ResourceKind::CpuInitializationSlots, 16),
    ])
}

fn terms(term_seconds: u64) -> LeaseTerms {
    LeaseTerms {
        term: Duration::from_secs(term_seconds),
        max_lifetime: Duration::from_secs(term_seconds * 2),
        cancel_within: 5 * SECOND,
    }
}

fn sandbox_key(of: &ExecutionId, boot: u64) -> ReservationKey {
    ReservationKey::derive(
        of,
        &ReservationPurpose::Sandbox {
            boot: SandboxBootGeneration::new(boot),
        },
    )
}

fn replay_config() -> ReplayConfig {
    ReplayConfig {
        window: 64,
        persist_margin: 16,
        max_scopes: 8,
    }
}

fn registration(
    watcher: WatcherId,
    of: &ExecutionId,
    holder: WatcherHolder,
    staleness_seconds: u64,
) -> WatcherRegistration {
    WatcherRegistration {
        watcher,
        execution: of.clone(),
        holder,
        max_staleness: Duration::from_secs(staleness_seconds),
    }
}

fn open_log(directory: &Path) -> RevocationLog {
    RevocationLog::open(
        directory,
        DurableStreamId::new("coordinator.revocations").unwrap(),
        ProducerId::new("coordinator.revocations").unwrap(),
        LogConfig {
            max_entries: 16,
            max_bytes: 1 << 20,
            segment_entries: 8,
            segment_bytes: 1 << 16,
        },
    )
    .unwrap()
    .0
}

/// One host: its evidence registry, ledger and VM backend, and the coordinator over them.
struct World {
    clock: TestClock,
    registry: ProbeRegistry<TestClock>,
    category: Arc<FakeProbe>,
    ledger: FakeLedger,
    port: FakeSandbox,
    coordinator: TestCoordinator,
    execution: ExecutionId,
    model: ModelId,
}

impl World {
    fn new() -> Self {
        Self::with_ledger(host_ledger())
    }

    fn with_ledger(ledger: FakeLedger) -> Self {
        let clock = Arc::new(SettableClock::default());
        clock.set(at(100));
        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
        let category = Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe));
        registry.register(Box::new(Arc::clone(&category))).unwrap();
        let coordinator = Coordinator::new(Arc::clone(&clock), session(1), ledger.clone());
        Self {
            clock,
            registry,
            category,
            ledger,
            port: FakeSandbox::new(),
            coordinator,
            execution: execution("exe-sandbox"),
            model: ModelId::new(named("yougori/test/model/v1", "chat-model")),
        }
    }

    fn advance(&self, seconds: u64) {
        self.clock.advance(Duration::from_secs(seconds));
    }

    /// The runtime admitted on host evidence observed now.
    fn admit(&mut self) -> AdmittedRuntime {
        let runtime = vm_runtime();
        let subject = Subject::Runtime(runtime.clone());
        self.category.respond(
            &subject,
            Observation::supported(
                configuration(),
                HOUR,
                SupportDetail::RuntimeCategory {
                    category: runtime.category,
                },
            ),
        );
        self.registry
            .refresh(Capability::RuntimeCategory, &subject)
            .unwrap();
        let offer = RuntimeOffer::observe(&self.registry, runtime, HOUR, configuration()).unwrap();
        RuntimeRequirement::VmSandbox.admit(&offer).unwrap()
    }

    fn plan_for(&mut self, of: &ExecutionId) -> LaunchPlan {
        LaunchPlan {
            execution: of.clone(),
            tenant: tenant(),
            runtime: self.admit(),
            demand: demand(),
            priority: ReservationPriority::Background,
            authority_lifetime: 600 * SECOND,
            readiness_max_age: 5 * SECOND,
            runtime_evidence_max_age: HOUR,
        }
    }

    /// A launch of `of`; the error is boxed, being large.
    fn try_launch(&mut self, of: &ExecutionId) -> Result<LaunchOutcome, Box<CoordinationError>> {
        let plan = self.plan_for(of);
        self.coordinator
            .launch_with(plan, settings_grant(), &mut self.port, &self.registry)
            .map_err(Box::new)
    }

    fn launch(&mut self) -> AuthorityGrant {
        let of = self.execution.clone();
        match self.try_launch(&of).unwrap() {
            LaunchOutcome::AuthorityActive { grant, .. } => grant,
            other => panic!("{other:?}"),
        }
    }

    /// Stores the coordinator's state and confirms it, as the engine does.
    fn persist(&mut self) -> PersistedState {
        let state = self.coordinator.persist();
        self.coordinator.confirm_persisted(&state);
        state
    }

    fn activate(&mut self, grant: AuthorityGrant) -> GpuAllocationHandle {
        let handle = self
            .coordinator
            .begin_activation(
                &self.execution,
                self.model,
                model_settings(grant),
                GpuDemand {
                    device: device(),
                    memory_bytes: 10 * GIB,
                },
            )
            .unwrap();
        self.coordinator
            .complete_activation(&self.execution, self.model, handle.generations.activation)
            .unwrap();
        handle
    }

    fn child(&mut self, name: &str, term_seconds: u64) -> Lease {
        self.coordinator
            .start_child_work(
                &self.execution,
                operation(name),
                LeaseKind::ChildWork,
                terms(term_seconds),
            )
            .unwrap()
    }

    /// Revokes the sandbox and drives it to stopped; every lease acknowledges.
    fn stop(&mut self) {
        self.coordinator.revoke(&self.execution).unwrap();
        let leases: Vec<LeaseId> = self
            .coordinator
            .leases()
            .map(|record| record.lease().id())
            .collect();
        for lease in leases {
            let _ = self.coordinator.acknowledge_cancellation(lease);
        }
        let status = self
            .coordinator
            .advance_revocation(&self.execution, &mut self.port)
            .unwrap();
        assert!(
            matches!(status, RevocationStatus::Completed { .. }),
            "{status:?}"
        );
    }

    /// A cold relaunch; the error is boxed, being large.
    fn try_relaunch(&mut self) -> Result<RelaunchReport, Box<CoordinationError>> {
        let plan = RelaunchPlan {
            runtime: self.admit(),
            demand: demand(),
            authority_lifetime: 600 * SECOND,
            readiness_max_age: 5 * SECOND,
            runtime_evidence_max_age: HOUR,
            recovery: CompositeRecovery::default(),
            authorized_volumes: BTreeSet::new(),
        };
        let verified = ArtifactVerification::Verified {
            artifacts: BTreeSet::from([artifact()]),
        };
        let context = RecoveryContext {
            expected_image_profile: named("yougori/test/image/v1", "sandbox-image"),
            checkpoint_evidence: None,
            artifact_verification: &verified,
        };
        let of = self.execution.clone();
        self.coordinator
            .relaunch(&of, plan, &context, &mut self.port, &self.registry)
            .map_err(Box::new)
    }

    fn relaunch(&mut self) -> AuthorityGrant {
        match self.try_relaunch().unwrap().outcome {
            LaunchOutcome::AuthorityActive { grant, .. } => grant,
            other => panic!("{other:?}"),
        }
    }

    /// Restarts the coordinator from `state` on clock session `run`.
    fn recover(&mut self, state: PersistedState, run: u128) -> RecoveryReport {
        let (coordinator, report) = TestCoordinator::recover(
            state,
            Arc::clone(&self.clock),
            session(run),
            self.ledger.clone(),
            &mut self.port,
        )
        .unwrap();
        self.coordinator = coordinator;
        report
    }
}

/// The watchers that block a retirement of `of`, in registry order.
fn pending_watchers(
    world: &World,
    of: &ExecutionId,
    watchers: &WatcherRegistry,
    policy: CompactionPolicy,
) -> Vec<WatcherId> {
    match world
        .coordinator
        .prove_retirement(issuer(), of, watchers, policy)
    {
        Ok(_) => Vec::new(),
        Err(blocked) => blocked
            .blockers
            .iter()
            .filter_map(|blocker| match blocker {
                RetirementBlocker::WatcherPending { watcher, .. } => Some(*watcher),
                _ => None,
            })
            .collect(),
    }
}

#[test]
fn scoped_epochs_and_grants_belong_to_their_host_issuer_run_and_execution() {
    let mut world = World::new();
    let grant = world.launch();
    let of = world.execution.clone();
    // Nothing is scoped by a run that a crash could recover again.
    assert_eq!(
        world.coordinator.scoped_epoch(issuer(), &of),
        Err(ScopeRefusal::IncarnationNotPersisted)
    );
    world.persist();
    let epoch = world.coordinator.scoped_epoch(issuer(), &of).unwrap();
    assert_eq!(epoch.incarnation, Incarnation::FIRST);
    assert_eq!(epoch.authorization, grant.epoch);
    assert_eq!(
        world.coordinator.check_scoped_epoch(issuer(), &epoch),
        Ok(())
    );

    let check = |presented: &ScopedEpoch| world.coordinator.check_scoped_epoch(issuer(), presented);
    let mut foreign_host = epoch.clone();
    foreign_host.issuer.host = HostId::named("host-b");
    assert_eq!(
        check(&foreign_host),
        Err(ScopeRefusal::ForeignHost {
            presented: HostId::named("host-b"),
            expected: issuer().host
        })
    );
    let mut foreign_issuer = epoch.clone();
    foreign_issuer.issuer.issuer = IssuerId::named("broker");
    assert_eq!(
        check(&foreign_issuer),
        Err(ScopeRefusal::ForeignIssuer {
            presented: IssuerId::named("broker"),
            expected: issuer().issuer
        })
    );
    let mut other_sandbox = epoch.clone();
    other_sandbox.execution = execution("exe-other");
    assert_eq!(
        check(&other_sandbox),
        Err(ScopeRefusal::UnknownExecution {
            execution: execution("exe-other")
        })
    );
    let mut future_run = epoch.clone();
    future_run.incarnation = Incarnation::new(2);
    assert_eq!(
        check(&future_run),
        Err(ScopeRefusal::UnknownIncarnation {
            presented: Incarnation::new(2),
            current: Incarnation::FIRST
        })
    );
    let mut future_epoch = epoch.clone();
    future_epoch.authorization = epoch.authorization.next().unwrap();
    assert_eq!(
        check(&future_epoch),
        Err(ScopeRefusal::FutureEpoch {
            presented: future_epoch.authorization,
            current: epoch.authorization
        })
    );

    // A scoped grant is honoured under its epoch; leases are issued under its identity.
    let delegation = world
        .coordinator
        .scoped_grant(issuer(), &of, named("yougori/test/local/v1", "delegation"))
        .unwrap();
    let id = world
        .coordinator
        .check_scoped_grant(issuer(), &delegation)
        .unwrap();
    assert_eq!(id, delegation.id());
    let lease = world
        .coordinator
        .start_granted_work(
            &of,
            operation("op-delegated"),
            LeaseKind::ChildWork,
            terms(60),
            BTreeSet::from([id]),
        )
        .unwrap();
    // A model activation counter is not an authorization epoch: activating a model leaves
    // the scoped epoch and every scoped grant as they were (S3.1).
    let handle = world.activate(grant);
    assert_eq!(
        handle.generations.activation.get(),
        epoch.authorization.get(),
        "the counters happen to agree, and still mean nothing to each other"
    );
    assert_eq!(
        world.coordinator.scoped_epoch(issuer(), &of),
        Ok(epoch.clone())
    );

    // Revoking the grant tombstones its scoped identity and cancels the lease under it.
    world.coordinator.revoke_grant(&of, id).unwrap();
    assert_eq!(
        world.coordinator.check_scoped_grant(issuer(), &delegation),
        Err(ScopeRefusal::GrantRevoked { grant: id })
    );
    assert!(world.coordinator.check_lease(lease.id()).is_err());

    // Another scoped grant dies with its epoch, with no tombstone of its own.
    let other = world
        .coordinator
        .scoped_grant(issuer(), &of, named("yougori/test/local/v1", "other"))
        .unwrap();
    assert!(world
        .coordinator
        .check_scoped_grant(issuer(), &other)
        .is_ok());
    let notice = world.coordinator.revoke(&of).unwrap();
    assert_eq!(
        world.coordinator.check_scoped_grant(issuer(), &other),
        Err(ScopeRefusal::StaleEpoch {
            presented: epoch.authorization,
            current: notice.current
        })
    );
    assert!(!world.coordinator.grant_revoked(&of, other.id()));
}

#[test]
fn a_stale_watcher_never_revives_authorization() {
    let mut world = World::new();
    let grant = world.launch();
    world.persist();
    let of = world.execution.clone();
    let mut watchers = WatcherRegistry::new();
    let relay = WatcherId::named("relay");
    let holder = WatcherHolder::Engine;
    let first = watchers
        .register(
            &world.coordinator,
            issuer(),
            registration(relay, &of, holder, 30),
        )
        .unwrap();
    assert_eq!(world.coordinator.check_view(issuer(), &first), Ok(()));
    watchers.acknowledge(relay, &holder, first.clone()).unwrap();
    assert_eq!(
        watchers.register(
            &world.coordinator,
            issuer(),
            registration(relay, &of, holder, 30)
        ),
        Err(WatcherRefusal::Duplicate { watcher: relay })
    );

    // A model activation is no change of authority: the view stays current.
    world.activate(grant);
    assert_eq!(world.coordinator.check_view(issuer(), &first), Ok(()));

    // A grant revocation makes every earlier view stale.
    world
        .coordinator
        .revoke_grant(&of, grant_id("route"))
        .unwrap();
    let current = world.coordinator.authority_revision(&of).unwrap();
    assert_eq!(current.revoked_grants, 1);
    assert_eq!(
        world.coordinator.check_view(issuer(), &first),
        Err(ViewRefusal::Stale {
            presented: first.revision(),
            current
        })
    );
    // The watcher takes the current view; its acknowledgment never moves back, and nobody
    // else answers for it.
    let second = watchers
        .view(&world.coordinator, issuer(), relay, &holder)
        .unwrap();
    watchers
        .acknowledge(relay, &holder, second.clone())
        .unwrap();
    assert!(matches!(
        watchers.acknowledge(relay, &holder, first.clone()),
        Err(WatcherRefusal::Backwards { .. })
    ));
    let remote = WatcherHolder::Remote {
        host: HostId::named("host-b"),
    };
    assert_eq!(
        watchers.acknowledge(relay, &remote, second.clone()),
        Err(WatcherRefusal::HolderMismatch { watcher: relay })
    );

    // A clock that goes back extends no view: none is honoured or issued until the clock
    // passes the reading it already gave.
    world.advance(10);
    assert_eq!(world.coordinator.check_view(issuer(), &second), Ok(()));
    world.clock.set(at(105));
    assert_eq!(
        world.coordinator.check_view(issuer(), &second),
        Err(ViewRefusal::ClockWentBack {
            now: at(105),
            high_water: at(110)
        })
    );
    assert!(matches!(
        watchers.view(&world.coordinator, issuer(), relay, &holder),
        Err(WatcherRefusal::View {
            refusal: ViewRefusal::ClockWentBack { .. }
        })
    ));
    // At its staleness bound the view is refused.
    world.clock.set(at(130));
    assert_eq!(
        world.coordinator.check_view(issuer(), &second),
        Err(ViewRefusal::Expired {
            fresh_until: at(130)
        })
    );

    // A revocation advances the epoch: a view of the earlier epoch fails its scope.
    let third = watchers
        .view(&world.coordinator, issuer(), relay, &holder)
        .unwrap();
    world.coordinator.revoke(&of).unwrap();
    assert!(matches!(
        world.coordinator.check_view(issuer(), &third),
        Err(ViewRefusal::Scope {
            refusal: ScopeRefusal::StaleEpoch { .. }
        })
    ));

    // After a restart nothing from the earlier run is taken up again, and the engine's own
    // cache ended with it.
    let state = world.persist();
    world.recover(state, 2);
    assert_eq!(
        world.coordinator.check_view(issuer(), &third),
        Err(ViewRefusal::Scope {
            refusal: ScopeRefusal::IncarnationNotPersisted
        })
    );
    world.persist();
    assert!(matches!(
        world.coordinator.check_view(issuer(), &third),
        Err(ViewRefusal::Scope {
            refusal: ScopeRefusal::EarlierIncarnation { .. }
        })
    ));
    assert_eq!(watchers.engine_restarted(Incarnation::new(2)), vec![relay]);
    assert!(matches!(
        watchers.view(&world.coordinator, issuer(), relay, &holder),
        Err(WatcherRefusal::Ended {
            end: WatcherEnd::EngineRestarted { .. },
            ..
        })
    ));
}

#[test]
fn a_restored_older_state_is_raised_to_the_floor_and_revives_nothing() {
    let mut world = World::new();
    let of = world.execution.clone();
    let first_grant = world.launch();
    let older = world.persist();
    let floor = AuthorityFloor::new(issuer())
        .seal(&older, &ReplayRecord::default(), None)
        .unwrap();
    assert_eq!(floor.sequence(), 1);
    // A receiver of authority-bearing messages keeps its replay record beside the state.
    let mut receiver = ReplayState::new(replay_config()).unwrap();
    let first_scope = world.coordinator.scoped_epoch(issuer(), &of).unwrap();
    let _ = receiver.accept(&first_scope, Nonce::new(1), MessageClass::Renewal);
    let older_record = receiver.persist();
    receiver.confirm_persisted(&older_record);
    let older_generations = world.coordinator.sandbox(&of).unwrap().generations();

    // After the older state: a grant revoked, a model activated, a lease issued, the
    // sandbox revoked, stopped and booted again, and a model activated under the new boot.
    world
        .coordinator
        .revoke_grant(&of, grant_id("late"))
        .unwrap();
    world.activate(first_grant);
    let lost_lease = world.child("op-lost", 60);
    world.stop();
    let second_grant = world.relaunch();
    let lost_handle = world.activate(second_grant);
    let lost_vm = world.coordinator.sandbox(&of).unwrap().vm().unwrap();
    let lost_epoch = world.coordinator.scoped_epoch(issuer(), &of).unwrap();
    let lost_grant = world
        .coordinator
        .scoped_grant(issuer(), &of, named("yougori/test/local/v1", "delegation"))
        .unwrap();
    let _ = receiver.accept(&lost_epoch, Nonce::new(1), MessageClass::Renewal);
    let record = receiver.persist();
    receiver.confirm_persisted(&record);
    for number in 1..=5 {
        receiver
            .accept(&lost_epoch, Nonce::new(number), MessageClass::Renewal)
            .unwrap();
    }
    let newer = world.persist();
    let newer_record = receiver.persist();
    receiver.confirm_persisted(&newer_record);
    let newer_generations = world.coordinator.sandbox(&of).unwrap().generations();
    let floor = floor.seal(&newer, &newer_record, None).unwrap();

    // The floor never moves back: the older state does not seal again.
    let regression = floor
        .seal(&older, &ReplayRecord::default(), None)
        .unwrap_err();
    for expected in [
        Regression::SandboxGenerations {
            execution: of.clone(),
            floor: newer_generations,
            state: older_generations,
        },
        Regression::TombstoneMissing {
            execution: of.clone(),
            grant: grant_id("late"),
        },
        Regression::ModelMissing {
            execution: of.clone(),
            model: world.model,
        },
    ] {
        assert!(regression.regressions.contains(&expected), "{regression:?}");
    }
    assert!(regression
        .regressions
        .iter()
        .any(|regression| matches!(regression, Regression::NextLease { .. })));

    // The floor is stored apart from the state and reads back strictly.
    let stored: AuthorityFloor =
        serde_json::from_str(&serde_json::to_string(&floor).unwrap()).unwrap();
    assert_eq!(stored, floor);
    let mut extra = serde_json::to_value(&floor).unwrap();
    extra["epoch"] = serde_json::json!(1);
    assert!(serde_json::from_value::<AuthorityFloor>(extra).is_err());

    // The engine restarts from the older state, as from a backup restored over the newer
    // one, and the receiver from its older record. The state is raised, not trusted.
    let mut restored = older.clone();
    let restore = stored
        .restore(issuer(), &mut restored, &older_record, None)
        .unwrap();
    assert!(!restore.is_current());
    assert_eq!(restore.stale, BTreeSet::from([of.clone()]));
    assert!(restore.upgrades.contains(&FloorUpgrade::SandboxRaised {
        execution: of.clone(),
        from: older_generations,
        to: newer_generations
    }));
    assert!(restore
        .upgrades
        .contains(&FloorUpgrade::TombstonesRestored {
            execution: of.clone(),
            grants: BTreeSet::from([grant_id("late")])
        }));
    assert!(restore.upgrades.iter().any(|upgrade| matches!(
        upgrade,
        FloorUpgrade::ModelRecreated { model, .. } if *model == world.model
    )));
    assert!(restore
        .upgrades
        .iter()
        .any(|upgrade| matches!(upgrade, FloorUpgrade::NextLease { .. })));
    assert!(stored.regressions(&restored, None).is_empty());

    // Recovery: the VM of the lost boot has no trusted record and is ended through its
    // handle; the raised sandbox ends.
    let report = world.recover(restored, 2);
    assert!(report.untrusted_vms_terminated.contains(&lost_vm));
    let ended = world.coordinator.end_stale(&restore, &mut world.port);
    assert!(matches!(ended.get(&of), Some(Ok(_))), "{ended:?}");
    assert_eq!(
        world.coordinator.sandbox(&of).unwrap().state(),
        SandboxState::Stopped
    );
    let recovered = world.persist();
    let floor = stored.seal(&recovered, &restore.replay, None).unwrap();
    assert_eq!(floor.incarnation(), Incarnation::new(2));

    // Nothing from the lost period is honoured or handed out again.
    assert!(world.coordinator.grant_revoked(&of, grant_id("late")));
    assert!(matches!(
        world.coordinator.check_scoped_epoch(issuer(), &lost_epoch),
        Err(ScopeRefusal::EarlierIncarnation { .. })
    ));
    assert!(matches!(
        world.coordinator.check_scoped_grant(issuer(), &lost_grant),
        Err(ScopeRefusal::EarlierIncarnation { .. })
    ));
    assert_eq!(
        world.coordinator.check_lease(lost_lease.id()),
        Err(LeaseRefusal::UnknownLease {
            lease: lost_lease.id()
        })
    );
    assert!(world.coordinator.check_gpu_handle(&lost_handle).is_err());
    let relaunched = world.relaunch();
    let generations = world.coordinator.sandbox(&of).unwrap().generations();
    assert!(generations.boot > newer_generations.boot);
    assert!(relaunched.epoch > newer_generations.authorization);
    assert_ne!(world.coordinator.sandbox(&of).unwrap().vm(), Some(lost_vm));
    let fresh_lease = world.child("op-fresh", 60);
    assert!(fresh_lease.id() >= newer.next_lease);
    let fresh_handle = world.activate(relaunched);
    assert!(fresh_handle.generations.activation > lost_handle.generations.activation);
    assert!(fresh_handle.generations.gpu_allocation > lost_handle.generations.gpu_allocation);
    assert!(world.coordinator.check_gpu_handle(&lost_handle).is_err());

    // The receiver, restarted from its older record raised to the floor's, accepts nothing
    // it accepted in the lost period, and the current run retires the earlier run's scopes.
    let mut restarted = ReplayState::restore(replay_config(), &restore.replay).unwrap();
    for number in 1..=5 {
        assert!(matches!(
            restarted.accept(&lost_epoch, Nonce::new(number), MessageClass::Renewal),
            Err(ReplayRefusal::BelowWindow { .. })
        ));
    }
    let current = world.coordinator.scoped_epoch(issuer(), &of).unwrap();
    assert_eq!(current.incarnation, Incarnation::new(2));
    restarted.retire_below(&current);
    assert!(matches!(
        restarted.accept(&lost_epoch, Nonce::new(99), MessageClass::Renewal),
        Err(ReplayRefusal::ScopeRetired { .. })
    ));
    assert_eq!(floor.sequence(), 3);
}

#[test]
fn a_revocation_stream_behind_the_floor_refuses_the_restore() {
    let mut world = World::new();
    world.launch();
    let of = world.execution.clone();
    let directory = tempfile::tempdir().unwrap();
    let mut log = open_log(directory.path());
    let epoch = world
        .coordinator
        .sandbox(&of)
        .unwrap()
        .generations()
        .authorization;
    for name in ["first", "second"] {
        world.coordinator.revoke_grant(&of, grant_id(name)).unwrap();
        let context = EventContext::new(operation(&format!("op-{name}")), Phase::Revoked)
            .with_generations(Generations::NONE.with_authorization(epoch));
        log.record_grant(
            context,
            world.coordinator.now(),
            GrantRevocation {
                execution: of.clone(),
                grant: grant_id(name),
                epoch,
                reason: RevocationReason::SecurityEvent,
            },
        )
        .unwrap();
    }
    let state = world.persist();
    let last = log.log().last();
    assert_eq!(last, EventSequence::new(2));
    let floor = AuthorityFloor::new(issuer())
        .seal(&state, &ReplayRecord::default(), last)
        .unwrap();
    assert_eq!(floor.revocation_log(), last);

    // The stream as sealed: the newest state restores as it is.
    let restore = floor
        .restore(issuer(), &mut state.clone(), &ReplayRecord::default(), last)
        .unwrap();
    assert!(restore.is_current());
    assert!(restore.stale.is_empty());

    // A stream replaced by an empty one, or cut back: refused, and the state is untouched.
    let replaced = tempfile::tempdir().unwrap();
    let empty = open_log(replaced.path());
    let mut untouched = state.clone();
    assert_eq!(
        floor.restore(
            issuer(),
            &mut untouched,
            &ReplayRecord::default(),
            empty.log().last()
        ),
        Err(FloorRefusal::RevocationLogBehind {
            floor: EventSequence::new(2).unwrap(),
            found: None
        })
    );
    assert_eq!(
        floor.restore(
            issuer(),
            &mut untouched,
            &ReplayRecord::default(),
            EventSequence::new(1)
        ),
        Err(FloorRefusal::RevocationLogBehind {
            floor: EventSequence::new(2).unwrap(),
            found: EventSequence::new(1)
        })
    );
    assert_eq!(untouched, state);
    // Sealing against a stream behind the floor is a regression too.
    assert_eq!(
        floor
            .seal(&state, &ReplayRecord::default(), None)
            .unwrap_err()
            .regressions,
        vec![Regression::RevocationLog {
            floor: EventSequence::new(2).unwrap(),
            found: None
        }]
    );
    // Another host's floor is refused.
    let other = AuthorityIssuer {
        host: HostId::named("host-b"),
        issuer: issuer().issuer,
    };
    assert_eq!(
        floor.restore(other, &mut untouched, &ReplayRecord::default(), last),
        Err(FloorRefusal::ForeignFloor { floor: issuer() })
    );
    log.close().unwrap();
    empty.close().unwrap();
}

#[test]
fn tombstones_leave_only_with_a_retirement_proof() {
    let mut world = World::new();
    let grant = world.launch();
    world.persist();
    let of = world.execution.clone();
    let mut watchers = WatcherRegistry::new();
    let cache = WatcherId::named("engine-cache");
    let relay = WatcherId::named("remote-relay");
    let engine = WatcherHolder::Engine;
    let remote = WatcherHolder::Remote {
        host: HostId::named("host-b"),
    };
    let view = watchers
        .register(
            &world.coordinator,
            issuer(),
            registration(cache, &of, engine, 30),
        )
        .unwrap();
    watchers.acknowledge(cache, &engine, view).unwrap();
    let remote_view = watchers
        .register(
            &world.coordinator,
            issuer(),
            registration(relay, &of, remote, 30),
        )
        .unwrap();
    watchers
        .acknowledge(relay, &remote, remote_view.clone())
        .unwrap();
    world
        .coordinator
        .revoke_grant(&of, grant_id("route"))
        .unwrap();
    world.activate(grant);
    let lease = world.child("op-child", 60);
    let before = world.persist();
    let floor = AuthorityFloor::new(issuer())
        .seal(&before, &ReplayRecord::default(), None)
        .unwrap();
    let policy = CompactionPolicy {
        watcher_skew: 5 * SECOND,
    };

    // While the sandbox runs, everything that could still present authority blocks.
    let blocked = world
        .coordinator
        .prove_retirement(issuer(), &of, &watchers, policy)
        .unwrap_err();
    assert!(blocked.blockers.contains(&RetirementBlocker::NotStopped {
        state: SandboxState::AuthorityActive
    }));
    assert!(blocked.blockers.iter().any(|blocker| matches!(
        blocker,
        RetirementBlocker::LeaseMayPresent { lease: id, .. } if *id == lease.id()
    )));
    assert!(blocked.blockers.iter().any(|blocker| matches!(
        blocker,
        RetirementBlocker::ActivationUnretired { model, .. } if *model == world.model
    )));
    assert_eq!(pending_watchers(&world, &of, &watchers, policy).len(), 2);

    // Stopped: the lease acknowledged its cancellation and the activation retired, but the
    // watchers still hold views from before the grant's revocation.
    world.stop();
    let blocked = world
        .coordinator
        .prove_retirement(issuer(), &of, &watchers, policy)
        .unwrap_err();
    assert_eq!(blocked.blockers.len(), 2, "{blocked:?}");
    // The engine's cache takes and acknowledges the current view.
    let current = watchers
        .view(&world.coordinator, issuer(), cache, &engine)
        .unwrap();
    watchers.acknowledge(cache, &engine, current).unwrap();
    // The remote relay is partitioned. Its last view is fresh until 130 on the
    // coordinator's clock; with 5 s of skew it may use it until 135.
    world.clock.set(at(134));
    assert_eq!(
        pending_watchers(&world, &of, &watchers, policy),
        vec![relay]
    );
    // A clock that went back judges no lapse and no expiry.
    world.clock.set(at(120));
    let blocked = world
        .coordinator
        .prove_retirement(issuer(), &of, &watchers, policy)
        .unwrap_err();
    assert!(blocked
        .blockers
        .contains(&RetirementBlocker::ClockWentBack {
            now: at(120),
            high_water: at(134)
        }));
    world.clock.set(at(135));
    let proof = world
        .coordinator
        .prove_retirement(issuer(), &of, &watchers, policy)
        .unwrap();
    assert_eq!(proof.tombstones(), &BTreeSet::from([grant_id("route")]));
    assert_eq!(proof.leases(), &[(lease.id(), LeaseClosure::Cancelled)]);
    assert_eq!(proof.activations().len(), 1);
    assert!(proof
        .watchers()
        .iter()
        .any(|(watcher, standing)| *watcher == cache
            && matches!(standing, WatcherStanding::Current { .. })));
    assert!(proof.watchers().contains(&(
        relay,
        WatcherStanding::Lapsed {
            fresh_until: remote_view.fresh_until()
        }
    )));
    assert_eq!(proof.relaunch_settings(), &settings_grant());

    let retirement = world
        .coordinator
        .retire(issuer(), &of, &mut watchers, policy)
        .unwrap();
    assert_eq!(retirement.generations, SandboxGenerations::RETIRED);
    assert_eq!(retirement.watchers_forgotten, 2);
    assert!(world.coordinator.is_retired(&of));
    assert!(!world.coordinator.grant_revoked(&of, grant_id("route")));
    // Nothing under the execution is honoured or granted again: no scoped epoch, no work
    // under the compacted grant, no launch and no relaunch.
    assert_eq!(
        world.coordinator.scoped_epoch(issuer(), &of),
        Err(ScopeRefusal::Retired {
            execution: of.clone()
        })
    );
    assert!(world
        .coordinator
        .start_granted_work(
            &of,
            operation("op-again"),
            LeaseKind::ChildWork,
            terms(60),
            BTreeSet::from([grant_id("route")]),
        )
        .is_err());
    assert!(matches!(
        world.try_launch(&of).map_err(|error| *error),
        Err(CoordinationError::NotLaunchable {
            state: SandboxState::Stopped
        })
    ));
    assert!(matches!(
        world.try_relaunch().map_err(|error| *error),
        Err(CoordinationError::Transition {
            refusal: TransitionRefusal::GenerationExhausted { .. }
        })
    ));
    assert!(matches!(
        world.coordinator.prove_retirement(issuer(), &of, &watchers, policy),
        Err(RetirementBlocked { blockers, .. })
            if blockers == vec![RetirementBlocker::Scope {
                refusal: ScopeRefusal::Retired { execution: of.clone() }
            }]
    ));

    // The retirement is durable: the floor takes it, and the state from before it, still
    // running and carrying the tombstone, is raised to it again at a restart.
    let after = world.persist();
    let floor = floor.seal(&after, &ReplayRecord::default(), None).unwrap();
    let kept = floor.execution(&of).unwrap();
    assert!(kept.is_retired());
    assert!(kept.revoked_grants().is_empty());
    let mut restored = before.clone();
    let restore = floor
        .restore(issuer(), &mut restored, &ReplayRecord::default(), None)
        .unwrap();
    assert!(restore.upgrades.contains(&FloorUpgrade::SandboxRetired {
        execution: of.clone(),
        recorded: SandboxState::AuthorityActive
    }));
    world.recover(restored, 2);
    world.persist();
    assert!(world.coordinator.is_retired(&of));
    assert_eq!(
        world.coordinator.sandbox(&of).unwrap().state(),
        SandboxState::Stopped
    );
    assert_eq!(
        world.coordinator.scoped_epoch(issuer(), &of),
        Err(ScopeRefusal::Retired {
            execution: of.clone()
        })
    );
    assert!(world.try_relaunch().is_err());
}

#[cfg(windows)]
#[test]
fn a_reused_pid_never_answers_for_a_watcher() {
    use crate::foundation::process::{IdentityCheck, ProcessIdentity};

    // This process, as the host identifies it, and an earlier process that held the same
    // PID: same number, earlier creation time.
    let own = ProcessIdentity::holder_of(std::process::id())
        .unwrap()
        .unwrap();
    assert_eq!(own.check().unwrap(), IdentityCheck::Same);
    let earlier = ProcessIdentity {
        pid: own.pid,
        start_time_ticks: own.start_time_ticks.saturating_sub(1),
    };
    assert_eq!(earlier.check().unwrap(), IdentityCheck::Reused);
    assert_ne!(earlier.digest(), own.digest());

    let mut world = World::new();
    world.launch();
    world.persist();
    let of = world.execution.clone();
    let mut watchers = WatcherRegistry::new();
    let files = WatcherId::named("file-service");
    let relay = WatcherId::named("relay");
    let gone = WatcherHolder::Process { identity: earlier };
    let live = WatcherHolder::Process { identity: own };
    watchers
        .register(
            &world.coordinator,
            issuer(),
            registration(files, &of, gone, 30),
        )
        .unwrap();
    let relay_view = watchers
        .register(
            &world.coordinator,
            issuer(),
            registration(relay, &of, live, 30),
        )
        .unwrap();
    watchers.acknowledge(relay, &live, relay_view).unwrap();
    world
        .coordinator
        .revoke_grant(&of, grant_id("files"))
        .unwrap();

    // The process holding the PID now cannot acknowledge, view or deregister for the
    // earlier one.
    let current = watchers
        .view(&world.coordinator, issuer(), relay, &live)
        .unwrap();
    assert_eq!(
        watchers.acknowledge(files, &live, current),
        Err(WatcherRefusal::HolderMismatch { watcher: files })
    );
    assert_eq!(
        watchers.view(&world.coordinator, issuer(), files, &live),
        Err(WatcherRefusal::HolderMismatch { watcher: files })
    );
    assert_eq!(
        watchers.deregister(files, &live),
        Err(WatcherRefusal::HolderMismatch { watcher: files })
    );
    // The host's observation ends the earlier one; the live one goes on.
    assert_eq!(
        watchers.observe_process(files, earlier.check().unwrap()),
        Ok(Some(WatcherEnd::ProcessReused { identity: earlier }))
    );
    assert_eq!(
        watchers.observe_process(relay, own.check().unwrap()),
        Ok(None)
    );

    world.stop();
    let policy = CompactionPolicy {
        watcher_skew: 5 * SECOND,
    };
    assert_eq!(
        pending_watchers(&world, &of, &watchers, policy),
        vec![relay]
    );
    let after = watchers
        .view(&world.coordinator, issuer(), relay, &live)
        .unwrap();
    watchers.acknowledge(relay, &live, after).unwrap();
    let proof = world
        .coordinator
        .prove_retirement(issuer(), &of, &watchers, policy)
        .unwrap();
    assert!(proof.watchers().contains(&(
        files,
        WatcherStanding::Ended {
            end: WatcherEnd::ProcessReused { identity: earlier }
        }
    )));
}

#[test]
fn a_partitioned_watcher_lapses_only_on_this_clock_and_never_across_a_restart() {
    let mut world = World::new();
    world.launch();
    world.persist();
    let of = world.execution.clone();
    let mut watchers = WatcherRegistry::new();
    let relay = WatcherId::named("remote-relay");
    let cache = WatcherId::named("engine-cache");
    let remote = WatcherHolder::Remote {
        host: HostId::named("host-b"),
    };
    let engine = WatcherHolder::Engine;
    // Both views are fresh until 110.
    let relay_view = watchers
        .register(
            &world.coordinator,
            issuer(),
            registration(relay, &of, remote, 10),
        )
        .unwrap();
    watchers
        .acknowledge(relay, &remote, relay_view.clone())
        .unwrap();
    let cache_view = watchers
        .register(
            &world.coordinator,
            issuer(),
            registration(cache, &of, engine, 10),
        )
        .unwrap();
    watchers.acknowledge(cache, &engine, cache_view).unwrap();
    // The relay is partitioned from here on; the sandbox is revoked and stopped.
    world.stop();
    let policy = CompactionPolicy {
        watcher_skew: 5 * SECOND,
    };
    world.clock.set(at(114));
    let mut pending = pending_watchers(&world, &of, &watchers, policy);
    pending.sort();
    let mut both = vec![relay, cache];
    both.sort();
    assert_eq!(pending, both);

    // The engine restarts before either lapses.
    let state = world.persist();
    world.recover(state, 2);
    world.persist();
    assert_eq!(watchers.engine_restarted(Incarnation::new(2)), vec![cache]);
    // The relay's last view is on the earlier clock session: no lapse is measured for it on
    // this one, however late.
    world.clock.set(at(10_000));
    let blocked = world
        .coordinator
        .prove_retirement(issuer(), &of, &watchers, policy)
        .unwrap_err();
    assert_eq!(
        blocked.blockers,
        vec![RetirementBlocker::WatcherPending {
            watcher: relay,
            standing: WatcherStanding::Pending {
                acknowledged: Some(relay_view.position())
            }
        }]
    );
    // Its stale view is refused when it comes back; it acknowledges this run's view.
    assert!(matches!(
        world.coordinator.check_view(issuer(), &relay_view),
        Err(ViewRefusal::Scope {
            refusal: ScopeRefusal::EarlierIncarnation { .. }
        })
    ));
    let current = watchers
        .view(&world.coordinator, issuer(), relay, &remote)
        .unwrap();
    assert_eq!(current.epoch().incarnation, Incarnation::new(2));
    watchers.acknowledge(relay, &remote, current).unwrap();
    assert!(world
        .coordinator
        .prove_retirement(issuer(), &of, &watchers, policy)
        .is_ok());
}

#[test]
fn partial_cleanup_and_a_failed_supervisor_keep_the_five_acknowledgments_apart() {
    let mut world = World::new();
    world.launch();
    let of = world.execution.clone();
    world.coordinator.start_running(&of).unwrap();
    let lease = world.child("op-stream", 60);
    world.advance(1);
    world.coordinator.revoke(&of).unwrap();
    // New effects: denied at once, and the first refusal is its own milestone.
    world.advance(1);
    assert!(world
        .coordinator
        .start_child_work(&of, operation("op-late"), LeaseKind::ChildWork, terms(60))
        .is_err());
    // Existing channels: the host observed every release channel closed.
    world.advance(1);
    world
        .coordinator
        .acknowledge_revocation(
            &of,
            RevocationMilestone::AllChannelsClosed,
            SourceClass::HostProbe,
        )
        .unwrap();
    // Billing: the provider's API reported it stopped, before the VM stops.
    world.advance(1);
    world
        .coordinator
        .acknowledge_revocation(
            &of,
            RevocationMilestone::ProviderStoppedBilling,
            SourceClass::ProviderApi,
        )
        .unwrap();
    world
        .coordinator
        .acknowledge_cancellation(lease.id())
        .unwrap();

    // The supervisor is down: the VM cannot be terminated, nothing is freed, and new work
    // stays refused.
    world.port.failing.insert(PortOperation::TerminateVm);
    world.advance(1);
    assert!(matches!(
        world.coordinator.advance_revocation(&of, &mut world.port),
        Err(CoordinationError::Stalled { .. })
    ));
    let operation_now = world.coordinator.revocation(&of).unwrap();
    assert_eq!(
        operation_now.milestone(RevocationMilestone::VmStopped),
        None
    );
    assert_eq!(
        operation_now.milestone(RevocationMilestone::CleanupFinished),
        None
    );
    assert!(world.ledger.is_held(&sandbox_key(&of, 1)));
    assert!(world
        .coordinator
        .start_child_work(&of, operation("op-later"), LeaseKind::ChildWork, terms(60))
        .is_err());

    // A new supervisor terminates the VM, but the perimeter teardown fails: the VM
    // stopped, cleanup did not finish.
    world.port.failing = BTreeSet::from([PortOperation::TeardownPerimeter]);
    world.advance(1);
    assert!(matches!(
        world.coordinator.advance_revocation(&of, &mut world.port),
        Err(CoordinationError::Stalled { .. })
    ));
    let operation_now = world.coordinator.revocation(&of).unwrap();
    assert_eq!(
        operation_now.milestone(RevocationMilestone::VmStopped),
        Some(at(106))
    );
    assert_eq!(
        operation_now.milestone(RevocationMilestone::CleanupFinished),
        None
    );

    // Cleanup finishes on the next attempt.
    world.port.failing.clear();
    world.advance(1);
    assert!(matches!(
        world.coordinator.advance_revocation(&of, &mut world.port),
        Ok(RevocationStatus::Completed { .. })
    ));
    let done = world.coordinator.revocation(&of).unwrap();
    let expected = [
        (
            RevocationMilestone::NewAuthorizationsDenied,
            at(101),
            MilestoneSource::Coordinator,
        ),
        (
            RevocationMilestone::FirstDeniedAuthorization,
            at(102),
            MilestoneSource::Coordinator,
        ),
        (
            RevocationMilestone::AllChannelsClosed,
            at(103),
            MilestoneSource::Acknowledged {
                source: SourceClass::HostProbe,
            },
        ),
        (
            RevocationMilestone::ProviderStoppedBilling,
            at(104),
            MilestoneSource::Acknowledged {
                source: SourceClass::ProviderApi,
            },
        ),
        (
            RevocationMilestone::VmStopped,
            at(106),
            MilestoneSource::Coordinator,
        ),
        (
            RevocationMilestone::CleanupFinished,
            at(107),
            MilestoneSource::Coordinator,
        ),
    ];
    for (milestone, when, source) in expected {
        assert_eq!(done.milestone(milestone), Some(when), "{milestone:?}");
        assert_eq!(
            done.milestone_source(milestone),
            Some(source),
            "{milestone:?}"
        );
    }
    // The coordinator's own milestones are never acknowledged from outside.
    assert_eq!(
        world.coordinator.acknowledge_revocation(
            &of,
            RevocationMilestone::VmStopped,
            SourceClass::HostProbe
        ),
        Err(CoordinationError::NotAcknowledgedExternally {
            milestone: RevocationMilestone::VmStopped
        })
    );
    assert!(!world.ledger.is_held(&sandbox_key(&of, 1)));
}

#[test]
fn a_revocation_takes_its_reserved_slot_under_overload() {
    // A ledger with room for exactly one sandbox and no queue.
    let ledger = FakeLedger::new(demand());
    let mut world = World::with_ledger(ledger);
    let of = world.execution.clone();
    let mut channel = ControlChannel::<&'static str>::new(ControlConfig {
        ordinary_capacity: 4,
        revocation_slots: 2,
        grants_per_slot: 2,
    })
    .unwrap();
    // The supervisor admits the execution with its revocation slot, then launches it.
    channel.reserve(&of).unwrap();
    world.launch();
    world.persist();
    let lease = world.child("op-stream", 60);
    // The host is exhausted: another execution is admitted to the channel, but the ledger
    // has nothing left for it.
    let other = execution("exe-other");
    channel.reserve(&other).unwrap();
    assert!(!matches!(
        world.try_launch(&other),
        Ok(LaunchOutcome::AuthorityActive { .. })
    ));
    // Ordinary traffic fills the channel, and a third execution cannot be admitted, since
    // its revocation could not be reserved.
    for target in [&of, &other, &of, &other] {
        channel.send(target, "status").unwrap();
    }
    assert_eq!(
        channel.send(&other, "status"),
        Err(ControlRefusal::Overloaded { capacity: 4 })
    );
    let third = execution("exe-third");
    assert_eq!(
        channel.reserve(&third),
        Err(ControlRefusal::SlotsExhausted { slots: 2 })
    );

    // The revocation messages arrive authenticated and numbered: a replayed revocation is
    // still delivered, a replayed renewal is not.
    let mut receiver = ReplayState::new(replay_config()).unwrap();
    let scope = world.coordinator.scoped_epoch(issuer(), &of).unwrap();
    for _ in 0..2 {
        assert_eq!(
            receiver.accept(&scope, Nonce::new(7), MessageClass::Revocation),
            Ok(Delivery::Idempotent)
        );
    }
    let _ = receiver.accept(&scope, Nonce::new(7), MessageClass::Renewal);
    let record = receiver.persist();
    receiver.confirm_persisted(&record);
    assert_eq!(
        receiver.accept(&scope, Nonce::new(7), MessageClass::Renewal),
        Ok(Delivery::Accepted)
    );
    assert!(matches!(
        receiver.accept(&scope, Nonce::new(7), MessageClass::Renewal),
        Err(ReplayRefusal::Replayed { .. })
    ));

    // The revocation goes into its reserved slot and supersedes what was queued for it.
    assert_eq!(
        channel.revoke(
            &of,
            RevocationRequest::Grant {
                grant: grant_id("route"),
                operation: operation("op-revoke-route"),
            }
        ),
        Ok(RevocationQueued::Queued)
    );
    assert_eq!(
        channel.revoke(
            &of,
            RevocationRequest::Execution {
                operation: operation("op-revoke"),
            }
        ),
        Ok(RevocationQueued::Queued)
    );
    assert_eq!(channel.ordinary_len(), 2);
    assert_eq!(channel.totals().superseded, 2);
    assert_eq!(
        channel.send(&of, "status"),
        Err(ControlRefusal::Revoking {
            execution: of.clone()
        })
    );
    assert_eq!(
        channel.revoke(
            &third,
            RevocationRequest::Execution {
                operation: operation("op-third"),
            }
        ),
        Err(ControlRefusal::NoRevocationSlot { execution: third })
    );

    // It is drained before the older ordinary messages and carried out with nothing from
    // the exhausted ledger.
    let Some(ControlItem::Revocation(pending)) = channel.next_item() else {
        panic!("the revocation comes first");
    };
    assert_eq!(pending.execution, of);
    assert_eq!(pending.whole, Some(operation("op-revoke")));
    assert!(pending.grants.is_empty());
    world.coordinator.revoke(&pending.execution).unwrap();
    world
        .coordinator
        .acknowledge_cancellation(lease.id())
        .unwrap();
    assert!(matches!(
        world.coordinator.advance_revocation(&of, &mut world.port),
        Ok(RevocationStatus::Completed { .. })
    ));
    assert_eq!(
        world.coordinator.sandbox(&of).unwrap().state(),
        SandboxState::Stopped
    );
    assert!(matches!(
        channel.next_item(),
        Some(ControlItem::Message { execution, .. }) if execution == other
    ));
}

#[test]
fn a_refused_relaunch_of_a_retired_sandbox_changes_nothing() {
    let mut world = World::new();
    let grant = world.launch();
    world.persist();
    let of = world.execution.clone();
    world.activate(grant);
    world.stop();
    let policy = CompactionPolicy {
        watcher_skew: 5 * SECOND,
    };
    world
        .coordinator
        .retire(issuer(), &of, &mut WatcherRegistry::new(), policy)
        .unwrap();
    let revocation = world.coordinator.revocation(&of).cloned();
    assert!(revocation.is_some());
    let before = world.coordinator.persist();

    assert!(matches!(
        world.try_relaunch().map_err(|error| *error),
        Err(CoordinationError::Transition {
            refusal: TransitionRefusal::GenerationExhausted { .. }
        })
    ));
    // The refused call changed nothing: the revocation record, the sandbox, the models,
    // the leases and the tombstones are as they were.
    assert_eq!(world.coordinator.revocation(&of).cloned(), revocation);
    assert_eq!(world.coordinator.persist(), before);
}
