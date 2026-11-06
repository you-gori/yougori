//! Tests of the durable authority store (S2 CORE-04; VM part §6.1–§6.3; VM-W29;
//! docs/combined-plan-leftover-tasks.md S04): crash points through a directory that refuses
//! one file's write, an older state copied back, a floor or a state removed or rolled back,
//! torn, edited and foreign files, revocation streams behind the floor or replaced, a
//! second store on one directory, and a full persist, restart and restore round trip with
//! a revocation adopted from the stream. Each restart drops the store, the streams and the
//! coordinator; the VMs and the ledger stay, as the host's do.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::fakes::{FakeLedger, FakeSandbox};
use super::*;
use crate::foundation::events::{
    CursorError, DurableStreamId, EventContext, EventSequence, Generations, GrantRevocation,
    LogConfig, LogEntry, LogError, OwnerError, Phase, ProducerId, ReadItem, Revocation,
    RevocationLog, RevocationReason, Takeover,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Backend, BackendRelease, Capability, ClockSession, ConfigurationFingerprint, Observation,
    ProbeRegistry, RuntimeOffer, RuntimeRequirement, RuntimeSubject, SourceClass, Subject,
    SupportDetail,
};
use crate::foundation::ids::{
    digest, Digest, DigestBuilder, ExecutionCategory, ExecutionId, Incarnation, ManualClock,
    MonotonicTime, OperationId, TenantId,
};

const HOUR: Duration = Duration::from_secs(3600);
const GIB: u64 = 1 << 30;

type TestClock = Arc<ManualClock>;
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

fn grant(name: &str) -> GrantId {
    GrantId::from_digest(named("yougori/test/grant/v1", name))
}

/// The coordination authority under test: issuer `coordinator` on host `host-a`.
fn issuer() -> AuthorityIssuer {
    AuthorityIssuer {
        host: HostId::named("host-a"),
        issuer: IssuerId::named("coordinator"),
    }
}

fn owner() -> ProducerId {
    ProducerId::new("coordinator.authority").unwrap()
}

fn configuration() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_digest(named("yougori/test/configuration/v1", "launch"))
}

fn vm_runtime() -> RuntimeSubject {
    RuntimeSubject {
        category: ExecutionCategory::VmSandbox,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance: named("yougori/test/instance/v1", "vm-host-1"),
    }
}

fn replay_config() -> ReplayConfig {
    ReplayConfig {
        window: 64,
        persist_margin: 16,
        max_scopes: 8,
    }
}

fn log_config() -> LogConfig {
    LogConfig {
        max_entries: 64,
        max_bytes: 1 << 20,
        segment_entries: 8,
        segment_bytes: 1 << 16,
    }
}

/// The directories of one host: the store's, the revocation stream's and the recovery
/// stream's, each its own.
struct Dirs {
    _root: tempfile::TempDir,
    root: PathBuf,
    store: PathBuf,
    revocations: PathBuf,
    recovery: PathBuf,
}

impl Dirs {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().to_path_buf();
        Self {
            store: path.join("authority"),
            revocations: path.join("revocations"),
            recovery: path.join("recovery"),
            root: path,
            _root: root,
        }
    }

    fn file(&self, file: StoreFile) -> PathBuf {
        self.store.join(file.name())
    }
}

fn open_store(directory: &Path) -> AuthorityStore {
    AuthorityStore::open(directory, issuer(), owner())
        .unwrap()
        .0
}

fn open_revocations(directory: &Path) -> RevocationLog {
    RevocationLog::open(
        directory,
        DurableStreamId::new("coordinator.revocations").unwrap(),
        ProducerId::new("coordinator.revocations").unwrap(),
        log_config(),
    )
    .unwrap()
    .0
}

fn open_recovery(directory: &Path) -> RecoveryLog {
    open_recovery_log(
        directory,
        DurableStreamId::new("coordinator.recovery").unwrap(),
        ProducerId::new("coordinator.recovery").unwrap(),
        log_config(),
    )
    .unwrap()
    .0
}

/// The events the recovery stream keeps, in order.
fn recovery_events(log: &RecoveryLog) -> Vec<RecoveryEvent> {
    log.log()
        .read(&log.log().start(), usize::MAX)
        .unwrap()
        .items
        .into_iter()
        .filter_map(|item| match item {
            ReadItem::Entry {
                entry: LogEntry::Record(event),
                ..
            } => Some(event.payload().clone()),
            _ => None,
        })
        .collect()
}

fn restored(load: StoreLoad<PersistedState>) -> (PersistedState, StoreRestore) {
    match load {
        StoreLoad::Restored { state, restore } => (state, restore),
        StoreLoad::Fresh => panic!("nothing was restored"),
    }
}

/// Puts a directory where `file`'s temporary copy is written, so that its next write fails
/// before any of it is stored, as a crash just before that write leaves the store.
fn block(dirs: &Dirs, file: StoreFile) -> PathBuf {
    let path = dirs.file(file).with_extension("tmp");
    fs::create_dir(&path).unwrap();
    path
}

/// The receiver's scope in run `incarnation` of `world`'s sandbox.
fn scope(world: &World, incarnation: u64) -> ScopedEpoch {
    ScopedEpoch {
        issuer: issuer(),
        incarnation: Incarnation::new(incarnation),
        execution: world.execution.clone(),
        authorization: world
            .coordinator
            .sandbox(&world.execution)
            .unwrap()
            .generations()
            .authorization,
    }
}

fn not_persisted(receiver: &mut ReplayState, scope: &ScopedEpoch) -> bool {
    matches!(
        receiver.accept(scope, Nonce::new(1), MessageClass::Renewal),
        Err(ReplayRefusal::LimitNotPersisted { .. })
    )
}

/// Records the revocation of `granted` under `world`'s sandbox on the durable stream.
fn record_grant(log: &mut RevocationLog, world: &World, granted: GrantId) {
    let epoch = world
        .coordinator
        .sandbox(&world.execution)
        .unwrap()
        .generations()
        .authorization;
    let context = EventContext::new(operation("op-revoke-grant"), Phase::Revoked)
        .with_generations(Generations::NONE.with_authorization(epoch));
    log.record_grant(
        context,
        world.coordinator.now(),
        GrantRevocation {
            execution: world.execution.clone(),
            grant: granted,
            epoch,
            reason: RevocationReason::SecurityEvent,
        },
    )
    .unwrap();
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
}

impl World {
    fn new() -> Self {
        let clock = Arc::new(ManualClock::new(at(100)));
        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
        let category = Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe));
        registry.register(Box::new(Arc::clone(&category))).unwrap();
        let ledger = FakeLedger::new([
            (ResourceKind::HostMemoryBytes, 64 * GIB),
            (ResourceKind::CpuInitializationSlots, 16),
        ]);
        let coordinator = Coordinator::new(Arc::clone(&clock), session(1), ledger.clone());
        Self {
            clock,
            registry,
            category,
            ledger,
            port: FakeSandbox::new(),
            coordinator,
            execution: execution("exe-sandbox"),
        }
    }

    /// Launches the sandbox through to authority, on host evidence observed now.
    fn launch(&mut self) {
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
        let plan = LaunchPlan {
            execution: self.execution.clone(),
            tenant: TenantId::new("tenant-a").unwrap(),
            runtime: RuntimeRequirement::VmSandbox.admit(&offer).unwrap(),
            demand: BTreeMap::from([
                (ResourceKind::HostMemoryBytes, 16 * GIB),
                (ResourceKind::CpuInitializationSlots, 4),
            ]),
            priority: ReservationPriority::Background,
            authority_lifetime: Duration::from_secs(600),
            readiness_max_age: Duration::from_secs(5),
            runtime_evidence_max_age: HOUR,
        };
        let outcome = self
            .coordinator
            .launch(plan, &mut self.port, &self.registry)
            .unwrap();
        assert!(
            matches!(outcome, LaunchOutcome::AuthorityActive { .. }),
            "{outcome:?}"
        );
    }

    /// Recovers the coordinator through the store's restore, on clock session `run`.
    fn recover(
        &mut self,
        restore: StoreRestore,
        state: PersistedState,
        run: u128,
    ) -> StoreRecovery<TestClock, FakeLedger> {
        restore
            .recover(
                state,
                Arc::clone(&self.clock),
                session(run),
                self.ledger.clone(),
                &mut self.port,
            )
            .unwrap()
    }
}

/// S04, the whole protocol: a fresh directory, two persists (the receiver's record
/// included), a grant revoked after the last of them and kept only by the revocation
/// stream, a restart that adopts it, recovery, the restart's events on the recovery stream
/// and the persist that hands the new run out.
#[test]
fn a_persist_restart_and_restore_round_trip_adopts_a_revocation_from_the_stream() {
    let dirs = Dirs::new();
    let mut world = World::new();
    let of = world.execution.clone();
    let mut revocations = open_revocations(&dirs.revocations);
    let (mut store, takeover): (AuthorityStore, _) =
        AuthorityStore::open(&dirs.store, issuer(), owner()).unwrap();
    assert_eq!(takeover, Takeover::Fresh);
    // Nothing is stored before the store knows what its directory holds: here, nothing.
    assert_eq!(
        store.persist(&mut world.coordinator, None, &revocations),
        Err(StoreError::NotLoaded)
    );
    assert_eq!(store.load(&revocations).unwrap(), StoreLoad::Fresh);
    world.launch();
    let mut receiver = ReplayState::new(replay_config()).unwrap();
    assert_eq!(
        store
            .persist(&mut world.coordinator, Some(&mut receiver), &revocations)
            .unwrap(),
        StorePersisted {
            floor: 1,
            revocation_log: None
        }
    );
    // The run is handed out once its state is durable; the receiver takes a message once a
    // stored record covers it.
    let current = world.coordinator.scoped_epoch(issuer(), &of).unwrap();
    assert_eq!(current, scope(&world, 1));
    assert!(not_persisted(&mut receiver, &current));
    let second = store
        .persist(&mut world.coordinator, Some(&mut receiver), &revocations)
        .unwrap();
    assert_eq!(second.floor, 2);
    receiver
        .accept(&current, Nonce::new(1), MessageClass::Renewal)
        .unwrap();
    // After the last persist a grant is revoked; only the revocation stream keeps it.
    world.coordinator.revoke_grant(&of, grant("late")).unwrap();
    record_grant(&mut revocations, &world, grant("late"));

    // The engine restarts.
    store.release().unwrap();
    revocations.close().unwrap();
    let revocations = open_revocations(&dirs.revocations);
    let (mut store, takeover): (AuthorityStore, _) =
        AuthorityStore::open(&dirs.store, issuer(), owner()).unwrap();
    assert!(matches!(takeover, Takeover::Released { .. }));
    let (state, restore) = restored(store.load(&revocations).unwrap());
    assert_eq!(restore.standing, StateStanding::Sealed);
    assert_eq!(restore.floor, 2);
    assert!(restore.restore.is_current());
    assert_eq!(
        restore.rebuilt.tombstones_restored,
        BTreeMap::from([(of.clone(), BTreeSet::from([grant("late")]))])
    );
    assert!(restore.rebuilt.gaps.is_empty());
    assert!(state.revoked_grants[&of].contains(&grant("late")));
    // The receiver restarts from the record stored with the state: what it accepted before
    // is never accepted again.
    let mut restarted = ReplayState::restore(replay_config(), restore.replay()).unwrap();
    assert!(restarted
        .accept(&current, Nonce::new(1), MessageClass::Renewal)
        .is_err());

    let recovery = world.recover(restore, state, 2);
    assert!(matches!(
        recovery.report.sandboxes.get(&of),
        Some(SandboxRecovery::VmKeptWithoutAuthority { .. })
    ));
    assert!(recovery.coordinator.grant_revoked(&of, grant("late")));
    assert!(recovery.stale_ended.is_empty());
    assert!(recovery.revocations_completed.is_empty());
    let mut log = open_recovery(&dirs.recovery);
    assert!(recovery
        .publish(&operation("op-restart-2"), &mut log)
        .is_complete());
    let events = recovery_events(&log);
    assert_eq!(events, recovery.events());
    assert_eq!(
        events.first(),
        Some(&RecoveryEvent::adopted(&recovery.restore.rebuilt))
    );
    assert!(!events
        .iter()
        .any(|event| matches!(event, RecoveryEvent::FloorRaised { .. })));
    assert!(matches!(
        events.last(),
        Some(RecoveryEvent::Recovered { sandboxes: 1, .. })
    ));

    // The recovered run is handed out only once its state is stored.
    world.coordinator = recovery.coordinator;
    assert!(world.coordinator.current_incarnation().is_err());
    assert_eq!(
        store
            .persist(&mut world.coordinator, Some(&mut restarted), &revocations)
            .unwrap(),
        StorePersisted {
            floor: 3,
            revocation_log: EventSequence::new(1)
        }
    );
    assert_eq!(
        world.coordinator.current_incarnation(),
        Ok(Incarnation::new(2))
    );
    assert_eq!(store.floor().unwrap().incarnation(), Incarnation::new(2));
    assert_eq!(
        store.floor().unwrap().revocation_log(),
        EventSequence::new(1)
    );
}

/// The floor's write fails after the state's, which leaves the files as a crash between
/// the two stores does: on the first persist and on a later one. Each time the state is
/// above the floor, recovers as it is and is reported, and the next persist seals the
/// floor it named.
#[test]
fn a_crash_between_the_state_and_the_floor_recovers_the_state_as_it_is() {
    let dirs = Dirs::new();
    let mut world = World::new();
    let revocations = open_revocations(&dirs.revocations);
    let mut store = open_store(&dirs.store);
    store.load(&revocations).unwrap();
    world.launch();
    let blocked = block(&dirs, StoreFile::Floor);
    let failed = store
        .persist(&mut world.coordinator, None, &revocations)
        .unwrap_err();
    assert!(
        matches!(
            &failed,
            StoreError::Io {
                file: StoreFile::Floor,
                action: "write",
                ..
            }
        ),
        "{failed:?}"
    );
    assert!(failed.to_string().contains("floor.json"));
    assert!(dirs.file(StoreFile::State).is_file());
    assert!(!dirs.file(StoreFile::Floor).exists());
    fs::remove_dir(&blocked).unwrap();

    // The first state, with no floor yet.
    drop(store);
    let mut store = open_store(&dirs.store);
    let (state, restore) = restored(store.load(&revocations).unwrap());
    assert_eq!(restore.standing, StateStanding::Unsealed { floor: 0 });
    assert_eq!(restore.floor, 0);
    assert!(restore.restore.is_current());
    assert!(restore.restore.stale.is_empty());
    let recovery = world.recover(restore, state, 2);
    assert!(matches!(
        recovery.report.sandboxes.get(&world.execution),
        Some(SandboxRecovery::VmKeptWithoutAuthority { .. })
    ));
    assert!(!recovery
        .events()
        .iter()
        .any(|event| matches!(event, RecoveryEvent::FloorRaised { .. })));
    world.coordinator = recovery.coordinator;
    assert_eq!(
        store
            .persist(&mut world.coordinator, None, &revocations)
            .unwrap()
            .floor,
        1
    );

    // A later state, one floor ahead of the stored floor.
    let blocked = block(&dirs, StoreFile::Floor);
    assert!(store
        .persist(&mut world.coordinator, None, &revocations)
        .is_err());
    fs::remove_dir(&blocked).unwrap();
    drop(store);
    let mut store = open_store(&dirs.store);
    let (state, restore) = restored(store.load(&revocations).unwrap());
    assert_eq!(restore.standing, StateStanding::Unsealed { floor: 1 });
    assert!(restore.restore.is_current());
    assert_eq!(state.incarnation, Incarnation::new(2));
    let recovery = world.recover(restore, state, 3);
    world.coordinator = recovery.coordinator;
    assert_eq!(
        store
            .persist(&mut world.coordinator, None, &revocations)
            .unwrap()
            .floor,
        2
    );
    assert_eq!(
        world.coordinator.current_incarnation(),
        Ok(Incarnation::new(3))
    );
}

/// A failed state write, a failed floor write and a refused seal each confirm nothing: the
/// recovered coordinator still issues no lease id and hands out no run, the receiver still
/// takes no new message, and the files are as they were wherever the store stopped first.
#[test]
fn a_failed_write_or_a_refused_seal_confirms_nothing() {
    let dirs = Dirs::new();
    let mut world = World::new();
    let revocations = open_revocations(&dirs.revocations);
    let mut store = open_store(&dirs.store);
    store.load(&revocations).unwrap();
    world.launch();
    store
        .persist(&mut world.coordinator, None, &revocations)
        .unwrap();
    drop(store);
    let mut store = open_store(&dirs.store);
    let (state, restore) = restored(store.load(&revocations).unwrap());
    let mut receiver = ReplayState::restore(replay_config(), restore.replay()).unwrap();
    let mark = state.next_lease;
    world.coordinator = world.recover(restore, state, 2).coordinator;
    // The recovered coordinator issues no lease id: its limit is the persisted mark itself.
    let limit = world.coordinator.lease_id_limit();
    assert_eq!(limit, mark);
    let scope = scope(&world, 2);
    assert!(not_persisted(&mut receiver, &scope));
    let stored_state = fs::read(dirs.file(StoreFile::State)).unwrap();
    let stored_floor = fs::read(dirs.file(StoreFile::Floor)).unwrap();

    let blocked = block(&dirs, StoreFile::State);
    assert!(matches!(
        store.persist(&mut world.coordinator, Some(&mut receiver), &revocations),
        Err(StoreError::Io {
            file: StoreFile::State,
            ..
        })
    ));
    fs::remove_dir(&blocked).unwrap();
    assert_eq!(fs::read(dirs.file(StoreFile::State)).unwrap(), stored_state);
    let blocked = block(&dirs, StoreFile::Floor);
    assert!(matches!(
        store.persist(&mut world.coordinator, Some(&mut receiver), &revocations),
        Err(StoreError::Io {
            file: StoreFile::Floor,
            ..
        })
    ));
    fs::remove_dir(&blocked).unwrap();
    assert_eq!(fs::read(dirs.file(StoreFile::Floor)).unwrap(), stored_floor);
    assert_eq!(world.coordinator.lease_id_limit(), limit);
    assert!(world.coordinator.current_incarnation().is_err());
    assert!(not_persisted(&mut receiver, &scope));

    // A coordinator without the sandbox the floor keeps is below it: the seal refuses it
    // before anything is written.
    let mut fresh: TestCoordinator =
        Coordinator::new(Arc::clone(&world.clock), session(9), world.ledger.clone());
    let written = fs::read(dirs.file(StoreFile::State)).unwrap();
    match store.persist(&mut fresh, None, &revocations) {
        Err(StoreError::Regression(regression)) => {
            assert!(regression
                .regressions
                .contains(&Regression::SandboxMissing {
                    execution: world.execution.clone()
                }))
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(fs::read(dirs.file(StoreFile::State)).unwrap(), written);
    assert_eq!(fs::read(dirs.file(StoreFile::Floor)).unwrap(), stored_floor);
    assert!(fresh.current_incarnation().is_err());

    // Once both writes succeed, both are confirmed; the retry sealed from the same floor.
    assert_eq!(
        store
            .persist(&mut world.coordinator, Some(&mut receiver), &revocations)
            .unwrap()
            .floor,
        2
    );
    assert!(world.coordinator.lease_id_limit() > limit);
    assert_eq!(
        world.coordinator.current_incarnation(),
        Ok(Incarnation::new(2))
    );
    receiver
        .accept(&scope, Nonce::new(1), MessageClass::Renewal)
        .unwrap();
}

/// S04 / M17, a restored snapshot: the sandbox is revoked after one persist and before the
/// next, with its VM still running and the revocation on no stream, and the older state is
/// then copied back over the newer one. The state is raised to the floor, the sandbox's VM,
/// which recovery would keep for a fresh grant, is ended, and what the floor raised is
/// published.
#[test]
fn an_older_state_copied_back_is_raised_and_its_sandbox_ended_never_revived() {
    let dirs = Dirs::new();
    let mut world = World::new();
    let of = world.execution.clone();
    let revocations = open_revocations(&dirs.revocations);
    let mut store = open_store(&dirs.store);
    store.load(&revocations).unwrap();
    world.launch();
    store
        .persist(&mut world.coordinator, None, &revocations)
        .unwrap();
    let older = fs::read(dirs.file(StoreFile::State)).unwrap();
    let older_generations = world.coordinator.sandbox(&of).unwrap().generations();
    let vm = world.coordinator.sandbox(&of).unwrap().vm().unwrap();
    world.coordinator.revoke(&of).unwrap();
    let revoked = world.coordinator.sandbox(&of).unwrap().generations();
    assert!(revoked.authorization > older_generations.authorization);
    assert_eq!(
        store
            .persist(&mut world.coordinator, None, &revocations)
            .unwrap()
            .floor,
        2
    );

    drop(store);
    fs::write(dirs.file(StoreFile::State), &older).unwrap();
    let mut store = open_store(&dirs.store);
    let (state, restore) = restored(store.load(&revocations).unwrap());
    assert_eq!(
        restore.standing,
        StateStanding::Older {
            sealed_into: 1,
            floor: 2
        }
    );
    assert_eq!(restore.restore.stale, BTreeSet::from([of.clone()]));
    assert!(restore
        .restore
        .upgrades
        .contains(&FloorUpgrade::SandboxRaised {
            execution: of.clone(),
            from: older_generations,
            to: revoked,
        }));

    let recovery = world.recover(restore, state, 2);
    assert!(matches!(
        recovery.report.sandboxes.get(&of),
        Some(SandboxRecovery::VmKeptWithoutAuthority { vm: kept, .. }) if *kept == vm
    ));
    let ended = recovery.stale_ended[&of].as_ref().unwrap();
    assert!(ended
        .compensations
        .contains(&Compensation::TerminateVm { vm }));
    assert_eq!(
        recovery.coordinator.sandbox(&of).unwrap().state(),
        SandboxState::Stopped
    );
    assert!(!world.port.live.contains_key(&vm));
    let mut log = open_recovery(&dirs.recovery);
    assert!(recovery
        .publish(&operation("op-restart-2"), &mut log)
        .is_complete());
    let events = recovery_events(&log);
    assert_eq!(
        events[1],
        RecoveryEvent::FloorRaised {
            floor: 2,
            upgrades: recovery.restore.restore.upgrades.clone(),
            stale: BTreeSet::from([of.clone()]),
        }
    );
    assert!(matches!(events[2], RecoveryEvent::Sandbox { .. }));

    // The raised and recovered state seals the next floor.
    world.coordinator = recovery.coordinator;
    assert_eq!(
        store
            .persist(&mut world.coordinator, None, &revocations)
            .unwrap()
            .floor,
        3
    );
    assert!(
        world
            .coordinator
            .sandbox(&of)
            .unwrap()
            .generations()
            .authorization
            > revoked.authorization
    );
}

/// A floor without its state, a state whose floor was removed and a floor rolled back
/// behind its state are refused, nothing is replaced, and nothing is stored after a
/// refused load.
#[test]
fn a_floor_without_its_state_or_a_state_without_its_floor_is_refused() {
    let dirs = Dirs::new();
    let mut world = World::new();
    let revocations = open_revocations(&dirs.revocations);
    let mut store = open_store(&dirs.store);
    store.load(&revocations).unwrap();
    world.launch();
    store
        .persist(&mut world.coordinator, None, &revocations)
        .unwrap();
    let first_floor = fs::read(dirs.file(StoreFile::Floor)).unwrap();
    for _ in 0..2 {
        store
            .persist(&mut world.coordinator, None, &revocations)
            .unwrap();
    }
    drop(store);
    let state = fs::read(dirs.file(StoreFile::State)).unwrap();
    let floor = fs::read(dirs.file(StoreFile::Floor)).unwrap();

    fs::remove_file(dirs.file(StoreFile::State)).unwrap();
    let mut store = open_store(&dirs.store);
    assert_eq!(
        store.load(&revocations),
        Err(StoreError::StateMissing { floor: 3 })
    );
    assert_eq!(
        store.persist(&mut world.coordinator, None, &revocations),
        Err(StoreError::NotLoaded)
    );
    assert!(!dirs.file(StoreFile::State).exists());

    fs::write(dirs.file(StoreFile::State), &state).unwrap();
    fs::remove_file(dirs.file(StoreFile::Floor)).unwrap();
    assert_eq!(
        store.load(&revocations),
        Err(StoreError::FloorMissing { sealed_into: 3 })
    );
    fs::write(dirs.file(StoreFile::Floor), &first_floor).unwrap();
    let refused = store.load(&revocations).unwrap_err();
    assert_eq!(
        refused,
        StoreError::FloorBehindState {
            floor: 1,
            sealed_into: 3
        }
    );
    assert!(refused.to_string().contains("rolled back"));
    assert_eq!(fs::read(dirs.file(StoreFile::Floor)).unwrap(), first_floor);

    fs::write(dirs.file(StoreFile::Floor), &floor).unwrap();
    let (_, restore) = restored(store.load(&revocations).unwrap());
    assert_eq!(restore.standing, StateStanding::Sealed);
}

/// Torn and edited files, the floor under the state's name, another format and a body
/// that matches its digest but not its record are each refused with the file named, and
/// left as they are.
#[test]
fn torn_edited_or_misplaced_files_are_refused_and_named() {
    let dirs = Dirs::new();
    let mut world = World::new();
    let revocations = open_revocations(&dirs.revocations);
    let mut store = open_store(&dirs.store);
    store.load(&revocations).unwrap();
    world.launch();
    store
        .persist(&mut world.coordinator, None, &revocations)
        .unwrap();
    let state = fs::read(dirs.file(StoreFile::State)).unwrap();
    let floor = fs::read(dirs.file(StoreFile::Floor)).unwrap();
    let newline = state.iter().position(|byte| *byte == b'\n').unwrap();
    let body = &state[newline + 1..];

    let mut flipped_state = state.clone();
    let last = flipped_state.len() - 3;
    flipped_state[last] ^= 0x01;
    let mut flipped_floor = floor.clone();
    let last = flipped_floor.len() - 3;
    flipped_floor[last] ^= 0x01;
    let other_format = [
        serde_json::to_vec(&serde_json::json!({
            "file": "state",
            "format": 2,
            "digest": "0".repeat(64),
        }))
        .unwrap()
        .as_slice(),
        b"\n",
        body,
    ]
    .concat();
    let unknown_header = [
        &state[..newline - 1],
        br#","note":"x"}"#.as_slice(),
        b"\n",
        body,
    ]
    .concat();
    // A body with a field its record does not have, under a digest that matches it.
    let mut value: serde_json::Value = serde_json::from_slice(body).unwrap();
    value["note"] = serde_json::json!("x");
    let extra_body = serde_json::to_vec(&value).unwrap();
    let digest = DigestBuilder::new("yougori/coordination/authority-store/v1")
        .str("state")
        .u64(1)
        .bytes(&extra_body)
        .finish();
    let extra_field = [
        serde_json::to_vec(&serde_json::json!({
            "file": "state",
            "format": 1,
            "digest": digest.to_hex(),
        }))
        .unwrap()
        .as_slice(),
        b"\n",
        extra_body.as_slice(),
    ]
    .concat();

    let cases: Vec<(StoreFile, Vec<u8>, FileProblem)> = vec![
        (
            StoreFile::State,
            state[..state.len() / 2].to_vec(),
            FileProblem::Digest,
        ),
        (StoreFile::State, flipped_state, FileProblem::Digest),
        (StoreFile::Floor, flipped_floor, FileProblem::Digest),
        (
            StoreFile::State,
            floor.clone(),
            FileProblem::OtherFile {
                found: StoreFile::Floor,
            },
        ),
        (
            StoreFile::State,
            other_format,
            FileProblem::Format { found: 2 },
        ),
    ];
    for (file, bytes, problem) in cases {
        fs::write(dirs.file(file), &bytes).unwrap();
        let refused = store.load(&revocations).unwrap_err();
        assert_eq!(
            refused,
            StoreError::Unreadable {
                file,
                path: store.directory().join(file.name()),
                problem,
            }
        );
        assert!(refused.to_string().contains(file.name()), "{refused}");
        assert_eq!(fs::read(dirs.file(file)).unwrap(), bytes);
        fs::write(dirs.file(StoreFile::State), &state).unwrap();
        fs::write(dirs.file(StoreFile::Floor), &floor).unwrap();
    }
    for bytes in [
        state[..newline / 2].to_vec(),
        Vec::new(),
        unknown_header,
        extra_field,
    ] {
        fs::write(dirs.file(StoreFile::State), &bytes).unwrap();
        let refused = store.load(&revocations).unwrap_err();
        assert!(
            matches!(
                &refused,
                StoreError::Unreadable {
                    file: StoreFile::State,
                    problem: FileProblem::Header { .. } | FileProblem::Body { .. },
                    ..
                }
            ),
            "{refused:?}"
        );
        assert_eq!(fs::read(dirs.file(StoreFile::State)).unwrap(), bytes);
    }
    fs::write(dirs.file(StoreFile::State), &state).unwrap();
    let (_, restore) = restored(store.load(&revocations).unwrap());
    assert_eq!(restore.standing, StateStanding::Sealed);
}

/// S06 through the store: the sandbox is revoked after the last persist and only the
/// revocation stream keeps it. The restore adopts it, recovery keeps the VM without
/// authority, and the revocation then ends the sandbox; how it ended follows the closing
/// summary on the recovery stream.
#[test]
fn a_revocation_the_state_predates_ends_its_sandbox_after_the_restore() {
    let dirs = Dirs::new();
    let mut world = World::new();
    let of = world.execution.clone();
    let mut revocations = open_revocations(&dirs.revocations);
    let mut store = open_store(&dirs.store);
    store.load(&revocations).unwrap();
    world.launch();
    store
        .persist(&mut world.coordinator, None, &revocations)
        .unwrap();
    let vm = world.coordinator.sandbox(&of).unwrap().vm().unwrap();
    let notice = world.coordinator.revoke(&of).unwrap();
    let context = EventContext::new(operation("op-revoke"), Phase::Revoked)
        .with_generations(Generations::NONE.with_authorization(notice.current));
    revocations
        .record(
            context,
            notice.at,
            Revocation {
                execution: of.clone(),
                epoch: notice.current,
                reason: RevocationReason::UserRequested,
            },
        )
        .unwrap();

    drop(store);
    revocations.close().unwrap();
    let revocations = open_revocations(&dirs.revocations);
    let mut store = open_store(&dirs.store);
    let (state, restore) = restored(store.load(&revocations).unwrap());
    assert_eq!(restore.standing, StateStanding::Sealed);
    assert!(restore.restore.is_current());
    assert_eq!(
        restore.rebuilt.unpersisted.keys().collect::<Vec<_>>(),
        [&of]
    );
    let recovery = world.recover(restore, state, 2);
    assert!(matches!(
        recovery.report.sandboxes.get(&of),
        Some(SandboxRecovery::VmKeptWithoutAuthority { .. })
    ));
    assert!(recovery.stale_ended.is_empty());
    let ended = recovery.revocations_completed[&of].as_ref().unwrap();
    assert!(ended.contains(&Compensation::TerminateVm { vm }));
    assert_eq!(
        recovery.coordinator.sandbox(&of).unwrap().state(),
        SandboxState::Stopped
    );
    let mut log = open_recovery(&dirs.recovery);
    assert!(recovery
        .publish(&operation("op-restart-2"), &mut log)
        .is_complete());
    let events = recovery_events(&log);
    let closing = events
        .iter()
        .position(|event| matches!(event, RecoveryEvent::Recovered { .. }))
        .unwrap();
    assert_eq!(
        events[closing + 1..],
        [RecoveryEvent::RevocationCompleted {
            execution: of.clone(),
            compensations: ended.clone(),
        }]
    );
}

/// One writer per directory, through the durable streams' owner lock.
#[test]
fn a_second_store_on_the_same_directory_is_refused() {
    let dirs = Dirs::new();
    let (store, takeover): (AuthorityStore, _) =
        AuthorityStore::open(&dirs.store, issuer(), owner()).unwrap();
    assert_eq!(takeover, Takeover::Fresh);
    assert!(matches!(
        AuthorityStore::<PersistedState>::open(&dirs.store, issuer(), owner()),
        Err(StoreError::Owner(OwnerError::HeldInProcess { .. }))
    ));
    // Another path to the same directory is the same store.
    assert!(matches!(
        AuthorityStore::<PersistedState>::open(&dirs.store.join("."), issuer(), owner()),
        Err(StoreError::Owner(OwnerError::HeldInProcess { .. }))
    ));
    drop(store);
    let (_, takeover): (AuthorityStore, _) =
        AuthorityStore::open(&dirs.store, issuer(), owner()).unwrap();
    assert!(matches!(takeover, Takeover::Released { .. }));
}

/// A revocation stream replaced by an empty one is behind the floor; one replaced by a
/// longer one passes the floor but does not continue the cursor stored with the state.
/// Both are refused; the stream itself loads.
#[test]
fn a_revocation_stream_behind_the_floor_or_replaced_refuses_the_load() {
    let dirs = Dirs::new();
    let mut world = World::new();
    world.launch();
    let mut revocations = open_revocations(&dirs.revocations);
    for name in ["first", "second"] {
        world
            .coordinator
            .revoke_grant(&world.execution, grant(name))
            .unwrap();
        record_grant(&mut revocations, &world, grant(name));
    }
    let mut store = open_store(&dirs.store);
    store.load(&revocations).unwrap();
    assert_eq!(
        store
            .persist(&mut world.coordinator, None, &revocations)
            .unwrap()
            .revocation_log,
        EventSequence::new(2)
    );
    drop(store);
    revocations.close().unwrap();

    let empty = open_revocations(&dirs.root.join("empty"));
    let mut store = open_store(&dirs.store);
    assert_eq!(
        store.load(&empty),
        Err(StoreError::Floor(FloorRefusal::RevocationLogBehind {
            floor: EventSequence::new(2).unwrap(),
            found: None,
        }))
    );
    let mut longer = open_revocations(&dirs.root.join("longer"));
    for name in ["a", "b", "c"] {
        record_grant(&mut longer, &world, grant(name));
    }
    assert!(matches!(
        store.load(&longer),
        Err(StoreError::Revocations(LogError::Cursor(
            CursorError::WrongStream { .. }
        )))
    ));
    assert_eq!(
        store.persist(&mut world.coordinator, None, &longer),
        Err(StoreError::NotLoaded)
    );

    let revocations = open_revocations(&dirs.revocations);
    let (state, restore) = restored(store.load(&revocations).unwrap());
    assert_eq!(restore.rebuilt, Default::default());
    assert_eq!(
        state.revoked_grants[&world.execution],
        BTreeSet::from([grant("first"), grant("second")])
    );
}

/// Another authority's floor in this directory, and this directory opened as another
/// authority, are refused.
#[test]
fn another_authoritys_floor_or_state_is_refused() {
    let dirs = Dirs::new();
    let mut world = World::new();
    world.launch();
    let revocations = open_revocations(&dirs.revocations);
    let mut store = open_store(&dirs.store);
    store.load(&revocations).unwrap();
    store
        .persist(&mut world.coordinator, None, &revocations)
        .unwrap();
    drop(store);
    let other = AuthorityIssuer {
        host: HostId::named("host-b"),
        issuer: issuer().issuer,
    };
    let theirs = dirs.root.join("theirs");
    let (mut store, _): (AuthorityStore, _) =
        AuthorityStore::open(&theirs, other, owner()).unwrap();
    store.load(&revocations).unwrap();
    store
        .persist(&mut world.coordinator, None, &revocations)
        .unwrap();
    drop(store);
    let ours = fs::read(dirs.file(StoreFile::Floor)).unwrap();
    fs::copy(theirs.join("floor.json"), dirs.file(StoreFile::Floor)).unwrap();

    let mut store = open_store(&dirs.store);
    assert_eq!(
        store.load(&revocations),
        Err(StoreError::Floor(FloorRefusal::ForeignFloor {
            floor: other
        }))
    );
    drop(store);
    fs::write(dirs.file(StoreFile::Floor), &ours).unwrap();
    let (mut store, _): (AuthorityStore, _) =
        AuthorityStore::open(&dirs.store, other, owner()).unwrap();
    assert_eq!(
        store.load(&revocations),
        Err(StoreError::ForeignState { state: issuer() })
    );
}

/// The new recovery outcome reads back strictly, and a current restore raises none.
#[test]
fn a_floor_raised_event_reads_back_strictly() {
    let current = FloorRestore {
        upgrades: Vec::new(),
        stale: BTreeSet::new(),
        replay: ReplayRecord::default(),
    };
    assert_eq!(RecoveryEvent::raised(4, &current), None);
    let raised = FloorRestore {
        upgrades: vec![FloorUpgrade::NextLease {
            from: LeaseId::new(3),
            to: LeaseId::new(9),
        }],
        stale: BTreeSet::from([execution("exe-a")]),
        ..current
    };
    let event = RecoveryEvent::raised(4, &raised).unwrap();
    assert_eq!(
        event,
        RecoveryEvent::FloorRaised {
            floor: 4,
            upgrades: raised.upgrades.clone(),
            stale: raised.stale.clone(),
        }
    );
    let json = serde_json::to_value(&event).unwrap();
    assert_eq!(json["outcome"], "floor_raised");
    assert_eq!(
        serde_json::from_value::<RecoveryEvent>(json.clone()).unwrap(),
        event
    );
    let mut extra = json;
    extra["note"] = serde_json::json!("x");
    assert!(serde_json::from_value::<RecoveryEvent>(extra).is_err());
    assert_eq!(event.phase(), Phase::Restoring);
    assert_eq!(event.generations(), Generations::NONE);
}
