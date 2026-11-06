//! Test doubles (tests only): signals, policies and bounds; a capacity port that grants
//! everything, a quiet sandbox backend and a launched coordinator; in-memory audit storage
//! and spool that can be told to refuse; the CORE-06 hub; the coordinator's durable
//! revocation stream on a temporary directory; and a fake sandbox host holding user-data
//! identities, which applies response actions as the runtime would. Nothing else here
//! touches the host.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::num::NonZeroU32;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::foundation::coordination::{
    BootRequest, CapacityPort, CapacityRefusal, Coordinator, ExecutionCancellation, LaunchOutcome,
    LaunchPlan, LeaseTerms, ObservedVm, PerimeterId, PortFailure, PortOperation, Readiness,
    ReadinessReport, ReconcileReport, ReleaseOutcome, ReservationKey, ReservationPriority,
    ReservationRequest, ReserveOutcome, ResourceKind, RestoredVmReport, ReturnHold, SandboxPort,
    SettingsGrant, SnapshotManifest, VmInstanceId,
};
use crate::foundation::events::{
    AuditAppendAuthority, AuditConfig, AuditEntry, AuditFailurePolicy, AuditJournal, AuditRecord,
    AuditSpool, AuditStore, DurableStreamId, EmissionLimit, EventHub, HubConfig, JournalId,
    LogConfig, MetricsConfig, OpenReport, ProducerId, ProducerIncarnation, ProgressConfig,
    RedactionPolicy, RevocationConfig, RevocationIssuer, RevocationLog, StoreRefusal,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Backend, BackendRelease, Capability, ClockSession, ConfigurationFingerprint, Observation,
    ProbeRegistry, RuntimeOffer, RuntimeRequirement, RuntimeSubject, SourceClass, Subject,
    SupportDetail,
};
use crate::foundation::ids::{
    digest, Clock, Digest, ExecutionCategory, ExecutionId, ManualClock, MonotonicTime,
    SandboxBootGeneration, TenantId,
};
use crate::sandbox_contract::files::{SandboxClass, ViolationAction, VolumeClass};

pub const SECOND: Duration = Duration::from_secs(1);
pub const MINUTE: Duration = Duration::from_secs(60);
pub const HOUR: Duration = Duration::from_secs(3_600);

/// Where every test clock starts: 1,000 s after its origin.
pub const START_SECONDS: u64 = 1_000;

pub fn at(seconds: u64) -> MonotonicTime {
    MonotonicTime::from_nanos(seconds * 1_000_000_000)
}

pub fn session(number: u128) -> ClockSession {
    ClockSession::from_uuid(uuid::Uuid::from_u128(number))
}

/// The host's clock session in these tests.
pub fn host_session() -> ClockSession {
    session(1)
}

pub fn clock() -> ManualClock {
    ManualClock::new(at(START_SECONDS))
}

pub fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

pub fn subject(name: &str) -> Digest {
    digest("yougori/test/subject/v1", &[name.as_bytes()])
}

pub fn grant(name: &str) -> GrantRef {
    GrantRef::from_digest(digest("yougori/test/grant/v1", &[name.as_bytes()]))
}

pub fn limit(max_events: u32, window: Duration) -> EmissionLimit {
    EmissionLimit::new(max_events, window).unwrap()
}

/// Observations older than 30 s are stale.
pub fn uncertain() -> UncertainPolicy {
    UncertainPolicy::new(30 * SECOND).unwrap()
}

/// Default triggers; three notifications per sandbox and minute.
pub fn policies() -> ResponsePolicies {
    ResponsePolicies::with_default_triggers(NotifyPolicy::new(limit(3, MINUTE)), uncertain())
}

/// Two repeats per sandbox and minute; 64 incidents; 16 sandboxes.
pub fn bounds() -> ResponseBounds {
    ResponseBounds::new(limit(2, MINUTE), 64, 16).unwrap()
}

pub fn violation(kind: ViolationKind) -> SignalClass {
    SignalClass::Violation { kind }
}

pub fn resource(resource: MonitoredResource) -> SignalClass {
    SignalClass::Resource { resource }
}

pub fn host(observer: HostObserver) -> SignalSource {
    SignalSource::HostObserved { observer }
}

/// The first host observer that can see `class`.
pub fn observer_for(class: SignalClass) -> HostObserver {
    class.host_observers()[0]
}

/// A draft about `sandbox` observed at `observed_at` on the host session.
pub fn draft(
    sandbox: &str,
    class: SignalClass,
    source: SignalSource,
    reading: Reading,
    observed_at: MonotonicTime,
) -> SignalDraft {
    SignalDraft {
        sandbox: execution(sandbox),
        class,
        source,
        subject: subject(class.label()),
        reading,
        observed_at,
        session: host_session(),
        violated_grant: None,
    }
}

/// A host observation of `kind` by its first observer.
pub fn host_violation(
    sandbox: &str,
    kind: ViolationKind,
    observed_at: MonotonicTime,
) -> MonitoringSignal {
    let class = violation(kind);
    MonitoringSignal::new(draft(
        sandbox,
        class,
        host(observer_for(class)),
        Reading::ViolationObserved,
        observed_at,
    ))
    .unwrap()
}

/// A host check of `kind`'s subject by `observer` that found nothing.
pub fn host_check_passed(
    sandbox: &str,
    kind: ViolationKind,
    observer: HostObserver,
    observed_at: MonotonicTime,
) -> MonitoringSignal {
    MonitoringSignal::new(draft(
        sandbox,
        violation(kind),
        host(observer),
        Reading::CheckPassed,
        observed_at,
    ))
    .unwrap()
}

/// A guest report of `kind`.
pub fn guest_violation(
    sandbox: &str,
    kind: ViolationKind,
    observed_at: MonotonicTime,
) -> MonitoringSignal {
    MonitoringSignal::new(draft(
        sandbox,
        violation(kind),
        SignalSource::GuestReported,
        Reading::ViolationObserved,
        observed_at,
    ))
    .unwrap()
}

/// A resource sample of `amount` from `source`.
pub fn sample(
    sandbox: &str,
    monitored: MonitoredResource,
    source: SignalSource,
    amount: u64,
    observed_at: MonotonicTime,
) -> MonitoringSignal {
    MonitoringSignal::new(draft(
        sandbox,
        resource(monitored),
        source,
        Reading::Amount { amount },
        observed_at,
    ))
    .unwrap()
}

/// A fresh host assessment of `class` about `sandbox`, through the real assessment paths.
pub fn fresh_host_assessment(
    sandbox: &str,
    kind: ViolationKind,
    now: &ManualClock,
) -> SignalAssessment {
    let signal = host_violation(sandbox, kind, now.now());
    match assess_violation(&[signal], &uncertain(), now, host_session()).unwrap() {
        Assessment::Signal(assessment) => assessment,
        other => panic!("{other:?}"),
    }
}

/// The same with a violated grant.
pub fn fresh_host_assessment_with_grant(
    sandbox: &str,
    kind: ViolationKind,
    violated: GrantRef,
    now: &ManualClock,
) -> SignalAssessment {
    let class = violation(kind);
    let mut signal = draft(
        sandbox,
        class,
        host(observer_for(class)),
        Reading::ViolationObserved,
        now.now(),
    );
    signal.violated_grant = Some(violated);
    let signal = MonitoringSignal::new(signal).unwrap();
    match assess_violation(&[signal], &uncertain(), now, host_session()).unwrap() {
        Assessment::Signal(assessment) => assessment,
        other => panic!("{other:?}"),
    }
}

/// The responder's outcome as a record.
pub fn responded(outcome: ResponseOutcome) -> ResponseRecord {
    match outcome {
        ResponseOutcome::Responded(record) => record,
        other => panic!("expected a response, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------
// CORE-04 world

/// A capacity port that grants every reservation.
#[derive(Debug, Default)]
pub struct GrantAll;

impl CapacityPort for GrantAll {
    fn reserve(
        &mut self,
        _request: &ReservationRequest,
    ) -> Result<ReserveOutcome, CapacityRefusal> {
        Ok(ReserveOutcome::Granted)
    }

    fn begin_create(&mut self, _key: &ReservationKey) -> Result<(), CapacityRefusal> {
        Ok(())
    }

    fn release(&mut self, _key: &ReservationKey) -> Result<ReleaseOutcome, CapacityRefusal> {
        Ok(ReleaseOutcome::Pending)
    }

    fn confirm_release(
        &mut self,
        _key: &ReservationKey,
        _source: SourceClass,
    ) -> Result<ReleaseOutcome, CapacityRefusal> {
        Ok(ReleaseOutcome::Released)
    }

    fn cancel_execution(
        &mut self,
        _execution: &ExecutionId,
    ) -> Result<ExecutionCancellation, CapacityRefusal> {
        Ok(ExecutionCancellation::default())
    }

    fn reconcile(
        &mut self,
        _execution: &ExecutionId,
        expected: &BTreeSet<ReservationKey>,
    ) -> Result<ReconcileReport, CapacityRefusal> {
        Ok(ReconcileReport {
            confirmed: expected.clone(),
            ..ReconcileReport::default()
        })
    }

    fn begin_hold(
        &mut self,
        _resources: &BTreeSet<ResourceKind>,
    ) -> Result<ReturnHold, CapacityRefusal> {
        Ok(ReturnHold::new(1))
    }

    fn end_hold(&mut self, _hold: ReturnHold) -> Result<(), CapacityRefusal> {
        Ok(())
    }
}

/// A sandbox backend that creates fresh VMs, reports them ready to a host probe and
/// records terminations. It has no snapshots and touches no volume.
#[derive(Debug, Default)]
pub struct QuietBackend {
    pub running: Vec<ObservedVm>,
    pub terminated: Vec<VmInstanceId>,
    pub perimeters_removed: usize,
}

impl SandboxPort for QuietBackend {
    fn prepare_perimeter(&mut self, request: &BootRequest) -> Result<PerimeterId, PortFailure> {
        Ok(PerimeterId::new(digest(
            "yougori/test/perimeter/v1",
            &[
                request.execution.as_str().as_bytes(),
                &request.generations.boot.get().to_be_bytes(),
            ],
        )))
    }

    fn create_vm(
        &mut self,
        request: &BootRequest,
        _perimeter: &PerimeterId,
    ) -> Result<VmInstanceId, PortFailure> {
        let vm = VmInstanceId::new(digest(
            "yougori/test/vm/v1",
            &[
                request.execution.as_str().as_bytes(),
                &request.generations.boot.get().to_be_bytes(),
            ],
        ));
        self.running.push(ObservedVm {
            vm,
            execution: request.execution.clone(),
            boot: request.generations.boot,
        });
        Ok(vm)
    }

    fn restore_vm(
        &mut self,
        _request: &BootRequest,
        _perimeter: &PerimeterId,
        _snapshot: &SnapshotManifest,
    ) -> Result<VmInstanceId, PortFailure> {
        Err(PortFailure {
            operation: PortOperation::RestoreVm,
            detail: "no snapshots in these tests".into(),
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
        _vm: &VmInstanceId,
        _boot: SandboxBootGeneration,
    ) -> RestoredVmReport {
        unreachable!("these tests never restore a VM")
    }

    fn terminate_vm(&mut self, vm: &VmInstanceId) -> Result<(), PortFailure> {
        self.running.retain(|observed| observed.vm != *vm);
        self.terminated.push(*vm);
        Ok(())
    }

    fn teardown_perimeter(&mut self, _perimeter: &PerimeterId) -> Result<(), PortFailure> {
        self.perimeters_removed += 1;
        Ok(())
    }

    fn list_vms(&mut self) -> Result<Vec<ObservedVm>, PortFailure> {
        Ok(self.running.clone())
    }
}

fn configuration() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_digest(digest("yougori/test/configuration/v1", &[b"launch"]))
}

/// A coordinator on a shared manual clock with host evidence that one runtime is a VM
/// sandbox.
pub struct World {
    pub clock: Arc<ManualClock>,
    registry: ProbeRegistry<Arc<ManualClock>>,
    category: Arc<FakeProbe>,
    runtime: RuntimeSubject,
    pub port: QuietBackend,
    pub coordinator: Coordinator<Arc<ManualClock>, GrantAll>,
}

impl World {
    pub fn new() -> Self {
        let clock = Arc::new(clock());
        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
        let category = Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe));
        registry.register(Box::new(Arc::clone(&category))).unwrap();
        let coordinator = Coordinator::new(Arc::clone(&clock), session(2), GrantAll);
        Self {
            clock,
            registry,
            category,
            runtime: RuntimeSubject {
                category: ExecutionCategory::VmSandbox,
                release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
                instance: digest("yougori/test/instance/v1", &[b"vm-host-1"]),
            },
            port: QuietBackend::default(),
            coordinator,
        }
    }

    fn plan(&mut self, of: &ExecutionId) -> LaunchPlan {
        let subject = Subject::Runtime(self.runtime.clone());
        self.category.respond(
            &subject,
            Observation::supported(
                configuration(),
                HOUR,
                SupportDetail::RuntimeCategory {
                    category: ExecutionCategory::VmSandbox,
                },
            ),
        );
        self.registry
            .refresh(Capability::RuntimeCategory, &subject)
            .unwrap();
        let offer =
            RuntimeOffer::observe(&self.registry, self.runtime.clone(), HOUR, configuration())
                .unwrap();
        LaunchPlan {
            execution: of.clone(),
            tenant: TenantId::new("tenant-a").unwrap(),
            runtime: RuntimeRequirement::VmSandbox.admit(&offer).unwrap(),
            demand: BTreeMap::from([(ResourceKind::HostMemoryBytes, 1 << 30)]),
            priority: ReservationPriority::Background,
            authority_lifetime: HOUR,
            readiness_max_age: 5 * SECOND,
            runtime_evidence_max_age: HOUR,
        }
    }

    /// Launches `of` to authority_active, then running.
    pub fn launch(&mut self, of: &ExecutionId) {
        let plan = self.plan(of);
        let outcome = self
            .coordinator
            .launch_with(
                plan,
                SettingsGrant::default(),
                &mut self.port,
                &self.registry,
            )
            .unwrap();
        assert!(
            matches!(outcome, LaunchOutcome::AuthorityActive { .. }),
            "{outcome:?}"
        );
        self.coordinator.start_running(of).unwrap();
    }

    /// Whether `of` can still start child work: the authoritative check of §6.3. A probe
    /// lease that was granted is released at once.
    pub fn has_authority(&mut self, of: &ExecutionId) -> bool {
        match self.coordinator.start_child_work(
            of,
            crate::foundation::ids::OperationId::new("op-probe").unwrap(),
            crate::foundation::coordination::LeaseKind::ChildWork,
            terms(),
        ) {
            Ok(lease) => {
                self.coordinator.release_lease(lease.id()).unwrap();
                true
            }
            Err(_) => false,
        }
    }

    /// The authorization epoch `of` is at.
    pub fn epoch(&self, of: &ExecutionId) -> crate::foundation::ids::AuthorizationEpoch {
        self.coordinator
            .sandbox(of)
            .unwrap()
            .generations()
            .authorization
    }
}

pub fn terms() -> LeaseTerms {
    LeaseTerms {
        term: MINUTE,
        max_lifetime: HOUR,
        cancel_within: 5 * SECOND,
    }
}

// ---------------------------------------------------------------------------------------
// CORE-06 plane

/// Audit storage in memory; it can be told to refuse everything.
#[derive(Clone, Debug, Default)]
pub struct MemoryAuditStore {
    pub records: Rc<RefCell<Vec<AuditRecord>>>,
    pub refuse: Rc<RefCell<Option<StoreRefusal>>>,
}

impl AuditStore for MemoryAuditStore {
    fn append(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        if let Some(refusal) = *self.refuse.borrow() {
            return Err(refusal);
        }
        let mut records = self.records.borrow_mut();
        if !records.contains(record) {
            records.push(record.clone());
        }
        Ok(())
    }
}

impl MemoryAuditStore {
    /// How many stored records are revocations.
    pub fn revocations(&self) -> usize {
        self.records
            .borrow()
            .iter()
            .filter(|record| matches!(record.event().payload(), AuditEntry::Revocation { .. }))
            .count()
    }
}

/// A bounded spool in memory; it can be told to refuse everything.
#[derive(Clone, Debug, Default)]
pub struct MemorySpool {
    pub records: Rc<RefCell<VecDeque<AuditRecord>>>,
    pub refuse: Rc<RefCell<bool>>,
}

impl AuditSpool for MemorySpool {
    fn push(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        if *self.refuse.borrow() {
            return Err(StoreRefusal::Failed);
        }
        self.records.borrow_mut().push_back(record.clone());
        Ok(())
    }

    fn front(&self) -> Result<Option<AuditRecord>, StoreRefusal> {
        Ok(self.records.borrow().front().cloned())
    }

    fn pop_front(&mut self) -> Result<(), StoreRefusal> {
        self.records.borrow_mut().pop_front();
        Ok(())
    }

    fn len(&self) -> usize {
        self.records.borrow().len()
    }

    fn records(&self) -> Result<Vec<AuditRecord>, StoreRefusal> {
        Ok(self.records.borrow().iter().cloned().collect())
    }
}

pub type Journal = AuditJournal<MemoryAuditStore, MemorySpool, Arc<ManualClock>>;

/// A journal of `spool_records` spool slots, one reserved for revocations.
pub fn journal(
    clock: &Arc<ManualClock>,
    spool_records: usize,
    failure_policy: AuditFailurePolicy,
) -> (Journal, AuditAppendAuthority, MemoryAuditStore, MemorySpool) {
    let store = MemoryAuditStore::default();
    let spool = MemorySpool::default();
    let (journal, authority) = AuditJournal::open(
        JournalId::new("engine").unwrap(),
        ProducerId::new("engine.audit").unwrap(),
        store.clone(),
        spool.clone(),
        Arc::clone(clock),
        AuditConfig {
            spool_records,
            revocation_reserve_records: 1,
            failure_policy,
            guest_observations: limit(4, SECOND),
            redaction: RedactionPolicy::metadata_only(),
        },
    )
    .unwrap();
    (journal, authority, store, spool)
}

/// The CORE-06 hub with the coordinator registered as a revocation issuer.
pub fn hub(clock: &Arc<ManualClock>) -> (EventHub<Arc<ManualClock>>, RevocationIssuer) {
    let mut hub = EventHub::new(
        Arc::clone(clock),
        HubConfig {
            metrics: MetricsConfig {
                capacity_events: 64,
                sample_above_events: 48,
                keep_one_in: NonZeroU32::new(8).unwrap(),
                retention: HOUR,
                max_series: 4,
            },
            progress: ProgressConfig {
                max_tracked: 4,
                terminal_retention: HOUR,
            },
            revocation: RevocationConfig {
                max_pending_executions: 4,
            },
            first_incarnation: ProducerIncarnation::new(1).unwrap(),
        },
    )
    .unwrap();
    let issuer = hub
        .register_revocation_issuer(ProducerId::new(ISSUER).unwrap())
        .unwrap();
    (hub, issuer)
}

/// The coordinator's name as the issuer of revocations on the lane.
pub const ISSUER: &str = "coordinator";

/// The coordinator's name as the owner of its durable revocation stream, never a hub
/// producer (S06).
pub const REVOCATIONS_OWNER: &str = "coordinator.revocations";

/// Room for 64 records in segments of eight.
pub fn revocation_log_config() -> LogConfig {
    LogConfig {
        max_entries: 64,
        max_bytes: 1 << 20,
        segment_entries: 8,
        segment_bytes: 1 << 16,
    }
}

/// Takes the coordinator's durable revocation stream in `directory` for `owner`, as
/// CORE-04's own tests open it on a temporary directory.
pub fn open_revocation_log(
    directory: &Path,
    owner: &str,
    config: LogConfig,
) -> (RevocationLog, OpenReport) {
    RevocationLog::open(
        directory,
        DurableStreamId::new("coordinator.revocations").unwrap(),
        ProducerId::new(owner).unwrap(),
        config,
    )
    .unwrap()
}

// ---------------------------------------------------------------------------------------
// A fake sandbox host with user data

/// The user-data identities of one sandbox: what no response may change (VM-W43).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserData {
    pub volumes: BTreeMap<Digest, VolumeClass>,
    pub host_workspaces: BTreeSet<Digest>,
    pub artifacts: BTreeSet<Digest>,
    pub snapshots: BTreeSet<Digest>,
    pub overlay_and_scratch: BTreeSet<Digest>,
}

impl UserData {
    /// One volume of every V05 class, a workspace, two artifacts, a snapshot, an overlay
    /// and a scratch directory, all named after `sandbox`.
    pub fn for_sandbox(sandbox: &str) -> Self {
        let id = |what: &str| {
            digest(
                "yougori/test/user-data/v1",
                &[sandbox.as_bytes(), what.as_bytes()],
            )
        };
        Self {
            volumes: VolumeClass::ALL
                .iter()
                .map(|&class| (id(&format!("volume-{class:?}")), class))
                .collect(),
            host_workspaces: BTreeSet::from([id("workspace")]),
            artifacts: BTreeSet::from([id("artifact-1"), id("artifact-2")]),
            snapshots: BTreeSet::from([id("snapshot")]),
            overlay_and_scratch: BTreeSet::from([id("overlay"), id("scratch")]),
        }
    }
}

/// What the runtime would hold for one sandbox: user data, channel and network state, the
/// VM and the high-impact gate. It applies response actions by their documented meaning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeSandboxHost {
    pub class: SandboxClass,
    pub user_data: UserData,
    pub network_cut: bool,
    pub channels_cut: bool,
    pub vm_running: bool,
    pub locked_down: bool,
    pub high_impact_denied: bool,
    /// Grants revoked here as a bystander; the sandbox keeps everything else.
    pub revoked_grants: BTreeSet<GrantRef>,
    pub corroboration_requests: u32,
    pub notifications: u32,
}

impl FakeSandboxHost {
    pub fn new(sandbox: &str, class: SandboxClass) -> Self {
        Self {
            class,
            user_data: UserData::for_sandbox(sandbox),
            network_cut: false,
            channels_cut: false,
            vm_running: true,
            locked_down: false,
            high_impact_denied: false,
            revoked_grants: BTreeSet::new(),
            corroboration_requests: 0,
            notifications: 0,
        }
    }

    /// Applies one target's actions.
    pub fn apply(&mut self, target: &TargetResponse) {
        for action in &target.actions {
            match action {
                ResponseAction::NotifyUser => self.notifications += 1,
                ResponseAction::RequestHostCorroboration => self.corroboration_requests += 1,
                ResponseAction::DenyNewHighImpact => self.high_impact_denied = true,
                ResponseAction::Isolate => {
                    for cut in IsolatePolicy::CUTS {
                        match cut {
                            IsolationCut::GuestChannels => self.channels_cut = true,
                            IsolationCut::Network => self.network_cut = true,
                        }
                    }
                }
                ResponseAction::RevokeGrant => match target.role {
                    TargetRole::SharesViolatedGrant { grant } => {
                        self.revoked_grants.insert(grant);
                    }
                    TargetRole::Observed => panic!("a grant revocation that names no grant"),
                },
                ResponseAction::Revoke => self.high_impact_denied = true,
                ResponseAction::Stop => match target.class_response {
                    Some(ViolationAction::Stop) => self.vm_running = false,
                    Some(ViolationAction::LockDown) => self.locked_down = true,
                    None => panic!("a stop without a class response"),
                },
            }
        }
    }

    /// The user released isolation: channels and network come back.
    pub fn release_isolation(&mut self) {
        self.channels_cut = false;
        self.network_cut = false;
    }
}
