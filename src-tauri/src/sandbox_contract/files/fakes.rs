//! Test doubles (tests only): a capacity port that grants everything, a quiet sandbox
//! backend, a clock a test can set backwards, a launched coordinator, and in-memory audit
//! storage. Nothing here touches the host.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::foundation::coordination::{
    BootRequest, CapacityPort, CapacityRefusal, Coordinator, ExecutionCancellation, LaunchOutcome,
    LaunchPlan, ObservedVm, PerimeterId, PortFailure, PortOperation, Readiness, ReadinessReport,
    ReconcileReport, ReleaseOutcome, ReservationKey, ReservationPriority, ReservationRequest,
    ReserveOutcome, ResourceKind, RestoredVmReport, ReturnHold, SandboxPort, SettingsGrant,
    SnapshotManifest, VmInstanceId,
};
use crate::foundation::events::{
    AuditConfig, AuditFailurePolicy, AuditRecord, AuditSpool, AuditStore, EmissionLimit,
    RedactionPolicy, StoreRefusal,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Backend, BackendRelease, Capability, ClockSession, ConfigurationFingerprint, Observation,
    ProbeRegistry, RuntimeOffer, RuntimeRequirement, RuntimeSubject, SourceClass, Subject,
    SupportDetail,
};
use crate::foundation::ids::{
    digest, Clock, ExecutionCategory, ExecutionId, MonotonicTime, SandboxBootGeneration, TenantId,
};

pub const SECOND: Duration = Duration::from_secs(1);
pub const HOUR: Duration = Duration::from_secs(3_600);

pub fn at(seconds: u64) -> MonotonicTime {
    MonotonicTime::from_nanos(seconds * 1_000_000_000)
}

pub fn session(number: u128) -> ClockSession {
    ClockSession::from_uuid(uuid::Uuid::from_u128(number))
}

/// A clock a test can move in either direction, to model a misbehaving time source.
#[derive(Debug, Default)]
pub struct RewindableClock {
    nanos: AtomicU64,
}

impl RewindableClock {
    pub fn new(start: MonotonicTime) -> Self {
        Self {
            nanos: AtomicU64::new(start.as_nanos()),
        }
    }

    pub fn set(&self, to: MonotonicTime) {
        self.nanos.store(to.as_nanos(), Ordering::SeqCst);
    }
}

impl Clock for RewindableClock {
    fn now(&self) -> MonotonicTime {
        MonotonicTime::from_nanos(self.nanos.load(Ordering::SeqCst))
    }
}

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
/// records terminations. It has no snapshots.
#[derive(Debug, Default)]
pub struct QuietBackend {
    pub running: Vec<ObservedVm>,
    pub terminated: Vec<VmInstanceId>,
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
        Ok(())
    }

    fn list_vms(&mut self) -> Result<Vec<ObservedVm>, PortFailure> {
        Ok(self.running.clone())
    }
}

pub fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

fn configuration() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_digest(digest("yougori/test/configuration/v1", &[b"launch"]))
}

/// A coordinator on clock `K` with host evidence that one runtime is a VM sandbox.
pub struct World<K: Clock + Clone> {
    pub clock: K,
    registry: ProbeRegistry<K>,
    category: Arc<FakeProbe>,
    runtime: RuntimeSubject,
    pub port: QuietBackend,
    pub coordinator: Coordinator<K, GrantAll>,
}

impl<K: Clock + Clone> World<K> {
    pub fn new(clock: K, coordinator_session: ClockSession) -> Self {
        let mut registry = ProbeRegistry::new(clock.clone());
        let category = Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe));
        registry.register(Box::new(Arc::clone(&category))).unwrap();
        let coordinator = Coordinator::new(clock.clone(), coordinator_session, GrantAll);
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

    /// A launch plan for `of` whose authority lasts `authority_lifetime`, on fresh host
    /// evidence.
    pub fn plan(&mut self, of: &ExecutionId, authority_lifetime: Duration) -> LaunchPlan {
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
            authority_lifetime,
            readiness_max_age: 5 * SECOND,
            runtime_evidence_max_age: HOUR,
        }
    }

    /// Launches `of` to authority_active, then running.
    pub fn launch(&mut self, plan: LaunchPlan) {
        let of = plan.execution.clone();
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
        self.coordinator.start_running(&of).unwrap();
    }
}

/// Audit storage in memory; it can be told to refuse everything.
#[derive(Clone, Debug, Default)]
pub struct MemoryAuditStore {
    pub records: Rc<RefCell<Vec<AuditRecord>>>,
    pub refuse: Rc<RefCell<bool>>,
}

impl AuditStore for MemoryAuditStore {
    fn append(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        if *self.refuse.borrow() {
            return Err(StoreRefusal::Full);
        }
        let mut records = self.records.borrow_mut();
        if records.last() != Some(record) {
            records.push(record.clone());
        }
        Ok(())
    }
}

/// A spool that holds nothing: every refused store is refused outright.
#[derive(Clone, Debug, Default)]
pub struct NoSpool;

impl AuditSpool for NoSpool {
    fn push(&mut self, _record: &AuditRecord) -> Result<(), StoreRefusal> {
        Err(StoreRefusal::Full)
    }

    fn front(&self) -> Result<Option<AuditRecord>, StoreRefusal> {
        Ok(None)
    }

    fn pop_front(&mut self) -> Result<(), StoreRefusal> {
        Ok(())
    }

    fn len(&self) -> usize {
        0
    }

    fn records(&self) -> Result<Vec<AuditRecord>, StoreRefusal> {
        Ok(Vec::new())
    }
}

/// An audit configuration that denies high-impact operations without a durable record.
pub fn audit_config() -> AuditConfig {
    AuditConfig {
        spool_records: 4,
        revocation_reserve_records: 1,
        failure_policy: AuditFailurePolicy::DenyHighImpact,
        guest_observations: EmissionLimit::new(10, SECOND).unwrap(),
        redaction: RedactionPolicy::metadata_only(),
    }
}
