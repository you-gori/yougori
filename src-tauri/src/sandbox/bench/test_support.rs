//! The fake hosts of the tests: the lifecycle supervisor over the real CORE-04
//! coordinator and CORE-03 ledger, with either the VB1 fake backend behind the
//! integration module's backend port ([`ContractWorld`]) or the lifecycle's scripted
//! backend ([`ScriptedWorld`]), a CORE-01 registry with fake probes and a manual clock.
//! Nothing here touches the host.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use super::host::{Drive, FakeVmHost, RecordTemplate};
use super::runner::RunnerConfig;
use super::timing::FakeVmTiming;
use super::BenchError;
use crate::foundation::coordination::{
    BootRequest, LedgerCapacity, PerimeterId, ReadinessReport, ReservationPriority, ResourceKind,
    RestoredVmReport, SettingsGrant, SharedLedger, SnapshotManifest, SnapshotOrigin,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    AdmittedRuntime, Backend, BackendRelease, BackendVersion, Capability, ClockSession,
    ConfigurationFingerprint, HostSubject, HypervisorKind, HypervisorSubject, Observation, OsKind,
    ProbeRegistry, RuntimeOffer, RuntimeRequirement, RuntimeSubject, SourceClass, Subject,
    SupportDetail,
};
use crate::foundation::ids::{
    digest, Clock, Digest, ExecutionCategory, ExecutionId, ManualClock, MonotonicTime, TenantId,
};
use crate::foundation::ledger::{
    CapacityDeclaration, HostResource, Ledger, LedgerConfig, QueueLimits, ResourceKey,
};
use crate::foundation::report::{
    BuildIdentity, ClientDescription, ClientPlacement, ClockId, CpuDescription, HostDescription,
    Label, LaunchDescription, Measured, NotMeasuredReason,
};
use crate::sandbox::backend::{
    Architecture, BackendFeatures, BuildId, DeviceExposure, DeviceProfile, FakeBackend, Feature,
    HostBuild, HostScript, PinnedArtifacts, RequiredProperties,
};
use crate::sandbox::integration::{
    BackendPort, LaunchProfile, LaunchTable, LedgerReservations, PortConfig,
};
use crate::sandbox::lifecycle::fakes::ScriptedBackend;
use crate::sandbox::lifecycle::{
    BackendCapabilities, BackendFailure, BackendOperation, HandleIdentity, IssuerId, LaunchRequest,
    LeaseLimits, Profile, RevocationPolicy, SandboxClass, SkewPolicy, StateReset, StopOutcome,
    Supervisor, SupervisorConfig, SupervisorDeathFallback, TerminationTiming, VmBackend, VmHandle,
};

pub const MILLI: u64 = 1_000_000;
pub const SECOND: Duration = Duration::from_secs(1);
pub const MINUTE: Duration = Duration::from_secs(60);
pub const HOUR: Duration = Duration::from_secs(3600);
pub const GIB: u64 = 1 << 30;

/// How often the fake hosts' probes observe again as time passes; well inside the
/// one-minute evidence age the launch profile requires.
const OBSERVE_EVERY: Duration = Duration::from_secs(30);

pub type TestClock = Arc<ManualClock>;

pub fn named(domain: &str, name: &str) -> Digest {
    digest(domain, &[name.as_bytes()])
}

pub fn label(value: &str) -> Label {
    Label::new(value).unwrap()
}

pub fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

pub fn config(name: &str) -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("host", name)]).unwrap()
}

pub fn machine() -> Digest {
    named("yougori/test/machine/v1", "bench-host")
}

pub fn image() -> Digest {
    named("yougori/test/image/v1", "sandbox-image")
}

pub fn artifact() -> Digest {
    named("yougori/test/backend/v1", "fake-backend")
}

pub fn tenant() -> TenantId {
    TenantId::new("tenant-bench").unwrap()
}

pub fn runtime() -> RuntimeSubject {
    RuntimeSubject {
        category: ExecutionCategory::VmSandbox,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance: named("yougori/test/instance/v1", "vm-host-1"),
    }
}

fn hypervisor_subject() -> Subject {
    Subject::Hypervisor(HypervisorSubject {
        machine: machine(),
        hypervisor: HypervisorKind::Kvm,
    })
}

pub fn timing() -> FakeVmTiming {
    FakeVmTiming {
        api_ack_nanos: 40 * MILLI,
        cold_first_command_nanos: 900 * MILLI,
        warm_first_command_nanos: 250 * MILLI,
        contention_nanos_per_booting_vm: 50 * MILLI,
        jitter_per_mille: 50,
        clone_prepare_nanos: 600 * MILLI,
        seed: 11,
    }
}

pub fn limits() -> super::plan::AttemptLimits {
    super::plan::AttemptLimits {
        deadline_nanos: 2_000 * MILLI,
        timeout_nanos: 5_000 * MILLI,
        hold_nanos: 200 * MILLI,
        burst_gap_nanos: 10_000 * MILLI,
    }
}

pub fn template() -> RecordTemplate {
    RecordTemplate {
        build: BuildIdentity {
            plan: named("yougori/test/plan/v1", "combined-plan"),
            runner_build: named("yougori/test/runner/v1", "vm-bench-harness"),
            runner_version: label("0.1.0"),
        },
        host: HostDescription {
            os: label("fake-substrate"),
            os_version: label("0"),
            cpu: CpuDescription {
                model: label("fake-substrate"),
                logical_cores: 16,
            },
            host_memory_bytes: 64 * GIB,
            gpus: Measured::not_measured(NotMeasuredReason::NotApplicable),
            gpu_driver: Measured::not_measured(NotMeasuredReason::NotApplicable),
            gpu_power_clock: Measured::not_measured(NotMeasuredReason::NotApplicable),
            power_source: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
            displays_on_gpu: Measured::not_measured(NotMeasuredReason::NotApplicable),
        },
        client: ClientDescription {
            name: label("yougori-vm-bench"),
            version: label("0.1.0"),
            region: label("local"),
            placement: ClientPlacement::SameHost,
        },
        launch: LaunchDescription {
            image: image(),
            backend: label("fake"),
        },
    }
}

pub fn runner_config(prefix: &str) -> RunnerConfig {
    RunnerConfig {
        run: execution("exe-vm-bench-run"),
        prefix: prefix.to_owned(),
        clock: ClockId::new(label("fake-manual-clock")),
        template: template(),
        timing: timing(),
    }
}

/// The ledger's capacity and queue for one world.
#[derive(Clone, Copy, Debug)]
pub struct Capacity {
    /// Each create reserves 8 GiB, so this many GiB over 8 is the concurrent limit.
    pub memory_gib: u64,
    /// Creates that do not fit wait this long in the ledger's queue; `None` refuses them.
    pub queue_wait: Option<Duration>,
}

impl Default for Capacity {
    fn default() -> Self {
        Self {
            memory_gib: 64,
            queue_wait: None,
        }
    }
}

fn ledger(clock: &TestClock, capacity: Capacity) -> Ledger<TestClock> {
    let config = LedgerConfig {
        queue: QueueLimits {
            max_entries: 8,
            max_entries_per_tenant: 4,
            max_wait: 60 * SECOND,
        },
        grant_ttl: 300 * SECOND,
        unmanaged_usage_max_age: 1000 * HOUR,
    };
    let mut ledger = Ledger::new(
        Arc::clone(clock),
        HostSubject { machine: machine() },
        config,
    );
    for (key, total) in [
        (
            ResourceKey::Host(HostResource::Ram),
            capacity.memory_gib * GIB,
        ),
        (ResourceKey::Host(HostResource::CpuInitializationSlots), 64),
    ] {
        ledger
            .declare_capacity(
                key,
                CapacityDeclaration {
                    total,
                    supervisor_reserve: 0,
                    unmanaged_in_use: 0,
                    source: SourceClass::HostProbe,
                },
            )
            .unwrap();
        ledger.set_tenant_budget(tenant(), key, total).unwrap();
    }
    ledger
}

fn capacity_port<L: crate::foundation::coordination::LedgerHandle<TestClock>>(
    port: LedgerCapacity<TestClock, L>,
    capacity: Capacity,
) -> LedgerCapacity<TestClock, L> {
    match capacity.queue_wait {
        Some(wait) => port.with_queue_wait(wait),
        None => port,
    }
}

pub fn supervisor_config() -> SupervisorConfig {
    SupervisorConfig {
        profile: Profile::Strict,
        readiness_max_age: 5 * SECOND,
        runtime_evidence_max_age: HOUR,
        skew: SkewPolicy {
            allowed_clock_uncertainty: 30 * SECOND,
        },
        revocation: RevocationPolicy {
            timing: TerminationTiming::AfterChannelAcknowledgmentOrBound,
            cleanup_bound: 60 * SECOND,
        },
        death_fallback: SupervisorDeathFallback::ServiceManagerRestart {
            restart_within: 30 * SECOND,
        },
        cancel_within: 5 * SECOND,
        issuer: IssuerId::named("bench-host"),
        expected_image_profile: image(),
    }
}

fn launch_request(execution: &ExecutionId, runtime: AdmittedRuntime) -> LaunchRequest {
    LaunchRequest {
        execution: execution.clone(),
        tenant: tenant(),
        runtime,
        demand: BTreeMap::from([
            (ResourceKind::HostMemoryBytes, 8 * GIB),
            (ResourceKind::CpuInitializationSlots, 1),
        ]),
        priority: ReservationPriority::Foreground,
        class: SandboxClass::Task,
        limits: LeaseLimits::defaults(SandboxClass::Task),
        settings: SettingsGrant::default(),
        volumes: BTreeMap::new(),
        provider_bills: false,
    }
}

/// The CORE-01 registry of a world: the runtime category probe and, for the contract
/// world, the hypervisor probe, observed again every [`OBSERVE_EVERY`].
pub struct Evidence {
    pub registry: ProbeRegistry<TestClock>,
    category: Arc<FakeProbe>,
    hypervisor: Option<Arc<FakeProbe>>,
    admitted: Option<AdmittedRuntime>,
    observed_at: MonotonicTime,
}

impl Evidence {
    fn new(clock: &TestClock, with_hypervisor: bool) -> Self {
        let mut registry = ProbeRegistry::new(Arc::clone(clock));
        let category = Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe));
        registry.register(Box::new(Arc::clone(&category))).unwrap();
        let hypervisor = with_hypervisor.then(|| {
            let probe = Arc::new(FakeProbe::new(
                Capability::HypervisorAvailable,
                SourceClass::HostProbe,
            ));
            registry.register(Box::new(Arc::clone(&probe))).unwrap();
            probe
        });
        let mut evidence = Self {
            registry,
            category,
            hypervisor,
            admitted: None,
            observed_at: clock.now(),
        };
        evidence.observe(clock.now());
        evidence
    }

    /// The probes observe now: KVM available and the runtime a VM sandbox.
    fn observe(&mut self, now: MonotonicTime) {
        if let Some(probe) = &self.hypervisor {
            probe.respond(
                &hypervisor_subject(),
                Observation::supported(
                    config("a"),
                    600 * SECOND,
                    SupportDetail::Hypervisor {
                        hypervisor: HypervisorKind::Kvm,
                    },
                ),
            );
            self.registry
                .refresh(Capability::HypervisorAvailable, &hypervisor_subject())
                .unwrap();
        }
        let subject = Subject::Runtime(runtime());
        self.category.respond(
            &subject,
            Observation::supported(
                config("a"),
                HOUR,
                SupportDetail::RuntimeCategory {
                    category: ExecutionCategory::VmSandbox,
                },
            ),
        );
        self.registry
            .refresh(Capability::RuntimeCategory, &subject)
            .unwrap();
        let offer = RuntimeOffer::observe(&self.registry, runtime(), HOUR, config("a")).unwrap();
        self.admitted = Some(RuntimeRequirement::VmSandbox.admit(&offer).unwrap());
        self.observed_at = now;
    }

    fn maybe_observe(&mut self, now: MonotonicTime) {
        if now.saturating_duration_since(self.observed_at) >= OBSERVE_EVERY {
            self.observe(now);
        }
    }

    fn admitted(&self) -> AdmittedRuntime {
        self.admitted.clone().unwrap()
    }
}

pub type ContractCapacity = LedgerCapacity<TestClock, SharedLedger<TestClock>>;

/// The VB1 fake backend behind the integration module's backend port.
pub struct ContractWorld {
    pub clock: TestClock,
    pub evidence: Evidence,
    pub backend: FakeBackend,
    pub table: LaunchTable,
    pub reservations: LedgerReservations<TestClock>,
    pub supervisor: Supervisor<TestClock, ContractCapacity>,
}

/// What a contract world is built with.
#[derive(Clone, Debug)]
pub struct ContractOptions {
    pub capacity: Capacity,
    pub snapshots: bool,
    pub state_reset: StateReset,
}

impl Default for ContractOptions {
    fn default() -> Self {
        Self {
            capacity: Capacity::default(),
            snapshots: false,
            state_reset: StateReset::Supported,
        }
    }
}

impl ContractWorld {
    pub fn new() -> Self {
        Self::with(ContractOptions::default())
    }

    pub fn with(options: ContractOptions) -> Self {
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(
            100 * 1_000_000_000,
        )));
        let evidence = Evidence::new(&clock, true);
        let capacity = capacity_port(
            LedgerCapacity::new(ledger(&clock, options.capacity)),
            options.capacity,
        )
        .into_shared();
        let reservations = LedgerReservations::new(capacity.handle());
        let supervisor = Supervisor::new(
            Arc::clone(&clock),
            ClockSession::from_uuid(uuid::Uuid::from_u128(1)),
            capacity,
            supervisor_config(),
        );
        let script = HostScript::hardware_vm(
            HypervisorKind::Kvm,
            HostBuild {
                os: OsKind::Linux,
                build: BuildId::new("6.6.0").unwrap(),
                architecture: Architecture::X86_64,
            },
            image(),
            config("a"),
        );
        let features = if options.snapshots {
            BackendFeatures::of([Feature::Snapshot, Feature::Restore])
        } else {
            BackendFeatures::none()
        };
        let backend = FakeBackend::new(
            HypervisorKind::Kvm,
            BackendVersion::new("0.1.0").unwrap(),
            artifact(),
            script,
        )
        .with_features(features);
        let table = LaunchTable::new(PortConfig {
            machine: machine(),
            state_reset: options.state_reset,
        });
        Self {
            clock,
            evidence,
            backend,
            table,
            reservations,
            supervisor,
        }
    }

    fn profile() -> LaunchProfile {
        LaunchProfile {
            configuration: config("a"),
            contract: named("yougori/test/contract/v1", "vm-bench"),
            pinned: PinnedArtifacts {
                guest_image: image(),
                backend: artifact(),
            },
            device_profile: DeviceProfile {
                identity: named("yougori/test/profile/v1", "minimal"),
                devices: DeviceExposure::cpu_only(),
            },
            required: RequiredProperties::strictest(MINUTE),
        }
    }
}

impl FakeVmHost for ContractWorld {
    type Clock = TestClock;
    type Capacity = ContractCapacity;
    type Evidence = TestClock;

    fn now(&self) -> MonotonicTime {
        self.clock.now()
    }

    fn advance_to(&mut self, at: MonotonicTime) {
        self.clock.advance_to(at);
        self.evidence.maybe_observe(self.clock.now());
    }

    fn drive(&mut self) -> Drive<'_, TestClock, ContractCapacity, TestClock> {
        let port: BackendPort<
            '_,
            FakeBackend,
            ProbeRegistry<TestClock>,
            LedgerReservations<TestClock>,
        > = self.table.port(
            &mut self.backend,
            &self.evidence.registry,
            &self.reservations,
        );
        Drive {
            supervisor: &mut self.supervisor,
            backend: Box::new(port),
            registry: &self.evidence.registry,
        }
    }

    fn request(&mut self, execution: &ExecutionId) -> Result<LaunchRequest, BenchError> {
        if self.table.profile(execution).is_none() {
            self.table.set_profile(execution.clone(), Self::profile());
        }
        Ok(launch_request(execution, self.evidence.admitted()))
    }

    fn refuse_creates(&mut self, refuse: bool) {
        self.backend.script_mut().create_failure =
            refuse.then(|| "injected create failure".to_owned());
    }
}

/// The lifecycle's scripted backend, lent for one supervisor call.
pub struct Lent<'a>(&'a mut ScriptedBackend);

impl VmBackend for Lent<'_> {
    fn capabilities(&self) -> BackendCapabilities {
        self.0.capabilities()
    }

    fn prepare_perimeter(&mut self, request: &BootRequest) -> Result<PerimeterId, BackendFailure> {
        self.0.prepare_perimeter(request)
    }

    fn launch(
        &mut self,
        request: &BootRequest,
        perimeter: &PerimeterId,
    ) -> Result<VmHandle, BackendFailure> {
        self.0.launch(request, perimeter)
    }

    fn restore(
        &mut self,
        request: &BootRequest,
        perimeter: &PerimeterId,
        snapshot: &SnapshotManifest,
    ) -> Result<VmHandle, BackendFailure> {
        self.0.restore(request, perimeter, snapshot)
    }

    fn observe_readiness(&mut self, handle: &VmHandle) -> ReadinessReport {
        self.0.observe_readiness(handle)
    }

    fn inspect_restored(&mut self, handle: &VmHandle) -> RestoredVmReport {
        self.0.inspect_restored(handle)
    }

    fn check_handle(&mut self, handle: &VmHandle) -> HandleIdentity {
        self.0.check_handle(handle)
    }

    fn stop(&mut self, handle: &VmHandle) -> Result<StopOutcome, BackendFailure> {
        self.0.stop(handle)
    }

    fn snapshot(
        &mut self,
        handle: &VmHandle,
        origin: SnapshotOrigin,
    ) -> Result<SnapshotManifest, BackendFailure> {
        self.0.snapshot(handle, origin)
    }

    fn teardown_perimeter(&mut self, perimeter: &PerimeterId) -> Result<(), BackendFailure> {
        self.0.teardown_perimeter(perimeter)
    }

    fn list(&mut self) -> Result<Vec<VmHandle>, BackendFailure> {
        self.0.list()
    }
}

/// The lifecycle's scripted backend under the same supervisor and ledger.
pub struct ScriptedWorld {
    pub clock: TestClock,
    pub evidence: Evidence,
    pub backend: ScriptedBackend,
    pub supervisor: Supervisor<TestClock, LedgerCapacity<TestClock>>,
}

impl ScriptedWorld {
    pub fn new() -> Self {
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(
            100 * 1_000_000_000,
        )));
        let evidence = Evidence::new(&clock, false);
        let capacity = Capacity::default();
        let supervisor = Supervisor::new(
            Arc::clone(&clock),
            ClockSession::from_uuid(uuid::Uuid::from_u128(2)),
            capacity_port(LedgerCapacity::new(ledger(&clock, capacity)), capacity),
            supervisor_config(),
        );
        let mut backend = ScriptedBackend::new();
        backend.image_profile = image();
        Self {
            clock,
            evidence,
            backend,
            supervisor,
        }
    }
}

impl FakeVmHost for ScriptedWorld {
    type Clock = TestClock;
    type Capacity = LedgerCapacity<TestClock>;
    type Evidence = TestClock;

    fn now(&self) -> MonotonicTime {
        self.clock.now()
    }

    fn advance_to(&mut self, at: MonotonicTime) {
        self.clock.advance_to(at);
        self.evidence.maybe_observe(self.clock.now());
    }

    fn drive(&mut self) -> Drive<'_, TestClock, LedgerCapacity<TestClock>, TestClock> {
        Drive {
            supervisor: &mut self.supervisor,
            backend: Box::new(Lent(&mut self.backend)),
            registry: &self.evidence.registry,
        }
    }

    fn request(&mut self, execution: &ExecutionId) -> Result<LaunchRequest, BenchError> {
        Ok(launch_request(execution, self.evidence.admitted()))
    }

    fn refuse_creates(&mut self, refuse: bool) {
        for operation in [BackendOperation::Launch, BackendOperation::Restore] {
            if refuse {
                self.backend.failing.insert(operation);
            } else {
                self.backend.failing.remove(&operation);
            }
        }
    }
}

/// A host whose manual clock never moves: what a supervisor on another clock looks like
/// to the runner.
pub struct Frozen(pub ScriptedWorld);

impl FakeVmHost for Frozen {
    type Clock = TestClock;
    type Capacity = LedgerCapacity<TestClock>;
    type Evidence = TestClock;

    fn now(&self) -> MonotonicTime {
        self.0.now()
    }

    fn advance_to(&mut self, _at: MonotonicTime) {}

    fn drive(&mut self) -> Drive<'_, TestClock, LedgerCapacity<TestClock>, TestClock> {
        self.0.drive()
    }

    fn request(&mut self, execution: &ExecutionId) -> Result<LaunchRequest, BenchError> {
        self.0.request(execution)
    }

    fn refuse_creates(&mut self, refuse: bool) {
        self.0.refuse_creates(refuse);
    }
}

/// A host whose launch requests name a class their limits do not have: the supervisor
/// refuses every create.
pub struct Misconfigured(pub ScriptedWorld);

impl FakeVmHost for Misconfigured {
    type Clock = TestClock;
    type Capacity = LedgerCapacity<TestClock>;
    type Evidence = TestClock;

    fn now(&self) -> MonotonicTime {
        self.0.now()
    }

    fn advance_to(&mut self, at: MonotonicTime) {
        self.0.advance_to(at);
    }

    fn drive(&mut self) -> Drive<'_, TestClock, LedgerCapacity<TestClock>, TestClock> {
        self.0.drive()
    }

    fn request(&mut self, execution: &ExecutionId) -> Result<LaunchRequest, BenchError> {
        let mut request = self.0.request(execution)?;
        request.limits = LeaseLimits::defaults(SandboxClass::Service);
        Ok(request)
    }

    fn refuse_creates(&mut self, refuse: bool) {
        self.0.refuse_creates(refuse);
    }
}
