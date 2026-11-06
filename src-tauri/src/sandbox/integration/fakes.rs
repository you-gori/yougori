//! The test world of the scenarios: a manual clock, a CORE-01 registry with a runtime
//! category probe, a hypervisor probe and a perimeter must-probe, the real CORE-03 ledger
//! shared between the coordinator's capacity port and the reservation resolver, the fake
//! backend of VB1 behind the port, the lifecycle supervisor, one audit stream on
//! in-memory segments, and an assurance ledger. Nothing here touches the host.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::assurance::ClaimParts;
use super::audit_sink::{AuditSink, LaunchAudit, SinkRefusal};
use super::backend_port::{LaunchTable, PortConfig};
use super::profile::{LaunchProfile, LedgerReservations};
use crate::foundation::coordination::{
    LedgerCapacity, ReservationPriority, ResourceKind, SandboxState, SettingsGrant, SharedLedger,
    VmInstanceId,
};
use crate::foundation::events::{
    AuditConfig, AuditFailurePolicy, AuditReceipt, AuditRecord, AuditSpool, EmissionLimit,
    EventSequence, JournalId, ProducerId, RedactionPolicy, StoreRefusal,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    AdmittedRuntime, Backend, BackendRelease, BackendVersion, Capability, ClockSession,
    ConfigurationFingerprint, HostSubject, HypervisorKind, HypervisorSubject, Observation, OsKind,
    PerimeterRuleSubject, ProbeRegistry, RuntimeOffer, RuntimeRequirement, RuntimeSubject,
    SourceClass, Subject, SupportDetail, UnsupportedReason,
};
use crate::foundation::ids::{
    digest, Digest, ExecutionCategory, ExecutionId, ManualClock, MonotonicTime, OperationId,
    PolicyEpoch, SandboxBootGeneration, TenantId,
};
use crate::foundation::ledger::{
    CapacityDeclaration, HostResource, Ledger, LedgerConfig, QueueLimits, ResourceKey,
};
use crate::sandbox::audit::{
    Anchoring, AssumptionId, AssumptionKind, AssuranceLedger, ClaimId, NoAnchor, ProfileId, RiskId,
    RiskKind, SegmentConfig, SegmentHeader, SegmentSeal, SegmentStorage, StoredSegment,
    StreamConfig, StreamDirectory,
};
use crate::sandbox::backend::{
    Architecture, BackendFeatures, BuildId, DeviceExposure, DeviceProfile, FakeBackend, FakeCall,
    HostBuild, HostScript, LaunchRecord, PerimeterRequirement, PinnedArtifacts, RequiredProperties,
};
use crate::sandbox::lifecycle::{
    Acknowledgment, CallTerms, IssuerId, LaunchReceipt, LaunchRequest, LeaseLimits,
    LifecycleReceipt, Profile, RevocationCause, RevocationPolicy, SandboxClass, SkewPolicy,
    StateReset, Supervisor, SupervisorConfig, SupervisorDeathFallback, TerminationTiming, VmHandle,
};
use crate::sandbox_contract::policy::{
    plan_launch, resolve, BudgetSet, Context, ContractIdentity, DelegationDraft, GenerationScope,
    LaunchRefusal as PolicyLaunchRefusal, LaunchTargets, Operation, PermissionTuple,
    Phase as PolicyPhase, Principal, ProductPolicyDraft, RequestDocument, RequestSource,
    ResolvedPolicy, ResourceKind as PolicyResource, ResourceRef, SecurityPredicate, SourceKind,
    SourceName, Validator, CONTRACT_SCHEMA_VERSION,
};

pub const SECOND: Duration = Duration::from_secs(1);
pub const MINUTE: Duration = Duration::from_secs(60);
pub const HOUR: Duration = Duration::from_secs(3600);
pub const GIB: u64 = 1 << 30;

pub type TestClock = Arc<ManualClock>;
pub type Capacity = LedgerCapacity<TestClock, SharedLedger<TestClock>>;
pub type TestSupervisor = Supervisor<TestClock, Capacity>;
pub type Sink = AuditSink<MemorySegments, MemorySpool, NoAnchor, TestClock>;

/// The lifecycle port of a world, built from its fields so the supervisor can be
/// borrowed beside it.
macro_rules! port {
    ($world:expr) => {
        $world
            .table
            .port(&mut $world.backend, &$world.registry, &$world.reservations)
    };
}
pub(crate) use port;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Debug, Default)]
struct SegmentsState {
    segments: Vec<StoredSegment>,
    capacity_records: usize,
}

impl SegmentsState {
    fn records(&self) -> usize {
        self.segments
            .iter()
            .map(|segment| segment.records.len())
            .sum()
    }
}

/// In-memory segment storage with a record capacity, like a disk that fills. Clones
/// share one content.
#[derive(Clone, Debug, Default)]
pub struct MemorySegments {
    shared: Arc<Mutex<SegmentsState>>,
}

impl MemorySegments {
    pub fn new(capacity_records: usize) -> Self {
        let storage = Self::default();
        lock(&storage.shared).capacity_records = capacity_records;
        storage
    }

    pub fn snapshot(&self) -> Vec<StoredSegment> {
        lock(&self.shared).segments.clone()
    }

    pub fn all_records(&self) -> Vec<AuditRecord> {
        lock(&self.shared)
            .segments
            .iter()
            .flat_map(|segment| segment.records.iter().cloned())
            .collect()
    }
}

impl SegmentStorage for MemorySegments {
    fn begin_segment(&mut self, header: &SegmentHeader) -> Result<(), StoreRefusal> {
        let mut state = lock(&self.shared);
        if state
            .segments
            .last()
            .is_some_and(|last| last.header == *header)
        {
            return Ok(());
        }
        state.segments.push(StoredSegment {
            header: header.clone(),
            records: Vec::new(),
            seal: None,
        });
        Ok(())
    }

    fn append(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        let mut state = lock(&self.shared);
        let stored = state.records();
        let capacity = state.capacity_records;
        let Some(last) = state.segments.last() else {
            return Err(StoreRefusal::Failed);
        };
        if last.seal.is_some() {
            return Err(StoreRefusal::Failed);
        }
        if state
            .segments
            .iter()
            .any(|segment| segment.records.iter().any(|known| known == record))
        {
            return Ok(());
        }
        if stored >= capacity {
            return Err(StoreRefusal::Full);
        }
        if let Some(last) = state.segments.last_mut() {
            last.records.push(record.clone());
        }
        Ok(())
    }

    fn seal_segment(&mut self, seal: &SegmentSeal) -> Result<(), StoreRefusal> {
        let mut state = lock(&self.shared);
        let Some(last) = state.segments.last_mut() else {
            return Err(StoreRefusal::Failed);
        };
        match &last.seal {
            Some(existing) if existing == seal => Ok(()),
            Some(_) => Err(StoreRefusal::Failed),
            None => {
                last.seal = Some(seal.clone());
                Ok(())
            }
        }
    }

    fn segments(&self) -> Result<Vec<StoredSegment>, StoreRefusal> {
        Ok(self.snapshot())
    }

    fn record(&self, sequence: EventSequence) -> Result<Option<AuditRecord>, StoreRefusal> {
        Ok(lock(&self.shared)
            .segments
            .iter()
            .flat_map(|segment| segment.records.iter())
            .find(|record| record.sequence() == sequence)
            .cloned())
    }
}

/// A spool standing in for durable local storage; clones share one content.
#[derive(Clone, Debug, Default)]
pub struct MemorySpool {
    shared: Arc<Mutex<VecDeque<AuditRecord>>>,
}

impl MemorySpool {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AuditSpool for MemorySpool {
    fn push(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        lock(&self.shared).push_back(record.clone());
        Ok(())
    }

    fn front(&self) -> Result<Option<AuditRecord>, StoreRefusal> {
        Ok(lock(&self.shared).front().cloned())
    }

    fn pop_front(&mut self) -> Result<(), StoreRefusal> {
        lock(&self.shared).pop_front();
        Ok(())
    }

    fn len(&self) -> usize {
        lock(&self.shared).len()
    }

    fn records(&self) -> Result<Vec<AuditRecord>, StoreRefusal> {
        Ok(lock(&self.shared).iter().cloned().collect())
    }
}

pub fn at(seconds: u64) -> MonotonicTime {
    MonotonicTime::from_nanos(seconds * 1_000_000_000)
}

pub fn session(number: u128) -> ClockSession {
    ClockSession::from_uuid(uuid::Uuid::from_u128(number))
}

pub fn named(domain: &str, name: &str) -> Digest {
    digest(domain, &[name.as_bytes()])
}

pub fn config(name: &str) -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("host", name)]).unwrap()
}

pub fn machine() -> Digest {
    named("yougori/test/machine/v1", "workstation")
}

pub fn image() -> Digest {
    named("yougori/test/image/v1", "sandbox-image")
}

pub fn artifact() -> Digest {
    named("yougori/test/backend/v1", "fake-backend")
}

pub fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

pub fn operation(name: &str) -> OperationId {
    OperationId::new(name).unwrap()
}

pub fn tenant() -> TenantId {
    TenantId::new("tenant-a").unwrap()
}

pub fn runtime() -> RuntimeSubject {
    RuntimeSubject {
        category: ExecutionCategory::VmSandbox,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance: named("yougori/test/instance/v1", "vm-host-1"),
    }
}

/// The host's perimeter, as its installer identifies it.
pub fn perimeter() -> Digest {
    named("yougori/test/perimeter/v1", "host-perimeter")
}

/// The transport broker's identity, the principal the perimeter's block rules restrict.
pub fn broker() -> Digest {
    named("yougori/test/principal/v1", "transport-broker")
}

/// One block rule of the host's perimeter for the broker, as a CORE-01 subject.
pub fn perimeter_rule(name: &str) -> PerimeterRuleSubject {
    PerimeterRuleSubject {
        machine: machine(),
        perimeter: perimeter(),
        rule: named("yougori/test/rule/v1", name),
        principal: broker(),
    }
}

pub fn hypervisor_subject() -> Subject {
    Subject::Hypervisor(HypervisorSubject {
        machine: machine(),
        hypervisor: HypervisorKind::Kvm,
    })
}

pub fn host_build() -> HostBuild {
    HostBuild {
        os: OsKind::Linux,
        build: BuildId::new("6.6.0").unwrap(),
        architecture: Architecture::X86_64,
    }
}

pub fn host_script() -> HostScript {
    HostScript::hardware_vm(HypervisorKind::Kvm, host_build(), image(), config("a"))
}

pub fn call() -> CallTerms {
    CallTerms {
        per_call: 30 * SECOND,
        task: HOUR,
    }
}

pub fn parts(id: &str) -> ClaimParts {
    ClaimParts {
        id: ClaimId::new(id).unwrap(),
        profile: ProfileId::new("local-containment").unwrap(),
        assumptions: BTreeSet::from([AssumptionId::new("host-admin").unwrap()]),
        residual_risks: BTreeSet::from([RiskId::new("unknown-escape").unwrap()]),
    }
}

/// An assurance ledger under `configuration` that knows the assumption and the risk
/// [`parts`] names.
pub fn assurance(configuration: ConfigurationFingerprint) -> AssuranceLedger {
    let mut ledger = AssuranceLedger::new(configuration);
    ledger
        .add_assumption(
            AssumptionId::new("host-admin").unwrap(),
            AssumptionKind::HostAdministratorTrusted,
        )
        .unwrap();
    ledger
        .add_risk(
            RiskId::new("unknown-escape").unwrap(),
            RiskKind::UnknownEscape,
        )
        .unwrap();
    ledger
}

/// The CORE-03 ledger of the host: 64 GiB of RAM, 16 CPU initialization slots, the
/// tenant budgeted for all of it.
pub fn real_ledger(clock: &TestClock) -> Ledger<TestClock> {
    let host = HostSubject { machine: machine() };
    let config = LedgerConfig {
        queue: QueueLimits {
            max_entries: 8,
            max_entries_per_tenant: 4,
            max_wait: 60 * SECOND,
        },
        grant_ttl: 300 * SECOND,
        unmanaged_usage_max_age: 1000 * HOUR,
    };
    let mut ledger = Ledger::new(Arc::clone(clock), host, config);
    for (key, total) in [
        (ResourceKey::Host(HostResource::Ram), 64 * GIB),
        (ResourceKey::Host(HostResource::CpuInitializationSlots), 16),
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

pub fn supervisor_config(timing: TerminationTiming) -> SupervisorConfig {
    SupervisorConfig {
        profile: Profile::Strict,
        readiness_max_age: 5 * SECOND,
        runtime_evidence_max_age: HOUR,
        skew: SkewPolicy {
            allowed_clock_uncertainty: 30 * SECOND,
        },
        revocation: RevocationPolicy {
            timing,
            cleanup_bound: 60 * SECOND,
        },
        death_fallback: SupervisorDeathFallback::ServiceManagerRestart {
            restart_within: 30 * SECOND,
        },
        cancel_within: 5 * SECOND,
        issuer: IssuerId::named("host-a"),
        expected_image_profile: image(),
    }
}

pub fn stream_config(spool_records: usize) -> StreamConfig {
    stream_config_reserving(spool_records, 1)
}

/// A stream configuration whose spool keeps `revocation_reserve_records` of its
/// `spool_records` for revocations and grant revocations.
pub fn stream_config_reserving(
    spool_records: usize,
    revocation_reserve_records: usize,
) -> StreamConfig {
    StreamConfig {
        audit: AuditConfig {
            spool_records,
            revocation_reserve_records,
            failure_policy: AuditFailurePolicy::SpoolHighImpact,
            guest_observations: EmissionLimit::new(16, SECOND).unwrap(),
            redaction: RedactionPolicy::metadata_only(),
        },
        segment: SegmentConfig {
            max_records_per_segment: 16,
        },
        anchoring: Anchoring::Off,
    }
}

/// What a world is built with.
pub struct WorldOptions {
    pub hypervisor_source: SourceClass,
    pub perimeter_source: SourceClass,
    pub features: BackendFeatures,
    pub state_reset: StateReset,
    pub timing: TerminationTiming,
    pub storage_capacity: usize,
    pub spool_records: usize,
    /// Spool slots kept for revocations and grant revocations.
    pub revocation_reserve: usize,
}

impl Default for WorldOptions {
    fn default() -> Self {
        Self {
            hypervisor_source: SourceClass::HostProbe,
            perimeter_source: SourceClass::HostProbe,
            features: BackendFeatures::none(),
            state_reset: StateReset::Unsupported {
                detail: "no state reset declared".to_owned(),
            },
            timing: TerminationTiming::AfterChannelAcknowledgmentOrBound,
            storage_capacity: 1_000,
            spool_records: 8,
            revocation_reserve: 1,
        }
    }
}

/// What one audit drain recorded, in order.
#[derive(Debug, Default)]
pub struct AuditDrain {
    pub lifecycle: Vec<LifecycleReceipt>,
    pub receipts: Vec<Result<AuditReceipt, SinkRefusal>>,
    pub refusals: Vec<Result<AuditReceipt, SinkRefusal>>,
    pub launches: Vec<Result<LaunchAudit, SinkRefusal>>,
}

pub struct World {
    pub clock: TestClock,
    pub registry: ProbeRegistry<TestClock>,
    pub category: Arc<FakeProbe>,
    pub hypervisor: Arc<FakeProbe>,
    pub perimeter: Arc<FakeProbe>,
    pub backend: FakeBackend,
    pub table: LaunchTable,
    pub reservations: LedgerReservations<TestClock>,
    pub supervisor: TestSupervisor,
    pub sink: Sink,
    pub storage: MemorySegments,
    pub assurance: AssuranceLedger,
    recorded: BTreeSet<Digest>,
}

impl World {
    pub fn new() -> Self {
        Self::with(WorldOptions::default())
    }

    pub fn with(options: WorldOptions) -> Self {
        let clock = Arc::new(ManualClock::new(at(100)));
        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
        let category = Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe));
        let hypervisor = Arc::new(FakeProbe::new(
            Capability::HypervisorAvailable,
            options.hypervisor_source,
        ));
        let perimeter = Arc::new(FakeProbe::new(
            Capability::PerimeterRuleEnforced,
            options.perimeter_source,
        ));
        registry.register(Box::new(Arc::clone(&category))).unwrap();
        registry
            .register(Box::new(Arc::clone(&hypervisor)))
            .unwrap();
        registry.register(Box::new(Arc::clone(&perimeter))).unwrap();
        let capacity = LedgerCapacity::new(real_ledger(&clock)).into_shared();
        let reservations = LedgerReservations::new(capacity.handle());
        let supervisor = Supervisor::new(
            Arc::clone(&clock),
            session(1),
            capacity,
            supervisor_config(options.timing),
        );
        let backend = FakeBackend::new(
            HypervisorKind::Kvm,
            BackendVersion::new("0.1.0").unwrap(),
            artifact(),
            host_script(),
        )
        .with_features(options.features);
        let table = LaunchTable::new(PortConfig {
            machine: machine(),
            state_reset: options.state_reset,
        });
        let storage = MemorySegments::new(options.storage_capacity);
        let mut directory = StreamDirectory::new();
        let sink = AuditSink::open(
            &mut directory,
            JournalId::new("supervisor").unwrap(),
            ProducerId::new("supervisor.audit").unwrap(),
            storage.clone(),
            MemorySpool::new(),
            NoAnchor,
            Arc::clone(&clock),
            stream_config_reserving(options.spool_records, options.revocation_reserve),
        )
        .unwrap();
        let mut world = Self {
            clock,
            registry,
            category,
            hypervisor,
            perimeter,
            backend,
            table,
            reservations,
            supervisor,
            sink,
            storage,
            assurance: assurance(config("a")),
            recorded: BTreeSet::new(),
        };
        world.observe_hypervisor(true, config("a"));
        world
    }

    pub fn advance(&mut self, by: Duration) {
        self.clock.advance(by);
    }

    /// The hypervisor probe observes KVM available or unavailable under
    /// `configuration`, fresh for ten minutes.
    pub fn observe_hypervisor(&mut self, available: bool, configuration: ConfigurationFingerprint) {
        let observation = if available {
            Observation::supported(
                configuration,
                600 * SECOND,
                SupportDetail::Hypervisor {
                    hypervisor: HypervisorKind::Kvm,
                },
            )
        } else {
            Observation::unsupported(
                configuration,
                600 * SECOND,
                UnsupportedReason::HypervisorUnavailable,
            )
        };
        self.hypervisor.respond(&hypervisor_subject(), observation);
        self.registry
            .refresh(Capability::HypervisorAvailable, &hypervisor_subject())
            .unwrap();
    }

    /// The perimeter's must-probe of `rule` shows it enforced, or not, under
    /// `configuration`, fresh for ten minutes.
    pub fn observe_perimeter_rule(
        &mut self,
        rule: PerimeterRuleSubject,
        enforced: bool,
        configuration: ConfigurationFingerprint,
    ) {
        let observation = if enforced {
            Observation::supported(
                configuration,
                600 * SECOND,
                SupportDetail::PerimeterRuleEnforced,
            )
        } else {
            Observation::unsupported(configuration, 600 * SECOND, UnsupportedReason::NotEnforced)
        };
        let subject = Subject::PerimeterRule(rule);
        self.perimeter.respond(&subject, observation);
        self.registry
            .refresh(Capability::PerimeterRuleEnforced, &subject)
            .unwrap();
    }

    /// The runtime's category, observed by the host probe now and admitted.
    pub fn admit(&mut self) -> AdmittedRuntime {
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
        RuntimeRequirement::VmSandbox.admit(&offer).unwrap()
    }

    /// A minimal strict contract resolved through V01: one file read permitted at every
    /// layer, a VM sandbox and hardware hypervisor availability required.
    pub fn resolved_contract() -> ResolvedPolicy {
        let read = PermissionTuple {
            principal: Principal::role("main").unwrap(),
            operation: Operation::FileRead,
            resource: ResourceRef::new(PolicyResource::FileGrant, "inputs").unwrap(),
            context: Context {
                phase: PolicyPhase::Analysis,
            },
            generation: GenerationScope::EveryGeneration,
        };
        let product = Validator::product(&ProductPolicyDraft {
            policy_epoch: PolicyEpoch::FIRST,
            ceiling: vec![read.clone()],
            requirements: vec![
                SecurityPredicate::VmSandbox,
                SecurityPredicate::HardwareHypervisorAvailable,
            ],
            approvals: Vec::new(),
            budgets: BudgetSet::vm_d12_task_defaults().into(),
        })
        .unwrap();
        let request = Validator::request(&RequestDocument {
            schema_version: CONTRACT_SCHEMA_VERSION,
            source: RequestSource {
                kind: SourceKind::Template,
                name: SourceName::new("analysis-template").unwrap(),
            },
            requested: vec![read.clone()],
            dependencies: vec![read.clone()],
            requires: Vec::new(),
            legacy_tier: None,
            approvals: Vec::new(),
            budgets: Vec::new(),
        })
        .unwrap();
        let delegation = Validator::delegation(&DelegationDraft {
            granted: vec![read],
            approvals: Vec::new(),
            budgets: Vec::new(),
        })
        .unwrap();
        resolve(&product, &request, &delegation)
    }

    /// What the launch would run on, as V01's evidence checker needs it.
    pub fn launch_targets() -> LaunchTargets {
        LaunchTargets {
            runtime: runtime(),
            runtime_configuration: config("a"),
            hypervisor: HypervisorSubject {
                machine: machine(),
                hypervisor: HypervisorKind::Kvm,
            },
            hypervisor_configuration: config("a"),
            max_age: MINUTE,
            perimeter: None,
        }
    }

    /// The V01 plan of the minimal contract on this world's registry, with the runtime's
    /// category freshly admitted; its identity is what a launch profile carries.
    pub fn plan_contract(&mut self) -> Result<ContractIdentity, PolicyLaunchRefusal> {
        let resolved = Self::resolved_contract();
        let _ = self.admit();
        let plan = plan_launch(&resolved, &self.registry, &Self::launch_targets())?;
        assert_eq!(plan.contract(), resolved.identity());
        Ok(plan.contract())
    }

    pub fn profile(contract: ContractIdentity) -> LaunchProfile {
        LaunchProfile::new(
            config("a"),
            contract,
            PinnedArtifacts {
                guest_image: image(),
                backend: artifact(),
            },
            DeviceProfile {
                identity: named("yougori/test/profile/v1", "minimal"),
                devices: DeviceExposure::cpu_only(),
            },
            RequiredProperties::strictest(MINUTE),
        )
    }

    /// Sets the launch profile of `name` under a freshly planned contract.
    pub fn set_profile(&mut self, name: &str) -> ContractIdentity {
        let contract = self.plan_contract().unwrap();
        self.table
            .set_profile(execution(name), Self::profile(contract));
        contract
    }

    /// Sets the launch profile of `name` under a freshly planned contract, with a network
    /// facet that asks for the host's independent perimeter enforcing `rules` for the
    /// broker.
    pub fn set_perimeter_profile(&mut self, name: &str, rules: &[PerimeterRuleSubject]) {
        let contract = self.plan_contract().unwrap();
        let mut profile = Self::profile(contract);
        profile.required.perimeter = PerimeterRequirement::Independent {
            perimeter: perimeter(),
            principal: broker(),
            rules: rules.iter().map(|rule| rule.rule).collect(),
        };
        self.table.set_profile(execution(name), profile);
    }

    /// Sets the launch profile of `name` under `contract` without planning, for worlds
    /// whose evidence V01 refuses.
    pub fn set_profile_under(&mut self, name: &str, contract: ContractIdentity) {
        self.table
            .set_profile(execution(name), Self::profile(contract));
    }

    /// A launch request straight to the backend contract, bypassing the port: what a VM
    /// this integration never launched looks like.
    pub fn direct_request(name: &str, reservation: u64) -> crate::sandbox::backend::LaunchRequest {
        crate::sandbox::backend::LaunchRequest {
            execution: execution(name),
            tenant: tenant(),
            generations: crate::foundation::coordination::SandboxGenerations::FIRST,
            machine: machine(),
            configuration: config("a"),
            contract: named("yougori/test/contract/v1", "direct"),
            pinned: PinnedArtifacts {
                guest_image: image(),
                backend: artifact(),
            },
            device_profile: DeviceProfile {
                identity: named("yougori/test/profile/v1", "minimal"),
                devices: DeviceExposure::cpu_only(),
            },
            required: RequiredProperties::strictest(MINUTE),
            reservation: serde_json::from_value(reservation.into()).unwrap(),
        }
    }

    pub fn request(&mut self, name: &str, class: SandboxClass) -> LaunchRequest {
        LaunchRequest {
            execution: execution(name),
            tenant: tenant(),
            runtime: self.admit(),
            demand: BTreeMap::from([
                (ResourceKind::HostMemoryBytes, 8 * GIB),
                (ResourceKind::CpuInitializationSlots, 1),
            ]),
            priority: ReservationPriority::Foreground,
            class,
            limits: LeaseLimits::defaults(class),
            settings: SettingsGrant::default(),
            volumes: BTreeMap::new(),
            provider_bills: false,
        }
    }

    pub fn launch_request(
        &mut self,
        request: LaunchRequest,
    ) -> Result<LaunchReceipt, crate::sandbox::lifecycle::SupervisorError> {
        let mut port = port!(self);
        self.supervisor.launch(request, &mut port, &self.registry)
    }

    /// Launches `name` with a profile set under a planned contract when it has none.
    pub fn launch(&mut self, name: &str, class: SandboxClass) -> LaunchReceipt {
        if self.table.profile(&execution(name)).is_none() {
            self.set_profile(name);
        }
        let request = self.request(name, class);
        self.launch_request(request).unwrap()
    }

    pub fn launched(&mut self, name: &str, class: SandboxClass) -> SandboxBootGeneration {
        match self.launch(name, class) {
            LaunchReceipt::AuthorityActive { boot, .. } => boot,
            other => panic!("{other:?}"),
        }
    }

    pub fn state(&self, name: &str) -> SandboxState {
        self.supervisor
            .coordinator()
            .sandbox(&execution(name))
            .unwrap()
            .state()
    }

    pub fn vm(&self, name: &str) -> VmInstanceId {
        self.supervisor
            .coordinator()
            .sandbox(&execution(name))
            .unwrap()
            .vm()
            .unwrap()
    }

    pub fn handle(&self, name: &str) -> VmHandle {
        self.supervisor
            .handles()
            .get(&self.vm(name))
            .unwrap()
            .clone()
    }

    pub fn record(&self, name: &str) -> &LaunchRecord {
        self.table.record(&self.vm(name)).unwrap()
    }

    /// The supervisor asks the backend, through the port, to observe `name`'s VM again.
    pub fn observe_readiness(
        &mut self,
        name: &str,
    ) -> Result<
        crate::sandbox::lifecycle::ObservedReadiness,
        crate::sandbox::lifecycle::SupervisorError,
    > {
        let mut port = port!(self);
        self.supervisor
            .observe_readiness(&execution(name), &mut port)
    }

    pub fn work(
        &mut self,
        name: &str,
        op: &str,
    ) -> Result<crate::foundation::coordination::Lease, crate::sandbox::lifecycle::SupervisorError>
    {
        self.supervisor.authorize_work(
            &execution(name),
            operation(op),
            crate::foundation::coordination::LeaseKind::ChildWork,
            call(),
        )
    }

    /// Revokes and drives the sandbox to stopped: channels acknowledged, every lease
    /// acknowledged, the coordinator advanced through the port.
    pub fn stop_fully(&mut self, name: &str) {
        let exe = execution(name);
        {
            let mut port = port!(self);
            self.supervisor
                .revoke(&exe, RevocationCause::UserRequested, &mut port)
                .unwrap();
        }
        self.supervisor
            .acknowledge(&exe, Acknowledgment::ChannelsClosed)
            .unwrap();
        let leases: Vec<_> = self
            .supervisor
            .coordinator()
            .leases()
            .map(|record| record.lease().id())
            .collect();
        for lease in leases {
            let _ = self
                .supervisor
                .coordinator_mut()
                .acknowledge_cancellation(lease);
        }
        let mut port = port!(self);
        let progress = self.supervisor.advance(&exe, &mut port).unwrap();
        assert!(
            progress.acknowledged.contains(&Acknowledgment::VmStopped),
            "{progress:?}"
        );
        assert_eq!(self.state(name), SandboxState::Stopped);
    }

    pub fn stops_of(&self, name: &str) -> usize {
        let vm = self
            .supervisor
            .coordinator()
            .sandbox(&execution(name))
            .and_then(|sandbox| sandbox.vm());
        self.backend
            .calls()
            .iter()
            .filter(|call| matches!(call, FakeCall::Stop { vm: stopped } if Some(*stopped) == vm))
            .count()
    }

    /// Records every lifecycle receipt since the last drain, every refused launch and
    /// every new launch record, in that order.
    pub fn drain_audit(&mut self) -> AuditDrain {
        let lifecycle = self.supervisor.take_receipts();
        let mut drain = AuditDrain::default();
        for receipt in &lifecycle {
            drain.receipts.push(self.sink.record_receipt(receipt));
        }
        for refused in self.table.take_refused() {
            drain.refusals.push(self.sink.record_refusal(&refused));
        }
        let new: Vec<LaunchRecord> = self
            .table
            .records()
            .filter(|record| !self.recorded.contains(&record.identity()))
            .cloned()
            .collect();
        for record in new {
            drain.launches.push(self.sink.record_launch(&record));
            self.recorded.insert(record.identity());
        }
        drain.lifecycle = lifecycle;
        drain
    }

    pub fn audit_records(&self) -> Vec<AuditRecord> {
        self.storage.all_records()
    }
}
