//! Combined acceptance scenarios INT-01 to INT-10
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, S6 lines 91–110; task T16).
//!
//! Test-only. Every scenario drives the committed modules through their public APIs:
//! the CORE-03 ledger, CORE-04 coordinator, CORE-05 transfer gate, CORE-02 catalog,
//! CORE-06 event plane and CORE-01 evidence registry, with the model-memory modules on
//! top. Fakes stand only at the edges: the VM backend ([`Vms`]), CORE-01 probe adapters,
//! audit storage, the normal loader of GPU §3.10 and bytes held in memory. Time is a
//! manual clock; files go to temporary directories.
//!
//! INT-11 and INT-12 are not applicable yet. INT-11 (model runner migration while old
//! model data and setups exist) needs the runner migration of VM-W38 and the shared
//! setup/API/CLI/UI contract CORE-07, neither of which exists. INT-12 (final legacy
//! appliance retirement) needs the static caller inventory and retirement of VM-W40 and
//! VM-W56. Both are deferred by the rollout plan (§2) and have no module to drive.
//!
//! Tests marked `#[ignore = "integration gap: …"]` state what the plan requires where
//! wiring two committed modules shows that one path cannot reach the other, or that one
//! path bypasses a rule the other enforces. They fail today and are listed in the T16
//! report with the smallest fix in the owning module.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::num::{NonZeroU32, NonZeroU64};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crate::foundation::catalog::{
    ArtifactClass, ArtifactVerifier, Catalog, CatalogConfig, Checkpoint, ContentDescriptor,
    EvictionRefusal, FailureReason, GrantRequest, ImportControl, ImportManifest, ImportProgress,
    ImportRefusal, ImportRequest as CatalogImport, ImportSource, ImportStart, ImportStatus,
    MetadataRefusal, ObjectBytes, ObjectId, ObjectMetadata, ObjectRole, ObjectStatus, Proceed,
    PublisherId, ReadError, ReadRefusal, Scope, SourceError, SourceIdentity as CatalogSource,
    TrustClaim, TrustPolicy, TrustRefusal, Uninterrupted, VerifierRegistry, VerifierRejection,
    VerifyError,
};
use crate::foundation::coordination::{
    validate_model_cache, ActivationDemand, BootRequest, CacheDefect, CheckpointDefect,
    ComponentDefects, CompositeRecovery, CoordinationError, Coordinator, FallbackContext,
    GpuCheckpointManifest, GpuDemand, GpuReservationState, HoldingId, LaunchFailure, LaunchOutcome,
    LaunchPlan, LeaseKind, LeaseRefusal, LeaseTerms, LedgerCapacity, ModelCacheManifest, ModelId,
    ModelRefusal, ObservedVm, PerimeterId, PortFailure, Readiness, ReadinessReport,
    RecoveryComponent, RecoveryContext, RecoveryPath, RecoveryReport as CoordinatorRecovery,
    RelaunchPlan, RelaunchReport, RenewalLimit, ReservationKey, ReservationPriority,
    ReservationPurpose, ResourceKind, RestoreAction, RestoreFailure, RestoredVmReport, Retention,
    RevocationEvents, RevocationMilestone, RevocationStatus, SandboxPort, SandboxRecovery,
    SandboxState, SettingsGrant, SharedLedger, SnapshotContent, SnapshotId, SnapshotManifest,
    SnapshotOrigin, UncertainOutcome, ValidatorVerdict, VmInstanceId,
};
use crate::foundation::events::{
    verify_chain, AuditConfig, AuditDraft, AuditEntry, AuditFailurePolicy, AuditHealth,
    AuditJournal, AuditRecord, AuditRefusal, AuditSpool, AuditStore, DataSource, Durability,
    EmissionLimit, EventContext, EventHub, Field, HostFact, HubConfig, JournalHead, JournalId,
    MetricDraft, MetricValue, MetricsConfig, MetricsProducer, Phase, ProducerId,
    ProducerIncarnation, ProgressConfig, RedactionPolicy, ResourceKind as EventResource,
    Revocation, RevocationAdmission, RevocationConfig, RevocationReason, StoreRefusal,
    TrackedResourceId,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    guard_fallback, AdmittedRuntime, AllowedChange, ArtifactVerification, AuthorityGrant, Backend,
    BackendRelease, Capability, CategoryRefusal, ConfigurationFingerprint, EvidencePolicy,
    FallbackViolation, HostSubject, LoaderGate, LoaderRefusal, LoaderRequest, Necessity,
    NetworkGrant, NotEnabled, Observation, Optimization, ProbeRegistry, RequirementError,
    Residency, RuntimeOffer, RuntimeProfile, RuntimeRequirement, RuntimeSettings, RuntimeSubject,
    SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Clock, ContentKey, Digest, ExecutionCategory, ExecutionId,
    GpuDeviceKey, Incarnation, LeaseId, ManualClock, MonotonicTime, OperationId, PolicyEpoch,
    SandboxBootGeneration, TenantId, TrustScope,
};
use crate::foundation::ledger::{
    Admission, Amounts, CapacityDeclaration, CostPurpose, HostResource, Ledger, LedgerConfig,
    LedgerError, LedgerEvent, Limit, Priority, Provenance, QueueLimits, ReleaseOutcome, Requester,
    ReservationId, ReservationState, ResourceKey, RetryProspect, UsageObservation,
};
use crate::foundation::report::{ClockId, Label as ReportLabel};
use crate::foundation::transfer::fakes::{FakeByteLedger, FakeExtents, FakeProgress};
use crate::foundation::transfer::{
    ByteBudgetRefusal, ByteOrigin, ByteRange, CatalogExtents, Connection, CoordinatorAuthority,
    CredentialRef, Direction, Endpoint, EndpointError, EnvelopeError, EnvelopeFields,
    EventProgress, LedgerByteBudget, ObjectGrant, RangeSet, RetryViolation, SealedEnvelope,
    StopBounds, StopReason, TransferEnvelope, TransferGate, TransferKey, TransferPorts,
    TransferRefusal, TransferScope, TransferStatus, VerifiedExtentsPort,
};
use crate::model_memory::adapters::kv::{
    check_kv_reuse, KvRequest, KvReuseRefusal, KvReuseSpec, KvSharing, PublicPrefixScope,
    PublicPrefixSharing, RankPosition, StoredKv,
};
use crate::model_memory::backends::{
    BackendRuntime, ComputePlatform, PinnedCapabilities, QueriedCapabilities, RuntimeRefusal,
};
use crate::model_memory::executor::{
    CapacityLimit as ExecutorLimit, CapacityRefusal as ExecutorCapacityRefusal, LedgerReservations,
    LoaderPermissions, Priority as ExecutorPriority, ReadMethod, ReservationPort,
    ReservationPurpose as ExecutorPurpose, ReservationRefusal as ExecutorRefusal,
    ReservationRequest as ExecutorRequest, ReservedResource, RetryAdvice, StagingAccount,
};
use crate::model_memory::identity::fakes::scope_enforcement;
use crate::model_memory::identity::{
    decide_storage_sharing, AdapterRecipe, ArtifactIdentity, AuthorityBinding, CodePolicy,
    CommitId, CompileConfiguration, Dtype, ExecutionIdentity, ExecutionSpec,
    GrantRefusal as IdentityGrantRefusal, GrantTerms, GrantedUse, ImmutableRevision, KvAuthority,
    KvPosition, KvRepresentation, KvReuseRefusal as IdentityKvRefusal, KvScopeComponent,
    KvScopeSpec, Label, LogicalModelSpec, PositionalEncoding, Quantization, RankTopology,
    RelativePath, RevocationPort, RevokedAuthorities, ScopeEnforcement, ScopedGrant, ShareRequest,
    SharingMedium, SharingRefusal, SourceFile, SourceIdentity, SourceLocation, SourceSpec,
    StoredRepresentation, TokenPrefix, VersionedName,
};
use crate::model_memory::manifest::{ReadBackChannel, SidecarVerifier};
use crate::model_memory::placement::{
    ActivationError, ActivationIdentity, ActivationRequest, ActivationStarted, AdmissionRequest,
    ArtifactValidity, AssignedRequest, Component,
    CoordinationRefusal as PlacementCoordinationRefusal, CoordinatorBinding, CoordinatorPlacement,
    ExtentKey, ExtentProgress, ExtentSpec, LeaseStatus, PlacementChoice, PlacementSlot,
    ProcessInstance, PublishReport, Rank, ReadinessReport as RankReadiness, RequestShape,
    RequestTicket, ResourceDemand, RouteRefusal, SlotId, SlotSpec, SupportedShape, TransitionMode,
    TransitionPreference, ValidationReport, WeightPosition,
};
use crate::model_memory::progress::fakes::FakeLoader;
use crate::model_memory::progress::{
    JobControl, JobIntent, JobKind, ProgressPublisher, PublishError, PublishPolicy, Stage,
    Submission, TrackRequest,
};
use crate::model_memory::residency::host::{
    HostBacking, HostDemand, HostPlan, HostScope, HostScopeKind, ScopeOccupancy,
};
use crate::model_memory::residency::reservation::{vram_resource, PlacementReservation};
use crate::model_memory::residency::vram::{
    ImmutableAllocation, ImmutableKind, KvBound, ProcessVram, TransientDemand, TransientKind,
    VramPlan,
};
use crate::model_memory::residency::{Capacity, Interval};
use crate::model_memory::vmm::{
    BatchSpec, DeviceOrdinal, ExportId, FakeDeviceSpec, FakeDriver, ProcessContext, ProcessId,
    StreamId, VmmError, VmmModel,
};

// ---------------------------------------------------------------------------------------
// Shared fixtures: units, names, the host's ledger, evidence and VM backend.
// ---------------------------------------------------------------------------------------

type TestClock = Arc<ManualClock>;
/// The coordinator's capacity port over the host's one ledger, shared with its other
/// clients (CORE-03: one capacity authority).
type HostCapacity = LedgerCapacity<TestClock, SharedLedger<TestClock>>;
type HostCoordinator = Coordinator<TestClock, HostCapacity>;

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;
const SECOND: Duration = Duration::from_secs(1);
const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3_600);

const RAM: ResourceKey = ResourceKey::Host(HostResource::Ram);
const PINNED: ResourceKey = ResourceKey::Host(HostResource::PinnedRam);
const STORAGE: ResourceKey = ResourceKey::Host(HostResource::StorageQuota);
const CPU_INIT: ResourceKey = ResourceKey::Host(HostResource::CpuInitializationSlots);

fn named(domain: &str, name: &str) -> Digest {
    digest(domain, &[name.as_bytes()])
}

fn machine() -> Digest {
    named("yougori/test/scenarios/machine/v1", "workstation")
}

/// GPU `index` of the test host, keyed as ledger, coordinator and placement key it.
fn gpu(index: u8) -> GpuDeviceKey {
    GpuDeviceKey {
        machine: machine(),
        device: digest("yougori/test/scenarios/gpu/v1", &[&[index]]),
    }
}

fn vram(index: u8) -> ResourceKey {
    vram_resource(gpu(index))
}

fn tenant(name: &str) -> TenantId {
    TenantId::new(name).unwrap()
}

fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

fn operation(name: &str) -> OperationId {
    OperationId::new(name).unwrap()
}

fn configuration(name: &str) -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_digest(named("yougori/test/scenarios/configuration/v1", name))
}

fn at_seconds(seconds: u64) -> MonotonicTime {
    MonotonicTime::from_nanos(seconds * 1_000_000_000)
}

fn span(start_seconds: u64, end_seconds: u64) -> Interval {
    Interval::new(at_seconds(start_seconds), at_seconds(end_seconds)).unwrap()
}

/// A runtime instance of `category` running vLLM 0.31.0.
fn runtime(category: ExecutionCategory, instance: &str) -> RuntimeSubject {
    RuntimeSubject {
        category,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance: named("yougori/test/scenarios/instance/v1", instance),
    }
}

fn vm_runtime() -> RuntimeSubject {
    runtime(ExecutionCategory::VmSandbox, "vm-host-1")
}

fn model_id(name: &str) -> ModelId {
    ModelId::new(named("yougori/test/scenarios/model/v1", name))
}

/// The CORE-03 ledger of the test host, every capacity observed by a host probe:
/// 32 GiB of RAM with a 2 GiB supervisor reserve, 8 GiB pinned, 24 GiB of VRAM on GPU 0
/// with a 1 GiB reserve, 64 GiB of storage quota and 8 CPU initialization slots. Tenants
/// `tenant-a` and `tenant-b` may each budget all of it.
fn host_ledger(clock: &TestClock) -> Ledger<TestClock> {
    let mut ledger = Ledger::new(
        Arc::clone(clock),
        HostSubject { machine: machine() },
        LedgerConfig {
            queue: QueueLimits {
                max_entries: 8,
                max_entries_per_tenant: 4,
                max_wait: MINUTE,
            },
            grant_ttl: 5 * MINUTE,
            unmanaged_usage_max_age: 24 * HOUR,
        },
    );
    for (resource, total, supervisor_reserve) in [
        (RAM, 32 * GIB, 2 * GIB),
        (PINNED, 8 * GIB, 0),
        (vram(0), 24 * GIB, GIB),
        (STORAGE, 64 * GIB, 0),
        (CPU_INIT, 8, 0),
    ] {
        ledger
            .declare_capacity(
                resource,
                CapacityDeclaration {
                    total,
                    supervisor_reserve,
                    unmanaged_in_use: 0,
                    source: SourceClass::HostProbe,
                },
            )
            .unwrap();
        for name in ["tenant-a", "tenant-b"] {
            ledger
                .set_tenant_budget(tenant(name), resource, total)
                .unwrap();
        }
    }
    ledger
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The loader and sharing capabilities the host probes for INT-06.
const LOADER_CAPABILITIES: [Capability; 8] = [
    Capability::IoUring,
    Capability::GpuDirectStorage,
    Capability::CudaCheckpoint,
    Capability::CudaIpcLegacy,
    Capability::ZeroCopyPreload,
    Capability::SleepWeightOffload,
    Capability::SleepWeightDiscard,
    Capability::ExecuteWhileLoad,
];

/// The host's CORE-01 registry with fake probe adapters: runtime categories as the host
/// and as a provider API observe them, and the loader capabilities of INT-06.
struct Evidence {
    registry: ProbeRegistry<TestClock>,
    host_category: Arc<FakeProbe>,
    provider_category: Arc<FakeProbe>,
    loader: BTreeMap<Capability, Arc<FakeProbe>>,
}

impl Evidence {
    fn new(clock: &TestClock) -> Self {
        let mut registry = ProbeRegistry::new(Arc::clone(clock));
        let host_category =
            Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe).scripted_only());
        let provider_category =
            Arc::new(FakeProbe::runtime_category(SourceClass::ProviderApi).scripted_only());
        registry
            .register(Box::new(Arc::clone(&host_category)))
            .unwrap();
        registry
            .register(Box::new(Arc::clone(&provider_category)))
            .unwrap();
        let loader: BTreeMap<Capability, Arc<FakeProbe>> = LOADER_CAPABILITIES
            .into_iter()
            .map(|capability| {
                (
                    capability,
                    Arc::new(FakeProbe::new(capability, SourceClass::HostProbe)),
                )
            })
            .collect();
        for probe in loader.values() {
            registry.register(Box::new(Arc::clone(probe))).unwrap();
        }
        Self {
            registry,
            host_category,
            provider_category,
            loader,
        }
    }

    /// The host observes the loader capability `capability` working on `runtime` under
    /// configuration `name`, with the detail CORE-01 requires of it.
    fn support(&mut self, capability: Capability, runtime: &RuntimeSubject, name: &str) {
        let subject = Subject::Runtime(runtime.clone());
        let detail = match capability {
            Capability::IoUring | Capability::GpuDirectStorage | Capability::CudaCheckpoint => {
                SupportDetail::Plain
            }
            Capability::CudaIpcLegacy => SupportDetail::CudaIpcLegacy,
            Capability::ZeroCopyPreload
            | Capability::SleepWeightOffload
            | Capability::SleepWeightDiscard => SupportDetail::BackendMode {
                release: runtime.release.clone(),
            },
            Capability::ExecuteWhileLoad => SupportDetail::ExecuteWhileLoad,
            other => panic!("{other} is not a loader capability the test host probes"),
        };
        self.loader[&capability].respond(
            &subject,
            Observation::supported(configuration(name), HOUR, detail),
        );
        self.registry.refresh(capability, &subject).unwrap();
    }

    /// The host (or, for a provider container, the provider API) observes `runtime` as
    /// `observed` now.
    fn observe_category(&mut self, runtime: &RuntimeSubject, observed: ExecutionCategory) {
        let subject = Subject::Runtime(runtime.clone());
        let probe = if runtime.category == ExecutionCategory::ProviderContainerRuntime {
            &self.provider_category
        } else {
            &self.host_category
        };
        probe.respond(
            &subject,
            Observation::supported(
                configuration("launch"),
                HOUR,
                SupportDetail::RuntimeCategory { category: observed },
            ),
        );
        self.registry
            .refresh(Capability::RuntimeCategory, &subject)
            .unwrap();
    }

    /// An offer of `runtime` on fresh evidence of its own category.
    fn offer(&mut self, runtime: &RuntimeSubject) -> RuntimeOffer {
        self.observe_category(runtime, runtime.category);
        RuntimeOffer::observe(
            &self.registry,
            runtime.clone(),
            HOUR,
            configuration("launch"),
        )
        .unwrap()
    }

    /// `runtime` admitted as a VM sandbox on fresh host evidence.
    fn admit_vm(&mut self, runtime: &RuntimeSubject) -> AdmittedRuntime {
        let offer = self.offer(runtime);
        RuntimeRequirement::VmSandbox.admit(&offer).unwrap()
    }
}

/// The VM backend at the edge (VM part §6.1): boots succeed, the host observes
/// readiness, and a restored VM reports what the restore did. Nothing touches the host.
#[derive(Default)]
struct Vms {
    live: BTreeMap<VmInstanceId, ObservedVm>,
    /// The snapshot the last restore used.
    restored: Option<SnapshotManifest>,
    /// Whether a restore skips the reset and keeps the snapshot's guest identity.
    dirty_restores: bool,
    terminated: Vec<VmInstanceId>,
}

impl Vms {
    fn handle(kind: &str, request: &BootRequest) -> Digest {
        digest(
            "yougori/test/scenarios/vm/v1",
            &[
                kind.as_bytes(),
                request.execution.as_str().as_bytes(),
                &request.generations.boot.get().to_be_bytes(),
            ],
        )
    }

    fn boot(&mut self, kind: &str, request: &BootRequest) -> VmInstanceId {
        let vm = VmInstanceId::new(Self::handle(kind, request));
        self.live.insert(
            vm,
            ObservedVm {
                vm,
                execution: request.execution.clone(),
                boot: request.generations.boot,
            },
        );
        vm
    }
}

/// The data volume a restored sandbox may attach.
fn data_volume() -> Digest {
    named("yougori/test/scenarios/volume/v1", "data")
}

impl SandboxPort for Vms {
    fn prepare_perimeter(&mut self, request: &BootRequest) -> Result<PerimeterId, PortFailure> {
        Ok(PerimeterId::new(Self::handle("perimeter", request)))
    }

    fn create_vm(
        &mut self,
        request: &BootRequest,
        _perimeter: &PerimeterId,
    ) -> Result<VmInstanceId, PortFailure> {
        Ok(self.boot("fresh", request))
    }

    fn restore_vm(
        &mut self,
        request: &BootRequest,
        _perimeter: &PerimeterId,
        snapshot: &SnapshotManifest,
    ) -> Result<VmInstanceId, PortFailure> {
        self.restored = Some(snapshot.clone());
        Ok(self.boot("restored", request))
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
        let snapshot = self.restored.clone();
        let guest_identity = match (&snapshot, self.dirty_restores) {
            (Some(snapshot), true) => snapshot.guest_identity,
            _ => digest(
                "yougori/test/scenarios/guest/v1",
                &[&boot.get().to_be_bytes()],
            ),
        };
        RestoredVmReport {
            vm: *vm,
            boot,
            snapshot: snapshot
                .as_ref()
                .map(|snapshot| snapshot.snapshot)
                .unwrap_or_else(|| SnapshotId::new(Digest::from_bytes([0; 32]))),
            guest_identity,
            actions: RestoreAction::REQUIRED.into_iter().collect(),
            attached_volumes: BTreeSet::from([data_volume()]),
            policy: PolicyEpoch::FIRST,
            image_profile: snapshot
                .map(|snapshot| snapshot.image_profile)
                .unwrap_or_else(|| Digest::from_bytes([0; 32])),
            presented_epochs: BTreeSet::new(),
            source: SourceClass::HostProbe,
        }
    }

    fn terminate_vm(&mut self, vm: &VmInstanceId) -> Result<(), PortFailure> {
        self.live.remove(vm);
        self.terminated.push(*vm);
        Ok(())
    }

    fn teardown_perimeter(&mut self, _perimeter: &PerimeterId) -> Result<(), PortFailure> {
        Ok(())
    }

    fn list_vms(&mut self) -> Result<Vec<ObservedVm>, PortFailure> {
        Ok(self.live.values().cloned().collect())
    }
}

/// One host: the manual clock, the evidence registry, the VM backend and the CORE-04
/// coordinator over the host's one CORE-03 ledger. The coordinator is shared, as the
/// transfer authority adapter needs it.
struct Host {
    clock: TestClock,
    evidence: Evidence,
    vms: Vms,
    coordinator: Arc<Mutex<HostCoordinator>>,
    /// The host's one ledger: the coordinator's capacity port charges it, and the handle
    /// it shares (`handle()`) goes to the transfer byte budget, the executor's
    /// reservations and T08's placement adapter, so each resource is granted once.
    ledger: SharedLedger<TestClock>,
    /// The host's transfer key, loaded once; every gate gets a clone, so replay state is
    /// shared (CORE-05).
    key: TransferKey,
}

impl Host {
    fn new() -> Self {
        Self::with_capacity(LedgerCapacity::shared)
    }

    /// A host whose launch reservations may wait in the ledger's bounded queue.
    fn queueing() -> Self {
        Self::with_capacity(|ledger| LedgerCapacity::shared(ledger).with_queue_wait(MINUTE))
    }

    fn with_capacity(capacity: impl FnOnce(SharedLedger<TestClock>) -> HostCapacity) -> Self {
        let clock = Arc::new(ManualClock::new(at_seconds(1_000)));
        let evidence = Evidence::new(&clock);
        let capacity = capacity(Arc::new(Mutex::new(host_ledger(&clock))));
        let ledger = capacity.handle();
        let coordinator =
            Coordinator::new(Arc::clone(&clock), evidence.registry.session(), capacity);
        Self {
            clock,
            evidence,
            vms: Vms::default(),
            coordinator: Arc::new(Mutex::new(coordinator)),
            ledger,
            key: TransferKey::from_bytes(&[0x5a; 32]).unwrap(),
        }
    }

    /// The host's one ledger, locked while the guard lives.
    fn ledger(&self) -> MutexGuard<'_, Ledger<TestClock>> {
        lock(&self.ledger)
    }

    /// T14's byte budget over the host's one ledger: downloads and peer transfers are
    /// charged to the storage quota the coordinator's reservations draw on too.
    fn byte_budget(&self) -> Arc<LedgerByteBudget<TestClock>> {
        Arc::new(
            LedgerByteBudget::new(
                Arc::clone(&self.ledger),
                Arc::clone(&self.clock) as Arc<dyn Clock>,
                BTreeMap::from([(Direction::Download, STORAGE), (Direction::Peer, STORAGE)]),
                Priority::Foreground,
            )
            .unwrap(),
        )
    }

    /// The state of the transfer reservation `name` holds in the host's ledger, while it
    /// is open.
    fn transfer_reservation(&self, name: &str) -> Option<ReservationState> {
        self.ledger()
            .open_reservations()
            .find(|record| {
                let provenance = record.provenance();
                provenance.requester == Requester::Transfer
                    && provenance.operation == operation(name)
            })
            .map(|record| record.state())
    }

    /// Seals `fields` with the host's transfer key, as the issuer of a grant does.
    fn seal(&self, fields: EnvelopeFields) -> SealedEnvelope {
        self.key.seal(TransferEnvelope::new(fields).unwrap())
    }

    fn coordinator(&self) -> MutexGuard<'_, HostCoordinator> {
        lock(&self.coordinator)
    }

    fn advance(&self, by: Duration) {
        self.clock.advance(by);
    }

    /// A VM sandbox launch for `of` of `owner`, reserving `demand`, in the foreground.
    fn plan(
        &mut self,
        of: &ExecutionId,
        owner: &TenantId,
        demand: BTreeMap<ResourceKind, u64>,
    ) -> LaunchPlan {
        LaunchPlan {
            execution: of.clone(),
            tenant: owner.clone(),
            runtime: self.evidence.admit_vm(&vm_runtime()),
            demand,
            priority: ReservationPriority::Foreground,
            authority_lifetime: HOUR,
            readiness_max_age: 5 * SECOND,
            runtime_evidence_max_age: HOUR,
        }
    }

    fn try_launch(&mut self, plan: LaunchPlan) -> Result<LaunchOutcome, CoordinationError> {
        let mut coordinator = lock(&self.coordinator);
        coordinator.launch(plan, &mut self.vms, &self.evidence.registry)
    }

    fn launch(&mut self, plan: LaunchPlan) -> LaunchOutcome {
        self.try_launch(plan).unwrap()
    }

    /// Launches `of` to authority and running; returns its grant. Its models get no
    /// network and no verified artifact.
    fn launched(
        &mut self,
        of: &ExecutionId,
        owner: &TenantId,
        demand: BTreeMap<ResourceKind, u64>,
    ) -> AuthorityGrant {
        self.launched_with(of, owner, demand, SettingsGrant::default())
    }

    /// Launches `of` with its authority granting its models `settings`.
    fn launched_with(
        &mut self,
        of: &ExecutionId,
        owner: &TenantId,
        demand: BTreeMap<ResourceKind, u64>,
        settings: SettingsGrant,
    ) -> AuthorityGrant {
        let plan = self.plan(of, owner, demand);
        let outcome = {
            let mut coordinator = lock(&self.coordinator);
            coordinator
                .launch_with(plan, settings, &mut self.vms, &self.evidence.registry)
                .unwrap()
        };
        let LaunchOutcome::AuthorityActive { grant, .. } = outcome else {
            panic!("the sandbox launches");
        };
        self.coordinator().start_running(of).unwrap();
        grant
    }

    /// Advances the revocation of `of` as far as acknowledgments and time allow.
    fn advance_revocation(&mut self, of: &ExecutionId) -> RevocationStatus {
        let mut coordinator = lock(&self.coordinator);
        coordinator.advance_revocation(of, &mut self.vms).unwrap()
    }

    /// The ledger's own number for the sandbox reservation of `of`'s current boot.
    fn sandbox_reservation(&self, of: &ExecutionId) -> ReservationId {
        let coordinator = self.coordinator();
        let key = coordinator.sandbox(of).unwrap().reservation().unwrap();
        coordinator.capacity().record(&key).unwrap().id()
    }

    fn available(&self, resource: ResourceKey) -> Option<u64> {
        self.ledger().available(resource)
    }

    fn reserved(&self, resource: ResourceKey) -> u64 {
        self.ledger().reserved(resource)
    }
}

/// The demand of a VM sandbox: host RAM, pinned staging, VRAM on GPU 0 and one CPU
/// initialization slot.
fn sandbox_demand(
    ram_bytes: u64,
    pinned_bytes: u64,
    vram_bytes: u64,
) -> BTreeMap<ResourceKind, u64> {
    BTreeMap::from([
        (ResourceKind::HostMemoryBytes, ram_bytes),
        (ResourceKind::PinnedHostMemoryBytes, pinned_bytes),
        (ResourceKind::GpuMemoryBytes { device: gpu(0) }, vram_bytes),
        (ResourceKind::CpuInitializationSlots, 1),
    ])
}

/// The settings a model activation runs with under `grant`: the parent's category, no
/// network, verified weights, the ordinary loader.
fn settings_for(grant: AuthorityGrant, verified: BTreeSet<Digest>) -> RuntimeSettings {
    RuntimeSettings {
        execution_category: ExecutionCategory::VmSandbox,
        network: BTreeSet::new(),
        authority: grant,
        artifact_verification: ArtifactVerification::Verified {
            artifacts: verified,
        },
        loader: BTreeSet::new(),
        batch_size: NonZeroU32::new(8).unwrap(),
        residency: Residency::Device,
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

// ---------------------------------------------------------------------------------------
// INT-01: VM start and model load race for host RAM and pinned staging.
// ---------------------------------------------------------------------------------------

fn placement_provenance(of: &ExecutionId, owner: &TenantId) -> Provenance {
    Provenance {
        requester: Requester::ModelPlacement,
        execution: of.clone(),
        operation: operation(&format!("op-load-{of}")),
        tenant: owner.clone(),
        purpose: CostPurpose::Compute,
        retry_number: 0,
    }
}

/// A model load as T08 residency plans it (GPU §2.7): 8 GiB of weights, a 2 GiB KV pool
/// and a 512 MiB context for ten seconds, with 1 GiB of device staging during [2, 3).
/// The host side runs a 6 GiB runtime and a 3 GiB pinned staging ring throughout, plus a
/// 4 GiB unpack buffer and a 2 GiB pinned copy during [2, 4), so its peaks overlap there.
fn model_load_plans(scope: TrustScope) -> (VramPlan, HostPlan) {
    let vram_plan = VramPlan {
        device: gpu(0),
        usable_vram: Capacity::Physical { bytes: 23 * GIB },
        safety_reserve_bytes: 256 * MIB,
        allocations: vec![ImmutableAllocation {
            key: "weights".to_owned(),
            kind: ImmutableKind::Weights,
            bytes: 8 * GIB,
            sharing_domain: scope,
            resident: span(0, 10),
        }],
        processes: vec![ProcessVram {
            process: "runner".to_owned(),
            sharing_domain: scope,
            lifetime: span(0, 10),
            maps: vec!["weights".to_owned()],
            context_bytes: 512 * MIB,
            graph_pool_bytes: 0,
            kv: KvBound::Reserved { bytes: 2 * GIB },
            transients: vec![TransientDemand {
                kind: TransientKind::Staging,
                bytes: GIB,
                during: span(2, 3),
            }],
        }],
    };
    let demand = |label: &str, backing: HostBacking, bytes: u64, during: Interval| HostDemand {
        label: label.to_owned(),
        backing,
        bytes,
        during,
        memory_scope: "host-ram".to_owned(),
        pinned_scope: (backing == HostBacking::Pinned).then(|| "pinned".to_owned()),
    };
    let host_plan = HostPlan {
        scopes: vec![
            HostScope {
                name: "host-ram".to_owned(),
                kind: HostScopeKind::HostRam,
                parent: None,
                capacity: Capacity::Physical { bytes: 30 * GIB },
                safety_reserve_bytes: 256 * MIB,
                occupancy: ScopeOccupancy::default(),
            },
            HostScope {
                name: "pinned".to_owned(),
                kind: HostScopeKind::PinnedRam,
                parent: None,
                capacity: Capacity::Physical { bytes: 8 * GIB },
                safety_reserve_bytes: 256 * MIB,
                occupancy: ScopeOccupancy::default(),
            },
        ],
        demands: vec![
            demand("runtime", HostBacking::Anonymous, 6 * GIB, span(0, 10)),
            demand("staging ring", HostBacking::Pinned, 3 * GIB, span(0, 10)),
            demand("unpack buffer", HostBacking::Anonymous, 4 * GIB, span(2, 4)),
            demand("pinned copy", HostBacking::Pinned, 2 * GIB, span(2, 4)),
        ],
    };
    (vram_plan, host_plan)
}

/// The model load of tenant B on a labelled WSL runtime: a host-level reservation of its
/// peaks, through T08's adapter.
fn model_load(owner: &TenantId) -> PlacementReservation {
    let scope = TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, owner.as_str());
    let (vram_plan, host_plan) = model_load_plans(scope);
    PlacementReservation::new(
        placement_provenance(&execution("exe-wsl-load"), owner),
        Priority::Foreground,
        &[vram_plan],
        Some(&host_plan),
    )
    .unwrap()
}

/// INT-01 (S6 line 97): a VM start and a model load race for host RAM and pinned staging,
/// in either order. One CORE-03 ledger, reached by the CORE-04 launch transaction and by
/// T08 residency's placement adapter, accounts for both: their RAM fits together, their
/// pinned staging does not, so exactly one is granted and the other is told which
/// resource limits it and that a release lets it fit. Nothing is double-allocated.
#[test]
fn int01_vm_start_and_model_load_never_both_take_the_same_pinned_staging() {
    for vm_first in [true, false] {
        let mut host = Host::new();
        let sandbox = execution("exe-vm-a");
        let owner = tenant("tenant-a");
        let load = model_load(&tenant("tenant-b"));
        // T08 combined the overlapping peaks: RAM 6 + 3 + 4 + 2 GiB and pinned 3 + 2 GiB
        // during [2, 4); VRAM 8 + 2 + 0.5 + 1 GiB during [2, 3).
        assert_eq!(load.request().demand.get(RAM), 15 * GIB);
        assert_eq!(load.request().demand.get(PINNED), 5 * GIB);
        assert_eq!(load.request().demand.get(vram(0)), 11 * GIB + 512 * MIB);

        let plan = host.plan(
            &sandbox,
            &owner,
            sandbox_demand(12 * GIB, 4 * GIB, 10 * GIB),
        );
        let (vm_outcome, load_outcome) = if vm_first {
            let vm = host.launch(plan);
            let load = load.reserve(&mut host.ledger());
            (vm, load)
        } else {
            let load = load.reserve(&mut host.ledger());
            let vm = host.launch(plan);
            (vm, load)
        };

        // Exactly one contender holds the pinned staging; the host never grants more
        // than its 8 GiB, and RAM, which fits both, is never double-counted either.
        let pinned = host.reserved(PINNED);
        assert!(
            pinned <= 8 * GIB,
            "pinned staging double-allocated: {pinned}"
        );
        assert_eq!(pinned + host.available(PINNED).unwrap(), 8 * GIB);
        assert_eq!(host.reserved(RAM) + host.available(RAM).unwrap(), 30 * GIB);
        if vm_first {
            assert!(matches!(vm_outcome, LaunchOutcome::AuthorityActive { .. }));
            let Err(LedgerError::Capacity(refusal)) = load_outcome else {
                panic!("the model load must be refused, got {load_outcome:?}");
            };
            assert_eq!(refusal.resource(), PINNED, "pinned staging limits the load");
            assert_eq!(refusal.limiting().limit, Limit::PhysicalCapacity);
            assert_eq!(refusal.limiting().available, 4 * GIB);
            assert_eq!(
                refusal.limiting().prospect,
                RetryProspect::FitsAfterRelease { shortfall: GIB }
            );
            assert!(refusal.retry_can_progress());
            assert_eq!(host.reserved(PINNED), 4 * GIB);
            assert_eq!(host.reserved(RAM), 12 * GIB);
        } else {
            assert!(matches!(load_outcome, Ok(Admission::Granted(_))));
            let LaunchOutcome::RolledBack { failure, .. } = &vm_outcome else {
                panic!("the VM start must be refused, got {vm_outcome:?}");
            };
            let LaunchFailure::Capacity { refusal } = failure else {
                panic!("a capacity refusal, got {failure:?}");
            };
            assert_eq!(
                refusal.limiting_resource(),
                Some(ResourceKind::PinnedHostMemoryBytes)
            );
            assert_eq!(host.reserved(PINNED), 5 * GIB);
            assert_eq!(host.reserved(RAM), 15 * GIB);
            assert_eq!(
                host.coordinator().sandbox(&sandbox).unwrap().state(),
                SandboxState::Stopped,
                "a refused launch leaves nothing behind"
            );
        }
    }
}

/// INT-01: the VM start waits in the ledger's bounded queue behind a model load. When
/// the load stops after it was created, its staging stays counted until the host
/// observes the release: a guest report frees nothing (S3.2, S2 CORE-03), so the VM still
/// waits. The host's observation wakes the queue and the launch completes. Inside the
/// sandbox, the coordinator's model holdings and a T08 placement carved directly from the
/// same parent share one parent budget.
#[test]
fn int01_released_load_frees_capacity_only_on_host_observation_and_children_share_the_parent() {
    let mut host = Host::queueing();
    let sandbox = execution("exe-vm-a");
    let owner = tenant("tenant-a");
    let Ok(Admission::Granted(load)) = model_load(&tenant("tenant-b")).reserve(&mut host.ledger())
    else {
        panic!("the model load is granted first");
    };
    host.ledger().begin_create(load).unwrap();

    let plan = host.plan(
        &sandbox,
        &owner,
        sandbox_demand(12 * GIB, 4 * GIB, 10 * GIB),
    );
    assert_eq!(
        host.launch(plan.clone()),
        LaunchOutcome::Queued { position: 1 }
    );
    assert_eq!(
        host.coordinator().sandbox(&sandbox).unwrap().state(),
        SandboxState::Planned
    );

    // The load stops; its workload existed, so its amounts still count.
    let cancelled = host.ledger().cancel(load).unwrap();
    assert_eq!(cancelled, ReleaseOutcome::Pending);
    assert_eq!(host.available(PINNED), Some(3 * GIB));
    assert_eq!(
        host.launch(plan.clone()),
        LaunchOutcome::Queued { position: 1 }
    );

    // A guest says the memory is free: an observation, never authority.
    {
        let mut ledger = host.ledger();
        ledger
            .observe_usage(
                load,
                UsageObservation {
                    source: SourceClass::GuestReport,
                    in_use: Amounts::new(),
                },
            )
            .unwrap();
        assert_eq!(
            ledger.confirm_release(load, SourceClass::GuestReport),
            Err(LedgerError::SourceNotAuthoritative {
                source: SourceClass::GuestReport,
                required: SourceClass::HostProbe,
            })
        );
    }
    assert_eq!(host.available(PINNED), Some(3 * GIB));
    assert_eq!(
        host.launch(plan.clone()),
        LaunchOutcome::Queued { position: 1 }
    );

    // The host observes the release; the queue wakes and grants the VM start.
    let released = host
        .ledger()
        .confirm_release(load, SourceClass::HostProbe)
        .unwrap();
    assert!(matches!(released, ReleaseOutcome::Released { .. }));
    let events = host.ledger().drain_events();
    assert!(events
        .iter()
        .any(|event| matches!(event, LedgerEvent::QueueGranted { .. })));
    let LaunchOutcome::AuthorityActive { grant, .. } = host.launch(plan) else {
        panic!("the queued launch completes once its reservation is granted");
    };
    host.coordinator().start_running(&sandbox).unwrap();
    assert_eq!(host.reserved(PINNED), 4 * GIB);
    assert_eq!(host.reserved(RAM), 12 * GIB);

    // Inside the sandbox: a coordinator activation reserves 2 GiB of pinned staging as a
    // child of the sandbox reservation; host-level totals do not move.
    let parent = host.sandbox_reservation(&sandbox);
    host.coordinator()
        .begin_activation_with(
            &sandbox,
            model_id("chat"),
            settings_for(grant, BTreeSet::new()),
            ActivationDemand {
                gpu_memory_bytes: BTreeMap::from([(gpu(0), 6 * GIB)]),
                host_memory_bytes: 4 * GIB,
                pinned_host_memory_bytes: 2 * GIB,
                acquire: BTreeSet::new(),
                retention: Retention::ReleaseWhenUnused,
            },
        )
        .unwrap();
    assert_eq!(host.reserved(PINNED), 4 * GIB);
    let room = |host: &Host, resource| host.ledger().parent_room(parent, resource).unwrap();
    assert_eq!(room(&host, PINNED), 2 * GIB);

    // A T08 placement carved directly from the same parent sees the same budget: its
    // peaks (15 GiB RAM, 5 GiB pinned, 11.5 GiB VRAM) exceed what the parent has, and
    // every shortfall names the parent, the pinned one with the 2 GiB left.
    let in_vm = TrustScope::named(ExecutionCategory::VmSandbox, "tenant-a");
    let (vram_plan, host_plan) = model_load_plans(in_vm);
    let refused = PlacementReservation::new(
        placement_provenance(&sandbox, &owner),
        Priority::Foreground,
        &[vram_plan],
        Some(&host_plan),
    )
    .unwrap()
    .within(parent)
    .reserve(&mut host.ledger());
    let Err(LedgerError::Capacity(refusal)) = refused else {
        panic!("the child does not fit its parent, got {refused:?}");
    };
    assert!(refusal
        .shortfalls()
        .all(|shortfall| shortfall.limit == Limit::ParentReservation { parent }));
    let pinned = refusal
        .shortfalls()
        .find(|shortfall| shortfall.resource == PINNED)
        .unwrap();
    assert_eq!((pinned.requested, pinned.available), (5 * GIB, 2 * GIB));
    assert_eq!(room(&host, PINNED), 2 * GIB, "a refusal reserves nothing");
    assert_eq!(host.reserved(PINNED), 4 * GIB);
    assert_eq!(host.reserved(RAM) + host.available(RAM).unwrap(), 30 * GIB);
}

// ---------------------------------------------------------------------------------------
// Placement fixtures: T07 identities and P04 activation requests for one model slot.
// ---------------------------------------------------------------------------------------

const SHAPE: SupportedShape = SupportedShape {
    max_context_tokens: 8_192,
    max_batch_sequences: 4,
};

fn label(value: &str) -> Label {
    Label::new(value).unwrap()
}

fn versioned(name: &str, version: &str) -> VersionedName {
    VersionedName::new(name, version).unwrap()
}

/// The T07 source identity of a published model named `name`.
fn source_of(name: &str) -> SourceIdentity {
    SourceSpec {
        location: SourceLocation::Repository {
            host: label("huggingface.co"),
            repository: label(&format!("example-org/{name}")),
        },
        revision: ImmutableRevision::Commit(
            CommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap(),
        ),
        files: vec![SourceFile {
            path: RelativePath::new("model.safetensors").unwrap(),
            length_bytes: 1_000,
            content: ContentKey::of(name.as_bytes()),
        }],
        configuration: named("yougori/test/scenarios/model-config/v1", name),
        published_dtype: Dtype::BFloat16,
        license: label("apache-2.0"),
        provenance: None,
    }
    .identity()
    .unwrap()
}

/// The T07 execution identity of `model` on one rank.
fn execution_of(model: &str) -> ExecutionIdentity {
    let logical = LogicalModelSpec {
        source: source_of(model),
        dtype: Dtype::BFloat16,
        quantization: Quantization::None,
        tokenizer: named("yougori/test/scenarios/tokenizer/v1", model),
        generation_config: named("yougori/test/scenarios/generation/v1", model),
        adapters: AdapterRecipe::None,
        code_policy: CodePolicy::BuiltInOnly,
    }
    .identity();
    ExecutionSpec {
        logical,
        runner: versioned("vllm", "0.31.0"),
        architecture_adapter: versioned("llama", "1"),
        kernel_layout: versioned("flash-attn", "2.7.4"),
        gpu_architectures: BTreeSet::from([label("sm_90a")]),
        topology: RankTopology::new(1, 1, 1).unwrap(),
        processed_weights: versioned("vllm-bf16", "1"),
        compile: CompileConfiguration::Eager,
    }
    .identity()
    .unwrap()
}

fn artifact_of(model: &str) -> ArtifactIdentity {
    ArtifactIdentity::from_manifest_digest(&named("yougori/test/scenarios/manifest/v1", model))
}

fn extent(content: &str) -> ExtentKey {
    ExtentKey {
        content: ContentKey::of(content.as_bytes()),
        device: gpu(0),
    }
}

fn position(component: Component) -> WeightPosition {
    WeightPosition::new(Rank::new(0), component)
}

/// Model A: 10 GiB of weights in four parts on rank 0, GPU 0.
fn model_a() -> Vec<(Component, &'static str, u64)> {
    vec![
        (Component::Embedding, "a-embed", GIB),
        (Component::Layer(0), "a-layer-0", 4 * GIB),
        (Component::Layer(1), "a-layer-1", 4 * GIB),
        (Component::OutputHead, "a-head", GIB),
    ]
}

/// A weight update of model A: layer 1 changed, the other three parts shared.
fn model_b() -> Vec<(Component, &'static str, u64)> {
    let mut parts = model_a();
    parts[2] = (Component::Layer(1), "b-layer-1", 4 * GIB);
    parts
}

/// Step 1 of GPU §3.6 for `model`: steady state of its weights plus 2 GiB, and a 1 GiB
/// transition peak, on GPU 0.
fn activation_request(model: &str, parts: &[(Component, &'static str, u64)]) -> ActivationRequest {
    let weights: u64 = parts.iter().map(|(_, _, bytes)| bytes).sum();
    ActivationRequest {
        operation: operation(&format!("activate-{model}")),
        identity: ActivationIdentity {
            execution: execution_of(model),
            artifact: artifact_of(model),
            adapters: BTreeMap::new(),
        },
        placement: PlacementChoice::New {
            process: ProcessInstance::new(1),
        },
        artifact: ArtifactValidity::Verified {
            artifact: artifact_of(model),
        },
        layout: BTreeMap::from([(Rank::new(0), gpu(0))]),
        components: parts
            .iter()
            .map(|(component, content, bytes)| ExtentSpec {
                position: position(*component),
                extent: extent(content),
                bytes: *bytes,
            })
            .collect(),
        steady: ResourceDemand {
            vram_bytes: BTreeMap::from([(gpu(0), weights + 2 * GIB)]),
            host_ram_bytes: 0,
            pinned_host_bytes: 0,
        },
        transition_peak: ResourceDemand {
            vram_bytes: BTreeMap::from([(gpu(0), GIB)]),
            host_ram_bytes: 0,
            pinned_host_bytes: 0,
        },
        declared_shape: SHAPE,
        preference: TransitionPreference::OverlapOrPause,
    }
}

/// One P04 model slot of a sandbox, driven through the coordinator's ports.
struct ModelSlot {
    owner: ExecutionId,
    model: ModelId,
    state: CoordinatorPlacement,
    slot: PlacementSlot<TestClock>,
}

impl ModelSlot {
    fn new(
        host: &Host,
        owner: &ExecutionId,
        owner_tenant: &TenantId,
        grant: AuthorityGrant,
    ) -> Self {
        let model = model_id("chat");
        Self {
            owner: owner.clone(),
            model,
            state: CoordinatorPlacement::new(CoordinatorBinding {
                execution: owner.clone(),
                model,
                settings: settings_for(grant, BTreeSet::new()),
                cancel_within: 5 * SECOND,
                release_source: SourceClass::GuestReport,
            }),
            slot: PlacementSlot::new(
                SlotSpec {
                    slot: SlotId::new(named("yougori/test/scenarios/slot/v1", "chat")),
                    tenant: owner_tenant.clone(),
                    authority: AuthorityBinding::new(
                        owner.clone(),
                        ExecutionCategory::VmSandbox,
                        Some(grant.epoch),
                    )
                    .unwrap(),
                },
                Arc::clone(&host.clock),
            ),
        }
    }

    fn begin(
        &mut self,
        host: &Host,
        request: &ActivationRequest,
    ) -> Result<ActivationStarted, ActivationError> {
        let mut coordinator = host.coordinator();
        self.slot
            .begin_activation(request, &mut self.state.port(&mut coordinator))
    }

    /// Step 2 up to allocation: the extents are allocated but not yet usable.
    fn allocate(&mut self, host: &Host) -> ExtentProgress {
        let mut coordinator = host.coordinator();
        self.slot
            .prepare_extents(&mut self.state.port(&mut coordinator))
            .unwrap()
    }

    /// The rest of step 2: every allocated extent populated and verified.
    fn finish_loading(&mut self, progress: &ExtentProgress) {
        for (extent, _) in &progress.allocated {
            self.slot.record_extent_usable(*extent).unwrap();
        }
        self.slot.record_runtime_initialized().unwrap();
        self.slot.materialize().unwrap();
    }

    /// Steps 3–5 on the one rank.
    fn validate_and_publish(&mut self, host: &Host) -> Result<PublishReport, ActivationError> {
        self.slot.begin_activating()?;
        let Some(activation) = self.slot.activation() else {
            return Err(ActivationError::NoActivation);
        };
        let mut coordinator = host.coordinator();
        let mut port = self.state.port(&mut coordinator);
        for rank in activation.waiting_ranks {
            self.slot.record_validation(
                &ValidationReport {
                    generation: activation.generation,
                    rank,
                    weights_verified: true,
                    buffers_ready: true,
                    graphs_compatible: true,
                    coordination: named("yougori/test/scenarios/communicator/v1", "nccl"),
                },
                &mut port,
            )?;
            self.slot.record_readiness(
                activation.generation,
                rank,
                &RankReadiness::Ready { supported: SHAPE },
                &mut port,
            )?;
        }
        self.slot.publish(&mut port)
    }

    fn activate(&mut self, host: &Host, request: &ActivationRequest) -> PublishReport {
        self.begin(host, request).unwrap();
        let progress = self.allocate(host);
        self.finish_loading(&progress);
        self.validate_and_publish(host).unwrap()
    }

    fn admission(&self, host: &Host, name: &str, epoch: AuthorizationEpoch) -> AdmissionRequest {
        AdmissionRequest {
            request: operation(name),
            execution: self.owner.clone(),
            epoch,
            shape: RequestShape {
                context_tokens: 1_024,
                batch_sequences: 1,
            },
            adapter: None,
            lease_expires_at: host.clock.now().saturating_add(HOUR),
        }
    }

    fn admit(
        &mut self,
        host: &Host,
        name: &str,
        epoch: AuthorizationEpoch,
    ) -> Result<RequestTicket, RouteRefusal> {
        let admission = self.admission(host, name, epoch);
        let mut coordinator = host.coordinator();
        self.slot
            .admit(&admission, &mut self.state.port(&mut coordinator))
    }

    fn finish(&mut self, host: &Host, ticket: &RequestTicket) {
        let mut coordinator = host.coordinator();
        self.slot
            .finish(ticket, &mut self.state.port(&mut coordinator))
            .unwrap();
    }
}

// ---------------------------------------------------------------------------------------
// INT-02: sandbox authorization revoked while weights load, stream or prefetch.
// ---------------------------------------------------------------------------------------

/// A transfer gate whose authority is the host's coordinator (CORE-05 over CORE-04) and
/// whose byte budget is charged to the host's one ledger. Verified extents and progress
/// are the transfer module's fakes here; INT-08 and INT-10 use the real adapters.
fn coordinator_gate(host: &Host) -> (TransferGate, Arc<LedgerByteBudget<TestClock>>) {
    let budget = host.byte_budget();
    let gate = TransferGate::new(
        host.key.clone(),
        TransferPorts {
            clock: Arc::clone(&host.clock) as Arc<dyn Clock>,
            clock_session: host.evidence.registry.session(),
            authority: Arc::new(CoordinatorAuthority::new(Arc::clone(&host.coordinator))),
            budget: budget.clone(),
            extents: Arc::new(FakeExtents::default()),
            progress: Arc::new(FakeProgress::default()),
        },
    );
    (gate, budget)
}

fn hub_route() -> Endpoint {
    Endpoint::NamedRoute {
        route: named("yougori/test/scenarios/route/v1", "model-hub"),
    }
}

fn hub_credential() -> CredentialRef {
    CredentialRef::from_digest(named("yougori/test/scenarios/credential/v1", "hub-token"))
}

/// A credentialed download into the host catalog of `objects` (each a whole object of its
/// size), under `epoch` of `parent`, with a byte budget of the scope plus half again.
fn download(
    host: &Host,
    name: &str,
    parent: &ExecutionId,
    owner: &TenantId,
    epoch: AuthorizationEpoch,
    objects: &[(ContentKey, u64)],
) -> EnvelopeFields {
    let scope = TransferScope::new(
        objects
            .iter()
            .map(|(key, size)| (*key, ObjectGrant::whole(*size).unwrap())),
    )
    .unwrap();
    let total: u64 = objects.iter().map(|(_, size)| size).sum();
    EnvelopeFields {
        operation: operation(name),
        tenant: owner.clone(),
        parent: parent.clone(),
        epoch,
        direction: Direction::Download,
        source: hub_route(),
        recipient: Endpoint::HostCatalog,
        credential: Some(hub_credential()),
        scope,
        budget_bytes: total + total / 2,
        stop_bounds: StopBounds {
            max_in_flight_bytes: 64,
            max_chunk_duration: 10 * SECOND,
        },
        clock: host.evidence.registry.session(),
        expires_at: host.clock.now().saturating_add(HOUR),
    }
}

fn hub_connection() -> Connection {
    Connection {
        source: hub_route(),
        recipient: Endpoint::HostCatalog,
        credential: Some(hub_credential()),
    }
}

fn byte_range(start_bytes: u64, end_bytes: u64) -> ByteRange {
    ByteRange::new(start_bytes, end_bytes).unwrap()
}

/// INT-02 (S6 line 98): the sandbox's authorization is revoked while model B's weights
/// load (with one request assigned to compute while they load), a request streams from
/// model A, and the next model's weights prefetch. New work is denied at once on every
/// path, every lease is cancelled with its declared bound, the open transfer stops at its
/// next chunk, its byte budget on the host's one ledger is cancelled by the revocation and
/// counted until its dropped chunk's deadline, GPU memory is reclaimed only once no lease
/// may still use it, and nothing extends authority.
#[test]
fn int02_revocation_while_loading_streaming_and_prefetching_reclaims_safely() {
    let mut host = Host::new();
    let owner = execution("exe-vm-a");
    let owner_tenant = tenant("tenant-a");
    let grant = host.launched(
        &owner,
        &owner_tenant,
        sandbox_demand(16 * GIB, 4 * GIB, 22 * GIB),
    );
    let epoch = grant.epoch;
    let mut slot = ModelSlot::new(&host, &owner, &owner_tenant, grant);

    // Streaming: model A serves, and one request holds a serving lease.
    let first = slot.activate(&host, &activation_request("model-a", &model_a()));
    let streaming = slot.admit(&host, "req-stream", epoch).unwrap();
    assert_eq!(streaming.generation, first.generation);

    // Loading: model B's activation overlaps A's, its new extent allocated but not yet
    // usable, and one pending request computes while it loads (GPU §3.6 line 601).
    let started = slot
        .begin(&host, &activation_request("model-b", &model_b()))
        .unwrap();
    assert_eq!(started.mode, TransitionMode::Overlap);
    let loading = slot.allocate(&host);
    assert_eq!(loading.allocated.len(), 1);
    let early = {
        let assigned = AssignedRequest {
            request: operation("req-early"),
            execution: owner.clone(),
            epoch,
            required: BTreeSet::from([position(Component::Layer(0))]),
            lease_expires_at: host.clock.now().saturating_add(10 * MINUTE),
        };
        let mut coordinator = host.coordinator();
        slot.slot
            .assign_early_request(&assigned, &mut slot.state.port(&mut coordinator))
            .unwrap()
    };

    // Prefetch: a transfer lease and an open download of the next model's weights.
    let terms = LeaseTerms {
        term: 10 * MINUTE,
        max_lifetime: HOUR,
        cancel_within: 2 * SECOND,
    };
    let prefetch_lease = host
        .coordinator()
        .start_child_work(&owner, operation("op-prefetch"), LeaseKind::Transfer, terms)
        .unwrap();
    let (gate, budget) = coordinator_gate(&host);
    let next_weights = ContentKey::of(b"next model weights");
    let mut prefetch = gate
        .open(
            &host.seal(download(
                &host,
                "op-prefetch",
                &owner,
                &owner_tenant,
                epoch,
                &[(next_weights, 256)],
            )),
            &hub_connection(),
        )
        .unwrap();
    let in_flight = prefetch.admit(&next_weights, byte_range(0, 64)).unwrap();
    let sandbox_vram = host.reserved(vram(0));
    assert_eq!(sandbox_vram, 22 * GIB);
    // The prefetch's whole byte budget (256 bytes and half again) is reserved on the
    // host's one ledger.
    assert_eq!(host.reserved(STORAGE), 384);

    // Revocation.
    host.advance(SECOND);
    let revoked_at = host.clock.now();
    let notice = host.coordinator().revoke(&owner).unwrap();
    assert_eq!(notice.revoked, epoch);
    assert!(notice.current > epoch);
    // The ledger cancels every reservation of the execution, so the revocation reaches the
    // prefetch's too; created, it stays counted until its release is observed.
    assert_eq!(
        host.transfer_reservation("op-prefetch"),
        Some(ReservationState::Releasing)
    );
    assert_eq!(host.reserved(STORAGE), 384);

    // New work is denied at once, on every path.
    assert_eq!(
        host.coordinator()
            .start_child_work(&owner, operation("op-more"), LeaseKind::ChildWork, terms)
            .map(|lease| lease.id()),
        Err(LeaseRefusal::NoAuthority {
            state: SandboxState::Revoking
        })
    );
    assert_eq!(
        slot.admit(&host, "req-new", epoch)
            .map(|ticket| ticket.lease),
        Err(RouteRefusal::LeaseRefused {
            refusal: PlacementCoordinationRefusal::StaleAuthorization {
                presented: epoch,
                current: notice.current,
            }
        })
    );
    assert!(matches!(
        slot.admit(&host, "req-new", notice.current),
        Err(RouteRefusal::AuthorityMismatch { .. })
    ));
    assert!(matches!(
        host.coordinator().begin_activation_with(
            &owner,
            model_id("other"),
            settings_for(grant, BTreeSet::new()),
            ActivationDemand {
                gpu_memory_bytes: BTreeMap::from([(gpu(0), GIB)]),
                ..ActivationDemand::default()
            },
        ),
        Err(ModelRefusal::Parent { .. })
    ));
    for presented in [epoch, notice.current] {
        let refused = gate
            .open(
                &host.seal(download(
                    &host,
                    &format!("op-later-{presented}"),
                    &owner,
                    &owner_tenant,
                    presented,
                    &[(next_weights, 256)],
                )),
                &hub_connection(),
            )
            .unwrap_err();
        assert!(matches!(
            refused,
            TransferRefusal::Stopped {
                reason: StopReason::AuthorityNotCurrent { .. }
                    | StopReason::ParentWithoutAuthority { .. }
            }
        ));
    }

    // The open transfer stops at its next chunk; the chunk in flight never counts, and
    // its bytes stay counted only until its declared deadline.
    let stopped = prefetch
        .admit(&next_weights, byte_range(64, 128))
        .unwrap_err();
    let TransferRefusal::Stopped { reason } = &stopped else {
        panic!("the transfer stops, got {stopped:?}");
    };
    assert!(reason.is_revocation(), "{reason}");
    assert!(matches!(
        prefetch.deliver(in_flight),
        Err(TransferRefusal::NotActive { .. })
    ));
    assert_eq!(prefetch.delivered_bytes(), 0);
    let TransferStatus::Stopped(record) = prefetch.status().clone() else {
        panic!("stopped");
    };
    assert_eq!(record.cancelled_in_flight_bytes, 64);
    assert!(record.settled_by <= record.at.saturating_add(10 * SECOND));
    assert!(
        record.settled_by > record.at,
        "the dropped chunk may still be moving"
    );
    assert_eq!(budget.settle_due(), 0);
    assert_eq!(
        host.reserved(STORAGE),
        384,
        "a stop never shows false free capacity"
    );

    // Every lease of the sandbox is cancelling within its own declared bound.
    let cancellations = host
        .coordinator()
        .revocation(&owner)
        .unwrap()
        .cancellations()
        .to_vec();
    let bound_of = |lease: LeaseId| {
        cancellations
            .iter()
            .find(|cancellation| cancellation.lease == lease)
            .map(|cancellation| cancellation.bound_at)
            .unwrap()
    };
    assert_eq!(cancellations.len(), 3);
    assert_eq!(
        bound_of(streaming.lease),
        revoked_at.saturating_add(5 * SECOND)
    );
    assert_eq!(bound_of(early.lease), revoked_at.saturating_add(5 * SECOND));
    assert_eq!(
        bound_of(prefetch_lease.id()),
        revoked_at.saturating_add(2 * SECOND)
    );
    let ended = {
        let mut coordinator = host.coordinator();
        let port = slot.state.port(&mut coordinator);
        slot.slot.reconcile_leases(&port)
    };
    assert!(ended
        .iter()
        .any(|lease| lease.lease == streaming.lease && lease.status == LeaseStatus::Revoked));

    // Nothing is reclaimed while holders may still act.
    let status = host.advance_revocation(&owner);
    assert!(matches!(status, RevocationStatus::WaitingForLeases { .. }));
    host.coordinator()
        .acknowledge_cancellation(streaming.lease)
        .unwrap();
    host.coordinator()
        .acknowledge_cancellation(prefetch_lease.id())
        .unwrap();

    // The computing request never acknowledges. Past its bound it is recorded as
    // uncertain, and the memory it may use stays until its lease expires.
    host.advance(5 * SECOND);
    let status = host.advance_revocation(&owner);
    let RevocationStatus::WaitingForGpuReclaim { blocking, safe_at } = status else {
        panic!("the GPU memory waits for the computing request, got {status:?}");
    };
    assert_eq!(blocking, vec![early.lease]);
    assert_eq!(
        host.reserved(vram(0)),
        sandbox_vram,
        "nothing is freed early"
    );
    assert_eq!(host.available(vram(0)), Some(GIB));

    host.clock.advance_to(safe_at);
    let status = host.advance_revocation(&owner);
    assert!(
        matches!(status, RevocationStatus::Completed { .. }),
        "{status:?}"
    );
    let revocation = host.coordinator().revocation(&owner).unwrap().clone();
    assert!(revocation.uncertain().iter().any(|outcome| matches!(
        outcome,
        UncertainOutcome::UnacknowledgedLease { lease, kind: LeaseKind::Preparation, .. }
            if *lease == early.lease
    )));
    let milestones = revocation.milestones();
    assert_eq!(
        milestones[&RevocationMilestone::NewAuthorizationsDenied],
        revoked_at
    );
    assert!(milestones[&RevocationMilestone::LeasesClosed] < safe_at);
    assert_eq!(milestones[&RevocationMilestone::GpuReclaimed], safe_at);
    assert_eq!(milestones[&RevocationMilestone::CleanupFinished], safe_at);
    assert_eq!(host.reserved(vram(0)), 0);
    assert_eq!(host.available(vram(0)), Some(23 * GIB));
    // The prefetch's bytes return once its dropped chunk's deadline has passed.
    assert!(record.settled_by <= safe_at);
    assert_eq!(budget.settle_due(), 1);
    assert_eq!(host.transfer_reservation("op-prefetch"), None);
    assert_eq!(host.reserved(STORAGE), 0);
    assert_eq!(
        host.vms.terminated.len(),
        1,
        "the VM ended through its handle"
    );
    assert!(host.vms.live.is_empty());

    // Nothing extends authority: leases stay cancelled, the stopped sandbox holds none,
    // model B is never published, and a re-issued grant cannot continue the transfer.
    assert!(matches!(
        host.coordinator().renew_lease(streaming.lease),
        Err(LeaseRefusal::Cancelled { .. })
    ));
    assert_eq!(
        host.coordinator().sandbox(&owner).unwrap().state(),
        SandboxState::Stopped
    );
    assert_eq!(
        host.coordinator().sandbox(&owner).unwrap().authority(),
        None
    );
    assert!(slot.validate_and_publish(&host).is_err());
    let mut reissued = prefetch.envelope().fields().clone();
    reissued.epoch = notice.current;
    assert!(matches!(
        prefetch.retry_with_grant(&host.seal(reissued), &hub_connection()),
        Err(TransferRefusal::Stopped {
            reason: StopReason::AuthorityNotCurrent { current: None, .. }
        })
    ));
    let coordinator = host.coordinator();
    let activations = coordinator.model_activations(&owner, slot.model).unwrap();
    assert!(activations
        .activations()
        .iter()
        .all(|activation| activation.state().is_retired()));
    assert!(activations
        .holdings()
        .iter()
        .all(|holding| holding.state() == GpuReservationState::Released));
}

// ---------------------------------------------------------------------------------------
// INT-03: model activation changes while a service lease remains valid.
// ---------------------------------------------------------------------------------------

/// INT-03 (S6 line 99): model B replaces model A while a service lease of the sandbox
/// stays valid. The request admitted to A keeps A's generation and A's weights until it
/// finishes; new requests get B; memory shared by both counts once. The service lease is
/// neither reset nor extended by the change, and its renewals stay capped by its own
/// lifetime and the parent's authority.
#[test]
fn int03_requests_keep_their_generation_and_the_service_lease_is_untouched() {
    let mut host = Host::new();
    let owner = execution("exe-vm-a");
    let owner_tenant = tenant("tenant-a");
    let grant = host.launched(
        &owner,
        &owner_tenant,
        sandbox_demand(16 * GIB, 4 * GIB, 22 * GIB),
    );
    let service = host
        .coordinator()
        .start_child_work(
            &owner,
            operation("svc-session"),
            LeaseKind::Service,
            LeaseTerms {
                term: 10 * MINUTE,
                max_lifetime: 30 * MINUTE,
                cancel_within: 5 * SECOND,
            },
        )
        .unwrap();
    let generations_before = host.coordinator().sandbox(&owner).unwrap().generations();
    let mut slot = ModelSlot::new(&host, &owner, &owner_tenant, grant);

    let first = slot.activate(&host, &activation_request("model-a", &model_a()));
    let old = slot.admit(&host, "req-old", grant.epoch).unwrap();
    host.advance(MINUTE);

    // B shares three of A's four extents: it acquires A's memory and reserves only the
    // 7 GiB its own steady state and peak do not share (12 + 1 − 6 GiB).
    let parent = host.sandbox_reservation(&owner);
    let room = |host: &Host| host.ledger().parent_room(parent, vram(0)).unwrap();
    let room_before = room(&host);
    let second = slot.activate(&host, &activation_request("model-b", &model_b()));
    assert_eq!(second.previous, Some(first.generation));
    assert_eq!(second.mode, TransitionMode::Overlap);
    assert_eq!(room_before - room(&host), 7 * GIB);

    // The old request keeps generation 1 and A's weights; a new one gets B's.
    let new = slot.admit(&host, "req-new", grant.epoch).unwrap();
    assert_eq!(old.generation, first.generation);
    assert_eq!(new.generation, second.generation);
    let layer = position(Component::Layer(1));
    assert_eq!(slot.slot.weight_for(&old, layer), Ok(extent("a-layer-1")));
    assert_eq!(slot.slot.weight_for(&new, layer), Ok(extent("b-layer-1")));
    assert!(slot
        .slot
        .check_weight(&old, layer, extent("b-layer-1"))
        .is_err());
    let binding = |lease: LeaseId| {
        host.coordinator()
            .check_lease(lease)
            .unwrap()
            .model()
            .unwrap()
            .generations
            .activation
    };
    assert_eq!(binding(old.lease), first.generation);
    assert_eq!(binding(new.lease), second.generation);

    // The service lease and the parent's authority are exactly as before.
    assert_eq!(
        host.coordinator()
            .check_presented_lease(service.id(), service.clock()),
        Ok(service.clone()),
        "neither reset nor extended"
    );
    assert_eq!(
        host.coordinator().sandbox(&owner).unwrap().generations(),
        generations_before
    );
    assert_eq!(
        host.coordinator().sandbox(&owner).unwrap().authority(),
        Some(grant)
    );
    let activation_authority = host
        .coordinator()
        .model_activations(&owner, slot.model)
        .unwrap()
        .activation(second.generation)
        .unwrap()
        .settings()
        .authority;
    assert_eq!(
        activation_authority, grant,
        "the activation claims no new authority"
    );

    // Finishing the old request retires generation 1; it is never served again.
    slot.finish(&host, &old);
    let retired = host
        .coordinator()
        .model_activations(&owner, slot.model)
        .unwrap()
        .activation(first.generation)
        .unwrap()
        .state();
    assert!(retired.is_retired());
    assert_eq!(
        host.coordinator()
            .check_presented_lease(service.id(), service.clock()),
        Ok(service.clone())
    );

    // Renewal follows the lease's own rules, as before the change: each renewal moves
    // the expiry one term ahead, never past the lease's 30-minute lifetime.
    let mut renewed = service.clone();
    while renewed.expires_at() < service.deadline() {
        host.advance(8 * MINUTE);
        renewed = host
            .coordinator()
            .renew_presented_lease(service.id(), service.clock())
            .unwrap();
    }
    assert_eq!(renewed.expires_at(), service.deadline());
    assert!(renewed.expires_at() <= grant.expires_at);
    assert!(matches!(
        host.coordinator()
            .renew_presented_lease(service.id(), service.clock()),
        Err(LeaseRefusal::RenewalLimitReached {
            limit: RenewalLimit::MaxLifetime,
            ..
        })
    ));
}

// ---------------------------------------------------------------------------------------
// Catalog fixtures: a CORE-02 catalog in a temporary directory, sources and verifiers.
// ---------------------------------------------------------------------------------------

/// Bytes held in memory as an import source: a repository file or a peer at the edge.
struct MemorySource {
    name: String,
    bytes: Vec<u8>,
}

impl MemorySource {
    fn new(name: &str, bytes: &[u8]) -> Self {
        Self {
            name: name.to_owned(),
            bytes: bytes.to_vec(),
        }
    }
}

impl ImportSource for MemorySource {
    fn identity(&self) -> CatalogSource {
        CatalogSource::describe("test-memory", &self.name)
    }

    fn length_bytes(&mut self) -> Result<u64, SourceError> {
        Ok(self.bytes.len() as u64)
    }

    fn read_at(&mut self, offset_bytes: u64, buffer: &mut [u8]) -> Result<usize, SourceError> {
        let start = usize::try_from(offset_bytes).unwrap_or(usize::MAX);
        let available = self.bytes.get(start..).unwrap_or(&[]);
        let count = available.len().min(buffer.len());
        buffer[..count].copy_from_slice(&available[..count]);
        Ok(count)
    }
}

/// The responsible verifier of model weights in these scenarios: no publisher is
/// authenticated for weights, and any bytes are structurally acceptable.
struct WeightsVerifier;

impl ArtifactVerifier for WeightsVerifier {
    fn class(&self) -> ArtifactClass {
        ArtifactClass::ModelWeights
    }

    fn authenticate(
        &self,
        _content: &ContentDescriptor,
        _publisher: &PublisherId,
        _attestation: &[u8],
    ) -> Result<(), VerifierRejection> {
        Err(VerifierRejection::AttestationInvalid)
    }

    fn validate(
        &self,
        _content: &ContentDescriptor,
        _bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        Ok(())
    }
}

/// A CORE-02 catalog in its own temporary directory. Committed files are read-only, so
/// dropping it makes them writable first and the directory can be removed.
struct Store {
    catalog: Arc<Mutex<Catalog>>,
    dir: tempfile::TempDir,
}

impl Store {
    /// Tenants A and B may each store 1 MiB; tenant-selected weights are trusted, and
    /// `extra` registers more verifiers and policies.
    fn open(
        clock: &TestClock,
        extra: impl FnOnce(CatalogConfig, &mut VerifierRegistry) -> CatalogConfig,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut verifiers = VerifierRegistry::new();
        verifiers.register(Box::new(WeightsVerifier)).unwrap();
        let config = CatalogConfig::new(MINUTE)
            .with_quota(Scope::tenant(tenant("tenant-a")), MIB)
            .with_quota(Scope::tenant(tenant("tenant-b")), MIB)
            .with_trust(
                ArtifactClass::ModelWeights,
                TrustPolicy::new().accept_user_selected(),
            );
        let config = extra(config, &mut verifiers);
        let (catalog, _) = Catalog::open(
            dir.path(),
            config,
            verifiers,
            Arc::clone(clock) as Arc<dyn Clock>,
        )
        .unwrap();
        Self {
            catalog: Arc::new(Mutex::new(catalog)),
            dir,
        }
    }

    fn catalog(&self) -> MutexGuard<'_, Catalog> {
        lock(&self.catalog)
    }

    /// Imports `bytes` into `scope` as `class` and `role` under `trust`, to the end.
    fn import(
        &self,
        scope: &Scope,
        by: &ExecutionId,
        class: ArtifactClass,
        role: ObjectRole,
        bytes: &[u8],
        trust: TrustClaim,
    ) -> Result<ImportStatus, ImportRefusal> {
        let name = format!("{}-{}", class.tag(), ContentKey::of(bytes));
        let mut source = MemorySource::new(&name, bytes);
        let request = CatalogImport {
            operation: operation(&format!("op-import-{}", class.tag())),
            execution: by.clone(),
            scope: scope.clone(),
            class,
            role,
            manifest: ImportManifest::describe(bytes, NonZeroU64::new(64).unwrap()),
            trust,
            depends_on: BTreeSet::new(),
            metadata: ObjectMetadata::new().with_label("display-name", "private model name"),
        };
        let mut catalog = self.catalog();
        let ticket = match catalog.begin_import(request, source.identity())? {
            ImportStart::Started(ticket) | ImportStart::Attached(ticket) => ticket,
            ImportStart::AlreadyPublished(object) => {
                return Ok(ImportStatus::Published {
                    object,
                    progress: ImportProgress::default(),
                })
            }
        };
        Ok(catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap())
    }

    /// Publishes `bytes` as `owner`'s own original model weights.
    fn original(&self, owner: &TenantId, by: &ExecutionId, bytes: &[u8]) -> ObjectId {
        let status = self
            .import(
                &Scope::tenant(owner.clone()),
                by,
                ArtifactClass::ModelWeights,
                ObjectRole::Original,
                bytes,
                TrustClaim::UserSelected,
            )
            .unwrap();
        let ImportStatus::Published { object, .. } = status else {
            panic!("the original is published, got {status:?}");
        };
        object
    }
}

fn make_writable(path: &Path) {
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            make_writable(&entry.path());
        }
    }
    if let Ok(metadata) = fs::metadata(path) {
        let mut permissions = metadata.permissions();
        if permissions.readonly() {
            #[allow(clippy::permissions_set_readonly_false)]
            permissions.set_readonly(false);
            let _ = fs::set_permissions(path, permissions);
        }
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        make_writable(self.dir.path());
    }
}

// ---------------------------------------------------------------------------------------
// INT-04: VM, engine or governor crash and clean snapshot restore.
//
// Not covered with fakes: a real process crashing part-way through a write (the persisted
// state is taken whole, in memory), the durability of that state, the host ledger itself
// surviving a host restart (CORE-03 persists nothing, so the same in-memory ledger is
// handed to the recovered coordinator), what a restored guest really did (the backend's
// host report is scripted), CUDA checkpoint and restore of real GPU state and real device
// pointers (GPU handles are generations here), and the persisted boot counter that should
// feed every `Incarnation` (CORE-04 has none yet; the test chooses incarnations 1 and 2).
// ---------------------------------------------------------------------------------------

impl Host {
    /// The governor (engine) crashes and restarts: the coordinator's persisted state is
    /// recovered on a new clock session with a new evidence registry; the VM backend and
    /// the host ledger survive.
    fn restart(&mut self) -> CoordinatorRecovery {
        let persisted = self.coordinator().persist();
        self.evidence = Evidence::new(&self.clock);
        let session = self.evidence.registry.session();
        let mut coordinator = lock(&self.coordinator);
        let stand_in = Coordinator::new(
            Arc::clone(&self.clock),
            session,
            LedgerCapacity::shared(Arc::new(Mutex::new(host_ledger(&self.clock)))),
        );
        let crashed = std::mem::replace(&mut *coordinator, stand_in);
        let (recovered, report) = Coordinator::recover(
            persisted,
            Arc::clone(&self.clock),
            session,
            crashed.into_capacity(),
            &mut self.vms,
        )
        .unwrap();
        *coordinator = recovered;
        report
    }

    /// Revokes `of`, acknowledges every cancelled lease and drives it to stopped.
    fn stop(&mut self, of: &ExecutionId) {
        self.coordinator().revoke(of).unwrap();
        let leases: Vec<LeaseId> = self
            .coordinator()
            .leases()
            .map(|record| record.lease().id())
            .collect();
        for lease in leases {
            let _ = self.coordinator().acknowledge_cancellation(lease);
        }
        let status = self.advance_revocation(of);
        assert!(
            matches!(status, RevocationStatus::Completed { .. }),
            "{status:?}"
        );
    }

    /// Boots the stopped sandbox `of` again with `recovery`.
    fn relaunch(
        &mut self,
        of: &ExecutionId,
        recovery: CompositeRecovery,
        context: &RecoveryContext<'_>,
    ) -> RelaunchReport {
        let plan = RelaunchPlan {
            runtime: self.evidence.admit_vm(&vm_runtime()),
            demand: sandbox_demand(16 * GIB, 4 * GIB, 22 * GIB),
            authority_lifetime: HOUR,
            readiness_max_age: 5 * SECOND,
            runtime_evidence_max_age: HOUR,
            recovery,
            authorized_volumes: BTreeSet::from([data_volume()]),
        };
        let mut coordinator = lock(&self.coordinator);
        coordinator
            .relaunch(of, plan, context, &mut self.vms, &self.evidence.registry)
            .unwrap()
    }
}

fn weights_bytes(name: &str) -> Vec<u8> {
    format!("model weights of {name}: ")
        .into_bytes()
        .into_iter()
        .cycle()
        .take(4_096)
        .collect()
}

fn verified(contents: &[&[u8]]) -> BTreeSet<Digest> {
    contents
        .iter()
        .map(|bytes| *ContentKey::of(bytes).digest())
        .collect()
}

fn event_hub(clock: &TestClock, first_incarnation: u64) -> EventHub<TestClock> {
    event_hub_with(clock, first_incarnation, 4_096, 64)
}

/// The CORE-06 event plane with a metrics buffer of `capacity_events` (sampled one in
/// eight above three quarters of it) and at most `max_tracked` progress states.
fn event_hub_with(
    clock: &TestClock,
    first_incarnation: u64,
    capacity_events: usize,
    max_tracked: usize,
) -> EventHub<TestClock> {
    EventHub::new(
        Arc::clone(clock),
        HubConfig {
            metrics: MetricsConfig {
                capacity_events,
                sample_above_events: capacity_events / 4 * 3,
                keep_one_in: NonZeroU32::new(8).unwrap(),
                retention: MINUTE,
                max_series: 16,
            },
            progress: ProgressConfig {
                max_tracked,
                terminal_retention: MINUTE,
            },
            revocation: RevocationConfig {
                max_pending_executions: 16,
            },
            first_incarnation: ProducerIncarnation::new(first_incarnation).unwrap(),
        },
    )
    .unwrap()
}

/// INT-04 (S6 line 100), part 1: the governor crashes while a model serves, a request and
/// a child hold leases, a transfer is open and P08 has journaled two loads. Recovery
/// reconciles the VM and the ledger and revives nothing: the leases, the GPU allocation
/// and the old authorization are refused everywhere (coordinator, transfer gate, progress
/// publisher), P08 resubmits its jobs through the normal loader under a new incarnation
/// with the catalog deciding what is committed, and fresh authority comes only from a new
/// readiness check. New leases wait until the recovered state is persisted and never reuse
/// a pre-crash id, and a reload passes the S3.5 guard only with the fresh grant.
#[test]
fn int04_a_governor_crash_revives_no_lease_pointer_or_authority() {
    let mut host = Host::new();
    let owner = execution("exe-vm-a");
    let owner_tenant = tenant("tenant-a");
    let chat = weights_bytes("chat");
    let grant = host.launched_with(
        &owner,
        &owner_tenant,
        sandbox_demand(16 * GIB, 4 * GIB, 22 * GIB),
        SettingsGrant {
            network: BTreeSet::new(),
            verified_artifacts: verified(&[&chat]),
        },
    );
    let model = model_id("chat");
    let handle = host
        .coordinator()
        .begin_activation(
            &owner,
            model,
            settings_for(grant, verified(&[&chat])),
            GpuDemand {
                device: gpu(0),
                memory_bytes: 10 * GIB,
            },
        )
        .unwrap();
    host.coordinator()
        .complete_activation(&owner, model, handle.generations.activation)
        .unwrap();
    let terms = LeaseTerms {
        term: 10 * MINUTE,
        max_lifetime: HOUR,
        cancel_within: 5 * SECOND,
    };
    let request = host
        .coordinator()
        .admit_request(&owner, model, operation("req-1"), terms)
        .unwrap();
    let child = host
        .coordinator()
        .start_child_work(&owner, operation("op-child"), LeaseKind::ChildWork, terms)
        .unwrap();
    let (old_gate, _) = coordinator_gate(&host);
    let next = ContentKey::of(b"next model");
    let old_envelope = host.seal(download(
        &host,
        "op-prefetch",
        &owner,
        &owner_tenant,
        grant.epoch,
        &[(next, 256)],
    ));
    let mut prefetch = old_gate.open(&old_envelope, &hub_connection()).unwrap();

    // P08 journals two loads: one of weights the catalog already publishes (the journal
    // missed the commit), one of weights still to be fetched.
    let store = Store::open(&host.clock, |config, _| config);
    store.original(&owner_tenant, &owner, &chat);
    let journal = tempfile::tempdir().unwrap();
    let intent = |name: &str, bytes: &[u8]| JobIntent {
        operation: operation(name),
        execution: owner.clone(),
        tenant: owner_tenant.clone(),
        kind: JobKind::Load,
        class: ArtifactClass::ModelWeights,
        content: ContentKey::of(bytes),
        total_bytes: bytes.len() as u64,
    };
    {
        let mut loader = FakeLoader::default();
        let (mut control, _) = JobControl::start(
            journal.path(),
            Incarnation::FIRST,
            &*store.catalog(),
            &*host.coordinator(),
            &CoordinatorRecovery::default(),
            &mut loader,
        )
        .unwrap();
        for (name, bytes) in [
            ("op-load-chat", chat.clone()),
            ("op-load-next", b"next".to_vec()),
        ] {
            assert_eq!(
                control.submit(intent(name, &bytes), &mut loader),
                Ok(Submission::Submitted)
            );
        }
    }

    // The governor crashes; the VM survives; the coordinator recovers.
    host.advance(SECOND);
    let report = host.restart();
    let Some(SandboxRecovery::VmKeptWithoutAuthority { generations, .. }) =
        report.sandboxes.get(&owner)
    else {
        panic!("the live VM is kept without authority: {report:?}");
    };
    assert!(generations.authorization > grant.epoch);
    assert_eq!(
        BTreeSet::from_iter(report.leases_not_revived.iter().copied()),
        BTreeSet::from([request.id(), child.id()])
    );
    assert!(report.retired_activations.contains(&handle));
    assert!(
        !report.gpu_reservations_counted.is_empty(),
        "the VM may still use them"
    );
    assert!(report.reservations[&owner]
        .confirmed
        .contains(&sandbox_key(&owner, 1)));
    assert_eq!(
        host.reserved(RAM),
        16 * GIB,
        "the live VM's memory stays counted"
    );

    // Nothing from before the crash is honoured.
    for lease in [request.id(), child.id()] {
        assert_eq!(
            host.coordinator().check_lease(lease),
            Err(LeaseRefusal::NotRevived)
        );
        assert_eq!(
            host.coordinator().renew_lease(lease),
            Err(LeaseRefusal::NotRevived)
        );
    }
    assert!(matches!(
        host.coordinator().check_gpu_handle(&handle),
        Err(LeaseRefusal::StaleGpuAllocation { .. })
    ));
    assert_eq!(
        host.coordinator().sandbox(&owner).unwrap().state(),
        SandboxState::VmCreated
    );
    assert!(matches!(
        host.coordinator().start_child_work(
            &owner,
            operation("op-new"),
            LeaseKind::ChildWork,
            terms
        ),
        Err(LeaseRefusal::NoAuthority { .. })
    ));
    assert!(matches!(
        prefetch.admit(&next, byte_range(0, 64)),
        Err(TransferRefusal::Stopped { .. })
    ));
    let (new_gate, _) = coordinator_gate(&host);
    assert_eq!(
        new_gate
            .open(&old_envelope, &hub_connection())
            .map(|session| session.attempt()),
        Err(TransferRefusal::Stopped {
            reason: StopReason::EnvelopeOnOtherClock
        })
    );

    // P08 reconciles on the recovered coordinator, under incarnation 2 only.
    let mut loader = FakeLoader::default();
    assert!(JobControl::start(
        journal.path(),
        Incarnation::FIRST,
        &*store.catalog(),
        &*host.coordinator(),
        &report,
        &mut loader,
    )
    .is_err());
    let (_control, restarted) = JobControl::start(
        journal.path(),
        Incarnation::new(2),
        &*store.catalog(),
        &*host.coordinator(),
        &report,
        &mut loader,
    )
    .unwrap();
    assert!(restarted.stale_allocations.contains(&handle));
    assert_eq!(
        restarted.found_committed,
        vec![operation("op-load-chat")],
        "the catalog, not the journal, decides what is committed"
    );
    assert_eq!(loader.submitted.len(), 2);
    for submitted in &loader.submitted {
        assert_eq!(submitted.incarnation, Incarnation::new(2));
        assert_eq!(
            submitted.resume.artifact_committed,
            submitted.intent.operation == operation("op-load-chat")
        );
    }
    let mut hub = event_hub(&host.clock, 2);
    let producer = hub
        .register_progress(
            ProducerId::new("engine.progress").unwrap(),
            SourceClass::HostProbe,
            None,
        )
        .unwrap();
    let mut publisher = ProgressPublisher::new(
        producer,
        Incarnation::new(2),
        Arc::clone(&host.clock),
        ClockId::new(ReportLabel::new("host-monotonic").unwrap()),
        PublishPolicy::default(),
    )
    .unwrap();
    let load = operation("op-load-chat");
    publisher
        .track(
            &mut hub,
            &load,
            TrackRequest {
                resource: TrackedResourceId::new(*ContentKey::of(&chat).digest()),
                kind: EventResource::Weights,
                total_bytes: chat.len() as u64,
                stage: Stage::at(Phase::Loading),
            },
        )
        .unwrap();
    assert!(matches!(
        publisher.set_allocation(&mut hub, &*host.coordinator(), &load, &handle),
        Err(PublishError::StaleAllocation { .. })
    ));

    // Authority comes back only through fresh host-observed readiness: a new grant under
    // the new epoch and clock session, never the old one.
    let plan = host.plan(
        &owner,
        &owner_tenant,
        sandbox_demand(16 * GIB, 4 * GIB, 22 * GIB),
    );
    let LaunchOutcome::AuthorityActive { grant: fresh, .. } = host.launch(plan) else {
        panic!("the kept VM is re-authorized");
    };
    assert_eq!(fresh.epoch, generations.authorization);
    assert_ne!(fresh.clock, grant.clock);
    assert_eq!(
        host.coordinator().check_lease(request.id()),
        Err(LeaseRefusal::NotRevived)
    );
    // A holder outside the VM presenting a pre-crash lease is refused too, on either
    // clock session.
    for session in [grant.clock, fresh.clock] {
        assert!(host
            .coordinator()
            .check_presented_lease(request.id(), session)
            .is_err());
    }
    // No lease is issued until the recovered state is persisted again, and then only
    // under ids no pre-crash lease ever had.
    assert!(matches!(
        host.coordinator().start_child_work(
            &owner,
            operation("op-after"),
            LeaseKind::ChildWork,
            terms
        ),
        Err(LeaseRefusal::LeaseIdsNotPersisted { .. })
    ));
    let state = host.coordinator().persist();
    host.coordinator().confirm_persisted(&state);
    let after = host
        .coordinator()
        .start_child_work(&owner, operation("op-after"), LeaseKind::ChildWork, terms)
        .unwrap();
    assert!(after.id() > request.id() && after.id() > child.id());

    // A reload after recovery may change the batch size within the S3.5 guard, from the
    // coordinator's own record, and only under the fresh grant.
    let gate = LoaderGate::recorded();
    let plan = gate
        .plan(
            &RuntimeProfile {
                runtime: vm_runtime(),
                configuration: configuration("loader"),
                permitted: BTreeMap::new(),
            },
            &LoaderRequest::default(),
            &host.evidence.registry,
        )
        .unwrap();
    let fallback = FallbackContext {
        gate: &gate,
        registry: &host.evidence.registry,
        plan: &plan,
    };
    let mut proposed = settings_for(grant, verified(&[&chat]));
    proposed.batch_size = NonZeroU32::new(4).unwrap();
    let demand = GpuDemand {
        device: gpu(0),
        memory_bytes: 10 * GIB,
    };
    let Err(ModelRefusal::Fallback { refusal }) =
        host.coordinator()
            .reload_model(&owner, model, &fallback, proposed.clone(), demand)
    else {
        panic!("the old grant is never accepted again");
    };
    assert!(refusal
        .violations()
        .iter()
        .any(|violation| matches!(violation, FallbackViolation::RenewsAuthority { .. })));
    proposed.authority = fresh;
    let reloaded = host
        .coordinator()
        .reload_model(&owner, model, &fallback, proposed, demand)
        .unwrap();
    assert!(reloaded.generations.activation > handle.generations.activation);
    assert!(reloaded.generations.gpu_allocation > handle.generations.gpu_allocation);
    assert!(host.coordinator().check_gpu_handle(&handle).is_err());
}

/// INT-04, part 2: a stopped sandbox boots again. A composite recovery restores only
/// when every applicable validator passes (VM snapshot reset, GPU checkpoint restore,
/// model-cache recovery, S3.4); a GPU checkpoint without CUDA checkpoint evidence, a
/// tenant-workload snapshot or another tenant's cache sends it to a cold boot, and a
/// restored VM that kept the snapshot's guest identity is undone and cold-booted. Every
/// boot gets a new boot generation and authorization epoch.
#[test]
fn int04_b_a_composite_restore_needs_every_validator_and_otherwise_cold_boots() {
    let mut host = Host::new();
    let owner = execution("exe-vm-a");
    let owner_tenant = tenant("tenant-a");
    let first = host.launched(
        &owner,
        &owner_tenant,
        sandbox_demand(16 * GIB, 4 * GIB, 22 * GIB),
    );
    host.stop(&owner);

    let chat = weights_bytes("chat");
    let golden = SnapshotManifest {
        snapshot: SnapshotId::new(named("yougori/test/scenarios/snapshot/v1", "golden")),
        origin: SnapshotOrigin::PreTenantGolden,
        image_profile: named("yougori/test/scenarios/image/v1", "sandbox"),
        contents: BTreeSet::new(),
        source_vm: VmInstanceId::new(named("yougori/test/scenarios/vm/v1", "image-builder")),
        guest_identity: named("yougori/test/scenarios/guest/v1", "golden"),
    };
    let cache = ModelCacheManifest {
        tenant: owner_tenant.clone(),
        artifacts: BTreeSet::from([ContentKey::of(&chat)]),
    };
    let checkpoint = GpuCheckpointManifest {
        recorded: ContentKey::of(b"checkpoint"),
        observed: ContentKey::of(b"checkpoint"),
        runtime: Subject::Runtime(vm_runtime()).identity(),
    };
    let artifacts = ArtifactVerification::Verified {
        artifacts: verified(&[&chat]),
    };
    let context = RecoveryContext {
        expected_image_profile: golden.image_profile,
        checkpoint_evidence: None,
        artifact_verification: &artifacts,
    };
    let state = |host: &Host| {
        let coordinator = host.coordinator();
        let sandbox = coordinator.sandbox(&owner).unwrap();
        (
            sandbox.generations(),
            sandbox.restored_from(),
            sandbox.verified_restore(),
            sandbox.vm(),
        )
    };

    // The GPU checkpoint has no CUDA checkpoint evidence on this runtime: cold boot.
    let report = host.relaunch(
        &owner,
        CompositeRecovery {
            vm_snapshot: Some(golden.clone()),
            gpu_checkpoint: Some(checkpoint),
            model_cache: Some(cache.clone()),
        },
        &context,
    );
    assert_eq!(report.decision.path, RecoveryPath::ColdBootReload);
    assert_eq!(
        report.decision.verdicts[&RecoveryComponent::VmSnapshotReset],
        ValidatorVerdict::Passed
    );
    assert_eq!(
        report.decision.verdicts[&RecoveryComponent::ModelCacheRecovery],
        ValidatorVerdict::Passed
    );
    assert!(matches!(
        &report.decision.verdicts[&RecoveryComponent::GpuCheckpointRestore],
        ValidatorVerdict::Failed { defects: ComponentDefects::GpuCheckpoint { defects } }
            if defects.contains(&CheckpointDefect::NoCapabilityEvidence)
    ));
    let LaunchOutcome::AuthorityActive { grant: cold, .. } = report.outcome else {
        panic!("the cold boot gets authority");
    };
    let (generations, restored_from, _, _) = state(&host);
    assert_eq!(restored_from, None, "nothing was restored");
    assert!(generations.boot > SandboxBootGeneration::FIRST);
    assert!(cold.epoch > first.epoch);
    host.stop(&owner);

    // A clean pre-tenant snapshot and this tenant's verified cache: restored, then
    // verified with fresh identities before it receives authority.
    let report = host.relaunch(
        &owner,
        CompositeRecovery {
            vm_snapshot: Some(golden.clone()),
            gpu_checkpoint: None,
            model_cache: Some(cache.clone()),
        },
        &context,
    );
    assert_eq!(report.decision.path, RecoveryPath::Restore);
    assert_eq!(report.refused_restore, None);
    let LaunchOutcome::AuthorityActive {
        grant: restored, ..
    } = report.outcome
    else {
        panic!("the verified restore gets authority");
    };
    let (generations, restored_from, verified_restore, vm) = state(&host);
    assert_eq!(restored_from, Some(golden.snapshot));
    assert_eq!(verified_restore, vm);
    assert_ne!(vm, Some(golden.source_vm));
    assert!(restored.epoch > cold.epoch);
    assert_eq!(generations.authorization, restored.epoch);
    host.stop(&owner);

    // A restore that kept the snapshot's guest identity is refused and undone; the
    // sandbox cold-boots instead and still gets a fresh grant.
    host.vms.dirty_restores = true;
    let report = host.relaunch(
        &owner,
        CompositeRecovery {
            vm_snapshot: Some(golden.clone()),
            gpu_checkpoint: None,
            model_cache: None,
        },
        &context,
    );
    assert_eq!(report.decision.path, RecoveryPath::Restore);
    assert!(matches!(
        &report.refused_restore,
        Some(LaunchOutcome::RolledBack {
            failure: LaunchFailure::RestoreRefused { refusal },
            ..
        }) if refusal.failures().contains(&RestoreFailure::GuestIdentityReused)
    ));
    assert!(matches!(
        report.outcome,
        LaunchOutcome::AuthorityActive { .. }
    ));
    assert_eq!(state(&host).1, None);
    host.vms.dirty_restores = false;
    host.stop(&owner);

    // A tenant-workload snapshot, or another tenant's cache, is never restored.
    let mut dirty = golden.clone();
    dirty.origin = SnapshotOrigin::TenantWorkload;
    dirty.contents = BTreeSet::from([SnapshotContent::LiveTenantSecrets]);
    let report = host.relaunch(
        &owner,
        CompositeRecovery {
            vm_snapshot: Some(dirty),
            gpu_checkpoint: None,
            model_cache: Some(cache.clone()),
        },
        &context,
    );
    assert_eq!(report.decision.path, RecoveryPath::ColdBootReload);
    host.stop(&owner);
    let report = host.relaunch(
        &owner,
        CompositeRecovery {
            vm_snapshot: Some(golden),
            gpu_checkpoint: None,
            model_cache: Some(ModelCacheManifest {
                tenant: tenant("tenant-b"),
                artifacts: cache.artifacts,
            }),
        },
        &context,
    );
    assert_eq!(report.decision.path, RecoveryPath::ColdBootReload);
    assert!(matches!(
        &report.decision.verdicts[&RecoveryComponent::ModelCacheRecovery],
        ValidatorVerdict::Failed { defects: ComponentDefects::ModelCache { defects } }
            if defects.contains(&CacheDefect::OtherTenant { tenant: tenant("tenant-b") })
    ));
    assert_eq!(state(&host).1, None);
}

// ---------------------------------------------------------------------------------------
// INT-05: two tenants request identical model objects.
// ---------------------------------------------------------------------------------------

/// The KV state of a session of `owner` in `session`, for one model, prefix and rank.
fn kv_spec(owner: &TenantId, session: &ExecutionId) -> KvReuseSpec {
    KvReuseSpec {
        scope: KvScopeSpec {
            model: execution_of("shared-base"),
            tokenizer: named("yougori/test/scenarios/tokenizer/v1", "shared-base"),
            adapter: None,
            prefix: TokenPrefix::from_token_ids(&[101, 2023, 2003, 1037]),
            position: KvPosition {
                encoding: PositionalEncoding {
                    scheme: versioned("rope", "1"),
                    parameters: named("yougori/test/scenarios/rope/v1", "base-10000"),
                },
                first_position: 0,
            },
            cache: KvRepresentation::new(
                Dtype::BFloat16,
                Quantization::None,
                16,
                versioned("paged", "1"),
            )
            .unwrap(),
            authority: KvAuthority {
                tenant: owner.clone(),
                session: AuthorityBinding::new(
                    session.clone(),
                    ExecutionCategory::SharedKernelGpuRuntime,
                    None,
                )
                .unwrap(),
            },
        },
        attention_semantics: named("yougori/test/scenarios/attention/v1", "causal"),
        rank: RankPosition::new(0, 1).unwrap(),
    }
}

/// One GPU shared by runner processes on a labelled runtime (P05's fake driver at the
/// edge), each process registered with the runtime it runs in.
fn shared_gpu(processes: &[(ProcessId, &RuntimeSubject)]) -> (FakeDriver, VmmModel) {
    let mut driver = FakeDriver::new();
    driver.add_device(
        DeviceOrdinal(0),
        FakeDeviceSpec {
            capacity_bytes: GIB,
            granularity_bytes: BTreeMap::from([(None, 2 * MIB)]),
        },
    );
    let mut vmm = VmmModel::new();
    for (process, runtime) in processes {
        driver.add_process(*process, DeviceOrdinal(0));
        vmm.register_process(ProcessContext {
            process: *process,
            device: DeviceOrdinal(0),
            runtime: (*runtime).clone(),
            configuration: configuration("driver"),
            reports_from: SourceClass::HostProbe,
            evidence_policy: EvidencePolicy {
                minimum_source: SourceClass::HostProbe,
                max_age: HOUR,
            },
        })
        .unwrap();
    }
    (driver, vmm)
}

/// Installs the CORE-01 gate's plan for `process`'s runtime under a profile that permits
/// legacy CUDA IPC (INT-06); the gate enables it only where evidence shows it.
fn permit_legacy_ipc(evidence: &Evidence, vmm: &mut VmmModel, process: ProcessId) {
    let context = vmm.process_context(process).unwrap();
    let profile = RuntimeProfile {
        runtime: context.runtime.clone(),
        configuration: context.configuration,
        permitted: BTreeMap::from([(
            Optimization::CudaIpcLegacy,
            EvidencePolicy {
                minimum_source: SourceClass::HostProbe,
                max_age: HOUR,
            },
        )]),
    };
    let request = LoaderRequest {
        optimizations: BTreeMap::from([(Optimization::CudaIpcLegacy, Necessity::Optional)]),
    };
    let plan = LoaderGate::recorded()
        .plan(&profile, &request, &evidence.registry)
        .unwrap();
    vmm.set_loader_plan(process, plan).unwrap();
}

/// `process` loads `name` into one dedicated allocation, publishes it and exports it
/// through legacy CUDA IPC (Appendix E step 8).
fn legacy_export(
    evidence: &Evidence,
    driver: &mut FakeDriver,
    vmm: &mut VmmModel,
    process: ProcessId,
    name: &str,
) -> Result<ExportId, VmmError> {
    let batch = named("yougori/test/scenarios/batch/v1", name);
    let key = vmm
        .plan_legacy(
            process,
            named("yougori/test/scenarios/artifact/v1", name),
            ContentKey::of(name.as_bytes()),
            BatchSpec {
                length_bytes: 4 * MIB,
                digest: batch,
            },
        )
        .unwrap();
    vmm.back_batch(driver, &evidence.registry, key, 0).unwrap();
    let event = vmm.populate_batch(driver, key, 0, StreamId(1)).unwrap();
    assert!(driver.complete(event));
    vmm.publish_batch(driver, key, 0, batch).unwrap();
    vmm.legacy_export(driver, &evidence.registry, key)
}

/// INT-05 (S6 line 101): tenants A and B ask for the same model bytes. Storage is reused
/// only under the owner's grant for that exact object and execution, and even then B
/// reads content facts, never A's private metadata or A's adapter, and B's own
/// transfers and quota never count A's copy. Identical execution state is shared only
/// within one trust scope under a grant for that use, KV never crosses tenants, and GPU
/// memory is never acquired or opened across sandboxes or runtimes.
#[test]
fn int05_identical_objects_cross_tenants_only_under_a_grant_and_private_state_never_does() {
    let clock: TestClock = Arc::new(ManualClock::new(at_seconds(1_000)));
    let store = Store::open(&clock, |config, _| config);
    let (a, b) = (tenant("tenant-a"), tenant("tenant-b"));
    let (exe_a, exe_b) = (execution("exe-vm-a"), execution("exe-vm-b"));
    let (scope_a, scope_b) = (Scope::tenant(a.clone()), Scope::tenant(b.clone()));
    let base = weights_bytes("shared-base");
    let adapter = weights_bytes("tenant-a-adapter");
    let base_key = ContentKey::of(&base);
    let a_base = store.original(&a, &exe_a, &base);
    let a_adapter = store.original(&a, &exe_a, &adapter);

    // Equal bytes are not permission: B can neither view nor lease A's copy, and B's
    // identity for the same bytes is another object B does not have.
    let b_base = ObjectId::new(&scope_b, ArtifactClass::ModelWeights, base_key);
    assert_ne!(b_base, a_base);
    {
        let mut catalog = store.catalog();
        assert!(matches!(
            catalog.object_view(&scope_b, &exe_b, a_base),
            Err(ReadRefusal::NotGranted { .. })
        ));
        assert!(matches!(
            catalog.acquire_lease(&scope_b, &exe_b, a_base, MINUTE),
            Err(ReadRefusal::NotGranted { .. })
        ));
        assert_eq!(catalog.status(&scope_b, b_base), ObjectStatus::Absent);
    }
    // A transfer for B counts nothing as already verified: B fetches every byte.
    let extents = CatalogExtents::new(Arc::clone(&store.catalog), ArtifactClass::ModelWeights);
    let whole = RangeSet::single(byte_range(0, base.len() as u64));
    assert_eq!(
        extents.verified(&a, &exe_a, &Endpoint::HostCatalog, &base_key),
        whole
    );
    assert!(extents
        .verified(&b, &exe_b, &Endpoint::HostCatalog, &base_key)
        .is_empty());

    // A grants one execution of B read access to exactly the base.
    let grant = store
        .catalog()
        .grant(
            &scope_a,
            GrantRequest {
                object: a_base,
                grantee: scope_b.clone(),
                execution: Some(exe_b.clone()),
                expires_at: clock.now().saturating_add(HOUR),
            },
        )
        .unwrap();
    let mut handle = {
        let mut catalog = store.catalog();
        let lease = catalog
            .acquire_lease(&scope_b, &exe_b, a_base, MINUTE)
            .unwrap();
        catalog.open_read(&scope_b, &exe_b, lease).unwrap()
    };
    assert_eq!(handle.read_all().unwrap(), base);
    {
        let mut catalog = store.catalog();
        assert_eq!(
            catalog
                .object_view(&scope_b, &exe_b, a_base)
                .unwrap()
                .content_key,
            base_key
        );
        // The grant covers content only.
        assert_eq!(
            catalog.private_metadata(&scope_b, a_base),
            Err(MetadataRefusal { object: a_base })
        );
        assert!(catalog.private_metadata(&scope_a, a_base).is_ok());
        assert!(matches!(
            catalog.object_view(&scope_b, &exe_b, a_adapter),
            Err(ReadRefusal::NotGranted { .. })
        ));
        assert!(matches!(
            catalog.acquire_lease(&scope_b, &execution("exe-vm-b-2"), a_base, MINUTE),
            Err(ReadRefusal::NotGranted { .. })
        ));
        // Revoking the grant stops B's open handle at once.
        catalog.revoke_grant(&scope_a, grant).unwrap();
    }
    assert_eq!(handle.read_all(), Err(ReadError::LeaseRevoked));

    // Reading under a grant never made A's copy B's: B still fetches and pays for its own.
    assert!(extents
        .verified(&b, &exe_b, &Endpoint::HostCatalog, &base_key)
        .is_empty());
    assert_eq!(store.original(&b, &exe_b, &base), b_base);
    assert_eq!(
        store.catalog().quota_usage(&scope_b).published_bytes,
        base.len() as u64
    );
    assert_eq!(
        store.catalog().quota_usage(&scope_a).published_bytes,
        (base.len() + adapter.len()) as u64
    );

    // Identical execution state (T07): device memory never crosses a VM boundary, storage
    // is shared only inside one trust scope, and there only under the owner's grant for
    // that very use.
    let vm_a = TrustScope::named(ExecutionCategory::VmSandbox, "tenant-a");
    let vm_b = TrustScope::named(ExecutionCategory::VmSandbox, "tenant-b");
    let pool = TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, "host-pool");
    let stored = |scope: TrustScope| StoredRepresentation {
        execution: execution_of("shared-base"),
        artifact: artifact_of("shared-base"),
        owner: a.clone(),
        scope,
    };
    let share = |scope: TrustScope, medium: SharingMedium| ShareRequest {
        execution: execution_of("shared-base"),
        tenant: b.clone(),
        scope,
        medium,
    };
    let decide = |stored_in, wanted_in, medium, grant: Option<&ScopedGrant>| {
        decide_storage_sharing(
            &stored(stored_in),
            &share(wanted_in, medium),
            grant,
            &*clock,
        )
    };
    assert_eq!(
        decide(vm_a, vm_b, SharingMedium::DeviceMemory, None),
        Err(SharingRefusal::CrossVmDeviceMemory)
    );
    assert_eq!(
        decide(vm_a, vm_b, SharingMedium::ImmutableStorage, None),
        Err(SharingRefusal::DifferentTrustScope)
    );
    assert_eq!(
        decide(pool, pool, SharingMedium::ImmutableStorage, None),
        Err(SharingRefusal::Unauthorized(IdentityGrantRefusal::Missing))
    );
    store
        .catalog()
        .grant(
            &scope_a,
            GrantRequest {
                object: a_base,
                grantee: scope_b.clone(),
                execution: Some(exe_b.clone()),
                expires_at: clock.now().saturating_add(HOUR),
            },
        )
        .unwrap();
    let scoped = ScopedGrant::from_catalog(
        &store.catalog,
        a_base,
        exe_b.clone(),
        GrantTerms {
            grantor: a.clone(),
            grantee: b.clone(),
            artifact: artifact_of("shared-base"),
            scope: pool,
            uses: BTreeSet::from([GrantedUse::ShareImmutableStorage]),
            expires_at: clock.now().saturating_add(HOUR),
        },
    )
    .unwrap();
    assert!(decide(pool, pool, SharingMedium::ImmutableStorage, Some(&scoped)).is_ok());
    assert_eq!(
        decide(pool, pool, SharingMedium::DeviceMemory, Some(&scoped)),
        Err(SharingRefusal::Unauthorized(
            IdentityGrantRefusal::UseNotGranted {
                requested: GrantedUse::ShareDeviceMemory
            }
        ))
    );

    // KV (P07 over T07's FAST-03 key): B never reuses A's KV for the same model and
    // prefix, and claiming the prefix public without configuration does not help.
    let enforced = scope_enforcement(clock.now(), HOUR);
    let standing = RevokedAuthorities::new();
    let stored_kv = StoredKv {
        spec: kv_spec(&a, &exe_a),
        trust_scope: pool,
        sharing: KvSharing::TenantScoped,
    };
    let from_b = KvRequest {
        spec: kv_spec(&b, &exe_b),
        trust_scope: pool,
    };
    assert_eq!(
        check_kv_reuse(
            &stored_kv,
            &from_b,
            &PublicPrefixSharing::none(),
            &standing,
            &enforced,
            clock.now()
        ),
        Err(KvReuseRefusal::Scope(IdentityKvRefusal::ScopeMismatch {
            components: vec![KvScopeComponent::Tenant, KvScopeComponent::SessionAuthority]
        }))
    );
    let from_a = KvRequest {
        spec: kv_spec(&a, &exe_a),
        trust_scope: pool,
    };
    assert!(check_kv_reuse(
        &stored_kv,
        &from_a,
        &PublicPrefixSharing::none(),
        &standing,
        &enforced,
        clock.now()
    )
    .is_ok());
    let claimed_public = StoredKv {
        sharing: KvSharing::PublicPrefix {
            prefix: stored_kv.spec.scope.prefix,
        },
        ..stored_kv.clone()
    };
    assert_eq!(
        check_kv_reuse(
            &claimed_public,
            &from_b,
            &PublicPrefixSharing::none(),
            &standing,
            &enforced,
            clock.now()
        ),
        Err(KvReuseRefusal::Scope(
            IdentityKvRefusal::PublicPrefixNotConfigured
        ))
    );

    // GPU memory (CORE-04): each sandbox reserves its own; B cannot acquire A's
    // allocation, and nothing of A's sandbox runs under B.
    let mut host = Host::new();
    let grant_a = host.launched(&exe_a, &a, sandbox_demand(8 * GIB, 2 * GIB, 11 * GIB));
    let grant_b = host.launched(&exe_b, &b, sandbox_demand(8 * GIB, 2 * GIB, 11 * GIB));
    let model = model_id("shared-base");
    let demand = GpuDemand {
        device: gpu(0),
        memory_bytes: 8 * GIB,
    };
    let a_gpu = host
        .coordinator()
        .begin_activation(
            &exe_a,
            model,
            settings_for(grant_a, BTreeSet::new()),
            demand,
        )
        .unwrap();
    assert!(matches!(
        host.coordinator().begin_activation_with(
            &exe_b,
            model,
            settings_for(grant_b, BTreeSet::new()),
            ActivationDemand {
                acquire: BTreeSet::from([HoldingId::Gpu {
                    allocation: a_gpu.generations.gpu_allocation
                }]),
                ..ActivationDemand::default()
            },
        ),
        Err(ModelRefusal::HoldingUnavailable { .. })
    ));
    host.coordinator()
        .begin_activation(
            &exe_b,
            model,
            settings_for(grant_b, BTreeSet::new()),
            demand,
        )
        .unwrap();
    assert_eq!(
        host.reserved(vram(0)),
        22 * GIB,
        "one model, two sandboxes, no sharing"
    );
    for of in [&exe_a, &exe_b] {
        let parent = host.sandbox_reservation(of);
        assert_eq!(host.ledger().parent_room(parent, vram(0)).unwrap(), 3 * GIB);
    }
    let plan = host.plan(&exe_a, &b, sandbox_demand(8 * GIB, 2 * GIB, 11 * GIB));
    assert!(matches!(
        host.try_launch(plan),
        Err(CoordinationError::TenantMismatch { .. })
    ));

    // CUDA IPC (P05): A's runner processes may share an allocation within A's runtime;
    // B's runtime never opens it, whatever evidence it holds.
    let (wsl_a, wsl_b) = (
        runtime(ExecutionCategory::SharedKernelGpuRuntime, "wsl-tenant-a"),
        runtime(ExecutionCategory::SharedKernelGpuRuntime, "wsl-tenant-b"),
    );
    let mut evidence = Evidence::new(&clock);
    evidence.support(Capability::CudaIpcLegacy, &wsl_a, "driver");
    evidence.support(Capability::CudaIpcLegacy, &wsl_b, "driver");
    let (p1, p2, p3) = (ProcessId(1), ProcessId(2), ProcessId(3));
    let (mut driver, mut vmm) = shared_gpu(&[(p1, &wsl_a), (p2, &wsl_a), (p3, &wsl_b)]);
    permit_legacy_ipc(&evidence, &mut vmm, p1);
    permit_legacy_ipc(&evidence, &mut vmm, p2);
    let export = legacy_export(&evidence, &mut driver, &mut vmm, p1, "shared-base").unwrap();
    vmm.legacy_open(&mut driver, &evidence.registry, p2, export)
        .unwrap();
    assert_eq!(
        vmm.legacy_open(&mut driver, &evidence.registry, p3, export),
        Err(VmmError::CrossesRuntimeBoundary {
            exporter: p1,
            importer: p3
        })
    );
}

// ---------------------------------------------------------------------------------------
// INT-06: the loader selects optional IPC, io_uring, GDS or checkpoint optimization.
//
// Not covered with fakes: whether io_uring, GPUDirect Storage, CUDA IPC or CUDA
// checkpoint really work on a kernel, driver or GPU (the probes are scripted); the
// confinement itself (VM device assignment, seccomp) that keeps an unapproved loader
// out; reads by the transfer executor with a gated method end to end (only the read
// permissions it derives from the gate's plan are checked); and real backend mode
// switching (only vLLM 0.31.0's recorded mode rules).
// ---------------------------------------------------------------------------------------

/// INT-06 (S6 line 102): the loader asks for optional and required optimizations. The
/// CORE-01 gate enables one only where the exact runtime profile permits it and fresh
/// evidence about that runtime shows it working; otherwise the ordinary loader runs, or a
/// required feature is refused. Evidence alone never widens the profile. The same plan
/// sets the transfer executor's read methods (P03), bounds every S3.5 fallback and lapses
/// with its evidence, and CUDA IPC (P05) needs its own evidence and stays inside one
/// runtime.
#[test]
fn int06_an_optimization_needs_the_exact_profile_and_evidence_or_falls_back_or_is_refused() {
    use Necessity::{Optional, Required};
    use Optimization::{
        CudaCheckpoint, CudaIpcLegacy, ExecuteWhileLoad, GpuDirectStorage, IoUring,
        SleepWeightDiscard, SleepWeightOffload, ZeroCopyPreload,
    };

    let clock: TestClock = Arc::new(ManualClock::new(at_seconds(1_000)));
    let mut evidence = Evidence::new(&clock);
    let sandbox = vm_runtime();
    // The host showed io_uring, CUDA checkpoint, legacy CUDA IPC and both backend modes
    // working on this exact runtime, and nothing about GPUDirect Storage.
    for capability in [
        Capability::IoUring,
        Capability::CudaCheckpoint,
        Capability::CudaIpcLegacy,
        Capability::ZeroCopyPreload,
        Capability::SleepWeightOffload,
    ] {
        evidence.support(capability, &sandbox, "loader");
    }
    // The profile permits io_uring, GPUDirect Storage and the two backend modes; not IPC
    // and not checkpoint.
    let host_hour = EvidencePolicy {
        minimum_source: SourceClass::HostProbe,
        max_age: HOUR,
    };
    let profile = RuntimeProfile {
        runtime: sandbox.clone(),
        configuration: configuration("loader"),
        permitted: [
            IoUring,
            GpuDirectStorage,
            ZeroCopyPreload,
            SleepWeightOffload,
        ]
        .into_iter()
        .map(|optimization| (optimization, host_hour))
        .collect(),
    };
    let gate = LoaderGate::recorded();
    let request = |entries: &[(Optimization, Necessity)]| LoaderRequest {
        optimizations: entries.iter().copied().collect(),
    };

    let plan = gate
        .plan(
            &profile,
            &request(&[
                (IoUring, Optional),
                (GpuDirectStorage, Optional),
                (CudaIpcLegacy, Optional),
                (CudaCheckpoint, Optional),
            ]),
            &evidence.registry,
        )
        .unwrap();
    assert_eq!(plan.enabled_set(), BTreeSet::from([IoUring]));
    let ordinary = plan.ordinary();
    assert!(matches!(
        ordinary[&GpuDirectStorage],
        NotEnabled::Evidence { .. }
    ));
    assert_eq!(
        ordinary[&CudaIpcLegacy],
        NotEnabled::NotPermitted,
        "evidence alone never widens the profile"
    );
    assert_eq!(ordinary[&CudaCheckpoint], NotEnabled::NotPermitted);

    // A required feature that cannot be enabled refuses the load; nothing replaces it.
    let refusal = gate
        .plan(
            &profile,
            &request(&[(GpuDirectStorage, Required)]),
            &evidence.registry,
        )
        .unwrap_err();
    assert_eq!(refusal.optimization, GpuDirectStorage);
    assert!(matches!(refusal.reason, NotEnabled::Evidence { .. }));
    let refusal = gate
        .plan(
            &profile,
            &request(&[(CudaCheckpoint, Required)]),
            &evidence.registry,
        )
        .unwrap_err();
    assert_eq!(refusal.reason, NotEnabled::NotPermitted);

    // vLLM 0.31.0 documents zero-copy preload and sleep offload as incompatible: as
    // optional modes both give way to the ordinary loader; required, the load is refused.
    let modes = gate
        .plan(
            &profile,
            &request(&[(ZeroCopyPreload, Optional), (SleepWeightOffload, Optional)]),
            &evidence.registry,
        )
        .unwrap();
    assert!(modes.is_ordinary_loader());
    assert!(matches!(
        modes.ordinary()[&ZeroCopyPreload],
        NotEnabled::Conflict { .. }
    ));
    assert!(matches!(
        gate.plan(
            &profile,
            &request(&[(ZeroCopyPreload, Required), (SleepWeightOffload, Required)]),
            &evidence.registry,
        ),
        Err(LoaderRefusal {
            reason: NotEnabled::Conflict { .. },
            ..
        })
    ));

    // The newer optimizations meet the same rules. With fresh evidence on this runtime and
    // a profile that permits both, execute-while-load runs; sleep-mode weight discarding
    // is a backend mode no recorded rule of vLLM 0.31.0 supports, so it gives way to the
    // ordinary loader.
    evidence.support(Capability::ExecuteWhileLoad, &sandbox, "loader");
    evidence.support(Capability::SleepWeightDiscard, &sandbox, "loader");
    let newer = gate
        .plan(
            &RuntimeProfile {
                runtime: sandbox.clone(),
                configuration: configuration("loader"),
                permitted: BTreeMap::from([
                    (ExecuteWhileLoad, host_hour),
                    (SleepWeightDiscard, host_hour),
                ]),
            },
            &request(&[(ExecuteWhileLoad, Optional), (SleepWeightDiscard, Optional)]),
            &evidence.registry,
        )
        .unwrap();
    assert_eq!(newer.enabled_set(), BTreeSet::from([ExecuteWhileLoad]));
    assert!(matches!(
        newer.ordinary()[&SleepWeightDiscard],
        NotEnabled::Release { .. }
    ));

    // The plan becomes the transfer executor's read methods (P03).
    let permissions = LoaderPermissions::from_plan(&plan);
    let now = clock.now();
    assert!(permissions.permits(ReadMethod::IoUring, &evidence.registry));
    assert!(!permissions.permits(ReadMethod::GpuDirectStorage, &evidence.registry));
    assert!(permissions.permits(ReadMethod::PositionedRead, &evidence.registry));
    assert!(permissions.required().is_empty());

    // S3.5: a fallback may give io_uring up, shrink the batch or move residency inside
    // the authorized runtime; it never enables what the gate did not, changes category,
    // opens the network or bypasses verification.
    let authorized = RuntimeSettings {
        execution_category: ExecutionCategory::VmSandbox,
        network: BTreeSet::new(),
        authority: AuthorityGrant {
            epoch: AuthorizationEpoch::FIRST,
            clock: evidence.registry.session(),
            expires_at: now.saturating_add(HOUR),
        },
        artifact_verification: ArtifactVerification::Verified {
            artifacts: verified(&[b"weights"]),
        },
        loader: BTreeSet::from([IoUring]),
        batch_size: NonZeroU32::new(8).unwrap(),
        residency: Residency::Device,
    };
    let approved = guard_fallback(
        &gate,
        &evidence.registry,
        &plan,
        &authorized,
        RuntimeSettings {
            loader: BTreeSet::new(),
            batch_size: NonZeroU32::new(4).unwrap(),
            residency: Residency::HostPinned,
            ..authorized.clone()
        },
    )
    .unwrap();
    assert_eq!(
        approved.changes(),
        &BTreeSet::from([
            AllowedChange::Loader,
            AllowedChange::BatchSize,
            AllowedChange::Residency
        ])
    );
    let refusal = guard_fallback(
        &gate,
        &evidence.registry,
        &plan,
        &authorized,
        RuntimeSettings {
            execution_category: ExecutionCategory::SharedKernelGpuRuntime,
            network: BTreeSet::from([NetworkGrant::NamedRoute {
                route: named("yougori/test/scenarios/route/v1", "anywhere"),
            }]),
            artifact_verification: ArtifactVerification::Bypassed,
            loader: BTreeSet::from([IoUring, GpuDirectStorage, CudaIpcLegacy]),
            ..authorized.clone()
        },
    )
    .unwrap_err();
    let violations = refusal.violations();
    assert!(violations.iter().any(|violation| matches!(
        violation,
        FallbackViolation::ChangesExecutionCategory { .. }
    )));
    assert!(violations
        .iter()
        .any(|violation| matches!(violation, FallbackViolation::ReopensNetworkAccess { .. })));
    assert!(violations.iter().any(|violation| matches!(
        violation,
        FallbackViolation::BypassesArtifactVerification { .. }
    )));
    assert!(
        violations.contains(&FallbackViolation::EnablesUngatedOptimization {
            added: BTreeSet::from([GpuDirectStorage, CudaIpcLegacy])
        })
    );

    // CUDA IPC (P05) needs its own evidence on the exporting and the opening side, and
    // never leaves the runtime.
    let wsl = runtime(ExecutionCategory::SharedKernelGpuRuntime, "wsl");
    let other = runtime(ExecutionCategory::SharedKernelGpuRuntime, "wsl-other");
    let (p1, p2, p3) = (ProcessId(1), ProcessId(2), ProcessId(3));
    let (mut driver, mut vmm) = shared_gpu(&[(p1, &wsl), (p2, &wsl), (p3, &other)]);
    assert!(matches!(
        legacy_export(&evidence, &mut driver, &mut vmm, p1, "no-evidence"),
        Err(VmmError::Evidence(_))
    ));
    evidence.support(Capability::CudaIpcLegacy, &wsl, "driver");
    evidence.support(Capability::CudaIpcLegacy, &other, "driver");
    permit_legacy_ipc(&evidence, &mut vmm, p1);
    permit_legacy_ipc(&evidence, &mut vmm, p2);
    let export = legacy_export(&evidence, &mut driver, &mut vmm, p1, "weights").unwrap();
    assert!(matches!(
        vmm.legacy_open(&mut driver, &evidence.registry, p3, export),
        Err(VmmError::CrossesRuntimeBoundary { .. })
    ));
    vmm.legacy_open(&mut driver, &evidence.registry, p2, export)
        .unwrap();

    // P06: a CUDA mechanism is never assumed off CUDA. A Metal runtime whose probe claims
    // GPUDirect Storage, and whose profile permits it, still gets no backend runtime with
    // it.
    let metal = runtime(ExecutionCategory::HostProcessModelRuntime, "metal");
    evidence.support(Capability::GpuDirectStorage, &metal, "loader");
    let metal_profile = RuntimeProfile {
        runtime: metal.clone(),
        configuration: configuration("loader"),
        permitted: BTreeMap::from([(GpuDirectStorage, host_hour)]),
    };
    let metal_plan = gate
        .plan(
            &metal_profile,
            &request(&[(GpuDirectStorage, Optional)]),
            &evidence.registry,
        )
        .unwrap();
    assert!(metal_plan.is_enabled(GpuDirectStorage));
    let pinned = PinnedCapabilities::new(
        QueriedCapabilities {
            release: metal.release.clone(),
            source: SourceClass::HostProbe,
            sleep_levels: BTreeMap::new(),
            features: BTreeSet::new(),
        },
        gate.rules(),
    )
    .unwrap();
    assert!(matches!(
        BackendRuntime::new(
            &metal_profile,
            ComputePlatform::Metal,
            &metal_plan,
            gate.rules(),
            pinned
        ),
        Err(RuntimeRefusal::CudaOnOtherPlatform {
            optimization: GpuDirectStorage,
            platform: ComputePlatform::Metal,
        })
    ));

    // A changed configuration invalidates the loader evidence: keeping io_uring is
    // refused from then on, and the plan must be made again.
    evidence
        .registry
        .invalidate_configuration(configuration("loader"));
    let refusal = guard_fallback(
        &gate,
        &evidence.registry,
        &plan,
        &authorized,
        authorized.clone(),
    )
    .unwrap_err();
    assert!(matches!(
        refusal.violations(),
        [FallbackViolation::LoaderEvidenceNoLongerHolds {
            optimization: IoUring,
            ..
        }]
    ));
    assert!(plan.recheck(IoUring, &evidence.registry).is_err());

    // Once the plan's evidence ages out, the executor gives io_uring up for the ordinary
    // loader.
    clock.advance(HOUR + SECOND);
    assert!(!permissions.permits(ReadMethod::IoUring, &evidence.registry));
    assert!(permissions.permits(ReadMethod::PositionedRead, &evidence.registry));
}

// ---------------------------------------------------------------------------------------
// INT-07: the CLI or UI chooses WSL CUDA, RunPod or Metal.
//
// The CLI and UI themselves are CORE-07, which does not exist yet; this drives the
// contracts they would call: CORE-01's category matrix, the CORE-04 launch, the model
// activation's category check and the S3.5 guard.
// ---------------------------------------------------------------------------------------

/// INT-07 (S6 line 103): the user picks WSL CUDA, a RunPod pod or Metal. Each is admitted
/// only as the category its own host or provider evidence shows, keeps its label and its
/// recorded decision (VM-D4–VM-D6), and is never presented as a VM sandbox. A
/// VM-required setup rejects all three and substitutes none; the coordinator gives the
/// sandbox lifecycle only to a VM sandbox, and nothing inside a sandbox moves a model
/// into a labelled runtime's category.
#[test]
fn int07_labelled_runtimes_keep_their_label_and_never_stand_in_for_a_vm_sandbox() {
    let mut host = Host::new();
    let labelled = [
        (
            runtime(ExecutionCategory::SharedKernelGpuRuntime, "wsl"),
            "VM-D4",
        ),
        (
            runtime(ExecutionCategory::ProviderContainerRuntime, "runpod-pod-1"),
            "VM-D5",
        ),
        (
            runtime(ExecutionCategory::HostProcessModelRuntime, "metal"),
            "VM-D6",
        ),
    ];
    let offers: Vec<RuntimeOffer> = labelled
        .iter()
        .map(|(runtime, _)| host.evidence.offer(runtime))
        .collect();

    // An explicit choice admits exactly that runtime, with its label and decision.
    for (offer, (runtime, decision)) in offers.iter().zip(&labelled) {
        let chosen = RuntimeRequirement::explicit([runtime.category]).unwrap();
        let admitted = chosen.admit(offer).unwrap();
        assert_eq!(admitted.runtime(), runtime);
        assert_eq!(admitted.decision(), Some(*decision));
        assert!(!admitted.is_vm_sandbox());
        assert!(admitted.label().ends_with("not a sandbox"));
        let recorded = serde_json::to_value(&admitted).unwrap();
        assert_eq!(
            recorded["runtime"]["category"],
            serde_json::to_value(runtime.category).unwrap(),
            "the recorded choice keeps its category"
        );
        for (other, _) in labelled.iter().filter(|(other, _)| other != runtime) {
            assert!(RuntimeRequirement::explicit([other.category])
                .unwrap()
                .admit(offer)
                .is_err());
        }
    }

    // A VM-required setup rejects every labelled runtime and selects none.
    let refusal = RuntimeRequirement::VmSandbox.select(&offers).unwrap_err();
    assert_eq!(refusal.refusals.len(), 3);
    for (each, (runtime, decision)) in refusal.refusals.iter().zip(&labelled) {
        assert_eq!(
            each,
            &CategoryRefusal::VmSandboxRequired {
                offered: runtime.category
            }
        );
        assert_eq!(each.decision(), Some(*decision));
        assert!(each.to_string().contains("never selected or substituted"));
    }
    assert_eq!(
        RuntimeRequirement::explicit([
            ExecutionCategory::VmSandbox,
            ExecutionCategory::SharedKernelGpuRuntime
        ]),
        Err(RequirementError::VmSandboxListed)
    );
    // A pod presented as a VM sandbox is refused by the provider's own evidence.
    let disguised = RuntimeSubject {
        category: ExecutionCategory::VmSandbox,
        ..labelled[1].0.clone()
    };
    host.evidence
        .observe_category(&disguised, ExecutionCategory::ProviderContainerRuntime);
    assert!(RuntimeOffer::observe(
        &host.evidence.registry,
        disguised,
        HOUR,
        configuration("launch")
    )
    .is_err());

    // The coordinator launches only VM sandboxes; a labelled runtime reserves nothing.
    let wsl = RuntimeRequirement::explicit([ExecutionCategory::SharedKernelGpuRuntime])
        .unwrap()
        .admit(&offers[0])
        .unwrap();
    let owner = execution("exe-vm-a");
    let owner_tenant = tenant("tenant-a");
    let mut plan = host.plan(
        &owner,
        &owner_tenant,
        sandbox_demand(16 * GIB, 4 * GIB, 22 * GIB),
    );
    plan.runtime = wsl;
    assert_eq!(
        host.try_launch(plan),
        Err(CoordinationError::NotAVmSandbox {
            category: ExecutionCategory::SharedKernelGpuRuntime
        })
    );
    assert_eq!(host.reserved(RAM), 0);

    // Inside a sandbox a model cannot take a labelled category, and no fallback moves it
    // there or reuses another runtime's loader plan.
    let grant = host.launched(
        &owner,
        &owner_tenant,
        sandbox_demand(16 * GIB, 4 * GIB, 22 * GIB),
    );
    let mut labelled_settings = settings_for(grant, BTreeSet::new());
    labelled_settings.execution_category = ExecutionCategory::SharedKernelGpuRuntime;
    assert_eq!(
        host.coordinator().begin_activation(
            &owner,
            model_id("chat"),
            labelled_settings.clone(),
            GpuDemand {
                device: gpu(0),
                memory_bytes: GIB,
            },
        ),
        Err(ModelRefusal::CategoryMismatch {
            parent: ExecutionCategory::VmSandbox,
            settings: ExecutionCategory::SharedKernelGpuRuntime,
        })
    );
    let gate = LoaderGate::recorded();
    let plan_for = |runtime: RuntimeSubject, registry: &ProbeRegistry<TestClock>| {
        gate.plan(
            &RuntimeProfile {
                runtime,
                configuration: configuration("loader"),
                permitted: BTreeMap::new(),
            },
            &LoaderRequest::default(),
            registry,
        )
        .unwrap()
    };
    let authorized = settings_for(grant, BTreeSet::new());
    let refusal = guard_fallback(
        &gate,
        &host.evidence.registry,
        &plan_for(vm_runtime(), &host.evidence.registry),
        &authorized,
        labelled_settings,
    )
    .unwrap_err();
    assert!(refusal
        .violations()
        .contains(&FallbackViolation::ChangesExecutionCategory {
            from: ExecutionCategory::VmSandbox,
            to: ExecutionCategory::SharedKernelGpuRuntime,
        }));
    assert!(refusal.to_string().contains("VM-D4"));
    let refusal = guard_fallback(
        &gate,
        &host.evidence.registry,
        &plan_for(labelled[0].0.clone(), &host.evidence.registry),
        &authorized,
        authorized.clone(),
    )
    .unwrap_err();
    assert!(refusal
        .violations()
        .contains(&FallbackViolation::PlanForAnotherRuntime {
            plan: ExecutionCategory::SharedKernelGpuRuntime,
            authorized: ExecutionCategory::VmSandbox,
        }));
}

// ---------------------------------------------------------------------------------------
// INT-08: a credentialed model download or peer transfer retries after revocation.
// ---------------------------------------------------------------------------------------

/// INT-08 (S6 line 104): a credentialed download is interrupted, retried, then stopped by
/// revocation. Every retry keeps the envelope's object, range, recipient, credential,
/// expiry and budget: a plain retry after revocation is refused, a re-issued grant must
/// come from a newer epoch, which only a new boot of the parent provides, and may not
/// widen anything. Bytes already moved stay charged, extents the catalog verified are
/// reused rather than moved, and no endpoint is ever a URL. Driven through the real
/// adapters: authority over the coordinator, verified extents over the catalog, and the
/// byte budget over the host's one CORE-03 ledger.
#[test]
fn int08_a_retry_after_revocation_keeps_every_bound_and_gains_no_url_authority() {
    let mut host = Host::new();
    let owner = execution("exe-vm-a");
    let owner_tenant = tenant("tenant-a");
    let grant = host.launched(
        &owner,
        &owner_tenant,
        sandbox_demand(16 * GIB, 4 * GIB, 22 * GIB),
    );
    let store = Store::open(&host.clock, |config, _| config);
    let base = weights_bytes("base");
    let delta = weights_bytes("delta");
    store.original(&owner_tenant, &owner, &base);

    // The byte budget is charged to the storage quota of the host's one ledger, through
    // the handle the coordinator's capacity port shares (T14's adapter).
    let budget = host.byte_budget();
    let progress = Arc::new(FakeProgress::default());
    let gate = TransferGate::new(
        host.key.clone(),
        TransferPorts {
            clock: Arc::clone(&host.clock) as Arc<dyn Clock>,
            clock_session: host.evidence.registry.session(),
            authority: Arc::new(CoordinatorAuthority::new(Arc::clone(&host.coordinator))),
            budget: budget.clone(),
            extents: Arc::new(CatalogExtents::new(
                Arc::clone(&store.catalog),
                ArtifactClass::ModelWeights,
            )),
            progress: progress.clone(),
        },
    );
    let (base_key, delta_key) = (ContentKey::of(&base), ContentKey::of(&delta));
    let mut original = download(
        &host,
        "op-model",
        &owner,
        &owner_tenant,
        grant.epoch,
        &[(base_key, 4_096), (delta_key, 4_096)],
    );
    original.stop_bounds.max_in_flight_bytes = 1_024;
    let mut session = gate
        .open(&host.seal(original.clone()), &hub_connection())
        .unwrap();

    // The base is already verified in this tenant's catalog scope: reused, not moved.
    assert_eq!(session.verified_bytes(), 4_096);
    assert_eq!(
        session.missing(),
        BTreeMap::from([(delta_key, RangeSet::single(byte_range(0, 4_096)))])
    );
    assert_eq!(host.reserved(STORAGE), 12_288);

    // First attempt: one chunk delivered, one dropped by a transport failure. Both stay
    // charged, since the dropped one may have moved.
    let first = session.admit(&delta_key, byte_range(0, 1_024)).unwrap();
    session.deliver(first).unwrap();
    let _dropped = session.admit(&delta_key, byte_range(1_024, 2_048)).unwrap();
    session.interrupt().unwrap();
    assert_eq!(session.used_bytes(), 2_048);

    // A retry connects exactly as granted: another credential, source or recipient is
    // refused.
    let other_credential = CredentialRef::from_digest(named(
        "yougori/test/scenarios/credential/v1",
        "someone-else",
    ));
    let other_route = Endpoint::NamedRoute {
        route: named("yougori/test/scenarios/route/v1", "mirror"),
    };
    for wrong in [
        Connection {
            credential: Some(other_credential),
            ..hub_connection()
        },
        Connection {
            source: other_route.clone(),
            ..hub_connection()
        },
        Connection {
            recipient: Endpoint::Execution {
                execution: owner.clone(),
            },
            ..hub_connection()
        },
    ] {
        assert!(session.retry(&wrong).is_err());
    }
    session.retry(&hub_connection()).unwrap();
    assert_eq!(session.attempt(), 2);
    assert_eq!(
        session.used_bytes(),
        2_048,
        "the budget counts every attempt"
    );

    // Revocation stops it at its next chunk; a plain retry is refused. In the one ledger
    // the revocation has already cancelled its reservation.
    host.advance(11 * SECOND);
    let notice = host.coordinator().revoke(&owner).unwrap();
    assert_eq!(
        host.transfer_reservation("op-model"),
        Some(ReservationState::Releasing)
    );
    let stopped = session.admit(&delta_key, byte_range(0, 1_024)).unwrap_err();
    assert!(matches!(
        stopped,
        TransferRefusal::Stopped { ref reason } if reason.is_revocation()
    ));
    assert!(matches!(
        session.retry(&hub_connection()),
        Err(TransferRefusal::NotRetryable { .. })
    ));
    // The same grant again is not a new authorization.
    let Err(TransferRefusal::RetryWidens { violations }) =
        session.retry_with_grant(&host.seal(original.clone()), &hub_connection())
    else {
        panic!("a grant from the revoked epoch cannot continue the transfer");
    };
    assert!(violations
        .iter()
        .any(|violation| matches!(violation, RetryViolation::EpochNotNewer { .. })));
    // Nor does the epoch the revocation moved to, under which nothing was granted.
    let mut under_revoked = original.clone();
    under_revoked.epoch = notice.current;
    assert!(matches!(
        session.retry_with_grant(&host.seal(under_revoked), &hub_connection()),
        Err(TransferRefusal::Stopped { .. })
    ));

    // Every revocation ends in termination; only a new boot authorizes the parent again.
    host.stop(&owner);
    let nothing = ArtifactVerification::Bypassed;
    let report = host.relaunch(
        &owner,
        CompositeRecovery::default(),
        &RecoveryContext {
            expected_image_profile: Digest::from_bytes([0; 32]),
            checkpoint_evidence: None,
            artifact_verification: &nothing,
        },
    );
    let LaunchOutcome::AuthorityActive { grant: fresh, .. } = report.outcome else {
        panic!("the parent boots again");
    };
    let mut reissued = original.clone();
    reissued.epoch = fresh.epoch;

    // A re-issued grant that widens anything is refused, every widening named.
    let mut wider = reissued.clone();
    wider.scope = TransferScope::new([
        (base_key, ObjectGrant::whole(4_096).unwrap()),
        (delta_key, ObjectGrant::whole(4_096).unwrap()),
        (ContentKey::of(b"extra"), ObjectGrant::whole(64).unwrap()),
    ])
    .unwrap();
    wider.budget_bytes += 1;
    wider.recipient = Endpoint::Execution {
        execution: owner.clone(),
    };
    wider.credential = Some(other_credential);
    wider.expires_at = wider.expires_at.saturating_add(HOUR);
    wider.stop_bounds.max_in_flight_bytes *= 2;
    let Err(TransferRefusal::RetryWidens { violations }) =
        session.retry_with_grant(&host.seal(wider), &hub_connection())
    else {
        panic!("a wider grant cannot continue the transfer");
    };
    for expected in [
        "scope",
        "budget",
        "recipient",
        "credential",
        "expiry",
        "stop bounds",
    ] {
        assert!(
            violations.iter().any(|violation| match violation {
                RetryViolation::WiderScope { .. } => expected == "scope",
                RetryViolation::LargerBudget { .. } => expected == "budget",
                RetryViolation::OtherRecipient { .. } => expected == "recipient",
                RetryViolation::OtherCredential => expected == "credential",
                RetryViolation::LaterExpiry { .. } => expected == "expiry",
                RetryViolation::LooserStopBounds { .. } => expected == "stop bounds",
                _ => false,
            }),
            "missing {expected} in {violations:?}"
        );
    }

    // The faithful re-issue continues: what was used still counts, verified data is
    // reused, and the budget never grows.
    session
        .retry_with_grant(&host.seal(reissued), &hub_connection())
        .unwrap();
    assert_eq!(session.used_bytes(), 2_048);
    assert_eq!(session.remaining_budget_bytes(), 12_288 - 2_048);
    assert_eq!(session.verified_bytes(), 4_096);
    for start in (0..4_096).step_by(1_024) {
        let permit = session
            .admit(&delta_key, byte_range(start, start + 1_024))
            .unwrap();
        session.deliver(permit).unwrap();
    }
    assert_eq!(session.used_bytes(), 2_048 + 4_096);
    // The transfer completes only once the catalog's importer has verified what arrived.
    assert!(matches!(
        session.finish(),
        Err(TransferRefusal::Incomplete {
            missing_bytes: 4_096
        })
    ));
    store.original(&owner_tenant, &owner, &delta);
    session.finish().unwrap();
    budget.settle_due();
    assert_eq!(host.reserved(STORAGE), 0);
    assert!(progress
        .events()
        .iter()
        .all(|event| event.origin == ByteOrigin::Remote));

    // No URL authority: endpoints are typed, a URL is refused, and only a registered
    // route is ever presented a credential.
    assert_eq!(
        Endpoint::parse("https://huggingface.co/org/model/resolve/main/model.safetensors"),
        Err(EndpointError::UrlNotAccepted)
    );
    assert_eq!(Endpoint::parse(&hub_route().to_string()), Ok(hub_route()));
    let mut peer = original;
    peer.direction = Direction::Peer;
    peer.source = Endpoint::PeerHost {
        host: named("yougori/test/scenarios/peer/v1", "donor"),
    };
    assert_eq!(
        TransferEnvelope::new(peer).map(|envelope| envelope.fields().operation.clone()),
        Err(EnvelopeError::CredentialWithoutRoute {
            direction: Direction::Peer
        })
    );
}

// ---------------------------------------------------------------------------------------
// INT-09: a corrupt prepared artifact or runtime update.
// ---------------------------------------------------------------------------------------

/// What the fake release publisher signs: a digest of the publisher and content key.
fn attestation(publisher: &PublisherId, content: &ContentKey) -> Vec<u8> {
    digest(
        "yougori/test/scenarios/attestation/v1",
        &[publisher.digest().as_bytes(), content.digest().as_bytes()],
    )
    .as_bytes()
    .to_vec()
}

/// The responsible verifier of runtime updates at the edge: it authenticates the fake
/// publisher's signature and requires an update image to start with its magic.
struct UpdateVerifier;

impl ArtifactVerifier for UpdateVerifier {
    fn class(&self) -> ArtifactClass {
        ArtifactClass::RuntimeUpdate
    }

    fn authenticate(
        &self,
        content: &ContentDescriptor,
        publisher: &PublisherId,
        signature: &[u8],
    ) -> Result<(), VerifierRejection> {
        if signature == attestation(publisher, &content.content_key).as_slice() {
            Ok(())
        } else {
            Err(VerifierRejection::AttestationInvalid)
        }
    }

    fn validate(
        &self,
        _content: &ContentDescriptor,
        bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        let mut magic = [0u8; 8];
        bytes
            .read_exact_at(0, &mut magic)
            .map_err(|error| VerifierRejection::Unreadable {
                detail: error.to_string(),
            })?;
        if &magic == b"YGUPDATE" {
            Ok(())
        } else {
            Err(VerifierRejection::CorruptStructure {
                detail: "the update image has no magic".to_owned(),
            })
        }
    }
}

/// Flips the first byte of every file under `dir` that holds exactly `bytes`, as disk
/// corruption would.
fn corrupt_on_disk(dir: &Path, bytes: &[u8]) -> usize {
    let mut corrupted = 0;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                corrupted += corrupt_on_disk(&path, bytes);
            } else if fs::read(&path).is_ok_and(|held| held == bytes) {
                make_writable(&path);
                let mut changed = bytes.to_vec();
                changed[0] ^= 0xff;
                fs::write(&path, changed).unwrap();
                corrupted += 1;
            }
        }
    }
    corrupted
}

/// INT-09 (S6 line 105): corrupt prepared artifacts and runtime updates meet their
/// responsible typed verifier: P01's sidecar verifier for a model sidecar and the update
/// verifier for a runtime update. A consistent checksum never stands in for trust, an
/// untrusted publisher is refused even with a valid signature, a prepared copy corrupted
/// on disk is quarantined and never read, and the user's original stays published,
/// byte-for-byte intact and never evictable.
#[test]
fn int09_corrupt_artifacts_meet_their_responsible_verifier_and_originals_stay_intact() {
    let clock: TestClock = Arc::new(ManualClock::new(at_seconds(1_000)));
    let release = PublisherId::from_key_fingerprint(named(
        "yougori/test/scenarios/publisher/v1",
        "yougori-release",
    ));
    let mirror = PublisherId::from_key_fingerprint(named(
        "yougori/test/scenarios/publisher/v1",
        "unknown-mirror",
    ));
    let store = Store::open(&clock, |config, verifiers| {
        verifiers
            .register(Box::new(SidecarVerifier::new(ReadBackChannel::new(), MIB)))
            .unwrap();
        verifiers.register(Box::new(UpdateVerifier)).unwrap();
        config
            .with_quota(Scope::Host, MIB)
            .with_trust(
                ArtifactClass::ModelSidecar,
                TrustPolicy::new().accept_user_selected(),
            )
            .with_trust(
                ArtifactClass::RuntimeUpdate,
                TrustPolicy::new().trust_publisher(release.clone()),
            )
    });
    let owner = tenant("tenant-a");
    let by = execution("exe-vm-a");
    let scope = Scope::tenant(owner.clone());
    let weights = weights_bytes("chat");
    let original = store.original(&owner, &by, &weights);

    // A corrupt prepared sidecar: its bytes match their checksum and the tenant selected
    // it, but the verifier responsible for sidecars finds no valid manifest in it.
    let corrupt_sidecar = b"YGSC not a sidecar manifest ".repeat(16);
    let derived = ObjectRole::Prepared {
        derived_from: BTreeSet::from([original]),
    };
    let status = store
        .import(
            &scope,
            &by,
            ArtifactClass::ModelSidecar,
            derived.clone(),
            &corrupt_sidecar,
            TrustClaim::UserSelected,
        )
        .unwrap();
    let ImportStatus::Failed { failure } = status else {
        panic!("the sidecar verifier rejects it, got {status:?}");
    };
    assert!(matches!(
        failure.reason,
        FailureReason::VerifierRejected {
            rejection: VerifierRejection::CorruptStructure { .. }
        }
    ));
    let sidecar = ObjectId::new(
        &scope,
        ArtifactClass::ModelSidecar,
        ContentKey::of(&corrupt_sidecar),
    );
    assert_eq!(
        store.catalog().status(&scope, sidecar),
        ObjectStatus::Absent,
        "nothing was published"
    );

    // A checksum alone is never trust, whatever the class.
    for (class, scope) in [
        (ArtifactClass::ModelSidecar, scope.clone()),
        (ArtifactClass::RuntimeUpdate, Scope::Host),
    ] {
        assert_eq!(
            store.import(
                &scope,
                &by,
                class,
                ObjectRole::Original,
                b"YGUPDATE checksum only",
                TrustClaim::ChecksumOnly
            ),
            Err(ImportRefusal::Trust {
                refusal: TrustRefusal::ChecksumIsNotTrust { class }
            })
        );
    }

    // A runtime update needs a publisher its class trusts, a valid signature and a
    // structure its verifier accepts.
    let updater = execution("exe-updater");
    let image = [b"YGUPDATE".as_slice(), &[7u8; 504]].concat();
    let corrupt_image = [b"NOTUPDTE".as_slice(), &[7u8; 504]].concat();
    let update = |bytes: &[u8], publisher: &PublisherId, signature: Vec<u8>| {
        store.import(
            &Scope::Host,
            &updater,
            ArtifactClass::RuntimeUpdate,
            ObjectRole::Original,
            bytes,
            TrustClaim::Publisher {
                publisher: publisher.clone(),
                attestation: signature,
            },
        )
    };
    let image_key = ContentKey::of(&image);
    assert!(matches!(
        update(&image, &mirror, attestation(&mirror, &image_key)),
        Err(ImportRefusal::Trust {
            refusal: TrustRefusal::PublisherNotTrusted { .. }
        })
    ));
    assert!(matches!(
        update(&image, &release, b"forged".to_vec()),
        Err(ImportRefusal::Trust {
            refusal: TrustRefusal::AttestationRejected { .. }
        })
    ));
    let status = update(
        &corrupt_image,
        &release,
        attestation(&release, &ContentKey::of(&corrupt_image)),
    )
    .unwrap();
    assert!(matches!(
        status,
        ImportStatus::Failed { ref failure } if matches!(
            failure.reason,
            FailureReason::VerifierRejected { rejection: VerifierRejection::CorruptStructure { .. } }
        )
    ));
    assert!(matches!(
        update(&image, &release, attestation(&release, &image_key)).unwrap(),
        ImportStatus::Published { .. }
    ));

    // A prepared copy corrupted on disk after publication: verification quarantines it
    // and it is never read again.
    let prepared_bytes = weights_bytes("chat-prepared");
    let ImportStatus::Published {
        object: prepared, ..
    } = store
        .import(
            &scope,
            &by,
            ArtifactClass::ModelWeights,
            derived,
            &prepared_bytes,
            TrustClaim::UserSelected,
        )
        .unwrap()
    else {
        panic!("the prepared copy is published");
    };
    assert!(corrupt_on_disk(store.dir.path(), &prepared_bytes) > 0);
    {
        let mut catalog = store.catalog();
        assert!(matches!(
            catalog.verify_object(&scope, prepared),
            Err(VerifyError::Quarantined { .. })
        ));
        assert!(matches!(
            catalog.status(&scope, prepared),
            ObjectStatus::Quarantined { .. }
        ));
        assert!(matches!(
            catalog.acquire_lease(&scope, &by, prepared, MINUTE),
            Err(ReadRefusal::Quarantined { .. })
        ));
    }

    // The user's original is intact: published, verified, readable and never evicted.
    let mut catalog = store.catalog();
    assert_eq!(catalog.status(&scope, original), ObjectStatus::Published);
    catalog.verify_object(&scope, original).unwrap();
    let lease = catalog
        .acquire_lease(&scope, &by, original, MINUTE)
        .unwrap();
    assert_eq!(
        catalog
            .open_read(&scope, &by, lease)
            .unwrap()
            .read_all()
            .unwrap(),
        weights
    );
    catalog.release_lease(&scope, &by, lease).unwrap();
    assert!(catalog
        .eviction_candidates(&scope)
        .iter()
        .all(|candidate| candidate.object != original));
    assert!(matches!(
        catalog.evict_cache(&scope, &[original]),
        Err(EvictionRefusal::UserOriginal { .. })
    ));
}

// ---------------------------------------------------------------------------------------
// INT-10: high-volume GPU progress while audit storage is slow or full.
// ---------------------------------------------------------------------------------------

/// What audit storage at the edge holds.
struct DiskState {
    records: Vec<AuditRecord>,
    slow_writes: u32,
    capacity: usize,
}

/// Audit storage at the edge: slow for a number of writes, full at a capacity. Clones
/// share one disk, so the test can fill and free the disk the journal owns.
#[derive(Clone)]
struct AuditDisk(Arc<Mutex<DiskState>>);

impl AuditDisk {
    fn slow_for(slow_writes: u32) -> Self {
        Self(Arc::new(Mutex::new(DiskState {
            records: Vec::new(),
            slow_writes,
            capacity: usize::MAX,
        })))
    }

    /// No more record fits from now on.
    fn fill(&self) {
        let mut state = lock(&self.0);
        state.capacity = state.records.len();
    }

    fn free(&self) {
        lock(&self.0).capacity = usize::MAX;
    }

    fn records(&self) -> Vec<AuditRecord> {
        lock(&self.0).records.clone()
    }
}

impl AuditStore for AuditDisk {
    fn append(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        let mut state = lock(&self.0);
        if state.records.iter().any(|stored| stored == record) {
            return Ok(());
        }
        if state.slow_writes > 0 {
            state.slow_writes -= 1;
            return Err(StoreRefusal::Slow);
        }
        if state.records.len() >= state.capacity {
            return Err(StoreRefusal::Full);
        }
        state.records.push(record.clone());
        Ok(())
    }
}

/// The journal's bounded local spool, kept in memory.
#[derive(Default)]
struct AuditSpoolFile {
    records: VecDeque<AuditRecord>,
}

impl AuditSpool for AuditSpoolFile {
    fn push(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        self.records.push_back(record.clone());
        Ok(())
    }

    fn front(&self) -> Result<Option<AuditRecord>, StoreRefusal> {
        Ok(self.records.front().cloned())
    }

    fn pop_front(&mut self) -> Result<(), StoreRefusal> {
        self.records.pop_front();
        Ok(())
    }

    fn len(&self) -> usize {
        self.records.len()
    }

    fn records(&self) -> Result<Vec<AuditRecord>, StoreRefusal> {
        Ok(self.records.iter().cloned().collect())
    }
}

/// INT-10 (S6 line 106): P08's GPU progress for four loads, the transfer's progress over
/// CORE-06 and a flood of runner metrics share the event plane while audit storage is
/// slow, then full. Progress coalesces and, when its bound is reached, is refused without
/// stopping the transfer; metrics are sampled and dropped, every loss counted. The
/// coordinator's revocation goes out ahead of the whole backlog and stops the transfer
/// at its next chunk; its audit record takes the revocation reserve while ordinary
/// records fail closed, visibly. Once storage recovers, every accepted record is stored
/// once, in order, on an unbroken chain.
#[test]
fn int10_a_progress_and_metrics_flood_never_delays_revocation_or_reorders_audit() {
    let mut host = Host::new();
    let owner = execution("exe-vm-a");
    let owner_tenant = tenant("tenant-a");
    let grant = host.launched(
        &owner,
        &owner_tenant,
        sandbox_demand(16 * GIB, 4 * GIB, 22 * GIB),
    );
    let handle = host
        .coordinator()
        .begin_activation(
            &owner,
            model_id("chat"),
            settings_for(grant, BTreeSet::new()),
            GpuDemand {
                device: gpu(0),
                memory_bytes: 10 * GIB,
            },
        )
        .unwrap();
    let hub = Arc::new(Mutex::new(event_hub_with(&host.clock, 1, 512, 5)));

    // P08 publishes the GPU progress of four loads, one bound to the activation.
    let producer = lock(&hub)
        .register_progress(
            ProducerId::new("engine.progress").unwrap(),
            SourceClass::HostProbe,
            None,
        )
        .unwrap();
    let mut publisher = ProgressPublisher::new(
        producer,
        Incarnation::FIRST,
        Arc::clone(&host.clock),
        ClockId::new(ReportLabel::new("host-monotonic").unwrap()),
        PublishPolicy::default(),
    )
    .unwrap();
    let loads: Vec<OperationId> = (0..4)
        .map(|index| operation(&format!("op-load-{index}")))
        .collect();
    for load in &loads {
        publisher
            .track(
                &mut *lock(&hub),
                load,
                TrackRequest {
                    resource: TrackedResourceId::new(named(
                        "yougori/test/scenarios/resource/v1",
                        load.as_str(),
                    )),
                    kind: EventResource::Weights,
                    total_bytes: 64 * MIB,
                    stage: Stage::from_source(Phase::Loading, DataSource::LocalStorage),
                },
            )
            .unwrap();
    }
    publisher
        .set_allocation(&mut *lock(&hub), &*host.coordinator(), &loads[0], &handle)
        .unwrap();

    // The transfer reports through T14's adapter onto the same hub; the progress bound
    // leaves room for only one of its two objects.
    let transfer_progress = Arc::new(
        EventProgress::register(
            Arc::clone(&hub),
            ProducerId::new("engine.transfer").unwrap(),
            EventResource::Weights,
        )
        .unwrap(),
    );
    let gate = TransferGate::new(
        host.key.clone(),
        TransferPorts {
            clock: Arc::clone(&host.clock) as Arc<dyn Clock>,
            clock_session: host.evidence.registry.session(),
            authority: Arc::new(CoordinatorAuthority::new(Arc::clone(&host.coordinator))),
            budget: host.byte_budget(),
            extents: Arc::new(FakeExtents::default()),
            progress: transfer_progress.clone(),
        },
    );
    let shards = [ContentKey::of(b"shard-0"), ContentKey::of(b"shard-1")];
    let mut transfer = gate
        .open(
            &host.seal(download(
                &host,
                "op-prefetch",
                &owner,
                &owner_tenant,
                grant.epoch,
                &[(shards[0], 4_096), (shards[1], 4_096)],
            )),
            &hub_connection(),
        )
        .unwrap();
    assert!(
        transfer_progress.refused() > 0,
        "the progress bound refuses"
    );

    let mut runners: Vec<MetricsProducer> = (0..4)
        .map(|index| {
            lock(&hub)
                .register_metrics(
                    ProducerId::new(format!("runner-{index}")).unwrap(),
                    SourceClass::HostProbe,
                    RedactionPolicy::metadata_only(),
                    None,
                )
                .unwrap()
        })
        .collect();
    let mut issuer = lock(&hub)
        .register_revocation_issuer(ProducerId::new("coordinator").unwrap())
        .unwrap();
    let journal_id = JournalId::new("engine").unwrap();
    let audit_owner = ProducerId::new("engine.audit").unwrap();
    let disk = AuditDisk::slow_for(4);
    let (mut journal, mut authority) = AuditJournal::open(
        journal_id.clone(),
        audit_owner.clone(),
        disk.clone(),
        AuditSpoolFile::default(),
        Arc::clone(&host.clock),
        AuditConfig {
            spool_records: 8,
            revocation_reserve_records: 2,
            failure_policy: AuditFailurePolicy::DenyHighImpact,
            guest_observations: EmissionLimit::new(10, SECOND).unwrap(),
            redaction: RedactionPolicy::metadata_only(),
        },
    )
    .unwrap();

    let steps = 20_000u64;
    let mut accepted = Vec::new();
    let mut denied_but_kept = Vec::new();
    let mut fail_closed = 0;
    let mut delivered_bytes = 0u64;
    let mut revocation = None;
    let mut transfer_stopped_at = None;
    for step in 0..steps {
        host.clock.advance(Duration::from_micros(500));
        let mut events = lock(&hub);
        let runner = &mut runners[usize::try_from(step % 4).unwrap()];
        events
            .emit_metric(
                runner,
                EventContext::new(operation("op-serve"), Phase::Running),
                MetricDraft::new(
                    "gpu.resident_bytes",
                    MetricValue::GaugeBytes { bytes: step },
                ),
            )
            .unwrap();
        // High-volume GPU progress: one extent per step, coalesced per load.
        let index = step / 4;
        if index < 64 {
            let load = &loads[usize::try_from(step % 4).unwrap()];
            publisher
                .extent_arrived(&mut *events, load, index, MIB)
                .unwrap();
            publisher
                .extent_committed(&mut *events, load, index)
                .unwrap();
        }
        drop(events);
        // The transfer moves one chunk every hundred steps, whatever the progress plane
        // took of its reports.
        if step % 100 == 0 && transfer_stopped_at.is_none() {
            let shard = shards[usize::try_from((step / 100) % 2).unwrap()];
            let start = (step / 200) * 64;
            match transfer.admit(&shard, byte_range(start, start + 64)) {
                Ok(permit) => {
                    transfer.deliver(permit).unwrap();
                    delivered_bytes += 64;
                }
                Err(TransferRefusal::Stopped { reason }) => {
                    assert!(reason.is_revocation(), "{reason}");
                    transfer_stopped_at = Some(step);
                }
                Err(other) => panic!("{other:?}"),
            }
        }
        // Audit storage is slow at first, full from step 3,000 and back at 15,000.
        if step == 3_000 {
            disk.fill();
        }
        if step == 15_000 {
            disk.free();
        }
        if step % 1_000 == 0 {
            let context = EventContext::new(operation("op-serve"), Phase::Running);
            let fields = vec![Field::metadata("step", step)];
            match journal.admit_high_impact(&mut authority, context, fields) {
                Ok(receipt) => accepted.push(receipt.sequence.get()),
                Err(AuditRefusal::FailClosed { kept, .. }) => {
                    fail_closed += 1;
                    denied_but_kept.extend(kept.map(|sequence| sequence.get()));
                }
                Err(other) => panic!("unexpected audit refusal: {other}"),
            }
            let context = EventContext::new(operation("op-serve"), Phase::Running);
            let fact = AuditDraft::HostFact {
                fact: HostFact::Lease,
                fields: vec![Field::metadata("step", step)],
            };
            match journal.append(&mut authority, context, fact) {
                Ok(receipt) => accepted.push(receipt.sequence.get()),
                Err(AuditRefusal::FailClosed { kept, .. }) => {
                    fail_closed += 1;
                    denied_but_kept.extend(kept.map(|sequence| sequence.get()));
                }
                Err(other) => panic!("unexpected audit refusal: {other}"),
            }
        }
        if step == 10_000 {
            assert!(
                lock(&hub).metrics().buffered() > 256,
                "a large metrics backlog stands"
            );
            // Ordinary records fail closed while storage is full.
            assert!(matches!(journal.health(), AuditHealth::FailClosed { .. }));
            // The coordinator revokes and publishes the notice through the event plane's
            // own authorities: on the priority lane and into the audit journal, where it
            // takes the revocation reserve.
            let published = host
                .coordinator()
                .revoke_and_publish(
                    &owner,
                    operation("op-revoke"),
                    RevocationReason::SecurityEvent,
                    &mut RevocationEvents {
                        hub: &mut lock(&hub),
                        issuer: &mut issuer,
                        journal: &mut journal,
                        authority: &mut authority,
                    },
                )
                .unwrap();
            let revoked = Revocation {
                execution: owner.clone(),
                epoch: published.notice.current,
                reason: RevocationReason::SecurityEvent,
            };
            assert_eq!(published.lane, Ok(RevocationAdmission::Queued));
            let delivery = lock(&hub).drain(16);
            assert_eq!(delivery.revocations.notices.len(), 1);
            assert_eq!(delivery.revocations.notices[0].payload(), &revoked);
            assert!(delivery.metrics.events.len() <= 16);
            let receipt = published.audit.unwrap();
            assert!(matches!(receipt.durability, Durability::Spooled { .. }));
            accepted.push(receipt.sequence.get());
            revocation = Some(receipt.sequence.get());
        }
        // The receiver drains now and then, but stalls from step 4,000 to 12,000.
        if step % 2_000 == 1_999 && !(4_000..12_000).contains(&step) {
            lock(&hub).drain(256);
        }
    }

    // The transfer stopped at its first chunk after the revocation.
    assert_eq!(transfer_stopped_at, Some(10_100));
    assert!(delivered_bytes > 0);
    assert!(transfer_progress.refused() > 0);

    // Once nothing uses the revoked sandbox's memory, P08 refuses its allocation.
    let status = host.advance_revocation(&owner);
    assert!(
        matches!(status, RevocationStatus::Completed { .. }),
        "{status:?}"
    );
    assert!(matches!(
        publisher.set_allocation(&mut *lock(&hub), &*host.coordinator(), &loads[1], &handle),
        Err(PublishError::StaleAllocation { .. })
    ));

    // Audit: storage recovered. Every accepted record, and every refused one storage may
    // have seen (kept under its sequence, its operation still denied), is stored once,
    // in sequence order, on one unbroken chain; the failures were visible refusals.
    journal.flush();
    assert_eq!(journal.health(), AuditHealth::Durable);
    assert!(fail_closed > 0);
    let records = disk.records();
    let head = verify_chain(&JournalHead::genesis(journal_id, audit_owner), &records).unwrap();
    let stored: Vec<u64> = records
        .iter()
        .map(|record| record.sequence().get())
        .collect();
    assert_eq!(stored, (1..=stored.len() as u64).collect::<Vec<_>>());
    let mut recorded: BTreeSet<u64> = accepted.iter().copied().collect();
    recorded.extend(denied_but_kept.iter().copied());
    assert_eq!(stored, recorded.into_iter().collect::<Vec<_>>());
    assert_eq!(head.last.map(|last| last.get()), stored.last().copied());
    let revocations: Vec<u64> = records
        .iter()
        .filter(|record| matches!(record.event().payload(), AuditEntry::Revocation { .. }))
        .map(|record| record.sequence().get())
        .collect();
    assert_eq!(revocations, revocation.into_iter().collect::<Vec<_>>());

    // Metrics: everything offered was delivered or counted lost; progress coalesced.
    lock(&hub).drain(usize::MAX);
    let events = lock(&hub);
    let totals = events.metrics().totals();
    assert_eq!(totals.offered, steps);
    assert!(totals.lost() > 0);
    assert_eq!(totals.offered, totals.delivered + totals.lost());
    assert!(publisher.stats().coalesced > 0);
    assert!(events.progress().tracked() <= 5);
    assert_eq!(events.revocations().totals().delivered, 1);
}

// ---------------------------------------------------------------------------------------
// Integration gaps: what the plan requires where one committed module cannot reach
// another, or one path bypasses a rule another enforces. Each fails today.
// ---------------------------------------------------------------------------------------

/// INT-01, INT-02 and INT-08 need one host ledger (CORE-03: one capacity authority). The
/// coordinator's capacity port charges the host's ledger through a shared handle
/// (`LedgerCapacity::shared`), and the transfer byte budget and the executor's
/// reservations hold the same handle (`handle()`). So the storage quota and pinned
/// staging are granted once across all three, and a revocation's `cancel_execution`
/// reaches the transfer's reservation (gap G1, closed).
#[test]
fn gap_transfer_budgets_and_the_coordinator_cannot_share_one_host_ledger() {
    let mut host = Host::new();
    let owner = execution("exe-vm-a");
    let owner_tenant = tenant("tenant-a");
    let mut demand = sandbox_demand(16 * GIB, 4 * GIB, 22 * GIB);
    demand.insert(ResourceKind::StorageBytes, 40 * GIB);
    let grant = host.launched(&owner, &owner_tenant, demand);
    let ledger = host.coordinator().capacity().handle();
    assert!(Arc::ptr_eq(&ledger, &host.ledger));
    let budget = Arc::new(
        LedgerByteBudget::new(
            Arc::clone(&ledger),
            Arc::clone(&host.clock) as Arc<dyn Clock>,
            BTreeMap::from([(Direction::Download, STORAGE)]),
            Priority::Foreground,
        )
        .unwrap(),
    );
    let gate = TransferGate::new(
        host.key.clone(),
        TransferPorts {
            clock: Arc::clone(&host.clock) as Arc<dyn Clock>,
            clock_session: host.evidence.registry.session(),
            authority: Arc::new(CoordinatorAuthority::new(Arc::clone(&host.coordinator))),
            budget,
            extents: Arc::new(FakeExtents::default()),
            progress: Arc::new(FakeProgress::default()),
        },
    );
    let open = |name: &str, object: &[u8], bytes: u64| {
        gate.open(
            &host.seal(download(
                &host,
                name,
                &owner,
                &owner_tenant,
                grant.epoch,
                &[(ContentKey::of(object), bytes)],
            )),
            &hub_connection(),
        )
    };

    // The sandbox holds 40 of the 64 GiB of storage quota. A 20 GiB download, whose budget
    // is 30 GiB, does not fit beside it: the quota is never granted twice.
    let refused = open("op-large", b"a large model", 20 * GIB).unwrap_err();
    assert_eq!(
        refused,
        TransferRefusal::ReservationRefused {
            refusal: ByteBudgetRefusal {
                requested_bytes: 30 * GIB,
                available_bytes: 24 * GIB,
                retry_can_progress: true,
            }
        }
    );
    assert_eq!(host.reserved(STORAGE), 40 * GIB);
    // A 16 GiB download takes exactly what is left.
    let _session = open("op-fits", b"a smaller model", 16 * GIB).unwrap();
    assert_eq!(host.reserved(STORAGE), 64 * GIB);
    assert_eq!(host.available(STORAGE), Some(0));

    // The executor's reservations hold the same handle: its pinned staging meets the
    // sandbox's 4 GiB of the host's 8 GiB, and is charged to host RAM too.
    let mut executor = LedgerReservations::new(
        Arc::clone(&ledger),
        StagingAccount {
            execution: execution("exe-executor"),
            tenant: tenant("tenant-b"),
        },
    );
    let staging = |bytes| ExecutorRequest {
        operation: operation("op-staging"),
        execution: None,
        tenant: None,
        priority: ExecutorPriority::Foreground,
        resource: ReservedResource::PinnedHostMemory,
        purpose: ExecutorPurpose::HostStaging,
        bytes,
        parent: None,
    };
    assert_eq!(
        executor.reserve(&staging(5 * GIB)),
        Err(ExecutorRefusal::Capacity(ExecutorCapacityRefusal {
            resource: ReservedResource::PinnedHostMemory,
            limit: ExecutorLimit::PhysicalCapacity,
            requested_bytes: 5 * GIB,
            available_bytes: 4 * GIB,
            retry: RetryAdvice::CanProgress,
        }))
    );
    let ring = executor.reserve(&staging(4 * GIB)).unwrap();
    assert_eq!(host.reserved(PINNED), 8 * GIB);
    assert_eq!(host.reserved(RAM), 20 * GIB);

    // The revocation's ledger cancellation reaches the transfer's reservation, which stays
    // counted until its release is observed; the executor's own staging is untouched.
    host.coordinator().revoke(&owner).unwrap();
    assert_eq!(
        host.transfer_reservation("op-fits"),
        Some(ReservationState::Releasing)
    );
    assert_eq!(host.reserved(STORAGE), 64 * GIB);
    let ring = executor.ledger_reservation(ring).unwrap();
    assert_eq!(
        host.ledger().reservation(ring).map(|record| record.state()),
        Some(ReservationState::Granted)
    );
}

/// INT-04 and INT-09: the catalog's `artifact_verification`, the set a loader declares as
/// its verified artifacts, names scoped object identities, and CORE-04's model-cache
/// validator accepts the tenant's catalog object for each content key, so a cache of
/// artifacts the catalog verified for this very tenant can be restored (gap G2, closed).
#[test]
fn gap_catalog_verified_artifacts_cannot_validate_a_model_cache() {
    let clock: TestClock = Arc::new(ManualClock::new(at_seconds(1_000)));
    let store = Store::open(&clock, |config, _| config);
    let owner = tenant("tenant-a");
    let by = execution("exe-vm-a");
    let weights = weights_bytes("chat");
    let object = store.original(&owner, &by, &weights);
    let verification = store
        .catalog()
        .artifact_verification(&Scope::tenant(owner.clone()), &by, [object])
        .unwrap();
    let cache = ModelCacheManifest {
        tenant: owner.clone(),
        artifacts: BTreeSet::from([ContentKey::of(&weights)]),
    };
    assert_eq!(validate_model_cache(&cache, &owner, &verification), Ok(()));
}

/// INT-05: T07's `ScopedGrant` is made only from a live catalog grant check and asks the
/// catalog again at every use, so revoking the owner's catalog grant ends the sharing
/// decision it backed (closed by the T07 integration fix).
#[test]
fn gap_storage_sharing_survives_the_revocation_of_the_owners_catalog_grant() {
    let clock: TestClock = Arc::new(ManualClock::new(at_seconds(1_000)));
    let store = Store::open(&clock, |config, _| config);
    let (a, b) = (tenant("tenant-a"), tenant("tenant-b"));
    let (exe_a, exe_b) = (execution("exe-vm-a"), execution("exe-vm-b"));
    let object = store.original(&a, &exe_a, &weights_bytes("shared-base"));
    let catalog_grant = store
        .catalog()
        .grant(
            &Scope::tenant(a.clone()),
            GrantRequest {
                object,
                grantee: Scope::tenant(b.clone()),
                execution: Some(exe_b.clone()),
                expires_at: clock.now().saturating_add(HOUR),
            },
        )
        .unwrap();
    let pool = TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, "host-pool");
    let scoped = ScopedGrant::from_catalog(
        &store.catalog,
        object,
        exe_b,
        GrantTerms {
            grantor: a.clone(),
            grantee: b.clone(),
            artifact: artifact_of("shared-base"),
            scope: pool,
            uses: BTreeSet::from([GrantedUse::ShareImmutableStorage]),
            expires_at: clock.now().saturating_add(HOUR),
        },
    )
    .unwrap();
    let decide = || {
        decide_storage_sharing(
            &StoredRepresentation {
                execution: execution_of("shared-base"),
                artifact: artifact_of("shared-base"),
                owner: a.clone(),
                scope: pool,
            },
            &ShareRequest {
                execution: execution_of("shared-base"),
                tenant: b.clone(),
                scope: pool,
                medium: SharingMedium::ImmutableStorage,
            },
            Some(&scoped),
            &*clock,
        )
    };
    assert!(decide().is_ok(), "the live catalog grant backs the sharing");
    store
        .catalog()
        .revoke_grant(&Scope::tenant(a.clone()), catalog_grant)
        .unwrap();
    let decision = decide();
    assert!(
        decision.is_err(),
        "sharing outlived the owner's revoked grant: {decision:?}"
    );
}

/// INT-05: cross-request KV reuse needs CORE-01 evidence that the backend enforces the
/// KV scope (FAST-03). `ScopeEnforcement::Verified` holds `evidence::Satisfied`, which
/// only a probe registry makes, so a claim no registry produced cannot be written, and
/// reuse is refused without evidence (closed by the T07 integration fix).
#[test]
fn gap_kv_reuse_accepts_scope_enforcement_without_evidence() {
    let owner = tenant("tenant-a");
    let session = execution("exe-vm-a");
    let pool = TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, "host-pool");
    let stored = StoredKv {
        spec: kv_spec(&owner, &session),
        trust_scope: pool,
        sharing: KvSharing::TenantScoped,
    };
    let request = KvRequest {
        spec: kv_spec(&owner, &session),
        trust_scope: pool,
    };
    let reuse = check_kv_reuse(
        &stored,
        &request,
        &PublicPrefixSharing::none(),
        &RevokedAuthorities::new(),
        &ScopeEnforcement::NotVerified,
        MonotonicTime::ZERO,
    );
    assert!(
        reuse.is_err(),
        "KV reuse was enabled without scope-enforcement evidence"
    );
    let evidenced = scope_enforcement(MonotonicTime::ZERO, HOUR);
    assert!(
        check_kv_reuse(
            &stored,
            &request,
            &PublicPrefixSharing::none(),
            &RevokedAuthorities::new(),
            &evidenced,
            MonotonicTime::ZERO
        )
        .is_ok(),
        "registry evidence enables reuse"
    );
}

/// INT-06: the coordinator records an activation's settings as authorized only within the
/// loader the CORE-01 gate approved for this runtime (`grant_loader`), so optimizations no
/// `LoaderPlan` enabled never become the "authorized" baseline that every later S3.5
/// fallback is compared with (gap G5, closed).
#[test]
fn gap_an_activation_records_an_unapproved_loader_as_authorized() {
    let mut host = Host::new();
    let owner = execution("exe-vm-a");
    let grant = host.launched(
        &owner,
        &tenant("tenant-a"),
        sandbox_demand(16 * GIB, 4 * GIB, 22 * GIB),
    );
    // No evidence and no profile permit either optimization on this runtime.
    let mut settings = settings_for(grant, BTreeSet::new());
    settings.loader = BTreeSet::from([Optimization::CudaIpcLegacy, Optimization::GpuDirectStorage]);
    let activation = host.coordinator().begin_activation(
        &owner,
        model_id("chat"),
        settings,
        GpuDemand {
            device: gpu(0),
            memory_bytes: GIB,
        },
    );
    assert!(
        activation.is_err(),
        "an ungated loader was recorded as authorized"
    );
}

/// INT-06: P05's IPC export needs both CORE-01 evidence and a loader plan that enables
/// CUDA IPC for the process's runtime, so a runtime whose profile does not permit it (the
/// gate leaves it to the ordinary loader) exports no device memory (gap G6, closed).
#[test]
fn gap_ipc_export_bypasses_the_runtime_profile() {
    let clock: TestClock = Arc::new(ManualClock::new(at_seconds(1_000)));
    let mut evidence = Evidence::new(&clock);
    let wsl = runtime(ExecutionCategory::SharedKernelGpuRuntime, "wsl");
    evidence.support(Capability::CudaIpcLegacy, &wsl, "driver");
    let profile = RuntimeProfile {
        runtime: wsl.clone(),
        configuration: configuration("driver"),
        permitted: BTreeMap::new(),
    };
    let plan = LoaderGate::recorded()
        .plan(
            &profile,
            &LoaderRequest {
                optimizations: BTreeMap::from([(Optimization::CudaIpcLegacy, Necessity::Optional)]),
            },
            &evidence.registry,
        )
        .unwrap();
    assert_eq!(
        plan.ordinary()[&Optimization::CudaIpcLegacy],
        NotEnabled::NotPermitted
    );
    let (mut driver, mut vmm) = shared_gpu(&[(ProcessId(1), &wsl), (ProcessId(2), &wsl)]);
    let export = legacy_export(&evidence, &mut driver, &mut vmm, ProcessId(1), "weights");
    assert!(
        export.is_err(),
        "CUDA IPC was exported where the runtime profile does not permit it"
    );
}

/// INT-06: after a configuration change invalidates the plan's evidence (CORE-01), the
/// plan must be made again, and the transfer executor stops reading with io_uring, since
/// its read permissions recheck the plan's evidence on every use (gap G7, closed).
#[test]
fn gap_executor_keeps_a_gated_read_method_after_its_evidence_is_invalidated() {
    let clock: TestClock = Arc::new(ManualClock::new(at_seconds(1_000)));
    let mut evidence = Evidence::new(&clock);
    let sandbox = vm_runtime();
    evidence.support(Capability::IoUring, &sandbox, "loader");
    let plan = LoaderGate::recorded()
        .plan(
            &RuntimeProfile {
                runtime: sandbox,
                configuration: configuration("loader"),
                permitted: BTreeMap::from([(
                    Optimization::IoUring,
                    EvidencePolicy {
                        minimum_source: SourceClass::HostProbe,
                        max_age: HOUR,
                    },
                )]),
            },
            &LoaderRequest {
                optimizations: BTreeMap::from([(Optimization::IoUring, Necessity::Optional)]),
            },
            &evidence.registry,
        )
        .unwrap();
    let permissions = LoaderPermissions::from_plan(&plan);
    evidence
        .registry
        .invalidate_configuration(configuration("loader"));
    assert!(plan
        .recheck(Optimization::IoUring, &evidence.registry)
        .is_err());
    assert!(
        !permissions.permits(ReadMethod::IoUring, &evidence.registry),
        "io_uring stays permitted after its evidence was invalidated"
    );
}

/// INT-06: P06 refuses a CUDA mechanism off CUDA whatever the evidence claims, and so
/// does the transfer executor: read permissions made from a plan alone treat the platform
/// as unknown, so a Metal runtime whose probe wrongly claims GPUDirect Storage gets no CUDA
/// read method (gap G8, closed).
#[test]
fn gap_executor_permits_a_cuda_read_method_on_metal() {
    let clock: TestClock = Arc::new(ManualClock::new(at_seconds(1_000)));
    let mut evidence = Evidence::new(&clock);
    let metal = runtime(ExecutionCategory::HostProcessModelRuntime, "metal");
    evidence.support(Capability::GpuDirectStorage, &metal, "loader");
    let plan = LoaderGate::recorded()
        .plan(
            &RuntimeProfile {
                runtime: metal,
                configuration: configuration("loader"),
                permitted: BTreeMap::from([(
                    Optimization::GpuDirectStorage,
                    EvidencePolicy {
                        minimum_source: SourceClass::HostProbe,
                        max_age: HOUR,
                    },
                )]),
            },
            &LoaderRequest {
                optimizations: BTreeMap::from([(
                    Optimization::GpuDirectStorage,
                    Necessity::Optional,
                )]),
            },
            &evidence.registry,
        )
        .unwrap();
    let permissions = LoaderPermissions::from_plan(&plan);
    assert!(
        !permissions.permits(ReadMethod::GpuDirectStorage, &evidence.registry),
        "GPUDirect Storage reads are permitted on a Metal runtime"
    );
}

/// INT-08: a retry reuses the extents the tenant's interrupted catalog import of the same
/// content already verified, not only whole published objects, because the catalog adapter
/// reports the import's staged verified extents (gap G9, closed). Only the rest is moved
/// and charged.
#[test]
fn gap_a_retry_moves_extents_the_catalog_already_verified() {
    struct StopAt(u32);

    impl ImportControl for StopAt {
        fn proceed(&mut self, at: Checkpoint) -> Proceed {
            match at {
                Checkpoint::Extent { extent } if extent >= self.0 => Proceed::Interrupt,
                _ => Proceed::Continue,
            }
        }
    }

    let mut host = Host::new();
    let owner = execution("exe-vm-a");
    let owner_tenant = tenant("tenant-a");
    let grant = host.launched(
        &owner,
        &owner_tenant,
        sandbox_demand(16 * GIB, 4 * GIB, 22 * GIB),
    );
    let store = Store::open(&host.clock, |config, _| config);
    let weights = weights_bytes("large");
    // The catalog's import of these bytes verified and staged 48 of 64 extents.
    let mut source = MemorySource::new("large", &weights);
    let request = CatalogImport {
        operation: operation("op-import-large"),
        execution: owner.clone(),
        scope: Scope::tenant(owner_tenant.clone()),
        class: ArtifactClass::ModelWeights,
        role: ObjectRole::Original,
        manifest: ImportManifest::describe(&weights, NonZeroU64::new(64).unwrap()),
        trust: TrustClaim::UserSelected,
        depends_on: BTreeSet::new(),
        metadata: ObjectMetadata::new(),
    };
    {
        let mut catalog = store.catalog();
        let ImportStart::Started(ticket) =
            catalog.begin_import(request, source.identity()).unwrap()
        else {
            panic!("a new import");
        };
        let status = catalog
            .drive_import(&ticket, &mut source, &mut StopAt(48))
            .unwrap();
        assert!(matches!(status, ImportStatus::Pending { .. }));
    }
    let gate = TransferGate::new(
        host.key.clone(),
        TransferPorts {
            clock: Arc::clone(&host.clock) as Arc<dyn Clock>,
            clock_session: host.evidence.registry.session(),
            authority: Arc::new(CoordinatorAuthority::new(Arc::clone(&host.coordinator))),
            budget: Arc::new(FakeByteLedger::new(GIB)),
            extents: Arc::new(CatalogExtents::new(
                Arc::clone(&store.catalog),
                ArtifactClass::ModelWeights,
            )),
            progress: Arc::new(FakeProgress::default()),
        },
    );
    let session = gate
        .open(
            &host.seal(download(
                &host,
                "op-large",
                &owner,
                &owner_tenant,
                grant.epoch,
                &[(ContentKey::of(&weights), weights.len() as u64)],
            )),
            &hub_connection(),
        )
        .unwrap();
    assert!(
        session.verified_bytes() >= 48 * 64,
        "the {} bytes the catalog verified are moved again",
        48 * 64
    );
}

/// INT-10: the coordinator's `revoke_and_publish` carries a CORE-04 revocation onto the
/// CORE-06 priority revocation lane, through the coordinator's registered issuer, and
/// into the audit journal, through its one append authority (gap G10, closed).
#[test]
fn gap_coordinator_revocations_never_reach_the_event_plane() {
    let mut host = Host::new();
    let owner = execution("exe-vm-a");
    let grant = host.launched(
        &owner,
        &tenant("tenant-a"),
        sandbox_demand(16 * GIB, 4 * GIB, 22 * GIB),
    );
    // T07: the sandbox allows its system prompt's KV as public in its pool.
    let sandbox_authority = AuthorityBinding::new(
        owner.clone(),
        ExecutionCategory::VmSandbox,
        Some(grant.epoch),
    )
    .unwrap();
    let public = PublicPrefixScope {
        prefix: TokenPrefix::from_token_ids(&[101, 2023, 2003, 1037]),
        trust_scope: TrustScope::named(ExecutionCategory::VmSandbox, "tenant-a"),
    };
    let mut sharing = PublicPrefixSharing::none();
    sharing.allow(public, sandbox_authority.clone());
    let mut revocations = RevokedAuthorities::new();
    assert!(sharing.allows(&public, &revocations));
    let mut hub = event_hub(&host.clock, 1);
    let mut issuer = hub
        .register_revocation_issuer(ProducerId::new("coordinator").unwrap())
        .unwrap();
    let journal_id = JournalId::new("engine").unwrap();
    let audit_owner = ProducerId::new("engine.audit").unwrap();
    let disk = AuditDisk::slow_for(0);
    let (mut journal, mut authority) = AuditJournal::open(
        journal_id.clone(),
        audit_owner.clone(),
        disk.clone(),
        AuditSpoolFile::default(),
        Arc::clone(&host.clock),
        AuditConfig {
            spool_records: 8,
            revocation_reserve_records: 2,
            failure_policy: AuditFailurePolicy::DenyHighImpact,
            guest_observations: EmissionLimit::new(10, SECOND).unwrap(),
            redaction: RedactionPolicy::metadata_only(),
        },
    )
    .unwrap();
    let mut events = RevocationEvents {
        hub: &mut hub,
        issuer: &mut issuer,
        journal: &mut journal,
        authority: &mut authority,
    };
    let published = host
        .coordinator()
        .revoke_and_publish(
            &owner,
            operation("op-revoke"),
            RevocationReason::SecurityEvent,
            &mut events,
        )
        .unwrap();
    assert_eq!(
        host.coordinator().sandbox(&owner).unwrap().state(),
        SandboxState::Revoking,
        "the revocation is in force in the coordinator first"
    );
    // The published notice ends the sandbox's public-prefix allowance at once (T07).
    revocations.record(&published.notice);
    assert!(revocations.is_revoked(&sandbox_authority));
    assert!(!sharing.allows(&public, &revocations));
    let revoked = Revocation {
        execution: owner.clone(),
        epoch: published.notice.current,
        reason: RevocationReason::SecurityEvent,
    };

    // The priority lane holds it ahead of everything else and delivers it once.
    assert_eq!(published.lane, Ok(RevocationAdmission::Queued));
    assert_eq!(
        hub.revocations().pending(),
        1,
        "the revocation reached the priority lane"
    );
    let delivery = hub.drain(16);
    assert_eq!(delivery.revocations.notices.len(), 1);
    assert_eq!(delivery.revocations.notices[0].payload(), &revoked);

    // The audit journal stored it durably, as the first link of its chain.
    let receipt = published.audit.unwrap();
    assert_eq!(receipt.durability, Durability::Durable);
    let records = disk.records();
    verify_chain(&JournalHead::genesis(journal_id, audit_owner), &records).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].sequence(), receipt.sequence);
    assert!(matches!(
        records[0].event().payload(),
        AuditEntry::Revocation { revocation } if *revocation == revoked
    ));
}
