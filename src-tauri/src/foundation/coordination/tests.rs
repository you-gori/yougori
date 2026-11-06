//! Scenario tests on fakes: the launch transaction, child work and leases, INT-02
//! revocation, INT-03 activation changes, INT-04 recovery, composite recovery, restored-VM
//! verification, recovery fallbacks and the staged owner resource return.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::num::NonZeroU32;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::fakes::{FakeLedger, FakeSandbox, FakeState, LedgerCall, PortCall};
use super::ledger_adapter::ledger_resource;
use super::*;
use crate::foundation::catalog::{ArtifactClass, ObjectId, Scope};
use crate::foundation::events::{
    AuditAppendAuthority, AuditConfig, AuditEntry, AuditFailurePolicy, AuditJournal, AuditRecord,
    AuditSpool, AuditStore, EmissionLimit, EventHub, GrantRevocation, HubConfig, JournalId,
    MetricsConfig, Phase, ProducerId, ProducerIncarnation, ProgressConfig, RedactionPolicy,
    Revocation, RevocationAdmission, RevocationConfig, RevocationIssuer, RevocationReason,
    StoreRefusal,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    AdmittedRuntime, ArtifactBypass, ArtifactVerification, AuthorityGrant, Backend, BackendRelease,
    Capability, ClockSession, ConfigurationFingerprint, EvidencePolicy, HostSubject, LoaderGate,
    LoaderPlan, LoaderRequest, Necessity, NetworkGrant, Observation, Optimization, ProbeRegistry,
    Requirement, Residency, RuntimeOffer, RuntimeRequirement, RuntimeSettings, RuntimeSubject,
    Satisfied, SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Clock, ContentKey, Digest, ExecutionCategory, ExecutionId,
    GpuAllocationGeneration, GpuDeviceKey, Incarnation, ManualClock, ModelActivationGeneration,
    MonotonicTime, OperationId, PolicyEpoch, SandboxBootGeneration, TenantId,
};
use crate::foundation::ledger::{
    Admission, Amounts, CapacityDeclaration, CloseReason, CostPurpose, Ledger, LedgerConfig,
    Priority, Provenance, QueueLimits, Requester, ReservationRequest as LedgerRequest,
    ReservationState,
};

const SECOND: Duration = Duration::from_secs(1);
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

fn configuration(name: &str) -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_digest(named("yougori/test/configuration/v1", name))
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

fn runtime(category: ExecutionCategory, instance: &str) -> RuntimeSubject {
    RuntimeSubject {
        category,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance: named("yougori/test/instance/v1", instance),
    }
}

fn route(name: &str) -> NetworkGrant {
    NetworkGrant::NamedRoute {
        route: named("yougori/test/route/v1", name),
    }
}

fn content(name: &str) -> ContentKey {
    ContentKey::of(name.as_bytes())
}

/// The verified identity of an artifact: its content key's digest.
fn artifact(name: &str) -> Digest {
    *content(name).digest()
}

/// The host's one GPU, on the machine the test ledger counts.
fn device() -> GpuDeviceKey {
    GpuDeviceKey {
        machine: named("yougori/test/machine/v1", "host"),
        device: named("yougori/test/device/v1", "gpu0"),
    }
}

fn gpu(memory_bytes: u64) -> GpuDemand {
    GpuDemand {
        device: device(),
        memory_bytes,
    }
}

fn held_gpu() -> BTreeSet<ResourceKind> {
    BTreeSet::from([ResourceKind::GpuMemoryBytes { device: device() }])
}

fn settings_for(grant: AuthorityGrant) -> RuntimeSettings {
    RuntimeSettings {
        execution_category: ExecutionCategory::VmSandbox,
        network: BTreeSet::from([route("model-download")]),
        authority: grant,
        artifact_verification: verified_artifacts(),
        loader: BTreeSet::from([Optimization::IoUring]),
        batch_size: NonZeroU32::new(8).unwrap(),
        residency: Residency::Device,
    }
}

fn volume(name: &str) -> Digest {
    named("yougori/test/volume/v1", name)
}

fn image_profile() -> Digest {
    named("yougori/test/image/v1", "sandbox-image")
}

fn verified_artifacts() -> ArtifactVerification {
    ArtifactVerification::Verified {
        artifacts: BTreeSet::from([artifact("weights")]),
    }
}

fn terms(term_seconds: u64, lifetime_seconds: u64, cancel_seconds: u64) -> LeaseTerms {
    LeaseTerms {
        term: Duration::from_secs(term_seconds),
        max_lifetime: Duration::from_secs(lifetime_seconds),
        cancel_within: Duration::from_secs(cancel_seconds),
    }
}

fn demand() -> BTreeMap<ResourceKind, u64> {
    BTreeMap::from([
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

fn sandbox_key(of: &ExecutionId, boot: u64) -> ReservationKey {
    ReservationKey::derive(
        of,
        &ReservationPurpose::Sandbox {
            boot: SandboxBootGeneration::new(boot),
        },
    )
}

fn gpu_key(of: &ExecutionId, model: ModelId, allocation: u64) -> ReservationKey {
    ReservationKey::derive(
        of,
        &ReservationPurpose::ModelGpu {
            model,
            gpu_allocation: GpuAllocationGeneration::new(allocation),
        },
    )
}

fn vm(of: &ExecutionId, boot: u64, restored: bool) -> VmInstanceId {
    FakeSandbox::vm_for(of, SandboxBootGeneration::new(boot), restored)
}

fn perimeter(of: &ExecutionId, boot: u64) -> PerimeterId {
    FakeSandbox::perimeter_for(of, SandboxBootGeneration::new(boot))
}

fn generation(value: u64) -> ModelActivationGeneration {
    ModelActivationGeneration::new(value)
}

fn golden() -> SnapshotManifest {
    SnapshotManifest {
        snapshot: SnapshotId::new(named("yougori/test/snapshot/v1", "golden")),
        origin: SnapshotOrigin::PreTenantGolden,
        image_profile: image_profile(),
        contents: BTreeSet::new(),
        source_vm: VmInstanceId::new(named("yougori/test/vm/v1", "image-builder")),
        guest_identity: named("yougori/test/guest/v1", "golden"),
    }
}

/// What a clean restore looks like to the host: every required action, fresh guest
/// identity, current policy, no old epoch, only authorized volumes.
fn clean_restore(vm: VmInstanceId, boot: SandboxBootGeneration) -> RestoredVmReport {
    RestoredVmReport {
        vm,
        boot,
        snapshot: golden().snapshot,
        guest_identity: digest("yougori/test/guest/v1", &[&boot.get().to_be_bytes()]),
        actions: RestoreAction::REQUIRED.into_iter().collect(),
        attached_volumes: BTreeSet::from([volume("data")]),
        policy: PolicyEpoch::FIRST,
        image_profile: image_profile(),
        presented_epochs: BTreeSet::new(),
        source: SourceClass::HostProbe,
    }
}

/// Host evidence: each runtime's category, CUDA checkpoint support and io_uring.
struct Evidence {
    registry: ProbeRegistry<TestClock>,
    category: Arc<FakeProbe>,
    checkpoint: Arc<FakeProbe>,
    io_uring: Arc<FakeProbe>,
}

impl Evidence {
    fn new(clock: &TestClock) -> Self {
        let mut registry = ProbeRegistry::new(Arc::clone(clock));
        let category = Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe));
        let checkpoint = Arc::new(FakeProbe::new(
            Capability::CudaCheckpoint,
            SourceClass::HostProbe,
        ));
        let io_uring = Arc::new(FakeProbe::new(Capability::IoUring, SourceClass::HostProbe));
        for probe in [&category, &checkpoint, &io_uring] {
            registry.register(Box::new(Arc::clone(probe))).unwrap();
        }
        Self {
            registry,
            category,
            checkpoint,
            io_uring,
        }
    }

    /// The host observes `runtime` as `category` now.
    fn observe_category(&mut self, runtime: &RuntimeSubject, category: ExecutionCategory) {
        let subject = Subject::Runtime(runtime.clone());
        self.category.respond(
            &subject,
            Observation::supported(
                configuration("launch"),
                HOUR,
                SupportDetail::RuntimeCategory { category },
            ),
        );
        self.registry
            .refresh(Capability::RuntimeCategory, &subject)
            .unwrap();
    }

    /// The one place the tests obtain an admitted runtime: an offer on fresh host
    /// evidence, admitted by its category's requirement.
    fn admit(&mut self, runtime: &RuntimeSubject) -> AdmittedRuntime {
        self.observe_category(runtime, runtime.category);
        let offer = RuntimeOffer::observe(
            &self.registry,
            runtime.clone(),
            HOUR,
            configuration("launch"),
        )
        .unwrap();
        let requirement = if runtime.category.is_vm_sandbox() {
            RuntimeRequirement::VmSandbox
        } else {
            RuntimeRequirement::explicit([runtime.category]).unwrap()
        };
        requirement.admit(&offer).unwrap()
    }

    /// Satisfied host evidence that CUDA checkpoint works on `runtime`.
    fn checkpoint_support(&mut self, runtime: &RuntimeSubject) -> Satisfied {
        let subject = Subject::Runtime(runtime.clone());
        self.checkpoint.respond(
            &subject,
            Observation::supported(configuration("gpu"), HOUR, SupportDetail::Plain),
        );
        self.registry
            .refresh(Capability::CudaCheckpoint, &subject)
            .unwrap();
        self.registry
            .evaluate(&Requirement::host_only(
                Capability::CudaCheckpoint,
                subject,
                HOUR,
                configuration("gpu"),
            ))
            .unwrap()
    }

    /// The gate's plan for `runtime`: io_uring permitted on host evidence and accepted as
    /// optional.
    fn loader_plan(&mut self, gate: &LoaderGate, runtime: &RuntimeSubject) -> LoaderPlan {
        let subject = Subject::Runtime(runtime.clone());
        self.io_uring.respond(
            &subject,
            Observation::supported(configuration("loader"), HOUR, SupportDetail::Plain),
        );
        self.registry
            .refresh(Capability::IoUring, &subject)
            .unwrap();
        let profile = RuntimeProfile {
            runtime: runtime.clone(),
            configuration: configuration("loader"),
            permitted: BTreeMap::from([(
                Optimization::IoUring,
                EvidencePolicy {
                    minimum_source: SourceClass::HostProbe,
                    max_age: HOUR,
                },
            )]),
        };
        let request = LoaderRequest {
            optimizations: BTreeMap::from([(Optimization::IoUring, Necessity::Optional)]),
        };
        gate.plan(&profile, &request, &self.registry).unwrap()
    }
}

use crate::foundation::evidence::RuntimeProfile;

struct World {
    clock: TestClock,
    evidence: Evidence,
    ledger: FakeLedger,
    port: FakeSandbox,
    coordinator: TestCoordinator,
    execution: ExecutionId,
    model: ModelId,
    runtime: RuntimeSubject,
    sandbox_demand: BTreeMap<ResourceKind, u64>,
}

impl World {
    fn new() -> Self {
        Self::with_ledger(host_ledger())
    }

    fn with_ledger(ledger: FakeLedger) -> Self {
        let clock = Arc::new(ManualClock::new(at(100)));
        let evidence = Evidence::new(&clock);
        let coordinator = Coordinator::new(Arc::clone(&clock), session(1), ledger.clone());
        Self {
            clock,
            evidence,
            ledger,
            port: FakeSandbox::new(),
            coordinator,
            execution: execution("exe-sandbox"),
            model: ModelId::new(named("yougori/test/model/v1", "chat-model")),
            runtime: runtime(ExecutionCategory::VmSandbox, "vm-host-1"),
            sandbox_demand: demand(),
        }
    }

    fn advance(&self, seconds: u64) {
        self.clock.advance(Duration::from_secs(seconds));
    }

    fn plan_for(&mut self, of: &ExecutionId) -> LaunchPlan {
        let runtime = self.runtime.clone();
        LaunchPlan {
            execution: of.clone(),
            tenant: tenant(),
            runtime: self.evidence.admit(&runtime),
            demand: self.sandbox_demand.clone(),
            priority: ReservationPriority::Background,
            authority_lifetime: 600 * SECOND,
            readiness_max_age: 5 * SECOND,
            runtime_evidence_max_age: HOUR,
        }
    }

    fn plan(&mut self) -> LaunchPlan {
        let of = self.execution.clone();
        self.plan_for(&of)
    }

    fn launch(&mut self) -> LaunchOutcome {
        let plan = self.plan();
        let outcome = self
            .coordinator
            .launch_with(plan, world_grant(), &mut self.port, &self.evidence.registry)
            .unwrap();
        if matches!(outcome, LaunchOutcome::AuthorityActive { .. }) {
            self.grant_loader();
        }
        outcome
    }

    /// Grants the sandbox's models the loader the gate planned for its runtime: io_uring.
    fn grant_loader(&mut self) {
        let gate = LoaderGate::recorded();
        let runtime = self.runtime.clone();
        let plan = self.evidence.loader_plan(&gate, &runtime);
        self.coordinator
            .grant_loader(&self.execution, &plan)
            .unwrap();
    }

    fn launched(&mut self) -> AuthorityGrant {
        match self.launch() {
            LaunchOutcome::AuthorityActive { grant, .. } => grant,
            other => panic!("{other:?}"),
        }
    }

    fn settings(&self, grant: AuthorityGrant) -> RuntimeSettings {
        settings_for(grant)
    }

    /// Launched, running and serving the model's first activation.
    fn serving(&mut self) -> (AuthorityGrant, GpuAllocationHandle) {
        let grant = self.launched();
        self.coordinator.start_running(&self.execution).unwrap();
        let handle = self
            .coordinator
            .begin_activation(
                &self.execution,
                self.model,
                self.settings(grant),
                gpu(10 * GIB),
            )
            .unwrap();
        self.coordinator
            .complete_activation(&self.execution, self.model, handle.generations.activation)
            .unwrap();
        (grant, handle)
    }

    fn child(&mut self, name: &str, kind: LeaseKind, terms: LeaseTerms) -> Lease {
        self.coordinator
            .start_child_work(&self.execution, operation(name), kind, terms)
            .unwrap()
    }

    fn request(&mut self, name: &str, terms: LeaseTerms) -> Lease {
        self.coordinator
            .admit_request(&self.execution, self.model, operation(name), terms)
            .unwrap()
    }

    fn sandbox(&self) -> &SandboxLifecycle {
        self.coordinator.sandbox(&self.execution).unwrap()
    }

    fn activation(&self, value: u64) -> &Activation {
        self.coordinator
            .model_activations(&self.execution, self.model)
            .unwrap()
            .activation(generation(value))
            .unwrap()
    }

    /// Revokes the sandbox and drives it to stopped; no lease is left to wait for.
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

    fn relaunch(
        &mut self,
        recovery: CompositeRecovery,
        checkpoint: Option<&Satisfied>,
    ) -> RelaunchReport {
        let runtime = self.runtime.clone();
        let plan = RelaunchPlan {
            runtime: self.evidence.admit(&runtime),
            demand: self.sandbox_demand.clone(),
            authority_lifetime: 600 * SECOND,
            readiness_max_age: 5 * SECOND,
            runtime_evidence_max_age: HOUR,
            recovery,
            authorized_volumes: BTreeSet::from([volume("data")]),
        };
        let verified = verified_artifacts();
        let context = RecoveryContext {
            expected_image_profile: image_profile(),
            checkpoint_evidence: checkpoint,
            artifact_verification: &verified,
        };
        let report = self
            .coordinator
            .relaunch(
                &self.execution,
                plan,
                &context,
                &mut self.port,
                &self.evidence.registry,
            )
            .unwrap();
        if matches!(report.outcome, LaunchOutcome::AuthorityActive { .. }) {
            self.grant_loader();
        }
        report
    }
}

#[test]
fn launch_reserves_creates_checks_host_readiness_then_grants_authority() {
    let mut world = World::new();
    let LaunchOutcome::AuthorityActive { grant, generations } = world.launch() else {
        panic!("not launched");
    };
    assert_eq!(generations, SandboxGenerations::FIRST);
    assert_eq!(
        grant,
        AuthorityGrant {
            epoch: AuthorizationEpoch::FIRST,
            clock: session(1),
            expires_at: at(700),
        }
    );
    let created = vm(&world.execution, 1, false);
    assert_eq!(
        world.ledger.calls(),
        [
            LedgerCall::Reserve(sandbox_key(&world.execution, 1)),
            LedgerCall::BeginCreate(sandbox_key(&world.execution, 1)),
        ],
        "reserved, then creation announced before the VM was created"
    );
    assert_eq!(
        world.port.calls,
        [
            PortCall::PreparePerimeter(SandboxBootGeneration::FIRST),
            PortCall::CreateVm(SandboxBootGeneration::FIRST),
            PortCall::ObserveReadiness(created),
        ]
    );
    let steps: Vec<StepKind> = world
        .sandbox()
        .log()
        .iter()
        .map(|record| record.step.kind())
        .collect();
    assert_eq!(
        steps,
        [
            StepKind::ReserveResources,
            StepKind::PreparePerimeter,
            StepKind::CreateVm,
            StepKind::CheckBootEvidence,
            StepKind::ActivateAuthority,
        ]
    );
    for record in world.sandbox().log() {
        assert_eq!(record.presented, SandboxGenerations::FIRST);
        assert_eq!(record.generations, SandboxGenerations::FIRST);
    }
    assert_eq!(
        world
            .sandbox()
            .readiness()
            .map(|readiness| readiness.source),
        Some(SourceClass::HostProbe)
    );
}

#[derive(Clone, Copy, Debug)]
enum Break {
    Perimeter,
    Create,
    NotReady,
    GuestReadiness,
    Grant,
}

#[test]
fn a_failed_launch_undoes_its_steps_in_reverse_order() {
    for case in [
        Break::Perimeter,
        Break::Create,
        Break::NotReady,
        Break::GuestReadiness,
        Break::Grant,
    ] {
        let mut world = World::new();
        let mut plan = world.plan();
        match case {
            Break::Perimeter => {
                world.port.failing.insert(PortOperation::PreparePerimeter);
            }
            Break::Create => {
                world.port.failing.insert(PortOperation::CreateVm);
            }
            Break::NotReady => {
                world.port.readiness.readiness = Readiness::NotReady {
                    detail: "the guest agent never answered".to_owned(),
                };
            }
            Break::GuestReadiness => world.port.readiness.source = SourceClass::GuestReport,
            Break::Grant => plan.authority_lifetime = Duration::ZERO,
        }
        let outcome = world
            .coordinator
            .launch(plan, &mut world.port, &world.evidence.registry)
            .unwrap();
        let LaunchOutcome::RolledBack {
            failure,
            compensations,
        } = outcome
        else {
            panic!("{case:?}: {outcome:?}");
        };
        let (of, key) = (world.execution.clone(), sandbox_key(&world.execution, 1));
        let release = Compensation::ReleaseReservation { reservation: key };
        let teardown = Compensation::TeardownPerimeter {
            perimeter: perimeter(&of, 1),
        };
        let terminate = Compensation::TerminateVm {
            vm: vm(&of, 1, false),
        };
        let expected = match case {
            Break::Perimeter => vec![release],
            Break::Create => vec![teardown, release],
            Break::NotReady | Break::GuestReadiness | Break::Grant => {
                vec![terminate, teardown, release]
            }
        };
        assert_eq!(compensations, expected, "{case:?}");
        match case {
            Break::Perimeter | Break::Create => {
                assert!(matches!(failure, LaunchFailure::Port { .. }))
            }
            Break::NotReady => assert!(matches!(failure, LaunchFailure::NotReady { .. })),
            Break::GuestReadiness => assert_eq!(
                failure,
                LaunchFailure::Transition {
                    refusal: TransitionRefusal::ReadinessNotHostObserved {
                        source: SourceClass::GuestReport
                    }
                }
            ),
            Break::Grant => assert!(matches!(
                failure,
                LaunchFailure::Transition {
                    refusal: TransitionRefusal::AuthorityWouldBeExpired { .. }
                }
            )),
        }
        assert_eq!(world.sandbox().state(), SandboxState::Stopped);
        assert_eq!(world.sandbox().authority(), None);
        assert_eq!(world.sandbox().failure(), Some(&failure));
        assert!(world.ledger.held().is_empty(), "{case:?}");
        assert!(world.port.live.is_empty() && world.port.perimeters.is_empty());
    }
}

#[test]
fn a_capacity_refusal_names_its_limit_and_a_queued_launch_resumes() {
    let mut world = World::with_ledger(FakeLedger::new([
        (ResourceKind::HostMemoryBytes, 8 * GIB),
        (ResourceKind::GpuMemoryBytes { device: device() }, 48 * GIB),
        (ResourceKind::CpuInitializationSlots, 16),
    ]));
    let LaunchOutcome::RolledBack {
        failure: LaunchFailure::Capacity { refusal },
        compensations,
    } = world.launch()
    else {
        panic!("not refused");
    };
    assert!(compensations.is_empty());
    assert_eq!(
        refusal.limiting_resource(),
        Some(ResourceKind::HostMemoryBytes)
    );
    assert_eq!(refusal.retry(), RetryProspect::CannotProgress);
    assert!(
        world.port.calls.is_empty(),
        "nothing is created before the reservation"
    );
    assert_eq!(world.sandbox().state(), SandboxState::Stopped);

    let ledger = FakeLedger::new([
        (ResourceKind::HostMemoryBytes, 20 * GIB),
        (ResourceKind::GpuMemoryBytes { device: device() }, 48 * GIB),
        (ResourceKind::CpuInitializationSlots, 16),
    ])
    .with_queue(2);
    let other = execution("exe-other");
    let busy = ReservationRequest {
        key: sandbox_key(&other, 1),
        tenant: tenant(),
        execution: other,
        purpose: ReservationPurpose::Sandbox {
            boot: SandboxBootGeneration::FIRST,
        },
        priority: ReservationPriority::Background,
        parent: None,
        demand: BTreeMap::from([(ResourceKind::HostMemoryBytes, 10 * GIB)]),
    };
    ledger.insert_unrecorded(busy.clone(), FakeState::InUse);
    let mut world = World::with_ledger(ledger);
    assert_eq!(world.launch(), LaunchOutcome::Queued { position: 1 });
    assert_eq!(world.sandbox().state(), SandboxState::Planned);
    assert!(world.port.calls.is_empty());
    world.ledger.forget(&busy.key);
    assert!(matches!(
        world.launch(),
        LaunchOutcome::AuthorityActive { .. }
    ));
    assert_eq!(
        world.ledger.reserve_calls(),
        2,
        "the same key was asked again"
    );
    let reserved = world
        .sandbox()
        .log()
        .iter()
        .filter(|record| record.step.kind() == StepKind::ReserveResources)
        .count();
    assert_eq!(reserved, 1);
}

#[test]
fn launching_again_and_replaying_transitions_change_nothing() {
    let mut world = World::new();
    let first = world.launch();
    let (calls, steps) = (world.port.calls.len(), world.sandbox().log().len());
    assert_eq!(world.launch(), first);
    assert_eq!(world.port.calls.len(), calls);
    assert_eq!(world.sandbox().log().len(), steps);
    assert_eq!(world.ledger.reserve_calls(), 1);

    let sandbox = world
        .coordinator
        .sandboxes
        .get_mut(&world.execution)
        .unwrap();
    for record in sandbox.log().to_vec() {
        let replay = sandbox
            .apply(record.step.clone(), record.presented, at(999))
            .unwrap();
        assert_eq!(replay, Applied::AlreadyApplied { record });
    }
    assert_eq!(sandbox.log().len(), steps);

    let other = runtime(ExecutionCategory::VmSandbox, "vm-host-2");
    let admitted = world.evidence.admit(&other);
    let plan = LaunchPlan {
        runtime: admitted,
        ..world.plan()
    };
    assert_eq!(
        world
            .coordinator
            .launch(plan, &mut world.port, &world.evidence.registry),
        Err(CoordinationError::RuntimeMismatch {
            execution: world.execution.clone()
        })
    );
}

#[test]
fn a_labelled_runtime_never_gets_the_vm_sandbox_lifecycle() {
    let mut world = World::new();
    for category in [
        ExecutionCategory::SharedKernelGpuRuntime,
        ExecutionCategory::HostProcessModelRuntime,
    ] {
        let labelled = runtime(category, "labelled-runtime");
        let admitted = world.evidence.admit(&labelled);
        let plan = LaunchPlan {
            runtime: admitted,
            ..world.plan()
        };
        assert_eq!(
            world
                .coordinator
                .launch(plan, &mut world.port, &world.evidence.registry),
            Err(CoordinationError::NotAVmSandbox { category })
        );
    }
    assert!(world.coordinator.sandbox(&world.execution).is_none());
    assert!(world.port.calls.is_empty());
    assert!(world.ledger.calls().is_empty());
}

#[test]
fn the_runtime_category_evidence_is_rechecked_before_authority() {
    let mut world = World::new();
    let plan = world.plan();
    world.evidence.registry.invalidate(
        Capability::RuntimeCategory,
        &Subject::Runtime(world.runtime.clone()),
    );
    let outcome = world
        .coordinator
        .launch(plan, &mut world.port, &world.evidence.registry)
        .unwrap();
    let LaunchOutcome::RolledBack {
        failure: LaunchFailure::RuntimeEvidence { .. },
        compensations,
    } = outcome
    else {
        panic!("{outcome:?}");
    };
    assert_eq!(compensations.len(), 3);
    assert_eq!(world.sandbox().authority(), None);

    let mut world = World::new();
    let mut plan = world.plan();
    plan.runtime_evidence_max_age = 10 * SECOND;
    world.advance(11);
    let outcome = world
        .coordinator
        .launch(plan, &mut world.port, &world.evidence.registry)
        .unwrap();
    assert!(
        matches!(
            outcome,
            LaunchOutcome::RolledBack {
                failure: LaunchFailure::RuntimeEvidence { .. },
                ..
            }
        ),
        "evidence older than its limit is not rechecked as fresh: {outcome:?}"
    );

    let mut world = World::new();
    let plan = world.plan();
    let current = world.runtime.clone();
    world
        .evidence
        .observe_category(&current, ExecutionCategory::SharedKernelGpuRuntime);
    let outcome = world
        .coordinator
        .launch(plan, &mut world.port, &world.evidence.registry)
        .unwrap();
    assert!(matches!(
        outcome,
        LaunchOutcome::RolledBack {
            failure: LaunchFailure::RuntimeEvidence { .. },
            ..
        }
    ));
}

#[test]
fn nothing_is_exposed_before_authority_is_active() {
    let mut world = World::new();
    let of = world.execution.clone();
    world.coordinator.sandboxes.insert(
        of.clone(),
        SandboxLifecycle::new(
            of.clone(),
            tenant(),
            world.runtime.clone(),
            ReservationPriority::Background,
        ),
    );
    let created = vm(&of, 1, false);
    let fake_grant = AuthorityGrant {
        epoch: AuthorizationEpoch::FIRST,
        clock: session(1),
        expires_at: at(700),
    };
    let steps = [
        SandboxStep::ReserveResources {
            reservation: sandbox_key(&of, 1),
        },
        SandboxStep::PreparePerimeter {
            perimeter: perimeter(&of, 1),
        },
        SandboxStep::CreateVm {
            vm: created,
            restored_from: None,
        },
        SandboxStep::CheckBootEvidence {
            readiness: ReadinessEvidence {
                vm: created,
                boot: SandboxBootGeneration::FIRST,
                source: SourceClass::HostProbe,
                observed_at: at(100),
            },
        },
    ];
    let mut seen = Vec::new();
    for step in steps.into_iter().map(Some).chain([None]) {
        let state = world.sandbox().state();
        seen.push(state);
        assert_eq!(
            world.coordinator.start_child_work(
                &of,
                operation("op-early"),
                LeaseKind::ChildWork,
                terms(10, 60, 1)
            ),
            Err(LeaseRefusal::NoAuthority { state })
        );
        assert_eq!(
            world.coordinator.begin_activation(
                &of,
                world.model,
                world.settings(fake_grant),
                gpu(GIB)
            ),
            Err(ModelRefusal::Parent {
                refusal: LeaseRefusal::NoAuthority { state }
            })
        );
        if let Some(step) = step {
            world.coordinator.apply_step(&of, step).unwrap();
        }
    }
    assert_eq!(
        seen,
        [
            SandboxState::Planned,
            SandboxState::ResourcesReserved,
            SandboxState::PerimeterReady,
            SandboxState::VmCreated,
            SandboxState::BootEvidenceChecked,
        ]
    );
}

#[test]
fn child_work_runs_under_its_parent_and_carries_every_generation() {
    let mut world = World::new();
    let (grant, handle) = world.serving();
    let work = world.child("op-index", LeaseKind::ChildWork, terms(30, 120, 2));
    assert_eq!(work.parent(), &world.execution);
    assert_eq!(work.sandbox(), SandboxGenerations::FIRST);
    assert_eq!(work.model(), None);
    assert_eq!(work.clock(), session(1));
    assert_eq!(work.expires_at(), at(130));
    assert_eq!(world.coordinator.check_lease(work.id()), Ok(work.clone()));

    let request = world.request("op-chat", terms(30, 120, 1));
    assert_eq!(handle.generations, ModelGenerations::FIRST);
    assert_eq!(
        request.model(),
        Some(ModelBinding {
            model: world.model,
            generations: handle.generations
        })
    );
    let long = world.child("op-long", LeaseKind::Transfer, terms(3600, 7200, 5));
    assert_eq!(
        long.expires_at(),
        grant.expires_at,
        "never past the parent's authority"
    );

    assert_eq!(
        world.coordinator.start_child_work(
            &execution("exe-unknown"),
            operation("op-x"),
            LeaseKind::ChildWork,
            terms(10, 60, 1)
        ),
        Err(LeaseRefusal::UnknownExecution {
            execution: execution("exe-unknown")
        })
    );
    assert_eq!(
        world.coordinator.start_child_work(
            &world.execution,
            operation("op-x"),
            LeaseKind::ModelRequest,
            terms(10, 60, 1)
        ),
        Err(LeaseRefusal::NeedsModelAdmission)
    );
}

#[test]
fn neither_state_machine_advances_the_others_generations() {
    let mut world = World::new();
    let (grant, _) = world.serving();
    let sandbox_before = world.sandbox().generations();

    let second = world
        .coordinator
        .begin_activation(
            &world.execution,
            world.model,
            world.settings(grant),
            gpu(8 * GIB),
        )
        .unwrap();
    world
        .coordinator
        .complete_activation(&world.execution, world.model, second.generations.activation)
        .unwrap();
    world
        .coordinator
        .evict(&world.execution, world.model, second.generations.activation)
        .unwrap();
    assert_eq!(world.sandbox().generations(), sandbox_before);
    assert_eq!(world.sandbox().authority(), Some(grant));

    let models_before = world
        .coordinator
        .model_activations(&world.execution, world.model)
        .unwrap()
        .clone();
    assert_eq!(
        world.coordinator.raise_policy_epoch(&world.execution),
        Ok(PolicyEpoch::new(2))
    );
    assert_eq!(
        world
            .coordinator
            .model_activations(&world.execution, world.model)
            .unwrap(),
        &models_before,
        "a policy change touches no model state"
    );
    assert_eq!(
        world.sandbox().generations(),
        SandboxGenerations {
            policy: PolicyEpoch::new(2),
            ..sandbox_before
        }
    );
    assert_eq!(
        world.sandbox().authority(),
        Some(grant),
        "nor the authorization epoch"
    );

    world.coordinator.revoke(&world.execution).unwrap();
    let revoked = world
        .coordinator
        .model_activations(&world.execution, world.model)
        .unwrap();
    assert_eq!(revoked.next_generations(), models_before.next_generations());
    for (before, after) in models_before
        .activations()
        .iter()
        .zip(revoked.activations())
    {
        assert_eq!(before.generations(), after.generations());
    }
}

#[test]
fn a_policy_change_cancels_leases_bound_to_the_old_policy_only() {
    let mut world = World::new();
    let (grant, _) = world.serving();
    let old = world.child("op-old", LeaseKind::ChildWork, terms(60, 600, 1));
    world
        .coordinator
        .raise_policy_epoch(&world.execution)
        .unwrap();
    assert_eq!(
        world.coordinator.check_lease(old.id()),
        Err(LeaseRefusal::Cancelled {
            cause: CancelCause::PolicyChange
        })
    );
    let fresh = world.child("op-new", LeaseKind::ChildWork, terms(60, 600, 1));
    assert_eq!(fresh.sandbox().policy, PolicyEpoch::new(2));
    assert_eq!(fresh.sandbox().authorization, grant.epoch);
    assert!(world.coordinator.check_lease(fresh.id()).is_ok());
    world.request("op-chat", terms(30, 60, 1));
}

#[test]
fn int02_revocation_denies_new_work_and_cancels_by_declared_bounds() {
    let mut world = World::new();
    let (grant, handle) = world.serving();
    let weights = world.child("op-weights", LeaseKind::Transfer, terms(60, 600, 2));
    let prefetch = world.child("op-prefetch", LeaseKind::Transfer, terms(60, 600, 5));
    let stream = world.request("op-stream", terms(30, 600, 1));
    let issued: Vec<(LeaseId, MonotonicTime)> = [&weights, &prefetch, &stream]
        .iter()
        .map(|lease| (lease.id(), lease.expires_at()))
        .collect();
    world.advance(10);

    let notice = world.coordinator.revoke(&world.execution).unwrap();
    assert_eq!(
        notice,
        RevocationNotice {
            execution: world.execution.clone(),
            revoked: AuthorizationEpoch::FIRST,
            current: AuthorizationEpoch::new(2),
            at: at(110),
        }
    );
    assert_eq!(world.coordinator.revoke(&world.execution), Ok(notice));

    assert_eq!(
        world.coordinator.start_child_work(
            &world.execution,
            operation("op-new"),
            LeaseKind::ChildWork,
            terms(10, 60, 1)
        ),
        Err(LeaseRefusal::NoAuthority {
            state: SandboxState::Revoking
        })
    );
    assert_eq!(
        world.coordinator.admit_request(
            &world.execution,
            world.model,
            operation("op-new"),
            terms(10, 60, 1)
        ),
        Err(ModelRefusal::NoServingActivation { model: world.model })
    );
    assert!(matches!(
        world.coordinator.begin_activation(
            &world.execution,
            world.model,
            world.settings(grant),
            gpu(GIB)
        ),
        Err(ModelRefusal::Parent {
            refusal: LeaseRefusal::NoAuthority { .. }
        })
    ));
    for lease in [&weights, &prefetch, &stream] {
        let cancelled = Err(LeaseRefusal::Cancelled {
            cause: CancelCause::Revocation,
        });
        assert_eq!(world.coordinator.check_lease(lease.id()), cancelled);
        assert_eq!(world.coordinator.renew_lease(lease.id()), cancelled);
    }

    let bounds: BTreeMap<LeaseId, MonotonicTime> = world
        .coordinator
        .revocation(&world.execution)
        .unwrap()
        .cancellations()
        .iter()
        .map(|cancellation| (cancellation.lease, cancellation.bound_at))
        .collect();
    assert_eq!(
        bounds,
        BTreeMap::from([
            (weights.id(), at(112)),
            (prefetch.id(), at(115)),
            (stream.id(), at(111)),
        ])
    );
    assert_eq!(
        world
            .coordinator
            .advance_revocation(&world.execution, &mut world.port),
        Ok(RevocationStatus::WaitingForLeases {
            pending: vec![weights.id(), prefetch.id(), stream.id()],
            next_bound_at: at(111),
        })
    );

    world.advance(1);
    world
        .coordinator
        .acknowledge_cancellation(weights.id())
        .unwrap();
    world.advance(1);
    world
        .coordinator
        .acknowledge_cancellation(prefetch.id())
        .unwrap();
    let gpu = gpu_key(&world.execution, world.model, 1);
    assert_eq!(
        world
            .coordinator
            .advance_revocation(&world.execution, &mut world.port),
        Ok(RevocationStatus::WaitingForGpuReclaim {
            blocking: vec![stream.id()],
            safe_at: at(130),
        })
    );
    assert_eq!(
        world.ledger.state_of(&gpu),
        Some(FakeState::Releasing),
        "memory a holder may still use is not reclaimed, and stays counted"
    );
    assert_eq!(
        world
            .coordinator
            .revocation(&world.execution)
            .unwrap()
            .uncertain(),
        [UncertainOutcome::UnacknowledgedLease {
            lease: stream.id(),
            kind: LeaseKind::ModelRequest,
            bound_at: at(111),
            expires_at: at(130),
        }]
    );

    world.clock.advance_to(at(130));
    let Ok(RevocationStatus::Completed { compensations }) = world
        .coordinator
        .advance_revocation(&world.execution, &mut world.port)
    else {
        panic!("not completed");
    };
    let of = world.execution.clone();
    assert_eq!(
        compensations,
        [
            Compensation::TerminateVm {
                vm: vm(&of, 1, false)
            },
            Compensation::TeardownPerimeter {
                perimeter: perimeter(&of, 1)
            },
            Compensation::ReleaseReservation {
                reservation: sandbox_key(&of, 1)
            },
        ]
    );
    assert_eq!(
        world.coordinator.revocation(&of).unwrap().ledger(),
        Some(ExecutionCancellation {
            released: 0,
            pending: 1,
            dequeued: 0
        }),
        "the ledger cancelled the execution when the revocation began"
    );
    assert_eq!(
        world.ledger.calls().last(),
        Some(&LedgerCall::ConfirmRelease(
            sandbox_key(&of, 1),
            SourceClass::HostProbe
        )),
        "the amounts returned only when the host observed the VM's end"
    );
    assert!(world.ledger.held().is_empty());
    assert_eq!(
        world.activation(1).gpu_reservation_state(),
        GpuReservationState::Released
    );
    assert_eq!(world.sandbox().state(), SandboxState::Stopped);
    assert_eq!(
        world.activation(1).state(),
        ActivationState::Retired {
            reason: RetireReason::Revoked
        }
    );
    assert!(world.coordinator.check_gpu_handle(&handle).is_err());
    let revocation = world.coordinator.revocation(&of).unwrap();
    assert_eq!(
        revocation.milestones(),
        BTreeMap::from([
            (RevocationMilestone::NewAuthorizationsDenied, at(110)),
            (RevocationMilestone::FirstDeniedAuthorization, at(110)),
            (RevocationMilestone::LeasesClosed, at(112)),
            (RevocationMilestone::GpuReclaimed, at(130)),
            (RevocationMilestone::VmStopped, at(130)),
            (RevocationMilestone::CleanupFinished, at(130)),
        ])
    );
    // The first refusal after the decision stands: the new child work, refused at once.
    assert_eq!(
        revocation.first_denied_authorization(),
        Some(&DeniedAuthorization {
            at: at(110),
            denial: Denial::Coordinator {
                request: DeniedRequest::NewLease {
                    kind: LeaseKind::ChildWork
                },
                refusal: LeaseRefusal::NoAuthority {
                    state: SandboxState::Revoking
                },
            },
        })
    );
    for milestone in revocation.milestones().into_keys() {
        assert_eq!(
            revocation.milestone_source(milestone),
            Some(MilestoneSource::Coordinator),
            "{milestone:?} was reached by the coordinator itself"
        );
    }
    for (lease, expires_at) in issued {
        assert_eq!(
            world
                .coordinator
                .lease_record(lease)
                .unwrap()
                .lease()
                .expires_at(),
            expires_at,
            "revocation extends no lease"
        );
    }
    assert_eq!(world.sandbox().authority(), None);
}

#[test]
fn revocation_never_extends_or_renews_authority() {
    let mut world = World::new();
    let (grant, _) = world.serving();
    let service = world.child("op-service", LeaseKind::Service, terms(60, 600, 1));
    world.coordinator.revoke(&world.execution).unwrap();
    let plan = world.plan();
    assert_eq!(
        world
            .coordinator
            .launch(plan, &mut world.port, &world.evidence.registry),
        Err(CoordinationError::NotLaunchable {
            state: SandboxState::Revoking
        }),
        "a revoked sandbox is never granted authority again"
    );
    assert_eq!(
        world
            .coordinator
            .resume_termination(&world.execution, &mut world.port),
        Err(CoordinationError::Transition {
            refusal: TransitionRefusal::InvalidTransition {
                from: SandboxState::Revoking,
                step: StepKind::Terminate
            }
        }),
        "termination never skips the revocation's waits"
    );
    world
        .coordinator
        .acknowledge_cancellation(service.id())
        .unwrap();
    assert!(matches!(
        world
            .coordinator
            .advance_revocation(&world.execution, &mut world.port),
        Ok(RevocationStatus::Completed { .. })
    ));
    assert_eq!(
        world
            .coordinator
            .advance_revocation(&world.execution, &mut world.port),
        Ok(RevocationStatus::Completed {
            compensations: Vec::new()
        })
    );
    assert_eq!(world.sandbox().authority(), None);
    assert_eq!(
        world
            .coordinator
            .lease_record(service.id())
            .unwrap()
            .lease()
            .expires_at(),
        service.expires_at()
    );

    let report = world.relaunch(CompositeRecovery::default(), None);
    let LaunchOutcome::AuthorityActive { grant: fresh, .. } = report.outcome else {
        panic!("not relaunched");
    };
    assert_eq!(fresh.epoch, AuthorizationEpoch::new(3));
    assert!(fresh.epoch > grant.epoch);
    assert_eq!(
        world.coordinator.check_lease(service.id()),
        Err(LeaseRefusal::Cancelled {
            cause: CancelCause::Revocation
        })
    );
}

#[test]
fn int03_requests_keep_their_activation_and_service_authority_is_unchanged() {
    let mut world = World::new();
    let (grant, first) = world.serving();
    let service = world.child("op-service", LeaseKind::Service, terms(60, 300, 1));
    let early = world.request("op-early", terms(30, 120, 1));
    world.advance(5);

    let second = world
        .coordinator
        .begin_activation(
            &world.execution,
            world.model,
            world.settings(grant),
            gpu(10 * GIB),
        )
        .unwrap();
    assert_eq!(
        second.generations,
        ModelGenerations {
            activation: generation(2),
            gpu_allocation: GpuAllocationGeneration::new(2),
        }
    );
    assert_eq!(
        world
            .coordinator
            .complete_activation(&world.execution, world.model, generation(2)),
        Ok(Completion {
            already_active: false,
            draining: Some(first.generations),
        })
    );
    assert_eq!(
        world
            .coordinator
            .check_lease(early.id())
            .unwrap()
            .model()
            .map(|binding| binding.generations),
        Some(first.generations),
        "an admitted request keeps its generation"
    );
    let late = world.request("op-late", terms(30, 120, 1));
    assert_eq!(
        late.model().map(|binding| binding.generations),
        Some(second.generations)
    );
    assert!(world.coordinator.check_gpu_handle(&first).is_ok());

    assert_eq!(
        world.coordinator.check_lease(service.id()),
        Ok(service.clone())
    );
    assert_eq!(world.sandbox().authority(), Some(grant));
    assert_eq!(world.sandbox().generations(), SandboxGenerations::FIRST);
    assert_eq!(
        world
            .coordinator
            .complete_activation(&world.execution, world.model, generation(2)),
        Ok(Completion {
            already_active: true,
            draining: None,
        })
    );

    let first_gpu = gpu_key(&world.execution, world.model, 1);
    assert!(world.ledger.is_held(&first_gpu));
    assert_eq!(
        world.coordinator.finish_request(early.id()),
        Ok(vec![first.generations])
    );
    assert_eq!(
        world.ledger.state_of(&first_gpu),
        Some(FakeState::Releasing)
    );
    assert!(
        matches!(
            world.coordinator.begin_activation(
                &world.execution,
                world.model,
                world.settings(grant),
                gpu(8 * GIB)
            ),
            Err(ModelRefusal::Capacity {
                refusal: CapacityRefusal::ExceedsParentBudget { remaining, .. }
            }) if remaining == 4 * GIB
        ),
        "stopped work frees nothing until its release is observed"
    );
    assert_eq!(
        world.coordinator.confirm_gpu_released(
            &world.execution,
            world.model,
            generation(1),
            SourceClass::RecordedDeclaration
        ),
        Err(ModelRefusal::Capacity {
            refusal: CapacityRefusal::SourceTooWeak {
                source: SourceClass::RecordedDeclaration,
                required: SourceClass::GuestReport,
            }
        })
    );
    assert_eq!(
        world.coordinator.confirm_gpu_released(
            &world.execution,
            world.model,
            generation(2),
            SourceClass::GuestReport
        ),
        Err(ModelRefusal::NothingToRelease {
            activation: generation(2)
        }),
        "a serving activation's memory is never released"
    );
    world
        .coordinator
        .confirm_gpu_released(
            &world.execution,
            world.model,
            generation(1),
            SourceClass::GuestReport,
        )
        .unwrap();
    assert!(!world.ledger.is_held(&first_gpu));
    assert_eq!(
        world.activation(1).state(),
        ActivationState::Retired {
            reason: RetireReason::Replaced
        }
    );
    assert_eq!(
        world.coordinator.check_gpu_handle(&first),
        Err(LeaseRefusal::StaleGpuAllocation {
            bound: GpuAllocationGeneration::FIRST,
            current: Some(GpuAllocationGeneration::new(2)),
        })
    );

    world.advance(50);
    let renewed = world.coordinator.renew_lease(service.id()).unwrap();
    assert_eq!(
        renewed.expires_at(),
        at(215),
        "one term from now, as before the change"
    );
    assert_eq!(renewed.deadline(), service.deadline());
}

#[test]
fn eviction_never_renews_sandbox_authority() {
    let mut world = World::new();
    let (grant, first) = world.serving();
    let service = world.child("op-service", LeaseKind::Service, terms(60, 900, 1));
    let busy = world.request("op-busy", terms(30, 120, 1));
    assert_eq!(
        world
            .coordinator
            .evict(&world.execution, world.model, generation(1)),
        Err(ModelRefusal::RequestsInFlight {
            activation: generation(1),
            leases: vec![busy.id()],
        })
    );
    world.coordinator.finish_request(busy.id()).unwrap();
    assert_eq!(
        world
            .coordinator
            .evict(&world.execution, world.model, generation(1)),
        Ok(first.generations)
    );
    assert_eq!(world.sandbox().authority(), Some(grant));
    assert_eq!(world.sandbox().generations(), SandboxGenerations::FIRST);
    assert_eq!(
        world.coordinator.check_lease(service.id()),
        Ok(service.clone())
    );
    assert!(world.coordinator.check_gpu_handle(&first).is_err());

    let mut beyond = world.settings(grant);
    beyond.authority.expires_at = at(10_000);
    assert!(matches!(
        world
            .coordinator
            .begin_activation(&world.execution, world.model, beyond, gpu(GIB)),
        Err(ModelRefusal::AuthorityExceedsParent { .. })
    ));
    let again = world
        .coordinator
        .begin_activation(
            &world.execution,
            world.model,
            world.settings(grant),
            gpu(GIB),
        )
        .unwrap();
    world
        .coordinator
        .complete_activation(&world.execution, world.model, again.generations.activation)
        .unwrap();
    assert_eq!(again.generations.activation, generation(2));

    world.clock.advance_to(at(690));
    let late = world.request("op-late", terms(60, 120, 1));
    assert_eq!(late.expires_at(), grant.expires_at);
    world.clock.advance_to(grant.expires_at);
    assert_eq!(
        world.coordinator.check_lease(late.id()),
        Err(LeaseRefusal::Expired {
            expired_at: at(700)
        })
    );
    assert!(matches!(
        world.coordinator.begin_activation(
            &world.execution,
            world.model,
            world.settings(grant),
            gpu(GIB)
        ),
        Err(ModelRefusal::Parent {
            refusal: LeaseRefusal::AuthorityExpired { .. }
        })
    ));
}

#[test]
fn a_model_reserves_gpu_memory_within_its_parent_budget() {
    let mut world = World::new();
    let (grant, _) = world.serving();
    let next = world
        .coordinator
        .model_activations(&world.execution, world.model)
        .unwrap()
        .next_generations();
    let parent = sandbox_key(&world.execution, 1);
    assert_eq!(
        world.coordinator.begin_activation(
            &world.execution,
            world.model,
            world.settings(grant),
            gpu(20 * GIB)
        ),
        Err(ModelRefusal::Capacity {
            refusal: CapacityRefusal::ExceedsParentBudget {
                parent,
                resource: ResourceKind::GpuMemoryBytes { device: device() },
                requested: 20 * GIB,
                remaining: 14 * GIB,
                retry: RetryProspect::CanProgress,
            }
        })
    );
    assert!(matches!(
        world.coordinator.begin_activation(
            &world.execution,
            world.model,
            world.settings(grant),
            gpu(30 * GIB)
        ),
        Err(ModelRefusal::Capacity {
            refusal: CapacityRefusal::ExceedsParentBudget {
                retry: RetryProspect::CannotProgress,
                ..
            }
        })
    ));
    assert_eq!(
        world
            .coordinator
            .model_activations(&world.execution, world.model)
            .unwrap()
            .next_generations(),
        next,
        "a refused reservation consumes no generation"
    );
}

#[test]
fn int04_an_engine_crash_reconciles_and_revives_nothing() {
    let mut world = World::new();
    let (grant, first) = world.serving();
    let service = world.child("op-service", LeaseKind::Service, terms(60, 600, 1));
    let request = world.request("op-chat", terms(60, 600, 1));
    let persisted = world.coordinator.persist();
    let json = serde_json::to_string(&persisted).unwrap();
    let restored: PersistedState = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, persisted);

    let (mut coordinator, report) = TestCoordinator::recover(
        restored,
        Arc::clone(&world.clock),
        session(2),
        world.ledger.clone(),
        &mut world.port,
    )
    .unwrap();
    let of = world.execution.clone();
    let kept = vm(&of, 1, false);
    assert_eq!(
        report.sandboxes[&of],
        SandboxRecovery::VmKeptWithoutAuthority {
            vm: kept,
            generations: SandboxGenerations {
                authorization: AuthorizationEpoch::new(2),
                ..SandboxGenerations::FIRST
            },
        }
    );
    assert_eq!(report.leases_not_revived, vec![service.id(), request.id()]);
    assert_eq!(report.retired_activations, vec![first.clone()]);
    let first_gpu = gpu_key(&of, world.model, 1);
    assert_eq!(report.gpu_reservations_counted, vec![first_gpu]);
    assert_eq!(
        report.reservations[&of].confirmed,
        BTreeSet::from([sandbox_key(&of, 1), first_gpu])
    );
    assert!(report.untrusted_vms_terminated.is_empty());

    let sandbox = coordinator.sandbox(&of).unwrap();
    assert_eq!(sandbox.state(), SandboxState::VmCreated);
    assert_eq!(sandbox.authority(), None);
    for lease in [&service, &request] {
        assert_eq!(
            coordinator.check_lease(lease.id()),
            Err(LeaseRefusal::NotRevived)
        );
        assert_eq!(
            coordinator.renew_lease(lease.id()),
            Err(LeaseRefusal::NotRevived)
        );
    }
    assert!(coordinator.check_gpu_handle(&first).is_err());
    assert_eq!(
        coordinator.start_child_work(
            &of,
            operation("op-new"),
            LeaseKind::ChildWork,
            terms(10, 60, 1)
        ),
        Err(LeaseRefusal::NoAuthority {
            state: SandboxState::VmCreated
        })
    );

    let plan = world.plan();
    let LaunchOutcome::AuthorityActive { grant: fresh, .. } = coordinator
        .launch(plan, &mut world.port, &world.evidence.registry)
        .unwrap()
    else {
        panic!("not re-authorized");
    };
    assert_eq!(fresh.epoch, AuthorizationEpoch::new(2));
    assert_eq!(fresh.clock, session(2));
    assert_ne!(
        fresh.epoch, grant.epoch,
        "the pre-crash epoch is never reused"
    );
    assert_eq!(
        world.port.calls.last(),
        Some(&PortCall::ObserveReadiness(kept)),
        "fresh host-observed readiness came first"
    );
    assert!(matches!(
        coordinator.begin_activation(&of, world.model, world.settings(grant), gpu(GIB)),
        Err(ModelRefusal::AuthorityExceedsParent { .. })
    ));
    assert_eq!(
        coordinator
            .begin_activation(&of, world.model, world.settings(fresh), gpu(10 * GIB))
            .map(|_| ()),
        Err(ModelRefusal::LoaderNotGranted {
            optimizations: BTreeSet::from([Optimization::IoUring])
        }),
        "the loader grant is not revived either"
    );
    let gate = LoaderGate::recorded();
    let runtime = world.runtime.clone();
    let plan = world.evidence.loader_plan(&gate, &runtime);
    coordinator.grant_loader(&of, &plan).unwrap();
    let again = coordinator
        .begin_activation(&of, world.model, world.settings(fresh), gpu(10 * GIB))
        .unwrap();
    assert_eq!(
        again.generations,
        ModelGenerations {
            activation: generation(2),
            gpu_allocation: GpuAllocationGeneration::new(2),
        },
        "old GPU allocation generations are never handed out again"
    );
    assert!(world.ledger.is_held(&first_gpu));
    coordinator
        .confirm_gpu_released(&of, world.model, generation(1), SourceClass::GuestReport)
        .unwrap();
    assert!(!world.ledger.is_held(&first_gpu));
    assert_eq!(
        coordinator.start_child_work(
            &of,
            operation("op-new"),
            LeaseKind::ChildWork,
            terms(10, 60, 1)
        ),
        Err(LeaseRefusal::LeaseIdsNotPersisted {
            limit: persisted.next_lease
        })
    );
    let state = coordinator.persist();
    coordinator.confirm_persisted(&state);
    let fresh_lease = coordinator
        .start_child_work(
            &of,
            operation("op-new"),
            LeaseKind::ChildWork,
            terms(10, 60, 1),
        )
        .unwrap();
    assert!(
        fresh_lease.id() > request.id(),
        "lease numbers are never reused"
    );
    assert_eq!(fresh_lease.clock(), session(2));
}

#[test]
fn int04_recovery_cleans_up_lost_vms_partial_starts_and_orphans() {
    let mut world = World::new();
    let (_, lost_handle) = world.serving();
    let of = world.execution.clone();
    let lost = vm(&of, 1, false);
    world.port.live.remove(&lost);

    let partial = execution("exe-partial");
    let partial_key = sandbox_key(&partial, 1);
    world.coordinator.sandboxes.insert(
        partial.clone(),
        SandboxLifecycle::new(
            partial.clone(),
            tenant(),
            world.runtime.clone(),
            ReservationPriority::Background,
        ),
    );
    let partial_request = ReservationRequest {
        key: partial_key,
        tenant: tenant(),
        execution: partial.clone(),
        purpose: ReservationPurpose::Sandbox {
            boot: SandboxBootGeneration::FIRST,
        },
        priority: ReservationPriority::Background,
        parent: None,
        demand: BTreeMap::from([(ResourceKind::HostMemoryBytes, 4 * GIB)]),
    };
    world
        .coordinator
        .capacity_mut()
        .reserve(&partial_request)
        .unwrap();
    world
        .coordinator
        .apply_step(
            &partial,
            SandboxStep::ReserveResources {
                reservation: partial_key,
            },
        )
        .unwrap();
    let boot = BootRequest {
        execution: partial.clone(),
        tenant: tenant(),
        generations: SandboxGenerations::FIRST,
        reservation: partial_key,
    };
    let partial_perimeter = world.port.prepare_perimeter(&boot).unwrap();
    world
        .coordinator
        .apply_step(
            &partial,
            SandboxStep::PreparePerimeter {
                perimeter: partial_perimeter,
            },
        )
        .unwrap();
    world
        .coordinator
        .capacity_mut()
        .begin_create(&partial_key)
        .unwrap();
    let unrecorded = world.port.create_vm(&boot, &partial_perimeter).unwrap();

    let orphan = execution("exe-orphan");
    let orphan_key = sandbox_key(&orphan, 1);
    let orphan_boot = BootRequest {
        execution: orphan.clone(),
        tenant: tenant(),
        generations: SandboxGenerations::FIRST,
        reservation: orphan_key,
    };
    let orphan_vm = world
        .port
        .create_vm(&orphan_boot, &perimeter(&orphan, 1))
        .unwrap();
    world.ledger.insert_unrecorded(
        ReservationRequest {
            key: orphan_key,
            tenant: tenant(),
            execution: orphan.clone(),
            purpose: ReservationPurpose::Sandbox {
                boot: SandboxBootGeneration::FIRST,
            },
            priority: ReservationPriority::Background,
            parent: None,
            demand: BTreeMap::from([(ResourceKind::CpuInitializationSlots, 2)]),
        },
        FakeState::InUse,
    );

    let persisted = world.coordinator.persist();
    let (coordinator, report) = TestCoordinator::recover(
        persisted,
        Arc::clone(&world.clock),
        session(2),
        world.ledger.clone(),
        &mut world.port,
    )
    .unwrap();
    assert_eq!(
        report.sandboxes[&of],
        SandboxRecovery::VmLost {
            compensations: vec![
                Compensation::TerminateVm { vm: lost },
                Compensation::ReleaseReservation {
                    reservation: gpu_key(&of, world.model, 1)
                },
                Compensation::TeardownPerimeter {
                    perimeter: perimeter(&of, 1)
                },
                Compensation::ReleaseReservation {
                    reservation: sandbox_key(&of, 1)
                },
            ],
        }
    );
    assert_eq!(
        report.sandboxes[&partial],
        SandboxRecovery::PartialStartRolledBack {
            compensations: vec![
                Compensation::TeardownPerimeter {
                    perimeter: partial_perimeter
                },
                Compensation::ReleaseReservation {
                    reservation: partial_key
                },
            ],
        }
    );
    assert_eq!(report.untrusted_vms_terminated, vec![unrecorded, orphan_vm]);
    assert_eq!(
        report.reservations[&orphan].released_orphans,
        BTreeSet::from([orphan_key])
    );
    assert_eq!(report.retired_activations, vec![lost_handle]);
    assert!(report.gpu_reservations_counted.is_empty());
    assert!(world.ledger.held().is_empty());
    assert!(world.port.live.is_empty());
    for stopped in [&of, &partial] {
        assert_eq!(
            coordinator.sandbox(stopped).unwrap().state(),
            SandboxState::Stopped
        );
    }
}

#[test]
fn a_restored_vm_gets_fresh_identity_and_never_revives_a_lease() {
    let mut world = World::new();
    let (_, first) = world.serving();
    let work = world.child("op-work", LeaseKind::ChildWork, terms(60, 600, 1));
    let request = world.request("op-chat", terms(60, 600, 1));
    world.stop();
    world.port.calls.clear();
    world.port.restored = Some(Box::new(clean_restore));

    let report = world.relaunch(
        CompositeRecovery {
            vm_snapshot: Some(golden()),
            ..CompositeRecovery::default()
        },
        None,
    );
    assert_eq!(report.decision.path, RecoveryPath::Restore);
    assert_eq!(report.refused_restore, None);
    let LaunchOutcome::AuthorityActive { grant, generations } = report.outcome else {
        panic!("not restored");
    };
    assert_eq!(
        generations,
        SandboxGenerations {
            boot: SandboxBootGeneration::new(2),
            policy: PolicyEpoch::FIRST,
            authorization: AuthorizationEpoch::new(3),
        }
    );
    assert_eq!(grant.epoch, AuthorizationEpoch::new(3));
    let restored = vm(&world.execution, 2, true);
    assert_eq!(
        world.port.calls,
        [
            PortCall::PreparePerimeter(SandboxBootGeneration::new(2)),
            PortCall::RestoreVm(SandboxBootGeneration::new(2)),
            PortCall::InspectRestoredVm(restored),
            PortCall::ObserveReadiness(restored),
        ],
        "the restored VM is verified before its readiness counts"
    );
    assert_eq!(world.sandbox().restored_from(), Some(golden().snapshot));
    assert_eq!(world.sandbox().verified_restore(), Some(restored));

    for lease in [&work, &request] {
        assert!(world.coordinator.check_lease(lease.id()).is_err());
        assert!(world.coordinator.renew_lease(lease.id()).is_err());
    }
    assert!(world.coordinator.check_gpu_handle(&first).is_err());
    world.coordinator.start_running(&world.execution).unwrap();
    let fresh = world.child("op-work-2", LeaseKind::ChildWork, terms(60, 600, 1));
    assert_eq!(fresh.sandbox(), generations);
    let again = world
        .coordinator
        .begin_activation(
            &world.execution,
            world.model,
            world.settings(grant),
            gpu(10 * GIB),
        )
        .unwrap();
    assert_eq!(again.generations.activation, generation(2));
    assert_eq!(world.activation(2).bound_to(), generations);
}

#[test]
fn a_composite_recovery_restores_only_when_every_validator_passes() {
    let mut world = World::new();
    let checkpoint_runtime = world.runtime.clone();
    let support = world.evidence.checkpoint_support(&checkpoint_runtime);
    let target = world.runtime.clone();
    let now = world.coordinator.now();
    let full = CompositeRecovery {
        vm_snapshot: Some(golden()),
        gpu_checkpoint: Some(GpuCheckpointManifest {
            recorded: content("checkpoint"),
            observed: content("checkpoint"),
            runtime: Subject::Runtime(checkpoint_runtime).identity(),
        }),
        model_cache: Some(ModelCacheManifest {
            tenant: tenant(),
            artifacts: BTreeSet::from([content("weights")]),
        }),
    };
    let verified = verified_artifacts();
    let context = RecoveryContext {
        expected_image_profile: image_profile(),
        checkpoint_evidence: Some(&support),
        artifact_verification: &verified,
    };
    let decision = full.evaluate(&context, &tenant(), &target, now);
    assert_eq!(decision.path, RecoveryPath::Restore);
    assert_eq!(full.applicable().len(), 3);
    assert!(decision
        .verdicts
        .values()
        .all(|verdict| *verdict == ValidatorVerdict::Passed));

    let mut dirty = full.clone();
    if let Some(snapshot) = dirty.vm_snapshot.as_mut() {
        snapshot.origin = SnapshotOrigin::TenantWorkload;
    }
    let mut corrupt = full.clone();
    if let Some(checkpoint) = corrupt.gpu_checkpoint.as_mut() {
        checkpoint.observed = content("checkpoint, corrupted");
    }
    let mut foreign = full.clone();
    if let Some(cache) = foreign.model_cache.as_mut() {
        cache.tenant = TenantId::new("tenant-b").unwrap();
    }
    for (broken, failing) in [
        (&dirty, RecoveryComponent::VmSnapshotReset),
        (&corrupt, RecoveryComponent::GpuCheckpointRestore),
        (&foreign, RecoveryComponent::ModelCacheRecovery),
    ] {
        let decision = broken.evaluate(&context, &tenant(), &target, now);
        assert_eq!(decision.path, RecoveryPath::ColdBootReload, "{failing:?}");
        for (component, verdict) in &decision.verdicts {
            assert_eq!(
                *component == failing,
                *verdict != ValidatorVerdict::Passed,
                "{component:?}"
            );
        }
    }
    let without_evidence = RecoveryContext {
        checkpoint_evidence: None,
        ..context
    };
    assert_eq!(
        full.evaluate(&without_evidence, &tenant(), &target, now)
            .path,
        RecoveryPath::ColdBootReload,
        "CUDA checkpoint is capability-gated"
    );
    assert_eq!(
        CompositeRecovery::default()
            .evaluate(&context, &tenant(), &target, now)
            .path,
        RecoveryPath::ColdBootReload
    );

    world.serving();
    world.stop();
    world.port.calls.clear();
    world.port.restored = Some(Box::new(clean_restore));
    let report = world.relaunch(corrupt, Some(&support));
    assert_eq!(report.decision.path, RecoveryPath::ColdBootReload);
    assert!(matches!(
        report.outcome,
        LaunchOutcome::AuthorityActive { .. }
    ));
    assert!(world
        .port
        .calls
        .contains(&PortCall::CreateVm(SandboxBootGeneration::new(2))));
    assert!(
        !world
            .port
            .calls
            .iter()
            .any(|call| matches!(call, PortCall::RestoreVm(_))),
        "a failing GPU checkpoint sends even a clean snapshot to a cold boot"
    );
    assert_eq!(world.sandbox().restored_from(), None);
}

#[test]
fn a_restored_vm_failing_verification_gets_no_authority_and_the_sandbox_cold_boots() {
    let mut world = World::new();
    world.serving();
    world.stop();
    world.port.calls.clear();
    world.port.restored = Some(Box::new(|vm, boot| {
        let mut report = clean_restore(vm, boot);
        report
            .actions
            .remove(&RestoreAction::ApplicationStateRecreated);
        report.actions.insert(RestoreAction::VmGenIdNotified);
        report.presented_epochs.insert(AuthorizationEpoch::FIRST);
        report
    }));
    let report = world.relaunch(
        CompositeRecovery {
            vm_snapshot: Some(golden()),
            ..CompositeRecovery::default()
        },
        None,
    );
    assert_eq!(report.decision.path, RecoveryPath::Restore);
    let Some(LaunchOutcome::RolledBack {
        failure: LaunchFailure::RestoreRefused { refusal },
        compensations,
    }) = report.refused_restore
    else {
        panic!("the restore was not refused");
    };
    assert!(refusal.failures().contains(&RestoreFailure::MissingAction {
        action: RestoreAction::ApplicationStateRecreated,
        substitutes: BTreeSet::from([RestoreAction::VmGenIdNotified]),
    }));
    assert!(refusal
        .failures()
        .contains(&RestoreFailure::OldEpochsPresent {
            epochs: BTreeSet::from([AuthorizationEpoch::FIRST]),
        }));
    let of = world.execution.clone();
    let restored = vm(&of, 2, true);
    assert_eq!(
        compensations,
        [
            Compensation::TerminateVm { vm: restored },
            Compensation::TeardownPerimeter {
                perimeter: perimeter(&of, 2)
            },
            Compensation::ReleaseReservation {
                reservation: sandbox_key(&of, 2)
            },
        ]
    );
    let LaunchOutcome::AuthorityActive { generations, .. } = report.outcome else {
        panic!("no cold boot");
    };
    assert_eq!(generations.boot, SandboxBootGeneration::new(3));
    assert_eq!(
        world.port.calls,
        [
            PortCall::PreparePerimeter(SandboxBootGeneration::new(2)),
            PortCall::RestoreVm(SandboxBootGeneration::new(2)),
            PortCall::InspectRestoredVm(restored),
            PortCall::TerminateVm(restored),
            PortCall::TeardownPerimeter(perimeter(&of, 2)),
            PortCall::PreparePerimeter(SandboxBootGeneration::new(3)),
            PortCall::CreateVm(SandboxBootGeneration::new(3)),
            PortCall::ObserveReadiness(vm(&of, 3, false)),
        ],
        "the refused VM was never checked for readiness, so it never neared authority"
    );
}

#[test]
fn recovery_fallbacks_stay_within_the_authorized_runtime() {
    let mut world = World::new();
    let (old_grant, _) = world.serving();
    world.stop();
    let report = world.relaunch(CompositeRecovery::default(), None);
    let LaunchOutcome::AuthorityActive { grant, .. } = report.outcome else {
        panic!("not relaunched");
    };
    let gate = LoaderGate::recorded();
    let current = world.runtime.clone();
    let other = runtime(ExecutionCategory::VmSandbox, "vm-host-9");
    let other_plan = world.evidence.loader_plan(&gate, &other);
    let plan = world.evidence.loader_plan(&gate, &current);
    assert_eq!(plan.enabled_set(), BTreeSet::from([Optimization::IoUring]));
    let authorized = world.settings(grant);

    let wrong = FallbackContext {
        gate: &gate,
        registry: &world.evidence.registry,
        plan: &other_plan,
    };
    assert!(matches!(
        world.coordinator.reload_model(
            &world.execution,
            world.model,
            &wrong,
            authorized.clone(),
            gpu(GIB)
        ),
        Err(ModelRefusal::PlanForOtherRuntime { .. })
    ));

    let fallback = FallbackContext {
        gate: &gate,
        registry: &world.evidence.registry,
        plan: &plan,
    };
    let held = world.ledger.held();
    let mut forbidden = Vec::new();
    let mut labelled = authorized.clone();
    labelled.execution_category = ExecutionCategory::SharedKernelGpuRuntime;
    forbidden.push(labelled);
    let mut reopened = authorized.clone();
    reopened.network.insert(route("package-index"));
    forbidden.push(reopened);
    let mut renewed = authorized.clone();
    renewed.authority.expires_at = at(10_000);
    forbidden.push(renewed);
    let mut unverified = authorized.clone();
    unverified.artifact_verification = ArtifactVerification::Bypassed;
    forbidden.push(unverified);
    let mut revived = authorized.clone();
    revived.authority = old_grant;
    forbidden.push(revived);
    let mut ungated = authorized.clone();
    ungated.loader.insert(Optimization::GpuDirectStorage);
    forbidden.push(ungated);
    for proposed in forbidden {
        let refused = world.coordinator.reload_model(
            &world.execution,
            world.model,
            &fallback,
            proposed,
            gpu(8 * GIB),
        );
        assert!(
            matches!(refused, Err(ModelRefusal::Fallback { .. })),
            "{refused:?}"
        );
    }
    assert_eq!(
        world.ledger.held(),
        held,
        "a refused fallback reserves nothing"
    );

    let proposed = RuntimeSettings {
        loader: BTreeSet::new(),
        batch_size: NonZeroU32::new(4).unwrap(),
        residency: Residency::HostPinned,
        ..authorized
    };
    let handle = world
        .coordinator
        .reload_model(
            &world.execution,
            world.model,
            &fallback,
            proposed.clone(),
            gpu(8 * GIB),
        )
        .unwrap();
    assert_eq!(handle.generations.activation, generation(2));
    assert_eq!(world.activation(2).settings(), &proposed);
}

#[test]
fn a_stalled_rollback_never_reports_capacity_in_use_as_free() {
    let mut world = World::new();
    world.port.readiness.readiness = Readiness::NotReady {
        detail: "kernel panic".to_owned(),
    };
    world.port.failing.insert(PortOperation::TerminateVm);
    let LaunchOutcome::RollbackStalled { failure, stall } = world.launch() else {
        panic!("not stalled");
    };
    assert!(matches!(failure, LaunchFailure::NotReady { .. }));
    assert!(stall.completed.is_empty());
    assert!(matches!(stall.cause, StallCause::Port { .. }));
    assert_eq!(world.sandbox().state(), SandboxState::Terminating);
    let key = sandbox_key(&world.execution, 1);
    assert!(
        world.ledger.is_held(&key),
        "the VM may still run, so its reservation stays held"
    );
    world.port.failing.clear();
    let of = world.execution.clone();
    assert_eq!(
        world.coordinator.resume_termination(&of, &mut world.port),
        Ok(vec![
            Compensation::TerminateVm {
                vm: vm(&of, 1, false)
            },
            Compensation::TeardownPerimeter {
                perimeter: perimeter(&of, 1)
            },
            Compensation::ReleaseReservation { reservation: key },
        ])
    );
    assert!(world.ledger.held().is_empty());
}

#[test]
fn a_shared_gpu_returns_in_stages_with_three_separate_measurements() {
    let mut world = World::new();
    let (grant, first) = world.serving();
    let drains = world.request("op-drains", terms(60, 600, 1));
    let cancelled = world.request("op-cancelled", terms(60, 600, 3));
    let of = world.execution.clone();
    assert_eq!(
        world.coordinator.begin_resource_return(
            &of,
            GpuAssignment::Shared,
            BTreeSet::from([CancellationBoundary::BetweenBatches]),
            held_gpu()
        ),
        Ok(ReturnStage::NewWorkDenied)
    );
    let other = execution("exe-background");
    let background = world.plan_for(&other);
    assert!(
        matches!(
            world
                .coordinator
                .launch(background, &mut world.port, &world.evidence.registry),
            Ok(LaunchOutcome::RolledBack {
                failure: LaunchFailure::Capacity {
                    refusal: CapacityRefusal::OwnerReturnHold { .. }
                },
                ..
            })
        ),
        "the ledger hold denies new background work on the held GPU host-wide"
    );
    let interactive = execution("exe-foreground");
    let foreground = LaunchPlan {
        priority: ReservationPriority::Foreground,
        ..world.plan_for(&interactive)
    };
    assert!(matches!(
        world
            .coordinator
            .launch(foreground, &mut world.port, &world.evidence.registry),
        Ok(LaunchOutcome::AuthorityActive { .. })
    ));
    let denied = LeaseRefusal::NewWorkDenied {
        execution: of.clone(),
    };
    assert_eq!(
        world.coordinator.start_child_work(
            &of,
            operation("op-new"),
            LeaseKind::ChildWork,
            terms(10, 60, 1)
        ),
        Err(denied.clone())
    );
    assert_eq!(
        world
            .coordinator
            .admit_request(&of, world.model, operation("op-new"), terms(10, 60, 1)),
        Err(ModelRefusal::Parent {
            refusal: denied.clone()
        })
    );
    assert_eq!(
        world
            .coordinator
            .begin_activation(&of, world.model, world.settings(grant), gpu(GIB)),
        Err(ModelRefusal::Parent { refusal: denied })
    );
    assert_eq!(
        world.coordinator.begin_resource_return(
            &of,
            GpuAssignment::Shared,
            BTreeSet::new(),
            held_gpu()
        ),
        Err(ReturnRefusal::AlreadyInProgress)
    );
    assert_eq!(
        world
            .coordinator
            .release_resource(&of, ReleaseMechanism::RuntimeFree),
        Err(ReturnRefusal::OutOfOrder {
            stage: ReturnStage::NewWorkDenied,
            step: ReturnStep::Release,
        })
    );

    assert_eq!(
        world.coordinator.cancel_at_boundary(
            &of,
            cancelled.id(),
            CancellationBoundary::BetweenDecodeSteps
        ),
        Err(ReturnRefusal::UnsupportedBoundary {
            boundary: CancellationBoundary::BetweenDecodeSteps,
            supported: BTreeSet::from([CancellationBoundary::BetweenBatches]),
        })
    );
    assert_eq!(
        world.coordinator.cancel_at_boundary(
            &of,
            cancelled.id(),
            CancellationBoundary::BetweenBatches
        ),
        Ok(at(103))
    );
    world.advance(1);
    world.coordinator.finish_request(drains.id()).unwrap();
    assert_eq!(
        world.coordinator.poll_resource_return(&of),
        Ok(ReturnStage::NewWorkDenied),
        "the cancelled request has not stopped yet"
    );
    world.advance(1);
    world
        .coordinator
        .acknowledge_cancellation(cancelled.id())
        .unwrap();
    assert_eq!(
        world.coordinator.poll_resource_return(&of),
        Ok(ReturnStage::WorkStopped)
    );

    assert_eq!(
        world
            .coordinator
            .release_resource(&of, ReleaseMechanism::ProcessPause),
        Err(ReturnRefusal::PauseIsNotRelease)
    );
    let reset = DeviceReset {
        device: device(),
        source: SourceClass::HostProbe,
    };
    assert!(matches!(
        world
            .coordinator
            .release_resource(&of, ReleaseMechanism::TerminateResetReassign { reset }),
        Err(ReturnRefusal::MechanismNotForAssignment { .. })
    ));
    world.advance(1);
    let impact = ForegroundImpact {
        baseline_latency: Duration::from_millis(16),
        observed_latency: Duration::from_millis(21),
    };
    world
        .coordinator
        .record_foreground_impact(&of, impact)
        .unwrap();
    world.advance(1);
    let first_gpu = gpu_key(&of, world.model, 1);
    assert!(world.ledger.is_held(&first_gpu));
    let measured = world
        .coordinator
        .release_resource(&of, ReleaseMechanism::RuntimeFree)
        .unwrap();
    assert_eq!(
        measured,
        ReturnMeasurements {
            request_stop: Some(2 * SECOND),
            vram_release: Some(4 * SECOND),
            foreground_impact: Some(impact),
            foreground_measured_after: Some(3 * SECOND),
        }
    );
    assert!(!world.ledger.is_held(&first_gpu));
    assert_eq!(
        world.activation(1).state(),
        ActivationState::Retired {
            reason: RetireReason::ReturnedToOwner
        }
    );
    assert!(world.coordinator.check_gpu_handle(&first).is_err());
    let json = serde_json::to_value(measured).unwrap();
    let fields: BTreeSet<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        fields,
        BTreeSet::from([
            "foreground_impact",
            "foreground_measured_after",
            "request_stop",
            "vram_release",
        ]),
        "only measurements, never a promised time"
    );

    let report = world.coordinator.finish_resource_return(&of).unwrap();
    assert!(matches!(
        world.ledger.calls().last(),
        Some(LedgerCall::EndHold(_))
    ));
    assert_eq!(report.cancelled, vec![cancelled.id()]);
    assert_eq!(report.mechanism, ReleaseMechanism::RuntimeFree);
    assert!(world.coordinator.resource_return(&of).is_none());
    world.child("op-after", LeaseKind::ChildWork, terms(10, 60, 1));
}

#[test]
fn an_exclusive_gpu_returns_only_through_termination_and_a_host_observed_reset() {
    let mut world = World::new();
    world.serving();
    let of = world.execution.clone();
    assert_eq!(
        world.coordinator.begin_resource_return(
            &of,
            GpuAssignment::ExclusiveToVm,
            BTreeSet::from([CancellationBoundary::BetweenRequests]),
            held_gpu()
        ),
        Ok(ReturnStage::WorkStopped)
    );
    for mechanism in [ReleaseMechanism::RuntimeFree, ReleaseMechanism::ProcessExit] {
        assert_eq!(
            world.coordinator.release_resource(&of, mechanism),
            Err(ReturnRefusal::MechanismNotForAssignment {
                assignment: GpuAssignment::ExclusiveToVm,
                mechanism,
            })
        );
    }
    assert_eq!(
        world
            .coordinator
            .release_resource(&of, ReleaseMechanism::ProcessPause),
        Err(ReturnRefusal::PauseIsNotRelease)
    );
    let host_reset = ReleaseMechanism::TerminateResetReassign {
        reset: DeviceReset {
            device: device(),
            source: SourceClass::HostProbe,
        },
    };
    assert_eq!(
        world.coordinator.release_resource(&of, host_reset),
        Err(ReturnRefusal::VmNotTerminated {
            state: SandboxState::Running
        })
    );
    world.stop();
    let guest_reset = ReleaseMechanism::TerminateResetReassign {
        reset: DeviceReset {
            device: device(),
            source: SourceClass::GuestReport,
        },
    };
    assert_eq!(
        world.coordinator.release_resource(&of, guest_reset),
        Err(ReturnRefusal::ResetNotHostObserved {
            source: SourceClass::GuestReport
        })
    );
    assert!(world.coordinator.release_resource(&of, host_reset).is_ok());
    assert_eq!(
        world
            .coordinator
            .finish_resource_return(&of)
            .map(|report| report.mechanism),
        Ok(host_reset)
    );
}

#[test]
fn a_live_request_moves_only_to_an_authorized_matching_worker_in_time() {
    let mut world = World::new();
    world.serving();
    let request = world.request("op-chat", terms(60, 600, 1));
    let of = world.execution.clone();
    world
        .coordinator
        .begin_resource_return(
            &of,
            GpuAssignment::Shared,
            BTreeSet::from([CancellationBoundary::BetweenRequests]),
            held_gpu(),
        )
        .unwrap();
    let representation = SessionRepresentation {
        model: world.model,
        format: named("yougori/test/format/v1", "kv-v1"),
    };
    let unauthorized = SessionMove {
        source: representation,
        target_authorized: None,
        transfer_time_needed: SECOND,
        transfer_time_available: 2 * SECOND,
    };
    assert_eq!(
        world
            .coordinator
            .move_session(&of, request.id(), &unauthorized),
        Err(ReturnRefusal::SessionMove {
            refusals: vec![SessionMoveRefusal::TargetNotAuthorized]
        })
    );
    let allowed = SessionMove {
        target_authorized: Some(representation),
        ..unauthorized
    };
    assert_eq!(
        world.coordinator.move_session(&of, request.id(), &allowed),
        Ok(ReturnStage::WorkStopped)
    );
    assert_eq!(
        world
            .coordinator
            .resource_return(&of)
            .map(|operation| operation.moved().to_vec()),
        Some(vec![request.id()])
    );
}

/// The CORE-03 ledger of the host the tests run on: its RAM, the one GPU and CPU
/// initialization slots, all observed by the host, with the tenant budgeted for all of it.
fn host_real_ledger(clock: &TestClock) -> Ledger<TestClock> {
    let host = HostSubject {
        machine: named("yougori/test/machine/v1", "host"),
    };
    let config = LedgerConfig {
        queue: QueueLimits {
            max_entries: 8,
            max_entries_per_tenant: 4,
            max_wait: 60 * SECOND,
        },
        grant_ttl: 300 * SECOND,
        unmanaged_usage_max_age: HOUR,
    };
    let mut ledger = Ledger::new(Arc::clone(clock), host, config);
    for (resource, total) in [
        (ResourceKind::HostMemoryBytes, 64 * GIB),
        (ResourceKind::GpuMemoryBytes { device: device() }, 48 * GIB),
        (ResourceKind::CpuInitializationSlots, 16),
    ] {
        let key = ledger_resource(resource);
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

fn real_ledger(clock: &TestClock) -> LedgerCapacity<TestClock> {
    LedgerCapacity::new(host_real_ledger(clock))
}

struct RealWorld {
    clock: TestClock,
    evidence: Evidence,
    port: FakeSandbox,
    coordinator: Coordinator<TestClock, LedgerCapacity<TestClock>>,
    runtime: RuntimeSubject,
}

impl RealWorld {
    fn new() -> Self {
        let clock = Arc::new(ManualClock::new(at(100)));
        let evidence = Evidence::new(&clock);
        let coordinator = Coordinator::new(Arc::clone(&clock), session(1), real_ledger(&clock));
        Self {
            clock,
            evidence,
            port: FakeSandbox::new(),
            coordinator,
            runtime: runtime(ExecutionCategory::VmSandbox, "vm-host-1"),
        }
    }

    fn plan(&mut self, of: &ExecutionId, priority: ReservationPriority) -> LaunchPlan {
        let runtime = self.runtime.clone();
        LaunchPlan {
            execution: of.clone(),
            tenant: tenant(),
            runtime: self.evidence.admit(&runtime),
            demand: demand(),
            priority,
            authority_lifetime: 600 * SECOND,
            readiness_max_age: 5 * SECOND,
            runtime_evidence_max_age: HOUR,
        }
    }

    fn launch(&mut self, of: &ExecutionId, priority: ReservationPriority) -> LaunchOutcome {
        let plan = self.plan(of, priority);
        let outcome = self
            .coordinator
            .launch_with(plan, world_grant(), &mut self.port, &self.evidence.registry)
            .unwrap();
        if matches!(outcome, LaunchOutcome::AuthorityActive { .. }) {
            let gate = LoaderGate::recorded();
            let runtime = self.runtime.clone();
            let plan = self.evidence.loader_plan(&gate, &runtime);
            self.coordinator.grant_loader(of, &plan).unwrap();
        }
        outcome
    }

    fn available(&self, resource: ResourceKind) -> Option<u64> {
        self.coordinator
            .capacity()
            .ledger()
            .available(ledger_resource(resource))
    }
}

#[test]
fn the_launch_transaction_runs_through_the_real_ledger() {
    let mut world = RealWorld::new();
    let of = execution("exe-real");
    let model = ModelId::new(named("yougori/test/model/v1", "chat-model"));
    let LaunchOutcome::AuthorityActive { grant, .. } =
        world.launch(&of, ReservationPriority::Background)
    else {
        panic!("not launched");
    };
    let key = sandbox_key(&of, 1);
    let record = world.coordinator.capacity().record(&key).unwrap().clone();
    assert_eq!(
        record.state(),
        ReservationState::InUse,
        "created after it was reserved"
    );
    assert_eq!(record.provenance().requester, Requester::Coordination);
    assert_eq!(record.provenance().execution, of);
    assert_eq!(record.parent(), None);
    let ram = ResourceKind::HostMemoryBytes;
    assert_eq!(world.available(ram), Some(48 * GIB));

    world.coordinator.start_running(&of).unwrap();
    let handle = world
        .coordinator
        .begin_activation(&of, model, settings_for(grant), gpu(10 * GIB))
        .unwrap();
    let child_key = gpu_key(&of, model, 1);
    let child = world.coordinator.capacity().record(&child_key).unwrap();
    assert_eq!(
        child.parent(),
        Some(record.id()),
        "carved from the sandbox reservation"
    );
    assert_eq!(child.state(), ReservationState::InUse);
    assert!(matches!(
        world
            .coordinator
            .begin_activation(&of, model, settings_for(grant), gpu(20 * GIB)),
        Err(ModelRefusal::Capacity {
            refusal: CapacityRefusal::ExceedsParentBudget {
                parent,
                remaining,
                retry: RetryProspect::CanProgress,
                ..
            }
        }) if parent == key && remaining == 14 * GIB
    ));

    world.coordinator.revoke(&of).unwrap();
    assert_eq!(
        world.coordinator.revocation(&of).unwrap().ledger(),
        Some(ExecutionCancellation {
            released: 0,
            pending: 1,
            dequeued: 0
        })
    );
    assert_eq!(
        world
            .coordinator
            .capacity()
            .record(&key)
            .map(|record| record.state()),
        Some(ReservationState::Releasing)
    );
    assert_eq!(
        world.available(ram),
        Some(48 * GIB),
        "stopping work frees nothing before the host observes it"
    );
    let status = world
        .coordinator
        .advance_revocation(&of, &mut world.port)
        .unwrap();
    assert!(
        matches!(status, RevocationStatus::Completed { .. }),
        "{status:?}"
    );
    assert!(world.coordinator.capacity().record(&key).is_none());
    assert!(world.coordinator.capacity().record(&child_key).is_none());
    assert_eq!(world.available(ram), Some(64 * GIB));
    let reasons: BTreeSet<String> = world
        .coordinator
        .capacity()
        .ledger()
        .closed_records()
        .iter()
        .map(|record| format!("{:?}", record.close_reason()))
        .collect();
    assert!(reasons.contains(&format!(
        "{:?}",
        Some(CloseReason::ReleaseObserved {
            source: SourceClass::HostProbe
        })
    )));
    assert!(world.coordinator.check_gpu_handle(&handle).is_err());
}

#[test]
fn a_failed_launch_rolls_back_through_the_real_ledger() {
    let mut world = RealWorld::new();
    let of = execution("exe-real");
    world.port.readiness.readiness = Readiness::NotReady {
        detail: "no answer from the guest agent".to_owned(),
    };
    let LaunchOutcome::RolledBack {
        failure: LaunchFailure::NotReady { .. },
        compensations,
    } = world.launch(&of, ReservationPriority::Background)
    else {
        panic!("not rolled back");
    };
    assert_eq!(
        compensations,
        [
            Compensation::TerminateVm {
                vm: vm(&of, 1, false)
            },
            Compensation::TeardownPerimeter {
                perimeter: perimeter(&of, 1)
            },
            Compensation::ReleaseReservation {
                reservation: sandbox_key(&of, 1)
            },
        ]
    );
    assert_eq!(
        world
            .coordinator
            .capacity()
            .ledger()
            .open_reservations()
            .count(),
        0
    );
    assert_eq!(
        world.available(ResourceKind::HostMemoryBytes),
        Some(64 * GIB)
    );
    let closed = world.coordinator.capacity().ledger().closed_records();
    assert_eq!(
        closed.last().and_then(|record| record.close_reason()),
        Some(CloseReason::ReleaseObserved {
            source: SourceClass::HostProbe
        }),
        "its VM was created, so it closed on the host's observation"
    );

    let mut world = RealWorld::new();
    let mut plan = world.plan(&of, ReservationPriority::Background);
    plan.demand.insert(ResourceKind::HostMemoryBytes, 100 * GIB);
    let outcome = world
        .coordinator
        .launch(plan, &mut world.port, &world.evidence.registry)
        .unwrap();
    assert!(
        matches!(
            &outcome,
            LaunchOutcome::RolledBack {
                failure: LaunchFailure::Capacity {
                    refusal: CapacityRefusal::Insufficient {
                        resource: ResourceKind::HostMemoryBytes,
                        retry: RetryProspect::CannotProgress,
                        ..
                    }
                },
                ..
            }
        ),
        "{outcome:?}"
    );
    assert!(
        world.port.calls.is_empty(),
        "nothing is created before the reservation"
    );

    let mut world = RealWorld::new();
    world
        .coordinator
        .capacity_mut()
        .ledger_mut()
        .set_tenant_budget(
            tenant(),
            ledger_resource(ResourceKind::HostMemoryBytes),
            8 * GIB,
        )
        .unwrap();
    let outcome = world.launch(&of, ReservationPriority::Background);
    assert!(
        matches!(
            &outcome,
            LaunchOutcome::RolledBack {
                failure: LaunchFailure::Capacity {
                    refusal: CapacityRefusal::Insufficient {
                        limit: CapacityLimit::TenantBudget,
                        ..
                    }
                },
                ..
            }
        ),
        "{outcome:?}"
    );
}

#[test]
fn an_owner_return_hold_in_the_real_ledger_denies_only_new_background_work() {
    let mut world = RealWorld::new();
    let owner = execution("exe-background");
    assert!(matches!(
        world.launch(&owner, ReservationPriority::Background),
        LaunchOutcome::AuthorityActive { .. }
    ));
    world
        .coordinator
        .begin_resource_return(
            &owner,
            GpuAssignment::Shared,
            BTreeSet::from([CancellationBoundary::BetweenRequests]),
            held_gpu(),
        )
        .unwrap();
    assert_eq!(
        world.coordinator.capacity().ledger().active_holds().len(),
        1
    );
    let later = execution("exe-later");
    let outcome = world.launch(&later, ReservationPriority::Background);
    assert!(
        matches!(
            &outcome,
            LaunchOutcome::RolledBack {
                failure: LaunchFailure::Capacity {
                    refusal: CapacityRefusal::OwnerReturnHold {
                        resource: ResourceKind::GpuMemoryBytes { .. }
                    }
                },
                ..
            }
        ),
        "{outcome:?}"
    );
    let foreground = execution("exe-foreground");
    assert!(matches!(
        world.launch(&foreground, ReservationPriority::Foreground),
        LaunchOutcome::AuthorityActive { .. }
    ));
    world
        .coordinator
        .release_resource(&owner, ReleaseMechanism::RuntimeFree)
        .unwrap();
    world.coordinator.finish_resource_return(&owner).unwrap();
    assert!(world
        .coordinator
        .capacity()
        .ledger()
        .active_holds()
        .is_empty());
    let after = execution("exe-after");
    let outcome = world.launch(&after, ReservationPriority::Background);
    assert!(
        matches!(
            &outcome,
            LaunchOutcome::RolledBack {
                failure: LaunchFailure::Capacity {
                    refusal: CapacityRefusal::Insufficient {
                        resource: ResourceKind::GpuMemoryBytes { .. },
                        limit: CapacityLimit::Host,
                        retry: RetryProspect::CanProgress,
                        ..
                    }
                },
                ..
            }
        ),
        "with the hold ended, only the GPU's real use limits background work: {outcome:?}"
    );
}

#[test]
fn recovery_reconciles_the_real_ledger_and_finds_its_reservations_by_key() {
    let mut world = RealWorld::new();
    let of = execution("exe-real");
    let LaunchOutcome::AuthorityActive { .. } = world.launch(&of, ReservationPriority::Background)
    else {
        panic!("not launched");
    };
    let persisted = world.coordinator.persist();
    let capacity = std::mem::replace(
        &mut world.coordinator,
        Coordinator::new(
            Arc::clone(&world.clock),
            session(9),
            real_ledger(&world.clock),
        ),
    );
    let (ledger, port) = (capacity_into(capacity), &mut world.port);
    let (recovered, report) = Coordinator::recover(
        persisted,
        Arc::clone(&world.clock),
        session(2),
        ledger,
        port,
    )
    .unwrap();
    assert_eq!(
        report.reservations[&of].confirmed,
        BTreeSet::from([sandbox_key(&of, 1)]),
        "the adapter found the reservation in the ledger's own records"
    );
    assert!(matches!(
        report.sandboxes[&of],
        SandboxRecovery::VmKeptWithoutAuthority { .. }
    ));
    assert_eq!(
        recovered
            .capacity()
            .record(&sandbox_key(&of, 1))
            .map(|record| record.state()),
        Some(ReservationState::InUse)
    );
}

/// The ledger a coordinator held, handed to the coordinator that recovers.
fn capacity_into(
    coordinator: Coordinator<TestClock, LedgerCapacity<TestClock>>,
) -> LedgerCapacity<TestClock> {
    coordinator.into_capacity()
}

#[test]
fn the_ledger_adapter_keeps_the_port_semantics() {
    let clock = Arc::new(ManualClock::new(at(100)));
    let mut port = real_ledger(&clock).with_queue_wait(30 * SECOND);
    let request = |of: &ExecutionId, boot: u64, host_memory_bytes: u64| ReservationRequest {
        key: sandbox_key(of, boot),
        tenant: tenant(),
        execution: of.clone(),
        purpose: ReservationPurpose::Sandbox {
            boot: SandboxBootGeneration::new(boot),
        },
        priority: ReservationPriority::Background,
        parent: None,
        demand: BTreeMap::from([(ResourceKind::HostMemoryBytes, host_memory_bytes)]),
    };

    let first = request(&execution("exe-a"), 1, 40 * GIB);
    assert_eq!(port.reserve(&first), Ok(ReserveOutcome::Granted));
    assert_eq!(
        port.reserve(&first),
        Ok(ReserveOutcome::Granted),
        "the same key again"
    );
    assert_eq!(port.ledger().open_reservations().count(), 1);
    assert_eq!(
        port.record(&first.key)
            .unwrap()
            .provenance()
            .operation
            .as_str(),
        format!("rsv-{}", first.key.digest().to_hex()),
        "the key is the reservation's operation identity in the ledger"
    );
    let mut changed = first.clone();
    changed
        .demand
        .insert(ResourceKind::HostMemoryBytes, 41 * GIB);
    assert_eq!(
        port.reserve(&changed),
        Err(CapacityRefusal::KeyConflict { key: first.key })
    );

    let second = request(&execution("exe-b"), 1, 40 * GIB);
    assert_eq!(
        port.reserve(&second),
        Ok(ReserveOutcome::Queued { position: 1 })
    );
    assert_eq!(
        port.reserve(&second),
        Ok(ReserveOutcome::Queued { position: 1 })
    );
    assert_eq!(
        port.release(&first.key),
        Ok(ReleaseOutcome::Released),
        "never created, so returned at once"
    );
    assert_eq!(
        port.reserve(&second),
        Ok(ReserveOutcome::Granted),
        "the queue granted it"
    );

    port.begin_create(&second.key).unwrap();
    assert_eq!(port.release(&second.key), Ok(ReleaseOutcome::Pending));
    assert_eq!(
        port.reserve(&second),
        Err(CapacityRefusal::KeyConflict { key: second.key }),
        "a releasing reservation is never granted again"
    );
    assert_eq!(
        port.confirm_release(&second.key, SourceClass::GuestReport),
        Err(CapacityRefusal::SourceTooWeak {
            source: SourceClass::GuestReport,
            required: SourceClass::HostProbe,
        }),
        "a guest cannot release host capacity"
    );
    assert_eq!(
        port.confirm_release(&second.key, SourceClass::HostProbe),
        Ok(ReleaseOutcome::Released)
    );
    assert_eq!(port.release(&second.key), Ok(ReleaseOutcome::NotHeld));

    let owner = execution("exe-c");
    let kept = request(&owner, 1, 4 * GIB);
    let unused = request(&owner, 2, 4 * GIB);
    let created = request(&owner, 3, 4 * GIB);
    for reservation in [&kept, &unused, &created] {
        assert_eq!(port.reserve(reservation), Ok(ReserveOutcome::Granted));
    }
    port.begin_create(&created.key).unwrap();
    let lost = sandbox_key(&owner, 9);
    assert_eq!(
        port.reconcile(&owner, &BTreeSet::from([kept.key, lost])),
        Ok(ReconcileReport {
            confirmed: BTreeSet::from([kept.key]),
            missing: BTreeSet::from([lost]),
            released_orphans: BTreeSet::from([unused.key]),
            pending_orphans: BTreeSet::from([created.key]),
        })
    );

    let hold = port
        .begin_hold(&BTreeSet::from([ResourceKind::HostMemoryBytes]))
        .unwrap();
    let background = request(&execution("exe-d"), 1, GIB);
    assert_eq!(
        port.reserve(&background),
        Err(CapacityRefusal::OwnerReturnHold {
            resource: ResourceKind::HostMemoryBytes
        })
    );
    let foreground = ReservationRequest {
        priority: ReservationPriority::Foreground,
        ..background
    };
    assert_eq!(port.reserve(&foreground), Ok(ReserveOutcome::Granted));
    port.end_hold(hold).unwrap();
    port.end_hold(hold).unwrap();
    assert_eq!(
        port.reserve(&request(&execution("exe-e"), 1, GIB)),
        Ok(ReserveOutcome::Granted)
    );
}

#[test]
fn a_vm_the_lifecycle_refuses_is_ended_before_the_rest_is_undone() {
    let mut world = World::new();
    world.launched();
    world.stop();
    let first = vm(&world.execution, 1, false);
    world.port.reused = Some(first);
    world.port.calls.clear();
    let report = world.relaunch(CompositeRecovery::default(), None);
    let LaunchOutcome::RolledBack {
        failure,
        compensations,
    } = report.outcome
    else {
        panic!("a reused handle was accepted");
    };
    assert_eq!(
        failure,
        LaunchFailure::Transition {
            refusal: TransitionRefusal::VmIdentityReused { vm: first }
        }
    );
    let of = world.execution.clone();
    assert_eq!(
        compensations,
        [
            Compensation::TerminateVm { vm: first },
            Compensation::TeardownPerimeter {
                perimeter: perimeter(&of, 2)
            },
            Compensation::ReleaseReservation {
                reservation: sandbox_key(&of, 2)
            },
        ]
    );
    assert!(world.ledger.held().is_empty());
    assert!(world.port.live.is_empty());
}

// Memory holdings (GPU part §3.6 lines 576–602): acquired extents, several devices, host
// memory, execute-while-load, drain-first handover, reactivation and confirmed release.

/// A second GPU on the host's machine.
fn device_b() -> GpuDeviceKey {
    GpuDeviceKey {
        machine: named("yougori/test/machine/v1", "host"),
        device: named("yougori/test/device/v1", "gpu1"),
    }
}

fn gpu_holding(allocation: u64) -> HoldingId {
    HoldingId::Gpu {
        allocation: GpuAllocationGeneration::new(allocation),
    }
}

fn host_key(of: &ExecutionId, model: ModelId, activation: u64) -> ReservationKey {
    ReservationKey::derive(
        of,
        &ReservationPurpose::ModelHost {
            model,
            activation: generation(activation),
        },
    )
}

/// A world whose host and sandbox have two GPUs and pinned host memory.
fn two_gpu_world() -> World {
    let ledger = FakeLedger::new([
        (ResourceKind::HostMemoryBytes, 64 * GIB),
        (ResourceKind::PinnedHostMemoryBytes, 8 * GIB),
        (ResourceKind::GpuMemoryBytes { device: device() }, 48 * GIB),
        (
            ResourceKind::GpuMemoryBytes { device: device_b() },
            48 * GIB,
        ),
        (ResourceKind::CpuInitializationSlots, 16),
    ]);
    let mut world = World::with_ledger(ledger);
    world.sandbox_demand = BTreeMap::from([
        (ResourceKind::HostMemoryBytes, 16 * GIB),
        (ResourceKind::PinnedHostMemoryBytes, 2 * GIB),
        (ResourceKind::GpuMemoryBytes { device: device() }, 16 * GIB),
        (
            ResourceKind::GpuMemoryBytes { device: device_b() },
            16 * GIB,
        ),
        (ResourceKind::CpuInitializationSlots, 4),
    ]);
    world
}

impl World {
    /// Launched and running, with no model activated yet.
    fn running(&mut self) -> AuthorityGrant {
        let grant = self.launched();
        self.coordinator.start_running(&self.execution).unwrap();
        grant
    }

    fn models(&self) -> &ModelActivations {
        self.coordinator
            .model_activations(&self.execution, self.model)
            .unwrap()
    }

    fn holding(&self, holding: HoldingId) -> &Holding {
        self.models().holding(holding).unwrap()
    }

    fn begin_with(
        &mut self,
        grant: AuthorityGrant,
        demand: ActivationDemand,
    ) -> Result<ActivationHandle, ModelRefusal> {
        let settings = self.settings(grant);
        self.coordinator
            .begin_activation_with(&self.execution, self.model, settings, demand)
    }

    fn complete(&mut self, activation: u64) {
        self.coordinator
            .complete_activation(&self.execution, self.model, generation(activation))
            .unwrap();
    }

    fn confirm(&mut self, activation: u64, source: SourceClass) -> Result<(), ModelRefusal> {
        self.coordinator.confirm_gpu_released(
            &self.execution,
            self.model,
            generation(activation),
            source,
        )
    }

    fn model_gpu(&self, allocation: u64) -> ReservationKey {
        gpu_key(&self.execution, self.model, allocation)
    }
}

#[test]
fn an_acquired_extent_keeps_its_generation_and_counts_once() {
    let mut world = World::new();
    let (grant, first) = world.serving();
    let reserved = world.ledger.reserve_calls();

    // The base weights stay resident; only the adapter's memory is new (§3.6 step 2).
    let second = world
        .begin_with(
            grant,
            ActivationDemand {
                gpu_memory_bytes: BTreeMap::from([(device(), 4 * GIB)]),
                acquire: BTreeSet::from([gpu_holding(1)]),
                ..ActivationDemand::default()
            },
        )
        .unwrap();
    assert_eq!(
        second.allocated,
        BTreeMap::from([(device(), GpuAllocationGeneration::new(2))])
    );
    assert_eq!(second.acquired, BTreeSet::from([gpu_holding(1)]));
    assert_eq!(
        second.generations,
        ModelGenerations {
            activation: generation(2),
            gpu_allocation: GpuAllocationGeneration::new(2),
        }
    );
    assert_eq!(
        world.ledger.reserve_calls(),
        reserved + 1,
        "only the new memory is reserved"
    );
    assert_eq!(
        world.ledger.held(),
        BTreeSet::from([
            sandbox_key(&world.execution, 1),
            world.model_gpu(1),
            world.model_gpu(2),
        ]),
        "the shared extent is counted once"
    );
    assert!(
        matches!(
            world.coordinator.begin_activation(
                &world.execution,
                world.model,
                world.settings(grant),
                gpu(11 * GIB)
            ),
            Err(ModelRefusal::Capacity {
                refusal: CapacityRefusal::ExceedsParentBudget { remaining, .. }
            }) if remaining == 10 * GIB
        ),
        "10 + 4 of the parent's 24 GiB are counted"
    );

    // An extent of another boot or authorization epoch is never acquired (INT-04).
    let acquire_first = ActivationDemand {
        acquire: BTreeSet::from([gpu_holding(1)]),
        ..ActivationDemand::default()
    };
    let current = world.sandbox().generations();
    assert!(world.models().plan(&acquire_first, current, None).is_ok());
    for later in [
        SandboxGenerations {
            authorization: AuthorizationEpoch::new(2),
            ..current
        },
        SandboxGenerations {
            boot: SandboxBootGeneration::new(2),
            ..current
        },
    ] {
        assert!(matches!(
            world.models().plan(&acquire_first, later, None),
            Err(ModelRefusal::HoldingUnavailable { holding }) if holding == gpu_holding(1)
        ));
    }

    world.complete(2);
    assert_eq!(
        world.activation(1).state(),
        ActivationState::Retired {
            reason: RetireReason::Replaced
        }
    );
    assert_eq!(
        world.ledger.state_of(&world.model_gpu(1)),
        Some(FakeState::InUse),
        "the extent stays in use by the new activation"
    );
    assert_eq!(
        world.holding(gpu_holding(1)).users(),
        &BTreeSet::from([generation(1), generation(2)])
    );
    assert_eq!(
        world.confirm(1, SourceClass::GuestReport),
        Err(ModelRefusal::NothingToRelease {
            activation: generation(1)
        }),
        "memory still in use is never released"
    );
    // The retired activation's pointer into the shared extent is refused; the new
    // activation's pointers into both allocations are honoured.
    assert!(matches!(
        world.coordinator.check_gpu_handle(&first),
        Err(LeaseRefusal::StaleGpuAllocation { .. })
    ));
    let handles = second.gpu_handles();
    assert_eq!(handles.len(), 2);
    for handle in &handles {
        assert_eq!(world.coordinator.check_gpu_handle(handle), Ok(()));
    }

    // The last user's end releases both, and one confirmation closes both.
    world
        .coordinator
        .evict(&world.execution, world.model, generation(2))
        .unwrap();
    for allocation in [1, 2] {
        assert_eq!(
            world.ledger.state_of(&world.model_gpu(allocation)),
            Some(FakeState::Releasing)
        );
    }
    world.confirm(2, SourceClass::GuestReport).unwrap();
    assert_eq!(
        world.ledger.held(),
        BTreeSet::from([sandbox_key(&world.execution, 1)])
    );
    assert_eq!(
        world.activation(2).gpu_reservation_state(),
        GpuReservationState::Released
    );
    assert_eq!(
        world.begin_with(grant, acquire_first),
        Err(ModelRefusal::HoldingUnavailable {
            holding: gpu_holding(1)
        }),
        "released memory is never acquired"
    );
}

#[test]
fn a_multi_device_activation_gets_one_allocation_generation_per_device() {
    let mut world = two_gpu_world();
    let grant = world.running();
    let parent = sandbox_key(&world.execution, 1);
    let (low, high) = if device() < device_b() {
        (device(), device_b())
    } else {
        (device_b(), device())
    };
    let split = |low_bytes: u64, high_bytes: u64| ActivationDemand {
        gpu_memory_bytes: BTreeMap::from([(low, low_bytes), (high, high_bytes)]),
        ..ActivationDemand::default()
    };

    // The second device's part does not fit: the first device's grant is withdrawn and no
    // generation is consumed.
    assert_eq!(
        world.begin_with(grant, split(8 * GIB, 20 * GIB)),
        Err(ModelRefusal::Capacity {
            refusal: CapacityRefusal::ExceedsParentBudget {
                parent,
                resource: ResourceKind::GpuMemoryBytes { device: high },
                requested: 20 * GIB,
                remaining: 16 * GIB,
                retry: RetryProspect::CannotProgress,
            }
        })
    );
    let calls = world.ledger.calls();
    assert_eq!(
        calls[calls.len() - 3..],
        [
            LedgerCall::Reserve(world.model_gpu(1)),
            LedgerCall::Reserve(world.model_gpu(2)),
            LedgerCall::Release(world.model_gpu(1)),
        ]
    );
    assert_eq!(world.ledger.held(), BTreeSet::from([parent]));

    let handle = world.begin_with(grant, split(8 * GIB, 6 * GIB)).unwrap();
    assert_eq!(
        handle.allocated,
        BTreeMap::from([
            (low, GpuAllocationGeneration::new(1)),
            (high, GpuAllocationGeneration::new(2)),
        ]),
        "one allocation generation per device"
    );
    assert_eq!(
        handle.generations,
        ModelGenerations {
            activation: generation(1),
            gpu_allocation: GpuAllocationGeneration::new(2),
        }
    );
    assert_eq!(
        world.ledger.held(),
        BTreeSet::from([parent, world.model_gpu(1), world.model_gpu(2)])
    );
    assert_eq!(
        world.holding(gpu_holding(2)).memory(),
        HoldingMemory::Gpu {
            device: high,
            memory_bytes: 6 * GIB,
        }
    );
    world.complete(1);
    let handles = handle.gpu_handles();
    assert_eq!(handles.len(), 2);
    for handle in &handles {
        assert_eq!(world.coordinator.check_gpu_handle(handle), Ok(()));
    }

    assert_eq!(
        world.begin_with(grant, split(8 * GIB, 0)),
        Err(ModelRefusal::InvalidDemand {
            problem: DemandProblem::ZeroGpuMemory { device: high }
        })
    );
    assert_eq!(
        world.begin_with(
            grant,
            ActivationDemand {
                host_memory_bytes: GIB,
                ..ActivationDemand::default()
            }
        ),
        Err(ModelRefusal::InvalidDemand {
            problem: DemandProblem::NoGpuMemory
        })
    );

    world
        .coordinator
        .evict(&world.execution, world.model, generation(1))
        .unwrap();
    world.confirm(1, SourceClass::GuestReport).unwrap();
    assert_eq!(world.ledger.held(), BTreeSet::from([parent]));
    for handle in &handles {
        assert!(world.coordinator.check_gpu_handle(handle).is_err());
    }
}

#[test]
fn host_memory_is_reserved_beside_vram_and_released_with_it() {
    let mut world = two_gpu_world();
    let grant = world.running();
    let parent = sandbox_key(&world.execution, 1);
    let with_host = |memory_bytes: u64, pinned_bytes: u64| ActivationDemand {
        gpu_memory_bytes: BTreeMap::from([(device(), 8 * GIB)]),
        host_memory_bytes: memory_bytes,
        pinned_host_memory_bytes: pinned_bytes,
        ..ActivationDemand::default()
    };

    // Host memory beyond the parent's budget: the VRAM granted in the same call is
    // withdrawn.
    assert_eq!(
        world.begin_with(grant, with_host(20 * GIB, 0)),
        Err(ModelRefusal::Capacity {
            refusal: CapacityRefusal::ExceedsParentBudget {
                parent,
                resource: ResourceKind::HostMemoryBytes,
                requested: 20 * GIB,
                remaining: 16 * GIB,
                retry: RetryProspect::CannotProgress,
            }
        })
    );
    assert!(!world.ledger.is_held(&world.model_gpu(1)));

    let handle = world.begin_with(grant, with_host(4 * GIB, GIB)).unwrap();
    let host = host_key(&world.execution, world.model, 1);
    assert_eq!(
        world.ledger.held(),
        BTreeSet::from([parent, world.model_gpu(1), host])
    );
    let holding = world.holding(HoldingId::Host {
        reserved_by: generation(1),
    });
    assert_eq!(
        holding.memory(),
        HoldingMemory::Host {
            memory_bytes: 4 * GIB,
            pinned_memory_bytes: GIB,
        }
    );
    assert_eq!(holding.reservations(), &[host]);
    assert_eq!(
        handle.gpu_handles().len(),
        1,
        "host memory is no GPU allocation"
    );
    assert!(
        matches!(
            world.begin_with(grant, with_host(0, 2 * GIB)),
            Err(ModelRefusal::Capacity {
                refusal: CapacityRefusal::ExceedsParentBudget {
                    resource: ResourceKind::PinnedHostMemoryBytes,
                    remaining,
                    ..
                }
            }) if remaining == GIB
        ),
        "pinned memory is counted on its own"
    );

    world.complete(1);
    world
        .coordinator
        .evict(&world.execution, world.model, generation(1))
        .unwrap();
    assert_eq!(world.ledger.state_of(&host), Some(FakeState::Releasing));
    world.confirm(1, SourceClass::GuestReport).unwrap();
    assert_eq!(world.ledger.held(), BTreeSet::from([parent]));
}

#[test]
fn a_preparation_lease_serves_only_its_assigned_request() {
    let mut world = World::new();
    let (grant, first) = world.serving();
    let second = world
        .coordinator
        .begin_activation(
            &world.execution,
            world.model,
            world.settings(grant),
            gpu(8 * GIB),
        )
        .unwrap();

    let assigned = world
        .coordinator
        .admit_preparation_request(
            &world.execution,
            world.model,
            generation(2),
            operation("op-pending"),
            terms(30, 120, 1),
        )
        .unwrap();
    assert_eq!(assigned.kind(), LeaseKind::Preparation);
    assert_eq!(
        assigned.model().map(|binding| binding.generations),
        Some(second.generations)
    );
    assert_eq!(
        world.coordinator.check_lease(assigned.id()),
        Ok(assigned.clone()),
        "honoured while the generation is prepared"
    );
    assert_eq!(
        world.coordinator.check_result_publication(assigned.id()),
        Err(LeaseRefusal::ActivationNotServing {
            activation: generation(2),
            state: Some(ActivationState::Loading),
        }),
        "no result is published before the generation is"
    );
    let other = world.request("op-other", terms(30, 120, 1));
    assert_eq!(
        other.model().map(|binding| binding.generations),
        Some(first.generations),
        "unrelated traffic goes to the serving generation"
    );
    assert_eq!(
        world.coordinator.admit_preparation_request(
            &world.execution,
            world.model,
            generation(2),
            operation("op-second"),
            terms(30, 120, 1),
        ),
        Err(ModelRefusal::PreparationAssigned {
            assigned: operation("op-pending")
        })
    );
    assert_eq!(
        world.coordinator.start_child_work(
            &world.execution,
            operation("op-sneak"),
            LeaseKind::Preparation,
            terms(30, 120, 1),
        ),
        Err(LeaseRefusal::NeedsModelAdmission)
    );
    assert_eq!(
        world.coordinator.admit_preparation_request(
            &world.execution,
            world.model,
            generation(1),
            operation("op-late"),
            terms(30, 120, 1),
        ),
        Err(ModelRefusal::InvalidActivationTransition {
            activation: generation(1),
            state: ActivationState::Active,
            step: ActivationStep::Prepare,
        })
    );
    assert_eq!(
        world
            .coordinator
            .fail_activation(&world.execution, world.model, generation(2)),
        Err(ModelRefusal::RequestsInFlight {
            activation: generation(2),
            leases: vec![assigned.id()],
        }),
        "a load is never abandoned under the request it computes for"
    );

    // Publication keeps the assigned request on its generation (INT-03).
    world.complete(2);
    assert_eq!(
        world.coordinator.check_lease(assigned.id()),
        Ok(assigned.clone())
    );
    assert_eq!(
        world.coordinator.check_result_publication(assigned.id()),
        Ok(assigned.clone())
    );
    assert_eq!(
        world.coordinator.check_result_publication(other.id()),
        Ok(other.clone())
    );
    assert_eq!(
        world
            .coordinator
            .check_lease(other.id())
            .map(|lease| lease.model()),
        Ok(other.model())
    );
    world.coordinator.finish_request(assigned.id()).unwrap();

    // Each preparation takes one assigned request at a time.
    world
        .coordinator
        .begin_activation(
            &world.execution,
            world.model,
            world.settings(grant),
            gpu(2 * GIB),
        )
        .unwrap();
    let next = world
        .coordinator
        .admit_preparation_request(
            &world.execution,
            world.model,
            generation(3),
            operation("op-next"),
            terms(30, 120, 1),
        )
        .unwrap();
    world.coordinator.finish_request(next.id()).unwrap();
    world
        .coordinator
        .fail_activation(&world.execution, world.model, generation(3))
        .unwrap();
    assert_eq!(
        world.coordinator.check_lease(next.id()),
        Err(LeaseRefusal::Released)
    );
}

#[test]
fn drain_first_hands_the_old_share_over_without_freeing_it() {
    let mut world = World::new();
    let grant = world.running();
    let first = world
        .coordinator
        .begin_activation(
            &world.execution,
            world.model,
            world.settings(grant),
            gpu(16 * GIB),
        )
        .unwrap();
    world.complete(1);
    let busy = world.request("op-busy", terms(30, 120, 1));
    assert!(
        matches!(
            world.coordinator.begin_activation(
                &world.execution,
                world.model,
                world.settings(grant),
                gpu(20 * GIB)
            ),
            Err(ModelRefusal::Capacity {
                refusal: CapacityRefusal::ExceedsParentBudget { remaining, .. }
            }) if remaining == 8 * GIB
        ),
        "only one resident generation fits"
    );

    let reserved = world.ledger.reserve_calls();
    let settings = world.settings(grant);
    let second = world
        .coordinator
        .begin_drain_first(
            &world.execution,
            world.model,
            settings,
            ActivationDemand::gpu(gpu(20 * GIB)),
            generation(1),
        )
        .unwrap();
    assert_eq!(second.awaiting_handover, Some(generation(1)));
    assert_eq!(
        world.ledger.reserve_calls(),
        reserved + 1,
        "only the excess is reserved now"
    );
    assert_eq!(
        world.holding(gpu_holding(1)).promised_to(),
        Some((generation(2), gpu_holding(2)))
    );

    // A real pause: the old generation drains, and nothing serves new requests.
    assert_eq!(world.activation(1).state(), ActivationState::Draining);
    assert_eq!(
        world.coordinator.admit_request(
            &world.execution,
            world.model,
            operation("op-new"),
            terms(30, 120, 1)
        ),
        Err(ModelRefusal::NoServingActivation { model: world.model })
    );
    assert!(
        world.coordinator.check_lease(busy.id()).is_ok(),
        "the admitted request keeps its generation (INT-03)"
    );
    assert_eq!(
        world
            .coordinator
            .complete_activation(&world.execution, world.model, generation(2)),
        Err(ModelRefusal::HandoverPending {
            predecessor: generation(1)
        })
    );
    let new_handle = second.gpu_handles()[0].clone();
    assert_eq!(
        world.coordinator.check_gpu_handle(&new_handle),
        Err(LeaseRefusal::AllocationAwaitingHandover {
            allocation: GpuAllocationGeneration::new(2)
        })
    );
    assert_eq!(
        world.coordinator.admit_preparation_request(
            &world.execution,
            world.model,
            generation(2),
            operation("op-early"),
            terms(30, 120, 1),
        ),
        Err(ModelRefusal::HandoverPending {
            predecessor: generation(1)
        })
    );

    // The old generation retires with its last request; its share stays counted.
    assert_eq!(
        world.coordinator.finish_request(busy.id()),
        Ok(vec![first.generations])
    );
    let old = world.model_gpu(1);
    assert_eq!(world.ledger.state_of(&old), Some(FakeState::InUse));
    assert!(
        matches!(
            world.coordinator.begin_activation(
                &world.execution,
                world.model,
                world.settings(grant),
                gpu(8 * GIB)
            ),
            Err(ModelRefusal::Capacity {
                refusal: CapacityRefusal::ExceedsParentBudget { remaining, .. }
            }) if remaining == 4 * GIB
        ),
        "no other request can take the share in between"
    );
    assert_eq!(
        world.confirm(1, SourceClass::RecordedDeclaration),
        Err(ModelRefusal::Capacity {
            refusal: CapacityRefusal::SourceTooWeak {
                source: SourceClass::RecordedDeclaration,
                required: SourceClass::GuestReport,
            }
        })
    );
    world.confirm(1, SourceClass::GuestReport).unwrap();
    assert!(
        !world.ledger.calls().contains(&LedgerCall::Release(old)),
        "handed over, never returned to the ledger"
    );
    assert_eq!(
        world.holding(gpu_holding(2)).reservations(),
        &[world.model_gpu(2), old]
    );
    assert!(world.holding(gpu_holding(2)).is_backed());
    assert_eq!(
        world.holding(gpu_holding(1)).state(),
        GpuReservationState::Released
    );
    assert_eq!(world.activation(2).awaiting_handover(), None);
    assert_eq!(world.coordinator.check_gpu_handle(&new_handle), Ok(()));
    assert_eq!(
        world
            .coordinator
            .complete_activation(&world.execution, world.model, generation(2)),
        Ok(Completion {
            already_active: false,
            draining: None,
        })
    );
    let after = world.request("op-after", terms(30, 120, 1));
    assert_eq!(
        after.model().map(|binding| binding.generations),
        Some(second.generations)
    );

    // The inherited share is released with the generation that holds it.
    world.coordinator.finish_request(after.id()).unwrap();
    world
        .coordinator
        .evict(&world.execution, world.model, generation(2))
        .unwrap();
    assert_eq!(world.ledger.state_of(&old), Some(FakeState::Releasing));
    world.confirm(2, SourceClass::GuestReport).unwrap();
    assert_eq!(
        world.ledger.held(),
        BTreeSet::from([sandbox_key(&world.execution, 1)])
    );
}

#[test]
fn a_failed_drain_first_successor_gives_the_share_back() {
    let mut world = World::new();
    let grant = world.running();
    let first = world
        .coordinator
        .begin_activation(
            &world.execution,
            world.model,
            world.settings(grant),
            gpu(16 * GIB),
        )
        .unwrap();
    world.complete(1);
    let busy = world.request("op-busy", terms(30, 120, 1));
    let settings = world.settings(grant);
    world
        .coordinator
        .begin_drain_first(
            &world.execution,
            world.model,
            settings,
            ActivationDemand::gpu(gpu(20 * GIB)),
            generation(1),
        )
        .unwrap();
    world
        .coordinator
        .fail_activation(&world.execution, world.model, generation(2))
        .unwrap();
    assert_eq!(world.holding(gpu_holding(1)).promised_to(), None);
    assert_eq!(
        world.ledger.state_of(&world.model_gpu(1)),
        Some(FakeState::InUse)
    );
    assert_eq!(
        world.ledger.state_of(&world.model_gpu(2)),
        Some(FakeState::Releasing)
    );
    assert!(
        !world.holding(gpu_holding(2)).is_backed(),
        "memory never fully reserved is never acquired"
    );

    // The draining generation comes back within its own reservation: a rollback.
    let calls = world.ledger.calls().len();
    let settings = world.settings(grant);
    let third = world
        .coordinator
        .reactivate(&world.execution, world.model, settings, generation(1))
        .unwrap();
    assert_eq!(world.ledger.calls().len(), calls, "no new reservation");
    assert_eq!(third.acquired, BTreeSet::from([gpu_holding(1)]));
    assert_eq!(
        third.generations,
        ModelGenerations {
            activation: generation(3),
            gpu_allocation: GpuAllocationGeneration::FIRST,
        }
    );
    world.complete(3);
    let next = world.request("op-next", terms(30, 120, 1));
    assert_eq!(
        next.model().map(|binding| binding.generations),
        Some(third.generations)
    );
    assert_eq!(
        world.coordinator.finish_request(busy.id()),
        Ok(vec![first.generations])
    );
    assert_eq!(
        world.ledger.state_of(&world.model_gpu(1)),
        Some(FakeState::InUse),
        "the memory stays with the generation that uses it"
    );
    world.confirm(2, SourceClass::GuestReport).unwrap();
    assert!(!world.ledger.is_held(&world.model_gpu(2)));
}

#[test]
fn a_parked_activation_reactivates_within_its_reservation() {
    let mut world = World::new();
    let grant = world.running();
    let first = world
        .begin_with(
            grant,
            ActivationDemand {
                retention: Retention::KeepUntilReleased,
                ..ActivationDemand::gpu(gpu(10 * GIB))
            },
        )
        .unwrap();
    world.complete(1);
    world
        .coordinator
        .evict(&world.execution, world.model, generation(1))
        .unwrap();
    let key = world.model_gpu(1);
    assert_eq!(
        world.ledger.state_of(&key),
        Some(FakeState::InUse),
        "parked: retired, its memory retained"
    );

    let calls = world.ledger.calls().len();
    let settings = world.settings(grant);
    let second = world
        .coordinator
        .reactivate(&world.execution, world.model, settings, generation(1))
        .unwrap();
    assert_eq!(world.ledger.calls().len(), calls, "no new reservation");
    assert!(second.allocated.is_empty());
    assert_eq!(
        second.generations,
        ModelGenerations {
            activation: generation(2),
            gpu_allocation: GpuAllocationGeneration::FIRST,
        }
    );
    world.complete(2);
    assert!(
        world
            .coordinator
            .check_gpu_handle(&first.gpu_handles()[0])
            .is_err(),
        "the parked activation's pointers stay refused (INT-04)"
    );
    assert_eq!(
        world.coordinator.check_gpu_handle(&second.gpu_handles()[0]),
        Ok(())
    );

    // Released explicitly, retained memory is gone for good.
    world
        .coordinator
        .evict(&world.execution, world.model, generation(2))
        .unwrap();
    assert_eq!(world.ledger.state_of(&key), Some(FakeState::InUse));
    world.confirm(2, SourceClass::GuestReport).unwrap();
    assert!(!world.ledger.is_held(&key));
    let settings = world.settings(grant);
    assert_eq!(
        world
            .coordinator
            .reactivate(&world.execution, world.model, settings, generation(2)),
        Err(ModelRefusal::HoldingUnavailable {
            holding: gpu_holding(1)
        })
    );
}

#[test]
fn int02_revocation_reclaims_retained_memory_and_waits_for_memory_in_use() {
    let mut world = World::new();
    let grant = world.running();
    world
        .begin_with(
            grant,
            ActivationDemand {
                retention: Retention::KeepUntilReleased,
                ..ActivationDemand::gpu(gpu(6 * GIB))
            },
        )
        .unwrap();
    world.complete(1);
    world
        .coordinator
        .evict(&world.execution, world.model, generation(1))
        .unwrap();
    world
        .coordinator
        .begin_activation(
            &world.execution,
            world.model,
            world.settings(grant),
            gpu(8 * GIB),
        )
        .unwrap();
    world.complete(2);
    let busy = world.request("op-busy", terms(30, 120, 1));

    world.coordinator.revoke(&world.execution).unwrap();
    world.advance(2);
    let status = world
        .coordinator
        .advance_revocation(&world.execution, &mut world.port)
        .unwrap();
    assert!(
        matches!(
            &status,
            RevocationStatus::WaitingForGpuReclaim { blocking, .. } if blocking == &vec![busy.id()]
        ),
        "{status:?}"
    );
    assert_eq!(
        world.holding(gpu_holding(1)).state(),
        GpuReservationState::Releasing,
        "retained memory nothing uses is reclaimed at once"
    );
    assert_eq!(
        world.holding(gpu_holding(2)).state(),
        GpuReservationState::Held,
        "memory a request may still use is not"
    );
    assert!(world
        .coordinator
        .reactivate(
            &world.execution,
            world.model,
            world.settings(grant),
            generation(1)
        )
        .is_err());

    world.clock.advance_to(busy.expires_at());
    let status = world
        .coordinator
        .advance_revocation(&world.execution, &mut world.port)
        .unwrap();
    assert!(
        matches!(status, RevocationStatus::Completed { .. }),
        "{status:?}"
    );
    assert!(world
        .models()
        .holdings()
        .iter()
        .all(|holding| holding.state() == GpuReservationState::Released));
    assert!(world.ledger.held().is_empty());
}

#[test]
fn holdings_hand_over_and_close_through_the_real_ledger() {
    let mut world = RealWorld::new();
    let of = execution("exe-real");
    let model = ModelId::new(named("yougori/test/model/v1", "chat-model"));
    let LaunchOutcome::AuthorityActive { grant, .. } =
        world.launch(&of, ReservationPriority::Background)
    else {
        panic!("not launched");
    };
    world.coordinator.start_running(&of).unwrap();
    let parent = world
        .coordinator
        .capacity()
        .record(&sandbox_key(&of, 1))
        .unwrap()
        .id();
    let state = |world: &RealWorld, key: &ReservationKey| {
        world
            .coordinator
            .capacity()
            .record(key)
            .map(|record| record.state())
    };

    world
        .coordinator
        .begin_activation_with(
            &of,
            model,
            settings_for(grant),
            ActivationDemand {
                host_memory_bytes: 2 * GIB,
                ..ActivationDemand::gpu(gpu(16 * GIB))
            },
        )
        .unwrap();
    world
        .coordinator
        .complete_activation(&of, model, generation(1))
        .unwrap();
    let (old, host) = (gpu_key(&of, model, 1), host_key(&of, model, 1));
    let record = world.coordinator.capacity().record(&host).unwrap();
    assert_eq!(record.parent(), Some(parent));
    assert_eq!(record.state(), ReservationState::InUse);

    let second = world
        .coordinator
        .begin_drain_first(
            &of,
            model,
            settings_for(grant),
            ActivationDemand::gpu(gpu(20 * GIB)),
            generation(1),
        )
        .unwrap();
    assert_eq!(second.awaiting_handover, Some(generation(1)));
    assert_eq!(state(&world, &old), Some(ReservationState::InUse));
    assert_eq!(
        state(&world, &host),
        Some(ReservationState::Releasing),
        "the host memory nothing else uses is released"
    );
    assert!(matches!(
        world
            .coordinator
            .begin_activation(&of, model, settings_for(grant), gpu(8 * GIB)),
        Err(ModelRefusal::Capacity {
            refusal: CapacityRefusal::ExceedsParentBudget { remaining, .. }
        }) if remaining == 4 * GIB
    ));

    world
        .coordinator
        .confirm_gpu_released(&of, model, generation(1), SourceClass::GuestReport)
        .unwrap();
    assert_eq!(
        state(&world, &old),
        Some(ReservationState::InUse),
        "handed over, still counted"
    );
    assert_eq!(state(&world, &host), None);
    world
        .coordinator
        .complete_activation(&of, model, generation(2))
        .unwrap();
    world.coordinator.evict(&of, model, generation(2)).unwrap();
    let new = gpu_key(&of, model, 2);
    for key in [&old, &new] {
        assert_eq!(state(&world, key), Some(ReservationState::Releasing));
    }
    world
        .coordinator
        .confirm_gpu_released(&of, model, generation(2), SourceClass::GuestReport)
        .unwrap();
    for key in [&old, &new] {
        assert_eq!(state(&world, key), None);
    }
}

// Review round R1: each test below turns a reviewer's proof around and fails if its
// defect returns.

/// What the test sandboxes' authority grants their models: the route and the verified
/// artifact `settings_for` uses.
fn world_grant() -> SettingsGrant {
    SettingsGrant {
        network: BTreeSet::from([route("model-download")]),
        verified_artifacts: BTreeSet::from([artifact("weights")]),
    }
}

#[test]
fn a_lease_issued_after_the_last_persisted_state_is_never_honoured_again() {
    let mut world = World::new();
    world.running();
    let early = world.child("op-a", LeaseKind::ChildWork, terms(60, 600, 1));
    let persisted = world.coordinator.persist();
    world.coordinator.confirm_persisted(&persisted);
    // Issued after the snapshot, to a holder inside the VM that keeps running.
    let late = world.child("op-b", LeaseKind::Transfer, terms(60, 600, 1));
    assert!(late.id() < persisted.next_lease, "below the persisted mark");

    let (mut recovered, report) = TestCoordinator::recover(
        persisted.clone(),
        Arc::clone(&world.clock),
        session(2),
        world.ledger.clone(),
        &mut world.port,
    )
    .unwrap();
    assert!(matches!(
        report.sandboxes[&world.execution],
        SandboxRecovery::VmKeptWithoutAuthority { .. }
    ));
    assert_eq!(report.leases_not_revived, vec![early.id()]);
    let plan = world.plan();
    let LaunchOutcome::AuthorityActive { .. } = recovered
        .launch(plan, &mut world.port, &world.evidence.registry)
        .unwrap()
    else {
        panic!("not re-authorized");
    };
    assert_eq!(
        recovered.start_child_work(
            &world.execution,
            operation("op-c"),
            LeaseKind::ChildWork,
            terms(60, 600, 1)
        ),
        Err(LeaseRefusal::LeaseIdsNotPersisted {
            limit: persisted.next_lease
        }),
        "nothing is issued before the recovered state is persisted"
    );
    let state = recovered.persist();
    recovered.confirm_persisted(&state);
    assert_eq!(recovered.lease_id_limit(), state.next_lease);
    let fresh = recovered
        .start_child_work(
            &world.execution,
            operation("op-c"),
            LeaseKind::ChildWork,
            terms(60, 600, 1),
        )
        .unwrap();
    assert!(fresh.id() >= persisted.next_lease);

    // The pre-crash holder of the late lease is never honoured, with its number alone or
    // with its session.
    assert_eq!(
        recovered.check_lease(late.id()),
        Err(LeaseRefusal::UnknownLease { lease: late.id() })
    );
    assert_eq!(
        recovered.renew_lease(late.id()),
        Err(LeaseRefusal::UnknownLease { lease: late.id() })
    );
    assert_eq!(
        recovered.check_presented_lease(fresh.id(), late.clock()),
        Err(LeaseRefusal::OtherClock),
        "a lease of another run, even under a number issued again"
    );
    assert_eq!(
        recovered.renew_presented_lease(fresh.id(), late.clock()),
        Err(LeaseRefusal::OtherClock)
    );
    assert_eq!(
        recovered.check_presented_lease(fresh.id(), fresh.clock()),
        Ok(fresh.clone())
    );
}

#[test]
fn a_failed_recovery_hands_the_real_ledger_back_with_every_reservation() {
    let mut world = RealWorld::new();
    let of = execution("exe-real");
    let LaunchOutcome::AuthorityActive { .. } = world.launch(&of, ReservationPriority::Background)
    else {
        panic!("not launched");
    };
    let persisted = world.coordinator.persist();
    let capacity = std::mem::replace(
        &mut world.coordinator,
        Coordinator::new(
            Arc::clone(&world.clock),
            session(9),
            real_ledger(&world.clock),
        ),
    );
    let ledger = capacity_into(capacity);
    world.port.failing.insert(PortOperation::ListVms);
    world.port.calls.clear();
    let Err(failure) = Coordinator::recover(
        persisted.clone(),
        Arc::clone(&world.clock),
        session(2),
        ledger,
        &mut world.port,
    ) else {
        panic!("recovery cannot list the VMs");
    };
    assert!(matches!(
        failure.error,
        CoordinationError::Port {
            failure: PortFailure {
                operation: PortOperation::ListVms,
                ..
            }
        }
    ));
    assert_eq!(
        world.port.calls,
        vec![PortCall::ListVms],
        "the VMs are listed before anything changes"
    );
    assert_eq!(
        failure
            .capacity
            .record(&sandbox_key(&of, 1))
            .map(|record| record.state()),
        Some(ReservationState::InUse),
        "the live VM's reservation is still counted"
    );
    assert_eq!(world.port.live.len(), 1, "while the VM still runs");

    world.port.failing.clear();
    let (recovered, report) = Coordinator::recover(
        persisted,
        Arc::clone(&world.clock),
        session(2),
        failure.capacity,
        &mut world.port,
    )
    .unwrap();
    assert!(matches!(
        report.sandboxes[&of],
        SandboxRecovery::VmKeptWithoutAuthority { .. }
    ));
    assert_eq!(
        recovered
            .capacity()
            .record(&sandbox_key(&of, 1))
            .map(|record| record.state()),
        Some(ReservationState::InUse)
    );
}

#[test]
fn a_vm_recovery_kept_without_authority_ends_without_new_authority() {
    let mut world = World::new();
    world.serving();
    let persisted = world.coordinator.persist();
    let (mut recovered, report) = TestCoordinator::recover(
        persisted,
        Arc::clone(&world.clock),
        session(2),
        world.ledger.clone(),
        &mut world.port,
    )
    .unwrap();
    let of = world.execution.clone();
    assert!(matches!(
        report.sandboxes[&of],
        SandboxRecovery::VmKeptWithoutAuthority { .. }
    ));
    assert_eq!(
        recovered.sandbox(&of).unwrap().state(),
        SandboxState::VmCreated
    );

    let compensations = recovered.terminate(&of, &mut world.port).unwrap();
    assert_eq!(
        compensations,
        vec![
            Compensation::TerminateVm {
                vm: vm(&of, 1, false)
            },
            Compensation::ReleaseReservation {
                reservation: gpu_key(&of, world.model, 1)
            },
            Compensation::TeardownPerimeter {
                perimeter: perimeter(&of, 1)
            },
            Compensation::ReleaseReservation {
                reservation: sandbox_key(&of, 1)
            },
        ]
    );
    let sandbox = recovered.sandbox(&of).unwrap();
    assert_eq!(sandbox.state(), SandboxState::Stopped);
    assert_eq!(
        sandbox.authority(),
        None,
        "no authority was granted to end it"
    );
    assert!(world.port.live.is_empty());
    assert!(world.ledger.held().is_empty());
    assert_eq!(recovered.terminate(&of, &mut world.port), Ok(Vec::new()));

    // A sandbox that holds authority is revoked first; terminate refuses it.
    let mut running = World::new();
    running.serving();
    assert_eq!(
        running
            .coordinator
            .terminate(&running.execution, &mut running.port),
        Err(CoordinationError::Transition {
            refusal: TransitionRefusal::InvalidTransition {
                from: SandboxState::Running,
                step: StepKind::Terminate,
            }
        })
    );
}

#[test]
fn an_owner_return_hold_ends_with_recovery() {
    let mut world = RealWorld::new();
    let of = execution("exe-real");
    let LaunchOutcome::AuthorityActive { .. } = world.launch(&of, ReservationPriority::Background)
    else {
        panic!("not launched");
    };
    world.coordinator.start_running(&of).unwrap();
    world
        .coordinator
        .begin_resource_return(
            &of,
            GpuAssignment::Shared,
            BTreeSet::from([CancellationBoundary::BetweenRequests]),
            BTreeSet::from([ResourceKind::HostMemoryBytes]),
        )
        .unwrap();
    let hold = world.coordinator.resource_return(&of).unwrap().hold();
    let persisted = world.coordinator.persist();
    assert_eq!(persisted.return_holds, vec![hold]);
    let capacity = std::mem::replace(
        &mut world.coordinator,
        Coordinator::new(
            Arc::clone(&world.clock),
            session(9),
            real_ledger(&world.clock),
        ),
    );
    let ledger = capacity_into(capacity);
    assert_eq!(ledger.ledger().active_holds().len(), 1);

    let (recovered, report) = Coordinator::recover(
        persisted,
        Arc::clone(&world.clock),
        session(2),
        ledger,
        &mut world.port,
    )
    .unwrap();
    assert_eq!(report.return_holds_ended, vec![hold]);
    assert!(recovered.capacity().ledger().active_holds().is_empty());
    assert!(recovered.resource_return(&of).is_none());

    // Another background sandbox is no longer refused on a hold nobody can end.
    world.coordinator = recovered;
    assert!(matches!(
        world.launch(&execution("exe-other"), ReservationPriority::Background),
        LaunchOutcome::AuthorityActive { .. }
    ));
}

#[test]
fn a_gpu_checkpoint_restores_only_on_its_own_runtime_with_fresh_evidence() {
    let mut world = World::new();
    let taken_on = world.runtime.clone();
    let support = world.evidence.checkpoint_support(&taken_on);
    let manifest = GpuCheckpointManifest {
        recorded: content("checkpoint"),
        observed: content("checkpoint"),
        runtime: Subject::Runtime(taken_on.clone()).identity(),
    };
    let now = world.coordinator.now();
    assert_eq!(
        validate_gpu_checkpoint(&manifest, Some(&support), &taken_on, now),
        Ok(())
    );
    let other = runtime(ExecutionCategory::VmSandbox, "other-host-gpu-b");
    assert_eq!(
        validate_gpu_checkpoint(&manifest, Some(&support), &other, now),
        Err(vec![CheckpointDefect::CheckpointForOtherRuntime {
            checkpoint: manifest.runtime,
            runtime: Subject::Runtime(other.clone()).identity(),
        }])
    );
    let later = support.fresh_until().saturating_add(SECOND);
    assert_eq!(
        validate_gpu_checkpoint(&manifest, Some(&support), &taken_on, later),
        Err(vec![CheckpointDefect::StaleEvidence {
            fresh_until: support.fresh_until(),
            now: later,
        }])
    );

    // Two hours later, a relaunch on another runtime cold-boots.
    world.serving();
    world.stop();
    world.clock.advance(2 * HOUR);
    world.runtime = other.clone();
    let recovery = CompositeRecovery {
        gpu_checkpoint: Some(manifest),
        ..CompositeRecovery::default()
    };
    let report = world.relaunch(recovery, Some(&support));
    assert_eq!(report.decision.path, RecoveryPath::ColdBootReload);
    assert!(matches!(
        &report.decision.verdicts[&RecoveryComponent::GpuCheckpointRestore],
        ValidatorVerdict::Failed { .. }
    ));
    assert_eq!(world.sandbox().runtime(), &other);
}

#[test]
fn activation_settings_stay_within_what_the_authority_granted() {
    let mut world = World::new();
    let plan = world.plan();
    let LaunchOutcome::AuthorityActive { grant, .. } = world
        .coordinator
        .launch(plan, &mut world.port, &world.evidence.registry)
        .unwrap()
    else {
        panic!("not launched");
    };
    world.coordinator.start_running(&world.execution).unwrap();
    assert_eq!(
        world.sandbox().settings_grant(),
        &SettingsGrant::default(),
        "a plain launch grants a new sandbox's models nothing"
    );
    let offline = RuntimeSettings {
        network: BTreeSet::new(),
        artifact_verification: ArtifactVerification::Verified {
            artifacts: BTreeSet::new(),
        },
        loader: BTreeSet::new(),
        ..settings_for(grant)
    };
    let mut begin = |settings: RuntimeSettings| {
        world
            .coordinator
            .begin_activation(&world.execution, world.model, settings, gpu(GIB))
            .map(|_| ())
    };
    assert_eq!(
        begin(settings_for(grant)),
        Err(ModelRefusal::NetworkNotGranted {
            grants: BTreeSet::from([route("model-download")])
        }),
        "the caller of an activation never widens the authority"
    );
    assert_eq!(
        begin(RuntimeSettings {
            network: BTreeSet::new(),
            ..settings_for(grant)
        }),
        Err(ModelRefusal::ArtifactsNotGranted {
            bypass: ArtifactBypass::UnverifiedArtifacts {
                artifacts: BTreeSet::from([artifact("weights")])
            }
        })
    );
    assert_eq!(
        begin(RuntimeSettings {
            artifact_verification: ArtifactVerification::Bypassed,
            ..offline.clone()
        }),
        Err(ModelRefusal::ArtifactsNotGranted {
            bypass: ArtifactBypass::VerificationSkipped
        })
    );
    assert_eq!(begin(offline), Ok(()));

    // A sandbox launched with a grant: its models may use it, or less, never more.
    let mut granted = World::new();
    let grant = granted.running();
    assert_eq!(granted.sandbox().settings_grant(), &world_grant());
    assert!(
        granted.sandbox().log().iter().any(|record| matches!(
            &record.step,
            SandboxStep::ActivateAuthority { settings, .. } if *settings == world_grant()
        )),
        "recorded with the authority"
    );
    let mut wider = settings_for(grant);
    wider.network.insert(route("exfiltrate"));
    assert_eq!(
        granted
            .coordinator
            .begin_activation(&granted.execution, granted.model, wider, gpu(GIB))
            .map(|_| ()),
        Err(ModelRefusal::NetworkNotGranted {
            grants: BTreeSet::from([route("exfiltrate")])
        })
    );
    assert!(granted
        .coordinator
        .begin_activation(
            &granted.execution,
            granted.model,
            settings_for(grant),
            gpu(GIB)
        )
        .is_ok());
}

#[test]
fn pinned_host_memory_is_charged_to_host_ram_too() {
    let mut world = two_gpu_world();
    let grant = world.running();
    let parent = sandbox_key(&world.execution, 1);
    let host = |pageable_bytes: u64, pinned_bytes: u64| ActivationDemand {
        gpu_memory_bytes: BTreeMap::from([(device(), 4 * GIB)]),
        host_memory_bytes: pageable_bytes,
        pinned_host_memory_bytes: pinned_bytes,
        ..ActivationDemand::default()
    };
    // 15 GiB of pageable memory fits the parent's 16 GiB of host RAM; with 2 GiB pinned on
    // top it does not (decisions T08 and P02: pinned pages are host RAM).
    assert_eq!(
        world.begin_with(grant, host(15 * GIB, 2 * GIB)),
        Err(ModelRefusal::Capacity {
            refusal: CapacityRefusal::ExceedsParentBudget {
                parent,
                resource: ResourceKind::HostMemoryBytes,
                requested: 17 * GIB,
                remaining: 16 * GIB,
                retry: RetryProspect::CannotProgress,
            }
        })
    );
    world.begin_with(grant, host(4 * GIB, GIB)).unwrap();
    assert_eq!(
        world
            .holding(HoldingId::Host {
                reserved_by: generation(1)
            })
            .memory()
            .demand(),
        BTreeMap::from([
            (ResourceKind::HostMemoryBytes, 5 * GIB),
            (ResourceKind::PinnedHostMemoryBytes, GIB),
        ])
    );
    assert!(
        matches!(
            world.begin_with(grant, host(12 * GIB, 0)),
            Err(ModelRefusal::Capacity {
                refusal: CapacityRefusal::ExceedsParentBudget {
                    resource: ResourceKind::HostMemoryBytes,
                    remaining,
                    ..
                }
            }) if remaining == 11 * GIB
        ),
        "the pinned gibibyte counts against host RAM"
    );
}

// Integration round (T16's gaps G1, G2, G5 and G10; incarnation; weights apart from KV;
// parking; the authority record's settings).

/// An audit store kept in memory; the test reads what it holds.
#[derive(Clone, Default)]
struct MemoryAudit(Rc<RefCell<Vec<AuditRecord>>>);

impl AuditStore for MemoryAudit {
    fn append(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        self.0.borrow_mut().push(record.clone());
        Ok(())
    }
}

#[derive(Default)]
struct MemorySpool(VecDeque<AuditRecord>);

impl AuditSpool for MemorySpool {
    fn push(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        self.0.push_back(record.clone());
        Ok(())
    }

    fn front(&self) -> Result<Option<AuditRecord>, StoreRefusal> {
        Ok(self.0.front().cloned())
    }

    fn pop_front(&mut self) -> Result<(), StoreRefusal> {
        self.0.pop_front();
        Ok(())
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn records(&self) -> Result<Vec<AuditRecord>, StoreRefusal> {
        Ok(self.0.iter().cloned().collect())
    }
}

#[test]
fn the_coordinator_shares_the_host_ledger_with_its_other_clients() {
    let mut world = RealWorld::new();
    let shared: SharedLedger<TestClock> = Arc::new(Mutex::new(host_real_ledger(&world.clock)));
    let mut coordinator = Coordinator::new(
        Arc::clone(&world.clock),
        session(1),
        LedgerCapacity::shared(Arc::clone(&shared)),
    );
    let of = execution("exe-real");
    let plan = world.plan(&of, ReservationPriority::Background);
    let LaunchOutcome::AuthorityActive { .. } = coordinator
        .launch_with(
            plan,
            world_grant(),
            &mut world.port,
            &world.evidence.registry,
        )
        .unwrap()
    else {
        panic!("not launched");
    };
    let handle = coordinator.capacity().handle();
    assert!(Arc::ptr_eq(&handle, &shared), "one ledger, one handle");
    let ram = ledger_resource(ResourceKind::HostMemoryBytes);
    assert_eq!(lock_ledger(&shared).reserved(ram), 16 * GIB);

    // A transfer charging the same ledger sees the sandbox's 16 GiB: 50 of 64 GiB do not
    // fit, 48 do, and the coordinator sees the transfer's.
    let transfer = |bytes: u64| {
        LedgerRequest::new(
            Provenance {
                requester: Requester::Transfer,
                execution: of.clone(),
                operation: operation("op-transfer"),
                tenant: tenant(),
                purpose: CostPurpose::Transfer,
                retry_number: 0,
            },
            Priority::Foreground,
            Amounts::new().with(ram, bytes),
        )
    };
    assert!(lock_ledger(&handle).reserve(transfer(50 * GIB)).is_err());
    assert!(matches!(
        lock_ledger(&handle).reserve(transfer(48 * GIB)),
        Ok(Admission::Granted(_))
    ));
    assert_eq!(coordinator.capacity().ledger().reserved(ram), 64 * GIB);
    assert_eq!(
        coordinator
            .capacity()
            .record(&sandbox_key(&of, 1))
            .map(|record| record.state()),
        Some(ReservationState::InUse)
    );

    // An owned ledger can be shared later, with what it holds.
    let shared_later = real_ledger(&world.clock).into_shared();
    assert_eq!(lock_ledger(&shared_later.handle()).reserved(ram), 0);
}

fn lock_ledger(ledger: &SharedLedger<TestClock>) -> std::sync::MutexGuard<'_, Ledger<TestClock>> {
    ledger.lock().unwrap()
}

#[test]
fn a_cache_the_catalog_verified_restores_and_another_scope_does_not() {
    let weights = content("weights");
    let cache = ModelCacheManifest {
        tenant: tenant(),
        artifacts: BTreeSet::from([weights]),
    };
    let object = |scope: Scope, class: ArtifactClass| ArtifactVerification::Verified {
        artifacts: BTreeSet::from([ObjectId::new(&scope, class, weights).digest()]),
    };
    // As Catalog::artifact_verification names it: the tenant's object of that content.
    assert_eq!(
        validate_model_cache(
            &cache,
            &tenant(),
            &object(Scope::tenant(tenant()), ArtifactClass::ModelWeights)
        ),
        Ok(())
    );
    assert_eq!(
        validate_model_cache(
            &cache,
            &tenant(),
            &object(Scope::tenant(tenant()), ArtifactClass::ModelSidecar)
        ),
        Ok(())
    );
    // By content key, as before.
    assert_eq!(
        validate_model_cache(&cache, &tenant(), &verified_of(&[weights])),
        Ok(())
    );
    // Another tenant's object, or another class, never stands for this tenant's weights.
    let unverified = Err(vec![CacheDefect::UnverifiedArtifacts {
        artifacts: BTreeSet::from([weights]),
    }]);
    let other = TenantId::new("tenant-b").unwrap();
    assert_eq!(
        validate_model_cache(
            &cache,
            &tenant(),
            &object(Scope::tenant(other), ArtifactClass::ModelWeights)
        ),
        unverified
    );
    assert_eq!(
        validate_model_cache(
            &cache,
            &tenant(),
            &object(Scope::tenant(tenant()), ArtifactClass::GuestImage)
        ),
        unverified
    );
}

fn verified_of(contents: &[ContentKey]) -> ArtifactVerification {
    ArtifactVerification::Verified {
        artifacts: contents.iter().map(|content| *content.digest()).collect(),
    }
}

#[test]
fn an_activation_loader_stays_within_the_gates_plan() {
    let mut world = World::new();
    let launch = world.plan();
    let LaunchOutcome::AuthorityActive { grant, .. } = world
        .coordinator
        .launch_with(
            launch,
            world_grant(),
            &mut world.port,
            &world.evidence.registry,
        )
        .unwrap()
    else {
        panic!("not launched");
    };
    world.coordinator.start_running(&world.execution).unwrap();
    // Without a grant, only the ordinary loader runs.
    assert_eq!(world.sandbox().loader_grant(), None);
    assert_eq!(
        world
            .coordinator
            .begin_activation(&world.execution, world.model, settings_for(grant), gpu(GIB))
            .map(|_| ()),
        Err(ModelRefusal::LoaderNotGranted {
            optimizations: BTreeSet::from([Optimization::IoUring])
        })
    );

    // The gate's plan for this runtime enables io_uring and nothing else.
    let gate = LoaderGate::recorded();
    let runtime = world.runtime.clone();
    let plan = world.evidence.loader_plan(&gate, &runtime);
    let other = runtime_named("vm-host-9");
    let other_plan = world.evidence.loader_plan(&gate, &other);
    assert!(matches!(
        world
            .coordinator
            .grant_loader(&world.execution, &other_plan),
        Err(ModelRefusal::PlanForOtherRuntime { .. })
    ));
    world
        .coordinator
        .grant_loader(&world.execution, &plan)
        .unwrap();
    assert_eq!(
        world.sandbox().loader_grant(),
        Some(&LoaderGrant::from_plan(&plan))
    );
    let mut ungated = settings_for(grant);
    ungated
        .loader
        .extend([Optimization::CudaIpcLegacy, Optimization::GpuDirectStorage]);
    assert_eq!(
        world
            .coordinator
            .begin_activation(&world.execution, world.model, ungated, gpu(GIB))
            .map(|_| ()),
        Err(ModelRefusal::LoaderNotGranted {
            optimizations: BTreeSet::from([
                Optimization::CudaIpcLegacy,
                Optimization::GpuDirectStorage
            ])
        }),
        "an ungated loader is never recorded as authorized"
    );
    assert!(world
        .coordinator
        .begin_activation(&world.execution, world.model, settings_for(grant), gpu(GIB))
        .is_ok());

    // The grant ends with the authority: a revoked sandbox has none.
    world.coordinator.revoke(&world.execution).unwrap();
    assert_eq!(world.sandbox().loader_grant(), None);
}

fn runtime_named(instance: &str) -> RuntimeSubject {
    runtime(ExecutionCategory::VmSandbox, instance)
}

/// The event plane revocations go to: the hub with the coordinator's registered issuer,
/// and an audit journal kept in memory.
struct Plane {
    hub: EventHub<TestClock>,
    issuer: RevocationIssuer,
    journal: AuditJournal<MemoryAudit, MemorySpool, TestClock>,
    authority: AuditAppendAuthority,
    stored: MemoryAudit,
}

impl Plane {
    fn new(clock: &TestClock) -> Self {
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
            .register_revocation_issuer(ProducerId::new("coordinator").unwrap())
            .unwrap();
        let stored = MemoryAudit::default();
        let (journal, authority) = AuditJournal::open(
            JournalId::new("engine").unwrap(),
            ProducerId::new("engine.audit").unwrap(),
            stored.clone(),
            MemorySpool::default(),
            Arc::clone(clock),
            AuditConfig {
                spool_records: 8,
                revocation_reserve_records: 2,
                failure_policy: AuditFailurePolicy::DenyHighImpact,
                guest_observations: EmissionLimit::new(10, SECOND).unwrap(),
                redaction: RedactionPolicy::metadata_only(),
            },
        )
        .unwrap();
        Self {
            hub,
            issuer,
            journal,
            authority,
            stored,
        }
    }

    fn events(&mut self) -> RevocationEvents<'_, TestClock, MemoryAudit, MemorySpool, TestClock> {
        RevocationEvents {
            hub: &mut self.hub,
            issuer: &mut self.issuer,
            journal: &mut self.journal,
            authority: &mut self.authority,
        }
    }
}

#[test]
fn a_revocation_reaches_the_priority_lane_and_the_audit_journal() {
    let mut world = World::new();
    world.serving();
    let mut plane = Plane::new(&world.clock);
    let published = world
        .coordinator
        .revoke_and_publish(
            &world.execution,
            operation("op-revoke"),
            RevocationReason::SecurityEvent,
            &mut plane.events(),
        )
        .unwrap();
    assert_eq!(published.notice.current, AuthorizationEpoch::new(2));
    assert_eq!(published.lane, Ok(RevocationAdmission::Queued));
    assert!(published.audit.is_ok());
    assert_eq!(world.sandbox().state(), SandboxState::Revoking);

    let revoked = Revocation {
        execution: world.execution.clone(),
        epoch: AuthorizationEpoch::new(2),
        reason: RevocationReason::SecurityEvent,
    };
    let delivery = plane.hub.drain(16);
    assert_eq!(delivery.revocations.notices.len(), 1);
    assert_eq!(delivery.revocations.notices[0].payload(), &revoked);
    let records = plane.stored.0.borrow();
    assert_eq!(records.len(), 1);
    assert!(matches!(
        records[0].event().payload(),
        AuditEntry::Revocation { revocation } if *revocation == revoked
    ));
}

/// A recovery from `state` on a new clock session, with the world's ledger and VMs.
fn recover_from(world: &mut World, state: PersistedState, number: u128) -> TestCoordinator {
    TestCoordinator::recover(
        state,
        Arc::clone(&world.clock),
        session(number),
        world.ledger.clone(),
        &mut world.port,
    )
    .unwrap()
    .0
}

#[test]
fn the_incarnation_is_handed_out_only_once_a_state_carrying_it_is_persisted() {
    let mut world = World::new();
    assert_eq!(
        world.coordinator.current_incarnation(),
        Err(IncarnationNotPersisted),
        "not even the first run's number before a state carrying it is durable"
    );
    world.serving();
    let first = world.coordinator.persist();
    assert_eq!(first.incarnation, Incarnation::FIRST);
    world.coordinator.confirm_persisted(&first);
    let mut stamped = vec![world.coordinator.current_incarnation().unwrap()];
    assert_eq!(stamped, [Incarnation::FIRST]);

    // A crash before the recovered state is confirmed: its number was never handed out,
    // so nothing carries it, and recovering from the same snapshot again is safe.
    let crashed = recover_from(&mut world, first.clone(), 2);
    assert_eq!(crashed.current_incarnation(), Err(IncarnationNotPersisted));
    let written = crashed.persist();
    assert_eq!(written.incarnation, Incarnation::new(2));
    assert_eq!(
        crashed.current_incarnation(),
        Err(IncarnationNotPersisted),
        "written but not confirmed"
    );
    drop(crashed);
    let mut again = recover_from(&mut world, first.clone(), 3);
    assert_eq!(again.current_incarnation(), Err(IncarnationNotPersisted));
    // Confirming a state that carries another number hands out nothing.
    again.confirm_persisted(&first);
    assert_eq!(again.current_incarnation(), Err(IncarnationNotPersisted));

    // Once confirmed, the number is greater than every number handed out before.
    let state = again.persist();
    again.confirm_persisted(&state);
    let number = again.current_incarnation().unwrap();
    assert!(stamped.iter().all(|earlier| number > *earlier));
    stamped.push(number);
    let mut third = recover_from(&mut world, state, 4);
    let state = third.persist();
    third.confirm_persisted(&state);
    let number = third.current_incarnation().unwrap();
    assert!(stamped.iter().all(|earlier| number > *earlier));
    assert_eq!(number, Incarnation::new(3));

    // A state persisted before the counter existed is the first run's.
    let mut json = serde_json::to_value(&first).unwrap();
    json.as_object_mut().unwrap().remove("incarnation");
    let older: PersistedState = serde_json::from_value(json).unwrap();
    assert_eq!(older.incarnation, Incarnation::FIRST);

    // The last number is never wrapped.
    let last = PersistedState {
        incarnation: Incarnation::new(u64::MAX),
        ..first
    };
    let Err(failure) = TestCoordinator::recover(
        last,
        Arc::clone(&world.clock),
        session(5),
        world.ledger.clone(),
        &mut world.port,
    ) else {
        panic!("recovered past the last incarnation");
    };
    assert_eq!(failure.error, CoordinationError::IncarnationsExhausted);
}

#[test]
fn weights_reserved_apart_pass_to_a_successor_without_the_predecessors_kv() {
    let mut world = World::new();
    let grant = world.running();
    let weights = world
        .coordinator
        .reserve_weights(
            &world.execution,
            world.model,
            BTreeMap::from([(device(), 8 * GIB)]),
        )
        .unwrap();
    let base = weights[&device()];
    assert_eq!(base, gpu_holding(1));
    assert!(world.holding(base).holds_weights());
    assert!(world.holding(base).users().is_empty());

    let with_kv = |kv_bytes: u64| ActivationDemand {
        gpu_memory_bytes: BTreeMap::from([(device(), kv_bytes)]),
        acquire: BTreeSet::from([base]),
        ..ActivationDemand::default()
    };
    let first = world.begin_with(grant, with_kv(4 * GIB)).unwrap();
    world.complete(1);
    let second = world.begin_with(grant, with_kv(4 * GIB)).unwrap();
    assert_eq!(second.acquired, BTreeSet::from([base]));
    assert_eq!(
        first.allocated[&device()],
        GpuAllocationGeneration::new(2),
        "the first generation's own KV"
    );
    assert_eq!(
        world.ledger.held(),
        BTreeSet::from([
            sandbox_key(&world.execution, 1),
            world.model_gpu(1),
            world.model_gpu(2),
            world.model_gpu(3),
        ]),
        "8 GiB of weights counted once, with 4 GiB of KV per generation"
    );

    // The first generation drains: its KV goes, the shared weights stay.
    world.complete(2);
    assert_eq!(
        world.ledger.state_of(&world.model_gpu(2)),
        Some(FakeState::Releasing)
    );
    assert_eq!(
        world.ledger.state_of(&world.model_gpu(1)),
        Some(FakeState::InUse)
    );
    world.confirm(1, SourceClass::GuestReport).unwrap();
    assert!(!world.ledger.is_held(&world.model_gpu(2)));
    assert!(world.ledger.is_held(&world.model_gpu(1)));

    // With no activation left the weights stay reserved until released.
    assert_eq!(
        world.coordinator.release_unused_holding(
            &world.execution,
            world.model,
            base,
            SourceClass::GuestReport
        ),
        Err(ModelRefusal::HoldingInUse { holding: base })
    );
    world
        .coordinator
        .evict(&world.execution, world.model, generation(2))
        .unwrap();
    world.confirm(2, SourceClass::GuestReport).unwrap();
    assert_eq!(
        world.ledger.state_of(&world.model_gpu(1)),
        Some(FakeState::InUse)
    );
    assert_eq!(
        world.coordinator.release_unused_holding(
            &world.execution,
            world.model,
            base,
            SourceClass::RecordedDeclaration
        ),
        Err(ModelRefusal::Capacity {
            refusal: CapacityRefusal::SourceTooWeak {
                source: SourceClass::RecordedDeclaration,
                required: SourceClass::GuestReport,
            }
        })
    );
    world
        .coordinator
        .release_unused_holding(
            &world.execution,
            world.model,
            base,
            SourceClass::GuestReport,
        )
        .unwrap();
    assert_eq!(
        world.ledger.held(),
        BTreeSet::from([sandbox_key(&world.execution, 1)])
    );
    assert_eq!(
        world.coordinator.reserve_weights(
            &world.execution,
            world.model,
            BTreeMap::from([(device(), 0)])
        ),
        Err(ModelRefusal::InvalidDemand {
            problem: DemandProblem::ZeroGpuMemory { device: device() }
        })
    );
}

#[test]
fn a_parked_activation_keeps_its_memory_for_a_reactivation() {
    let mut world = World::new();
    let (grant, first) = world.serving();
    let busy = world.request("op-busy", terms(30, 120, 1));
    assert_eq!(
        world
            .coordinator
            .park(&world.execution, world.model, generation(1)),
        Err(ModelRefusal::RequestsInFlight {
            activation: generation(1),
            leases: vec![busy.id()],
        })
    );
    world.coordinator.finish_request(busy.id()).unwrap();
    assert_eq!(
        world
            .coordinator
            .park(&world.execution, world.model, generation(1)),
        Ok(first.generations)
    );
    assert_eq!(
        world.activation(1).state(),
        ActivationState::Retired {
            reason: RetireReason::Parked
        }
    );
    assert_eq!(
        world.ledger.state_of(&world.model_gpu(1)),
        Some(FakeState::InUse),
        "parking frees nothing"
    );
    assert_eq!(
        world.holding(gpu_holding(1)).retention(),
        Retention::KeepUntilReleased
    );
    assert_eq!(world.sandbox().authority(), Some(grant));

    let calls = world.ledger.calls().len();
    let settings = world.settings(grant);
    world
        .coordinator
        .reactivate(&world.execution, world.model, settings, generation(1))
        .unwrap();
    assert_eq!(world.ledger.calls().len(), calls, "no new reservation");
    assert_eq!(
        world
            .coordinator
            .park(&world.execution, world.model, generation(2)),
        Err(ModelRefusal::InvalidActivationTransition {
            activation: generation(2),
            state: ActivationState::Loading,
            step: ActivationStep::Park,
        })
    );
    world.complete(2);
}

#[test]
fn the_authority_record_supplies_the_settings_a_revert_is_judged_against() {
    let mut world = World::new();
    let (grant, _) = world.serving();
    assert_eq!(
        world
            .coordinator
            .authorized_settings(&world.execution, world.model),
        Ok(settings_for(grant))
    );
    let other = ModelId::new(named("yougori/test/model/v1", "other-model"));
    assert_eq!(
        world
            .coordinator
            .authorized_settings(&world.execution, other),
        Err(ModelRefusal::NoPriorActivation { model: other })
    );
    world.coordinator.revoke(&world.execution).unwrap();
    assert!(matches!(
        world
            .coordinator
            .authorized_settings(&world.execution, world.model),
        Err(ModelRefusal::Parent { .. })
    ));
}

#[test]
fn weights_reserved_apart_are_never_handed_over_by_a_drain_first_change() {
    let mut world = World::new();
    let grant = world.running();
    let base = world
        .coordinator
        .reserve_weights(
            &world.execution,
            world.model,
            BTreeMap::from([(device(), 8 * GIB)]),
        )
        .unwrap()[&device()];
    world
        .begin_with(
            grant,
            ActivationDemand {
                gpu_memory_bytes: BTreeMap::from([(device(), 4 * GIB)]),
                acquire: BTreeSet::from([base]),
                ..ActivationDemand::default()
            },
        )
        .unwrap();
    world.complete(1);
    let settings = world.settings(grant);
    let second = world
        .coordinator
        .begin_drain_first(
            &world.execution,
            world.model,
            settings,
            ActivationDemand::gpu(gpu(10 * GIB)),
            generation(1),
        )
        .unwrap();
    assert_eq!(second.awaiting_handover, Some(generation(1)));
    assert_eq!(
        world.holding(gpu_holding(2)).promised_to(),
        Some((generation(2), gpu_holding(3))),
        "the predecessor's own KV passes on"
    );
    assert_eq!(
        world.holding(base).promised_to(),
        None,
        "the weights stay the model's"
    );
}

// Integration round 2: labelled runtimes' authority records (T13 decision 4) and the
// clock high-water mark of lease checks (V05).

/// A clock a test can set anywhere, backward included.
#[derive(Debug, Default)]
struct SettableClock(std::sync::atomic::AtomicU64);

impl SettableClock {
    fn set(&self, to: MonotonicTime) {
        self.0
            .store(to.as_nanos(), std::sync::atomic::Ordering::SeqCst);
    }
}

impl Clock for SettableClock {
    fn now(&self) -> MonotonicTime {
        MonotonicTime::from_nanos(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}

#[test]
fn a_clock_that_goes_back_extends_no_lease_and_revives_none() {
    let mut world = World::new();
    let clock = Arc::new(SettableClock::default());
    clock.set(at(100));
    let mut coordinator = Coordinator::new(Arc::clone(&clock), session(1), host_ledger());
    let plan = world.plan();
    let LaunchOutcome::AuthorityActive { .. } = coordinator
        .launch_with(
            plan,
            world_grant(),
            &mut world.port,
            &world.evidence.registry,
        )
        .unwrap()
    else {
        panic!("not launched");
    };
    let of = world.execution.clone();
    let child = |coordinator: &mut Coordinator<Arc<SettableClock>, FakeLedger>, name| {
        coordinator.start_child_work(
            &of,
            operation(name),
            LeaseKind::ChildWork,
            terms(60, 600, 1),
        )
    };
    let expired = child(&mut coordinator, "op-a").unwrap();
    clock.set(at(200));
    assert_eq!(
        coordinator.check_lease(expired.id()),
        Err(LeaseRefusal::Expired {
            expired_at: at(160)
        })
    );
    let live = child(&mut coordinator, "op-b").unwrap();

    // The clock goes back to before both expiries: nothing is honoured, renewed or issued
    // until it passes its high-water mark again.
    clock.set(at(150));
    let went_back = LeaseRefusal::ClockWentBack {
        now: at(150),
        high_water: at(200),
    };
    assert_eq!(
        coordinator.check_lease(expired.id()),
        Err(went_back.clone()),
        "an expired lease is never revived"
    );
    assert_eq!(coordinator.check_lease(live.id()), Err(went_back.clone()));
    assert_eq!(
        coordinator.renew_lease(live.id()),
        Err(went_back.clone()),
        "nor is a live one extended"
    );
    assert_eq!(child(&mut coordinator, "op-c"), Err(went_back.clone()));
    assert_eq!(coordinator.clock_high_water(), at(200));
    assert_eq!(
        coordinator.now(),
        at(150),
        "the clock itself is read as it is"
    );

    // Forward again, every lease is where a monotonic clock would have it.
    clock.set(at(230));
    assert_eq!(
        coordinator.check_lease(expired.id()),
        Err(LeaseRefusal::Expired {
            expired_at: at(160)
        })
    );
    assert!(coordinator.check_lease(live.id()).is_ok());
    clock.set(at(270));
    assert_eq!(
        coordinator.check_lease(live.id()),
        Err(LeaseRefusal::Expired {
            expired_at: at(260)
        })
    );
}

#[test]
fn a_labelled_runtime_has_an_authority_record_its_reverts_are_judged_against() {
    let mut world = World::new();
    let shared = runtime(ExecutionCategory::SharedKernelGpuRuntime, "wsl-cuda");
    let admitted = world.evidence.admit(&shared);
    let of = execution("exe-labelled");
    let authorization = LabelledAuthorization {
        execution: of.clone(),
        tenant: tenant(),
        runtime: admitted,
        authority_lifetime: 600 * SECOND,
        runtime_evidence_max_age: HOUR,
        settings: world_grant(),
    };
    let grant = world
        .coordinator
        .authorize_labelled(authorization.clone(), &world.evidence.registry)
        .unwrap();
    assert_eq!(grant.epoch, AuthorizationEpoch::FIRST);
    assert_eq!(
        world
            .coordinator
            .authorize_labelled(authorization.clone(), &world.evidence.registry),
        Ok(grant),
        "authorizing again changes nothing"
    );

    // The model's settings are recorded in the runtime's own category, within its grant.
    let settings = RuntimeSettings {
        execution_category: ExecutionCategory::SharedKernelGpuRuntime,
        loader: BTreeSet::new(),
        ..settings_for(grant)
    };
    assert_eq!(
        world.coordinator.authorize_labelled_model(
            &of,
            world.model,
            RuntimeSettings {
                execution_category: ExecutionCategory::VmSandbox,
                ..settings.clone()
            }
        ),
        Err(ModelRefusal::CategoryMismatch {
            parent: ExecutionCategory::SharedKernelGpuRuntime,
            settings: ExecutionCategory::VmSandbox,
        })
    );
    assert_eq!(
        world.coordinator.authorize_labelled_model(
            &of,
            world.model,
            RuntimeSettings {
                loader: BTreeSet::from([Optimization::IoUring]),
                ..settings.clone()
            }
        ),
        Err(ModelRefusal::LoaderNotGranted {
            optimizations: BTreeSet::from([Optimization::IoUring])
        })
    );
    world
        .coordinator
        .authorize_labelled_model(&of, world.model, settings.clone())
        .unwrap();
    assert_eq!(
        world.coordinator.authorized_settings(&of, world.model),
        Ok(settings.clone())
    );

    // T13's revert takes them from the record, in the labelled runtime's category.
    let gate = LoaderGate::recorded();
    let plan = world.evidence.loader_plan(&gate, &shared);
    let reverted = crate::model_memory::profiles::AuthorizedRuntime::from_authority(
        &gate,
        &world.evidence.registry,
        &plan,
        &world.coordinator,
        &of,
        &world.model,
    )
    .unwrap();
    assert_eq!(
        reverted.settings().execution_category,
        ExecutionCategory::SharedKernelGpuRuntime
    );

    // A VM sandbox is launched, never recorded as a labelled runtime, and the labelled
    // execution never gets the VM sandbox lifecycle.
    let vm_runtime = world.runtime.clone();
    let vm = LabelledAuthorization {
        execution: execution("exe-vm"),
        runtime: world.evidence.admit(&vm_runtime),
        ..authorization.clone()
    };
    assert_eq!(
        world
            .coordinator
            .authorize_labelled(vm, &world.evidence.registry),
        Err(CoordinationError::NotALabelledRuntime {
            category: ExecutionCategory::VmSandbox
        })
    );
    let launch = LaunchPlan {
        execution: of.clone(),
        ..world.plan()
    };
    assert_eq!(
        world
            .coordinator
            .launch(launch, &mut world.port, &world.evidence.registry),
        Err(CoordinationError::NotAVmSandbox {
            category: ExecutionCategory::SharedKernelGpuRuntime
        })
    );

    // Revocation raises the epoch: nothing authorized under the old grant counts again.
    assert!(world.coordinator.labelled_authority(&of).is_ok());
    assert_eq!(
        world.coordinator.revoke_labelled(&of),
        Ok(AuthorizationEpoch::new(2))
    );
    assert_eq!(
        world.coordinator.labelled_authority(&of),
        Err(LeaseRefusal::RevokedAuthorization {
            bound: AuthorizationEpoch::FIRST,
            current: AuthorizationEpoch::new(2),
        })
    );
    assert_eq!(
        world.coordinator.labelled_authority(&execution("unknown")),
        Err(LeaseRefusal::UnknownExecution {
            execution: execution("unknown"),
        })
    );
    assert_eq!(
        world.coordinator.revoke_labelled(&of),
        Ok(AuthorizationEpoch::new(2))
    );
    assert_eq!(
        world.coordinator.authorized_settings(&of, world.model),
        Err(ModelRefusal::Parent {
            refusal: LeaseRefusal::RevokedAuthorization {
                bound: AuthorizationEpoch::FIRST,
                current: AuthorizationEpoch::new(2),
            }
        })
    );
    let regranted = world
        .coordinator
        .authorize_labelled(authorization.clone(), &world.evidence.registry)
        .unwrap();
    assert_eq!(regranted.epoch, AuthorizationEpoch::new(2));
    assert_eq!(
        world.coordinator.authorized_settings(&of, world.model),
        Err(ModelRefusal::NoPriorActivation { model: world.model }),
        "the model's settings are authorized again"
    );

    // An expired authority is granted again under a new epoch.
    world.advance(601);
    let renewed = world
        .coordinator
        .authorize_labelled(authorization, &world.evidence.registry)
        .unwrap();
    assert_eq!(renewed.epoch, AuthorizationEpoch::new(3));

    // A VM sandbox's record names its own category, as before.
    let (vm_grant, _) = world.serving();
    assert_eq!(
        world
            .coordinator
            .authorized_settings(&world.execution, world.model)
            .map(|settings| settings.execution_category),
        Ok(ExecutionCategory::VmSandbox)
    );
    assert_eq!(vm_grant.epoch, AuthorizationEpoch::FIRST);
}

#[test]
fn external_effects_acknowledge_their_own_revocation_milestones() {
    let mut world = World::new();
    world.serving();
    let of = world.execution.clone();
    assert_eq!(
        world.coordinator.acknowledge_revocation(
            &of,
            RevocationMilestone::SocketsClosed,
            SourceClass::HostProbe
        ),
        Err(CoordinationError::NotRevoking {
            state: SandboxState::Running
        })
    );
    world.coordinator.revoke(&of).unwrap();
    world.advance(1);
    assert_eq!(
        world.coordinator.acknowledge_revocation(
            &of,
            RevocationMilestone::SocketsClosed,
            SourceClass::GuestReport
        ),
        Err(CoordinationError::AcknowledgmentTooWeak {
            milestone: RevocationMilestone::SocketsClosed,
            source: SourceClass::GuestReport,
            required: SourceClass::HostProbe,
        })
    );
    assert_eq!(
        world.coordinator.acknowledge_revocation(
            &of,
            RevocationMilestone::SocketsClosed,
            SourceClass::HostProbe
        ),
        Ok(at(101))
    );
    world.advance(1);
    assert_eq!(
        world.coordinator.acknowledge_revocation(
            &of,
            RevocationMilestone::SocketsClosed,
            SourceClass::HostProbe
        ),
        Ok(at(101)),
        "recorded once, at the first acknowledgment"
    );
    assert_eq!(
        world.coordinator.acknowledge_revocation(
            &of,
            RevocationMilestone::ProviderStoppedBilling,
            SourceClass::ProviderApi
        ),
        Ok(at(102))
    );
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
    let milestones = world.coordinator.revocation(&of).unwrap().milestones();
    assert_eq!(milestones[&RevocationMilestone::SocketsClosed], at(101));
    assert_eq!(
        milestones[&RevocationMilestone::ProviderStoppedBilling],
        at(102)
    );
    assert!(!milestones.contains_key(&RevocationMilestone::VmStopped));
}

// Round 3: revocation of one grant, and the first denied authorization and all channels
// closed as milestones.

/// A scoped delegation under the sandbox's authority, by the identity the host assigned.
fn delegation(name: &str) -> GrantId {
    GrantId::from_digest(named("yougori/test/delegation/v1", name))
}

/// A second model, served under the tool route.
fn tool_model() -> ModelId {
    ModelId::new(named("yougori/test/model/v1", "tool-model"))
}

/// What a sandbox granting two routes lets its models use.
fn two_routes() -> SettingsGrant {
    SettingsGrant {
        network: BTreeSet::from([route("model-download"), route("tool-api")]),
        ..world_grant()
    }
}

impl World {
    /// Launched under `settings`, running, with the chat model serving under the download
    /// route and the tool model under the tool route.
    fn serving_two(&mut self, settings: SettingsGrant) -> AuthorityGrant {
        let plan = self.plan();
        let grant = match self
            .coordinator
            .launch_with(plan, settings, &mut self.port, &self.evidence.registry)
            .unwrap()
        {
            LaunchOutcome::AuthorityActive { grant, .. } => grant,
            other => panic!("{other:?}"),
        };
        self.grant_loader();
        self.coordinator.start_running(&self.execution).unwrap();
        for (model, network, memory) in [
            (self.model, route("model-download"), 10 * GIB),
            (tool_model(), route("tool-api"), 4 * GIB),
        ] {
            let settings = RuntimeSettings {
                network: BTreeSet::from([network]),
                ..settings_for(grant)
            };
            let handle = self
                .coordinator
                .begin_activation(&self.execution, model, settings, gpu(memory))
                .unwrap();
            self.coordinator
                .complete_activation(&self.execution, model, handle.generations.activation)
                .unwrap();
        }
        grant
    }

    fn granted(&mut self, name: &str, kind: LeaseKind, grants: &[GrantId]) -> Lease {
        self.coordinator
            .start_granted_work(
                &self.execution,
                operation(name),
                kind,
                terms(60, 600, 2),
                grants.iter().copied().collect(),
            )
            .unwrap()
    }
}

#[test]
fn network_grant_ids_name_the_kind_and_the_target() {
    let target = named("yougori/test/route/v1", "shared");
    let ids = [
        network_grant_id(&NetworkGrant::NamedRoute { route: target }),
        network_grant_id(&NetworkGrant::CredentialedOperation { operation: target }),
        network_grant_id(&NetworkGrant::PublishedService { service: target }),
    ];
    assert_eq!(
        BTreeSet::from(ids).len(),
        3,
        "each kind has its own identity"
    );
    assert_eq!(
        ids[0],
        network_grant_id(&NetworkGrant::NamedRoute { route: target })
    );
    assert_ne!(ids[0], network_grant_id(&route("other")));
    assert!(!ids.contains(&GrantId::from_digest(target)));
}

#[test]
fn an_absolute_child_deadline_caps_both_issue_and_every_renewal() {
    let mut world = World::new();
    world.launched();
    let deadline = world.clock.now().saturating_add(10 * SECOND);
    // Simulate work/queue delay between calculating the external deadline and issue.
    world.advance(3);
    let lease = world
        .coordinator
        .start_granted_work_until(
            &world.execution,
            operation("bounded-issue"),
            LeaseKind::Service,
            terms(60, 600, 1),
            BTreeSet::new(),
            Some(deadline),
        )
        .unwrap();
    assert_eq!(lease.expires_at(), deadline);
    world.advance(2);
    assert!(matches!(world.coordinator.renew_lease(lease.id()),
        Err(LeaseRefusal::RenewalLimitReached { expires_at, .. }) if expires_at == deadline));
    world.advance(5);
    assert!(matches!(world.coordinator.check_lease(lease.id()),
        Err(LeaseRefusal::Expired { expired_at }) if expired_at == deadline));
    assert!(matches!(world.coordinator.start_granted_work_until(
        &world.execution, operation("queued-too-late"), LeaseKind::Service,
        terms(60, 600, 1), BTreeSet::new(), Some(deadline),
    ), Err(LeaseRefusal::Expired { expired_at }) if expired_at == deadline));
}

#[test]
fn revoking_one_grant_cancels_only_what_is_bound_to_it_and_keeps_the_epoch() {
    let mut world = World::new();
    world.serving_two(two_routes());
    let of = world.execution.clone();
    let download = network_grant_id(&route("model-download"));
    let tool_route = network_grant_id(&route("tool-api"));
    let delegated = world.granted(
        "op-delegated",
        LeaseKind::ChildWork,
        &[delegation("deploy")],
    );
    let routed = world.granted("op-routed", LeaseKind::Transfer, &[tool_route]);
    let both = world.granted(
        "op-both",
        LeaseKind::Service,
        &[delegation("deploy"), download],
    );
    let plain = world.child("op-plain", LeaseKind::ChildWork, terms(60, 600, 1));
    let chat = world.request("op-chat", terms(30, 600, 1));
    let tool = world
        .coordinator
        .admit_request(&of, tool_model(), operation("op-tool"), terms(30, 600, 1))
        .unwrap();
    assert_eq!(
        both.grants(),
        &BTreeSet::from([delegation("deploy"), download])
    );
    assert!(plain.grants().is_empty());
    let generations = world.sandbox().generations();
    world.advance(10);

    // The delegation: its two leases are cancelled by their bounds, nothing else is.
    let revoked = world
        .coordinator
        .revoke_grant(&of, delegation("deploy"))
        .unwrap();
    assert_eq!(revoked.execution, of);
    assert_eq!(revoked.epoch, AuthorizationEpoch::FIRST);
    assert_eq!(revoked.at, at(110));
    assert_eq!(revoked.network, None);
    assert!(revoked.activations.is_empty());
    let bounds: Vec<(LeaseId, MonotonicTime)> = revoked
        .cancellations
        .iter()
        .map(|cancellation| (cancellation.lease, cancellation.bound_at))
        .collect();
    assert_eq!(bounds, [(delegated.id(), at(112)), (both.id(), at(112))]);
    assert_eq!(world.sandbox().generations(), generations);
    assert_eq!(world.sandbox().state(), SandboxState::Running);
    assert!(world.coordinator.revocation(&of).is_none());
    for lease in [&delegated, &both] {
        assert_eq!(
            world.coordinator.check_lease(lease.id()),
            Err(LeaseRefusal::Cancelled {
                cause: CancelCause::GrantRevoked
            })
        );
    }
    for lease in [&routed, &plain, &chat, &tool] {
        assert!(world.coordinator.check_lease(lease.id()).is_ok());
    }
    assert!(world.coordinator.grant_revoked(&of, delegation("deploy")));
    assert!(!world.coordinator.grant_revoked(&of, delegation("other")));
    world.advance(1);
    assert_eq!(
        world.coordinator.revoke_grant(&of, delegation("deploy")),
        Ok(revoked.clone()),
        "revoking again returns the same record"
    );
    assert_eq!(
        world.coordinator.revoked_grant(&of, delegation("deploy")),
        Some(&revoked)
    );

    // The download route: the chat model's request is cancelled with it, and the chat
    // model admits nothing more; the tool model and the other route keep serving.
    let revoked = world.coordinator.revoke_grant(&of, download).unwrap();
    assert_eq!(revoked.network, Some(route("model-download")));
    let chat_activation = world.activation(1).generations();
    assert_eq!(
        revoked.activations,
        [ModelBinding {
            model: world.model,
            generations: chat_activation,
        }]
    );
    let cancelled: Vec<LeaseId> = revoked
        .cancellations
        .iter()
        .map(|cancellation| cancellation.lease)
        .collect();
    assert_eq!(
        cancelled,
        [chat.id()],
        "a lease already cancelled stays as it is"
    );
    assert_eq!(
        world.sandbox().settings_grant().network,
        BTreeSet::from([route("tool-api")])
    );
    assert_eq!(
        world.coordinator.admit_request(
            &of,
            world.model,
            operation("op-chat-2"),
            terms(30, 600, 1)
        ),
        Err(ModelRefusal::Parent {
            refusal: LeaseRefusal::GrantRevoked { grant: download }
        })
    );
    assert!(world
        .coordinator
        .admit_request(&of, tool_model(), operation("op-tool-2"), terms(30, 600, 1))
        .is_ok());
    for lease in [&routed, &plain, &tool] {
        assert!(world.coordinator.check_lease(lease.id()).is_ok());
    }
    assert_eq!(world.sandbox().generations(), generations);
}

#[test]
fn a_revoked_grant_is_never_honoured_again() {
    let mut world = World::new();
    let grant = world.serving_two(two_routes());
    let of = world.execution.clone();
    let download = network_grant_id(&route("model-download"));
    let routed = world.granted("op-routed", LeaseKind::Transfer, &[download]);
    world.coordinator.revoke_grant(&of, download).unwrap();
    world
        .coordinator
        .revoke_grant(&of, delegation("deploy"))
        .unwrap();

    // No lease under it is issued, honoured or renewed; other grants still are.
    for grants in [vec![delegation("deploy")], vec![delegation("ok"), download]] {
        assert!(matches!(
            world.coordinator.start_granted_work(
                &of,
                operation("op-again"),
                LeaseKind::ChildWork,
                terms(60, 600, 1),
                grants.into_iter().collect(),
            ),
            Err(LeaseRefusal::GrantRevoked { .. })
        ));
    }
    assert!(world
        .coordinator
        .start_granted_work(
            &of,
            operation("op-ok"),
            LeaseKind::ChildWork,
            terms(60, 600, 1),
            BTreeSet::from([delegation("ok")]),
        )
        .is_ok());
    assert_eq!(
        world.coordinator.renew_lease(routed.id()),
        Err(LeaseRefusal::Cancelled {
            cause: CancelCause::GrantRevoked
        })
    );
    // Its network grant is not granted to a new activation, nor in the authorized
    // settings a fallback is judged against.
    assert_eq!(
        world
            .coordinator
            .begin_activation(&of, world.model, settings_for(grant), gpu(GIB))
            .map(|_| ()),
        Err(ModelRefusal::NetworkNotGranted {
            grants: BTreeSet::from([route("model-download")])
        })
    );
    assert_eq!(
        world
            .coordinator
            .authorized_settings(&of, tool_model())
            .unwrap()
            .network,
        BTreeSet::from([route("tool-api")])
    );

    // A relaunch grants the last settings again, without the route.
    world.stop();
    world.relaunch(CompositeRecovery::default(), None);
    assert_eq!(
        world.sandbox().settings_grant().network,
        BTreeSet::from([route("tool-api")])
    );
    assert!(world.coordinator.grant_revoked(&of, download));

    // Recovery keeps the tombstones, and a fresh authority never grants the route again.
    let state = world.coordinator.persist();
    assert_eq!(
        state.revoked_grants,
        BTreeMap::from([(of.clone(), BTreeSet::from([download, delegation("deploy")]))])
    );
    let json = serde_json::to_value(&state).unwrap();
    assert_eq!(
        serde_json::from_value::<PersistedState>(json.clone()).unwrap(),
        state
    );
    let mut older = json;
    older.as_object_mut().unwrap().remove("revoked_grants");
    assert!(serde_json::from_value::<PersistedState>(older)
        .unwrap()
        .revoked_grants
        .is_empty());
    world.coordinator = recover_from(&mut world, state, 2);
    assert!(world.coordinator.grant_revoked(&of, download));
    assert!(world.coordinator.revoked_grant(&of, download).is_none());
    let plan = world.plan();
    world
        .coordinator
        .launch_with(
            plan,
            two_routes(),
            &mut world.port,
            &world.evidence.registry,
        )
        .unwrap();
    assert_eq!(world.sandbox().state(), SandboxState::AuthorityActive);
    assert_eq!(
        world.sandbox().settings_grant().network,
        BTreeSet::from([route("tool-api")])
    );
    let confirmed = world.coordinator.persist();
    world.coordinator.confirm_persisted(&confirmed);
    assert!(matches!(
        world.coordinator.start_granted_work(
            &of,
            operation("op-after"),
            LeaseKind::ChildWork,
            terms(60, 600, 1),
            BTreeSet::from([delegation("deploy")]),
        ),
        Err(LeaseRefusal::GrantRevoked { .. })
    ));
    assert!(world
        .coordinator
        .start_granted_work(
            &of,
            operation("op-other"),
            LeaseKind::ChildWork,
            terms(60, 600, 1),
            BTreeSet::from([delegation("ok")]),
        )
        .is_ok());
}

#[test]
fn a_labelled_runtimes_grant_is_revoked_without_its_epoch() {
    let mut world = World::new();
    let shared = runtime(ExecutionCategory::SharedKernelGpuRuntime, "wsl-cuda");
    let of = execution("exe-labelled");
    let authorization = LabelledAuthorization {
        execution: of.clone(),
        tenant: tenant(),
        runtime: world.evidence.admit(&shared),
        authority_lifetime: 600 * SECOND,
        runtime_evidence_max_age: HOUR,
        settings: two_routes(),
    };
    let grant = world
        .coordinator
        .authorize_labelled(authorization.clone(), &world.evidence.registry)
        .unwrap();
    let download = network_grant_id(&route("model-download"));
    let revoked = world.coordinator.revoke_grant(&of, download).unwrap();
    assert_eq!(revoked.epoch, AuthorizationEpoch::FIRST);
    assert_eq!(revoked.network, Some(route("model-download")));
    assert!(revoked.cancellations.is_empty());
    let record = world.coordinator.labelled_runtime(&of).unwrap();
    assert_eq!(record.epoch(), AuthorizationEpoch::FIRST);
    assert_eq!(
        record.settings_grant().network,
        BTreeSet::from([route("tool-api")])
    );
    assert_eq!(world.coordinator.labelled_authority(&of), Ok(grant));
    let settings = RuntimeSettings {
        execution_category: ExecutionCategory::SharedKernelGpuRuntime,
        loader: BTreeSet::new(),
        ..settings_for(grant)
    };
    assert_eq!(
        world
            .coordinator
            .authorize_labelled_model(&of, world.model, settings),
        Err(ModelRefusal::NetworkNotGranted {
            grants: BTreeSet::from([route("model-download")])
        })
    );

    // A new authority after a revocation never grants the route again.
    world.coordinator.revoke_labelled(&of).unwrap();
    world
        .coordinator
        .authorize_labelled(authorization, &world.evidence.registry)
        .unwrap();
    assert_eq!(
        world
            .coordinator
            .labelled_runtime(&of)
            .unwrap()
            .settings_grant()
            .network,
        BTreeSet::from([route("tool-api")])
    );
    assert_eq!(
        world
            .coordinator
            .revoke_grant(&execution("exe-unknown"), download),
        Err(CoordinationError::UnknownExecution {
            execution: execution("exe-unknown")
        })
    );
}

#[test]
fn a_grant_revocation_takes_the_revocation_path_onto_the_event_plane() {
    let mut world = World::new();
    world.serving_two(two_routes());
    let of = world.execution.clone();
    let delegated = world.granted(
        "op-delegated",
        LeaseKind::ChildWork,
        &[delegation("deploy")],
    );
    let mut plane = Plane::new(&world.clock);
    let published = world
        .coordinator
        .revoke_grant_and_publish(
            &of,
            delegation("deploy"),
            operation("op-revoke-grant"),
            RevocationReason::SecurityEvent,
            &mut plane.events(),
        )
        .unwrap();
    assert_eq!(published.lane, Ok(RevocationAdmission::Queued));
    assert!(published.audit.is_ok());
    assert_eq!(published.revoked.cancellations.len(), 1);
    assert_eq!(published.revoked.cancellations[0].lease, delegated.id());
    assert_eq!(world.sandbox().state(), SandboxState::Running);

    let revoked = GrantRevocation {
        execution: of.clone(),
        grant: delegation("deploy"),
        epoch: AuthorizationEpoch::FIRST,
        reason: RevocationReason::SecurityEvent,
    };
    let delivery = plane.hub.drain(16);
    assert!(delivery.revocations.notices.is_empty(), "the epoch stays");
    assert_eq!(delivery.revocations.grants.len(), 1);
    let event = &delivery.revocations.grants[0];
    assert_eq!(event.payload(), &revoked);
    assert_eq!(event.phase(), Phase::Revoked);
    assert_eq!(
        event.generations().authorization,
        Some(AuthorizationEpoch::FIRST)
    );
    {
        let records = plane.stored.0.borrow();
        assert_eq!(records.len(), 1);
        assert!(matches!(
            records[0].event().payload(),
            AuditEntry::GrantRevocation { revocation } if *revocation == revoked
        ));
    }

    // The whole revocation still takes its own path afterwards.
    let published = world
        .coordinator
        .revoke_and_publish(
            &of,
            operation("op-revoke"),
            RevocationReason::SecurityEvent,
            &mut plane.events(),
        )
        .unwrap();
    assert_eq!(published.notice.current, AuthorizationEpoch::new(2));
    assert_eq!(plane.hub.drain(16).revocations.notices.len(), 1);
}

#[test]
fn all_channels_closed_implies_sockets_closed_and_never_the_reverse() {
    let mut world = World::new();
    world.serving();
    let of = world.execution.clone();
    world.coordinator.revoke(&of).unwrap();
    world.advance(1);
    assert_eq!(
        world.coordinator.acknowledge_revocation(
            &of,
            RevocationMilestone::AllChannelsClosed,
            SourceClass::GuestReport
        ),
        Err(CoordinationError::AcknowledgmentTooWeak {
            milestone: RevocationMilestone::AllChannelsClosed,
            source: SourceClass::GuestReport,
            required: SourceClass::HostProbe,
        })
    );
    assert_eq!(
        world.coordinator.acknowledge_revocation(
            &of,
            RevocationMilestone::AllChannelsClosed,
            SourceClass::HostProbe
        ),
        Ok(at(101))
    );
    world.advance(1);
    assert_eq!(
        world.coordinator.acknowledge_revocation(
            &of,
            RevocationMilestone::SocketsClosed,
            SourceClass::HostProbe
        ),
        Ok(at(101)),
        "every channel closed includes every socket"
    );
    let revocation = world.coordinator.revocation(&of).unwrap();
    assert_eq!(
        revocation.milestone(RevocationMilestone::SocketsClosed),
        Some(at(101))
    );
    assert_eq!(
        revocation.milestone_source(RevocationMilestone::SocketsClosed),
        Some(MilestoneSource::ImpliedBy {
            by: RevocationMilestone::AllChannelsClosed,
            source: SourceClass::HostProbe,
        })
    );
    assert_eq!(
        revocation.milestone_source(RevocationMilestone::AllChannelsClosed),
        Some(MilestoneSource::Acknowledged {
            source: SourceClass::HostProbe
        })
    );

    // Sockets closed first: all channels closed is not implied, and later stays apart.
    let mut world = World::new();
    world.serving();
    world.coordinator.revoke(&of).unwrap();
    world.advance(1);
    world
        .coordinator
        .acknowledge_revocation(
            &of,
            RevocationMilestone::SocketsClosed,
            SourceClass::HostProbe,
        )
        .unwrap();
    assert_eq!(
        world
            .coordinator
            .revocation(&of)
            .unwrap()
            .milestone(RevocationMilestone::AllChannelsClosed),
        None
    );
    world.advance(2);
    assert_eq!(
        world.coordinator.acknowledge_revocation(
            &of,
            RevocationMilestone::AllChannelsClosed,
            SourceClass::HostProbe
        ),
        Ok(at(103))
    );
    let revocation = world.coordinator.revocation(&of).unwrap();
    let milestones = revocation.milestones();
    assert_eq!(milestones[&RevocationMilestone::SocketsClosed], at(101));
    assert_eq!(milestones[&RevocationMilestone::AllChannelsClosed], at(103));
    assert_eq!(
        revocation.milestone_source(RevocationMilestone::SocketsClosed),
        Some(MilestoneSource::Acknowledged {
            source: SourceClass::HostProbe
        })
    );
    assert_eq!(
        revocation.milestone_source(RevocationMilestone::LeasesClosed),
        None
    );
}

#[test]
fn the_first_denied_authorization_is_recorded_once_with_what_refused_it() {
    let mut world = World::new();
    world.serving();
    let of = world.execution.clone();
    let held = world.child("op-held", LeaseKind::Service, terms(60, 600, 2));
    // Before any revocation a refusal is no milestone of one.
    assert!(world
        .coordinator
        .check_presented_lease(held.id(), session(9))
        .is_err());
    world.advance(5);
    world.coordinator.revoke(&of).unwrap();
    let first = |world: &World| {
        world
            .coordinator
            .revocation(&of)
            .unwrap()
            .first_denied_authorization()
            .cloned()
    };

    // Refusals of a request for its own sake are not denials of the revoked authority.
    let mut zero = terms(60, 600, 1);
    zero.term = Duration::ZERO;
    assert!(matches!(
        world
            .coordinator
            .start_child_work(&of, operation("op-zero"), LeaseKind::ChildWork, zero),
        Err(LeaseRefusal::InvalidTerms { .. })
    ));
    assert_eq!(
        world
            .coordinator
            .check_presented_lease(held.id(), session(9)),
        Err(LeaseRefusal::OtherClock)
    );
    assert_eq!(first(&world), None);

    // An enforcement point's check through a shared reference records the first denial.
    world.advance(2);
    let coordinator: &TestCoordinator = &world.coordinator;
    assert_eq!(
        coordinator.check_presented_lease(held.id(), session(1)),
        Err(LeaseRefusal::Cancelled {
            cause: CancelCause::Revocation
        })
    );
    let denied = DeniedAuthorization {
        at: at(107),
        denial: Denial::Coordinator {
            request: DeniedRequest::LeaseCheck { lease: held.id() },
            refusal: LeaseRefusal::Cancelled {
                cause: CancelCause::Revocation,
            },
        },
    };
    assert_eq!(first(&world), Some(denied.clone()));

    // It is recorded once: later refusals and acknowledgments leave it.
    world.advance(1);
    assert!(world
        .coordinator
        .start_child_work(
            &of,
            operation("op-late"),
            LeaseKind::ChildWork,
            terms(60, 600, 1)
        )
        .is_err());
    assert_eq!(
        world.coordinator.acknowledge_revocation(
            &of,
            RevocationMilestone::FirstDeniedAuthorization,
            SourceClass::GuestReport
        ),
        Err(CoordinationError::AcknowledgmentTooWeak {
            milestone: RevocationMilestone::FirstDeniedAuthorization,
            source: SourceClass::GuestReport,
            required: SourceClass::HostProbe,
        })
    );
    assert_eq!(
        world.coordinator.acknowledge_revocation(
            &of,
            RevocationMilestone::FirstDeniedAuthorization,
            SourceClass::HostProbe
        ),
        Ok(at(107))
    );
    assert_eq!(first(&world), Some(denied));
    let revocation = world.coordinator.revocation(&of).unwrap();
    assert_eq!(
        revocation.milestones()[&RevocationMilestone::FirstDeniedAuthorization],
        at(107)
    );
    assert_eq!(
        revocation.milestone_source(RevocationMilestone::FirstDeniedAuthorization),
        Some(MilestoneSource::Coordinator)
    );
    let json = serde_json::to_value(revocation).unwrap();
    assert_eq!(
        &serde_json::from_value::<RevocationOperation>(json).unwrap(),
        revocation
    );

    // An enforcement point outside the coordinator may refuse first.
    let mut world = World::new();
    world.serving();
    let held = world.child("op-held", LeaseKind::Service, terms(60, 600, 2));
    world.coordinator.revoke(&of).unwrap();
    world.advance(3);
    assert_eq!(
        world.coordinator.acknowledge_revocation(
            &of,
            RevocationMilestone::FirstDeniedAuthorization,
            SourceClass::HostProbe
        ),
        Ok(at(103))
    );
    world.advance(1);
    assert_eq!(
        world.coordinator.check_lease(held.id()),
        Err(LeaseRefusal::Cancelled {
            cause: CancelCause::Revocation
        })
    );
    let revocation = world.coordinator.revocation(&of).unwrap();
    assert_eq!(
        revocation.first_denied_authorization(),
        Some(&DeniedAuthorization {
            at: at(103),
            denial: Denial::EnforcementPoint {
                source: SourceClass::HostProbe
            },
        })
    );
    assert_eq!(
        revocation.milestone_source(RevocationMilestone::FirstDeniedAuthorization),
        Some(MilestoneSource::Acknowledged {
            source: SourceClass::HostProbe
        })
    );

    // A model request refused because the revocation reclaimed its activation counts, with
    // the parent's missing authority as the reason.
    let mut world = World::new();
    world.serving();
    world.coordinator.revoke(&of).unwrap();
    assert_eq!(
        world.coordinator.admit_request(
            &of,
            world.model,
            operation("op-request"),
            terms(30, 600, 1)
        ),
        Err(ModelRefusal::NoServingActivation { model: world.model })
    );
    assert_eq!(
        world
            .coordinator
            .revocation(&of)
            .unwrap()
            .first_denied_authorization()
            .map(|denied| denied.denial.clone()),
        Some(Denial::Coordinator {
            request: DeniedRequest::NewLease {
                kind: LeaseKind::ModelRequest
            },
            refusal: LeaseRefusal::NoAuthority {
                state: SandboxState::Revoking
            },
        })
    );
}

/// S06: the coordinator's revocations on its own durable revocation stream, which survives
/// a restart, never waits behind metrics or audit, and correlates with the lane and the
/// audit log by operation.
mod durable_revocations {
    use std::path::Path;

    use super::*;
    use crate::foundation::events::{
        AuditDraft, Correlated, DeliveryPump, DurableLog, DurableStreamId, EventContext,
        EventSequence, GapReason, HostFact, LogConfig, LogEntry, MetricDraft, MetricValue,
        MetricsProducer, ReadItem, RecordError, RevocationLog, RevocationRecord, SequenceRange,
        SubscriberConfig, Takeover,
    };

    fn log_config() -> LogConfig {
        LogConfig {
            max_entries: 2,
            max_bytes: 1 << 20,
            segment_entries: 1,
            segment_bytes: 1 << 16,
        }
    }

    fn open_log(directory: &Path, owner: &str) -> RevocationLog {
        RevocationLog::open(
            directory,
            DurableStreamId::new("coordinator.revocations").unwrap(),
            ProducerId::new(owner).unwrap(),
            log_config(),
        )
        .unwrap()
        .0
    }

    fn grant(name: &str) -> GrantId {
        GrantId::from_digest(named("yougori/test/grant/v1", name))
    }

    fn hub_config() -> HubConfig {
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
            first_incarnation: ProducerIncarnation::FIRST,
        }
    }

    fn audit_config(spool_records: usize) -> AuditConfig {
        AuditConfig {
            spool_records,
            revocation_reserve_records: 1,
            failure_policy: AuditFailurePolicy::DenyHighImpact,
            guest_observations: EmissionLimit::new(10, SECOND).unwrap(),
            redaction: RedactionPolicy::metadata_only(),
        }
    }

    /// Audit storage that is full and stays full.
    struct FullAudit;

    impl AuditStore for FullAudit {
        fn append(&mut self, _record: &AuditRecord) -> Result<(), StoreRefusal> {
            Err(StoreRefusal::Full)
        }
    }

    /// The restart of S06: revocations a crash kept out of the persisted state are on the
    /// durable stream; its owner is released and reacquired, recovery reads it back from
    /// the cursor stored with the state, restores the lost grant tombstone and ends the
    /// revoked sandbox recovery would otherwise keep for a fresh grant. A reader from the
    /// start meets retention's loss as an explicit gap.
    #[test]
    fn s06_a_restart_rebuilds_the_revocations_the_persisted_state_lacks() {
        let mut world = World::new();
        world.serving();
        let mut plane = Plane::new(&world.clock);
        let directory = tempfile::tempdir().unwrap();
        let mut log = open_log(directory.path(), "coordinator.revocations");
        let of = world.execution.clone();

        // A grant revoked before the state is persisted: the state carries its tombstone.
        let early = world
            .coordinator
            .revoke_grant_and_publish_durably(
                &of,
                grant("early"),
                operation("op-early"),
                RevocationReason::UserRequested,
                &mut plane.events(),
                &mut log,
            )
            .unwrap();
        assert_eq!(early.recorded, Ok(EventSequence::FIRST));
        let mut persisted = world.coordinator.persist();
        world.coordinator.confirm_persisted(&persisted);
        // The stream's cursor is stored with the state.
        let stored = log.log().end();

        // After it, another grant and then the sandbox itself are revoked.
        let late = world
            .coordinator
            .revoke_grant_and_publish_durably(
                &of,
                grant("late"),
                operation("op-late"),
                RevocationReason::SecurityEvent,
                &mut plane.events(),
                &mut log,
            )
            .unwrap();
        assert_eq!(late.recorded, Ok(EventSequence::new(2).unwrap()));
        let revoked = world
            .coordinator
            .revoke_and_publish_durably(
                &of,
                operation("op-revoke"),
                RevocationReason::SecurityEvent,
                &mut plane.events(),
                &mut log,
            )
            .unwrap();
        assert_eq!(revoked.recorded, Ok(EventSequence::new(3).unwrap()));
        assert_eq!(revoked.published.lane, Ok(RevocationAdmission::Queued));
        assert!(revoked.published.audit.is_ok());
        let epoch = revoked.published.notice.current;
        // Retention keeps two entries: the first one is gone from the stream.
        assert_eq!(log.log().retention().low_water, Some(EventSequence::FIRST));

        // The engine stops before it persists again: the stream's owner is released, and
        // the coordinator's revocations in memory are lost.
        log.close().unwrap();
        let (log, report) = RevocationLog::open(
            directory.path(),
            DurableStreamId::new("coordinator.revocations").unwrap(),
            ProducerId::new("coordinator.revocations").unwrap(),
            log_config(),
        )
        .unwrap();
        assert!(matches!(report.takeover, Takeover::Released { .. }));
        assert!(report.markers.is_empty());
        assert_eq!(log.log().owner().incarnation(), Incarnation::new(2));

        // Recovery's reader resumes from the stored cursor: the two later revocations,
        // with no gap.
        let replay = log.replay(&stored).unwrap();
        assert_eq!(replay.records, 2);
        assert!(replay.is_complete());
        let kept: Vec<(u64, OperationId)> = log
            .log()
            .read(&stored, usize::MAX)
            .unwrap()
            .items
            .into_iter()
            .map(|item| match item {
                ReadItem::Entry {
                    sequence,
                    entry: LogEntry::Record(record),
                    ..
                } => (sequence.get(), record.operation().clone()),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            kept,
            [(2, operation("op-late")), (3, operation("op-revoke"))]
        );
        // A reader from the start meets the record retention dropped as a gap.
        let everything = log.replay(&log.log().start()).unwrap();
        assert_eq!(
            everything.gaps,
            [(
                SequenceRange::new(EventSequence::FIRST, EventSequence::FIRST).unwrap(),
                GapReason::Retention
            )]
        );

        // The persisted state lacks the late grant and predates the sandbox's revocation.
        assert_eq!(
            persisted.revoked_grants.get(&of),
            Some(&BTreeSet::from([grant("early")]))
        );
        let rebuilt = persisted.adopt_revocations(&replay);
        assert_eq!(
            rebuilt.tombstones_restored,
            BTreeMap::from([(of.clone(), BTreeSet::from([grant("late")]))])
        );
        assert_eq!(rebuilt.unpersisted.len(), 1);
        assert_eq!(rebuilt.unpersisted[&of].payload().epoch, epoch);
        assert!(rebuilt.gaps.is_empty());
        // Adopting again restores nothing more; the earlier replay only adds its gap.
        let again = persisted.clone().adopt_revocations(&everything);
        assert!(again.tombstones_restored.is_empty());
        assert_eq!(again.gaps.len(), 1);

        // Recovery keeps the live VM without authority and restores both tombstones; the
        // revocation it had received ends the sandbox instead of leaving it for a grant.
        let (mut coordinator, report) = TestCoordinator::recover(
            persisted,
            Arc::clone(&world.clock),
            session(2),
            world.ledger.clone(),
            &mut world.port,
        )
        .unwrap();
        assert!(matches!(
            report.sandboxes.get(&of),
            Some(SandboxRecovery::VmKeptWithoutAuthority { .. })
        ));
        assert!(coordinator.grant_revoked(&of, grant("early")));
        assert!(coordinator.grant_revoked(&of, grant("late")));
        let completed = coordinator.complete_revocations(&rebuilt, &mut world.port);
        assert!(matches!(completed.get(&of), Some(Ok(_))), "{completed:?}");
        assert_eq!(
            coordinator.sandbox(&of).unwrap().state(),
            SandboxState::Stopped
        );
        assert!(coordinator
            .complete_revocations(&rebuilt, &mut world.port)
            .is_empty());
    }

    /// Neither a metrics flood nor audit overload holds up a revocation: the lane takes
    /// it, the durable stream records it while the audit journal refuses, and a slow
    /// subscriber that shed metrics and whole deliveries still gets it first.
    #[test]
    fn s06_metrics_floods_and_audit_overload_never_hold_up_a_revocation_or_its_record() {
        let mut world = World::new();
        world.serving();
        let hub = Arc::new(Mutex::new(
            EventHub::new(Arc::clone(&world.clock), hub_config()).unwrap(),
        ));
        let (mut issuer, mut runner) = {
            let mut hub = hub.lock().unwrap();
            (
                hub.register_revocation_issuer(ProducerId::new("coordinator").unwrap())
                    .unwrap(),
                hub.register_metrics(
                    ProducerId::new("runner").unwrap(),
                    SourceClass::HostProbe,
                    RedactionPolicy::metadata_only(),
                    None,
                )
                .unwrap(),
            )
        };
        let mut pump = DeliveryPump::new(Arc::clone(&hub), 8).unwrap();
        let slow = pump
            .subscribe(SubscriberConfig {
                max_deliveries: 1,
                max_events: 2,
                revocation_reserve: 2,
            })
            .unwrap();
        let (mut journal, mut authority) = AuditJournal::open(
            JournalId::new("engine").unwrap(),
            ProducerId::new("engine.audit").unwrap(),
            FullAudit,
            MemorySpool::default(),
            Arc::clone(&world.clock),
            audit_config(1),
        )
        .unwrap();
        // Audit is overloaded: storage is full, and the spool's one slot, the revocation
        // reserve, goes to the refused record that must be stored first.
        assert!(journal
            .append(
                &mut authority,
                EventContext::new(operation("op-lease"), Phase::Running),
                AuditDraft::HostFact {
                    fact: HostFact::Lease,
                    fields: Vec::new(),
                },
            )
            .is_err());
        let directory = tempfile::tempdir().unwrap();
        let mut log = open_log(directory.path(), "coordinator.revocations");
        let flood = |runner: &mut MetricsProducer, count: u64| {
            let mut hub = hub.lock().unwrap();
            for bytes in 0..count {
                hub.emit_metric(
                    runner,
                    EventContext::new(operation("op-serve"), Phase::Running),
                    MetricDraft::new("gpu.resident_bytes", MetricValue::GaugeBytes { bytes }),
                )
                .unwrap();
            }
        };
        let of = world.execution.clone();
        let mut publish = |grant_name: Option<&str>, name: &str| {
            let mut guard = hub.lock().unwrap();
            let mut events = RevocationEvents {
                hub: &mut guard,
                issuer: &mut issuer,
                journal: &mut journal,
                authority: &mut authority,
            };
            match grant_name {
                Some(granted) => {
                    let published = world
                        .coordinator
                        .revoke_grant_and_publish_durably(
                            &of,
                            grant(granted),
                            operation(name),
                            RevocationReason::SecurityEvent,
                            &mut events,
                            &mut log,
                        )
                        .unwrap();
                    (
                        published.published.lane,
                        published.published.audit.map(|_| ()),
                        published.recorded,
                    )
                }
                None => {
                    let published = world
                        .coordinator
                        .revoke_and_publish_durably(
                            &of,
                            operation(name),
                            RevocationReason::SecurityEvent,
                            &mut events,
                            &mut log,
                        )
                        .unwrap();
                    (
                        published.published.lane,
                        published.published.audit.map(|_| ()),
                        published.recorded,
                    )
                }
            }
        };

        flood(&mut runner, 500);
        // Audit refuses both revocations; the lane and the durable stream take them.
        let (lane, audit, recorded) = publish(Some("route"), "op-grant");
        assert_eq!(lane, Ok(RevocationAdmission::Queued));
        assert!(audit.is_err(), "audit is overloaded");
        assert_eq!(recorded, Ok(EventSequence::FIRST));
        pump.pump();
        flood(&mut runner, 500);
        let (lane, audit, recorded) = publish(None, "op-revoke");
        assert_eq!(lane, Ok(RevocationAdmission::Queued));
        assert!(audit.is_err(), "audit is overloaded");
        assert_eq!(recorded, Ok(EventSequence::new(2).unwrap()));
        for _ in 0..3 {
            pump.pump();
            flood(&mut runner, 500);
        }
        pump.pump();

        // The slow subscriber shed metrics and every delivery but the newest, never a
        // revocation: both ride the first delivery it takes, ahead of everything else.
        let batch = pump.take(slow, usize::MAX).unwrap();
        assert_eq!(batch.deliveries.len(), 1);
        assert!(batch.lag.is_some());
        let first = &batch.deliveries[0];
        assert_eq!(first.revocations.grants.len(), 1);
        assert_eq!(first.revocations.notices.len(), 1);
        assert_eq!(
            first.revocations.notices[0].operation(),
            &operation("op-revoke")
        );
        assert!(first.metrics.events.is_empty());
        let totals = pump.fanout().totals(slow).unwrap();
        assert!(totals.metrics_shed > 0 && totals.deliveries_shed > 0);
        assert_eq!(totals.revocations_taken, 2);
        // The flood cost metrics, every loss counted; none of it cost a revocation.
        assert!(hub.lock().unwrap().metrics().totals().lost() > 0);
        // The durable stream holds both, whatever audit did.
        let replay = log.replay(&log.log().start()).unwrap();
        assert_eq!(replay.records, 2);
        assert!(replay.executions.contains_key(&of));
        assert_eq!(replay.tombstones()[&of], BTreeSet::from([grant("route")]));
    }

    /// One revocation correlates by its operation across the lane's notice, the durable
    /// revocation stream and an audit journal kept on its own durable log, each with its
    /// own owner; a stream owned by the lane's issuer is refused.
    #[test]
    fn s06_an_operation_correlates_across_the_lane_the_revocation_stream_and_the_audit_log() {
        let mut world = World::new();
        world.serving();
        let mut plane = Plane::new(&world.clock);
        let audit_directory = tempfile::tempdir().unwrap();
        let (audit_log, _) = DurableLog::<AuditRecord>::open(
            audit_directory.path(),
            DurableStreamId::new("engine.audit").unwrap(),
            ProducerId::new("engine.audit").unwrap(),
            LogConfig {
                max_entries: 64,
                max_bytes: 1 << 20,
                segment_entries: 8,
                segment_bytes: 1 << 16,
            },
        )
        .unwrap();
        let (mut journal, mut authority) = AuditJournal::open(
            JournalId::new("engine").unwrap(),
            ProducerId::new("engine.audit").unwrap(),
            audit_log,
            MemorySpool::default(),
            Arc::clone(&world.clock),
            audit_config(4),
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut log = open_log(directory.path(), "coordinator.revocations");
        let of = world.execution.clone();

        // A stream owned under the lane issuer's own name is refused; the lane and audit
        // still take the revocation.
        let shared_directory = tempfile::tempdir().unwrap();
        let mut shared = open_log(shared_directory.path(), "coordinator");
        let refused = world
            .coordinator
            .revoke_grant_and_publish_durably(
                &of,
                grant("route"),
                operation("op-grant"),
                RevocationReason::UserRequested,
                &mut RevocationEvents {
                    hub: &mut plane.hub,
                    issuer: &mut plane.issuer,
                    journal: &mut journal,
                    authority: &mut authority,
                },
                &mut shared,
            )
            .unwrap();
        assert_eq!(
            refused.recorded,
            Err(RecordError::SharedProducer {
                producer: ProducerId::new("coordinator").unwrap()
            })
        );
        assert_eq!(refused.published.lane, Ok(RevocationAdmission::Queued));
        assert!(refused.published.audit.is_ok());
        assert_eq!(shared.log().last(), None);

        let published = world
            .coordinator
            .revoke_and_publish_durably(
                &of,
                operation("op-revoke"),
                RevocationReason::SecurityEvent,
                &mut RevocationEvents {
                    hub: &mut plane.hub,
                    issuer: &mut plane.issuer,
                    journal: &mut journal,
                    authority: &mut authority,
                },
                &mut log,
            )
            .unwrap();
        assert!(published.recorded.is_ok());
        let epoch = published.published.notice.current;

        let op = operation("op-revoke");
        let delivery = plane.hub.drain(16);
        let notice = &delivery.revocations.notices[0];
        assert_eq!(notice.operation(), &op);
        let durable = log.log().correlate(&op).unwrap();
        assert_eq!(durable.records.len(), 1);
        let RevocationRecord::Execution(record) = &durable.records[0].1 else {
            panic!("{:?}", durable.records);
        };
        let audited = journal.store().correlate(&op).unwrap();
        assert_eq!(audited.records.len(), 1);
        let audit = audited.records[0].1.event();
        // The same operation, generations and phase on all three, each in its own
        // producer's sequence space.
        assert_eq!(record.operation(), &op);
        assert_eq!(audit.operation(), &op);
        assert_eq!(notice.generations(), record.generations());
        assert_eq!(notice.generations(), audit.generations());
        assert_eq!(record.generations().authorization, Some(epoch));
        assert_eq!(record.payload(), notice.payload());
        assert_eq!(record.phase(), Phase::Revoked);
        assert_eq!(audit.phase(), Phase::Revoked);
        let keys = [notice.key(), record.key(), audit.key()];
        assert_eq!(
            keys.iter()
                .map(|key| key.producer.as_str())
                .collect::<Vec<_>>(),
            ["coordinator", "coordinator.revocations", "engine.audit"]
        );
        // The grant revocation's own operation correlates apart.
        let granted = journal.store().correlate(&operation("op-grant")).unwrap();
        assert_eq!(granted.records.len(), 1);
        assert!(log
            .log()
            .correlate(&operation("op-grant"))
            .unwrap()
            .records
            .is_empty());
    }
}
