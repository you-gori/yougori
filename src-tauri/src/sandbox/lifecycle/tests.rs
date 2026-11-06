//! Scenario tests over the supervisor with the real CORE-04 coordinator, the real CORE-03
//! ledger and the scripted backend: the launch transaction, failed starts, idempotent
//! transitions, the five leases under VM-P18, engine and supervisor death, handle reuse,
//! the revocation acknowledgments of VM-P14, VM-P21 snapshot identities, VM-P24 cleanup
//! paths, the VM-D7 and VM-D10 splits, warm-pool checkouts, the §6.4 reserve, CORE-06
//! receipts and the §12.3 model against the supervisor.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use super::fakes::{BackendCall, ScriptedBackend};
use super::model::{self, Op};
use super::*;
use crate::foundation::coordination::{
    network_grant_id, CancelCause, CoordinationError, Denial, DeniedRequest, GrantId,
    LaunchFailure, LeaseKind, LeaseRefusal, LedgerCapacity, MilestoneSource, ReservationKey,
    ReservationPurpose, ResourceKind, RevocationMilestone, SandboxState, SettingsGrant,
    SnapshotOrigin, StepKind,
};
use crate::foundation::events::{
    EventHub, HubConfig, MetricsConfig, Phase, ProducerId, ProducerIncarnation, ProgressConfig,
    RevocationAdmission, RevocationConfig, RevocationReason,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    AdmittedRuntime, Backend, BackendRelease, Capability, ClockSession, ConfigurationFingerprint,
    HostSubject, NetworkGrant, Observation, ProbeRegistry, RuntimeOffer, RuntimeRequirement,
    RuntimeSubject, SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Clock, Digest, ExecutionCategory, ExecutionId, ManualClock,
    MonotonicTime, OperationId, SandboxBootGeneration, TenantId,
};
use crate::foundation::ledger::{
    CapacityDeclaration, HostResource, Ledger, LedgerConfig, QueueLimits, ResourceKey,
};
use crate::foundation::report::Quantile;

const SECOND: Duration = Duration::from_secs(1);
const HOUR: Duration = Duration::from_secs(3600);
const GIB: u64 = 1 << 30;

type TestClock = Arc<ManualClock>;
type TestSupervisor = Supervisor<TestClock, LedgerCapacity<TestClock>>;

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

fn runtime(category: ExecutionCategory) -> RuntimeSubject {
    RuntimeSubject {
        category,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance: named("yougori/test/instance/v1", "vm-host-1"),
    }
}

fn image_profile() -> Digest {
    named("yougori/test/image/v1", "sandbox-image")
}

fn volume(name: &str) -> Digest {
    named("yougori/test/volume/v1", name)
}

fn demand() -> BTreeMap<ResourceKind, u64> {
    BTreeMap::from([
        (ResourceKind::HostMemoryBytes, 8 * GIB),
        (ResourceKind::CpuInitializationSlots, 1),
    ])
}

fn call() -> CallTerms {
    CallTerms {
        per_call: 30 * SECOND,
        task: HOUR,
    }
}

/// Host evidence of each runtime's category, refreshed before every admission.
struct Evidence {
    registry: ProbeRegistry<TestClock>,
    category: Arc<FakeProbe>,
}

impl Evidence {
    fn new(clock: &TestClock) -> Self {
        let mut registry = ProbeRegistry::new(Arc::clone(clock));
        let category = Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe));
        registry.register(Box::new(Arc::clone(&category))).unwrap();
        Self { registry, category }
    }

    fn admit(&mut self, runtime: &RuntimeSubject) -> AdmittedRuntime {
        let subject = Subject::Runtime(runtime.clone());
        self.category.respond(
            &subject,
            Observation::supported(
                configuration("launch"),
                HOUR,
                SupportDetail::RuntimeCategory {
                    category: runtime.category,
                },
            ),
        );
        self.registry
            .refresh(Capability::RuntimeCategory, &subject)
            .unwrap();
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
}

/// The CORE-03 ledger of the host: 64 GiB of RAM with a supervisor reserve, 16 CPU
/// initialization slots, the tenant budgeted for all of it.
fn real_ledger(clock: &TestClock, reserve_bytes: u64) -> LedgerCapacity<TestClock> {
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
        unmanaged_usage_max_age: 1000 * HOUR,
    };
    let mut ledger = Ledger::new(Arc::clone(clock), host, config);
    for (key, total, reserve) in [
        (
            ResourceKey::Host(HostResource::Ram),
            64 * GIB,
            reserve_bytes,
        ),
        (
            ResourceKey::Host(HostResource::CpuInitializationSlots),
            16,
            0,
        ),
    ] {
        ledger
            .declare_capacity(
                key,
                CapacityDeclaration {
                    total,
                    supervisor_reserve: reserve,
                    unmanaged_in_use: 0,
                    source: SourceClass::HostProbe,
                },
            )
            .unwrap();
        ledger.set_tenant_budget(tenant(), key, total).unwrap();
    }
    LedgerCapacity::new(ledger)
}

fn config(timing: TerminationTiming, fallback: SupervisorDeathFallback) -> SupervisorConfig {
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
        death_fallback: fallback,
        cancel_within: 5 * SECOND,
        issuer: IssuerId::named("host-a"),
        expected_image_profile: image_profile(),
    }
}

fn waiting() -> SupervisorConfig {
    config(
        TerminationTiming::AfterChannelAcknowledgmentOrBound,
        SupervisorDeathFallback::ServiceManagerRestart {
            restart_within: 30 * SECOND,
        },
    )
}

struct World {
    clock: TestClock,
    evidence: Evidence,
    backend: ScriptedBackend,
    supervisor: TestSupervisor,
}

impl World {
    fn new() -> Self {
        Self::with(waiting(), 0)
    }

    fn with(config: SupervisorConfig, reserve_bytes: u64) -> Self {
        let clock = Arc::new(ManualClock::new(at(100)));
        let evidence = Evidence::new(&clock);
        let ledger = real_ledger(&clock, reserve_bytes);
        let mut backend = ScriptedBackend::new();
        backend.image_profile = image_profile();
        let supervisor = Supervisor::new(Arc::clone(&clock), session(1), ledger, config);
        Self {
            clock,
            evidence,
            backend,
            supervisor,
        }
    }

    fn advance(&mut self, by: Duration) {
        self.clock.advance(by);
    }

    fn request(&mut self, name: &str, class: SandboxClass) -> LaunchRequest {
        LaunchRequest {
            execution: execution(name),
            tenant: tenant(),
            runtime: self.evidence.admit(&runtime(ExecutionCategory::VmSandbox)),
            demand: demand(),
            priority: crate::foundation::coordination::ReservationPriority::Foreground,
            class,
            limits: LeaseLimits::defaults(class),
            settings: SettingsGrant::default(),
            volumes: BTreeMap::new(),
            provider_bills: false,
        }
    }

    fn launch(&mut self, name: &str, class: SandboxClass) -> LaunchReceipt {
        let request = self.request(name, class);
        self.supervisor
            .launch(request, &mut self.backend, &self.evidence.registry)
            .unwrap()
    }

    fn launched(&mut self, name: &str, class: SandboxClass) -> SandboxBootGeneration {
        match self.launch(name, class) {
            LaunchReceipt::AuthorityActive { boot, .. } => boot,
            other => panic!("{other:?}"),
        }
    }

    fn state(&self, name: &str) -> SandboxState {
        self.supervisor
            .coordinator()
            .sandbox(&execution(name))
            .unwrap()
            .state()
    }

    fn vm(&self, name: &str) -> crate::foundation::coordination::VmInstanceId {
        self.supervisor
            .coordinator()
            .sandbox(&execution(name))
            .unwrap()
            .vm()
            .unwrap()
    }

    fn work(
        &mut self,
        name: &str,
        op: &str,
    ) -> Result<crate::foundation::coordination::Lease, SupervisorError> {
        self.supervisor.authorize_work(
            &execution(name),
            operation(op),
            LeaseKind::ChildWork,
            call(),
        )
    }

    fn admitted(&mut self) -> AdmittedRuntime {
        self.evidence.admit(&runtime(ExecutionCategory::VmSandbox))
    }

    /// Revokes and drives the sandbox to stopped: channels acknowledged, every lease
    /// acknowledged, the coordinator advanced.
    fn stop_fully(&mut self, name: &str) {
        let exe = execution(name);
        self.supervisor
            .revoke(&exe, RevocationCause::UserRequested, &mut self.backend)
            .unwrap();
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
        let progress = self.supervisor.advance(&exe, &mut self.backend).unwrap();
        assert!(
            progress.acknowledged.contains(&Acknowledgment::VmStopped),
            "{progress:?}"
        );
        assert_eq!(self.state(name), SandboxState::Stopped);
    }

    fn checkout(&mut self, name: &str, pool: &mut WarmPool) -> CheckoutReceipt {
        let request = self.request(name, SandboxClass::Task);
        self.supervisor
            .checkout(request, pool, &mut self.backend, &self.evidence.registry)
            .unwrap()
    }

    /// The boot generation `name` is at.
    fn boot(&self, name: &str) -> SandboxBootGeneration {
        self.supervisor
            .coordinator()
            .sandbox(&execution(name))
            .unwrap()
            .generations()
            .boot
    }

    /// The steps `name`'s boot `boot` went through, in order.
    fn steps_of(&self, name: &str, boot: SandboxBootGeneration) -> Vec<StepKind> {
        self.supervisor
            .coordinator()
            .sandbox(&execution(name))
            .unwrap()
            .log()
            .iter()
            .filter(|record| record.generations.boot == boot)
            .map(|record| record.step.kind())
            .collect()
    }

    fn stops_of(&self, name: &str) -> usize {
        let vm = self
            .supervisor
            .coordinator()
            .sandbox(&execution(name))
            .and_then(|sandbox| sandbox.vm());
        self.backend
            .calls
            .iter()
            .filter(|call| matches!(call, BackendCall::Stop(stopped) if Some(*stopped) == vm))
            .count()
    }
}

#[test]
fn launch_runs_the_transaction_through_the_coordinator_and_binds_the_tuple() {
    let mut world = World::new();
    let boot = world.launched("exe-task", SandboxClass::Task);
    assert_eq!(boot, SandboxBootGeneration::FIRST);
    let steps: Vec<StepKind> = world
        .supervisor
        .coordinator()
        .sandbox(&execution("exe-task"))
        .unwrap()
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
        ],
        "planned → resources_reserved → perimeter_ready → VM_created → boot_evidence_checked → authority_active"
    );
    assert_eq!(
        world.backend.calls,
        [
            BackendCall::PreparePerimeter(boot),
            BackendCall::Launch(boot),
            BackendCall::Readiness(world.vm("exe-task")),
        ]
    );
    assert_eq!(world.supervisor.handles().len(), 1);
    let receipts = world.supervisor.take_receipts();
    assert!(
        matches!(
            &receipts[..],
            [LifecycleReceipt::Launched { boot, context, .. }]
                if *boot == SandboxBootGeneration::FIRST
                    && context.phase == Phase::Running
                    && context.generations.authorization == Some(AuthorizationEpoch::FIRST)
        ),
        "{receipts:?}"
    );
    let tuple = world
        .supervisor
        .current_tuple(&execution("exe-task"), None)
        .unwrap();
    let channel = Binding::new(BoundKind::GuestChannel, tuple.clone()).unwrap();
    world.supervisor.check_binding(&channel).unwrap();
    assert_eq!(tuple.boot, boot);
    assert_eq!(tuple.snapshot, None);

    // The first command: running, measured from create initiation, counted as activity.
    world.advance(700 * Duration::from_millis(1));
    let elapsed = world
        .supervisor
        .first_command(&execution("exe-task"))
        .unwrap();
    assert_eq!(elapsed, Duration::from_millis(700));
    assert_eq!(world.state("exe-task"), SandboxState::Running);
    assert_eq!(world.supervisor.measurements().first_commands().len(), 1);
    assert_eq!(world.supervisor.measurements().pool().authority_checks, 1);
    world.advance(SECOND);
    assert_eq!(
        world
            .supervisor
            .first_command(&execution("exe-task"))
            .unwrap(),
        Duration::from_millis(700),
        "repeating the first command changes nothing"
    );

    // Launching an active sandbox again changes nothing (§6.1 idempotent transitions).
    let started = world
        .supervisor
        .sandbox(&execution("exe-task"))
        .unwrap()
        .lease
        .started_at();
    let again = world.launch("exe-task", SandboxClass::Task);
    assert!(matches!(again, LaunchReceipt::AuthorityActive { .. }));
    assert_eq!(
        world
            .supervisor
            .sandbox(&execution("exe-task"))
            .unwrap()
            .lease
            .started_at(),
        started
    );
    assert_eq!(
        world
            .supervisor
            .coordinator()
            .sandbox(&execution("exe-task"))
            .unwrap()
            .log()
            .len(),
        6
    );
    assert_eq!(world.backend.calls.len(), 3);
    let wrong_class = world.request("exe-task", SandboxClass::Service);
    assert!(matches!(
        world
            .supervisor
            .launch(wrong_class, &mut world.backend, &world.evidence.registry),
        Err(SupervisorError::WrongClass { .. })
    ));
}

#[test]
fn a_failed_start_leaves_no_authority_and_nothing_behind() {
    let mut world = World::new();
    world.backend.failing.insert(BackendOperation::Launch);
    let receipt = world.launch("exe-task", SandboxClass::Task);
    assert!(
        matches!(receipt, LaunchReceipt::RolledBack { .. }),
        "{receipt:?}"
    );
    assert_eq!(world.state("exe-task"), SandboxState::Stopped);
    assert_eq!(
        world
            .supervisor
            .coordinator()
            .sandbox(&execution("exe-task"))
            .unwrap()
            .authority(),
        None
    );
    assert!(world.supervisor.sandbox(&execution("exe-task")).is_none());
    assert!(world.supervisor.handles().is_empty());
    assert!(
        world.backend.perimeters.is_empty(),
        "the perimeter was undone"
    );
    assert_eq!(
        world
            .supervisor
            .coordinator()
            .capacity()
            .ledger()
            .open_reservations()
            .count(),
        0,
        "the reservation was released"
    );
    assert!(matches!(
        world.work("exe-task", "op-1"),
        Err(SupervisorError::UnknownSandbox { .. })
    ));
    let tuple = world
        .supervisor
        .current_tuple(&execution("exe-task"), None)
        .unwrap();
    let binding = Binding::new(BoundKind::GuestChannel, tuple).unwrap();
    assert!(matches!(
        world.supervisor.check_binding(&binding),
        Err(SupervisorError::NoAuthority {
            state: SandboxState::Stopped,
            ..
        })
    ));
    assert!(matches!(
        &world.supervisor.take_receipts()[..],
        [LifecycleReceipt::LaunchFailed { context, .. }] if context.phase == Phase::Failed
    ));

    // Readiness the host never observed: the VM is terminated, nothing is exposed.
    world.backend.failing.clear();
    world.backend.readiness.readiness = crate::foundation::coordination::Readiness::NotReady {
        detail: "no agent".to_owned(),
    };
    let receipt = world.launch("exe-slow", SandboxClass::Task);
    assert!(matches!(
        receipt,
        LaunchReceipt::RolledBack {
            failure: crate::foundation::coordination::LaunchFailure::NotReady { .. },
            ..
        }
    ));
    assert!(world
        .backend
        .calls
        .iter()
        .any(|call| matches!(call, BackendCall::Stop(_))));
    assert!(world.backend.live().is_empty());

    // A labelled runtime never gets the VM sandbox lifecycle (§2.6: no compatibility
    // fallback changes a required VM boundary).
    world.backend.readiness.readiness = crate::foundation::coordination::Readiness::Ready;
    let labelled = world
        .evidence
        .admit(&runtime(ExecutionCategory::SharedKernelGpuRuntime));
    let mut request = world.request("exe-labelled", SandboxClass::Task);
    request.runtime = labelled;
    assert!(matches!(
        world
            .supervisor
            .launch(request, &mut world.backend, &world.evidence.registry),
        Err(SupervisorError::Coordination {
            error: crate::foundation::coordination::CoordinationError::NotAVmSandbox { .. }
        })
    ));
}

#[test]
fn revocation_acknowledgments_are_distinct_facts_measured_separately() {
    let mut world = World::new();
    let mut request = world.request("exe-task", SandboxClass::Task);
    request.provider_bills = true;
    assert!(matches!(
        world
            .supervisor
            .launch(request, &mut world.backend, &world.evidence.registry)
            .unwrap(),
        LaunchReceipt::AuthorityActive { .. }
    ));
    let exe = execution("exe-task");
    let lease = world.work("exe-task", "op-stream").unwrap();
    world.advance(10 * SECOND);

    // Steps 1–2: the durable decision stops issuing at once; "new authorizations
    // denied" is acknowledged by the first request actually refused after it.
    let progress = world
        .supervisor
        .revoke(&exe, RevocationCause::UserRequested, &mut world.backend)
        .unwrap();
    assert!(progress.acknowledged.is_empty(), "{progress:?}");
    assert_eq!(progress.pending[0], Acknowledgment::NewAuthorizationsDenied);
    assert_eq!(progress.decided_at, at(110));
    assert!(matches!(
        world.work("exe-task", "op-late"),
        Err(SupervisorError::Revoked { .. })
    ));
    assert!(matches!(
        world.supervisor.coordinator().check_lease(lease.id()),
        Err(LeaseRefusal::Cancelled { .. } | LeaseRefusal::RevokedAuthorization { .. })
    ));
    let tombstones = world.supervisor.replay().tombstones();
    assert_eq!(tombstones.len(), 1);
    assert_eq!(tombstones[0].epoch, AuthorizationEpoch::FIRST);
    let run = world.supervisor.revocation(&exe).unwrap();
    assert_eq!(
        run.lease_expiry_bound_at(),
        lease
            .expires_at()
            .max(at(100).saturating_add(DEFAULT_TASK_ABSOLUTE))
            .saturating_add(30 * SECOND),
        "the §2.5 bound: the latest expiry plus the allowed clock uncertainty"
    );
    assert!(matches!(
        world.supervisor.take_receipts().last(),
        Some(LifecycleReceipt::Revoked { revocation, context, .. })
            if revocation.epoch == AuthorizationEpoch::new(2)
                && revocation.reason == RevocationReason::UserRequested
                && context.phase == Phase::Revoked
    ));
    // Revoking again changes nothing.
    let again = world
        .supervisor
        .revoke(&exe, RevocationCause::Violation, &mut world.backend)
        .unwrap();
    assert_eq!(again.decided_at, at(110));
    assert_eq!(world.supervisor.replay().tombstones().len(), 1);

    // Step 3: nothing stops before the channels acknowledge or the bound passes.
    let progress = world.supervisor.advance(&exe, &mut world.backend).unwrap();
    assert!(matches!(progress.gate, TerminationGate::Wait { .. }));
    assert_eq!(world.stops_of("exe-task"), 0);
    assert!(matches!(
        world
            .supervisor
            .acknowledge(&exe, Acknowledgment::VmStopped),
        Err(SupervisorError::Acknowledgment {
            refusal: AckRefusal::VmStopIsObserved
        })
    ));
    assert!(matches!(
        world
            .supervisor
            .acknowledge(&exe, Acknowledgment::ProviderBillingStopped),
        Err(SupervisorError::Acknowledgment {
            refusal: AckRefusal::NeedsProviderAcknowledgment
        })
    ));
    world.advance(SECOND);
    assert_eq!(
        world
            .supervisor
            .acknowledge(&exe, Acknowledgment::ChannelsClosed)
            .unwrap(),
        AckEffect::Recorded
    );
    assert_eq!(
        world
            .supervisor
            .acknowledge(&exe, Acknowledgment::ChannelsClosed)
            .unwrap(),
        AckEffect::AlreadyRecorded
    );
    // The coordinator still waits for the cancelled lease's declared bound.
    let progress = world.supervisor.advance(&exe, &mut world.backend).unwrap();
    assert!(!progress.acknowledged.contains(&Acknowledgment::VmStopped));
    world
        .supervisor
        .coordinator_mut()
        .acknowledge_cancellation(lease.id())
        .unwrap();
    world.advance(SECOND);
    // Step 4: the VM stops through its handle; step 5: cleanup starts, bounded.
    let progress = world.supervisor.advance(&exe, &mut world.backend).unwrap();
    assert!(progress.acknowledged.contains(&Acknowledgment::VmStopped));
    assert_eq!(world.stops_of("exe-task"), 1);
    assert_eq!(world.state("exe-task"), SandboxState::Stopped);
    assert!(matches!(
        world.supervisor.revocation(&exe).unwrap().cleanup(),
        CleanupState::Started { .. }
    ));
    assert_eq!(
        progress.pending,
        [
            Acknowledgment::ProviderBillingStopped,
            Acknowledgment::CleanupFinished
        ]
    );
    // Provider billing stops only on the provider's word, later than the VM.
    world.advance(20 * SECOND);
    world
        .supervisor
        .provider_acknowledged(
            &exe,
            ProviderAcknowledgment {
                provider: named("yougori/test/provider/v1", "cloud"),
                at: world.clock.now(),
            },
        )
        .unwrap();
    world.advance(5 * SECOND);
    assert!(!world
        .supervisor
        .finish_cleanup(
            &exe,
            CleanupReport::logical([LogicalCleanupAction::OverlayDeleted])
        )
        .unwrap());
    assert!(matches!(
        world
            .supervisor
            .finish_cleanup(&exe, CleanupReport::logical([])),
        Err(SupervisorError::Acknowledgment {
            refusal: AckRefusal::CleanupAlreadyFinished
        })
    ));
    let run = world.supervisor.revocation(&exe).unwrap();
    assert!(run.is_complete());
    assert_eq!(
        run.elapsed(Acknowledgment::NewAuthorizationsDenied),
        Some(Duration::ZERO)
    );
    assert_eq!(run.elapsed(Acknowledgment::ChannelsClosed), Some(SECOND));
    assert_eq!(run.elapsed(Acknowledgment::VmStopped), Some(2 * SECOND));
    assert_eq!(
        run.elapsed(Acknowledgment::ProviderBillingStopped),
        Some(22 * SECOND)
    );
    assert_eq!(
        run.elapsed(Acknowledgment::CleanupFinished),
        Some(27 * SECOND)
    );

    // Each phase has its own distribution (VM-P14).
    let measurements = world.supervisor.measurements();
    let p50 = |phase| {
        measurements
            .summarize(phase)
            .unwrap()
            .percentile(Quantile::P50)
            .unwrap()
            .value_nanos
            .value()
            .copied()
    };
    assert_eq!(p50(StopPhase::RevokeToDeny), Some(0.0));
    assert_eq!(p50(StopPhase::ChannelClose), Some(1e9));
    assert_eq!(p50(StopPhase::VmStop), Some(2e9));
    assert_eq!(
        p50(StopPhase::Cleanup),
        Some(25e9),
        "cleanup is measured from the VM stop"
    );
    let assessment = TargetAssessment::of(
        &measurements.summarize(StopPhase::VmStop).unwrap(),
        STOP_TARGET,
    );
    assert_eq!(
        assessment.within_target,
        Some(true),
        "two seconds is within the target in this run"
    );
    assert_eq!(
        assessment.claim,
        TargetClaim::ObservationUnderTestLoad,
        "an observation, never a guarantee"
    );
    // Advancing a finished revocation changes nothing.
    let progress = world.supervisor.advance(&exe, &mut world.backend).unwrap();
    assert!(progress.pending.is_empty());
    assert_eq!(world.stops_of("exe-task"), 1);
}

#[test]
fn expiry_during_a_busy_stream_a_stalled_engine_a_clock_jump_and_a_disconnected_ui() {
    // A busy stream of traffic is not activity: the idle limit ends the task (VM-P18).
    let mut world = World::new();
    world.launched("exe-stream", SandboxClass::Task);
    for _ in 0..12 {
        world.advance(HOUR);
        assert!(matches!(
            world
                .supervisor
                .activity(&execution("exe-stream"), ActivityKind::NetworkTraffic),
            Err(SupervisorError::Activity {
                refusal: ActivityRefusal::NotActivity { .. }
            })
        ));
        if world.clock.now() < at(100).saturating_add(12 * HOUR) {
            assert!(world
                .supervisor
                .tick(&mut world.backend)
                .unwrap()
                .expired
                .is_empty());
        }
    }
    let report = world.supervisor.tick(&mut world.backend).unwrap();
    assert_eq!(report.expired.len(), 1);
    assert_eq!(report.expired[0].1.kind, LimitKind::Idle);
    assert_eq!(world.state("exe-stream"), SandboxState::Revoking);
    assert!(matches!(
        world
            .supervisor
            .revocation(&execution("exe-stream"))
            .unwrap()
            .cause(),
        RevocationCause::LeaseExpired {
            kind: LimitKind::Idle
        }
    ));
    assert!(matches!(
        world.work("exe-stream", "op"),
        Err(SupervisorError::Revoked { .. })
    ));
    world
        .supervisor
        .acknowledge(&execution("exe-stream"), Acknowledgment::ChannelsClosed)
        .unwrap();
    world
        .supervisor
        .advance(&execution("exe-stream"), &mut world.backend)
        .unwrap();
    assert_eq!(world.state("exe-stream"), SandboxState::Stopped);

    // A stalled engine never acknowledges: the absolute limit ends a busy task anyway,
    // and the VM stops at the lease-expiry bound.
    let mut world = World::new();
    let mut request = world.request("exe-busy", SandboxClass::Task);
    request.limits = LeaseLimits::defaults(SandboxClass::Task)
        .lower(LimitKind::Absolute, 2 * HOUR)
        .unwrap();
    world
        .supervisor
        .launch(request, &mut world.backend, &world.evidence.registry)
        .unwrap();
    for _ in 0..12 {
        world.advance(10 * 60 * SECOND);
        world
            .supervisor
            .activity(&execution("exe-busy"), ActivityKind::Command)
            .unwrap();
        if world.clock.now() < at(100).saturating_add(2 * HOUR) {
            assert!(world
                .supervisor
                .tick(&mut world.backend)
                .unwrap()
                .expired
                .is_empty());
        }
    }
    let report = world.supervisor.tick(&mut world.backend).unwrap();
    assert_eq!(report.expired[0].1.kind, LimitKind::Absolute);
    let progress = world
        .supervisor
        .advance(&execution("exe-busy"), &mut world.backend)
        .unwrap();
    assert!(
        matches!(progress.gate, TerminationGate::Wait { until } if until == at(100).saturating_add(2 * HOUR + 30 * SECOND))
    );
    world.advance(30 * SECOND);
    let progress = world
        .supervisor
        .advance(&execution("exe-busy"), &mut world.backend)
        .unwrap();
    assert!(matches!(
        progress.gate,
        TerminationGate::BoundReached { .. }
    ));
    assert!(progress.acknowledged.contains(&Acknowledgment::VmStopped));
    assert_eq!(
        progress.uncertain, 1,
        "channels never acknowledged: recorded as uncertain"
    );

    // A clock jump of thirty hours ends a service's idle lease at the next tick; the
    // lease is never extended by the jump.
    let mut world = World::new();
    world.launched("exe-service", SandboxClass::Service);
    world.advance(30 * HOUR);
    let report = world.supervisor.tick(&mut world.backend).unwrap();
    assert_eq!(report.expired[0].1.kind, LimitKind::Idle);

    // A clock that reads earlier than the persisted mark is a rollback: the lease is
    // refused rather than honoured, and a rollback at the supervisor revokes.
    let mut lease = SandboxLease::new(
        LeaseLimits::defaults(SandboxClass::Task),
        session(1),
        at(500),
    );
    lease.check(at(600)).unwrap();
    assert!(matches!(
        SandboxLease::restore(lease, session(1), at(550)),
        Err(LeaseRestoreRefusal::ClockRolledBack { .. })
    ));

    // A disconnected UI changes nothing: services and tasks keep running.
    let mut world = World::new();
    world.launched("exe-task", SandboxClass::Task);
    world.launched("exe-service", SandboxClass::Service);
    world.advance(HOUR);
    let report = world.supervisor.gui_closed();
    assert_eq!((report.tasks_kept, report.services_kept), (1, 1));
    assert_eq!(world.state("exe-task"), SandboxState::AuthorityActive);
    assert_eq!(world.state("exe-service"), SandboxState::AuthorityActive);
    assert!(world.work("exe-service", "op-after-close").is_ok());
    assert_eq!(
        world
            .supervisor
            .sandbox(&execution("exe-service"))
            .unwrap()
            .lease
            .last_activity_at(),
        at(100),
        "GUI presence was never activity"
    );
}

#[test]
fn engine_death_ends_task_sandboxes_and_services_continue_under_supervisor_leases() {
    let mut world = World::new();
    world.launched("exe-task", SandboxClass::Task);
    world.launched("exe-service", SandboxClass::Service);
    let lease = world.work("exe-service", "op-serving").unwrap();
    let report = world.supervisor.engine_died(&mut world.backend).unwrap();
    assert_eq!(report.ended, [execution("exe-task")]);
    assert_eq!(report.continued, [execution("exe-service")]);
    assert_eq!(
        world.stops_of("exe-task"),
        1,
        "a task sandbox ends with the engine"
    );
    assert_eq!(world.stops_of("exe-service"), 0);
    assert_eq!(world.state("exe-service"), SandboxState::AuthorityActive);
    assert!(
        world
            .supervisor
            .coordinator()
            .check_lease(lease.id())
            .is_ok(),
        "existing operations follow their bounded leases"
    );
    assert!(matches!(
        world.work("exe-service", "op-new"),
        Err(SupervisorError::EngineDown { .. })
    ));
    world.supervisor.engine_reconciled();
    assert!(world.work("exe-service", "op-new").is_ok());
    assert!(matches!(
        world.supervisor.take_receipts().iter().find(|receipt| matches!(receipt, LifecycleReceipt::EngineDied { .. })),
        Some(LifecycleReceipt::EngineDied { report }) if report.ended.len() == 1
    ));
}

#[test]
fn supervisor_death_fallbacks_revive_no_authority() {
    // The OS job ends every VM with the supervisor; nothing holds authority afterwards.
    let mut world = World::with(
        config(
            TerminationTiming::AfterChannelAcknowledgmentOrBound,
            SupervisorDeathFallback::OsJobCleanup,
        ),
        0,
    );
    world.launched("exe-task", SandboxClass::Task);
    world.launched("exe-service", SandboxClass::Service);
    let persisted = world.supervisor.persist();
    world.backend.end_job();
    let ledger = real_ledger(&world.clock, 0);
    let (recovered, report) = Supervisor::recover(
        persisted,
        Arc::clone(&world.clock),
        session(2),
        ledger,
        config(
            TerminationTiming::AfterChannelAcknowledgmentOrBound,
            SupervisorDeathFallback::OsJobCleanup,
        ),
        &mut world.backend,
    )
    .unwrap();
    for name in ["exe-task", "exe-service"] {
        assert!(matches!(
            report.coordination.sandboxes.get(&execution(name)),
            Some(crate::foundation::coordination::SandboxRecovery::VmLost { .. })
        ));
        assert_eq!(
            recovered
                .coordinator()
                .sandbox(&execution(name))
                .unwrap()
                .authority(),
            None
        );
        assert_eq!(
            recovered
                .coordinator()
                .sandbox(&execution(name))
                .unwrap()
                .state(),
            SandboxState::Stopped
        );
    }
    assert_eq!(report.leases_ended.len(), 2);
    assert!(
        recovered.incarnation().is_err(),
        "no incarnation before the recovered state is confirmed"
    );

    // A service manager restarts the supervisor: it recovers, ends the task, keeps the
    // service without authority, and grants authority again only after fresh checks.
    let mut world = World::new();
    world.launched("exe-task", SandboxClass::Task);
    world.launched("exe-service", SandboxClass::Service);
    let old_tuple = world
        .supervisor
        .current_tuple(&execution("exe-service"), None)
        .unwrap();
    let old_channel = Binding::new(BoundKind::GuestChannel, old_tuple).unwrap();
    let persisted = world.supervisor.persist();
    world.supervisor.confirm_persisted(&persisted);
    assert_eq!(
        world.supervisor.incarnation().unwrap(),
        crate::foundation::ids::Incarnation::FIRST
    );
    let ledger = real_ledger(&world.clock, 0);
    world.advance(10 * SECOND);
    let (mut recovered, report) = Supervisor::recover(
        persisted,
        Arc::clone(&world.clock),
        session(2),
        ledger,
        waiting(),
        &mut world.backend,
    )
    .unwrap();
    assert_eq!(report.tasks_ended, [execution("exe-task")]);
    assert_eq!(
        report.services_awaiting_reauthorization,
        [execution("exe-service")]
    );
    assert!(world.backend.stopped().contains(&world.vm("exe-task")));
    assert!(world.backend.is_live(&world.vm("exe-service")));
    let service = recovered
        .coordinator()
        .sandbox(&execution("exe-service"))
        .unwrap();
    assert_eq!(service.state(), SandboxState::VmCreated);
    assert_eq!(service.authority(), None);
    assert_eq!(
        service.generations().authorization,
        AuthorizationEpoch::new(2),
        "a new epoch; the old one is tombstoned"
    );
    assert_eq!(
        recovered.replay().tombstones().len(),
        2,
        "one per sandbox whose epoch advanced"
    );
    assert_eq!(
        recovered
            .replay()
            .tombstoned_epoch(IssuerId::named("host-a"), &execution("exe-service")),
        Some(AuthorizationEpoch::FIRST)
    );
    assert!(matches!(
        recovered.check_binding(&old_channel),
        Err(SupervisorError::NoAuthority { .. })
    ));
    assert!(matches!(
        recovered.authorize_work(
            &execution("exe-service"),
            operation("op"),
            LeaseKind::ChildWork,
            call()
        ),
        Err(SupervisorError::Lease { .. })
    ));
    let admitted = world.admitted();
    let receipt = recovered
        .reauthorize(
            &execution("exe-service"),
            admitted,
            &mut world.backend,
            &world.evidence.registry,
        )
        .unwrap();
    assert!(
        matches!(
            receipt,
            LaunchReceipt::AuthorityActive {
                boot: SandboxBootGeneration::FIRST,
                ..
            }
        ),
        "{receipt:?}"
    );
    assert_eq!(
        recovered
            .coordinator()
            .sandbox(&execution("exe-service"))
            .unwrap()
            .state(),
        SandboxState::AuthorityActive
    );
    assert_eq!(
        recovered
            .sandbox(&execution("exe-service"))
            .unwrap()
            .lease
            .started_at(),
        at(110),
        "deadlines start at the new grant"
    );
    assert!(
        matches!(
            recovered.check_binding(&old_channel),
            Err(SupervisorError::Binding {
                refusal: BindingRefusal::Stale {
                    field: BindingField::Session
                }
            })
        ),
        "a binding from the earlier run is refused before any number is compared"
    );
    // Lease ids and the incarnation are handed out only once the recovered state is
    // persisted and confirmed (§6.3 replay protection across restarts).
    assert!(matches!(
        recovered.authorize_work(
            &execution("exe-service"),
            operation("op"),
            LeaseKind::ChildWork,
            call()
        ),
        Err(SupervisorError::Lease {
            refusal: LeaseRefusal::LeaseIdsNotPersisted { .. }
        })
    ));
    assert!(recovered.incarnation().is_err());
    let state = recovered.persist();
    recovered.confirm_persisted(&state);
    assert_eq!(
        recovered.incarnation().unwrap(),
        crate::foundation::ids::Incarnation::new(2)
    );
    assert!(recovered
        .authorize_work(
            &execution("exe-service"),
            operation("op"),
            LeaseKind::ChildWork,
            call()
        )
        .is_ok());
}

#[test]
fn recovery_and_stops_never_trust_a_reused_underlying_number() {
    let mut world = World::new();
    world.launched("exe-task", SandboxClass::Task);
    let handle = world
        .supervisor
        .handles()
        .get(&world.vm("exe-task"))
        .unwrap()
        .clone();
    let persisted = world.supervisor.persist();
    world.backend.reuse_underlying(&handle);
    let calls_before = world.backend.calls.len();
    let ledger = real_ledger(&world.clock, 0);
    let (recovered, report) = Supervisor::recover(
        persisted.clone(),
        Arc::clone(&world.clock),
        session(2),
        ledger,
        waiting(),
        &mut world.backend,
    )
    .unwrap();
    assert_eq!(report.handles_reused, [handle.vm]);
    assert!(
        !world.backend.calls[calls_before..]
            .iter()
            .any(|call| matches!(call, BackendCall::Stop(_))),
        "nothing was stopped through the reused handle: {:?}",
        &world.backend.calls[calls_before..]
    );
    assert!(
        world.backend.foreign_alive(&handle),
        "the unrelated process lives"
    );
    assert!(matches!(
        report.coordination.sandboxes.get(&execution("exe-task")),
        Some(crate::foundation::coordination::SandboxRecovery::VmLost { .. })
    ));
    assert!(recovered.handles().is_empty());

    // A stop during revocation checks the handle too and reports the reuse.
    let mut world = World::with(
        config(
            TerminationTiming::Immediate,
            SupervisorDeathFallback::OsJobCleanup,
        ),
        0,
    );
    world.launched("exe-task", SandboxClass::Task);
    let handle = world
        .supervisor
        .handles()
        .get(&world.vm("exe-task"))
        .unwrap()
        .clone();
    world.backend.reuse_underlying(&handle);
    assert!(matches!(
        world.supervisor.revoke(&execution("exe-task"), RevocationCause::Violation, &mut world.backend),
        Err(SupervisorError::HandleReused { vm }) if vm == handle.vm
    ));
    assert_eq!(world.stops_of("exe-task"), 0);
    assert!(world.backend.foreign_alive(&handle));
    let failures = world.supervisor.measurements().failures();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].cause, StopFailureCause::HandleReused);
    assert!(
        world
            .supervisor
            .revocation(&execution("exe-task"))
            .is_some(),
        "the revocation stands"
    );
}

#[test]
fn an_old_snapshot_identity_cannot_revive_authority_or_spend_again() {
    let mut world = World::new();
    world.launched("exe-service", SandboxClass::Service);
    let exe = execution("exe-service");
    let old_lease = world.work("exe-service", "op-old").unwrap();
    let old_tuple = world.supervisor.current_tuple(&exe, None).unwrap();
    let old_capability = Binding::new(BoundKind::OperationCapability, old_tuple.clone()).unwrap();
    world.supervisor.accept_nonce(&exe, Nonce::new(1)).unwrap();
    assert!(matches!(
        world.supervisor.accept_nonce(&exe, Nonce::new(1)),
        Err(SupervisorError::Replay {
            refusal: ReplayRefusal::Replayed { .. }
        })
    ));
    let golden_handle = world
        .supervisor
        .handles()
        .get(&world.vm("exe-service"))
        .unwrap()
        .clone();
    let manifest = world
        .backend
        .snapshot(&golden_handle, SnapshotOrigin::PreTenantGolden)
        .unwrap();
    let golden = GoldenSnapshot::certify(
        manifest,
        SnapshotProvenance {
            before_tenant_inputs: true,
            before_credentials: true,
            before_external_connections: true,
        },
        image_profile(),
    )
    .unwrap();
    let mut pool = WarmPool::new(2);
    pool.set_golden(golden);
    pool.replenish(2);
    world.stop_fully("exe-service");

    // The checkout restores under a fresh generation; everything old is refused.
    world.advance(HOUR);
    let request = world.request("exe-service", SandboxClass::Service);
    let receipt = world
        .supervisor
        .checkout(
            request,
            &mut pool,
            &mut world.backend,
            &world.evidence.registry,
        )
        .unwrap();
    assert_eq!(receipt.decision, CheckoutDecision::Restore);
    assert!(
        matches!(
            receipt.launch,
            LaunchReceipt::AuthorityActive { boot, path: BootPath::WarmRestore, .. } if boot == SandboxBootGeneration::new(2)
        ),
        "{receipt:?}"
    );
    assert_eq!(world.backend.restore_count(), 1);
    let new_tuple = world.supervisor.current_tuple(&exe, None).unwrap();
    assert_ne!(new_tuple.boot, old_tuple.boot);
    assert_ne!(new_tuple.authorization, old_tuple.authorization);
    assert!(new_tuple.snapshot.is_some());
    assert!(matches!(
        world.supervisor.check_binding(&old_capability),
        Err(SupervisorError::Binding {
            refusal: BindingRefusal::Stale {
                field: BindingField::Boot
            }
        })
    ));
    assert!(matches!(
        world.supervisor.coordinator().check_lease(old_lease.id()),
        Err(LeaseRefusal::Cancelled { .. } | LeaseRefusal::StaleBootGeneration { .. })
    ));
    let old_scope = NonceScope {
        issuer: IssuerId::named("host-a"),
        sandbox: exe.clone(),
        boot: old_tuple.boot,
        authorization: old_tuple.authorization,
    };
    assert!(matches!(
        world
            .supervisor
            .replay_mut()
            .accept(old_scope, Nonce::new(2)),
        Err(ReplayRefusal::TombstonedGeneration { .. })
    ));
    world.supervisor.accept_nonce(&exe, Nonce::new(1)).unwrap();
    assert_eq!(
        world.supervisor.sandbox(&exe).unwrap().lease.started_at(),
        at(100).saturating_add(HOUR),
        "deadlines are rebound at the checkout"
    );
    let restored = Binding::new(BoundKind::RestoredVmCapability, new_tuple).unwrap();
    world.supervisor.check_binding(&restored).unwrap();

    // A restored clone presenting an old epoch fails verification: it is cleaned up
    // and the sandbox cold-boots, counted as a failed clone (BENCH-06).
    world.stop_fully("exe-service");
    world
        .backend
        .presented_epochs
        .insert(AuthorizationEpoch::FIRST);
    let request = world.request("exe-service", SandboxClass::Service);
    let receipt = world
        .supervisor
        .checkout(
            request,
            &mut pool,
            &mut world.backend,
            &world.evidence.registry,
        )
        .unwrap();
    assert_eq!(
        receipt.decision,
        CheckoutDecision::ColdBoot {
            fallback: ColdFallback::CloneVerificationFailed
        }
    );
    assert!(receipt.failed_clone_cleaned_up);
    assert!(matches!(
        receipt.launch,
        LaunchReceipt::AuthorityActive {
            path: BootPath::Cold,
            ..
        }
    ));
    let counts = world.supervisor.measurements().pool();
    assert_eq!(
        (
            counts.warm_restores,
            counts.failed_clone_cleanups,
            counts.cold_fallbacks
        ),
        (1, 1, 1)
    );
    let restored_vm = ScriptedBackend::vm_for(&exe, SandboxBootGeneration::new(3), true);
    assert!(
        world.backend.stopped().contains(&restored_vm),
        "the failed clone was stopped"
    );
    assert!(!world.backend.is_live(&restored_vm));

    // §12.3 model 5: a persisted copy from before a revocation cannot resurrect it.
    let mut world = World::new();
    world.launched("exe-task", SandboxClass::Task);
    let before = world.supervisor.persist();
    let old_tuple = world
        .supervisor
        .current_tuple(&execution("exe-task"), None)
        .unwrap();
    world.stop_fully("exe-task");
    let ledger = real_ledger(&world.clock, 0);
    let (recovered, report) = Supervisor::recover(
        before,
        Arc::clone(&world.clock),
        session(2),
        ledger,
        waiting(),
        &mut world.backend,
    )
    .unwrap();
    assert!(matches!(
        report.coordination.sandboxes.get(&execution("exe-task")),
        Some(crate::foundation::coordination::SandboxRecovery::VmLost { .. })
    ));
    let sandbox = recovered
        .coordinator()
        .sandbox(&execution("exe-task"))
        .unwrap();
    assert_eq!(sandbox.authority(), None);
    assert!(sandbox.generations().authorization > old_tuple.authorization);
    assert_eq!(
        recovered
            .replay()
            .tombstoned_epoch(IssuerId::named("host-a"), &execution("exe-task")),
        Some(old_tuple.authorization)
    );
    let old_channel = Binding::new(BoundKind::GuestChannel, old_tuple).unwrap();
    assert!(matches!(
        recovered.check_binding(&old_channel),
        Err(SupervisorError::NoAuthority { .. })
    ));
}

#[test]
fn cleanup_cannot_follow_a_guest_path_and_preserves_user_source() {
    let mut world = World::new();
    world.launched("exe-task", SandboxClass::Task);
    let exe = execution("exe-task");
    let now = world.clock.now();
    let overlay =
        world
            .supervisor
            .roots_mut()
            .create(&exe, VolumeKind::ExecutableEnvironmentCache, now);
    let source = world
        .supervisor
        .roots_mut()
        .create(&exe, VolumeKind::SourceWorkspace, now);
    let path = RelativePath::new("tmp/build").unwrap();
    assert!(matches!(
        world.supervisor.plan_cleanup(
            &exe,
            CleanupTarget {
                root: overlay,
                path: path.clone()
            }
        ),
        Err(SupervisorError::NotRevoking { .. })
    ));
    world
        .supervisor
        .revoke(&exe, RevocationCause::UserRequested, &mut world.backend)
        .unwrap();
    assert!(
        matches!(
            world.supervisor.plan_cleanup(
                &exe,
                CleanupTarget {
                    root: overlay,
                    path: path.clone()
                }
            ),
            Err(SupervisorError::Acknowledgment {
                refusal: AckRefusal::VmNotStopped
            })
        ),
        "security revocation does not wait for cleanup, and cleanup waits for the stop"
    );
    world.stop_fully("exe-task");
    let plan = world
        .supervisor
        .plan_cleanup(
            &exe,
            CleanupTarget {
                root: overlay,
                path: path.clone(),
            },
        )
        .unwrap();
    assert_eq!(plan.open_mode, OpenMode::RootHandleNoFollowVerified);
    assert!(matches!(
        world.supervisor.plan_cleanup(
            &exe,
            CleanupTarget {
                root: source,
                path: path.clone()
            }
        ),
        Err(SupervisorError::Cleanup {
            refusal: CleanupRefusal::UserSourcePreserved { .. }
        })
    ));
    assert_eq!(
        RelativePath::new("../../etc/passwd"),
        Err(PathRefusal::ParentComponent)
    );
    assert_eq!(RelativePath::new("/var/lib/vm"), Err(PathRefusal::Absolute));
    let guest_message = serde_json::json!({
        "message": "cleanup", "execution": "exe-task",
        "target": {"root": overlay.digest().to_hex(), "path": "../../home"}
    });
    assert!(matches!(
        MessageFrame::parse(
            &PeerIdentity::Authenticated {
                principal: "engine".to_owned()
            },
            guest_message.to_string().as_bytes()
        ),
        Err(FrameRefusal::Malformed { .. })
    ));
    let message = MessageFrame::parse(
        &PeerIdentity::Authenticated {
            principal: "engine".to_owned(),
        },
        serde_json::json!({
            "message": "cleanup", "execution": "exe-task",
            "target": {"root": overlay.digest().to_hex(), "path": "tmp/build"}
        })
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    assert!(matches!(
        world
            .supervisor
            .apply_message(message, &mut world.backend)
            .unwrap(),
        MessageOutcome::CleanupPlanned { .. }
    ));
    let report = CleanupReport::logical([
        LogicalCleanupAction::OverlayDeleted,
        LogicalCleanupAction::PerimeterRemoved,
    ]);
    assert!(!world
        .supervisor
        .finish_cleanup(&exe, report.clone())
        .unwrap());
    assert_eq!(world.supervisor.roots().of(&exe).count(), 0);
    assert!(matches!(
        world.supervisor.take_receipts().last(),
        Some(LifecycleReceipt::CleanupFinished { report: finished, late: false, .. }) if finished.physical == PhysicalWipe::NotProven && *finished == report
    ));
}

#[test]
fn a_service_renewal_keeps_only_the_allowed_volume_kinds() {
    let mut world = World::new();
    let mut request = world.request("exe-service", SandboxClass::Service);
    request.volumes = BTreeMap::from([(volume("creds"), VolumeKind::CredentialState)]);
    assert!(matches!(
        world
            .supervisor
            .launch(request, &mut world.backend, &world.evidence.registry),
        Err(SupervisorError::Volume {
            refusal: VolumeRefusal::CredentialCopyInStrictProfile,
            ..
        })
    ));
    let mut request = world.request("exe-service", SandboxClass::Service);
    request.volumes = BTreeMap::from([
        (volume("data"), VolumeKind::PureApplicationData),
        (volume("src"), VolumeKind::SourceWorkspace),
        (volume("cache"), VolumeKind::ExecutableEnvironmentCache),
        (volume("out"), VolumeKind::UnreviewedOutput),
    ]);
    world
        .supervisor
        .launch(request, &mut world.backend, &world.evidence.registry)
        .unwrap();
    let exe = execution("exe-service");
    world.advance(3 * 24 * HOUR);
    let plan = ServiceRenewalPlan {
        shutdown: ShutdownMode::ApplicationConsistent {
            quiesce_within: 30 * SECOND,
        },
        application_recovery_before_serving: true,
        downtime_bound: 2 * 60 * SECOND,
        revoke_old_lease: true,
        rollback: RollbackPlan::ColdBootPreviousVolumes,
        cache: CachePolicy::RebuildFromManifest,
    };
    assert!(matches!(
        world.supervisor.begin_service_renewal(
            &exe,
            ServiceRenewalPlan {
                revoke_old_lease: false,
                ..plan
            },
            &mut world.backend
        ),
        Err(SupervisorError::RenewalPlan {
            problem: RenewalPlanProblem::KeepsOldLease
        })
    ));
    assert!(matches!(
        world.supervisor.begin_service_renewal(&execution("exe-service"), plan, &mut world.backend).unwrap(),
        RenewalReceipt::Begun { retained, .. } if retained == BTreeSet::from([volume("data"), volume("src")])
    ));
    assert_eq!(world.state("exe-service"), SandboxState::Revoking);
    let admitted = world.admitted();
    assert!(matches!(
        world.supervisor.complete_service_renewal(
            &exe,
            admitted,
            &mut world.backend,
            &world.evidence.registry
        ),
        Err(SupervisorError::NotStopped { .. })
    ));
    world
        .supervisor
        .acknowledge(&exe, Acknowledgment::ChannelsClosed)
        .unwrap();
    world.supervisor.advance(&exe, &mut world.backend).unwrap();
    assert_eq!(world.state("exe-service"), SandboxState::Stopped);
    world.advance(45 * SECOND);
    let admitted = world.admitted();
    let receipt = world
        .supervisor
        .complete_service_renewal(&exe, admitted, &mut world.backend, &world.evidence.registry)
        .unwrap();
    let RenewalReceipt::Completed {
        downtime,
        downtime_exceeded,
        retained,
        launch,
        ..
    } = receipt
    else {
        panic!("{receipt:?}");
    };
    assert_eq!(downtime, 45 * SECOND);
    assert!(!downtime_exceeded);
    assert_eq!(retained, BTreeSet::from([volume("data"), volume("src")]));
    assert!(
        matches!(launch, LaunchReceipt::AuthorityActive { boot, .. } if boot == SandboxBootGeneration::new(2))
    );
    let record = world.supervisor.sandbox(&exe).unwrap();
    assert_eq!(
        record.volumes.keys().copied().collect::<BTreeSet<_>>(),
        retained
    );
    assert_eq!(
        record.lease.renewed_at(),
        world.clock.now(),
        "the renewal period starts at the new boot"
    );
    assert!(record.renewal.is_none());
    assert!(matches!(
        world
            .supervisor
            .begin_service_renewal(&execution("exe-task"), plan, &mut world.backend),
        Err(SupervisorError::UnknownSandbox { .. })
    ));
    world.launched("exe-task", SandboxClass::Task);
    assert!(matches!(
        world
            .supervisor
            .begin_service_renewal(&execution("exe-task"), plan, &mut world.backend),
        Err(SupervisorError::WrongClass { .. })
    ));
}

#[test]
fn warm_pool_checkouts_get_unique_identities_and_fall_back_cold_when_needed() {
    let mut world = World::new();
    for name in ["exe-a", "exe-b"] {
        world.launched(name, SandboxClass::Task);
    }
    let handle = world
        .supervisor
        .handles()
        .get(&world.vm("exe-a"))
        .unwrap()
        .clone();
    let manifest = world
        .backend
        .snapshot(&handle, SnapshotOrigin::PreTenantGolden)
        .unwrap();
    let golden = GoldenSnapshot::certify(
        manifest,
        SnapshotProvenance {
            before_tenant_inputs: true,
            before_credentials: true,
            before_external_connections: true,
        },
        image_profile(),
    )
    .unwrap();
    let dirty = world
        .backend
        .snapshot(&handle, SnapshotOrigin::TenantWorkload)
        .unwrap();
    assert!(matches!(
        GoldenSnapshot::certify(
            dirty,
            SnapshotProvenance {
                before_tenant_inputs: false,
                before_credentials: true,
                before_external_connections: true
            },
            image_profile()
        ),
        Err(PoolRefusal::NotGolden { .. })
    ));
    let mut pool = WarmPool::new(2);
    pool.set_golden(golden);
    assert_eq!(pool.replenish(2), 2);
    for name in ["exe-a", "exe-b"] {
        world.stop_fully(name);
    }
    let checks_before = world.supervisor.measurements().pool().authority_checks;
    for name in ["exe-a", "exe-b"] {
        let request = world.request(name, SandboxClass::Task);
        let receipt = world
            .supervisor
            .checkout(
                request,
                &mut pool,
                &mut world.backend,
                &world.evidence.registry,
            )
            .unwrap();
        assert_eq!(receipt.decision, CheckoutDecision::Restore);
        assert!(
            matches!(receipt.launch, LaunchReceipt::AuthorityActive { boot, path: BootPath::WarmRestore, .. } if boot == SandboxBootGeneration::new(2))
        );
    }
    let counts = world.supervisor.measurements().pool();
    assert_eq!(
        counts.authority_checks - checks_before,
        2,
        "warm checkouts run the same authority checks as cold boots"
    );
    assert_eq!(
        counts.unique_identities, 4,
        "parallel restores get distinct identities"
    );
    assert_ne!(world.vm("exe-a"), world.vm("exe-b"));
    assert_eq!(counts.warm_restores, 2);
    assert_eq!(pool.available(), 0);

    // Depleted pool: cold, named.
    world.stop_fully("exe-a");
    let request = world.request("exe-a", SandboxClass::Task);
    let receipt = world
        .supervisor
        .checkout(
            request,
            &mut pool,
            &mut world.backend,
            &world.evidence.registry,
        )
        .unwrap();
    assert_eq!(
        receipt.decision,
        CheckoutDecision::ColdBoot {
            fallback: ColdFallback::PoolDepleted
        }
    );
    assert!(matches!(
        receipt.launch,
        LaunchReceipt::AuthorityActive {
            path: BootPath::Cold,
            ..
        }
    ));
    // A backend that cannot reset a clone's state: cold, named.
    pool.replenish(1);
    world.stop_fully("exe-a");
    world.backend.capabilities.state_reset = StateReset::Unsupported {
        detail: "no reseed".to_owned(),
    };
    let request = world.request("exe-a", SandboxClass::Task);
    let receipt = world
        .supervisor
        .checkout(
            request,
            &mut pool,
            &mut world.backend,
            &world.evidence.registry,
        )
        .unwrap();
    assert!(matches!(
        receipt.decision,
        CheckoutDecision::ColdBoot {
            fallback: ColdFallback::StateResetUnsupported { .. }
        }
    ));
    assert_eq!(pool.available(), 1, "a cold fallback takes no clone");
    // A new execution's first boot is always cold.
    world.backend.capabilities.state_reset = StateReset::Supported;
    let request = world.request("exe-new", SandboxClass::Task);
    let receipt = world
        .supervisor
        .checkout(
            request,
            &mut pool,
            &mut world.backend,
            &world.evidence.registry,
        )
        .unwrap();
    assert_eq!(
        receipt.decision,
        CheckoutDecision::ColdBoot {
            fallback: ColdFallback::NewExecution
        }
    );
    assert_eq!(world.supervisor.measurements().pool().cold_fallbacks, 3);
    // Restore refused by the backend: the transaction rolls back, nothing is exposed.
    world.stop_fully("exe-a");
    world.backend.failing.insert(BackendOperation::Restore);
    let request = world.request("exe-a", SandboxClass::Task);
    let receipt = world
        .supervisor
        .checkout(
            request,
            &mut pool,
            &mut world.backend,
            &world.evidence.registry,
        )
        .unwrap();
    assert!(matches!(receipt.launch, LaunchReceipt::RolledBack { .. }));
    assert_eq!(world.state("exe-a"), SandboxState::Stopped);
    let counts = world.supervisor.measurements().pool();
    assert_eq!(
        counts.warm_restores, 2,
        "a refused restore is not a warm restore"
    );
    assert_eq!(counts.restore_rollbacks, 1);
}

#[test]
fn a_queued_or_refused_warm_checkout_restores_nothing_and_keeps_its_clone() {
    for queue_wait in [Some(60 * SECOND), None] {
        queued_or_refused_checkout(queue_wait);
    }
}

/// A host with room for one 8 GiB sandbox (64 GiB, of which 56 GiB is the supervisor's
/// reserve), waiting up to `queue_wait` in the ledger's queue when given: exe-a is
/// stopped after its golden snapshot filled a pool of one clone, and exe-b holds the room.
fn one_room_world(queue_wait: Option<Duration>) -> (World, WarmPool) {
    let clock = Arc::new(ManualClock::new(at(100)));
    let evidence = Evidence::new(&clock);
    let mut ledger = real_ledger(&clock, 56 * GIB);
    if let Some(max_wait) = queue_wait {
        ledger = ledger.with_queue_wait(max_wait);
    }
    let mut backend = ScriptedBackend::new();
    backend.image_profile = image_profile();
    let supervisor = Supervisor::new(Arc::clone(&clock), session(1), ledger, waiting());
    let mut world = World {
        clock,
        evidence,
        backend,
        supervisor,
    };
    world.launched("exe-a", SandboxClass::Task);
    let handle = world
        .supervisor
        .handles()
        .get(&world.vm("exe-a"))
        .unwrap()
        .clone();
    let manifest = world
        .backend
        .snapshot(&handle, SnapshotOrigin::PreTenantGolden)
        .unwrap();
    let golden = GoldenSnapshot::certify(
        manifest,
        SnapshotProvenance {
            before_tenant_inputs: true,
            before_credentials: true,
            before_external_connections: true,
        },
        image_profile(),
    )
    .unwrap();
    let mut pool = WarmPool::new(1);
    pool.set_golden(golden);
    assert_eq!(pool.replenish(1), 1);
    world.stop_fully("exe-a");
    world.launched("exe-b", SandboxClass::Task);
    (world, pool)
}

fn queued_or_refused_checkout(queue_wait: Option<Duration>) {
    let (mut world, mut pool) = one_room_world(queue_wait);

    let request = world.request("exe-a", SandboxClass::Task);
    let receipt = world
        .supervisor
        .checkout(
            request,
            &mut pool,
            &mut world.backend,
            &world.evidence.registry,
        )
        .unwrap();
    match queue_wait {
        Some(_) => assert!(
            matches!(receipt.launch, LaunchReceipt::Queued { .. }),
            "{receipt:?}"
        ),
        None => assert!(
            matches!(
                receipt.launch,
                LaunchReceipt::RolledBack {
                    failure: crate::foundation::coordination::LaunchFailure::Capacity { .. },
                    ..
                }
            ),
            "{receipt:?}"
        ),
    }
    assert!(!world
        .backend
        .calls
        .iter()
        .any(|call| matches!(call, BackendCall::Restore(_))));
    assert_eq!(pool.available(), 1, "the clone goes back to the pool");
    let counts = world.supervisor.measurements().pool();
    assert_eq!(counts.warm_restores, 0);
    assert_eq!(counts.restore_rollbacks, 0);
}

/// The key of the reservation the coordinator's relaunch of `name` makes for `boot`.
fn relaunch_key(name: &str, boot: u64) -> ReservationKey {
    ReservationKey::derive(
        &execution(name),
        &ReservationPurpose::Sandbox {
            boot: SandboxBootGeneration::new(boot),
        },
    )
}

/// The reservations the ledger holds open for `name`.
fn open_reservations_of(world: &World, name: &str) -> usize {
    world
        .supervisor
        .coordinator()
        .capacity()
        .ledger()
        .open_reservations()
        .filter(|record| record.provenance().execution == execution(name))
        .count()
}

/// The steps of a boot from a stopped sandbox to authority, warm or cold.
const RELAUNCH_STEPS: [StepKind; 6] = [
    StepKind::NewBoot,
    StepKind::ReserveResources,
    StepKind::PreparePerimeter,
    StepKind::CreateVm,
    StepKind::CheckBootEvidence,
    StepKind::ActivateAuthority,
];

/// §6.6 lines 2336–2353 and S10 line 351 (bounded queueing): a warm checkout the ledger
/// queues keeps its warm decision. While it waits nothing is taken, restored or booted and
/// the sandbox stays stopped at its boot, even when the pool is empty for a while; once the
/// queue grants the relaunch's reservation, the next checkout takes a clone then and
/// restores it through the same relaunch and authority checks as a cold boot, under the
/// reservation the queue granted.
#[test]
fn a_queued_warm_checkout_restores_from_the_pool_once_capacity_is_granted() {
    let (mut world, mut pool) = one_room_world(Some(60 * SECOND));
    let counts_before = world.supervisor.measurements().pool();
    let calls_before = world.backend.calls.len();
    for _ in 0..2 {
        let receipt = world.checkout("exe-a", &mut pool);
        assert_eq!(receipt.decision, CheckoutDecision::Restore);
        assert!(
            matches!(receipt.launch, LaunchReceipt::Queued { position: 1, .. }),
            "{receipt:?}"
        );
        assert!(!receipt.failed_clone_cleaned_up);
        assert_eq!(
            pool.available(),
            1,
            "nothing is taken while the launch waits"
        );
        assert_eq!(world.state("exe-a"), SandboxState::Stopped);
        assert_eq!(world.boot("exe-a"), SandboxBootGeneration::FIRST);
    }
    assert_eq!(
        world.backend.calls.len(),
        calls_before,
        "no backend call while queued"
    );
    // The pool is empty for a while during the wait: the retry decides nothing yet.
    assert!(pool.take().is_ok());
    let receipt = world.checkout("exe-a", &mut pool);
    assert_eq!(
        receipt.decision,
        CheckoutDecision::ColdBoot {
            fallback: ColdFallback::PoolDepleted
        }
    );
    assert!(matches!(
        receipt.launch,
        LaunchReceipt::Queued { position: 1, .. }
    ));
    assert_eq!(world.state("exe-a"), SandboxState::Stopped);
    assert_eq!(pool.replenish(1), 1);

    // exe-b stops; the ledger's queue grants the relaunch's reservation.
    world.stop_fully("exe-b");
    assert!(world
        .supervisor
        .coordinator()
        .capacity()
        .record(&relaunch_key("exe-a", 2))
        .is_some());
    let receipt = world.checkout("exe-a", &mut pool);
    assert_eq!(receipt.decision, CheckoutDecision::Restore);
    assert!(
        matches!(
            receipt.launch,
            LaunchReceipt::AuthorityActive {
                path: BootPath::WarmRestore,
                boot,
                ..
            } if boot == SandboxBootGeneration::new(2)
        ),
        "{receipt:?}"
    );
    assert_eq!(
        pool.available(),
        0,
        "the clone is taken once capacity is granted"
    );
    let restores: Vec<_> = world.backend.calls[calls_before..]
        .iter()
        .filter(|call| matches!(call, BackendCall::Restore(_)))
        .collect();
    assert_eq!(
        restores,
        [&BackendCall::Restore(SandboxBootGeneration::new(2))]
    );
    assert_eq!(
        world.steps_of("exe-a", SandboxBootGeneration::new(2)),
        RELAUNCH_STEPS,
        "the restore passes every step a cold boot passes"
    );
    let sandbox = world
        .supervisor
        .coordinator()
        .sandbox(&execution("exe-a"))
        .unwrap();
    assert_eq!(sandbox.reservation(), Some(relaunch_key("exe-a", 2)));
    assert!(sandbox.restored_from().is_some());
    assert_eq!(sandbox.verified_restore(), sandbox.vm());
    assert_eq!(
        open_reservations_of(&world, "exe-a"),
        1,
        "the queue's grant is the relaunch's own reservation"
    );
    assert_eq!(
        world
            .supervisor
            .sandbox(&execution("exe-a"))
            .unwrap()
            .boot_path,
        BootPath::WarmRestore
    );
    let counts = world.supervisor.measurements().pool();
    assert_eq!(counts.warm_restores - counts_before.warm_restores, 1);
    assert_eq!(counts.cold_fallbacks, counts_before.cold_fallbacks);
    assert_eq!(counts.restore_rollbacks, 0);
    assert_eq!(
        counts.authority_checks - counts_before.authority_checks,
        4,
        "every checkout answered counts once, queued ones as a queued cold launch does"
    );
}

/// §6.6 line 2350 and VM-W27 line 2633: a queued warm checkout whose pool runs out before
/// capacity is granted boots cold with the depletion named, through the same steps.
#[test]
fn a_queued_warm_checkout_boots_cold_named_when_the_pool_runs_out_meanwhile() {
    let (mut world, mut pool) = one_room_world(Some(60 * SECOND));
    let counts_before = world.supervisor.measurements().pool();
    let receipt = world.checkout("exe-a", &mut pool);
    assert!(matches!(receipt.launch, LaunchReceipt::Queued { .. }));
    assert_eq!(pool.available(), 1);
    // Another checkout takes the last clone meanwhile. Retried while still queued, the
    // checkout decides, boots and counts nothing yet.
    assert!(pool.take().is_ok());
    let receipt = world.checkout("exe-a", &mut pool);
    assert_eq!(
        receipt.decision,
        CheckoutDecision::ColdBoot {
            fallback: ColdFallback::PoolDepleted
        }
    );
    assert!(matches!(receipt.launch, LaunchReceipt::Queued { .. }));
    assert_eq!(world.state("exe-a"), SandboxState::Stopped);
    assert_eq!(
        world.supervisor.measurements().pool().cold_fallbacks,
        counts_before.cold_fallbacks
    );
    world.stop_fully("exe-b");
    let calls_before = world.backend.calls.len();
    let receipt = world.checkout("exe-a", &mut pool);
    assert_eq!(
        receipt.decision,
        CheckoutDecision::ColdBoot {
            fallback: ColdFallback::PoolDepleted
        }
    );
    assert!(
        matches!(
            receipt.launch,
            LaunchReceipt::AuthorityActive {
                path: BootPath::Cold,
                boot,
                ..
            } if boot == SandboxBootGeneration::new(2)
        ),
        "{receipt:?}"
    );
    assert!(world.backend.calls[calls_before..]
        .iter()
        .all(|call| !matches!(call, BackendCall::Restore(_))));
    assert_eq!(
        world.steps_of("exe-a", SandboxBootGeneration::new(2)),
        RELAUNCH_STEPS
    );
    assert_eq!(open_reservations_of(&world, "exe-a"), 1);
    let counts = world.supervisor.measurements().pool();
    assert_eq!(counts.warm_restores, counts_before.warm_restores);
    assert_eq!(counts.cold_fallbacks - counts_before.cold_fallbacks, 1);
    assert_eq!(counts.restore_rollbacks, 0);
}

/// S10 line 351: a queued warm checkout the ledger then refuses ends with nothing taken,
/// restored or booted, and keeps the warm decision for when capacity returns.
#[test]
fn a_queued_warm_checkout_then_refused_takes_nothing() {
    let (mut world, mut pool) = one_room_world(Some(60 * SECOND));
    let counts_before = world.supervisor.measurements().pool();
    let receipt = world.checkout("exe-a", &mut pool);
    assert!(matches!(receipt.launch, LaunchReceipt::Queued { .. }));
    // The tenant's budget drops below the demand: the queue refuses the waiting request,
    // and so does the ledger when the checkout is retried.
    let ram = ResourceKey::Host(HostResource::Ram);
    world
        .supervisor
        .coordinator_mut()
        .capacity_mut()
        .ledger_mut()
        .set_tenant_budget(tenant(), ram, 4 * GIB)
        .unwrap();
    world.supervisor.take_receipts();
    let calls_before = world.backend.calls.len();
    let receipt = world.checkout("exe-a", &mut pool);
    assert_eq!(receipt.decision, CheckoutDecision::Restore);
    match &receipt.launch {
        LaunchReceipt::RolledBack {
            failure: LaunchFailure::Capacity { .. },
            compensations,
            ..
        } => assert!(compensations.is_empty(), "nothing was done to undo"),
        other => panic!("{other:?}"),
    }
    assert_eq!(pool.available(), 1, "nothing is taken");
    assert_eq!(world.backend.calls.len(), calls_before, "no backend call");
    assert_eq!(world.state("exe-a"), SandboxState::Stopped);
    assert_eq!(world.boot("exe-a"), SandboxBootGeneration::FIRST);
    assert_eq!(open_reservations_of(&world, "exe-a"), 0);
    assert!(matches!(
        world.supervisor.take_receipts().as_slice(),
        [LifecycleReceipt::LaunchFailed {
            failure: LaunchFailure::Capacity { .. },
            ..
        }]
    ));
    let counts = world.supervisor.measurements().pool();
    assert_eq!(counts.warm_restores, counts_before.warm_restores);
    assert_eq!(counts.cold_fallbacks, counts_before.cold_fallbacks);
    assert_eq!(counts.restore_rollbacks, 0);

    // Budget and room back: the warm decision still holds.
    world
        .supervisor
        .coordinator_mut()
        .capacity_mut()
        .ledger_mut()
        .set_tenant_budget(tenant(), ram, 64 * GIB)
        .unwrap();
    world.stop_fully("exe-b");
    let receipt = world.checkout("exe-a", &mut pool);
    assert!(
        matches!(
            receipt.launch,
            LaunchReceipt::AuthorityActive {
                path: BootPath::WarmRestore,
                ..
            }
        ),
        "{receipt:?}"
    );
    assert_eq!(pool.available(), 0);
}

#[test]
fn a_violation_stops_an_ephemeral_sandbox_and_locks_a_service_down() {
    let mut world = World::new();
    world.launched("exe-task", SandboxClass::Task);
    world.launched("exe-service", SandboxClass::Service);
    let response = world
        .supervisor
        .violation(&execution("exe-task"), &mut world.backend)
        .unwrap();
    assert!(matches!(response, ViolationResponse::Stopped { .. }));
    assert_eq!(world.stops_of("exe-task"), 1);
    assert!(!world.backend.is_live(&world.vm("exe-task")));
    let response = world
        .supervisor
        .violation(&execution("exe-service"), &mut world.backend)
        .unwrap();
    let ViolationResponse::LockedDown { token, .. } = response else {
        panic!("{response:?}");
    };
    assert_eq!(
        world.stops_of("exe-service"),
        0,
        "a service locks down; it does not stop"
    );
    assert!(matches!(
        world.work("exe-service", "op"),
        Err(SupervisorError::LockedDown { .. })
    ));
    assert!(matches!(
        world.supervisor.violation(&execution("exe-service"), &mut world.backend).unwrap(),
        ViolationResponse::LockedDown { token: same, .. } if same == token
    ));
    let wrong = StopToken::from_digest_for_test(named("yougori/test/token/v1", "forged"));
    assert!(matches!(
        world
            .supervisor
            .stop_locked_down(&execution("exe-service"), wrong, &mut world.backend),
        Err(SupervisorError::WrongStopToken { .. })
    ));
    assert!(matches!(
        world
            .supervisor
            .stop_locked_down(&execution("exe-task"), token, &mut world.backend),
        Err(SupervisorError::NotLockedDown { .. })
    ));
    let progress = world
        .supervisor
        .stop_locked_down(&execution("exe-service"), token, &mut world.backend)
        .unwrap();
    assert!(
        progress.acknowledged.contains(&Acknowledgment::VmStopped),
        "one step: the VM is stopped"
    );
    assert_eq!(world.stops_of("exe-service"), 1);
}

#[test]
fn the_revocation_reserve_is_never_consumed_and_revocation_needs_no_capacity() {
    let mut world = World::with(waiting(), 8 * GIB);
    let mut request = world.request("exe-big", SandboxClass::Task);
    request.demand = BTreeMap::from([(ResourceKind::HostMemoryBytes, 56 * GIB)]);
    assert!(matches!(
        world
            .supervisor
            .launch(request, &mut world.backend, &world.evidence.registry)
            .unwrap(),
        LaunchReceipt::AuthorityActive { .. }
    ));
    let mut request = world.request("exe-more", SandboxClass::Task);
    request.demand = BTreeMap::from([(ResourceKind::HostMemoryBytes, GIB)]);
    let receipt = world
        .supervisor
        .launch(request, &mut world.backend, &world.evidence.registry)
        .unwrap();
    assert!(
        matches!(
            receipt,
            LaunchReceipt::RolledBack {
                failure: crate::foundation::coordination::LaunchFailure::Capacity {
                    refusal: crate::foundation::coordination::CapacityRefusal::Insufficient {
                        available: 0,
                        ..
                    }
                },
                ..
            }
        ),
        "{receipt:?}"
    );
    let ram = ResourceKey::Host(HostResource::Ram);
    let capacity = world
        .supervisor
        .coordinator()
        .capacity()
        .ledger()
        .capacity(ram)
        .unwrap();
    assert_eq!(capacity.supervisor_reserve, 8 * GIB);
    assert_eq!(capacity.grantable(), 56 * GIB);
    let reserves_before = world.backend.calls.len();
    world.stop_fully("exe-big");
    assert!(world.backend.calls[reserves_before..]
        .iter()
        .all(|call| matches!(
            call,
            BackendCall::CheckHandle(_) | BackendCall::Stop(_) | BackendCall::Teardown(_)
        )));
    assert_eq!(
        world
            .supervisor
            .coordinator()
            .capacity()
            .ledger()
            .reserved(ram),
        0
    );
}

#[test]
fn revocation_receipts_travel_on_the_core06_priority_lane() {
    let mut world = World::new();
    world.launched("exe-task", SandboxClass::Task);
    world
        .supervisor
        .revoke(
            &execution("exe-task"),
            RevocationCause::PolicyChanged,
            &mut world.backend,
        )
        .unwrap();
    let receipts = world.supervisor.take_receipts();
    let Some(LifecycleReceipt::Revoked {
        revocation,
        context,
        cause,
    }) = receipts
        .iter()
        .find(|receipt| matches!(receipt, LifecycleReceipt::Revoked { .. }))
    else {
        panic!("{receipts:?}");
    };
    assert_eq!(*cause, RevocationCause::PolicyChanged);
    let mut hub = EventHub::new(
        Arc::clone(&world.clock),
        HubConfig {
            metrics: MetricsConfig {
                capacity_events: 4,
                sample_above_events: 2,
                keep_one_in: NonZeroU32::new(2).unwrap(),
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
        },
    )
    .unwrap();
    let mut issuer = hub
        .register_revocation_issuer(ProducerId::new("lifecycle-supervisor").unwrap())
        .unwrap();
    assert_eq!(
        hub.emit_revocation(&mut issuer, context.clone(), revocation.clone())
            .unwrap(),
        RevocationAdmission::Queued
    );
    let batch = hub.drain_revocations();
    assert_eq!(batch.notices.len(), 1);
    assert_eq!(batch.notices[0].payload().epoch, AuthorizationEpoch::new(2));
    assert_eq!(
        batch.notices[0].payload().reason,
        RevocationReason::PolicyChanged
    );
    assert_eq!(batch.notices[0].phase(), Phase::Revoked);
    assert_eq!(
        batch.notices[0].generations().authorization,
        Some(AuthorizationEpoch::new(2))
    );
}

#[test]
fn bounded_messages_drive_the_supervisor() {
    let mut world = World::new();
    world.launched("exe-task", SandboxClass::Task);
    let peer = PeerIdentity::Authenticated {
        principal: "engine".to_owned(),
    };
    let parse =
        |json: serde_json::Value| MessageFrame::parse(&peer, json.to_string().as_bytes()).unwrap();
    let activity = parse(
        serde_json::json!({"message": "activity", "execution": "exe-task", "kind": "command"}),
    );
    assert_eq!(
        world
            .supervisor
            .apply_message(activity, &mut world.backend)
            .unwrap(),
        MessageOutcome::ActivityRecorded
    );
    let traffic = parse(
        serde_json::json!({"message": "activity", "execution": "exe-task", "kind": "network_traffic"}),
    );
    assert!(matches!(
        world.supervisor.apply_message(traffic, &mut world.backend),
        Err(SupervisorError::Activity { .. })
    ));
    let revoke = parse(
        serde_json::json!({"message": "revoke", "execution": "exe-task", "cause": {"cause": "user_requested"}}),
    );
    assert!(matches!(
        world
            .supervisor
            .apply_message(revoke, &mut world.backend)
            .unwrap(),
        MessageOutcome::Revoked { .. }
    ));
    let ack = parse(
        serde_json::json!({"message": "acknowledge", "execution": "exe-task", "acknowledgment": "channels_closed"}),
    );
    assert_eq!(
        world
            .supervisor
            .apply_message(ack, &mut world.backend)
            .unwrap(),
        MessageOutcome::Acknowledged {
            effect: AckEffect::Recorded
        }
    );
    let stop = parse(serde_json::json!({"message": "stop", "execution": "exe-task"}));
    assert!(matches!(
        world
            .supervisor
            .apply_message(stop, &mut world.backend)
            .unwrap(),
        MessageOutcome::Stopped { .. }
    ));
    assert_eq!(world.state("exe-task"), SandboxState::Stopped);
    let mut graph = WatchdogGraph::new();
    graph
        .declare(
            WatchdogId::new("service-manager").unwrap(),
            WatchdogId::new("supervisor").unwrap(),
        )
        .unwrap();
    assert!(matches!(
        graph.declare(
            WatchdogId::new("supervisor").unwrap(),
            WatchdogId::new("service-manager").unwrap()
        ),
        Err(WatchdogRefusal::MutualDependency { .. })
    ));
}

/// The §12.3 model against the supervisor: every sequence of the mapped operations up to
/// depth four, each on a fresh world with one service sandbox. Launch maps to a new boot
/// where the model allows one, then reserve, enforcement ready and authorize; Revoke to
/// revoke; Advance to a cleanup retry past the lease-expiry bound; Persist and Restore to
/// themselves, a restore confirming its recovered state as a real supervisor does.
/// State-space bound: 5^4 sequences.
#[test]
fn the_lifecycle_model_agrees_with_the_supervisor_on_every_short_sequence() {
    let enumeration = model::enumerate(model::DEFAULT_DEPTH);
    assert!(enumeration.violations.is_empty(), "{enumeration}");
    #[derive(Clone, Copy, Debug)]
    enum Step {
        Launch,
        Revoke,
        Advance,
        Persist,
        Restore,
    }
    const STEPS: [Step; 5] = [
        Step::Launch,
        Step::Revoke,
        Step::Advance,
        Step::Persist,
        Step::Restore,
    ];
    const DEPTH: usize = 4;
    let mut sequences = 0u64;
    let mut stack: Vec<Vec<Step>> = STEPS.iter().map(|step| vec![*step]).collect();
    while let Some(sequence) = stack.pop() {
        sequences += 1;
        let mut world = World::new();
        let mut model = model::ModelState::initial();
        let mut persisted: Option<PersistedSupervisor> = None;
        let exe = execution("exe-model");
        for step in &sequence {
            let tombstones_before = world.supervisor.replay().tombstones().len();
            let epoch_before = world
                .supervisor
                .coordinator()
                .sandbox(&exe)
                .map(|s| s.generations().authorization);
            let mut restored = false;
            match step {
                Step::Launch => {
                    let request = world.request("exe-model", SandboxClass::Service);
                    let _ = world.supervisor.launch(
                        request,
                        &mut world.backend,
                        &world.evidence.registry,
                    );
                    if model.accepts(Op::NewBoot) {
                        model = model.step(Op::NewBoot);
                    }
                    model = model
                        .step(Op::Reserve)
                        .step(Op::EnforcementReady)
                        .step(Op::Authorize);
                }
                Step::Revoke => {
                    let _ = world.supervisor.revoke(
                        &exe,
                        RevocationCause::UserRequested,
                        &mut world.backend,
                    );
                    model = model.step(Op::Revoke);
                }
                Step::Advance => {
                    if world.supervisor.revocation(&exe).is_some() {
                        world.clock.advance(DEFAULT_SERVICE_RENEWAL + 60 * SECOND);
                    }
                    let _ = world.supervisor.advance(&exe, &mut world.backend);
                    model = model.step(Op::CleanupRetry);
                }
                Step::Persist => {
                    persisted = Some(world.supervisor.persist());
                    model = model.step(Op::Persist);
                }
                Step::Restore => {
                    if let Some(state) = persisted.clone() {
                        let ledger = real_ledger(&world.clock, 0);
                        let (mut recovered, _) = Supervisor::recover(
                            state,
                            Arc::clone(&world.clock),
                            session(9),
                            ledger,
                            waiting(),
                            &mut world.backend,
                        )
                        .unwrap();
                        let state = recovered.persist();
                        recovered.confirm_persisted(&state);
                        world.supervisor = recovered;
                        restored = true;
                    }
                    model = model.step(Op::RestorePersisted);
                }
            }
            let sandbox = world.supervisor.coordinator().sandbox(&exe);
            let holds =
                sandbox.is_some_and(|s| s.state().holds_authority() && s.authority().is_some());
            assert_eq!(holds, model.authority.is_some(), "{sequence:?} at {step:?}");
            if holds {
                let kinds: Vec<StepKind> = sandbox
                    .unwrap()
                    .log()
                    .iter()
                    .map(|r| r.step.kind())
                    .collect();
                let ready = kinds
                    .iter()
                    .rposition(|k| *k == StepKind::CheckBootEvidence);
                let granted = kinds
                    .iter()
                    .rposition(|k| *k == StepKind::ActivateAuthority);
                assert!(ready < granted, "authority before enforcement: {kinds:?}");
            }
            if !restored {
                assert!(
                    world.supervisor.replay().tombstones().len() >= tombstones_before,
                    "tombstones never shrink"
                );
            }
            if matches!(step, Step::Advance) {
                let epoch_after = world
                    .supervisor
                    .coordinator()
                    .sandbox(&exe)
                    .map(|s| s.generations().authorization);
                assert_eq!(
                    epoch_before, epoch_after,
                    "a cleanup retry never changes the epoch"
                );
            }
            if restored {
                assert!(
                    !holds,
                    "a restore never brings authority back: {sequence:?}"
                );
            }
            let authorizes = world.work("exe-model", "op").is_ok();
            assert_eq!(
                authorizes,
                holds && world.supervisor.revocation(&exe).is_none(),
                "{sequence:?} at {step:?}"
            );
        }
        if sequence.len() < DEPTH {
            for step in STEPS {
                let mut longer = sequence.clone();
                longer.push(step);
                stack.push(longer);
            }
        }
    }
    assert_eq!(sequences, 5 + 25 + 125 + 625);
}

// ---- CORE-04 milestones and per-grant revocation (§6.3 lines 2304–2323; VM-P14) ----

fn route(name: &str) -> NetworkGrant {
    NetworkGrant::NamedRoute {
        route: named("yougori/test/route/v1", name),
    }
}

fn granted(names: &[GrantId]) -> BTreeSet<GrantId> {
    names.iter().copied().collect()
}

fn priority_hub(clock: &TestClock) -> EventHub<TestClock> {
    EventHub::new(
        Arc::clone(clock),
        HubConfig {
            metrics: MetricsConfig {
                capacity_events: 4,
                sample_above_events: 2,
                keep_one_in: NonZeroU32::new(2).unwrap(),
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
        },
    )
    .unwrap()
}

/// VM-P14 and VM-CP-14: "new authorizations denied" is CORE-04's first denied
/// authorization, the first request actually refused after the decision, measured apart
/// from the decision and kept with what refused it; the decision alone never
/// acknowledges it, and the first refusal stands.
#[test]
fn new_authorizations_denied_is_the_first_refusal_core04_records() {
    let mut world = World::new();
    world.launched("exe-task", SandboxClass::Task);
    let exe = execution("exe-task");
    world.advance(10 * SECOND);
    world
        .supervisor
        .revoke(&exe, RevocationCause::UserRequested, &mut world.backend)
        .unwrap();
    world.supervisor.take_receipts();
    assert!(world.supervisor.sync_revocation(&exe).unwrap().is_empty());
    let run = world.supervisor.revocation(&exe).unwrap();
    assert_eq!(
        run.acknowledged_at(Acknowledgment::NewAuthorizationsDenied),
        None
    );
    assert_eq!(
        world
            .supervisor
            .coordinator()
            .revocation(&exe)
            .unwrap()
            .milestone(RevocationMilestone::NewAuthorizationsDenied),
        Some(at(110)),
        "CORE-04's decision milestone is the decision, not the acknowledgment"
    );
    assert!(world
        .supervisor
        .measurements()
        .summarize(StopPhase::RevokeToDeny)
        .map_or(true, |summary| summary.successes == 0));

    // Two seconds later a request comes: the coordinator's own check refuses it.
    world.advance(2 * SECOND);
    assert!(matches!(
        world.work("exe-task", "op-late"),
        Err(SupervisorError::Revoked { .. })
    ));
    let operation = world.supervisor.coordinator().revocation(&exe).unwrap();
    assert_eq!(
        operation.milestone(RevocationMilestone::FirstDeniedAuthorization),
        Some(at(112))
    );
    assert!(matches!(
        operation.first_denied_authorization().unwrap().denial,
        Denial::Coordinator {
            request: DeniedRequest::NewLease {
                kind: LeaseKind::ChildWork
            },
            ..
        }
    ));
    assert!(
        world.supervisor.take_receipts().is_empty(),
        "the run takes it at its next step"
    );
    assert_eq!(
        world.supervisor.sync_revocation(&exe).unwrap(),
        [Acknowledgment::NewAuthorizationsDenied]
    );
    let run = world.supervisor.revocation(&exe).unwrap();
    assert_eq!(
        run.elapsed(Acknowledgment::NewAuthorizationsDenied),
        Some(2 * SECOND)
    );
    assert_eq!(
        run.source(Acknowledgment::NewAuthorizationsDenied),
        Some(AckSource::Coordination {
            milestone: RevocationMilestone::FirstDeniedAuthorization,
            source: MilestoneSource::Coordinator
        })
    );
    let receipts = world.supervisor.take_receipts();
    assert!(
        matches!(
            &receipts[..],
            [LifecycleReceipt::Acknowledged {
                acknowledgment: Acknowledgment::NewAuthorizationsDenied,
                at: when,
                source: AckSource::Coordination { .. },
                ..
            }] if *when == at(112)
        ),
        "{receipts:?}"
    );
    assert_eq!(
        world
            .supervisor
            .measurements()
            .summarize(StopPhase::RevokeToDeny)
            .unwrap()
            .percentile(Quantile::P50)
            .unwrap()
            .value_nanos
            .value()
            .copied(),
        Some(2e9)
    );
    // A later refusal, or an enforcement point's report, never moves the first.
    world.advance(SECOND);
    assert_eq!(
        world
            .supervisor
            .acknowledge(&exe, Acknowledgment::NewAuthorizationsDenied)
            .unwrap(),
        AckEffect::AlreadyRecorded
    );
    assert!(world.supervisor.sync_revocation(&exe).unwrap().is_empty());
    assert_eq!(
        world
            .supervisor
            .revocation(&exe)
            .unwrap()
            .acknowledged_at(Acknowledgment::NewAuthorizationsDenied),
        Some(at(112))
    );

    // An enforcement point outside the coordinator may be the first to refuse, as the host
    // observed; a guest's word is too weak for CORE-04.
    let mut world = World::new();
    world.launched("exe-task", SandboxClass::Task);
    world
        .supervisor
        .revoke(&exe, RevocationCause::PolicyChanged, &mut world.backend)
        .unwrap();
    world.advance(SECOND);
    assert!(matches!(
        world.supervisor.acknowledge_from(
            &exe,
            Acknowledgment::NewAuthorizationsDenied,
            SourceClass::GuestReport
        ),
        Err(SupervisorError::Coordination {
            error: CoordinationError::AcknowledgmentTooWeak { .. }
        })
    ));
    assert_eq!(
        world
            .supervisor
            .acknowledge(&exe, Acknowledgment::NewAuthorizationsDenied)
            .unwrap(),
        AckEffect::Recorded
    );
    assert_eq!(
        world
            .supervisor
            .revocation(&exe)
            .unwrap()
            .source(Acknowledgment::NewAuthorizationsDenied),
        Some(AckSource::Coordination {
            milestone: RevocationMilestone::FirstDeniedAuthorization,
            source: MilestoneSource::Acknowledged {
                source: SourceClass::HostProbe
            }
        })
    );
}

/// §6.3 step 2: "channels closed" is CORE-04's all channels closed as the host observed
/// it; sockets closed alone never is, a guest's report is refused, and an enforcement
/// point that reports to the coordinator directly is taken at the run's next step.
#[test]
fn channels_closed_is_core04s_all_channels_closed_from_the_host() {
    let mut world = World::new();
    world.launched("exe-task", SandboxClass::Task);
    let exe = execution("exe-task");
    world
        .supervisor
        .revoke(&exe, RevocationCause::UserRequested, &mut world.backend)
        .unwrap();
    world.advance(SECOND);
    world
        .supervisor
        .coordinator_mut()
        .acknowledge_revocation(
            &exe,
            RevocationMilestone::SocketsClosed,
            SourceClass::HostProbe,
        )
        .unwrap();
    let progress = world.supervisor.advance(&exe, &mut world.backend).unwrap();
    assert!(matches!(progress.gate, TerminationGate::Wait { .. }));
    assert!(!progress
        .acknowledged
        .contains(&Acknowledgment::ChannelsClosed));
    assert_eq!(world.stops_of("exe-task"), 0);
    assert!(matches!(
        world.supervisor.acknowledge_from(
            &exe,
            Acknowledgment::ChannelsClosed,
            SourceClass::GuestReport
        ),
        Err(SupervisorError::Coordination {
            error: CoordinationError::AcknowledgmentTooWeak { .. }
        })
    ));
    assert_eq!(
        world
            .supervisor
            .acknowledge(&exe, Acknowledgment::ChannelsClosed)
            .unwrap(),
        AckEffect::Recorded
    );
    assert_eq!(
        world
            .supervisor
            .acknowledge(&exe, Acknowledgment::ChannelsClosed)
            .unwrap(),
        AckEffect::AlreadyRecorded
    );
    let run = world.supervisor.revocation(&exe).unwrap();
    assert_eq!(run.elapsed(Acknowledgment::ChannelsClosed), Some(SECOND));
    assert_eq!(
        run.source(Acknowledgment::ChannelsClosed),
        Some(AckSource::Coordination {
            milestone: RevocationMilestone::AllChannelsClosed,
            source: MilestoneSource::Acknowledged {
                source: SourceClass::HostProbe
            }
        })
    );
    assert_eq!(
        run.termination_gate(
            world.clock.now(),
            TerminationTiming::AfterChannelAcknowledgmentOrBound
        ),
        TerminationGate::ChannelsClosed
    );

    // An enforcement point reporting to the coordinator itself: the next tick takes it.
    let mut world = World::new();
    world.launched("exe-task", SandboxClass::Task);
    world
        .supervisor
        .revoke(&exe, RevocationCause::UserRequested, &mut world.backend)
        .unwrap();
    world.advance(3 * SECOND);
    world
        .supervisor
        .coordinator_mut()
        .acknowledge_revocation(
            &exe,
            RevocationMilestone::AllChannelsClosed,
            SourceClass::HostProbe,
        )
        .unwrap();
    assert_eq!(
        world
            .supervisor
            .revocation(&exe)
            .unwrap()
            .acknowledged_at(Acknowledgment::ChannelsClosed),
        None
    );
    world.supervisor.tick(&mut world.backend).unwrap();
    assert_eq!(
        world
            .supervisor
            .revocation(&exe)
            .unwrap()
            .elapsed(Acknowledgment::ChannelsClosed),
        Some(3 * SECOND)
    );
    assert!(matches!(
        world
            .supervisor
            .acknowledge(&exe, Acknowledgment::CleanupFinished),
        Err(SupervisorError::Acknowledgment {
            refusal: AckRefusal::NeedsCleanupReport
        })
    ));
}

/// CORE-04 per-grant revocation as a supervisor operation: one grant is revoked alone,
/// its work is cancelled and refused, and the epoch, the state, the VM, the sandbox's
/// other grants and its other work stay; the receipt is a grant revocation on the
/// priority lane, never a revocation, and nothing about it can be acknowledged.
#[test]
fn a_grant_revocation_leaves_the_epoch_the_other_grants_and_the_vm() {
    let mut world = World::new();
    let mut request = world.request("exe-task", SandboxClass::Task);
    request.settings.network = [route("a"), route("b")].into_iter().collect();
    world
        .supervisor
        .launch(request, &mut world.backend, &world.evidence.registry)
        .unwrap();
    let exe = execution("exe-task");
    let (grant_a, grant_b) = (network_grant_id(&route("a")), network_grant_id(&route("b")));
    let on_a = world
        .supervisor
        .authorize_granted_work(
            &exe,
            operation("op-a"),
            LeaseKind::ChildWork,
            call(),
            granted(&[grant_a]),
        )
        .unwrap();
    let on_b = world
        .supervisor
        .authorize_granted_work(
            &exe,
            operation("op-b"),
            LeaseKind::ChildWork,
            call(),
            granted(&[grant_b]),
        )
        .unwrap();
    let plain = world.work("exe-task", "op-plain").unwrap();
    let epoch = world
        .supervisor
        .coordinator()
        .sandbox(&exe)
        .unwrap()
        .generations()
        .authorization;
    world.supervisor.take_receipts();
    world.advance(SECOND);

    let record = world
        .supervisor
        .revoke_grant(&exe, grant_a, GrantRevocationCause::Violation)
        .unwrap();
    assert_eq!(record.revoked.epoch, epoch);
    assert_eq!(record.revoked.network, Some(route("a")));
    assert_eq!(
        record
            .revoked
            .cancellations
            .iter()
            .map(|cancellation| cancellation.lease)
            .collect::<Vec<_>>(),
        [on_a.id()]
    );
    // The epoch, the state, the VM, the other grants and the other work stay.
    let sandbox = world.supervisor.coordinator().sandbox(&exe).unwrap();
    assert_eq!(sandbox.generations().authorization, epoch);
    assert!(!sandbox.settings_grant().network.contains(&route("a")));
    assert!(sandbox.settings_grant().network.contains(&route("b")));
    assert_eq!(world.state("exe-task"), SandboxState::AuthorityActive);
    assert_eq!(world.stops_of("exe-task"), 0);
    assert!(world.supervisor.revocation(&exe).is_none());
    assert!(world.supervisor.replay().tombstones().is_empty());
    assert_eq!(
        world.supervisor.coordinator().check_lease(on_a.id()),
        Err(LeaseRefusal::Cancelled {
            cause: CancelCause::GrantRevoked
        })
    );
    assert!(world
        .supervisor
        .coordinator()
        .check_lease(on_b.id())
        .is_ok());
    assert!(world
        .supervisor
        .coordinator()
        .check_lease(plain.id())
        .is_ok());
    assert!(matches!(
        world.supervisor.authorize_granted_work(
            &exe,
            operation("op-a2"),
            LeaseKind::ChildWork,
            call(),
            granted(&[grant_a, grant_b]),
        ),
        Err(SupervisorError::Lease {
            refusal: LeaseRefusal::GrantRevoked { grant }
        }) if grant == grant_a
    ));
    assert!(world
        .supervisor
        .authorize_granted_work(
            &exe,
            operation("op-b2"),
            LeaseKind::ChildWork,
            call(),
            granted(&[grant_b]),
        )
        .is_ok());

    // Its receipt is a grant revocation naming the epoch left in force.
    let receipts = world.supervisor.take_receipts();
    let [LifecycleReceipt::GrantRevoked {
        revocation,
        cause,
        cancelled,
        context,
    }] = &receipts[..]
    else {
        panic!("{receipts:?}");
    };
    assert_eq!(*revocation, record.revocation());
    assert_eq!(revocation.grant, grant_a);
    assert_eq!(revocation.epoch, epoch);
    assert_eq!(revocation.reason, RevocationReason::SecurityEvent);
    assert_eq!(*cause, GrantRevocationCause::Violation);
    assert_eq!(cancelled, &[on_a.id()]);
    assert_eq!(context.phase, Phase::Revoked);
    assert_eq!(context.generations.authorization, Some(epoch));
    let mut hub = priority_hub(&world.clock);
    let mut issuer = hub
        .register_revocation_issuer(ProducerId::new("lifecycle-supervisor").unwrap())
        .unwrap();
    assert_eq!(
        hub.emit_grant_revocation(&mut issuer, context.clone(), revocation.clone())
            .unwrap(),
        RevocationAdmission::Queued
    );
    let batch = hub.drain_revocations();
    assert!(batch.notices.is_empty(), "no revocation of the sandbox");
    assert_eq!(batch.grants.len(), 1);
    assert_eq!(batch.grants[0].payload().grant, grant_a);
    assert_eq!(batch.grants[0].payload().epoch, epoch);

    // Revoking it again returns the same record and adds no receipt.
    assert_eq!(
        world
            .supervisor
            .revoke_grant(&exe, grant_a, GrantRevocationCause::UserRequested)
            .unwrap(),
        record
    );
    assert!(world.supervisor.take_receipts().is_empty());
    assert_eq!(
        world.supervisor.grant_revocation(&exe, grant_a),
        Some(&record)
    );
    assert_eq!(world.supervisor.grant_revocations().count(), 1);

    // A grant revocation has nothing to acknowledge, advance or take.
    assert!(matches!(
        world
            .supervisor
            .acknowledge(&exe, Acknowledgment::ChannelsClosed),
        Err(SupervisorError::NotRevoking { .. })
    ));
    assert!(matches!(
        world
            .supervisor
            .acknowledge(&exe, Acknowledgment::NewAuthorizationsDenied),
        Err(SupervisorError::NotRevoking { .. })
    ));
    assert!(matches!(
        world.supervisor.sync_revocation(&exe),
        Err(SupervisorError::NotRevoking { .. })
    ));
    assert!(matches!(
        world.supervisor.advance(&exe, &mut world.backend),
        Err(SupervisorError::NotRevoking { .. })
    ));
    assert!(matches!(
        world.supervisor.revoke_grant(
            &execution("exe-unknown"),
            grant_a,
            GrantRevocationCause::PolicyChanged
        ),
        Err(SupervisorError::UnknownSandbox { .. })
    ));
}

/// Never the reverse either: a later revocation of the sandbox takes nothing from a grant
/// revocation (the refused lease of the revoked grant is no denial of the sandbox's
/// revocation), and a grant revoked during a revocation of the sandbox acknowledges
/// nothing of it. The grant stays revoked after a relaunch.
#[test]
fn a_revocation_of_the_sandbox_and_a_grant_revocation_never_acknowledge_each_other() {
    let mut world = World::new();
    let mut request = world.request("exe-task", SandboxClass::Task);
    request.settings.network = [route("a"), route("b")].into_iter().collect();
    world
        .supervisor
        .launch(request, &mut world.backend, &world.evidence.registry)
        .unwrap();
    let exe = execution("exe-task");
    let (grant_a, grant_b) = (network_grant_id(&route("a")), network_grant_id(&route("b")));
    let on_a = world
        .supervisor
        .authorize_granted_work(
            &exe,
            operation("op-a"),
            LeaseKind::ChildWork,
            call(),
            granted(&[grant_a]),
        )
        .unwrap();
    world
        .supervisor
        .revoke_grant(&exe, grant_a, GrantRevocationCause::PolicyChanged)
        .unwrap();
    world.advance(SECOND);
    let progress = world
        .supervisor
        .revoke(&exe, RevocationCause::UserRequested, &mut world.backend)
        .unwrap();
    assert!(progress.acknowledged.is_empty(), "{progress:?}");
    assert_eq!(
        world.supervisor.coordinator().check_lease(on_a.id()),
        Err(LeaseRefusal::Cancelled {
            cause: CancelCause::GrantRevoked
        })
    );
    assert!(world.supervisor.sync_revocation(&exe).unwrap().is_empty());
    assert_eq!(
        world
            .supervisor
            .revocation(&exe)
            .unwrap()
            .acknowledged_at(Acknowledgment::NewAuthorizationsDenied),
        None,
        "the grant revocation's refusal is not this revocation's denial"
    );
    let run = world.supervisor.revocation(&exe).unwrap();
    assert!(run.lease_expiry_bound_at() >= on_a.expires_at());

    // A grant revoked during the revocation of the sandbox: no acknowledgment, no change.
    world.supervisor.take_receipts();
    let before = world.supervisor.revocation(&exe).unwrap().clone();
    world
        .supervisor
        .revoke_grant(&exe, grant_b, GrantRevocationCause::Violation)
        .unwrap();
    assert_eq!(world.supervisor.revocation(&exe), Some(&before));
    assert!(matches!(
        &world.supervisor.take_receipts()[..],
        [LifecycleReceipt::GrantRevoked { .. }]
    ));

    // After the stop and a relaunch the grant stays revoked: neither granted nor honoured.
    world.stop_fully("exe-task");
    let mut request = world.request("exe-task", SandboxClass::Task);
    request.settings.network = [route("a"), route("b")].into_iter().collect();
    assert!(matches!(
        world
            .supervisor
            .launch(request, &mut world.backend, &world.evidence.registry)
            .unwrap(),
        LaunchReceipt::AuthorityActive { .. }
    ));
    assert!(world
        .supervisor
        .coordinator()
        .sandbox(&exe)
        .unwrap()
        .settings_grant()
        .network
        .is_empty());
    assert!(matches!(
        world.supervisor.authorize_granted_work(
            &exe,
            operation("op-a3"),
            LeaseKind::ChildWork,
            call(),
            granted(&[grant_a]),
        ),
        Err(SupervisorError::Lease {
            refusal: LeaseRefusal::GrantRevoked { .. }
        })
    ));
    assert!(world.work("exe-task", "op-plain").is_ok());
}

#[test]
fn a_grant_revocation_is_a_bounded_lifecycle_message() {
    let mut world = World::new();
    world.launched("exe-task", SandboxClass::Task);
    let grant = network_grant_id(&route("a"));
    let peer = PeerIdentity::Authenticated {
        principal: "engine".to_owned(),
    };
    let message = serde_json::json!({
        "message": "revoke_grant",
        "execution": "exe-task",
        "grant": grant,
        "cause": "policy_changed",
    });
    let parsed = MessageFrame::parse(&peer, message.to_string().as_bytes()).unwrap();
    let MessageOutcome::GrantRevoked { record } = world
        .supervisor
        .apply_message(parsed, &mut world.backend)
        .unwrap()
    else {
        panic!("not a grant revocation");
    };
    assert_eq!(record.revoked.grant, grant);
    assert_eq!(record.cause, GrantRevocationCause::PolicyChanged);
    assert!(world
        .supervisor
        .coordinator()
        .grant_revoked(&execution("exe-task"), grant));
    // A cause that ends the whole sandbox has no per-grant form.
    let mut whole = message;
    whole["cause"] = "engine_died".into();
    assert!(MessageFrame::parse(&peer, whole.to_string().as_bytes()).is_err());
}

/// §6.3: "persist replay protection across restarts". The grant's tombstone is persisted
/// with CORE-04's state and its record with the supervisor's, so a service re-authorized
/// after the supervisor's recovery is neither granted nor honoured the revoked grant, and
/// keeps the other.
#[test]
fn a_revoked_grant_stays_revoked_across_supervisor_recovery() {
    let mut world = World::new();
    let mut request = world.request("exe-service", SandboxClass::Service);
    request.settings.network = [route("a"), route("b")].into_iter().collect();
    world
        .supervisor
        .launch(request, &mut world.backend, &world.evidence.registry)
        .unwrap();
    let exe = execution("exe-service");
    let (grant_a, grant_b) = (network_grant_id(&route("a")), network_grant_id(&route("b")));
    let record = world
        .supervisor
        .revoke_grant(&exe, grant_a, GrantRevocationCause::OwnerReclaimed)
        .unwrap();
    let persisted = world.supervisor.persist();
    world.supervisor.confirm_persisted(&persisted);
    world.advance(10 * SECOND);
    let (mut recovered, _) = Supervisor::recover(
        persisted,
        Arc::clone(&world.clock),
        session(2),
        real_ledger(&world.clock, 0),
        waiting(),
        &mut world.backend,
    )
    .unwrap();
    assert!(recovered.coordinator().grant_revoked(&exe, grant_a));
    assert!(!recovered.coordinator().grant_revoked(&exe, grant_b));
    assert_eq!(
        recovered.grant_revocation(&exe, grant_a),
        Some(&record),
        "the record is persisted with the supervisor's state, the tombstone with CORE-04's"
    );
    let admitted = world.admitted();
    assert!(matches!(
        recovered
            .reauthorize(&exe, admitted, &mut world.backend, &world.evidence.registry)
            .unwrap(),
        LaunchReceipt::AuthorityActive { .. }
    ));
    let settings = recovered
        .coordinator()
        .sandbox(&exe)
        .unwrap()
        .settings_grant()
        .network
        .clone();
    assert_eq!(settings, [route("b")].into_iter().collect());
    let state = recovered.persist();
    recovered.confirm_persisted(&state);
    assert!(matches!(
        recovered.authorize_granted_work(
            &exe,
            operation("op-a"),
            LeaseKind::ChildWork,
            call(),
            granted(&[grant_a]),
        ),
        Err(SupervisorError::Lease {
            refusal: LeaseRefusal::GrantRevoked { .. }
        })
    ));
    assert!(recovered
        .authorize_granted_work(
            &exe,
            operation("op-b"),
            LeaseKind::ChildWork,
            call(),
            granted(&[grant_b]),
        )
        .is_ok());
    // Revoking it again after recovery is recognized: the same record, no second receipt.
    recovered.take_receipts();
    let again = recovered
        .revoke_grant(&exe, grant_a, GrantRevocationCause::OwnerReclaimed)
        .unwrap();
    assert_eq!(again, record);
    assert!(recovered.take_receipts().is_empty());
}

/// Recovers `persisted` on a fresh ledger in a new clock session.
fn recover_from(
    world: &mut World,
    persisted: PersistedSupervisor,
) -> Result<(TestSupervisor, SupervisorRecovery), CoordinationError> {
    Supervisor::recover(
        persisted,
        Arc::clone(&world.clock),
        session(2),
        real_ledger(&world.clock, 0),
        waiting(),
        &mut world.backend,
    )
    .map_err(|failure| failure.error)
}

/// §6.3 lines 2308 and 2318: a grant revocation's record, with what it cancelled, goes
/// through storage with the supervisor's state. After recovery, revoking the grant again
/// returns that record and adds no receipt, whatever cause is given; the grant is neither
/// granted nor honoured again, and the record carries on into the next persisted state.
#[test]
fn a_grant_revocation_record_survives_recovery_and_is_never_made_twice() {
    let mut world = World::new();
    let mut request = world.request("exe-service", SandboxClass::Service);
    request.settings.network = [route("a"), route("b")].into_iter().collect();
    world
        .supervisor
        .launch(request, &mut world.backend, &world.evidence.registry)
        .unwrap();
    let exe = execution("exe-service");
    let (grant_a, grant_b) = (network_grant_id(&route("a")), network_grant_id(&route("b")));
    let on_a = world
        .supervisor
        .authorize_granted_work(
            &exe,
            operation("op-a"),
            LeaseKind::ChildWork,
            call(),
            granted(&[grant_a]),
        )
        .unwrap();
    world.advance(SECOND);
    let record = world
        .supervisor
        .revoke_grant(&exe, grant_a, GrantRevocationCause::Violation)
        .unwrap();
    assert_eq!(
        record
            .revoked
            .cancellations
            .iter()
            .map(|cancellation| cancellation.lease)
            .collect::<Vec<_>>(),
        [on_a.id()]
    );
    let persisted = world.supervisor.persist();
    world.supervisor.confirm_persisted(&persisted);
    let stored = serde_json::to_string(&persisted).unwrap();
    let persisted: PersistedSupervisor = serde_json::from_str(&stored).unwrap();
    assert_eq!(persisted.grant_revocations, [record.clone()]);
    world.advance(10 * SECOND);

    let (mut recovered, report) = recover_from(&mut world, persisted).unwrap();
    assert!(report.grant_tombstones_recorded_again.is_empty());
    assert_eq!(recovered.grant_revocation(&exe, grant_a), Some(&record));
    assert_eq!(recovered.grant_revocations().count(), 1);
    for cause in [
        GrantRevocationCause::Violation,
        GrantRevocationCause::UserRequested,
    ] {
        assert_eq!(
            recovered.revoke_grant(&exe, grant_a, cause).unwrap(),
            record,
            "one record, cancellations and cause included"
        );
    }
    assert!(recovered.take_receipts().is_empty(), "no second receipt");
    let admitted = world.admitted();
    assert!(matches!(
        recovered
            .reauthorize(&exe, admitted, &mut world.backend, &world.evidence.registry)
            .unwrap(),
        LaunchReceipt::AuthorityActive { .. }
    ));
    assert_eq!(
        recovered
            .coordinator()
            .sandbox(&exe)
            .unwrap()
            .settings_grant()
            .network,
        [route("b")].into_iter().collect()
    );
    let state = recovered.persist();
    recovered.confirm_persisted(&state);
    assert_eq!(state.grant_revocations, [record]);
    assert!(matches!(
        recovered.authorize_granted_work(
            &exe,
            operation("op-a-again"),
            LeaseKind::ChildWork,
            call(),
            granted(&[grant_a]),
        ),
        Err(SupervisorError::Lease {
            refusal: LeaseRefusal::GrantRevoked { .. }
        })
    ));
    assert!(recovered
        .authorize_granted_work(
            &exe,
            operation("op-b"),
            LeaseKind::ChildWork,
            call(),
            granted(&[grant_b]),
        )
        .is_ok());
}

/// State persisted before grant revocation records were kept still reads; a grant revoked
/// in it is recognized as revoked by its CORE-04 tombstone, with one record and no second
/// receipt. A persisted record whose tombstone the coordination state lacks gets it again
/// at recovery, and one that cannot be kept in force fails the recovery.
#[test]
fn recovery_keeps_every_recorded_grant_revoked_and_reads_older_state() {
    let mut world = World::new();
    let mut request = world.request("exe-service", SandboxClass::Service);
    request.settings.network = [route("a"), route("b")].into_iter().collect();
    world
        .supervisor
        .launch(request, &mut world.backend, &world.evidence.registry)
        .unwrap();
    let exe = execution("exe-service");
    let grant_a = network_grant_id(&route("a"));
    world
        .supervisor
        .revoke_grant(&exe, grant_a, GrantRevocationCause::PolicyChanged)
        .unwrap();
    let persisted = world.supervisor.persist();
    world.supervisor.confirm_persisted(&persisted);
    world.advance(10 * SECOND);

    // Older state: no records, the tombstone only.
    let mut older = serde_json::to_value(&persisted).unwrap();
    assert!(older
        .as_object_mut()
        .unwrap()
        .remove("grant_revocations")
        .is_some());
    let older: PersistedSupervisor = serde_json::from_value(older).unwrap();
    assert!(older.grant_revocations.is_empty());
    let (mut recovered, _) = recover_from(&mut world, older).unwrap();
    assert!(recovered.grant_revocation(&exe, grant_a).is_none());
    assert!(recovered.coordinator().grant_revoked(&exe, grant_a));
    let again = recovered
        .revoke_grant(&exe, grant_a, GrantRevocationCause::PolicyChanged)
        .unwrap();
    assert!(again.revoked.cancellations.is_empty());
    assert!(
        recovered.take_receipts().is_empty(),
        "already revoked before the recovery: no second receipt"
    );
    assert_eq!(
        recovered
            .revoke_grant(&exe, grant_a, GrantRevocationCause::Violation)
            .unwrap(),
        again,
        "one record"
    );

    // A record whose CORE-04 tombstone is missing: recovery records it again.
    let mut lacking = persisted.clone();
    lacking.coordination.revoked_grants.clear();
    let (mut recovered, report) = recover_from(&mut world, lacking).unwrap();
    assert_eq!(
        report.grant_tombstones_recorded_again,
        [(exe.clone(), grant_a)]
    );
    assert!(recovered.coordinator().grant_revoked(&exe, grant_a));
    let admitted = world.admitted();
    recovered
        .reauthorize(&exe, admitted, &mut world.backend, &world.evidence.registry)
        .unwrap();
    assert_eq!(
        recovered
            .coordinator()
            .sandbox(&exe)
            .unwrap()
            .settings_grant()
            .network,
        [route("b")].into_iter().collect(),
        "the grant is not granted again"
    );

    // A record CORE-04 cannot keep in force: the recovery fails rather than revive it.
    let mut ghost = persisted;
    ghost.coordination.revoked_grants.clear();
    ghost.grant_revocations[0].revoked.execution = execution("exe-unknown");
    assert!(matches!(
        recover_from(&mut world, ghost),
        Err(CoordinationError::UnknownExecution { .. })
    ));
}

/// §8.1 line 2439 and leftover entries H01, S01, M02, M08: the supervisor asks the backend
/// to observe the VM again; while the host does not find it ready, no new work is
/// authorized under the sandbox, and a guest's word never makes it ready.
#[test]
fn readiness_observed_again_gates_new_work_until_the_host_finds_the_vm_ready() {
    use crate::foundation::coordination::{Readiness, ReadinessReport};
    let mut world = World::new();
    world.launched("exe-task", SandboxClass::Task);
    let vm = world.vm("exe-task");
    let exe = execution("exe-task");
    assert_eq!(
        world.supervisor.sandbox(&exe).unwrap().readiness,
        ObservedReadiness::AtLaunch
    );

    let calls = world.backend.calls.len();
    assert_eq!(
        world
            .supervisor
            .observe_readiness(&exe, &mut world.backend)
            .unwrap(),
        ObservedReadiness::Ready {
            at: world.clock.now()
        }
    );
    assert_eq!(world.backend.calls[calls..], [BackendCall::Readiness(vm)]);
    assert!(world.work("exe-task", "op-1").is_ok());

    // The backend no longer finds fresh evidence: unavailable, and new work is refused.
    world.backend.readiness = ReadinessReport {
        source: SourceClass::HostProbe,
        readiness: Readiness::NotReady {
            detail: "the launch record is not current".to_owned(),
        },
    };
    world.advance(SECOND);
    let since = world.clock.now();
    assert_eq!(
        world
            .supervisor
            .observe_readiness(&exe, &mut world.backend)
            .unwrap(),
        ObservedReadiness::Unavailable {
            since,
            detail: "the launch record is not current".to_owned(),
        }
    );
    let refusal = world.work("exe-task", "op-2").unwrap_err();
    assert_eq!(
        refusal,
        SupervisorError::ReadinessUnavailable {
            execution: exe.clone(),
            since,
            detail: "the launch record is not current".to_owned(),
        }
    );
    assert!(refusal.to_string().contains("no new work is authorized"));

    // A guest's report of readiness changes nothing; unavailable since the first report.
    world.backend.readiness = ReadinessReport {
        source: SourceClass::GuestReport,
        readiness: Readiness::Ready,
    };
    world.advance(SECOND);
    assert!(matches!(
        world.supervisor.observe_readiness(&exe, &mut world.backend).unwrap(),
        ObservedReadiness::Unavailable { since: first, .. } if first == since
    ));
    assert!(world.work("exe-task", "op-3").is_err());

    // The state persists with the sandbox; state persisted before it reads as at launch.
    let persisted = world.supervisor.persist();
    assert!(persisted.sandboxes[0].readiness.is_unavailable());
    let mut json = serde_json::to_value(&persisted).unwrap();
    json["sandboxes"][0]
        .as_object_mut()
        .unwrap()
        .remove("readiness");
    let older: PersistedSupervisor = serde_json::from_value(json).unwrap();
    assert_eq!(older.sandboxes[0].readiness, ObservedReadiness::AtLaunch);

    // Observed ready by the host again: work is authorized again.
    world.backend.readiness = ReadinessReport {
        source: SourceClass::HostProbe,
        readiness: Readiness::Ready,
    };
    world.advance(SECOND);
    assert_eq!(
        world
            .supervisor
            .observe_readiness(&exe, &mut world.backend)
            .unwrap(),
        ObservedReadiness::Ready {
            at: world.clock.now()
        }
    );
    assert!(world.work("exe-task", "op-4").is_ok());

    // A sandbox without authority is not observed, and a new boot starts from its own
    // launch readiness.
    world.backend.readiness = ReadinessReport {
        source: SourceClass::HostProbe,
        readiness: Readiness::NotReady {
            detail: "not running".to_owned(),
        },
    };
    world
        .supervisor
        .observe_readiness(&exe, &mut world.backend)
        .unwrap();
    world.backend.readiness = ReadinessReport {
        source: SourceClass::HostProbe,
        readiness: Readiness::Ready,
    };
    world.stop_fully("exe-task");
    assert!(matches!(
        world.supervisor.observe_readiness(&exe, &mut world.backend),
        Err(SupervisorError::NoAuthority { .. })
    ));
    world.launched("exe-task", SandboxClass::Task);
    assert_eq!(
        world.supervisor.sandbox(&exe).unwrap().readiness,
        ObservedReadiness::AtLaunch
    );
    assert!(world.work("exe-task", "op-5").is_ok());
}

/// Admission on fresh readiness: once the host last found the VM ready longer ago than
/// the configured age, the supervisor asks the backend again before it authorizes work.
#[test]
fn observed_work_asks_the_backend_again_once_readiness_is_older_than_its_age() {
    use crate::foundation::coordination::{Readiness, ReadinessReport};
    let mut world = World::new();
    world.launched("exe-task", SandboxClass::Task);
    let vm = world.vm("exe-task");
    let exe = execution("exe-task");
    let readiness_calls = |world: &World| {
        world
            .backend
            .calls
            .iter()
            .filter(|call| **call == BackendCall::Readiness(vm))
            .count()
    };
    let launch_checks = readiness_calls(&world);
    let observed = |world: &mut World, op: &str| {
        world.supervisor.authorize_observed_work(
            &exe,
            operation(op),
            LeaseKind::ChildWork,
            call(),
            BTreeSet::new(),
            &mut world.backend,
        )
    };

    // Within the age of the launch's readiness, nothing is observed again.
    assert!(observed(&mut world, "op-1").is_ok());
    assert_eq!(readiness_calls(&world), launch_checks);

    // Older than the age: observed again first; while the host does not find the VM
    // ready, the work is refused.
    world.advance(6 * SECOND);
    world.backend.readiness = ReadinessReport {
        source: SourceClass::HostProbe,
        readiness: Readiness::NotReady {
            detail: "the confinement evidence is stale".to_owned(),
        },
    };
    assert!(matches!(
        observed(&mut world, "op-2"),
        Err(SupervisorError::ReadinessUnavailable { .. })
    ));
    assert_eq!(readiness_calls(&world), launch_checks + 1);
    // Unavailable readiness is observed again at once, and fresh readiness admits.
    world.backend.readiness = ReadinessReport {
        source: SourceClass::HostProbe,
        readiness: Readiness::Ready,
    };
    assert!(observed(&mut world, "op-3").is_ok());
    assert_eq!(readiness_calls(&world), launch_checks + 2);
    assert!(observed(&mut world, "op-4").is_ok());
    assert_eq!(readiness_calls(&world), launch_checks + 2);
}

#[test]
fn bounded_remote_work_keeps_readiness_and_revocation_checks() {
    use crate::foundation::coordination::{Readiness, ReadinessReport};
    let mut world = World::new();
    world.launched("remote-parent", SandboxClass::Task);
    let exe = execution("remote-parent");
    let deadline = world.clock.now().saturating_add(10 * SECOND);
    let observed = |world: &mut World, op: &str| {
        world.supervisor.authorize_observed_work_until(
            &exe,
            operation(op),
            LeaseKind::Service,
            call(),
            BTreeSet::new(),
            Some(deadline),
            &mut world.backend,
        )
    };
    world.advance(6 * SECOND);
    world.backend.readiness = ReadinessReport {
        source: SourceClass::HostProbe,
        readiness: Readiness::NotReady {
            detail: "confinement lost".into(),
        },
    };
    assert!(matches!(
        observed(&mut world, "not-ready"),
        Err(SupervisorError::ReadinessUnavailable { .. })
    ));
    world.backend.readiness = ReadinessReport {
        source: SourceClass::HostProbe,
        readiness: Readiness::Ready,
    };
    let lease = observed(&mut world, "ready").unwrap();
    assert!(lease.expires_at() <= deadline);
    world.stop_fully("remote-parent");
    assert!(observed(&mut world, "revoked").is_err());
    assert!(world
        .supervisor
        .coordinator()
        .check_lease(lease.id())
        .is_err());
}

#[test]
fn renewing_an_existing_child_rechecks_readiness_and_service_lockdown() {
    use crate::foundation::coordination::{Readiness, ReadinessReport};
    let mut world = World::new();
    world.launched("remote-parent", SandboxClass::Service);
    let exe = execution("remote-parent");
    let lease = world
        .supervisor
        .authorize_observed_work(
            &exe,
            operation("remote-child"),
            LeaseKind::Service,
            CallTerms {
                per_call: 20 * SECOND,
                task: 60 * SECOND,
            },
            BTreeSet::new(),
            &mut world.backend,
        )
        .unwrap();
    let session = world.supervisor.coordinator().session();
    world.advance(6 * SECOND);
    world.backend.readiness = ReadinessReport {
        source: SourceClass::HostProbe,
        readiness: Readiness::NotReady {
            detail: "host confinement lost".into(),
        },
    };
    assert!(matches!(
        world
            .supervisor
            .renew_observed_work(lease.id(), session, &mut world.backend),
        Err(SupervisorError::ReadinessUnavailable { .. })
    ));
    assert_eq!(
        world
            .supervisor
            .coordinator()
            .check_lease(lease.id())
            .unwrap()
            .expires_at(),
        lease.expires_at()
    );
    world.backend.readiness = ReadinessReport {
        source: SourceClass::HostProbe,
        readiness: Readiness::Ready,
    };
    assert!(world
        .supervisor
        .check_observed_work(lease.id(), &mut world.backend)
        .is_ok());
    world
        .supervisor
        .violation(&exe, &mut world.backend)
        .unwrap();
    assert!(matches!(
        world
            .supervisor
            .check_observed_work(lease.id(), &mut world.backend),
        Err(SupervisorError::LockedDown { .. })
    ));
    assert!(matches!(
        world
            .supervisor
            .renew_observed_work(lease.id(), session, &mut world.backend),
        Err(SupervisorError::LockedDown { .. })
    ));
}

/// A persisted supervisor state with the lifecycle records it carries beside CORE-04's
/// state: the engine down, a service whose readiness the host last found unavailable and
/// with one grant revoked alone and a nonce accepted, a service mid renewal with its
/// shutdown and rollback plans, managed roots, and the stop measurements of a task.
fn a_persisted_state_with_every_record() -> PersistedSupervisor {
    use crate::foundation::coordination::{Readiness, ReadinessReport};
    let mut world = World::new();
    let mut request = world.request("exe-service", SandboxClass::Service);
    request.settings.network = [route("a"), route("b")].into_iter().collect();
    request.volumes = BTreeMap::from([
        (volume("data"), VolumeKind::PureApplicationData),
        (volume("src"), VolumeKind::SourceWorkspace),
    ]);
    world
        .supervisor
        .launch(request, &mut world.backend, &world.evidence.registry)
        .unwrap();
    let service = execution("exe-service");
    world
        .supervisor
        .revoke_grant(
            &service,
            network_grant_id(&route("a")),
            GrantRevocationCause::PolicyChanged,
        )
        .unwrap();
    world
        .supervisor
        .accept_nonce(&service, Nonce::new(1))
        .unwrap();
    let now = world.clock.now();
    world
        .supervisor
        .roots_mut()
        .create(&service, VolumeKind::ExecutableEnvironmentCache, now);

    world.launched("exe-renewed", SandboxClass::Service);
    let plan = ServiceRenewalPlan {
        shutdown: ShutdownMode::ApplicationConsistent {
            quiesce_within: 30 * SECOND,
        },
        application_recovery_before_serving: true,
        downtime_bound: 2 * 60 * SECOND,
        revoke_old_lease: true,
        rollback: RollbackPlan::ColdBootPreviousVolumes,
        cache: CachePolicy::RebuildFromManifest,
    };
    world
        .supervisor
        .begin_service_renewal(&execution("exe-renewed"), plan, &mut world.backend)
        .unwrap();

    world.launched("exe-task", SandboxClass::Task);
    world.stop_fully("exe-task");
    world.backend.readiness = ReadinessReport {
        source: SourceClass::HostProbe,
        readiness: Readiness::NotReady {
            detail: "the launch record is not current".to_owned(),
        },
    };
    world
        .supervisor
        .observe_readiness(&service, &mut world.backend)
        .unwrap();
    world.supervisor.engine_died(&mut world.backend).unwrap();
    world.supervisor.persist()
}

/// A persisted supervisor state reads only its written form (tracker E01Y follow-up):
/// every variant name in it, of the lifecycle's records and CORE-04's alike, swapped for
/// its variant index is refused, read at the top level and buffered; a key repeated in any
/// of its records is refused; and it writes back unchanged.
#[test]
fn a_persisted_state_with_a_number_tag_or_a_repeated_key_is_refused() {
    use super::strict_tests::{assert_no_problems, check_repeats_in_records, check_sample, shown};
    let state = a_persisted_state_with_every_record();
    assert!(matches!(state.engine, EngineState::Down { .. }));
    assert!(state
        .sandboxes
        .iter()
        .any(|record| matches!(record.readiness, ObservedReadiness::Unavailable { .. })));
    assert!(state
        .sandboxes
        .iter()
        .any(|record| record.renewal.is_some()));
    assert_eq!(state.grant_revocations.len(), 1);
    let stored = serde_json::to_string(&state).unwrap();
    let (mut problems, names) = check_sample::<PersistedSupervisor>("persisted state", &stored);
    let (repeated, records) =
        check_repeats_in_records::<PersistedSupervisor>("persisted state", &stored, &names);
    problems.extend(repeated);
    assert_no_problems(&problems);

    let paths: Vec<String> = names.iter().map(|name| shown(&name.path)).collect();
    for path in [
        "engine.engine",
        "sandboxes[0].renewal.plan.shutdown.shutdown",
        "sandboxes[0].renewal.plan.rollback.rollback",
        "sandboxes[1].readiness.readiness",
        "sandboxes[2].readiness.readiness",
    ] {
        assert!(paths.iter().any(|name| name == path), "{path} not checked");
    }
    // CORE-04's network grant sits inside a launch step's tagged enum, where serde
    // buffers it.
    assert!(paths
        .iter()
        .any(|name| name.ends_with(".step.settings.network[0].grant")));
    for record in [
        "engine",
        "sandboxes[0].renewal.plan.shutdown",
        "sandboxes[1].readiness",
        "grant_revocations[0]",
    ] {
        assert!(
            records.iter().any(|path| path == record),
            "{record} not checked"
        );
    }
    assert!(
        !records.iter().any(|path| path.ends_with(".volumes")),
        "a map is not a record"
    );
}
