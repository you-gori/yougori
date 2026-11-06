//! Stale-state reconciliation against the real CORE-03 ledger on a manual clock: with the
//! real transfer executor over boundaries' in-memory backend where its jobs matter, and
//! with a fixed executor view for the cases a real executor cannot be steered into.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::*;
use crate::foundation::coordination::LeaseState;
use crate::foundation::evidence::HostSubject;
use crate::foundation::ids::{
    digest, ContentKey, Digest, GpuAllocationGeneration, GpuDeviceKey, LeaseId, ManualClock,
    TenantId,
};
use crate::foundation::ledger::{
    Admission, CapacityDeclaration, CostPurpose, HostResource, LedgerConfig,
    Priority as LedgerPriority, QueueLimits, ReservationRequest, ResourceKey,
};
use crate::model_memory::boundaries::fakes::{BytesBackend, Coalescer, EventLog};
use crate::model_memory::boundaries::PreparationStep;
use crate::model_memory::executor::{
    AllocationKey, CatalogPort, CatalogRefusal, DependencyId, DependencySpec, Destination, EventId,
    ExecutorConfig, ExecutorFault, ExecutorPorts, ExtentFailure, HostStagingConfig,
    HostStagingMemory, JobPriority, LedgerReservations, LoaderPermissions, ManifestExtent,
    ProgressSnapshot, ReadMethod, ResolveRequest, ResolvedManifest, SourceCandidate, SourceKind,
    StagingAccount, StoredForm, SubmitOptions, TransferRequest,
};
use crate::model_memory::graph::node::DurationEstimate;
use crate::model_memory::math::bounds::BandwidthRating;
use crate::model_memory::math::prefetch::{
    expected_value, CandidateOrigin, Objective, PrefetchBudget, PrefetchCandidate, RawCost,
};
use crate::model_memory::math::sources::{SourceAuthorization, SourceSpec, StealPolicy};
use crate::model_memory::math::{CandidateId, SourceId};
use crate::model_memory::readiness::adoption::governor::{
    ArrivalReport, DeclaredStep, GovernorConfig, GovernorEvent, StepOutcome, WorkGrant,
    WorkflowIntent,
};
use crate::model_memory::readiness::adoption::observed::{Basis, EstimateReason, Labelled};
use crate::model_memory::readiness::adoption::shared::{
    LedgerRelease, PrerequisiteDemand, PrerequisiteKey,
};
use crate::model_memory::readiness::intent::{PrepareBounds, PrepareRefusal, PrepareWork};
use crate::model_memory::readiness::test_support::{at, label, target, GB};

const KIB: u64 = 1_024;
const MIB: u64 = 1_024 * 1_024;

type TestClock = Arc<ManualClock>;
type TestLedger = Ledger<TestClock>;
type Executor = TransferExecutor<TestClock>;

fn op(name: &str) -> OperationId {
    OperationId::new(name).unwrap()
}

fn test_digest(part: &str) -> Digest {
    digest("yougori/test/readiness/reconcile/v1", &[part.as_bytes()])
}

fn gpu() -> GpuDeviceKey {
    GpuDeviceKey {
        machine: test_digest("workstation"),
        device: test_digest("gpu-0"),
    }
}

fn vram() -> ResourceKey {
    ResourceKey::vram(gpu())
}

fn vram_gb(gb: u64) -> Amounts {
    Amounts::new().vram_bytes(gpu(), gb * GB)
}

fn tenant() -> TenantId {
    TenantId::new("tenant-a").unwrap()
}

fn workflow() -> ExecutionId {
    ExecutionId::new("exe-workflow").unwrap()
}

fn staging_account() -> StagingAccount {
    StagingAccount {
        execution: ExecutionId::new("exe-executor").unwrap(),
        tenant: TenantId::new("executor").unwrap(),
    }
}

fn clock() -> TestClock {
    Arc::new(ManualClock::new(at(10)))
}

/// The host's one ledger: `vram_total_gb` of VRAM on GPU 0 for the tenant, host and
/// pinned RAM for the executor's staging ring.
fn host_ledger(clock: &TestClock, vram_total_gb: u64) -> TestLedger {
    let mut ledger = Ledger::new(
        Arc::clone(clock),
        HostSubject {
            machine: test_digest("workstation"),
        },
        LedgerConfig {
            queue: QueueLimits {
                max_entries: 16,
                max_entries_per_tenant: 16,
                max_wait: Duration::from_secs(600),
            },
            grant_ttl: Duration::from_secs(600),
            unmanaged_usage_max_age: Duration::from_secs(3_600),
        },
    );
    for (resource, total) in [
        (vram(), vram_total_gb * GB),
        (ResourceKey::Host(HostResource::Ram), MIB),
        (ResourceKey::Host(HostResource::PinnedRam), MIB),
    ] {
        ledger
            .declare_capacity(
                resource,
                CapacityDeclaration {
                    total,
                    supervisor_reserve: 0,
                    unmanaged_in_use: 0,
                    source: SourceClass::HostProbe,
                },
            )
            .unwrap();
    }
    ledger
        .set_tenant_budget(tenant(), vram(), u64::MAX)
        .unwrap();
    for resource in [
        ResourceKey::Host(HostResource::Ram),
        ResourceKey::Host(HostResource::PinnedRam),
    ] {
        ledger
            .set_tenant_budget(staging_account().tenant, resource, MIB)
            .unwrap();
    }
    ledger
}

fn governor() -> PreparationGovernor {
    let mut governor = PreparationGovernor::new(GovernorConfig {
        execution: ExecutionId::new("exe-placement-governor").unwrap(),
        prepare: PrepareBounds {
            max_lead: Duration::from_secs(900),
            max_retention_ttl: Duration::from_secs(120),
        },
        max_active: 8,
        max_lookahead: 4,
        max_speculative_bytes: 60 * GB,
        max_outcomes: 32,
        promotion_wait: Duration::from_secs(60),
        objective: Objective::new(1.0, 1e-9, 0.0, 0.0).unwrap(),
    })
    .unwrap();
    governor.enable_workflow_intent();
    governor
}

fn reconciler() -> StaleStateReconciler {
    StaleStateReconciler::new(NonZeroUsize::new(64).unwrap())
}

fn base() -> PrerequisiteDemand {
    PrerequisiteDemand {
        key: PrerequisiteKey::new(test_digest("base-14b")),
        demand: vram_gb(14),
    }
}

/// A step preparing `model` by second 300, holding `own_gb` itself.
fn step(name: &str, model: &str, own_gb: u64) -> DeclaredStep {
    DeclaredStep {
        operation: op(name),
        target: target(model),
        deadline: at(300),
        retention_ttl: Duration::from_secs(60),
        work: vec![PrepareWork::Step {
            step: PreparationStep::InboundTransfer,
        }],
        assigned_request: None,
        lease: LeaseId::new(7),
        probability: 1.0,
        cost: Labelled {
            value: DurationEstimate::new(
                Duration::from_secs(4),
                Duration::from_secs(5),
                Duration::from_secs(8),
            )
            .unwrap(),
            basis: Basis::Estimated {
                source: label("catalog-bytes-over-nominal-bandwidth"),
                reason: EstimateReason::NoObservations,
            },
        },
        demand: if own_gb == 0 {
            Amounts::new()
        } else {
            vram_gb(own_gb)
        },
        prerequisites: Vec::new(),
    }
}

fn with_base(mut step: DeclaredStep) -> DeclaredStep {
    step.prerequisites.push(base());
    step
}

fn intent_of(execution: &str, steps: Vec<DeclaredStep>) -> WorkflowIntent {
    WorkflowIntent {
        execution: ExecutionId::new(execution).unwrap(),
        tenant: tenant(),
        steps,
    }
}

fn intent(steps: Vec<DeclaredStep>) -> WorkflowIntent {
    intent_of(workflow().as_str(), steps)
}

fn active(_: LeaseId) -> Option<LeaseState> {
    Some(LeaseState::Active)
}

/// Declares `steps` for the workflow, polls, and begins the work of every granted one.
fn prepare(
    governor: &mut PreparationGovernor,
    ledger: &mut TestLedger,
    clock: &ManualClock,
    steps: Vec<DeclaredStep>,
) -> BTreeMap<OperationId, WorkGrant> {
    let report = governor.declare(intent(steps), ledger, &active, clock);
    assert!(report.steps.iter().all(|decision| matches!(
        decision.outcome,
        StepOutcome::Admitted { .. } | StepOutcome::AlreadyPreparing
    )));
    governor
        .poll(ledger, &active, clock)
        .into_iter()
        .filter_map(|event| match event {
            GovernorEvent::Granted { operation } => Some(operation),
            GovernorEvent::Ended { .. } => None,
        })
        .map(|operation| {
            let grant = governor.begin_work(&operation, ledger).unwrap();
            (operation, grant)
        })
        .collect()
}

fn own(grants: &BTreeMap<OperationId, WorkGrant>, name: &str) -> ReservationId {
    grants[&op(name)].own.unwrap()
}

fn state_of(ledger: &TestLedger, reservation: ReservationId) -> Option<ReservationState> {
    ledger
        .reservation(reservation)
        .map(ReservationRecord::state)
}

fn finding<'r>(report: &'r ReconcileReport, name: &str) -> &'r PreparationFinding {
    report
        .preparations
        .iter()
        .find(|finding| finding.operation == op(name))
        .unwrap()
}

fn sorted(mut reservations: Vec<ReservationId>) -> Vec<ReservationId> {
    reservations.sort();
    reservations
}

/// Every open reservation and its state, to show that nothing changed.
fn snapshot(ledger: &TestLedger) -> BTreeMap<ReservationId, ReservationState> {
    ledger
        .open_reservations()
        .map(|record| (record.id(), record.state()))
        .collect()
}

fn host_probe(reservation: ReservationId) -> ReleaseObservation {
    ReleaseObservation {
        reservation,
        source: SourceClass::HostProbe,
    }
}

/// An executor view that reports what the test sets, and absent otherwise.
#[derive(Default)]
struct Jobs(BTreeMap<OperationId, WorkObservation>);

impl Jobs {
    fn with(mut self, name: &str, observed: WorkObservation) -> Self {
        self.0.insert(op(name), observed);
        self
    }
}

impl ExecutorView for Jobs {
    fn observe(&self, operation: &OperationId) -> WorkObservation {
        self.0
            .get(operation)
            .cloned()
            .unwrap_or(WorkObservation::Absent)
    }
}

fn failure() -> JobFailure {
    JobFailure {
        extent: 1,
        failure: ExtentFailure::RetriesExhausted {
            attempts: Vec::new(),
        },
    }
}

// ---------------------------------------------------------------------------------------
// The real transfer executor over the host's one ledger.

/// The manifests the catalog would resolve, by artifact and representation.
#[derive(Clone, Default)]
struct Manifests(Arc<Mutex<BTreeMap<(ContentKey, ContentKey), ResolvedManifest>>>);

impl CatalogPort for Manifests {
    fn resolve(&self, request: &ResolveRequest) -> Result<ResolvedManifest, CatalogRefusal> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(request.artifact, request.representation))
            .cloned()
            .ok_or(CatalogRefusal::NotFound)
    }
}

fn source() -> SourceId {
    SourceId::new("local-catalog").unwrap()
}

/// Two raw 32-byte extents of deterministic bytes.
struct Artifact {
    key: ContentKey,
    representation: ContentKey,
    stored: Vec<u8>,
    extents: Vec<ManifestExtent>,
}

impl Artifact {
    const BYTES: u64 = 64;

    fn new(name: &str) -> Self {
        let seed = name.bytes().fold(7u8, |acc, byte| acc.wrapping_add(byte));
        let stored: Vec<u8> = (0..Self::BYTES)
            .map(|index| {
                u8::try_from(index)
                    .unwrap()
                    .wrapping_mul(37)
                    .wrapping_add(seed)
            })
            .collect();
        let extents = (0..2u64)
            .map(|index| {
                let start = index * 32;
                let slice = &stored[usize::try_from(start).unwrap()..][..32];
                ManifestExtent {
                    index,
                    stored_offset_bytes: start,
                    stored_length_bytes: 32,
                    stored: StoredForm::Raw,
                    decoded_offset_bytes: start,
                    decoded_length_bytes: 32,
                    decoded_key: ContentKey::of(slice),
                }
            })
            .collect();
        Self {
            key: ContentKey::of(name.as_bytes()),
            representation: ContentKey::of(&stored),
            stored,
            extents,
        }
    }
}

/// The host's ledger shared by the governor and the executor's ledger adapter, the
/// in-memory native side and the catalog's manifests.
struct World {
    clock: TestClock,
    ledger: Arc<Mutex<TestLedger>>,
    backend: BytesBackend,
    manifests: Manifests,
}

impl World {
    fn new() -> Self {
        let clock = clock();
        let ledger = Arc::new(Mutex::new(host_ledger(&clock, 160)));
        Self {
            clock,
            ledger,
            backend: BytesBackend::new(),
            manifests: Manifests::default(),
        }
    }

    fn ledger(&self) -> MutexGuard<'_, TestLedger> {
        self.ledger.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A started executor; a second one stands for the executor after a restart.
    fn executor(&self) -> Executor {
        let config = ExecutorConfig {
            operation: op("transfer-executor"),
            host_staging: HostStagingConfig {
                memory: HostStagingMemory::Pinned,
                slots: 4,
                slot_bytes: 64,
            },
            device_staging: BTreeMap::new(),
            alignment_bytes: 16,
            max_attempts: 2,
            local_read_method: ReadMethod::PositionedRead,
            steal_policy: StealPolicy {
                min_gain_seconds: 1.0,
                min_gain_fraction: 0.5,
                max_moves_per_batch: 1,
                max_moves_per_rebalance: 1,
            },
            prefetch_budget: PrefetchBudget {
                max_speculative_bytes: 4 * KIB,
                capacity_bytes: MIB,
                reserved_foreground_bytes: KIB,
            },
        };
        let ports = ExecutorPorts {
            backend: Box::new(self.backend.clone()),
            catalog: Box::new(self.manifests.clone()),
            batches: Box::new(Coalescer),
            reservations: Box::new(LedgerReservations::new(
                Arc::clone(&self.ledger),
                staging_account(),
            )),
            events: Box::new(EventLog::default()),
        };
        TransferExecutor::new(config, Arc::clone(&self.clock), ports).unwrap()
    }

    /// Stores `stored` as `artifact`'s representation on the local source and publishes
    /// the artifact's manifest.
    fn publish(&self, artifact: &Artifact, stored: Vec<u8>) {
        self.backend
            .state()
            .objects
            .insert((source(), artifact.representation), stored);
        let manifest = ResolvedManifest {
            manifest: ContentKey::of(b"manifest"),
            artifact: artifact.key,
            representation: artifact.representation,
            object_length_bytes: Artifact::BYTES,
            extents: artifact.extents.clone(),
            sources: vec![SourceCandidate {
                kind: SourceKind::LocalFile,
                spec: SourceSpec {
                    id: source(),
                    authorization: SourceAuthorization::Authorized,
                    startup_seconds: 0.0,
                    bandwidth: BandwidthRating::measured_directional(1e9).unwrap(),
                    cuts: vec![],
                    max_in_flight: 4,
                    interference_seconds_per_byte: 0.0,
                },
            }],
            cuts: vec![],
        };
        self.manifests
            .0
            .lock()
            .unwrap()
            .insert((artifact.key, artifact.representation), manifest);
    }

    /// Submits the preparation's work as one speculative job of the same operation,
    /// carved from its own reservation (production caller step 1).
    fn submit(&self, executor: &mut Executor, name: &str, artifact: &Artifact, own: ReservationId) {
        let candidate = PrefetchCandidate {
            id: CandidateId::new(name).unwrap(),
            origin: CandidateOrigin::QueuedWork,
            probability: 1.0,
            bytes: Artifact::BYTES,
            saved_if_used: RawCost {
                milliseconds: 100.0,
                ..RawCost::default()
            },
            waste_if_unused: RawCost::default(),
            interference: RawCost::default(),
            retention: RawCost::default(),
        };
        let value =
            expected_value(&candidate, &Objective::new(1.0, 0.0, 0.0, 0.0).unwrap()).unwrap();
        let request = TransferRequest {
            operation: op(name),
            execution: workflow(),
            tenant: tenant(),
            artifact: artifact.key,
            representation: artifact.representation,
            destination: Destination {
                allocation: AllocationKey {
                    device: gpu(),
                    allocation: test_digest(name),
                    generation: GpuAllocationGeneration::FIRST,
                },
                base_offset_bytes: 0,
                capacity_bytes: MIB,
            },
            dependencies: vec![DependencySpec {
                id: DependencyId(1),
                extents: vec![0, 1],
                requires: vec![],
            }],
            priority: JobPriority::Speculative { value },
            loader: LoaderPermissions::ordinary(),
        };
        executor
            .submit_with(
                request,
                SubmitOptions {
                    within: Some(own),
                    transfers: Vec::new(),
                },
            )
            .unwrap();
    }

    /// Pumps until nothing is queued or in flight; never unbounded.
    fn drive(&self, executor: &mut Executor) {
        for _ in 0..1_000 {
            executor.pump().unwrap();
            if executor.is_idle() {
                return;
            }
            self.clock.advance(Duration::from_nanos(50));
        }
        panic!("the executor did not go idle");
    }
}

#[test]
fn the_executor_view_maps_lifecycle_status_and_progress() {
    let running = Lifecycle::Running;
    let progress = JobProgress {
        snapshot: ProgressSnapshot {
            total_bytes: 64,
            verified_bytes: 64,
            committed_bytes: 64,
            usable_dependencies: 1,
            total_dependencies: 1,
        },
        stages: BTreeMap::new(),
    };
    assert_eq!(observe_job(&running, None, None), WorkObservation::Absent);
    assert_eq!(
        observe_job(&running, Some(&JobStatus::Running), Some(&progress)),
        WorkObservation::Running
    );
    assert_eq!(
        observe_job(&running, Some(&JobStatus::Completed), Some(&progress)),
        WorkObservation::Completed {
            committed_bytes: 64
        }
    );
    let failed = JobStatus::Failed { failure: failure() };
    assert_eq!(
        observe_job(&running, Some(&failed), None),
        WorkObservation::Failed { failure: failure() }
    );
    let cancelled = JobStatus::Cancelled {
        reason: TransferCancelReason::DemandOnly,
    };
    assert_eq!(
        observe_job(&running, Some(&cancelled), None),
        WorkObservation::Cancelled {
            reason: TransferCancelReason::DemandOnly
        }
    );
    // A faulted executor's jobs neither progress nor end: what it last recorded is
    // unknown.
    let faulted = Lifecycle::Faulted {
        fault: ExecutorFault::EventReused { event: EventId(3) },
    };
    assert_eq!(
        observe_job(&faulted, Some(&JobStatus::Completed), Some(&progress)),
        WorkObservation::Unknown
    );
    assert_eq!(observe_job(&faulted, None, None), WorkObservation::Unknown);
}

#[test]
fn a_lost_completion_is_adopted_once() {
    let world = World::new();
    let artifact = Artifact::new("next-model");
    world.publish(&artifact, artifact.stored.clone());
    let mut executor = world.executor();
    let mut governor = governor();
    let mut reconciler = reconciler();
    let clock = world.clock.as_ref();
    let grants = prepare(
        &mut governor,
        &mut world.ledger(),
        clock,
        vec![step("op-next", "next-model", 8)],
    );
    let own = own(&grants, "op-next");
    world.submit(&mut executor, "op-next", &artifact, own);
    world.drive(&mut executor);
    assert_eq!(executor.status(&op("op-next")), Some(&JobStatus::Completed));
    // The completion never reached the governor: it still holds the work as running.

    let report = reconciler.reconcile(&mut governor, &mut world.ledger(), &executor, &[], clock);
    let adopted = finding(&report, "op-next");
    assert_eq!(adopted.view, PreparationView::Running);
    assert_eq!(
        adopted.observed,
        WorkObservation::Completed {
            committed_bytes: Artifact::BYTES
        }
    );
    assert!(matches!(
        adopted.finding,
        Finding::AdoptedCompletion {
            committed_bytes: Artifact::BYTES,
            state: PrepareState::Ready { .. }
        }
    ));
    assert!(report.unowned.is_empty() && report.awaiting_release.is_empty());
    assert_eq!(
        state_of(&world.ledger(), own),
        Some(ReservationState::InUse)
    );

    // Once: the next reconciliation finds it consistent, and a late completion is refused.
    let again = reconciler.reconcile(&mut governor, &mut world.ledger(), &executor, &[], clock);
    assert_eq!(finding(&again, "op-next").view, PreparationView::Ready);
    assert_eq!(finding(&again, "op-next").finding, Finding::Consistent);
    assert_eq!(
        governor.complete(&op("op-next"), 1, clock),
        Err(GovernorError::Prepare(PrepareRefusal::NotRunning))
    );
    // Forgetting a finished job is normal: the prepared bytes stay in the destination.
    executor.forget(&op("op-next")).unwrap();
    let forgotten = reconciler.reconcile(&mut governor, &mut world.ledger(), &executor, &[], clock);
    assert_eq!(finding(&forgotten, "op-next").finding, Finding::Consistent);
    assert!(forgotten.orphan_work.is_empty());
    assert_eq!(
        governor.request_arrived(&target("next-model"), &mut world.ledger(), clock),
        ArrivalReport::Used {
            operation: op("op-next"),
            prepared_bytes: Artifact::BYTES
        }
    );
}

#[test]
fn work_lost_in_an_executor_restart_is_released_only_on_an_authoritative_observation() {
    let world = World::new();
    let artifact = Artifact::new("next-model");
    world.publish(&artifact, artifact.stored.clone());
    let mut executor = world.executor();
    let mut governor = governor();
    let mut reconciler = reconciler();
    let clock = world.clock.as_ref();
    let grants = prepare(
        &mut governor,
        &mut world.ledger(),
        clock,
        vec![step("op-next", "next-model", 8)],
    );
    let own = own(&grants, "op-next");
    world.submit(&mut executor, "op-next", &artifact, own);
    assert_eq!(executor.status(&op("op-next")), Some(&JobStatus::Running));
    let token = governor.token(&op("op-next")).unwrap();

    // The executor restarts: the new one knows no job of the preparation.
    drop(executor);
    let executor = world.executor();
    let report = reconciler.reconcile(&mut governor, &mut world.ledger(), &executor, &[], clock);
    let ended = finding(&report, "op-next");
    assert_eq!(ended.view, PreparationView::Running);
    assert_eq!(ended.observed, WorkObservation::Absent);
    let Finding::Ended { outcome } = &ended.finding else {
        panic!("not ended: {:?}", ended.finding);
    };
    assert_eq!(
        outcome.end,
        PreparationEnd::WorkLost {
            loss: WorkLoss::Absent
        }
    );
    assert_eq!(
        outcome.released,
        vec![LedgerRelease::AwaitingObservedRelease { reservation: own }]
    );
    assert!(token.is_cancelled());
    assert_eq!(governor.active().count(), 0);
    assert_eq!(governor.take_outcomes(), vec![outcome.as_ref().clone()]);
    // Stopping work frees nothing by itself: the reservation counts until a release is
    // observed.
    assert_eq!(
        state_of(&world.ledger(), own),
        Some(ReservationState::Releasing)
    );
    assert_eq!(world.ledger().reserved(vram()), 8 * GB);
    assert_eq!(report.awaiting_release, vec![own]);
    assert!(report.unowned.is_empty());

    // A guest report has no authority over a host-level reservation.
    let guest = ReleaseObservation {
        reservation: own,
        source: SourceClass::GuestReport,
    };
    let refused = reconciler.reconcile(
        &mut governor,
        &mut world.ledger(),
        &executor,
        &[guest],
        clock,
    );
    assert!(matches!(
        refused.releases.as_slice(),
        [ReleaseFinding::Refused {
            reservation,
            error: LedgerError::SourceNotAuthoritative { .. }
        }] if *reservation == own
    ));
    assert_eq!(refused.awaiting_release, vec![own]);
    assert_eq!(world.ledger().reserved(vram()), 8 * GB);

    // The host's own probe has: the reservation and the destination carved from it close.
    let confirmed = reconciler.reconcile(
        &mut governor,
        &mut world.ledger(),
        &executor,
        &[host_probe(own)],
        clock,
    );
    assert!(matches!(
        confirmed.releases.as_slice(),
        [ReleaseFinding::Confirmed { reservation, .. }] if *reservation == own
    ));
    assert_eq!(state_of(&world.ledger(), own), None);
    assert_eq!(world.ledger().reserved(vram()), 0);
    assert!(confirmed.awaiting_release.is_empty());
    // Nothing holds anything for the preparation any more, so it is forgotten.
    assert!(!reconciler.answers_for(&workflow(), &op("op-next")));
}

#[test]
fn a_cancelled_or_failed_transfer_ends_its_preparation() {
    let world = World::new();
    let cancelled = Artifact::new("cancelled-model");
    let failing = Artifact::new("failing-model");
    world.publish(&cancelled, cancelled.stored.clone());
    // Every read of the failing representation is corrupt, so each attempt fails its
    // content check until the job gives up.
    world.publish(&failing, vec![0; 64]);
    let mut executor = world.executor();
    let mut governor = governor();
    let mut reconciler = reconciler();
    let clock = world.clock.as_ref();
    let grants = prepare(
        &mut governor,
        &mut world.ledger(),
        clock,
        vec![
            step("op-cancelled", "cancelled-model", 4),
            step("op-failing", "failing-model", 4),
        ],
    );
    world.submit(
        &mut executor,
        "op-cancelled",
        &cancelled,
        own(&grants, "op-cancelled"),
    );
    world.submit(
        &mut executor,
        "op-failing",
        &failing,
        own(&grants, "op-failing"),
    );
    executor.cancel(&op("op-cancelled")).unwrap();
    world.drive(&mut executor);
    assert!(matches!(
        executor.status(&op("op-failing")),
        Some(JobStatus::Failed { .. })
    ));

    let report = reconciler.reconcile(&mut governor, &mut world.ledger(), &executor, &[], clock);
    let end = |name: &str| match &finding(&report, name).finding {
        Finding::Ended { outcome } => outcome.end.clone(),
        other => panic!("{name} did not end: {other:?}"),
    };
    assert_eq!(
        end("op-cancelled"),
        PreparationEnd::WorkLost {
            loss: WorkLoss::Cancelled {
                reason: TransferCancelReason::Requested
            }
        }
    );
    assert!(matches!(
        end("op-failing"),
        PreparationEnd::WorkLost {
            loss: WorkLoss::Failed { .. }
        }
    ));
    assert_eq!(governor.active().count(), 0);
    assert_eq!(
        sorted(report.awaiting_release.clone()),
        sorted(vec![
            own(&grants, "op-cancelled"),
            own(&grants, "op-failing")
        ])
    );
}

#[test]
fn after_a_governor_restart_finished_work_is_adopted_and_old_reservations_are_never_freed() {
    let world = World::new();
    let artifact = Artifact::new("next-model");
    world.publish(&artifact, artifact.stored.clone());
    let mut executor = world.executor();
    let clock = world.clock.as_ref();
    let mut first = governor();
    let grants = prepare(
        &mut first,
        &mut world.ledger(),
        clock,
        vec![with_base(step("op-next", "next-model", 8))],
    );
    let old_own = own(&grants, "op-next");
    let old_base = grants[&op("op-next")].prerequisites[0];
    // A later step its workflow will not declare again: granted, never begun.
    let later_grants = first.declare(
        intent(vec![
            with_base(step("op-next", "next-model", 8)),
            step("op-later", "later-model", 2),
        ]),
        &mut world.ledger(),
        &active,
        clock,
    );
    let StepOutcome::Admitted {
        own: Some(Holding::Granted { reservation: later }),
        ..
    } = later_grants.steps[1].outcome
    else {
        panic!("op-later was not granted: {later_grants:?}");
    };
    world.submit(&mut executor, "op-next", &artifact, old_own);
    world.drive(&mut executor);

    // The governor restarts: its reservations stay in the ledger, the executor keeps the
    // finished job, and the workflow declares its next step again.
    drop(first);
    let mut governor = governor();
    let mut reconciler = reconciler();
    let declared = governor.declare(
        intent(vec![with_base(step("op-next", "next-model", 8))]),
        &mut world.ledger(),
        &active,
        clock,
    );
    let StepOutcome::Admitted {
        own: Some(Holding::Granted {
            reservation: new_own,
        }),
        ..
    } = declared.steps[0].outcome
    else {
        panic!("op-next was not granted: {declared:?}");
    };
    let new_base = governor
        .shared()
        .holding(&tenant(), base().key)
        .and_then(Holding::reservation)
        .unwrap();
    let before = snapshot(&world.ledger());

    let report = reconciler.reconcile(&mut governor, &mut world.ledger(), &executor, &[], clock);
    let adopted = finding(&report, "op-next");
    assert_eq!(adopted.view, PreparationView::Granted);
    assert!(matches!(
        adopted.finding,
        Finding::AdoptedCompletion {
            committed_bytes: Artifact::BYTES,
            state: PrepareState::Ready { .. }
        }
    ));
    // Adopting marked the new holdings in use, since the work exists; nothing else moved.
    let mut after = snapshot(&world.ledger());
    assert_eq!(after.remove(&new_own), Some(ReservationState::InUse));
    assert_eq!(after.remove(&new_base), Some(ReservationState::InUse));
    let mut unchanged = before;
    unchanged.remove(&new_own);
    unchanged.remove(&new_base);
    assert_eq!(after, unchanged);
    // The earlier governor's own reservation and shared base are reported and left in
    // use; the step it never began is not one the reconciler knows of yet.
    let unowned: BTreeMap<ReservationId, ReservationState> = report
        .unowned
        .iter()
        .map(|unowned| (unowned.reservation, unowned.state))
        .collect();
    assert_eq!(
        unowned,
        BTreeMap::from([
            (old_own, ReservationState::InUse),
            (old_base, ReservationState::InUse)
        ])
    );
    assert!(report.unowned.iter().any(|unowned| unowned
        .provenance
        .operation
        .as_str()
        .starts_with(PREREQUISITE_OPERATION_PREFIX)));
    // Adopted work counts as announced: the next poll does not ask for it again.
    assert!(governor
        .poll(&mut world.ledger(), &active, clock)
        .is_empty());

    // An observation never frees a reservation still in use, owned or not; recalled from
    // the persisted job intent, the never-begun step's reservation is reported too.
    reconciler.recall(workflow(), op("op-later"));
    let again = reconciler.reconcile(
        &mut governor,
        &mut world.ledger(),
        &executor,
        &[host_probe(old_own)],
        clock,
    );
    assert_eq!(
        again.releases,
        vec![ReleaseFinding::NotReleasing {
            reservation: old_own,
            state: ReservationState::InUse
        }]
    );
    assert_eq!(finding(&again, "op-next").finding, Finding::Consistent);
    assert_eq!(
        sorted(
            again
                .unowned
                .iter()
                .map(|unowned| unowned.reservation)
                .collect()
        ),
        sorted(vec![old_own, old_base, later])
    );
    assert_eq!(
        state_of(&world.ledger(), old_own),
        Some(ReservationState::InUse)
    );
    assert_eq!(
        state_of(&world.ledger(), later),
        Some(ReservationState::Granted)
    );
    // The executor's own staging and destinations are not the governor's.
    assert!(again
        .unowned
        .iter()
        .all(|unowned| unowned.provenance.requester == Requester::ModelPlacement));
}

#[test]
fn a_shared_base_leaves_only_with_its_last_lost_holder() {
    let clock = clock();
    let mut ledger = host_ledger(&clock, 160);
    let mut governor = governor();
    let mut reconciler = reconciler();
    let clock = clock.as_ref();
    let grants = prepare(
        &mut governor,
        &mut ledger,
        clock,
        vec![
            with_base(step("op-one", "one", 2)),
            with_base(step("op-two", "two", 2)),
        ],
    );
    let base_reservation = grants[&op("op-one")].prerequisites[0];
    assert_eq!(grants[&op("op-two")].prerequisites, vec![base_reservation]);

    let two_runs = Jobs::default().with("op-two", WorkObservation::Running);
    let report = reconciler.reconcile(&mut governor, &mut ledger, &two_runs, &[], clock);
    let Finding::Ended { outcome } = &finding(&report, "op-one").finding else {
        panic!("op-one did not end");
    };
    assert_eq!(
        outcome.released,
        vec![
            LedgerRelease::AwaitingObservedRelease {
                reservation: own(&grants, "op-one")
            },
            LedgerRelease::StillShared {
                key: base().key,
                holders: 1
            },
        ]
    );
    assert_eq!(finding(&report, "op-two").finding, Finding::Consistent);
    // The base is still held, so an observation of it frees nothing.
    let held = reconciler.reconcile(
        &mut governor,
        &mut ledger,
        &two_runs,
        &[host_probe(base_reservation)],
        clock,
    );
    assert_eq!(
        held.releases,
        vec![ReleaseFinding::NotReleasing {
            reservation: base_reservation,
            state: ReservationState::InUse
        }]
    );

    let report = reconciler.reconcile(&mut governor, &mut ledger, &Jobs::default(), &[], clock);
    let Finding::Ended { outcome } = &finding(&report, "op-two").finding else {
        panic!("op-two did not end");
    };
    assert_eq!(
        outcome.released,
        vec![
            LedgerRelease::AwaitingObservedRelease {
                reservation: own(&grants, "op-two")
            },
            LedgerRelease::AwaitingObservedRelease {
                reservation: base_reservation
            },
        ]
    );
    let all = sorted(vec![
        own(&grants, "op-one"),
        own(&grants, "op-two"),
        base_reservation,
    ]);
    assert_eq!(sorted(report.awaiting_release.clone()), all);
    let probes: Vec<ReleaseObservation> = all.iter().copied().map(host_probe).collect();
    let released =
        reconciler.reconcile(&mut governor, &mut ledger, &Jobs::default(), &probes, clock);
    assert!(released
        .releases
        .iter()
        .all(|finding| matches!(finding, ReleaseFinding::Confirmed { .. })));
    assert_eq!(ledger.reserved(vram()), 0);
}

#[test]
fn uncertain_cases_stay_uncertain_and_change_nothing() {
    let clock = clock();
    // 40 GB, of which another client holds 4 and the steps below 20: a 20 GB step waits.
    let mut ledger = host_ledger(&clock, 40);
    let other = ReservationRequest::new(
        Provenance {
            requester: Requester::ModelPlacement,
            execution: ExecutionId::new("exe-other").unwrap(),
            operation: op("op-other"),
            tenant: tenant(),
            purpose: CostPurpose::Compute,
            retry_number: 0,
        },
        LedgerPriority::Foreground,
        vram_gb(4),
    );
    assert!(matches!(
        ledger.reserve(other).unwrap(),
        Admission::Granted(_)
    ));
    let mut governor = governor();
    let mut reconciler = reconciler();
    let clock = clock.as_ref();
    // op-running and op-ready begun, op-ready completed; op-shared holds only the base,
    // which is in use.
    let grants = prepare(
        &mut governor,
        &mut ledger,
        clock,
        vec![
            with_base(step("op-running", "running", 2)),
            step("op-ready", "ready", 2),
            with_base(step("op-shared", "shared", 0)),
        ],
    );
    assert_eq!(grants.len(), 3);
    governor.complete(&op("op-ready"), 99, clock).unwrap();
    // op-granted granted and not begun; op-queued waiting for capacity.
    governor.declare(
        intent_of(
            "exe-second",
            vec![
                step("op-granted", "granted", 2),
                step("op-queued", "queued", 20),
            ],
        ),
        &mut ledger,
        &active,
        clock,
    );
    let running = || Jobs::default().with("op-running", WorkObservation::Running);
    let views: BTreeMap<OperationId, PreparationView> = reconciler
        .reconcile(&mut governor, &mut ledger, &running(), &[], clock)
        .preparations
        .into_iter()
        .map(|finding| (finding.operation, finding.view))
        .collect();
    assert_eq!(
        views,
        BTreeMap::from([
            (op("op-granted"), PreparationView::Granted),
            (op("op-queued"), PreparationView::Queued),
            (op("op-ready"), PreparationView::Ready),
            (op("op-running"), PreparationView::Running),
            (op("op-shared"), PreparationView::GrantedOrRunning),
        ])
    );

    let cases = [
        // An executor that cannot answer.
        (
            Jobs::default().with("op-running", WorkObservation::Unknown),
            "op-running",
            Uncertainty::ExecutorUnknown,
        ),
        // A job for work the governor never granted, or granted and never began.
        (
            running().with("op-queued", WorkObservation::Running),
            "op-queued",
            Uncertainty::JobBeforeStart,
        ),
        (
            running().with("op-granted", WorkObservation::Failed { failure: failure() }),
            "op-granted",
            Uncertainty::JobBeforeStart,
        ),
        // Only a base in use backs it, and its job is gone.
        (running(), "op-shared", Uncertainty::StartUnknown),
        // The executor contradicts a completion the governor holds.
        (
            running().with(
                "op-ready",
                WorkObservation::Cancelled {
                    reason: TransferCancelReason::Requested,
                },
            ),
            "op-ready",
            Uncertainty::CompletionContradicted,
        ),
    ];
    for (jobs, name, expected) in cases {
        let before = snapshot(&ledger);
        let active_before: Vec<OperationId> = governor.active().cloned().collect();
        let report = reconciler.reconcile(&mut governor, &mut ledger, &jobs, &[], clock);
        assert_eq!(
            finding(&report, name).finding,
            Finding::Uncertain { reason: expected },
            "{name}"
        );
        assert_eq!(snapshot(&ledger), before, "{name}");
        assert_eq!(
            governor.active().cloned().collect::<Vec<_>>(),
            active_before,
            "{name}"
        );
    }
}

#[test]
fn work_the_governor_no_longer_holds_is_reported_until_it_is_gone() {
    let clock = clock();
    let mut ledger = host_ledger(&clock, 160);
    let mut governor = governor();
    let mut reconciler = reconciler();
    let clock = clock.as_ref();
    governor.declare(
        intent(vec![step("op-next", "next", 4)]),
        &mut ledger,
        &active,
        clock,
    );
    // The caller submitted the job without recording its start: the start is adopted, so
    // the ledger counts the work as created.
    let running = Jobs::default().with("op-next", WorkObservation::Running);
    let report = reconciler.reconcile(&mut governor, &mut ledger, &running, &[], clock);
    assert_eq!(finding(&report, "op-next").view, PreparationView::Granted);
    assert_eq!(finding(&report, "op-next").finding, Finding::AdoptedRunning);
    assert!(governor.poll(&mut ledger, &active, clock).is_empty());

    // The caller cancels the preparation, but its job keeps running.
    governor
        .cancel(&op("op-next"), CancelReason::Requester, &mut ledger, clock)
        .unwrap();
    let report = reconciler.reconcile(&mut governor, &mut ledger, &running, &[], clock);
    assert_eq!(
        report.orphan_work,
        vec![OrphanWork {
            execution: workflow(),
            operation: op("op-next"),
            observed: WorkObservation::Running
        }]
    );
    let [cancelled] = report.awaiting_release.as_slice() else {
        panic!("not one awaiting release: {:?}", report.awaiting_release);
    };
    // Once the executor and the ledger hold nothing more for it, it is forgotten.
    let report = reconciler.reconcile(
        &mut governor,
        &mut ledger,
        &Jobs::default(),
        &[host_probe(*cancelled)],
        clock,
    );
    assert!(report.orphan_work.is_empty());
    assert!(matches!(
        report.releases.as_slice(),
        [ReleaseFinding::Confirmed { .. }]
    ));
    assert!(!reconciler.answers_for(&workflow(), &op("op-next")));
}

#[test]
fn the_reconciler_remembers_a_bounded_number_of_preparations() {
    let mut reconciler = StaleStateReconciler::new(NonZeroUsize::new(2).unwrap());
    for name in ["op-1", "op-2", "op-2", "op-3"] {
        reconciler.recall(workflow(), op(name));
    }
    assert_eq!(reconciler.claims_dropped(), 1);
    assert!(!reconciler.answers_for(&workflow(), &op("op-1")));
    assert!(reconciler.answers_for(&workflow(), &op("op-2")));
    assert!(reconciler.answers_for(&workflow(), &op("op-3")));
}
