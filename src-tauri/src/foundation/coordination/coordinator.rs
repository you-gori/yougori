//! The coordinator (S2 CORE-04): the two state machines, the lease table and the two ports,
//! joined only by explicit adapter calls.
//!
//! The sandbox lifecycle (RUNTIME) and the model activations (MODELS) never hold each
//! other. The coordinator passes values between them: the parent's generations and
//! authority when an activation or a lease is checked, and a revocation notice when the
//! parent is revoked. Neither side can advance the other's generations (S3.1).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::capacity::{
    CapacityPort, CapacityRefusal, ReleaseOutcome, ReservationKey, ReservationPriority,
    ReservationPurpose, ReservationRequest, ReserveOutcome, ResourceKind,
};
use super::grants::RevokedGrant;
use super::identity::{ModelGenerations, ModelId, PerimeterId, SandboxGenerations, VmInstanceId};
use super::labelled::LabelledRuntime;
use super::lease::{
    self, ActivationView, CancelCause, Lease, LeaseContext, LeaseKind, LeaseRecord, LeaseRefusal,
    LeaseRequest, LeaseTable, LeaseTerms, ModelBinding,
};
use super::model::{
    ActivationDemand, ActivationHandle, ActivationState, ActivationStep, Closing, Completion,
    FreshHolding, GpuAllocationHandle, GpuDemand, GpuReservationState, HandleProblem, Holding,
    HoldingId, ModelActivations, ModelRefusal, RetireReason,
};
use super::port::{BootRequest, PortFailure, Readiness, SandboxPort};
use super::recovery::{verify_restored_vm, RestoreExpectation, SnapshotManifest};
use super::resource_return::ResourceReturn;
use super::revocation::{DeniedRequest, RevocationMilestone, RevocationOperation};
use super::sandbox::{
    Applied, LaunchFailure, LoaderGrant, ReadinessEvidence, SandboxLifecycle, SandboxState,
    SandboxStep, SettingsGrant, StepKind, TransitionRefusal,
};
use crate::foundation::evidence::{
    AdmittedRuntime, ArtifactBypass, ArtifactVerification, AuthorityGrant, ClockSession,
    LoaderPlan, NetworkGrant, Optimization, ProbeRegistry, RuntimeOffer, RuntimeRequirement,
    RuntimeSettings, SourceClass,
};
use crate::foundation::ids::{
    Clock, Digest, ExecutionCategory, ExecutionId, GpuDeviceKey, GrantId, Incarnation, LeaseId,
    ModelActivationGeneration, MonotonicTime, OperationId, PolicyEpoch, TenantId,
};

/// The execution category of an admitted runtime. Every use of the evidence module's
/// admission goes through here and [`recheck_admission`].
pub(super) fn admitted_category(runtime: &AdmittedRuntime) -> ExecutionCategory {
    runtime.category()
}

/// Rechecks, on the registry's evidence now, that the admitted runtime is still a VM
/// sandbox (INT-07). The offer's category evidence was judged fresh only when it was
/// offered, so the launch rechecks it before boot evidence counts and before authority is
/// granted (VM part §6.1 boot_evidence_checked).
pub(super) fn recheck_admission<R: Clock>(
    runtime: &AdmittedRuntime,
    registry: &ProbeRegistry<R>,
    max_age: Duration,
) -> Result<(), LaunchFailure> {
    let offer = RuntimeOffer::observe(
        registry,
        runtime.runtime().clone(),
        max_age,
        runtime.evidence().configuration(),
    )
    .map_err(|refusal| LaunchFailure::RuntimeEvidence { refusal })?;
    RuntimeRequirement::VmSandbox
        .admit(&offer)
        .map(|_| ())
        .map_err(|refusal| LaunchFailure::RuntimeCategory { refusal })
}

/// Whether `settings` stay within what the parent's authority grants (S3.5): no network
/// grant beyond it, a loader that verifies every artifact it reads, over artifacts the
/// authority verified (INT-09), and one that uses only optimizations the gate enabled for
/// the parent's runtime, none without a loader grant (INT-06).
pub(super) fn settings_within(
    settings: &RuntimeSettings,
    granted: &SettingsGrant,
    loader: Option<&LoaderGrant>,
) -> Result<(), ModelRefusal> {
    let grants: BTreeSet<NetworkGrant> = settings
        .network
        .difference(&granted.network)
        .copied()
        .collect();
    if !grants.is_empty() {
        return Err(ModelRefusal::NetworkNotGranted { grants });
    }
    let bypass = match &settings.artifact_verification {
        ArtifactVerification::Bypassed => Some(ArtifactBypass::VerificationSkipped),
        ArtifactVerification::Verified { artifacts } => {
            let unverified: BTreeSet<Digest> = artifacts
                .difference(&granted.verified_artifacts)
                .copied()
                .collect();
            (!unverified.is_empty()).then_some(ArtifactBypass::UnverifiedArtifacts {
                artifacts: unverified,
            })
        }
    };
    if let Some(bypass) = bypass {
        return Err(ModelRefusal::ArtifactsNotGranted { bypass });
    }
    let enabled = loader.map(|grant| &grant.optimizations);
    let optimizations: BTreeSet<Optimization> = settings
        .loader
        .iter()
        .filter(|optimization| !enabled.is_some_and(|enabled| enabled.contains(optimization)))
        .copied()
        .collect();
    if optimizations.is_empty() {
        Ok(())
    } else {
        Err(ModelRefusal::LoaderNotGranted { optimizations })
    }
}

/// What to launch (VM part §6.1).
#[derive(Clone, Debug)]
pub struct LaunchPlan {
    pub execution: ExecutionId,
    pub tenant: TenantId,
    /// The runtime the request admitted. Only a VM sandbox has this lifecycle; a labelled
    /// runtime is never launched as one (INT-07).
    pub runtime: AdmittedRuntime,
    /// What the sandbox reserves, each amount in its resource's unit (CORE-03).
    pub demand: BTreeMap<ResourceKind, u64>,
    /// Background or foreground; an owner resource-return hold denies new background
    /// reservations (S10 line 185).
    pub priority: ReservationPriority,
    /// How long granted authority lasts.
    pub authority_lifetime: Duration,
    /// How old host-observed readiness may be when authority is granted.
    pub readiness_max_age: Duration,
    /// How old the runtime's category evidence may be when it is rechecked before
    /// authority.
    pub runtime_evidence_max_age: Duration,
}

/// One step a rollback or a termination undid, in the order it was undone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "compensation", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum Compensation {
    TerminateVm { vm: VmInstanceId },
    TeardownPerimeter { perimeter: PerimeterId },
    ReleaseReservation { reservation: ReservationKey },
}

crate::foundation::strict_serde::strict_tag!(Compensation, "compensation");

/// Why a termination stopped part-way.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cause", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum StallCause {
    Port { failure: PortFailure },
    Capacity { refusal: CapacityRefusal },
    Transition { refusal: TransitionRefusal },
}

crate::foundation::strict_serde::strict_tag!(StallCause, "cause");

/// A termination that stopped part-way. Nothing after the failed step was undone, so no
/// capacity still in use is reported free; recovery or a retry finishes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminationStalled {
    pub completed: Vec<Compensation>,
    pub cause: StallCause,
}

/// How a launch ended (VM part §6.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum LaunchOutcome {
    /// Authority is active (§6.1 authority_active).
    AuthorityActive {
        grant: AuthorityGrant,
        generations: SandboxGenerations,
    },
    /// The reservation waits in the ledger's bounded queue; launching again continues
    /// (S10).
    Queued { position: u32 },
    /// A step failed, and every completed step was undone in reverse order.
    RolledBack {
        failure: LaunchFailure,
        compensations: Vec<Compensation>,
    },
    /// A step failed, and undoing stopped part-way.
    RollbackStalled {
        failure: LaunchFailure,
        stall: TerminationStalled,
    },
}

/// Why a coordinator call was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum CoordinationError {
    UnknownExecution {
        execution: ExecutionId,
    },
    /// The execution is recorded for another tenant.
    TenantMismatch {
        execution: ExecutionId,
    },
    /// A launch was resumed with another runtime than the boot was admitted on.
    RuntimeMismatch {
        execution: ExecutionId,
    },
    /// Only a VM sandbox has this lifecycle (INT-07).
    NotAVmSandbox {
        category: ExecutionCategory,
    },
    /// Only a labelled runtime gets a labelled runtime's authority record; a VM sandbox is
    /// launched, and one execution is never both (INT-07).
    NotALabelledRuntime {
        category: ExecutionCategory,
    },
    /// The runtime's category evidence, rechecked before authority, no longer admits it
    /// (INT-07).
    NotAdmitted {
        failure: LaunchFailure,
    },
    /// The revocation reaches this milestone itself; no external effect acknowledges it.
    NotAcknowledgedExternally {
        milestone: RevocationMilestone,
    },
    /// The acknowledgment came from too weak a source: sockets closed needs the host,
    /// billing stopped the provider's API (VM part §6.3).
    AcknowledgmentTooWeak {
        milestone: RevocationMilestone,
        source: SourceClass,
        required: SourceClass,
    },
    NotLaunchable {
        state: SandboxState,
    },
    NotStopped {
        state: SandboxState,
    },
    NotRevoking {
        state: SandboxState,
    },
    Transition {
        refusal: TransitionRefusal,
    },
    Capacity {
        refusal: CapacityRefusal,
    },
    Port {
        failure: PortFailure,
    },
    Stalled {
        stall: TerminationStalled,
    },
    Model {
        refusal: ModelRefusal,
    },
    /// The coordination authority used its last incarnation; it must be replaced, never
    /// wrapped back to a number already used (ids::Incarnation).
    IncarnationsExhausted,
}

impl fmt::Display for CoordinationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownExecution { execution } => write!(f, "execution {execution} is unknown"),
            Self::TenantMismatch { execution } => {
                write!(f, "execution {execution} belongs to another tenant")
            }
            Self::RuntimeMismatch { execution } => write!(
                f,
                "execution {execution} was admitted on another runtime for this boot"
            ),
            Self::NotAVmSandbox { category } => write!(
                f,
                "\"{}\" is not a VM sandbox and never gets the VM sandbox lifecycle",
                category.label()
            ),
            Self::NotALabelledRuntime { category } => write!(
                f,
                "\"{}\" does not get a labelled runtime's authority record",
                category.label()
            ),
            Self::NotAdmitted { failure } => write!(f, "{failure}"),
            Self::NotAcknowledgedExternally { milestone } => write!(
                f,
                "the revocation reaches {milestone:?} itself; no external effect acknowledges it"
            ),
            Self::AcknowledgmentTooWeak {
                milestone,
                source,
                required,
            } => write!(
                f,
                "{milestone:?} reported by a {source} cannot be recorded; it needs a {required}"
            ),
            Self::NotLaunchable { state } => write!(f, "a sandbox cannot launch while {state}"),
            Self::NotStopped { state } => {
                write!(
                    f,
                    "a sandbox boots again only when stopped, not while {state}"
                )
            }
            Self::NotRevoking { state } => {
                write!(f, "no revocation is in progress; the sandbox is {state}")
            }
            Self::Transition { refusal } => write!(f, "{refusal}"),
            Self::Capacity { refusal } => write!(f, "{refusal}"),
            Self::Port { failure } => write!(f, "{failure}"),
            Self::Stalled { stall } => write!(
                f,
                "termination stopped after {} step(s)",
                stall.completed.len()
            ),
            Self::Model { refusal } => write!(f, "{refusal}"),
            Self::IncarnationsExhausted => {
                f.write_str("the coordination authority used its last incarnation")
            }
        }
    }
}

impl std::error::Error for CoordinationError {}

/// How a boot gets its VM.
#[derive(Clone, Debug)]
pub(super) enum BootSource {
    Fresh,
    /// Restore from `snapshot`; the restored VM may attach only `authorized_volumes`.
    Restore {
        snapshot: SnapshotManifest,
        authorized_volumes: BTreeSet<Digest>,
    },
}

/// What one boot needs.
#[derive(Clone, Debug)]
pub(super) struct BootTerms {
    pub(super) runtime: AdmittedRuntime,
    pub(super) demand: BTreeMap<ResourceKind, u64>,
    pub(super) authority_lifetime: Duration,
    pub(super) readiness_max_age: Duration,
    pub(super) runtime_evidence_max_age: Duration,
    /// What the authority this boot gets lets its models use.
    pub(super) settings: SettingsGrant,
    pub(super) source: BootSource,
}

/// The coordination protocol for launch, child work, typed generations, leases,
/// cancellation, reconciliation and recovery (S2 CORE-04).
///
/// Time comes from the injected [`Clock`], whose readings belong to one [`ClockSession`]:
/// a restart gets a new session, so grants and leases from before it are never compared
/// with times after it. Capacity comes from the [`CapacityPort`].
pub struct Coordinator<C: Clock, P: CapacityPort> {
    pub(super) clock: C,
    pub(super) session: ClockSession,
    pub(super) capacity: P,
    pub(super) sandboxes: BTreeMap<ExecutionId, SandboxLifecycle>,
    pub(super) models: BTreeMap<(ExecutionId, ModelId), ModelActivations>,
    pub(super) leases: LeaseTable,
    pub(super) revocations: BTreeMap<ExecutionId, RevocationOperation>,
    pub(super) returns: BTreeMap<ExecutionId, ResourceReturn>,
    pub(super) incarnation: Incarnation,
    /// Whether a persisted state carrying `incarnation` was confirmed durable.
    pub(super) incarnation_persisted: bool,
    /// The highest clock reading taken on `session`, in nanoseconds.
    pub(super) clock_high_water: AtomicU64,
    /// The authority records of labelled runtimes (INT-07).
    pub(super) labelled: BTreeMap<ExecutionId, LabelledRuntime>,
    /// The grants revoked under each execution's authority, never honoured there again;
    /// persisted (CORE-04 per-grant revocation; VM part §6.3 step 1).
    pub(super) grant_tombstones: BTreeMap<ExecutionId, BTreeSet<GrantId>>,
    /// This run's grant revocations, with what each cancelled.
    pub(super) grant_revocations: BTreeMap<(ExecutionId, GrantId), RevokedGrant>,
}

/// The coordination authority's incarnation is not handed out yet: no persisted state
/// carrying it has been confirmed durable ([`Coordinator::confirm_persisted`]). A crash
/// before then recovers the same number again, so nothing may be stamped with it until
/// then (ids::Incarnation; GPU §3.10). The refusal names no number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncarnationNotPersisted;

impl fmt::Display for IncarnationNotPersisted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "the coordination authority's incarnation is handed out only once a persisted \
             state carrying it is confirmed",
        )
    }
}

impl std::error::Error for IncarnationNotPersisted {}

impl<C: Clock, P: CapacityPort> Coordinator<C, P> {
    /// A coordinator on `clock`, whose readings belong to `session`. Share the session
    /// of the evidence registry on the same clock; a restart needs a new one.
    pub fn new(clock: C, session: ClockSession, capacity: P) -> Self {
        Self {
            clock,
            session,
            capacity,
            sandboxes: BTreeMap::new(),
            models: BTreeMap::new(),
            leases: LeaseTable::new(),
            revocations: BTreeMap::new(),
            returns: BTreeMap::new(),
            incarnation: Incarnation::FIRST,
            incarnation_persisted: false,
            clock_high_water: AtomicU64::new(0),
            labelled: BTreeMap::new(),
            grant_tombstones: BTreeMap::new(),
            grant_revocations: BTreeMap::new(),
        }
    }

    /// This run of the coordination authority (ids::Incarnation; GPU §3.10): the first
    /// for a coordinator with no earlier run, one more than the recovered state's after
    /// every recovery. CORE-04 owns the counter and persists it with its state. It is
    /// handed out only once a persisted state carrying it is confirmed durable
    /// ([`Coordinator::persist`], then [`Coordinator::confirm_persisted`]): before that a
    /// crash would recover the same number again, so it is refused, and every number
    /// handed out is greater than every number handed out before a crash.
    pub fn current_incarnation(&self) -> Result<Incarnation, IncarnationNotPersisted> {
        if self.incarnation_persisted {
            Ok(self.incarnation)
        } else {
            Err(IncarnationNotPersisted)
        }
    }

    /// The coordinator's clock now, as read. The coordinator's own decisions take the
    /// reading through its high-water mark ([`Coordinator::clock_high_water`]): a lease is
    /// never issued, honoured or renewed while the clock reads earlier than the mark, and
    /// nothing else ever goes back in time with it (VM part §6.2).
    pub fn now(&self) -> MonotonicTime {
        self.read_clock().0
    }

    /// The clock now, never earlier than a reading taken before on this clock session: a
    /// clock that went backward reads as the high-water mark until it passes it again.
    pub(super) fn monotonic_now(&self) -> MonotonicTime {
        let (reading, mark) = self.read_clock();
        reading.max(mark)
    }

    /// The highest clock reading the coordinator took on its clock session. A new session
    /// starts again, since its readings are never compared with an earlier one's.
    pub fn clock_high_water(&self) -> MonotonicTime {
        MonotonicTime::from_nanos(self.clock_high_water.load(Ordering::SeqCst))
    }

    /// Reads the clock and raises the high-water mark to the reading. Returns the reading
    /// and the mark before it.
    fn read_clock(&self) -> (MonotonicTime, MonotonicTime) {
        let reading = self.clock.now();
        let before = self
            .clock_high_water
            .fetch_max(reading.as_nanos(), Ordering::SeqCst);
        (reading, MonotonicTime::from_nanos(before))
    }

    /// The time a lease is issued, honoured or renewed at: the clock now, refused while it
    /// reads earlier than its high-water mark, so a clock that went backward never extends
    /// a lease nor revives an expired one (fails closed; VM part §6.2).
    pub(super) fn lease_time(&self) -> Result<MonotonicTime, LeaseRefusal> {
        let (reading, mark) = self.read_clock();
        if reading < mark {
            Err(LeaseRefusal::ClockWentBack {
                now: reading,
                high_water: mark,
            })
        } else {
            Ok(reading)
        }
    }

    /// The clock session every grant and lease of this coordinator is stamped with.
    pub fn session(&self) -> ClockSession {
        self.session
    }

    /// The capacity port, such as the ledger adapter.
    pub fn capacity(&self) -> &P {
        &self.capacity
    }

    /// The capacity port, for host observations and budgets.
    pub fn capacity_mut(&mut self) -> &mut P {
        &mut self.capacity
    }

    /// Hands the capacity port back, such as to the coordinator that recovers after this
    /// one stops.
    pub fn into_capacity(self) -> P {
        self.capacity
    }

    /// The lifecycle of `execution`'s sandbox.
    pub fn sandbox(&self, execution: &ExecutionId) -> Option<&SandboxLifecycle> {
        self.sandboxes.get(execution)
    }

    /// Every activation of `model` under `execution`.
    pub fn model_activations(
        &self,
        execution: &ExecutionId,
        model: ModelId,
    ) -> Option<&ModelActivations> {
        self.models.get(&(execution.clone(), model))
    }

    /// A lease and where it is in its life.
    pub fn lease_record(&self, lease: LeaseId) -> Option<&LeaseRecord> {
        self.leases.get(lease)
    }

    /// Every lease issued, in id order.
    pub fn leases(&self) -> impl Iterator<Item = &LeaseRecord> {
        self.leases.records()
    }

    pub(super) fn sandbox_ref(
        &self,
        execution: &ExecutionId,
    ) -> Result<&SandboxLifecycle, CoordinationError> {
        self.sandboxes
            .get(execution)
            .ok_or_else(|| CoordinationError::UnknownExecution {
                execution: execution.clone(),
            })
    }

    /// Applies `step` to the sandbox, presented with its current generations.
    pub(super) fn apply_step(
        &mut self,
        execution: &ExecutionId,
        step: SandboxStep,
    ) -> Result<Applied, CoordinationError> {
        let now = self.monotonic_now();
        let sandbox = self.sandboxes.get_mut(execution).ok_or_else(|| {
            CoordinationError::UnknownExecution {
                execution: execution.clone(),
            }
        })?;
        let presented = sandbox.generations();
        sandbox
            .apply(step, presented, now)
            .map_err(|refusal| CoordinationError::Transition { refusal })
    }

    fn launch_step(
        &mut self,
        execution: &ExecutionId,
        step: SandboxStep,
    ) -> Result<Result<(), LaunchFailure>, CoordinationError> {
        match self.apply_step(execution, step) {
            Ok(_) => Ok(Ok(())),
            Err(CoordinationError::Transition { refusal }) => {
                Ok(Err(LaunchFailure::Transition { refusal }))
            }
            Err(error) => Err(error),
        }
    }

    /// Launches a VM sandbox, or continues a launch that stopped part-way: reserve through
    /// the capacity port, prepare the perimeter, create the VM, check host-observed
    /// readiness, then grant authority (VM part §6.1). The admitted runtime's category
    /// evidence is rechecked on `registry` before boot evidence counts and again before
    /// the grant. A failure at any step undoes the completed steps in reverse. Launching an
    /// active sandbox again changes nothing. The authority grants the sandbox's models what
    /// its last authority granted, and a new sandbox's models no network and no artifacts;
    /// [`Coordinator::launch_with`] grants them anew.
    pub fn launch<R: Clock>(
        &mut self,
        plan: LaunchPlan,
        port: &mut dyn SandboxPort,
        registry: &ProbeRegistry<R>,
    ) -> Result<LaunchOutcome, CoordinationError> {
        let settings = self
            .sandboxes
            .get(&plan.execution)
            .map(|sandbox| sandbox.settings_grant().clone())
            .unwrap_or_default();
        self.launch_with(plan, settings, port, registry)
    }

    /// [`Coordinator::launch`], with the authority granting the sandbox's models
    /// `settings`: the network grants and verified artifacts every activation's settings
    /// must stay within, and the baseline recovery fallbacks are judged against (S3.5; T01
    /// review: authorized settings come from the authority record, never from the caller
    /// of an activation). They are recorded when authority is granted; a sandbox that
    /// already holds authority keeps its grant, and a relaunch grants the last one again.
    /// A network grant revoked under the execution is never granted again
    /// ([`Coordinator::revoke_grant`]): the authority records the settings without it.
    pub fn launch_with<R: Clock>(
        &mut self,
        plan: LaunchPlan,
        settings: SettingsGrant,
        port: &mut dyn SandboxPort,
        registry: &ProbeRegistry<R>,
    ) -> Result<LaunchOutcome, CoordinationError> {
        let settings = self.without_revoked(&plan.execution, settings);
        let category = admitted_category(&plan.runtime);
        if !category.is_vm_sandbox() {
            return Err(CoordinationError::NotAVmSandbox { category });
        }
        if let Some(labelled) = self.labelled.get(&plan.execution) {
            return Err(CoordinationError::NotAVmSandbox {
                category: labelled.runtime().category,
            });
        }
        match self.sandboxes.get(&plan.execution) {
            Some(sandbox) if sandbox.tenant() != &plan.tenant => {
                return Err(CoordinationError::TenantMismatch {
                    execution: plan.execution,
                })
            }
            Some(sandbox) if sandbox.runtime() != plan.runtime.runtime() => {
                return Err(CoordinationError::RuntimeMismatch {
                    execution: plan.execution,
                })
            }
            Some(_) => {}
            None => {
                self.sandboxes.insert(
                    plan.execution.clone(),
                    SandboxLifecycle::new(
                        plan.execution.clone(),
                        plan.tenant.clone(),
                        plan.runtime.runtime().clone(),
                        plan.priority,
                    ),
                );
            }
        }
        let terms = BootTerms {
            runtime: plan.runtime,
            demand: plan.demand,
            authority_lifetime: plan.authority_lifetime,
            readiness_max_age: plan.readiness_max_age,
            runtime_evidence_max_age: plan.runtime_evidence_max_age,
            settings,
            source: BootSource::Fresh,
        };
        self.drive(&plan.execution, &terms, port, registry)
    }

    /// Runs the launch transaction from the sandbox's current state.
    pub(super) fn drive<R: Clock>(
        &mut self,
        execution: &ExecutionId,
        terms: &BootTerms,
        port: &mut dyn SandboxPort,
        registry: &ProbeRegistry<R>,
    ) -> Result<LaunchOutcome, CoordinationError> {
        loop {
            let sandbox = self.sandbox_ref(execution)?;
            let state = sandbox.state();
            let generations = sandbox.generations();
            let tenant = sandbox.tenant().clone();
            let priority = sandbox.priority();
            let (reservation, perimeter, vm) =
                (sandbox.reservation(), sandbox.perimeter(), sandbox.vm());
            let needs_verification =
                sandbox.restored_from().is_some() && sandbox.verified_restore() != vm;
            let authority = sandbox.authority();
            let now = self.monotonic_now();
            let invalid = |step| {
                Err(LaunchFailure::Transition {
                    refusal: TransitionRefusal::InvalidTransition { from: state, step },
                })
            };
            let boot_request = |reservation| BootRequest {
                execution: execution.clone(),
                tenant: tenant.clone(),
                generations,
                reservation,
            };

            let progress = match state {
                SandboxState::Planned => {
                    let purpose = ReservationPurpose::Sandbox {
                        boot: generations.boot,
                    };
                    let key = ReservationKey::derive(execution, &purpose);
                    let request = ReservationRequest {
                        key,
                        tenant: tenant.clone(),
                        execution: execution.clone(),
                        purpose,
                        priority,
                        parent: None,
                        demand: terms.demand.clone(),
                    };
                    match self.capacity.reserve(&request) {
                        Ok(ReserveOutcome::Granted) => self.launch_step(
                            execution,
                            SandboxStep::ReserveResources { reservation: key },
                        )?,
                        Ok(ReserveOutcome::Queued { position }) => {
                            return Ok(LaunchOutcome::Queued { position })
                        }
                        Err(refusal) => Err(LaunchFailure::Capacity { refusal }),
                    }
                }
                SandboxState::ResourcesReserved => match reservation {
                    None => invalid(StepKind::PreparePerimeter),
                    Some(reservation) => match port.prepare_perimeter(&boot_request(reservation)) {
                        Ok(perimeter) => self
                            .launch_step(execution, SandboxStep::PreparePerimeter { perimeter })?,
                        Err(failure) => Err(LaunchFailure::Port { failure }),
                    },
                },
                SandboxState::PerimeterReady => match (reservation, perimeter) {
                    (Some(reservation), Some(perimeter)) => {
                        match self.capacity.begin_create(&reservation) {
                            Err(refusal) => Err(LaunchFailure::Capacity { refusal }),
                            Ok(()) => {
                                let request = boot_request(reservation);
                                let created = match &terms.source {
                                    BootSource::Fresh => {
                                        port.create_vm(&request, &perimeter).map(|vm| (vm, None))
                                    }
                                    BootSource::Restore { snapshot, .. } => port
                                        .restore_vm(&request, &perimeter, snapshot)
                                        .map(|vm| (vm, Some(snapshot.snapshot))),
                                };
                                match created {
                                    Ok((vm, restored_from)) => {
                                        let step = SandboxStep::CreateVm { vm, restored_from };
                                        if let Err(failure) = self.launch_step(execution, step)? {
                                            return self
                                                .undo_refused_vm(execution, vm, failure, port);
                                        }
                                        Ok(())
                                    }
                                    Err(failure) => Err(LaunchFailure::Port { failure }),
                                }
                            }
                        }
                    }
                    _ => invalid(StepKind::CreateVm),
                },
                SandboxState::VmCreated => match vm {
                    None => invalid(StepKind::CheckBootEvidence),
                    Some(vm) if needs_verification => {
                        self.verify_restore(execution, vm, generations, terms, port)?
                    }
                    Some(vm) => {
                        let report = port.observe_readiness(&vm, generations.boot);
                        let recheck = recheck_admission(
                            &terms.runtime,
                            registry,
                            terms.runtime_evidence_max_age,
                        );
                        match report.readiness {
                            _ if recheck.is_err() => recheck,
                            Readiness::NotReady { detail } => {
                                Err(LaunchFailure::NotReady { detail })
                            }
                            Readiness::Ready => self.launch_step(
                                execution,
                                SandboxStep::CheckBootEvidence {
                                    readiness: ReadinessEvidence {
                                        vm,
                                        boot: generations.boot,
                                        source: report.source,
                                        observed_at: now,
                                    },
                                },
                            )?,
                        }
                    }
                },
                SandboxState::BootEvidenceChecked => {
                    match recheck_admission(
                        &terms.runtime,
                        registry,
                        terms.runtime_evidence_max_age,
                    ) {
                        Err(failure) => Err(failure),
                        Ok(()) => self.launch_step(
                            execution,
                            SandboxStep::ActivateAuthority {
                                clock: self.session,
                                expires_at: now.saturating_add(terms.authority_lifetime),
                                readiness_max_age: terms.readiness_max_age,
                                settings: terms.settings.clone(),
                            },
                        )?,
                    }
                }
                SandboxState::AuthorityActive | SandboxState::Running => {
                    return match authority {
                        Some(grant) => Ok(LaunchOutcome::AuthorityActive { grant, generations }),
                        None => Err(CoordinationError::NotLaunchable { state }),
                    };
                }
                SandboxState::Revoking
                | SandboxState::Terminating
                | SandboxState::CleanupPending
                | SandboxState::Stopped => return Err(CoordinationError::NotLaunchable { state }),
            };
            if let Err(failure) = progress {
                return self.roll_back(execution, failure, port, Vec::new());
            }
        }
    }

    /// The backend created `vm`, but the lifecycle refused to record it, as for a reused
    /// handle. The VM is ended through its handle before the rest is undone; if that
    /// fails, nothing else is released.
    fn undo_refused_vm(
        &mut self,
        execution: &ExecutionId,
        vm: VmInstanceId,
        failure: LaunchFailure,
        port: &mut dyn SandboxPort,
    ) -> Result<LaunchOutcome, CoordinationError> {
        if let Err(port_failure) = port.terminate_vm(&vm) {
            if let Some(sandbox) = self.sandboxes.get_mut(execution) {
                sandbox.record_failure(failure.clone());
            }
            return Ok(LaunchOutcome::RollbackStalled {
                failure,
                stall: TerminationStalled {
                    completed: Vec::new(),
                    cause: StallCause::Port {
                        failure: port_failure,
                    },
                },
            });
        }
        self.roll_back(
            execution,
            failure,
            port,
            vec![Compensation::TerminateVm { vm }],
        )
    }

    /// The restored-VM verification hook (S10 line 181; VM part §6.6): the restored VM is
    /// verified, with fresh identity and no old epochs, before its boot evidence counts.
    fn verify_restore(
        &mut self,
        execution: &ExecutionId,
        vm: VmInstanceId,
        generations: SandboxGenerations,
        terms: &BootTerms,
        port: &mut dyn SandboxPort,
    ) -> Result<Result<(), LaunchFailure>, CoordinationError> {
        let BootSource::Restore {
            snapshot,
            authorized_volumes,
        } = &terms.source
        else {
            return Ok(Err(LaunchFailure::Transition {
                refusal: TransitionRefusal::RestoreNotVerified { vm },
            }));
        };
        let report = port.inspect_restored_vm(&vm, generations.boot);
        let expectation = RestoreExpectation {
            boot: generations.boot,
            snapshot: snapshot.clone(),
            authorized_volumes: authorized_volumes.clone(),
            policy: generations.policy,
        };
        let verified = match verify_restored_vm(&report, &expectation) {
            Ok(verified) => verified,
            Err(refusal) => return Ok(Err(LaunchFailure::RestoreRefused { refusal })),
        };
        let sandbox = self.sandboxes.get_mut(execution).ok_or_else(|| {
            CoordinationError::UnknownExecution {
                execution: execution.clone(),
            }
        })?;
        Ok(sandbox
            .record_verified_restore(&verified)
            .map_err(|refusal| LaunchFailure::Transition { refusal }))
    }

    /// Undoes every completed launch step in reverse: the VM, then the perimeter, then the
    /// reservation (VM part §6.1). Before authority nothing external was exposed. `undone`
    /// lists what was already undone.
    pub(super) fn roll_back(
        &mut self,
        execution: &ExecutionId,
        failure: LaunchFailure,
        port: &mut dyn SandboxPort,
        mut undone: Vec<Compensation>,
    ) -> Result<LaunchOutcome, CoordinationError> {
        let sandbox = self.sandboxes.get_mut(execution).ok_or_else(|| {
            CoordinationError::UnknownExecution {
                execution: execution.clone(),
            }
        })?;
        sandbox.record_failure(failure.clone());
        let first = match sandbox.state() {
            SandboxState::Planned => Some(SandboxStep::Stop),
            SandboxState::ResourcesReserved | SandboxState::PerimeterReady => {
                Some(SandboxStep::BeginCleanup)
            }
            SandboxState::VmCreated | SandboxState::BootEvidenceChecked => {
                Some(SandboxStep::Terminate)
            }
            _ => None,
        };
        if let Some(step) = first {
            match self.apply_step(execution, step) {
                Ok(_) => {}
                Err(CoordinationError::Transition { refusal }) => {
                    return Ok(LaunchOutcome::RollbackStalled {
                        failure,
                        stall: TerminationStalled {
                            completed: undone,
                            cause: StallCause::Transition { refusal },
                        },
                    })
                }
                Err(error) => return Err(error),
            }
        }
        Ok(match self.finish_termination(execution, port)? {
            Ok(compensations) => {
                undone.extend(compensations);
                LaunchOutcome::RolledBack {
                    failure,
                    compensations: undone,
                }
            }
            Err(mut stall) => {
                undone.append(&mut stall.completed);
                stall.completed = undone;
                LaunchOutcome::RollbackStalled { failure, stall }
            }
        })
    }

    /// Drives a sandbox from revoking, terminating or cleanup_pending to stopped: the VM is
    /// terminated through its handle, then the model GPU reservations, the perimeter and
    /// the sandbox reservation are released, children before their parent. A failed step
    /// stops the sequence, so nothing still in use is reported free.
    pub(super) fn finish_termination(
        &mut self,
        execution: &ExecutionId,
        port: &mut dyn SandboxPort,
    ) -> Result<Result<Vec<Compensation>, TerminationStalled>, CoordinationError> {
        let mut completed = Vec::new();
        loop {
            let sandbox = self.sandbox_ref(execution)?;
            let state = sandbox.state();
            let (vm, perimeter, reservation) =
                (sandbox.vm(), sandbox.perimeter(), sandbox.reservation());
            let step = match state {
                SandboxState::Revoking => SandboxStep::Terminate,
                SandboxState::Terminating => {
                    if let Some(vm) = vm {
                        if let Err(failure) = port.terminate_vm(&vm) {
                            return Ok(Err(TerminationStalled {
                                completed,
                                cause: StallCause::Port { failure },
                            }));
                        }
                        completed.push(Compensation::TerminateVm { vm });
                    }
                    SandboxStep::BeginCleanup
                }
                SandboxState::CleanupPending => {
                    if let Err(cause) = self.release_model_reservations(execution, &mut completed) {
                        return Ok(Err(TerminationStalled { completed, cause }));
                    }
                    if let Some(perimeter) = perimeter {
                        if let Err(failure) = port.teardown_perimeter(&perimeter) {
                            return Ok(Err(TerminationStalled {
                                completed,
                                cause: StallCause::Port { failure },
                            }));
                        }
                        completed.push(Compensation::TeardownPerimeter { perimeter });
                    }
                    if let Some(reservation) = reservation {
                        if let Err(refusal) = self.release_observed(&reservation) {
                            return Ok(Err(TerminationStalled {
                                completed,
                                cause: StallCause::Capacity { refusal },
                            }));
                        }
                        for ((owner, _), models) in self.models.iter_mut() {
                            if owner == execution {
                                models.mark_all_gpu_released();
                            }
                        }
                        completed.push(Compensation::ReleaseReservation { reservation });
                    }
                    SandboxStep::Stop
                }
                SandboxState::Planned => SandboxStep::Stop,
                SandboxState::Stopped => return Ok(Ok(completed)),
                state => {
                    return Ok(Err(TerminationStalled {
                        completed,
                        cause: StallCause::Transition {
                            refusal: TransitionRefusal::InvalidTransition {
                                from: state,
                                step: StepKind::Terminate,
                            },
                        },
                    }))
                }
            };
            match self.apply_step(execution, step) {
                Ok(_) => {}
                Err(CoordinationError::Transition { refusal }) => {
                    return Ok(Err(TerminationStalled {
                        completed,
                        cause: StallCause::Transition { refusal },
                    }))
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Retires every activation of `execution` and cancels every holding still held,
    /// retained and promised ones included, before the parent reservation is released.
    fn release_model_reservations(
        &mut self,
        execution: &ExecutionId,
        completed: &mut Vec<Compensation>,
    ) -> Result<(), StallCause> {
        let stall = |refusal| match refusal {
            ModelRefusal::Capacity { refusal } => StallCause::Capacity { refusal },
            other => StallCause::Capacity {
                refusal: CapacityRefusal::Refused {
                    reason: other.to_string(),
                },
            },
        };
        let mut releasing = Vec::new();
        for ((owner, model), models) in self.models.iter_mut() {
            if owner != execution {
                continue;
            }
            models.retire_all(RetireReason::SandboxStopped);
            releasing.extend(
                models
                    .releasable(true)
                    .into_iter()
                    .map(|holding| (*model, holding)),
            );
        }
        for (model, holding) in releasing {
            let released = self
                .release_holding(execution, model, holding)
                .map_err(stall)?;
            completed.extend(
                released
                    .into_iter()
                    .map(|reservation| Compensation::ReleaseReservation { reservation }),
            );
        }
        Ok(())
    }

    /// Cancels a host-level reservation whose workload the host saw end: its VM was
    /// terminated through the host's own port, or was never created. A created workload's
    /// release is confirmed as that host observation (S2 CORE-03).
    fn release_observed(&mut self, reservation: &ReservationKey) -> Result<(), CapacityRefusal> {
        match self.capacity.release(reservation)? {
            ReleaseOutcome::Released | ReleaseOutcome::NotHeld => Ok(()),
            ReleaseOutcome::Pending => self
                .capacity
                .confirm_release(reservation, SourceClass::HostProbe)
                .map(|_| ()),
        }
    }

    /// Continues a termination or cleanup that stalled, through to stopped. A revoking
    /// sandbox goes through [`Coordinator::advance_revocation`] instead, which first waits
    /// for its leases.
    pub fn resume_termination(
        &mut self,
        execution: &ExecutionId,
        port: &mut dyn SandboxPort,
    ) -> Result<Vec<Compensation>, CoordinationError> {
        let state = self.sandbox_ref(execution)?.state();
        if !matches!(
            state,
            SandboxState::Terminating | SandboxState::CleanupPending | SandboxState::Stopped
        ) {
            return Err(CoordinationError::Transition {
                refusal: TransitionRefusal::InvalidTransition {
                    from: state,
                    step: StepKind::Terminate,
                },
            });
        }
        self.finish_termination(execution, port)?
            .map_err(|stall| CoordinationError::Stalled { stall })
    }

    /// Ends a sandbox that holds no authority, through to stopped (VM part §6.1). A VM that
    /// recovery kept without authority (VM_created), or one whose boot evidence was checked
    /// but which was never granted authority, is terminated through its handle; a start
    /// that created no VM is undone; then everything the sandbox held is released,
    /// children before their parent. A termination or cleanup that stalled continues. A
    /// sandbox holding authority, or being revoked, ends through [`Coordinator::revoke`]
    /// and [`Coordinator::advance_revocation`], which wait for its leases (INT-02); it is
    /// refused here.
    pub fn terminate(
        &mut self,
        execution: &ExecutionId,
        port: &mut dyn SandboxPort,
    ) -> Result<Vec<Compensation>, CoordinationError> {
        let state = self.sandbox_ref(execution)?.state();
        let step = match state {
            SandboxState::VmCreated | SandboxState::BootEvidenceChecked => {
                Some(SandboxStep::Terminate)
            }
            SandboxState::ResourcesReserved | SandboxState::PerimeterReady => {
                Some(SandboxStep::BeginCleanup)
            }
            SandboxState::Planned
            | SandboxState::Terminating
            | SandboxState::CleanupPending
            | SandboxState::Stopped => None,
            SandboxState::AuthorityActive | SandboxState::Running | SandboxState::Revoking => {
                return Err(CoordinationError::Transition {
                    refusal: TransitionRefusal::InvalidTransition {
                        from: state,
                        step: StepKind::Terminate,
                    },
                })
            }
        };
        if let Some(step) = step {
            self.apply_step(execution, step)?;
        }
        self.finish_termination(execution, port)?
            .map_err(|stall| CoordinationError::Stalled { stall })
    }

    /// Moves an authority-holding sandbox to running.
    pub fn start_running(&mut self, execution: &ExecutionId) -> Result<Applied, CoordinationError> {
        self.apply_step(execution, SandboxStep::StartRunning)
    }

    /// A policy change: only the policy epoch advances (S3.1), and leases bound to the old
    /// policy are cancelled with their declared bounds.
    pub fn raise_policy_epoch(
        &mut self,
        execution: &ExecutionId,
    ) -> Result<PolicyEpoch, CoordinationError> {
        let applied = self.apply_step(execution, SandboxStep::RaisePolicyEpoch)?;
        let record = applied.record();
        let (old, new) = (record.presented.policy, record.generations.policy);
        let now = self.monotonic_now();
        self.leases.cancel_where(
            |lease| lease.parent() == execution && lease.sandbox().policy == old,
            CancelCause::PolicyChange,
            now,
        );
        Ok(new)
    }

    /// The parent's state as a lease sees it, read through the sandbox adapter, with the
    /// bound activation read through the model adapter.
    pub(super) fn lease_context(
        &self,
        execution: &ExecutionId,
        model: Option<ModelBinding>,
    ) -> Result<LeaseContext, LeaseRefusal> {
        let sandbox =
            self.sandboxes
                .get(execution)
                .ok_or_else(|| LeaseRefusal::UnknownExecution {
                    execution: execution.clone(),
                })?;
        let activation = model.map(|binding| {
            self.models
                .get(&(execution.clone(), binding.model))
                .map_or(ActivationView::Unknown, |models| {
                    models.view(binding.generations.activation)
                })
        });
        Ok(LeaseContext {
            clock: self.session,
            state: sandbox.state(),
            generations: sandbox.generations(),
            authority: sandbox.authority(),
            activation,
        })
    }

    /// The context for new work, refused while the owner takes a resource back.
    pub(super) fn new_work_context(
        &self,
        execution: &ExecutionId,
        model: Option<ModelBinding>,
    ) -> Result<LeaseContext, LeaseRefusal> {
        if self.returns.contains_key(execution) {
            return Err(LeaseRefusal::NewWorkDenied {
                execution: execution.clone(),
            });
        }
        self.lease_context(execution, model)
    }

    /// Starts child work under its parent execution (S2 CORE-04). The parent must hold
    /// current, unexpired authority; the lease carries the parent's generations.
    /// [`Coordinator::start_granted_work`] issues it under grants of that authority.
    pub fn start_child_work(
        &mut self,
        execution: &ExecutionId,
        operation: OperationId,
        kind: LeaseKind,
        terms: LeaseTerms,
    ) -> Result<Lease, LeaseRefusal> {
        self.start_granted_work(execution, operation, kind, terms, BTreeSet::new())
    }

    /// Whether `lease` is honoured now; enforcement points ask this (VM part §6.3: an
    /// authoritative check). A lease that depends on a grant revoked under its parent is
    /// refused. A refusal for want of the authority the parent's revocation took away is
    /// recorded as the revocation's first denied authorization, if it is the first.
    pub fn check_lease(&self, lease: LeaseId) -> Result<Lease, LeaseRefusal> {
        let record = self
            .leases
            .get(lease)
            .ok_or(LeaseRefusal::UnknownLease { lease })?;
        let checked = self.check_record(record);
        if let Err(refusal) = &checked {
            self.note_denial(
                record.lease().parent(),
                DeniedRequest::LeaseCheck { lease },
                refusal,
            );
        }
        checked
    }

    /// Whether the lease `record` holds is honoured now.
    fn check_record(&self, record: &LeaseRecord) -> Result<Lease, LeaseRefusal> {
        let context = self.lease_context(record.lease().parent(), record.lease().model())?;
        lease::check(record, self.lease_time()?, &context)?;
        if let Some(grant) = self.revoked_grant_of(record.lease()) {
            return Err(LeaseRefusal::GrantRevoked { grant });
        }
        Ok(record.lease().clone())
    }

    /// Whether `lease`, presented by its holder with the clock session it was issued on
    /// ([`Lease::clock`]), is honoured now (VM part §6.3: never reuse an identity while old
    /// capabilities can exist). A lease from another run is refused with
    /// [`LeaseRefusal::OtherClock`] even where its number was issued again. Enforcement
    /// points that receive a lease from its holder check it here.
    pub fn check_presented_lease(
        &self,
        lease: LeaseId,
        session: ClockSession,
    ) -> Result<Lease, LeaseRefusal> {
        self.presented(lease, session)?;
        self.check_lease(lease)
    }

    /// Renews `lease` for its holder, who presents the clock session it was issued on;
    /// a lease from another run is refused as in [`Coordinator::check_presented_lease`].
    pub fn renew_presented_lease(
        &mut self,
        lease: LeaseId,
        session: ClockSession,
    ) -> Result<Lease, LeaseRefusal> {
        self.presented(lease, session)?;
        self.renew_lease(lease)
    }

    /// Whether the lease recorded as `lease` was issued on `session`.
    fn presented(&self, lease: LeaseId, session: ClockSession) -> Result<(), LeaseRefusal> {
        let record = self
            .leases
            .get(lease)
            .ok_or(LeaseRefusal::UnknownLease { lease })?;
        if record.lease().clock() == session {
            Ok(())
        } else {
            Err(LeaseRefusal::OtherClock)
        }
    }

    /// Renews `lease` by the rules on [`LeaseTerms`]. A lease that depends on a revoked
    /// grant never renews.
    pub fn renew_lease(&mut self, lease: LeaseId) -> Result<Lease, LeaseRefusal> {
        let renewed = self.renew(lease);
        if let (Err(refusal), Some(record)) = (&renewed, self.leases.get(lease)) {
            self.note_denial(
                record.lease().parent(),
                DeniedRequest::LeaseRenewal { lease },
                refusal,
            );
        }
        renewed
    }

    fn renew(&mut self, lease: LeaseId) -> Result<Lease, LeaseRefusal> {
        let record = self
            .leases
            .get(lease)
            .ok_or(LeaseRefusal::UnknownLease { lease })?;
        let context = self.lease_context(record.lease().parent(), record.lease().model())?;
        let now = self.lease_time()?;
        lease::check(record, now, &context)?;
        if let Some(grant) = self.revoked_grant_of(record.lease()) {
            return Err(LeaseRefusal::GrantRevoked { grant });
        }
        self.leases.renew(lease, now, &context)
    }

    /// The holder is done; releasing a cancelling lease acknowledges the cancellation.
    pub fn release_lease(&mut self, lease: LeaseId) -> Result<(), LeaseRefusal> {
        let now = self.monotonic_now();
        self.leases.release(lease, now)
    }

    /// The holder stopped after a cancellation (VM part §6.3: enforcement
    /// acknowledgment).
    pub fn acknowledge_cancellation(&mut self, lease: LeaseId) -> Result<(), LeaseRefusal> {
        let now = self.monotonic_now();
        self.leases.acknowledge(lease, now)
    }

    /// Begins a model activation with one new GPU allocation (S3.1, S3.2): the parent
    /// must hold current authority, the settings may not leave the parent's category,
    /// claim more authority than the parent holds or use network grants and artifacts its
    /// authority did not grant (S3.5), and the GPU memory is reserved as a child of the
    /// sandbox reservation before loading begins. The memory is released
    /// once no unretired activation uses it. [`Coordinator::begin_activation_with`] takes
    /// several devices, host memory, acquired memory and retention.
    pub fn begin_activation(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        settings: RuntimeSettings,
        demand: GpuDemand,
    ) -> Result<GpuAllocationHandle, ModelRefusal> {
        let handle = self.begin(
            execution,
            model,
            settings,
            ActivationDemand::gpu(demand),
            None,
        )?;
        Ok(GpuAllocationHandle {
            execution: handle.execution,
            model: handle.model,
            generations: handle.generations,
        })
    }

    /// Begins a model activation with `demand` (GPU part §3.6 steps 1–2): a new GPU
    /// allocation, with its own generation, on each device named; host and pinned host
    /// memory; and holdings of earlier activations acquired as they are, under their own
    /// generations, so memory several activations share counts once (GPU part §2.7).
    /// Every new holding is reserved as a child of the sandbox reservation before loading
    /// begins, all of them or none; a refusal consumes no generation. If the ledger
    /// refuses to start creation, the grants are cancelled; one whose creation began stays
    /// counted until reconciled, and an unused grant lapses after its grant lifetime
    /// (CORE-03). The parent's checks are those of [`Coordinator::begin_activation`].
    pub fn begin_activation_with(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        settings: RuntimeSettings,
        demand: ActivationDemand,
    ) -> Result<ActivationHandle, ModelRefusal> {
        self.begin(execution, model, settings, demand, None)
    }

    /// Begins a model activation that runs only after `predecessor` has drained, for when
    /// capacity allows one resident generation (GPU part §3.6 line 597). The predecessor
    /// stops admitting at once: new requests find no serving activation, a real pause,
    /// while the requests it admitted finish (INT-03). Holdings it alone uses pass to the
    /// new activation when [`Coordinator::confirm_gpu_released`] confirms their release,
    /// without returning to the ledger in between, so no other request can take the
    /// share; only what they do not cover is reserved now. A successor that needs less
    /// than its predecessor keeps the predecessor's whole share until it is released. The
    /// new activation completes only once its handover is done; retiring it first leaves
    /// the share with the predecessor, or releases it if the predecessor has retired.
    pub fn begin_drain_first(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        settings: RuntimeSettings,
        demand: ActivationDemand,
        predecessor: ModelActivationGeneration,
    ) -> Result<ActivationHandle, ModelRefusal> {
        let handle = self.begin(execution, model, settings, demand, Some(predecessor))?;
        // The predecessor retires at once if no lease holds it. A ledger refusal to release
        // memory it alone used leaves that memory counted, never free, and the next
        // retire_drained retries it.
        let _ = self.retire_drained(execution, model);
        Ok(handle)
    }

    /// Activates the model again within the memory `from` holds, with no new reservation:
    /// every holding of `from` is acquired as it is, under its own generation (GPU part
    /// §3.6). `from` may still be draining, as for a rollback before reclamation, or may
    /// have retired with its memory retained. A holding already released or from an
    /// earlier boot or authorization epoch is refused, so reloading may be necessary.
    pub fn reactivate(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        settings: RuntimeSettings,
        from: ModelActivationGeneration,
    ) -> Result<ActivationHandle, ModelRefusal> {
        let acquire = self
            .models
            .get(&(execution.clone(), model))
            .ok_or(ModelRefusal::UnknownModel { model })?
            .activation(from)
            .ok_or(ModelRefusal::UnknownActivation { activation: from })?
            .holdings()
            .clone();
        let demand = ActivationDemand {
            acquire,
            ..ActivationDemand::default()
        };
        self.begin(execution, model, settings, demand, None)
    }

    fn begin(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        settings: RuntimeSettings,
        demand: ActivationDemand,
        predecessor: Option<ModelActivationGeneration>,
    ) -> Result<ActivationHandle, ModelRefusal> {
        let begun = self.begin_under_parent(execution, model, settings, demand, predecessor);
        if let Err(refusal) = &begun {
            self.note_model_denial(execution, DeniedRequest::Activation { model }, refusal);
        }
        begun
    }

    fn begin_under_parent(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        settings: RuntimeSettings,
        demand: ActivationDemand,
        predecessor: Option<ModelActivationGeneration>,
    ) -> Result<ActivationHandle, ModelRefusal> {
        let parent = |refusal| ModelRefusal::Parent { refusal };
        let context = self.new_work_context(execution, None).map_err(parent)?;
        let grant = lease::parent_authority(&context, self.monotonic_now()).map_err(parent)?;
        let parent_category = ExecutionCategory::VmSandbox;
        if settings.execution_category != parent_category {
            return Err(ModelRefusal::CategoryMismatch {
                parent: parent_category,
                settings: settings.execution_category,
            });
        }
        if settings.authority.epoch != grant.epoch
            || settings.authority.clock != grant.clock
            || settings.authority.expires_at > grant.expires_at
        {
            return Err(ModelRefusal::AuthorityExceedsParent {
                parent: grant,
                settings: settings.authority,
            });
        }
        let sandbox = self.sandbox_of(execution)?;
        settings_within(&settings, sandbox.settings_grant(), sandbox.loader_grant())?;
        let key = (execution.clone(), model);
        let plan = match self.models.get(&key) {
            Some(models) => models.plan(&demand, context.generations, predecessor)?,
            None => ModelActivations::new(execution.clone(), model).plan(
                &demand,
                context.generations,
                predecessor,
            )?,
        };
        let reserved = self.reserve_fresh(execution, model, &plan.fresh)?;
        Ok(self
            .models
            .entry(key)
            .or_insert_with(|| ModelActivations::new(execution.clone(), model))
            .apply(plan, settings, context.generations, &reserved))
    }

    /// The parent sandbox of model work.
    fn sandbox_of(&self, execution: &ExecutionId) -> Result<&SandboxLifecycle, ModelRefusal> {
        self.sandboxes
            .get(execution)
            .ok_or_else(|| ModelRefusal::Parent {
                refusal: LeaseRefusal::UnknownExecution {
                    execution: execution.clone(),
                },
            })
    }

    /// Reserves `fresh` holdings as children of the sandbox reservation, all of them or
    /// none, and starts their creation (S2 CORE-03: reserve before create).
    fn reserve_fresh(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        fresh: &[FreshHolding],
    ) -> Result<BTreeMap<HoldingId, ReservationKey>, ModelRefusal> {
        let sandbox = self.sandbox_of(execution)?;
        let parent_reservation = sandbox
            .reservation()
            .ok_or(ModelRefusal::NoSandboxReservation)?;
        let tenant = sandbox.tenant().clone();
        let priority = sandbox.priority();
        let mut reserved = BTreeMap::new();
        for fresh in fresh {
            let own = fresh.own.demand();
            if own.is_empty() {
                continue;
            }
            let purpose = match fresh.id {
                HoldingId::Gpu { allocation } => ReservationPurpose::ModelGpu {
                    model,
                    gpu_allocation: allocation,
                },
                HoldingId::Host { reserved_by } => ReservationPurpose::ModelHost {
                    model,
                    activation: reserved_by,
                },
            };
            let reservation = ReservationKey::derive(execution, &purpose);
            let request = ReservationRequest {
                key: reservation,
                tenant: tenant.clone(),
                execution: execution.clone(),
                purpose,
                priority,
                parent: Some(parent_reservation),
                demand: own,
            };
            let refusal = match self.capacity.reserve(&request) {
                Ok(ReserveOutcome::Granted) => {
                    reserved.insert(fresh.id, reservation);
                    continue;
                }
                Ok(ReserveOutcome::Queued { position }) => ModelRefusal::Queued { position },
                Err(refusal) => ModelRefusal::Capacity { refusal },
            };
            self.withdraw(&reserved);
            return Err(refusal);
        }
        for reservation in reserved.values() {
            if let Err(refusal) = self.capacity.begin_create(reservation) {
                self.withdraw(&reserved);
                return Err(ModelRefusal::Capacity { refusal });
            }
        }
        Ok(reserved)
    }

    /// Grants the models of the sandbox, or of the labelled runtime, `execution` the loader
    /// optimizations `plan` enabled: the CORE-01 gate's current plan for the runtime it runs
    /// now (S3.5; INT-06). Models may use only these, and only the ordinary loader without
    /// a grant. The grant is recorded with the authority held now and ends with it, so a
    /// recovered, rebooted or re-authorized runtime is granted its loader again; a plan for
    /// another runtime is refused.
    pub fn grant_loader(
        &mut self,
        execution: &ExecutionId,
        plan: &LoaderPlan,
    ) -> Result<(), ModelRefusal> {
        if self.labelled.contains_key(execution) {
            return self.grant_labelled_loader(execution, plan);
        }
        let sandbox = self
            .sandboxes
            .get_mut(execution)
            .ok_or_else(|| ModelRefusal::Parent {
                refusal: LeaseRefusal::UnknownExecution {
                    execution: execution.clone(),
                },
            })?;
        if plan.runtime() != sandbox.runtime() {
            return Err(ModelRefusal::PlanForOtherRuntime {
                plan: plan.runtime().clone(),
                runtime: sandbox.runtime().clone(),
            });
        }
        if sandbox.authority().is_none() {
            return Err(ModelRefusal::Parent {
                refusal: LeaseRefusal::NoAuthority {
                    state: sandbox.state(),
                },
            });
        }
        sandbox.grant_loader(LoaderGrant::from_plan(plan));
        Ok(())
    }

    /// Reserves immutable weights for `model` apart from any activation's own memory (GPU
    /// part §2.7: shared weights count once; T15 decision 1): one holding per device of
    /// `weights_bytes`, each a child of the sandbox reservation with its own GPU allocation
    /// generation, kept until released. Activations acquire them through
    /// [`ActivationDemand::acquire`] beside the working memory (KV, contexts, workspaces)
    /// they reserve themselves, so a successor takes the weights without its
    /// predecessor's KV. The parent must hold current authority; all of them are reserved
    /// or none, and a refusal consumes no generation. Released by
    /// [`Coordinator::release_unused_holding`], or with the parent's authority.
    pub fn reserve_weights(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        weights_bytes: BTreeMap<GpuDeviceKey, u64>,
    ) -> Result<BTreeMap<GpuDeviceKey, HoldingId>, ModelRefusal> {
        let parent = |refusal| ModelRefusal::Parent { refusal };
        let context = self.new_work_context(execution, None).map_err(parent)?;
        lease::parent_authority(&context, self.monotonic_now()).map_err(parent)?;
        let key = (execution.clone(), model);
        let plan = match self.models.get(&key) {
            Some(models) => models.plan_weights(&weights_bytes)?,
            None => ModelActivations::new(execution.clone(), model).plan_weights(&weights_bytes)?,
        };
        let reserved = self.reserve_fresh(execution, model, &plan.fresh)?;
        Ok(self
            .models
            .entry(key)
            .or_insert_with(|| ModelActivations::new(execution.clone(), model))
            .apply_weights(plan, context.generations, &reserved))
    }

    /// Releases `holding` once `source` observed its memory freed (GPU part §3.6 step 7):
    /// weights reserved apart from activations, or memory a parked or retired activation
    /// retained. A holding an unretired activation uses, or a drain-first successor waits
    /// for, is refused. The runtime's own report is enough within the sandbox reservation;
    /// a guest cannot release anything at host level (S3.2).
    pub fn release_unused_holding(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        holding: HoldingId,
        source: SourceClass,
    ) -> Result<(), ModelRefusal> {
        let key = (execution.clone(), model);
        let models = self
            .models
            .get(&key)
            .ok_or(ModelRefusal::UnknownModel { model })?;
        let entry = models
            .holding(holding)
            .ok_or(ModelRefusal::HoldingUnavailable { holding })?;
        if models.in_use(entry) {
            return Err(ModelRefusal::HoldingInUse { holding });
        }
        let state = entry.state();
        if state == GpuReservationState::Released {
            return Err(ModelRefusal::HoldingUnavailable { holding });
        }
        if !source.satisfies(SourceClass::GuestReport) {
            return Err(ModelRefusal::Capacity {
                refusal: CapacityRefusal::SourceTooWeak {
                    source,
                    required: SourceClass::GuestReport,
                },
            });
        }
        if state == GpuReservationState::Held {
            self.release_holding(execution, model, holding)?;
        }
        let releasing = self
            .models
            .get(&key)
            .and_then(|models| models.holding(holding))
            .is_some_and(|entry| entry.state() == GpuReservationState::Releasing);
        if releasing {
            self.confirm_holding(execution, model, holding, source)?;
        }
        Ok(())
    }

    /// Parks an idle activation (GPU part §3.6: draining → parked): it serves no more, as
    /// if evicted, and every holding it used is kept until released, so the model can be
    /// activated again within the same memory ([`Coordinator::reactivate`]), or the memory
    /// released once freed ([`Coordinator::confirm_gpu_released`],
    /// [`Coordinator::release_unused_holding`]). Parking frees nothing and never touches
    /// the parent's authority or generations (S2 CORE-04). An activation a lease may still
    /// use is refused.
    pub fn park(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        activation: ModelActivationGeneration,
    ) -> Result<ModelGenerations, ModelRefusal> {
        let key = (execution.clone(), model);
        self.models
            .get(&key)
            .ok_or(ModelRefusal::UnknownModel { model })?
            .check_step(activation, ActivationStep::Park)?;
        let now = self.monotonic_now();
        let leases = self.live_leases(execution, model, activation, now);
        if !leases.is_empty() {
            return Err(ModelRefusal::RequestsInFlight { activation, leases });
        }
        let models = self
            .models
            .get_mut(&key)
            .ok_or(ModelRefusal::UnknownModel { model })?;
        models.retain(activation);
        let generations = models.retire(activation, RetireReason::Parked)?;
        self.settle_holdings(execution, model, false)?;
        Ok(generations)
    }

    /// Cancels what a refused activation reserved. Anything the ledger still counts, such
    /// as a reservation whose creation began, stays counted until reconciled: it is never
    /// reported free while it may be in use (S2 CORE-03).
    fn withdraw(&mut self, reserved: &BTreeMap<HoldingId, ReservationKey>) {
        for reservation in reserved.values() {
            let _ = self.capacity.release(reservation);
        }
    }

    /// Makes a loaded activation the serving one (INT-03). The activation it replaces
    /// drains: requests admitted to it keep it, and it retires once none remains. An
    /// activation still waiting for a drain-first handover is refused.
    pub fn complete_activation(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        activation: ModelActivationGeneration,
    ) -> Result<Completion, ModelRefusal> {
        let completion = self
            .models
            .get_mut(&(execution.clone(), model))
            .ok_or(ModelRefusal::UnknownModel { model })?
            .complete(activation)?;
        self.retire_drained(execution, model)?;
        Ok(completion)
    }

    /// The load failed or was abandoned: the activation retires and the memory nothing
    /// else keeps is released. A drain-first successor retired this way leaves its
    /// predecessor's share with the predecessor, or releases it if the predecessor has
    /// retired; a draining predecessor may be activated again with
    /// [`Coordinator::reactivate`]. While the request assigned to it for execute-while-load
    /// may still run, it is refused: memory is never released under a request that may
    /// still use it.
    pub fn fail_activation(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        activation: ModelActivationGeneration,
    ) -> Result<(), ModelRefusal> {
        let key = (execution.clone(), model);
        self.models
            .get(&key)
            .ok_or(ModelRefusal::UnknownModel { model })?
            .check_step(activation, ActivationStep::FailLoad)?;
        let now = self.monotonic_now();
        let leases = self.live_leases(execution, model, activation, now);
        if !leases.is_empty() {
            return Err(ModelRefusal::RequestsInFlight { activation, leases });
        }
        self.models
            .get_mut(&key)
            .ok_or(ModelRefusal::UnknownModel { model })?
            .retire(activation, RetireReason::LoadFailed)?;
        self.settle_holdings(execution, model, false)?;
        Ok(())
    }

    /// Admits one request to the serving activation; the lease keeps that activation's
    /// generations for the request's whole life (INT-03). An activation whose settings
    /// use a grant revoked under the parent admits nothing.
    pub fn admit_request(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        operation: OperationId,
        terms: LeaseTerms,
    ) -> Result<Lease, ModelRefusal> {
        let admitted = self.admit(execution, model, operation, terms);
        if let Err(refusal) = &admitted {
            let request = DeniedRequest::NewLease {
                kind: LeaseKind::ModelRequest,
            };
            self.note_model_denial(execution, request, refusal);
        }
        admitted
    }

    fn admit(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        operation: OperationId,
        terms: LeaseTerms,
    ) -> Result<Lease, ModelRefusal> {
        let serving = self
            .models
            .get(&(execution.clone(), model))
            .and_then(ModelActivations::serving)
            .map(|activation| activation.generations())
            .ok_or(ModelRefusal::NoServingActivation { model })?;
        let binding = ModelBinding {
            model,
            generations: serving,
        };
        let parent = |refusal| ModelRefusal::Parent { refusal };
        let context = self
            .new_work_context(execution, Some(binding))
            .map_err(parent)?;
        let now = self.lease_time().map_err(parent)?;
        let revoked_grant = self.activation_revoked_grant(execution, model, serving.activation);
        self.leases
            .issue(
                LeaseRequest {
                    parent: execution.clone(),
                    operation,
                    kind: LeaseKind::ModelRequest,
                    model: Some(binding),
                    grants: BTreeSet::new(),
                    revoked_grant,
                    terms,
                },
                now,
                &context,
            )
            .map_err(parent)
    }

    /// Assigns one pending request to an activation being prepared, under a
    /// preparation-generation lease (GPU part §3.6 line 601: execute-while-load computes
    /// only for an explicitly assigned pending request). The lease carries the
    /// activation's generations and is honoured from preparation through serving; while it
    /// lives, no other request is assigned, and unrelated traffic waits for serving leases.
    /// An activation still waiting for a drain-first handover is refused: its memory is
    /// not all reserved yet, and so is one whose settings use a revoked grant.
    pub fn admit_preparation_request(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        activation: ModelActivationGeneration,
        operation: OperationId,
        terms: LeaseTerms,
    ) -> Result<Lease, ModelRefusal> {
        let admitted = self.admit_preparation(execution, model, activation, operation, terms);
        if let Err(refusal) = &admitted {
            let request = DeniedRequest::NewLease {
                kind: LeaseKind::Preparation,
            };
            self.note_model_denial(execution, request, refusal);
        }
        admitted
    }

    fn admit_preparation(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        activation: ModelActivationGeneration,
        operation: OperationId,
        terms: LeaseTerms,
    ) -> Result<Lease, ModelRefusal> {
        let models = self
            .models
            .get(&(execution.clone(), model))
            .ok_or(ModelRefusal::UnknownModel { model })?;
        models.check_step(activation, ActivationStep::Prepare)?;
        let entry = models
            .activation(activation)
            .ok_or(ModelRefusal::UnknownActivation { activation })?;
        if let Some(predecessor) = entry.awaiting_handover() {
            return Err(ModelRefusal::HandoverPending { predecessor });
        }
        let generations = entry.generations();
        let now = self
            .lease_time()
            .map_err(|refusal| ModelRefusal::Parent { refusal })?;
        let assigned = self.leases.records().find(|record| {
            let lease = record.lease();
            lease.kind() == LeaseKind::Preparation
                && lease.parent() == execution
                && lease.model().is_some_and(|binding| {
                    binding.model == model && binding.generations.activation == activation
                })
                && record.may_be_in_use(now)
        });
        if let Some(record) = assigned {
            return Err(ModelRefusal::PreparationAssigned {
                assigned: record.lease().operation().clone(),
            });
        }
        let binding = ModelBinding { model, generations };
        let parent = |refusal| ModelRefusal::Parent { refusal };
        let context = self
            .new_work_context(execution, Some(binding))
            .map_err(parent)?;
        let revoked_grant = self.activation_revoked_grant(execution, model, activation);
        self.leases
            .issue(
                LeaseRequest {
                    parent: execution.clone(),
                    operation,
                    kind: LeaseKind::Preparation,
                    model: Some(binding),
                    grants: BTreeSet::new(),
                    revoked_grant,
                    terms,
                },
                now,
                &context,
            )
            .map_err(parent)
    }

    /// Whether the request holding `lease` may publish a result now (GPU part §3.6 line
    /// 601): the lease is honoured and its activation has been published. A request
    /// computing under a preparation lease publishes nothing while its activation is
    /// still being prepared; the dependency checks of its computation stay with the
    /// placement.
    pub fn check_result_publication(&self, lease: LeaseId) -> Result<Lease, LeaseRefusal> {
        let lease = self.check_lease(lease)?;
        if let Some(binding) = lease.model() {
            let activation = binding.generations.activation;
            let view = self
                .models
                .get(&(lease.parent().clone(), binding.model))
                .map_or(ActivationView::Unknown, |models| models.view(activation));
            if let ActivationView::Loading { .. } = view {
                return Err(LeaseRefusal::ActivationNotServing {
                    activation,
                    state: Some(ActivationState::Loading),
                });
            }
        }
        Ok(lease)
    }

    /// A request finished: its lease is released, and a drained activation it kept alive
    /// retires. Returns the activations that retired.
    pub fn finish_request(
        &mut self,
        lease: LeaseId,
    ) -> Result<Vec<ModelGenerations>, ModelRefusal> {
        let parent = |refusal| ModelRefusal::Parent { refusal };
        let record = self
            .leases
            .get(lease)
            .ok_or(LeaseRefusal::UnknownLease { lease })
            .map_err(parent)?;
        let (owner, binding) = (record.lease().parent().clone(), record.lease().model());
        let now = self.monotonic_now();
        self.leases.release(lease, now).map_err(parent)?;
        match binding {
            Some(binding) => self.retire_drained(&owner, binding.model),
            None => Ok(Vec::new()),
        }
    }

    /// Retires every draining activation of `model` that no lease may still use, and
    /// releases the memory nothing else keeps.
    pub fn retire_drained(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
    ) -> Result<Vec<ModelGenerations>, ModelRefusal> {
        let now = self.monotonic_now();
        let key = (execution.clone(), model);
        let draining: Vec<ModelGenerations> = match self.models.get(&key) {
            Some(models) => models
                .activations()
                .iter()
                .filter(|activation| activation.state() == ActivationState::Draining)
                .map(|activation| activation.generations())
                .collect(),
            None => return Ok(Vec::new()),
        };
        let mut retired = Vec::new();
        for generations in draining {
            if !self
                .live_leases(execution, model, generations.activation, now)
                .is_empty()
            {
                continue;
            }
            if let Some(models) = self.models.get_mut(&key) {
                models.retire(generations.activation, RetireReason::Replaced)?;
            }
            retired.push(generations);
        }
        self.settle_holdings(execution, model, false)?;
        Ok(retired)
    }

    /// Evicts an idle activation, or parks it when its memory is retained, and releases
    /// the memory nothing else keeps. Eviction belongs to the model side alone: it never
    /// touches the parent's authority or generations (S2 CORE-04: model eviction cannot
    /// renew sandbox authority).
    pub fn evict(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        activation: ModelActivationGeneration,
    ) -> Result<ModelGenerations, ModelRefusal> {
        let key = (execution.clone(), model);
        self.models
            .get(&key)
            .ok_or(ModelRefusal::UnknownModel { model })?
            .check_step(activation, ActivationStep::Evict)?;
        let now = self.monotonic_now();
        let leases = self.live_leases(execution, model, activation, now);
        if !leases.is_empty() {
            return Err(ModelRefusal::RequestsInFlight { activation, leases });
        }
        let generations = self
            .models
            .get_mut(&key)
            .ok_or(ModelRefusal::UnknownModel { model })?
            .retire(activation, RetireReason::Evicted)?;
        self.settle_holdings(execution, model, false)?;
        Ok(generations)
    }

    /// Whether a GPU allocation handle still points into a live allocation as its
    /// activation uses it. A handle of a retired activation, or into an allocation the
    /// activation does not use, is refused (INT-04), and so is one into an allocation still
    /// waiting for a drain-first handover.
    pub fn check_gpu_handle(&self, handle: &GpuAllocationHandle) -> Result<(), LeaseRefusal> {
        let models = self.models.get(&(handle.execution.clone(), handle.model));
        let bound = handle.generations.gpu_allocation;
        let current = models.and_then(|models| {
            models
                .activations()
                .iter()
                .rev()
                .find(|activation| !activation.state().is_retired())
                .map(|activation| activation.generations().gpu_allocation)
        });
        let problem = models.map_or(Some(HandleProblem::Stale), |models| {
            models.handle_problem(handle.generations)
        });
        match problem {
            None => Ok(()),
            Some(HandleProblem::AwaitingHandover) => {
                Err(LeaseRefusal::AllocationAwaitingHandover { allocation: bound })
            }
            Some(HandleProblem::Stale) => Err(LeaseRefusal::StaleGpuAllocation { bound, current }),
        }
    }

    /// Leases bound to `activation` whose holders may still be acting.
    pub(super) fn live_leases(
        &self,
        execution: &ExecutionId,
        model: ModelId,
        activation: ModelActivationGeneration,
        now: MonotonicTime,
    ) -> Vec<LeaseId> {
        self.leases
            .records()
            .filter(|record| {
                let lease = record.lease();
                lease.parent() == execution
                    && lease.model().is_some_and(|binding| {
                        binding.model == model && binding.generations.activation == activation
                    })
                    && record.may_be_in_use(now)
            })
            .map(|record| record.lease().id())
            .collect()
    }

    /// Releases every holding of `model` that nothing keeps: used by no unretired
    /// activation, and, unless `force`, neither retained nor promised to a drain-first
    /// successor. `force` is for when the parent's authority or the sandbox ends. Returns
    /// the reservations cancelled.
    pub(super) fn settle_holdings(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        force: bool,
    ) -> Result<Vec<ReservationKey>, ModelRefusal> {
        let holdings = match self.models.get(&(execution.clone(), model)) {
            Some(models) => models.releasable(force),
            None => return Ok(Vec::new()),
        };
        let mut released = Vec::new();
        for holding in holdings {
            released.extend(self.release_holding(execution, model, holding)?);
        }
        Ok(released)
    }

    /// Cancels one holding's reservations. Those of a created workload stay counted until
    /// their release is observed (S2 CORE-03), so the holding is releasing until then.
    pub(super) fn release_holding(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        holding: HoldingId,
    ) -> Result<Vec<ReservationKey>, ModelRefusal> {
        let key = (execution.clone(), model);
        let reservations = self
            .models
            .get(&key)
            .and_then(|models| models.holding(holding))
            .map(|entry| entry.reservations().to_vec())
            .unwrap_or_default();
        let mut pending = false;
        for reservation in &reservations {
            let outcome = self
                .capacity
                .release(reservation)
                .map_err(|refusal| ModelRefusal::Capacity { refusal })?;
            pending |= outcome == ReleaseOutcome::Pending;
        }
        let state = if pending {
            GpuReservationState::Releasing
        } else {
            GpuReservationState::Released
        };
        if let Some(models) = self.models.get_mut(&key) {
            models.set_holding_state(holding, state);
        }
        Ok(reservations)
    }

    /// Confirms that `source` observed the memory a retired activation left released (S2
    /// CORE-03: unknown usage is never free). Each holding it used that no unretired
    /// activation uses is closed: a releasing one is confirmed; a retained one, or one not
    /// yet released, is released and confirmed; and one promised to a drain-first
    /// successor passes to it without returning to the ledger, so the share is never free
    /// in between (GPU part §3.6 line 597). The runtime's own report is enough within the
    /// sandbox reservation; a guest cannot release anything at host level (S3.2). Model
    /// code confirms through this call, never in the ledger directly, so the record and
    /// the ledger agree.
    pub fn confirm_gpu_released(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        activation: ModelActivationGeneration,
        source: SourceClass,
    ) -> Result<(), ModelRefusal> {
        let key = (execution.clone(), model);
        let models = self
            .models
            .get(&key)
            .ok_or(ModelRefusal::UnknownModel { model })?;
        let state = models
            .activation(activation)
            .ok_or(ModelRefusal::UnknownActivation { activation })?
            .state();
        let closing = models.closing(activation);
        if !state.is_retired() || closing.is_empty() {
            return Err(ModelRefusal::NothingToRelease { activation });
        }
        if !source.satisfies(SourceClass::GuestReport) {
            return Err(ModelRefusal::Capacity {
                refusal: CapacityRefusal::SourceTooWeak {
                    source,
                    required: SourceClass::GuestReport,
                },
            });
        }
        for (holding, step) in closing {
            match step {
                Closing::HandOver => {
                    if let Some(models) = self.models.get_mut(&key) {
                        models.hand_over(holding);
                    }
                }
                Closing::Release => {
                    self.release_holding(execution, model, holding)?;
                    let releasing = self
                        .models
                        .get(&key)
                        .and_then(|models| models.holding(holding))
                        .is_some_and(|entry| entry.state() == GpuReservationState::Releasing);
                    if releasing {
                        self.confirm_holding(execution, model, holding, source)?;
                    }
                }
                Closing::Confirm => self.confirm_holding(execution, model, holding, source)?,
            }
        }
        Ok(())
    }

    /// Confirms, as `source` observed, the release of every releasing GPU holding of
    /// `model`: the runtime's real mechanism freed its GPU memory (S10 line 185). Host
    /// memory holdings wait for their own observation.
    pub(super) fn confirm_gpu_holdings(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        source: SourceClass,
    ) -> Result<(), ModelRefusal> {
        let releasing: Vec<HoldingId> = self
            .models
            .get(&(execution.clone(), model))
            .map(|models| {
                models
                    .holdings()
                    .iter()
                    .filter(|holding| holding.state() == GpuReservationState::Releasing)
                    .map(Holding::id)
                    .filter(|holding| matches!(holding, HoldingId::Gpu { .. }))
                    .collect()
            })
            .unwrap_or_default();
        for holding in releasing {
            self.confirm_holding(execution, model, holding, source)?;
        }
        Ok(())
    }

    /// Confirms a releasing holding's release as `source` observed it: the runtime's own
    /// report suffices within the sandbox reservation (S3.2).
    pub(super) fn confirm_holding(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        holding: HoldingId,
        source: SourceClass,
    ) -> Result<(), ModelRefusal> {
        let key = (execution.clone(), model);
        let reservations = self
            .models
            .get(&key)
            .and_then(|models| models.holding(holding))
            .map(|entry| entry.reservations().to_vec())
            .unwrap_or_default();
        for reservation in &reservations {
            self.capacity
                .confirm_release(reservation, source)
                .map_err(|refusal| ModelRefusal::Capacity { refusal })?;
        }
        if let Some(models) = self.models.get_mut(&key) {
            models.set_holding_state(holding, GpuReservationState::Released);
        }
        Ok(())
    }
}
