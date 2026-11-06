//! The supervisor (VM part §3.1 lines 2037–2047; §6.1–§6.6 lines 2284–2353; VM-W24–VM-W27
//! lines 2630–2633; VM-D7 line 3204; VM-D10 line 3206; VM-D12 line 3207).
//!
//! The supervisor owns VM lifetimes. It drives the CORE-04 launch transaction through the
//! coordinator with the backend behind the [`Bridge`], keeps one [`SandboxLease`] per
//! sandbox with the five limits, runs the §6.3 revocation protocol as a
//! [`RevocationRun`] over the coordinator's notice, applies the per-class rules of VM-D7
//! and VM-D10, records the kill measurements, and recovers from its persisted state
//! through handles whose identity the backend checks, never through stored PIDs. Lifecycle
//! receipts carry CORE-06 event contexts; revocations are CORE-06 [`Revocation`] events
//! ready for the hub's priority lane.
//!
//! The acknowledgments CORE-04 records are taken from its revocation operation with their
//! sources ([`Supervisor::sync_revocation`]): "new authorizations denied" is the first
//! authorization refused after the decision, and "channels closed" is all channels
//! closed, which an enforcement point reports through the coordinator
//! ([`Supervisor::acknowledge_from`]). One grant under a sandbox's authority can be
//! revoked alone ([`Supervisor::revoke_grant`]): a CORE-04 tombstone that leaves the
//! epoch, the other grants and the VM as they were, with its own receipt, a CORE-06
//! [`GrantRevocation`], and a record persisted with the supervisor's state, so revoking
//! it again after a recovery is recognized. A grant revocation never acknowledges a
//! revocation of the sandbox, and a revocation of the sandbox never takes anything from
//! one. A warm-pool checkout takes its clone only once the ledger grants the relaunch's
//! capacity ([`Supervisor::checkout`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::backend::{Bridge, HandleIdentity, HandleTable, VmBackend};
use super::identity::{Binding, BindingRefusal, BindingTuple, SandboxIdentity};
use super::leases::{
    child_lease_terms, ActivityKind, ActivityRefusal, CallTerms, Expiry, LeaseLimits,
    LeaseRestoreRefusal, SandboxClass, SandboxLease, SkewPolicy,
};
use super::measurements::{
    BootPath, CleanupReport, FirstCommandSample, KillMeasurements, PhaseFailure, PhaseSample,
    StopFailureCause, StopPhase,
};
use super::pool::{
    decide_checkout, CachePolicy, CheckoutDecision, ColdFallback, PoolRefusal, Profile,
    RenewalPlanProblem, ServiceRenewalPlan, VolumeAttachment, VolumeKind, VolumeRefusal, WarmPool,
};
use super::readiness::ObservedReadiness;
use super::replay::{IssuerId, Nonce, NonceScope, ReplayGuard, ReplayRefusal, Tombstone};
use super::revocation::{
    AckEffect, AckRefusal, AckSource, Acknowledgment, GrantRevocationCause, ProviderAcknowledgment,
    RevocationCause, RevocationPolicy, RevocationProgress, RevocationRun, TerminationGate,
    TerminationTiming, Uncertain,
};
use super::safety::{
    CleanupPlan, CleanupRefusal, CleanupTarget, LifecycleMessage, ManagedRoots,
    SupervisorDeathFallback,
};
use crate::foundation::coordination::{
    CapacityPort, Compensation, CompositeRecovery, CoordinationError, Coordinator, GenerationName,
    IncarnationNotPersisted, LaunchFailure, LaunchOutcome, LaunchPlan, LeaseKind, LeaseRefusal,
    PersistedState, Readiness, ReadinessReport, RecoveryContext, RecoveryFailure, RecoveryReport,
    RelaunchPlan, RelaunchReport, ReservationKey, ReservationPriority, ReservationPurpose,
    ReservationRequest, ReserveOutcome, ResourceKind, RevocationStatus, RevokedGrant,
    SandboxRecovery, SandboxState, SettingsGrant, TerminationStalled, TermsProblem,
    TransitionRefusal, VmInstanceId,
};
use crate::foundation::events::{EventContext, Generations, GrantRevocation, Phase, Revocation};
use crate::foundation::evidence::{
    AdmittedRuntime, ArtifactVerification, ClockSession, ProbeRegistry, SourceClass,
};
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Clock, Digest, ExecutionId, GrantId, IdError, Incarnation, LeaseId,
    MonotonicTime, OperationId, SandboxBootGeneration, TenantId,
};

/// What a supervisor is configured with. Every field is required: the fallback when the
/// supervisor dies is declared, never assumed (§6.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorConfig {
    pub profile: Profile,
    /// How old host-observed readiness may be when authority is granted.
    pub readiness_max_age: Duration,
    /// How old the runtime's category evidence may be when rechecked before authority.
    pub runtime_evidence_max_age: Duration,
    pub skew: SkewPolicy,
    pub revocation: RevocationPolicy,
    pub death_fallback: SupervisorDeathFallback,
    /// The declared bound within which child-work holders stop after a cancellation.
    pub cancel_within: Duration,
    /// This host as the issuer nonces and tombstones are scoped by.
    pub issuer: IssuerId,
    /// The image and ABI profile approved for restores.
    pub expected_image_profile: Digest,
}

/// Whether the engine is alive (§6.2: "engine failure denies new privileged
/// authorizations until reconciliation").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "engine", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum EngineState {
    Alive,
    Down { since: MonotonicTime },
}

crate::foundation::strict_serde::strict_tag!(EngineState, "engine");

/// A service sandbox locked down after a violation (VM-D10), with its one-step stop.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lockdown {
    pub since: MonotonicTime,
    pub token: StopToken,
}

/// The token that stops a locked-down service in one step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StopToken(Digest);

impl StopToken {
    pub const DOMAIN: &'static str = "yougori/lifecycle/stop-token/v1";

    /// A token made from a digest, for tests that present a forged one.
    #[cfg(test)]
    pub(crate) const fn from_digest_for_test(digest: Digest) -> Self {
        Self(digest)
    }
}

/// A service renewal in progress (§5.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingRenewal {
    pub plan: ServiceRenewalPlan,
    pub began_at: MonotonicTime,
    /// The volumes that ride into the renewed boot.
    pub retained: BTreeSet<Digest>,
}

/// One grant revoked alone under a sandbox's authority (§6.3 step 1, line 2308: a
/// tombstone, not an epoch advance; CORE-04 per-grant revocation). Only
/// [`Supervisor::revoke_grant`] makes one; it is persisted with the supervisor's state and
/// restored by [`Supervisor::recover`] (§6.3 line 2318: "persist replay protection across
/// restarts"). It is never a revocation of the sandbox: the authorization epoch, the
/// sandbox's other grants and leases and its VM stay as they were, and no acknowledgment of
/// a revocation of the sandbox is taken from it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRevocationRecord {
    /// CORE-04's record: the epoch left in force, the network grant withdrawn from the
    /// settings, the leases cancelled with their bounds and the activations that used it.
    pub revoked: RevokedGrant,
    pub cause: GrantRevocationCause,
}

impl GrantRevocationRecord {
    /// The CORE-06 grant revocation, for the hub's priority lane and the audit journal: it
    /// names the authorization epoch left in force.
    pub fn revocation(&self) -> GrantRevocation {
        GrantRevocation {
            execution: self.revoked.execution.clone(),
            grant: self.revoked.grant,
            epoch: self.revoked.epoch,
            reason: self.cause.reason(),
        }
    }
}

/// What the supervisor keeps about one sandbox beside the coordinator's lifecycle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxRecord {
    pub identity: SandboxIdentity,
    pub class: SandboxClass,
    pub lease: SandboxLease,
    pub demand: Vec<(ResourceKind, u64)>,
    pub priority: ReservationPriority,
    /// When the create of the current boot was initiated (the BENCH-05 clock start).
    pub created_at: MonotonicTime,
    pub first_command_at: Option<MonotonicTime>,
    pub boot_path: BootPath,
    pub provider_bills: bool,
    pub volumes: BTreeMap<Digest, VolumeKind>,
    pub lockdown: Option<Lockdown>,
    pub renewal: Option<PendingRenewal>,
    /// Recovery found the VM alive and kept it without authority; it serves again only
    /// after [`Supervisor::reauthorize`].
    pub awaiting_reauthorization: bool,
    /// What the host found when the supervisor last asked the backend to observe the VM
    /// again ([`Supervisor::observe_readiness`]). Records persisted before it read as only
    /// the launch's readiness.
    #[serde(default)]
    pub readiness: ObservedReadiness,
}

/// What to launch.
#[derive(Clone, Debug)]
pub struct LaunchRequest {
    pub execution: ExecutionId,
    pub tenant: TenantId,
    pub runtime: AdmittedRuntime,
    pub demand: BTreeMap<ResourceKind, u64>,
    pub priority: ReservationPriority,
    pub class: SandboxClass,
    pub limits: LeaseLimits,
    pub settings: SettingsGrant,
    pub volumes: BTreeMap<Digest, VolumeKind>,
    pub provider_bills: bool,
}

/// How a launch ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "launch", rename_all = "snake_case")]
pub enum LaunchReceipt {
    AuthorityActive {
        execution: ExecutionId,
        boot: SandboxBootGeneration,
        path: BootPath,
    },
    Queued {
        execution: ExecutionId,
        position: u32,
    },
    /// Every completed step was undone; no authority was ever exposed.
    RolledBack {
        execution: ExecutionId,
        failure: LaunchFailure,
        compensations: Vec<Compensation>,
    },
    RollbackStalled {
        execution: ExecutionId,
        failure: LaunchFailure,
        stall: TerminationStalled,
    },
}

impl LaunchReceipt {
    pub fn execution(&self) -> &ExecutionId {
        match self {
            Self::AuthorityActive { execution, .. }
            | Self::Queued { execution, .. }
            | Self::RolledBack { execution, .. }
            | Self::RollbackStalled { execution, .. } => execution,
        }
    }
}

/// How a warm-pool checkout went (§6.6; BENCH-06).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CheckoutReceipt {
    pub decision: CheckoutDecision,
    /// A restored clone that failed verification was cleaned up before the cold boot.
    pub failed_clone_cleaned_up: bool,
    pub launch: LaunchReceipt,
}

/// How a service renewal went.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "renewal", rename_all = "snake_case")]
pub enum RenewalReceipt {
    Begun {
        execution: ExecutionId,
        retained: BTreeSet<Digest>,
    },
    Completed {
        execution: ExecutionId,
        downtime: Duration,
        downtime_exceeded: bool,
        retained: BTreeSet<Digest>,
        launch: LaunchReceipt,
    },
}

/// What the engine's death did (VM-D7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EngineDeathReport {
    pub since: MonotonicTime,
    /// Task sandboxes, ended with the engine.
    pub ended: Vec<ExecutionId>,
    /// Service sandboxes, continuing under their supervisor leases.
    pub continued: Vec<ExecutionId>,
}

/// What a GUI closure did: nothing to any sandbox (§6.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GuiClosureReport {
    pub tasks_kept: usize,
    pub services_kept: usize,
}

/// The response to a clear violation (VM-D10).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum ViolationResponse {
    /// An ephemeral sandbox stopped.
    Stopped {
        execution: ExecutionId,
        progress: RevocationProgress,
    },
    /// A service sandbox locked down; `token` stops it in one step.
    LockedDown {
        execution: ExecutionId,
        token: StopToken,
    },
}

/// What applying one lifecycle message did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum MessageOutcome {
    ActivityRecorded,
    Acknowledged { effect: AckEffect },
    Revoked { progress: RevocationProgress },
    GrantRevoked { record: GrantRevocationRecord },
    Stopped { progress: RevocationProgress },
    CleanupPlanned { plan: CleanupPlan },
}

/// What one tick of lease enforcement did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct TickReport {
    pub expired: Vec<(ExecutionId, Expiry)>,
    pub clock_rolled_back: Vec<ExecutionId>,
}

/// A lifecycle receipt, with its CORE-06 event context where a stream carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LifecycleReceipt {
    Launched {
        execution: ExecutionId,
        boot: SandboxBootGeneration,
        context: EventContext,
    },
    LaunchFailed {
        execution: ExecutionId,
        failure: LaunchFailure,
        context: EventContext,
    },
    FirstCommand {
        execution: ExecutionId,
        boot: SandboxBootGeneration,
        elapsed: Duration,
    },
    /// Ready for the hub's priority lane with `context` (phase revoked).
    Revoked {
        revocation: Revocation,
        cause: RevocationCause,
        context: EventContext,
    },
    Acknowledged {
        execution: ExecutionId,
        acknowledgment: Acknowledgment,
        at: MonotonicTime,
        /// What established it.
        source: AckSource,
    },
    /// One grant revoked alone, ready for the hub's priority lane as a grant revocation
    /// with `context` (phase revoked, the epoch left in force); never a revocation of the
    /// sandbox.
    GrantRevoked {
        revocation: GrantRevocation,
        cause: GrantRevocationCause,
        /// The leases the revocation cancelled, each bound to the grant.
        cancelled: Vec<LeaseId>,
        context: EventContext,
    },
    Stopped {
        execution: ExecutionId,
        context: EventContext,
    },
    CleanupFinished {
        execution: ExecutionId,
        report: CleanupReport,
        late: bool,
        context: EventContext,
    },
    GuiClosed {
        report: GuiClosureReport,
    },
    EngineDied {
        report: EngineDeathReport,
    },
    LockedDown {
        execution: ExecutionId,
        since: MonotonicTime,
    },
}

/// What recovery found and did (§6.1 recovery; §6.4 handles).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SupervisorRecovery {
    pub coordination: RecoveryReport,
    /// Stored handles whose object was reused by something else: dropped, never stopped.
    pub handles_reused: Vec<VmInstanceId>,
    pub handles_gone: Vec<VmInstanceId>,
    /// Every sandbox lease ended; none is revived across a restart.
    pub leases_ended: Vec<ExecutionId>,
    /// Task sandboxes found alive, terminated (VM-D7).
    pub tasks_ended: Vec<ExecutionId>,
    /// Service sandboxes found alive, kept without authority until re-authorized.
    pub services_awaiting_reauthorization: Vec<ExecutionId>,
    /// Grants revoked alone whose CORE-04 tombstone the persisted coordination state did
    /// not carry, recorded again before anything is authorized (§6.3 line 2318).
    pub grant_tombstones_recorded_again: Vec<(ExecutionId, GrantId)>,
}

/// What the supervisor persists; recovery starts from it (§6.1; §6.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedSupervisor {
    pub coordination: PersistedState,
    pub sandboxes: Vec<SandboxRecord>,
    pub handles: HandleTable,
    pub replay: ReplayGuard,
    pub roots: ManagedRoots,
    pub measurements: KillMeasurements,
    pub engine: EngineState,
    pub burst: u32,
    /// The grants revoked alone, each with what its revocation cancelled and why (§6.3
    /// line 2318). State persisted before these were kept reads as none.
    #[serde(default)]
    pub grant_revocations: Vec<GrantRevocationRecord>,
}

/// Why a supervisor call was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SupervisorError {
    UnknownSandbox {
        execution: ExecutionId,
    },
    Coordination {
        error: CoordinationError,
    },
    Lease {
        refusal: LeaseRefusal,
    },
    Terms {
        problem: TermsProblem,
    },
    /// The sandbox lease is not live: expired, rolled back or not revived.
    SandboxLease {
        refusal: LeaseRestoreRefusal,
    },
    Activity {
        refusal: ActivityRefusal,
    },
    /// The sandbox is being revoked or is stopped; no new work.
    Revoked {
        execution: ExecutionId,
    },
    NotRevoking {
        execution: ExecutionId,
    },
    LockedDown {
        execution: ExecutionId,
    },
    NotLockedDown {
        execution: ExecutionId,
    },
    WrongStopToken {
        execution: ExecutionId,
    },
    EngineDown {
        since: MonotonicTime,
    },
    WrongClass {
        execution: ExecutionId,
        expected: SandboxClass,
        found: SandboxClass,
    },
    NotStopped {
        execution: ExecutionId,
        state: SandboxState,
    },
    NoAuthority {
        execution: ExecutionId,
        state: SandboxState,
    },
    NotAwaitingReauthorization {
        execution: ExecutionId,
    },
    Cleanup {
        refusal: CleanupRefusal,
    },
    Acknowledgment {
        refusal: AckRefusal,
    },
    RenewalPlan {
        problem: RenewalPlanProblem,
    },
    NoPendingRenewal {
        execution: ExecutionId,
    },
    Volume {
        volume: Digest,
        refusal: VolumeRefusal,
    },
    Binding {
        refusal: BindingRefusal,
    },
    Replay {
        refusal: ReplayRefusal,
    },
    Pool {
        refusal: PoolRefusal,
    },
    Identifier {
        error: String,
    },
    Stalled {
        stall: TerminationStalled,
    },
    /// The VM's handle was reused; nothing was stopped (§6.4).
    HandleReused {
        vm: VmInstanceId,
    },
    /// The host did not find the sandbox's VM ready when the backend observed it again;
    /// no new work is authorized until a later observation does.
    ReadinessUnavailable {
        execution: ExecutionId,
        since: MonotonicTime,
        detail: String,
    },
}

impl fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSandbox { execution } => write!(f, "sandbox {execution} is unknown"),
            Self::Coordination { error } => write!(f, "{error}"),
            Self::Lease { refusal } => write!(f, "{refusal}"),
            Self::Terms { problem } => write!(f, "invalid lease terms: {problem:?}"),
            Self::SandboxLease { refusal } => write!(f, "{refusal}"),
            Self::Activity { refusal } => write!(f, "{refusal}"),
            Self::Revoked { execution } => {
                write!(
                    f,
                    "sandbox {execution} is revoked; no new work is authorized"
                )
            }
            Self::NotRevoking { execution } => {
                write!(f, "sandbox {execution} is not being revoked")
            }
            Self::LockedDown { execution } => write!(f, "sandbox {execution} is locked down"),
            Self::NotLockedDown { execution } => {
                write!(f, "sandbox {execution} is not locked down")
            }
            Self::WrongStopToken { execution } => {
                write!(f, "the stop token is not the one of sandbox {execution}")
            }
            Self::EngineDown { since } => write!(
                f,
                "the engine has been down since {} ns; new authorizations are denied until \
                 reconciliation",
                since.as_nanos()
            ),
            Self::WrongClass {
                execution,
                expected,
                found,
            } => write!(f, "sandbox {execution} is a {found}, not a {expected}"),
            Self::NotStopped { execution, state } => {
                write!(f, "sandbox {execution} is {state}, not stopped")
            }
            Self::NoAuthority { execution, state } => {
                write!(f, "sandbox {execution} holds no authority while {state}")
            }
            Self::NotAwaitingReauthorization { execution } => {
                write!(f, "sandbox {execution} is not awaiting re-authorization")
            }
            Self::Cleanup { refusal } => write!(f, "{refusal}"),
            Self::Acknowledgment { refusal } => write!(f, "{refusal}"),
            Self::RenewalPlan { problem } => write!(f, "{problem}"),
            Self::NoPendingRenewal { execution } => {
                write!(f, "sandbox {execution} has no renewal in progress")
            }
            Self::Volume { volume, refusal } => {
                write!(f, "volume {volume} is not attached: {refusal:?}")
            }
            Self::Binding { refusal } => write!(f, "{refusal}"),
            Self::Replay { refusal } => write!(f, "{refusal}"),
            Self::Pool { refusal } => write!(f, "{refusal}"),
            Self::Identifier { error } => write!(f, "{error}"),
            Self::Stalled { stall } => write!(
                f,
                "termination stopped after {} step(s)",
                stall.completed.len()
            ),
            Self::HandleReused { vm } => write!(
                f,
                "the object behind the handle of VM {vm} was reused; it was not stopped"
            ),
            Self::ReadinessUnavailable {
                execution,
                since,
                detail,
            } => write!(
                f,
                "sandbox {execution} has not been observed ready since {} ns, so no new work \
                 is authorized: {detail}",
                since.as_nanos()
            ),
        }
    }
}

impl std::error::Error for SupervisorError {}

impl From<CoordinationError> for SupervisorError {
    fn from(error: CoordinationError) -> Self {
        Self::Coordination { error }
    }
}

impl From<AckRefusal> for SupervisorError {
    fn from(refusal: AckRefusal) -> Self {
        Self::Acknowledgment { refusal }
    }
}

/// The digest domain of lifecycle operation identities.
const OPERATION_DOMAIN: &str = "yougori/lifecycle/operation/v1";

/// The operation identity lifecycle events of `execution` are correlated under.
fn lifecycle_operation(execution: &ExecutionId) -> Result<OperationId, SupervisorError> {
    let hex = digest(OPERATION_DOMAIN, &[execution.as_str().as_bytes()]).to_hex();
    let short: String = hex.chars().take(32).collect();
    OperationId::new(format!("lc-{short}")).map_err(|error: IdError| SupervisorError::Identifier {
        error: error.to_string(),
    })
}

/// Nanoseconds from `from` to `to`, saturating.
fn elapsed_nanos(from: MonotonicTime, to: MonotonicTime) -> u64 {
    u64::try_from(to.saturating_duration_since(from).as_nanos()).unwrap_or(u64::MAX)
}

/// The supervisor of VM lifetimes (§3.1: "launch, leases, revoke, terminate").
pub struct Supervisor<C: Clock + Clone, P: CapacityPort> {
    clock: C,
    config: SupervisorConfig,
    coordinator: Coordinator<C, P>,
    sandboxes: BTreeMap<ExecutionId, SandboxRecord>,
    handles: HandleTable,
    runs: BTreeMap<ExecutionId, RevocationRun>,
    grant_revocations: BTreeMap<(ExecutionId, GrantId), GrantRevocationRecord>,
    roots: ManagedRoots,
    replay: ReplayGuard,
    measurements: KillMeasurements,
    receipts: Vec<LifecycleReceipt>,
    engine: EngineState,
    identities: BTreeSet<VmInstanceId>,
    burst: u32,
}

impl<C: Clock + Clone, P: CapacityPort> Supervisor<C, P> {
    /// A supervisor on `clock` and `session` over the capacity port.
    pub fn new(clock: C, session: ClockSession, capacity: P, config: SupervisorConfig) -> Self {
        let coordinator = Coordinator::new(clock.clone(), session, capacity);
        Self {
            clock,
            config,
            coordinator,
            sandboxes: BTreeMap::new(),
            handles: HandleTable::default(),
            runs: BTreeMap::new(),
            grant_revocations: BTreeMap::new(),
            roots: ManagedRoots::new(),
            replay: ReplayGuard::new(),
            measurements: KillMeasurements::new(),
            receipts: Vec::new(),
            engine: EngineState::Alive,
            identities: BTreeSet::new(),
            burst: 0,
        }
    }

    pub fn config(&self) -> &SupervisorConfig {
        &self.config
    }

    pub fn now(&self) -> MonotonicTime {
        self.clock.now()
    }

    pub fn coordinator(&self) -> &Coordinator<C, P> {
        &self.coordinator
    }

    /// The coordinator, for the capacity port's host observations and budgets.
    pub fn coordinator_mut(&mut self) -> &mut Coordinator<C, P> {
        &mut self.coordinator
    }

    pub fn sandbox(&self, execution: &ExecutionId) -> Option<&SandboxRecord> {
        self.sandboxes.get(execution)
    }

    pub fn sandboxes(&self) -> impl Iterator<Item = &SandboxRecord> {
        self.sandboxes.values()
    }

    pub fn revocation(&self, execution: &ExecutionId) -> Option<&RevocationRun> {
        self.runs.get(execution)
    }

    /// The revocation of `grant` alone under `execution`'s authority this supervisor
    /// recorded, this run or before a recovery, if any.
    pub fn grant_revocation(
        &self,
        execution: &ExecutionId,
        grant: GrantId,
    ) -> Option<&GrantRevocationRecord> {
        self.grant_revocations.get(&(execution.clone(), grant))
    }

    /// Every grant revoked alone, this run or before a recovery, by sandbox and grant.
    pub fn grant_revocations(&self) -> impl Iterator<Item = &GrantRevocationRecord> {
        self.grant_revocations.values()
    }

    pub fn handles(&self) -> &HandleTable {
        &self.handles
    }

    pub fn roots(&self) -> &ManagedRoots {
        &self.roots
    }

    pub fn roots_mut(&mut self) -> &mut ManagedRoots {
        &mut self.roots
    }

    pub fn replay(&self) -> &ReplayGuard {
        &self.replay
    }

    pub fn replay_mut(&mut self) -> &mut ReplayGuard {
        &mut self.replay
    }

    pub fn measurements(&self) -> &KillMeasurements {
        &self.measurements
    }

    pub fn engine(&self) -> EngineState {
        self.engine
    }

    /// This run of the authority, once a persisted state carrying it was confirmed.
    pub fn incarnation(&self) -> Result<Incarnation, IncarnationNotPersisted> {
        self.coordinator.current_incarnation()
    }

    /// The receipts since the last take, in order.
    pub fn take_receipts(&mut self) -> Vec<LifecycleReceipt> {
        std::mem::take(&mut self.receipts)
    }

    /// Starts a new measurement burst (S11: "several independent bursts").
    pub fn begin_burst(&mut self) {
        self.burst = self.burst.saturating_add(1);
    }

    fn state_of(&self, execution: &ExecutionId) -> Option<SandboxState> {
        self.coordinator
            .sandbox(execution)
            .map(|sandbox| sandbox.state())
    }

    fn record(&self, execution: &ExecutionId) -> Result<&SandboxRecord, SupervisorError> {
        self.sandboxes
            .get(execution)
            .ok_or_else(|| SupervisorError::UnknownSandbox {
                execution: execution.clone(),
            })
    }

    fn record_mut(
        &mut self,
        execution: &ExecutionId,
    ) -> Result<&mut SandboxRecord, SupervisorError> {
        self.sandboxes
            .get_mut(execution)
            .ok_or_else(|| SupervisorError::UnknownSandbox {
                execution: execution.clone(),
            })
    }

    /// The CORE-06 context lifecycle events of `execution` travel with.
    fn context(
        &self,
        execution: &ExecutionId,
        phase: Phase,
    ) -> Result<EventContext, SupervisorError> {
        let operation = lifecycle_operation(execution)?;
        let generations = match self.coordinator.sandbox(execution) {
            Some(sandbox) => {
                let generations = sandbox.generations();
                Generations::NONE
                    .with_sandbox_boot(generations.boot)
                    .with_policy(generations.policy)
                    .with_authorization(generations.authorization)
            }
            None => Generations::NONE,
        };
        Ok(EventContext::new(operation, phase).with_generations(generations))
    }

    /// The tuple `execution` presents now, with `credential_lease` for credentialed use.
    pub fn current_tuple(
        &self,
        execution: &ExecutionId,
        credential_lease: Option<crate::foundation::ids::LeaseId>,
    ) -> Result<BindingTuple, SupervisorError> {
        let sandbox =
            self.coordinator
                .sandbox(execution)
                .ok_or_else(|| SupervisorError::UnknownSandbox {
                    execution: execution.clone(),
                })?;
        Ok(BindingTuple::current(
            sandbox,
            self.coordinator.session(),
            credential_lease,
        ))
    }

    /// Whether `binding` is honoured now: its sandbox holds authority and every bound
    /// part is current (§6.1).
    pub fn check_binding(&self, binding: &Binding) -> Result<(), SupervisorError> {
        let execution = &binding.tuple().sandbox.execution;
        let state = self
            .state_of(execution)
            .ok_or_else(|| SupervisorError::UnknownSandbox {
                execution: execution.clone(),
            })?;
        if !state.holds_authority() {
            return Err(SupervisorError::NoAuthority {
                execution: execution.clone(),
                state,
            });
        }
        let current = self.current_tuple(execution, binding.tuple().credential_lease)?;
        binding
            .check(&current)
            .map_err(|refusal| SupervisorError::Binding { refusal })
    }

    /// Accepts `nonce` under this host's issuer identity and the sandbox's current
    /// generations (§6.3; VM-W29).
    pub fn accept_nonce(
        &mut self,
        execution: &ExecutionId,
        nonce: Nonce,
    ) -> Result<(), SupervisorError> {
        let sandbox =
            self.coordinator
                .sandbox(execution)
                .ok_or_else(|| SupervisorError::UnknownSandbox {
                    execution: execution.clone(),
                })?;
        let generations = sandbox.generations();
        let scope = NonceScope {
            issuer: self.config.issuer,
            sandbox: execution.clone(),
            boot: generations.boot,
            authorization: generations.authorization,
        };
        self.replay
            .accept(scope, nonce)
            .map_err(|refusal| SupervisorError::Replay { refusal })
    }

    fn check_volumes(&self, volumes: &BTreeMap<Digest, VolumeKind>) -> Result<(), SupervisorError> {
        for (volume, kind) in volumes {
            if *kind == VolumeKind::CredentialState && self.config.profile == Profile::Strict {
                return Err(SupervisorError::Volume {
                    volume: *volume,
                    refusal: VolumeRefusal::CredentialCopyInStrictProfile,
                });
            }
        }
        Ok(())
    }

    /// Launches a sandbox cold (§6.1): the launch transaction runs through the
    /// coordinator with the backend behind the bridge, and authority is granted only after
    /// host-observed readiness. A stopped sandbox boots again with fresh generations; an
    /// active one is unchanged. A failed start exposes no authority.
    pub fn launch<B: VmBackend + ?Sized, R: Clock>(
        &mut self,
        request: LaunchRequest,
        backend: &mut B,
        registry: &ProbeRegistry<R>,
    ) -> Result<LaunchReceipt, SupervisorError> {
        let (receipt, _) = self.boot(request, None, backend, registry)?;
        Ok(receipt)
    }

    /// Checks `request` out of `pool` (§6.6 lines 2336–2353; VM-W27 line 2633): a stopped
    /// sandbox restores the golden snapshot when the backend can restore and reset state
    /// and the pool holds a clone, and cold-boots otherwise, each fallback named. A new
    /// execution always boots cold. A restored clone that fails verification is cleaned up
    /// before the cold boot. Only a restore that reaches authority counts as a warm
    /// restore.
    ///
    /// A stopped sandbox the backend can restore consults the pool only once capacity is
    /// granted: the relaunch's reservation is made first, under the key the coordinator's
    /// relaunch uses. While the ledger queues it, the sandbox stays stopped and nothing is
    /// taken, restored, booted or counted as a restore or a fallback, so a later checkout
    /// keeps the warm decision; the decision a queued receipt carries is the one as of its
    /// checkout. Once the queue grants the reservation, that checkout takes a clone then and
    /// restores through the same relaunch and authority checks as a cold boot, or boots
    /// cold with the pool's depletion named when no clone is left by then. A refused
    /// reservation ends the launch with nothing taken. A launch the coordinator still
    /// queues or refuses for capacity restored nothing (capacity comes before any backend
    /// call), so its clone goes back to the pool; any other rollback after a restore was
    /// asked for is counted as a restore rollback and its clone is not reused.
    pub fn checkout<B: VmBackend + ?Sized, R: Clock>(
        &mut self,
        request: LaunchRequest,
        pool: &mut WarmPool,
        backend: &mut B,
        registry: &ProbeRegistry<R>,
    ) -> Result<CheckoutReceipt, SupervisorError> {
        self.check_request(&request)?;
        let stopped = self.state_of(&request.execution) == Some(SandboxState::Stopped);
        let has_clone = pool.golden().is_some() && pool.available() > 0;
        let decision = decide_checkout(&backend.capabilities(), has_clone, stopped);
        // The backend can restore this stopped sandbox; only the pool is in question.
        let restorable = matches!(
            decision,
            CheckoutDecision::Restore
                | CheckoutDecision::ColdBoot {
                    fallback: ColdFallback::PoolDepleted
                }
        );
        if restorable {
            if let Some(launch) = self.reserve_relaunch(&request)? {
                return Ok(CheckoutReceipt {
                    decision,
                    failed_clone_cleaned_up: false,
                    launch,
                });
            }
        }
        let recovery = match &decision {
            CheckoutDecision::Restore => match pool.take() {
                Ok(golden) => Some(CompositeRecovery {
                    vm_snapshot: Some(golden.manifest().clone()),
                    ..CompositeRecovery::default()
                }),
                Err(refusal) => return Err(SupervisorError::Pool { refusal }),
            },
            CheckoutDecision::ColdBoot { .. } => None,
        };
        let (mut launch, relaunch) = self.boot(request, recovery, backend, registry)?;
        let failed_clone = relaunch
            .as_ref()
            .is_some_and(|report| report.refused_restore.is_some());
        let reached = matches!(launch, LaunchReceipt::AuthorityActive { .. });
        let unused_clone = matches!(
            launch,
            LaunchReceipt::Queued { .. }
                | LaunchReceipt::RolledBack {
                    failure: LaunchFailure::Capacity { .. },
                    ..
                }
        );
        let restored = matches!(decision, CheckoutDecision::Restore) && !failed_clone && reached;
        if matches!(decision, CheckoutDecision::Restore) && unused_clone {
            pool.replenish(1);
        }
        let counts = self.measurements.pool_mut();
        match (&decision, failed_clone) {
            (CheckoutDecision::Restore, true) => {
                counts.failed_clone_cleanups = counts.failed_clone_cleanups.saturating_add(1);
                counts.cold_fallbacks = counts.cold_fallbacks.saturating_add(1);
            }
            (CheckoutDecision::Restore, false) if reached => {
                counts.warm_restores = counts.warm_restores.saturating_add(1);
            }
            (CheckoutDecision::Restore, false) if unused_clone => {}
            (CheckoutDecision::Restore, false) => {
                counts.restore_rollbacks = counts.restore_rollbacks.saturating_add(1);
            }
            (CheckoutDecision::ColdBoot { .. }, _) => {
                counts.cold_fallbacks = counts.cold_fallbacks.saturating_add(1);
            }
        }
        let decision = if failed_clone {
            CheckoutDecision::ColdBoot {
                fallback: ColdFallback::CloneVerificationFailed,
            }
        } else {
            decision
        };
        if restored {
            if let Some(record) = self.sandboxes.get_mut(launch.execution()) {
                record.boot_path = BootPath::WarmRestore;
            }
            if let LaunchReceipt::AuthorityActive { path, .. } = &mut launch {
                *path = BootPath::WarmRestore;
            }
        }
        Ok(CheckoutReceipt {
            decision,
            failed_clone_cleaned_up: failed_clone,
            launch,
        })
    }

    /// The first step of a restorable checkout's relaunch, taken before the pool is
    /// consulted (§6.1 line 2292; S10 line 351: reserve before creating, with bounded
    /// queueing): reserves through the coordinator's capacity port what the coordinator's
    /// relaunch of the stopped sandbox reserves for its next boot, the same key, tenant,
    /// priority and demand, so the relaunch finds that reservation as its own (the port
    /// answers the same request under the same key the same way). `None` once it is
    /// granted. While the ledger queues it, or when it is refused, the launch ends here:
    /// the sandbox stays stopped at its boot, nothing is taken from the pool and the
    /// backend is not called; the receipt is queued, or rolled back with nothing to undo.
    /// Either is counted as one launch put to the authority checks, as a queued or refused
    /// cold launch is.
    fn reserve_relaunch(
        &mut self,
        request: &LaunchRequest,
    ) -> Result<Option<LaunchReceipt>, SupervisorError> {
        let execution = request.execution.clone();
        let sandbox = self.coordinator.sandbox(&execution).ok_or_else(|| {
            SupervisorError::UnknownSandbox {
                execution: execution.clone(),
            }
        })?;
        let boot = sandbox
            .generations()
            .boot
            .next()
            .ok_or(SupervisorError::Coordination {
                error: CoordinationError::Transition {
                    refusal: TransitionRefusal::GenerationExhausted {
                        generation: GenerationName::Boot,
                    },
                },
            })?;
        let purpose = ReservationPurpose::Sandbox { boot };
        let reservation = ReservationRequest {
            key: ReservationKey::derive(&execution, &purpose),
            tenant: sandbox.tenant().clone(),
            execution: execution.clone(),
            purpose,
            priority: sandbox.priority(),
            parent: None,
            demand: request.demand.clone(),
        };
        let launch = match self.coordinator.capacity_mut().reserve(&reservation) {
            Ok(ReserveOutcome::Granted) => return Ok(None),
            Ok(ReserveOutcome::Queued { position }) => LaunchReceipt::Queued {
                execution,
                position,
            },
            Err(refusal) => {
                let failure = LaunchFailure::Capacity { refusal };
                let context = self.context(&execution, Phase::Failed)?;
                self.receipts.push(LifecycleReceipt::LaunchFailed {
                    execution: execution.clone(),
                    failure: failure.clone(),
                    context,
                });
                LaunchReceipt::RolledBack {
                    execution,
                    failure,
                    compensations: Vec::new(),
                }
            }
        };
        let counts = self.measurements.pool_mut();
        counts.authority_checks = counts.authority_checks.saturating_add(1);
        Ok(Some(launch))
    }

    /// Refuses `request` before anything is reserved when its class differs from its
    /// limits' or from the sandbox's record, or a volume is not allowed in the profile.
    fn check_request(&self, request: &LaunchRequest) -> Result<(), SupervisorError> {
        if request.limits.class != request.class {
            return Err(SupervisorError::WrongClass {
                execution: request.execution.clone(),
                expected: request.class,
                found: request.limits.class,
            });
        }
        self.check_volumes(&request.volumes)?;
        if let Some(record) = self.sandboxes.get(&request.execution) {
            if record.class != request.class {
                return Err(SupervisorError::WrongClass {
                    execution: request.execution.clone(),
                    expected: record.class,
                    found: request.class,
                });
            }
        }
        Ok(())
    }

    /// Boots `request`: a first boot or a relaunch of a stopped sandbox, restoring
    /// `recovery` when given. Every path runs the same authority checks.
    fn boot<B: VmBackend + ?Sized, R: Clock>(
        &mut self,
        request: LaunchRequest,
        recovery: Option<CompositeRecovery>,
        backend: &mut B,
        registry: &ProbeRegistry<R>,
    ) -> Result<(LaunchReceipt, Option<RelaunchReport>), SupervisorError> {
        self.check_request(&request)?;
        let execution = request.execution.clone();
        let now = self.clock.now();
        let stopped = self.state_of(&execution) == Some(SandboxState::Stopped);
        let replace_record = match self.sandboxes.get(&execution) {
            None => true,
            Some(existing) => stopped || existing.awaiting_reauthorization,
        };
        let (outcome, relaunch) = if stopped {
            let retained: BTreeSet<Digest> = request
                .volumes
                .iter()
                .filter(|(_, kind)| {
                    matches!(
                        kind.at_renewal(CachePolicy::RebuildFromManifest, self.config.profile),
                        VolumeAttachment::Attached { .. }
                    )
                })
                .map(|(volume, _)| *volume)
                .collect();
            let plan = RelaunchPlan {
                runtime: request.runtime.clone(),
                demand: request.demand.clone(),
                authority_lifetime: request.limits.authority_lifetime(),
                readiness_max_age: self.config.readiness_max_age,
                runtime_evidence_max_age: self.config.runtime_evidence_max_age,
                recovery: recovery.unwrap_or_default(),
                authorized_volumes: retained,
            };
            let verification = ArtifactVerification::Verified {
                artifacts: request.settings.verified_artifacts.clone(),
            };
            let context = RecoveryContext {
                expected_image_profile: self.config.expected_image_profile,
                checkpoint_evidence: None,
                artifact_verification: &verification,
            };
            let mut bridge = Bridge::new(backend, &mut self.handles);
            let report =
                self.coordinator
                    .relaunch(&execution, plan, &context, &mut bridge, registry)?;
            (report.outcome.clone(), Some(report))
        } else {
            let plan = LaunchPlan {
                execution: execution.clone(),
                tenant: request.tenant.clone(),
                runtime: request.runtime.clone(),
                demand: request.demand.clone(),
                priority: request.priority,
                authority_lifetime: request.limits.authority_lifetime(),
                readiness_max_age: self.config.readiness_max_age,
                runtime_evidence_max_age: self.config.runtime_evidence_max_age,
            };
            let mut bridge = Bridge::new(backend, &mut self.handles);
            let outcome = self.coordinator.launch_with(
                plan,
                request.settings.clone(),
                &mut bridge,
                registry,
            )?;
            (outcome, None)
        };
        let counts = self.measurements.pool_mut();
        counts.authority_checks = counts.authority_checks.saturating_add(1);
        let receipt = match outcome {
            LaunchOutcome::AuthorityActive { generations, .. } => {
                if let Some(vm) = self.coordinator.sandbox(&execution).and_then(|s| s.vm()) {
                    self.identities.insert(vm);
                    self.measurements.pool_mut().unique_identities = self.identities.len() as u64;
                }
                let session = self.coordinator.session();
                let record = SandboxRecord {
                    identity: SandboxIdentity {
                        execution: execution.clone(),
                        tenant: request.tenant.clone(),
                    },
                    class: request.class,
                    lease: SandboxLease::new(request.limits, session, now),
                    demand: request.demand.iter().map(|(k, v)| (*k, *v)).collect(),
                    priority: request.priority,
                    created_at: now,
                    first_command_at: None,
                    boot_path: BootPath::Cold,
                    provider_bills: request.provider_bills,
                    volumes: request.volumes.clone(),
                    lockdown: None,
                    renewal: None,
                    awaiting_reauthorization: false,
                    readiness: ObservedReadiness::AtLaunch,
                };
                if replace_record {
                    self.sandboxes.insert(execution.clone(), record);
                }
                self.runs.remove(&execution);
                let context = self.context(&execution, Phase::Running)?;
                self.receipts.push(LifecycleReceipt::Launched {
                    execution: execution.clone(),
                    boot: generations.boot,
                    context,
                });
                LaunchReceipt::AuthorityActive {
                    execution,
                    boot: generations.boot,
                    path: BootPath::Cold,
                }
            }
            LaunchOutcome::Queued { position } => LaunchReceipt::Queued {
                execution,
                position,
            },
            LaunchOutcome::RolledBack {
                failure,
                compensations,
            } => {
                let context = self.context(&execution, Phase::Failed)?;
                self.receipts.push(LifecycleReceipt::LaunchFailed {
                    execution: execution.clone(),
                    failure: failure.clone(),
                    context,
                });
                LaunchReceipt::RolledBack {
                    execution,
                    failure,
                    compensations,
                }
            }
            LaunchOutcome::RollbackStalled { failure, stall } => {
                let context = self.context(&execution, Phase::Failed)?;
                self.receipts.push(LifecycleReceipt::LaunchFailed {
                    execution: execution.clone(),
                    failure: failure.clone(),
                    context,
                });
                LaunchReceipt::RollbackStalled {
                    execution,
                    failure,
                    stall,
                }
            }
        };
        Ok((receipt, relaunch))
    }

    /// The first successful command in the guest: the sandbox runs, the BENCH-05 clock
    /// stops, and the idle limit restarts. Repeating it returns the same elapsed time.
    pub fn first_command(&mut self, execution: &ExecutionId) -> Result<Duration, SupervisorError> {
        let now = self.clock.now();
        let state = self
            .state_of(execution)
            .ok_or_else(|| SupervisorError::UnknownSandbox {
                execution: execution.clone(),
            })?;
        if !state.holds_authority() {
            return Err(SupervisorError::NoAuthority {
                execution: execution.clone(),
                state,
            });
        }
        if state == SandboxState::AuthorityActive {
            self.coordinator.start_running(execution)?;
        }
        let boot = self
            .coordinator
            .sandbox(execution)
            .map(|sandbox| sandbox.generations().boot)
            .unwrap_or(SandboxBootGeneration::FIRST);
        let burst = self.burst;
        let record = self.record_mut(execution)?;
        if let Some(first) = record.first_command_at {
            return Ok(first.saturating_duration_since(record.created_at));
        }
        record.first_command_at = Some(now);
        let elapsed = now.saturating_duration_since(record.created_at);
        let path = record.boot_path;
        record
            .lease
            .activity(ActivityKind::Command, now)
            .map_err(|refusal| SupervisorError::Activity { refusal })?;
        self.measurements.record_first_command(FirstCommandSample {
            execution: execution.clone(),
            boot,
            path,
            nanos: elapsed.as_nanos().min(u128::from(u64::MAX)) as u64,
            burst,
        });
        self.receipts.push(LifecycleReceipt::FirstCommand {
            execution: execution.clone(),
            boot,
            elapsed,
        });
        Ok(elapsed)
    }

    /// Asks the backend to observe the sandbox's VM again now, through its handle for the
    /// current boot (VM part §6.1; §8.1 line 2439: launch-time evidence does not stay
    /// current indefinitely). Readiness the host observed renews the sandbox's readiness;
    /// anything else makes it unavailable, and no new work is authorized under the
    /// sandbox until a later observation finds the VM ready. Only a sandbox that holds
    /// authority is observed.
    pub fn observe_readiness<B: VmBackend + ?Sized>(
        &mut self,
        execution: &ExecutionId,
        backend: &mut B,
    ) -> Result<ObservedReadiness, SupervisorError> {
        let sandbox =
            self.coordinator
                .sandbox(execution)
                .ok_or_else(|| SupervisorError::UnknownSandbox {
                    execution: execution.clone(),
                })?;
        let state = sandbox.state();
        if !state.holds_authority() {
            return Err(SupervisorError::NoAuthority {
                execution: execution.clone(),
                state,
            });
        }
        let boot = sandbox.generations().boot;
        let handle = sandbox
            .vm()
            .and_then(|vm| self.handles.get(&vm))
            .filter(|handle| handle.boot == boot)
            .cloned();
        let report = match handle {
            Some(handle) => backend.observe_readiness(&handle),
            None => ReadinessReport {
                source: SourceClass::HostProbe,
                readiness: Readiness::NotReady {
                    detail: format!("no handle for the VM of boot generation {boot}"),
                },
            },
        };
        let now = self.clock.now();
        let record = self.record_mut(execution)?;
        record.readiness = ObservedReadiness::after(&record.readiness, &report, now);
        Ok(record.readiness.clone())
    }

    /// When the host last found the sandbox's VM ready: the launch transaction's readiness
    /// until the supervisor observes again, then the last observation that found it
    /// ready; none while readiness is unavailable.
    fn ready_at(&self, execution: &ExecutionId) -> Option<MonotonicTime> {
        match &self.sandboxes.get(execution)?.readiness {
            ObservedReadiness::AtLaunch => self
                .coordinator
                .sandbox(execution)?
                .readiness()
                .map(|readiness| readiness.observed_at),
            ObservedReadiness::Ready { at } => Some(*at),
            ObservedReadiness::Unavailable { .. } => None,
        }
    }

    /// [`Supervisor::authorize_granted_work`] on fresh readiness: when the host last found
    /// the sandbox's VM ready longer ago than the configured `readiness_max_age`, or never
    /// since it became unavailable, the supervisor first asks the backend to observe it
    /// again ([`Supervisor::observe_readiness`]), so launch-time readiness does not stay
    /// current indefinitely and work is authorized only on fresh host evidence. A sandbox
    /// under revocation goes straight to the refusal of
    /// [`Supervisor::authorize_granted_work`].
    pub fn authorize_observed_work<B: VmBackend + ?Sized>(
        &mut self,
        execution: &ExecutionId,
        operation: OperationId,
        kind: LeaseKind,
        call: CallTerms,
        grants: BTreeSet<GrantId>,
        backend: &mut B,
    ) -> Result<crate::foundation::coordination::Lease, SupervisorError> {
        self.authorize_observed_work_until(execution, operation, kind, call, grants, None, backend)
    }

    /// Fresh host readiness and all ordinary authorization checks, with an optional
    /// absolute deadline that also caps renewal lifetime. The coordinator applies
    /// it at actual issuance, after any readiness probe has completed.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_observed_work_until<B: VmBackend + ?Sized>(
        &mut self,
        execution: &ExecutionId,
        operation: OperationId,
        kind: LeaseKind,
        call: CallTerms,
        grants: BTreeSet<GrantId>,
        deadline: Option<MonotonicTime>,
        backend: &mut B,
    ) -> Result<crate::foundation::coordination::Lease, SupervisorError> {
        self.refresh_work_readiness(execution, backend)?;
        self.authorize_granted_work_until(execution, operation, kind, call, grants, deadline)
    }

    fn refresh_work_readiness<B: VmBackend + ?Sized>(
        &mut self,
        execution: &ExecutionId,
        backend: &mut B,
    ) -> Result<(), SupervisorError> {
        let now = self.clock.now();
        let stale = self
            .ready_at(execution)
            .is_none_or(|at| now.saturating_duration_since(at) > self.config.readiness_max_age);
        let holds_authority = self
            .state_of(execution)
            .is_some_and(SandboxState::holds_authority);
        if stale && holds_authority && !self.runs.contains_key(execution) {
            self.observe_readiness(execution, backend)?;
        }
        Ok(())
    }

    /// Recheck an existing child on the same fresh host evidence and parent
    /// policy as a new operation. This issues no throwaway lease or new ledger.
    pub fn check_observed_work<B: VmBackend + ?Sized>(
        &mut self,
        lease: crate::foundation::ids::LeaseId,
        backend: &mut B,
    ) -> Result<crate::foundation::coordination::Lease, SupervisorError> {
        let checked = self
            .coordinator
            .check_lease(lease)
            .map_err(|refusal| SupervisorError::Lease { refusal })?;
        let execution = checked.parent();
        self.refresh_work_readiness(execution, backend)?;
        if self.runs.contains_key(execution) {
            return Err(SupervisorError::Revoked {
                execution: execution.clone(),
            });
        }
        self.check_work_parent(execution)?;
        // A backend probe can block; check the child again after the observation.
        self.coordinator
            .check_lease(lease)
            .map_err(|refusal| SupervisorError::Lease { refusal })
    }

    /// Renew only after fresh readiness, engine, lockdown and parent checks.
    pub fn renew_observed_work<B: VmBackend + ?Sized>(
        &mut self,
        lease: crate::foundation::ids::LeaseId,
        presented: crate::foundation::evidence::ClockSession,
        backend: &mut B,
    ) -> Result<crate::foundation::coordination::Lease, SupervisorError> {
        self.check_observed_work(lease, backend)?;
        self.coordinator
            .renew_presented_lease(lease, presented)
            .map_err(|refusal| SupervisorError::Lease { refusal })
    }

    /// Records activity; only typed activity resets the idle limit (§6.2).
    pub fn activity(
        &mut self,
        execution: &ExecutionId,
        kind: ActivityKind,
    ) -> Result<(), SupervisorError> {
        let now = self.clock.now();
        self.record_mut(execution)?
            .lease
            .activity(kind, now)
            .map_err(|refusal| SupervisorError::Activity { refusal })
    }

    /// Authorizes child work under the sandbox: refused while the engine is down, the
    /// sandbox is locked down or revoked, or its lease is not live; otherwise a CORE-04
    /// lease with the per-call and task limits as its terms.
    pub fn authorize_work(
        &mut self,
        execution: &ExecutionId,
        operation: OperationId,
        kind: LeaseKind,
        call: CallTerms,
    ) -> Result<crate::foundation::coordination::Lease, SupervisorError> {
        self.authorize_granted_work(execution, operation, kind, call, BTreeSet::new())
    }

    /// Authorizes child work issued under `grants` of the sandbox's authority, such as a
    /// route or a scoped delegation (VM part §4.6, line 2187; CORE-04
    /// `start_granted_work`): revoking any one of them alone
    /// ([`Supervisor::revoke_grant`]) cancels the lease and leaves the sandbox's other
    /// work. Refused as [`Supervisor::authorize_work`] refuses, for a grant revoked under
    /// the sandbox, and while the sandbox's readiness is unavailable
    /// ([`Supervisor::observe_readiness`]). Under a revocation of the sandbox the request
    /// is still put to the coordinator, whose own check refuses it and records it as that
    /// revocation's first denied authorization if it is the first (§6.3 step 2, line
    /// 2309; VM-P14 line 2614); the run takes it at its next step
    /// ([`Supervisor::sync_revocation`]).
    pub fn authorize_granted_work(
        &mut self,
        execution: &ExecutionId,
        operation: OperationId,
        kind: LeaseKind,
        call: CallTerms,
        grants: BTreeSet<GrantId>,
    ) -> Result<crate::foundation::coordination::Lease, SupervisorError> {
        self.authorize_granted_work_until(execution, operation, kind, call, grants, None)
    }

    fn authorize_granted_work_until(
        &mut self,
        execution: &ExecutionId,
        operation: OperationId,
        kind: LeaseKind,
        call: CallTerms,
        grants: BTreeSet<GrantId>,
        deadline: Option<MonotonicTime>,
    ) -> Result<crate::foundation::coordination::Lease, SupervisorError> {
        if let EngineState::Down { since } = self.engine {
            return Err(SupervisorError::EngineDown { since });
        }
        if self.runs.contains_key(execution) {
            if let Ok(terms) = child_lease_terms(call, self.config.cancel_within) {
                if let Ok(lease) = self
                    .coordinator
                    .start_granted_work_until(execution, operation, kind, terms, grants, deadline)
                {
                    // The coordinator issues nothing under a recorded revocation, since the
                    // sandbox holds no authority; a lease issued all the same is given up.
                    let _ = self.coordinator.release_lease(lease.id());
                }
            }
            return Err(SupervisorError::Revoked {
                execution: execution.clone(),
            });
        }
        self.check_work_parent(execution)?;
        let terms = child_lease_terms(call, self.config.cancel_within)
            .map_err(|problem| SupervisorError::Terms { problem })?;
        self.coordinator
            .start_granted_work_until(execution, operation, kind, terms, grants, deadline)
            .map_err(|refusal| SupervisorError::Lease { refusal })
    }

    fn check_work_parent(&mut self, execution: &ExecutionId) -> Result<(), SupervisorError> {
        if let EngineState::Down { since } = self.engine {
            return Err(SupervisorError::EngineDown { since });
        }
        let now = self.clock.now();
        let record = self.record_mut(execution)?;
        if record.lockdown.is_some() {
            return Err(SupervisorError::LockedDown {
                execution: execution.clone(),
            });
        }
        if let ObservedReadiness::Unavailable { since, detail } = &record.readiness {
            return Err(SupervisorError::ReadinessUnavailable {
                execution: execution.clone(),
                since: *since,
                detail: detail.clone(),
            });
        }
        record
            .lease
            .check(now)
            .map_err(|refusal| SupervisorError::SandboxLease { refusal })?;
        Ok(())
    }

    /// Enforces every sandbox lease at the clock's reading now: an expired limit or a
    /// rolled-back clock revokes the sandbox (§6.2; VM-P18).
    pub fn tick<B: VmBackend + ?Sized>(
        &mut self,
        backend: &mut B,
    ) -> Result<TickReport, SupervisorError> {
        let now = self.clock.now();
        let mut report = TickReport::default();
        let executions: Vec<ExecutionId> = self.sandboxes.keys().cloned().collect();
        for execution in executions {
            if self.runs.contains_key(&execution) {
                continue;
            }
            if !self
                .state_of(&execution)
                .is_some_and(SandboxState::holds_authority)
            {
                continue;
            }
            let outcome = match self.sandboxes.get_mut(&execution) {
                Some(record) => record.lease.check(now),
                None => continue,
            };
            match outcome {
                Ok(_) => {}
                Err(LeaseRestoreRefusal::AlreadyExpired { expiry }) => {
                    self.revoke(
                        &execution,
                        RevocationCause::LeaseExpired { kind: expiry.kind },
                        backend,
                    )?;
                    report.expired.push((execution, expiry));
                }
                Err(LeaseRestoreRefusal::ClockRolledBack { .. })
                | Err(LeaseRestoreRefusal::OtherClockSession) => {
                    self.revoke(&execution, RevocationCause::ClockRolledBack, backend)?;
                    report.clock_rolled_back.push(execution);
                }
            }
        }
        let revoking: Vec<ExecutionId> = self.runs.keys().cloned().collect();
        for execution in &revoking {
            self.sync_revocation(execution)?;
        }
        for run in self.runs.values_mut() {
            run.note_bound_reached(now);
            run.note_cleanup_bound(now);
        }
        Ok(report)
    }

    /// Revokes the sandbox (§6.3 steps 1–2): the coordinator advances the durable epoch
    /// (the linearization point), cancels every lease and stops issuing; a tombstone is
    /// recorded for the revoked generation; the CORE-06 revocation receipt is produced;
    /// and under an immediate termination policy the VM is stopped at once through its
    /// handle. The lease-expiry bound is the authority's expiry or later, which also
    /// covers leases a grant revocation cancelled earlier, since no lease outlives its
    /// parent's authority. "New authorizations denied" is acknowledged once an
    /// authorization is actually refused after the decision. Revoking again changes
    /// nothing; it only takes what CORE-04 recorded since
    /// ([`Supervisor::sync_revocation`]).
    pub fn revoke<B: VmBackend + ?Sized>(
        &mut self,
        execution: &ExecutionId,
        cause: RevocationCause,
        backend: &mut B,
    ) -> Result<RevocationProgress, SupervisorError> {
        let timing = self.config.revocation.timing;
        let now = self.clock.now();
        if self.runs.contains_key(execution) {
            self.sync_revocation(execution)?;
            return self.progress(execution);
        }
        let provider_bills = self.record(execution)?.provider_bills;
        let authority_expiry = self
            .coordinator
            .sandbox(execution)
            .and_then(|sandbox| sandbox.authority())
            .map(|grant| grant.expires_at);
        let notice = self.coordinator.revoke(execution)?;
        let latest_lease = self
            .coordinator
            .revocation(execution)
            .and_then(|operation| {
                operation
                    .cancellations()
                    .iter()
                    .map(|cancellation| cancellation.expires_at)
                    .max()
            });
        let latest = [authority_expiry, latest_lease, Some(notice.at)]
            .into_iter()
            .flatten()
            .max()
            .unwrap_or(notice.at);
        let bound = latest.saturating_add(self.config.skew.allowed_clock_uncertainty);
        self.replay.record_tombstone(Tombstone {
            issuer: self.config.issuer,
            sandbox: execution.clone(),
            epoch: notice.revoked,
            recorded_at: now,
            latest_capability_expiry: latest,
        });
        let run = RevocationRun::new(&notice, cause, bound, provider_bills);
        let context = self.context(execution, Phase::Revoked)?;
        self.receipts.push(LifecycleReceipt::Revoked {
            revocation: Revocation {
                execution: execution.clone(),
                epoch: notice.current,
                reason: cause.reason(),
            },
            cause,
            context,
        });
        self.runs.insert(execution.clone(), run);
        self.sync_revocation(execution)?;
        if timing == TerminationTiming::Immediate {
            self.stop_vm_now(execution, backend)?;
        }
        self.progress(execution)
    }

    /// Takes into the sandbox's revocation run what CORE-04 recorded for it since (§6.3
    /// step 3, line 2310): the first denied authorization as "new authorizations denied"
    /// and all channels closed as "channels closed", each at its own time and with what
    /// established it, whoever reported it to the coordinator, such as an enforcement
    /// point checking a lease through the shared coordinator. Each newly taken
    /// acknowledgment is measured from the decision (VM-P14: revoke to deny, channel
    /// close) and gets its receipt. Returns what was taken.
    pub fn sync_revocation(
        &mut self,
        execution: &ExecutionId,
    ) -> Result<Vec<Acknowledgment>, SupervisorError> {
        let run = self
            .runs
            .get_mut(execution)
            .ok_or_else(|| SupervisorError::NotRevoking {
                execution: execution.clone(),
            })?;
        let Some(operation) = self.coordinator.revocation(execution) else {
            return Ok(Vec::new());
        };
        let decided_at = run.decided_at();
        let taken = run.observe_operation(operation)?;
        let mut acknowledged = Vec::with_capacity(taken.len());
        for (acknowledgment, at, source) in taken {
            let phase = match acknowledgment {
                Acknowledgment::NewAuthorizationsDenied => Some(StopPhase::RevokeToDeny),
                Acknowledgment::ChannelsClosed => Some(StopPhase::ChannelClose),
                Acknowledgment::VmStopped
                | Acknowledgment::ProviderBillingStopped
                | Acknowledgment::CleanupFinished => None,
            };
            if let Some(phase) = phase {
                self.measurements.record(PhaseSample {
                    execution: execution.clone(),
                    phase,
                    nanos: elapsed_nanos(decided_at, at),
                    burst: self.burst,
                });
            }
            self.receipts.push(LifecycleReceipt::Acknowledged {
                execution: execution.clone(),
                acknowledgment,
                at,
                source,
            });
            acknowledged.push(acknowledgment);
        }
        Ok(acknowledged)
    }

    /// Revokes one grant under the sandbox's authority alone (§6.3 step 1, line 2308:
    /// "records a generation tombstone"; CORE-04 per-grant revocation), through the
    /// coordinator: the grant is never honoured under the sandbox again, not after a
    /// relaunch either; the leases bound to it are cancelled with their declared bounds;
    /// a network grant leaves the settings the sandbox's models may use. The
    /// authorization epoch, the sandbox's other grants and leases and its VM stay as they
    /// were. It is no revocation of the sandbox: no revocation run starts, no epoch
    /// tombstone is recorded, nothing is acknowledged, and a later revocation of the
    /// sandbox takes nothing from it. Its receipt is a CORE-06 grant revocation, never a
    /// revocation. Revoking the same grant again returns the same record and adds no
    /// receipt, after a recovery too, since the record is persisted with the supervisor's
    /// state; a grant the sandbox never held is tombstoned all the same. A grant whose
    /// CORE-04 tombstone dates from before a recovery that restored no record of it, as
    /// from state persisted before records were kept, is already revoked: it gets a record
    /// of what is left to cancel with `cause`, and no second receipt.
    pub fn revoke_grant(
        &mut self,
        execution: &ExecutionId,
        grant: GrantId,
        cause: GrantRevocationCause,
    ) -> Result<GrantRevocationRecord, SupervisorError> {
        self.record(execution)?;
        let key = (execution.clone(), grant);
        if let Some(record) = self.grant_revocations.get(&key) {
            return Ok(record.clone());
        }
        let revoked_before_recovery = self.coordinator.grant_revoked(execution, grant)
            && self.coordinator.revoked_grant(execution, grant).is_none();
        let revoked = self.coordinator.revoke_grant(execution, grant)?;
        let record = GrantRevocationRecord { revoked, cause };
        if !revoked_before_recovery {
            let context = self.context(execution, Phase::Revoked)?;
            self.receipts.push(LifecycleReceipt::GrantRevoked {
                revocation: record.revocation(),
                cause,
                cancelled: record
                    .revoked
                    .cancellations
                    .iter()
                    .map(|cancellation| cancellation.lease)
                    .collect(),
                context,
            });
        }
        self.grant_revocations.insert(key, record.clone());
        Ok(record)
    }

    /// Stops the VM through its handle now, after the identity check, and records the
    /// stop. A reused handle stops nothing and is reported.
    fn stop_vm_now<B: VmBackend + ?Sized>(
        &mut self,
        execution: &ExecutionId,
        backend: &mut B,
    ) -> Result<(), SupervisorError> {
        let Some(vm) = self
            .coordinator
            .sandbox(execution)
            .and_then(|sandbox| sandbox.vm())
        else {
            return Ok(());
        };
        let stopped = {
            let mut bridge = Bridge::new(backend, &mut self.handles);
            let outcome = bridge.stop_checked(&vm);
            (outcome, !bridge.reused.is_empty())
        };
        let now = self.clock.now();
        match stopped {
            (Ok(_), _) => {
                self.record_vm_stopped(execution, now)?;
                Ok(())
            }
            (Err(failure), reused) => {
                let cause = if reused {
                    StopFailureCause::HandleReused
                } else {
                    StopFailureCause::BackendStalled
                };
                self.record_stop_failure(execution, cause, failure.to_string());
                if reused {
                    Err(SupervisorError::HandleReused { vm })
                } else {
                    Err(SupervisorError::Coordination {
                        error: CoordinationError::Port { failure },
                    })
                }
            }
        }
    }

    fn record_vm_stopped(
        &mut self,
        execution: &ExecutionId,
        now: MonotonicTime,
    ) -> Result<(), SupervisorError> {
        let burst = self.burst;
        let cleanup_bound = self.config.revocation.cleanup_bound;
        let (effect, decided_at) = match self.runs.get_mut(execution) {
            Some(run) => (
                run.acknowledge(Acknowledgment::VmStopped, now)?,
                run.decided_at(),
            ),
            None => return Ok(()),
        };
        if effect == AckEffect::Recorded {
            let nanos = now
                .saturating_duration_since(decided_at)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64;
            self.measurements.record(PhaseSample {
                execution: execution.clone(),
                phase: StopPhase::VmStop,
                nanos,
                burst,
            });
            let context = self.context(execution, Phase::Releasing)?;
            self.receipts.push(LifecycleReceipt::Stopped {
                execution: execution.clone(),
                context,
            });
        }
        if let Some(run) = self.runs.get_mut(execution) {
            let _ = run.start_cleanup(now, cleanup_bound);
        }
        Ok(())
    }

    fn record_stop_failure(
        &mut self,
        execution: &ExecutionId,
        cause: StopFailureCause,
        detail: String,
    ) {
        let already = self.runs.get(execution).is_some_and(|run| {
            run.uncertain()
                .iter()
                .any(|outcome| matches!(outcome, Uncertain::VmStopUncertain { .. }))
        });
        if let Some(run) = self.runs.get_mut(execution) {
            run.record_uncertain(Uncertain::VmStopUncertain { detail });
        }
        if !already {
            self.measurements.record_failure(PhaseFailure {
                execution: execution.clone(),
                phase: StopPhase::VmStop,
                cause,
            });
        }
    }

    /// Advances a revocation (§6.3 steps 3–5): waits for the channels' acknowledgment or
    /// the lease-expiry bound as the policy says, lets the coordinator wait for its leases,
    /// terminates the VM through its handle, releases everything and starts the bounded
    /// cleanup. Advancing a finished revocation changes nothing.
    pub fn advance<B: VmBackend + ?Sized>(
        &mut self,
        execution: &ExecutionId,
        backend: &mut B,
    ) -> Result<RevocationProgress, SupervisorError> {
        let timing = self.config.revocation.timing;
        let now = self.clock.now();
        self.sync_revocation(execution)?;
        let gate = {
            let run = self
                .runs
                .get_mut(execution)
                .ok_or_else(|| SupervisorError::NotRevoking {
                    execution: execution.clone(),
                })?;
            run.note_bound_reached(now);
            run.note_cleanup_bound(now);
            run.termination_gate(now, timing)
        };
        if let TerminationGate::Wait { .. } = gate {
            return self.progress(execution);
        }
        let (status, stopped_now, reused) = {
            let mut bridge = Bridge::new(backend, &mut self.handles);
            let status = self.coordinator.advance_revocation(execution, &mut bridge);
            (status, bridge.stopped, !bridge.reused.is_empty())
        };
        match status {
            Ok(RevocationStatus::WaitingForLeases { .. })
            | Ok(RevocationStatus::WaitingForGpuReclaim { .. }) => {}
            Ok(RevocationStatus::Completed { compensations }) => {
                let terminated = !stopped_now.is_empty()
                    || compensations
                        .iter()
                        .any(|step| matches!(step, Compensation::TerminateVm { .. }))
                    || self.state_of(execution) == Some(SandboxState::Stopped);
                if terminated {
                    self.record_vm_stopped(execution, now)?;
                }
            }
            Err(CoordinationError::Stalled { stall }) => {
                let cause = if reused {
                    StopFailureCause::HandleReused
                } else {
                    StopFailureCause::BackendStalled
                };
                self.record_stop_failure(execution, cause, format!("{:?}", stall.cause));
                return Err(SupervisorError::Stalled { stall });
            }
            Err(error) => return Err(error.into()),
        }
        self.progress(execution)
    }

    fn progress(&self, execution: &ExecutionId) -> Result<RevocationProgress, SupervisorError> {
        let now = self.clock.now();
        self.runs
            .get(execution)
            .map(|run| run.progress(now, self.config.revocation.timing))
            .ok_or_else(|| SupervisorError::NotRevoking {
                execution: execution.clone(),
            })
    }

    /// Revokes under the policy's timing and advances as far as time allows: a user's
    /// stop.
    pub fn stop<B: VmBackend + ?Sized>(
        &mut self,
        execution: &ExecutionId,
        backend: &mut B,
    ) -> Result<RevocationProgress, SupervisorError> {
        self.revoke(execution, RevocationCause::UserRequested, backend)?;
        self.advance(execution, backend)
    }

    /// Revokes and stops the VM at once, whatever the policy's timing (VM-D7 for a task
    /// sandbox when the engine dies; VM-D10 for an ephemeral sandbox on a violation).
    fn revoke_and_stop<B: VmBackend + ?Sized>(
        &mut self,
        execution: &ExecutionId,
        cause: RevocationCause,
        backend: &mut B,
    ) -> Result<RevocationProgress, SupervisorError> {
        self.revoke(execution, cause, backend)?;
        self.stop_vm_now(execution, backend)?;
        self.advance(execution, backend)
    }

    /// A host enforcement point acknowledges a fact about the revocation over the
    /// supervisor's authenticated local IPC (§6.3 step 3; §6.4), recorded as a host
    /// observation: [`Supervisor::acknowledge_from`] with [`SourceClass::HostProbe`].
    pub fn acknowledge(
        &mut self,
        execution: &ExecutionId,
        acknowledgment: Acknowledgment,
    ) -> Result<AckEffect, SupervisorError> {
        self.acknowledge_from(execution, acknowledgment, SourceClass::HostProbe)
    }

    /// An enforcement point acknowledges a fact about the revocation from `source` (§6.3
    /// step 3, line 2310; line 2314). New authorizations denied and channels closed go to
    /// CORE-04 as its first denied authorization and all channels closed, which refuses a
    /// source weaker than the host's, and the run takes them back with their sources
    /// ([`Supervisor::sync_revocation`]); the first record stands. The VM's stop is the
    /// supervisor's own observation, and billing and cleanup have their own typed inputs;
    /// none of them can be acknowledged here. A grant revocation has no acknowledgments:
    /// without a revocation of the sandbox this is refused.
    pub fn acknowledge_from(
        &mut self,
        execution: &ExecutionId,
        acknowledgment: Acknowledgment,
        source: SourceClass,
    ) -> Result<AckEffect, SupervisorError> {
        if acknowledgment == Acknowledgment::VmStopped {
            return Err(AckRefusal::VmStopIsObserved.into());
        }
        if !self.runs.contains_key(execution) {
            return Err(SupervisorError::NotRevoking {
                execution: execution.clone(),
            });
        }
        let milestone = match acknowledgment.milestone() {
            Some(milestone) => milestone,
            None if acknowledgment == Acknowledgment::ProviderBillingStopped => {
                return Err(AckRefusal::NeedsProviderAcknowledgment.into())
            }
            None => return Err(AckRefusal::NeedsCleanupReport.into()),
        };
        let reached_before = self
            .coordinator
            .revocation(execution)
            .and_then(|operation| operation.milestone(milestone))
            .is_some();
        self.coordinator
            .acknowledge_revocation(execution, milestone, source)?;
        self.sync_revocation(execution)?;
        Ok(if reached_before {
            AckEffect::AlreadyRecorded
        } else {
            AckEffect::Recorded
        })
    }

    /// The provider acknowledged that billing stopped (§6.5).
    pub fn provider_acknowledged(
        &mut self,
        execution: &ExecutionId,
        acknowledgment: ProviderAcknowledgment,
    ) -> Result<AckEffect, SupervisorError> {
        let run = self
            .runs
            .get_mut(execution)
            .ok_or_else(|| SupervisorError::NotRevoking {
                execution: execution.clone(),
            })?;
        let effect = run.provider_acknowledged(acknowledgment)?;
        if effect == AckEffect::Recorded {
            self.receipts.push(LifecycleReceipt::Acknowledged {
                execution: execution.clone(),
                acknowledgment: Acknowledgment::ProviderBillingStopped,
                at: acknowledgment.at,
                source: AckSource::Provider {
                    provider: acknowledgment.provider,
                },
            });
        }
        Ok(effect)
    }

    /// Applies one bounded lifecycle message from authenticated local IPC (§6.4). The
    /// message type is the whole surface: nothing else can be asked.
    pub fn apply_message<B: VmBackend + ?Sized>(
        &mut self,
        message: LifecycleMessage,
        backend: &mut B,
    ) -> Result<MessageOutcome, SupervisorError> {
        match message {
            LifecycleMessage::Activity { execution, kind } => {
                self.activity(&execution, kind)?;
                Ok(MessageOutcome::ActivityRecorded)
            }
            LifecycleMessage::Acknowledge {
                execution,
                acknowledgment,
            } => Ok(MessageOutcome::Acknowledged {
                effect: self.acknowledge(&execution, acknowledgment)?,
            }),
            LifecycleMessage::Revoke { execution, cause } => Ok(MessageOutcome::Revoked {
                progress: self.revoke(&execution, cause, backend)?,
            }),
            LifecycleMessage::RevokeGrant {
                execution,
                grant,
                cause,
            } => Ok(MessageOutcome::GrantRevoked {
                record: self.revoke_grant(&execution, grant, cause)?,
            }),
            LifecycleMessage::Stop { execution } => Ok(MessageOutcome::Stopped {
                progress: self.stop(&execution, backend)?,
            }),
            LifecycleMessage::Cleanup { execution, target } => Ok(MessageOutcome::CleanupPlanned {
                plan: self.plan_cleanup(&execution, target)?,
            }),
        }
    }

    /// Plans one cleanup step inside a managed root of the sandbox, once its VM stopped
    /// (§6.4; VM-P24). A path a guest chose has no way in.
    pub fn plan_cleanup(
        &self,
        execution: &ExecutionId,
        target: CleanupTarget,
    ) -> Result<CleanupPlan, SupervisorError> {
        let run = self
            .runs
            .get(execution)
            .ok_or_else(|| SupervisorError::NotRevoking {
                execution: execution.clone(),
            })?;
        if run.acknowledged_at(Acknowledgment::VmStopped).is_none() {
            return Err(AckRefusal::VmNotStopped.into());
        }
        self.roots
            .plan_cleanup(execution, target)
            .map_err(|refusal| SupervisorError::Cleanup { refusal })
    }

    /// Finishes the sandbox's cleanup with `report`, always a logical cleanup (§6.5).
    /// Returns whether it finished after the bound.
    pub fn finish_cleanup(
        &mut self,
        execution: &ExecutionId,
        report: CleanupReport,
    ) -> Result<bool, SupervisorError> {
        let now = self.clock.now();
        let burst = self.burst;
        let run = self
            .runs
            .get_mut(execution)
            .ok_or_else(|| SupervisorError::NotRevoking {
                execution: execution.clone(),
            })?;
        let stopped_at = run.acknowledged_at(Acknowledgment::VmStopped);
        let late = run.finish_cleanup(now, report.clone())?;
        let since = stopped_at.unwrap_or(run.decided_at());
        self.measurements.record(PhaseSample {
            execution: execution.clone(),
            phase: StopPhase::Cleanup,
            nanos: now
                .saturating_duration_since(since)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
            burst,
        });
        if late {
            self.measurements.record_failure(PhaseFailure {
                execution: execution.clone(),
                phase: StopPhase::Cleanup,
                cause: StopFailureCause::CleanupBound,
            });
        }
        self.roots.release(execution);
        let context = self.context(execution, Phase::Completed)?;
        self.receipts.push(LifecycleReceipt::CleanupFinished {
            execution: execution.clone(),
            report,
            late,
            context,
        });
        Ok(late)
    }

    /// The engine died (VM-D7): task sandboxes end with it; service sandboxes continue
    /// under their supervisor leases. New authorizations are denied until
    /// [`Supervisor::engine_reconciled`].
    pub fn engine_died<B: VmBackend + ?Sized>(
        &mut self,
        backend: &mut B,
    ) -> Result<EngineDeathReport, SupervisorError> {
        let since = self.clock.now();
        self.engine = EngineState::Down { since };
        let mut report = EngineDeathReport {
            since,
            ended: Vec::new(),
            continued: Vec::new(),
        };
        let executions: Vec<(ExecutionId, SandboxClass)> = self
            .sandboxes
            .iter()
            .map(|(execution, record)| (execution.clone(), record.class))
            .collect();
        for (execution, class) in executions {
            let live = self
                .state_of(&execution)
                .is_some_and(|state| state.holds_authority() || state == SandboxState::Revoking);
            if !live {
                continue;
            }
            match class {
                SandboxClass::Task => {
                    self.revoke_and_stop(&execution, RevocationCause::EngineDied, backend)?;
                    report.ended.push(execution);
                }
                SandboxClass::Service => report.continued.push(execution),
            }
        }
        self.receipts.push(LifecycleReceipt::EngineDied {
            report: report.clone(),
        });
        Ok(report)
    }

    /// The engine is back and reconciled; new authorizations are allowed again.
    pub fn engine_reconciled(&mut self) {
        self.engine = EngineState::Alive;
    }

    /// The GUI closed: no sandbox is affected (§6.2 "routine GUI closure should not
    /// accidentally destroy unrelated services"), and GUI presence was never activity.
    pub fn gui_closed(&mut self) -> GuiClosureReport {
        let now = self.clock.now();
        let mut report = GuiClosureReport {
            tasks_kept: 0,
            services_kept: 0,
        };
        for record in self.sandboxes.values_mut() {
            let _ = record.lease.activity(ActivityKind::GuiPresence, now);
            match record.class {
                SandboxClass::Task => report.tasks_kept = report.tasks_kept.saturating_add(1),
                SandboxClass::Service => {
                    report.services_kept = report.services_kept.saturating_add(1)
                }
            }
        }
        self.receipts.push(LifecycleReceipt::GuiClosed {
            report: report.clone(),
        });
        report
    }

    /// A clear violation (VM-D10): an ephemeral sandbox stops; a service sandbox locks
    /// down with a one-step stop.
    pub fn violation<B: VmBackend + ?Sized>(
        &mut self,
        execution: &ExecutionId,
        backend: &mut B,
    ) -> Result<ViolationResponse, SupervisorError> {
        let now = self.clock.now();
        let class = self.record(execution)?.class;
        match class {
            SandboxClass::Task => {
                let progress =
                    self.revoke_and_stop(execution, RevocationCause::Violation, backend)?;
                Ok(ViolationResponse::Stopped {
                    execution: execution.clone(),
                    progress,
                })
            }
            SandboxClass::Service => {
                let record = self.record_mut(execution)?;
                if let Some(lockdown) = &record.lockdown {
                    return Ok(ViolationResponse::LockedDown {
                        execution: execution.clone(),
                        token: lockdown.token,
                    });
                }
                let token = StopToken(digest(
                    StopToken::DOMAIN,
                    &[execution.as_str().as_bytes(), &now.as_nanos().to_be_bytes()],
                ));
                record.lockdown = Some(Lockdown { since: now, token });
                self.receipts.push(LifecycleReceipt::LockedDown {
                    execution: execution.clone(),
                    since: now,
                });
                Ok(ViolationResponse::LockedDown {
                    execution: execution.clone(),
                    token,
                })
            }
        }
    }

    /// The one-step stop of a locked-down service (VM-D10).
    pub fn stop_locked_down<B: VmBackend + ?Sized>(
        &mut self,
        execution: &ExecutionId,
        token: StopToken,
        backend: &mut B,
    ) -> Result<RevocationProgress, SupervisorError> {
        let record = self.record(execution)?;
        let lockdown = record
            .lockdown
            .as_ref()
            .ok_or_else(|| SupervisorError::NotLockedDown {
                execution: execution.clone(),
            })?;
        if lockdown.token != token {
            return Err(SupervisorError::WrongStopToken {
                execution: execution.clone(),
            });
        }
        self.revoke_and_stop(execution, RevocationCause::Violation, backend)
    }

    /// Begins a service renewal (§5.5; §6.2): the plan must define shutdown, recovery,
    /// downtime, lease revocation and rollback; the old authority is revoked, and only
    /// the volumes whose kind rides into a renewal are retained.
    pub fn begin_service_renewal<B: VmBackend + ?Sized>(
        &mut self,
        execution: &ExecutionId,
        plan: ServiceRenewalPlan,
        backend: &mut B,
    ) -> Result<RenewalReceipt, SupervisorError> {
        plan.check()
            .map_err(|problem| SupervisorError::RenewalPlan { problem })?;
        let now = self.clock.now();
        let profile = self.config.profile;
        let record = self.record_mut(execution)?;
        if record.class != SandboxClass::Service {
            return Err(SupervisorError::WrongClass {
                execution: execution.clone(),
                expected: SandboxClass::Service,
                found: record.class,
            });
        }
        let volumes: Vec<(Digest, VolumeKind)> = record
            .volumes
            .iter()
            .map(|(volume, kind)| (*volume, *kind))
            .collect();
        let retained = plan.retained(&volumes, profile);
        record.renewal = Some(PendingRenewal {
            plan,
            began_at: now,
            retained: retained.clone(),
        });
        self.revoke(execution, RevocationCause::ServiceRenewal, backend)?;
        Ok(RenewalReceipt::Begun {
            execution: execution.clone(),
            retained,
        })
    }

    /// Completes a service renewal once the old boot stopped: a cold relaunch with the
    /// retained volumes, fresh generations and a lease whose renewal period starts now.
    pub fn complete_service_renewal<B: VmBackend + ?Sized, R: Clock>(
        &mut self,
        execution: &ExecutionId,
        runtime: AdmittedRuntime,
        backend: &mut B,
        registry: &ProbeRegistry<R>,
    ) -> Result<RenewalReceipt, SupervisorError> {
        let now = self.clock.now();
        let record = self.record(execution)?;
        let pending = record
            .renewal
            .clone()
            .ok_or_else(|| SupervisorError::NoPendingRenewal {
                execution: execution.clone(),
            })?;
        let state = self.state_of(execution).unwrap_or(SandboxState::Planned);
        if state != SandboxState::Stopped {
            return Err(SupervisorError::NotStopped {
                execution: execution.clone(),
                state,
            });
        }
        let retained_volumes: BTreeMap<Digest, VolumeKind> = record
            .volumes
            .iter()
            .filter(|(volume, _)| pending.retained.contains(volume))
            .map(|(volume, kind)| (*volume, *kind))
            .collect();
        let settings = self
            .coordinator
            .sandbox(execution)
            .map(|sandbox| sandbox.settings_grant().clone())
            .unwrap_or_default();
        let request = LaunchRequest {
            execution: execution.clone(),
            tenant: record.identity.tenant.clone(),
            runtime,
            demand: record.demand.iter().copied().collect(),
            priority: record.priority,
            class: SandboxClass::Service,
            limits: *record.lease.limits(),
            settings,
            volumes: retained_volumes,
            provider_bills: record.provider_bills,
        };
        let (launch, _) = self.boot(request, None, backend, registry)?;
        let downtime = now.saturating_duration_since(pending.began_at);
        if let Some(record) = self.sandboxes.get_mut(execution) {
            record.renewal = None;
        }
        Ok(RenewalReceipt::Completed {
            execution: execution.clone(),
            downtime,
            downtime_exceeded: downtime > pending.plan.downtime_bound,
            retained: pending.retained,
            launch,
        })
    }

    /// What to persist. Store it durably, then confirm it with
    /// [`Supervisor::confirm_persisted`] so lease ids and the incarnation are handed out.
    pub fn persist(&self) -> PersistedSupervisor {
        PersistedSupervisor {
            coordination: self.coordinator.persist(),
            sandboxes: self.sandboxes.values().cloned().collect(),
            handles: self.handles.clone(),
            replay: self.replay.clone(),
            roots: self.roots.clone(),
            measurements: self.measurements.clone(),
            engine: self.engine,
            burst: self.burst,
            grant_revocations: self.grant_revocations.values().cloned().collect(),
        }
    }

    /// `state` was stored durably.
    pub fn confirm_persisted(&mut self, state: &PersistedSupervisor) {
        self.coordinator.confirm_persisted(&state.coordination);
    }

    /// Recovers after a crash of the supervisor or the host (§6.1 "recovery reconciles
    /// actual VM objects and resources rather than trusting old PID numbers"; VM-D7;
    /// INT-04). Every stored handle is checked with the backend first: one whose object
    /// was reused is dropped and never acted on. The coordinator reconciles the VMs it
    /// lists; no lease or authority is revived. A task sandbox found alive ends; a
    /// service sandbox is kept without authority until [`Supervisor::reauthorize`].
    /// The grants revoked alone come back with their records, so revoking one again is
    /// recognized; each keeps its CORE-04 tombstone, recorded again if the persisted
    /// coordination state lacks it, so no revoked grant is honoured after recovery (§6.3
    /// line 2318); a record whose tombstone CORE-04 cannot record, its execution being
    /// unknown, fails the recovery. `session` is the clock session after the restart.
    pub fn recover<B: VmBackend + ?Sized>(
        persisted: PersistedSupervisor,
        clock: C,
        session: ClockSession,
        capacity: P,
        config: SupervisorConfig,
        backend: &mut B,
    ) -> Result<(Self, SupervisorRecovery), RecoveryFailure<P>> {
        let mut handles = persisted.handles;
        let mut report = SupervisorRecovery::default();
        let stored: Vec<_> = handles.iter().cloned().collect();
        for handle in stored {
            match backend.check_handle(&handle) {
                HandleIdentity::Matches => {}
                HandleIdentity::Gone => {
                    handles.remove(&handle.vm);
                    report.handles_gone.push(handle.vm);
                }
                HandleIdentity::Reused { .. } => {
                    handles.remove(&handle.vm);
                    report.handles_reused.push(handle.vm);
                }
            }
        }
        let old_epochs: BTreeMap<ExecutionId, AuthorizationEpoch> = persisted
            .coordination
            .sandboxes
            .iter()
            .map(|sandbox| {
                (
                    sandbox.execution().clone(),
                    sandbox.generations().authorization,
                )
            })
            .collect();
        let (mut coordinator, coordination) = {
            let mut bridge = Bridge::new(backend, &mut handles);
            Coordinator::recover(
                persisted.coordination,
                clock.clone(),
                session,
                capacity,
                &mut bridge,
            )?
        };
        report.coordination = coordination;
        let mut grant_revocations = BTreeMap::new();
        for record in persisted.grant_revocations {
            let (execution, grant) = (record.revoked.execution.clone(), record.revoked.grant);
            if !coordinator.grant_revoked(&execution, grant) {
                if let Err(error) = coordinator.revoke_grant(&execution, grant) {
                    return Err(RecoveryFailure {
                        error,
                        capacity: coordinator.into_capacity(),
                    });
                }
                report
                    .grant_tombstones_recorded_again
                    .push((execution.clone(), grant));
            }
            grant_revocations.insert((execution, grant), record);
        }
        let now = clock.now();
        let mut replay = persisted.replay;
        let mut sandboxes = BTreeMap::new();
        for mut record in persisted.sandboxes {
            let execution = record.identity.execution.clone();
            report.leases_ended.push(execution.clone());
            // Every epoch the coordinator advanced past at recovery is tombstoned, so a
            // capability from before the crash is refused even if the persisted copy
            // predates the revocation that ended it (§12.3 model 5).
            if let (Some(old), Some(sandbox)) =
                (old_epochs.get(&execution), coordinator.sandbox(&execution))
            {
                let current = sandbox.generations().authorization;
                if *old < current {
                    replay.record_tombstone(Tombstone {
                        issuer: config.issuer,
                        sandbox: execution.clone(),
                        epoch: *old,
                        recorded_at: now,
                        latest_capability_expiry: now
                            .saturating_add(record.lease.limits().authority_lifetime()),
                    });
                }
            }
            let kept = matches!(
                report.coordination.sandboxes.get(&execution),
                Some(SandboxRecovery::VmKeptWithoutAuthority { .. })
            );
            record.lockdown = None;
            record.renewal = None;
            record.awaiting_reauthorization = false;
            if kept {
                match record.class {
                    SandboxClass::Task => {
                        let mut bridge = Bridge::new(backend, &mut handles);
                        if let Err(error) = coordinator.terminate(&execution, &mut bridge) {
                            return Err(RecoveryFailure {
                                error,
                                capacity: coordinator.into_capacity(),
                            });
                        }
                        report.tasks_ended.push(execution.clone());
                    }
                    SandboxClass::Service => {
                        record.awaiting_reauthorization = true;
                        report
                            .services_awaiting_reauthorization
                            .push(execution.clone());
                    }
                }
            }
            // The lease is from the old session and is not revived; a fresh one starts
            // only when authority is granted again.
            record.lease = SandboxLease::new(*record.lease.limits(), session, now);
            sandboxes.insert(execution, record);
        }
        let identities = handles.iter().map(|handle| handle.vm).collect();
        let supervisor = Self {
            clock,
            config,
            coordinator,
            sandboxes,
            handles,
            runs: BTreeMap::new(),
            grant_revocations,
            roots: persisted.roots,
            replay,
            measurements: persisted.measurements,
            receipts: Vec::new(),
            engine: EngineState::Alive,
            identities,
            burst: persisted.burst,
        };
        Ok((supervisor, report))
    }

    /// Grants authority again to a service sandbox recovery kept without it: the launch
    /// transaction continues from VM_created with fresh readiness and evidence checks.
    pub fn reauthorize<B: VmBackend + ?Sized, R: Clock>(
        &mut self,
        execution: &ExecutionId,
        runtime: AdmittedRuntime,
        backend: &mut B,
        registry: &ProbeRegistry<R>,
    ) -> Result<LaunchReceipt, SupervisorError> {
        let record = self.record(execution)?;
        if !record.awaiting_reauthorization {
            return Err(SupervisorError::NotAwaitingReauthorization {
                execution: execution.clone(),
            });
        }
        let settings = self
            .coordinator
            .sandbox(execution)
            .map(|sandbox| sandbox.settings_grant().clone())
            .unwrap_or_default();
        let request = LaunchRequest {
            execution: execution.clone(),
            tenant: record.identity.tenant.clone(),
            runtime,
            demand: record.demand.iter().copied().collect(),
            priority: record.priority,
            class: record.class,
            limits: *record.lease.limits(),
            settings,
            volumes: record.volumes.clone(),
            provider_bills: record.provider_bills,
        };
        let (receipt, _) = self.boot(request, None, backend, registry)?;
        if let LaunchReceipt::AuthorityActive { .. } = &receipt {
            if let Some(record) = self.sandboxes.get_mut(execution) {
                record.awaiting_reauthorization = false;
            }
        }
        Ok(receipt)
    }
}
