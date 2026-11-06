//! The VM sandbox lifecycle (S2 CORE-04; VM part §6.1), owned by RUNTIME.
//!
//! One durable state machine per sandbox, in the states VM part §6.1 names:
//!
//! ```text
//! planned → resources_reserved → perimeter_ready → VM_created
//!   → boot_evidence_checked → authority_active → running
//!   → revoking → terminating → cleanup_pending → stopped
//! ```
//!
//! A failed launch leaves through the same teardown states, undoing its steps in reverse.
//! Recovery may return a live VM to VM_created without authority, and a stopped sandbox
//! may boot again with fresh generations. Every transition is idempotent and records the
//! generations it was presented with and the ones it left. The lifecycle owns the boot
//! generation, policy epoch and authorization epoch; the model side cannot advance them
//! (S3.1).

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::capacity::{CapacityRefusal, ReservationKey, ReservationPriority};
use super::identity::{PerimeterId, SandboxGenerations, SnapshotId, VmInstanceId};
use super::port::PortFailure;
use super::recovery::{RestoreRefusal, VerifiedRestore};
use crate::foundation::evidence::{
    AuthorityGrant, CategoryRefusal, ClockSession, EvidenceRefusal, LoaderPlan, NetworkGrant,
    Optimization, RuntimeSubject, SourceClass,
};
use crate::foundation::ids::{Digest, ExecutionId, MonotonicTime, SandboxBootGeneration, TenantId};

/// What a sandbox's authority lets its models use (S3.5): the network grants and the
/// verified artifacts the launch approved. It is recorded with the authority when the
/// authority is granted, so a model's settings are judged against the coordinator's own
/// record and never against what the caller of an activation supplies (T01 review). The
/// default grants nothing: no network, and no artifact a loader may read. The loader
/// optimizations come from the gate's plan instead ([`LoaderGrant`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsGrant {
    /// Network grants a model may use; an activation may use fewer, never more.
    pub network: BTreeSet<NetworkGrant>,
    /// The artifacts verified for this sandbox. An activation's loader verifies every
    /// artifact it reads and reads only these (INT-09).
    pub verified_artifacts: BTreeSet<Digest>,
}

/// The loader optimizations the CORE-01 gate's plan enabled for the sandbox's runtime,
/// recorded with the authority it holds (S3.5; INT-06). An activation's loader uses only
/// these; without a grant, only the ordinary loader runs. It ends with that authority,
/// so a new boot or a recovered sandbox is granted its loader again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoaderGrant {
    /// The exact runtime the plan was made for.
    pub runtime: RuntimeSubject,
    /// The optimizations it enabled.
    pub optimizations: BTreeSet<Optimization>,
}

impl SettingsGrant {
    /// Removes the network grants `named` picks; returns one of them, if any was granted.
    pub(super) fn withdraw_network(
        &mut self,
        named: impl Fn(&NetworkGrant) -> bool,
    ) -> Option<NetworkGrant> {
        let withdrawn = self.network.iter().copied().find(|grant| named(grant));
        self.network.retain(|grant| !named(grant));
        withdrawn
    }
}

impl LoaderGrant {
    /// What `plan` enabled, for the runtime it was made for.
    pub fn from_plan(plan: &LoaderPlan) -> Self {
        Self {
            runtime: plan.runtime().clone(),
            optimizations: plan.enabled_set(),
        }
    }
}

/// A state of the launch transaction (VM part §6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxState {
    Planned,
    ResourcesReserved,
    PerimeterReady,
    #[serde(rename = "VM_created")]
    VmCreated,
    BootEvidenceChecked,
    AuthorityActive,
    Running,
    Revoking,
    Terminating,
    CleanupPending,
    Stopped,
}

impl SandboxState {
    /// Every state, in VM part §6.1 order.
    pub const ALL: [Self; 11] = [
        Self::Planned,
        Self::ResourcesReserved,
        Self::PerimeterReady,
        Self::VmCreated,
        Self::BootEvidenceChecked,
        Self::AuthorityActive,
        Self::Running,
        Self::Revoking,
        Self::Terminating,
        Self::CleanupPending,
        Self::Stopped,
    ];

    /// The name VM part §6.1 gives the state.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::ResourcesReserved => "resources_reserved",
            Self::PerimeterReady => "perimeter_ready",
            Self::VmCreated => "VM_created",
            Self::BootEvidenceChecked => "boot_evidence_checked",
            Self::AuthorityActive => "authority_active",
            Self::Running => "running",
            Self::Revoking => "revoking",
            Self::Terminating => "terminating",
            Self::CleanupPending => "cleanup_pending",
            Self::Stopped => "stopped",
        }
    }

    /// Whether the sandbox holds authority. Nothing external is exposed before
    /// authority_active (VM part §6.1).
    pub const fn holds_authority(self) -> bool {
        matches!(self, Self::AuthorityActive | Self::Running)
    }
}

impl fmt::Display for SandboxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Readiness the host observed for one boot of one VM (VM part §6.1
/// boot_evidence_checked). The coordinator stamps the time; only a host probe counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessEvidence {
    pub vm: VmInstanceId,
    pub boot: SandboxBootGeneration,
    pub source: SourceClass,
    pub observed_at: MonotonicTime,
}

/// A transition of the lifecycle, with what it records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum SandboxStep {
    /// The sandbox reservation is held (S10: reserve before creating).
    ReserveResources {
        reservation: ReservationKey,
    },
    /// The perimeter for this boot is ready.
    PreparePerimeter {
        perimeter: PerimeterId,
    },
    /// The VM exists, freshly booted or restored from a snapshot.
    CreateVm {
        vm: VmInstanceId,
        restored_from: Option<SnapshotId>,
    },
    /// The host observed the VM ready.
    CheckBootEvidence {
        readiness: ReadinessEvidence,
    },
    /// Authority is granted under the current authorization epoch until `expires_at` on
    /// `clock`, if the readiness evidence is no older than `readiness_max_age`; its models
    /// may use what `settings` grants (S3.5).
    ActivateAuthority {
        clock: ClockSession,
        expires_at: MonotonicTime,
        readiness_max_age: Duration,
        settings: SettingsGrant,
    },
    StartRunning,
    /// The authorization epoch advances and authority ends (VM part §6.3 steps 1–2).
    Revoke,
    /// Recovery found the VM alive: the authorization epoch advances, authority is not
    /// revived, and the VM needs fresh readiness evidence and a fresh grant (INT-04).
    Reconcile,
    Terminate,
    BeginCleanup,
    Stop,
    /// A new boot of a stopped sandbox on `runtime`, with a fresh boot generation and
    /// authorization epoch (S7 line 125: fresh identifiers and lease epochs).
    NewBoot {
        runtime: RuntimeSubject,
    },
    /// A policy change: only the policy epoch advances (S3.1).
    RaisePolicyEpoch,
}

crate::foundation::strict_serde::strict_tag!(SandboxStep, "step");

/// A [`SandboxStep`] without what it records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    ReserveResources,
    PreparePerimeter,
    CreateVm,
    CheckBootEvidence,
    ActivateAuthority,
    StartRunning,
    Revoke,
    Reconcile,
    Terminate,
    BeginCleanup,
    Stop,
    NewBoot,
    RaisePolicyEpoch,
}

impl fmt::Display for StepKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReserveResources => "reserve resources",
            Self::PreparePerimeter => "prepare the perimeter",
            Self::CreateVm => "create the VM",
            Self::CheckBootEvidence => "check boot evidence",
            Self::ActivateAuthority => "activate authority",
            Self::StartRunning => "start running",
            Self::Revoke => "revoke",
            Self::Reconcile => "reconcile",
            Self::Terminate => "terminate",
            Self::BeginCleanup => "begin cleanup",
            Self::Stop => "stop",
            Self::NewBoot => "boot again",
            Self::RaisePolicyEpoch => "raise the policy epoch",
        })
    }
}

impl SandboxStep {
    /// The step without what it records.
    pub fn kind(&self) -> StepKind {
        match self {
            Self::ReserveResources { .. } => StepKind::ReserveResources,
            Self::PreparePerimeter { .. } => StepKind::PreparePerimeter,
            Self::CreateVm { .. } => StepKind::CreateVm,
            Self::CheckBootEvidence { .. } => StepKind::CheckBootEvidence,
            Self::ActivateAuthority { .. } => StepKind::ActivateAuthority,
            Self::StartRunning => StepKind::StartRunning,
            Self::Revoke => StepKind::Revoke,
            Self::Reconcile => StepKind::Reconcile,
            Self::Terminate => StepKind::Terminate,
            Self::BeginCleanup => StepKind::BeginCleanup,
            Self::Stop => StepKind::Stop,
            Self::NewBoot { .. } => StepKind::NewBoot,
            Self::RaisePolicyEpoch => StepKind::RaisePolicyEpoch,
        }
    }

    /// The state the step leads to from `from`; `None` where the lifecycle has no edge.
    pub fn target(&self, from: SandboxState) -> Option<SandboxState> {
        use SandboxState as S;
        match (self.kind(), from) {
            (StepKind::ReserveResources, S::Planned) => Some(S::ResourcesReserved),
            (StepKind::PreparePerimeter, S::ResourcesReserved) => Some(S::PerimeterReady),
            (StepKind::CreateVm, S::PerimeterReady) => Some(S::VmCreated),
            (StepKind::CheckBootEvidence, S::VmCreated) => Some(S::BootEvidenceChecked),
            (StepKind::ActivateAuthority, S::BootEvidenceChecked) => Some(S::AuthorityActive),
            (StepKind::StartRunning, S::AuthorityActive) => Some(S::Running),
            (StepKind::Revoke, S::AuthorityActive | S::Running) => Some(S::Revoking),
            (
                StepKind::Reconcile,
                S::VmCreated | S::BootEvidenceChecked | S::AuthorityActive | S::Running,
            ) => Some(S::VmCreated),
            (StepKind::Terminate, S::VmCreated | S::BootEvidenceChecked | S::Revoking) => {
                Some(S::Terminating)
            }
            (StepKind::BeginCleanup, S::ResourcesReserved | S::PerimeterReady | S::Terminating) => {
                Some(S::CleanupPending)
            }
            (StepKind::Stop, S::Planned | S::CleanupPending) => Some(S::Stopped),
            (StepKind::NewBoot, S::Stopped) => Some(S::Planned),
            (StepKind::RaisePolicyEpoch, state) if state != S::Stopped => Some(state),
            _ => None,
        }
    }
}

/// One applied transition (VM part §6.1: every transition records its generation).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionRecord {
    pub sequence: u64,
    pub step: SandboxStep,
    /// The generations the step was presented with.
    pub presented: SandboxGenerations,
    pub from: SandboxState,
    pub to: SandboxState,
    /// The generations after the step.
    pub generations: SandboxGenerations,
    pub at: MonotonicTime,
}

/// What applying a step did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "applied", rename_all = "snake_case")]
pub enum Applied {
    /// The step moved the lifecycle.
    Advanced { record: TransitionRecord },
    /// The same step was already applied under the same generations; nothing changed.
    AlreadyApplied { record: TransitionRecord },
}

impl Applied {
    /// The transition, applied now or before.
    pub fn record(&self) -> &TransitionRecord {
        match self {
            Self::Advanced { record } | Self::AlreadyApplied { record } => record,
        }
    }
}

/// Which generation ran out. A sandbox at the last value is replaced, never wrapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationName {
    Boot,
    Policy,
    Authorization,
}

/// Why a step was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum TransitionRefusal {
    /// The step was presented with generations that are no longer current and was never
    /// applied under them.
    StaleGeneration {
        presented: SandboxGenerations,
        current: SandboxGenerations,
    },
    /// The same kind of step was already applied under these generations with different
    /// content.
    Conflict {
        recorded: SandboxStep,
        presented: SandboxStep,
    },
    /// VM part §6.1 has no such edge.
    InvalidTransition {
        from: SandboxState,
        step: StepKind,
    },
    /// Readiness reported by anything but a host probe, such as the guest itself.
    ReadinessNotHostObserved {
        source: SourceClass,
    },
    /// Readiness of another VM or boot.
    ReadinessForOtherBoot {
        vm: VmInstanceId,
        boot: SandboxBootGeneration,
    },
    /// A restored VM must be verified before its boot evidence counts (S10 line 181).
    RestoreNotVerified {
        vm: VmInstanceId,
    },
    NoReadiness,
    ReadinessStale {
        age: Duration,
        limit: Duration,
    },
    AuthorityWouldBeExpired {
        expires_at: MonotonicTime,
    },
    /// The backend returned a VM handle an earlier boot used (VM part §6.3: never reuse
    /// an identity).
    VmIdentityReused {
        vm: VmInstanceId,
    },
    GenerationExhausted {
        generation: GenerationName,
    },
}

crate::foundation::strict_serde::strict_tag!(TransitionRefusal, "refusal");

impl fmt::Display for TransitionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleGeneration { presented, current } => write!(
                f,
                "the step was presented with {presented}, but the sandbox is at {current}"
            ),
            Self::Conflict { recorded, .. } => write!(
                f,
                "\"{}\" was already applied under these generations with different content",
                recorded.kind()
            ),
            Self::InvalidTransition { from, step } => {
                write!(f, "a sandbox cannot {step} while {from}")
            }
            Self::ReadinessNotHostObserved { source } => write!(
                f,
                "readiness came from a {source}; only readiness the host observed counts"
            ),
            Self::ReadinessForOtherBoot { vm, boot } => write!(
                f,
                "the readiness evidence is about VM {vm} at boot generation {boot}, not this boot"
            ),
            Self::RestoreNotVerified { vm } => write!(
                f,
                "restored VM {vm} has not been verified; it receives no authority before that"
            ),
            Self::NoReadiness => f.write_str("no readiness evidence was checked for this boot"),
            Self::ReadinessStale { age, limit } => write!(
                f,
                "the readiness evidence is {} ms old, older than the {} ms allowed",
                age.as_millis(),
                limit.as_millis()
            ),
            Self::AuthorityWouldBeExpired { expires_at } => write!(
                f,
                "authority expiring at {} ns would already be expired",
                expires_at.as_nanos()
            ),
            Self::VmIdentityReused { vm } => write!(
                f,
                "VM handle {vm} was used by an earlier boot; an identity is never reused"
            ),
            Self::GenerationExhausted { generation } => write!(
                f,
                "the sandbox's {} generation is exhausted; replace the sandbox",
                match generation {
                    GenerationName::Boot => "boot",
                    GenerationName::Policy => "policy",
                    GenerationName::Authorization => "authorization",
                }
            ),
        }
    }
}

impl std::error::Error for TransitionRefusal {}

/// Why a launch failed. The launch undid every completed step in reverse (VM part §6.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "launch_failure", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum LaunchFailure {
    /// The ledger refused the reservation.
    Capacity { refusal: CapacityRefusal },
    /// The backend failed a step.
    Port { failure: PortFailure },
    /// The host did not observe the VM ready.
    NotReady { detail: String },
    /// The lifecycle refused a step, such as readiness the host did not observe.
    Transition { refusal: TransitionRefusal },
    /// The restored VM failed verification (S10 line 181).
    RestoreRefused { refusal: RestoreRefusal },
    /// The admitted runtime's category evidence no longer holds when rechecked before
    /// authority (INT-07; VM part §6.1 boot_evidence_checked).
    RuntimeEvidence { refusal: EvidenceRefusal },
    /// The rechecked evidence shows a category other than a VM sandbox (INT-07).
    RuntimeCategory { refusal: CategoryRefusal },
}

crate::foundation::strict_serde::strict_tag!(LaunchFailure, "launch_failure");

impl fmt::Display for LaunchFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity { refusal } => write!(f, "{refusal}"),
            Self::Port { failure } => write!(f, "{failure}"),
            Self::NotReady { detail } => write!(f, "the VM did not become ready: {detail}"),
            Self::Transition { refusal } => write!(f, "{refusal}"),
            Self::RestoreRefused { refusal } => write!(f, "{refusal}"),
            Self::RuntimeEvidence { refusal } => write!(f, "{refusal}"),
            Self::RuntimeCategory { refusal } => write!(f, "{refusal}"),
        }
    }
}

/// The durable state machine of one VM sandbox (VM part §6.1), owned by RUNTIME.
///
/// The handles are those of the current or last boot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxLifecycle {
    execution: ExecutionId,
    tenant: TenantId,
    runtime: RuntimeSubject,
    priority: ReservationPriority,
    state: SandboxState,
    generations: SandboxGenerations,
    authority: Option<AuthorityGrant>,
    settings: SettingsGrant,
    #[serde(default)]
    loader: Option<LoaderGrant>,
    reservation: Option<ReservationKey>,
    perimeter: Option<PerimeterId>,
    vm: Option<VmInstanceId>,
    restored_from: Option<SnapshotId>,
    verified_restore: Option<VmInstanceId>,
    readiness: Option<ReadinessEvidence>,
    previous_vms: BTreeSet<VmInstanceId>,
    failure: Option<LaunchFailure>,
    log: Vec<TransitionRecord>,
}

impl SandboxLifecycle {
    pub(super) fn new(
        execution: ExecutionId,
        tenant: TenantId,
        runtime: RuntimeSubject,
        priority: ReservationPriority,
    ) -> Self {
        Self {
            execution,
            tenant,
            runtime,
            priority,
            state: SandboxState::Planned,
            generations: SandboxGenerations::FIRST,
            authority: None,
            settings: SettingsGrant::default(),
            loader: None,
            reservation: None,
            perimeter: None,
            vm: None,
            restored_from: None,
            verified_restore: None,
            readiness: None,
            previous_vms: BTreeSet::new(),
            failure: None,
            log: Vec::new(),
        }
    }

    /// The stable sandbox identity: its parent execution (VM part §6.1: separate stable
    /// identity from boot generation).
    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    /// The tenant whose budgets and grants apply.
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// The admitted runtime of the current or last boot (INT-07).
    pub fn runtime(&self) -> &RuntimeSubject {
        &self.runtime
    }

    /// Whether the sandbox's reservations are background work, which an owner
    /// resource-return hold denies, or foreground work; children keep it.
    pub fn priority(&self) -> ReservationPriority {
        self.priority
    }

    /// The state now.
    pub fn state(&self) -> SandboxState {
        self.state
    }

    /// The boot generation, policy epoch and authorization epoch now.
    pub fn generations(&self) -> SandboxGenerations {
        self.generations
    }

    /// The authority held now; `None` outside authority_active and running.
    pub fn authority(&self) -> Option<AuthorityGrant> {
        self.authority
    }

    /// What the latest authority grant lets the sandbox's models use (S3.5). It counts
    /// only while authority is held; a new boot is granted it again.
    pub fn settings_grant(&self) -> &SettingsGrant {
        &self.settings
    }

    /// The loader optimizations granted with the authority held now, if any (S3.5;
    /// INT-06).
    pub fn loader_grant(&self) -> Option<&LoaderGrant> {
        self.loader.as_ref()
    }

    /// Records `grant` with the authority held now; it ends with that authority.
    pub(super) fn grant_loader(&mut self, grant: LoaderGrant) {
        self.loader = Some(grant);
    }

    /// Withdraws the network grants `named` picks from what the authority grants the
    /// sandbox's models, when one of them is revoked (CORE-04 per-grant revocation); the
    /// authority and its other grants stay. Returns one of them, if any was granted.
    pub(super) fn withdraw_network(
        &mut self,
        named: impl Fn(&NetworkGrant) -> bool,
    ) -> Option<NetworkGrant> {
        self.settings.withdraw_network(named)
    }

    /// Raises each generation to at least `floor`'s (CORE-04 durable epochs): a record
    /// restored from a state older than the durable floor hands out no boot generation,
    /// policy epoch or authorization epoch that was already used, and a retired sandbox's
    /// generations stay exhausted. Applied outside the transition log, before recovery or
    /// at retirement. Returns the generations before.
    pub(super) fn raise_generations(&mut self, floor: SandboxGenerations) -> SandboxGenerations {
        let before = self.generations;
        self.generations = SandboxGenerations {
            boot: before.boot.max(floor.boot),
            policy: before.policy.max(floor.policy),
            authorization: before.authorization.max(floor.authorization),
        };
        before
    }

    /// The sandbox reservation's key.
    pub fn reservation(&self) -> Option<ReservationKey> {
        self.reservation
    }

    /// The perimeter.
    pub fn perimeter(&self) -> Option<PerimeterId> {
        self.perimeter
    }

    /// The VM's handle.
    pub fn vm(&self) -> Option<VmInstanceId> {
        self.vm
    }

    /// The snapshot this boot was restored from, if any.
    pub fn restored_from(&self) -> Option<SnapshotId> {
        self.restored_from
    }

    /// The restored VM verified for this boot, if any.
    pub fn verified_restore(&self) -> Option<VmInstanceId> {
        self.verified_restore
    }

    /// The readiness evidence checked for this boot.
    pub fn readiness(&self) -> Option<ReadinessEvidence> {
        self.readiness
    }

    /// Every VM handle any boot of this sandbox used.
    pub fn previous_vms(&self) -> &BTreeSet<VmInstanceId> {
        &self.previous_vms
    }

    /// Why the last launch failed, if it did.
    pub fn failure(&self) -> Option<&LaunchFailure> {
        self.failure.as_ref()
    }

    /// Every applied transition, in order.
    pub fn log(&self) -> &[TransitionRecord] {
        &self.log
    }

    /// Applies `step`, presented with the generations the caller believes current.
    ///
    /// A step already applied under the same generations returns its record and changes
    /// nothing. A step presented with stale generations is refused, as is one VM part
    /// §6.1 has no edge for.
    pub(super) fn apply(
        &mut self,
        step: SandboxStep,
        presented: SandboxGenerations,
        at: MonotonicTime,
    ) -> Result<Applied, TransitionRefusal> {
        if let Some(record) = self
            .log
            .iter()
            .rev()
            .find(|record| record.presented == presented && record.step == step)
        {
            return Ok(Applied::AlreadyApplied {
                record: record.clone(),
            });
        }
        if presented != self.generations {
            return Err(TransitionRefusal::StaleGeneration {
                presented,
                current: self.generations,
            });
        }
        if let Some(record) = self
            .log
            .iter()
            .rev()
            .find(|record| record.presented == presented && record.step.kind() == step.kind())
        {
            return Err(TransitionRefusal::Conflict {
                recorded: record.step.clone(),
                presented: step,
            });
        }
        let from = self.state;
        let to = step
            .target(from)
            .ok_or(TransitionRefusal::InvalidTransition {
                from,
                step: step.kind(),
            })?;
        let generations = self.next_generations(&step)?;
        self.validate(&step, at)?;

        match &step {
            SandboxStep::ReserveResources { reservation } => self.reservation = Some(*reservation),
            SandboxStep::PreparePerimeter { perimeter } => self.perimeter = Some(*perimeter),
            SandboxStep::CreateVm { vm, restored_from } => {
                self.vm = Some(*vm);
                self.previous_vms.insert(*vm);
                self.restored_from = *restored_from;
                self.verified_restore = None;
                self.readiness = None;
            }
            SandboxStep::CheckBootEvidence { readiness } => self.readiness = Some(*readiness),
            SandboxStep::ActivateAuthority {
                clock,
                expires_at,
                settings,
                ..
            } => {
                self.authority = Some(AuthorityGrant {
                    epoch: generations.authorization,
                    clock: *clock,
                    expires_at: *expires_at,
                });
                self.settings = settings.clone();
            }
            SandboxStep::Reconcile => {
                self.authority = None;
                self.loader = None;
                self.readiness = None;
            }
            SandboxStep::Revoke | SandboxStep::Terminate | SandboxStep::Stop => {
                self.authority = None;
                self.loader = None;
            }
            SandboxStep::NewBoot { runtime } => {
                self.runtime = runtime.clone();
                self.authority = None;
                self.loader = None;
                self.reservation = None;
                self.perimeter = None;
                self.vm = None;
                self.restored_from = None;
                self.verified_restore = None;
                self.readiness = None;
                self.failure = None;
            }
            SandboxStep::StartRunning
            | SandboxStep::BeginCleanup
            | SandboxStep::RaisePolicyEpoch => {}
        }
        let record = TransitionRecord {
            sequence: (self.log.len() as u64).saturating_add(1),
            step,
            presented,
            from,
            to,
            generations,
            at,
        };
        self.generations = generations;
        self.state = to;
        self.log.push(record.clone());
        Ok(Applied::Advanced { record })
    }

    fn next_generations(
        &self,
        step: &SandboxStep,
    ) -> Result<SandboxGenerations, TransitionRefusal> {
        let exhausted = |generation| TransitionRefusal::GenerationExhausted { generation };
        let mut next = self.generations;
        match step.kind() {
            StepKind::Revoke | StepKind::Reconcile => {
                next.authorization = next
                    .authorization
                    .next()
                    .ok_or(exhausted(GenerationName::Authorization))?;
            }
            StepKind::NewBoot => {
                next.boot = next.boot.next().ok_or(exhausted(GenerationName::Boot))?;
                next.authorization = next
                    .authorization
                    .next()
                    .ok_or(exhausted(GenerationName::Authorization))?;
            }
            StepKind::RaisePolicyEpoch => {
                next.policy = next
                    .policy
                    .next()
                    .ok_or(exhausted(GenerationName::Policy))?;
            }
            _ => {}
        }
        Ok(next)
    }

    fn validate(&self, step: &SandboxStep, at: MonotonicTime) -> Result<(), TransitionRefusal> {
        match step {
            SandboxStep::CreateVm { vm, .. } if self.previous_vms.contains(vm) => {
                Err(TransitionRefusal::VmIdentityReused { vm: *vm })
            }
            SandboxStep::CheckBootEvidence { readiness } => {
                if readiness.source != SourceClass::HostProbe {
                    return Err(TransitionRefusal::ReadinessNotHostObserved {
                        source: readiness.source,
                    });
                }
                if self.vm != Some(readiness.vm) || readiness.boot != self.generations.boot {
                    return Err(TransitionRefusal::ReadinessForOtherBoot {
                        vm: readiness.vm,
                        boot: readiness.boot,
                    });
                }
                if self.restored_from.is_some() && self.verified_restore != Some(readiness.vm) {
                    return Err(TransitionRefusal::RestoreNotVerified { vm: readiness.vm });
                }
                Ok(())
            }
            SandboxStep::ActivateAuthority {
                expires_at,
                readiness_max_age,
                ..
            } => {
                let readiness = self.readiness.ok_or(TransitionRefusal::NoReadiness)?;
                let age = at.saturating_duration_since(readiness.observed_at);
                if age > *readiness_max_age {
                    return Err(TransitionRefusal::ReadinessStale {
                        age,
                        limit: *readiness_max_age,
                    });
                }
                if *expires_at <= at {
                    return Err(TransitionRefusal::AuthorityWouldBeExpired {
                        expires_at: *expires_at,
                    });
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Records that the restored VM of this boot passed verification (S10 line 181).
    pub(super) fn record_verified_restore(
        &mut self,
        verified: &VerifiedRestore,
    ) -> Result<(), TransitionRefusal> {
        let matches = self.state == SandboxState::VmCreated
            && self.vm == Some(verified.vm())
            && self.generations.boot == verified.boot()
            && self.restored_from == Some(verified.snapshot());
        if !matches {
            return Err(TransitionRefusal::RestoreNotVerified { vm: verified.vm() });
        }
        self.verified_restore = Some(verified.vm());
        Ok(())
    }

    pub(super) fn record_failure(&mut self, failure: LaunchFailure) {
        self.failure = Some(failure);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::evidence::{Backend, BackendRelease};
    use crate::foundation::ids::{digest, AuthorizationEpoch, ExecutionCategory, PolicyEpoch};

    fn at(seconds: u64) -> MonotonicTime {
        MonotonicTime::from_nanos(seconds * 1_000_000_000)
    }

    fn vm(name: &str) -> VmInstanceId {
        VmInstanceId::new(digest("yougori/test/vm/v1", &[name.as_bytes()]))
    }

    fn session() -> ClockSession {
        ClockSession::from_uuid(uuid::Uuid::from_u128(1))
    }

    fn runtime(instance: &str) -> RuntimeSubject {
        RuntimeSubject {
            category: ExecutionCategory::VmSandbox,
            release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
            instance: digest("yougori/test/instance/v1", &[instance.as_bytes()]),
        }
    }

    fn lifecycle() -> SandboxLifecycle {
        SandboxLifecycle::new(
            ExecutionId::new("exe-sandbox").unwrap(),
            TenantId::new("tenant-a").unwrap(),
            runtime("vm-1"),
            ReservationPriority::Background,
        )
    }

    fn reservation() -> ReservationKey {
        ReservationKey::derive(
            &ExecutionId::new("exe-sandbox").unwrap(),
            &super::super::capacity::ReservationPurpose::Sandbox {
                boot: SandboxBootGeneration::FIRST,
            },
        )
    }

    fn perimeter() -> PerimeterId {
        PerimeterId::new(digest("yougori/test/perimeter/v1", &[b"p"]))
    }

    fn readiness(of: VmInstanceId, source: SourceClass, observed: u64) -> ReadinessEvidence {
        ReadinessEvidence {
            vm: of,
            boot: SandboxBootGeneration::FIRST,
            source,
            observed_at: at(observed),
        }
    }

    fn step(sandbox: &mut SandboxLifecycle, step: SandboxStep, now: u64) -> Applied {
        let presented = sandbox.generations();
        sandbox.apply(step, presented, at(now)).unwrap()
    }

    fn to_authority(sandbox: &mut SandboxLifecycle) {
        step(
            sandbox,
            SandboxStep::ReserveResources {
                reservation: reservation(),
            },
            1,
        );
        step(
            sandbox,
            SandboxStep::PreparePerimeter {
                perimeter: perimeter(),
            },
            2,
        );
        step(
            sandbox,
            SandboxStep::CreateVm {
                vm: vm("a"),
                restored_from: None,
            },
            3,
        );
        step(
            sandbox,
            SandboxStep::CheckBootEvidence {
                readiness: readiness(vm("a"), SourceClass::HostProbe, 4),
            },
            4,
        );
        step(
            sandbox,
            SandboxStep::ActivateAuthority {
                clock: session(),
                expires_at: at(100),
                readiness_max_age: Duration::from_secs(5),
                settings: SettingsGrant::default(),
            },
            5,
        );
    }

    #[test]
    fn state_names_are_those_of_vm_part_6_1() {
        let names: Vec<&str> = SandboxState::ALL.iter().map(|state| state.name()).collect();
        assert_eq!(
            names,
            [
                "planned",
                "resources_reserved",
                "perimeter_ready",
                "VM_created",
                "boot_evidence_checked",
                "authority_active",
                "running",
                "revoking",
                "terminating",
                "cleanup_pending",
                "stopped"
            ]
        );
        for state in SandboxState::ALL {
            assert_eq!(
                serde_json::to_value(state).unwrap(),
                serde_json::Value::from(state.name())
            );
        }
        let holding: Vec<SandboxState> = SandboxState::ALL
            .into_iter()
            .filter(|state| state.holds_authority())
            .collect();
        assert_eq!(
            holding,
            [SandboxState::AuthorityActive, SandboxState::Running]
        );
    }

    #[test]
    fn the_forward_path_records_every_generation() {
        let mut sandbox = lifecycle();
        to_authority(&mut sandbox);
        step(&mut sandbox, SandboxStep::StartRunning, 6);
        let states: Vec<(SandboxState, SandboxState)> = sandbox
            .log()
            .iter()
            .map(|record| (record.from, record.to))
            .collect();
        assert_eq!(
            states,
            [
                (SandboxState::Planned, SandboxState::ResourcesReserved),
                (
                    SandboxState::ResourcesReserved,
                    SandboxState::PerimeterReady
                ),
                (SandboxState::PerimeterReady, SandboxState::VmCreated),
                (SandboxState::VmCreated, SandboxState::BootEvidenceChecked),
                (
                    SandboxState::BootEvidenceChecked,
                    SandboxState::AuthorityActive
                ),
                (SandboxState::AuthorityActive, SandboxState::Running),
            ]
        );
        for (index, record) in sandbox.log().iter().enumerate() {
            assert_eq!(record.sequence, index as u64 + 1);
            assert_eq!(record.presented, SandboxGenerations::FIRST);
            assert_eq!(record.generations, SandboxGenerations::FIRST);
        }
        assert_eq!(
            sandbox.authority(),
            Some(AuthorityGrant {
                epoch: AuthorizationEpoch::FIRST,
                clock: session(),
                expires_at: at(100)
            })
        );
    }

    #[test]
    fn transitions_are_idempotent_and_refuse_conflicts() {
        let mut sandbox = lifecycle();
        let first = step(
            &mut sandbox,
            SandboxStep::ReserveResources {
                reservation: reservation(),
            },
            1,
        );
        assert!(matches!(first, Applied::Advanced { .. }));
        let again = sandbox
            .apply(
                SandboxStep::ReserveResources {
                    reservation: reservation(),
                },
                SandboxGenerations::FIRST,
                at(9),
            )
            .unwrap();
        assert_eq!(
            again,
            Applied::AlreadyApplied {
                record: first.record().clone()
            }
        );
        assert_eq!(sandbox.log().len(), 1);
        assert_eq!(sandbox.state(), SandboxState::ResourcesReserved);

        let other = ReservationKey::derive(
            &ExecutionId::new("exe-other").unwrap(),
            &super::super::capacity::ReservationPurpose::Sandbox {
                boot: SandboxBootGeneration::FIRST,
            },
        );
        assert!(matches!(
            sandbox.apply(
                SandboxStep::ReserveResources { reservation: other },
                SandboxGenerations::FIRST,
                at(9)
            ),
            Err(TransitionRefusal::Conflict { .. })
        ));
        assert_eq!(
            sandbox.apply(SandboxStep::StartRunning, SandboxGenerations::FIRST, at(9)),
            Err(TransitionRefusal::InvalidTransition {
                from: SandboxState::ResourcesReserved,
                step: StepKind::StartRunning
            })
        );
    }

    #[test]
    fn stale_generations_are_refused_and_old_replays_stay_idempotent() {
        let mut sandbox = lifecycle();
        to_authority(&mut sandbox);
        let revoke = step(&mut sandbox, SandboxStep::Revoke, 10);
        assert_eq!(
            revoke.record().generations.authorization,
            AuthorizationEpoch::new(2)
        );
        assert_eq!(sandbox.authority(), None);
        let replay = sandbox
            .apply(SandboxStep::Revoke, SandboxGenerations::FIRST, at(11))
            .unwrap();
        assert!(matches!(replay, Applied::AlreadyApplied { .. }));
        assert_eq!(
            sandbox.generations().authorization,
            AuthorizationEpoch::new(2),
            "a replayed revocation advances the epoch only once"
        );
        assert_eq!(
            sandbox.apply(SandboxStep::Terminate, SandboxGenerations::FIRST, at(11)),
            Err(TransitionRefusal::StaleGeneration {
                presented: SandboxGenerations::FIRST,
                current: sandbox.generations()
            })
        );
    }

    #[test]
    fn readiness_must_be_host_observed_for_this_boot() {
        let mut sandbox = lifecycle();
        step(
            &mut sandbox,
            SandboxStep::ReserveResources {
                reservation: reservation(),
            },
            1,
        );
        step(
            &mut sandbox,
            SandboxStep::PreparePerimeter {
                perimeter: perimeter(),
            },
            2,
        );
        step(
            &mut sandbox,
            SandboxStep::CreateVm {
                vm: vm("a"),
                restored_from: None,
            },
            3,
        );
        let presented = sandbox.generations();
        for source in [
            SourceClass::GuestReport,
            SourceClass::ProviderApi,
            SourceClass::RecordedDeclaration,
            SourceClass::Fixture,
        ] {
            assert_eq!(
                sandbox.apply(
                    SandboxStep::CheckBootEvidence {
                        readiness: readiness(vm("a"), source, 3)
                    },
                    presented,
                    at(3)
                ),
                Err(TransitionRefusal::ReadinessNotHostObserved { source })
            );
        }
        assert!(matches!(
            sandbox.apply(
                SandboxStep::CheckBootEvidence {
                    readiness: readiness(vm("other"), SourceClass::HostProbe, 3)
                },
                presented,
                at(3)
            ),
            Err(TransitionRefusal::ReadinessForOtherBoot { .. })
        ));
        step(
            &mut sandbox,
            SandboxStep::CheckBootEvidence {
                readiness: readiness(vm("a"), SourceClass::HostProbe, 3),
            },
            3,
        );
        let presented = sandbox.generations();
        assert_eq!(
            sandbox.apply(
                SandboxStep::ActivateAuthority {
                    clock: session(),
                    expires_at: at(100),
                    readiness_max_age: Duration::from_secs(5),
                    settings: SettingsGrant::default(),
                },
                presented,
                at(9)
            ),
            Err(TransitionRefusal::ReadinessStale {
                age: Duration::from_secs(6),
                limit: Duration::from_secs(5)
            })
        );
        assert_eq!(
            sandbox.apply(
                SandboxStep::ActivateAuthority {
                    clock: session(),
                    expires_at: at(4),
                    readiness_max_age: Duration::from_secs(5),
                    settings: SettingsGrant::default(),
                },
                presented,
                at(4)
            ),
            Err(TransitionRefusal::AuthorityWouldBeExpired { expires_at: at(4) })
        );
    }

    #[test]
    fn a_restored_vm_needs_verification_before_boot_evidence() {
        let mut sandbox = lifecycle();
        let snapshot = SnapshotId::new(digest("yougori/test/snapshot/v1", &[b"golden"]));
        step(
            &mut sandbox,
            SandboxStep::ReserveResources {
                reservation: reservation(),
            },
            1,
        );
        step(
            &mut sandbox,
            SandboxStep::PreparePerimeter {
                perimeter: perimeter(),
            },
            2,
        );
        step(
            &mut sandbox,
            SandboxStep::CreateVm {
                vm: vm("restored"),
                restored_from: Some(snapshot),
            },
            3,
        );
        let presented = sandbox.generations();
        assert_eq!(
            sandbox.apply(
                SandboxStep::CheckBootEvidence {
                    readiness: readiness(vm("restored"), SourceClass::HostProbe, 3)
                },
                presented,
                at(3)
            ),
            Err(TransitionRefusal::RestoreNotVerified { vm: vm("restored") })
        );
    }

    #[test]
    fn each_generation_moves_only_by_its_own_step() {
        let mut sandbox = lifecycle();
        to_authority(&mut sandbox);
        step(&mut sandbox, SandboxStep::RaisePolicyEpoch, 6);
        assert_eq!(
            sandbox.generations(),
            SandboxGenerations {
                policy: PolicyEpoch::new(2),
                ..SandboxGenerations::FIRST
            }
        );
        assert_eq!(
            sandbox.authority().map(|grant| grant.epoch),
            Some(AuthorizationEpoch::FIRST),
            "a policy change does not refresh the authorization epoch"
        );
        step(&mut sandbox, SandboxStep::Reconcile, 7);
        assert_eq!(sandbox.state(), SandboxState::VmCreated);
        assert_eq!(sandbox.authority(), None);
        assert_eq!(sandbox.readiness(), None);
        assert_eq!(sandbox.generations().boot, SandboxBootGeneration::FIRST);
        assert_eq!(
            sandbox.generations().authorization,
            AuthorizationEpoch::new(2)
        );
        step(&mut sandbox, SandboxStep::Terminate, 8);
        step(&mut sandbox, SandboxStep::BeginCleanup, 8);
        step(&mut sandbox, SandboxStep::Stop, 8);
        step(
            &mut sandbox,
            SandboxStep::NewBoot {
                runtime: runtime("vm-2"),
            },
            9,
        );
        assert_eq!(sandbox.state(), SandboxState::Planned);
        assert_eq!(sandbox.runtime(), &runtime("vm-2"));
        assert_eq!(
            sandbox.generations(),
            SandboxGenerations {
                boot: SandboxBootGeneration::new(2),
                policy: PolicyEpoch::new(2),
                authorization: AuthorizationEpoch::new(3),
            }
        );
        assert_eq!(sandbox.vm(), None);
        assert!(sandbox.previous_vms().contains(&vm("a")));
        step(
            &mut sandbox,
            SandboxStep::ReserveResources {
                reservation: reservation(),
            },
            10,
        );
        step(
            &mut sandbox,
            SandboxStep::PreparePerimeter {
                perimeter: perimeter(),
            },
            10,
        );
        let presented = sandbox.generations();
        assert_eq!(
            sandbox.apply(
                SandboxStep::CreateVm {
                    vm: vm("a"),
                    restored_from: None
                },
                presented,
                at(10)
            ),
            Err(TransitionRefusal::VmIdentityReused { vm: vm("a") })
        );
    }

    #[test]
    fn an_exhausted_epoch_is_never_wrapped() {
        let mut sandbox = lifecycle();
        to_authority(&mut sandbox);
        sandbox.generations.authorization = AuthorizationEpoch::new(u64::MAX);
        if let Some(grant) = sandbox.authority.as_mut() {
            grant.epoch = AuthorizationEpoch::new(u64::MAX);
        }
        let presented = sandbox.generations();
        assert_eq!(
            sandbox.apply(SandboxStep::Revoke, presented, at(10)),
            Err(TransitionRefusal::GenerationExhausted {
                generation: GenerationName::Authorization
            })
        );
        assert_eq!(sandbox.state(), SandboxState::AuthorityActive);
    }
}
