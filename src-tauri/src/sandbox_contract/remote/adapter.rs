//! The remote-VM adapter state machine (VM-W39; VM part §6.2, §6.3, §7.6; VM-P40, VM-P42).
//!
//! ```text
//! planned → spend_reserved → provisioned → identity_enrolled → runtime_confirmed
//!         → running ⇄ (renewals) → authority_ended → terminating → terminated → closed
//! ```
//!
//! - Spend: before anything is provisioned, the most the run can cost
//!   ([`RemoteVmAdapter::max_cost_microunits`]) is reserved in V07's central spend ledger
//!   under the provisioning effect's identity. A provisioning call whose outcome is
//!   unknown leaves the whole reservation counted as spent; billing settles only from
//!   the provider's final bill, and a missing bill keeps it spent.
//! - Provider and isolation never change silently: the request names the selected
//!   offering's provider, region, offering and kind, and an instance that differs in any
//!   of them is refused and terminated. The adapter has no fallback region, provider or
//!   kind, and a failed attempt stays failed; another offering is another adapter.
//! - The runtime is admitted only on CORE-01 category evidence, through the request's
//!   own [`RuntimeRequirement`](crate::foundation::evidence::RuntimeRequirement); for a
//!   per-sandbox VM it must be the VM management launched, observed as a
//!   hardware-accelerated VM workload, never the host shell and never an emulated VM.
//! - Delegated authority stands on the host's CORE-04 coordinator ([`Delegation`]): for a
//!   remote VM, one service lease, child work of the parent VM sandbox; for a remote
//!   provider container, the coordinator's labelled-runtime record (VM-D5), never a lease
//!   or the VM sandbox lifecycle. The host sends the remote short grants over a live
//!   authenticated control session; the remote side can only ask. Loss of the control
//!   session stops new grants, so the delegation runs out; a reconnect is judged against
//!   the host's record and never revives authority that ended. A changed host key, shown
//!   to [`RemoteVmAdapter::connect`] or reported by management through
//!   [`RemoteVmAdapter::report_host_key_mismatch`], is recorded against the enrollment in
//!   [`KnownHosts`] and ends delegation at once (M16E); so do excessive clock skew and a
//!   remote claiming more time than it was granted. A stale identity is refused, so the
//!   remote gets no new grant and the delegation runs out.
//! - Termination is retried until the provider confirms it; cleanup never reports done
//!   without that confirmation, and spend stays reserved meanwhile. Each §6.3
//!   acknowledgment is a CORE-04 [`RevocationMilestone`], recorded separately; the
//!   provider's final bill is also acknowledged on the parent's revocation, when one is
//!   in progress, as `ProviderStoppedBilling` from the provider's API.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::attestation::{AttestationRecord, AttestationUse};
use super::control::{
    ControlBody, ControlRefusal, ControlSession, GrantRef, LeaseGrant, RemoteIdentity, SealedFrame,
};
use super::lease::HostAuthority;
use super::offering::{
    select_remote, OfferingKind, OfferingName, PriceProblem, RegionName, RemoteOffering,
    RemoteRequest, RemoteSelection, RemoteSelectionRefusal, VmPath,
};
use super::rejection::{HostKeyRejection, RejectionEvidence, RejectionObserver, RejectionRefusal};
use super::ssh::{
    EnrollmentEvidence, EnrollmentGeneration, EnrollmentPolicy, EnrollmentRefusal, HostKey,
    HostKeyRefusal, KnownHosts, RemoteCapabilityEvidence, RemoteEvidenceRefusal, RemoteHostId,
};
use crate::foundation::coordination::{
    CoordinationError, Lease, LeaseRefusal, LeaseTerms, RevocationMilestone, TermsProblem,
};
use crate::foundation::evidence::{
    AdmittedRuntime, AuthorityGrant, CategoryRefusal, ClockSession, ProviderKind, RuntimeOffer,
    SourceClass,
};
use crate::foundation::ids::{
    Clock, Digest, DigestBuilder, ExecutionCategory, ExecutionId, MonotonicTime, OperationId,
    SandboxBootGeneration,
};
use crate::sandbox_contract::effects::{AccountRef, EffectDescription, EffectId};
use crate::sandbox_contract::files::{
    ClockSkewPolicy, LifetimeRefusal, LocalExpiry, RemoteExpiry, RemoteObservation, SkewRefusal,
    WallClockGuard,
};
use crate::sandbox_contract::policy::SecurityPredicate;
use crate::sandbox_contract::provider::{SharedSpendLedger, SpendHold, SpendRefusal, SpendStatus};

/// One attempt to run one remote VM; also the provider idempotency key, so a retried or
/// uncertain provisioning call can be found again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AttemptId(Digest);

impl AttemptId {
    /// An attempt named by a caller-chosen digest, unique per run.
    pub const fn new(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(&self) -> &Digest {
        &self.0
    }
}

/// What the adapter asks the provider to create.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionRequest {
    pub attempt: AttemptId,
    pub provider: ProviderKind,
    pub region: RegionName,
    pub offering: OfferingName,
    pub kind: OfferingKind,
    pub account: AccountRef,
}

/// An instance the provider reports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderInstance {
    pub provider: ProviderKind,
    pub region: RegionName,
    pub offering: OfferingName,
    pub kind: OfferingKind,
    /// The digest of the provider's instance identity.
    pub instance: Digest,
}

impl ProviderInstance {
    /// The host identity SSH enrollment is keyed by.
    pub fn host(&self) -> RemoteHostId {
        RemoteHostId::of(self.provider, &self.region, &self.instance)
    }
}

/// A definite provider failure: the provider confirms nothing was done.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderError {
    RegionUnavailable,
    CapacityUnavailable,
    QuotaExceeded,
    Unauthorized,
    InvalidRequest,
    ProviderUnavailable,
}

/// Why an outcome is unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UncertainCause {
    Timeout,
    ConnectionLost,
    AmbiguousResponse,
}

strict_remote_enum! {
    /// How a provisioning call ended.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ProvisionOutcome tag "outcome" {
        Created { instance: ProviderInstance },
        /// The provider confirms nothing was created.
        NotCreated { error: ProviderError },
        /// Something may have been created.
        Unknown { cause: UncertainCause },
    }
}

strict_remote_enum! {
    /// How a termination call ended.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TerminationOutcome tag "outcome" {
        Confirmed,
        /// The provider confirms the instance no longer exists.
        AlreadyGone,
        Failed { error: ProviderError },
        Unknown { cause: UncertainCause },
    }
}

strict_remote_enum! {
    /// What a lookup by idempotency key found.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum LookupOutcome tag "outcome" {
        Found { instance: ProviderInstance },
        /// The provider confirms no instance exists for the key.
        ConfirmedAbsent,
        Unknown { cause: UncertainCause },
    }
}

strict_remote_enum! {
    /// The provider's final bill for an attempt.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum BillingReport tag "report" {
        /// Billing stopped; this is everything charged.
        Final { cost_microunits: u64 },
        Unavailable,
    }
}

/// The provider port (VM-W39). Tests use a fake; no provider is called here.
pub trait RemoteProviderPort {
    fn provision(&mut self, request: &ProvisionRequest) -> ProvisionOutcome;
    fn terminate(&mut self, instance: &ProviderInstance) -> TerminationOutcome;
    /// Finds whatever the provider created for `request`'s attempt, by its idempotency key.
    fn find(&mut self, request: &ProvisionRequest) -> LookupOutcome;
    fn final_bill(&mut self, attempt: &AttemptId) -> BillingReport;
}

strict_remote_enum! {
    /// A field in which the delivered instance differs from the request.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Substitution tag "field" {
        Provider { requested: ProviderKind, delivered: ProviderKind },
        Region { requested: RegionName, delivered: RegionName },
        Offering { requested: OfferingName, delivered: OfferingName },
        Kind { requested: OfferingKind, delivered: OfferingKind },
    }
}

fn substitution(request: &ProvisionRequest, instance: &ProviderInstance) -> Option<Substitution> {
    if instance.provider != request.provider {
        return Some(Substitution::Provider {
            requested: request.provider,
            delivered: instance.provider,
        });
    }
    if instance.region != request.region {
        return Some(Substitution::Region {
            requested: request.region.clone(),
            delivered: instance.region.clone(),
        });
    }
    if instance.offering != request.offering {
        return Some(Substitution::Offering {
            requested: request.offering.clone(),
            delivered: instance.offering.clone(),
        });
    }
    if instance.kind != request.kind {
        return Some(Substitution::Kind {
            requested: request.kind,
            delivered: instance.kind,
        });
    }
    None
}

/// The host authority a remote run's delegation stands on (CORE-04).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "delegation", rename_all = "snake_case")]
pub enum Delegation {
    /// A remote VM: a service lease, child work of the parent VM sandbox, as last issued
    /// or renewed.
    Lease { lease: Lease },
    /// A remote provider container: the labelled runtime's authority record (VM-D5),
    /// bound to the grant in force at launch. A later grant, such as one made after this
    /// one expired, is never adopted.
    Labelled { grant: AuthorityGrant },
}

impl Delegation {
    /// The authority as the remote names it.
    pub fn grant_ref(&self) -> GrantRef {
        match self {
            Self::Lease { lease } => GrantRef::Lease { lease: lease.id() },
            Self::Labelled { grant } => GrantRef::Labelled { epoch: grant.epoch },
        }
    }

    /// The host clock session its times are points on.
    pub fn clock(&self) -> ClockSession {
        match self {
            Self::Lease { lease } => lease.clock(),
            Self::Labelled { grant } => grant.clock,
        }
    }

    /// When the host's authority ends unless renewed.
    pub fn expires_at(&self) -> MonotonicTime {
        match self {
            Self::Lease { lease } => lease.expires_at(),
            Self::Labelled { grant } => grant.expires_at,
        }
    }
}

/// Why delegated authority ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum AuthorityEnd {
    /// The host's lease is no longer honoured: expired, cancelled, revoked or stale.
    LeaseRefused { refusal: LifetimeRefusal },
    /// The labelled runtime's grant is no longer honoured: expired, revoked or from
    /// another clock session.
    LabelledRefused { refusal: LeaseRefusal },
    /// The labelled runtime's record holds another grant than the one this run is bound
    /// to; it is not adopted.
    GrantReplaced,
    /// The remote's view of its lease failed the clock-skew policy (§6.2).
    SkewRefused { refusal: SkewRefusal },
    /// The remote claimed a later expiry than it was granted.
    RemoteClaimedLongerLease,
    /// The host presented another key than the one enrolled under `generation`, as
    /// `observer` saw it; the rejection is recorded in [`KnownHosts`] (M16E).
    HostKeyRejected {
        host: RemoteHostId,
        generation: EnrollmentGeneration,
        observer: RejectionObserver,
    },
    /// The host stopped the run.
    Stopped,
}

strict_remote_enum! {
    /// How billing ended.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum BillingOutcome tag "billing" {
        /// Charged from the provider's final bill, or nothing for a definite failure.
        Settled { charged_microunits: u64 },
        /// No final bill: the whole reservation stays counted as spent until reconciled.
        Uncertain { held_microunits: u64 },
        /// Nothing was dispatched; the reservation was returned.
        Released { returned_microunits: u64 },
        /// Only the attached VM was stopped. The existing host's billing belongs
        /// to its owner; no price, settlement or stopped-billing claim is made.
        ExternallyManaged,
    }
}

/// Where the adapter is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AdapterState {
    Planned,
    SpendReserved,
    Provisioned,
    IdentityEnrolled,
    RuntimeConfirmed,
    Running,
    AuthorityEnded {
        reason: AuthorityEnd,
    },
    /// Cleanup retries until the provider confirms termination.
    Terminating,
    Terminated,
    Closed {
        billing: BillingOutcome,
    },
    /// The provider confirmed nothing was created.
    Failed {
        error: ProviderError,
    },
    /// Stopped before anything was provisioned.
    Cancelled,
}

/// One adapter step, for refusals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterStep {
    ReserveSpend,
    Provision,
    Enroll,
    ConfirmRuntime,
    Connect,
    Launch,
    Renew,
    HandleFrame,
    ObserveStatus,
    CheckAuthority,
    ReportHostKeyMismatch,
    BeginTermination,
    TerminateStep,
    SettleBilling,
    Cancel,
}

/// One state the adapter entered, and when.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TransitionEntry {
    pub at: MonotonicTime,
    pub state: AdapterState,
}

/// What a confidential launch requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfidentialLaunch {
    /// The workload the attestation must be bound to.
    pub workload: Digest,
    /// How old an accepted attestation may be at launch.
    pub max_record_age_seconds: u64,
}

/// How the adapter runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterConfig {
    /// The delegated lease: each grant lasts one term, never past the maximum lifetime
    /// or the parent's authority.
    pub terms: LeaseTerms,
    /// Renewals need an authenticated frame from the remote within this silence.
    pub max_control_silence: Duration,
    pub skew: ClockSkewPolicy,
    /// Billable time allowed for termination beyond the lease's maximum lifetime.
    pub termination_allowance_seconds: u64,
    /// Cleanup asks for an operator after this many unconfirmed attempts; it never stops.
    pub escalate_after_attempts: u32,
    pub enrollment: EnrollmentPolicy,
    /// Present for a confidential profile: launch then needs an accepted attestation.
    pub confidential: Option<ConfidentialLaunch>,
}

strict_remote_enum! {
    /// Why a cleanup attempt did not confirm termination.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum CleanupFailure tag "failure" {
        Termination { error: ProviderError },
        TerminationUnknown { cause: UncertainCause },
        LookupUnknown { cause: UncertainCause },
    }
}

/// Where cleanup stands after one attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "cleanup", rename_all = "snake_case")]
pub enum CleanupStatus {
    /// The provider confirmed termination, or that nothing exists.
    Confirmed { attempts: u32 },
    /// Not confirmed; retry. Spend stays reserved.
    Retrying {
        attempts: u32,
        needs_operator: bool,
        last: CleanupFailure,
    },
}

/// What an inbound control frame did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameOutcome {
    Heard,
    /// The host renewed the delegation; send the grant.
    Renewed {
        grant: SealedFrame,
    },
    /// The remote stated its view of its lease; judge it with
    /// [`RemoteVmAdapter::observe_remote_expiry`].
    StatusReported {
        expiry: RemoteExpiry,
    },
}

/// Why an adapter step was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AdapterRefusal {
    /// No offering qualifies; nothing was provisioned (VM-P42).
    NoQualifyingOffering {
        refusal: RemoteSelectionRefusal,
    },
    InvalidTerms {
        problem: TermsProblem,
    },
    /// An existing host is never provisioned, billed or terminated by this adapter.
    ExternallyManagedHost,
    InvalidStep {
        state: AdapterState,
        step: AdapterStep,
    },
    /// A record the state implies is missing.
    Inconsistent {
        missing: &'static str,
    },
    Price {
        problem: PriceProblem,
    },
    WrongAccount {
        expected: AccountRef,
        described: AccountRef,
    },
    CostCeilingTooLow {
        required_microunits: u64,
        ceiling_microunits: u64,
    },
    Spend {
        refusal: SpendRefusal,
    },
    ProvisionFailed {
        error: ProviderError,
    },
    /// The outcome is unknown: the reservation counts as spent and cleanup runs.
    ProvisionUncertain {
        cause: UncertainCause,
    },
    /// The provider delivered something else; it is being terminated.
    Substituted {
        substitution: Substitution,
    },
    Category {
        refusal: CategoryRefusal,
    },
    IsolationChanged {
        planned: ExecutionCategory,
        observed: ExecutionCategory,
    },
    PerSandboxVmEvidenceMissing,
    EvidenceForAnotherIdentity,
    ManagementEvidence {
        refusal: RemoteEvidenceRefusal,
    },
    InstanceMismatch {
        expected: Digest,
        observed: Digest,
    },
    Enrollment {
        refusal: EnrollmentRefusal,
    },
    HostKey {
        refusal: HostKeyRefusal,
    },
    /// Management's host-key mismatch was not recorded: the run's enrollment is no
    /// longer the host's current one. Delegated authority still ended.
    RejectionNotRecorded {
        refusal: RejectionRefusal,
    },
    StaleIdentity,
    NoControlSession,
    ControlNotLive {
        silent_for_nanos: u64,
    },
    Control {
        refusal: ControlRefusal,
    },
    UnexpectedFrame,
    /// The remote named another authority than this run's delegation.
    ForeignAuthority {
        presented: GrantRef,
    },
    Authority {
        refusal: LifetimeRefusal,
    },
    /// The labelled runtime's authority record refused (VM-D5).
    Labelled {
        refusal: LeaseRefusal,
    },
    /// The labelled record is for another runtime than the one admitted for this run.
    LabelledRecordForAnotherRuntime,
    /// The labelled record now holds another grant than the one this run is bound to.
    LabelledGrantReplaced {
        bound: AuthorityGrant,
        current: AuthorityGrant,
    },
    /// The coordinator refused to record an acknowledgment.
    Coordination {
        error: CoordinationError,
    },
    Skew {
        refusal: SkewRefusal,
    },
    UnknownRight,
    RemoteClaimsLongerLease {
        claimed: MonotonicTime,
        limit: MonotonicTime,
    },
    AttestationRequired,
    AttestationNotUsable {
        reason: AttestationUse,
    },
}

impl fmt::Display for AdapterRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoQualifyingOffering { refusal } => write!(f, "{refusal}"),
            Self::InvalidTerms { problem } => write!(f, "invalid lease terms: {problem:?}"),
            Self::ExternallyManagedHost => f.write_str(
                "this SSH host is externally managed; only this run's VM may be stopped",
            ),
            Self::InvalidStep { state, step } => {
                write!(f, "{step:?} is not possible in state {state:?}")
            }
            Self::Inconsistent { missing } => write!(f, "the adapter has no {missing}"),
            Self::Price { problem } => write!(f, "{problem}"),
            Self::WrongAccount { .. } => {
                f.write_str("the effect is charged to another account than the offering's")
            }
            Self::CostCeilingTooLow {
                required_microunits,
                ceiling_microunits,
            } => write!(
                f,
                "the run can cost {required_microunits} microunits; the approved ceiling is \
                 {ceiling_microunits}"
            ),
            Self::Spend { refusal } => write!(f, "{refusal}"),
            Self::ProvisionFailed { error } => write!(f, "the provider refused: {error:?}"),
            Self::ProvisionUncertain { cause } => write!(
                f,
                "provisioning outcome unknown ({cause:?}); counted as spent, cleanup runs"
            ),
            Self::Substituted { substitution } => write!(
                f,
                "the provider delivered something else ({substitution:?}); it is refused and \
                 terminated"
            ),
            Self::Category { refusal } => write!(f, "{refusal}"),
            Self::IsolationChanged { planned, observed } => write!(
                f,
                "planned \"{}\" but the evidence shows \"{}\"",
                planned.label(),
                observed.label()
            ),
            Self::PerSandboxVmEvidenceMissing => {
                f.write_str("a per-sandbox VM needs management evidence of the VM workload itself")
            }
            Self::EvidenceForAnotherIdentity => {
                f.write_str("the evidence was observed under another enrollment or host")
            }
            Self::ManagementEvidence { refusal } => write!(f, "{refusal}"),
            Self::InstanceMismatch { .. } => {
                f.write_str("the evidence is about another runtime instance")
            }
            Self::Enrollment { refusal } => write!(f, "{refusal}"),
            Self::HostKey { refusal } => write!(f, "{refusal}"),
            Self::RejectionNotRecorded { refusal } => write!(f, "{refusal}"),
            Self::StaleIdentity => f.write_str("the remote presented a stale identity"),
            Self::NoControlSession => f.write_str("no control session is open"),
            Self::ControlNotLive { .. } => {
                f.write_str("the control session is lost or silent; nothing is renewed")
            }
            Self::Control { refusal } => write!(f, "{refusal}"),
            Self::UnexpectedFrame => f.write_str("the remote sent a frame only the host sends"),
            Self::ForeignAuthority { presented } => {
                write!(f, "{presented:?} is not this run's delegation")
            }
            Self::Authority { refusal } => write!(f, "{refusal}"),
            Self::Labelled { refusal } => write!(f, "{refusal}"),
            Self::LabelledRecordForAnotherRuntime => f.write_str(
                "the labelled runtime's authority record is for another runtime than this run's",
            ),
            Self::LabelledGrantReplaced { .. } => f.write_str(
                "the labelled runtime holds another grant than this run's; it is not adopted",
            ),
            Self::Coordination { error } => write!(f, "{error}"),
            Self::Skew { refusal } => write!(f, "{refusal}"),
            Self::UnknownRight => f.write_str("the remote reported another right than its lease"),
            Self::RemoteClaimsLongerLease { .. } => {
                f.write_str("the remote claims a later expiry than it was granted")
            }
            Self::AttestationRequired => {
                f.write_str("a confidential launch needs an accepted attestation")
            }
            Self::AttestationNotUsable { reason } => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for AdapterRefusal {}

/// Where the provisioning effect's reservation is in V07's ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
enum SpendPhase {
    Reserved,
    InFlight,
    Unknown,
    Settled { charged_microunits: u64 },
    Released { returned_microunits: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct SpendBinding {
    effect: EffectId,
    reserved_microunits: u64,
    phase: SpendPhase,
}

/// The remote-VM adapter; see the module notes. `clock` must be the host clock the
/// coordinator reads.
pub struct RemoteVmAdapter<C: Clock> {
    clock: C,
    attempt: AttemptId,
    /// For a remote VM, the parent VM sandbox its lease is child work of; for a provider
    /// container, the labelled runtime's own execution (VM-D5).
    execution: ExecutionId,
    selection: RemoteSelection,
    config: AdapterConfig,
    state: AdapterState,
    spend: Option<SpendBinding>,
    instance: Option<ProviderInstance>,
    identity: Option<RemoteIdentity>,
    runtime: Option<AdmittedRuntime>,
    control: Option<ControlSession>,
    delegation: Option<Delegation>,
    last_grant: Option<(MonotonicTime, LeaseGrant)>,
    cleanup_attempts: u32,
    acknowledgments: BTreeMap<RevocationMilestone, MonotonicTime>,
    history: Vec<TransitionEntry>,
}

fn ceil_seconds(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() > 0))
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

impl<C: Clock> RemoteVmAdapter<C> {
    /// Attach an explicitly selected, existing SSH host without reserving money
    /// or calling a provisioning API. Enrollment and VM evidence are still
    /// required before any delegation. The host itself is never owned by this run.
    pub fn attach_existing(&mut self, host: ProviderInstance) -> Result<(), AdapterRefusal> {
        if self.state != AdapterState::Planned {
            return Err(self.refuse(AdapterStep::Provision));
        }
        if !self.externally_managed() {
            return Err(AdapterRefusal::ExternallyManagedHost);
        }
        if let Some(substitution) = substitution(&self.provision_request(), &host) {
            return Err(AdapterRefusal::Substituted { substitution });
        }
        self.instance = Some(host);
        self.set_state(AdapterState::Provisioned);
        Ok(())
    }

    pub fn externally_managed(&self) -> bool {
        self.selection.offering().provider == ProviderKind::ExistingSsh
    }

    /// Complete cleanup only after authenticated management has observed the
    /// exact admitted workload gone under this same enrollment. A channel loss,
    /// local lease expiry or a host-shell report alone is not that observation.
    /// This does not stop the host or settle its externally managed bill.
    pub fn confirm_attached_workload_stopped(
        &mut self,
        identity: &RemoteIdentity,
        workload: Digest,
    ) -> Result<(), AdapterRefusal> {
        if !self.externally_managed() {
            return Err(AdapterRefusal::ExternallyManagedHost);
        }
        if self.state != AdapterState::Terminating {
            return Err(self.refuse(AdapterStep::TerminateStep));
        }
        if self.identity.as_ref() != Some(identity) {
            return Err(AdapterRefusal::EvidenceForAnotherIdentity);
        }
        let expected = self
            .runtime
            .as_ref()
            .ok_or(AdapterRefusal::Inconsistent {
                missing: "admitted attached workload",
            })?
            .runtime()
            .instance;
        if workload != expected {
            return Err(AdapterRefusal::InstanceMismatch {
                expected,
                observed: workload,
            });
        }
        self.cleanup_attempts = self.cleanup_attempts.saturating_add(1);
        self.terminated();
        self.set_state(AdapterState::Closed {
            billing: BillingOutcome::ExternallyManaged,
        });
        Ok(())
    }

    /// Selects an offering for `request` and plans the run under `execution` (see
    /// [`RemoteVmAdapter::execution`]). With no qualifying offering nothing exists to
    /// provision (VM-P42).
    pub fn plan(
        clock: C,
        attempt: AttemptId,
        execution: ExecutionId,
        request: &RemoteRequest,
        offerings: &[RemoteOffering],
        config: AdapterConfig,
    ) -> Result<Self, AdapterRefusal> {
        let selection = select_remote(request, offerings)
            .map_err(|refusal| AdapterRefusal::NoQualifyingOffering { refusal })?;
        Self::from_selection(clock, attempt, execution, selection, config)
    }

    /// Plans the run on an offering already selected by [`select_remote`]; refuses lease
    /// terms CORE-04 would refuse.
    pub fn from_selection(
        clock: C,
        attempt: AttemptId,
        execution: ExecutionId,
        selection: RemoteSelection,
        config: AdapterConfig,
    ) -> Result<Self, AdapterRefusal> {
        config
            .terms
            .check()
            .map_err(|problem| AdapterRefusal::InvalidTerms { problem })?;
        let now = clock.now();
        Ok(Self {
            clock,
            attempt,
            execution,
            selection,
            config,
            state: AdapterState::Planned,
            spend: None,
            instance: None,
            identity: None,
            runtime: None,
            control: None,
            delegation: None,
            last_grant: None,
            cleanup_attempts: 0,
            acknowledgments: BTreeMap::new(),
            history: vec![TransitionEntry {
                at: now,
                state: AdapterState::Planned,
            }],
        })
    }

    /// Where the adapter is.
    pub fn state(&self) -> &AdapterState {
        &self.state
    }

    pub fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// For a remote VM, the parent VM sandbox its lease is child work of; for a provider
    /// container, the labelled runtime's own execution (VM-D5).
    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    /// The offering selected, with its category, label and the offerings passed over.
    pub fn selection(&self) -> &RemoteSelection {
        &self.selection
    }

    /// The provider instance, once one exists or was found by idempotency key.
    pub fn instance(&self) -> Option<&ProviderInstance> {
        self.instance.as_ref()
    }

    /// The enrolled remote identity.
    pub fn identity(&self) -> Option<&RemoteIdentity> {
        self.identity.as_ref()
    }

    /// The runtime CORE-01 admitted under the request's requirement.
    pub fn runtime(&self) -> Option<&AdmittedRuntime> {
        self.runtime.as_ref()
    }

    /// The current control session, live or not.
    pub fn control(&self) -> Option<&ControlSession> {
        self.control.as_ref()
    }

    /// The host authority the delegation stands on.
    pub fn delegation(&self) -> Option<&Delegation> {
        self.delegation.as_ref()
    }

    /// The delegated CORE-04 lease as last issued or renewed, for a remote VM.
    pub fn lease(&self) -> Option<&Lease> {
        match &self.delegation {
            Some(Delegation::Lease { lease }) => Some(lease),
            Some(Delegation::Labelled { .. }) | None => None,
        }
    }

    /// The last grant sent, with when it was sent on the host clock.
    pub fn last_grant(&self) -> Option<(MonotonicTime, LeaseGrant)> {
        self.last_grant
    }

    /// Cleanup attempts made so far.
    pub fn cleanup_attempts(&self) -> u32 {
        self.cleanup_attempts
    }

    /// Each §6.3 acknowledgment reached, with when; none implies another.
    pub fn acknowledgments(&self) -> &BTreeMap<RevocationMilestone, MonotonicTime> {
        &self.acknowledgments
    }

    /// Every state entered, in order, with when.
    pub fn history(&self) -> &[TransitionEntry] {
        &self.history
    }

    /// Whether the adapter may hold provider resources that need terminating.
    pub fn needs_cleanup(&self) -> bool {
        matches!(
            self.state,
            AdapterState::Provisioned
                | AdapterState::IdentityEnrolled
                | AdapterState::RuntimeConfirmed
                | AdapterState::Running
                | AdapterState::AuthorityEnded { .. }
                | AdapterState::Terminating
        )
    }

    fn set_state(&mut self, state: AdapterState) {
        let at = self.clock.now();
        self.history.push(TransitionEntry {
            at,
            state: state.clone(),
        });
        self.state = state;
    }

    fn acknowledge(&mut self, milestone: RevocationMilestone) {
        let at = self.clock.now();
        self.acknowledgments.entry(milestone).or_insert(at);
    }

    fn refuse(&self, step: AdapterStep) -> AdapterRefusal {
        AdapterRefusal::InvalidStep {
            state: self.state.clone(),
            step,
        }
    }

    /// The most the run can cost: the offering's price over the lease's maximum lifetime
    /// plus the termination allowance, rounded as [`OfferingPrice::max_cost_microunits`]
    /// rounds.
    ///
    /// [`OfferingPrice::max_cost_microunits`]: super::offering::OfferingPrice::max_cost_microunits
    pub fn max_cost_microunits(&self) -> Result<u64, AdapterRefusal> {
        if self.externally_managed() {
            return Err(AdapterRefusal::ExternallyManagedHost);
        }
        let runtime_seconds = ceil_seconds(self.config.terms.max_lifetime)
            .checked_add(self.config.termination_allowance_seconds)
            .ok_or(AdapterRefusal::Price {
                problem: PriceProblem::Overflow,
            })?;
        self.selection
            .offering()
            .price
            .ok_or(AdapterRefusal::Inconsistent {
                missing: "managed offering price",
            })?
            .max_cost_microunits(runtime_seconds)
            .map_err(|problem| AdapterRefusal::Price { problem })
    }

    /// Reserves the run's maximum cost against the offering's account under the
    /// provisioning effect's identity. The effect's approved cost ceiling must cover it.
    pub fn reserve_spend(
        &mut self,
        ledger: &SharedSpendLedger,
        description: &EffectDescription,
    ) -> Result<SpendHold, AdapterRefusal> {
        if self.externally_managed() {
            return Err(AdapterRefusal::ExternallyManagedHost);
        }
        if self.state != AdapterState::Planned {
            return Err(self.refuse(AdapterStep::ReserveSpend));
        }
        let account = self.selection.offering().account;
        let described = description.resource().account;
        if described != account {
            return Err(AdapterRefusal::WrongAccount {
                expected: account,
                described,
            });
        }
        let required = self.max_cost_microunits()?;
        let ceiling = description.max_cost().max_spend_microunits;
        if ceiling < required {
            return Err(AdapterRefusal::CostCeilingTooLow {
                required_microunits: required,
                ceiling_microunits: ceiling,
            });
        }
        let effect = description.id();
        let hold = ledger
            .with(|book| book.reserve(effect, account, required))
            .map_err(|refusal| AdapterRefusal::Spend { refusal })?;
        self.spend = Some(SpendBinding {
            effect,
            reserved_microunits: required,
            phase: SpendPhase::Reserved,
        });
        self.set_state(AdapterState::SpendReserved);
        Ok(hold)
    }

    /// The provisioning request: exactly the selected offering, keyed by the attempt.
    pub fn provision_request(&self) -> ProvisionRequest {
        let offering = self.selection.offering();
        ProvisionRequest {
            attempt: self.attempt,
            provider: offering.provider,
            region: offering.region.clone(),
            offering: offering.offering.clone(),
            kind: offering.kind,
            account: offering.account,
        }
    }

    /// Dispatches provisioning against the reservation. A definite failure returns the
    /// reservation less anything reported; an unknown outcome counts it all as spent and
    /// starts cleanup; a substituted instance is refused and terminated.
    pub fn provision(
        &mut self,
        provider: &mut dyn RemoteProviderPort,
        ledger: &SharedSpendLedger,
    ) -> Result<ProviderInstance, AdapterRefusal> {
        if self.externally_managed() {
            return Err(AdapterRefusal::ExternallyManagedHost);
        }
        if self.state != AdapterState::SpendReserved {
            return Err(self.refuse(AdapterStep::Provision));
        }
        let spend = self.spend.ok_or(AdapterRefusal::Inconsistent {
            missing: "spend reservation",
        })?;
        ledger
            .with(|book| book.consume(&spend.effect, spend.reserved_microunits))
            .map_err(|refusal| AdapterRefusal::Spend { refusal })?;
        self.set_spend_phase(SpendPhase::InFlight);
        let request = self.provision_request();
        match provider.provision(&request) {
            ProvisionOutcome::Created { instance } => {
                let substituted = substitution(&request, &instance);
                self.instance = Some(instance.clone());
                if let Some(substitution) = substituted {
                    self.set_state(AdapterState::Terminating);
                    return Err(AdapterRefusal::Substituted { substitution });
                }
                self.set_state(AdapterState::Provisioned);
                Ok(instance)
            }
            ProvisionOutcome::NotCreated { error } => {
                let _ = self.settle_spend(ledger, SpendStatus::NotCommitted, None);
                self.set_state(AdapterState::Failed { error });
                Err(AdapterRefusal::ProvisionFailed { error })
            }
            ProvisionOutcome::Unknown { cause } => {
                let _ = self.settle_spend(ledger, SpendStatus::Unknown, None);
                self.set_state(AdapterState::Terminating);
                Err(AdapterRefusal::ProvisionUncertain { cause })
            }
        }
    }

    fn set_spend_phase(&mut self, phase: SpendPhase) {
        if let Some(spend) = self.spend.as_mut() {
            spend.phase = phase;
        }
    }

    /// Moves the reservation by `status`. An in-flight hold settles; an unknown one is
    /// reconciled only to a definite outcome and otherwise stays counted as spent.
    fn settle_spend(
        &mut self,
        ledger: &SharedSpendLedger,
        status: SpendStatus,
        reported_microunits: Option<u64>,
    ) -> Result<BillingOutcome, AdapterRefusal> {
        let spend = self.spend.ok_or(AdapterRefusal::Inconsistent {
            missing: "spend reservation",
        })?;
        let outcome = match (spend.phase, status) {
            (SpendPhase::Settled { charged_microunits }, _) => {
                BillingOutcome::Settled { charged_microunits }
            }
            (
                SpendPhase::Released {
                    returned_microunits,
                },
                _,
            ) => BillingOutcome::Released {
                returned_microunits,
            },
            (SpendPhase::Reserved, _) => {
                let returned = ledger
                    .with(|book| book.release(&spend.effect))
                    .map_err(|refusal| AdapterRefusal::Spend { refusal })?;
                self.set_spend_phase(SpendPhase::Released {
                    returned_microunits: returned,
                });
                BillingOutcome::Released {
                    returned_microunits: returned,
                }
            }
            (SpendPhase::Unknown, SpendStatus::Unknown) => BillingOutcome::Uncertain {
                held_microunits: spend.reserved_microunits,
            },
            (SpendPhase::InFlight, SpendStatus::Unknown) => {
                ledger
                    .with(|book| book.settle(&spend.effect, SpendStatus::Unknown, None))
                    .map_err(|refusal| AdapterRefusal::Spend { refusal })?;
                self.set_spend_phase(SpendPhase::Unknown);
                BillingOutcome::Uncertain {
                    held_microunits: spend.reserved_microunits,
                }
            }
            (SpendPhase::InFlight, status) => {
                let settlement = ledger
                    .with(|book| book.settle(&spend.effect, status, reported_microunits))
                    .map_err(|refusal| AdapterRefusal::Spend { refusal })?;
                self.set_spend_phase(SpendPhase::Settled {
                    charged_microunits: settlement.charged_microunits,
                });
                BillingOutcome::Settled {
                    charged_microunits: settlement.charged_microunits,
                }
            }
            (SpendPhase::Unknown, status) => {
                let settlement = ledger
                    .with(|book| book.reconcile(&spend.effect, status, reported_microunits))
                    .map_err(|refusal| AdapterRefusal::Spend { refusal })?;
                self.set_spend_phase(SpendPhase::Settled {
                    charged_microunits: settlement.charged_microunits,
                });
                BillingOutcome::Settled {
                    charged_microunits: settlement.charged_microunits,
                }
            }
        };
        Ok(outcome)
    }

    /// Enrolls the instance's host key through a supported flow (§7.6).
    pub fn enroll(
        &mut self,
        known: &mut KnownHosts,
        presented: &HostKey,
        evidence: EnrollmentEvidence,
    ) -> Result<RemoteIdentity, AdapterRefusal> {
        if self.state != AdapterState::Provisioned {
            return Err(self.refuse(AdapterStep::Enroll));
        }
        let host = self
            .instance
            .as_ref()
            .ok_or(AdapterRefusal::Inconsistent {
                missing: "instance",
            })?
            .host();
        let now = self.clock.now();
        let enrollment = known
            .enroll(host, presented, evidence, self.config.enrollment, now)
            .map_err(|refusal| AdapterRefusal::Enrollment { refusal })?;
        let identity = RemoteIdentity::from_enrollment(&enrollment);
        self.identity = Some(identity.clone());
        self.set_state(AdapterState::IdentityEnrolled);
        Ok(identity)
    }

    /// Reuse the engine's already-enrolled shared host authority. This never
    /// enrolls, replaces or forgives a host key and does not copy its rejection book.
    pub fn adopt_enrollment(
        &mut self,
        known: &KnownHosts,
        presented: &HostKey,
    ) -> Result<RemoteIdentity, AdapterRefusal> {
        if self.state != AdapterState::Provisioned {
            return Err(self.refuse(AdapterStep::Enroll));
        }
        let host = self
            .instance
            .as_ref()
            .ok_or(AdapterRefusal::Inconsistent {
                missing: "instance",
            })?
            .host();
        let enrollment = known
            .verify(&host, presented)
            .map_err(|refusal| AdapterRefusal::HostKey { refusal })?;
        let identity = RemoteIdentity::from_enrollment(enrollment);
        self.identity = Some(identity.clone());
        self.set_state(AdapterState::IdentityEnrolled);
        Ok(identity)
    }

    /// Admits the runtime on CORE-01 category evidence under the request's requirement.
    /// For a per-sandbox VM, `management` must show the VM workload itself, hardware
    /// accelerated, under the current enrollment; the CORE-01 evidence must then be about
    /// that VM. A refused category, a changed one or an emulated VM starts termination.
    pub fn confirm_runtime(
        &mut self,
        offer: &RuntimeOffer,
        management: Option<&RemoteCapabilityEvidence>,
    ) -> Result<AdmittedRuntime, AdapterRefusal> {
        if self.state != AdapterState::IdentityEnrolled {
            return Err(self.refuse(AdapterStep::ConfirmRuntime));
        }
        let instance = self
            .instance
            .as_ref()
            .ok_or(AdapterRefusal::Inconsistent {
                missing: "instance",
            })?
            .instance;
        let identity = self.identity.clone().ok_or(AdapterRefusal::Inconsistent {
            missing: "identity",
        })?;
        let admitted = match self.selection.requirement().admit(offer) {
            Ok(admitted) => admitted,
            Err(refusal) => {
                self.set_state(AdapterState::Terminating);
                return Err(AdapterRefusal::Category { refusal });
            }
        };
        let planned = self.selection.category();
        if admitted.category() != planned {
            self.set_state(AdapterState::Terminating);
            return Err(AdapterRefusal::IsolationChanged {
                planned,
                observed: admitted.category(),
            });
        }
        let expected = match self.selection.vm_path() {
            Some(VmPath::PerSandboxVm) => {
                let evidence = management.ok_or(AdapterRefusal::PerSandboxVmEvidenceMissing)?;
                if evidence.context.host() != identity.host
                    || evidence.enrollment != identity.enrollment
                {
                    return Err(AdapterRefusal::EvidenceForAnotherIdentity);
                }
                match evidence.supports(SecurityPredicate::VmSandbox) {
                    Ok(workload) => workload.instance(),
                    Err(refusal @ RemoteEvidenceRefusal::EmulatedVm { .. }) => {
                        self.set_state(AdapterState::Terminating);
                        return Err(AdapterRefusal::ManagementEvidence { refusal });
                    }
                    Err(refusal) => return Err(AdapterRefusal::ManagementEvidence { refusal }),
                }
            }
            Some(VmPath::ProviderVm) | None => instance,
        };
        let observed = admitted.runtime().instance;
        if observed != expected {
            return Err(AdapterRefusal::InstanceMismatch { expected, observed });
        }
        self.runtime = Some(admitted.clone());
        self.set_state(AdapterState::RuntimeConfirmed);
        Ok(admitted)
    }

    /// Installs a control session after checking the presented host key against the
    /// enrollment. A key other than the enrolled one, or any key once this run's
    /// enrollment was rejected, is refused, recorded against the enrollment in `known` and
    /// ends delegated authority at once (VM-W41, M16E); against a host enrolled again
    /// since, the identity is stale, nothing is recorded and the refusal changes nothing.
    /// While running, the host's authority is checked next: a reconnect never revives
    /// authority that ended.
    pub fn connect(
        &mut self,
        known: &KnownHosts,
        presented: &HostKey,
        session: ControlSession,
        authority: &mut dyn HostAuthority,
    ) -> Result<(), AdapterRefusal> {
        if !matches!(
            self.state,
            AdapterState::RuntimeConfirmed | AdapterState::Running
        ) {
            return Err(self.refuse(AdapterStep::Connect));
        }
        let identity = self.identity.clone().ok_or(AdapterRefusal::Inconsistent {
            missing: "identity",
        })?;
        let enrollment = match known.verify(&identity.host, presented) {
            Ok(enrollment) => enrollment,
            Err(refusal) => {
                if matches!(
                    refusal,
                    HostKeyRefusal::Changed { .. } | HostKeyRefusal::Rejected { .. }
                ) {
                    let recorded = known.record_rejection(
                        &identity.host,
                        identity.enrollment,
                        RejectionObserver::ControlConnect,
                        RejectionEvidence::PresentedKey {
                            presented: presented.fingerprint(),
                        },
                        self.clock.now(),
                    );
                    if let Ok(rejection) = recorded {
                        self.end_for_rejected_key(
                            authority,
                            rejection.host(),
                            rejection.generation(),
                            rejection.observer,
                        );
                    }
                }
                return Err(AdapterRefusal::HostKey { refusal });
            }
        };
        if RemoteIdentity::from_enrollment(enrollment).digest() != identity.digest()
            || session.identity().digest() != identity.digest()
        {
            return Err(AdapterRefusal::StaleIdentity);
        }
        if self.state == AdapterState::Running {
            self.check_delegation(authority)?;
        }
        let now = self.clock.now();
        if let Some(old) = self.control.as_mut() {
            old.close(now);
        }
        self.control = Some(session);
        Ok(())
    }

    /// The control session is gone; renewals stop until a reconnect.
    pub fn connection_lost(&mut self) {
        let now = self.clock.now();
        if let Some(control) = self.control.as_mut() {
            control.mark_lost(now);
        }
    }

    /// Management's SSH client met another host key than the enrolled one (VM-W41,
    /// M16E), with `evidence` of what it was shown. Records the rejection of this run's
    /// enrollment in `known` and ends delegated authority at once, as
    /// [`RemoteVmAdapter::connect`] does for a changed key; termination and billing then
    /// proceed as for any ended authority. Once authority has ended it only records.
    /// Returns the rejection, or the first one recorded for the enrollment. If the host
    /// was retired or enrolled again since, nothing is recorded, and authority still
    /// ends, because the client was checking this run's enrolled key. A genuine loss of
    /// the control connection is [`RemoteVmAdapter::connection_lost`].
    // Every adapter step returns `AdapterRefusal` unboxed; boxing it would change them all.
    #[allow(clippy::result_large_err)]
    pub fn report_host_key_mismatch(
        &mut self,
        known: &KnownHosts,
        authority: &mut dyn HostAuthority,
        evidence: RejectionEvidence,
    ) -> Result<HostKeyRejection, AdapterRefusal> {
        let identity = match (&self.state, &self.identity) {
            (
                AdapterState::IdentityEnrolled
                | AdapterState::RuntimeConfirmed
                | AdapterState::Running
                | AdapterState::AuthorityEnded { .. }
                | AdapterState::Terminating,
                Some(identity),
            ) => identity.clone(),
            _ => return Err(self.refuse(AdapterStep::ReportHostKeyMismatch)),
        };
        let recorded = known.record_rejection(
            &identity.host,
            identity.enrollment,
            RejectionObserver::ManagementSsh,
            evidence,
            self.clock.now(),
        );
        let observer = recorded
            .as_ref()
            .map_or(RejectionObserver::ManagementSsh, |rejection| {
                rejection.observer
            });
        self.end_for_rejected_key(authority, identity.host, identity.enrollment, observer);
        recorded.map_err(|refusal| AdapterRefusal::RejectionNotRecorded { refusal })
    }

    /// Ends delegation for a rejected host key from any state in which the run holds or
    /// could still reach authority. Before launch there is no delegation to release, and
    /// the run ends all the same, so it never launches.
    fn end_for_rejected_key(
        &mut self,
        authority: &mut dyn HostAuthority,
        host: RemoteHostId,
        generation: EnrollmentGeneration,
        observer: RejectionObserver,
    ) {
        if matches!(
            self.state,
            AdapterState::IdentityEnrolled | AdapterState::RuntimeConfirmed | AdapterState::Running
        ) {
            self.end_authority(
                authority,
                AuthorityEnd::HostKeyRejected {
                    host,
                    generation,
                    observer,
                },
            );
        }
    }

    fn require_live_control(&self) -> Result<(), AdapterRefusal> {
        let now = self.clock.now();
        let control = self
            .control
            .as_ref()
            .ok_or(AdapterRefusal::NoControlSession)?;
        if control.is_live(now, self.config.max_control_silence) {
            Ok(())
        } else {
            Err(AdapterRefusal::ControlNotLive {
                silent_for_nanos: nanos(control.silent_for(now)),
            })
        }
    }

    /// Seals a grant of the current delegation: a lease's remaining term, or for a
    /// labelled grant one term, never past the grant.
    fn grant_frame(&mut self, now: MonotonicTime) -> Result<SealedFrame, AdapterRefusal> {
        let delegation = self
            .delegation
            .as_ref()
            .ok_or(AdapterRefusal::Inconsistent {
                missing: "delegation",
            })?;
        let until = match delegation {
            Delegation::Lease { lease } => lease.expires_at(),
            Delegation::Labelled { grant } => grant
                .expires_at
                .min(now.saturating_add(self.config.terms.term)),
        };
        let grant = LeaseGrant {
            authority: delegation.grant_ref(),
            clock: delegation.clock(),
            ttl_nanos: nanos(until.saturating_duration_since(now)),
        };
        let frame = self
            .control
            .as_mut()
            .ok_or(AdapterRefusal::NoControlSession)?
            .seal_outbound(ControlBody::Grant { grant })
            .map_err(|refusal| AdapterRefusal::Control { refusal })?;
        self.last_grant = Some((now, grant));
        Ok(frame)
    }

    /// Delegates authority and seals its first grant on the live control session. A
    /// remote VM gets a CORE-04 service lease under its parent VM sandbox. A provider
    /// container is bound to the labelled-runtime record the host granted for its
    /// execution, which must be for exactly the runtime admitted here (VM-D5). A
    /// confidential profile first needs an accepted attestation bound to this identity,
    /// this session's key and the workload.
    pub fn launch(
        &mut self,
        authority: &mut dyn HostAuthority,
        operation: OperationId,
        attestation: Option<&AttestationRecord>,
    ) -> Result<SealedFrame, AdapterRefusal> {
        if self.state != AdapterState::RuntimeConfirmed {
            return Err(self.refuse(AdapterStep::Launch));
        }
        self.require_live_control()?;
        if let Some(confidential) = self.config.confidential {
            let record = attestation.ok_or(AdapterRefusal::AttestationRequired)?;
            let identity = self.identity.as_ref().ok_or(AdapterRefusal::Inconsistent {
                missing: "identity",
            })?;
            let session_key = self
                .control
                .as_ref()
                .ok_or(AdapterRefusal::NoControlSession)?
                .session_key();
            record
                .usable_for(
                    identity.digest(),
                    session_key,
                    confidential.workload,
                    authority.session(),
                    authority.now(),
                    Duration::from_secs(confidential.max_record_age_seconds),
                )
                .map_err(|reason| AdapterRefusal::AttestationNotUsable { reason })?;
        }
        let delegation = if self.selection.is_vm_sandbox() {
            let lease = authority
                .issue(&self.execution, operation, self.config.terms)
                .map_err(|refusal| AdapterRefusal::Authority { refusal })?;
            Delegation::Lease { lease }
        } else {
            let record = authority
                .check_labelled(&self.execution)
                .map_err(|refusal| AdapterRefusal::Labelled { refusal })?;
            let admitted = self.runtime.as_ref().ok_or(AdapterRefusal::Inconsistent {
                missing: "admitted runtime",
            })?;
            if &record.runtime != admitted.runtime() {
                return Err(AdapterRefusal::LabelledRecordForAnotherRuntime);
            }
            Delegation::Labelled {
                grant: record.grant,
            }
        };
        self.delegation = Some(delegation);
        self.set_state(AdapterState::Running);
        self.grant_frame(authority.now())
    }

    /// Renews the delegation through the host's authority, only over a live control
    /// session. A lease is renewed by the coordinator; a labelled grant is rechecked and
    /// a new grant sent within it. A refusal for authority no longer honoured ends
    /// delegation; a renewal limit on a lease still honoured leaves it to run out.
    pub fn renew(
        &mut self,
        authority: &mut dyn HostAuthority,
    ) -> Result<SealedFrame, AdapterRefusal> {
        if self.state != AdapterState::Running {
            return Err(self.refuse(AdapterStep::Renew));
        }
        self.require_live_control()?;
        match self.delegation.clone() {
            Some(Delegation::Lease { lease }) => match authority.renew(lease.id(), lease.clock()) {
                Ok(renewed) => {
                    self.delegation = Some(Delegation::Lease { lease: renewed });
                    self.grant_frame(authority.now())
                }
                Err(refusal) => {
                    if authority.check(lease.id()).is_err() {
                        self.end_authority(
                            authority,
                            AuthorityEnd::LeaseRefused {
                                refusal: refusal.clone(),
                            },
                        );
                    }
                    Err(AdapterRefusal::Authority { refusal })
                }
            },
            Some(Delegation::Labelled { grant }) => {
                self.check_labelled_grant(authority, grant)?;
                self.grant_frame(authority.now())
            }
            None => Err(AdapterRefusal::Inconsistent {
                missing: "delegation",
            }),
        }
    }

    /// Accepts an authenticated frame from the remote. A renewal request is only a
    /// request: the host renews through its authority, or refuses.
    pub fn handle_frame(
        &mut self,
        sealed: &SealedFrame,
        authority: &mut dyn HostAuthority,
    ) -> Result<FrameOutcome, AdapterRefusal> {
        if !matches!(
            self.state,
            AdapterState::RuntimeConfirmed | AdapterState::Running
        ) {
            return Err(self.refuse(AdapterStep::HandleFrame));
        }
        let now = self.clock.now();
        let body = self
            .control
            .as_mut()
            .ok_or(AdapterRefusal::NoControlSession)?
            .accept(sealed, now)
            .map_err(|refusal| AdapterRefusal::Control { refusal })?;
        match body {
            ControlBody::Heartbeat => Ok(FrameOutcome::Heard),
            ControlBody::RenewalRequest {
                authority: presented,
                clock,
            } => {
                if self.state != AdapterState::Running {
                    return Err(self.refuse(AdapterStep::Renew));
                }
                let current = self
                    .delegation
                    .as_ref()
                    .ok_or(AdapterRefusal::Inconsistent {
                        missing: "delegation",
                    })?;
                if presented != current.grant_ref() || clock != current.clock() {
                    return Err(AdapterRefusal::ForeignAuthority { presented });
                }
                self.renew(authority)
                    .map(|grant| FrameOutcome::Renewed { grant })
            }
            ControlBody::StatusReport { expiry } => Ok(FrameOutcome::StatusReported { expiry }),
            ControlBody::Grant { .. } | ControlBody::Stop => Err(AdapterRefusal::UnexpectedFrame),
        }
    }

    /// The digest the remote names its delegation by in status reports.
    pub fn delegation_right(&self) -> Option<Digest> {
        self.delegation.as_ref().map(|delegation| {
            let builder = DigestBuilder::new("yougori/remote/delegation-right/v1")
                .digest(self.attempt.digest());
            let builder = match delegation.grant_ref() {
                GrantRef::Lease { lease } => builder.str("lease").u64(lease.get()),
                GrantRef::Labelled { epoch } => builder.str("labelled").u64(epoch.get()),
            };
            builder
                .bytes(delegation.clock().as_uuid().as_bytes())
                .finish()
        })
    }

    /// When the last grant sent to the remote ends on the host clock.
    pub fn granted_until(&self) -> Option<MonotonicTime> {
        self.last_grant
            .map(|(at, grant)| at.saturating_add(Duration::from_nanos(grant.ttl_nanos)))
    }

    /// Judges the remote's view of its delegation under the explicit clock-skew policy
    /// (§6.2). Excessive skew, an inconsistent or expired report, or a claimed expiry
    /// later than the last grant plus the skew allowance ends delegation. A labelled
    /// runtime has no boot generation, so its local expiry is bound to the first one and
    /// to the grant's epoch through the right it names.
    pub fn observe_remote_expiry(
        &mut self,
        expiry: &RemoteExpiry,
        observation: &RemoteObservation,
        guard: &mut WallClockGuard,
        authority: &mut dyn HostAuthority,
    ) -> Result<LocalExpiry, AdapterRefusal> {
        if self.state != AdapterState::Running {
            return Err(self.refuse(AdapterStep::ObserveStatus));
        }
        let boot = match &self.delegation {
            Some(Delegation::Lease { lease }) => lease.sandbox().boot,
            Some(Delegation::Labelled { .. }) => SandboxBootGeneration::FIRST,
            None => {
                return Err(AdapterRefusal::Inconsistent {
                    missing: "delegation",
                })
            }
        };
        if Some(expiry.right) != self.delegation_right() {
            return Err(AdapterRefusal::UnknownRight);
        }
        let granted_until = self
            .granted_until()
            .ok_or(AdapterRefusal::Inconsistent { missing: "grant" })?;
        let local =
            match self
                .config
                .skew
                .localize(expiry, observation, authority.session(), boot, guard)
            {
                Ok(local) => local,
                Err(refusal) => {
                    self.end_authority(authority, AuthorityEnd::SkewRefused { refusal });
                    return Err(AdapterRefusal::Skew { refusal });
                }
            };
        let limit =
            granted_until.saturating_add(Duration::from_secs(self.config.skew.max_skew_seconds));
        if local.deadline > limit {
            self.end_authority(authority, AuthorityEnd::RemoteClaimedLongerLease);
            return Err(AdapterRefusal::RemoteClaimsLongerLease {
                claimed: local.deadline,
                limit,
            });
        }
        Ok(local)
    }

    /// Whether the delegation is still honoured; a refusal ends it.
    pub fn check_authority(
        &mut self,
        authority: &mut dyn HostAuthority,
    ) -> Result<Delegation, AdapterRefusal> {
        if self.state != AdapterState::Running {
            return Err(self.refuse(AdapterStep::CheckAuthority));
        }
        self.check_delegation(authority)
    }

    fn check_delegation(
        &mut self,
        authority: &mut dyn HostAuthority,
    ) -> Result<Delegation, AdapterRefusal> {
        match self.delegation.clone() {
            Some(Delegation::Lease { lease }) => match authority.check(lease.id()) {
                Ok(current) => Ok(Delegation::Lease { lease: current }),
                Err(refusal) => {
                    self.end_authority(
                        authority,
                        AuthorityEnd::LeaseRefused {
                            refusal: refusal.clone(),
                        },
                    );
                    Err(AdapterRefusal::Authority { refusal })
                }
            },
            Some(Delegation::Labelled { grant }) => self
                .check_labelled_grant(authority, grant)
                .map(|grant| Delegation::Labelled { grant }),
            None => Err(AdapterRefusal::Inconsistent {
                missing: "delegation",
            }),
        }
    }

    /// The labelled record must still honour exactly the grant this run is bound to.
    fn check_labelled_grant(
        &mut self,
        authority: &mut dyn HostAuthority,
        bound: AuthorityGrant,
    ) -> Result<AuthorityGrant, AdapterRefusal> {
        match authority.check_labelled(&self.execution) {
            Ok(record) if record.grant == bound => Ok(bound),
            Ok(record) => {
                self.end_authority(authority, AuthorityEnd::GrantReplaced);
                Err(AdapterRefusal::LabelledGrantReplaced {
                    bound,
                    current: record.grant,
                })
            }
            Err(refusal) => {
                self.end_authority(
                    authority,
                    AuthorityEnd::LabelledRefused {
                        refusal: refusal.clone(),
                    },
                );
                Err(AdapterRefusal::Labelled { refusal })
            }
        }
    }

    /// Ends the host's authority: a lease is released; a labelled runtime is revoked, so
    /// its grant is never honoured again.
    fn end_authority(&mut self, authority: &mut dyn HostAuthority, reason: AuthorityEnd) {
        // An authority that already ended refuses again; that changes nothing here.
        match &self.delegation {
            Some(Delegation::Lease { lease }) => {
                let _ = authority.release(lease.id());
            }
            Some(Delegation::Labelled { .. }) => {
                let _ = authority.revoke_labelled(&self.execution);
            }
            None => {}
        }
        self.acknowledge(RevocationMilestone::NewAuthorizationsDenied);
        self.set_state(AdapterState::AuthorityEnded { reason });
    }

    /// Starts cleanup of whatever the provider may hold: ends the delegation, closes the
    /// host's end of the control session and moves to terminating. The remote's own
    /// sockets are not observed, so `SocketsClosed` is not claimed.
    pub fn begin_termination(
        &mut self,
        authority: &mut dyn HostAuthority,
    ) -> Result<(), AdapterRefusal> {
        match self.state {
            AdapterState::Terminating => return Ok(()),
            AdapterState::Running => self.end_authority(authority, AuthorityEnd::Stopped),
            AdapterState::Provisioned
            | AdapterState::IdentityEnrolled
            | AdapterState::RuntimeConfirmed
            | AdapterState::AuthorityEnded { .. } => {}
            _ => return Err(self.refuse(AdapterStep::BeginTermination)),
        }
        let now = self.clock.now();
        if let Some(control) = self.control.as_mut() {
            control.close(now);
        }
        self.set_state(AdapterState::Terminating);
        Ok(())
    }

    /// One cleanup attempt. Termination is confirmed only by the provider: a confirmed
    /// termination, an instance already gone, or for an uncertain provisioning a
    /// confirmation that nothing exists for the attempt.
    pub fn terminate_step(
        &mut self,
        provider: &mut dyn RemoteProviderPort,
    ) -> Result<CleanupStatus, AdapterRefusal> {
        if self.externally_managed() {
            return Err(AdapterRefusal::ExternallyManagedHost);
        }
        if self.state != AdapterState::Terminating {
            return Err(self.refuse(AdapterStep::TerminateStep));
        }
        self.cleanup_attempts = self.cleanup_attempts.saturating_add(1);
        let target = match self.instance.clone() {
            Some(instance) => instance,
            None => match provider.find(&self.provision_request()) {
                LookupOutcome::Found { instance } => {
                    self.instance = Some(instance.clone());
                    instance
                }
                LookupOutcome::ConfirmedAbsent => return Ok(self.terminated()),
                LookupOutcome::Unknown { cause } => {
                    return Ok(self.retrying(CleanupFailure::LookupUnknown { cause }))
                }
            },
        };
        Ok(match provider.terminate(&target) {
            TerminationOutcome::Confirmed | TerminationOutcome::AlreadyGone => self.terminated(),
            TerminationOutcome::Failed { error } => {
                self.retrying(CleanupFailure::Termination { error })
            }
            TerminationOutcome::Unknown { cause } => {
                self.retrying(CleanupFailure::TerminationUnknown { cause })
            }
        })
    }

    fn terminated(&mut self) -> CleanupStatus {
        if self.selection.is_vm_sandbox() {
            self.acknowledge(RevocationMilestone::VmStopped);
        }
        self.set_state(AdapterState::Terminated);
        CleanupStatus::Confirmed {
            attempts: self.cleanup_attempts,
        }
    }

    fn retrying(&self, last: CleanupFailure) -> CleanupStatus {
        CleanupStatus::Retrying {
            attempts: self.cleanup_attempts,
            needs_operator: self.cleanup_attempts >= self.config.escalate_after_attempts,
            last,
        }
    }

    /// Settles the reservation from the provider's final bill once termination is
    /// confirmed, or after a definite failure. Without a final bill the whole
    /// reservation stays counted as spent; calling again later reconciles it. A final
    /// bill is the provider's API stating billing stopped: it is recorded as
    /// `ProviderStoppedBilling`, and for a remote VM also on the parent sandbox's
    /// revocation when one is in progress (§6.3).
    pub fn settle_billing(
        &mut self,
        provider: &mut dyn RemoteProviderPort,
        ledger: &SharedSpendLedger,
        authority: &mut dyn HostAuthority,
    ) -> Result<BillingOutcome, AdapterRefusal> {
        if self.externally_managed() {
            return Err(AdapterRefusal::ExternallyManagedHost);
        }
        let closable = matches!(
            self.state,
            AdapterState::Terminated
                | AdapterState::Closed {
                    billing: BillingOutcome::Uncertain { .. }
                }
        );
        if !closable && !matches!(self.state, AdapterState::Failed { .. }) {
            return Err(self.refuse(AdapterStep::SettleBilling));
        }
        let spend = self.spend.ok_or(AdapterRefusal::Inconsistent {
            missing: "spend reservation",
        })?;
        let outcome = match spend.phase {
            SpendPhase::InFlight | SpendPhase::Unknown => {
                match provider.final_bill(&self.attempt) {
                    BillingReport::Final { cost_microunits } => {
                        if self.selection.is_vm_sandbox() {
                            authority
                                .acknowledge_revocation(
                                    &self.execution,
                                    RevocationMilestone::ProviderStoppedBilling,
                                    SourceClass::ProviderApi,
                                )
                                .map_err(|error| AdapterRefusal::Coordination { error })?;
                        }
                        let outcome = self.settle_spend(
                            ledger,
                            SpendStatus::Committed,
                            Some(cost_microunits),
                        )?;
                        self.acknowledge(RevocationMilestone::ProviderStoppedBilling);
                        outcome
                    }
                    BillingReport::Unavailable => {
                        self.settle_spend(ledger, SpendStatus::Unknown, None)?
                    }
                }
            }
            SpendPhase::Reserved | SpendPhase::Settled { .. } | SpendPhase::Released { .. } => {
                self.settle_spend(ledger, SpendStatus::NotCommitted, None)?
            }
        };
        if closable {
            self.set_state(AdapterState::Closed { billing: outcome });
        }
        Ok(outcome)
    }

    /// Stops a run before anything was provisioned and returns its reservation.
    pub fn cancel(&mut self, ledger: &SharedSpendLedger) -> Result<(), AdapterRefusal> {
        match self.state {
            AdapterState::Planned => {}
            AdapterState::SpendReserved => {
                self.settle_spend(ledger, SpendStatus::NotCommitted, None)?;
            }
            _ => return Err(self.refuse(AdapterStep::Cancel)),
        }
        self.set_state(AdapterState::Cancelled);
        Ok(())
    }
}
