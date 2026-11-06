//! The durable effect state machine (VM part §9.2 lines 2346–2353; §4.6 line 2026;
//! VM-P31; §12.3 model 2).
//!
//! ```text
//! proposed → validated → authorized → reserved → dispatched
//!   → confirmed | failed | outcome_unknown
//! ```
//!
//! An [`EffectRecord`] keeps one effect's immutable description, its state and its
//! transition history. Every method checks the edge it takes and the state it needs;
//! nothing here performs I/O, so the [`EffectController`](super::EffectController) drives
//! it through ports and the §12.3 model checks it exhaustively.
//!
//! Rules: authorization and reservation precede every dispatch; the identity and the
//! description never change, and an attempt's capability (with its epochs) is fixed
//! from authorization to outcome; a retry keeps the identity and starts the pipeline
//! again; `failed` always means the provider certainly did not commit; an
//! `outcome_unknown` effect is never retried until reconciliation decides it.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::budget::{ReleaseRefusal, ReleaseReservation};
use super::capability::{CapabilityRefusal, SealedCapability};
use super::contract::{ContractRefusal, DeliveryGuarantee};
use super::delegation::{BudgetRefusal, ScopeViolation};
use super::description::{EffectDescription, EffectId, PayloadMismatch, RouteRef};
use super::executor::ExecutorRefusal;
use super::replay::ReplayRefusal;
use crate::foundation::coordination::LeaseRefusal;
use crate::foundation::ids::{
    AuthorizationEpoch, Digest, DigestBuilder, MonotonicTime, PolicyEpoch, SandboxBootGeneration,
};

/// The phase of an effect (§9.2 lines 2348–2349).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectPhase {
    Proposed,
    Validated,
    Authorized,
    Reserved,
    Dispatched,
    Confirmed,
    Failed,
    OutcomeUnknown,
}

impl EffectPhase {
    pub const ALL: [Self; 8] = [
        Self::Proposed,
        Self::Validated,
        Self::Authorized,
        Self::Reserved,
        Self::Dispatched,
        Self::Confirmed,
        Self::Failed,
        Self::OutcomeUnknown,
    ];

    /// Whether `next` may follow `self`: the §9.2 chain, a failure from any phase before
    /// an outcome, reconciliation out of `outcome_unknown`, and a retry from `failed` back
    /// to `proposed` under the same identity. Nothing follows `confirmed`.
    pub const fn may_follow(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Proposed, Self::Validated)
                | (Self::Validated, Self::Authorized)
                | (Self::Authorized, Self::Reserved)
                | (Self::Reserved, Self::Dispatched)
                | (Self::Dispatched, Self::Confirmed)
                | (Self::Dispatched, Self::OutcomeUnknown)
                | (Self::OutcomeUnknown, Self::Confirmed)
                | (
                    Self::Proposed
                        | Self::Validated
                        | Self::Authorized
                        | Self::Reserved
                        | Self::Dispatched
                        | Self::OutcomeUnknown,
                    Self::Failed
                )
                | (Self::Failed, Self::Proposed)
        )
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Validated => "validated",
            Self::Authorized => "authorized",
            Self::Reserved => "reserved",
            Self::Dispatched => "dispatched",
            Self::Confirmed => "confirmed",
            Self::Failed => "failed",
            Self::OutcomeUnknown => "outcome_unknown",
        }
    }
}

impl fmt::Display for EffectPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What an effect holds in the central ledgers while reserved, dispatched or uncertain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldReservation {
    /// Wire bytes on the provider-request channel.
    pub release: ReleaseReservation,
    /// Spend held under the authorization basis; one effect is held with it.
    pub spend_microunits: u64,
}

/// The permitted representation of a provider's result (§4.5 line 2004).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderResult {
    /// The digest of the permitted response representation.
    pub result: Digest,
    pub spend_microunits: u64,
    pub volume_units: u64,
}

strict_tagged_enum! {
    /// Why an outcome is unknown (VM-P31).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum UnknownCause (tag = "cause", wire = UnknownCauseWire, wire_name = "UnknownCauseWire") {
        /// The request left and no reply came back.
        ResponseLost,
        /// The host crashed between dispatch and receipt (§4.6 line 2026).
        CrashBeforeReceipt,
        /// The provider reported partial success; what committed must be reconciled.
        PartialSuccess { partial: ProviderResult },
    }
}

/// How a reconciliation learned the outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationSource {
    /// The provider's own lookup by idempotency key or resource state.
    ProviderLookup,
    /// The user checked the provider and recorded the answer.
    UserConfirmation,
}

strict_tagged_enum! {
    /// What a reconciliation observed.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Observation (tag = "observed", wire = ObservationWire, wire_name = "ObservationWire") {
        Committed { result: ProviderResult },
        NotCommitted,
        StillUnknown,
    }
}

/// One reconciliation of an uncertain outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reconciliation {
    pub observation: Observation,
    pub source: ReconciliationSource,
}

strict_tagged_enum! {
    /// Why an effect failed. Every failure means the provider certainly did not commit.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum EffectFailure (tag = "failure", wire = EffectFailureWire, wire_name = "EffectFailureWire") {
        Validation { refusal: ContractRefusal },
        Authorization { violation: ScopeViolation },
        Budget { refusal: BudgetRefusal },
        Release { refusal: ReleaseRefusal },
        Capability { refusal: CapabilityRefusal },
        Replay { refusal: ReplayRefusal },
        /// The policy epoch moved between authorization and the dispatch boundary.
        PolicyEpochChanged { bound: PolicyEpoch, current: PolicyEpoch },
        AuthorizationEpochChanged { bound: AuthorizationEpoch, current: AuthorizationEpoch },
        BootGenerationChanged { bound: SandboxBootGeneration, current: SandboxBootGeneration },
        /// The sandbox holds no authority now.
        NoAuthority,
        LeaseRefused { refusal: LeaseRefusal },
        /// The revocation tombstone denies the capability's epoch.
        Revoked { through: AuthorizationEpoch },
        DeadlinePassed { deadline: MonotonicTime },
        PayloadMismatch { mismatch: PayloadMismatch },
        /// The executor refused or sent nothing; never recorded as the provider's.
        Executor { refusal: ExecutorRefusal },
        /// The provider itself rejected the request it received.
        ProviderRejected { code: String },
        /// The provider redirected; the executor never follows to another destination.
        RedirectRefused { route: RouteRef },
        ReconciledNotCommitted { source: ReconciliationSource },
        Cancelled,
    }
}

impl fmt::Display for EffectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation { refusal } => write!(f, "{refusal}"),
            Self::Authorization { violation } => write!(f, "{violation}"),
            Self::Budget { refusal } => write!(f, "{refusal}"),
            Self::Release { refusal } => write!(f, "{refusal}"),
            Self::Capability { refusal } => write!(f, "{refusal}"),
            Self::Replay { refusal } => write!(f, "{refusal}"),
            Self::PolicyEpochChanged { bound, current } => write!(
                f,
                "the policy moved from epoch {bound} to {current} before dispatch"
            ),
            Self::AuthorizationEpochChanged { bound, current } => write!(
                f,
                "authorization epoch {bound} is no longer current; the sandbox is at {current}"
            ),
            Self::BootGenerationChanged { bound, current } => write!(
                f,
                "boot generation {bound} is no longer current; the sandbox is at {current}"
            ),
            Self::NoAuthority => f.write_str("the sandbox holds no authority"),
            Self::LeaseRefused { refusal } => write!(f, "{refusal}"),
            Self::Revoked { through } => {
                write!(f, "authorization through epoch {through} was revoked")
            }
            Self::DeadlinePassed { deadline } => {
                write!(f, "the deadline at {} ns passed", deadline.as_nanos())
            }
            Self::PayloadMismatch { mismatch } => write!(f, "{mismatch}"),
            Self::Executor { refusal } => write!(f, "{refusal}"),
            Self::ProviderRejected { code } => write!(f, "the provider rejected it: {code}"),
            Self::RedirectRefused { .. } => {
                f.write_str("the provider redirected, and the executor does not follow")
            }
            Self::ReconciledNotCommitted { .. } => {
                f.write_str("reconciliation found the provider did not commit")
            }
            Self::Cancelled => f.write_str("cancelled before dispatch"),
        }
    }
}

/// Where an audit record of the effect sits in the CORE-06 journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditMark {
    pub phase: EffectPhase,
    pub sequence: u64,
    pub digest: Digest,
}

/// Proof of a confirmed effect, bound to its description and the provider's result
/// (§9.2 line 2351).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectReceipt {
    pub effect: EffectId,
    pub capability: Digest,
    pub attempt: u32,
    pub provider_result: ProviderResult,
    pub confirmed_at: MonotonicTime,
    pub source: Option<ReconciliationSource>,
    /// The digest of every field above.
    pub digest: Digest,
}

impl EffectReceipt {
    fn new(
        effect: EffectId,
        capability: Digest,
        attempt: u32,
        provider_result: ProviderResult,
        confirmed_at: MonotonicTime,
        source: Option<ReconciliationSource>,
    ) -> Self {
        let builder = DigestBuilder::new("yougori/sandbox/effect-receipt/v1")
            .digest(effect.digest())
            .digest(&capability)
            .u64(u64::from(attempt))
            .digest(&provider_result.result)
            .u64(provider_result.spend_microunits)
            .u64(provider_result.volume_units)
            .u64(confirmed_at.as_nanos());
        let digest = match source {
            None => builder.str("dispatch"),
            Some(ReconciliationSource::ProviderLookup) => builder.str("provider_lookup"),
            Some(ReconciliationSource::UserConfirmation) => builder.str("user_confirmation"),
        }
        .finish();
        Self {
            effect,
            capability,
            attempt,
            provider_result,
            confirmed_at,
            source,
            digest,
        }
    }
}

strict_tagged_enum! {
    /// An effect's state and what it holds there.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum EffectState (tag = "state", wire = EffectStateWire, wire_name = "EffectStateWire") {
        Proposed,
        Validated { delivery: DeliveryGuarantee },
        Authorized { delivery: DeliveryGuarantee, capability: SealedCapability },
        Reserved {
            delivery: DeliveryGuarantee,
            capability: SealedCapability,
            held: HeldReservation,
        },
        Dispatched {
            delivery: DeliveryGuarantee,
            capability: SealedCapability,
            held: HeldReservation,
            dispatched_at: MonotonicTime,
        },
        Confirmed {
            delivery: DeliveryGuarantee,
            capability: SealedCapability,
            receipt: EffectReceipt,
        },
        Failed { failure: EffectFailure },
        OutcomeUnknown {
            delivery: DeliveryGuarantee,
            capability: SealedCapability,
            held: HeldReservation,
            cause: UnknownCause,
            since: MonotonicTime,
        },
    }
}

impl EffectState {
    pub const fn phase(&self) -> EffectPhase {
        match self {
            Self::Proposed => EffectPhase::Proposed,
            Self::Validated { .. } => EffectPhase::Validated,
            Self::Authorized { .. } => EffectPhase::Authorized,
            Self::Reserved { .. } => EffectPhase::Reserved,
            Self::Dispatched { .. } => EffectPhase::Dispatched,
            Self::Confirmed { .. } => EffectPhase::Confirmed,
            Self::Failed { .. } => EffectPhase::Failed,
            Self::OutcomeUnknown { .. } => EffectPhase::OutcomeUnknown,
        }
    }

    /// The capability of the current attempt, from authorization to outcome.
    pub fn capability(&self) -> Option<&SealedCapability> {
        match self {
            Self::Authorized { capability, .. }
            | Self::Reserved { capability, .. }
            | Self::Dispatched { capability, .. }
            | Self::Confirmed { capability, .. }
            | Self::OutcomeUnknown { capability, .. } => Some(capability),
            _ => None,
        }
    }

    /// What the effect holds in the ledgers.
    pub fn held(&self) -> Option<HeldReservation> {
        match self {
            Self::Reserved { held, .. }
            | Self::Dispatched { held, .. }
            | Self::OutcomeUnknown { held, .. } => Some(*held),
            _ => None,
        }
    }

    pub fn delivery(&self) -> Option<DeliveryGuarantee> {
        match self {
            Self::Validated { delivery }
            | Self::Authorized { delivery, .. }
            | Self::Reserved { delivery, .. }
            | Self::Dispatched { delivery, .. }
            | Self::Confirmed { delivery, .. }
            | Self::OutcomeUnknown { delivery, .. } => Some(*delivery),
            Self::Proposed | Self::Failed { .. } => None,
        }
    }
}

/// One transition, as the history keeps it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionEntry {
    pub from: EffectPhase,
    pub to: EffectPhase,
    pub at: MonotonicTime,
    pub attempt: u32,
    /// The capability digest of the attempt, once authorized.
    pub capability: Option<Digest>,
}

/// Why a transition was refused; the record did not change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateRefusal {
    WrongPhase {
        phase: EffectPhase,
        action: &'static str,
    },
    /// The capability is for another effect or does not match this description.
    Capability(CapabilityRefusal),
    AttemptMismatch {
        expected: u32,
        presented: u32,
    },
    /// An uncertain outcome must be reconciled before any retry (§4.6 line 2026).
    NeedsReconciliation,
    /// A confirmed effect is never retried or revoked retroactively.
    AlreadyConfirmed,
    /// A dispatched effect waits for its outcome.
    InFlight,
    AttemptsExhausted,
}

impl fmt::Display for StateRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongPhase { phase, action } => {
                write!(f, "cannot {action} an effect that is {phase}")
            }
            Self::Capability(refusal) => write!(f, "{refusal}"),
            Self::AttemptMismatch {
                expected,
                presented,
            } => write!(
                f,
                "the capability is for attempt {presented}, not {expected}"
            ),
            Self::NeedsReconciliation => f.write_str(
                "the outcome is uncertain; reconcile it with the provider before any retry",
            ),
            Self::AlreadyConfirmed => f.write_str("the effect is confirmed and stays so"),
            Self::InFlight => f.write_str("the effect is dispatched and awaits its outcome"),
            Self::AttemptsExhausted => f.write_str("no attempt numbers are left"),
        }
    }
}

impl std::error::Error for StateRefusal {}

/// What a dispatch did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchStep {
    Dispatched,
    /// Refused at the boundary; the held reservation is returned.
    Refused {
        held: HeldReservation,
    },
}

/// What a provider outcome means for the effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Settlement {
    Committed(ProviderResult),
    NotCommitted(EffectFailure),
    Unknown(UnknownCause),
}

/// What a settlement or reconciliation released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettleStep {
    /// Committed: charge the actual result against `held`.
    Confirmed {
        held: HeldReservation,
        receipt: EffectReceipt,
    },
    /// Certainly not committed: return `held`.
    Failed { held: HeldReservation },
    /// Still uncertain: `held` stays held.
    Unknown,
}

/// One effect's durable record (§9.2 line 2348).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRecord {
    description: EffectDescription,
    state: EffectState,
    /// The attempt of the latest capability; 0 before the first authorization.
    attempt: u32,
    history: Vec<TransitionEntry>,
    audit: Vec<AuditMark>,
}

impl EffectRecord {
    pub fn propose(description: EffectDescription) -> Self {
        Self {
            description,
            state: EffectState::Proposed,
            attempt: 0,
            history: Vec::new(),
            audit: Vec::new(),
        }
    }

    pub fn id(&self) -> EffectId {
        self.description.id()
    }

    pub fn description(&self) -> &EffectDescription {
        &self.description
    }

    pub fn state(&self) -> &EffectState {
        &self.state
    }

    pub fn phase(&self) -> EffectPhase {
        self.state.phase()
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    pub fn history(&self) -> &[TransitionEntry] {
        &self.history
    }

    pub fn audit_marks(&self) -> &[AuditMark] {
        &self.audit
    }

    pub(super) fn add_audit(&mut self, mark: AuditMark) {
        self.audit.push(mark);
    }

    fn wrong(&self, action: &'static str) -> StateRefusal {
        StateRefusal::WrongPhase {
            phase: self.phase(),
            action,
        }
    }

    fn enter(&mut self, next: EffectState, at: MonotonicTime) {
        let from = self.phase();
        let to = next.phase();
        let capability = next.capability().map(|sealed| sealed.capability().digest());
        self.state = next;
        self.history.push(TransitionEntry {
            from,
            to,
            at,
            attempt: self.attempt,
            capability,
        });
    }

    /// proposed → validated, or → failed when the contract refused.
    pub fn validate(
        &mut self,
        result: Result<DeliveryGuarantee, ContractRefusal>,
        at: MonotonicTime,
    ) -> Result<(), StateRefusal> {
        if self.phase() != EffectPhase::Proposed {
            return Err(self.wrong("validate"));
        }
        match result {
            Ok(delivery) => self.enter(EffectState::Validated { delivery }, at),
            Err(refusal) => self.enter(
                EffectState::Failed {
                    failure: EffectFailure::Validation { refusal },
                },
                at,
            ),
        }
        Ok(())
    }

    /// validated → authorized with the next attempt's capability, which must be for this
    /// effect and match this description field by field.
    pub fn authorize(
        &mut self,
        capability: SealedCapability,
        at: MonotonicTime,
    ) -> Result<(), StateRefusal> {
        let EffectState::Validated { delivery } = self.state else {
            return Err(self.wrong("authorize"));
        };
        let expected = self
            .attempt
            .checked_add(1)
            .ok_or(StateRefusal::AttemptsExhausted)?;
        capability
            .capability()
            .check_binding(&self.description)
            .map_err(StateRefusal::Capability)?;
        if capability.capability().attempt != expected {
            return Err(StateRefusal::AttemptMismatch {
                expected,
                presented: capability.capability().attempt,
            });
        }
        self.attempt = expected;
        self.enter(
            EffectState::Authorized {
                delivery,
                capability,
            },
            at,
        );
        Ok(())
    }

    /// authorized → reserved.
    pub fn reserve(
        &mut self,
        held: HeldReservation,
        at: MonotonicTime,
    ) -> Result<(), StateRefusal> {
        let EffectState::Authorized {
            delivery,
            capability,
        } = &self.state
        else {
            return Err(self.wrong("reserve"));
        };
        let next = EffectState::Reserved {
            delivery: *delivery,
            capability: capability.clone(),
            held,
        };
        self.enter(next, at);
        Ok(())
    }

    /// reserved → dispatched if the dispatch boundary's checks passed, else → failed with
    /// the held reservation returned. Only a reserved effect dispatches, so a second
    /// dispatch of the same attempt is refused.
    pub fn dispatch(
        &mut self,
        gate: Result<(), EffectFailure>,
        at: MonotonicTime,
    ) -> Result<DispatchStep, StateRefusal> {
        let EffectState::Reserved {
            delivery,
            capability,
            held,
        } = &self.state
        else {
            return Err(match self.phase() {
                EffectPhase::Dispatched => StateRefusal::InFlight,
                EffectPhase::OutcomeUnknown => StateRefusal::NeedsReconciliation,
                EffectPhase::Confirmed => StateRefusal::AlreadyConfirmed,
                _ => self.wrong("dispatch"),
            });
        };
        let held = *held;
        match gate {
            Ok(()) => {
                let next = EffectState::Dispatched {
                    delivery: *delivery,
                    capability: capability.clone(),
                    held,
                    dispatched_at: at,
                };
                self.enter(next, at);
                Ok(DispatchStep::Dispatched)
            }
            Err(failure) => {
                self.enter(EffectState::Failed { failure }, at);
                Ok(DispatchStep::Refused { held })
            }
        }
    }

    /// dispatched → confirmed, failed or outcome_unknown.
    pub fn settle(
        &mut self,
        settlement: Settlement,
        at: MonotonicTime,
    ) -> Result<SettleStep, StateRefusal> {
        let EffectState::Dispatched {
            delivery,
            capability,
            held,
            ..
        } = &self.state
        else {
            return Err(self.wrong("settle"));
        };
        let (delivery, capability, held) = (*delivery, capability.clone(), *held);
        Ok(self.conclude(delivery, capability, held, settlement, None, at))
    }

    fn conclude(
        &mut self,
        delivery: DeliveryGuarantee,
        capability: SealedCapability,
        held: HeldReservation,
        settlement: Settlement,
        source: Option<ReconciliationSource>,
        at: MonotonicTime,
    ) -> SettleStep {
        match settlement {
            Settlement::Committed(result) => {
                let receipt = EffectReceipt::new(
                    self.id(),
                    capability.capability().digest(),
                    self.attempt,
                    result,
                    at,
                    source,
                );
                self.enter(
                    EffectState::Confirmed {
                        delivery,
                        capability,
                        receipt,
                    },
                    at,
                );
                SettleStep::Confirmed { held, receipt }
            }
            Settlement::NotCommitted(failure) => {
                self.enter(EffectState::Failed { failure }, at);
                SettleStep::Failed { held }
            }
            Settlement::Unknown(cause) => {
                if self.phase() != EffectPhase::OutcomeUnknown {
                    self.enter(
                        EffectState::OutcomeUnknown {
                            delivery,
                            capability,
                            held,
                            cause,
                            since: at,
                        },
                        at,
                    );
                }
                SettleStep::Unknown
            }
        }
    }

    /// After a crash, a dispatched effect has no receipt: its outcome is unknown (§4.6
    /// line 2026). Returns whether the record changed.
    pub fn recover_after_crash(&mut self, at: MonotonicTime) -> bool {
        let EffectState::Dispatched {
            delivery,
            capability,
            held,
            ..
        } = &self.state
        else {
            return false;
        };
        let next = EffectState::OutcomeUnknown {
            delivery: *delivery,
            capability: capability.clone(),
            held: *held,
            cause: UnknownCause::CrashBeforeReceipt,
            since: at,
        };
        self.enter(next, at);
        true
    }

    /// outcome_unknown → confirmed or failed by an explicit observation; a still-unknown
    /// observation changes nothing.
    pub fn reconcile(
        &mut self,
        reconciliation: Reconciliation,
        at: MonotonicTime,
    ) -> Result<SettleStep, StateRefusal> {
        let EffectState::OutcomeUnknown {
            delivery,
            capability,
            held,
            ..
        } = &self.state
        else {
            return Err(self.wrong("reconcile"));
        };
        let (delivery, capability, held) = (*delivery, capability.clone(), *held);
        let settlement = match reconciliation.observation {
            Observation::Committed { result } => Settlement::Committed(result),
            Observation::NotCommitted => {
                Settlement::NotCommitted(EffectFailure::ReconciledNotCommitted {
                    source: reconciliation.source,
                })
            }
            Observation::StillUnknown => return Ok(SettleStep::Unknown),
        };
        Ok(self.conclude(
            delivery,
            capability,
            held,
            settlement,
            Some(reconciliation.source),
            at,
        ))
    }

    /// Fails an effect before dispatch, returning what it held.
    pub fn fail(
        &mut self,
        failure: EffectFailure,
        at: MonotonicTime,
    ) -> Result<Option<HeldReservation>, StateRefusal> {
        match self.phase() {
            EffectPhase::Proposed
            | EffectPhase::Validated
            | EffectPhase::Authorized
            | EffectPhase::Reserved => {
                let held = self.state.held();
                self.enter(EffectState::Failed { failure }, at);
                Ok(held)
            }
            EffectPhase::Dispatched => Err(StateRefusal::InFlight),
            EffectPhase::OutcomeUnknown => Err(StateRefusal::NeedsReconciliation),
            EffectPhase::Confirmed => Err(StateRefusal::AlreadyConfirmed),
            EffectPhase::Failed => Err(self.wrong("fail")),
        }
    }

    /// failed → proposed, keeping the identity and the description: the retry is
    /// validated, authorized and reserved again before it can dispatch. Refused for an
    /// uncertain outcome until it is reconciled, and for a confirmed effect.
    pub fn retry(&mut self, at: MonotonicTime) -> Result<(), StateRefusal> {
        match self.phase() {
            EffectPhase::Failed => {
                self.enter(EffectState::Proposed, at);
                Ok(())
            }
            EffectPhase::OutcomeUnknown => Err(StateRefusal::NeedsReconciliation),
            EffectPhase::Confirmed => Err(StateRefusal::AlreadyConfirmed),
            EffectPhase::Dispatched => Err(StateRefusal::InFlight),
            _ => Err(self.wrong("retry")),
        }
    }

    /// Whether every recorded transition is an allowed edge, every dispatch follows an
    /// authorization and a reservation of the same attempt, and every attempt's
    /// capability stays the same from authorization to outcome (§12.3 model 2).
    pub fn history_violation(&self) -> Option<String> {
        let mut authorized: Option<(u32, Option<Digest>)> = None;
        let mut reserved = false;
        for entry in &self.history {
            if !entry.from.may_follow(entry.to) {
                return Some(format!("{} -> {} is not an edge", entry.from, entry.to));
            }
            match entry.to {
                EffectPhase::Authorized => {
                    authorized = Some((entry.attempt, entry.capability));
                    reserved = false;
                }
                EffectPhase::Reserved => {
                    if authorized.map(|(attempt, _)| attempt) != Some(entry.attempt) {
                        return Some("a reservation without an authorization".to_owned());
                    }
                    reserved = true;
                }
                EffectPhase::Dispatched => {
                    if !reserved || authorized.map(|(attempt, _)| attempt) != Some(entry.attempt) {
                        return Some("a dispatch without authorization and reservation".into());
                    }
                }
                EffectPhase::Proposed => {
                    authorized = None;
                    reserved = false;
                }
                _ => {}
            }
            if let (Some((_, bound)), Some(current)) = (authorized, entry.capability) {
                if bound != Some(current) {
                    return Some("an attempt's capability changed".to_owned());
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_edges_are_the_section_9_2_chain_plus_failure_reconcile_and_retry() {
        use EffectPhase::*;
        let allowed = [
            (Proposed, Validated),
            (Validated, Authorized),
            (Authorized, Reserved),
            (Reserved, Dispatched),
            (Dispatched, Confirmed),
            (Dispatched, Failed),
            (Dispatched, OutcomeUnknown),
            (OutcomeUnknown, Confirmed),
            (OutcomeUnknown, Failed),
            (Proposed, Failed),
            (Validated, Failed),
            (Authorized, Failed),
            (Reserved, Failed),
            (Failed, Proposed),
        ];
        for from in EffectPhase::ALL {
            for to in EffectPhase::ALL {
                assert_eq!(
                    from.may_follow(to),
                    allowed.contains(&(from, to)),
                    "{from} -> {to}"
                );
            }
        }
        // Nothing leaves confirmed, nothing reaches dispatched except from reserved, and
        // outcome_unknown never goes back to dispatched.
        assert!(EffectPhase::ALL.iter().all(|to| !Confirmed.may_follow(*to)));
        assert!(EffectPhase::ALL
            .iter()
            .filter(|from| from.may_follow(Dispatched))
            .eq([Reserved].iter()));
        assert!(!OutcomeUnknown.may_follow(Dispatched));
        assert!(!OutcomeUnknown.may_follow(Proposed));
    }

    #[test]
    fn effect_state_refuses_unknown_fields() {
        assert!(serde_json::from_value::<EffectState>(serde_json::json!({
            "state": "proposed", "capability": null
        }))
        .is_err());
        assert_eq!(
            serde_json::from_value::<EffectState>(serde_json::json!({"state": "proposed"}))
                .unwrap(),
            EffectState::Proposed
        );
        assert!(serde_json::from_value::<EffectFailure>(serde_json::json!({
            "failure": "cancelled", "retry": true
        }))
        .is_err());
    }
}
