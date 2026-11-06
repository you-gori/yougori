//! The effect controller (VM part §9.2 lines 2344–2353; §4.6 lines 2014–2026; §2.5;
//! §6.3; VM-W31; VM-P13, VM-P30–VM-P32).
//!
//! The controller drives each [`EffectRecord`] through its state machine and keeps every
//! piece of state that must agree in one [`PersistedEffects`]: the records, the
//! idempotency index, the authorization book, the release ledger, the replay guard and
//! the revocation tombstones. Each step works on a copy, persists it through the
//! [`EffectStore`] and only then takes it, so a step either happens completely or not at
//! all, and the reservation an effect consumes at dispatch is consumed exactly once.
//!
//! It reaches the rest of the host through ports: the CORE-04 coordinator for the
//! sandbox's generations, authority and leases ([`AuthorityPort`], implemented over the
//! real coordinator by [`CoordinatorEffectAuthority`]); the CORE-06 audit journal through
//! its one append authority ([`AuditPort`], implemented by [`JournalAudit`]); and a
//! narrow executor ([`EffectExecutor`]).
//!
//! The dispatch boundary rechecks everything a capability depends on immediately before
//! the executor is called: expiry and deadline, the sandbox's authority and all three
//! generations, the revocation tombstone, the executor's lease, the authorization basis
//! and the nonce. A dispatched effect without a receipt becomes `outcome_unknown` after a
//! crash; it is reported and must be reconciled before any retry.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::budget::{
    ChannelKey, ReleaseChannelKind, ReleaseLedger, ReleaseRefusal, ReleaseReservation,
    ReservationToken, WireMeasure,
};
use super::capability::{
    AuthorizationBasis, CapabilityKey, CapabilityRefusal, ExecutorIdentity, OperationCapability,
    PolicyVersion, SealedCapability,
};
use super::contract::{ContractRegistry, DeliveryGuarantee};
use super::delegation::{
    ApprovalId, AuthorizationBook, BudgetRefusal, DelegationId, IndividualApproval, ScopeViolation,
    StandingDelegation,
};
use super::description::{EffectDescription, EffectId, IdempotencyKey, IssuerId, SandboxRef};
use super::executor::{EffectExecutor, ExecutorOutcome, PermittedResponse, TypedOperation};
use super::replay::{NonceRecord, ReplayGuard, ReplayRefusal};
use super::revocation::{
    AckRefusal, BoundNotApplicable, EnforcementPoint, PostRevocationBounds, RevocationAck,
    RevocationRecord, RevocationRegistry,
};
use super::secrets::CredentialHandle;
use super::state::{
    AuditMark, EffectFailure, EffectPhase, EffectReceipt, EffectRecord, EffectState,
    Reconciliation, ReconciliationSource, SettleStep, Settlement, StateRefusal, UnknownCause,
};
use crate::foundation::coordination::{
    CapacityPort, Coordinator, LeaseRefusal, RevocationNotice, SandboxGenerations, SandboxState,
};
use crate::foundation::events::{
    AuditAppendAuthority, AuditDraft, AuditJournal, AuditReceipt, AuditRefusal, AuditSpool,
    AuditStore, EventContext, Field, Generations, HostFact, Phase, Revocation, RevocationReason,
};
use crate::foundation::evidence::{ClockSession, SourceClass};
use crate::foundation::ids::{
    AuthorizationEpoch, Clock, ExecutionId, LeaseId, MonotonicTime, OperationId,
};

/// Where a sandbox stands, as the CORE-04 coordinator reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxStanding {
    /// The sandbox holds authority under its current generations until
    /// `authority_expires_at` on `clock`.
    Authorized {
        generations: SandboxGenerations,
        clock: ClockSession,
        authority_expires_at: MonotonicTime,
    },
    /// The sandbox is at `generations` but holds no authority, as after a revocation.
    NoAuthority {
        generations: SandboxGenerations,
    },
    NotRunning,
}

/// A lease as the coordinator honours it now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseView {
    pub lease: LeaseId,
    pub parent: ExecutionId,
    pub generations: SandboxGenerations,
    pub clock: ClockSession,
    pub expires_at: MonotonicTime,
}

/// The CORE-04 coordinator, as the effect controller reads it (§6.3: an authoritative
/// check, not an eventually delivered notification).
pub trait AuthorityPort {
    fn standing(&self, sandbox: &ExecutionId) -> SandboxStanding;

    /// Whether `lease` is honoured now, with every generation it binds current.
    fn lease(&self, lease: LeaseId) -> Result<LeaseView, LeaseRefusal>;
}

/// [`AuthorityPort`] over the host's [`Coordinator`], shared with the VM lifecycle.
pub struct CoordinatorEffectAuthority<C: Clock, P: CapacityPort> {
    coordinator: Arc<Mutex<Coordinator<C, P>>>,
}

impl<C: Clock, P: CapacityPort> CoordinatorEffectAuthority<C, P> {
    pub fn new(coordinator: Arc<Mutex<Coordinator<C, P>>>) -> Self {
        Self { coordinator }
    }
}

impl<C: Clock, P: CapacityPort> AuthorityPort for CoordinatorEffectAuthority<C, P> {
    fn standing(&self, sandbox: &ExecutionId) -> SandboxStanding {
        let coordinator = self
            .coordinator
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(lifecycle) = coordinator.sandbox(sandbox) else {
            return SandboxStanding::NotRunning;
        };
        let state = lifecycle.state();
        if state == SandboxState::Stopped {
            return SandboxStanding::NotRunning;
        }
        let generations = lifecycle.generations();
        match lifecycle.authority() {
            Some(grant) if state.holds_authority() && grant.epoch == generations.authorization => {
                SandboxStanding::Authorized {
                    generations,
                    clock: grant.clock,
                    authority_expires_at: grant.expires_at,
                }
            }
            _ => SandboxStanding::NoAuthority { generations },
        }
    }

    fn lease(&self, lease: LeaseId) -> Result<LeaseView, LeaseRefusal> {
        let coordinator = self
            .coordinator
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        coordinator.check_lease(lease).map(|lease| LeaseView {
            lease: lease.id(),
            parent: lease.parent().clone(),
            generations: lease.sandbox(),
            clock: lease.clock(),
            expires_at: lease.expires_at(),
        })
    }
}

/// The CORE-06 audit journal, as the effect controller appends to it.
pub trait AuditPort {
    fn record(
        &mut self,
        context: EventContext,
        draft: AuditDraft,
    ) -> Result<AuditReceipt, AuditRefusal>;

    /// The receipt is the permission for a high-impact operation to go ahead.
    fn admit_high_impact(
        &mut self,
        context: EventContext,
        fields: Vec<Field>,
    ) -> Result<AuditReceipt, AuditRefusal>;
}

/// [`AuditPort`] over one [`AuditJournal`] and its one append authority.
pub struct JournalAudit<S, P, C> {
    journal: AuditJournal<S, P, C>,
    authority: AuditAppendAuthority,
}

impl<S: AuditStore, P: AuditSpool, C: Clock> JournalAudit<S, P, C> {
    pub fn new(journal: AuditJournal<S, P, C>, authority: AuditAppendAuthority) -> Self {
        Self { journal, authority }
    }

    pub fn journal(&self) -> &AuditJournal<S, P, C> {
        &self.journal
    }
}

impl<S: AuditStore, P: AuditSpool, C: Clock> AuditPort for JournalAudit<S, P, C> {
    fn record(
        &mut self,
        context: EventContext,
        draft: AuditDraft,
    ) -> Result<AuditReceipt, AuditRefusal> {
        self.journal.append(&mut self.authority, context, draft)
    }

    fn admit_high_impact(
        &mut self,
        context: EventContext,
        fields: Vec<Field>,
    ) -> Result<AuditReceipt, AuditRefusal> {
        self.journal
            .admit_high_impact(&mut self.authority, context, fields)
    }
}

/// Durable storage could not take the state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreFailure {
    pub detail: String,
}

impl fmt::Display for StoreFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the effect state could not be persisted: {}",
            self.detail
        )
    }
}

impl std::error::Error for StoreFailure {}

/// Durable storage of the controller's state; `Ok` once the state is durable.
pub trait EffectStore {
    fn persist(&mut self, state: &PersistedEffects) -> Result<(), StoreFailure>;
}

/// Everything the controller must persist together.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedEffects {
    records: BTreeMap<EffectId, EffectRecord>,
    idempotency: BTreeMap<IdempotencyKey, EffectId>,
    authorizations: AuthorizationBook,
    release: ReleaseLedger,
    replay: ReplayGuard,
    revocations: RevocationRegistry,
    /// Outcomes the audit journal refused, to append again.
    unaudited: BTreeSet<EffectId>,
}

impl PersistedEffects {
    /// A fresh state over `release`.
    pub fn new(release: ReleaseLedger) -> Self {
        Self {
            records: BTreeMap::new(),
            idempotency: BTreeMap::new(),
            authorizations: AuthorizationBook::new(),
            release,
            replay: ReplayGuard::new(),
            revocations: RevocationRegistry::new(),
            unaudited: BTreeSet::new(),
        }
    }

    pub fn records(&self) -> impl Iterator<Item = &EffectRecord> {
        self.records.values()
    }

    /// The record of `effect`, if there is one.
    pub fn record(&self, effect: &EffectId) -> Option<&EffectRecord> {
        self.records.get(effect)
    }

    /// Every grant and budget hold, as persisted with the records (§2.5 line 1815).
    pub fn authorizations(&self) -> &AuthorizationBook {
        &self.authorizations
    }

    /// Checks that each record sits under its own identity and that the idempotency index
    /// names exactly the records.
    fn verify(&self) -> Result<(), EffectError> {
        for (id, record) in &self.records {
            if record.id() != *id {
                return Err(EffectError::CorruptState {
                    detail: format!("a record is stored under another identity ({id})"),
                });
            }
            if self
                .idempotency
                .get(&record.description().idempotency().key)
                != Some(id)
            {
                return Err(EffectError::CorruptState {
                    detail: format!("effect {id} is missing from the idempotency index"),
                });
            }
        }
        if self.idempotency.len() != self.records.len() {
            return Err(EffectError::CorruptState {
                detail: "the idempotency index names unknown effects".to_owned(),
            });
        }
        Ok(())
    }
}

/// The controller's fixed settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControllerConfig {
    /// This host as an issuer; it scopes nonces and generations.
    pub issuer: IssuerId,
    /// The clock session of the controller's clock; a restart needs a new one.
    pub session: ClockSession,
    /// How long an issued capability lasts at most.
    pub capability_lifetime: Duration,
    /// The clock uncertainty compaction and the post-revocation bounds allow for.
    pub allowed_clock_uncertainty: Duration,
}

/// What an authorization asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub basis: AuthorizationBasis,
    pub executor: ExecutorIdentity,
    /// The CORE-04 lease the executor acts under.
    pub lease: LeaseId,
    pub policy_version: PolicyVersion,
}

/// Why a controller call was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectError {
    UnknownEffect {
        effect: EffectId,
    },
    /// Another description already uses this idempotency key; retries keep their exact
    /// description.
    IdempotencyConflict {
        existing: EffectId,
    },
    State(StateRefusal),
    /// The step was refused and the effect moved to `failed` with this failure.
    Refused {
        failure: EffectFailure,
    },
    Audit(AuditRefusal),
    Store(StoreFailure),
    Release(ReleaseRefusal),
    Ack(AckRefusal),
    CorruptState {
        detail: String,
    },
}

impl fmt::Display for EffectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownEffect { effect } => write!(f, "effect {effect} is unknown"),
            Self::IdempotencyConflict { existing } => write!(
                f,
                "effect {existing} already uses this idempotency key with another description"
            ),
            Self::State(refusal) => write!(f, "{refusal}"),
            Self::Refused { failure } => write!(f, "refused: {failure}"),
            Self::Audit(refusal) => write!(f, "{refusal}"),
            Self::Store(failure) => write!(f, "{failure}"),
            Self::Release(refusal) => write!(f, "{refusal}"),
            Self::Ack(refusal) => write!(f, "{refusal}"),
            Self::CorruptState { detail } => write!(f, "the persisted state is corrupt: {detail}"),
        }
    }
}

impl std::error::Error for EffectError {}

/// What a dispatch came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchOutcome {
    /// `confirmed`, `failed` or `outcome_unknown`.
    pub phase: EffectPhase,
    pub receipt: Option<EffectReceipt>,
    pub failure: Option<EffectFailure>,
    pub response: Option<PermittedResponse>,
    /// The bytes that left; `None` when nothing was sent.
    pub sent: Option<WireMeasure>,
    /// Set when the bytes that left could not be counted within the reservation and the
    /// allowance: an executor broke its ceiling, and the caller must treat the release
    /// budget as spent.
    pub release_refusal: Option<ReleaseRefusal>,
    pub audited: bool,
    /// False when storage refused the settled state; recovery from the stored state then
    /// reports the effect as `outcome_unknown`, never as not sent.
    pub persisted: bool,
}

/// An uncertain outcome, as it is reported to the user (VM-P31).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UncertainReport {
    pub effect: EffectId,
    pub sandbox: SandboxRef,
    pub attempt: u32,
    pub since: MonotonicTime,
    pub cause: UnknownCause,
    pub delivery: DeliveryGuarantee,
}

impl UncertainReport {
    /// What the user is told; it never promises exactly-once delivery the provider cannot
    /// give.
    pub fn message(&self) -> String {
        let promise = if self.delivery.promises_exactly_once() {
            "the provider can deduplicate a retry, but"
        } else {
            "the provider cannot deduplicate a retry, so"
        };
        format!(
            "the outcome of attempt {} is unknown; {promise} it is not retried until the \
             provider's state is checked and reconciled",
            self.attempt
        )
    }
}

/// What a revocation did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationReport {
    pub record: RevocationRecord,
    /// Effects authorized or reserved under a revoked epoch, now failed with their
    /// reservations returned.
    pub cancelled: Vec<EffectId>,
    /// Effects dispatched before the linearization point; they settle by their outcome or
    /// by reconciliation, and committed ones stay committed.
    pub in_flight: Vec<EffectId>,
    /// False when the audit journal refused the revocation record; the revocation took
    /// effect regardless.
    pub audited: bool,
}

/// How an attempt concludes: by its dispatch's outcome or by reconciliation.
enum Conclusion {
    Dispatch(Settlement),
    Reconcile(Reconciliation),
}

/// The effect controller of one host (§9.2; VM-W31).
pub struct EffectController<C: Clock, A: AuthorityPort, J: AuditPort, S: EffectStore> {
    config: ControllerConfig,
    clock: C,
    key: CapabilityKey,
    authority: A,
    audit: J,
    store: S,
    contracts: ContractRegistry,
    state: PersistedEffects,
}

fn effect_operation(effect: &EffectId) -> Result<OperationId, EffectError> {
    OperationId::new(format!("effect-{}", effect.digest().to_hex())).map_err(|error| {
        EffectError::CorruptState {
            detail: error.to_string(),
        }
    })
}

fn generations_of(generations: SandboxGenerations) -> Generations {
    Generations::NONE
        .with_sandbox_boot(generations.boot)
        .with_policy(generations.policy)
        .with_authorization(generations.authorization)
}

fn mark(phase: EffectPhase, receipt: AuditReceipt) -> AuditMark {
    AuditMark {
        phase,
        sequence: receipt.sequence.get(),
        digest: receipt.digest,
    }
}

fn provider_channel(description: &EffectDescription) -> ChannelKey {
    ChannelKey {
        kind: ReleaseChannelKind::ProviderRequest,
        trust: description.destination().trust,
    }
}

impl<C: Clock, A: AuthorityPort, J: AuditPort, S: EffectStore> EffectController<C, A, J, S> {
    /// A controller with no effects yet; the empty state is persisted first.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: ControllerConfig,
        clock: C,
        key: CapabilityKey,
        authority: A,
        audit: J,
        store: S,
        contracts: ContractRegistry,
        release: ReleaseLedger,
    ) -> Result<Self, EffectError> {
        let mut controller = Self {
            config,
            clock,
            key,
            authority,
            audit,
            store,
            contracts,
            state: PersistedEffects::new(release.clone()),
        };
        controller.commit(PersistedEffects::new(release))?;
        Ok(controller)
    }

    /// A controller resumed from persisted state after a restart or crash (§4.6 line
    /// 2026). Every effect dispatched without a recorded outcome becomes
    /// `outcome_unknown`; its wire bytes are counted in full, since how many left is
    /// unknown, and its spend stays held until reconciliation.
    #[allow(clippy::too_many_arguments)]
    pub fn recover(
        config: ControllerConfig,
        clock: C,
        key: CapabilityKey,
        authority: A,
        audit: J,
        store: S,
        contracts: ContractRegistry,
        persisted: PersistedEffects,
    ) -> Result<Self, EffectError> {
        persisted.verify()?;
        let mut next = persisted.clone();
        let now = clock.now();
        for record in next.records.values_mut() {
            let Some(held) = record.state().held() else {
                continue;
            };
            if record.recover_after_crash(now) {
                let token = held.release.token;
                let _ = next
                    .release
                    .charge(token, &WireMeasure::body(held.release.reserved_bytes));
                let _ = next.release.release(token);
                next.revocations
                    .note_uncertain(record.description().sandbox(), record.id());
            }
        }
        let mut controller = Self {
            config,
            clock,
            key,
            authority,
            audit,
            store,
            contracts,
            state: persisted,
        };
        controller.commit(next)?;
        Ok(controller)
    }

    fn commit(&mut self, next: PersistedEffects) -> Result<(), EffectError> {
        self.store.persist(&next).map_err(EffectError::Store)?;
        self.state = next;
        Ok(())
    }

    pub fn now(&self) -> MonotonicTime {
        self.clock.now()
    }

    pub fn clock(&self) -> &C {
        &self.clock
    }

    pub fn config(&self) -> &ControllerConfig {
        &self.config
    }

    pub fn authority(&self) -> &A {
        &self.authority
    }

    pub fn authority_mut(&mut self) -> &mut A {
        &mut self.authority
    }

    pub fn audit(&self) -> &J {
        &self.audit
    }

    pub fn audit_mut(&mut self) -> &mut J {
        &mut self.audit
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    pub fn persisted(&self) -> &PersistedEffects {
        &self.state
    }

    pub fn record(&self, effect: &EffectId) -> Option<&EffectRecord> {
        self.state.records.get(effect)
    }

    pub fn release_ledger(&self) -> &ReleaseLedger {
        &self.state.release
    }

    pub fn authorizations(&self) -> &AuthorizationBook {
        &self.state.authorizations
    }

    pub fn revocations(&self) -> &RevocationRegistry {
        &self.state.revocations
    }

    pub fn replay(&self) -> &ReplayGuard {
        &self.state.replay
    }

    fn record_of<'a>(
        state: &'a mut PersistedEffects,
        effect: &EffectId,
    ) -> Result<&'a mut EffectRecord, EffectError> {
        state
            .records
            .get_mut(effect)
            .ok_or(EffectError::UnknownEffect { effect: *effect })
    }

    /// Records a proposed effect. The same description again is the same effect; another
    /// description under an idempotency key already in use is refused.
    pub fn propose(&mut self, description: EffectDescription) -> Result<EffectId, EffectError> {
        let id = description.id();
        if self.state.records.contains_key(&id) {
            return Ok(id);
        }
        let key = description.idempotency().key;
        if let Some(existing) = self.state.idempotency.get(&key) {
            return Err(EffectError::IdempotencyConflict {
                existing: *existing,
            });
        }
        let mut next = self.state.clone();
        next.idempotency.insert(key, id);
        next.records.insert(id, EffectRecord::propose(description));
        self.commit(next)?;
        Ok(id)
    }

    /// Validates the effect against its operation contract.
    pub fn validate(&mut self, effect: &EffectId) -> Result<EffectPhase, EffectError> {
        let now = self.clock.now();
        let mut next = self.state.clone();
        let record = Self::record_of(&mut next, effect)?;
        let result = self
            .contracts
            .get(record.description().operation())
            .and_then(|contract| contract.validate(record.description()));
        record.validate(result, now).map_err(EffectError::State)?;
        let phase = record.phase();
        self.commit(next)?;
        Ok(phase)
    }

    /// Records a standing delegation.
    pub fn grant_delegation(
        &mut self,
        delegation: StandingDelegation,
    ) -> Result<DelegationId, EffectError> {
        let mut next = self.state.clone();
        let id = next.authorizations.grant(delegation);
        self.commit(next)?;
        Ok(id)
    }

    /// Records an individual approval.
    pub fn approve(&mut self, approval: IndividualApproval) -> Result<ApprovalId, EffectError> {
        let mut next = self.state.clone();
        let id = next.authorizations.approve(approval);
        self.commit(next)?;
        Ok(id)
    }

    pub fn revoke_delegation(&mut self, delegation: &DelegationId) -> Result<bool, EffectError> {
        let now = self.clock.now();
        let mut next = self.state.clone();
        let revoked = next.authorizations.revoke_delegation(delegation, now);
        self.commit(next)?;
        Ok(revoked)
    }

    /// The sandbox's current generations and authority expiry, or why it holds none.
    fn current_authority(
        &self,
        sandbox: &SandboxRef,
        now: MonotonicTime,
    ) -> Result<(SandboxGenerations, MonotonicTime), EffectFailure> {
        match self.authority.standing(&sandbox.execution) {
            SandboxStanding::Authorized {
                generations,
                clock,
                authority_expires_at,
            } if clock == self.config.session && now < authority_expires_at => {
                Ok((generations, authority_expires_at))
            }
            _ => Err(EffectFailure::NoAuthority),
        }
    }

    fn check_lease(
        &self,
        lease: LeaseId,
        sandbox: &SandboxRef,
        generations: SandboxGenerations,
    ) -> Result<LeaseView, EffectFailure> {
        let view = self
            .authority
            .lease(lease)
            .map_err(|refusal| EffectFailure::LeaseRefused { refusal })?;
        if view.parent != sandbox.execution
            || view.generations != generations
            || view.clock != self.config.session
        {
            return Err(EffectFailure::LeaseRefused {
                refusal: LeaseRefusal::UnknownLease { lease },
            });
        }
        Ok(view)
    }

    /// What an authorization depends on, checked now.
    fn authorization_terms(
        &self,
        description: &EffectDescription,
        request: &AuthorizationRequest,
        now: MonotonicTime,
    ) -> Result<(SandboxGenerations, MonotonicTime), EffectFailure> {
        let sandbox = description.sandbox();
        if sandbox.issuer != self.config.issuer {
            return Err(EffectFailure::Authorization {
                violation: ScopeViolation::OtherSandbox,
            });
        }
        let deadline = description.deadline();
        if deadline.clock != self.config.session || now >= deadline.at {
            return Err(EffectFailure::DeadlinePassed {
                deadline: deadline.at,
            });
        }
        let (generations, authority_expires_at) = self.current_authority(sandbox, now)?;
        if let Some(record) = self.state.revocations.record(sandbox) {
            if record.denies(generations.authorization) {
                return Err(EffectFailure::Revoked {
                    through: record.revoked_through,
                });
            }
        }
        let lease = self.check_lease(request.lease, sandbox, generations)?;
        self.state
            .authorizations
            .check(
                &request.basis,
                description,
                &request.executor,
                generations.policy,
                now,
                self.config.session,
            )
            .map_err(|violation| EffectFailure::Authorization { violation })?;
        let expires_at = now
            .saturating_add(self.config.capability_lifetime)
            .min(deadline.at)
            .min(lease.expires_at)
            .min(authority_expires_at);
        Ok((generations, expires_at))
    }

    /// validated → authorized: checks the basis, the sandbox's authority and generations,
    /// the tombstone and the executor's lease, then issues and seals a one-use capability
    /// bound to the current generations. A refusal fails the effect.
    pub fn authorize(
        &mut self,
        effect: &EffectId,
        request: AuthorizationRequest,
    ) -> Result<SealedCapability, EffectError> {
        let now = self.clock.now();
        let record = self
            .state
            .records
            .get(effect)
            .ok_or(EffectError::UnknownEffect { effect: *effect })?;
        if record.phase() != EffectPhase::Validated {
            return Err(EffectError::State(StateRefusal::WrongPhase {
                phase: record.phase(),
                action: "authorize",
            }));
        }
        let description = record.description().clone();
        let attempt = record.attempt().saturating_add(1);
        let (generations, expires_at) = match self.authorization_terms(&description, &request, now)
        {
            Ok(terms) => terms,
            Err(failure) => return self.fail_effect(effect, failure, now),
        };
        let mut next = self.state.clone();
        let nonce = next
            .replay
            .issue(description.sandbox())
            .map_err(|refusal| EffectError::Refused {
                failure: EffectFailure::Replay { refusal },
            })?;
        let capability = OperationCapability {
            effect: *effect,
            principal: description.principal().clone(),
            sandbox: description.sandbox().clone(),
            generations,
            policy_version: request.policy_version,
            executor: request.executor,
            lease: request.lease,
            operation: description.operation().clone(),
            resource: description.resource(),
            destination: description.destination(),
            payload: description.payload(),
            attachments: description.attachments_digest(),
            max_cost: description.max_cost(),
            clock: self.config.session,
            expires_at,
            nonce,
            idempotency: description.idempotency(),
            attempt,
            basis: request.basis,
        };
        let sealed = self.key.seal(capability);
        let record = Self::record_of(&mut next, effect)?;
        record
            .authorize(sealed.clone(), now)
            .map_err(EffectError::State)?;
        let receipt = self
            .audit
            .record(
                EventContext::new(effect_operation(effect)?, Phase::Requested)
                    .with_generations(generations_of(generations)),
                AuditDraft::HostFact {
                    fact: HostFact::AuthorizationDecision,
                    fields: vec![
                        Field::metadata("effect", *effect.digest()),
                        Field::metadata("capability", sealed.capability().digest()),
                        Field::metadata("attempt", u64::from(attempt)),
                    ],
                },
            )
            .map_err(EffectError::Audit)?;
        record.add_audit(mark(EffectPhase::Authorized, receipt));
        self.commit(next)?;
        Ok(sealed)
    }

    fn fail_effect<T>(
        &mut self,
        effect: &EffectId,
        failure: EffectFailure,
        now: MonotonicTime,
    ) -> Result<T, EffectError> {
        let mut next = self.state.clone();
        let record = Self::record_of(&mut next, effect)?;
        let held = record
            .fail(failure.clone(), now)
            .map_err(EffectError::State)?;
        if let Some(held) = held {
            let _ = next.release.release(held.release.token);
            let _ = next.authorizations.release(effect);
        }
        self.commit(next)?;
        Err(EffectError::Refused { failure })
    }

    /// authorized → reserved: wire bytes on the provider-request channel and spend under
    /// the authorization basis, both held centrally. Either both are held or neither.
    pub fn reserve(&mut self, effect: &EffectId) -> Result<(), EffectError> {
        let now = self.clock.now();
        let mut next = self.state.clone();
        let record = Self::record_of(&mut next, effect)?;
        let EffectState::Authorized { capability, .. } = record.state() else {
            return Err(EffectError::State(StateRefusal::WrongPhase {
                phase: record.phase(),
                action: "reserve",
            }));
        };
        let basis = capability.capability().basis;
        let description = record.description().clone();
        let release = match next.release.reserve(
            provider_channel(&description),
            description.max_wire_bytes_out(),
        ) {
            Ok(release) => release,
            Err(refusal) => {
                return self.fail_effect(effect, EffectFailure::Release { refusal }, now)
            }
        };
        let spend = description.max_cost().max_spend_microunits;
        if let Err(refusal) = next.authorizations.reserve(basis, *effect, spend) {
            return self.fail_effect(effect, EffectFailure::Budget { refusal }, now);
        }
        Self::record_of(&mut next, effect)?
            .reserve(
                super::state::HeldReservation {
                    release,
                    spend_microunits: spend,
                },
                now,
            )
            .map_err(EffectError::State)?;
        self.commit(next)
    }

    /// The dispatch boundary's checks (§9.2 line 2351: recheck policy epoch immediately
    /// before the dispatch boundary). On success the nonce is consumed in `next`.
    fn dispatch_gate(
        &self,
        next: &mut PersistedEffects,
        description: &EffectDescription,
        sealed: &SealedCapability,
        executor: &ExecutorIdentity,
        now: MonotonicTime,
    ) -> Result<(), EffectFailure> {
        let session = self.config.session;
        let capability = self
            .key
            .verify(sealed)
            .map_err(|refusal| EffectFailure::Capability { refusal })?;
        capability
            .check_binding(description)
            .and_then(|()| capability.check_time(now, session))
            .map_err(|refusal| EffectFailure::Capability { refusal })?;
        if &capability.executor != executor {
            return Err(EffectFailure::Capability {
                refusal: CapabilityRefusal::WrongExecutor,
            });
        }
        let deadline = description.deadline();
        if deadline.clock != session || now >= deadline.at {
            return Err(EffectFailure::DeadlinePassed {
                deadline: deadline.at,
            });
        }
        let sandbox = description.sandbox();
        let (current, _) = self.current_authority(sandbox, now)?;
        let bound = capability.generations;
        if bound.boot != current.boot {
            return Err(EffectFailure::BootGenerationChanged {
                bound: bound.boot,
                current: current.boot,
            });
        }
        if bound.authorization != current.authorization {
            return Err(EffectFailure::AuthorizationEpochChanged {
                bound: bound.authorization,
                current: current.authorization,
            });
        }
        if bound.policy != current.policy {
            return Err(EffectFailure::PolicyEpochChanged {
                bound: bound.policy,
                current: current.policy,
            });
        }
        if let Some(record) = next.revocations.record(sandbox) {
            if record.denies(bound.authorization) {
                return Err(EffectFailure::Revoked {
                    through: record.revoked_through,
                });
            }
        }
        self.check_lease(capability.lease, sandbox, current)?;
        next.authorizations
            .check(
                &capability.basis,
                description,
                &capability.executor,
                current.policy,
                now,
                session,
            )
            .map_err(|violation| EffectFailure::Authorization { violation })?;
        next.replay
            .consume_issued(
                sandbox,
                capability.nonce,
                NonceRecord {
                    clock: capability.clock,
                    expires_at: capability.expires_at,
                    epoch: bound.authorization,
                },
                now,
                session,
                current.authorization,
            )
            .map_err(|refusal: ReplayRefusal| EffectFailure::Replay { refusal })
    }

    /// reserved → dispatched → confirmed, failed or outcome_unknown.
    ///
    /// The boundary checks run first; a refusal fails the effect and returns its
    /// reservations without sending anything. Otherwise the dispatch is admitted through
    /// the audit journal (its receipt is the permission), the reservation is consumed and
    /// the dispatched state is persisted, and only then is the executor called. A second
    /// dispatch of the same effect is refused, so one reservation backs one dispatch.
    pub fn dispatch(
        &mut self,
        effect: &EffectId,
        executor: &mut dyn EffectExecutor,
        credential: CredentialHandle,
    ) -> Result<DispatchOutcome, EffectError> {
        let now = self.clock.now();
        let record = self
            .state
            .records
            .get(effect)
            .ok_or(EffectError::UnknownEffect { effect: *effect })?;
        let EffectState::Reserved {
            capability, held, ..
        } = record.state()
        else {
            let refusal = match record.phase() {
                EffectPhase::Dispatched => StateRefusal::InFlight,
                EffectPhase::OutcomeUnknown => StateRefusal::NeedsReconciliation,
                EffectPhase::Confirmed => StateRefusal::AlreadyConfirmed,
                phase => StateRefusal::WrongPhase {
                    phase,
                    action: "dispatch",
                },
            };
            return Err(EffectError::State(refusal));
        };
        let (sealed, held) = (capability.clone(), *held);
        let description = record.description().clone();
        let mut next = self.state.clone();
        if let Err(failure) =
            self.dispatch_gate(&mut next, &description, &sealed, executor.identity(), now)
        {
            let mut refused = self.state.clone();
            Self::record_of(&mut refused, effect)?
                .dispatch(Err(failure.clone()), now)
                .map_err(EffectError::State)?;
            let _ = refused.release.release(held.release.token);
            let _ = refused.authorizations.release(effect);
            self.commit(refused)?;
            return Ok(DispatchOutcome {
                phase: EffectPhase::Failed,
                receipt: None,
                failure: Some(failure),
                response: None,
                sent: None,
                release_refusal: None,
                audited: false,
                persisted: true,
            });
        }
        let capability = sealed.capability();
        let admitted = self
            .audit
            .admit_high_impact(
                EventContext::new(effect_operation(effect)?, Phase::Running)
                    .with_generations(generations_of(capability.generations)),
                vec![
                    Field::metadata("effect", *effect.digest()),
                    Field::metadata("capability", capability.digest()),
                    Field::metadata("attempt", u64::from(capability.attempt)),
                    Field::metadata("route", *description.destination().route.digest()),
                ],
            )
            .map_err(EffectError::Audit)?;
        next.authorizations
            .consume(effect)
            .map_err(|refusal: BudgetRefusal| EffectError::Refused {
                failure: EffectFailure::Budget { refusal },
            })?;
        let record = Self::record_of(&mut next, effect)?;
        record.dispatch(Ok(()), now).map_err(EffectError::State)?;
        record.add_audit(mark(EffectPhase::Dispatched, admitted));
        self.commit(next)?;

        let report = executor.execute(
            TypedOperation {
                description: &description,
                capability: &sealed,
                credential,
            },
            now,
        );
        let mut response = None;
        let settlement = match report.outcome {
            ExecutorOutcome::Refused(refusal) => {
                Settlement::NotCommitted(EffectFailure::Executor { refusal })
            }
            ExecutorOutcome::Committed {
                result,
                response: permitted,
            } => {
                response = Some(permitted);
                Settlement::Committed(result)
            }
            ExecutorOutcome::Rejected { code } => {
                Settlement::NotCommitted(EffectFailure::ProviderRejected { code })
            }
            ExecutorOutcome::RedirectRefused { route } => {
                Settlement::NotCommitted(EffectFailure::RedirectRefused { route })
            }
            ExecutorOutcome::PartialSuccess { partial } => {
                Settlement::Unknown(UnknownCause::PartialSuccess { partial })
            }
            ExecutorOutcome::NoResponse => Settlement::Unknown(UnknownCause::ResponseLost),
        };
        let release_refusal = self.settle_wire(held.release, report.sent.as_ref());
        let mut outcome = self.conclude(effect, Conclusion::Dispatch(settlement))?;
        outcome.sent = report.sent;
        outcome.response = response;
        outcome.release_refusal = release_refusal;
        Ok(outcome)
    }

    /// Counts the bytes that left and returns the rest of the wire reservation. Wire bytes
    /// settle when the attempt ends, whatever its outcome, because the sender knows what
    /// it sent even when no reply came.
    fn settle_wire(
        &mut self,
        release: ReleaseReservation,
        sent: Option<&WireMeasure>,
    ) -> Option<ReleaseRefusal> {
        let mut refusal = None;
        if let Some(measure) = sent {
            if let Err(error) = self.state.release.charge(release.token, measure) {
                // The bytes already left: count the whole reservation and report the rest.
                let _ = self
                    .state
                    .release
                    .charge(release.token, &WireMeasure::body(release.reserved_bytes));
                refusal = Some(error);
            }
        }
        let _ = self.state.release.release(release.token);
        refusal
    }

    /// Applies a settlement or a reconciliation, settles the spend hold, audits the
    /// outcome and persists.
    fn conclude(
        &mut self,
        effect: &EffectId,
        conclusion: Conclusion,
    ) -> Result<DispatchOutcome, EffectError> {
        let now = self.clock.now();
        let mut next = self.state.clone();
        let record = Self::record_of(&mut next, effect)?;
        let step = match conclusion {
            Conclusion::Dispatch(settlement) => record.settle(settlement, now),
            Conclusion::Reconcile(reconciliation) => record.reconcile(reconciliation, now),
        }
        .map_err(EffectError::State)?;
        let phase = record.phase();
        let sandbox = record.description().sandbox().clone();
        let generations = record
            .state()
            .capability()
            .map(|sealed| sealed.capability().generations);
        let failure = match record.state() {
            EffectState::Failed { failure } => Some(failure.clone()),
            _ => None,
        };
        let receipt = match step {
            SettleStep::Confirmed { receipt, .. } => {
                let _ = next.authorizations.settle(
                    effect,
                    true,
                    receipt.provider_result.spend_microunits,
                );
                next.revocations.resolve_uncertain(&sandbox, effect);
                Some(receipt)
            }
            SettleStep::Failed { .. } => {
                let _ = next.authorizations.settle(effect, false, 0);
                next.revocations.resolve_uncertain(&sandbox, effect);
                None
            }
            SettleStep::Unknown => {
                next.revocations.note_uncertain(&sandbox, *effect);
                None
            }
        };
        let audit_phase = match phase {
            EffectPhase::Confirmed => Phase::Completed,
            EffectPhase::Failed => Phase::Failed,
            _ => Phase::Running,
        };
        let mut fields = vec![
            Field::metadata("effect", *effect.digest()),
            Field::metadata("outcome", phase.name()),
        ];
        if let Some(receipt) = &receipt {
            fields.push(Field::metadata("receipt", receipt.digest));
            fields.push(Field::metadata("result", receipt.provider_result.result));
        }
        let mut context = EventContext::new(effect_operation(effect)?, audit_phase);
        if let Some(generations) = generations {
            context = context.with_generations(generations_of(generations));
        }
        let audited = match self.audit.record(
            context,
            AuditDraft::HostFact {
                fact: HostFact::ExternalEffect,
                fields,
            },
        ) {
            Ok(receipt) => {
                Self::record_of(&mut next, effect)?.add_audit(mark(phase, receipt));
                next.unaudited.remove(effect);
                true
            }
            Err(_) => {
                next.unaudited.insert(*effect);
                false
            }
        };
        let persisted = match self.store.persist(&next) {
            Ok(()) => true,
            Err(_) => false,
        };
        // The outcome happened whether or not storage took it, so memory keeps it.
        self.state = next;
        Ok(DispatchOutcome {
            phase,
            receipt,
            failure,
            response: None,
            sent: None,
            release_refusal: None,
            audited,
            persisted,
        })
    }

    /// Reconciles an uncertain outcome by asking the provider through the executor, at
    /// the controller's clock reading.
    pub fn reconcile(
        &mut self,
        effect: &EffectId,
        executor: &mut dyn EffectExecutor,
        credential: CredentialHandle,
    ) -> Result<DispatchOutcome, EffectError> {
        let now = self.clock.now();
        let record = self
            .state
            .records
            .get(effect)
            .ok_or(EffectError::UnknownEffect { effect: *effect })?;
        if record.phase() != EffectPhase::OutcomeUnknown {
            return Err(EffectError::State(StateRefusal::WrongPhase {
                phase: record.phase(),
                action: "reconcile",
            }));
        }
        let description = record.description().clone();
        let observation = executor.lookup(&description, credential, now);
        self.reconcile_with(
            effect,
            Reconciliation {
                observation,
                source: ReconciliationSource::ProviderLookup,
            },
        )
    }

    /// Reconciles an uncertain outcome with an explicit observation, such as the user's.
    pub fn reconcile_with(
        &mut self,
        effect: &EffectId,
        reconciliation: Reconciliation,
    ) -> Result<DispatchOutcome, EffectError> {
        self.conclude(effect, Conclusion::Reconcile(reconciliation))
    }

    /// failed → proposed under the same identity and description.
    pub fn retry(&mut self, effect: &EffectId) -> Result<(), EffectError> {
        let now = self.clock.now();
        let mut next = self.state.clone();
        Self::record_of(&mut next, effect)?
            .retry(now)
            .map_err(EffectError::State)?;
        self.commit(next)
    }

    /// Cancels an effect before dispatch and returns its reservations.
    pub fn cancel(&mut self, effect: &EffectId) -> Result<(), EffectError> {
        let now = self.clock.now();
        match self.fail_effect::<()>(effect, EffectFailure::Cancelled, now) {
            Err(EffectError::Refused { .. }) => Ok(()),
            other => other,
        }
    }

    /// Revokes `sandbox` through `revoked_through` (§6.3 steps 1, 2 and 5). The tombstone
    /// is the linearization point: no authorization or dispatch bound to a revoked epoch
    /// succeeds afterwards. Authorized and reserved effects under it fail and return their
    /// reservations; dispatched and uncertain ones are recorded as uncertain until they
    /// settle; confirmed ones are untouched, since committed actions are never revoked
    /// retroactively. Every delegation and approval of the sandbox is revoked.
    pub fn revoke(
        &mut self,
        sandbox: &SandboxRef,
        revoked_through: AuthorizationEpoch,
        reason: RevocationReason,
    ) -> Result<RevocationReport, EffectError> {
        let now = self.clock.now();
        let mut next = self.state.clone();
        next.revocations
            .revoke(sandbox, revoked_through, reason, now);
        next.authorizations.revoke_sandbox(sandbox, now);
        let mut cancelled = Vec::new();
        let mut in_flight = Vec::new();
        let ids: Vec<EffectId> = next
            .records
            .values()
            .filter(|record| record.description().sandbox() == sandbox)
            .map(EffectRecord::id)
            .collect();
        for id in ids {
            let record = Self::record_of(&mut next, &id)?;
            let epoch = record
                .state()
                .capability()
                .map(|sealed| sealed.capability().generations.authorization);
            match record.phase() {
                EffectPhase::Authorized | EffectPhase::Reserved
                    if epoch.is_some_and(|epoch| epoch <= revoked_through) =>
                {
                    let held = record
                        .fail(
                            EffectFailure::Revoked {
                                through: revoked_through,
                            },
                            now,
                        )
                        .map_err(EffectError::State)?;
                    if let Some(held) = held {
                        let _ = next.release.release(held.release.token);
                        let _ = next.authorizations.release(&id);
                    }
                    cancelled.push(id);
                }
                EffectPhase::Dispatched | EffectPhase::OutcomeUnknown => {
                    next.revocations.note_uncertain(sandbox, id);
                    in_flight.push(id);
                }
                _ => {}
            }
        }
        // A revocation never waits on audit storage: a refused record is reported, and
        // the revocation still takes effect.
        let audited = self
            .audit
            .record(
                EventContext::new(
                    OperationId::new(format!("revoke-{}", sandbox.execution)).map_err(|error| {
                        EffectError::CorruptState {
                            detail: error.to_string(),
                        }
                    })?,
                    Phase::Revoked,
                ),
                AuditDraft::Revocation(Revocation {
                    execution: sandbox.execution.clone(),
                    epoch: revoked_through.next().unwrap_or(revoked_through),
                    reason,
                }),
            )
            .is_ok();
        let record =
            next.revocations
                .record(sandbox)
                .cloned()
                .ok_or_else(|| EffectError::CorruptState {
                    detail: "the tombstone was not recorded".to_owned(),
                })?;
        self.commit(next)?;
        Ok(RevocationReport {
            record,
            cancelled,
            in_flight,
            audited,
        })
    }

    /// [`EffectController::revoke`] for a CORE-04 revocation notice of this host's sandbox.
    pub fn revoke_from_notice(
        &mut self,
        notice: &RevocationNotice,
        reason: RevocationReason,
    ) -> Result<RevocationReport, EffectError> {
        let sandbox = SandboxRef {
            issuer: self.config.issuer,
            execution: notice.execution.clone(),
        };
        self.revoke(&sandbox, notice.revoked, reason)
    }

    /// Records one revocation acknowledgment, backed by evidence from `source`.
    pub fn acknowledge(
        &mut self,
        sandbox: &SandboxRef,
        ack: RevocationAck,
        source: SourceClass,
    ) -> Result<(), EffectError> {
        let now = self.clock.now();
        let mut next = self.state.clone();
        next.revocations
            .acknowledge(sandbox, ack, source, now)
            .map_err(EffectError::Ack)?;
        self.commit(next)
    }

    /// Every uncertain outcome, for the user (VM-P31).
    pub fn uncertain_outcomes(&self) -> Vec<UncertainReport> {
        self.state
            .records
            .values()
            .filter_map(|record| match record.state() {
                EffectState::OutcomeUnknown {
                    delivery,
                    cause,
                    since,
                    ..
                } => Some(UncertainReport {
                    effect: record.id(),
                    sandbox: record.description().sandbox().clone(),
                    attempt: record.attempt(),
                    since: *since,
                    cause: *cause,
                    delivery: *delivery,
                }),
                _ => None,
            })
            .collect()
    }

    /// Effects of `sandbox` that hold a reservation: reserved, dispatched or uncertain.
    pub fn outstanding_reserved_effects(&self, sandbox: &SandboxRef) -> u64 {
        let count = self
            .state
            .records
            .values()
            .filter(|record| {
                record.description().sandbox() == sandbox && record.state().held().is_some()
            })
            .count();
        u64::try_from(count).unwrap_or(u64::MAX)
    }

    /// The §2.5 post-revocation bounds for `sandbox` behind an enforcement point holding a
    /// lease of `lease_ttl` with `valid_lease_budget` effects left.
    pub fn post_revocation_bounds(
        &self,
        sandbox: &SandboxRef,
        point: EnforcementPoint,
        lease_ttl: Duration,
        valid_lease_budget: u64,
    ) -> Result<PostRevocationBounds, BoundNotApplicable> {
        PostRevocationBounds::compute(
            point,
            lease_ttl,
            self.config.allowed_clock_uncertainty,
            self.outstanding_reserved_effects(sandbox),
            valid_lease_budget,
        )
    }

    /// Reserves bytes on a non-provider release channel, such as DNS, logs or previews.
    pub fn reserve_release(
        &mut self,
        channel: ChannelKey,
        bytes: u64,
    ) -> Result<ReleaseReservation, EffectError> {
        let mut next = self.state.clone();
        let reservation = next
            .release
            .reserve(channel, bytes)
            .map_err(EffectError::Release)?;
        self.commit(next)?;
        Ok(reservation)
    }

    /// Charges one release before its bytes leave.
    pub fn charge_release(
        &mut self,
        token: ReservationToken,
        measure: &WireMeasure,
    ) -> Result<super::budget::ReleaseCharge, EffectError> {
        let mut next = self.state.clone();
        let charge = next
            .release
            .charge(token, measure)
            .map_err(EffectError::Release)?;
        self.commit(next)?;
        Ok(charge)
    }

    /// Ends a release reservation and returns its unspent bytes.
    pub fn return_release(&mut self, token: ReservationToken) -> Result<u64, EffectError> {
        let mut next = self.state.clone();
        let returned = next.release.release(token).map_err(EffectError::Release)?;
        self.commit(next)?;
        Ok(returned)
    }

    /// Compacts replay records and tombstones that no live capability can need.
    pub fn compact(&mut self) -> Result<(usize, usize), EffectError> {
        let now = self.clock.now();
        let session = self.config.session;
        let uncertainty = self.config.allowed_clock_uncertainty;
        let mut next = self.state.clone();
        let current = |sandbox: &SandboxRef| match self.authority.standing(&sandbox.execution) {
            SandboxStanding::Authorized { generations, .. }
            | SandboxStanding::NoAuthority { generations } => Some(generations.authorization),
            SandboxStanding::NotRunning => None,
        };
        let replay = next.replay.compact(now, session, uncertainty, current);
        let latest: BTreeMap<SandboxRef, (ClockSession, MonotonicTime)> = next
            .records
            .values()
            .filter_map(|record| {
                record.state().capability().map(|sealed| {
                    let capability = sealed.capability();
                    (
                        capability.sandbox.clone(),
                        (capability.clock, capability.expires_at),
                    )
                })
            })
            .fold(BTreeMap::new(), |mut latest, (sandbox, (clock, at))| {
                let entry = latest.entry(sandbox).or_insert((clock, at));
                if entry.0 == clock && at > entry.1 {
                    entry.1 = at;
                }
                latest
            });
        let tombstones = next
            .revocations
            .compact(now, session, uncertainty, current, |sandbox| {
                latest.get(sandbox).copied()
            });
        self.commit(next)?;
        Ok((replay.removed, tombstones))
    }
}
