//! Workflow intent turned into bounded, cancellable preparation under the CORE-03 ledger
//! and CORE-04 leases (GPU §4.1 lines 824–830; §2.9 lines 624–633; GPU-W06: prepare
//! deadlines, TTLs, per-tenant budgets and explicit workflow intent; bounded speculative
//! work with foreground promotion and cancellation; queue fairness; stale-state
//! reconciliation; demand-only as the runtime rollback).
//!
//! A [`PreparationGovernor`] takes a workflow's declared next steps ([`WorkflowIntent`])
//! and prepares each through the existing readiness pieces:
//!
//! - Policy. [`PreparationMode::DemandOnly`] is the default and the rollback: nothing is
//!   prepared, and rolling back ([`PreparationGovernor::roll_back`], or following the
//!   §2.9 [`ModeController`] with [`PreparationGovernor::follow`]) cancels every
//!   speculative preparation and returns its reservations. Workflow intent runs only once
//!   enabled.
//! - Bounds. At most `max_lookahead` steps per declaration and `max_active` preparations,
//!   and at most `max_speculative_bytes` of background reservations, a shared
//!   prerequisite counted once. A step whose §2.9 expected value
//!   ([`expected_value`]) is not positive is declined: its saved delay is the step's
//!   reload cost from [`super::observed`], measured or labelled. A re-declaration
//!   supersedes the workflow's speculative preparations it no longer names.
//! - Admission. Each step is a [`PrepareOperation`] admitted against its deadline with
//!   the pessimistic end of its reload cost (uncertainty-aware). Its prerequisites are
//!   acquired once through [`SharedPrerequisites`] and its own demand is reserved as
//!   background work by the model placement governor, waiting in the ledger's bounded
//!   queue only until the latest start that still meets the deadline, so the ledger
//!   refuses it before the deadline passes. Tenant budgets, holds and queue fairness are
//!   the ledger's.
//! - Following ([`PreparationGovernor::poll`]). Each preparation follows the CORE-04
//!   lease it runs under through its [`CancellationToken`]; its deadline and retention TTL
//!   through [`PrepareOperation::poll`]; and its requests and reservations in the ledger:
//!   a grant is taken up, and a refused request or a reservation closed or released by
//!   someone else (reclaimed, revoked) ends the preparation. Every ending withdraws or cancels what it
//!   held; a shared prerequisite is released only by its last holder.
//! - Promotion ([`PreparationGovernor::request_arrived`]). A request for a ready target
//!   uses it; for a running one, the preparation is promoted to demand: its waiting
//!   background requests are re-filed as foreground, which the ledger's foreground-first
//!   fairness serves first, and the caller promotes the same transfer in the executor
//!   (§2.9: promotion reuses the transfer).
//!
//! The governor never changes the ledger's queue fairness, which is host-wide: it stays
//! arrival order unless the host owner opts in to foreground first. Promotion then still
//! re-files, but only foreground first serves it ahead of background work.
//!
//! Time comes from the caller's [`Clock`], which must read the same monotonic clock as
//! the ledger's.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::time::Duration;

use crate::foundation::coordination::LeaseState;
use crate::foundation::ids::{Clock, ExecutionId, LeaseId, MonotonicTime, OperationId, TenantId};
use crate::foundation::ledger::{
    Amounts, Ledger, LedgerError, Priority, QueueTicket, ReservationId,
};
use crate::model_memory::math::calibration::{DemandOnlyReason, ModeController, SchedulingMode};
use crate::model_memory::math::prefetch::{
    expected_value, CandidateOrigin, Objective, PrefetchCandidate, PrefetchError, RawCost,
};
use crate::model_memory::math::CandidateId;
use crate::model_memory::readiness::intent::{
    Arrival, CancelReason, CancellationToken, PrepareBounds, PrepareOperation, PrepareRefusal,
    PrepareRequest, PrepareState, PrepareTarget, PrepareWork, ReleaseReason,
};

use super::observed::{Basis, ReloadCost};
use super::shared::{
    bytes_of, file, follow, promote_holding, provenance, release_holding, Holding, LedgerRelease,
    PrerequisiteDemand, PrerequisiteKey, PromotionEffect, SharedEvent, SharedPrerequisites,
    SharedRefusal,
};

pub mod reconcile;
pub mod tenants;

/// Why preparation is demand-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RollbackCause {
    /// Workflow intent was never enabled: the default.
    Default,
    /// An operator rolled back.
    Operator,
    /// The §2.9 mode controller fell back: low confidence, overload or drift.
    Controller { reason: DemandOnlyReason },
}

/// Whether the governor prepares anything (§2.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparationMode {
    /// Demand loads only; nothing is prepared ahead.
    DemandOnly { cause: RollbackCause },
    /// Declared workflow steps are prepared within the bounds.
    WorkflowIntent,
}

/// The governor's settings.
#[derive(Clone, Debug, PartialEq)]
pub struct GovernorConfig {
    /// The placement governor's own execution: shared prerequisites are reserved under
    /// it, so revoking one workflow does not take what other workflows hold.
    pub execution: ExecutionId,
    /// Deadline and retention TTL limits of every preparation.
    pub prepare: PrepareBounds,
    /// Preparations admitted and not ended, at most.
    pub max_active: usize,
    /// Declared steps looked at per workflow; later ones are left for a later
    /// declaration.
    pub max_lookahead: usize,
    /// Bytes of background reservations the governor holds or waits for at once, a
    /// shared prerequisite counted once.
    pub max_speculative_bytes: u64,
    /// Ended preparations kept until taken; older ones are dropped first and counted.
    pub max_outcomes: usize,
    /// How long a promoted preparation's foreground request may wait in the queue.
    pub promotion_wait: Duration,
    /// The declared objective a step's expected value is scored in (§2.9).
    pub objective: Objective,
}

/// One declared next step of a workflow (§4.1: model identity, optional adapter,
/// deadline, cancellation and retention TTL).
#[derive(Clone, Debug, PartialEq)]
pub struct DeclaredStep {
    /// The preparation's own operation.
    pub operation: OperationId,
    pub target: PrepareTarget,
    /// When the step's request is expected; the preparation must be ready by then.
    pub deadline: MonotonicTime,
    pub retention_ttl: Duration,
    pub work: Vec<PrepareWork>,
    /// The pending request computing ahead is assigned to (§3.6).
    pub assigned_request: Option<OperationId>,
    /// The CORE-04 lease the preparation runs under.
    pub lease: LeaseId,
    /// How likely the step's request is: 1 for the next queued step, less for a branch.
    pub probability: f64,
    /// The target's reload cost, measured or labelled ([`super::observed`]).
    pub cost: ReloadCost,
    /// What the preparation holds itself, such as an adapter, KV or a process.
    pub demand: Amounts,
    /// What it shares with other preparations, such as a base model.
    pub prerequisites: Vec<PrerequisiteDemand>,
}

/// A workflow's declared next steps, nearest first. Each declaration replaces the
/// previous one of the same execution.
#[derive(Clone, Debug, PartialEq)]
pub struct WorkflowIntent {
    pub execution: ExecutionId,
    pub tenant: TenantId,
    pub steps: Vec<DeclaredStep>,
}

/// Why a declared step is not prepared.
#[derive(Clone, Debug, PartialEq)]
pub enum DeclineReason {
    DemandOnly {
        cause: RollbackCause,
    },
    /// Beyond `max_lookahead`.
    BeyondLookahead,
    ActiveLimit {
        max_active: usize,
    },
    SpeculativeBytes {
        requested: u64,
        held: u64,
        limit: u64,
    },
    /// The §2.9 expected value is not positive.
    NotWorthIt {
        expected_value: f64,
    },
    Value(PrefetchError),
    /// The operation is already used by another workflow or target.
    DuplicateOperation,
    /// The step lists the same prerequisite twice.
    DuplicatePrerequisite {
        key: PrerequisiteKey,
    },
    Prepare(PrepareRefusal),
    Prerequisite(SharedRefusal),
    Capacity(LedgerError),
}

/// What a declaration did with one step.
#[derive(Clone, Debug, PartialEq)]
pub enum StepOutcome {
    Admitted {
        /// Its own reservation; `None` when everything it needs is shared.
        own: Option<Holding>,
        expected_value: f64,
    },
    /// The same step is already being prepared.
    AlreadyPreparing,
    Declined {
        reason: DeclineReason,
    },
}

/// One step's decision.
#[derive(Clone, Debug, PartialEq)]
pub struct StepDecision {
    pub operation: OperationId,
    pub outcome: StepOutcome,
}

/// What a declaration did.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DeclarationReport {
    pub steps: Vec<StepDecision>,
    /// Speculative preparations of the workflow that the new declaration no longer names.
    pub superseded: Vec<PreparationOutcome>,
}

/// Why a preparation ended. When the governor itself ends a preparation, for a ledger,
/// prerequisite, supersession or rollback reason, it cancels the preparation's token
/// first, as the requester unless a closer [`CancelReason`] exists, and this names the
/// true reason.
#[derive(Clone, Debug, PartialEq)]
pub enum PreparationEnd {
    /// By its own rules: cancelled (requester, superseded, lease, demand-only), its
    /// deadline missed, or its retention TTL expired.
    Released { reason: ReleaseReason },
    /// Preparation was rolled back to demand-only.
    RolledBack { cause: RollbackCause },
    /// The ledger refused its waiting request: its latest start passed, a hold denied it
    /// or its execution was cancelled.
    CapacityRefused { ticket: QueueTicket },
    /// Its reservation was closed or set releasing by someone else: reclaimed unused,
    /// or cancelled with its execution.
    ReservationLost { reservation: ReservationId },
    /// A shared prerequisite it needs was refused or closed.
    PrerequisiteLost { key: PrerequisiteKey },
    /// The caller finished with it after a request used it.
    Finished,
    /// Its work began, and stale-state reconciliation found that the executor no longer
    /// carries it ([`reconcile`]).
    WorkLost { loss: reconcile::WorkLoss },
}

/// One ended preparation, with what it cost and what the ledger did with its holdings.
#[derive(Clone, Debug, PartialEq)]
pub struct PreparationOutcome {
    pub operation: OperationId,
    pub execution: ExecutionId,
    pub tenant: TenantId,
    pub target: PrepareTarget,
    pub end: PreparationEnd,
    /// Whether a request used or promoted it.
    pub used: bool,
    pub prepared_bytes: u64,
    /// Prepared bytes no request used.
    pub wasted_bytes: u64,
    pub admitted_at: MonotonicTime,
    pub ended_at: MonotonicTime,
    /// Where the reload cost it was admitted with came from.
    pub cost_basis: Basis,
    pub expected_value: f64,
    /// Its own holding first, then each prerequisite in declared order.
    pub released: Vec<LedgerRelease>,
}

/// Something the governor's following found.
#[derive(Clone, Debug, PartialEq)]
pub enum GovernorEvent {
    /// Everything the preparation needs is granted: its work may begin
    /// ([`PreparationGovernor::begin_work`]).
    Granted {
        operation: OperationId,
    },
    Ended {
        outcome: PreparationOutcome,
    },
}

/// What the ledger granted for one preparation's work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkGrant {
    pub own: Option<ReservationId>,
    pub prerequisites: Vec<ReservationId>,
}

/// What a request's arrival found.
#[derive(Clone, Debug, PartialEq)]
pub enum ArrivalReport {
    /// A ready preparation serves the request.
    Used {
        operation: OperationId,
        prepared_bytes: u64,
    },
    /// A running preparation was promoted to demand. The caller promotes the same
    /// transfer in the executor (`TransferExecutor::promote`).
    Promoted {
        operation: OperationId,
        own: PromotionEffect,
        prerequisites: Vec<(PrerequisiteKey, Result<PromotionEffect, SharedRefusal>)>,
    },
    /// Nothing was prepared for the target: the ordinary demand load serves it.
    NoPreparation,
}

/// Why a governor call was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum GovernorError {
    InvalidConfig {
        field: &'static str,
    },
    UnknownPreparation {
        operation: OperationId,
    },
    /// Its work cannot begin: it is not running.
    NotRunning {
        operation: OperationId,
    },
    /// Its work cannot begin: something it needs still waits for capacity.
    NotGranted {
        operation: OperationId,
    },
    /// No request used it, so there is nothing to finish; cancel it instead.
    NotUsed {
        operation: OperationId,
    },
    Prepare(PrepareRefusal),
    Prerequisite(SharedRefusal),
    Ledger(LedgerError),
}

impl fmt::Display for GovernorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { field } => write!(f, "the governor's {field} is invalid"),
            Self::UnknownPreparation { operation } => write!(f, "no preparation {operation}"),
            Self::NotRunning { operation } => write!(f, "{operation} is not running"),
            Self::NotGranted { operation } => {
                write!(f, "{operation} still waits for capacity")
            }
            Self::NotUsed { operation } => {
                write!(f, "no request used {operation}; cancel it instead")
            }
            Self::Prepare(refusal) => refusal.fmt(f),
            Self::Prerequisite(refusal) => refusal.fmt(f),
            Self::Ledger(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for GovernorError {}

/// Where a governed preparation is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Prepared ahead of its request.
    Speculative,
    /// Its request arrived while it ran; it is demand work now.
    Promoted,
    /// Its request uses the prepared state.
    Serving,
}

#[derive(Clone, Debug)]
struct Governed {
    operation: PrepareOperation,
    lease: LeaseId,
    phase: Phase,
    demand: Amounts,
    own: Option<Holding>,
    prerequisites: Vec<PrerequisiteKey>,
    cost_basis: Basis,
    expected_value: f64,
    /// Whether [`GovernorEvent::Granted`] was reported.
    announced: bool,
    /// Bytes the work of a promoted preparation completed with.
    promoted_bytes: u64,
}

impl Governed {
    fn execution(&self) -> &ExecutionId {
        &self.operation.request().execution
    }

    fn tenant(&self) -> &TenantId {
        &self.operation.request().tenant
    }
}

/// How an ending treats the preparation's own token.
enum Ending {
    /// Cancel it with this reason first.
    Cancel(CancelReason),
    /// It already ended by its own rules.
    AsIs,
}

/// Prepares declared workflow steps under the ledger and leases (see the module
/// documentation). Demand-only until workflow intent is enabled.
#[derive(Debug)]
pub struct PreparationGovernor {
    config: GovernorConfig,
    mode: PreparationMode,
    active: BTreeMap<OperationId, Governed>,
    shared: SharedPrerequisites,
    outcomes: VecDeque<PreparationOutcome>,
    outcomes_dropped: u64,
}

impl PreparationGovernor {
    /// A demand-only governor. Refuses zero bounds.
    pub fn new(config: GovernorConfig) -> Result<Self, GovernorError> {
        let invalid = |field| Err(GovernorError::InvalidConfig { field });
        if config.prepare.max_lead.is_zero() {
            return invalid("prepare.max_lead");
        }
        if config.prepare.max_retention_ttl.is_zero() {
            return invalid("prepare.max_retention_ttl");
        }
        if config.max_active == 0 {
            return invalid("max_active");
        }
        if config.max_lookahead == 0 {
            return invalid("max_lookahead");
        }
        if config.max_outcomes == 0 {
            return invalid("max_outcomes");
        }
        let shared = SharedPrerequisites::new(config.execution.clone());
        Ok(Self {
            config,
            mode: PreparationMode::DemandOnly {
                cause: RollbackCause::Default,
            },
            active: BTreeMap::new(),
            shared,
            outcomes: VecDeque::new(),
            outcomes_dropped: 0,
        })
    }

    /// Whether the governor prepares anything now.
    pub fn mode(&self) -> PreparationMode {
        self.mode
    }

    /// Prepares declared steps from now on.
    pub fn enable_workflow_intent(&mut self) {
        self.mode = PreparationMode::WorkflowIntent;
    }

    /// The shared prerequisites held now.
    pub fn shared(&self) -> &SharedPrerequisites {
        &self.shared
    }

    /// Preparations admitted and not ended.
    pub fn active(&self) -> impl Iterator<Item = &OperationId> {
        self.active.keys()
    }

    /// A preparation's state as last computed.
    pub fn state(&self, operation: &OperationId) -> Option<PrepareState> {
        self.active
            .get(operation)
            .map(|governed| governed.operation.state())
    }

    /// A preparation's cancellation token, for the work that carries it out.
    pub fn token(&self, operation: &OperationId) -> Option<CancellationToken> {
        self.active
            .get(operation)
            .map(|governed| governed.operation.request().cancellation.clone())
    }

    /// Bytes of background reservations held or waited for: speculative preparations'
    /// own demand plus shared prerequisites no request uses yet, each once.
    pub fn speculative_bytes(&self) -> u64 {
        self.active
            .values()
            .filter(|governed| governed.phase == Phase::Speculative)
            .fold(self.shared.speculative_bytes(), |total, governed| {
                total.saturating_add(bytes_of(&governed.demand))
            })
    }

    /// Ended preparations not yet taken, oldest first.
    pub fn take_outcomes(&mut self) -> Vec<PreparationOutcome> {
        self.outcomes.drain(..).collect()
    }

    /// Outcomes dropped untaken by the `max_outcomes` bound.
    pub fn outcomes_dropped(&self) -> u64 {
        self.outcomes_dropped
    }

    /// Takes a workflow's declared next steps (§4.1). Speculative preparations of the
    /// workflow that the declaration no longer names are superseded; the first
    /// `max_lookahead` steps are admitted in order within the bounds; the rest wait for a
    /// later declaration. A step whose lease (`leases`, as in [`Self::poll`]) is no longer
    /// active is refused. Demand-only declines every step.
    pub fn declare<C: Clock>(
        &mut self,
        intent: WorkflowIntent,
        ledger: &mut Ledger<C>,
        leases: &dyn Fn(LeaseId) -> Option<LeaseState>,
        clock: &dyn Clock,
    ) -> DeclarationReport {
        let mut report = DeclarationReport::default();
        let named: BTreeSet<OperationId> = intent
            .steps
            .iter()
            .take(self.config.max_lookahead)
            .map(|step| step.operation.clone())
            .collect();
        let superseded: Vec<OperationId> = self
            .active
            .iter()
            .filter(|(operation, governed)| {
                *governed.execution() == intent.execution
                    && governed.phase == Phase::Speculative
                    && !named.contains(*operation)
            })
            .map(|(operation, _)| operation.clone())
            .collect();
        for operation in superseded {
            let end = PreparationEnd::Released {
                reason: ReleaseReason::Cancelled {
                    reason: CancelReason::Superseded,
                },
            };
            if let Some(outcome) = self.end(
                &operation,
                Ending::Cancel(CancelReason::Superseded),
                end,
                ledger,
                clock,
            ) {
                report.superseded.push(outcome);
            }
        }
        let WorkflowIntent {
            execution,
            tenant,
            steps,
        } = intent;
        for (index, step) in steps.into_iter().enumerate() {
            let operation = step.operation.clone();
            let outcome = if index >= self.config.max_lookahead {
                StepOutcome::Declined {
                    reason: DeclineReason::BeyondLookahead,
                }
            } else {
                match self.admit(&execution, &tenant, step, ledger, leases, clock) {
                    Ok(outcome) => outcome,
                    Err(reason) => StepOutcome::Declined { reason },
                }
            };
            report.steps.push(StepDecision { operation, outcome });
        }
        report
    }

    fn admit<C: Clock>(
        &mut self,
        execution: &ExecutionId,
        tenant: &TenantId,
        step: DeclaredStep,
        ledger: &mut Ledger<C>,
        leases: &dyn Fn(LeaseId) -> Option<LeaseState>,
        clock: &dyn Clock,
    ) -> Result<StepOutcome, DeclineReason> {
        if let PreparationMode::DemandOnly { cause } = self.mode {
            return Err(DeclineReason::DemandOnly { cause });
        }
        if let Some(existing) = self.active.get(&step.operation) {
            let same = existing.execution() == execution
                && existing.operation.request().target == step.target;
            return if same {
                Ok(StepOutcome::AlreadyPreparing)
            } else {
                Err(DeclineReason::DuplicateOperation)
            };
        }
        if self.active.len() >= self.config.max_active {
            return Err(DeclineReason::ActiveLimit {
                max_active: self.config.max_active,
            });
        }
        let mut keys = BTreeSet::new();
        let mut requested = bytes_of(&step.demand);
        for prerequisite in &step.prerequisites {
            if !keys.insert(prerequisite.key) {
                return Err(DeclineReason::DuplicatePrerequisite {
                    key: prerequisite.key,
                });
            }
            if !self.shared.holds(tenant, prerequisite.key) {
                requested = requested.saturating_add(bytes_of(&prerequisite.demand));
            }
        }
        let held = self.speculative_bytes();
        if held.saturating_add(requested) > self.config.max_speculative_bytes {
            return Err(DeclineReason::SpeculativeBytes {
                requested,
                held,
                limit: self.config.max_speculative_bytes,
            });
        }
        // §2.9: the step is worth preparing when the delay its reload cost would add, at
        // its probability, outweighs the bytes it would waste otherwise; a base already
        // held adds no bytes (shared bases counted once).
        let candidate = PrefetchCandidate {
            id: CandidateId::new(step.operation.as_str())
                .map_err(|error| DeclineReason::Value(error.into()))?,
            origin: CandidateOrigin::QueuedWork,
            probability: step.probability,
            bytes: requested,
            saved_if_used: RawCost {
                milliseconds: step.cost.reload_seconds() * 1_000.0,
                ..RawCost::default()
            },
            waste_if_unused: RawCost {
                bytes: requested as f64,
                ..RawCost::default()
            },
            interference: RawCost::default(),
            retention: RawCost::default(),
        };
        let value = expected_value(&candidate, &self.config.objective)
            .map_err(DeclineReason::Value)?
            .expected_value;
        if value.is_nan() || value <= 0.0 {
            return Err(DeclineReason::NotWorthIt {
                expected_value: value,
            });
        }
        let estimated = step.cost.admission_duration();
        // Work under a lease that is no longer active is refused at admission.
        let cancellation = CancellationToken::new();
        cancellation.observe_lease(&leases(step.lease).unwrap_or(LeaseState::NotRevived));
        let request = PrepareRequest {
            operation: step.operation.clone(),
            execution: execution.clone(),
            tenant: tenant.clone(),
            target: step.target,
            origin: CandidateOrigin::QueuedWork,
            deadline: step.deadline,
            retention_ttl: step.retention_ttl,
            cancellation,
            work: step.work,
            assigned_request: step.assigned_request,
        };
        let operation = PrepareOperation::admit(request, estimated, &self.config.prepare, clock)
            .map_err(DeclineReason::Prepare)?;
        // Wait only until the latest start that still meets the deadline.
        let wait = step
            .deadline
            .saturating_duration_since(clock.now())
            .saturating_sub(estimated);
        let holder = step.operation.clone();
        let mut acquired: Vec<PrerequisiteKey> = Vec::new();
        for prerequisite in &step.prerequisites {
            if let Err(refusal) = self
                .shared
                .acquire(ledger, tenant, prerequisite, &holder, wait)
            {
                for key in acquired {
                    let _ = self.shared.release(ledger, tenant, key, &holder);
                }
                return Err(DeclineReason::Prerequisite(refusal));
            }
            acquired.push(prerequisite.key);
        }
        let own = if step.demand.is_empty() {
            None
        } else {
            match file(
                ledger,
                provenance(execution, &holder, tenant),
                Priority::Background,
                &step.demand,
                wait,
            ) {
                Ok(holding) => Some(holding),
                Err(error) => {
                    for key in acquired {
                        let _ = self.shared.release(ledger, tenant, key, &holder);
                    }
                    return Err(DeclineReason::Capacity(error));
                }
            }
        };
        self.active.insert(
            holder,
            Governed {
                operation,
                lease: step.lease,
                phase: Phase::Speculative,
                demand: step.demand,
                own,
                prerequisites: acquired,
                cost_basis: step.cost.basis,
                expected_value: value,
                announced: false,
                promoted_bytes: 0,
            },
        );
        Ok(StepOutcome::Admitted {
            own,
            expected_value: value,
        })
    }

    /// Follows every preparation (see the module documentation). It first lets the
    /// ledger's time act ([`Ledger::tick`]), then follows shared prerequisites and own
    /// requests in the ledger, each speculative preparation's lease (`leases` gives a
    /// lease's state; an unknown lease counts as not revived), its deadline and its
    /// retention TTL. Reports preparations whose holdings are all granted, once, and every
    /// preparation that ended.
    pub fn poll<C: Clock>(
        &mut self,
        ledger: &mut Ledger<C>,
        leases: &dyn Fn(LeaseId) -> Option<LeaseState>,
        clock: &dyn Clock,
    ) -> Vec<GovernorEvent> {
        // Let the ledger's time act first: expired grants, expired waits, queue grants.
        ledger.tick();
        let mut lost: BTreeMap<OperationId, PrerequisiteKey> = BTreeMap::new();
        for event in self.shared.poll(ledger) {
            if let SharedEvent::Lost { key, holders, .. } = event {
                for holder in holders {
                    lost.entry(holder).or_insert(key);
                }
            }
        }
        let mut events = Vec::new();
        let operations: Vec<OperationId> = self.active.keys().cloned().collect();
        for operation in operations {
            match self.check(&operation, &lost, ledger, leases, clock) {
                Some((ending, end)) => {
                    if let Some(outcome) = self.end(&operation, ending, end, ledger, clock) {
                        events.push(GovernorEvent::Ended { outcome });
                    }
                }
                None => {
                    if self.newly_granted(&operation) {
                        events.push(GovernorEvent::Granted { operation });
                    }
                }
            }
        }
        events
    }

    /// Whether everything the preparation holds is granted and was not reported yet.
    fn newly_granted(&mut self, operation: &OperationId) -> bool {
        let Some(governed) = self.active.get(operation) else {
            return false;
        };
        let granted = governed.own.is_none_or(|own| own.reservation().is_some())
            && governed.prerequisites.iter().all(|key| {
                self.shared
                    .holding(governed.tenant(), *key)
                    .is_some_and(|holding| holding.reservation().is_some())
            });
        match self.active.get_mut(operation) {
            Some(governed) if granted && !governed.announced => {
                governed.announced = true;
                true
            }
            _ => false,
        }
    }

    /// Why one preparation must end now, if it must.
    fn check<C: Clock>(
        &mut self,
        operation: &OperationId,
        lost: &BTreeMap<OperationId, PrerequisiteKey>,
        ledger: &Ledger<C>,
        leases: &dyn Fn(LeaseId) -> Option<LeaseState>,
        clock: &dyn Clock,
    ) -> Option<(Ending, PreparationEnd)> {
        let governed = self.active.get_mut(operation)?;
        if let Some(key) = lost.get(operation) {
            return Some((
                Ending::Cancel(CancelReason::Requester),
                PreparationEnd::PrerequisiteLost { key: *key },
            ));
        }
        if let Some(own) = governed.own {
            match follow(ledger, own) {
                Some(holding) => governed.own = Some(holding),
                None => {
                    let end = match own {
                        Holding::Queued { ticket, .. } => {
                            PreparationEnd::CapacityRefused { ticket }
                        }
                        Holding::Granted { reservation } => {
                            PreparationEnd::ReservationLost { reservation }
                        }
                    };
                    return Some((Ending::Cancel(CancelReason::Requester), end));
                }
            }
        }
        if governed.phase != Phase::Speculative {
            return None;
        }
        let state = leases(governed.lease).unwrap_or(LeaseState::NotRevived);
        governed
            .operation
            .request()
            .cancellation
            .observe_lease(&state);
        match governed.operation.poll(clock) {
            PrepareState::Released { reason, .. } => {
                Some((Ending::AsIs, PreparationEnd::Released { reason }))
            }
            _ => None,
        }
    }

    /// Ends one preparation: cancels its token when asked, withdraws or cancels what it
    /// holds, and records its outcome.
    fn end<C: Clock>(
        &mut self,
        operation: &OperationId,
        ending: Ending,
        end: PreparationEnd,
        ledger: &mut Ledger<C>,
        clock: &dyn Clock,
    ) -> Option<PreparationOutcome> {
        let mut governed = self.active.remove(operation)?;
        if let Ending::Cancel(reason) = ending {
            governed.operation.cancel(reason, clock);
        }
        let tenant = governed.tenant().clone();
        let mut released = Vec::new();
        if let Some(own) = governed.own {
            released.push(release_holding(ledger, own));
        }
        for key in &governed.prerequisites {
            released.push(
                match self.shared.release(ledger, &tenant, *key, operation) {
                    Ok(release) => release,
                    // The ledger already dropped it, so it holds nothing more for anyone.
                    Err(_) => LedgerRelease::PrerequisiteGone { key: *key },
                },
            );
        }
        let used = governed.phase != Phase::Speculative;
        // A promoted preparation's operation was consumed while it ran, so its work's
        // bytes are kept beside it.
        let prepared_bytes = governed
            .operation
            .prepared_bytes()
            .max(governed.promoted_bytes);
        let request = governed.operation.request();
        let outcome = PreparationOutcome {
            operation: operation.clone(),
            execution: request.execution.clone(),
            tenant,
            target: request.target,
            end,
            used,
            prepared_bytes,
            wasted_bytes: if used { 0 } else { prepared_bytes },
            admitted_at: governed.operation.admitted_at(),
            ended_at: clock.now(),
            cost_basis: governed.cost_basis,
            expected_value: governed.expected_value,
            released,
        };
        if self.outcomes.len() >= self.config.max_outcomes {
            self.outcomes.pop_front();
            self.outcomes_dropped = self.outcomes_dropped.saturating_add(1);
        }
        self.outcomes.push_back(outcome.clone());
        Some(outcome)
    }

    /// Marks the start of a preparation's work (CORE-03 reserve before create): every
    /// holding must be granted; prerequisites and then its own reservation begin
    /// creation. Idempotent.
    pub fn begin_work<C: Clock>(
        &mut self,
        operation: &OperationId,
        ledger: &mut Ledger<C>,
    ) -> Result<WorkGrant, GovernorError> {
        let unknown = || GovernorError::UnknownPreparation {
            operation: operation.clone(),
        };
        let governed = self.active.get(operation).ok_or_else(unknown)?;
        let running = match governed.phase {
            Phase::Speculative => {
                matches!(governed.operation.state(), PrepareState::Running { .. })
            }
            Phase::Promoted => true,
            Phase::Serving => false,
        };
        if !running {
            return Err(GovernorError::NotRunning {
                operation: operation.clone(),
            });
        }
        let not_granted = || GovernorError::NotGranted {
            operation: operation.clone(),
        };
        let own = match governed.own {
            None => None,
            Some(holding) => Some(holding.reservation().ok_or_else(not_granted)?),
        };
        let tenant = governed.tenant().clone();
        let keys = governed.prerequisites.clone();
        if keys.iter().any(|key| {
            self.shared
                .holding(&tenant, *key)
                .is_none_or(|holding| holding.reservation().is_none())
        }) {
            return Err(not_granted());
        }
        let mut prerequisites = Vec::new();
        for key in keys {
            prerequisites.push(
                self.shared
                    .begin_create(ledger, &tenant, key)
                    .map_err(GovernorError::Prerequisite)?,
            );
        }
        if let Some(reservation) = own {
            ledger
                .begin_create(reservation)
                .map_err(GovernorError::Ledger)?;
        }
        Ok(WorkGrant { own, prerequisites })
    }

    /// Records that a preparation's work finished with `prepared_bytes` ready. A
    /// speculative preparation becomes ready until its retention TTL, or, past its
    /// deadline or once cancelled, ends at the next poll; a promoted one now serves its
    /// request.
    pub fn complete(
        &mut self,
        operation: &OperationId,
        prepared_bytes: u64,
        clock: &dyn Clock,
    ) -> Result<PrepareState, GovernorError> {
        let governed =
            self.active
                .get_mut(operation)
                .ok_or_else(|| GovernorError::UnknownPreparation {
                    operation: operation.clone(),
                })?;
        match governed.phase {
            Phase::Speculative => governed
                .operation
                .complete(prepared_bytes, clock)
                .map_err(GovernorError::Prepare),
            Phase::Promoted => {
                governed.promoted_bytes = prepared_bytes;
                governed.phase = Phase::Serving;
                Ok(governed.operation.state())
            }
            Phase::Serving => Err(GovernorError::NotRunning {
                operation: operation.clone(),
            }),
        }
    }

    /// A request for `target` arrived. A ready preparation of the target serves it; a
    /// running one is promoted to demand: its waiting background requests are re-filed
    /// as foreground, and the caller promotes the same transfer in the executor. Ready
    /// preparations are preferred, then the earliest admitted.
    pub fn request_arrived<C: Clock>(
        &mut self,
        target: &PrepareTarget,
        ledger: &mut Ledger<C>,
        clock: &dyn Clock,
    ) -> ArrivalReport {
        let mut chosen: Option<(bool, MonotonicTime, OperationId)> = None;
        for (operation, governed) in &mut self.active {
            if governed.phase != Phase::Speculative
                || governed.operation.request().target != *target
            {
                continue;
            }
            let rank = match governed.operation.poll(clock) {
                PrepareState::Ready { .. } => false,
                PrepareState::Running { .. } => true,
                _ => continue,
            };
            let key = (rank, governed.operation.admitted_at(), operation.clone());
            if chosen.as_ref().is_none_or(|best| key < *best) {
                chosen = Some(key);
            }
        }
        let Some((_, _, operation)) = chosen else {
            return ArrivalReport::NoPreparation;
        };
        let wait = self.config.promotion_wait;
        let Some(governed) = self.active.get_mut(&operation) else {
            return ArrivalReport::NoPreparation;
        };
        match governed.operation.request_arrived(target, clock) {
            Arrival::Used { prepared_bytes, .. } => {
                governed.phase = Phase::Serving;
                ArrivalReport::Used {
                    operation,
                    prepared_bytes,
                }
            }
            Arrival::Promoted => {
                governed.phase = Phase::Promoted;
                let tenant = governed.tenant().clone();
                let execution = governed.execution().clone();
                let own = match governed.own.as_mut() {
                    Some(holding) => promote_holding(
                        ledger,
                        provenance(&execution, &operation, &tenant),
                        &governed.demand,
                        holding,
                        wait,
                    ),
                    None => PromotionEffect::NothingHeld,
                };
                let keys = governed.prerequisites.clone();
                let prerequisites = keys
                    .into_iter()
                    .map(|key| {
                        (
                            key,
                            self.shared.promote(ledger, &tenant, key, &operation, wait),
                        )
                    })
                    .collect();
                ArrivalReport::Promoted {
                    operation,
                    own,
                    prerequisites,
                }
            }
            Arrival::NotUsed { .. }
            | Arrival::AlreadyReleased { .. }
            | Arrival::AlreadyConsumed => ArrivalReport::NoPreparation,
        }
    }

    /// Cancels one preparation with `reason` and returns what it held.
    pub fn cancel<C: Clock>(
        &mut self,
        operation: &OperationId,
        reason: CancelReason,
        ledger: &mut Ledger<C>,
        clock: &dyn Clock,
    ) -> Result<PreparationOutcome, GovernorError> {
        let end = PreparationEnd::Released {
            reason: ReleaseReason::Cancelled { reason },
        };
        self.end(operation, Ending::Cancel(reason), end, ledger, clock)
            .ok_or_else(|| GovernorError::UnknownPreparation {
                operation: operation.clone(),
            })
    }

    /// The caller is done with a preparation a request used: it returns what it held; a
    /// shared prerequisite only when it was the last holder. An unused preparation is
    /// cancelled, not finished.
    pub fn finish<C: Clock>(
        &mut self,
        operation: &OperationId,
        ledger: &mut Ledger<C>,
        clock: &dyn Clock,
    ) -> Result<PreparationOutcome, GovernorError> {
        if self
            .active
            .get(operation)
            .is_some_and(|governed| governed.phase == Phase::Speculative)
        {
            return Err(GovernorError::NotUsed {
                operation: operation.clone(),
            });
        }
        self.end(
            operation,
            Ending::AsIs,
            PreparationEnd::Finished,
            ledger,
            clock,
        )
        .ok_or_else(|| GovernorError::UnknownPreparation {
            operation: operation.clone(),
        })
    }

    /// Rolls back to demand-only (§2.9 runtime rollback): every speculative preparation
    /// is cancelled and returns what it held. Preparations a request already uses or
    /// promoted are demand work and stay.
    pub fn roll_back<C: Clock>(
        &mut self,
        cause: RollbackCause,
        ledger: &mut Ledger<C>,
        clock: &dyn Clock,
    ) -> Vec<PreparationOutcome> {
        self.mode = PreparationMode::DemandOnly { cause };
        let reason = match cause {
            RollbackCause::Controller { reason } => CancelReason::DemandOnly { reason },
            RollbackCause::Default | RollbackCause::Operator => CancelReason::Requester,
        };
        let speculative: Vec<OperationId> = self
            .active
            .iter()
            .filter(|(_, governed)| governed.phase == Phase::Speculative)
            .map(|(operation, _)| operation.clone())
            .collect();
        speculative
            .into_iter()
            .filter_map(|operation| {
                self.end(
                    &operation,
                    Ending::Cancel(reason),
                    PreparationEnd::RolledBack { cause },
                    ledger,
                    clock,
                )
            })
            .collect()
    }

    /// Follows the §2.9 mode controller: its demand-only fallback rolls back, and its
    /// recovery re-enables workflow intent only when the controller caused the rollback;
    /// an operator's or the default demand-only stays.
    pub fn follow<C: Clock>(
        &mut self,
        controller: &ModeController,
        ledger: &mut Ledger<C>,
        clock: &dyn Clock,
    ) -> Vec<PreparationOutcome> {
        match (controller.mode(), self.mode) {
            (SchedulingMode::DemandOnly, PreparationMode::WorkflowIntent) => {
                let reason = controller
                    .reason()
                    .unwrap_or(DemandOnlyReason::LowConfidence);
                self.roll_back(RollbackCause::Controller { reason }, ledger, clock)
            }
            (
                SchedulingMode::Speculative,
                PreparationMode::DemandOnly {
                    cause: RollbackCause::Controller { .. },
                },
            ) => {
                self.mode = PreparationMode::WorkflowIntent;
                Vec::new()
            }
            _ => Vec::new(),
        }
    }
}
