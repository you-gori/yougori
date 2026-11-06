//! Stale-state reconciliation between the [`PreparationGovernor`], the transfer executor
//! and the CORE-03 ledger (GPU-W06 of docs/combined-gpu-memory-and-vm-sandbox-plan.md,
//! line 1246: "stale-state reconciliation"; §3.10 line 824: "Reconcile actual state after
//! restart"; CORE-03: a created workload counts until a host observes its release; G05 in
//! docs/combined-plan-remaining-only.md).
//!
//! The governor hears of a preparation's work only from its caller: `begin_work` when it
//! starts and `complete` when it ends. A restart of the executor or of the governor, a
//! completion that never reached it, or a transfer the executor cancelled on its own
//! (demand-only, a revocation, a caller's cancel) leaves its view stale.
//! [`StaleStateReconciler::reconcile`] compares each preparation's [`PreparationView`]
//! with what the executor holds for its work ([`WorkObservation`], through an
//! [`ExecutorView`]: the job of the same operation) and with the ledger, and acts only
//! where that evidence decides:
//!
//! | Governor's view | Executor | Reconciliation |
//! | --- | --- | --- |
//! | granted | running | marks the work begun, so the ledger counts it as created |
//! | granted, running or shared-only | completed | adopts the work once: marks it begun, then completes it with the committed bytes |
//! | running | failed, cancelled or absent | ends it ([`PreparationEnd::WorkLost`]) and returns its holdings through the ledger |
//! | queued or granted | absent | consistent: its work has not begun |
//! | running or shared-only | running | consistent |
//! | ready or serving | completed or absent | consistent: a finished job may be forgotten |
//! | any | unknown | uncertain |
//! | queued | any job | uncertain: work the governor never granted |
//! | granted | failed or cancelled | uncertain: a job its work cannot have started |
//! | shared-only | failed, cancelled or absent | uncertain: whether its own work began is not known |
//! | ready or serving | running, failed or cancelled | uncertain: the executor contradicts the completion |
//!
//! Shared-only ([`PreparationView::GrantedOrRunning`]) is a preparation without demand of
//! its own whose shared prerequisites are all in use, perhaps by another holder's work. A
//! preparation that already ended by its own rules or lost a holding is left to the next
//! [`PreparationGovernor::poll`]. An uncertain case changes nothing and is reported with
//! its reason ([`Uncertainty`]). Adopted work is announced as granted, so a later poll
//! never asks for it again; a later reconciliation finds it consistent, and a late
//! completion is refused as not running.
//!
//! Reconciliation never frees capacity itself. Ending a preparation cancels its
//! holdings: one never created returns at once, one in use counts until its release is
//! observed, and a shared prerequisite leaves only with its last holder. A release
//! observation the caller passes ([`ReleaseObservation`]) goes to
//! [`Ledger::confirm_release`], which accepts it only from a source with authority (a
//! host probe for a host-level reservation), and only for a reservation of the governor's
//! that was cancelled and that nothing holds; an observation of one still granted or in
//! use frees nothing.
//!
//! # Whose reservations
//!
//! A reservation is the governor's when the model placement governor filed it at the top
//! level ([`Requester::ModelPlacement`], no parent) and it is either a shared
//! prerequisite (under the governor's own execution, with the operation
//! [`SharedPrerequisites`](super::super::shared::SharedPrerequisites) names
//! [`PREREQUISITE_OPERATION_PREFIX`] and a digest) or filed under the execution and
//! operation of a preparation the reconciler answers for: one the governor holds or
//! held while the reconciler watched, one among its untaken outcomes, or one the caller
//! recalls after a restart ([`StaleStateReconciler::recall`]). Among those, every open
//! reservation nothing holds is reported: granted or in use as [`UnownedReservation`]
//! (left by an earlier governor, a refused release or a crash), never cancelled or
//! confirmed; releasing in [`ReconcileReport::awaiting_release`] until a source with
//! authority observes it. A preparation the reconciler answers for that the governor no
//! longer holds, but whose job the executor still runs or keeps completed, is reported
//! as [`OrphanWork`]. A preparation is forgotten once neither the governor, the ledger
//! nor the executor holds anything for it; at most `max_claims` are remembered, the
//! oldest dropped first and counted. Queued requests carry no provenance in the ledger,
//! so one nothing follows is reported only once it is granted.
//!
//! # Production callers
//!
//! `model_runner` is not changed. A production caller would:
//!
//! 1. Submit each preparation's work as one executor job whose `TransferRequest::operation`
//!    is the preparation's operation, carved from its own reservation
//!    (`SubmitOptions::within` with [`WorkGrant::own`](super::WorkGrant::own)).
//! 2. Hold one [`StaleStateReconciler`] beside the [`PreparationGovernor`].
//! 3. Under the ledger lock, right after [`PreparationGovernor::poll`] and before
//!    [`PreparationGovernor::take_outcomes`], and once after any executor or governor
//!    restart, call [`StaleStateReconciler::reconcile`] with the governor, the ledger,
//!    the `TransferExecutor` (its [`ExecutorView`]), the host's own observations of
//!    released device memory as [`ReleaseObservation`]s with `SourceClass::HostProbe`, and
//!    the clock.
//! 4. After a governor restart, [`StaleStateReconciler::recall`] each preparation the
//!    persisted job intent names, before its workflow declares again.
//! 5. Treat [`Finding::Ended`] outcomes as any ended preparation; cancel or forget the
//!    jobs of [`OrphanWork`] (`TransferExecutor::cancel`, `forget`,
//!    `retire_destination`); surface [`UnownedReservation`]s and uncertain findings to
//!    the operator, who decides.

use std::collections::{BTreeSet, VecDeque};
use std::num::NonZeroUsize;

use super::{
    follow, Ending, GovernorError, Holding, Phase, PreparationEnd, PreparationGovernor,
    PreparationOutcome,
};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{Clock, ExecutionId, OperationId};
use crate::foundation::ledger::{
    Amounts, Ledger, LedgerError, Provenance, QueueTicket, ReleaseOutcome, Requester,
    ReservationId, ReservationRecord, ReservationState,
};
use crate::model_memory::executor::{
    CancelReason as TransferCancelReason, JobFailure, JobProgress, JobStatus, Lifecycle,
    TransferExecutor,
};
use crate::model_memory::readiness::intent::{CancelReason, PrepareState};

/// The prefix of the operation a shared prerequisite's reservation is filed under
/// ([`SharedPrerequisites`](super::super::shared::SharedPrerequisites) follows it with a
/// digest of its tenant and key).
pub const PREREQUISITE_OPERATION_PREFIX: &str = "prereq-";

/// What the executor holds for one preparation's work, as observed now.
#[derive(Clone, Debug, PartialEq)]
pub enum WorkObservation {
    /// Its job runs.
    Running,
    /// Its job completed: every dependency is usable.
    Completed {
        committed_bytes: u64,
    },
    Failed {
        failure: JobFailure,
    },
    Cancelled {
        reason: TransferCancelReason,
    },
    /// The executor has no such job: it was never submitted, the executor forgot it, or
    /// the executor restarted.
    Absent,
    /// The executor cannot say: it stopped after a fault, so its jobs neither progress nor
    /// end, or it could not be reached.
    Unknown,
}

/// The executor's side of reconciliation.
pub trait ExecutorView {
    /// What the executor holds for the work of the preparation `operation`.
    fn observe(&self, operation: &OperationId) -> WorkObservation;
}

impl<C: Clock> ExecutorView for TransferExecutor<C> {
    /// The job of the same operation ([`observe_job`]).
    fn observe(&self, operation: &OperationId) -> WorkObservation {
        observe_job(
            self.lifecycle(),
            self.status(operation),
            self.progress(operation),
        )
    }
}

/// One executor job as an observation: every job of a faulted executor is unknown, and a
/// completed job's bytes are the decoded bytes whose completion events were observed.
pub fn observe_job(
    lifecycle: &Lifecycle,
    status: Option<&JobStatus>,
    progress: Option<&JobProgress>,
) -> WorkObservation {
    if matches!(lifecycle, Lifecycle::Faulted { .. }) {
        return WorkObservation::Unknown;
    }
    match status {
        None => WorkObservation::Absent,
        Some(JobStatus::Running) => WorkObservation::Running,
        Some(JobStatus::Completed) => WorkObservation::Completed {
            committed_bytes: progress.map_or(0, |progress| progress.snapshot.committed_bytes),
        },
        Some(JobStatus::Failed { failure }) => WorkObservation::Failed {
            failure: failure.clone(),
        },
        Some(JobStatus::Cancelled { reason }) => WorkObservation::Cancelled { reason: *reason },
    }
}

/// The governor's view of one preparation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparationView {
    /// Something it needs still waits in the ledger's queue.
    Queued,
    /// Everything it needs is granted; its work has not begun.
    Granted,
    /// Its work began (its own reservation is in use) and has not completed.
    Running,
    /// It holds no demand of its own, and every shared prerequisite it needs is in use,
    /// perhaps by another holder's work: whether its own work began is not known.
    GrantedOrRunning,
    /// Its work completed; no request used it yet.
    Ready,
    /// A request uses it.
    Serving,
    /// It ended by its own rules (token, deadline, TTL) or lost a holding; the next poll
    /// records it.
    Ending,
}

/// How the executor lost a preparation's work.
#[derive(Clone, Debug, PartialEq)]
pub enum WorkLoss {
    Failed {
        failure: JobFailure,
    },
    Cancelled {
        reason: TransferCancelReason,
    },
    /// The executor no longer has its job: it restarted, or it forgot the job before the
    /// job's end reached the governor.
    Absent,
}

/// Why reconciliation left a preparation as it was.
#[derive(Clone, Debug, PartialEq)]
pub enum Uncertainty {
    /// The executor could not say what it holds.
    ExecutorUnknown,
    /// The executor has a job for a preparation whose work has not begun: an earlier
    /// attempt's, or one submitted before what it needs was granted.
    JobBeforeStart,
    /// Only shared prerequisites in use back it and its job is gone or ended, so whether
    /// its own work began is not known.
    StartUnknown,
    /// The governor holds its work as done, but the executor runs it or reports it failed
    /// or cancelled.
    CompletionContradicted,
    /// Adopting the work was refused.
    AdoptionRefused { error: GovernorError },
}

/// What reconciliation did with one preparation.
#[derive(Clone, Debug, PartialEq)]
pub enum Finding {
    /// The governor's view and the executor agree.
    Consistent,
    /// Work the executor runs for a granted preparation was marked begun.
    AdoptedRunning,
    /// Work the executor finished was adopted: the preparation is ready, or serves the
    /// request that promoted it.
    AdoptedCompletion {
        committed_bytes: u64,
        state: PrepareState,
    },
    /// The executor no longer carries its work: the preparation ended. The same outcome
    /// is among the governor's untaken outcomes.
    Ended {
        outcome: Box<PreparationOutcome>,
    },
    /// It ended by its own rules or lost a holding; the next poll records it.
    LeftToPoll,
    Uncertain {
        reason: Uncertainty,
    },
}

/// One preparation's reconciliation.
#[derive(Clone, Debug, PartialEq)]
pub struct PreparationFinding {
    pub operation: OperationId,
    /// The governor's view before reconciliation.
    pub view: PreparationView,
    pub observed: WorkObservation,
    pub finding: Finding,
}

/// A release of a reservation's workload that a source observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseObservation {
    pub reservation: ReservationId,
    pub source: SourceClass,
}

/// What one release observation did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseFinding {
    /// The ledger accepted it: the reservation and everything carved from it closed, and
    /// their amounts are back.
    Confirmed {
        reservation: ReservationId,
        amounts: Amounts,
    },
    /// The ledger refused it, as from a source without authority; the reservation still
    /// counts.
    Refused {
        reservation: ReservationId,
        error: LedgerError,
    },
    /// The reservation is granted or in use, held by a preparation or by nothing: an
    /// observation alone never frees it.
    NotReleasing {
        reservation: ReservationId,
        state: ReservationState,
    },
    /// A preparation or shared prerequisite still holds it; the next poll ends that
    /// holder.
    StillHeld { reservation: ReservationId },
    /// Not one of the governor's reservations.
    NotGovernors { reservation: ReservationId },
    /// No open reservation has this id.
    NotOpen { reservation: ReservationId },
}

/// An open reservation of the governor's that nothing holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnownedReservation {
    pub reservation: ReservationId,
    pub provenance: Provenance,
    /// Granted or in use.
    pub state: ReservationState,
    /// What it holds now.
    pub amounts: Amounts,
}

/// Work the executor holds for a preparation the governor no longer holds.
#[derive(Clone, Debug, PartialEq)]
pub struct OrphanWork {
    pub execution: ExecutionId,
    pub operation: OperationId,
    /// Running or completed.
    pub observed: WorkObservation,
}

/// What one reconciliation found and did.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReconcileReport {
    /// Every preparation the governor held, in operation order.
    pub preparations: Vec<PreparationFinding>,
    /// Open reservations of the governor's that nothing holds, granted or in use:
    /// reported, never freed.
    pub unowned: Vec<UnownedReservation>,
    /// Reservations of the governor's that were cancelled while in use and nothing holds,
    /// whose release no source with authority has observed yet: the ledger still counts
    /// them.
    pub awaiting_release: Vec<ReservationId>,
    /// What each release observation did, in the order given.
    pub releases: Vec<ReleaseFinding>,
    pub orphan_work: Vec<OrphanWork>,
}

/// What reconciliation decides for one preparation.
enum Decision {
    Consistent,
    AdoptRunning,
    AdoptCompletion { committed_bytes: u64 },
    End(WorkLoss),
    LeftToPoll,
    Uncertain(Uncertainty),
}

/// The decision table of the module documentation.
fn decide(view: PreparationView, observed: &WorkObservation) -> Decision {
    use PreparationView as View;
    use WorkObservation as Work;
    match (view, observed) {
        (View::Ending, _) => Decision::LeftToPoll,
        (_, Work::Unknown) => Decision::Uncertain(Uncertainty::ExecutorUnknown),
        (View::Queued | View::Granted, Work::Absent) => Decision::Consistent,
        (View::Queued, _) | (View::Granted, Work::Failed { .. } | Work::Cancelled { .. }) => {
            Decision::Uncertain(Uncertainty::JobBeforeStart)
        }
        (View::Granted, Work::Running) => Decision::AdoptRunning,
        (
            View::Granted | View::Running | View::GrantedOrRunning,
            Work::Completed { committed_bytes },
        ) => Decision::AdoptCompletion {
            committed_bytes: *committed_bytes,
        },
        (View::Running | View::GrantedOrRunning, Work::Running) => Decision::Consistent,
        (View::Running, Work::Failed { failure }) => Decision::End(WorkLoss::Failed {
            failure: failure.clone(),
        }),
        (View::Running, Work::Cancelled { reason }) => {
            Decision::End(WorkLoss::Cancelled { reason: *reason })
        }
        (View::Running, Work::Absent) => Decision::End(WorkLoss::Absent),
        (View::GrantedOrRunning, Work::Failed { .. } | Work::Cancelled { .. } | Work::Absent) => {
            Decision::Uncertain(Uncertainty::StartUnknown)
        }
        (View::Ready | View::Serving, Work::Completed { .. } | Work::Absent) => {
            Decision::Consistent
        }
        (
            View::Ready | View::Serving,
            Work::Running | Work::Failed { .. } | Work::Cancelled { .. },
        ) => Decision::Uncertain(Uncertainty::CompletionContradicted),
    }
}

impl PreparationGovernor {
    /// The governor's view of one preparation, its token, deadline and TTL applied first
    /// as [`Self::poll`] applies them.
    fn view_of<C: Clock>(
        &mut self,
        operation: &OperationId,
        ledger: &Ledger<C>,
        clock: &dyn Clock,
    ) -> Option<PreparationView> {
        let governed = self.active.get_mut(operation)?;
        let state = match governed.phase {
            Phase::Speculative => Some(governed.operation.poll(clock)),
            Phase::Promoted | Phase::Serving => None,
        };
        let governed = self.active.get(operation)?;
        let own = match governed.own {
            None => None,
            Some(holding) => match follow(ledger, holding) {
                Some(holding) => Some(holding),
                None => return Some(PreparationView::Ending),
            },
        };
        let mut shared = Vec::with_capacity(governed.prerequisites.len());
        for key in &governed.prerequisites {
            match self
                .shared
                .holding(governed.tenant(), *key)
                .and_then(|holding| follow(ledger, holding))
            {
                Some(holding) => shared.push(holding),
                None => return Some(PreparationView::Ending),
            }
        }
        match (governed.phase, state) {
            (Phase::Serving, _) => return Some(PreparationView::Serving),
            (_, Some(PrepareState::Ready { .. })) => return Some(PreparationView::Ready),
            (_, Some(PrepareState::Consumed { .. } | PrepareState::Released { .. })) => {
                return Some(PreparationView::Ending)
            }
            _ => {}
        }
        if own
            .iter()
            .chain(&shared)
            .any(|holding| holding.reservation().is_none())
        {
            return Some(PreparationView::Queued);
        }
        let in_use = |holding: &Holding| {
            holding
                .reservation()
                .and_then(|reservation| ledger.reservation(reservation))
                .is_some_and(|record| record.state() == ReservationState::InUse)
        };
        Some(match own {
            Some(holding) if in_use(&holding) => PreparationView::Running,
            Some(_) => PreparationView::Granted,
            None if shared.iter().all(in_use) => PreparationView::GrantedOrRunning,
            None => PreparationView::Granted,
        })
    }

    /// Reconciles one preparation with the executor (see the module documentation).
    fn reconcile_one<C: Clock>(
        &mut self,
        operation: &OperationId,
        ledger: &mut Ledger<C>,
        executor: &dyn ExecutorView,
        clock: &dyn Clock,
    ) -> Option<PreparationFinding> {
        let view = self.view_of(operation, ledger, clock)?;
        let observed = executor.observe(operation);
        let refused = |error| Finding::Uncertain {
            reason: Uncertainty::AdoptionRefused { error },
        };
        let finding = match decide(view, &observed) {
            Decision::Consistent => Finding::Consistent,
            Decision::LeftToPoll => Finding::LeftToPoll,
            Decision::Uncertain(reason) => Finding::Uncertain { reason },
            // Marking the work begun (idempotent) also counts as announcing its grant, so
            // a later poll never asks for work that already exists.
            Decision::AdoptRunning => match self.begin_work(operation, ledger) {
                Ok(_) => {
                    self.announce(operation);
                    Finding::AdoptedRunning
                }
                Err(error) => refused(error),
            },
            Decision::AdoptCompletion { committed_bytes } => {
                match self.begin_work(operation, ledger) {
                    Ok(_) => {
                        self.announce(operation);
                        match self.complete(operation, committed_bytes, clock) {
                            Ok(state) => Finding::AdoptedCompletion {
                                committed_bytes,
                                state,
                            },
                            Err(error) => refused(error),
                        }
                    }
                    Err(error) => refused(error),
                }
            }
            Decision::End(loss) => match self.end(
                operation,
                Ending::Cancel(CancelReason::Requester),
                PreparationEnd::WorkLost { loss },
                ledger,
                clock,
            ) {
                Some(outcome) => Finding::Ended {
                    outcome: Box::new(outcome),
                },
                None => Finding::LeftToPoll,
            },
        };
        Some(PreparationFinding {
            operation: operation.clone(),
            view,
            observed,
            finding,
        })
    }

    /// Records that a preparation's grant was taken up, as [`Self::poll`] records it once
    /// reported.
    fn announce(&mut self, operation: &OperationId) {
        if let Some(governed) = self.active.get_mut(operation) {
            governed.announced = true;
        }
    }

    /// The reservations and queue tickets the governor's preparations and shared
    /// prerequisites hold, a ticket granted since it was last followed as its grant too.
    fn holdings<C: Clock>(
        &self,
        ledger: &Ledger<C>,
    ) -> (BTreeSet<ReservationId>, BTreeSet<QueueTicket>) {
        let mut reservations = BTreeSet::new();
        let mut tickets = BTreeSet::new();
        for governed in self.active.values() {
            let prerequisites = governed
                .prerequisites
                .iter()
                .filter_map(|key| self.shared.holding(governed.tenant(), *key));
            for holding in governed.own.into_iter().chain(prerequisites) {
                for holding in std::iter::once(holding).chain(follow(ledger, holding)) {
                    match holding {
                        Holding::Granted { reservation } => reservations.insert(reservation),
                        Holding::Queued { ticket, .. } => tickets.insert(ticket),
                    };
                }
            }
        }
        (reservations, tickets)
    }
}

/// Reconciles a [`PreparationGovernor`] with the executor and the ledger (see the module
/// documentation), remembering which preparations it answers for.
#[derive(Clone, Debug)]
pub struct StaleStateReconciler {
    max_claims: NonZeroUsize,
    /// Executions and operations of preparations it answers for, oldest first.
    claims: VecDeque<(ExecutionId, OperationId)>,
    claims_dropped: u64,
}

impl StaleStateReconciler {
    /// Answers for nothing yet; remembers at most `max_claims` preparations.
    pub fn new(max_claims: NonZeroUsize) -> Self {
        Self {
            max_claims,
            claims: VecDeque::new(),
            claims_dropped: 0,
        }
    }

    /// Answers for the preparation `operation` of `execution` from now on, as one the
    /// persisted job intent names after a restart.
    pub fn recall(&mut self, execution: ExecutionId, operation: OperationId) {
        self.claim(execution, operation);
    }

    /// Whether it answers for the preparation `operation` of `execution`.
    pub fn answers_for(&self, execution: &ExecutionId, operation: &OperationId) -> bool {
        self.claims
            .iter()
            .any(|(claimed, named)| claimed == execution && named == operation)
    }

    /// Preparations dropped by the `max_claims` bound.
    pub fn claims_dropped(&self) -> u64 {
        self.claims_dropped
    }

    fn claim(&mut self, execution: ExecutionId, operation: OperationId) {
        if self.answers_for(&execution, &operation) {
            return;
        }
        if self.claims.len() >= self.max_claims.get() {
            self.claims.pop_front();
            self.claims_dropped = self.claims_dropped.saturating_add(1);
        }
        self.claims.push_back((execution, operation));
    }

    /// Whether `record` is one of the governor's reservations.
    fn is_governors(&self, record: &ReservationRecord, governor: &ExecutionId) -> bool {
        let provenance = record.provenance();
        provenance.requester == Requester::ModelPlacement
            && record.parent().is_none()
            && ((provenance.execution == *governor
                && provenance
                    .operation
                    .as_str()
                    .starts_with(PREREQUISITE_OPERATION_PREFIX))
                || self.answers_for(&provenance.execution, &provenance.operation))
    }

    /// Reconciles `governor` with `executor` and `ledger`, and hands `observations` to the
    /// ledger for the governor's cancelled reservations (see the module documentation).
    /// Call it after [`PreparationGovernor::poll`], under the same ledger lock.
    pub fn reconcile<C: Clock>(
        &mut self,
        governor: &mut PreparationGovernor,
        ledger: &mut Ledger<C>,
        executor: &dyn ExecutorView,
        observations: &[ReleaseObservation],
        clock: &dyn Clock,
    ) -> ReconcileReport {
        let known: Vec<(ExecutionId, OperationId)> = governor
            .active
            .iter()
            .map(|(operation, governed)| (governed.execution().clone(), operation.clone()))
            .chain(
                governor
                    .outcomes
                    .iter()
                    .map(|outcome| (outcome.execution.clone(), outcome.operation.clone())),
            )
            .collect();
        for (execution, operation) in known {
            self.claim(execution, operation);
        }
        let mut report = ReconcileReport::default();
        let operations: Vec<OperationId> = governor.active.keys().cloned().collect();
        for operation in operations {
            if let Some(finding) = governor.reconcile_one(&operation, ledger, executor, clock) {
                report.preparations.push(finding);
            }
        }
        let mut working = BTreeSet::new();
        for (execution, operation) in &self.claims {
            if governor.active.contains_key(operation) {
                continue;
            }
            let observed = executor.observe(operation);
            if matches!(
                observed,
                WorkObservation::Running | WorkObservation::Completed { .. }
            ) {
                working.insert((execution.clone(), operation.clone()));
                report.orphan_work.push(OrphanWork {
                    execution: execution.clone(),
                    operation: operation.clone(),
                    observed,
                });
            }
        }
        let own_execution = governor.config.execution.clone();
        let (reservations, tickets) = governor.holdings(ledger);
        let held = |record: &ReservationRecord| {
            reservations.contains(&record.id())
                || record
                    .ticket()
                    .is_some_and(|ticket| tickets.contains(&ticket))
        };
        for observation in observations {
            let finding = self.observe_release(observation, &own_execution, ledger, &held);
            report.releases.push(finding);
        }
        let mut carried = BTreeSet::new();
        for record in ledger.open_reservations() {
            if !self.is_governors(record, &own_execution) {
                continue;
            }
            let provenance = record.provenance();
            carried.insert((provenance.execution.clone(), provenance.operation.clone()));
            if held(record) {
                continue;
            }
            match record.state() {
                ReservationState::Granted | ReservationState::InUse => {
                    report.unowned.push(UnownedReservation {
                        reservation: record.id(),
                        provenance: provenance.clone(),
                        state: record.state(),
                        amounts: record.current().clone(),
                    })
                }
                ReservationState::Releasing => report.awaiting_release.push(record.id()),
                ReservationState::Closed => {}
            }
        }
        self.claims.retain(|claim| {
            governor.active.contains_key(&claim.1)
                || carried.contains(claim)
                || working.contains(claim)
        });
        report
    }

    /// Hands one release observation to the ledger when it names a reservation of the
    /// governor's that was cancelled and that nothing holds.
    fn observe_release<C: Clock>(
        &self,
        observation: &ReleaseObservation,
        own_execution: &ExecutionId,
        ledger: &mut Ledger<C>,
        held: &dyn Fn(&ReservationRecord) -> bool,
    ) -> ReleaseFinding {
        let reservation = observation.reservation;
        let Some(record) = ledger.reservation(reservation) else {
            return ReleaseFinding::NotOpen { reservation };
        };
        if !self.is_governors(record, own_execution) {
            return ReleaseFinding::NotGovernors { reservation };
        }
        let state = record.state();
        if state != ReservationState::Releasing {
            return ReleaseFinding::NotReleasing { reservation, state };
        }
        if held(record) {
            return ReleaseFinding::StillHeld { reservation };
        }
        match ledger.confirm_release(reservation, observation.source) {
            Ok(ReleaseOutcome::Released { amounts }) => ReleaseFinding::Confirmed {
                reservation,
                amounts,
            },
            Ok(ReleaseOutcome::Pending | ReleaseOutcome::AlreadyClosed) => {
                ReleaseFinding::NotOpen { reservation }
            }
            Err(error) => ReleaseFinding::Refused { reservation, error },
        }
    }
}

#[cfg(test)]
mod tests;
