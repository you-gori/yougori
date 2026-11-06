//! Request preparation from known future work: the bounded prepare operation, intent
//! strength with weak-intent rate limiting, the two refusals, and lifecycle accounting
//! (GPU §4.1 lines 663–669; §2.9 lines 463–472; GPU-W06 line 1070).
//!
//! A [`PrepareOperation`] prepares one exact model identity, optionally with an adapter,
//! before its request exists. It is bounded three ways: a deadline it must be ready by
//! (admission refuses work that cannot finish in time, and a running preparation that
//! passes its deadline is released), a [`CancellationToken`] the requester or a CORE-04
//! lease cancellation can trip, and a retention TTL after which unused prepared state is
//! released. Promotion to demand reuses the same work (§2.9).
//!
//! Queued workflow work is strong intent and is admitted at once; a UI selection is
//! weak intent and hover is weaker still. Both weak sources pass an [`IntentGate`]: a
//! target must stay unchanged for a dwell time, and weak admissions are spaced by a
//! minimum interval, so hover and rapidly changing selections are rate-limited.
//!
//! Preparation never pre-executes an externally visible action ([`PrepareWork::External`]
//! is refused at admission, matching the boundaries' rule that a preparation never
//! authorizes an external action) and never charges a generated answer before its request
//! exists ([`ChargeBook`]). Computing ahead needs an explicitly assigned pending request
//! (§3.6 line 601).
//!
//! Whether a preparation paid off is decided after the fact by [`account`]: each
//! preparation's realized value is the §2.9 expected value with the outcome known
//! (probability 1 if used, 0 if not), computed by [`expected_value`] itself, and the sum
//! must be positive with no foreground regression ("preparation succeeds only if its
//! benefit survives full lifecycle accounting").

use std::collections::BTreeSet;
use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use crate::foundation::coordination::{CancelCause as LeaseCancelCause, LeaseState};
use crate::foundation::ids::{Clock, ExecutionId, MonotonicTime, OperationId, TenantId};
use crate::model_memory::boundaries::{ExternalAction, PreparationStep};
use crate::model_memory::identity::{AdapterIdentity, ExecutionIdentity};
use crate::model_memory::math::calibration::DemandOnlyReason;
use crate::model_memory::math::prefetch::{
    expected_value, CandidateOrigin, Objective, PrefetchCandidate, PrefetchError, PrefetchValue,
    RawCost,
};
use crate::model_memory::math::{CandidateId, InputError};

/// What one preparation makes ready: an exact model execution identity and, optionally,
/// one adapter (GPU §4.1; identities from §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct PrepareTarget {
    pub model: ExecutionIdentity,
    pub adapter: Option<AdapterIdentity>,
}

/// Where an intent came from (GPU §4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentSource {
    /// Actual queued workflow work that names its next model.
    QueuedWorkflow,
    /// A model the user selected in the UI.
    UiSelection,
    /// A model the pointer rests on.
    Hover,
}

/// How strongly an intent predicts a request (GPU §4.1: "a UI selection may provide weak
/// intent; actual queued work provides stronger intent").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStrength {
    Strong,
    Weak,
}

impl IntentSource {
    pub const fn strength(self) -> IntentStrength {
        match self {
            Self::QueuedWorkflow => IntentStrength::Strong,
            Self::UiSelection | Self::Hover => IntentStrength::Weak,
        }
    }

    /// The §2.9 candidate origin: queued work, or explicit user intent for the UI
    /// sources; both rank ahead of recency and Markov predictions.
    pub const fn origin(self) -> CandidateOrigin {
        match self {
            Self::QueuedWorkflow => CandidateOrigin::QueuedWork,
            Self::UiSelection | Self::Hover => CandidateOrigin::ExplicitUserIntent,
        }
    }
}

/// Why a preparation was cancelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CancelReason {
    /// The requester withdrew the intent.
    Requester,
    /// A newer intent replaced it.
    Superseded,
    /// The CORE-04 lease the preparation runs under is being cancelled.
    Lease { cause: LeaseCancelCause },
    /// The lease was released or not revived after a restart.
    LeaseEnded,
    /// Scheduling fell back to demand-only (§2.9).
    DemandOnly {
        #[serde(serialize_with = "super::wire::demand_only_reason")]
        reason: DemandOnlyReason,
    },
}

impl CancelReason {
    const fn code(self) -> u8 {
        match self {
            Self::Requester => 1,
            Self::Superseded => 2,
            Self::Lease { cause } => match cause {
                LeaseCancelCause::Revocation => 3,
                LeaseCancelCause::PolicyChange => 4,
                LeaseCancelCause::NewBoot => 5,
                LeaseCancelCause::ResourceReturn => 6,
                LeaseCancelCause::GrantRevoked => 11,
            },
            Self::DemandOnly { reason } => match reason {
                DemandOnlyReason::LowConfidence => 7,
                DemandOnlyReason::Overload => 8,
                DemandOnlyReason::Drift => 9,
            },
            Self::LeaseEnded => 10,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Requester,
            2 => Self::Superseded,
            3 => Self::Lease {
                cause: LeaseCancelCause::Revocation,
            },
            4 => Self::Lease {
                cause: LeaseCancelCause::PolicyChange,
            },
            5 => Self::Lease {
                cause: LeaseCancelCause::NewBoot,
            },
            6 => Self::Lease {
                cause: LeaseCancelCause::ResourceReturn,
            },
            7 => Self::DemandOnly {
                reason: DemandOnlyReason::LowConfidence,
            },
            8 => Self::DemandOnly {
                reason: DemandOnlyReason::Overload,
            },
            9 => Self::DemandOnly {
                reason: DemandOnlyReason::Drift,
            },
            10 => Self::LeaseEnded,
            11 => Self::Lease {
                cause: LeaseCancelCause::GrantRevoked,
            },
            _ => return None,
        })
    }
}

/// A cancellation token shared by the requester and the preparation (GPU §4.1). The
/// first cancellation wins and is never undone.
#[derive(Clone, Default)]
pub struct CancellationToken {
    state: Arc<AtomicU8>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancels with `reason`; returns whether this call was the one that cancelled.
    pub fn cancel(&self, reason: CancelReason) -> bool {
        self.state
            .compare_exchange(0, reason.code(), Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Why it was cancelled; `None` while not cancelled.
    pub fn reason(&self) -> Option<CancelReason> {
        CancelReason::from_code(self.state.load(Ordering::SeqCst))
    }

    pub fn is_cancelled(&self) -> bool {
        self.reason().is_some()
    }

    /// Follows the CORE-04 lease the preparation runs under: a cancelling or cancelled
    /// lease cancels with its cause, a released or unrevived lease ends the preparation.
    pub fn observe_lease(&self, state: &LeaseState) -> Option<CancelReason> {
        let reason = match state {
            LeaseState::Active => return self.reason(),
            LeaseState::Cancelling { cause, .. } | LeaseState::Cancelled { cause, .. } => {
                CancelReason::Lease { cause: *cause }
            }
            LeaseState::Released { .. } | LeaseState::NotRevived => CancelReason::LeaseEnded,
        };
        self.cancel(reason);
        self.reason()
    }
}

impl fmt::Debug for CancellationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CancellationToken")
            .field("reason", &self.reason())
            .finish()
    }
}

/// One piece of work a prepare request asks for. Every [`PreparationStep`] is allowed;
/// an external action is named only so that admission can refuse it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "work", rename_all = "snake_case")]
pub enum PrepareWork {
    Step {
        step: PreparationStep,
    },
    /// An externally visible action, which a preparation never pre-executes.
    External {
        action: ExternalAction,
    },
}

/// A bounded prepare request (GPU §4.1: model identity, optional adapter, deadline,
/// cancellation token and retention TTL).
#[derive(Clone, Debug)]
pub struct PrepareRequest {
    pub operation: OperationId,
    /// The parent execution the preparation runs under.
    pub execution: ExecutionId,
    pub tenant: TenantId,
    pub target: PrepareTarget,
    /// Queued work, explicit user intent, or a recency or Markov prediction (§2.9).
    pub origin: CandidateOrigin,
    /// When the prepared state must be ready to be useful.
    pub deadline: MonotonicTime,
    /// How long unused prepared state is kept after it is ready.
    pub retention_ttl: Duration,
    pub cancellation: CancellationToken,
    pub work: Vec<PrepareWork>,
    /// The pending request computing ahead is assigned to (§3.6 line 601).
    pub assigned_request: Option<OperationId>,
}

/// Limits every prepare request is checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PrepareBounds {
    /// The furthest ahead a deadline may lie.
    pub max_lead: Duration,
    /// The longest retention TTL.
    pub max_retention_ttl: Duration,
}

impl PrepareBounds {
    fn check(&self) -> Result<(), PrepareRefusal> {
        if self.max_lead.is_zero() {
            return Err(PrepareRefusal::InvalidBounds { field: "max_lead" });
        }
        if self.max_retention_ttl.is_zero() {
            return Err(PrepareRefusal::InvalidBounds {
                field: "max_retention_ttl",
            });
        }
        Ok(())
    }
}

/// Why a preparation, an intent limit or a charge was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum PrepareRefusal {
    InvalidBounds {
        field: &'static str,
    },
    NoWork,
    /// A preparation never pre-executes an externally visible action (GPU §4.1).
    ExternalAction {
        action: ExternalAction,
    },
    /// Computing ahead serves only an explicitly assigned pending request (§3.6).
    ComputeAheadWithoutRequest,
    AlreadyCancelled {
        reason: CancelReason,
    },
    ZeroRetentionTtl,
    RetentionTtlTooLong {
        ttl: Duration,
        max: Duration,
    },
    DeadlinePassed {
        deadline: MonotonicTime,
        now: MonotonicTime,
    },
    DeadlineTooFar {
        deadline: MonotonicTime,
        latest: MonotonicTime,
    },
    /// The estimated work would not be ready by the deadline.
    CannotFinishByDeadline {
        ready_by: MonotonicTime,
        deadline: MonotonicTime,
    },
    ClockOverflow,
    /// The operation is not running, so it cannot complete.
    NotRunning,
    /// No request with this id has arrived, so no generated answer can be charged
    /// (GPU §4.1).
    AnswerBeforeRequest {
        request: OperationId,
    },
    /// A preparation is not a request: its cost is never charged as an answer.
    PreparationIsNotARequest {
        operation: OperationId,
    },
    DuplicateCharge {
        operation: OperationId,
    },
}

impl fmt::Display for PrepareRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBounds { field } => write!(f, "{field} must be more than zero"),
            Self::NoWork => f.write_str("a prepare request names no work"),
            Self::ExternalAction { action } => write!(
                f,
                "preparing a model never pre-executes an externally visible action ({action:?})"
            ),
            Self::ComputeAheadWithoutRequest => f.write_str(
                "computing ahead needs an explicitly assigned pending request; none exists yet",
            ),
            Self::AlreadyCancelled { reason } => write!(f, "already cancelled: {reason:?}"),
            Self::ZeroRetentionTtl => f.write_str("the retention TTL must be more than zero"),
            Self::RetentionTtlTooLong { ttl, max } => {
                write!(f, "a retention TTL of {ttl:?} exceeds the limit of {max:?}")
            }
            Self::DeadlinePassed { deadline, now } => write!(
                f,
                "the deadline {} ns is not after now ({} ns)",
                deadline.as_nanos(),
                now.as_nanos()
            ),
            Self::DeadlineTooFar { deadline, latest } => write!(
                f,
                "the deadline {} ns is beyond the latest allowed {} ns",
                deadline.as_nanos(),
                latest.as_nanos()
            ),
            Self::CannotFinishByDeadline { ready_by, deadline } => write!(
                f,
                "the work would be ready at {} ns, after its deadline {} ns",
                ready_by.as_nanos(),
                deadline.as_nanos()
            ),
            Self::ClockOverflow => f.write_str("a time does not fit on the clock"),
            Self::NotRunning => f.write_str("the preparation is not running"),
            Self::AnswerBeforeRequest { request } => write!(
                f,
                "no request {request} has arrived, so no generated answer can be charged"
            ),
            Self::PreparationIsNotARequest { operation } => write!(
                f,
                "{operation} is a preparation; its cost is never charged as an answer"
            ),
            Self::DuplicateCharge { operation } => write!(f, "{operation} is already charged"),
        }
    }
}

impl std::error::Error for PrepareRefusal {}

/// Why prepared state was released before a request used it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "release", rename_all = "snake_case")]
pub enum ReleaseReason {
    Cancelled {
        reason: CancelReason,
    },
    /// The work was not ready by its deadline.
    DeadlineMissed,
    /// The retention TTL passed with no request.
    Expired,
    /// A request for another target arrived.
    NotRequested,
}

/// Where a preparation is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PrepareState {
    Running {
        started_at: MonotonicTime,
    },
    Ready {
        ready_at: MonotonicTime,
        expires_at: MonotonicTime,
    },
    /// A request for the target arrived and took the prepared state.
    Consumed {
        at: MonotonicTime,
    },
    Released {
        at: MonotonicTime,
        reason: ReleaseReason,
    },
}

/// What a request's arrival found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "arrival", rename_all = "snake_case")]
pub enum Arrival {
    /// The prepared state serves the request.
    Used {
        prepared_bytes: u64,
        ready_at: MonotonicTime,
    },
    /// The work was still running; promotion to demand reuses it (§2.9).
    Promoted,
    /// A request for another target arrived; the prepared bytes were wasted.
    NotUsed { wasted_bytes: u64 },
    /// The prepared state was released before the request arrived.
    AlreadyReleased { reason: ReleaseReason },
    /// An earlier request already took the prepared state.
    AlreadyConsumed,
}

/// One bounded preparation (GPU §4.1). Time comes from the caller's [`Clock`].
#[derive(Clone, Debug)]
pub struct PrepareOperation {
    request: PrepareRequest,
    admitted_at: MonotonicTime,
    estimated: Duration,
    state: PrepareState,
    prepared_bytes: u64,
}

impl PrepareOperation {
    /// Admits `request` when its work would be ready by its deadline. Refuses an external
    /// action, computing ahead without an assigned request, empty work, a cancelled token,
    /// a zero or too long TTL, a deadline that is not after now or lies beyond
    /// `bounds.max_lead`, and work whose `estimated` duration ends after the deadline.
    pub fn admit(
        request: PrepareRequest,
        estimated: Duration,
        bounds: &PrepareBounds,
        clock: &dyn Clock,
    ) -> Result<Self, PrepareRefusal> {
        bounds.check()?;
        if request.work.is_empty() {
            return Err(PrepareRefusal::NoWork);
        }
        if let Some(action) = request.work.iter().find_map(|work| match work {
            PrepareWork::External { action } => Some(*action),
            PrepareWork::Step { .. } => None,
        }) {
            return Err(PrepareRefusal::ExternalAction { action });
        }
        let computes_ahead = request.work.contains(&PrepareWork::Step {
            step: PreparationStep::ComputeAhead,
        });
        if computes_ahead && request.assigned_request.is_none() {
            return Err(PrepareRefusal::ComputeAheadWithoutRequest);
        }
        if let Some(reason) = request.cancellation.reason() {
            return Err(PrepareRefusal::AlreadyCancelled { reason });
        }
        if request.retention_ttl.is_zero() {
            return Err(PrepareRefusal::ZeroRetentionTtl);
        }
        if request.retention_ttl > bounds.max_retention_ttl {
            return Err(PrepareRefusal::RetentionTtlTooLong {
                ttl: request.retention_ttl,
                max: bounds.max_retention_ttl,
            });
        }
        let now = clock.now();
        if request.deadline <= now {
            return Err(PrepareRefusal::DeadlinePassed {
                deadline: request.deadline,
                now,
            });
        }
        let latest = now
            .checked_add(bounds.max_lead)
            .ok_or(PrepareRefusal::ClockOverflow)?;
        if request.deadline > latest {
            return Err(PrepareRefusal::DeadlineTooFar {
                deadline: request.deadline,
                latest,
            });
        }
        let ready_by = now
            .checked_add(estimated)
            .ok_or(PrepareRefusal::ClockOverflow)?;
        if ready_by > request.deadline {
            return Err(PrepareRefusal::CannotFinishByDeadline {
                ready_by,
                deadline: request.deadline,
            });
        }
        Ok(Self {
            request,
            admitted_at: now,
            estimated,
            state: PrepareState::Running { started_at: now },
            prepared_bytes: 0,
        })
    }

    pub fn request(&self) -> &PrepareRequest {
        &self.request
    }

    pub fn admitted_at(&self) -> MonotonicTime {
        self.admitted_at
    }

    /// The duration admission was checked with.
    pub fn estimated(&self) -> Duration {
        self.estimated
    }

    /// The state last computed; call [`Self::poll`] to apply the clock first.
    pub fn state(&self) -> PrepareState {
        self.state
    }

    /// Bytes the preparation holds now: its prepared bytes while ready, else zero.
    pub fn retained_bytes(&self) -> u64 {
        match self.state {
            PrepareState::Ready { .. } => self.prepared_bytes,
            _ => 0,
        }
    }

    /// Bytes the work prepared, whether or not they were used.
    pub fn prepared_bytes(&self) -> u64 {
        self.prepared_bytes
    }

    /// Applies the token, the deadline and the TTL at the clock's now.
    pub fn poll(&mut self, clock: &dyn Clock) -> PrepareState {
        let now = clock.now();
        let release = |reason| PrepareState::Released { at: now, reason };
        self.state = match self.state {
            PrepareState::Running { .. } | PrepareState::Ready { .. }
                if self.request.cancellation.is_cancelled() =>
            {
                match self.request.cancellation.reason() {
                    Some(reason) => release(ReleaseReason::Cancelled { reason }),
                    None => self.state,
                }
            }
            PrepareState::Running { .. } if now > self.request.deadline => {
                release(ReleaseReason::DeadlineMissed)
            }
            PrepareState::Ready { expires_at, .. } if now >= expires_at => PrepareState::Released {
                at: expires_at,
                reason: ReleaseReason::Expired,
            },
            other => other,
        };
        self.state
    }

    /// Records that the work finished with `prepared_bytes` ready. Work that finishes
    /// after its deadline or a cancellation is released at once and retains nothing.
    pub fn complete(
        &mut self,
        prepared_bytes: u64,
        clock: &dyn Clock,
    ) -> Result<PrepareState, PrepareRefusal> {
        match self.poll(clock) {
            PrepareState::Running { .. } => {
                let now = clock.now();
                let expires_at = now
                    .checked_add(self.request.retention_ttl)
                    .ok_or(PrepareRefusal::ClockOverflow)?;
                self.prepared_bytes = prepared_bytes;
                self.state = PrepareState::Ready {
                    ready_at: now,
                    expires_at,
                };
                Ok(self.state)
            }
            state @ PrepareState::Released { .. } => {
                self.prepared_bytes = prepared_bytes;
                Ok(state)
            }
            _ => Err(PrepareRefusal::NotRunning),
        }
    }

    /// Cancels through the operation's own token.
    pub fn cancel(&mut self, reason: CancelReason, clock: &dyn Clock) -> PrepareState {
        self.request.cancellation.cancel(reason);
        self.poll(clock)
    }

    /// A request for `target` arrived: matching ready state is used, matching running
    /// work is promoted, and anything else prepared for another target is released.
    pub fn request_arrived(&mut self, target: &PrepareTarget, clock: &dyn Clock) -> Arrival {
        let state = self.poll(clock);
        let now = clock.now();
        let matches = *target == self.request.target;
        match state {
            PrepareState::Ready { ready_at, .. } if matches => {
                self.state = PrepareState::Consumed { at: now };
                Arrival::Used {
                    prepared_bytes: self.prepared_bytes,
                    ready_at,
                }
            }
            PrepareState::Running { .. } if matches => {
                self.state = PrepareState::Consumed { at: now };
                Arrival::Promoted
            }
            PrepareState::Ready { .. } | PrepareState::Running { .. } => {
                self.state = PrepareState::Released {
                    at: now,
                    reason: ReleaseReason::NotRequested,
                };
                Arrival::NotUsed {
                    wasted_bytes: self.prepared_bytes,
                }
            }
            PrepareState::Released { reason, .. } => Arrival::AlreadyReleased { reason },
            PrepareState::Consumed { .. } => Arrival::AlreadyConsumed,
        }
    }
}

/// A generated answer charged to an arrived request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AnswerCharge {
    pub request: OperationId,
    pub output_tokens: u64,
    pub at: MonotonicTime,
}

/// A preparation's cost, booked as preparation and never as an answer.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PreparationCharge {
    pub operation: OperationId,
    pub tenant: TenantId,
    pub prepared_bytes: u64,
    pub preparation_seconds: f64,
}

/// Charges for answers and preparations (GPU §4.1: never "charge a generated answer
/// before a request exists").
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct ChargeBook {
    arrived: BTreeSet<OperationId>,
    preparations: BTreeSet<OperationId>,
    answers: Vec<AnswerCharge>,
    preparation_charges: Vec<PreparationCharge>,
}

impl ChargeBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that request `request` arrived; a preparation's id is not a request.
    pub fn request_arrived(&mut self, request: OperationId) -> Result<(), PrepareRefusal> {
        if self.preparations.contains(&request) {
            return Err(PrepareRefusal::PreparationIsNotARequest { operation: request });
        }
        self.arrived.insert(request);
        Ok(())
    }

    /// Books a preparation's cost under the preparation, once.
    pub fn charge_preparation(
        &mut self,
        operation: &PrepareOperation,
        preparation_seconds: f64,
    ) -> Result<(), PrepareRefusal> {
        let id = operation.request().operation.clone();
        if self.arrived.contains(&id) {
            return Err(PrepareRefusal::PreparationIsNotARequest { operation: id });
        }
        if !self.preparations.insert(id.clone()) {
            return Err(PrepareRefusal::DuplicateCharge { operation: id });
        }
        self.preparation_charges.push(PreparationCharge {
            operation: id,
            tenant: operation.request().tenant.clone(),
            prepared_bytes: operation.prepared_bytes(),
            preparation_seconds,
        });
        Ok(())
    }

    /// Charges a generated answer to `request`, which must have arrived and must not be
    /// a preparation.
    pub fn charge_answer(
        &mut self,
        request: &OperationId,
        output_tokens: u64,
        clock: &dyn Clock,
    ) -> Result<(), PrepareRefusal> {
        if self.preparations.contains(request) {
            return Err(PrepareRefusal::PreparationIsNotARequest {
                operation: request.clone(),
            });
        }
        if !self.arrived.contains(request) {
            return Err(PrepareRefusal::AnswerBeforeRequest {
                request: request.clone(),
            });
        }
        self.answers.push(AnswerCharge {
            request: request.clone(),
            output_tokens,
            at: clock.now(),
        });
        Ok(())
    }

    pub fn answers(&self) -> &[AnswerCharge] {
        &self.answers
    }

    pub fn preparation_charges(&self) -> &[PreparationCharge] {
        &self.preparation_charges
    }
}

/// Dwell times and spacing for weak intent (GPU §4.1: "Rate-limit hover or rapidly
/// changing selections").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct WeakIntentLimits {
    /// How long a selected target must stay unchanged before it is admitted.
    pub selection_dwell: Duration,
    /// The same for a hovered target; at least the selection dwell.
    pub hover_dwell: Duration,
    /// The shortest time between two weak admissions.
    pub min_interval: Duration,
}

impl WeakIntentLimits {
    fn check(&self) -> Result<(), PrepareRefusal> {
        if self.min_interval.is_zero() {
            return Err(PrepareRefusal::InvalidBounds {
                field: "min_interval",
            });
        }
        if self.hover_dwell < self.selection_dwell {
            return Err(PrepareRefusal::InvalidBounds {
                field: "hover_dwell",
            });
        }
        Ok(())
    }
}

/// An intent the gate let through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct AdmittedIntent {
    pub target: PrepareTarget,
    pub source: IntentSource,
    /// When the target was first indicated.
    pub observed_at: MonotonicTime,
    pub admitted_at: MonotonicTime,
}

/// What the gate decided at one moment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum IntentDecision {
    Admitted {
        intent: AdmittedIntent,
    },
    /// A weak target waits for its dwell to pass unchanged.
    Pending {
        ready_at: MonotonicTime,
    },
    /// A weak target is stable but the previous weak admission was too recent.
    RateLimited {
        until: MonotonicTime,
    },
    /// Nothing is pending.
    Idle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingIntent {
    target: PrepareTarget,
    source: IntentSource,
    since: MonotonicTime,
}

/// Admits strong intent at once and rate-limits weak intent (GPU §4.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntentGate {
    limits: WeakIntentLimits,
    pending: Option<PendingIntent>,
    last_weak_admission: Option<MonotonicTime>,
    superseded: u64,
}

impl IntentGate {
    pub fn new(limits: WeakIntentLimits) -> Result<Self, PrepareRefusal> {
        limits.check()?;
        Ok(Self {
            limits,
            pending: None,
            last_weak_admission: None,
            superseded: 0,
        })
    }

    /// Weak targets replaced before they were admitted.
    pub fn superseded(&self) -> u64 {
        self.superseded
    }

    /// Observes an intent at the clock's now. Strong intent is admitted at once and
    /// replaces any pending weak target. A weak target restarts the dwell unless it is
    /// the pending target, which a selection may confirm without restarting it.
    pub fn observe(
        &mut self,
        source: IntentSource,
        target: PrepareTarget,
        clock: &dyn Clock,
    ) -> IntentDecision {
        let now = clock.now();
        match source.strength() {
            IntentStrength::Strong => {
                if self.pending.take().is_some() {
                    self.superseded += 1;
                }
                IntentDecision::Admitted {
                    intent: AdmittedIntent {
                        target,
                        source,
                        observed_at: now,
                        admitted_at: now,
                    },
                }
            }
            IntentStrength::Weak => {
                match &mut self.pending {
                    Some(pending) if pending.target == target => {
                        if source == IntentSource::UiSelection {
                            pending.source = source;
                        }
                    }
                    slot => {
                        if slot.is_some() {
                            self.superseded += 1;
                        }
                        *slot = Some(PendingIntent {
                            target,
                            source,
                            since: now,
                        });
                    }
                }
                self.poll(clock)
            }
        }
    }

    /// Admits the pending weak target once its dwell has passed and the minimum interval
    /// since the last weak admission has elapsed.
    pub fn poll(&mut self, clock: &dyn Clock) -> IntentDecision {
        let now = clock.now();
        let Some(pending) = self.pending else {
            return IntentDecision::Idle;
        };
        let dwell = match pending.source {
            IntentSource::UiSelection => self.limits.selection_dwell,
            IntentSource::Hover => self.limits.hover_dwell,
            IntentSource::QueuedWorkflow => Duration::ZERO,
        };
        let ready_at = pending.since.saturating_add(dwell);
        if now < ready_at {
            return IntentDecision::Pending { ready_at };
        }
        if let Some(last) = self.last_weak_admission {
            let until = last.saturating_add(self.limits.min_interval);
            if now < until {
                return IntentDecision::RateLimited { until };
            }
        }
        self.pending = None;
        self.last_weak_admission = Some(now);
        IntentDecision::Admitted {
            intent: AdmittedIntent {
                target: pending.target,
                source: pending.source,
                observed_at: pending.since,
                admitted_at: now,
            },
        }
    }
}

/// One preparation's measured lifecycle (GPU §4.1 "full lifecycle accounting").
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LifecycleEntry {
    pub operation: OperationId,
    #[serde(serialize_with = "super::wire::origin")]
    pub origin: CandidateOrigin,
    /// Whether a request used the prepared state.
    pub used: bool,
    /// Request time saved against the matched demand-only request.
    pub saved_seconds: f64,
    /// Foreground time the preparation cost other requests.
    pub interference_seconds: f64,
    /// Prepared bytes no request used.
    pub wasted_bytes: u64,
    /// Bytes held times the seconds they were held.
    pub retained_byte_seconds: f64,
    /// Time the preparation work itself took.
    pub preparation_seconds: f64,
}

/// How lifecycle quantities become one score: the §2.9 objective for milliseconds and
/// bytes, and declared prices for retained memory and preparation time, both expressed
/// in the objective's currency units.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct LifecyclePrices {
    #[serde(skip)]
    pub objective: Objective,
    pub currency_per_retained_byte_second: f64,
    pub currency_per_preparation_second: f64,
}

impl LifecyclePrices {
    /// Refuses a negative or non-finite price.
    pub fn new(
        objective: Objective,
        currency_per_retained_byte_second: f64,
        currency_per_preparation_second: f64,
    ) -> Result<Self, PrefetchError> {
        for (field, value) in [
            (
                "currency_per_retained_byte_second",
                currency_per_retained_byte_second,
            ),
            (
                "currency_per_preparation_second",
                currency_per_preparation_second,
            ),
        ] {
            if !value.is_finite() {
                return Err(InputError::NotFinite { field }.into());
            }
            if value < 0.0 {
                return Err(InputError::Negative { field }.into());
            }
        }
        Ok(Self {
            objective,
            currency_per_retained_byte_second,
            currency_per_preparation_second,
        })
    }
}

/// The realized value of one preparation: the §2.9 expected value with the outcome
/// known, probability 1 when used and 0 when not.
pub fn realized_value(
    entry: &LifecycleEntry,
    prices: &LifecyclePrices,
) -> Result<PrefetchValue, PrefetchError> {
    let candidate = PrefetchCandidate {
        id: CandidateId::new(entry.operation.as_str())?,
        origin: entry.origin,
        probability: if entry.used { 1.0 } else { 0.0 },
        bytes: entry.wasted_bytes,
        saved_if_used: RawCost {
            milliseconds: entry.saved_seconds * 1_000.0,
            ..RawCost::default()
        },
        waste_if_unused: RawCost {
            bytes: entry.wasted_bytes as f64,
            ..RawCost::default()
        },
        interference: RawCost {
            milliseconds: entry.interference_seconds * 1_000.0,
            ..RawCost::default()
        },
        retention: RawCost {
            currency_units: entry.retained_byte_seconds * prices.currency_per_retained_byte_second
                + entry.preparation_seconds * prices.currency_per_preparation_second,
            ..RawCost::default()
        },
    };
    expected_value(&candidate, &prices.objective)
}

/// The foreground numbers a preparation policy must not regress.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct ForegroundGuard {
    pub baseline_success_rate: f64,
    pub candidate_success_rate: f64,
    pub baseline_p99_nanos: f64,
    pub candidate_p99_nanos: f64,
    /// Relative p99 increase tolerated.
    pub p99_tolerance: f64,
}

/// Why lifecycle accounting failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleFailure {
    NetValueNotPositive,
    ReliabilityRegressed,
    ForegroundP99Regressed,
}

/// The verdict of lifecycle accounting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum PreparationVerdict {
    Succeeded,
    /// No preparation ran and the foreground did not regress.
    NothingPrepared,
    Failed {
        failures: Vec<LifecycleFailure>,
    },
}

/// A policy's lifecycle account.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LifecycleAccount {
    pub preparations: usize,
    pub used: usize,
    /// Sum of realized values.
    pub net_score: f64,
    pub saved_score: f64,
    /// Waste, interference and retention scores.
    pub cost_score: f64,
    pub verdict: PreparationVerdict,
}

/// Accounts every preparation and checks the foreground guard (GPU §4.1). Succeeds only
/// when the summed realized value is positive, reliability did not fall and the
/// foreground p99 stayed within its tolerance.
pub fn account(
    entries: &[LifecycleEntry],
    prices: &LifecyclePrices,
    guard: &ForegroundGuard,
) -> Result<LifecycleAccount, PrefetchError> {
    let mut net_score = 0.0;
    let mut saved_score = 0.0;
    let mut cost_score = 0.0;
    for entry in entries {
        let value = realized_value(entry, prices)?;
        net_score += value.expected_value;
        saved_score += value.probability * value.saved_score;
        cost_score += (1.0 - value.probability) * value.waste_score
            + value.interference_score
            + value.retention_score;
    }
    let mut failures = Vec::new();
    if guard.candidate_success_rate < guard.baseline_success_rate {
        failures.push(LifecycleFailure::ReliabilityRegressed);
    }
    if guard.candidate_p99_nanos > guard.baseline_p99_nanos * (1.0 + guard.p99_tolerance) {
        failures.push(LifecycleFailure::ForegroundP99Regressed);
    }
    let verdict = if entries.is_empty() && failures.is_empty() {
        PreparationVerdict::NothingPrepared
    } else {
        if net_score <= 0.0 {
            failures.insert(0, LifecycleFailure::NetValueNotPositive);
        }
        if failures.is_empty() {
            PreparationVerdict::Succeeded
        } else {
            PreparationVerdict::Failed { failures }
        }
    };
    Ok(LifecycleAccount {
        preparations: entries.len(),
        used: entries.iter().filter(|entry| entry.used).count(),
        net_score,
        saved_score,
        cost_score,
        verdict,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::{digest, ManualClock};
    use crate::model_memory::readiness::test_support::{at, target, SECOND};

    fn bounds() -> PrepareBounds {
        PrepareBounds {
            max_lead: Duration::from_secs(60),
            max_retention_ttl: Duration::from_secs(30),
        }
    }

    fn request(deadline_seconds: u64, ttl_seconds: u64) -> PrepareRequest {
        PrepareRequest {
            operation: OperationId::new("op-prepare-1").unwrap(),
            execution: ExecutionId::new("exe-workflow").unwrap(),
            tenant: TenantId::new("tenant-a").unwrap(),
            target: target("model-b"),
            origin: CandidateOrigin::QueuedWork,
            deadline: at(deadline_seconds),
            retention_ttl: Duration::from_secs(ttl_seconds),
            cancellation: CancellationToken::new(),
            work: vec![
                PrepareWork::Step {
                    step: PreparationStep::Reserve,
                },
                PrepareWork::Step {
                    step: PreparationStep::InboundTransfer,
                },
                PrepareWork::Step {
                    step: PreparationStep::Verify,
                },
            ],
            assigned_request: None,
        }
    }

    fn admit(
        request: PrepareRequest,
        estimated_seconds: u64,
        clock: &ManualClock,
    ) -> Result<PrepareOperation, PrepareRefusal> {
        PrepareOperation::admit(
            request,
            Duration::from_secs(estimated_seconds),
            &bounds(),
            clock,
        )
    }

    #[test]
    fn admission_enforces_the_deadline_ttl_and_lead_bounds() {
        let clock = ManualClock::new(at(100));
        assert!(admit(request(110, 20), 10, &clock).is_ok());
        assert_eq!(
            admit(request(100, 20), 0, &clock).unwrap_err(),
            PrepareRefusal::DeadlinePassed {
                deadline: at(100),
                now: at(100)
            }
        );
        assert_eq!(
            admit(request(161, 20), 1, &clock).unwrap_err(),
            PrepareRefusal::DeadlineTooFar {
                deadline: at(161),
                latest: at(160)
            }
        );
        // Ten seconds of work cannot be ready nine seconds from now.
        assert_eq!(
            admit(request(109, 20), 10, &clock).unwrap_err(),
            PrepareRefusal::CannotFinishByDeadline {
                ready_by: at(110),
                deadline: at(109)
            }
        );
        assert_eq!(
            admit(request(110, 0), 1, &clock).unwrap_err(),
            PrepareRefusal::ZeroRetentionTtl
        );
        assert_eq!(
            admit(request(110, 31), 1, &clock).unwrap_err(),
            PrepareRefusal::RetentionTtlTooLong {
                ttl: Duration::from_secs(31),
                max: Duration::from_secs(30)
            }
        );
        let mut empty = request(110, 20);
        empty.work.clear();
        assert_eq!(admit(empty, 1, &clock).unwrap_err(), PrepareRefusal::NoWork);
        let cancelled = request(110, 20);
        cancelled.cancellation.cancel(CancelReason::Requester);
        assert_eq!(
            admit(cancelled, 1, &clock).unwrap_err(),
            PrepareRefusal::AlreadyCancelled {
                reason: CancelReason::Requester
            }
        );
        let zero_lead = PrepareBounds {
            max_lead: Duration::ZERO,
            ..bounds()
        };
        assert_eq!(
            PrepareOperation::admit(request(110, 20), Duration::ZERO, &zero_lead, &clock)
                .unwrap_err(),
            PrepareRefusal::InvalidBounds { field: "max_lead" }
        );
    }

    #[test]
    fn running_work_past_its_deadline_is_released_and_retains_nothing() {
        let clock = ManualClock::new(at(100));
        let mut operation = admit(request(110, 20), 5, &clock).unwrap();
        clock.advance_to(at(110));
        assert!(matches!(
            operation.poll(&clock),
            PrepareState::Running { .. }
        ));
        clock.advance_to(MonotonicTime::from_nanos(110 * SECOND + 1));
        assert_eq!(
            operation.poll(&clock),
            PrepareState::Released {
                at: MonotonicTime::from_nanos(110 * SECOND + 1),
                reason: ReleaseReason::DeadlineMissed
            }
        );
        // Late completion keeps nothing ready.
        assert!(matches!(
            operation.complete(1_000, &clock).unwrap(),
            PrepareState::Released { .. }
        ));
        assert_eq!(operation.retained_bytes(), 0);
    }

    #[test]
    fn cancellation_comes_from_the_requester_or_the_lease_and_the_first_wins() {
        let clock = ManualClock::new(at(100));
        let mut operation = admit(request(110, 20), 5, &clock).unwrap();
        let token = operation.request().cancellation.clone();
        assert!(token.cancel(CancelReason::Requester));
        assert!(!token.cancel(CancelReason::Superseded));
        assert_eq!(
            operation.poll(&clock),
            PrepareState::Released {
                at: at(100),
                reason: ReleaseReason::Cancelled {
                    reason: CancelReason::Requester
                }
            }
        );

        let mut operation = admit(request(110, 20), 5, &clock).unwrap();
        operation.complete(4_096, &clock).unwrap();
        let token = operation.request().cancellation.clone();
        assert_eq!(token.observe_lease(&LeaseState::Active), None);
        let lease = LeaseState::Cancelling {
            cause: LeaseCancelCause::Revocation,
            requested_at: at(101),
            bound_at: at(102),
        };
        assert_eq!(
            token.observe_lease(&lease),
            Some(CancelReason::Lease {
                cause: LeaseCancelCause::Revocation
            })
        );
        assert!(matches!(
            operation.poll(&clock),
            PrepareState::Released {
                reason: ReleaseReason::Cancelled { .. },
                ..
            }
        ));
        assert_eq!(operation.retained_bytes(), 0);
        let ended = CancellationToken::new();
        assert_eq!(
            ended.observe_lease(&LeaseState::NotRevived),
            Some(CancelReason::LeaseEnded)
        );
        // Every reason survives the token's encoding.
        for reason in [
            CancelReason::Requester,
            CancelReason::Superseded,
            CancelReason::LeaseEnded,
            CancelReason::Lease {
                cause: LeaseCancelCause::ResourceReturn,
            },
            CancelReason::Lease {
                cause: LeaseCancelCause::GrantRevoked,
            },
            CancelReason::DemandOnly {
                reason: DemandOnlyReason::Drift,
            },
        ] {
            let token = CancellationToken::new();
            token.cancel(reason);
            assert_eq!(token.reason(), Some(reason));
        }
    }

    #[test]
    fn unused_ready_state_expires_after_its_ttl() {
        let clock = ManualClock::new(at(100));
        let mut operation = admit(request(110, 20), 5, &clock).unwrap();
        clock.advance_to(at(104));
        assert_eq!(
            operation.complete(4_096, &clock).unwrap(),
            PrepareState::Ready {
                ready_at: at(104),
                expires_at: at(124)
            }
        );
        assert_eq!(operation.retained_bytes(), 4_096);
        clock.advance_to(at(123));
        assert!(matches!(operation.poll(&clock), PrepareState::Ready { .. }));
        clock.advance_to(at(130));
        assert_eq!(
            operation.poll(&clock),
            PrepareState::Released {
                at: at(124),
                reason: ReleaseReason::Expired
            }
        );
        assert_eq!(operation.retained_bytes(), 0);
        assert_eq!(
            operation.request_arrived(&target("model-b"), &clock),
            Arrival::AlreadyReleased {
                reason: ReleaseReason::Expired
            }
        );
    }

    #[test]
    fn arrival_uses_promotes_or_wastes_the_preparation() {
        let clock = ManualClock::new(at(100));
        let mut used = admit(request(110, 20), 5, &clock).unwrap();
        used.complete(4_096, &clock).unwrap();
        assert_eq!(
            used.request_arrived(&target("model-b"), &clock),
            Arrival::Used {
                prepared_bytes: 4_096,
                ready_at: at(100)
            }
        );
        assert_eq!(
            used.request_arrived(&target("model-b"), &clock),
            Arrival::AlreadyConsumed
        );
        let mut running = admit(request(110, 20), 5, &clock).unwrap();
        assert_eq!(
            running.request_arrived(&target("model-b"), &clock),
            Arrival::Promoted
        );
        let mut wasted = admit(request(110, 20), 5, &clock).unwrap();
        wasted.complete(4_096, &clock).unwrap();
        assert_eq!(
            wasted.request_arrived(&target("model-c"), &clock),
            Arrival::NotUsed {
                wasted_bytes: 4_096
            }
        );
        assert_eq!(wasted.retained_bytes(), 0);
    }

    #[test]
    fn preparation_never_pre_executes_an_external_action() {
        let clock = ManualClock::new(at(100));
        let action = ExternalAction::InvokeTool {
            tool: digest("yougori/test/tool/v1", &[b"run-tests"]),
        };
        let mut attempt = request(110, 20);
        attempt.work.push(PrepareWork::External { action });
        assert_eq!(
            admit(attempt, 1, &clock).unwrap_err(),
            PrepareRefusal::ExternalAction { action }
        );
        // Computing ahead is preparation work, but only for an assigned pending request.
        let mut ahead = request(110, 20);
        ahead.work.push(PrepareWork::Step {
            step: PreparationStep::ComputeAhead,
        });
        assert_eq!(
            admit(ahead.clone(), 1, &clock).unwrap_err(),
            PrepareRefusal::ComputeAheadWithoutRequest
        );
        ahead.assigned_request = Some(OperationId::new("op-pending-request").unwrap());
        assert!(admit(ahead, 1, &clock).is_ok());
    }

    #[test]
    fn no_answer_is_charged_before_its_request_exists() {
        let clock = ManualClock::new(at(100));
        let mut operation = admit(request(110, 20), 5, &clock).unwrap();
        operation.complete(4_096, &clock).unwrap();
        let mut book = ChargeBook::new();
        let request_id = OperationId::new("op-request-1").unwrap();
        assert_eq!(
            book.charge_answer(&request_id, 12, &clock),
            Err(PrepareRefusal::AnswerBeforeRequest {
                request: request_id.clone()
            })
        );
        book.charge_preparation(&operation, 5.0).unwrap();
        let prepare_id = operation.request().operation.clone();
        assert_eq!(
            book.charge_answer(&prepare_id, 12, &clock),
            Err(PrepareRefusal::PreparationIsNotARequest {
                operation: prepare_id.clone()
            })
        );
        assert_eq!(
            book.request_arrived(prepare_id.clone()),
            Err(PrepareRefusal::PreparationIsNotARequest {
                operation: prepare_id
            })
        );
        assert!(book.answers().is_empty());
        book.request_arrived(request_id.clone()).unwrap();
        book.charge_answer(&request_id, 12, &clock).unwrap();
        assert_eq!(book.answers().len(), 1);
        assert_eq!(book.preparation_charges().len(), 1);
        assert_eq!(
            book.charge_preparation(&operation, 5.0),
            Err(PrepareRefusal::DuplicateCharge {
                operation: operation.request().operation.clone()
            })
        );
    }

    fn limits() -> WeakIntentLimits {
        WeakIntentLimits {
            selection_dwell: Duration::from_millis(500),
            hover_dwell: Duration::from_millis(1_500),
            min_interval: Duration::from_secs(5),
        }
    }

    #[test]
    fn hover_and_rapidly_changing_selections_are_rate_limited() {
        let clock = ManualClock::new(at(100));
        let mut gate = IntentGate::new(limits()).unwrap();
        // Hovering across models every 200 ms never stays long enough.
        for (index, model) in ["model-a", "model-b", "model-c", "model-d"]
            .iter()
            .enumerate()
        {
            clock.advance_to(MonotonicTime::from_nanos(
                100 * SECOND + index as u64 * 200_000_000,
            ));
            let decision = gate.observe(IntentSource::Hover, target(model), &clock);
            assert!(matches!(decision, IntentDecision::Pending { .. }));
        }
        assert_eq!(gate.superseded(), 3);
        // A selection of a new model restarts the dwell, and is admitted after it.
        let selected_at = MonotonicTime::from_nanos(100 * SECOND + 700_000_000);
        clock.advance_to(selected_at);
        assert_eq!(
            gate.observe(IntentSource::UiSelection, target("model-b"), &clock),
            IntentDecision::Pending {
                ready_at: MonotonicTime::from_nanos(101 * SECOND + 200_000_000)
            }
        );
        clock.advance_to(MonotonicTime::from_nanos(101 * SECOND + 200_000_000));
        let IntentDecision::Admitted { intent } = gate.poll(&clock) else {
            panic!("the stable selection is admitted");
        };
        assert_eq!(intent.target, target("model-b"));
        assert_eq!(intent.observed_at, selected_at);
        // A second stable selection within the minimum interval waits for it.
        gate.observe(IntentSource::UiSelection, target("model-c"), &clock);
        clock.advance_to(at(103));
        assert_eq!(
            gate.poll(&clock),
            IntentDecision::RateLimited {
                until: MonotonicTime::from_nanos(106 * SECOND + 200_000_000)
            }
        );
        clock.advance_to(at(107));
        assert!(matches!(gate.poll(&clock), IntentDecision::Admitted { .. }));
        assert_eq!(gate.poll(&clock), IntentDecision::Idle);
    }

    #[test]
    fn queued_work_is_strong_intent_and_bypasses_the_weak_limits() {
        let clock = ManualClock::new(at(100));
        let mut gate = IntentGate::new(limits()).unwrap();
        gate.observe(IntentSource::UiSelection, target("model-c"), &clock);
        let decision = gate.observe(IntentSource::QueuedWorkflow, target("model-b"), &clock);
        assert!(matches!(
            decision,
            IntentDecision::Admitted { intent } if intent.target == target("model-b")
        ));
        // The strong intent replaced the pending weak one.
        assert_eq!(gate.superseded(), 1);
        assert_eq!(gate.poll(&clock), IntentDecision::Idle);
        assert_eq!(
            IntentSource::QueuedWorkflow.strength(),
            IntentStrength::Strong
        );
        assert_eq!(IntentSource::Hover.strength(), IntentStrength::Weak);
        assert_eq!(
            IntentSource::QueuedWorkflow.origin(),
            CandidateOrigin::QueuedWork
        );
        assert_eq!(
            IntentGate::new(WeakIntentLimits {
                min_interval: Duration::ZERO,
                ..limits()
            }),
            Err(PrepareRefusal::InvalidBounds {
                field: "min_interval"
            })
        );
        assert_eq!(
            IntentGate::new(WeakIntentLimits {
                hover_dwell: Duration::from_millis(100),
                ..limits()
            }),
            Err(PrepareRefusal::InvalidBounds {
                field: "hover_dwell"
            })
        );
    }

    fn prices() -> LifecyclePrices {
        // One score per saved millisecond, 1e-6 per wasted byte, one per currency unit.
        LifecyclePrices::new(Objective::new(1.0, 1e-6, 0.0, 1.0).unwrap(), 1e-9, 10.0).unwrap()
    }

    fn entry(used: bool) -> LifecycleEntry {
        LifecycleEntry {
            operation: OperationId::new("op-prepare-1").unwrap(),
            origin: CandidateOrigin::QueuedWork,
            used,
            saved_seconds: if used { 1.1 } else { 0.0 },
            interference_seconds: 0.0,
            wasted_bytes: if used { 0 } else { 6_000_000_000 },
            retained_byte_seconds: 6e9 * 2.0,
            preparation_seconds: 0.9,
        }
    }

    #[test]
    fn realized_value_is_the_expected_value_with_the_outcome_known() {
        // Used: 1,100 ms saved − (12e9 byte·s × 1e-9 + 0.9 s × 10) = 1,100 − 21 = 1,079.
        let used = realized_value(&entry(true), &prices()).unwrap();
        assert!((used.expected_value - 1_079.0).abs() < 1e-9);
        // Unused: −6e9 B × 1e-6 − 21 = −6,021.
        let unused = realized_value(&entry(false), &prices()).unwrap();
        assert!((unused.expected_value + 6_021.0).abs() < 1e-9);
        assert!(
            LifecyclePrices::new(Objective::new(1.0, 0.0, 0.0, 0.0).unwrap(), -1.0, 0.0).is_err()
        );
    }

    #[test]
    fn preparation_succeeds_only_if_its_benefit_survives_lifecycle_accounting() {
        let guard = ForegroundGuard {
            baseline_success_rate: 1.0,
            candidate_success_rate: 1.0,
            baseline_p99_nanos: 4e9,
            candidate_p99_nanos: 3e9,
            p99_tolerance: 0.05,
        };
        let good = account(&[entry(true)], &prices(), &guard).unwrap();
        assert_eq!(good.verdict, PreparationVerdict::Succeeded);
        assert_eq!(good.used, 1);
        // One hit cannot pay for one miss of this size.
        let mixed = account(&[entry(true), entry(false)], &prices(), &guard).unwrap();
        assert!((mixed.net_score - (1_079.0 - 6_021.0)).abs() < 1e-6);
        assert_eq!(
            mixed.verdict,
            PreparationVerdict::Failed {
                failures: vec![LifecycleFailure::NetValueNotPositive]
            }
        );
        let regressed = ForegroundGuard {
            candidate_success_rate: 0.9,
            candidate_p99_nanos: 4.3e9,
            ..guard
        };
        assert_eq!(
            account(&[entry(true)], &prices(), &regressed)
                .unwrap()
                .verdict,
            PreparationVerdict::Failed {
                failures: vec![
                    LifecycleFailure::ReliabilityRegressed,
                    LifecycleFailure::ForegroundP99Regressed
                ]
            }
        );
        assert_eq!(
            account(&[], &prices(), &guard).unwrap().verdict,
            PreparationVerdict::NothingPrepared
        );
    }
}
