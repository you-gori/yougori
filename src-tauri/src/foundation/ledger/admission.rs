//! The host admission and reservation ledger (CORE-03): physical capacity once per host
//! and device, tenant budgets charged separately, parent/child budgets, reserve before
//! create, a bounded queue served by the rules of [`QueueFairness`], cancellation, the
//! reclamation ladder of [`ReclaimLadder`], reclamation of unused grants and
//! reconciliation.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

use super::error::{
    CapacityError, LedgerError, Limit, ParentField, QueueRefusal, RetryProspect, Shortfall,
    Transition,
};
use super::fairness::{
    Charge, Claim, ClaimReason, Claims, QueueClaim, QueueEntry, QueueExit, QueueFairness,
    QueueRecord, TenantQueueStats, MAX_QUEUE_RECORDS,
};
use super::reclaim::{
    self, LadderReport, LadderSkip, NominationRefusal, ReclaimAdmission, ReclaimLadder,
    ReclaimNeed, ReclaimResponse, ReclaimStep, RefusedNomination, ReturnedReservation, StepOutcome,
    StepReport,
};
use super::record::{
    AmountChange, ChangeCause, CloseReason, RecordedObservation, ReservationRecord,
    ReservationState, UsageObservation,
};
use super::request::{
    HoldId, Priority, QueuePolicy, QueueTicket, Requester, ReservationId, ReservationRequest,
};
use super::resource::{Amounts, ResourceKey};
use crate::foundation::evidence::{HostSubject, SourceClass};
use crate::foundation::ids::{Clock, ExecutionId, MonotonicTime, TenantId};

pub(super) mod lifecycle;
pub(super) mod observed;
pub(super) mod ownership;
pub(super) mod sharing;
pub(super) mod transition;

/// How deep children nest below a host-level reservation: a VM, a runtime allocation in
/// it, a model load in that, and one more level (S3.2).
pub const MAX_NESTING_DEPTH: u8 = 4;

/// Bounds of the queue (S10 line 179: "bounded queueing").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueLimits {
    pub max_entries: usize,
    pub max_entries_per_tenant: usize,
    /// The longest any request waits; a request asking for longer waits this long.
    pub max_wait: Duration,
}

/// Ledger settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerConfig {
    pub queue: QueueLimits,
    /// How long a granted reservation waits for its workload to be created before the
    /// ledger reclaims it.
    pub grant_ttl: Duration,
    /// How long the host's latest observation of a resource's unmanaged usage (host
    /// pressure) stays current. Past it, the free amount is unknown, so new host-level
    /// grants of that resource are refused until the host observes it again; existing
    /// reservations stay. Declared physical capacity does not lapse.
    pub unmanaged_usage_max_age: Duration,
}

/// The host's observation of one resource's physical capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityDeclaration {
    pub total: u64,
    /// Kept for the supervisor, the host and consumers outside managed allocations, and
    /// never granted (S2 CORE-03; GPU part §2.7 safety reserve, §3.1 line 491).
    pub supervisor_reserve: u64,
    /// In use outside the ledger now, such as other processes, external GPU consumers or
    /// page cache, which is not free (GPU part §2.7, §3.1 line 491). A declaration is
    /// also an observation of this usage.
    pub unmanaged_in_use: u64,
    pub source: SourceClass,
}

/// Physical capacity of one resource as the host last observed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhysicalCapacity {
    pub total: u64,
    pub supervisor_reserve: u64,
    pub unmanaged_in_use: u64,
    /// When the host last observed the unmanaged usage, by a declaration or by
    /// [`Ledger::observe_unmanaged_usage`]; it lapses after
    /// [`LedgerConfig::unmanaged_usage_max_age`].
    pub observed_at: MonotonicTime,
}

impl PhysicalCapacity {
    /// The most that reservations together may hold: the total less the supervisor
    /// reserve.
    pub const fn grantable(self) -> u64 {
        self.total.saturating_sub(self.supervisor_reserve)
    }

    /// How old the unmanaged-usage observation is at `now` once it is past `max_age`;
    /// `None` while it is current.
    fn stale_age(self, now: MonotonicTime, max_age: Duration) -> Option<Duration> {
        let age = now.saturating_duration_since(self.observed_at);
        (age > max_age).then_some(age)
    }
}

/// The result of a reservation that was not refused (S10 line 179).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Granted before creation; create the workload now.
    Granted(ReservationId),
    /// Waiting in the bounded queue behind `ahead` earlier requests until `deadline`.
    Queued {
        ticket: QueueTicket,
        ahead: usize,
        deadline: MonotonicTime,
        waiting_for: CapacityError,
    },
}

/// The result of a cancellation or an observed release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseOutcome {
    /// Returned now.
    Released { amounts: Amounts },
    /// The workload exists, so its amounts count until their release is observed.
    Pending,
    /// Already closed; nothing changed.
    AlreadyClosed,
}

/// The result of a reconciliation (S10 line 179: reconcile after a partial start).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcileOutcome {
    /// Reserved but not in use, now returned.
    pub released: Amounts,
    /// In use beyond the reservation, now counted.
    pub overrun: Amounts,
}

/// What an owner resource-return hold found when it began (S10 line 185).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HoldReport {
    pub hold: HoldId,
    /// Existing background reservations on the held resources, left to drain.
    pub draining: Vec<ReservationId>,
    /// Queued background requests refused when the hold began.
    pub denied: Vec<QueueTicket>,
}

/// What cancelling an execution's reservations did (INT-02).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionCancelReport {
    pub released: Vec<ReservationId>,
    pub pending: Vec<ReservationId>,
    pub dequeued: Vec<QueueTicket>,
}

/// Something that happened to a request or reservation without its owner's call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerEvent {
    QueueGranted {
        ticket: QueueTicket,
        reservation: ReservationId,
    },
    QueueRefused {
        ticket: QueueTicket,
        error: LedgerError,
    },
    /// Reclaimed because its workload was not created within the grant lifetime.
    Reclaimed { reservation: ReservationId },
}

#[derive(Clone, Debug)]
struct QueuedRequest {
    ticket: QueueTicket,
    request: ReservationRequest,
    requested_at: MonotonicTime,
    deadline: MonotonicTime,
    waiting_for: CapacityError,
    /// How many later requests were granted capacity it falls short of.
    bypassed: u32,
    /// When it aged into protection from later requests.
    protected_at: Option<MonotonicTime>,
    /// When a background request was promoted into the foreground class.
    promoted_at: Option<MonotonicTime>,
}

impl QueuedRequest {
    fn tenant(&self) -> &TenantId {
        &self.request.provenance.tenant
    }

    /// Served in the foreground class: foreground, or background promoted by its wait.
    fn foreground(&self) -> bool {
        self.request.priority == Priority::Foreground || self.promoted_at.is_some()
    }

    /// What it keeps from the requests served after it: a protected request keeps its
    /// demand from every later request of its class and below, and with foreground first a
    /// foreground request keeps it from background ones.
    fn claim(&self, fairness: QueueFairness) -> Option<Claim> {
        let foreground = self.foreground();
        let (reason, binds_foreground) = if self.protected_at.is_some() {
            (ClaimReason::Aged, foreground || !fairness.foreground_first)
        } else if fairness.foreground_first && foreground {
            (ClaimReason::Foreground, false)
        } else {
            return None;
        };
        Some(Claim {
            held: QueueClaim {
                ticket: self.ticket,
                reason,
            },
            tenant: self.tenant().clone(),
            parent: self.request.parent,
            demand: self.request.demand.clone(),
            binds_foreground,
        })
    }

    fn entry(&self, now: MonotonicTime) -> QueueEntry {
        QueueEntry {
            ticket: self.ticket,
            tenant: self.tenant().clone(),
            priority: self.request.priority,
            requested_at: self.requested_at,
            deadline: self.deadline,
            waited: now.saturating_duration_since(self.requested_at),
            bypassed: self.bypassed,
            protected_at: self.protected_at,
            promoted_at: self.promoted_at,
            waiting_for: self.waiting_for.clone(),
        }
    }

    fn record(&self, left_at: MonotonicTime, exit: QueueExit) -> QueueRecord {
        QueueRecord {
            ticket: self.ticket,
            tenant: self.tenant().clone(),
            priority: self.request.priority,
            requested_at: self.requested_at,
            left_at,
            waited: left_at.saturating_duration_since(self.requested_at),
            bypassed: self.bypassed,
            protected_at: self.protected_at,
            promoted_at: self.promoted_at,
            exit,
        }
    }
}

/// Where a waiting request comes in the order the queue is served (GPU-W06), compared
/// field by field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ServiceKey {
    /// 0 for the foreground class, or for every request unless foreground goes first; 1
    /// for background.
    class: u8,
    /// Protected requests come first in their class, oldest first.
    unprotected: bool,
    /// Under tenant round-robin, the request's place among its tenant's requests.
    round: u32,
    /// Under tenant round-robin, the number of the queue grant its tenant last received.
    tenant_served: u64,
    /// Under tenant round-robin, the ticket of its tenant's oldest request in the class.
    tenant_first: QueueTicket,
    ticket: QueueTicket,
}

/// The CORE-03 host admission and reservation ledger for one host (S2 line 40).
///
/// Physical capacity is counted once per host resource and device, and only host
/// observations set it. A host-level reservation is charged against physical capacity
/// and, separately, against its tenant's budget; a child is carved from its parent and
/// charged to neither again (S3.2). The supervisor reserve is never granted. A guest
/// report is recorded as an observation and never raises available capacity: amounts
/// return to the host only when cancelled before creation, reclaimed unused, or released
/// as observed by the host (S2 line 40, S3.2, GPU part §3.1 line 491).
///
/// The ledger is synchronous and reads time only from its injected clock. Results that
/// happen without the owner's call (queue grants and refusals, reclamation) are kept as
/// [`LedgerEvent`]s until drained.
///
/// The queue is served by the rules of [`QueueFairness`], arrival order unless set
/// otherwise, and keeps each request's wait and bypass record (GPU-W06). A caller that
/// lends a [`ReclaimLadder`] to [`Ledger::reserve_reclaiming`] lets the owners of
/// speculation, scratch, caches and idle models give reservations up, in that order,
/// before a foreground request is queued or refused (GPU-W05).
pub struct Ledger<C> {
    clock: C,
    host: HostSubject,
    config: LedgerConfig,
    capacity: BTreeMap<ResourceKey, PhysicalCapacity>,
    budgets: BTreeMap<TenantId, Amounts>,
    open: BTreeMap<ReservationId, ReservationRecord>,
    queue: VecDeque<QueuedRequest>,
    holds: BTreeMap<HoldId, BTreeSet<ResourceKey>>,
    next_reservation: u64,
    next_ticket: u64,
    next_hold: u64,
    closed: Vec<ReservationRecord>,
    events: Vec<LedgerEvent>,
    fairness: QueueFairness,
    queue_stats: BTreeMap<TenantId, TenantQueueStats>,
    queue_records: Vec<QueueRecord>,
    queue_records_dropped: u64,
    /// Per tenant, the number of the queue grant it last received.
    last_served: BTreeMap<TenantId, u64>,
    queue_grants: u64,
    /// Lifecycle owners, transition peaks, shared extents and observed use (S03).
    ownership: ownership::Ownership,
}

impl<C: Clock> Ledger<C> {
    /// A ledger for `host` that reads time only from `clock`; no capacity is known until the host declares it.
    pub fn new(clock: C, host: HostSubject, config: LedgerConfig) -> Self {
        Self {
            clock,
            host,
            config,
            capacity: BTreeMap::new(),
            budgets: BTreeMap::new(),
            open: BTreeMap::new(),
            queue: VecDeque::new(),
            holds: BTreeMap::new(),
            next_reservation: 1,
            next_ticket: 1,
            next_hold: 1,
            closed: Vec::new(),
            events: Vec::new(),
            fairness: QueueFairness::ARRIVAL_ORDER,
            queue_stats: BTreeMap::new(),
            queue_records: Vec::new(),
            queue_records_dropped: 0,
            last_served: BTreeMap::new(),
            queue_grants: 0,
            ownership: ownership::Ownership::default(),
        }
    }

    /// The clock every reservation, grant and expiry of this ledger is measured on. A
    /// client that shares the ledger measures on the same clock (CORE-03: one host
    /// authority, one time base).
    pub fn clock(&self) -> &C {
        &self.clock
    }

    /// The host whose capacity this ledger counts.
    pub fn host(&self) -> HostSubject {
        self.host
    }

    /// The queue limits and the grant lifetime.
    pub fn config(&self) -> LedgerConfig {
        self.config
    }

    /// Sets how the queue is served from now on (GPU-W06) and serves it under the new
    /// rules. Waiting requests keep their wait, bypass count and protection.
    pub fn set_queue_fairness(&mut self, fairness: QueueFairness) {
        self.run(|ledger, _| ledger.fairness = fairness)
    }

    /// How the queue is served; [`QueueFairness::ARRIVAL_ORDER`] unless set otherwise.
    pub fn queue_fairness(&self) -> QueueFairness {
        self.fairness
    }

    /// Sets one resource's physical capacity from a host observation; a re-declaration
    /// replaces the previous one and never adds to it.
    pub fn declare_capacity(
        &mut self,
        resource: ResourceKey,
        declaration: CapacityDeclaration,
    ) -> Result<(), LedgerError> {
        self.declare_capacity_observed_at(resource, declaration, self.clock.now())
    }

    /// Declares a probe whose observation began at `observed_at`, in this ledger's
    /// clock domain. Waiting for I/O or a lock must not renew the probe's freshness.
    /// Future, expired and out-of-order observations leave the declaration unchanged.
    pub fn declare_capacity_observed_at(
        &mut self,
        resource: ResourceKey,
        declaration: CapacityDeclaration,
        observed_at: MonotonicTime,
    ) -> Result<(), LedgerError> {
        require_source(declaration.source, SourceClass::HostProbe)?;
        self.check_device(resource)?;
        if declaration.supervisor_reserve > declaration.total {
            return Err(LedgerError::ReserveExceedsCapacity {
                resource,
                total: declaration.total,
                supervisor_reserve: declaration.supervisor_reserve,
            });
        }
        self.run(|ledger, now| {
            if now
                .checked_duration_since(observed_at)
                .is_none_or(|age| age > ledger.config.unmanaged_usage_max_age)
                || ledger
                    .capacity
                    .get(&resource)
                    .is_some_and(|old| observed_at < old.observed_at)
            {
                return Err(LedgerError::ObservationNotCurrent {
                    resource,
                    observed_at,
                    now,
                });
            }
            ledger.capacity.insert(
                resource,
                PhysicalCapacity {
                    total: declaration.total,
                    supervisor_reserve: declaration.supervisor_reserve,
                    unmanaged_in_use: declaration.unmanaged_in_use,
                    observed_at,
                },
            );
            Ok(())
        })
    }

    /// Records host pressure: what consumers outside the ledger use now (S2 line 40).
    /// This refreshes the observation that lapses after
    /// [`LedgerConfig::unmanaged_usage_max_age`]; only a host probe can make it.
    pub fn observe_unmanaged_usage(
        &mut self,
        resource: ResourceKey,
        in_use: u64,
        source: SourceClass,
    ) -> Result<(), LedgerError> {
        require_source(source, SourceClass::HostProbe)?;
        if !self.capacity.contains_key(&resource) {
            return Err(LedgerError::CapacityNotDeclared { resource });
        }
        self.run(|ledger, now| {
            if let Some(capacity) = ledger.capacity.get_mut(&resource) {
                capacity.unmanaged_in_use = in_use;
                capacity.observed_at = now;
            }
        });
        Ok(())
    }

    /// The host's latest observation of `resource`; `None` when never observed.
    pub fn capacity(&self, resource: ResourceKey) -> Option<PhysicalCapacity> {
        self.capacity.get(&resource).copied()
    }

    /// GPU memory pools actually observed by this host ledger.
    pub fn vram_resources(&self) -> Vec<ResourceKey> {
        self.capacity.keys().filter(|key| matches!(key, ResourceKey::Vram(_))).copied().collect()
    }

    /// Sets a tenant's budget for one resource. A tenant without a budget for a resource
    /// cannot reserve it.
    pub fn set_tenant_budget(
        &mut self,
        tenant: TenantId,
        resource: ResourceKey,
        amount: u64,
    ) -> Result<(), LedgerError> {
        self.check_device(resource)?;
        self.run(|ledger, _| {
            ledger
                .budgets
                .entry(tenant)
                .or_default()
                .set(resource, amount)
        });
        Ok(())
    }

    /// The tenant's budget for `resource`; zero when none is set.
    pub fn tenant_budget(&self, tenant: &TenantId, resource: ResourceKey) -> u64 {
        self.budgets
            .get(tenant)
            .map_or(0, |budget| budget.get(resource))
    }

    /// Reserves before the workload is created (S10 line 179). The whole demand is
    /// granted or none of it; a request that does not fit waits in the bounded queue if
    /// it asked to and waiting can help, and is otherwise refused with an actionable
    /// [`CapacityError`]. A new request arrives after every waiting one, so it fits only
    /// in what the queue's fairness rules do not keep for them.
    pub fn reserve(&mut self, request: ReservationRequest) -> Result<Admission, LedgerError> {
        let now = self.clock.now();
        self.reclaim_expired_grants(now);
        self.serve_queue(now);
        match self.fit(&request, now, &self.waiting_claims())? {
            None => self.grant_new(request, now),
            Some(error) => self.queue_or_refuse(request, error, now),
        }
    }

    /// Reserves as [`Self::reserve`] does, but when a foreground request does not fit and
    /// only releases can make it fit, first runs the steps registered on `ladder` once, in
    /// [`ReclaimStep::ORDER`], until it fits (GPU-W05). Only what the ledger's own
    /// accounting returns counts: a reservation given up returns at once when its workload
    /// was never created, and otherwise only once its release is observed, which wakes the
    /// queue as any release does. A request that still does not fit is queued or refused
    /// with a capacity error listing each step tried and why it freed nothing. Serving the
    /// queue afterwards never runs the ladder again.
    pub fn reserve_reclaiming(
        &mut self,
        request: ReservationRequest,
        ladder: &mut ReclaimLadder<'_>,
    ) -> ReclaimAdmission {
        let now = self.clock.now();
        self.reclaim_expired_grants(now);
        self.serve_queue(now);
        let claims = self.waiting_claims();
        let error = match self.fit(&request, now, &claims) {
            Ok(Some(error)) => error,
            Ok(None) => {
                return ReclaimAdmission {
                    admission: self.grant_new(request, now),
                    report: LadderReport::skipped(LadderSkip::NotNeeded),
                }
            }
            Err(error) => {
                return ReclaimAdmission {
                    admission: Err(error),
                    report: LadderReport::skipped(LadderSkip::Invalid),
                }
            }
        };
        let (remaining, report, gave_up) = self.reclaim_for(&request, error, &claims, now, ladder);
        let admission = match remaining {
            Ok(None) => self.grant_new(request, now),
            Ok(Some(error)) => {
                self.queue_or_refuse(request, error.with_reclaim(report.clone()), now)
            }
            Err(error) => Err(error),
        };
        if gave_up {
            self.serve_queue(now);
        }
        ReclaimAdmission { admission, report }
    }

    /// Grants a new request that fits and counts the waiting requests it bypassed.
    fn grant_new(
        &mut self,
        request: ReservationRequest,
        now: MonotonicTime,
    ) -> Result<Admission, LedgerError> {
        let charge = Charge::of(None, &request);
        let reservation = self.grant(request, now, now, None)?;
        self.count_bypasses(&[charge], now);
        Ok(Admission::Granted(reservation))
    }

    /// Queues a new request that does not fit when it asked to wait and waiting can help,
    /// and refuses it otherwise.
    fn queue_or_refuse(
        &mut self,
        request: ReservationRequest,
        error: CapacityError,
        now: MonotonicTime,
    ) -> Result<Admission, LedgerError> {
        if !error.waitable() {
            return Err(LedgerError::Capacity(
                error.with_queue(QueueRefusal::NotWaitable),
            ));
        }
        let QueuePolicy::WaitUpTo(max_wait) = request.queue else {
            return Err(LedgerError::Capacity(
                error.with_queue(QueueRefusal::NotRequested),
            ));
        };
        let limits = self.config.queue;
        if self.queue.len() >= limits.max_entries {
            return Err(LedgerError::Capacity(error.with_queue(
                QueueRefusal::Full {
                    max_entries: limits.max_entries,
                },
            )));
        }
        let tenant = &request.provenance.tenant;
        let queued_for_tenant = self
            .queue
            .iter()
            .filter(|entry| entry.request.provenance.tenant == *tenant)
            .count();
        if queued_for_tenant >= limits.max_entries_per_tenant {
            return Err(LedgerError::Capacity(error.with_queue(
                QueueRefusal::TenantFull {
                    max_entries: limits.max_entries_per_tenant,
                },
            )));
        }
        let ticket = QueueTicket::new(take_next(&mut self.next_ticket)?);
        let deadline = now.saturating_add(max_wait.min(limits.max_wait));
        let ahead = self.queue.len();
        let stats = self.queue_stats.entry(tenant.clone()).or_default();
        stats.queued = stats.queued.saturating_add(1);
        self.queue.push_back(QueuedRequest {
            ticket,
            request,
            requested_at: now,
            deadline,
            waiting_for: error.clone(),
            bypassed: 0,
            protected_at: None,
            promoted_at: None,
        });
        Ok(Admission::Queued {
            ticket,
            ahead,
            deadline,
            waiting_for: error,
        })
    }

    /// Marks that creation of the reservation's workload has started; from now on its
    /// amounts return only through an observed release or reconciliation. Idempotent.
    pub fn begin_create(&mut self, reservation: ReservationId) -> Result<(), LedgerError> {
        self.run(|ledger, now| {
            let record = ledger.open_record(reservation)?;
            let (state, parent) = (record.state, record.parent);
            match state {
                ReservationState::InUse => return Ok(()),
                ReservationState::Granted => {}
                ReservationState::Releasing | ReservationState::Closed => {
                    return Err(LedgerError::InvalidTransition {
                        reservation,
                        state,
                        transition: Transition::BeginCreate,
                    })
                }
            }
            if let Some(parent) = parent {
                let parent_state = ledger.open.get(&parent).map(|record| record.state);
                if parent_state != Some(ReservationState::InUse) {
                    return Err(LedgerError::ParentNotInUse { parent });
                }
            }
            if let Some(record) = ledger.open.get_mut(&reservation) {
                record.state = ReservationState::InUse;
                record.create_started_at = Some(now);
            }
            Ok(())
        })
    }

    /// Cancels a reservation and its children. Before creation the amounts return at
    /// once and the queue wakes; after creation they count until their release is
    /// observed. Idempotent.
    pub fn cancel(&mut self, reservation: ReservationId) -> Result<ReleaseOutcome, LedgerError> {
        self.run(|ledger, now| ledger.cancel_at(reservation, now))
    }

    /// Withdraws a queued request. Idempotent: `false` when it already left the queue.
    pub fn cancel_queued(&mut self, ticket: QueueTicket) -> Result<bool, LedgerError> {
        if !issued(ticket.get(), self.next_ticket) {
            return Err(LedgerError::UnknownTicket { ticket });
        }
        Ok(self.run(|ledger, now| {
            let Some(index) = ledger.queue.iter().position(|entry| entry.ticket == ticket) else {
                return false;
            };
            match ledger.queue.remove(index) {
                Some(entry) => {
                    ledger.leave_queue(entry.record(now, QueueExit::Withdrawn));
                    true
                }
                None => false,
            }
        }))
    }

    /// Cancels every reservation and queued request of an execution, as on revocation
    /// (INT-02). Amounts of created workloads still count until their release is
    /// observed, so reclaiming never yields false free capacity.
    pub fn cancel_execution(&mut self, execution: &ExecutionId) -> ExecutionCancelReport {
        self.run(|ledger, now| {
            let mut report = ExecutionCancelReport::default();
            for entry in std::mem::take(&mut ledger.queue) {
                if entry.request.provenance.execution == *execution {
                    report.dequeued.push(entry.ticket);
                    let error = LedgerError::ExecutionCancelled {
                        execution: execution.clone(),
                    };
                    ledger.refuse_queued(entry, error, now);
                } else {
                    ledger.queue.push_back(entry);
                }
            }
            let roots: Vec<ReservationId> = ledger
                .open
                .values()
                .filter(|record| {
                    record.provenance.execution == *execution && record.parent.is_none()
                })
                .map(|record| record.id)
                .collect();
            for root in roots {
                match ledger.cancel_at(root, now) {
                    Ok(ReleaseOutcome::Released { .. }) => report.released.push(root),
                    Ok(ReleaseOutcome::Pending) => report.pending.push(root),
                    Ok(ReleaseOutcome::AlreadyClosed) | Err(_) => {}
                }
            }
            report
        })
    }

    /// Closes a reservation and its children once their release is observed. A
    /// host-level reservation needs a host observation; a child returns its amounts only
    /// to its parent, so its runtime's own report is enough. Idempotent.
    pub fn confirm_release(
        &mut self,
        reservation: ReservationId,
        source: SourceClass,
    ) -> Result<ReleaseOutcome, LedgerError> {
        self.run(|ledger, now| {
            let parent = match ledger.open_record(reservation) {
                Ok(record) => record.parent,
                Err(LedgerError::Closed { .. }) => return Ok(ReleaseOutcome::AlreadyClosed),
                Err(error) => return Err(error),
            };
            require_source(source, release_authority(parent))?;
            let amounts =
                ledger.close_tree(reservation, CloseReason::ReleaseObserved { source }, now);
            Ok(ReleaseOutcome::Released { amounts })
        })
    }

    /// Keeps what is actually in use and releases the rest, as after a partial start
    /// (S10 line 179). Use observed above the reservation is counted, never ignored. The
    /// observation needs the same authority as a release.
    pub fn reconcile(
        &mut self,
        reservation: ReservationId,
        observation: UsageObservation,
    ) -> Result<ReconcileOutcome, LedgerError> {
        self.run(|ledger, now| ledger.reconcile_at(reservation, observation, now))
    }

    /// Records what a workload reports using. Accounting never changes: an observation is
    /// not authority (S3.2). Only the latest report per source class is kept.
    pub fn observe_usage(
        &mut self,
        reservation: ReservationId,
        observation: UsageObservation,
    ) -> Result<(), LedgerError> {
        self.run(|ledger, now| {
            ledger.open_record(reservation)?;
            if let Some(record) = ledger.open.get_mut(&reservation) {
                record.record_observation(RecordedObservation {
                    source: observation.source,
                    recorded_at: now,
                    in_use: observation.in_use,
                });
            }
            Ok(())
        })
    }

    /// Begins an owner resource-return hold (S10 line 185): new background reservations
    /// of the held resources are denied and queued ones refused, while existing ones are
    /// listed to drain. Foreground work is unaffected.
    pub fn begin_hold(
        &mut self,
        resources: BTreeSet<ResourceKey>,
    ) -> Result<HoldReport, LedgerError> {
        let hold = HoldId::new(take_next(&mut self.next_hold)?);
        Ok(self.run(|ledger, now| {
            ledger.holds.insert(hold, resources.clone());
            let mut denied = Vec::new();
            for entry in std::mem::take(&mut ledger.queue) {
                match CapacityError::from_shortfalls(ledger.hold_shortfalls(&entry.request)) {
                    Some(error) => {
                        denied.push(entry.ticket);
                        let error =
                            LedgerError::Capacity(error.with_queue(QueueRefusal::NotWaitable));
                        ledger.refuse_queued(entry, error, now);
                    }
                    None => ledger.queue.push_back(entry),
                }
            }
            let draining = ledger
                .open
                .values()
                .filter(|record| {
                    record.priority == Priority::Background && record.current.touches(&resources)
                })
                .map(|record| record.id)
                .collect();
            HoldReport {
                hold,
                draining,
                denied,
            }
        }))
    }

    /// Ends a hold. Idempotent: `false` when it already ended.
    pub fn end_hold(&mut self, hold: HoldId) -> Result<bool, LedgerError> {
        if !issued(hold.get(), self.next_hold) {
            return Err(LedgerError::UnknownHold { hold });
        }
        Ok(self.run(|ledger, _| ledger.holds.remove(&hold).is_some()))
    }

    /// Lets time act: reclaims grants past their lifetime, refuses queued requests past
    /// their age limit and grants queued requests that now fit.
    pub fn tick(&mut self) {
        self.run(|_, _| {})
    }

    /// Grantable now: physical capacity less the supervisor reserve, unmanaged use and
    /// every host-level reservation. `None` when it is unknown: the host has not observed
    /// the capacity, or its latest observation of unmanaged usage is stale.
    pub fn available(&self, resource: ResourceKey) -> Option<u64> {
        let capacity = self.capacity.get(&resource)?;
        if capacity
            .stale_age(self.clock.now(), self.config.unmanaged_usage_max_age)
            .is_some()
        {
            return None;
        }
        let held =
            u128::from(capacity.unmanaged_in_use).saturating_add(self.top_level_sum(resource));
        Some(to_u64(
            u128::from(capacity.grantable()).saturating_sub(held),
        ))
    }

    /// Declared resources whose latest unmanaged-usage observation is stale, in resource
    /// order: the host observations to refresh before more of them can be granted.
    pub fn stale_observations(&self) -> Vec<ResourceKey> {
        let now = self.clock.now();
        let max_age = self.config.unmanaged_usage_max_age;
        self.capacity
            .iter()
            .filter(|(_, capacity)| capacity.stale_age(now, max_age).is_some())
            .map(|(resource, _)| *resource)
            .collect()
    }

    /// What host-level reservations hold of `resource`; children are inside these.
    pub fn reserved(&self, resource: ResourceKey) -> u64 {
        to_u64(self.top_level_sum(resource))
    }

    /// What the tenant's host-level reservations hold of `resource`.
    pub fn tenant_reserved(&self, tenant: &TenantId, resource: ResourceKey) -> u64 {
        to_u64(self.tenant_sum(tenant, resource))
    }

    /// What `parent` has not carved into children.
    pub fn parent_room(
        &self,
        parent: ReservationId,
        resource: ResourceKey,
    ) -> Result<u64, LedgerError> {
        let record = self.open_record(parent)?;
        let room = u128::from(record.current.get(resource))
            .saturating_sub(self.children_sum(parent, resource));
        Ok(to_u64(room))
    }

    /// An open reservation's record.
    pub fn reservation(&self, reservation: ReservationId) -> Option<&ReservationRecord> {
        self.open.get(&reservation)
    }

    /// Every reservation not yet closed, in the order granted.
    pub fn open_reservations(&self) -> impl Iterator<Item = &ReservationRecord> {
        self.open.values()
    }

    /// Records of closed reservations not yet taken.
    pub fn closed_records(&self) -> &[ReservationRecord] {
        &self.closed
    }

    /// Hands the closed records over, for cost attribution (BENCH-08).
    pub fn take_closed_records(&mut self) -> Vec<ReservationRecord> {
        std::mem::take(&mut self.closed)
    }

    /// Hands over the events kept since the last call, oldest first.
    pub fn drain_events(&mut self) -> Vec<LedgerEvent> {
        std::mem::take(&mut self.events)
    }

    /// How many requests wait in the queue.
    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    /// How many queued requests are ahead of `ticket`; `None` when it is not queued.
    pub fn queue_position(&self, ticket: QueueTicket) -> Option<usize> {
        self.queue.iter().position(|entry| entry.ticket == ticket)
    }

    /// Every waiting request with its wait, bypass count and protection, in arrival order
    /// (GPU-W06).
    pub fn queue_entries(&self) -> Vec<QueueEntry> {
        let now = self.clock.now();
        self.queue.iter().map(|entry| entry.entry(now)).collect()
    }

    /// Each tenant's use of the queue since the ledger began: waits, bypasses, aged and
    /// promoted requests, and how its requests left (GPU-W06).
    pub fn queue_stats(&self) -> &BTreeMap<TenantId, TenantQueueStats> {
        &self.queue_stats
    }

    /// Records of requests that left the queue and were not yet taken, oldest first; at
    /// most [`MAX_QUEUE_RECORDS`].
    pub fn queue_records(&self) -> &[QueueRecord] {
        &self.queue_records
    }

    /// Hands the records of requests that left the queue over, for a report.
    pub fn take_queue_records(&mut self) -> Vec<QueueRecord> {
        std::mem::take(&mut self.queue_records)
    }

    /// How many records of requests that left the queue were dropped untaken because more
    /// than [`MAX_QUEUE_RECORDS`] were kept.
    pub fn queue_records_dropped(&self) -> u64 {
        self.queue_records_dropped
    }

    /// The holds in force.
    pub fn active_holds(&self) -> Vec<HoldId> {
        self.holds.keys().copied().collect()
    }

    /// Runs an operation at one clock reading, after reclaiming expired grants and
    /// before serving the queue, so every change that frees capacity wakes it.
    fn run<T>(&mut self, operation: impl FnOnce(&mut Self, MonotonicTime) -> T) -> T {
        let now = self.clock.now();
        self.reclaim_expired_grants(now);
        let result = operation(self, now);
        self.serve_queue(now);
        result
    }

    fn cancel_at(
        &mut self,
        reservation: ReservationId,
        now: MonotonicTime,
    ) -> Result<ReleaseOutcome, LedgerError> {
        if let Some(error) = self.share_guard(reservation) {
            return Err(error);
        }
        let state = match self.open_record(reservation) {
            Ok(record) => record.state,
            Err(LedgerError::Closed { .. }) => return Ok(ReleaseOutcome::AlreadyClosed),
            Err(error) => return Err(error),
        };
        Ok(match state {
            ReservationState::Granted => ReleaseOutcome::Released {
                amounts: self.close_tree(reservation, CloseReason::CancelledBeforeCreate, now),
            },
            ReservationState::InUse | ReservationState::Releasing => {
                self.mark_releasing(reservation, now);
                ReleaseOutcome::Pending
            }
            ReservationState::Closed => ReleaseOutcome::AlreadyClosed,
        })
    }

    fn reconcile_at(
        &mut self,
        reservation: ReservationId,
        observation: UsageObservation,
        now: MonotonicTime,
    ) -> Result<ReconcileOutcome, LedgerError> {
        let record = self.open_record(reservation)?;
        let (state, parent, previous) = (record.state, record.parent, record.current.clone());
        if state == ReservationState::Granted {
            return Err(LedgerError::InvalidTransition {
                reservation,
                state,
                transition: Transition::Reconcile,
            });
        }
        require_source(observation.source, release_authority(parent))?;
        let observed = observation.in_use;
        for resource in observed.resources() {
            self.check_device(resource)?;
        }
        if let Some(parent) = parent {
            let parent_amounts = self
                .open
                .get(&parent)
                .map(|record| record.current.clone())
                .ok_or(LedgerError::ParentNotOpen { parent })?;
            for (resource, amount) in observed.iter() {
                let siblings = self
                    .children_sum(parent, resource)
                    .saturating_sub(u128::from(previous.get(resource)));
                let room = u128::from(parent_amounts.get(resource)).saturating_sub(siblings);
                if u128::from(amount) > room {
                    return Err(LedgerError::ExceedsParent {
                        reservation,
                        parent,
                        resource,
                        observed: amount,
                        room: to_u64(room),
                    });
                }
            }
        }
        for resource in self.child_resources(reservation) {
            let children = self.children_sum(reservation, resource);
            if children > u128::from(observed.get(resource)) {
                return Err(LedgerError::BelowChildren {
                    reservation,
                    resource,
                    observed: observed.get(resource),
                    children: to_u64(children),
                });
            }
        }
        let released = previous.excess_over(&observed);
        let overrun = observed.excess_over(&previous);
        if let Some(record) = self.open.get_mut(&reservation) {
            record.current = observed.clone();
            record.overrun |= !overrun.is_empty();
            record.history.push(AmountChange {
                at: now,
                amounts: observed.clone(),
                cause: ChangeCause::Reconciled {
                    source: observation.source,
                },
            });
            record.record_observation(RecordedObservation {
                source: observation.source,
                recorded_at: now,
                in_use: observed,
            });
        }
        Ok(ReconcileOutcome { released, overrun })
    }

    /// Every shortfall of a request at `now`, or why the request is invalid. A child is
    /// carved from its parent's existing amounts, so host observations do not limit it.
    fn assess(
        &self,
        request: &ReservationRequest,
        now: MonotonicTime,
    ) -> Result<Vec<Shortfall>, LedgerError> {
        self.assess_claimed(request, now, &Claims::default(), true)
            .map(|(shortfalls, _)| shortfalls)
    }

    /// The capacity error of a request at `now` that counts what `claims` keep for waiting
    /// requests as taken; `None` when it fits.
    fn fit(
        &self,
        request: &ReservationRequest,
        now: MonotonicTime,
        claims: &Claims,
    ) -> Result<Option<CapacityError>, LedgerError> {
        let foreground = request.priority == Priority::Foreground;
        let (shortfalls, kept_for) = self.assess_claimed(request, now, claims, foreground)?;
        Ok(CapacityError::from_shortfalls(shortfalls).map(|error| error.with_kept_for(kept_for)))
    }

    /// Every shortfall of a request at `now`, counting what `claims` keep from a request of
    /// its class as taken, and the waiting requests whose claims those were; or why the
    /// request is invalid (GPU-W06).
    fn assess_claimed(
        &self,
        request: &ReservationRequest,
        now: MonotonicTime,
        claims: &Claims,
        foreground: bool,
    ) -> Result<(Vec<Shortfall>, Vec<QueueClaim>), LedgerError> {
        if request.demand.is_empty() {
            return Err(LedgerError::EmptyDemand);
        }
        for resource in request.demand.resources() {
            self.check_device(resource)?;
        }
        let mut shortfalls = self.hold_shortfalls(request);
        let mut kept_for = Vec::new();
        let mut checked =
            |resource: ResourceKey, limit: Limit, requested: u64, limit_amount: u64, held: u128| {
                let (claimed, holders) = claims.on(&limit, resource, foreground);
                let shortfall = check(
                    resource,
                    limit,
                    requested,
                    limit_amount,
                    held.saturating_add(claimed),
                );
                if shortfall.is_some() {
                    kept_for.extend(holders);
                }
                shortfall
            };
        if let Some(parent) = request.parent {
            let record = self.carvable_parent(parent, request)?;
            for (resource, amount) in request.demand.iter() {
                shortfalls.extend(checked(
                    resource,
                    Limit::ParentReservation { parent },
                    amount,
                    record.current.get(resource),
                    self.children_sum(parent, resource),
                ));
            }
        } else {
            let tenant = &request.provenance.tenant;
            let max_age = self.config.unmanaged_usage_max_age;
            for (resource, amount) in request.demand.iter() {
                let capacity = self.capacity.get(&resource);
                match capacity.map(|capacity| (capacity, capacity.stale_age(now, max_age))) {
                    None => shortfalls.push(Shortfall {
                        resource,
                        limit: Limit::CapacityNotObserved,
                        requested: amount,
                        available: 0,
                        prospect: RetryProspect::AfterHostObservation,
                    }),
                    Some((capacity, Some(age))) => shortfalls.push(Shortfall {
                        resource,
                        limit: Limit::StaleHostObservation {
                            observed_at: capacity.observed_at,
                            age,
                            max_age,
                        },
                        requested: amount,
                        available: 0,
                        prospect: RetryProspect::AfterHostObservation,
                    }),
                    Some((capacity, None)) => shortfalls.extend(checked(
                        resource,
                        Limit::PhysicalCapacity,
                        amount,
                        capacity.grantable(),
                        u128::from(capacity.unmanaged_in_use)
                            .saturating_add(self.top_level_sum(resource)),
                    )),
                }
                shortfalls.extend(checked(
                    resource,
                    Limit::TenantBudget {
                        tenant: tenant.clone(),
                    },
                    amount,
                    self.tenant_budget(tenant, resource),
                    self.tenant_sum(tenant, resource),
                ));
            }
        }
        kept_for.sort_by_key(|claim| claim.ticket);
        kept_for.dedup();
        Ok((shortfalls, kept_for))
    }

    fn hold_shortfalls(&self, request: &ReservationRequest) -> Vec<Shortfall> {
        if request.priority != Priority::Background {
            return Vec::new();
        }
        request
            .demand
            .iter()
            .filter_map(|(resource, amount)| {
                self.holds
                    .iter()
                    .find(|(_, held)| held.contains(&resource))
                    .map(|(hold, _)| Shortfall {
                        resource,
                        limit: Limit::OwnerReturnHold { hold: *hold },
                        requested: amount,
                        available: 0,
                        prospect: RetryProspect::AfterHoldEnds,
                    })
            })
            .collect()
    }

    /// The parent a child may be carved from: open, not releasing, of the same tenant,
    /// execution and priority, and not nested too deep.
    fn carvable_parent(
        &self,
        parent: ReservationId,
        request: &ReservationRequest,
    ) -> Result<&ReservationRecord, LedgerError> {
        let record = match self.open_record(parent) {
            Ok(record) => record,
            Err(LedgerError::Closed { .. }) => return Err(LedgerError::ParentNotOpen { parent }),
            Err(error) => return Err(error),
        };
        if record.state == ReservationState::Releasing {
            return Err(LedgerError::ParentNotOpen { parent });
        }
        if let Some(error) = self.growth_refusal(parent) {
            return Err(error);
        }
        let field = if record.provenance.tenant != request.provenance.tenant {
            Some(ParentField::Tenant)
        } else if record.provenance.execution != request.provenance.execution {
            Some(ParentField::Execution)
        } else if record.priority != request.priority {
            Some(ParentField::Priority)
        } else {
            None
        };
        if let Some(field) = field {
            return Err(LedgerError::ParentMismatch { parent, field });
        }
        if record.depth >= MAX_NESTING_DEPTH {
            return Err(LedgerError::NestingTooDeep {
                max_depth: MAX_NESTING_DEPTH,
            });
        }
        Ok(record)
    }

    fn grant(
        &mut self,
        request: ReservationRequest,
        requested_at: MonotonicTime,
        now: MonotonicTime,
        ticket: Option<QueueTicket>,
    ) -> Result<ReservationId, LedgerError> {
        let id = ReservationId::new(take_next(&mut self.next_reservation)?);
        let depth = request
            .parent
            .and_then(|parent| self.open.get(&parent))
            .map_or(0, |parent| parent.depth.saturating_add(1));
        let record = ReservationRecord {
            id,
            provenance: request.provenance,
            priority: request.priority,
            parent: request.parent,
            depth,
            state: ReservationState::Granted,
            close_reason: None,
            ticket,
            requested_at,
            granted_at: now,
            create_started_at: None,
            release_requested_at: None,
            closed_at: None,
            granted: request.demand.clone(),
            current: request.demand.clone(),
            history: vec![AmountChange {
                at: now,
                amounts: request.demand,
                cause: ChangeCause::Granted,
            }],
            overrun: false,
            observations: Vec::new(),
        };
        self.open.insert(id, record);
        Ok(id)
    }

    /// Serves the queue once at `now` (S10 line 179; GPU-W06). Requests past their age
    /// limit are refused. The rest are taken in the order of the fairness rules: by class
    /// when foreground goes first, protected requests first and oldest first, then tenants
    /// in turn or arrival order. Each is granted when it fits in what the claims of the
    /// requests taken before it leave. In arrival order there are no claims, so a request
    /// that fits is never held back by an earlier one that does not.
    fn serve_queue(&mut self, now: MonotonicTime) {
        self.settle_ownership(now);
        let fairness = self.fairness;
        let mut waiting: Vec<QueuedRequest> = std::mem::take(&mut self.queue).into();
        for entry in &mut waiting {
            if now <= entry.deadline {
                self.age(entry, now);
            }
        }
        let order = service_order(&waiting, fairness, &self.last_served);
        let mut slots: Vec<Option<QueuedRequest>> = waiting.into_iter().map(Some).collect();
        let mut claims = Claims::default();
        let mut grants = Vec::new();
        let mut kept = Vec::new();
        for index in order {
            let Some(mut entry) = slots.get_mut(index).and_then(Option::take) else {
                continue;
            };
            let ticket = entry.ticket;
            if now > entry.deadline {
                let error = LedgerError::QueueWaitExpired {
                    ticket,
                    waited: now.saturating_duration_since(entry.requested_at),
                    waiting_for: entry.waiting_for.clone(),
                };
                self.refuse_queued(entry, error, now);
                continue;
            }
            match self.assess_claimed(&entry.request, now, &claims, entry.foreground()) {
                Err(error) => self.refuse_queued(entry, error, now),
                Ok((shortfalls, kept_for)) => match CapacityError::from_shortfalls(shortfalls) {
                    None => {
                        grants.push(Charge::of(Some(ticket), &entry.request));
                        self.grant_queued(entry, now);
                    }
                    Some(error) if error.waitable() => {
                        entry.waiting_for = error
                            .with_kept_for(kept_for)
                            .with_reclaim_of(&entry.waiting_for);
                        if let Some(claim) = entry.claim(fairness) {
                            claims.push(claim);
                        }
                        kept.push(entry);
                    }
                    Some(error) => {
                        let error =
                            LedgerError::Capacity(error.with_queue(QueueRefusal::NotWaitable));
                        self.refuse_queued(entry, error, now);
                    }
                },
            }
        }
        kept.sort_by_key(|entry| entry.ticket);
        self.queue = kept.into();
        self.count_bypasses(&grants, now);
    }

    /// Grants a waiting request that fits.
    fn grant_queued(&mut self, entry: QueuedRequest, now: MonotonicTime) {
        let ticket = entry.ticket;
        let exit = match self.grant(entry.request.clone(), entry.requested_at, now, Some(ticket)) {
            Ok(reservation) => {
                self.events.push(LedgerEvent::QueueGranted {
                    ticket,
                    reservation,
                });
                self.queue_grants = self.queue_grants.saturating_add(1);
                self.last_served
                    .insert(entry.tenant().clone(), self.queue_grants);
                QueueExit::Granted { reservation }
            }
            Err(error) => {
                self.events.push(LedgerEvent::QueueRefused {
                    ticket,
                    error: error.clone(),
                });
                QueueExit::Refused { error }
            }
        };
        self.leave_queue(entry.record(now, exit));
    }

    /// Refuses a waiting request that left the queue.
    fn refuse_queued(&mut self, entry: QueuedRequest, error: LedgerError, now: MonotonicTime) {
        self.events.push(LedgerEvent::QueueRefused {
            ticket: entry.ticket,
            error: error.clone(),
        });
        self.leave_queue(entry.record(now, QueueExit::Refused { error }));
    }

    /// Keeps the record of a request that left the queue and adds it to its tenant's use.
    fn leave_queue(&mut self, record: QueueRecord) {
        self.queue_stats
            .entry(record.tenant.clone())
            .or_default()
            .record_exit(&record);
        self.queue_records.push(record);
        let excess = self.queue_records.len().saturating_sub(MAX_QUEUE_RECORDS);
        if excess > 0 {
            self.queue_records.drain(..excess);
            self.queue_records_dropped = self
                .queue_records_dropped
                .saturating_add(u64::try_from(excess).unwrap_or(u64::MAX));
        }
    }

    /// Protects a waiting request, or promotes a background one into the foreground
    /// class, once the fairness rules say it has waited or been bypassed long enough.
    fn age(&mut self, entry: &mut QueuedRequest, now: MonotonicTime) {
        let fairness = self.fairness;
        let waited = now.saturating_duration_since(entry.requested_at);
        let protect = fairness.protect_after_wait.is_some_and(|age| waited >= age)
            || fairness
                .protect_after_bypasses
                .is_some_and(|bypasses| entry.bypassed >= bypasses);
        if entry.protected_at.is_none() && protect {
            entry.protected_at = Some(now);
            let stats = self.queue_stats.entry(entry.tenant().clone()).or_default();
            stats.protected = stats.protected.saturating_add(1);
        }
        let promote = fairness.foreground_first
            && entry.request.priority == Priority::Background
            && fairness
                .promote_background_after
                .is_some_and(|age| waited >= age);
        if entry.promoted_at.is_none() && promote {
            entry.promoted_at = Some(now);
            let stats = self.queue_stats.entry(entry.tenant().clone()).or_default();
            stats.promoted = stats.promoted.saturating_add(1);
        }
    }

    /// Counts, for every waiting request, the requests just granted that bypassed it, and
    /// lets protection by bypass count take effect at once.
    fn count_bypasses(&mut self, grants: &[Charge], now: MonotonicTime) {
        if grants.is_empty() || self.queue.is_empty() {
            return;
        }
        let counts: Vec<usize> = self
            .queue
            .iter()
            .map(|entry| match self.assess(&entry.request, now) {
                Ok(shortfalls) => grants
                    .iter()
                    .filter(|grant| grant.bypassed(entry.ticket, &shortfalls))
                    .count(),
                Err(_) => 0,
            })
            .collect();
        let mut waiting = std::mem::take(&mut self.queue);
        for (entry, count) in waiting.iter_mut().zip(counts) {
            if count == 0 {
                continue;
            }
            let count = u32::try_from(count).unwrap_or(u32::MAX);
            entry.bypassed = entry.bypassed.saturating_add(count);
            let stats = self.queue_stats.entry(entry.tenant().clone()).or_default();
            stats.bypasses = stats.bypasses.saturating_add(u64::from(count));
            self.age(entry, now);
        }
        self.queue = waiting;
    }

    /// The claims of every waiting request, which bind a new request: it arrived after
    /// all of them.
    fn waiting_claims(&self) -> Claims {
        let mut claims = Claims::default();
        for claim in self
            .queue
            .iter()
            .filter_map(|entry| entry.claim(self.fairness))
        {
            claims.push(claim);
        }
        claims
    }

    /// Runs the ladder once for a new request that does not fit (GPU-W05): each registered
    /// implementation in step order, until the request fits. Returns the capacity error
    /// that remains (`None` once it fits, or why the request became invalid), what the
    /// ladder did, and whether any reservation was given up.
    fn reclaim_for(
        &mut self,
        request: &ReservationRequest,
        error: CapacityError,
        claims: &Claims,
        now: MonotonicTime,
        ladder: &mut ReclaimLadder<'_>,
    ) -> (
        Result<Option<CapacityError>, LedgerError>,
        LadderReport,
        bool,
    ) {
        if request.priority != Priority::Foreground {
            let report = LadderReport::skipped(LadderSkip::Background);
            return (Ok(Some(error)), report, false);
        }
        if !error.waitable() {
            let report = LadderReport::skipped(LadderSkip::NoReleaseHelps);
            return (Ok(Some(error)), report, false);
        }
        let mut remaining = Ok(Some(error));
        let mut steps = Vec::new();
        let mut gave_up = false;
        for step in ReclaimStep::ORDER {
            if !matches!(&remaining, Ok(Some(error)) if error.waitable()) {
                break;
            }
            let mut registered = false;
            for registration in ladder.implementations(step) {
                registered = true;
                let error = match remaining {
                    Ok(Some(error)) if error.waitable() => error,
                    other => {
                        remaining = other;
                        break;
                    }
                };
                let shortfalls: Vec<Shortfall> = error.shortfalls().cloned().collect();
                let owner = registration.owner;
                let need = ReclaimNeed::new(step, owner, request, &shortfalls, &self.open);
                let response = registration.reclaimer.reclaim(&need);
                let outcome = match response {
                    ReclaimResponse::Decline(reason) => {
                        remaining = Ok(Some(error));
                        StepOutcome::Declined(reason)
                    }
                    ReclaimResponse::Release(nominated) => {
                        let (outcome, after) =
                            self.give_up(nominated, owner, request, error, claims, now);
                        gave_up |= matches!(
                            &outcome,
                            StepOutcome::Released { returned, releasing, .. }
                                if !returned.is_empty() || !releasing.is_empty()
                        );
                        remaining = after;
                        outcome
                    }
                };
                steps.push(StepReport {
                    step,
                    owner: Some(owner),
                    outcome,
                });
            }
            if !registered {
                steps.push(StepReport {
                    step,
                    owner: None,
                    outcome: StepOutcome::NotRegistered,
                });
            }
        }
        let covered = matches!(remaining, Ok(None));
        (remaining, LadderReport::ran(steps, covered), gave_up)
    }

    /// Cancels, in order, the reservations one step gave up that the ledger accepts, until
    /// the request fits; the rest are left alone. Returns what happened and the capacity
    /// error that remains, or why the request became invalid, which stops the ladder.
    fn give_up(
        &mut self,
        nominated: Vec<ReservationId>,
        owner: Requester,
        request: &ReservationRequest,
        error: CapacityError,
        claims: &Claims,
        now: MonotonicTime,
    ) -> (StepOutcome, Result<Option<CapacityError>, LedgerError>) {
        let mut returned = Vec::new();
        let mut releasing = Vec::new();
        let mut refused = Vec::new();
        let mut remaining = Ok(Some(error));
        for reservation in nominated {
            let refusal = match &remaining {
                Ok(Some(error)) => self.refuse_nomination(reservation, owner, error),
                Ok(None) => Some(NominationRefusal::NotNeeded),
                Err(_) => break,
            };
            if let Some(reason) = refusal {
                refused.push(RefusedNomination {
                    reservation,
                    reason,
                });
                continue;
            }
            match self.cancel_at(reservation, now) {
                Ok(ReleaseOutcome::Released { amounts }) => {
                    returned.push(ReturnedReservation {
                        reservation,
                        amounts,
                    });
                    remaining = self.fit(request, now, claims);
                }
                Ok(ReleaseOutcome::Pending) => releasing.push(reservation),
                Ok(ReleaseOutcome::AlreadyClosed) => refused.push(RefusedNomination {
                    reservation,
                    reason: NominationRefusal::AlreadyClosed,
                }),
                Err(_) => refused.push(RefusedNomination {
                    reservation,
                    reason: NominationRefusal::Unknown,
                }),
            }
        }
        let outcome = StepOutcome::Released {
            returned,
            releasing,
            refused,
        };
        (outcome, remaining)
    }

    /// Why the ledger does not act on a reservation a step gave up: it must be open, filed
    /// by the step's owner and hold a resource the request falls short of under the same
    /// limit. `None` when it acts.
    fn refuse_nomination(
        &self,
        reservation: ReservationId,
        owner: Requester,
        error: &CapacityError,
    ) -> Option<NominationRefusal> {
        match self.open_record(reservation) {
            Ok(record) => reclaim::nomination_refusal(record, owner, error.shortfalls()),
            Err(LedgerError::Closed { .. }) => Some(NominationRefusal::AlreadyClosed),
            Err(_) => Some(NominationRefusal::Unknown),
        }
    }

    /// Reclaims granted reservations whose workload was not created in time; nothing was
    /// created, so their amounts return at once.
    fn reclaim_expired_grants(&mut self, now: MonotonicTime) {
        let ttl = self.config.grant_ttl;
        let expired: Vec<ReservationId> = self
            .open
            .values()
            .filter(|record| {
                record.state == ReservationState::Granted
                    && now.saturating_duration_since(record.granted_at) > ttl
            })
            .map(|record| record.id)
            .collect();
        for reservation in expired {
            if self.open.contains_key(&reservation) {
                self.close_tree(reservation, CloseReason::GrantExpired, now);
                self.events.push(LedgerEvent::Reclaimed { reservation });
            }
        }
    }

    /// Moves a created reservation and its created children to releasing; children
    /// granted but not created close at once.
    fn mark_releasing(&mut self, reservation: ReservationId, now: MonotonicTime) {
        for (child, state) in self.children_of(reservation) {
            if state == ReservationState::Granted {
                self.close_tree(
                    child,
                    CloseReason::ParentClosed {
                        parent: reservation,
                    },
                    now,
                );
            } else {
                self.mark_releasing(child, now);
            }
        }
        if let Some(record) = self.open.get_mut(&reservation) {
            if record.state == ReservationState::InUse {
                record.state = ReservationState::Releasing;
                record.release_requested_at = Some(now);
            }
        }
    }

    /// Closes a reservation after its children and returns its own amounts.
    fn close_tree(
        &mut self,
        reservation: ReservationId,
        reason: CloseReason,
        now: MonotonicTime,
    ) -> Amounts {
        for (child, _) in self.children_of(reservation) {
            self.close_tree(
                child,
                CloseReason::ParentClosed {
                    parent: reservation,
                },
                now,
            );
        }
        let Some(mut record) = self.open.remove(&reservation) else {
            return Amounts::new();
        };
        let released = std::mem::take(&mut record.current);
        record.state = ReservationState::Closed;
        record.close_reason = Some(reason);
        record.closed_at = Some(now);
        record.history.push(AmountChange {
            at: now,
            amounts: Amounts::new(),
            cause: ChangeCause::Closed,
        });
        self.closed.push(record);
        released
    }

    fn children_of(&self, parent: ReservationId) -> Vec<(ReservationId, ReservationState)> {
        self.open
            .values()
            .filter(|record| record.parent == Some(parent))
            .map(|record| (record.id, record.state))
            .collect()
    }

    fn child_resources(&self, parent: ReservationId) -> BTreeSet<ResourceKey> {
        self.open
            .values()
            .filter(|record| record.parent == Some(parent))
            .flat_map(|record| record.current.resources())
            .collect()
    }

    fn top_level_sum(&self, resource: ResourceKey) -> u128 {
        sum_of(
            self.open.values().filter(|record| record.parent.is_none()),
            resource,
        )
    }

    fn tenant_sum(&self, tenant: &TenantId, resource: ResourceKey) -> u128 {
        sum_of(
            self.open
                .values()
                .filter(|record| record.parent.is_none() && record.provenance.tenant == *tenant),
            resource,
        )
    }

    fn children_sum(&self, parent: ReservationId, resource: ResourceKey) -> u128 {
        sum_of(
            self.open
                .values()
                .filter(|record| record.parent == Some(parent)),
            resource,
        )
    }

    fn open_record(&self, reservation: ReservationId) -> Result<&ReservationRecord, LedgerError> {
        match self.open.get(&reservation) {
            Some(record) => Ok(record),
            None if issued(reservation.get(), self.next_reservation) => {
                Err(LedgerError::Closed { reservation })
            }
            None => Err(LedgerError::UnknownReservation { reservation }),
        }
    }

    fn check_device(&self, resource: ResourceKey) -> Result<(), LedgerError> {
        match resource.device() {
            Some(device) if device.machine() != self.host.machine => {
                Err(LedgerError::ForeignDevice { device })
            }
            _ => Ok(()),
        }
    }
}

/// The order in which `waiting`, in arrival order, is served under `fairness` (GPU-W06):
/// indices into it. In arrival order unless the rules say otherwise.
fn service_order(
    waiting: &[QueuedRequest],
    fairness: QueueFairness,
    last_served: &BTreeMap<TenantId, u64>,
) -> Vec<usize> {
    if fairness.serves_in_arrival_order() {
        return (0..waiting.len()).collect();
    }
    let mut rounds: BTreeMap<(u8, &TenantId), u32> = BTreeMap::new();
    let mut firsts: BTreeMap<(u8, &TenantId), QueueTicket> = BTreeMap::new();
    let mut keyed: Vec<(ServiceKey, usize)> = Vec::with_capacity(waiting.len());
    for (index, entry) in waiting.iter().enumerate() {
        let class = u8::from(fairness.foreground_first && !entry.foreground());
        let mut key = ServiceKey {
            class,
            unprotected: entry.protected_at.is_none(),
            round: 0,
            tenant_served: 0,
            tenant_first: entry.ticket,
            ticket: entry.ticket,
        };
        if key.unprotected && fairness.tenant_round_robin {
            let tenant = entry.tenant();
            let round = rounds.entry((class, tenant)).or_insert(0);
            key.round = *round;
            *round = round.saturating_add(1);
            key.tenant_served = last_served.get(tenant).copied().unwrap_or(0);
            key.tenant_first = *firsts.entry((class, tenant)).or_insert(entry.ticket);
        }
        keyed.push((key, index));
    }
    keyed.sort();
    keyed.into_iter().map(|(_, index)| index).collect()
}

/// The shortfall of `requested` under a limit of `limit_amount` of which `held` is
/// taken; `None` when it fits.
fn check(
    resource: ResourceKey,
    limit: Limit,
    requested: u64,
    limit_amount: u64,
    held: u128,
) -> Option<Shortfall> {
    let available = to_u64(u128::from(limit_amount).saturating_sub(held));
    let prospect = if requested > limit_amount {
        RetryProspect::ExceedsLimit {
            limit: limit_amount,
        }
    } else if requested > available {
        RetryProspect::FitsAfterRelease {
            shortfall: requested - available,
        }
    } else {
        return None;
    };
    Some(Shortfall {
        resource,
        limit,
        requested,
        available,
        prospect,
    })
}

/// A host-level reservation's amounts return to the host, which only a host observation
/// may do; a child's return to its parent, so its runtime's own report suffices, though
/// a declaration or fixture never does.
fn release_authority(parent: Option<ReservationId>) -> SourceClass {
    match parent {
        None => SourceClass::HostProbe,
        Some(_) => SourceClass::GuestReport,
    }
}

fn require_source(source: SourceClass, required: SourceClass) -> Result<(), LedgerError> {
    if source.satisfies(required) {
        Ok(())
    } else {
        Err(LedgerError::SourceNotAuthoritative { source, required })
    }
}

fn sum_of<'a>(records: impl Iterator<Item = &'a ReservationRecord>, resource: ResourceKey) -> u128 {
    records.fold(0u128, |total, record| {
        total.saturating_add(u128::from(record.current.get(resource)))
    })
}

fn to_u64(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Whether a sequence number was handed out by a counter now at `next`.
fn issued(value: u64, next: u64) -> bool {
    value >= 1 && value < next
}

fn take_next(counter: &mut u64) -> Result<u64, LedgerError> {
    let value = *counter;
    *counter = value
        .checked_add(1)
        .ok_or(LedgerError::IdentifiersExhausted)?;
    Ok(value)
}
