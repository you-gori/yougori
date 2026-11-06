//! Queue fairness (GPU-W06, docs/combined-gpu-memory-and-vm-sandbox-plan.md line 1172:
//! "Track queue fairness, aging and protection against starvation"): the order in which
//! the bounded queue is served (S10 line 179), aging that stops later requests from taking
//! capacity an old request waits for, and the wait and bypass records a caller or report
//! reads.
//!
//! The default, [`QueueFairness::ARRIVAL_ORDER`], is what the ledger always did: the queue
//! is served in arrival order and a request that fits is granted even when an earlier one
//! does not, so a large request can wait until its age limit while smaller ones keep
//! taking whatever is released. It stays the default because the other rules are not
//! strictly safer for existing callers: they can turn a request that fits now into one
//! that waits, or that is refused when it asked not to wait. Every other behaviour is
//! opt-in:
//!
//! - Aging: a request that has waited `protect_after_wait`, or that later requests have
//!   bypassed `protect_after_bypasses` times, is *protected*. Protected requests are served
//!   first in their class, oldest first, and every request served after one sees its whole
//!   demand as taken. A later request may still backfill from what is left beyond that
//!   demand, so it never makes the protected request's shortfall larger, and capacity
//!   released for the protected request accumulates until it fits.
//! - Tenant round-robin: among unprotected requests of one class, tenants take turns,
//!   starting with the tenant least recently granted from the queue.
//! - Foreground first: foreground requests are served before background ones, and a
//!   background request is granted only from what waiting foreground requests leave. A
//!   background request that has waited `promote_background_after` is promoted into the
//!   foreground class.
//!
//! No request waits past its deadline (S10 line 179: "bounded queueing"): background work
//! is served, or refused with [`LedgerError::QueueWaitExpired`] when its wait ends.
//!
//! A request *bypasses* a waiting one when it arrived later, was granted, and charged a
//! resource under a limit the waiting one falls short of. Every queued request keeps its
//! wait and bypass count; [`QueueRecord`]s and per-tenant [`TenantQueueStats`] keep them
//! after it leaves the queue.

use std::fmt;
use std::time::Duration;

use super::error::{CapacityError, LedgerError, Limit, Shortfall};
use super::request::{Priority, QueueTicket, ReservationId, ReservationRequest};
use super::resource::{Amounts, ResourceKey};
use crate::foundation::ids::{MonotonicTime, TenantId};

/// How many records of requests that left the queue the ledger keeps until they are
/// taken; older ones are dropped first and counted.
pub const MAX_QUEUE_RECORDS: usize = 1024;

/// How the bounded queue is served (S10 line 179; GPU-W06). See the module documentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueFairness {
    /// A request that has waited this long is protected from later ones; `None`: never by
    /// age.
    pub protect_after_wait: Option<Duration>,
    /// A request bypassed this many times is protected from later ones; `None`: never by
    /// count.
    pub protect_after_bypasses: Option<u32>,
    /// Tenants take turns among unprotected requests of one class, instead of arrival
    /// order.
    pub tenant_round_robin: bool,
    /// Foreground requests are served before background ones, and background requests
    /// take only what waiting foreground requests leave.
    pub foreground_first: bool,
    /// A background request that has waited this long is served as foreground; only with
    /// `foreground_first`.
    pub promote_background_after: Option<Duration>,
}

impl QueueFairness {
    /// Arrival order with any request that fits granted at once: the ledger's behaviour
    /// before fairness existed, and the default.
    pub const ARRIVAL_ORDER: Self = Self {
        protect_after_wait: None,
        protect_after_bypasses: None,
        tenant_round_robin: false,
        foreground_first: false,
        promote_background_after: None,
    };

    /// Whether the queue is served in arrival order: no aging, turns or classes.
    pub(super) fn serves_in_arrival_order(self) -> bool {
        self.protect_after_wait.is_none()
            && self.protect_after_bypasses.is_none()
            && !self.tenant_round_robin
            && !self.foreground_first
    }
}

impl Default for QueueFairness {
    fn default() -> Self {
        Self::ARRIVAL_ORDER
    }
}

/// Why capacity is kept for a waiting request ahead of another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimReason {
    /// It aged: it waited past the age limit or was bypassed too often.
    Aged,
    /// It is foreground, and background requests take only what foreground ones leave.
    Foreground,
}

/// A waiting request whose demand was kept ahead of another request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueClaim {
    pub ticket: QueueTicket,
    pub reason: ClaimReason,
}

impl fmt::Display for QueueClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.reason {
            ClaimReason::Aged => write!(f, "{}, which aged", self.ticket),
            ClaimReason::Foreground => write!(f, "{}, a foreground request", self.ticket),
        }
    }
}

/// One request waiting in the queue, as the queue sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueEntry {
    pub ticket: QueueTicket,
    pub tenant: TenantId,
    pub priority: Priority,
    pub requested_at: MonotonicTime,
    pub deadline: MonotonicTime,
    /// How long it has waited so far.
    pub waited: Duration,
    /// How many later requests were granted capacity it falls short of.
    pub bypassed: u32,
    /// When it became protected from later requests; `None` while it is not.
    pub protected_at: Option<MonotonicTime>,
    /// When a background request was promoted into the foreground class.
    pub promoted_at: Option<MonotonicTime>,
    /// What it waits for, as of the last time the queue was served.
    pub waiting_for: CapacityError,
}

/// How a request left the queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueueExit {
    Granted {
        reservation: ReservationId,
    },
    /// Refused while waiting: its wait limit ended, waiting stopped helping, a hold
    /// denied it or its execution was cancelled.
    Refused {
        error: LedgerError,
    },
    /// Withdrawn by its owner.
    Withdrawn,
}

/// The wait and bypass record of one request that left the queue (GPU-W06).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueRecord {
    pub ticket: QueueTicket,
    pub tenant: TenantId,
    pub priority: Priority,
    pub requested_at: MonotonicTime,
    pub left_at: MonotonicTime,
    /// How long it waited.
    pub waited: Duration,
    pub bypassed: u32,
    pub protected_at: Option<MonotonicTime>,
    pub promoted_at: Option<MonotonicTime>,
    pub exit: QueueExit,
}

/// One tenant's use of the queue since the ledger began.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TenantQueueStats {
    /// Requests queued.
    pub queued: u64,
    /// Requests granted from the queue.
    pub granted: u64,
    /// Requests refused while waiting.
    pub refused: u64,
    /// Requests withdrawn by their owner.
    pub withdrawn: u64,
    /// The total wait of requests that left the queue.
    pub total_wait: Duration,
    /// The longest wait of a request that left the queue.
    pub longest_wait: Duration,
    /// How many times a later request was granted capacity one of its requests fell
    /// short of.
    pub bypasses: u64,
    /// Requests that aged into protection.
    pub protected: u64,
    /// Background requests promoted into the foreground class.
    pub promoted: u64,
}

impl TenantQueueStats {
    pub(super) fn record_exit(&mut self, record: &QueueRecord) {
        let count = match record.exit {
            QueueExit::Granted { .. } => &mut self.granted,
            QueueExit::Refused { .. } => &mut self.refused,
            QueueExit::Withdrawn => &mut self.withdrawn,
        };
        *count = count.saturating_add(1);
        self.total_wait = self.total_wait.saturating_add(record.waited);
        self.longest_wait = self.longest_wait.max(record.waited);
    }
}

/// What a waiting request keeps from the requests served after it.
#[derive(Clone, Debug)]
pub(super) struct Claim {
    pub(super) held: QueueClaim,
    pub(super) tenant: TenantId,
    pub(super) parent: Option<ReservationId>,
    pub(super) demand: Amounts,
    /// Whether foreground requests are bound too; every claim binds background ones.
    pub(super) binds_foreground: bool,
}

/// The claims in force while one request is assessed.
#[derive(Clone, Debug, Default)]
pub(super) struct Claims(Vec<Claim>);

impl Claims {
    pub(super) fn push(&mut self, claim: Claim) {
        self.0.push(claim);
    }

    /// What the claims keep of `resource` under `limit` from a request of the given
    /// class, and whose claims those are.
    pub(super) fn on(
        &self,
        limit: &Limit,
        resource: ResourceKey,
        foreground: bool,
    ) -> (u128, Vec<QueueClaim>) {
        self.0
            .iter()
            .filter(|claim| claim.binds_foreground || !foreground)
            .filter(|claim| counts_against(&claim.tenant, claim.parent, limit))
            .filter(|claim| claim.demand.get(resource) > 0)
            .fold((0u128, Vec::new()), |(total, mut holders), claim| {
                holders.push(claim.held);
                (
                    total.saturating_add(u128::from(claim.demand.get(resource))),
                    holders,
                )
            })
    }
}

/// What a request just granted charged, for counting whom it bypassed.
#[derive(Clone, Debug)]
pub(super) struct Charge {
    /// Its queue ticket; `None` for a new request, which arrived after every waiting one.
    pub(super) ticket: Option<QueueTicket>,
    pub(super) tenant: TenantId,
    pub(super) parent: Option<ReservationId>,
    pub(super) demand: Amounts,
}

impl Charge {
    pub(super) fn of(ticket: Option<QueueTicket>, request: &ReservationRequest) -> Self {
        Self {
            ticket,
            tenant: request.provenance.tenant.clone(),
            parent: request.parent,
            demand: request.demand.clone(),
        }
    }

    /// Whether it bypassed the waiting request `ticket`, which now falls short as
    /// `shortfalls` say: it arrived later and took a resource under a limit the waiting
    /// request falls short of.
    pub(super) fn bypassed(&self, ticket: QueueTicket, shortfalls: &[Shortfall]) -> bool {
        self.ticket.is_none_or(|own| own > ticket)
            && shortfalls.iter().any(|shortfall| {
                shortfall.prospect.waitable()
                    && takes_from(&self.tenant, self.parent, &self.demand, shortfall)
            })
    }
}

/// Whether amounts held by a reservation of `tenant` under `parent` count against the
/// limit and resource of `shortfall`, so that releasing them would let the short request
/// fit sooner, and taking more of them would push it further away.
pub(super) fn takes_from(
    tenant: &TenantId,
    parent: Option<ReservationId>,
    amounts: &Amounts,
    shortfall: &Shortfall,
) -> bool {
    amounts.get(shortfall.resource) > 0 && counts_against(tenant, parent, &shortfall.limit)
}

/// Whether a reservation of `tenant` under `parent` is charged against `limit`. Only the
/// three limits that releases can lift are shared this way.
fn counts_against(tenant: &TenantId, parent: Option<ReservationId>, limit: &Limit) -> bool {
    match limit {
        Limit::PhysicalCapacity => parent.is_none(),
        Limit::TenantBudget { tenant: limited } => parent.is_none() && tenant == limited,
        Limit::ParentReservation { parent: limited } => parent == Some(*limited),
        Limit::CapacityNotObserved
        | Limit::StaleHostObservation { .. }
        | Limit::OwnerReturnHold { .. } => false,
    }
}
