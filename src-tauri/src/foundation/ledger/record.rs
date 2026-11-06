//! The accounting record of one reservation: provenance, timestamps on the injected
//! clock, amounts over time and the observations reported about it (CORE-03 "accounting
//! provenance"; S7 line 128, BENCH-08).

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::request::{Priority, Provenance, QueueTicket, ReservationId};
use super::resource::{Amounts, ResourceKey};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::MonotonicTime;

/// Where a reservation is in its life (S10 line 179: reserve before create).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationState {
    /// Granted before the workload is created; nothing physical exists yet.
    Granted,
    /// The workload is being created or runs; its amounts count until a release is
    /// observed.
    InUse,
    /// Cancelled while in use; its amounts still count until a release is observed,
    /// because stopping or pausing work does not free its allocations (S10 line 185).
    Releasing,
    /// Its amounts were returned.
    Closed,
}

/// Why a reservation closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CloseReason {
    /// Cancelled before its workload was created.
    CancelledBeforeCreate,
    /// A release was observed by a source with authority over the amounts.
    ReleaseObserved { source: SourceClass },
    /// Reclaimed because its workload was not created within the grant lifetime.
    GrantExpired,
    /// Closed with its parent.
    ParentClosed { parent: ReservationId },
}

/// What changed a reservation's amounts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ChangeCause {
    Granted,
    Reconciled { source: SourceClass },
    Closed,
    // S03: a transition peak added on top of the steady amounts and taken off again, and
    // use beyond the amounts that an authoritative observation found and counted.
    TransitionPeakBegan,
    TransitionPeakEnded,
    OverUseCounted { source: SourceClass },
}

/// The amounts a reservation held from `at` until its next change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AmountChange {
    pub at: MonotonicTime,
    pub amounts: Amounts,
    pub cause: ChangeCause,
}

/// A report of what a workload uses, labelled with where it came from (CORE-01 source
/// classes). A guest report stays an observation: it is recorded and shown, and never
/// raises available host capacity (S2 CORE-03, S3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageObservation {
    pub source: SourceClass,
    pub in_use: Amounts,
}

/// The latest observation from one source class, as the ledger recorded it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedObservation {
    pub source: SourceClass,
    pub recorded_at: MonotonicTime,
    pub in_use: Amounts,
}

/// Time spent in each phase, for cost attribution (BENCH-08): queueing, idle time
/// reserved before the workload was created, use, and release.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseDurations {
    pub queued: Duration,
    pub reserved_before_create: Duration,
    pub in_use: Duration,
    pub releasing: Duration,
}

/// The accounting record of one reservation (CORE-03 "accounting provenance").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationRecord {
    pub(super) id: ReservationId,
    pub(super) provenance: Provenance,
    pub(super) priority: Priority,
    pub(super) parent: Option<ReservationId>,
    pub(super) depth: u8,
    pub(super) state: ReservationState,
    pub(super) close_reason: Option<CloseReason>,
    pub(super) ticket: Option<QueueTicket>,
    pub(super) requested_at: MonotonicTime,
    pub(super) granted_at: MonotonicTime,
    pub(super) create_started_at: Option<MonotonicTime>,
    pub(super) release_requested_at: Option<MonotonicTime>,
    pub(super) closed_at: Option<MonotonicTime>,
    pub(super) granted: Amounts,
    pub(super) current: Amounts,
    pub(super) history: Vec<AmountChange>,
    pub(super) overrun: bool,
    pub(super) observations: Vec<RecordedObservation>,
}

impl ReservationRecord {
    /// The reservation's number in its ledger.
    pub fn id(&self) -> ReservationId {
        self.id
    }

    /// Who asked, for which execution, operation and tenant, and the cost attribution.
    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    /// Foreground or background; a hold denies new background work.
    pub fn priority(&self) -> Priority {
        self.priority
    }

    /// The reservation this one is carved from; `None` at host level.
    pub fn parent(&self) -> Option<ReservationId> {
        self.parent
    }

    /// Zero for a host-level reservation, one more than its parent for a child.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Where the reservation is in its life.
    pub fn state(&self) -> ReservationState {
        self.state
    }

    /// Why it closed; `None` while open.
    pub fn close_reason(&self) -> Option<CloseReason> {
        self.close_reason
    }

    /// The queue ticket, when the request waited before it was granted.
    pub fn ticket(&self) -> Option<QueueTicket> {
        self.ticket
    }

    /// When the request arrived, before any queue wait.
    pub fn requested_at(&self) -> MonotonicTime {
        self.requested_at
    }

    /// When it was granted.
    pub fn granted_at(&self) -> MonotonicTime {
        self.granted_at
    }

    /// When creation of its workload started.
    pub fn create_started_at(&self) -> Option<MonotonicTime> {
        self.create_started_at
    }

    /// When it was cancelled after creation: the request stop of S7 line 131.
    pub fn release_requested_at(&self) -> Option<MonotonicTime> {
        self.release_requested_at
    }

    /// When its amounts returned: the observed release of S7 line 131.
    pub fn closed_at(&self) -> Option<MonotonicTime> {
        self.closed_at
    }

    /// The amounts first granted.
    pub fn granted(&self) -> &Amounts {
        &self.granted
    }

    /// The amounts held now; empty once closed.
    pub fn current(&self) -> &Amounts {
        &self.current
    }

    /// Every change of its amounts, oldest first.
    pub fn history(&self) -> &[AmountChange] {
        &self.history
    }

    /// Whether an authoritative observation found more in use than was reserved.
    pub fn overrun(&self) -> bool {
        self.overrun
    }

    /// The latest observation per source class, oldest first.
    pub fn observations(&self) -> &[RecordedObservation] {
        &self.observations
    }

    /// The latest observation from `source`.
    pub fn observation_from(&self, source: SourceClass) -> Option<&RecordedObservation> {
        self.observations
            .iter()
            .find(|observation| observation.source == source)
    }

    /// Time in each phase up to `now`, or up to closing for a closed record.
    pub fn phase_durations(&self, now: MonotonicTime) -> PhaseDurations {
        let end = self.closed_at.unwrap_or(now);
        let since = |from: MonotonicTime, to: MonotonicTime| to.saturating_duration_since(from);
        let use_ends = self.release_requested_at.unwrap_or(end);
        PhaseDurations {
            queued: since(self.requested_at, self.granted_at),
            reserved_before_create: since(self.granted_at, self.create_started_at.unwrap_or(end)),
            in_use: self
                .create_started_at
                .map_or(Duration::ZERO, |started| since(started, use_ends)),
            releasing: self
                .release_requested_at
                .map_or(Duration::ZERO, |requested| since(requested, end)),
        }
    }

    /// The integral of the amount of `resource` held over time up to `until`, in the
    /// resource's unit times nanoseconds (BENCH-08: VRAM byte-hours, VM hours).
    pub fn held_amount_nanoseconds(&self, resource: ResourceKey, until: MonotonicTime) -> u128 {
        self.history
            .iter()
            .enumerate()
            .fold(0u128, |total, (index, change)| {
                let end = self
                    .history
                    .get(index + 1)
                    .map_or(until, |next| next.at.min(until));
                let span = end.saturating_duration_since(change.at).as_nanos();
                total.saturating_add(u128::from(change.amounts.get(resource)).saturating_mul(span))
            })
    }

    /// Keeps the latest observation per source class, so a flood of reports takes
    /// bounded space.
    pub(super) fn record_observation(&mut self, observation: RecordedObservation) {
        self.observations
            .retain(|kept| kept.source != observation.source);
        self.observations.push(observation);
    }
}
