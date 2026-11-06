//! The response side of a revocation measurement (VM-P14 line 2614: "measure durable
//! decision, new-request denial, active-channel closure, guest stop and cleanup
//! separately"; VM-CP-14 line 2989; §6.3 lines 2135–2137).
//!
//! A [`RevocationTimeline`] keeps five separate events: the durable epoch advance, the
//! first denied new authorization, channel closure, VM stop and cleanup completion. None is
//! inferred from another: "new authorizations denied" is not "all sockets closed".
//!
//! The events come from CORE-04's revocation operation ([`RevocationTimeline::observe_operation`]),
//! which keeps each milestone with what established it: its first denied authorization
//! (refused by the coordinator's own check or by an enforcement point the host observed),
//! its all-channels-closed (every eligible release channel of §2.5, as the host observed
//! it), its VM stop and its cleanup. CORE-04's `SocketsClosed` covers network sockets only
//! and its `LeasesClosed` covers leases, so neither is ever taken as channel closure. An
//! event CORE-04 does not see can still be recorded from the measuring host's own
//! observation ([`RevocationTimeline::record`]); each observed entry says which way it
//! came ([`EventSource`]).
//!
//! The drill computes p50, p95 and p99 over many timelines with CORE-08; this module only
//! keeps the times apart. The §6.5 stop figure travels as a
//! [`TargetLabel::EngineeringTarget`], never as a guarantee, and a timeline that met it
//! says so for that one run only.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::responder::DecisionId;
use crate::foundation::coordination::{
    MilestoneSource, RevocationMilestone, RevocationNotice, RevocationOperation,
};
use crate::foundation::ids::{ExecutionId, MonotonicTime};

/// One of the five separately measured revocation events (VM-CP-14).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationEventKind {
    /// The authorization epoch advanced durably: the decision (§6.3 step 1).
    DurableEpochAdvance,
    /// An enforcement point first denied a new authorization (§6.3 step 2).
    FirstDeniedAuthorization,
    /// Every eligible channel was observed closed (§6.3 step 2).
    ChannelClosure,
    /// The VM stopped (§6.3 step 4).
    VmStop,
    /// Cleanup finished (§6.3 step 5).
    CleanupCompletion,
}

impl RevocationEventKind {
    /// The five events in protocol order.
    pub const ALL: [Self; 5] = [
        Self::DurableEpochAdvance,
        Self::FirstDeniedAuthorization,
        Self::ChannelClosure,
        Self::VmStop,
        Self::CleanupCompletion,
    ];

    /// The snake_case label used in audit fields.
    pub const fn label(self) -> &'static str {
        match self {
            Self::DurableEpochAdvance => "durable_epoch_advance",
            Self::FirstDeniedAuthorization => "first_denied_authorization",
            Self::ChannelClosure => "channel_closure",
            Self::VmStop => "vm_stop",
            Self::CleanupCompletion => "cleanup_completion",
        }
    }

    /// The CORE-04 milestone this event is, for the four CORE-04 records; the durable
    /// epoch advance is the notice itself.
    pub const fn milestone(self) -> Option<RevocationMilestone> {
        match self {
            Self::DurableEpochAdvance => None,
            Self::FirstDeniedAuthorization => Some(RevocationMilestone::FirstDeniedAuthorization),
            Self::ChannelClosure => Some(RevocationMilestone::AllChannelsClosed),
            Self::VmStop => Some(RevocationMilestone::VmStopped),
            Self::CleanupCompletion => Some(RevocationMilestone::CleanupFinished),
        }
    }
}

strict_response_enum! {
    /// How one event of a timeline was observed.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum EventSource tag "source" {
        /// The CORE-04 revocation notice: the durable epoch advance.
        Notice,
        /// Taken from CORE-04's revocation operation, with what established the milestone
        /// there.
        Coordination {
            milestone: RevocationMilestone,
            established_by: MilestoneSource,
        },
        /// Recorded on this timeline from the measuring host's own observation.
        Recorded,
    }
}

/// What a figure is: a target, and nothing stronger (VM-CP-14: "the engineering target of
/// section 6.5 is reported as a target, not a guarantee"). There is no guarantee variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetLabel {
    EngineeringTarget,
}

/// The §6.5 stop figure, measured from the durable epoch advance to the VM stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmStopTarget {
    pub event: RevocationEventKind,
    pub within_seconds: u64,
    pub label: TargetLabel,
}

/// "Stop a disposable VM within two seconds under specified test load" (§6.5): a target.
pub const VM_STOP_TARGET: VmStopTarget = VmStopTarget {
    event: RevocationEventKind::VmStop,
    within_seconds: 2,
    label: TargetLabel::EngineeringTarget,
};

strict_response_enum! {
    /// Whether one event was observed.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TimelineStatus tag "status" {
        Observed {
            at: MonotonicTime,
            /// Nanoseconds after the durable epoch advance.
            after_decision_nanos: u64,
            source: EventSource,
        },
        /// Not observed yet; never filled in from another event.
        NotObserved,
    }
}

/// One event of a timeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimelineEntry {
    pub event: RevocationEventKind,
    pub status: TimelineStatus,
}

/// Why an event was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimelineRefusal {
    /// The durable epoch advance is the decision itself, set when the timeline begins.
    DecisionIsFixed,
    /// Before the durable epoch advance.
    BeforeDecision {
        event: RevocationEventKind,
        at: MonotonicTime,
        decided_at: MonotonicTime,
    },
    /// Each event is recorded once; the first time stands.
    AlreadyRecorded {
        event: RevocationEventKind,
        first: MonotonicTime,
    },
    /// Cleanup cannot complete before the VM stopped.
    CleanupBeforeStop,
    /// The operation is another revocation than the one this timeline began at.
    OtherRevocation,
}

impl fmt::Display for TimelineRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecisionIsFixed => {
                f.write_str("the durable epoch advance is fixed when the timeline begins")
            }
            Self::BeforeDecision {
                event,
                at,
                decided_at,
            } => write!(
                f,
                "{} at {} ns precedes the decision at {} ns",
                event.label(),
                at.as_nanos(),
                decided_at.as_nanos()
            ),
            Self::AlreadyRecorded { event, first } => write!(
                f,
                "{} was already recorded at {} ns",
                event.label(),
                first.as_nanos()
            ),
            Self::CleanupBeforeStop => f.write_str("cleanup cannot complete before the VM stops"),
            Self::OtherRevocation => {
                f.write_str("the operation belongs to another revocation than this timeline")
            }
        }
    }
}

impl std::error::Error for TimelineRefusal {}

/// The five separate times of one revocation (VM-P14; VM-CP-14).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RevocationTimeline {
    execution: ExecutionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<DecisionId>,
    decided_at: MonotonicTime,
    events: BTreeMap<RevocationEventKind, (MonotonicTime, EventSource)>,
}

impl RevocationTimeline {
    /// Begins at the CORE-04 notice: its time is the durable epoch advance. `decision` is
    /// the response decision that caused it, if any.
    pub fn begin(notice: &RevocationNotice, decision: Option<DecisionId>) -> Self {
        Self {
            execution: notice.execution.clone(),
            decision,
            decided_at: notice.at,
            events: BTreeMap::from([(
                RevocationEventKind::DurableEpochAdvance,
                (notice.at, EventSource::Notice),
            )]),
        }
    }

    /// The revoked sandbox.
    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    /// The response decision that caused the revocation, if any.
    pub const fn decision(&self) -> Option<DecisionId> {
        self.decision
    }

    /// The durable epoch advance.
    pub const fn decided_at(&self) -> MonotonicTime {
        self.decided_at
    }

    /// Records one event at `at` from the measuring host's own observation.
    pub fn record(
        &mut self,
        event: RevocationEventKind,
        at: MonotonicTime,
    ) -> Result<(), TimelineRefusal> {
        self.insert(event, at, EventSource::Recorded)
    }

    fn insert(
        &mut self,
        event: RevocationEventKind,
        at: MonotonicTime,
        source: EventSource,
    ) -> Result<(), TimelineRefusal> {
        if event == RevocationEventKind::DurableEpochAdvance {
            return Err(TimelineRefusal::DecisionIsFixed);
        }
        if at < self.decided_at {
            return Err(TimelineRefusal::BeforeDecision {
                event,
                at,
                decided_at: self.decided_at,
            });
        }
        if let Some(&(first, _)) = self.events.get(&event) {
            return Err(TimelineRefusal::AlreadyRecorded { event, first });
        }
        if event == RevocationEventKind::CleanupCompletion {
            match self.events.get(&RevocationEventKind::VmStop) {
                Some(&(stopped, _)) if stopped <= at => {}
                _ => return Err(TimelineRefusal::CleanupBeforeStop),
            }
        }
        self.events.insert(event, (at, source));
        Ok(())
    }

    /// Takes from a CORE-04 revocation operation each of its four events it reached that
    /// is not recorded yet: the first denied authorization, all channels closed, the VM
    /// stop and cleanup completion, each with what established it there. Neither sockets
    /// closed nor leases closed is channel closure, so neither is copied. Refuses the
    /// operation of another revocation. Returns the events taken.
    pub fn observe_operation(
        &mut self,
        operation: &RevocationOperation,
    ) -> Result<Vec<RevocationEventKind>, TimelineRefusal> {
        let notice = operation.notice();
        if notice.execution != self.execution || notice.at != self.decided_at {
            return Err(TimelineRefusal::OtherRevocation);
        }
        let mut taken = Vec::new();
        for event in RevocationEventKind::ALL {
            let Some(milestone) = event.milestone() else {
                continue;
            };
            if self.events.contains_key(&event) {
                continue;
            }
            // CORE-04 keeps a source with every milestone it reaches.
            let (Some(at), Some(established_by)) = (
                operation.milestone(milestone),
                operation.milestone_source(milestone),
            ) else {
                continue;
            };
            let source = EventSource::Coordination {
                milestone,
                established_by,
            };
            self.insert(event, at, source)?;
            taken.push(event);
        }
        Ok(taken)
    }

    /// How `event` was observed, if it was.
    pub fn source(&self, event: RevocationEventKind) -> Option<EventSource> {
        self.events.get(&event).map(|&(_, source)| source)
    }

    /// The five events in order, each observed or not.
    pub fn entries(&self) -> [TimelineEntry; 5] {
        RevocationEventKind::ALL.map(|event| TimelineEntry {
            event,
            status: match self.events.get(&event) {
                Some(&(at, source)) => TimelineStatus::Observed {
                    at,
                    after_decision_nanos: at
                        .saturating_duration_since(self.decided_at)
                        .as_nanos()
                        .try_into()
                        .unwrap_or(u64::MAX),
                    source,
                },
                None => TimelineStatus::NotObserved,
            },
        })
    }

    /// The §6.5 figure this timeline is held against: a target.
    pub const fn vm_stop_target(&self) -> VmStopTarget {
        VM_STOP_TARGET
    }

    /// Whether this one run stopped the VM within the target; `None` before the VM stop.
    /// An observation of one run under its test load, never a guarantee.
    pub fn vm_stop_within_target(&self) -> Option<bool> {
        let (stopped, _) = self.events.get(&RevocationEventKind::VmStop)?;
        let elapsed = stopped.saturating_duration_since(self.decided_at);
        Some(elapsed <= Duration::from_secs(VM_STOP_TARGET.within_seconds))
    }
}
