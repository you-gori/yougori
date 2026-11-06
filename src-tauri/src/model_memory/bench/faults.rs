//! Fault injection for the fake runners (S10 line 183: "Make crash, disk-full, OOM, lost
//! event and stalled-provider cases reproducible with fakes"). Each fault ends the
//! attempts it reaches with a CORE-08 failure kind, so they stay in the raw data and the
//! denominators (S8). A crash recycles the runner, and the recycle is a recovery event
//! with its own latency and cost (S10).

use serde::{Deserialize, Serialize};

use super::resources::ResourceSnapshot;
use crate::foundation::ids::{MonotonicTime, OperationId};
use crate::foundation::report::{FailureKind, RunRecord};

/// A fault the fake runner can inject.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FaultKind {
    /// The engine process dies: every accepted request ends early and the runner
    /// recycles.
    Crash,
    /// The next load cannot write its staging data: the disk is full.
    DiskFull,
    /// The next GPU allocation, for a load or an admitted request, fails.
    OutOfMemory,
    /// The next completion event never reaches the client.
    LostEvent,
    /// The provider makes no progress for `stall_nanos`.
    StalledProvider { stall_nanos: u64 },
}

/// Where an attempt a fault ends lands in the CORE-08 taxonomy, with the provenance
/// written into its outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultClass {
    pub failure: FailureKind,
    pub component: &'static str,
    pub code: &'static str,
}

impl FaultKind {
    /// The five faults, with a representative stall.
    pub const ALL: [Self; 5] = [
        Self::Crash,
        Self::DiskFull,
        Self::OutOfMemory,
        Self::LostEvent,
        Self::StalledProvider { stall_nanos: 1 },
    ];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::Crash => "crash",
            Self::DiskFull => "disk-full",
            Self::OutOfMemory => "out-of-memory",
            Self::LostEvent => "lost-event",
            Self::StalledProvider { .. } => "stalled",
        }
    }

    /// The failure an attempt ended by this fault records (S8 failure taxonomy). A
    /// stalled attempt that still completes, after its deadline but before the client
    /// gives up, is a deadline failure with the same provenance.
    pub const fn classification(self) -> FaultClass {
        let (failure, component) = match self {
            Self::Crash => (FailureKind::EarlyTermination, "runner"),
            Self::DiskFull => (FailureKind::CommandFailure, "storage"),
            Self::OutOfMemory => (FailureKind::CommandFailure, "gpu-memory"),
            Self::LostEvent => (FailureKind::Timeout, "event-stream"),
            Self::StalledProvider { .. } => (FailureKind::Timeout, "provider"),
        };
        FaultClass {
            failure,
            component,
            code: self.slug(),
        }
    }

    /// Whether the fault takes the process down, so the runner recycles.
    pub const fn recycles(self) -> bool {
        matches!(self, Self::Crash)
    }
}

/// A fault at a time on the fake clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledFault {
    pub at: MonotonicTime,
    pub kind: FaultKind,
}

/// The raw data of one injected fault: when it was scheduled, when it took effect, which
/// attempts it ended and the recycle it caused. A fault that never met an operation it
/// affects stays here with no trigger time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultRecord {
    pub kind: FaultKind,
    pub scheduled_at: MonotonicTime,
    pub triggered_at: Option<MonotonicTime>,
    pub affected: Vec<OperationId>,
    /// Index into the runner's recycles.
    pub recycle: Option<usize>,
}

/// Why the runner recycled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecycleCause {
    /// An injected crash.
    Crash,
    /// A planned recycle; it is still a recovery event with a latency and a cost.
    Scheduled,
}

/// What a recycle cost (S10).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecycleCost {
    /// Time the runner could not serve.
    pub downtime_nanos: u64,
    /// Attempts the cause ended.
    pub failed_attempts: u64,
    /// Attempts refused while the runner was recycling.
    pub rejected_attempts: u64,
    /// Tokens the ended attempts had already produced and lost.
    pub lost_output_tokens: u64,
    /// Weight bytes moved to the GPU again.
    pub reloaded_bytes: u64,
    /// Weight bytes read from storage again.
    pub storage_read_bytes: u64,
}

/// A recycle: a visible recovery event with a latency and a cost (S10: "not an
/// unmeasured way to make a memory graph flat"). Its record is a CORE-08 stage record
/// whose primary interval is the recycle.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RecycleEvent {
    pub cause: RecycleCause,
    pub started_at: MonotonicTime,
    pub completed_at: MonotonicTime,
    pub latency_nanos: u64,
    pub cost: RecycleCost,
    /// The tracked resources just before the recycle and just after it.
    pub before: ResourceSnapshot,
    pub after: ResourceSnapshot,
    pub record: RunRecord,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_fault_has_a_place_in_the_taxonomy() {
        let kinds: Vec<FailureKind> = FaultKind::ALL
            .iter()
            .map(|fault| fault.classification().failure)
            .collect();
        assert_eq!(
            kinds,
            vec![
                FailureKind::EarlyTermination,
                FailureKind::CommandFailure,
                FailureKind::CommandFailure,
                FailureKind::Timeout,
                FailureKind::Timeout,
            ]
        );
        for fault in FaultKind::ALL {
            let class = fault.classification();
            assert_eq!(class.code, fault.slug());
            assert!(!class.component.is_empty());
        }
        assert!(FaultKind::Crash.recycles());
        assert!(!FaultKind::DiskFull.recycles());
    }

    #[test]
    fn fault_kinds_refuse_unknown_fields() {
        let stall: FaultKind =
            serde_json::from_str(r#"{"stalled_provider":{"stall_nanos":5}}"#).unwrap();
        assert_eq!(stall, FaultKind::StalledProvider { stall_nanos: 5 });
        assert!(serde_json::from_str::<FaultKind>(
            r#"{"stalled_provider":{"stall_nanos":5,"extra":1}}"#
        )
        .is_err());
        assert_eq!(
            serde_json::from_str::<FaultKind>(r#""crash""#).unwrap(),
            FaultKind::Crash
        );
        assert!(serde_json::from_str::<FaultKind>(r#"{"crash":{"extra":1}}"#).is_err());
    }
}
