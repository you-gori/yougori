//! The explicit placement states of §3.6 (lines 580–583) and their legal transitions.
//!
//! ```text
//! absent → preparing → materialized → activating → serving
//!                       ↑                 ↓           ↓
//!                    parked ← draining ←──────────────┘
//! any transient state → failed/recoverable, with stage and reason
//! ```
//!
//! The transient states are preparing, activating and draining. The diagram has no way
//! back to absent, so a placement could never be removed; [`is_allowed`] adds exactly
//! one kind of edge, retirement from a resting state (materialized, parked or failed) to
//! absent, which the slot permits only after everything the placement held has been
//! reclaimed.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::barrier::ValidationCheck;
use super::keys::{ExtentKey, Rank};
use crate::foundation::ids::MonotonicTime;

/// A placement state without its failure record, for transition checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateKind {
    Absent,
    Preparing,
    Materialized,
    Activating,
    Serving,
    Draining,
    Parked,
    Failed,
}

impl StateKind {
    /// Every state, in the diagram's order.
    pub const ALL: [Self; 8] = [
        Self::Absent,
        Self::Preparing,
        Self::Materialized,
        Self::Activating,
        Self::Serving,
        Self::Draining,
        Self::Parked,
        Self::Failed,
    ];

    /// Preparing, activating and draining: the states a placement passes through, and
    /// the only ones that can fail (line 583).
    pub const fn is_transient(self) -> bool {
        matches!(self, Self::Preparing | Self::Activating | Self::Draining)
    }

    /// The state's name in the plan.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Preparing => "preparing",
            Self::Materialized => "materialized",
            Self::Activating => "activating",
            Self::Serving => "serving",
            Self::Draining => "draining",
            Self::Parked => "parked",
            Self::Failed => "failed",
        }
    }
}

impl fmt::Display for StateKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Whether a placement may move from `from` to `to` (lines 580–583, plus retirement).
pub const fn is_allowed(from: StateKind, to: StateKind) -> bool {
    use StateKind::*;
    matches!(
        (from, to),
        (Absent, Preparing)
            | (Preparing, Materialized)
            | (Materialized, Activating)
            | (Activating, Serving)
            | (Activating, Draining)
            | (Serving, Draining)
            | (Draining, Parked)
            | (Parked, Materialized)
            | (Preparing, Failed)
            | (Activating, Failed)
            | (Draining, Failed)
            | (Materialized, Absent)
            | (Parked, Absent)
            | (Failed, Absent)
    )
}

/// The transient state a failure happened in: the failure's stage (line 583).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransientStage {
    Preparing,
    Activating,
    Draining,
}

impl TransientStage {
    /// The stage of a transient state; `None` for a resting one.
    pub const fn of(kind: StateKind) -> Option<Self> {
        match kind {
            StateKind::Preparing => Some(Self::Preparing),
            StateKind::Activating => Some(Self::Activating),
            StateKind::Draining => Some(Self::Draining),
            _ => None,
        }
    }

    /// The transient state this stage names.
    pub const fn state(self) -> StateKind {
        match self {
            Self::Preparing => StateKind::Preparing,
            Self::Activating => StateKind::Activating,
            Self::Draining => StateKind::Draining,
        }
    }
}

/// Why a placement failed (line 583).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum FailureReason {
    /// The activation was cancelled.
    Cancelled,
    /// The runtime process exited.
    ProcessExited,
    /// The artifact stopped being valid during preparation or activation.
    ArtifactInvalid,
    /// An extent could not be made usable (step 2).
    ExtentFailed { extent: ExtentKey },
    /// Runtime state could not be initialized (step 2).
    RuntimeInitializationFailed,
    /// A rank's validation of weights, buffers or graphs failed (step 3).
    ValidationFailed { rank: Rank, check: ValidationCheck },
    /// A rank reported a different rank coordination from the others (step 3).
    RankCoordinationMismatch { rank: Rank },
    /// A rank's readiness check failed or covered less than the declared shape (step 4).
    NotReady { rank: Rank },
}

crate::foundation::strict_serde::strict_tag!(FailureReason, "reason");

impl fmt::Display for FailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("the activation was cancelled"),
            Self::ProcessExited => f.write_str("the runtime process exited"),
            Self::ArtifactInvalid => f.write_str("the artifact stopped being valid"),
            Self::ExtentFailed { extent } => {
                write!(f, "extent {} could not be made usable", extent.content)
            }
            Self::RuntimeInitializationFailed => {
                f.write_str("runtime state could not be initialized")
            }
            Self::ValidationFailed { rank, check } => {
                write!(f, "rank {rank} failed validation of its {check}")
            }
            Self::RankCoordinationMismatch { rank } => {
                write!(f, "rank {rank} reported a different rank coordination")
            }
            Self::NotReady { rank } => {
                write!(f, "rank {rank} is not ready for the declared request shape")
            }
        }
    }
}

/// A failure with its stage and reason (line 583).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    pub stage: TransientStage,
    pub reason: FailureReason,
    pub at: MonotonicTime,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "failed while {}: {}",
            self.stage.state().name(),
            self.reason
        )
    }
}

/// A placement's state (§3.6 lines 580–583).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum PlacementState {
    Absent,
    Preparing,
    Materialized,
    Activating,
    Serving,
    Draining,
    Parked,
    Failed { failure: Failure },
}

crate::foundation::strict_serde::strict_tag!(PlacementState, "state");

impl PlacementState {
    /// The state without its failure record.
    pub const fn kind(&self) -> StateKind {
        match self {
            Self::Absent => StateKind::Absent,
            Self::Preparing => StateKind::Preparing,
            Self::Materialized => StateKind::Materialized,
            Self::Activating => StateKind::Activating,
            Self::Serving => StateKind::Serving,
            Self::Draining => StateKind::Draining,
            Self::Parked => StateKind::Parked,
            Self::Failed { .. } => StateKind::Failed,
        }
    }

    /// The failure record of a failed placement.
    pub const fn failure(&self) -> Option<&Failure> {
        match self {
            Self::Failed { failure } => Some(failure),
            _ => None,
        }
    }

    /// Moves to `to` along a legal edge. A failure carries a stage and a reason, so it
    /// goes through [`Self::fail`]; asking for `failed` here is refused.
    pub fn advance(&mut self, to: StateKind) -> Result<(), IllegalTransition> {
        *self = self.next(to)?;
        Ok(())
    }

    /// The state [`Self::advance`] would move to, without moving, so a caller can check
    /// every transition of a step before changing anything.
    pub fn next(&self, to: StateKind) -> Result<PlacementState, IllegalTransition> {
        let from = self.kind();
        let next = match to {
            StateKind::Absent => Self::Absent,
            StateKind::Preparing => Self::Preparing,
            StateKind::Materialized => Self::Materialized,
            StateKind::Activating => Self::Activating,
            StateKind::Serving => Self::Serving,
            StateKind::Draining => Self::Draining,
            StateKind::Parked => Self::Parked,
            StateKind::Failed => return Err(IllegalTransition { from, to }),
        };
        if !is_allowed(from, to) {
            return Err(IllegalTransition { from, to });
        }
        Ok(next)
    }

    /// Fails a transient state, recording the state as the stage (line 583). Resting
    /// states cannot fail.
    pub fn fail(
        &mut self,
        reason: FailureReason,
        at: MonotonicTime,
    ) -> Result<Failure, IllegalTransition> {
        let from = self.kind();
        let stage = TransientStage::of(from).ok_or(IllegalTransition {
            from,
            to: StateKind::Failed,
        })?;
        let failure = Failure { stage, reason, at };
        *self = Self::Failed { failure };
        Ok(failure)
    }
}

/// A transition the state diagram does not allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IllegalTransition {
    pub from: StateKind,
    pub to: StateKind,
}

impl fmt::Display for IllegalTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a placement cannot move from {} to {}",
            self.from, self.to
        )
    }
}

impl std::error::Error for IllegalTransition {}

#[cfg(test)]
mod tests {
    use super::*;

    const DIAGRAM_EDGES: [(StateKind, StateKind); 11] = [
        (StateKind::Absent, StateKind::Preparing),
        (StateKind::Preparing, StateKind::Materialized),
        (StateKind::Materialized, StateKind::Activating),
        (StateKind::Activating, StateKind::Serving),
        (StateKind::Activating, StateKind::Draining),
        (StateKind::Serving, StateKind::Draining),
        (StateKind::Draining, StateKind::Parked),
        (StateKind::Parked, StateKind::Materialized),
        (StateKind::Preparing, StateKind::Failed),
        (StateKind::Activating, StateKind::Failed),
        (StateKind::Draining, StateKind::Failed),
    ];

    const RETIREMENT_EDGES: [(StateKind, StateKind); 3] = [
        (StateKind::Materialized, StateKind::Absent),
        (StateKind::Parked, StateKind::Absent),
        (StateKind::Failed, StateKind::Absent),
    ];

    fn state_of(kind: StateKind) -> PlacementState {
        match kind {
            StateKind::Absent => PlacementState::Absent,
            StateKind::Preparing => PlacementState::Preparing,
            StateKind::Materialized => PlacementState::Materialized,
            StateKind::Activating => PlacementState::Activating,
            StateKind::Serving => PlacementState::Serving,
            StateKind::Draining => PlacementState::Draining,
            StateKind::Parked => PlacementState::Parked,
            StateKind::Failed => PlacementState::Failed {
                failure: Failure {
                    stage: TransientStage::Preparing,
                    reason: FailureReason::Cancelled,
                    at: MonotonicTime::ZERO,
                },
            },
        }
    }

    fn attempt(from: StateKind, to: StateKind) -> Result<PlacementState, IllegalTransition> {
        let mut state = state_of(from);
        if to == StateKind::Failed {
            state.fail(FailureReason::Cancelled, MonotonicTime::from_nanos(7))?;
        } else {
            state.advance(to)?;
        }
        Ok(state)
    }

    #[test]
    fn every_drawn_edge_and_retirement_is_allowed() {
        for (from, to) in DIAGRAM_EDGES.iter().chain(RETIREMENT_EDGES.iter()) {
            let state = attempt(*from, *to).unwrap();
            assert_eq!(state.kind(), *to, "{from} → {to}");
        }
    }

    #[test]
    fn every_other_transition_is_illegal() {
        let mut illegal = 0;
        for from in StateKind::ALL {
            for to in StateKind::ALL {
                let legal =
                    DIAGRAM_EDGES.contains(&(from, to)) || RETIREMENT_EDGES.contains(&(from, to));
                assert_eq!(is_allowed(from, to), legal, "{from} → {to}");
                if !legal {
                    illegal += 1;
                    let before = state_of(from);
                    let mut state = before;
                    let result = if to == StateKind::Failed {
                        state
                            .fail(FailureReason::Cancelled, MonotonicTime::ZERO)
                            .map(|_| ())
                    } else {
                        state.advance(to)
                    };
                    assert_eq!(result, Err(IllegalTransition { from, to }));
                    assert_eq!(state, before, "a refused transition changes nothing");
                }
            }
        }
        assert_eq!(illegal, 64 - DIAGRAM_EDGES.len() - RETIREMENT_EDGES.len());
    }

    #[test]
    fn a_failure_records_its_transient_stage_and_reason() {
        for (kind, stage) in [
            (StateKind::Preparing, TransientStage::Preparing),
            (StateKind::Activating, TransientStage::Activating),
            (StateKind::Draining, TransientStage::Draining),
        ] {
            assert!(kind.is_transient());
            let mut state = state_of(kind);
            let reason = FailureReason::NotReady { rank: Rank::new(1) };
            let failure = state.fail(reason, MonotonicTime::from_nanos(5)).unwrap();
            assert_eq!(failure.stage, stage);
            assert_eq!(failure.reason, reason);
            assert_eq!(state.failure(), Some(&failure));
            assert!(failure
                .to_string()
                .starts_with(&format!("failed while {}", kind.name())));
        }
        for kind in StateKind::ALL
            .into_iter()
            .filter(|kind| !kind.is_transient())
        {
            assert_eq!(TransientStage::of(kind), None);
            assert!(
                attempt(kind, StateKind::Failed).is_err(),
                "{kind} cannot fail"
            );
        }
    }

    #[test]
    fn failed_cannot_be_reached_without_a_reason() {
        let mut state = PlacementState::Activating;
        assert_eq!(
            state.advance(StateKind::Failed),
            Err(IllegalTransition {
                from: StateKind::Activating,
                to: StateKind::Failed
            })
        );
        assert_eq!(state, PlacementState::Activating);
    }

    #[test]
    fn a_failed_placement_can_only_be_retired() {
        for to in StateKind::ALL {
            assert_eq!(
                is_allowed(StateKind::Failed, to),
                to == StateKind::Absent,
                "failed → {to}"
            );
        }
    }
}
