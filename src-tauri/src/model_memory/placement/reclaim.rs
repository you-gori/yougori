//! The reclamation gate of §3.6 step 7: old resources are reclaimed only after process
//! references and GPU completion events permit it. A released lease is not enough:
//! work it enqueued can still be running on the GPU.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::keys::{CompletionEventId, ReferenceId};

/// What holds a reference to a placement's memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceKind {
    /// A process mapping of the memory.
    ProcessMapping,
    /// An imported handle in another process.
    ImportedHandle,
    /// A captured graph that embeds the addresses.
    CapturedGraph,
}

/// Process references and pending GPU completion events for one placement.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReclaimGate {
    references: BTreeMap<ReferenceId, ReferenceKind>,
    pending_events: BTreeSet<CompletionEventId>,
}

impl ReclaimGate {
    /// Records a reference. Each reference is held once.
    pub fn hold(&mut self, reference: ReferenceId, kind: ReferenceKind) -> Result<(), GateError> {
        if self.references.contains_key(&reference) {
            return Err(GateError::ReferenceAlreadyHeld { reference });
        }
        self.references.insert(reference, kind);
        Ok(())
    }

    /// Drops a reference the process closed.
    pub fn drop_reference(&mut self, reference: ReferenceId) -> Result<(), GateError> {
        self.references
            .remove(&reference)
            .map(|_| ())
            .ok_or(GateError::UnknownReference { reference })
    }

    /// Records GPU work enqueued on the memory; its completion event is now pending.
    pub fn enqueue(&mut self, event: CompletionEventId) -> Result<(), GateError> {
        if !self.pending_events.insert(event) {
            return Err(GateError::EventAlreadyPending { event });
        }
        Ok(())
    }

    /// Records that a pending completion event signalled.
    pub fn complete(&mut self, event: CompletionEventId) -> Result<(), GateError> {
        if !self.pending_events.remove(&event) {
            return Err(GateError::UnknownEvent { event });
        }
        Ok(())
    }

    /// Whether reclamation may proceed: no references and no pending events.
    pub fn check(&self) -> Result<(), ReclaimBlocked> {
        if self.references.is_empty() && self.pending_events.is_empty() {
            return Ok(());
        }
        Err(ReclaimBlocked {
            references: self
                .references
                .iter()
                .map(|(reference, kind)| (*reference, *kind))
                .collect(),
            pending_events: self.pending_events.iter().copied().collect(),
        })
    }

    /// Whether nothing blocks reclamation.
    pub fn is_clear(&self) -> bool {
        self.check().is_ok()
    }
}

/// What still blocks reclamation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReclaimBlocked {
    pub references: Vec<(ReferenceId, ReferenceKind)>,
    pub pending_events: Vec<CompletionEventId>,
}

impl fmt::Display for ReclaimBlocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} process reference(s) and {} pending GPU completion event(s) still use the memory",
            self.references.len(),
            self.pending_events.len()
        )
    }
}

impl std::error::Error for ReclaimBlocked {}

/// A malformed gate update.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum GateError {
    ReferenceAlreadyHeld { reference: ReferenceId },
    UnknownReference { reference: ReferenceId },
    EventAlreadyPending { event: CompletionEventId },
    UnknownEvent { event: CompletionEventId },
}

crate::foundation::strict_serde::strict_tag!(GateError, "error");

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReferenceAlreadyHeld { reference } => {
                write!(f, "reference {reference} is already held")
            }
            Self::UnknownReference { reference } => write!(f, "reference {reference} is not held"),
            Self::EventAlreadyPending { event } => {
                write!(f, "completion event {event} is already pending")
            }
            Self::UnknownEvent { event } => write!(f, "completion event {event} is not pending"),
        }
    }
}

impl std::error::Error for GateError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_and_events_each_block_reclamation() {
        let mut gate = ReclaimGate::default();
        assert!(gate.is_clear());

        gate.hold(ReferenceId::new(1), ReferenceKind::CapturedGraph)
            .unwrap();
        gate.enqueue(CompletionEventId::new(9)).unwrap();
        let blocked = gate.check().unwrap_err();
        assert_eq!(
            blocked.references,
            vec![(ReferenceId::new(1), ReferenceKind::CapturedGraph)]
        );
        assert_eq!(blocked.pending_events, vec![CompletionEventId::new(9)]);

        gate.drop_reference(ReferenceId::new(1)).unwrap();
        assert_eq!(
            gate.check().unwrap_err().pending_events,
            vec![CompletionEventId::new(9)],
            "a pending completion event alone still blocks"
        );
        gate.complete(CompletionEventId::new(9)).unwrap();
        assert!(gate.is_clear());
    }

    #[test]
    fn malformed_updates_are_refused() {
        let mut gate = ReclaimGate::default();
        gate.hold(ReferenceId::new(1), ReferenceKind::ProcessMapping)
            .unwrap();
        assert_eq!(
            gate.hold(ReferenceId::new(1), ReferenceKind::ImportedHandle),
            Err(GateError::ReferenceAlreadyHeld {
                reference: ReferenceId::new(1)
            })
        );
        assert_eq!(
            gate.drop_reference(ReferenceId::new(2)),
            Err(GateError::UnknownReference {
                reference: ReferenceId::new(2)
            })
        );
        gate.enqueue(CompletionEventId::new(3)).unwrap();
        assert_eq!(
            gate.enqueue(CompletionEventId::new(3)),
            Err(GateError::EventAlreadyPending {
                event: CompletionEventId::new(3)
            })
        );
        assert_eq!(
            gate.complete(CompletionEventId::new(4)),
            Err(GateError::UnknownEvent {
                event: CompletionEventId::new(4)
            })
        );
    }
}
