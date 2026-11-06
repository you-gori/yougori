//! Progress as shown (S2 CORE-06 progress stream, CORE-07; GPU part §3.10: "waiting for 4
//! GB of GPU memory", estimated remaining time with confidence, queue reason and safe
//! cancellation boundary).
//!
//! A [`ProgressShown`] is one CORE-06 progress state: its operation, its phase and the
//! [`ProgressUpdate`] itself, with CORE-06's own description. Reading one back runs
//! CORE-06's own check of the update against its phase and recomputes the description, so
//! a document cannot pair a completed phase with half the bytes, a queue reason outside
//! the queue or a description that says something else.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::text::ShownText;
use crate::foundation::events::{EventEnvelope, Phase, ProgressError, ProgressUpdate};
use crate::foundation::ids::OperationId;

/// One progress state as shown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProgressShown {
    operation: OperationId,
    phase: Phase,
    /// Whether the operation has ended (a terminal phase).
    ended: bool,
    update: ProgressUpdate,
    /// CORE-06's public explanation, such as "waiting for 4 GB of GPU memory".
    description: ShownText,
}

impl ProgressShown {
    /// The state `event` carries, checked as CORE-06 checks it.
    pub fn of(event: &EventEnvelope<ProgressUpdate>) -> Result<Self, ProgressError> {
        Self::new(event.operation().clone(), event.phase(), *event.payload())
    }

    fn new(
        operation: OperationId,
        phase: Phase,
        update: ProgressUpdate,
    ) -> Result<Self, ProgressError> {
        update.validate(phase)?;
        Ok(Self {
            operation,
            phase,
            ended: phase.is_terminal(),
            description: ShownText::new(&update.describe(phase)),
            update,
        })
    }

    pub fn operation(&self) -> &OperationId {
        &self.operation
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn ended(&self) -> bool {
        self.ended
    }

    pub fn update(&self) -> &ProgressUpdate {
        &self.update
    }

    pub fn description(&self) -> &ShownText {
        &self.description
    }
}

impl fmt::Display for ProgressShown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description.as_str())
    }
}

impl<'de> Deserialize<'de> for ProgressShown {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            operation: OperationId,
            phase: Phase,
            ended: bool,
            update: ProgressUpdate,
            description: ShownText,
        }
        let wire = Wire::deserialize(deserializer)?;
        let shown =
            Self::new(wire.operation, wire.phase, wire.update).map_err(serde::de::Error::custom)?;
        if wire.ended != shown.ended {
            return Err(serde::de::Error::custom(
                "a progress state has ended exactly when its phase is terminal",
            ));
        }
        if wire.description != shown.description {
            return Err(serde::de::Error::custom(
                "a progress description is CORE-06's description of its update",
            ));
        }
        Ok(shown)
    }
}
