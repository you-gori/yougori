//! Plain-language public progress (§3.10 line 654; the GPU-W11 single status view of
//! readiness, memory, queue reason and estimated wait; today's client states in
//! Appendix A.1, line 1487).
//!
//! A public API explains "waiting for 4 GB of GPU memory" or "restoring weights from
//! local storage" rather than exposing allocation handles. [`PublicProgress`] is built
//! from one CORE-06 progress event. Its message is CORE-06's own description of the
//! update, so every surface words a state the same way (GPU-W11: UI and CLI describe the
//! same actual state). It carries no resource identity, generation, handle or stage
//! timing; stage timing exists only in benchmark and debug output
//! ([`super::DiagnosticProgress`]).

use serde::{Deserialize, Serialize};

use crate::foundation::events::{
    CancellationBoundary, DataSource, EtaEstimate, EventEnvelope, Phase, ProgressUpdate,
    QueueReason, ResourceKind,
};

/// Today's client progress states (Appendix A.1, line 1487: docs/gpu-optimizer.md and
/// the website's `inference-progress.mjs`), which accept exactly these five. They keep
/// their names and meaning; the new detail travels in fields of its own beside them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientState {
    Queued,
    FreeingMemory,
    LoadingModel,
    Generating,
    Retrying,
}

impl ClientState {
    /// Today's five, in the order docs/gpu-optimizer.md lists them.
    pub const ALL: [Self; 5] = [
        Self::Queued,
        Self::FreeingMemory,
        Self::LoadingModel,
        Self::Generating,
        Self::Retrying,
    ];

    /// The written name, as today's clients read it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::FreeingMemory => "freeing_memory",
            Self::LoadingModel => "loading_model",
            Self::Generating => "generating",
            Self::Retrying => "retrying",
        }
    }
}

/// Today's client state of a CORE-06 phase (Appendix A.1).
///
/// Memory being reserved, drained or released is today's `freeing_memory`; every step
/// that brings weights into use is `loading_model`. An ended operation has none: its
/// stream ends and the client receives the reply or error through its existing channel,
/// as today. CORE-06's `Retrying` phase is today's `retrying`.
pub const fn client_state(phase: Phase) -> Option<ClientState> {
    match phase {
        Phase::Requested | Phase::Queued => Some(ClientState::Queued),
        Phase::Reserving | Phase::Draining | Phase::Releasing => Some(ClientState::FreeingMemory),
        Phase::Transferring
        | Phase::Verifying
        | Phase::Restoring
        | Phase::Loading
        | Phase::Booting
        | Phase::Activating => Some(ClientState::LoadingModel),
        Phase::Running => Some(ClientState::Generating),
        Phase::Retrying => Some(ClientState::Retrying),
        Phase::Completed | Phase::Failed | Phase::Cancelled | Phase::Revoked => None,
    }
}

/// The public progress of one operation (§3.10 line 654; GPU-W11 "memory, queue reason
/// and estimated wait").
///
/// `state` keeps one of today's five values; the phase, resource kind, source and queue
/// reason are additive detail beside it. It is written, never read: its message always
/// comes from the event it was built from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicProgress {
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<ClientState>,
    phase: Phase,
    kind: ResourceKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<DataSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    queue_reason: Option<QueueReason>,
    message: String,
    completed_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_bytes: Option<u64>,
    usable_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    eta: Option<EtaEstimate>,
    cancellation: CancellationBoundary,
}

impl PublicProgress {
    /// The public view of `update` in `phase`; its resource identity is left out.
    pub fn new(phase: Phase, update: &ProgressUpdate) -> Self {
        Self {
            state: client_state(phase),
            phase,
            kind: update.kind(),
            from: update.source(),
            queue_reason: update.queue_reason(),
            message: update.describe(phase),
            completed_bytes: update.completed_bytes(),
            total_bytes: update.total_bytes(),
            usable_bytes: update.committed_usable_bytes(),
            eta: update.eta(),
            cancellation: update.cancellation(),
        }
    }

    /// The public view of one received or snapshot event; its generations, provenance and
    /// resource identity are left out.
    pub fn from_event(event: &EventEnvelope<ProgressUpdate>) -> Self {
        Self::new(event.phase(), event.payload())
    }

    /// One of today's five client states, or `None` once the operation has ended.
    pub fn state(&self) -> Option<ClientState> {
        self.state
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn kind(&self) -> ResourceKind {
        self.kind
    }

    pub fn source(&self) -> Option<DataSource> {
        self.from
    }

    pub fn queue_reason(&self) -> Option<QueueReason> {
        self.queue_reason
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn completed_bytes(&self) -> u64 {
        self.completed_bytes
    }

    pub fn total_bytes(&self) -> Option<u64> {
        self.total_bytes
    }

    pub fn usable_bytes(&self) -> u64 {
        self.usable_bytes
    }

    pub fn eta(&self) -> Option<EtaEstimate> {
        self.eta
    }

    pub fn cancellation(&self) -> CancellationBoundary {
        self.cancellation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_client_state_keeps_its_written_name() {
        for state in ClientState::ALL {
            let json = serde_json::to_value(state).unwrap();
            assert_eq!(json, serde_json::Value::from(state.as_str()));
            assert_eq!(serde_json::from_value::<ClientState>(json).unwrap(), state);
        }
    }

    #[test]
    fn only_an_ended_operation_has_no_client_state() {
        for phase in Phase::ALL {
            assert_eq!(
                client_state(phase).is_none(),
                phase.is_terminal(),
                "{phase}"
            );
        }
    }
}
