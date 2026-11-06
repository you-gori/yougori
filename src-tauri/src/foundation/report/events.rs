//! The five clocks of S8 and the stage boundaries of GPU §2.1, as named intervals between
//! recorded events.
//!
//! Every duration comes from one monotonic clock ([`crate::foundation::ids::Clock`]). An
//! interval is refused when its end precedes its start or its two events come from
//! different clocks or different runs.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::error::ReportError;
use super::measured::{Measured, NotMeasuredReason};
use super::text::ClockId;
use crate::foundation::ids::{
    Clock, ExecutionId, MonotonicTime, OperationId, SandboxBootGeneration,
};

strict_tagged_enum! {
/// One observed event of a run (S8 "monotonic timestamps"; §2.1 boundaries).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventKind (tag = "kind", wire = EventKindWire, wire_name = "EventKindWire") {
    /// Serving: the server received and accepted the request (S8 "request accepted",
    /// §2.1 "request received"). The first-token clock starts here.
    RequestAccepted,
    /// Serving: the request left the queue and began executing; ends the queue wait.
    RequestDequeued,
    /// Serving: demand wake-up of a sleeping engine began.
    WakeStarted,
    WakeCompleted,
    /// Serving: demand loading of the model began.
    LoadStarted,
    LoadCompleted,
    /// FAST-01 restore time: restoring saved state (KV, checkpoint) began.
    RestoreStarted,
    RestoreCompleted,
    /// S10: a process recycle began, a visible recovery event with a latency and cost.
    RecycleStarted,
    RecycleCompleted,
    /// Serving: one token was emitted to the client. The first one is the first token.
    TokenEmitted,
    /// Serving: the response was complete.
    RequestCompleted,
    /// Switching: the scripted last output of model A.
    ModelAFinalOutput,
    /// VM provisioning: create was initiated for the intended guest.
    VmCreateInitiated {
        guest: ExecutionId,
        boot: SandboxBootGeneration,
    },
    /// VM provisioning: the API acknowledged the create. Not an interactive VM (S8).
    VmApiAcknowledged,
    /// VM provisioning: a command succeeded inside a guest.
    GuestCommandSucceeded {
        guest: ExecutionId,
        boot: SandboxBootGeneration,
    },
    /// First run: the fresh supported OS state, before any install.
    FreshStateReady,
    /// First run: the first model token reached the user.
    FirstModelToken,
    /// First run: the representative agent task completed.
    AgentTaskCompleted,
    /// Owner resource return: the first approved foreground signal, with the declared
    /// VRAM baseline to return to.
    ForegroundSignalApproved { vram_baseline_bytes: u64 },
    /// Owner resource return: new background work is denied.
    BackgroundWorkDenied,
    /// Owner resource return: background work was paused. A pause is not a GPU hand-back
    /// (S7) and ends no interval.
    BackgroundWorkPaused,
    /// Owner resource return: an observation of GPU memory in use.
    VramObserved { vram_bytes: u64 },
    /// Owner resource return: foreground work met its target.
    ForegroundTargetMet,
    /// §2.1 artifact preparation: a verified upstream artifact is available.
    UpstreamArtifactAvailable,
    /// §2.1 artifact preparation: the reusable representation is committed.
    RepresentationCommitted,
    /// §2.1 engine startup: the process was launched.
    ProcessLaunched,
    /// §2.1 engine startup: the runtime is initialised, independently of weights.
    RuntimeInitialized,
    /// §2.1 weight availability: placement was requested.
    PlacementRequested,
    /// §2.1 weight availability: every weight the placement needs is verified and usable.
    WeightsUsable,
    /// §2.1 ready latency: activation was requested.
    ActivationRequested,
    /// §2.1 ready latency: the engine can accept the declared request shape.
    EngineReadyForShape,
}
}

/// The name of an [`EventKind`] without its data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventName {
    RequestAccepted,
    RequestDequeued,
    WakeStarted,
    WakeCompleted,
    LoadStarted,
    LoadCompleted,
    RestoreStarted,
    RestoreCompleted,
    RecycleStarted,
    RecycleCompleted,
    TokenEmitted,
    RequestCompleted,
    ModelAFinalOutput,
    VmCreateInitiated,
    VmApiAcknowledged,
    GuestCommandSucceeded,
    FreshStateReady,
    FirstModelToken,
    AgentTaskCompleted,
    ForegroundSignalApproved,
    BackgroundWorkDenied,
    BackgroundWorkPaused,
    VramObserved,
    ForegroundTargetMet,
    UpstreamArtifactAvailable,
    RepresentationCommitted,
    ProcessLaunched,
    RuntimeInitialized,
    PlacementRequested,
    WeightsUsable,
    ActivationRequested,
    EngineReadyForShape,
}

impl EventKind {
    pub const fn name(&self) -> EventName {
        match self {
            Self::RequestAccepted => EventName::RequestAccepted,
            Self::RequestDequeued => EventName::RequestDequeued,
            Self::WakeStarted => EventName::WakeStarted,
            Self::WakeCompleted => EventName::WakeCompleted,
            Self::LoadStarted => EventName::LoadStarted,
            Self::LoadCompleted => EventName::LoadCompleted,
            Self::RestoreStarted => EventName::RestoreStarted,
            Self::RestoreCompleted => EventName::RestoreCompleted,
            Self::RecycleStarted => EventName::RecycleStarted,
            Self::RecycleCompleted => EventName::RecycleCompleted,
            Self::TokenEmitted => EventName::TokenEmitted,
            Self::RequestCompleted => EventName::RequestCompleted,
            Self::ModelAFinalOutput => EventName::ModelAFinalOutput,
            Self::VmCreateInitiated { .. } => EventName::VmCreateInitiated,
            Self::VmApiAcknowledged => EventName::VmApiAcknowledged,
            Self::GuestCommandSucceeded { .. } => EventName::GuestCommandSucceeded,
            Self::FreshStateReady => EventName::FreshStateReady,
            Self::FirstModelToken => EventName::FirstModelToken,
            Self::AgentTaskCompleted => EventName::AgentTaskCompleted,
            Self::ForegroundSignalApproved { .. } => EventName::ForegroundSignalApproved,
            Self::BackgroundWorkDenied => EventName::BackgroundWorkDenied,
            Self::BackgroundWorkPaused => EventName::BackgroundWorkPaused,
            Self::VramObserved { .. } => EventName::VramObserved,
            Self::ForegroundTargetMet => EventName::ForegroundTargetMet,
            Self::UpstreamArtifactAvailable => EventName::UpstreamArtifactAvailable,
            Self::RepresentationCommitted => EventName::RepresentationCommitted,
            Self::ProcessLaunched => EventName::ProcessLaunched,
            Self::RuntimeInitialized => EventName::RuntimeInitialized,
            Self::PlacementRequested => EventName::PlacementRequested,
            Self::WeightsUsable => EventName::WeightsUsable,
            Self::ActivationRequested => EventName::ActivationRequested,
            Self::EngineReadyForShape => EventName::EngineReadyForShape,
        }
    }
}

impl EventName {
    /// Every event name.
    pub const ALL: [Self; 32] = [
        Self::RequestAccepted,
        Self::RequestDequeued,
        Self::WakeStarted,
        Self::WakeCompleted,
        Self::LoadStarted,
        Self::LoadCompleted,
        Self::RestoreStarted,
        Self::RestoreCompleted,
        Self::RecycleStarted,
        Self::RecycleCompleted,
        Self::TokenEmitted,
        Self::RequestCompleted,
        Self::ModelAFinalOutput,
        Self::VmCreateInitiated,
        Self::VmApiAcknowledged,
        Self::GuestCommandSucceeded,
        Self::FreshStateReady,
        Self::FirstModelToken,
        Self::AgentTaskCompleted,
        Self::ForegroundSignalApproved,
        Self::BackgroundWorkDenied,
        Self::BackgroundWorkPaused,
        Self::VramObserved,
        Self::ForegroundTargetMet,
        Self::UpstreamArtifactAvailable,
        Self::RepresentationCommitted,
        Self::ProcessLaunched,
        Self::RuntimeInitialized,
        Self::PlacementRequested,
        Self::WeightsUsable,
        Self::ActivationRequested,
        Self::EngineReadyForShape,
    ];

    /// Events one run may record more than once; every other event is unique per run.
    pub const fn is_repeatable(self) -> bool {
        matches!(
            self,
            Self::TokenEmitted
                | Self::GuestCommandSucceeded
                | Self::VramObserved
                | Self::BackgroundWorkPaused
        )
    }

    /// The serialized name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestAccepted => "request_accepted",
            Self::RequestDequeued => "request_dequeued",
            Self::WakeStarted => "wake_started",
            Self::WakeCompleted => "wake_completed",
            Self::LoadStarted => "load_started",
            Self::LoadCompleted => "load_completed",
            Self::RestoreStarted => "restore_started",
            Self::RestoreCompleted => "restore_completed",
            Self::RecycleStarted => "recycle_started",
            Self::RecycleCompleted => "recycle_completed",
            Self::TokenEmitted => "token_emitted",
            Self::RequestCompleted => "request_completed",
            Self::ModelAFinalOutput => "model_a_final_output",
            Self::VmCreateInitiated => "vm_create_initiated",
            Self::VmApiAcknowledged => "vm_api_acknowledged",
            Self::GuestCommandSucceeded => "guest_command_succeeded",
            Self::FreshStateReady => "fresh_state_ready",
            Self::FirstModelToken => "first_model_token",
            Self::AgentTaskCompleted => "agent_task_completed",
            Self::ForegroundSignalApproved => "foreground_signal_approved",
            Self::BackgroundWorkDenied => "background_work_denied",
            Self::BackgroundWorkPaused => "background_work_paused",
            Self::VramObserved => "vram_observed",
            Self::ForegroundTargetMet => "foreground_target_met",
            Self::UpstreamArtifactAvailable => "upstream_artifact_available",
            Self::RepresentationCommitted => "representation_committed",
            Self::ProcessLaunched => "process_launched",
            Self::RuntimeInitialized => "runtime_initialized",
            Self::PlacementRequested => "placement_requested",
            Self::WeightsUsable => "weights_usable",
            Self::ActivationRequested => "activation_requested",
            Self::EngineReadyForShape => "engine_ready_for_shape",
        }
    }
}

/// An event stamped by one clock in one run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedEvent {
    /// The attempt this event belongs to.
    pub operation: OperationId,
    pub clock: ClockId,
    /// Order of recording on `clock`, strictly increasing.
    pub sequence: u64,
    /// Nanoseconds on `clock`; comparable only with times from the same clock.
    pub at_nanos: MonotonicTime,
    pub event: EventKind,
}

/// Records the events of one attempt, stamping each with one monotonic clock (S8, §2.1).
/// A run observed on two clocks, such as host and guest, uses one recorder per clock.
pub struct EventRecorder<C> {
    operation: OperationId,
    clock_id: ClockId,
    clock: C,
    next_sequence: u64,
    events: Vec<RecordedEvent>,
}

impl<C: Clock> EventRecorder<C> {
    /// Records events of `operation`, stamped by `clock` under the name `clock_id`.
    pub fn new(operation: OperationId, clock_id: ClockId, clock: C) -> Self {
        Self {
            operation,
            clock_id,
            clock,
            next_sequence: 0,
            events: Vec::new(),
        }
    }

    /// Stamps `event` with the clock's current time and returns that time.
    pub fn record(&mut self, event: EventKind) -> MonotonicTime {
        let at_nanos = self.clock.now();
        self.events.push(RecordedEvent {
            operation: self.operation.clone(),
            clock: self.clock_id.clone(),
            sequence: self.next_sequence,
            at_nanos,
            event,
        });
        self.next_sequence = self.next_sequence.saturating_add(1);
        at_nanos
    }

    pub fn events(&self) -> &[RecordedEvent] {
        &self.events
    }

    pub fn into_events(self) -> Vec<RecordedEvent> {
        self.events
    }
}

/// Which clock of S8, or which §2.1 stage, an interval belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockFamily {
    Serving,
    Switching,
    VmProvisioning,
    FirstRun,
    OwnerResourceReturn,
    /// A §2.1 measurement boundary outside the five clocks.
    Stage,
}

/// A named interval between two recorded events (S8 clocks, §2.1 boundaries).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntervalKind {
    /// S8 serving: queue wait, recorded separately.
    QueueWait,
    /// S8 serving and §2.1 TTFT: request accepted to first emitted token, including
    /// queueing and any demand wake or load (§1.3).
    TimeToFirstToken,
    /// Serving: request accepted to response complete.
    RequestLatency,
    DemandWake,
    DemandLoad,
    /// FAST-01 restore time.
    Restore,
    /// S10 recycle latency.
    Recycle,
    /// S8 switching: last output of model A to the accepted request for B; must cover
    /// the disclosed controlled gap.
    SwitchGap,
    /// S8 switching: last output of model A to first output of B.
    SwitchLastOutputToFirstOutput,
    /// S8 VM provisioning: create initiated to API acknowledgement, recorded separately.
    VmApiAcknowledgement,
    /// S8 VM provisioning: create initiated to the first successful command inside the
    /// intended guest.
    VmFirstGuestCommand,
    FirstRunToFirstToken,
    FirstRunToAgentTask,
    /// S8 owner resource return: signal to denial of new background work.
    OwnerReturnDenial,
    /// S8 owner resource return: signal to VRAM at its declared baseline.
    OwnerReturnVram,
    /// S8 owner resource return: signal to foreground work meeting its target.
    OwnerReturnForeground,
    /// §2.1 artifact preparation.
    ArtifactPreparation,
    /// §2.1 engine startup.
    EngineStartup,
    /// §2.1 weight availability.
    WeightAvailability,
    /// §2.1 ready latency.
    ReadyLatency,
}

impl IntervalKind {
    /// Every named interval.
    pub const ALL: [Self; 20] = [
        Self::QueueWait,
        Self::TimeToFirstToken,
        Self::RequestLatency,
        Self::DemandWake,
        Self::DemandLoad,
        Self::Restore,
        Self::Recycle,
        Self::SwitchGap,
        Self::SwitchLastOutputToFirstOutput,
        Self::VmApiAcknowledgement,
        Self::VmFirstGuestCommand,
        Self::FirstRunToFirstToken,
        Self::FirstRunToAgentTask,
        Self::OwnerReturnDenial,
        Self::OwnerReturnVram,
        Self::OwnerReturnForeground,
        Self::ArtifactPreparation,
        Self::EngineStartup,
        Self::WeightAvailability,
        Self::ReadyLatency,
    ];

    /// The event that starts the interval.
    pub const fn start(self) -> EventName {
        match self {
            Self::QueueWait | Self::TimeToFirstToken | Self::RequestLatency => {
                EventName::RequestAccepted
            }
            Self::DemandWake => EventName::WakeStarted,
            Self::DemandLoad => EventName::LoadStarted,
            Self::Restore => EventName::RestoreStarted,
            Self::Recycle => EventName::RecycleStarted,
            Self::SwitchGap | Self::SwitchLastOutputToFirstOutput => EventName::ModelAFinalOutput,
            Self::VmApiAcknowledgement | Self::VmFirstGuestCommand => EventName::VmCreateInitiated,
            Self::FirstRunToFirstToken | Self::FirstRunToAgentTask => EventName::FreshStateReady,
            Self::OwnerReturnDenial | Self::OwnerReturnVram | Self::OwnerReturnForeground => {
                EventName::ForegroundSignalApproved
            }
            Self::ArtifactPreparation => EventName::UpstreamArtifactAvailable,
            Self::EngineStartup => EventName::ProcessLaunched,
            Self::WeightAvailability => EventName::PlacementRequested,
            Self::ReadyLatency => EventName::ActivationRequested,
        }
    }

    /// The event that ends the interval. A repeatable end event ends it at its first
    /// matching occurrence.
    pub const fn end(self) -> EventName {
        match self {
            Self::QueueWait => EventName::RequestDequeued,
            Self::TimeToFirstToken | Self::SwitchLastOutputToFirstOutput => EventName::TokenEmitted,
            Self::RequestLatency => EventName::RequestCompleted,
            Self::DemandWake => EventName::WakeCompleted,
            Self::DemandLoad => EventName::LoadCompleted,
            Self::Restore => EventName::RestoreCompleted,
            Self::Recycle => EventName::RecycleCompleted,
            Self::SwitchGap => EventName::RequestAccepted,
            Self::VmApiAcknowledgement => EventName::VmApiAcknowledged,
            Self::VmFirstGuestCommand => EventName::GuestCommandSucceeded,
            Self::FirstRunToFirstToken => EventName::FirstModelToken,
            Self::FirstRunToAgentTask => EventName::AgentTaskCompleted,
            Self::OwnerReturnDenial => EventName::BackgroundWorkDenied,
            Self::OwnerReturnVram => EventName::VramObserved,
            Self::OwnerReturnForeground => EventName::ForegroundTargetMet,
            Self::ArtifactPreparation => EventName::RepresentationCommitted,
            Self::EngineStartup => EventName::RuntimeInitialized,
            Self::WeightAvailability => EventName::WeightsUsable,
            Self::ReadyLatency => EventName::EngineReadyForShape,
        }
    }

    pub const fn family(self) -> ClockFamily {
        match self {
            Self::QueueWait
            | Self::TimeToFirstToken
            | Self::RequestLatency
            | Self::DemandWake
            | Self::DemandLoad => ClockFamily::Serving,
            Self::SwitchGap | Self::SwitchLastOutputToFirstOutput => ClockFamily::Switching,
            Self::VmApiAcknowledgement | Self::VmFirstGuestCommand => ClockFamily::VmProvisioning,
            Self::FirstRunToFirstToken | Self::FirstRunToAgentTask => ClockFamily::FirstRun,
            Self::OwnerReturnDenial | Self::OwnerReturnVram | Self::OwnerReturnForeground => {
                ClockFamily::OwnerResourceReturn
            }
            Self::Restore
            | Self::Recycle
            | Self::ArtifactPreparation
            | Self::EngineStartup
            | Self::WeightAvailability
            | Self::ReadyLatency => ClockFamily::Stage,
        }
    }

    /// The serialized name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QueueWait => "queue_wait",
            Self::TimeToFirstToken => "time_to_first_token",
            Self::RequestLatency => "request_latency",
            Self::DemandWake => "demand_wake",
            Self::DemandLoad => "demand_load",
            Self::Restore => "restore",
            Self::Recycle => "recycle",
            Self::SwitchGap => "switch_gap",
            Self::SwitchLastOutputToFirstOutput => "switch_last_output_to_first_output",
            Self::VmApiAcknowledgement => "vm_api_acknowledgement",
            Self::VmFirstGuestCommand => "vm_first_guest_command",
            Self::FirstRunToFirstToken => "first_run_to_first_token",
            Self::FirstRunToAgentTask => "first_run_to_agent_task",
            Self::OwnerReturnDenial => "owner_return_denial",
            Self::OwnerReturnVram => "owner_return_vram",
            Self::OwnerReturnForeground => "owner_return_foreground",
            Self::ArtifactPreparation => "artifact_preparation",
            Self::EngineStartup => "engine_startup",
            Self::WeightAvailability => "weight_availability",
            Self::ReadyLatency => "ready_latency",
        }
    }

    /// Whether `end` may close an interval that `start` opened: the intended guest for
    /// VM provisioning, VRAM at or below the declared baseline for owner return.
    fn end_matches(self, start: &EventKind, end: &EventKind) -> bool {
        match (start, end) {
            (
                EventKind::VmCreateInitiated { guest, boot },
                EventKind::GuestCommandSucceeded {
                    guest: ended_guest,
                    boot: ended_boot,
                },
            ) => guest == ended_guest && boot == ended_boot,
            (
                EventKind::ForegroundSignalApproved {
                    vram_baseline_bytes,
                },
                EventKind::VramObserved { vram_bytes },
            ) => vram_bytes <= vram_baseline_bytes,
            _ => true,
        }
    }
}

/// A duration between two events of one run on one clock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MeasuredInterval {
    kind: IntervalKind,
    clock: ClockId,
    start_nanos: MonotonicTime,
    end_nanos: MonotonicTime,
    elapsed_nanos: u64,
}

impl MeasuredInterval {
    /// Measures `kind` from `start` to `end`.
    ///
    /// Refuses events of the wrong kind, events from different runs or clocks, an end
    /// that precedes its start (in time or in recording order), a guest command outside
    /// the intended guest, and a VRAM observation above the declared baseline.
    pub fn between(
        kind: IntervalKind,
        start: &RecordedEvent,
        end: &RecordedEvent,
    ) -> Result<Self, ReportError> {
        for (expected, event) in [(kind.start(), start), (kind.end(), end)] {
            let found = event.event.name();
            if found != expected {
                return Err(ReportError::WrongEvent {
                    interval: kind,
                    expected,
                    found,
                });
            }
        }
        if start.operation != end.operation {
            return Err(ReportError::DifferentRuns { interval: kind });
        }
        if start.clock != end.clock {
            return Err(ReportError::DifferentClocks { interval: kind });
        }
        let elapsed = end
            .at_nanos
            .checked_duration_since(start.at_nanos)
            .filter(|_| end.sequence > start.sequence)
            .ok_or(ReportError::EndBeforeStart { interval: kind })?;
        if !kind.end_matches(&start.event, &end.event) {
            return Err(match end.event {
                EventKind::VramObserved { .. } => ReportError::VramAboveBaseline,
                _ => ReportError::NotIntendedGuest,
            });
        }
        let elapsed_nanos =
            u64::try_from(elapsed.as_nanos()).map_err(|_| ReportError::DurationOverflow)?;
        Ok(Self {
            kind,
            clock: start.clock.clone(),
            start_nanos: start.at_nanos,
            end_nanos: end.at_nanos,
            elapsed_nanos,
        })
    }

    pub fn kind(&self) -> IntervalKind {
        self.kind
    }

    pub fn clock(&self) -> &ClockId {
        &self.clock
    }

    pub fn start(&self) -> MonotonicTime {
        self.start_nanos
    }

    pub fn end(&self) -> MonotonicTime {
        self.end_nanos
    }

    pub fn elapsed_nanos(&self) -> u64 {
        self.elapsed_nanos
    }

    pub fn elapsed(&self) -> Duration {
        Duration::from_nanos(self.elapsed_nanos)
    }

    pub fn seconds(&self) -> f64 {
        self.elapsed().as_secs_f64()
    }

    fn contains(&self, other: &Self) -> bool {
        self.clock == other.clock
            && other.start_nanos >= self.start_nanos
            && other.end_nanos <= self.end_nanos
    }
}

/// How model B became ready in a switch (S8: "Distinguish hot dispatch, wake, warm
/// reload and cold process start").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchMode {
    HotDispatch,
    Wake,
    WarmReload,
    ColdProcessStart,
}

/// How the owner's GPU came back (S7 owner GPU return; BENCH-12 records VM device cases
/// separately).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReturnPath {
    /// The runtime released the allocation by its real mechanism.
    RuntimeRelease,
    /// A VM with an exclusively assigned GPU: termination, device reset and reassignment.
    VmDeviceReset,
}

/// S8 serving clock: request accepted to first emitted token, then per-token latency and
/// output rate, with queue wait recorded separately.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ServingClock {
    /// Includes queue wait and any demand wake or load (§1.3).
    pub time_to_first_token: MeasuredInterval,
    pub queue_wait: MeasuredInterval,
    pub demand_wake: Measured<MeasuredInterval>,
    pub demand_load: Measured<MeasuredInterval>,
    pub request_latency: Measured<MeasuredInterval>,
    /// §2.1 inter-token latency: consecutive emitted tokens, including pauses.
    pub inter_token_latencies_nanos: Vec<u64>,
    pub emitted_tokens: u64,
    /// Decode per user: (tokens − 1) over first-to-last token time.
    pub decode_tokens_per_second: Measured<f64>,
}

/// S8 switching clock.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SwitchingClock {
    pub mode: SwitchMode,
    /// The scripted gap between A's last output and B's request, disclosed (S8).
    pub declared_controlled_gap_nanos: u64,
    pub measured_gap: MeasuredInterval,
    /// Last output of A to first output of B.
    pub last_output_to_first_output: MeasuredInterval,
    /// B's request on the serving clock: B accepted to first B token.
    pub request: ServingClock,
}

/// S8 VM provisioning clock.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct VmProvisioningClock {
    pub guest: ExecutionId,
    pub boot: SandboxBootGeneration,
    /// Create initiated to the first successful command inside the intended guest.
    pub first_guest_command: MeasuredInterval,
    /// Recorded separately; a fast acknowledgement is not an interactive VM (S8).
    pub api_acknowledgement: Measured<MeasuredInterval>,
}

/// S8 first-run clock.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FirstRunClock {
    pub to_first_model_token: MeasuredInterval,
    pub to_agent_task: MeasuredInterval,
}

/// S8 owner resource return: three separately measured events.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct OwnerReturnClock {
    pub path: ReturnPath,
    pub declared_vram_baseline_bytes: u64,
    pub denial_of_new_background_work: MeasuredInterval,
    pub vram_at_declared_baseline: MeasuredInterval,
    pub foreground_target_met: MeasuredInterval,
}

/// The §2.1 measurement boundaries a run recorded.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct StageReading {
    pub artifact_preparation: Measured<MeasuredInterval>,
    pub engine_startup: Measured<MeasuredInterval>,
    pub weight_availability: Measured<MeasuredInterval>,
    pub ready_latency: Measured<MeasuredInterval>,
    pub restore: Measured<MeasuredInterval>,
    /// S10: a recycle is a visible recovery event with its own latency.
    pub recycle: Measured<MeasuredInterval>,
    pub time_to_first_token: Measured<MeasuredInterval>,
    pub inter_token_latencies_nanos: Vec<u64>,
}

/// The validated events of one run.
#[derive(Clone, Copy, Debug)]
pub struct Timeline<'a> {
    events: &'a [RecordedEvent],
}

impl<'a> Timeline<'a> {
    /// Checks that every event belongs to one run, that each clock's sequence numbers
    /// rise and its times never fall, and that unique events occur at most once.
    pub fn new(events: &'a [RecordedEvent]) -> Result<Self, ReportError> {
        if let Some(first) = events.first() {
            if events
                .iter()
                .any(|event| event.operation != first.operation)
            {
                return Err(ReportError::EventFromAnotherRun);
            }
        }
        let mut last: BTreeMap<&ClockId, (u64, MonotonicTime)> = BTreeMap::new();
        for event in events {
            if let Some((sequence, at)) = last.get(&event.clock) {
                if event.sequence <= *sequence {
                    return Err(ReportError::SequenceNotIncreasing);
                }
                if event.at_nanos < *at {
                    return Err(ReportError::ClockWentBackwards);
                }
            }
            last.insert(&event.clock, (event.sequence, event.at_nanos));
        }
        let mut seen = BTreeSet::new();
        for event in events {
            let name = event.event.name();
            if !name.is_repeatable() && !seen.insert(name) {
                return Err(ReportError::DuplicateEvent { event: name });
            }
        }
        Ok(Self { events })
    }

    pub fn events(&self) -> &'a [RecordedEvent] {
        self.events
    }

    /// Whether the run recorded `name` at least once.
    pub fn contains(&self, name: EventName) -> bool {
        self.events.iter().any(|event| event.event.name() == name)
    }

    fn first(&self, name: EventName) -> Option<&'a RecordedEvent> {
        self.events.iter().find(|event| event.event.name() == name)
    }

    fn end_for(&self, kind: IntervalKind, start: &RecordedEvent) -> Option<&'a RecordedEvent> {
        self.events.iter().find(|event| {
            event.event.name() == kind.end() && kind.end_matches(&start.event, &event.event)
        })
    }

    /// Measures `kind`; both of its events must be present.
    pub fn interval(&self, kind: IntervalKind) -> Result<MeasuredInterval, ReportError> {
        let start = self.first(kind.start()).ok_or(ReportError::MissingEvent {
            event: kind.start(),
        })?;
        let end = self
            .end_for(kind, start)
            .ok_or(ReportError::MissingEvent { event: kind.end() })?;
        MeasuredInterval::between(kind, start, end)
    }

    /// Measures `kind` when the run reached it: "not applicable" without its start
    /// event, "the run ended first" without its end event. An end without its start is
    /// refused, except for the switching intervals, whose end events are ordinary
    /// serving events.
    pub fn optional_interval(
        &self,
        kind: IntervalKind,
    ) -> Result<Measured<MeasuredInterval>, ReportError> {
        match self.first(kind.start()) {
            None if kind.family() != ClockFamily::Switching && self.contains(kind.end()) => {
                Err(ReportError::MissingEvent {
                    event: kind.start(),
                })
            }
            None => Ok(Measured::not_measured(NotMeasuredReason::NotApplicable)),
            Some(start) => match self.end_for(kind, start) {
                None => Ok(Measured::not_measured(NotMeasuredReason::RunEndedFirst)),
                Some(end) => MeasuredInterval::between(kind, start, end).map(Measured::measured),
            },
        }
    }

    fn tokens(&self) -> impl Iterator<Item = &'a RecordedEvent> {
        self.events
            .iter()
            .filter(|event| event.event.name() == EventName::TokenEmitted)
    }

    /// The number of emitted-token events.
    pub fn emitted_tokens(&self) -> u64 {
        self.tokens().fold(0, |count, _| count.saturating_add(1))
    }

    /// §2.1 inter-token latency: consecutive emitted tokens, including pauses. All
    /// tokens must come from one clock.
    pub fn inter_token_latencies_nanos(&self) -> Result<Vec<u64>, ReportError> {
        let tokens: Vec<&RecordedEvent> = self.tokens().collect();
        let mut gaps = Vec::with_capacity(tokens.len().saturating_sub(1));
        for pair in tokens.windows(2) {
            if let [earlier, later] = pair {
                if earlier.clock != later.clock {
                    return Err(ReportError::DifferentClocks {
                        interval: IntervalKind::TimeToFirstToken,
                    });
                }
                let gap = later
                    .at_nanos
                    .checked_duration_since(earlier.at_nanos)
                    .ok_or(ReportError::ClockWentBackwards)?;
                gaps.push(
                    u64::try_from(gap.as_nanos()).map_err(|_| ReportError::DurationOverflow)?,
                );
            }
        }
        Ok(gaps)
    }

    /// The S8 serving clock. For a demand request (`demand`: the model was not ready to
    /// serve on arrival) the wake or load must lie inside the first-token clock; a
    /// request declared ready must show no demand work.
    pub fn serving(&self, demand: bool) -> Result<ServingClock, ReportError> {
        let time_to_first_token = self.interval(IntervalKind::TimeToFirstToken)?;
        let queue_wait = self.interval(IntervalKind::QueueWait)?;
        let demand_wake = self.optional_interval(IntervalKind::DemandWake)?;
        let demand_load = self.optional_interval(IntervalKind::DemandLoad)?;
        let demand_started =
            self.contains(EventName::WakeStarted) || self.contains(EventName::LoadStarted);
        if demand {
            if !demand_started {
                return Err(ReportError::DemandWorkOutsideFirstTokenClock);
            }
            for work in [&demand_wake, &demand_load] {
                match work {
                    Measured::Measured { value } if time_to_first_token.contains(value) => {}
                    Measured::NotMeasured {
                        reason: NotMeasuredReason::NotApplicable,
                    } => {}
                    _ => return Err(ReportError::DemandWorkOutsideFirstTokenClock),
                }
            }
        } else if demand_started {
            return Err(ReportError::UndeclaredDemandWork);
        }
        let request_latency = self.optional_interval(IntervalKind::RequestLatency)?;
        let inter_token_latencies_nanos = self.inter_token_latencies_nanos()?;
        let emitted_tokens = self.emitted_tokens();
        let decode_nanos: u64 = inter_token_latencies_nanos
            .iter()
            .fold(0u64, |total, gap| total.saturating_add(*gap));
        let decode_tokens_per_second = if emitted_tokens < 2 {
            Measured::not_measured(NotMeasuredReason::InsufficientTokens)
        } else if decode_nanos == 0 {
            Measured::not_measured(NotMeasuredReason::ZeroElapsedTime)
        } else {
            Measured::measured(
                (emitted_tokens - 1) as f64 / Duration::from_nanos(decode_nanos).as_secs_f64(),
            )
        };
        Ok(ServingClock {
            time_to_first_token,
            queue_wait,
            demand_wake,
            demand_load,
            request_latency,
            inter_token_latencies_nanos,
            emitted_tokens,
            decode_tokens_per_second,
        })
    }

    /// The S8 switching clock: B's request on the serving clock, the last output of A to
    /// the first output of B, and the disclosed controlled gap, which the measured gap
    /// must cover. The mode must match the demand work observed.
    pub fn switching(
        &self,
        mode: SwitchMode,
        controlled_gap_nanos: u64,
        demand: bool,
    ) -> Result<SwitchingClock, ReportError> {
        let request = self.serving(demand)?;
        let mode_matches = match mode {
            SwitchMode::HotDispatch => !demand,
            SwitchMode::Wake => demand && request.demand_wake.is_measured(),
            SwitchMode::WarmReload | SwitchMode::ColdProcessStart => {
                demand && request.demand_load.is_measured()
            }
        };
        if !mode_matches {
            return Err(ReportError::SwitchModeMismatch);
        }
        let measured_gap = self.interval(IntervalKind::SwitchGap)?;
        if measured_gap.elapsed_nanos() < controlled_gap_nanos {
            return Err(ReportError::ControlledGapNotHonoured {
                declared_nanos: controlled_gap_nanos,
                measured_nanos: measured_gap.elapsed_nanos(),
            });
        }
        let last_output_to_first_output =
            self.interval(IntervalKind::SwitchLastOutputToFirstOutput)?;
        Ok(SwitchingClock {
            mode,
            declared_controlled_gap_nanos: controlled_gap_nanos,
            measured_gap,
            last_output_to_first_output,
            request,
        })
    }

    /// The S8 VM provisioning clock. Ends only at a successful command inside the guest
    /// named at create; an API acknowledgement never ends it.
    pub fn vm_provisioning(&self) -> Result<VmProvisioningClock, ReportError> {
        let (guest, boot) = match self
            .first(EventName::VmCreateInitiated)
            .map(|event| &event.event)
        {
            Some(EventKind::VmCreateInitiated { guest, boot }) => (guest.clone(), *boot),
            _ => {
                return Err(ReportError::MissingEvent {
                    event: EventName::VmCreateInitiated,
                })
            }
        };
        Ok(VmProvisioningClock {
            guest,
            boot,
            first_guest_command: self.interval(IntervalKind::VmFirstGuestCommand)?,
            api_acknowledgement: self.optional_interval(IntervalKind::VmApiAcknowledgement)?,
        })
    }

    /// The S8 first-run clock.
    pub fn first_run(&self) -> Result<FirstRunClock, ReportError> {
        Ok(FirstRunClock {
            to_first_model_token: self.interval(IntervalKind::FirstRunToFirstToken)?,
            to_agent_task: self.interval(IntervalKind::FirstRunToAgentTask)?,
        })
    }

    /// The S8 owner resource return clock: all three events must be measured.
    pub fn owner_return(&self, path: ReturnPath) -> Result<OwnerReturnClock, ReportError> {
        let declared_vram_baseline_bytes = match self
            .first(EventName::ForegroundSignalApproved)
            .map(|event| &event.event)
        {
            Some(EventKind::ForegroundSignalApproved {
                vram_baseline_bytes,
            }) => *vram_baseline_bytes,
            _ => {
                return Err(ReportError::MissingEvent {
                    event: EventName::ForegroundSignalApproved,
                })
            }
        };
        Ok(OwnerReturnClock {
            path,
            declared_vram_baseline_bytes,
            denial_of_new_background_work: self.interval(IntervalKind::OwnerReturnDenial)?,
            vram_at_declared_baseline: self.interval(IntervalKind::OwnerReturnVram)?,
            foreground_target_met: self.interval(IntervalKind::OwnerReturnForeground)?,
        })
    }

    /// The §2.1 boundaries present in this run.
    pub fn stages(&self) -> Result<StageReading, ReportError> {
        Ok(StageReading {
            artifact_preparation: self.optional_interval(IntervalKind::ArtifactPreparation)?,
            engine_startup: self.optional_interval(IntervalKind::EngineStartup)?,
            weight_availability: self.optional_interval(IntervalKind::WeightAvailability)?,
            ready_latency: self.optional_interval(IntervalKind::ReadyLatency)?,
            restore: self.optional_interval(IntervalKind::Restore)?,
            recycle: self.optional_interval(IntervalKind::Recycle)?,
            time_to_first_token: self.optional_interval(IntervalKind::TimeToFirstToken)?,
            inter_token_latencies_nanos: self.inter_token_latencies_nanos()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::ManualClock;
    use crate::foundation::report::text::Label;

    fn op(value: &str) -> OperationId {
        OperationId::new(value).unwrap()
    }

    fn clock_id(value: &str) -> ClockId {
        ClockId::new(Label::new(value).unwrap())
    }

    fn guest(value: &str) -> ExecutionId {
        ExecutionId::new(value).unwrap()
    }

    /// Records `steps` (milliseconds after the previous event, event) on a manual clock.
    fn record(operation: &str, clock: &str, steps: Vec<(u64, EventKind)>) -> Vec<RecordedEvent> {
        let manual = ManualClock::new(MonotonicTime::from_nanos(1_000_000_000));
        let mut recorder = EventRecorder::new(op(operation), clock_id(clock), &manual);
        for (after_millis, event) in steps {
            manual.advance(Duration::from_millis(after_millis));
            recorder.record(event);
        }
        recorder.into_events()
    }

    fn millis(interval: &MeasuredInterval) -> u64 {
        interval.elapsed_nanos() / 1_000_000
    }

    #[test]
    fn serialized_names_match_as_str() {
        for kind in IntervalKind::ALL {
            assert_eq!(
                serde_json::to_string(&kind).unwrap(),
                format!("\"{}\"", kind.as_str())
            );
        }
        for name in EventName::ALL {
            assert_eq!(
                serde_json::to_string(&name).unwrap(),
                format!("\"{}\"", name.as_str())
            );
        }
        let events = record(
            "op-1",
            "host",
            vec![
                (0, EventKind::RequestAccepted),
                (0, EventKind::VramObserved { vram_bytes: 1 }),
            ],
        );
        for event in &events {
            let json = serde_json::to_value(&event.event).unwrap();
            assert_eq!(json["kind"], event.event.name().as_str());
        }
        // Unknown fields in an event are refused.
        assert!(serde_json::from_str::<EventKind>(
            r#"{"kind":"request_accepted","prompt":"secret"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<EventKind>(
            r#"{"kind":"vram_observed","vram_bytes":1,"path":"C:/x"}"#
        )
        .is_err());
    }

    #[test]
    fn hot_serving_clock_measures_queue_first_token_and_decode() {
        let events = record(
            "op-1",
            "host",
            vec![
                (0, EventKind::RequestAccepted),
                (5, EventKind::RequestDequeued),
                (45, EventKind::TokenEmitted),
                (20, EventKind::TokenEmitted),
                (30, EventKind::TokenEmitted),
                (1, EventKind::RequestCompleted),
            ],
        );
        let timeline = Timeline::new(&events).unwrap();
        let clock = timeline.serving(false).unwrap();
        assert_eq!(millis(&clock.queue_wait), 5);
        // The first-token clock includes the queue wait (§1.3).
        assert_eq!(millis(&clock.time_to_first_token), 50);
        assert_eq!(
            clock.inter_token_latencies_nanos,
            vec![20_000_000, 30_000_000]
        );
        assert_eq!(clock.emitted_tokens, 3);
        // Two decode steps in 50 ms.
        assert_eq!(clock.decode_tokens_per_second, Measured::measured(40.0));
        assert_eq!(clock.request_latency.value().map(millis), Some(101));
        assert_eq!(
            clock.demand_wake,
            Measured::not_measured(NotMeasuredReason::NotApplicable)
        );
    }

    #[test]
    fn demand_wake_counts_inside_the_first_token_clock() {
        let events = record(
            "op-1",
            "host",
            vec![
                (0, EventKind::RequestAccepted),
                (1, EventKind::WakeStarted),
                (1, EventKind::RequestDequeued),
                (300, EventKind::WakeCompleted),
                (40, EventKind::TokenEmitted),
                (1, EventKind::RequestCompleted),
            ],
        );
        let clock = Timeline::new(&events).unwrap().serving(true).unwrap();
        assert_eq!(millis(&clock.time_to_first_token), 342);
        assert_eq!(clock.demand_wake.value().map(millis), Some(301));
        assert_eq!(
            clock.decode_tokens_per_second,
            Measured::not_measured(NotMeasuredReason::InsufficientTokens)
        );
    }

    #[test]
    fn demand_work_outside_the_first_token_clock_is_refused() {
        // The engine woke before the request was accepted: the clock would hide it.
        let woke_first = record(
            "op-1",
            "host",
            vec![
                (0, EventKind::WakeStarted),
                (300, EventKind::WakeCompleted),
                (1, EventKind::RequestAccepted),
                (1, EventKind::RequestDequeued),
                (40, EventKind::TokenEmitted),
            ],
        );
        assert_eq!(
            Timeline::new(&woke_first)
                .unwrap()
                .serving(true)
                .unwrap_err(),
            ReportError::DemandWorkOutsideFirstTokenClock
        );
        // A demand request that shows no wake or load at all.
        let no_work = record(
            "op-1",
            "host",
            vec![
                (0, EventKind::RequestAccepted),
                (1, EventKind::RequestDequeued),
                (40, EventKind::TokenEmitted),
            ],
        );
        assert_eq!(
            Timeline::new(&no_work).unwrap().serving(true).unwrap_err(),
            ReportError::DemandWorkOutsideFirstTokenClock
        );
        // A request declared ready that loaded on demand.
        let undeclared = record(
            "op-1",
            "host",
            vec![
                (0, EventKind::RequestAccepted),
                (1, EventKind::LoadStarted),
                (1, EventKind::RequestDequeued),
                (300, EventKind::LoadCompleted),
                (40, EventKind::TokenEmitted),
            ],
        );
        assert_eq!(
            Timeline::new(&undeclared)
                .unwrap()
                .serving(false)
                .unwrap_err(),
            ReportError::UndeclaredDemandWork
        );
    }

    #[test]
    fn intervals_refuse_reversed_mixed_clock_and_cross_run_events() {
        let events = record(
            "op-1",
            "host",
            vec![
                (0, EventKind::RequestAccepted),
                (10, EventKind::RequestDequeued),
            ],
        );
        let (accepted, dequeued) = (&events[0], &events[1]);
        assert_eq!(
            MeasuredInterval::between(IntervalKind::QueueWait, accepted, dequeued)
                .unwrap()
                .elapsed_nanos(),
            10_000_000
        );

        // End before start.
        let mut reversed = dequeued.clone();
        reversed.at_nanos = MonotonicTime::from_nanos(accepted.at_nanos.as_nanos() - 1);
        assert_eq!(
            MeasuredInterval::between(IntervalKind::QueueWait, accepted, &reversed),
            Err(ReportError::EndBeforeStart {
                interval: IntervalKind::QueueWait
            })
        );
        // Same time but recorded before the start.
        let mut earlier_sequence = dequeued.clone();
        earlier_sequence.at_nanos = accepted.at_nanos;
        earlier_sequence.sequence = 0;
        let mut later_start = accepted.clone();
        later_start.sequence = 1;
        assert_eq!(
            MeasuredInterval::between(IntervalKind::QueueWait, &later_start, &earlier_sequence),
            Err(ReportError::EndBeforeStart {
                interval: IntervalKind::QueueWait
            })
        );

        // A guest clock cannot be subtracted from a host clock.
        let mut guest_clock = dequeued.clone();
        guest_clock.clock = clock_id("guest");
        assert_eq!(
            MeasuredInterval::between(IntervalKind::QueueWait, accepted, &guest_clock),
            Err(ReportError::DifferentClocks {
                interval: IntervalKind::QueueWait
            })
        );

        // Events of another attempt.
        let mut other_run = dequeued.clone();
        other_run.operation = op("op-2");
        assert_eq!(
            MeasuredInterval::between(IntervalKind::QueueWait, accepted, &other_run),
            Err(ReportError::DifferentRuns {
                interval: IntervalKind::QueueWait
            })
        );

        // The wrong event kinds.
        assert_eq!(
            MeasuredInterval::between(IntervalKind::QueueWait, dequeued, accepted),
            Err(ReportError::WrongEvent {
                interval: IntervalKind::QueueWait,
                expected: EventName::RequestAccepted,
                found: EventName::RequestDequeued,
            })
        );
    }

    #[test]
    fn timelines_refuse_inconsistent_logs() {
        let mut events = record(
            "op-1",
            "host",
            vec![
                (0, EventKind::RequestAccepted),
                (10, EventKind::RequestDequeued),
            ],
        );
        let mut mixed = events.clone();
        mixed[1].operation = op("op-2");
        assert_eq!(
            Timeline::new(&mixed).unwrap_err(),
            ReportError::EventFromAnotherRun
        );
        let mut backwards = events.clone();
        backwards[1].at_nanos = MonotonicTime::from_nanos(0);
        assert_eq!(
            Timeline::new(&backwards).unwrap_err(),
            ReportError::ClockWentBackwards
        );
        let mut resequenced = events.clone();
        resequenced[1].sequence = 0;
        assert_eq!(
            Timeline::new(&resequenced).unwrap_err(),
            ReportError::SequenceNotIncreasing
        );
        let mut duplicate = events[0].clone();
        duplicate.sequence = 5;
        duplicate.at_nanos = MonotonicTime::from_nanos(u64::MAX);
        events.push(duplicate);
        assert_eq!(
            Timeline::new(&events).unwrap_err(),
            ReportError::DuplicateEvent {
                event: EventName::RequestAccepted
            }
        );
        // Tokens before the request was accepted end the first-token clock too early.
        let early_token = record(
            "op-1",
            "host",
            vec![
                (0, EventKind::TokenEmitted),
                (1, EventKind::RequestAccepted),
                (1, EventKind::RequestDequeued),
                (1, EventKind::TokenEmitted),
            ],
        );
        assert_eq!(
            Timeline::new(&early_token)
                .unwrap()
                .interval(IntervalKind::TimeToFirstToken),
            Err(ReportError::EndBeforeStart {
                interval: IntervalKind::TimeToFirstToken
            })
        );
        // An end with no start is refused rather than reported as not applicable.
        let orphan = record("op-1", "host", vec![(0, EventKind::WakeCompleted)]);
        assert_eq!(
            Timeline::new(&orphan)
                .unwrap()
                .optional_interval(IntervalKind::DemandWake),
            Err(ReportError::MissingEvent {
                event: EventName::WakeStarted
            })
        );
    }

    #[test]
    fn switching_discloses_and_checks_the_controlled_gap() {
        let events = record(
            "op-1",
            "host",
            vec![
                (0, EventKind::ModelAFinalOutput),
                (250, EventKind::RequestAccepted),
                (1, EventKind::RequestDequeued),
                (1, EventKind::LoadStarted),
                (900, EventKind::LoadCompleted),
                (60, EventKind::TokenEmitted),
                (1, EventKind::RequestCompleted),
            ],
        );
        let timeline = Timeline::new(&events).unwrap();
        let clock = timeline
            .switching(SwitchMode::WarmReload, 250_000_000, true)
            .unwrap();
        assert_eq!(millis(&clock.measured_gap), 250);
        assert_eq!(millis(&clock.last_output_to_first_output), 1212);
        assert_eq!(millis(&clock.request.time_to_first_token), 962);
        assert_eq!(
            timeline.switching(SwitchMode::WarmReload, 300_000_000, true),
            Err(ReportError::ControlledGapNotHonoured {
                declared_nanos: 300_000_000,
                measured_nanos: 250_000_000,
            })
        );
        // A load is not hot dispatch, and a wake mode needs a wake.
        assert_eq!(
            timeline.switching(SwitchMode::HotDispatch, 0, true),
            Err(ReportError::SwitchModeMismatch)
        );
        assert_eq!(
            timeline.switching(SwitchMode::Wake, 0, true),
            Err(ReportError::SwitchModeMismatch)
        );
    }

    #[test]
    fn vm_provisioning_ends_at_a_command_in_the_intended_guest() {
        let intended = guest("exe-vm-1");
        let boot = SandboxBootGeneration::FIRST;
        let events = record(
            "op-1",
            "host",
            vec![
                (
                    0,
                    EventKind::VmCreateInitiated {
                        guest: intended.clone(),
                        boot,
                    },
                ),
                (40, EventKind::VmApiAcknowledged),
                // A pooled VM answering first is not the intended guest.
                (
                    100,
                    EventKind::GuestCommandSucceeded {
                        guest: guest("exe-pool-9"),
                        boot,
                    },
                ),
                // Nor is an earlier boot of the intended VM.
                (
                    100,
                    EventKind::GuestCommandSucceeded {
                        guest: intended.clone(),
                        boot: SandboxBootGeneration::new(7),
                    },
                ),
                (
                    560,
                    EventKind::GuestCommandSucceeded {
                        guest: intended.clone(),
                        boot,
                    },
                ),
            ],
        );
        let clock = Timeline::new(&events).unwrap().vm_provisioning().unwrap();
        assert_eq!(millis(&clock.first_guest_command), 800);
        assert_eq!(clock.api_acknowledgement.value().map(millis), Some(40));
        assert_eq!(clock.guest, intended);

        // An acknowledgement alone is not an interactive VM.
        let acknowledged_only = record(
            "op-1",
            "host",
            vec![
                (
                    0,
                    EventKind::VmCreateInitiated {
                        guest: intended.clone(),
                        boot,
                    },
                ),
                (40, EventKind::VmApiAcknowledged),
            ],
        );
        assert_eq!(
            Timeline::new(&acknowledged_only).unwrap().vm_provisioning(),
            Err(ReportError::MissingEvent {
                event: EventName::GuestCommandSucceeded
            })
        );
        assert_eq!(
            MeasuredInterval::between(IntervalKind::VmFirstGuestCommand, &events[0], &events[2]),
            Err(ReportError::NotIntendedGuest)
        );
    }

    #[test]
    fn owner_return_needs_three_measured_events_and_a_pause_is_not_a_release() {
        let steps = vec![
            (
                0,
                EventKind::ForegroundSignalApproved {
                    vram_baseline_bytes: 2_000,
                },
            ),
            (5, EventKind::BackgroundWorkDenied),
            (5, EventKind::BackgroundWorkPaused),
            (100, EventKind::VramObserved { vram_bytes: 9_000 }),
            (100, EventKind::VramObserved { vram_bytes: 1_500 }),
            (50, EventKind::ForegroundTargetMet),
        ];
        let events = record("op-1", "host", steps.clone());
        let clock = Timeline::new(&events)
            .unwrap()
            .owner_return(ReturnPath::RuntimeRelease)
            .unwrap();
        assert_eq!(millis(&clock.denial_of_new_background_work), 5);
        assert_eq!(millis(&clock.vram_at_declared_baseline), 210);
        assert_eq!(millis(&clock.foreground_target_met), 260);

        // Paused, but VRAM never came back to the baseline.
        let paused_only = record("op-1", "host", steps[..4].to_vec());
        assert_eq!(
            Timeline::new(&paused_only)
                .unwrap()
                .owner_return(ReturnPath::RuntimeRelease),
            Err(ReportError::MissingEvent {
                event: EventName::VramObserved
            })
        );
        assert_eq!(
            MeasuredInterval::between(IntervalKind::OwnerReturnVram, &events[0], &events[3]),
            Err(ReportError::VramAboveBaseline)
        );
    }

    #[test]
    fn first_run_and_stage_boundaries_are_named_intervals() {
        let events = record(
            "op-1",
            "host",
            vec![
                (0, EventKind::FreshStateReady),
                (60_000, EventKind::FirstModelToken),
                (240_000, EventKind::AgentTaskCompleted),
            ],
        );
        let clock = Timeline::new(&events).unwrap().first_run().unwrap();
        assert_eq!(millis(&clock.to_first_model_token), 60_000);
        assert_eq!(millis(&clock.to_agent_task), 300_000);

        let stages = record(
            "op-1",
            "host",
            vec![
                (0, EventKind::UpstreamArtifactAvailable),
                (10, EventKind::RepresentationCommitted),
                (1, EventKind::ProcessLaunched),
                (20, EventKind::RuntimeInitialized),
                (1, EventKind::PlacementRequested),
                (30, EventKind::WeightsUsable),
                (1, EventKind::ActivationRequested),
                (40, EventKind::EngineReadyForShape),
                (5, EventKind::RestoreStarted),
                (50, EventKind::RestoreCompleted),
                (5, EventKind::RecycleStarted),
                (700, EventKind::RecycleCompleted),
            ],
        );
        let reading = Timeline::new(&stages).unwrap().stages().unwrap();
        assert_eq!(reading.artifact_preparation.value().map(millis), Some(10));
        assert_eq!(reading.engine_startup.value().map(millis), Some(20));
        assert_eq!(reading.weight_availability.value().map(millis), Some(30));
        assert_eq!(reading.ready_latency.value().map(millis), Some(40));
        assert_eq!(reading.restore.value().map(millis), Some(50));
        // A recycle is a visible recovery event with its own latency (S10).
        assert_eq!(reading.recycle.value().map(millis), Some(700));
        assert_eq!(
            reading.time_to_first_token,
            Measured::not_measured(NotMeasuredReason::NotApplicable)
        );
        let started_only = record("op-1", "host", vec![(0, EventKind::ProcessLaunched)]);
        assert_eq!(
            Timeline::new(&started_only)
                .unwrap()
                .stages()
                .unwrap()
                .engine_startup,
            Measured::not_measured(NotMeasuredReason::RunEndedFirst)
        );
    }
}
