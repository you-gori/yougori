//! The coalescing progress stream (CORE-06; GPU part §3.10).
//!
//! Progress carries the GPU fields of §3.10: resource, phase, completed and total bytes,
//! committed usable bytes, estimated remaining time with confidence, queue reason and
//! safe cancellation boundary. The latest state per producer, operation and resource
//! wins; older or repeated updates change nothing, so a flood of updates costs one slot
//! per resource. A reconnecting receiver takes a snapshot instead of a replay.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::envelope::{
    ConfigError, DeliveryNumber, DeliverySequence, EventEnvelope, EventSequence, GenerationField,
    HighWater, Phase, ProducerId, ProducerIncarnation, ResolvedThrough, StreamKind,
};
use crate::foundation::ids::{Digest, MonotonicTime, OperationId};

/// The resource a progress update tracks, named by its catalog identity rather than a
/// path or a handle (GPU part §3.10: no private filesystem names, no allocation handles).
/// Not the planning resource name `ids::ResourceId`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TrackedResourceId(Digest);

impl TrackedResourceId {
    pub const fn new(identity: Digest) -> Self {
        Self(identity)
    }

    pub const fn identity(self) -> Digest {
        self.0
    }
}

/// What kind of state a resource is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Weights,
    Adapter,
    KvCache,
    CompiledGraph,
    GuestImage,
    Snapshot,
    Artifact,
}

impl ResourceKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Weights => "weights",
            Self::Adapter => "adapter",
            Self::KvCache => "KV cache",
            Self::CompiledGraph => "compiled graph",
            Self::GuestImage => "guest image",
            Self::Snapshot => "snapshot",
            Self::Artifact => "artifact",
        }
    }
}

/// Where the bytes of a resource come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSource {
    LocalStorage,
    HostMemory,
    PeerTransfer,
    RemoteDownload,
}

impl DataSource {
    pub const fn label(self) -> &'static str {
        match self {
            Self::LocalStorage => "local storage",
            Self::HostMemory => "host memory",
            Self::PeerTransfer => "a peer",
            Self::RemoteDownload => "a download",
        }
    }
}

strict_tagged_enum! {
    /// Why an operation waits (GPU part §3.10 "queue reason").
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum QueueReason (tag = "reason", wire = QueueReasonWire, wire_name = "QueueReasonWire") {
        GpuMemory { needed_bytes: u64 },
        HostMemory { needed_bytes: u64 },
        PinnedMemory { needed_bytes: u64 },
        TransferSlot,
        Storage,
        Authorization,
        /// Earlier requests run first; at least one is ahead.
        EarlierRequests { requests_ahead: u32 },
    }
}

impl QueueReason {
    /// The public explanation, such as "waiting for 4 GB of GPU memory" (GPU part §3.10).
    pub fn describe(self) -> String {
        match self {
            Self::EarlierRequests { requests_ahead: 1 } => {
                "waiting for 1 earlier request".to_owned()
            }
            Self::EarlierRequests { requests_ahead } => {
                format!("waiting for {requests_ahead} earlier requests")
            }
            Self::GpuMemory { needed_bytes } => {
                format!("waiting for {} of GPU memory", format_bytes(needed_bytes))
            }
            Self::HostMemory { needed_bytes } => {
                format!("waiting for {} of host memory", format_bytes(needed_bytes))
            }
            Self::PinnedMemory { needed_bytes } => format!(
                "waiting for {} of pinned host memory",
                format_bytes(needed_bytes)
            ),
            Self::TransferSlot => "waiting for a transfer slot".to_owned(),
            Self::Storage => "waiting for local storage".to_owned(),
            Self::Authorization => "waiting for authorization".to_owned(),
        }
    }
}

strict_tagged_enum! {
    /// When the operation can next be cancelled safely (GPU part §3.10 "safe cancellation
    /// boundary").
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum CancellationBoundary (tag = "boundary", wire = CancellationBoundaryWire, wire_name = "CancellationBoundaryWire") {
        /// Cancelling now is safe.
        Anytime,
        /// The next safe point is when this many bytes are complete.
        AtCompletedBytes { completed_bytes: u64 },
        /// Safe only once the current phase ends.
        EndOfPhase,
    }
}

/// Estimated remaining time as a range with a confidence (GPU part §3.10 "estimated
/// remaining time with confidence").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtaEstimate {
    remaining_low_seconds: u64,
    remaining_high_seconds: u64,
    confidence_percent: u8,
}

impl EtaEstimate {
    pub fn new(
        remaining_low_seconds: u64,
        remaining_high_seconds: u64,
        confidence_percent: u8,
    ) -> Result<Self, ProgressError> {
        let estimate = Self {
            remaining_low_seconds,
            remaining_high_seconds,
            confidence_percent,
        };
        estimate.validate()?;
        Ok(estimate)
    }

    pub fn remaining_low_seconds(&self) -> u64 {
        self.remaining_low_seconds
    }

    pub fn remaining_high_seconds(&self) -> u64 {
        self.remaining_high_seconds
    }

    pub fn confidence_percent(&self) -> u8 {
        self.confidence_percent
    }

    fn validate(&self) -> Result<(), ProgressError> {
        if self.remaining_low_seconds > self.remaining_high_seconds {
            return Err(ProgressError::EtaRangeInverted {
                remaining_low_seconds: self.remaining_low_seconds,
                remaining_high_seconds: self.remaining_high_seconds,
            });
        }
        if !(1..=100).contains(&self.confidence_percent) {
            return Err(ProgressError::ConfidenceOutOfRange {
                confidence_percent: self.confidence_percent,
            });
        }
        Ok(())
    }
}

/// The GPU progress fields of §3.10 for one resource. The phase is the envelope's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgressUpdate {
    resource: TrackedResourceId,
    kind: ResourceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<DataSource>,
    completed_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_bytes: Option<u64>,
    committed_usable_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    eta: Option<EtaEstimate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    queue_reason: Option<QueueReason>,
    cancellation: CancellationBoundary,
}

impl ProgressUpdate {
    /// An update; [`ProgressUpdate::validate`] checks it against its phase when it is
    /// emitted or recorded.
    pub fn new(
        resource: TrackedResourceId,
        kind: ResourceKind,
        completed_bytes: u64,
        total_bytes: Option<u64>,
        committed_usable_bytes: u64,
        cancellation: CancellationBoundary,
    ) -> Self {
        Self {
            resource,
            kind,
            from: None,
            completed_bytes,
            total_bytes,
            committed_usable_bytes,
            eta: None,
            queue_reason: None,
            cancellation,
        }
    }

    pub fn from_source(mut self, source: DataSource) -> Self {
        self.from = Some(source);
        self
    }

    pub fn with_eta(mut self, eta: EtaEstimate) -> Self {
        self.eta = Some(eta);
        self
    }

    pub fn queued_for(mut self, reason: QueueReason) -> Self {
        self.queue_reason = Some(reason);
        self
    }

    pub fn resource(&self) -> TrackedResourceId {
        self.resource
    }

    pub fn kind(&self) -> ResourceKind {
        self.kind
    }

    pub fn source(&self) -> Option<DataSource> {
        self.from
    }

    pub fn completed_bytes(&self) -> u64 {
        self.completed_bytes
    }

    pub fn total_bytes(&self) -> Option<u64> {
        self.total_bytes
    }

    pub fn committed_usable_bytes(&self) -> u64 {
        self.committed_usable_bytes
    }

    pub fn eta(&self) -> Option<EtaEstimate> {
        self.eta
    }

    pub fn queue_reason(&self) -> Option<QueueReason> {
        self.queue_reason
    }

    pub fn cancellation(&self) -> CancellationBoundary {
        self.cancellation
    }

    /// Committed usable bytes never exceed completed bytes, which never exceed the total;
    /// a completed resource has its total known and every byte complete and usable; an
    /// ended operation has no remaining time; a queued operation says why it waits and
    /// only a queued one has a queue reason; a cancellation point lies ahead and within
    /// the total.
    pub fn validate(&self, phase: Phase) -> Result<(), ProgressError> {
        if self.committed_usable_bytes > self.completed_bytes {
            return Err(ProgressError::CommittedExceedsCompleted {
                committed_usable_bytes: self.committed_usable_bytes,
                completed_bytes: self.completed_bytes,
            });
        }
        if let Some(total_bytes) = self.total_bytes {
            if self.completed_bytes > total_bytes {
                return Err(ProgressError::CompletedExceedsTotal {
                    completed_bytes: self.completed_bytes,
                    total_bytes,
                });
            }
        }
        if phase == Phase::Completed {
            let total_bytes = self
                .total_bytes
                .ok_or(ProgressError::CompletedWithoutTotal)?;
            if self.completed_bytes != total_bytes || self.committed_usable_bytes != total_bytes {
                return Err(ProgressError::CompletedNotWhole {
                    completed_bytes: self.completed_bytes,
                    committed_usable_bytes: self.committed_usable_bytes,
                    total_bytes,
                });
            }
        }
        if let Some(eta) = self.eta {
            if phase.is_terminal() {
                return Err(ProgressError::EtaAfterEnd { phase });
            }
            eta.validate()?;
        }
        match (phase, self.queue_reason) {
            (Phase::Queued, None) => return Err(ProgressError::QueuedWithoutReason),
            (phase, Some(_)) if phase != Phase::Queued => {
                return Err(ProgressError::ReasonOutsideQueue { phase })
            }
            (_, Some(QueueReason::EarlierRequests { requests_ahead: 0 })) => {
                return Err(ProgressError::NoRequestsAhead)
            }
            _ => {}
        }
        if let CancellationBoundary::AtCompletedBytes { completed_bytes } = self.cancellation {
            if completed_bytes < self.completed_bytes {
                return Err(ProgressError::BoundaryBehind {
                    boundary_bytes: completed_bytes,
                    completed_bytes: self.completed_bytes,
                });
            }
            if self
                .total_bytes
                .is_some_and(|total_bytes| completed_bytes > total_bytes)
            {
                return Err(ProgressError::BoundaryBeyondTotal {
                    boundary_bytes: completed_bytes,
                });
            }
        }
        Ok(())
    }

    /// The public explanation of this update in `phase`, such as "waiting for 4 GB of GPU
    /// memory" or "restoring weights from local storage". It names what is happening and
    /// never an allocation handle (GPU part §3.10).
    pub fn describe(&self, phase: Phase) -> String {
        if let Some(reason) = self.queue_reason {
            return reason.describe();
        }
        let kind = self.kind.label();
        let from = self
            .from
            .map(|source| format!(" from {}", source.label()))
            .unwrap_or_default();
        match phase {
            Phase::Requested => format!("{kind} requested"),
            Phase::Queued => format!("waiting to load {kind}"),
            Phase::Reserving => format!("reserving memory for {kind}"),
            Phase::Transferring => format!("transferring {kind}{from}"),
            Phase::Verifying => format!("verifying {kind}"),
            Phase::Restoring => format!("restoring {kind}{from}"),
            Phase::Loading => format!("loading {kind}{from}"),
            Phase::Booting => format!("booting {kind}"),
            Phase::Activating => format!("activating {kind}"),
            Phase::Running => format!("{kind} in use"),
            Phase::Retrying => format!("retrying {kind}{from}"),
            Phase::Draining => format!("draining {kind}"),
            Phase::Releasing => format!("releasing {kind}"),
            Phase::Completed => format!("{kind} ready"),
            Phase::Failed => format!("{kind} failed"),
            Phase::Cancelled => format!("{kind} cancelled"),
            Phase::Revoked => format!("{kind} stopped: authorization revoked"),
        }
    }
}

/// Bytes in decimal units with at most one decimal: 4,000,000,000 bytes is "4 GB".
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [(u64, &str); 4] = [
        (1_000_000_000_000, "TB"),
        (1_000_000_000, "GB"),
        (1_000_000, "MB"),
        (1_000, "kB"),
    ];
    for (unit, name) in UNITS {
        if bytes >= unit {
            let unit = u128::from(unit);
            let tenths = (u128::from(bytes) * 10 + unit / 2) / unit;
            let (whole, fraction) = (tenths / 10, tenths % 10);
            return if fraction == 0 {
                format!("{whole} {name}")
            } else {
                format!("{whole}.{fraction} {name}")
            };
        }
    }
    format!("{bytes} bytes")
}

/// An inconsistent progress update.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressError {
    CommittedExceedsCompleted {
        committed_usable_bytes: u64,
        completed_bytes: u64,
    },
    CompletedExceedsTotal {
        completed_bytes: u64,
        total_bytes: u64,
    },
    /// A completed resource must have a known total.
    CompletedWithoutTotal,
    /// A completed resource has every byte complete and usable.
    CompletedNotWhole {
        completed_bytes: u64,
        committed_usable_bytes: u64,
        total_bytes: u64,
    },
    /// An operation that has ended has no remaining time.
    EtaAfterEnd {
        phase: Phase,
    },
    /// Waiting for earlier requests needs at least one ahead.
    NoRequestsAhead,
    EtaRangeInverted {
        remaining_low_seconds: u64,
        remaining_high_seconds: u64,
    },
    ConfidenceOutOfRange {
        confidence_percent: u8,
    },
    /// A queued operation must say why it waits.
    QueuedWithoutReason,
    /// Only a queued operation has a queue reason.
    ReasonOutsideQueue {
        phase: Phase,
    },
    BoundaryBehind {
        boundary_bytes: u64,
        completed_bytes: u64,
    },
    BoundaryBeyondTotal {
        boundary_bytes: u64,
    },
}

impl fmt::Display for ProgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommittedExceedsCompleted {
                committed_usable_bytes,
                completed_bytes,
            } => write!(
                f,
                "{committed_usable_bytes} committed usable bytes exceed {completed_bytes} completed bytes"
            ),
            Self::CompletedExceedsTotal {
                completed_bytes,
                total_bytes,
            } => write!(
                f,
                "{completed_bytes} completed bytes exceed the total of {total_bytes}"
            ),
            Self::CompletedWithoutTotal => {
                f.write_str("a completed resource must state its total bytes")
            }
            Self::CompletedNotWhole {
                completed_bytes,
                committed_usable_bytes,
                total_bytes,
            } => write!(
                f,
                "a completed resource has all {total_bytes} bytes complete and usable, not {completed_bytes} complete and {committed_usable_bytes} usable"
            ),
            Self::EtaAfterEnd { phase } => {
                write!(f, "a {phase} operation has no remaining time")
            }
            Self::NoRequestsAhead => {
                f.write_str("waiting for earlier requests needs at least one ahead")
            }
            Self::EtaRangeInverted {
                remaining_low_seconds,
                remaining_high_seconds,
            } => write!(
                f,
                "the remaining-time range {remaining_low_seconds}–{remaining_high_seconds} s is inverted"
            ),
            Self::ConfidenceOutOfRange { confidence_percent } => write!(
                f,
                "a confidence of {confidence_percent}% is outside 1–100%"
            ),
            Self::QueuedWithoutReason => f.write_str("a queued operation must say why it waits"),
            Self::ReasonOutsideQueue { phase } => {
                write!(f, "a {phase} operation cannot have a queue reason")
            }
            Self::BoundaryBehind {
                boundary_bytes,
                completed_bytes,
            } => write!(
                f,
                "the cancellation point at {boundary_bytes} bytes is behind the {completed_bytes} bytes already complete"
            ),
            Self::BoundaryBeyondTotal { boundary_bytes } => write!(
                f,
                "the cancellation point at {boundary_bytes} bytes is beyond the total"
            ),
        }
    }
}

impl std::error::Error for ProgressError {}

/// Why the progress stream refused an update.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressRefusal {
    Invalid(ProgressError),
    /// The stream tracks its bound of live or undelivered states; the producer must report
    /// coarser resources (GPU part §3.10 "avoid one stream per tensor").
    TooManyTracked {
        limit: usize,
    },
    /// The resource already reached this terminal phase in this producer incarnation.
    AfterTerminal {
        phase: Phase,
    },
    /// The same producer incarnation and sequence arrived with different content.
    ConflictingDuplicate {
        sequence: EventSequence,
    },
}

impl fmt::Display for ProgressRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(error) => write!(f, "invalid progress update: {error}"),
            Self::TooManyTracked { limit } => write!(
                f,
                "progress already tracks {limit} resources; report coarser resources"
            ),
            Self::AfterTerminal { phase } => {
                write!(f, "the resource is already {phase}; nothing follows")
            }
            Self::ConflictingDuplicate { sequence } => write!(
                f,
                "sequence {sequence} arrived twice with different content"
            ),
        }
    }
}

impl std::error::Error for ProgressRefusal {}

/// Why an update changed nothing because it was older than the stored state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaleBy {
    /// An earlier incarnation or sequence than the stored state.
    Order,
    /// An older generation than the stored state's.
    Generation(GenerationField),
}

/// What the stream did with an update.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressAdmission {
    /// Stored as the resource's state.
    Applied,
    /// Stored, replacing a state that was not delivered yet.
    Coalesced,
    /// Already stored; applying it again changes nothing.
    Duplicate,
    /// Older than the stored state; ignored.
    Stale(StaleBy),
}

/// Bounds of the progress stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgressConfig {
    /// States tracked at most, one per producer, operation and resource.
    pub max_tracked: usize,
    /// How long a delivered terminal state stays for reconnect snapshots.
    pub terminal_retention: Duration,
}

impl ProgressConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_tracked == 0 {
            return Err(ConfigError::Zero {
                setting: "max_tracked",
            });
        }
        Ok(())
    }
}

/// Counts of what the stream did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgressTotals {
    pub applied: u64,
    pub coalesced: u64,
    pub duplicates: u64,
    pub stale: u64,
    pub delivered: u64,
    pub retired: u64,
}

/// One delivery: every state that changed since the last one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProgressBatch {
    pub updates: Vec<EventEnvelope<ProgressUpdate>>,
    /// Per producer, every sequence up to `through` was delivered or superseded.
    pub resolved: Vec<ResolvedThrough>,
}

/// What a reconnecting receiver starts from (GPU part §3.10 "reconnect snapshot"); see
/// [`super::Reconciler::resync`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProgressSnapshot {
    pub states: Vec<EventEnvelope<ProgressUpdate>>,
    pub resolved: Vec<ResolvedThrough>,
    /// The last delivery the hub made before the snapshot, which deliveries resume after;
    /// `None` before the first.
    pub after: Option<DeliveryNumber>,
    /// The latest delivery that carried a state the stream has since forgotten (a
    /// delivered terminal state past its retention, or one evicted for room). A receiver
    /// that missed that delivery or an earlier one cannot take its unfilled gaps for
    /// superseded.
    pub forgotten: Option<DeliverySequence>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct ProgressKey {
    producer: ProducerId,
    operation: OperationId,
    resource: TrackedResourceId,
}

impl ProgressKey {
    pub(super) fn new(
        producer: ProducerId,
        operation: OperationId,
        resource: TrackedResourceId,
    ) -> Self {
        Self {
            producer,
            operation,
            resource,
        }
    }

    fn of(event: &EventEnvelope<ProgressUpdate>) -> Self {
        Self::new(
            event.provenance().producer().clone(),
            event.operation().clone(),
            event.payload().resource,
        )
    }
}

#[derive(Clone, Debug)]
struct Tracked {
    state: EventEnvelope<ProgressUpdate>,
    delivered: bool,
    /// The numbered delivery that carried the state.
    delivered_in: Option<DeliverySequence>,
    ended_at: Option<MonotonicTime>,
}

/// The bounded, coalescing progress stream (CORE-06; GPU part §3.10).
#[derive(Clone, Debug)]
pub struct ProgressStream {
    config: ProgressConfig,
    tracked: BTreeMap<ProgressKey, Tracked>,
    marks: HighWater,
    /// The latest delivery that carried a state since forgotten.
    forgotten: Option<DeliverySequence>,
    totals: ProgressTotals,
}

impl ProgressStream {
    pub fn new(config: ProgressConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            tracked: BTreeMap::new(),
            marks: HighWater::new(StreamKind::Progress),
            forgotten: None,
            totals: ProgressTotals::default(),
        })
    }

    /// Records `event` as its resource's state unless a later state is stored. Applying
    /// the same event twice changes nothing.
    pub fn record(
        &mut self,
        event: EventEnvelope<ProgressUpdate>,
        now: MonotonicTime,
    ) -> Result<ProgressAdmission, ProgressRefusal> {
        event
            .payload()
            .validate(event.phase())
            .map_err(ProgressRefusal::Invalid)?;
        let key = ProgressKey::of(&event);
        let incarnation = event.provenance().incarnation();
        let sequence = event.sequence();
        if let Some(stored) = self.tracked.get(&key) {
            let state = &stored.state;
            let incoming = (incarnation, sequence);
            let current = (state.provenance().incarnation(), state.sequence());
            if incoming == current {
                if event == *state {
                    self.totals.duplicates = self.totals.duplicates.saturating_add(1);
                    return Ok(ProgressAdmission::Duplicate);
                }
                return Err(ProgressRefusal::ConflictingDuplicate { sequence });
            }
            let stale = if incoming < current {
                Some(StaleBy::Order)
            } else {
                event
                    .generations()
                    .stale_against(state.generations())
                    .map(StaleBy::Generation)
            };
            if let Some(stale) = stale {
                self.marks.note(&event.key(), sequence);
                self.totals.stale = self.totals.stale.saturating_add(1);
                return Ok(ProgressAdmission::Stale(stale));
            }
        }
        self.admit(&key, incarnation, now)?;
        self.marks.note(&event.key(), sequence);
        let ended_at = event.phase().is_terminal().then_some(now);
        let replaced = self.tracked.insert(
            key,
            Tracked {
                state: event,
                delivered: false,
                delivered_in: None,
                ended_at,
            },
        );
        self.totals.applied = self.totals.applied.saturating_add(1);
        Ok(match replaced {
            Some(previous) if !previous.delivered => {
                self.totals.coalesced = self.totals.coalesced.saturating_add(1);
                ProgressAdmission::Coalesced
            }
            _ => ProgressAdmission::Applied,
        })
    }

    /// Whether an update for `key` from `incarnation` can be stored: nothing follows a
    /// terminal phase, and a new resource needs room. Room comes only from delivered
    /// terminal states; live or undelivered states are never evicted.
    pub(super) fn admit(
        &mut self,
        key: &ProgressKey,
        incarnation: ProducerIncarnation,
        now: MonotonicTime,
    ) -> Result<(), ProgressRefusal> {
        if let Some(stored) = self.tracked.get(key) {
            let state = &stored.state;
            if state.phase().is_terminal() && state.provenance().incarnation() == incarnation {
                return Err(ProgressRefusal::AfterTerminal {
                    phase: state.phase(),
                });
            }
            return Ok(());
        }
        if self.tracked.len() < self.config.max_tracked {
            return Ok(());
        }
        self.retire(now);
        if self.tracked.len() < self.config.max_tracked {
            return Ok(());
        }
        let oldest = self
            .tracked
            .iter()
            .filter_map(
                |(key, tracked)| match (tracked.delivered, tracked.ended_at) {
                    (true, Some(ended_at)) => Some((ended_at, key.clone())),
                    _ => None,
                },
            )
            .min();
        match oldest {
            Some((_, key)) => {
                if let Some(evicted) = self.tracked.remove(&key) {
                    self.forgotten = self.forgotten.max(evicted.delivered_in);
                }
                self.totals.retired = self.totals.retired.saturating_add(1);
                Ok(())
            }
            None => Err(ProgressRefusal::TooManyTracked {
                limit: self.config.max_tracked,
            }),
        }
    }

    /// Every state that changed since the last delivery, in producer and sequence order,
    /// for a receiver that needs no delivery numbers; an [`super::EventHub`] numbers its
    /// deliveries.
    pub fn drain(&mut self, now: MonotonicTime) -> ProgressBatch {
        self.drain_in(now, None)
    }

    /// [`ProgressStream::drain`] as part of numbered delivery `delivery`.
    pub(super) fn drain_in(
        &mut self,
        now: MonotonicTime,
        delivery: Option<DeliverySequence>,
    ) -> ProgressBatch {
        self.retire(now);
        let mut updates: Vec<EventEnvelope<ProgressUpdate>> = self
            .tracked
            .values_mut()
            .filter(|tracked| !tracked.delivered)
            .map(|tracked| {
                tracked.delivered = true;
                tracked.delivered_in = delivery;
                tracked.state.clone()
            })
            .collect();
        sort_states(&mut updates);
        self.totals.delivered = self
            .totals
            .delivered
            .saturating_add(u64::try_from(updates.len()).unwrap_or(u64::MAX));
        ProgressBatch {
            updates,
            resolved: self.marks.take_unreported(),
        }
    }

    /// Every tracked state and how far each producer is resolved, for a receiver that
    /// reconnects. It marks nothing delivered. The stream knows no hub, so `after` is
    /// `None`; [`super::EventHub::progress_snapshot`] fills it.
    pub fn snapshot(&self) -> ProgressSnapshot {
        let mut states: Vec<EventEnvelope<ProgressUpdate>> = self
            .tracked
            .values()
            .map(|tracked| tracked.state.clone())
            .collect();
        sort_states(&mut states);
        ProgressSnapshot {
            states,
            resolved: self.marks.all(),
            after: None,
            forgotten: self.forgotten,
        }
    }

    pub fn tracked(&self) -> usize {
        self.tracked.len()
    }

    pub fn totals(&self) -> ProgressTotals {
        self.totals
    }

    /// Drops delivered terminal states older than the retention.
    fn retire(&mut self, now: MonotonicTime) {
        let retention = self.config.terminal_retention;
        let before = self.tracked.len();
        let mut forgotten = self.forgotten;
        self.tracked.retain(|_, tracked| {
            let expired = tracked.delivered
                && tracked
                    .ended_at
                    .is_some_and(|ended_at| now.saturating_duration_since(ended_at) >= retention);
            if expired {
                forgotten = forgotten.max(tracked.delivered_in);
            }
            !expired
        });
        self.forgotten = forgotten;
        let retired = before.saturating_sub(self.tracked.len());
        self.totals.retired = self
            .totals
            .retired
            .saturating_add(u64::try_from(retired).unwrap_or(u64::MAX));
    }
}

fn sort_states(states: &mut [EventEnvelope<ProgressUpdate>]) {
    states.sort_by(|a, b| {
        (
            a.provenance().producer(),
            a.provenance().incarnation(),
            a.sequence(),
        )
            .cmp(&(
                b.provenance().producer(),
                b.provenance().incarnation(),
                b.sequence(),
            ))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::events::envelope::{EventContext, Generations, ProducerCore};
    use crate::foundation::events::fakes::{context, producer, resource};
    use crate::foundation::evidence::SourceClass;
    use crate::foundation::ids::GpuAllocationGeneration;

    const GB: u64 = 1_000_000_000;

    fn loader(incarnation: u64) -> ProducerCore {
        ProducerCore::new(
            producer("loader"),
            ProducerIncarnation::new(incarnation).unwrap(),
            StreamKind::Progress,
            SourceClass::HostProbe,
        )
    }

    fn weights(completed_bytes: u64) -> ProgressUpdate {
        ProgressUpdate::new(
            resource("weights"),
            ResourceKind::Weights,
            completed_bytes,
            Some(8 * GB),
            completed_bytes,
            CancellationBoundary::Anytime,
        )
    }

    fn seal(
        core: &mut ProducerCore,
        context: EventContext,
        update: ProgressUpdate,
    ) -> EventEnvelope<ProgressUpdate> {
        core.seal(context, MonotonicTime::from_nanos(1), update)
            .unwrap()
    }

    fn stream(max_tracked: usize) -> ProgressStream {
        ProgressStream::new(ProgressConfig {
            max_tracked,
            terminal_retention: Duration::from_secs(60),
        })
        .unwrap()
    }

    const NOW: MonotonicTime = MonotonicTime::from_nanos(1_000);

    #[test]
    fn progress_coalesces_to_the_latest_state() {
        let mut progress = stream(4);
        let mut core = loader(1);
        let mut admissions = Vec::new();
        for step in 1..=1_000u64 {
            let event = seal(
                &mut core,
                context("op-1", Phase::Loading),
                weights(step * 8_000_000),
            );
            admissions.push(progress.record(event, NOW).unwrap());
        }
        assert_eq!(admissions[0], ProgressAdmission::Applied);
        assert!(admissions[1..]
            .iter()
            .all(|admission| *admission == ProgressAdmission::Coalesced));
        assert_eq!(progress.tracked(), 1);
        let batch = progress.drain(NOW);
        assert_eq!(batch.updates.len(), 1);
        assert_eq!(batch.updates[0].sequence().get(), 1_000);
        assert_eq!(batch.updates[0].payload().completed_bytes(), 8 * GB);
        // Every earlier sequence is resolved as superseded.
        assert_eq!(batch.resolved.len(), 1);
        assert_eq!(batch.resolved[0].through.get(), 1_000);
        assert!(progress.drain(NOW).updates.is_empty());
        // After delivery, a new state is applied rather than coalesced.
        let event = seal(
            &mut core,
            context("op-1", Phase::Verifying),
            weights(8 * GB),
        );
        assert_eq!(progress.record(event, NOW), Ok(ProgressAdmission::Applied));
    }

    #[test]
    fn duplicates_and_older_updates_change_nothing() {
        let mut progress = stream(4);
        let mut core = loader(1);
        let first = seal(&mut core, context("op-1", Phase::Loading), weights(GB));
        let second = seal(&mut core, context("op-1", Phase::Loading), weights(2 * GB));
        assert_eq!(
            progress.record(second.clone(), NOW),
            Ok(ProgressAdmission::Applied)
        );
        assert_eq!(
            progress.record(second.clone(), NOW),
            Ok(ProgressAdmission::Duplicate)
        );
        assert_eq!(
            progress.record(first, NOW),
            Ok(ProgressAdmission::Stale(StaleBy::Order))
        );
        let batch = progress.drain(NOW);
        assert_eq!(batch.updates, std::slice::from_ref(&second));
        // The same sequence with different content is refused, not merged.
        let mut forger = loader(1);
        let _ = seal(&mut forger, context("op-1", Phase::Loading), weights(GB));
        let forged = seal(
            &mut forger,
            context("op-1", Phase::Loading),
            weights(7 * GB),
        );
        assert_eq!(
            progress.record(forged, NOW),
            Err(ProgressRefusal::ConflictingDuplicate {
                sequence: second.sequence()
            })
        );
        assert_eq!(progress.totals().duplicates, 1);
        assert_eq!(progress.totals().stale, 1);
    }

    #[test]
    fn an_update_from_a_stale_generation_is_ignored() {
        let mut progress = stream(4);
        let mut core = loader(1);
        let current = Generations::NONE.with_gpu_allocation(GpuAllocationGeneration::new(5));
        let older = Generations::NONE.with_gpu_allocation(GpuAllocationGeneration::new(4));
        let fresh = seal(
            &mut core,
            context("op-1", Phase::Loading).with_generations(current),
            weights(GB),
        );
        progress.record(fresh, NOW).unwrap();
        let stale = seal(
            &mut core,
            context("op-1", Phase::Loading).with_generations(older),
            weights(2 * GB),
        );
        assert_eq!(
            progress.record(stale, NOW),
            Ok(ProgressAdmission::Stale(StaleBy::Generation(
                GenerationField::GpuAllocation
            )))
        );
        let batch = progress.drain(NOW);
        assert_eq!(batch.updates[0].payload().completed_bytes(), GB);
        // The stale event's sequence still counts as resolved.
        assert_eq!(batch.resolved[0].through.get(), 2);
    }

    #[test]
    fn a_restarted_producer_supersedes_its_earlier_incarnation() {
        let mut progress = stream(4);
        let mut old = loader(1);
        let mut new = loader(2);
        let late_old = seal(&mut old, context("op-1", Phase::Loading), weights(3 * GB));
        let restart = seal(&mut new, context("op-1", Phase::Loading), weights(GB));
        assert_eq!(
            progress.record(restart, NOW),
            Ok(ProgressAdmission::Applied)
        );
        assert_eq!(
            progress.record(late_old, NOW),
            Ok(ProgressAdmission::Stale(StaleBy::Order))
        );
        let batch = progress.drain(NOW);
        assert_eq!(batch.updates[0].provenance().incarnation().get(), 2);
        assert_eq!(batch.resolved[0].key.incarnation.get(), 2);
    }

    #[test]
    fn nothing_follows_a_terminal_phase() {
        let mut progress = stream(4);
        let mut core = loader(1);
        let done = seal(
            &mut core,
            context("op-1", Phase::Completed),
            weights(8 * GB),
        );
        progress.record(done, NOW).unwrap();
        let after = seal(&mut core, context("op-1", Phase::Loading), weights(GB));
        assert_eq!(
            progress.record(after, NOW),
            Err(ProgressRefusal::AfterTerminal {
                phase: Phase::Completed
            })
        );
    }

    #[test]
    fn the_stream_is_bounded_and_evicts_only_delivered_terminal_states() {
        let mut progress = stream(2);
        let mut core = loader(1);
        let update = |name: &str, completed_bytes: u64| {
            ProgressUpdate::new(
                resource(name),
                ResourceKind::Adapter,
                completed_bytes,
                Some(2),
                completed_bytes,
                CancellationBoundary::Anytime,
            )
        };
        progress
            .record(
                seal(&mut core, context("op-1", Phase::Loading), update("a", 1)),
                NOW,
            )
            .unwrap();
        progress
            .record(
                seal(&mut core, context("op-1", Phase::Completed), update("b", 2)),
                NOW,
            )
            .unwrap();
        // Full of undelivered states: a third resource is refused (backpressure).
        let third = seal(&mut core, context("op-1", Phase::Loading), update("c", 1));
        assert_eq!(
            progress.record(third.clone(), NOW),
            Err(ProgressRefusal::TooManyTracked { limit: 2 })
        );
        // Once the terminal state is delivered, it makes room; the live one stays.
        progress.drain(NOW);
        assert_eq!(progress.record(third, NOW), Ok(ProgressAdmission::Applied));
        assert_eq!(progress.tracked(), 2);
        assert_eq!(progress.totals().retired, 1);
        let snapshot = progress.snapshot();
        let resources: Vec<TrackedResourceId> = snapshot
            .states
            .iter()
            .map(|state| state.payload().resource())
            .collect();
        assert_eq!(resources, [resource("a"), resource("c")]);
    }

    #[test]
    fn delivered_terminal_states_retire_after_their_retention() {
        let mut progress = stream(4);
        let mut core = loader(1);
        let done = seal(
            &mut core,
            context("op-1", Phase::Completed),
            weights(8 * GB),
        );
        progress.record(done, NOW).unwrap();
        progress.drain(NOW);
        assert_eq!(progress.snapshot().states.len(), 1);
        let later = NOW.saturating_add(Duration::from_secs(60));
        progress.drain(later);
        assert_eq!(progress.tracked(), 0);
        // The snapshot still resolves the producer's sequences.
        assert_eq!(progress.snapshot().resolved[0].through.get(), 1);
    }

    #[test]
    fn updates_are_checked_against_their_phase() {
        let base = weights(GB);
        assert_eq!(base.validate(Phase::Loading), Ok(()));
        let committed = ProgressUpdate::new(
            resource("w"),
            ResourceKind::Weights,
            GB,
            Some(8 * GB),
            2 * GB,
            CancellationBoundary::Anytime,
        );
        assert_eq!(
            committed.validate(Phase::Loading),
            Err(ProgressError::CommittedExceedsCompleted {
                committed_usable_bytes: 2 * GB,
                completed_bytes: GB
            })
        );
        let over = ProgressUpdate::new(
            resource("w"),
            ResourceKind::Weights,
            9 * GB,
            Some(8 * GB),
            0,
            CancellationBoundary::Anytime,
        );
        assert!(matches!(
            over.validate(Phase::Loading),
            Err(ProgressError::CompletedExceedsTotal { .. })
        ));
        assert_eq!(
            base.validate(Phase::Queued),
            Err(ProgressError::QueuedWithoutReason)
        );
        let queued = base.queued_for(QueueReason::TransferSlot);
        assert_eq!(queued.validate(Phase::Queued), Ok(()));
        assert_eq!(
            queued.validate(Phase::Loading),
            Err(ProgressError::ReasonOutsideQueue {
                phase: Phase::Loading
            })
        );
        let behind = ProgressUpdate::new(
            resource("w"),
            ResourceKind::Weights,
            GB,
            Some(8 * GB),
            GB,
            CancellationBoundary::AtCompletedBytes {
                completed_bytes: GB / 2,
            },
        );
        assert!(matches!(
            behind.validate(Phase::Loading),
            Err(ProgressError::BoundaryBehind { .. })
        ));
        let beyond = ProgressUpdate::new(
            resource("w"),
            ResourceKind::Weights,
            GB,
            Some(8 * GB),
            GB,
            CancellationBoundary::AtCompletedBytes {
                completed_bytes: 9 * GB,
            },
        );
        assert!(matches!(
            beyond.validate(Phase::Loading),
            Err(ProgressError::BoundaryBeyondTotal { .. })
        ));
        assert_eq!(
            EtaEstimate::new(10, 5, 90),
            Err(ProgressError::EtaRangeInverted {
                remaining_low_seconds: 10,
                remaining_high_seconds: 5
            })
        );
        assert!(EtaEstimate::new(5, 10, 0).is_err());
        assert!(EtaEstimate::new(5, 10, 101).is_err());
        let eta = EtaEstimate::new(5, 10, 80).unwrap();
        assert_eq!(base.with_eta(eta).validate(Phase::Loading), Ok(()));

        // An invalid update read from the wire is refused by the stream too.
        let mut progress = stream(4);
        let mut core = loader(1);
        let event = seal(&mut core, context("op-1", Phase::Queued), weights(GB));
        assert_eq!(
            progress.record(event, NOW),
            Err(ProgressRefusal::Invalid(ProgressError::QueuedWithoutReason))
        );
    }

    #[test]
    fn a_completed_resource_has_every_byte_complete_and_usable() {
        let completed = |completed_bytes: u64, total_bytes: Option<u64>, usable_bytes: u64| {
            ProgressUpdate::new(
                resource("w"),
                ResourceKind::Weights,
                completed_bytes,
                total_bytes,
                usable_bytes,
                CancellationBoundary::Anytime,
            )
            .validate(Phase::Completed)
        };
        assert_eq!(completed(8 * GB, Some(8 * GB), 8 * GB), Ok(()));
        assert_eq!(
            completed(8 * GB, None, 8 * GB),
            Err(ProgressError::CompletedWithoutTotal)
        );
        assert_eq!(
            completed(7 * GB, Some(8 * GB), 7 * GB),
            Err(ProgressError::CompletedNotWhole {
                completed_bytes: 7 * GB,
                committed_usable_bytes: 7 * GB,
                total_bytes: 8 * GB
            })
        );
        // Every byte arrived, but not every byte is usable yet.
        assert_eq!(
            completed(8 * GB, Some(8 * GB), 6 * GB),
            Err(ProgressError::CompletedNotWhole {
                completed_bytes: 8 * GB,
                committed_usable_bytes: 6 * GB,
                total_bytes: 8 * GB
            })
        );
        // The same partial bytes are fine while the operation still runs.
        let partial = ProgressUpdate::new(
            resource("w"),
            ResourceKind::Weights,
            7 * GB,
            None,
            6 * GB,
            CancellationBoundary::Anytime,
        );
        assert_eq!(partial.validate(Phase::Loading), Ok(()));
        assert_eq!(partial.validate(Phase::Failed), Ok(()));
    }

    /// Appendix A.1's `retrying` client state: a live phase under the CORE-06 rules.
    #[test]
    fn retrying_is_a_live_phase_under_the_core_06_rules() {
        assert!(!Phase::Retrying.is_terminal());
        assert!(Phase::ALL.contains(&Phase::Retrying));
        assert_eq!(Phase::Retrying.to_string(), "retrying");
        assert_eq!(
            serde_json::to_value(Phase::Retrying).unwrap(),
            serde_json::json!("retrying")
        );
        // Partial bytes and a remaining time are fine; only a queued operation has a queue
        // reason.
        let retrying = weights(2 * GB).from_source(DataSource::RemoteDownload);
        let eta = EtaEstimate::new(5, 30, 50).unwrap();
        assert_eq!(retrying.validate(Phase::Retrying), Ok(()));
        assert_eq!(retrying.with_eta(eta).validate(Phase::Retrying), Ok(()));
        assert_eq!(
            retrying
                .queued_for(QueueReason::TransferSlot)
                .validate(Phase::Retrying),
            Err(ProgressError::ReasonOutsideQueue {
                phase: Phase::Retrying
            })
        );
        assert_eq!(
            retrying.describe(Phase::Retrying),
            "retrying weights from a download"
        );
        // Updates follow it and coalesce as for any live phase; nothing follows the end.
        let mut progress = stream(4);
        let mut core = loader(1);
        let phases = [
            Phase::Loading,
            Phase::Retrying,
            Phase::Retrying,
            Phase::Loading,
        ];
        let admissions: Vec<ProgressAdmission> = phases
            .into_iter()
            .zip(1..)
            .map(|(phase, step)| {
                let event = seal(&mut core, context("op-1", phase), weights(step * GB));
                progress.record(event, NOW).unwrap()
            })
            .collect();
        assert_eq!(admissions[0], ProgressAdmission::Applied);
        assert!(admissions[1..]
            .iter()
            .all(|admission| *admission == ProgressAdmission::Coalesced));
        let done = seal(
            &mut core,
            context("op-1", Phase::Completed),
            weights(8 * GB),
        );
        progress.record(done, NOW).unwrap();
        let after = seal(&mut core, context("op-1", Phase::Retrying), weights(GB));
        assert_eq!(
            progress.record(after, NOW),
            Err(ProgressRefusal::AfterTerminal {
                phase: Phase::Completed
            })
        );
    }

    #[test]
    fn an_ended_operation_has_no_remaining_time() {
        let eta = EtaEstimate::new(5, 10, 80).unwrap();
        for phase in Phase::ALL.into_iter().filter(|phase| phase.is_terminal()) {
            let update = weights(8 * GB).with_eta(eta);
            assert_eq!(
                update.validate(phase),
                Err(ProgressError::EtaAfterEnd { phase }),
                "{phase}"
            );
            assert_eq!(weights(8 * GB).validate(phase), Ok(()), "{phase}");
        }
        assert_eq!(weights(GB).with_eta(eta).validate(Phase::Loading), Ok(()));
    }

    #[test]
    fn waiting_for_earlier_requests_needs_one_ahead() {
        let waiting = |requests_ahead: u32| {
            weights(0).queued_for(QueueReason::EarlierRequests { requests_ahead })
        };
        assert_eq!(waiting(3).validate(Phase::Queued), Ok(()));
        assert_eq!(
            waiting(3).describe(Phase::Queued),
            "waiting for 3 earlier requests"
        );
        assert_eq!(
            waiting(1).describe(Phase::Queued),
            "waiting for 1 earlier request"
        );
        assert_eq!(
            waiting(0).validate(Phase::Queued),
            Err(ProgressError::NoRequestsAhead)
        );
        assert_eq!(
            waiting(2).validate(Phase::Loading),
            Err(ProgressError::ReasonOutsideQueue {
                phase: Phase::Loading
            })
        );
        assert_eq!(
            serde_json::to_value(QueueReason::EarlierRequests { requests_ahead: 3 }).unwrap(),
            serde_json::json!({"reason": "earlier_requests", "requests_ahead": 3})
        );
    }

    #[test]
    fn public_descriptions_follow_the_plan_examples() {
        let waiting = weights(0).queued_for(QueueReason::GpuMemory {
            needed_bytes: 4 * GB,
        });
        assert_eq!(
            waiting.describe(Phase::Queued),
            "waiting for 4 GB of GPU memory"
        );
        let restoring = weights(GB).from_source(DataSource::LocalStorage);
        assert_eq!(
            restoring.describe(Phase::Restoring),
            "restoring weights from local storage"
        );
        assert_eq!(format_bytes(4 * GB), "4 GB");
        assert_eq!(format_bytes(4_294_967_296), "4.3 GB");
        assert_eq!(format_bytes(1_500_000), "1.5 MB");
        assert_eq!(format_bytes(999), "999 bytes");
        assert_eq!(format_bytes(u64::MAX), "18446744.1 TB");
        // Every phase has a description that names no handle or identity.
        let hex = resource("weights").identity().to_hex();
        for phase in Phase::ALL {
            let text = restoring.describe(phase);
            assert!(
                !text.is_empty() && !text.contains(&hex[..8]),
                "{phase}: {text}"
            );
        }
    }

    #[test]
    fn tagged_progress_fields_refuse_unknown_fields() {
        assert_eq!(
            serde_json::from_str::<CancellationBoundary>(r#"{"boundary":"anytime"}"#).unwrap(),
            CancellationBoundary::Anytime
        );
        // serde would ignore this next to a unit variant's tag without the strict twin.
        assert!(serde_json::from_str::<CancellationBoundary>(
            r#"{"boundary":"anytime","completed_bytes":5}"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<QueueReason>(r#"{"reason":"storage","path":"/home/a"}"#)
                .is_err()
        );
        assert_eq!(
            serde_json::to_value(QueueReason::GpuMemory { needed_bytes: 4 }).unwrap(),
            serde_json::json!({"reason": "gpu_memory", "needed_bytes": 4})
        );
        let update = weights(GB).queued_for(QueueReason::Storage);
        let json = serde_json::to_value(update).unwrap();
        assert_eq!(
            serde_json::from_value::<ProgressUpdate>(json.clone()).unwrap(),
            update
        );
        let mut extra = json;
        extra["handle"] = serde_json::json!(140_000);
        assert!(serde_json::from_value::<ProgressUpdate>(extra).is_err());
    }
}
