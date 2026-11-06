//! Event-driven GPU progress on the CORE-06 progress stream (§3.10 line 650).
//!
//! Executors report extents per operation. The publisher folds them into one CORE-06
//! [`ProgressUpdate`] per operation and emits it through the [`EventHub`] with its
//! registered [`ProgressProducer`]: stage and allocation changes go out at once, byte
//! updates at most once per interval, and extent reports are keyed by index, so a
//! repeated report changes nothing. Progress is never one stream, or one event, per
//! tensor. When the hub's progress stream is full or the producer is rate limited, the
//! latest state waits for the next flush instead of blocking. A progress producer reaches
//! only the progress stream, so performance traffic never enters the audit stream.
//!
//! GPU allocations come from the CORE-04 coordinator, and one it does not honour, such
//! as an allocation retired by a restart, is refused (line 652).
//!
//! Stage timing is kept per operation for benchmark and debug output only (line 654),
//! with the §2.1 boundaries recorded as CORE-08 events.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::Serialize;

use super::eta::{ThroughputWindow, MIN_SEGMENTS_FOR_ESTIMATE};
use super::public::PublicProgress;
use crate::foundation::coordination::{
    CapacityPort, Coordinator, GpuAllocationHandle, LeaseRefusal, ModelGenerations, ModelId,
};
use crate::foundation::events::{
    CancellationBoundary, DataSource, EmitError, EventContext, EventHub, Generations, Phase,
    ProducerIncarnation, ProgressAdmission, ProgressError, ProgressProducer, ProgressRefusal,
    ProgressSnapshot, ProgressUpdate, QueueReason, ResourceKind, StaleBy, TrackedResourceId,
};
use crate::foundation::ids::{Clock, ExecutionId, Incarnation, MonotonicTime, OperationId};
use crate::foundation::report::{
    ClockId, EventKind, EventName, EventRecorder, IntervalKind, Measured, MeasuredInterval,
    NotMeasuredReason, RecordedEvent, ReportError, Timeline,
};

/// Whether bytes move in `phase`: transferring, verifying, restoring or loading. Extents
/// are reported, and remaining time is estimated, only in these phases.
pub const fn moves_bytes(phase: Phase) -> bool {
    matches!(
        phase,
        Phase::Transferring | Phase::Verifying | Phase::Restoring | Phase::Loading
    )
}

/// Where an operation is, as the publisher is told: a CORE-06 phase, why it waits and
/// where its bytes come from. CORE-06's rules decide which combinations are valid: a
/// queued operation names its queue reason, and only a queued one has one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Stage {
    phase: Phase,
    queue_reason: Option<QueueReason>,
    source: Option<DataSource>,
}

impl Stage {
    /// `phase` with no queue reason and no source.
    pub const fn at(phase: Phase) -> Self {
        Self {
            phase,
            queue_reason: None,
            source: None,
        }
    }

    /// Waiting for `reason` (CORE-06 `Queued`).
    pub const fn queued(reason: QueueReason) -> Self {
        Self {
            phase: Phase::Queued,
            queue_reason: Some(reason),
            source: None,
        }
    }

    /// `phase` with its bytes coming from `source`.
    pub const fn from_source(phase: Phase, source: DataSource) -> Self {
        Self {
            phase,
            queue_reason: None,
            source: Some(source),
        }
    }

    pub const fn phase(self) -> Phase {
        self.phase
    }

    pub const fn queue_reason(self) -> Option<QueueReason> {
        self.queue_reason
    }

    pub const fn source(self) -> Option<DataSource> {
        self.source
    }
}

/// The publisher's bounds (line 650).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublishPolicy {
    /// Byte updates of one operation go out at most once per interval. Stage and
    /// allocation changes, and the update that makes every byte usable, go out at once.
    pub min_publish_interval: Duration,
    /// Operations tracked at once, ended ones kept for diagnostics included.
    pub max_operations: usize,
    /// Throughput samples behind each estimate; more than
    /// [`MIN_SEGMENTS_FOR_ESTIMATE`], since n samples make n - 1 segments.
    pub eta_window_samples: usize,
}

impl Default for PublishPolicy {
    fn default() -> Self {
        Self {
            min_publish_interval: Duration::from_millis(250),
            max_operations: 256,
            eta_window_samples: 32,
        }
    }
}

/// Starts tracking one operation on one resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrackRequest {
    /// The resource, by its catalog or identity digest, never a path or a handle.
    pub resource: TrackedResourceId,
    pub kind: ResourceKind,
    pub total_bytes: u64,
    pub stage: Stage,
}

/// What a command or update did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    /// The hub's progress stream took it as the operation's latest state.
    Published,
    /// Held: the operation published less than an interval ago.
    Coalesced,
    /// The stream was full or the producer rate limited; the latest state waits for the
    /// next flush.
    Deferred,
    /// Nothing changed: a repeated command or update.
    Unchanged,
}

/// Counts of what the publisher did with commands and updates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublisherStats {
    pub published: u64,
    pub coalesced: u64,
    pub deferred: u64,
    pub unchanged: u64,
}

/// The two outputs that may show stage timing (line 654). There is no public level:
/// public output is [`PublicProgress`], which has no timing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticLevel {
    Debug,
    Benchmark,
}

/// Time spent in one phase, over all its entries (S8: queue wait is its own stage).
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct StageTiming {
    pub phase: Phase,
    pub entries: u32,
    pub duration_seconds: f64,
}

/// A §2.1 boundary interval of the operation, measured from its recorded events.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct StageInterval {
    pub kind: IntervalKind,
    pub measured: Measured<MeasuredInterval>,
}

/// Benchmark or debug output of one operation (line 654: "benchmark/debug output can
/// expose detailed stage timing").
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DiagnosticProgress {
    pub level: DiagnosticLevel,
    pub public: PublicProgress,
    pub resource: TrackedResourceId,
    /// The model generations of the operation's GPU allocation, as its events carry them.
    pub generations: Generations,
    /// Time in each phase; ended phases are not timed.
    pub stages: Vec<StageTiming>,
    /// §2.1 weight availability and ready latency for weights, restore time for a KV
    /// cache. An interval still open reads "not recorded".
    pub intervals: Vec<StageInterval>,
    /// The §2.1 boundary events, stamped by the publisher's monotonic clock (S8), for a
    /// CORE-08 run record.
    pub events: Vec<RecordedEvent>,
}

/// Why the publisher refused a command or update.
#[derive(Clone, Debug, PartialEq)]
pub enum PublishError {
    /// The producer was registered under another incarnation than this start's. Each
    /// start registers its progress producer once, under the incarnation it journaled,
    /// so receivers order every event of a restarted daemon after the earlier ones
    /// (line 652).
    WrongIncarnation {
        producer: ProducerIncarnation,
        daemon: Incarnation,
    },
    /// A zero interval, no operations, or too few throughput samples for an estimate.
    InvalidPolicy,
    UnknownOperation,
    /// The operation is tracked already, for another resource, kind or total.
    TrackConflict,
    /// An operation starts in an ended phase.
    StartsEnded,
    /// Every tracked operation is running or has an unpublished final state; nothing is
    /// dropped to make room.
    TooManyOperations {
        max: usize,
    },
    /// The operation has ended; nothing follows a terminal phase.
    Ended,
    /// The coordinator does not honour the GPU allocation, such as one retired by a
    /// restart (line 652) or replaced since.
    StaleAllocation {
        refusal: LeaseRefusal,
    },
    /// The allocation belongs to another execution or model than the operation's.
    AllocationConflict,
    /// Generations only move forward, and a cleared one never comes back.
    GenerationWentBack,
    /// Bytes move only while transferring, verifying, restoring or loading.
    BytesOutsideTransfer {
        phase: Phase,
    },
    /// Copies in flight arrive or are discarded before the operation leaves the phases
    /// that move bytes, unless it ends; otherwise its cancellation boundary would be
    /// wrong.
    CopiesInFlight {
        in_flight_bytes: u64,
    },
    EmptyExtent,
    /// The extent was reported before with another length.
    ExtentConflict {
        index: u64,
    },
    BytesExceedTotal,
    /// An extent is committed only after it arrived.
    ExtentNotArrived {
        index: u64,
    },
    /// Usable bytes never fall within one allocation generation.
    CommittedExtentDiscarded {
        index: u64,
    },
    /// A model generates only with every byte of its weights usable.
    NotAllUsable {
        phase: Phase,
    },
    /// CORE-06 refused the update, such as `Completed` before every byte is usable.
    Invalid(ProgressError),
    /// The hub refused the emission for a reason other than backpressure.
    Emit(EmitError),
    /// The hub holds a later state of the operation than the one sent.
    Superseded(StaleBy),
    /// The operation's boundary events did not form a valid CORE-08 timeline.
    Diagnostics(ReportError),
}

impl fmt::Display for PublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongIncarnation { producer, daemon } => write!(
                f,
                "the progress producer is incarnation {producer}, but this start is {daemon}"
            ),
            Self::InvalidPolicy => f.write_str(
                "the publish policy needs an interval, room for one operation and enough                  throughput samples for an estimate",
            ),
            Self::UnknownOperation => f.write_str("the operation is not tracked"),
            Self::TrackConflict => {
                f.write_str("the operation is tracked for another resource, kind or total")
            }
            Self::StartsEnded => f.write_str("an operation cannot start in an ended phase"),
            Self::TooManyOperations { max } => write!(
                f,
                "{max} operations are tracked and none has ended with its final state sent"
            ),
            Self::Ended => f.write_str("the operation has ended"),
            Self::StaleAllocation { refusal } => {
                write!(f, "the coordinator does not honour the allocation: {refusal}")
            }
            Self::AllocationConflict => {
                f.write_str("the allocation belongs to another execution or model")
            }
            Self::GenerationWentBack => f.write_str("generations only move forward"),
            Self::BytesOutsideTransfer { phase } => {
                write!(f, "bytes cannot move while {phase}")
            }
            Self::CopiesInFlight { in_flight_bytes } => write!(
                f,
                "{in_flight_bytes} bytes of copies are still in flight; they arrive or are                  discarded first"
            ),
            Self::EmptyExtent => f.write_str("an extent has at least one byte"),
            Self::ExtentConflict { index } => {
                write!(f, "extent {index} was reported with another length")
            }
            Self::BytesExceedTotal => f.write_str("the extents exceed the total bytes"),
            Self::ExtentNotArrived { index } => {
                write!(f, "extent {index} is committed before it arrived")
            }
            Self::CommittedExtentDiscarded { index } => {
                write!(f, "extent {index} is committed and cannot be discarded")
            }
            Self::NotAllUsable { phase } => {
                write!(f, "a {phase} operation needs every byte verified and usable")
            }
            Self::Invalid(error) => write!(f, "invalid progress update: {error}"),
            Self::Emit(error) => write!(f, "the progress stream refused the update: {error}"),
            Self::Superseded(by) => {
                write!(f, "the progress stream holds a later state ({by:?})")
            }
            Self::Diagnostics(error) => write!(f, "stage timing: {error:?}"),
        }
    }
}

impl std::error::Error for PublishError {}

/// Publishes GPU progress for many operations on the CORE-06 progress stream (§3.10).
pub struct ProgressPublisher<C> {
    producer: ProgressProducer,
    clock: C,
    clock_id: ClockId,
    policy: PublishPolicy,
    operations: BTreeMap<OperationId, Tracked<C>>,
    /// How many states were published, for the order in which ended operations leave.
    published: u64,
    stats: PublisherStats,
}

impl<C: Clock + Clone> ProgressPublisher<C> {
    /// A publisher emitting with `producer`, which must be registered on the hub under
    /// this start's `incarnation` ([`super::RecoveryReport::incarnation`]). `clock_id`
    /// names `clock` in benchmark records.
    pub fn new(
        producer: ProgressProducer,
        incarnation: Incarnation,
        clock: C,
        clock_id: ClockId,
        policy: PublishPolicy,
    ) -> Result<Self, PublishError> {
        let registered = producer.key().incarnation;
        if registered.get() != incarnation.get() {
            return Err(PublishError::WrongIncarnation {
                producer: registered,
                daemon: incarnation,
            });
        }
        if policy.min_publish_interval.is_zero()
            || policy.max_operations == 0
            || policy.eta_window_samples <= MIN_SEGMENTS_FOR_ESTIMATE
        {
            return Err(PublishError::InvalidPolicy);
        }
        Ok(Self {
            producer,
            clock,
            clock_id,
            policy,
            operations: BTreeMap::new(),
            published: 0,
            stats: PublisherStats::default(),
        })
    }

    /// Starts tracking `operation` and publishes its first state. Tracking it again with
    /// the same resource, kind and total changes nothing.
    pub fn track<H: Clock>(
        &mut self,
        hub: &mut EventHub<H>,
        operation: &OperationId,
        request: TrackRequest,
    ) -> Result<PublishOutcome, PublishError> {
        let now = self.clock.now();
        if let Some(existing) = self.operations.get(operation) {
            if existing.resource == request.resource
                && existing.kind == request.kind
                && existing.total_bytes == request.total_bytes
            {
                self.stats.unchanged = self.stats.unchanged.saturating_add(1);
                return Ok(PublishOutcome::Unchanged);
            }
            return Err(PublishError::TrackConflict);
        }
        if request.stage.phase().is_terminal() {
            return Err(PublishError::StartsEnded);
        }
        let recorder =
            EventRecorder::new(operation.clone(), self.clock_id.clone(), self.clock.clone());
        let mut tracked = Tracked::new(request, now, self.policy.eta_window_samples, recorder);
        tracked.update(tracked.stage, tracked.bytes())?;
        self.make_room()?;
        tracked.boundaries.started();
        if tracked.total_bytes == 0 {
            tracked.boundaries.weights_usable();
        }
        let Self {
            producer,
            published,
            stats,
            ..
        } = self;
        let outcome = publish(
            hub,
            producer,
            published,
            stats,
            operation,
            &mut tracked,
            now,
        );
        self.operations.insert(operation.clone(), tracked);
        outcome
    }

    /// Moves `operation` to `stage` and publishes at once. The same stage again changes
    /// nothing; nothing follows an ended phase. Leaving the phases that move bytes waits
    /// until no copy is in flight, unless the operation ends, when they are never used.
    pub fn set_stage<H: Clock>(
        &mut self,
        hub: &mut EventHub<H>,
        operation: &OperationId,
        stage: Stage,
    ) -> Result<PublishOutcome, PublishError> {
        let now = self.clock.now();
        let Self {
            producer,
            operations,
            published,
            stats,
            ..
        } = self;
        let tracked = operations
            .get_mut(operation)
            .ok_or(PublishError::UnknownOperation)?;
        if tracked.stage == stage {
            stats.unchanged = stats.unchanged.saturating_add(1);
            return Ok(PublishOutcome::Unchanged);
        }
        if tracked.stage.phase().is_terminal() {
            return Err(PublishError::Ended);
        }
        let phase = stage.phase();
        if tracked.in_flight_bytes > 0 && !moves_bytes(phase) && !phase.is_terminal() {
            return Err(PublishError::CopiesInFlight {
                in_flight_bytes: tracked.in_flight_bytes,
            });
        }
        tracked.update(stage, tracked.bytes())?;
        let previous = tracked.stage;
        if moves_bytes(phase) && (phase != previous.phase() || stage.source() != previous.source())
        {
            tracked.window.clear();
        }
        tracked.stages.enter(phase, now);
        tracked.stage = stage;
        tracked.boundaries.entered(phase);
        publish(hub, producer, published, stats, operation, tracked, now)
    }

    /// Records the GPU allocation `operation` loads into and publishes at once.
    ///
    /// The coordinator must honour `handle` now: one it retired at a restart, or since,
    /// is refused (line 652). An operation keeps one execution and model, its generations
    /// only move forward, and after a clear only an allocation above every earlier one may
    /// follow. A new allocation restarts byte progress: bytes committed into the old one
    /// are not usable in the new one.
    pub fn set_allocation<H: Clock, K: Clock, P: CapacityPort>(
        &mut self,
        hub: &mut EventHub<H>,
        coordinator: &Coordinator<K, P>,
        operation: &OperationId,
        handle: &GpuAllocationHandle,
    ) -> Result<PublishOutcome, PublishError> {
        let now = self.clock.now();
        let Self {
            producer,
            operations,
            published,
            stats,
            ..
        } = self;
        let tracked = operations
            .get_mut(operation)
            .ok_or(PublishError::UnknownOperation)?;
        if tracked.allocation.as_ref() == Some(handle) {
            stats.unchanged = stats.unchanged.saturating_add(1);
            return Ok(PublishOutcome::Unchanged);
        }
        if tracked.stage.phase().is_terminal() {
            return Err(PublishError::Ended);
        }
        coordinator
            .check_gpu_handle(handle)
            .map_err(|refusal| PublishError::StaleAllocation { refusal })?;
        if let Some((execution, model)) = &tracked.binding {
            if *execution != handle.execution || *model != handle.model {
                return Err(PublishError::AllocationConflict);
            }
        }
        let current = tracked.allocation.as_ref().map(|bound| bound.generations);
        if !moves_forward(current, tracked.highest, handle.generations) {
            return Err(PublishError::GenerationWentBack);
        }
        if current
            .is_some_and(|current| current.gpu_allocation != handle.generations.gpu_allocation)
        {
            tracked.update(tracked.stage, Bytes::NONE)?;
            tracked.reset_bytes();
        }
        tracked.binding = Some((handle.execution.clone(), handle.model));
        tracked.highest = Some(match tracked.highest {
            Some(highest) => ModelGenerations {
                activation: highest.activation.max(handle.generations.activation),
                gpu_allocation: highest
                    .gpu_allocation
                    .max(handle.generations.gpu_allocation),
            },
            None => handle.generations,
        });
        tracked.allocation = Some(handle.clone());
        publish(hub, producer, published, stats, operation, tracked, now)
    }

    /// The operation no longer holds a GPU allocation, such as after it was parked;
    /// its bytes in that allocation are no longer usable. Publishes at once.
    pub fn clear_allocation<H: Clock>(
        &mut self,
        hub: &mut EventHub<H>,
        operation: &OperationId,
    ) -> Result<PublishOutcome, PublishError> {
        let now = self.clock.now();
        let Self {
            producer,
            operations,
            published,
            stats,
            ..
        } = self;
        let tracked = operations
            .get_mut(operation)
            .ok_or(PublishError::UnknownOperation)?;
        if tracked.allocation.is_none() {
            stats.unchanged = stats.unchanged.saturating_add(1);
            return Ok(PublishOutcome::Unchanged);
        }
        if tracked.stage.phase().is_terminal() {
            return Err(PublishError::Ended);
        }
        tracked.update(tracked.stage, Bytes::NONE)?;
        tracked.reset_bytes();
        tracked.allocation = None;
        publish(hub, producer, published, stats, operation, tracked, now)
    }

    /// A copy of one extent of `length_bytes` is in flight. A cancellation takes effect
    /// once the copies in flight have arrived (CORE-06 `AtCompletedBytes`). A repeated
    /// report changes nothing.
    pub fn extent_started<H: Clock>(
        &mut self,
        hub: &mut EventHub<H>,
        operation: &OperationId,
        index: u64,
        length_bytes: u64,
    ) -> Result<PublishOutcome, PublishError> {
        let now = self.clock.now();
        let interval = self.policy.min_publish_interval;
        let Self {
            producer,
            operations,
            published,
            stats,
            ..
        } = self;
        let tracked = operations
            .get_mut(operation)
            .ok_or(PublishError::UnknownOperation)?;
        if let Some(extent) = tracked.extents.get(&index) {
            if extent.length_bytes == length_bytes {
                stats.unchanged = stats.unchanged.saturating_add(1);
                return Ok(PublishOutcome::Unchanged);
            }
            return Err(PublishError::ExtentConflict { index });
        }
        tracked.check_new_extent(length_bytes)?;
        tracked.extents.insert(
            index,
            Extent {
                length_bytes,
                state: ExtentState::InFlight,
            },
        );
        tracked.in_flight_bytes = tracked.in_flight_bytes.saturating_add(length_bytes);
        after_bytes(
            hub, producer, published, stats, operation, tracked, now, interval,
        )
    }

    /// One extent of `length_bytes` arrived, not yet verified. A repeated report changes
    /// nothing.
    pub fn extent_arrived<H: Clock>(
        &mut self,
        hub: &mut EventHub<H>,
        operation: &OperationId,
        index: u64,
        length_bytes: u64,
    ) -> Result<PublishOutcome, PublishError> {
        let now = self.clock.now();
        let interval = self.policy.min_publish_interval;
        let Self {
            producer,
            operations,
            published,
            stats,
            ..
        } = self;
        let tracked = operations
            .get_mut(operation)
            .ok_or(PublishError::UnknownOperation)?;
        match tracked.extents.get(&index).copied() {
            Some(extent) if extent.length_bytes != length_bytes => {
                return Err(PublishError::ExtentConflict { index })
            }
            Some(Extent {
                state: ExtentState::Arrived | ExtentState::Committed,
                ..
            }) => {
                stats.unchanged = stats.unchanged.saturating_add(1);
                return Ok(PublishOutcome::Unchanged);
            }
            Some(Extent {
                state: ExtentState::InFlight,
                ..
            }) => {
                tracked.check_moves_bytes()?;
                tracked.in_flight_bytes = tracked.in_flight_bytes.saturating_sub(length_bytes);
            }
            None => tracked.check_new_extent(length_bytes)?,
        }
        tracked.extents.insert(
            index,
            Extent {
                length_bytes,
                state: ExtentState::Arrived,
            },
        );
        tracked.completed_bytes = tracked.completed_bytes.saturating_add(length_bytes);
        after_bytes(
            hub, producer, published, stats, operation, tracked, now, interval,
        )
    }

    /// An arrived extent was verified and committed, so its bytes are usable. A repeated
    /// report changes nothing.
    pub fn extent_committed<H: Clock>(
        &mut self,
        hub: &mut EventHub<H>,
        operation: &OperationId,
        index: u64,
    ) -> Result<PublishOutcome, PublishError> {
        let now = self.clock.now();
        let interval = self.policy.min_publish_interval;
        let Self {
            producer,
            operations,
            published,
            stats,
            ..
        } = self;
        let tracked = operations
            .get_mut(operation)
            .ok_or(PublishError::UnknownOperation)?;
        let length_bytes = match tracked.extents.get(&index).copied() {
            None
            | Some(Extent {
                state: ExtentState::InFlight,
                ..
            }) => return Err(PublishError::ExtentNotArrived { index }),
            Some(Extent {
                state: ExtentState::Committed,
                ..
            }) => {
                stats.unchanged = stats.unchanged.saturating_add(1);
                return Ok(PublishOutcome::Unchanged);
            }
            Some(Extent {
                length_bytes,
                state: ExtentState::Arrived,
            }) => length_bytes,
        };
        tracked.check_moves_bytes()?;
        tracked.extents.insert(
            index,
            Extent {
                length_bytes,
                state: ExtentState::Committed,
            },
        );
        tracked.usable_bytes = tracked.usable_bytes.saturating_add(length_bytes);
        tracked.window.record(now, tracked.usable_bytes);
        if tracked.usable_bytes == tracked.total_bytes {
            tracked.boundaries.weights_usable();
        }
        after_bytes(
            hub, producer, published, stats, operation, tracked, now, interval,
        )
    }

    /// An extent in flight or arrived failed verification or its copy, and was
    /// discarded; it is fetched again and never used (§3.5: a hash mismatch is never a
    /// warning followed by use). A committed extent cannot be discarded.
    pub fn extent_discarded<H: Clock>(
        &mut self,
        hub: &mut EventHub<H>,
        operation: &OperationId,
        index: u64,
    ) -> Result<PublishOutcome, PublishError> {
        let now = self.clock.now();
        let interval = self.policy.min_publish_interval;
        let Self {
            producer,
            operations,
            published,
            stats,
            ..
        } = self;
        let tracked = operations
            .get_mut(operation)
            .ok_or(PublishError::UnknownOperation)?;
        let Some(extent) = tracked.extents.get(&index).copied() else {
            stats.unchanged = stats.unchanged.saturating_add(1);
            return Ok(PublishOutcome::Unchanged);
        };
        if extent.state == ExtentState::Committed {
            return Err(PublishError::CommittedExtentDiscarded { index });
        }
        tracked.check_moves_bytes()?;
        tracked.extents.remove(&index);
        if extent.state == ExtentState::InFlight {
            tracked.in_flight_bytes = tracked.in_flight_bytes.saturating_sub(extent.length_bytes);
        } else {
            tracked.completed_bytes = tracked.completed_bytes.saturating_sub(extent.length_bytes);
        }
        after_bytes(
            hub, producer, published, stats, operation, tracked, now, interval,
        )
    }

    /// Publishes held states whose interval has passed, and states the stream deferred.
    /// Returns how many went out.
    pub fn flush_due<H: Clock>(&mut self, hub: &mut EventHub<H>) -> Result<usize, PublishError> {
        let now = self.clock.now();
        let interval = self.policy.min_publish_interval;
        let Self {
            producer,
            operations,
            published,
            stats,
            ..
        } = self;
        let mut sent = 0;
        for (operation, tracked) in operations.iter_mut() {
            if tracked.dirty
                && (tracked.deferred || is_due(tracked.last_published_at, now, interval))
                && publish(hub, producer, published, stats, operation, tracked, now)?
                    == PublishOutcome::Published
            {
                sent += 1;
            }
        }
        Ok(sent)
    }

    /// The hub's reconnect snapshot (line 650), after every held state is published, so
    /// it holds the latest state of every tracked operation the stream has room for.
    pub fn snapshot<H: Clock>(
        &mut self,
        hub: &mut EventHub<H>,
    ) -> Result<ProgressSnapshot, PublishError> {
        let now = self.clock.now();
        let Self {
            producer,
            operations,
            published,
            stats,
            ..
        } = self;
        for (operation, tracked) in operations.iter_mut() {
            if tracked.dirty {
                publish(hub, producer, published, stats, operation, tracked, now)?;
            }
        }
        Ok(hub.progress_snapshot())
    }

    /// Stage timing of `operation` for benchmark or debug output (line 654).
    pub fn diagnostics(
        &self,
        operation: &OperationId,
        level: DiagnosticLevel,
    ) -> Result<DiagnosticProgress, PublishError> {
        let now = self.clock.now();
        let tracked = self
            .operations
            .get(operation)
            .ok_or(PublishError::UnknownOperation)?;
        let update = tracked.update(tracked.stage, tracked.bytes())?;
        let events = tracked.boundaries.recorder.events().to_vec();
        let timeline = Timeline::new(&events).map_err(PublishError::Diagnostics)?;
        let mut intervals = Vec::new();
        for &kind in tracked.boundaries.interval_kinds() {
            let measured = match timeline
                .optional_interval(kind)
                .map_err(PublishError::Diagnostics)?
            {
                // Still running: the end has not been recorded yet, not missed.
                Measured::NotMeasured {
                    reason: NotMeasuredReason::RunEndedFirst,
                } if !tracked.stage.phase().is_terminal() => {
                    Measured::not_measured(NotMeasuredReason::NotRecorded)
                }
                measured => measured,
            };
            intervals.push(StageInterval { kind, measured });
        }
        Ok(DiagnosticProgress {
            level,
            public: PublicProgress::new(tracked.stage.phase(), &update),
            resource: tracked.resource,
            generations: tracked.generations(),
            stages: tracked.stages.timings(now),
            intervals,
            events,
        })
    }

    /// The current phase and update of `operation`, published or not.
    pub fn progress(
        &self,
        operation: &OperationId,
    ) -> Result<(Phase, ProgressUpdate), PublishError> {
        let tracked = self
            .operations
            .get(operation)
            .ok_or(PublishError::UnknownOperation)?;
        let update = tracked.update(tracked.stage, tracked.bytes())?;
        Ok((tracked.stage.phase(), update))
    }

    /// The generations the operation's events carry.
    pub fn generations(&self, operation: &OperationId) -> Result<Generations, PublishError> {
        self.operations
            .get(operation)
            .map(Tracked::generations)
            .ok_or(PublishError::UnknownOperation)
    }

    pub fn producer(&self) -> &ProgressProducer {
        &self.producer
    }

    pub fn tracked(&self) -> usize {
        self.operations.len()
    }

    pub fn stats(&self) -> PublisherStats {
        self.stats
    }

    /// Frees one slot by dropping the ended operation published longest ago. An
    /// operation still running, or whose final state the stream has not taken, is never
    /// dropped.
    fn make_room(&mut self) -> Result<(), PublishError> {
        if self.operations.len() < self.policy.max_operations {
            return Ok(());
        }
        let oldest_ended = self
            .operations
            .iter()
            .filter(|(_, tracked)| tracked.stage.phase().is_terminal() && !tracked.dirty)
            .min_by_key(|(_, tracked)| tracked.published_order)
            .map(|(operation, _)| operation.clone());
        match oldest_ended {
            Some(operation) => {
                self.operations.remove(&operation);
                Ok(())
            }
            None => Err(PublishError::TooManyOperations {
                max: self.policy.max_operations,
            }),
        }
    }
}

/// Byte counts of one operation: arrived, in flight and committed usable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Bytes {
    completed: u64,
    in_flight: u64,
    usable: u64,
}

impl Bytes {
    const NONE: Self = Self {
        completed: 0,
        in_flight: 0,
        usable: 0,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExtentState {
    InFlight,
    Arrived,
    Committed,
}

#[derive(Clone, Copy, Debug)]
struct Extent {
    length_bytes: u64,
    state: ExtentState,
}

/// One tracked operation.
struct Tracked<C> {
    resource: TrackedResourceId,
    kind: ResourceKind,
    total_bytes: u64,
    stage: Stage,
    allocation: Option<GpuAllocationHandle>,
    /// The execution and model of the first allocation; every later one must match.
    binding: Option<(ExecutionId, ModelId)>,
    /// The highest generations ever set.
    highest: Option<ModelGenerations>,
    /// Reported extents by index.
    extents: BTreeMap<u64, Extent>,
    in_flight_bytes: u64,
    completed_bytes: u64,
    usable_bytes: u64,
    window: ThroughputWindow,
    stages: StageClock,
    boundaries: Boundaries<C>,
    last_published_at: Option<MonotonicTime>,
    published_order: Option<u64>,
    /// The current state differs from the last published one.
    dirty: bool,
    /// The stream refused the current state for backpressure.
    deferred: bool,
}

impl<C: Clock> Tracked<C> {
    fn new(
        request: TrackRequest,
        now: MonotonicTime,
        window_samples: usize,
        recorder: EventRecorder<C>,
    ) -> Self {
        Self {
            resource: request.resource,
            kind: request.kind,
            total_bytes: request.total_bytes,
            stage: request.stage,
            allocation: None,
            binding: None,
            highest: None,
            extents: BTreeMap::new(),
            in_flight_bytes: 0,
            completed_bytes: 0,
            usable_bytes: 0,
            window: ThroughputWindow::new(window_samples),
            stages: StageClock::new(request.stage.phase(), now),
            boundaries: Boundaries::new(request.kind, recorder),
            last_published_at: None,
            published_order: None,
            dirty: true,
            deferred: false,
        }
    }

    fn bytes(&self) -> Bytes {
        Bytes {
            completed: self.completed_bytes,
            in_flight: self.in_flight_bytes,
            usable: self.usable_bytes,
        }
    }

    /// The update this operation would publish in `stage` with `bytes`, refused if it
    /// breaks a CORE-06 rule or this module's: a running model has every byte usable.
    ///
    /// The cancellation boundary follows from the stage and the copies in flight: while
    /// bytes move, a cancellation takes effect once the copies in flight have arrived;
    /// activation is atomic and completes or rolls back first (§3.6 step 5); otherwise
    /// it takes effect at once. Remaining time is estimated only while bytes move.
    fn update(&self, stage: Stage, bytes: Bytes) -> Result<ProgressUpdate, PublishError> {
        let phase = stage.phase();
        if phase == Phase::Running && bytes.usable != self.total_bytes {
            return Err(PublishError::NotAllUsable { phase });
        }
        let cancellation = if moves_bytes(phase) && bytes.in_flight > 0 {
            CancellationBoundary::AtCompletedBytes {
                completed_bytes: bytes.completed.saturating_add(bytes.in_flight),
            }
        } else if phase == Phase::Activating {
            CancellationBoundary::EndOfPhase
        } else {
            CancellationBoundary::Anytime
        };
        let mut update = ProgressUpdate::new(
            self.resource,
            self.kind,
            bytes.completed,
            Some(self.total_bytes),
            bytes.usable,
            cancellation,
        );
        if let Some(source) = stage.source() {
            update = update.from_source(source);
        }
        if let Some(reason) = stage.queue_reason() {
            update = update.queued_for(reason);
        }
        if moves_bytes(phase) {
            if let Some(eta) = self
                .window
                .estimate(self.total_bytes.saturating_sub(bytes.usable))
            {
                update = update.with_eta(eta);
            }
        }
        update.validate(phase).map_err(PublishError::Invalid)?;
        Ok(update)
    }

    fn generations(&self) -> Generations {
        match &self.allocation {
            Some(handle) => Generations::NONE
                .with_model_activation(handle.generations.activation)
                .with_gpu_allocation(handle.generations.gpu_allocation),
            None => Generations::NONE,
        }
    }

    fn check_moves_bytes(&self) -> Result<(), PublishError> {
        let phase = self.stage.phase();
        if phase.is_terminal() {
            return Err(PublishError::Ended);
        }
        if !moves_bytes(phase) {
            return Err(PublishError::BytesOutsideTransfer { phase });
        }
        Ok(())
    }

    /// Whether an extent not reported before may start or arrive: bytes move now, it
    /// has bytes, and arrived and in-flight bytes stay within the total.
    fn check_new_extent(&self, length_bytes: u64) -> Result<(), PublishError> {
        self.check_moves_bytes()?;
        if length_bytes == 0 {
            return Err(PublishError::EmptyExtent);
        }
        self.completed_bytes
            .checked_add(self.in_flight_bytes)
            .and_then(|taken| taken.checked_add(length_bytes))
            .filter(|&taken| taken <= self.total_bytes)
            .map(drop)
            .ok_or(PublishError::BytesExceedTotal)
    }

    fn reset_bytes(&mut self) {
        self.extents.clear();
        self.in_flight_bytes = 0;
        self.completed_bytes = 0;
        self.usable_bytes = 0;
        self.window.clear();
    }
}

/// Generations move forward: a set allocation is replaced only by one at or above it,
/// and after a clear only one above every earlier allocation may follow.
fn moves_forward(
    current: Option<ModelGenerations>,
    highest: Option<ModelGenerations>,
    next: ModelGenerations,
) -> bool {
    match (current, highest) {
        (Some(current), _) => {
            next.activation >= current.activation && next.gpu_allocation >= current.gpu_allocation
        }
        (None, Some(highest)) => {
            next.activation > highest.activation && next.gpu_allocation > highest.gpu_allocation
        }
        (None, None) => true,
    }
}

fn is_due(
    last_published_at: Option<MonotonicTime>,
    now: MonotonicTime,
    interval: Duration,
) -> bool {
    last_published_at.map_or(true, |at| now.saturating_duration_since(at) >= interval)
}

/// Emits the operation's current state through the hub. A full stream or a rate limit
/// defers it; nothing blocks.
fn publish<H: Clock, C: Clock>(
    hub: &mut EventHub<H>,
    producer: &mut ProgressProducer,
    published: &mut u64,
    stats: &mut PublisherStats,
    operation: &OperationId,
    tracked: &mut Tracked<C>,
    now: MonotonicTime,
) -> Result<PublishOutcome, PublishError> {
    let update = tracked.update(tracked.stage, tracked.bytes())?;
    let context = EventContext::new(operation.clone(), tracked.stage.phase())
        .with_generations(tracked.generations());
    match hub.emit_progress(producer, context, update) {
        Ok(
            ProgressAdmission::Applied
            | ProgressAdmission::Coalesced
            | ProgressAdmission::Duplicate,
        ) => {
            *published = published.saturating_add(1);
            tracked.published_order = Some(*published);
            tracked.last_published_at = Some(now);
            tracked.dirty = false;
            tracked.deferred = false;
            stats.published = stats.published.saturating_add(1);
            Ok(PublishOutcome::Published)
        }
        Ok(ProgressAdmission::Stale(by)) => Err(PublishError::Superseded(by)),
        Err(
            EmitError::Progress(ProgressRefusal::TooManyTracked { .. })
            | EmitError::RateLimited { .. },
        ) => {
            tracked.dirty = true;
            tracked.deferred = true;
            stats.deferred = stats.deferred.saturating_add(1);
            Ok(PublishOutcome::Deferred)
        }
        Err(error) => Err(PublishError::Emit(error)),
    }
}

/// After a byte change: publish if the interval has passed or every byte is usable,
/// otherwise hold the state for the next update or flush.
#[allow(clippy::too_many_arguments)]
fn after_bytes<H: Clock, C: Clock>(
    hub: &mut EventHub<H>,
    producer: &mut ProgressProducer,
    published: &mut u64,
    stats: &mut PublisherStats,
    operation: &OperationId,
    tracked: &mut Tracked<C>,
    now: MonotonicTime,
    interval: Duration,
) -> Result<PublishOutcome, PublishError> {
    tracked.dirty = true;
    if is_due(tracked.last_published_at, now, interval)
        || tracked.usable_bytes == tracked.total_bytes
    {
        publish(hub, producer, published, stats, operation, tracked, now)
    } else {
        stats.coalesced = stats.coalesced.saturating_add(1);
        Ok(PublishOutcome::Coalesced)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct StageTotal {
    entries: u32,
    nanos: u64,
}

/// Time per phase on the publisher's monotonic clock (S8 "monotonic timestamps").
struct StageClock {
    current: Phase,
    since: MonotonicTime,
    totals: BTreeMap<Phase, StageTotal>,
}

impl StageClock {
    fn new(phase: Phase, now: MonotonicTime) -> Self {
        let mut totals = BTreeMap::new();
        totals.insert(
            phase,
            StageTotal {
                entries: 1,
                nanos: 0,
            },
        );
        Self {
            current: phase,
            since: now,
            totals,
        }
    }

    fn enter(&mut self, phase: Phase, now: MonotonicTime) {
        if phase == self.current {
            return;
        }
        let elapsed = nanos_between(self.since, now);
        let total = self.totals.entry(self.current).or_default();
        total.nanos = total.nanos.saturating_add(elapsed);
        let next = self.totals.entry(phase).or_default();
        next.entries = next.entries.saturating_add(1);
        self.current = phase;
        self.since = now;
    }

    fn timings(&self, now: MonotonicTime) -> Vec<StageTiming> {
        self.totals
            .iter()
            .map(|(&phase, total)| {
                let open = if phase == self.current && !phase.is_terminal() {
                    nanos_between(self.since, now)
                } else {
                    0
                };
                StageTiming {
                    phase,
                    entries: total.entries,
                    duration_seconds: Duration::from_nanos(total.nanos.saturating_add(open))
                        .as_secs_f64(),
                }
            })
            .collect()
    }
}

fn nanos_between(earlier: MonotonicTime, later: MonotonicTime) -> u64 {
    u64::try_from(later.saturating_duration_since(earlier).as_nanos()).unwrap_or(u64::MAX)
}

/// The §2.1 boundary events of one operation, each recorded once, on the CORE-08 event
/// recorder: placement requested, weights usable, activation requested and engine ready
/// for weights; restore started and completed for a KV cache.
struct Boundaries<C> {
    kind: ResourceKind,
    recorder: EventRecorder<C>,
    recorded: BTreeSet<EventName>,
}

impl<C: Clock> Boundaries<C> {
    fn new(kind: ResourceKind, recorder: EventRecorder<C>) -> Self {
        Self {
            kind,
            recorder,
            recorded: BTreeSet::new(),
        }
    }

    fn once(&mut self, event: EventKind) {
        if self.recorded.insert(event.name()) {
            self.recorder.record(event);
        }
    }

    fn started(&mut self) {
        match self.kind {
            ResourceKind::Weights => self.once(EventKind::PlacementRequested),
            ResourceKind::KvCache => self.once(EventKind::RestoreStarted),
            _ => {}
        }
    }

    /// Every weight the placement needs is verified and usable (§2.1). Recorded the
    /// first time only.
    fn weights_usable(&mut self) {
        if self.kind == ResourceKind::Weights {
            self.once(EventKind::WeightsUsable);
        }
    }

    fn entered(&mut self, phase: Phase) {
        match (self.kind, phase) {
            (ResourceKind::Weights, Phase::Activating) => self.once(EventKind::ActivationRequested),
            (ResourceKind::Weights, Phase::Completed)
                if self.recorded.contains(&EventName::ActivationRequested) =>
            {
                self.once(EventKind::EngineReadyForShape)
            }
            (ResourceKind::KvCache, Phase::Completed) => self.once(EventKind::RestoreCompleted),
            _ => {}
        }
    }

    fn interval_kinds(&self) -> &'static [IntervalKind] {
        match self.kind {
            ResourceKind::Weights => {
                &[IntervalKind::WeightAvailability, IntervalKind::ReadyLatency]
            }
            ResourceKind::KvCache => &[IntervalKind::Restore],
            _ => &[],
        }
    }
}
