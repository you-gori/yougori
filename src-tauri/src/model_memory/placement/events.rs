//! Placement lifecycle decisions on a durable CORE-06 stream
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: GPU part §3.6 lines 580–601 and §3.10;
//! S2 CORE-06; docs/combined-plan-leftover-tasks.md S06 "publish real launch, load ...
//! events through CORE-06 ... correlate operations").
//!
//! A [`PlacementSlot`] decides when a model is prepared (step 1), activated (step 5),
//! parked, released (step 7) and retired, and when an activation or a placement ends
//! without serving. Each `*_and_record` call makes exactly the decision of the plain call
//! and records it at once as a [`PlacementEvent`] on the host's model lifecycle stream: a
//! progress-class [`EventLog`] whose one owner is the model memory producer, so the
//! decisions survive a restart and a reader in another process follows them with a
//! [`DurableReader`](crate::foundation::events::DurableReader). Byte progress of a load
//! stays on the hub's progress stream ([`ProgressPublisher`]); this stream keeps the
//! decisions, which are never shed.
//!
//! Each event is correlated by the operation the decision belongs to: an activation's own
//! operation for its steps, its publication and its end, and the operation the caller
//! names for parking, reclaiming and retiring, such as the activation that replaced the
//! placement or an eviction. It carries the slot's own report of the decision
//! ([`ActivationStarted`], [`PublishReport`], [`AbortReport`], [`ReclaimReport`],
//! [`Failure`]), and its envelope the activation generation the decision concerns.
//!
//! Recording never changes a decision. A record the stream refuses is reported beside the
//! outcome in [`Recorded`], never dropped silently, and a call the slot refuses changed
//! nothing and records nothing.
//!
//! [`ProgressPublisher`]: crate::model_memory::progress::ProgressPublisher

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::activation::{
    AbortReport, ActivationError, ActivationRequest, ActivationStarted, PlacementChoice,
    PublishReport,
};
use super::keys::{PlacementKey, SlotId};
use super::ports::{PlacementPorts, ReservationPort};
use super::slot::{PlacementSlot, ReclaimReport, SlotError};
use super::state::{Failure, FailureReason};
use crate::foundation::events::{
    DurableStreamId, EventContext, EventLog, EventSequence, Generations, LogConfig, LogError,
    LoggedStream, OpenReport, Phase, ProducerId, RecordError,
};
use crate::foundation::ids::{Clock, Digest, ModelActivationGeneration, OperationId};

/// One lifecycle decision of a placement slot (§3.6), as the model lifecycle stream keeps
/// it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum PlacementEvent {
    /// Step 1 reserved steady state and transition peak and began preparing a placement:
    /// a new one that loads, or a resting one with exactly the requested content
    /// (`reused`, a rollback or a wake that loads nothing).
    Prepared {
        slot: SlotId,
        started: ActivationStarted,
        reused: bool,
        /// The digests of the T07 execution and artifact identities served, so that a
        /// reader tells a reload of released content from new content.
        execution_identity: Digest,
        artifact_identity: Digest,
    },
    /// Step 5 published the generation: new requests go to it.
    Activated {
        slot: SlotId,
        published: PublishReport,
    },
    /// The activation ended without publishing: cancelled, or failed at a step.
    ActivationEnded { slot: SlotId, ended: AbortReport },
    /// A placement failed outside an activation, such as a serving placement whose
    /// process exited.
    Failed {
        slot: SlotId,
        placement: PlacementKey,
        failure: Failure,
    },
    /// Draining → parked: it serves no more and keeps its GPU memory for a reactivation.
    Parked {
        slot: SlotId,
        placement: PlacementKey,
    },
    /// Step 7: its own memory released, shared extents kept for their other holders; the
    /// report says whether serving it again needs a reload.
    Released {
        slot: SlotId,
        reclaimed: ReclaimReport,
    },
    /// The placement is gone: it held nothing any more.
    Retired {
        slot: SlotId,
        placement: PlacementKey,
    },
}

crate::foundation::strict_serde::strict_tag!(PlacementEvent, "event");

impl PlacementEvent {
    /// The phase of the operation the decision belongs to.
    pub fn phase(&self) -> Phase {
        match self {
            Self::Prepared { .. } => Phase::Loading,
            Self::Activated { .. } => Phase::Running,
            Self::ActivationEnded { ended, .. } if ended.reason == FailureReason::Cancelled => {
                Phase::Cancelled
            }
            Self::ActivationEnded { .. } | Self::Failed { .. } => Phase::Failed,
            Self::Parked { .. } => Phase::Draining,
            Self::Released { .. } => Phase::Releasing,
            Self::Retired { .. } => Phase::Completed,
        }
    }
}

/// The host's model lifecycle stream (S06).
pub type PlacementLog = EventLog<PlacementEvent>;

/// Takes ownership of the model lifecycle stream `stream` in `directory` for `owner`, a
/// progress-class stream, as [`EventLog::open`] does. `owner` seals the events, so it must
/// be neither a hub producer nor another stream's owner: model memory owns it as, say,
/// `model_memory.placements`.
pub fn open_placement_log(
    directory: &Path,
    stream: DurableStreamId,
    owner: ProducerId,
    config: LogConfig,
) -> Result<(PlacementLog, OpenReport), LogError> {
    EventLog::open(directory, stream, owner, LoggedStream::Progress, config)
}

/// A slot's decision and what the lifecycle stream did with it. The decision stands either
/// way.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recorded<T> {
    /// What the slot decided, exactly as the plain call returns it.
    pub outcome: T,
    /// The event's sequence in the stream, or why the stream refused it; `None` when the
    /// call decided nothing to record, such as a refused call or a step that completed.
    pub recorded: Option<Result<EventSequence, RecordError>>,
}

/// The activation an outcome ended, if it ended one: an abort the call reported, or a
/// step that failed the activation.
fn ended<T>(outcome: &Result<T, ActivationError>) -> Option<&AbortReport> {
    match outcome {
        Err(ActivationError::Failed { report }) => Some(report),
        _ => None,
    }
}

impl<C: Clock> PlacementSlot<C> {
    /// Step 1, as [`PlacementSlot::begin_activation`], recorded as
    /// [`PlacementEvent::Prepared`] under the request's operation.
    pub fn begin_activation_and_record(
        &mut self,
        request: &ActivationRequest,
        ports: &mut dyn PlacementPorts,
        log: &mut PlacementLog,
    ) -> Recorded<Result<ActivationStarted, ActivationError>> {
        let outcome = self.begin_activation(request, ports);
        let recorded = match &outcome {
            Ok(started) => Some(self.record(
                log,
                request.operation.clone(),
                Some(started.generation),
                PlacementEvent::Prepared {
                    slot: self.spec.slot,
                    started: started.clone(),
                    reused: matches!(request.placement, PlacementChoice::Reuse { .. }),
                    execution_identity: *request.identity.execution.digest(),
                    artifact_identity: *request.identity.artifact.digest(),
                },
            )),
            Err(_) => self.record_ended(log, request.operation.clone(), ended(&outcome)),
        };
        Recorded { outcome, recorded }
    }

    /// Runs one step of the activation in progress, such as
    /// [`PlacementSlot::record_validation`] or [`PlacementSlot::record_readiness`], and
    /// records [`PlacementEvent::ActivationEnded`] under the activation's operation when
    /// the step failed the activation.
    pub fn step_and_record<T>(
        &mut self,
        log: &mut PlacementLog,
        step: impl FnOnce(&mut Self) -> Result<T, ActivationError>,
    ) -> Recorded<Result<T, ActivationError>> {
        let operation = self.activation_operation();
        let outcome = step(self);
        let recorded =
            operation.and_then(|operation| self.record_ended(log, operation, ended(&outcome)));
        Recorded { outcome, recorded }
    }

    /// Ends the activation in progress without publishing, through
    /// [`PlacementSlot::cancel_activation`], [`PlacementSlot::record_extent_failed`] or
    /// [`PlacementSlot::record_runtime_failed`], and records
    /// [`PlacementEvent::ActivationEnded`] under the activation's operation.
    pub fn end_and_record(
        &mut self,
        log: &mut PlacementLog,
        end: impl FnOnce(&mut Self) -> Result<AbortReport, ActivationError>,
    ) -> Recorded<Result<AbortReport, ActivationError>> {
        let operation = self.activation_operation();
        let outcome = end(self);
        let recorded = operation.and_then(|operation| {
            let report = match &outcome {
                Ok(report) => Some(report),
                Err(_) => ended(&outcome),
            };
            self.record_ended(log, operation, report)
        });
        Recorded { outcome, recorded }
    }

    /// Step 5, as [`PlacementSlot::publish`], recorded as [`PlacementEvent::Activated`]
    /// under the activation's operation.
    pub fn publish_and_record(
        &mut self,
        ports: &mut dyn PlacementPorts,
        log: &mut PlacementLog,
    ) -> Recorded<Result<PublishReport, ActivationError>> {
        let operation = self.activation_operation();
        let outcome = self.publish(ports);
        let recorded = operation.and_then(|operation| match &outcome {
            Ok(published) => Some(self.record(
                log,
                operation,
                Some(published.generation),
                PlacementEvent::Activated {
                    slot: self.spec.slot,
                    published: published.clone(),
                },
            )),
            Err(_) => self.record_ended(log, operation, ended(&outcome)),
        });
        Recorded { outcome, recorded }
    }

    /// Parks a drained placement, as [`PlacementSlot::park`], recorded as
    /// [`PlacementEvent::Parked`] under `operation`.
    pub fn park_and_record(
        &mut self,
        key: PlacementKey,
        operation: &OperationId,
        log: &mut PlacementLog,
    ) -> Recorded<Result<(), SlotError>> {
        let generation = self.last_generation(key);
        let outcome = self.park(key);
        let recorded = outcome.as_ref().ok().map(|()| {
            self.record(
                log,
                operation.clone(),
                generation,
                PlacementEvent::Parked {
                    slot: self.spec.slot,
                    placement: key,
                },
            )
        });
        Recorded { outcome, recorded }
    }

    /// Step 7, as [`PlacementSlot::reclaim`], recorded as [`PlacementEvent::Released`]
    /// under `operation`.
    pub fn reclaim_and_record(
        &mut self,
        key: PlacementKey,
        reservations: &mut dyn ReservationPort,
        operation: &OperationId,
        log: &mut PlacementLog,
    ) -> Recorded<Result<ReclaimReport, SlotError>> {
        let generation = self.last_generation(key);
        let outcome = self.reclaim(key, reservations);
        let recorded = outcome.as_ref().ok().map(|reclaimed| {
            self.record(
                log,
                operation.clone(),
                generation,
                PlacementEvent::Released {
                    slot: self.spec.slot,
                    reclaimed: reclaimed.clone(),
                },
            )
        });
        Recorded { outcome, recorded }
    }

    /// Removes a placement that holds nothing, as [`PlacementSlot::retire`], recorded as
    /// [`PlacementEvent::Retired`] under `operation`.
    pub fn retire_and_record(
        &mut self,
        key: PlacementKey,
        operation: &OperationId,
        log: &mut PlacementLog,
    ) -> Recorded<Result<(), SlotError>> {
        let generation = self.last_generation(key);
        let outcome = self.retire(key);
        let recorded = outcome.as_ref().ok().map(|()| {
            self.record(
                log,
                operation.clone(),
                generation,
                PlacementEvent::Retired {
                    slot: self.spec.slot,
                    placement: key,
                },
            )
        });
        Recorded { outcome, recorded }
    }

    /// Records what happened to `key`, through [`PlacementSlot::record_process_exit`] or
    /// [`PlacementSlot::record_artifact_invalid`], and records a failure it caused as
    /// [`PlacementEvent::Failed`]: under the activation's operation when it failed the
    /// activation of `key`, under `operation` otherwise.
    pub fn failure_and_record(
        &mut self,
        key: PlacementKey,
        operation: &OperationId,
        log: &mut PlacementLog,
        observe: impl FnOnce(&mut Self) -> Result<Option<Failure>, SlotError>,
    ) -> Recorded<Result<Option<Failure>, SlotError>> {
        let activation = self
            .activation()
            .filter(|activation| activation.placement == key)
            .map(|activation| (activation.operation, activation.generation));
        let generation = activation
            .as_ref()
            .map(|(_, generation)| *generation)
            .or_else(|| self.last_generation(key));
        let operation = activation.map_or_else(|| operation.clone(), |(operation, _)| operation);
        let outcome = observe(self);
        let recorded = match &outcome {
            Ok(Some(failure)) => Some(self.record(
                log,
                operation,
                generation,
                PlacementEvent::Failed {
                    slot: self.spec.slot,
                    placement: key,
                    failure: *failure,
                },
            )),
            _ => None,
        };
        Recorded { outcome, recorded }
    }

    fn activation_operation(&self) -> Option<OperationId> {
        self.activation
            .as_ref()
            .map(|activation| activation.operation.clone())
    }

    /// The newest generation `key` was published under, if any.
    fn last_generation(&self, key: PlacementKey) -> Option<ModelActivationGeneration> {
        self.placement(key)
            .and_then(|view| view.generations.iter().max().copied())
    }

    fn record_ended(
        &self,
        log: &mut PlacementLog,
        operation: OperationId,
        report: Option<&AbortReport>,
    ) -> Option<Result<EventSequence, RecordError>> {
        report.map(|report| {
            self.record(
                log,
                operation,
                Some(report.generation),
                PlacementEvent::ActivationEnded {
                    slot: self.spec.slot,
                    ended: report.clone(),
                },
            )
        })
    }

    /// Seals `event` under `operation`, in its phase, with the generation it concerns, at
    /// the slot's time.
    fn record(
        &self,
        log: &mut PlacementLog,
        operation: OperationId,
        generation: Option<ModelActivationGeneration>,
        event: PlacementEvent,
    ) -> Result<EventSequence, RecordError> {
        let generations = generation.map_or(Generations::NONE, |generation| {
            Generations::NONE.with_model_activation(generation)
        });
        let context = EventContext::new(operation, event.phase()).with_generations(generations);
        log.record(context, self.now(), event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::events::{DurableReader, EventEnvelope, LogEntry, ReadItem, StreamKind};
    use crate::model_memory::placement::test_support::*;
    use crate::model_memory::placement::{ProcessInstance, TransitionMode, ValidationReport};

    fn stream_id() -> DurableStreamId {
        DurableStreamId::new("model.placements").unwrap()
    }

    fn open(directory: &Path, segment_bytes: u64) -> PlacementLog {
        open_placement_log(
            directory,
            stream_id(),
            ProducerId::new("model_memory.placements").unwrap(),
            LogConfig {
                max_entries: 1_000,
                max_bytes: 1 << 24,
                segment_entries: 4,
                segment_bytes,
            },
        )
        .unwrap()
        .0
    }

    fn events_of(log: &PlacementLog) -> Vec<EventEnvelope<PlacementEvent>> {
        log.log()
            .read(&log.log().start(), usize::MAX)
            .unwrap()
            .items
            .into_iter()
            .filter_map(|item| match item {
                ReadItem::Entry {
                    entry: LogEntry::Record(event),
                    ..
                } => Some(event),
                _ => None,
            })
            .collect()
    }

    fn kept<T>(recorded: &Recorded<T>) -> u64 {
        match &recorded.recorded {
            Some(Ok(sequence)) => sequence.get(),
            other => panic!("not recorded: {other:?}"),
        }
    }

    fn name(event: &PlacementEvent) -> &'static str {
        match event {
            PlacementEvent::Prepared { .. } => "prepared",
            PlacementEvent::Activated { .. } => "activated",
            PlacementEvent::ActivationEnded { .. } => "activation_ended",
            PlacementEvent::Failed { .. } => "failed",
            PlacementEvent::Parked { .. } => "parked",
            PlacementEvent::Released { .. } => "released",
            PlacementEvent::Retired { .. } => "retired",
        }
    }

    #[test]
    fn a_placement_lifecycle_is_recorded_as_the_slot_decides_it() {
        let directory = tempfile::tempdir().unwrap();
        let mut log = open(directory.path(), 1 << 16);
        let mut world = World::new(32 * GB);
        let first = request("model-a", &model_a(), &[]);
        let prepared =
            world
                .slot
                .begin_activation_and_record(&first, &mut world.fakes.ports(), &mut log);
        assert_eq!(kept(&prepared), 1);
        let started = prepared.outcome.unwrap();
        world.load();
        world.validate_and_ready();
        let activated = world
            .slot
            .publish_and_record(&mut world.fakes.ports(), &mut log);
        assert_eq!(kept(&activated), 2);
        let first_generation = activated.outcome.unwrap().generation;

        // A new version replaces it, overlapping.
        let second = request("model-b", &model_b(), &[]);
        let replacing =
            world
                .slot
                .begin_activation_and_record(&second, &mut world.fakes.ports(), &mut log);
        assert_eq!(replacing.outcome.unwrap().mode, TransitionMode::Overlap);
        world.load();
        // A step that completes decides nothing to record.
        let step = world
            .slot
            .step_and_record(&mut log, |slot| slot.begin_activating());
        assert_eq!(step.recorded, None);
        let activation = world.slot.activation().unwrap();
        world
            .slot
            .record_validation(
                &validation(activation.generation, 0),
                &mut world.fakes.ports(),
            )
            .unwrap();
        world
            .slot
            .record_readiness(
                activation.generation,
                rank(0),
                &ready(),
                &mut world.fakes.ports(),
            )
            .unwrap();
        let replaced = world
            .slot
            .publish_and_record(&mut world.fakes.ports(), &mut log);
        let second_generation = replaced.outcome.unwrap().generation;

        // Steps 6 and 7 for the old placement, under the replacing activation's operation.
        let old = started.placement;
        assert!(world
            .slot
            .drain_status(old, &world.fakes.coordination)
            .unwrap()
            .is_drained());
        let parked = world.slot.park_and_record(old, &second.operation, &mut log);
        assert_eq!(parked.outcome, Ok(()));
        let released = world.slot.reclaim_and_record(
            old,
            &mut world.fakes.reservations,
            &second.operation,
            &mut log,
        );
        let reclaimed = released.outcome.clone().unwrap();
        let retired = world
            .slot
            .retire_and_record(old, &second.operation, &mut log);
        assert_eq!(retired.outcome, Ok(()));
        // A refused decision records nothing.
        let refused = world.slot.park_and_record(old, &second.operation, &mut log);
        assert!(refused.outcome.is_err());
        assert_eq!(refused.recorded, None);

        let events = events_of(&log);
        assert_eq!(
            events
                .iter()
                .map(|event| name(event.payload()))
                .collect::<Vec<_>>(),
            [
                "prepared",
                "activated",
                "prepared",
                "activated",
                "parked",
                "released",
                "retired"
            ]
        );
        assert_eq!(
            events.iter().map(|event| event.phase()).collect::<Vec<_>>(),
            [
                Phase::Loading,
                Phase::Running,
                Phase::Loading,
                Phase::Running,
                Phase::Draining,
                Phase::Releasing,
                Phase::Completed
            ]
        );
        assert!(events
            .iter()
            .all(|event| event.stream() == StreamKind::Progress));
        assert_eq!(
            events
                .iter()
                .map(|event| event.generations().model_activation)
                .collect::<Vec<_>>(),
            [
                Some(first_generation),
                Some(first_generation),
                Some(second_generation),
                Some(second_generation),
                Some(first_generation),
                None,
                None
            ]
        );
        assert!(matches!(
            events[0].payload(),
            PlacementEvent::Prepared { started: recorded, reused: false, artifact_identity, .. }
                if *recorded == started && artifact_identity == first.identity.artifact.digest()
        ));
        assert!(matches!(
            events[3].payload(),
            PlacementEvent::Activated { published, .. }
                if published.previous == Some(first_generation)
        ));
        assert!(matches!(
            events[5].payload(),
            PlacementEvent::Released { reclaimed: report, .. } if *report == reclaimed
        ));
        // Each activation's decisions correlate by its operation, here and in a reader
        // that does not own the stream.
        assert_eq!(
            log.log().correlate(&first.operation).unwrap().records.len(),
            2
        );
        let mut reader =
            DurableReader::<EventEnvelope<PlacementEvent>>::open(directory.path(), stream_id())
                .unwrap();
        let correlation = reader.correlate(&second.operation).unwrap();
        assert_eq!(correlation.records.len(), 5);
        assert!(correlation.gaps.is_empty());
    }

    #[test]
    fn an_activation_or_a_placement_that_ends_without_serving_is_recorded() {
        let directory = tempfile::tempdir().unwrap();
        let mut log = open(directory.path(), 1 << 16);
        let mut world = World::new(80 * GB);

        // Cancelled.
        let first = request("model-a", &model_a(), &[]);
        let prepared =
            world
                .slot
                .begin_activation_and_record(&first, &mut world.fakes.ports(), &mut log);
        assert_eq!(kept(&prepared), 1);
        let cancelled = world.slot.end_and_record(&mut log, |slot| {
            slot.cancel_activation(&mut world.fakes.ports())
        });
        assert_eq!(kept(&cancelled), 2);
        assert_eq!(cancelled.outcome.unwrap().reason, FailureReason::Cancelled);

        // Failed at a step: one rank's weights do not verify.
        let second = request("model-b", &model_b(), &[]);
        world
            .slot
            .begin_activation_and_record(&second, &mut world.fakes.ports(), &mut log)
            .outcome
            .unwrap();
        world.load();
        world.slot.begin_activating().unwrap();
        let generation = world.slot.activation().unwrap().generation;
        let failed = world.slot.step_and_record(&mut log, |slot| {
            slot.record_validation(
                &ValidationReport {
                    weights_verified: false,
                    ..validation(generation, 0)
                },
                &mut world.fakes.ports(),
            )
        });
        assert!(matches!(
            failed.outcome,
            Err(ActivationError::Failed { .. })
        ));
        assert_eq!(kept(&failed), 4);

        // A serving placement whose process exits fails outside any activation.
        let third = request("model-a", &model_a(), &[]);
        let serving = world.activate(&third).placement;
        let exited = world.slot.failure_and_record(
            serving,
            &OperationId::new("op-process-watch").unwrap(),
            &mut log,
            |slot| slot.record_process_exit(serving, &mut world.fakes.ports()),
        );
        assert!(matches!(exited.outcome, Ok(Some(_))));
        assert_eq!(kept(&exited), 5);
        // Nothing failed: nothing to record.
        let quiet = world.slot.failure_and_record(
            serving,
            &OperationId::new("op-process-watch").unwrap(),
            &mut log,
            |slot| slot.record_process_exit(serving, &mut world.fakes.ports()),
        );
        assert_eq!(quiet.outcome, Ok(None));
        assert_eq!(quiet.recorded, None);

        let events = events_of(&log);
        assert_eq!(
            events
                .iter()
                .map(|event| (
                    name(event.payload()),
                    event.phase(),
                    event.operation().as_str()
                ))
                .collect::<Vec<_>>(),
            [
                ("prepared", Phase::Loading, "activate-model-a"),
                ("activation_ended", Phase::Cancelled, "activate-model-a"),
                ("prepared", Phase::Loading, "activate-model-b"),
                ("activation_ended", Phase::Failed, "activate-model-b"),
                ("failed", Phase::Failed, "op-process-watch"),
            ]
        );
        assert!(matches!(
            events[4].payload(),
            PlacementEvent::Failed { placement, failure, .. }
                if *placement == serving && failure.reason == FailureReason::ProcessExited
        ));
        // The slot starts a process for it again, as nothing recorded changed the slot.
        world
            .slot
            .record_process_started(serving, ProcessInstance::new(2))
            .unwrap();
    }

    #[test]
    fn a_refused_record_is_reported_and_the_decision_stands() {
        let directory = tempfile::tempdir().unwrap();
        // Segments too small for any event: every record is refused.
        let mut log = open(directory.path(), 64);
        let mut world = World::new(32 * GB);
        let first = request("model-a", &model_a(), &[]);
        let prepared =
            world
                .slot
                .begin_activation_and_record(&first, &mut world.fakes.ports(), &mut log);
        assert!(matches!(
            prepared.recorded,
            Some(Err(RecordError::Log(LogError::TooLarge { .. })))
        ));
        // The activation began all the same.
        let started = prepared.outcome.unwrap();
        assert_eq!(
            world.slot.activation().unwrap().generation,
            started.generation
        );
        assert!(events_of(&log).is_empty());
    }

    #[test]
    fn events_read_back_strictly() {
        let mut world = World::new(32 * GB);
        let directory = tempfile::tempdir().unwrap();
        let mut log = open(directory.path(), 1 << 16);
        let first = request("model-a", &model_a(), &[]);
        world
            .slot
            .begin_activation_and_record(&first, &mut world.fakes.ports(), &mut log)
            .outcome
            .unwrap();
        let event = events_of(&log).remove(0).payload().clone();
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(
            serde_json::from_value::<PlacementEvent>(json.clone()).unwrap(),
            event
        );
        let mut extra = json.clone();
        extra["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<PlacementEvent>(extra).is_err());
        let mut nested = json;
        nested["started"]["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<PlacementEvent>(nested).is_err());
    }
}
