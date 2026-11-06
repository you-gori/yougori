//! S06: every decision the governor makes in a placement's slot is recorded on the model
//! lifecycle stream through CORE-06 under its operation: an activation's steps,
//! publication and end under its own, parking, reclaiming and retiring under the operation
//! of the activation that replaced the placement. Without a log the governor decides
//! exactly as before, and a record the stream refuses is reported in a bounded report
//! while the decision stands.

use std::path::Path;

use super::governor::{activation_request, residency_of};
use super::reload_resume::{pause_longer, publish, resumed, Paused, LONGER};
use super::support::*;
use crate::foundation::events::{
    DurableReader, DurableStreamId, EventEnvelope, LogConfig, LogEntry, LogError, Phase,
    ProducerId, ReadItem, RecordError,
};
use crate::foundation::evidence::SourceClass;
use crate::model_memory::boundaries::*;
use crate::model_memory::placement::{
    open_placement_log, PlacementEvent, PlacementLog, TransitionMode,
};

fn stream_id() -> DurableStreamId {
    DurableStreamId::new("model.placements").unwrap()
}

/// The model lifecycle stream in `directory`; segments of `segment_bytes`, so a small
/// value refuses every record.
fn open(directory: &Path, segment_bytes: u64) -> PlacementLog {
    open_placement_log(
        directory,
        stream_id(),
        ProducerId::new("model_memory.placements").unwrap(),
        LogConfig {
            max_entries: 1_000,
            max_bytes: 1 << 24,
            segment_entries: 8,
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

/// Each event's name and operation, in order.
fn recorded(log: &PlacementLog) -> Vec<(&'static str, String)> {
    events_of(log)
        .iter()
        .map(|event| (name(event.payload()), event.operation().as_str().to_owned()))
        .collect()
}

fn named(expected: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    expected
        .iter()
        .map(|(name, operation)| (*name, (*operation).to_owned()))
        .collect()
}

/// Model A's activation named `name` with adapter B and the longer context, which fits
/// beside the first generation.
fn adapter_b_request(world: &World, name: &str) -> AdmissionRequest {
    let mut request = activation_request(world, name);
    let spec = request.spec.as_mut().unwrap();
    for extent in &mut spec.extents {
        if extent.identity == state("adapter-a") {
            extent.identity = state("adapter-b");
        }
    }
    spec.declared = LONGER;
    request
}

/// One placement's life through the governor: a first generation served through the flow,
/// a second that replaces it overlapping, the first reclaimed, and an activation abandoned
/// and reclaimed. Returns every outcome, to compare runs.
fn lifecycle(world: &mut World) -> Vec<String> {
    let a = world.scenario.model_a;
    let placement = world.placement(a);
    let mut outcomes = Vec::new();
    let request = world.request("first", a);
    let first = world.serve(&request).unwrap().generation;
    outcomes.push(format!("{first:?}"));

    let pending = world
        .governor
        .admit(&adapter_b_request(world, "b"))
        .unwrap()
        .activation
        .unwrap();
    assert_eq!(pending.mode(), TransitionMode::Overlap);
    let residency = residency_of(world);
    outcomes.push(format!(
        "{:?}",
        world.governor.publish_activation(pending, residency)
    ));
    outcomes.push(format!(
        "{:?}",
        world
            .governor
            .confirm_released(&placement, first, SourceClass::GuestReport)
    ));
    outcomes.push(format!("{:?}", world.holdings()));

    let pending = world
        .governor
        .admit(&activation_request(world, "dropped"))
        .unwrap()
        .activation
        .unwrap();
    let dropped = pending.generation();
    outcomes.push(format!("{:?}", world.governor.abandon_activation(pending)));
    outcomes.push(format!(
        "{:?}",
        world
            .governor
            .confirm_released(&placement, dropped, SourceClass::GuestReport)
    ));
    outcomes.push(format!("{:?}", world.holdings()));
    outcomes.push(format!(
        "{:?}",
        world.governor.current_residency(&placement)
    ));
    outcomes
}

/// The events [`lifecycle`] records, each with its operation.
const LIFECYCLE: [(&str, &str); 11] = [
    ("prepared", "first"),
    ("activated", "first"),
    ("prepared", "b"),
    ("activated", "b"),
    // The first placement drained, is parked, released and retired under the operation
    // that replaced it.
    ("parked", "b"),
    ("released", "b"),
    ("retired", "b"),
    ("prepared", "dropped"),
    ("activation_ended", "dropped"),
    ("released", "dropped"),
    ("retired", "dropped"),
];

#[test]
fn every_decision_the_governor_makes_is_recorded_under_its_operation() {
    let directory = tempfile::tempdir().unwrap();
    let mut world = World::new();
    assert!(world
        .governor
        .record_lifecycle(open(directory.path(), 1 << 16))
        .is_none());
    lifecycle(&mut world);

    let log = world.governor.placement_log().unwrap();
    assert_eq!(recorded(log), named(&LIFECYCLE));
    let events = events_of(log);
    assert_eq!(
        events.iter().map(|event| event.phase()).collect::<Vec<_>>(),
        [
            Phase::Loading,
            Phase::Running,
            Phase::Loading,
            Phase::Running,
            Phase::Draining,
            Phase::Releasing,
            Phase::Completed,
            Phase::Loading,
            Phase::Cancelled,
            Phase::Releasing,
            Phase::Completed,
        ]
    );
    // Each event carries the generation its decision concerns while one is known.
    let generation = |index: usize| events[index].generations().model_activation;
    let first = generation(0).unwrap();
    let second = generation(2).unwrap();
    assert_eq!(generation(1), Some(first));
    assert_eq!(generation(3), Some(second));
    assert_eq!(generation(4), Some(first));
    assert!(matches!(
        events[3].payload(),
        PlacementEvent::Activated { published, .. } if published.previous == Some(first)
    ));
    assert!(matches!(
        events[8].payload(),
        PlacementEvent::ActivationEnded { ended, .. } if ended.generation == second.next().unwrap()
    ));
    // The replacing activation's decisions correlate by its operation, also for a reader
    // that does not own the stream.
    let mut reader =
        DurableReader::<EventEnvelope<PlacementEvent>>::open(directory.path(), stream_id())
            .unwrap();
    assert_eq!(reader.correlate(&op("b")).unwrap().records.len(), 5);
    assert_eq!(
        world.governor.take_recording_report(),
        RecordingReport {
            recorded: 11,
            ..RecordingReport::default()
        }
    );
    assert_eq!(
        world.governor.take_recording_report(),
        RecordingReport::default()
    );
}

#[test]
fn without_a_log_the_governor_decides_exactly_as_before() {
    let directory = tempfile::tempdir().unwrap();
    let mut recording = World::new();
    recording
        .governor
        .record_lifecycle(open(directory.path(), 1 << 16));
    let mut plain = World::new();
    assert_eq!(lifecycle(&mut recording), lifecycle(&mut plain));
    assert!(plain.governor.placement_log().is_none());
    assert_eq!(
        plain.governor.take_recording_report(),
        RecordingReport::default()
    );

    // Recording stops: the log comes back whole, and later decisions are only made.
    let log = recording.governor.stop_recording().unwrap();
    assert_eq!(recorded(&log), named(&LIFECYCLE));
    let pending = recording
        .governor
        .admit(&activation_request(&recording, "unrecorded"))
        .unwrap()
        .activation
        .unwrap();
    recording.governor.abandon_activation(pending).unwrap();
    assert_eq!(recorded(&log), named(&LIFECYCLE));
    assert_eq!(recording.governor.take_recording_report().recorded, 11);
    log.close().unwrap();
}

#[test]
fn a_refused_record_is_reported_and_the_decision_stands() {
    let directory = tempfile::tempdir().unwrap();
    // Segments too small for any event: the stream refuses every record.
    let mut refusing = World::new();
    refusing
        .governor
        .record_lifecycle(open(directory.path(), 64));
    let mut plain = World::new();
    assert_eq!(lifecycle(&mut refusing), lifecycle(&mut plain));
    assert!(events_of(refusing.governor.placement_log().unwrap()).is_empty());

    let report = refusing.governor.take_recording_report();
    assert_eq!(report.recorded, 0);
    assert_eq!(report.unrecorded_beyond_bound, 0);
    let placement = refusing.placement(refusing.scenario.model_a);
    assert!(report.unrecorded.iter().all(|unrecorded| {
        unrecorded.placement == placement
            && unrecorded.epoch == refusing.epoch()
            && matches!(
                unrecorded.error,
                RecordError::Log(LogError::TooLarge { .. })
            )
    }));
    assert_eq!(
        report
            .unrecorded
            .iter()
            .map(|unrecorded| (unrecorded.decision, unrecorded.operation.as_str()))
            .collect::<Vec<_>>(),
        [
            (LifecycleDecision::Prepare, "first"),
            (LifecycleDecision::Publish, "first"),
            (LifecycleDecision::Prepare, "b"),
            (LifecycleDecision::Publish, "b"),
            (LifecycleDecision::Park, "b"),
            (LifecycleDecision::Reclaim, "b"),
            (LifecycleDecision::Retire, "b"),
            (LifecycleDecision::Prepare, "dropped"),
            (LifecycleDecision::End, "dropped"),
            (LifecycleDecision::Reclaim, "dropped"),
            (LifecycleDecision::Retire, "dropped"),
        ]
    );

    // The report is bounded: past MAX_UNRECORDED the oldest refusals are only counted.
    let cycles = MAX_UNRECORDED / 4 + 1;
    for cycle in 0..cycles {
        let name = format!("cycle-{cycle}");
        let pending = refusing
            .governor
            .admit(&activation_request(&refusing, &name))
            .unwrap()
            .activation
            .unwrap();
        let generation = pending.generation();
        refusing.governor.abandon_activation(pending).unwrap();
        assert!(refusing
            .governor
            .confirm_released(&placement, generation, SourceClass::GuestReport)
            .unwrap());
    }
    let report = refusing.governor.take_recording_report();
    assert_eq!(report.unrecorded.len(), MAX_UNRECORDED);
    assert_eq!(
        report.unrecorded_beyond_bound,
        u64::try_from(cycles * 4 - MAX_UNRECORDED).unwrap()
    );
    let last = format!("cycle-{}", cycles - 1);
    assert_eq!(
        report.unrecorded.last().map(|unrecorded| (
            unrecorded.decision,
            unrecorded.operation.as_str().to_owned()
        )),
        Some((LifecycleDecision::Retire, last))
    );
}

#[test]
fn a_reload_is_recorded_from_its_pause_to_its_publication_or_its_end() {
    let directory = tempfile::tempdir().unwrap();
    let mut world = World::new();
    world
        .governor
        .record_lifecycle(open(directory.path(), 1 << 16));
    let Paused { first, old, .. } = pause_longer(&mut world);
    world.governor.release_execution_lease(old).unwrap();
    let (_, admission) = resumed(world.governor.resume_reloads().remove(0));
    let pending = admission.activation.unwrap();
    world
        .governor
        .hand_over(&pending, SourceClass::GuestReport)
        .unwrap();
    let reloaded = publish(&mut world, pending);

    // The reload began the pause, and its operation covers the old placement's release
    // at the handover and the publication that ended the pause.
    let log = world.governor.placement_log().unwrap();
    assert_eq!(
        recorded(log),
        named(&[
            ("prepared", "first"),
            ("activated", "first"),
            ("prepared", "longer"),
            ("parked", "longer"),
            ("released", "longer"),
            ("retired", "longer"),
            ("activated", "longer"),
        ])
    );
    let events = events_of(log);
    assert!(matches!(
        events[2].payload(),
        PlacementEvent::Prepared { started, .. }
            if started.mode == TransitionMode::DrainFirst && started.pause.is_some()
    ));
    assert!(matches!(
        events[6].payload(),
        PlacementEvent::Activated { published, .. }
            if published.generation == reloaded && published.pause.is_some()
    ));
    assert_eq!(events[3].generations().model_activation, Some(first));

    // A reload that ends is recorded as an activation that ended, under its request.
    let directory = tempfile::tempdir().unwrap();
    let mut world = World::new();
    world
        .governor
        .record_lifecycle(open(directory.path(), 1 << 16));
    let Paused { first, .. } = pause_longer(&mut world);
    let model = world.placement(world.scenario.model_a).model_id();
    world
        .governor
        .coordinator_mut()
        .fail_activation(&owner(), model, first.next().unwrap())
        .unwrap();
    let ended = world.governor.resume_reloads();
    assert!(matches!(
        ended.as_slice(),
        [ReloadResumption::Ended(ended)] if matches!(ended.end, ReloadEnd::Superseded { .. })
    ));
    assert_eq!(
        recorded(world.governor.placement_log().unwrap()),
        named(&[
            ("prepared", "first"),
            ("activated", "first"),
            ("prepared", "longer"),
            ("activation_ended", "longer"),
            ("released", "longer"),
            ("retired", "longer"),
        ])
    );
}
