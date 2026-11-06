//! The mapping protocol (§3.7; Appendix E steps 1–6): reserve, create, map, set access,
//! populate, and publish only after completion; unmap only when quiescent; retained
//! tensors never callable while unmapped.

use super::*;
use crate::foundation::ids::GpuAllocationGeneration;

fn map_ranges(world: &World) -> Vec<AddressRange> {
    world
        .driver
        .calls()
        .iter()
        .filter_map(|call| match call.call {
            DriverCall::Map { range, .. } => Some(range),
            _ => None,
        })
        .collect()
}

fn kernel_ranges(world: &World) -> Vec<Vec<AddressRange>> {
    world
        .driver
        .calls()
        .iter()
        .filter_map(|call| match &call.call {
            DriverCall::Enqueue {
                work: WorkKind::Kernel,
                ranges,
                ..
            } => Some(ranges.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn appendix_e_sequence_on_the_fake_driver() {
    let mut world = World::new();
    let key = world.load(P1, "model", &[4 * MIB, 4 * MIB, 3 * MIB], private());
    let view = world.model.create_view(key, 0, 11 * MIB).unwrap();
    let event = world.call(view).unwrap();
    world.driver.complete(event);
    let report = world.park(key, clean_drop("model")).unwrap();
    world.model.wake(key).unwrap();
    world.fill(key, "model", 3);
    world.call(view).unwrap();

    let batch = ["cuMemCreate", "cuMemMap", "cuMemSetAccess", "enqueue"];
    let mut expected = vec!["cuMemGetAllocationGranularity", "cuMemAddressReserve"];
    expected.extend(batch.repeat(3));
    expected.push("enqueue");
    expected.extend(["cuMemUnmap", "cuMemRelease"].repeat(3));
    expected.extend(batch.repeat(3));
    expected.push("enqueue");
    assert_eq!(world.calls_of(P1), expected);

    let maps = map_ranges(&world);
    assert_eq!(maps.len(), 6);
    assert_eq!(maps[..3], maps[3..], "wake maps at the same offsets");
    let reservation = world.model.reservation(key).unwrap();
    assert_eq!(reservation.length_bytes, 12 * MIB);
    for (range, offset) in maps.iter().zip([0, 4 * MIB, 8 * MIB]) {
        assert_eq!(range.start, reservation.start.checked_add(offset).unwrap());
        assert_eq!(range.length_bytes, 4 * MIB);
    }
    let kernels = kernel_ranges(&world);
    assert_eq!(
        kernels[0], kernels[1],
        "the retained view keeps its address"
    );
    assert_eq!(
        report,
        ParkReport {
            unmapped_bytes: 12 * MIB,
            released_bytes: 12 * MIB,
            device_to_host_bytes: 0,
            retained: Vec::new(),
        }
    );
    assert_eq!(
        world.model.batch(key, 0).unwrap().generation,
        Some(GpuAllocationGeneration::new(2)),
        "the woken batch is a new allocation"
    );
    assert_eq!(world.driver.used_bytes(DEVICE), 12 * MIB);
    world.assert_no_refusals();
}

#[test]
fn publication_waits_for_completion_and_verification() {
    let mut world = World::new();
    world.probe(P1, private());
    let key = world
        .plan(P1, &layout("a", &[4 * MIB]), private(), VmmOrigin::Create)
        .unwrap();
    let digest = batch_digest("a", 0);
    world.back(key, 0).unwrap();
    assert_eq!(
        world.publish(key, 0, digest),
        Err(VmmError::BatchState {
            key,
            batch: 0,
            state: BatchState::Ready,
            operation: "publish the batch",
        }),
        "nothing is published before it is populated"
    );
    let event = world.populate(key, 0).unwrap();
    assert_eq!(
        world.publish(key, 0, digest),
        Err(VmmError::NotComplete { event })
    );
    world.driver.complete(event);
    let wrong = named("tampered");
    assert_eq!(
        world.publish(key, 0, wrong),
        Err(VmmError::DigestMismatch {
            key,
            batch: 0,
            expected: digest,
            found: wrong,
        })
    );
    assert_eq!(
        world.model.batch(key, 0).unwrap().state,
        BatchState::Rejected
    );
    let view = world.model.create_view(key, 0, 4 * MIB).unwrap();
    assert_eq!(
        world.call(view),
        Err(VmmError::NotCallable {
            key,
            reason: NotCallableReason::NotPublished { batch: 0 },
        }),
        "a rejected batch is never used"
    );
    assert_eq!(
        world.publish(key, 0, digest),
        Err(VmmError::BatchState {
            key,
            batch: 0,
            state: BatchState::Rejected,
            operation: "publish the batch",
        }),
        "a rejected batch is populated again before it is published"
    );
    let event = world.populate(key, 0).unwrap();
    world.driver.complete(event);
    world.publish(key, 0, digest).unwrap();
    assert!(world.call(view).is_ok());
    world.assert_no_refusals();
}

#[test]
fn views_are_callable_only_over_published_batches() {
    let mut world = World::new();
    world.probe(P1, private());
    let key = world
        .plan(
            P1,
            &layout("a", &[4 * MIB, 4 * MIB]),
            private(),
            VmmOrigin::Create,
        )
        .unwrap();
    world.back(key, 0).unwrap();
    let event = world.populate(key, 0).unwrap();
    world.driver.complete(event);
    world.publish(key, 0, batch_digest("a", 0)).unwrap();
    let first = world.model.create_view(key, 0, 4 * MIB).unwrap();
    let spanning = world.model.create_view(key, 2 * MIB, 4 * MIB).unwrap();
    assert!(world.call(first).is_ok());
    assert_eq!(
        world.call(spanning),
        Err(VmmError::NotCallable {
            key,
            reason: NotCallableReason::Unmapped { batch: 1 },
        })
    );
    world.back(key, 1).unwrap();
    assert_eq!(
        world.call(spanning),
        Err(VmmError::NotCallable {
            key,
            reason: NotCallableReason::NotPublished { batch: 1 },
        })
    );
    let event = world.populate(key, 1).unwrap();
    world.driver.complete(event);
    world.publish(key, 1, batch_digest("a", 1)).unwrap();
    assert!(world.call(spanning).is_ok());
    for (offset, length) in [(8 * MIB - 1, 2), (0, 0), (u64::MAX, 2)] {
        assert!(matches!(
            world.model.create_view(key, offset, length),
            Err(VmmError::ViewOutOfRange { .. })
        ));
    }
    assert_eq!(
        world.call(ViewId::new(999)),
        Err(VmmError::UnknownView {
            view: ViewId::new(999)
        })
    );
    world.assert_no_refusals();
}

#[test]
fn unmapping_waits_for_quiescence() {
    let mut world = World::new();
    let key = world.load(P1, "a", &[4 * MIB], private());
    let view = world.model.create_view(key, 0, 4 * MIB).unwrap();
    let event = world.call(view).unwrap();
    world
        .model
        .begin_park(&mut world.driver, key, clean_drop("a"))
        .unwrap();
    assert_eq!(
        world.model.finish_park(&mut world.driver, key),
        Err(VmmError::NotQuiescent {
            events: vec![event]
        })
    );
    let start = world.model.reservation(key).unwrap().start;
    assert!(world.driver.is_mapped(P1, start), "still mapped");
    assert_eq!(
        world.call(view),
        Err(VmmError::NotCallable {
            key,
            reason: NotCallableReason::Draining,
        }),
        "no new work is admitted while draining"
    );
    world.driver.complete(event);
    world.model.finish_park(&mut world.driver, key).unwrap();
    assert!(!world.driver.is_mapped(P1, start));
    world.assert_no_refusals();
}

#[test]
fn retained_views_are_never_callable_while_unmapped() {
    let mut world = World::new();
    let key = world.load(P1, "a", &[4 * MIB], private());
    let view = world.model.create_view(key, 0, 4 * MIB).unwrap();
    world.park(key, clean_drop("a")).unwrap();
    assert_eq!(
        world.call(view),
        Err(VmmError::NotCallable {
            key,
            reason: NotCallableReason::Parked,
        })
    );
    world.model.wake(key).unwrap();
    assert_eq!(
        world.call(view),
        Err(VmmError::NotCallable {
            key,
            reason: NotCallableReason::Unmapped { batch: 0 },
        })
    );
    world.back(key, 0).unwrap();
    assert_eq!(
        world.call(view),
        Err(VmmError::NotCallable {
            key,
            reason: NotCallableReason::NotPublished { batch: 0 },
        }),
        "mapped again, but not yet refilled and verified"
    );
    let event = world.populate(key, 0).unwrap();
    world.driver.complete(event);
    world.publish(key, 0, batch_digest("a", 0)).unwrap();
    world.call(view).unwrap();
    assert_eq!(world.count_calls("enqueue"), 3);
    world.assert_no_refusals();
}

#[test]
fn the_reservation_is_made_once_and_kept() {
    let mut world = World::new();
    let key = world.load(P1, "a", &[4 * MIB], private());
    assert_eq!(
        world.plan(P1, &layout("a", &[4 * MIB]), private(), VmmOrigin::Create),
        Err(VmmError::AlreadyPlanned { key })
    );
    for _ in 0..2 {
        world.park(key, clean_drop("a")).unwrap();
        world.model.wake(key).unwrap();
        world.fill(key, "a", 1);
    }
    assert_eq!(world.count_calls("cuMemAddressReserve"), 1);
    assert_eq!(
        world.model.batch(key, 0).unwrap().generation,
        Some(GpuAllocationGeneration::new(3))
    );
}

#[test]
fn clean_drop_skips_the_device_to_host_copy() {
    let mut world = World::new();
    let key = world.load(P1, "a", &[4 * MIB, 3 * MIB], private());
    assert_eq!(
        world
            .model
            .begin_park(&mut world.driver, key, clean_drop("other")),
        Err(VmmError::CanonicalCopyMismatch {
            expected: content_of("a"),
            copy: content_of("other"),
        }),
        "a canonical copy of other content cannot rebuild this one"
    );
    assert_eq!(world.model.lifecycle(key), Some(Lifecycle::Active));
    let before = world.count_calls("enqueue");
    let report = world.park(key, clean_drop("a")).unwrap();
    assert_eq!(report.device_to_host_bytes, 0);
    assert_eq!(world.count_calls("enqueue"), before, "nothing copied back");

    let key = world.load(P1, "b", &[4 * MIB, 3 * MIB], private());
    world
        .model
        .begin_park(
            &mut world.driver,
            key,
            ParkSource::CopyBack { stream: STREAM },
        )
        .unwrap();
    let copies: Vec<u64> = world
        .driver
        .calls()
        .iter()
        .filter_map(|call| match &call.call {
            DriverCall::Enqueue {
                work: WorkKind::CopyToHost,
                ranges,
                ..
            } => Some(ranges.iter().map(|range| range.length_bytes).sum()),
            _ => None,
        })
        .collect();
    assert_eq!(copies, [4 * MIB, 3 * MIB]);
    assert!(matches!(
        world.model.finish_park(&mut world.driver, key),
        Err(VmmError::NotQuiescent { events }) if events.len() == 2
    ));
    world.driver.complete_all();
    let report = world.model.finish_park(&mut world.driver, key).unwrap();
    assert_eq!(report.device_to_host_bytes, 7 * MIB);
    world.assert_no_refusals();
}

#[test]
fn the_lifecycle_is_followed() {
    let mut world = World::new();
    let key = world.load(P1, "a", &[4 * MIB], private());
    assert_eq!(
        world.model.finish_park(&mut world.driver, key),
        Err(VmmError::NotInLifecycle {
            key,
            expected: Lifecycle::Draining,
            found: Lifecycle::Active,
        })
    );
    assert_eq!(
        world.model.wake(key),
        Err(VmmError::NotInLifecycle {
            key,
            expected: Lifecycle::Parked,
            found: Lifecycle::Active,
        })
    );
    world
        .model
        .begin_park(&mut world.driver, key, clean_drop("a"))
        .unwrap();
    assert!(matches!(
        world
            .model
            .begin_park(&mut world.driver, key, clean_drop("a")),
        Err(VmmError::NotInLifecycle { .. })
    ));
    assert!(matches!(
        world.populate(key, 0),
        Err(VmmError::NotInLifecycle { .. })
    ));
    world.model.finish_park(&mut world.driver, key).unwrap();
    assert_eq!(
        world.back(key, 0),
        Err(VmmError::NotInLifecycle {
            key,
            expected: Lifecycle::Active,
            found: Lifecycle::Parked,
        })
    );
    let unknown = MappingKey {
        process: P1,
        artifact: named("never planned"),
    };
    assert_eq!(
        world.model.wake(unknown),
        Err(VmmError::UnknownArtifact { key: unknown })
    );
}

#[test]
fn batch_states_are_followed() {
    let mut world = World::new();
    world.probe(P1, private());
    let key = world
        .plan(P1, &layout("a", &[4 * MIB]), private(), VmmOrigin::Create)
        .unwrap();
    assert_eq!(
        world.populate(key, 0),
        Err(VmmError::BatchState {
            key,
            batch: 0,
            state: BatchState::Empty,
            operation: "populate the batch",
        })
    );
    world.back(key, 0).unwrap();
    assert_eq!(
        world.back(key, 0),
        Err(VmmError::BatchState {
            key,
            batch: 0,
            state: BatchState::Ready,
            operation: "map the batch",
        })
    );
    assert_eq!(
        world.back(key, 1),
        Err(VmmError::UnknownBatch { key, batch: 1 })
    );
    let event = world.populate(key, 0).unwrap();
    assert!(matches!(
        world.populate(key, 0),
        Err(VmmError::BatchState {
            state: BatchState::Populating,
            ..
        })
    ));
    world.driver.complete(event);
    assert!(matches!(
        world.import(key, 0, ExportId::new(1)),
        Err(VmmError::WrongBacking { .. })
    ));
    assert_eq!(
        world.plan(P1, &layout("empty", &[]), private(), VmmOrigin::Create),
        Err(VmmError::EmptyLayout)
    );
    assert_eq!(
        world.plan(
            P1,
            &layout("zero", &[4 * MIB, 0]),
            private(),
            VmmOrigin::Create
        ),
        Err(VmmError::EmptyBatch { batch: 1 })
    );
}

#[test]
fn generations_never_wrap() {
    use super::super::model::next_generation;
    assert_eq!(next_generation(None), Ok(GpuAllocationGeneration::FIRST));
    assert_eq!(
        next_generation(Some(GpuAllocationGeneration::FIRST)),
        Ok(GpuAllocationGeneration::new(2))
    );
    assert_eq!(
        next_generation(Some(GpuAllocationGeneration::new(u64::MAX))),
        Err(VmmError::GenerationExhausted)
    );
}
