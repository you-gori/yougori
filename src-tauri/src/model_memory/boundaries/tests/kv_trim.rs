//! Trimming KV increments before reclaim (G06: "trimming increments before reclaim";
//! GPU-W10 line 1305, acceptance line 1310). Increments no lease needs are handed back
//! while the generation serves: they leave the pool at once and count in the ledger until
//! the runner's report of their unmapping is confirmed. The CORE-03 reclamation ladder
//! trims them as rung 2's scratch, before any costlier rung.

use std::collections::BTreeSet;

use super::governor::{activation_request, authority, residency_of, DECLARED};
use super::support::*;
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::ModelActivationGeneration;
use crate::foundation::ledger::{
    Amounts, CostPurpose, Priority, Provenance, ReclaimLadder, ReclaimStep, Requester,
    ReservationId, ReservationRequest, ReservationState, StepOutcome,
};
use crate::model_memory::boundaries::*;
use crate::model_memory::placement::RequestShape;
use crate::model_memory::reclaim::{
    register_model_reclaimers, ModelReclaimer, ReclaimUnusedScratch,
};

const KIB: u64 = 1 << 10;

/// 128 KiB of KV per token, grown 256 MiB at a time, in a 2 GiB pool.
const GROWING: KvSpec = KvSpec {
    bytes_per_token: 128 * KIB,
    pool_bytes: 2 * GIB,
    growth: KvGrowth::Increments {
        increment_bytes: 256 * MIB,
    },
};

fn publish(world: &mut World, kv: KvSpec) -> ModelActivationGeneration {
    let mut request = activation_request(world, "activation");
    if let Some(spec) = request.spec.as_mut() {
        spec.kv = kv;
        spec.declared = DECLARED;
    }
    let pending = world.governor.admit(&request).unwrap().activation.unwrap();
    let residency = residency_of(world);
    world
        .governor
        .publish_activation(pending, residency)
        .unwrap()
}

fn lease(
    world: &mut World,
    name: &str,
    generation: ModelActivationGeneration,
    shape: RequestShape,
) -> ExecutionLease {
    let placement = world.placement(world.scenario.model_a);
    let authority = authority(world, name);
    world
        .governor
        .lease_execution(&authority, &placement, generation, shape)
        .unwrap()
}

fn usage(world: &World, generation: ModelActivationGeneration) -> (u64, u64) {
    let placement = world.placement(world.scenario.model_a);
    world
        .governor
        .kv_usage(&placement, world.epoch(), generation)
        .unwrap()
}

/// The open KV increments, each with its bytes and state, oldest first: compute
/// reservations carved from the sandbox's children.
fn increments(world: &World) -> Vec<(ReservationId, u64, ReservationState)> {
    let sandbox = world.sandbox_reservation();
    let ledger = world.governor.ledger();
    let children: BTreeSet<ReservationId> = ledger
        .open_reservations()
        .filter(|record| record.parent() == Some(sandbox))
        .map(|record| record.id())
        .collect();
    ledger
        .open_reservations()
        .filter(|record| {
            record
                .parent()
                .is_some_and(|parent| children.contains(&parent))
                && record.provenance().purpose == CostPurpose::Compute
        })
        .map(|record| {
            (
                record.id(),
                record.granted().get(vram_key(gpu(0))),
                record.state(),
            )
        })
        .collect()
}

/// The generation's own reservation the increments are carved from, with its room left.
fn own_room(world: &World) -> (ReservationId, u64) {
    let ledger = world.governor.ledger();
    let (increment, ..) = increments(world)[0];
    let own = ledger.reservation(increment).unwrap().parent().unwrap();
    (own, ledger.parent_room(own, vram_key(gpu(0))).unwrap())
}

#[test]
fn increments_no_lease_needs_are_trimmed_while_the_generation_serves() {
    let mut world = World::new();
    let generation = publish(&mut world, GROWING);
    let placement = world.placement(world.scenario.model_a);
    let epoch = world.epoch();
    let first = lease(&mut world, "first", generation, shape(1_024));
    let mut held = Vec::new();
    for name in ["second", "third", "fourth"] {
        held.push(lease(&mut world, name, generation, shape(4_096)));
    }
    assert_eq!(usage(&world, generation), (1_792 * MIB, 1_664 * MIB));
    for lease in held {
        world.governor.release_execution_lease(lease).unwrap();
    }
    // The committed pool stays until trimmed; only what the one lease needs must stay.
    assert_eq!(usage(&world, generation), (1_792 * MIB, 128 * MIB));
    let (own, room) = own_room(&world);
    let trimmable = world
        .governor
        .kv_trimmable(&placement, epoch, generation)
        .unwrap();
    assert_eq!(trimmable.len(), 6);
    let all = increments(&world);
    assert_eq!(
        trimmable
            .iter()
            .map(|increment| increment.reservation)
            .collect::<Vec<_>>(),
        all.iter()
            .rev()
            .take(6)
            .map(|(reservation, ..)| *reservation)
            .collect::<Vec<_>>(),
        "newest first"
    );

    let trimmed = world
        .governor
        .trim_kv(&placement, epoch, generation)
        .unwrap();
    assert_eq!(trimmed, trimmable);
    assert_eq!(usage(&world, generation), (256 * MIB, 128 * MIB));
    // Trimmed increments release in the ledger, and count until the unmapping is seen.
    let states: Vec<ReservationState> = increments(&world)
        .into_iter()
        .map(|(_, _, state)| state)
        .collect();
    assert_eq!(states.len(), 7);
    assert_eq!(
        states
            .iter()
            .filter(|state| **state == ReservationState::Releasing)
            .count(),
        6
    );
    assert_eq!(own_room(&world), (own, room));
    assert_eq!(
        world
            .governor
            .kv_releasing(&placement, epoch, generation)
            .unwrap(),
        trimmed
    );
    assert!(world
        .governor
        .kv_trimmable(&placement, epoch, generation)
        .unwrap()
        .is_empty());

    // Only the runtime's own report or a stronger source confirms the unmapping.
    assert_eq!(
        world
            .governor
            .confirm_kv_trimmed(&placement, epoch, generation, SourceClass::Fixture)
            .unwrap_err(),
        KvTrimRefusal::ReleaseSourceTooWeak {
            source: SourceClass::Fixture
        }
    );
    let confirmed = world
        .governor
        .confirm_kv_trimmed(&placement, epoch, generation, SourceClass::GuestReport)
        .unwrap();
    assert_eq!(confirmed, trimmed);
    assert_eq!(increments(&world).len(), 1);
    assert_eq!(own_room(&world), (own, room + 6 * 256 * MIB));
    assert!(world
        .governor
        .kv_releasing(&placement, epoch, generation)
        .unwrap()
        .is_empty());

    // A later request grows the pool again, inside the generation's own reservation.
    let again = lease(&mut world, "again", generation, shape(4_096));
    assert_eq!(usage(&world, generation), (768 * MIB, 640 * MIB));
    assert_eq!(increments(&world).len(), 3);
    for lease in [first, again] {
        world.governor.release_execution_lease(lease).unwrap();
    }
}

#[test]
fn a_pool_held_whole_trims_nothing_and_reclaim_hands_back_what_is_still_releasing() {
    let mut world = World::new();
    let whole = publish(&mut world, KvSpec::bounded_by_pool(2 * GIB, &DECLARED));
    let placement = world.placement(world.scenario.model_a);
    let epoch = world.epoch();
    assert!(world
        .governor
        .kv_trimmable(&placement, epoch, whole)
        .unwrap()
        .is_empty());
    assert!(world
        .governor
        .trim_kv(&placement, epoch, whole)
        .unwrap()
        .is_empty());
    assert_eq!(
        world
            .governor
            .trim_kv(&placement, epoch, whole.next().unwrap()),
        Err(KvTrimRefusal::NoPool)
    );

    // A growing generation trimmed but not yet confirmed is reclaimed: everything,
    // releasing increments included, is handed back with it.
    let mut world = World::new();
    let generation = publish(&mut world, GROWING);
    let (placement, epoch) = (world.placement(world.scenario.model_a), world.epoch());
    let held = lease(&mut world, "held", generation, shape(4_096));
    world.governor.release_execution_lease(held).unwrap();
    let trimmed = world
        .governor
        .trim_kv(&placement, epoch, generation)
        .unwrap();
    assert_eq!(trimmed.len(), 2);
    let next = publish(&mut world, GROWING);
    assert!(world
        .governor
        .confirm_released(&placement, generation, SourceClass::GuestReport)
        .unwrap());
    assert!(increments(&world).is_empty());
    assert_eq!(usage(&world, next), (0, 0));
}

#[test]
fn the_reclamation_ladder_trims_unused_kv_as_scratch() {
    let mut world = World::new();
    let generation = publish(&mut world, GROWING);
    let placement = world.placement(world.scenario.model_a);
    let epoch = world.epoch();
    let first = lease(&mut world, "first", generation, shape(1_024));
    let mut held = Vec::new();
    for name in ["second", "third", "fourth"] {
        held.push(lease(&mut world, name, generation, shape(4_096)));
    }
    for lease in held {
        world.governor.release_execution_lease(lease).unwrap();
    }
    let (own, room) = own_room(&world);
    // A foreground child of the generation's own reservation, such as an adapter, needs
    // 512 MiB more than the room the committed KV leaves.
    let needed = room + 512 * MIB;
    let request = ReservationRequest::new(
        Provenance {
            requester: Requester::ModelPlacement,
            execution: owner(),
            operation: op("adapter"),
            tenant: tenant(),
            purpose: CostPurpose::Compute,
            retry_number: 0,
        },
        Priority::Foreground,
        Amounts::new().with(vram_key(gpu(0)), needed),
    )
    .within(own);

    let mut step = ReclaimUnusedScratch::new(Requester::ModelPlacement);
    let survey = step
        .prepare(&mut KvScratch::new(&mut world.governor))
        .unwrap();
    // Six unused increments are free scratch; the one under the lease is held by it.
    assert_eq!((survey.free, survey.leased, survey.pinned), (6, 1, 0));
    let admission = {
        let mut ladder = ReclaimLadder::new();
        register_model_reclaimers(&mut ladder, [&mut step as &mut dyn ModelReclaimer]);
        world
            .governor
            .coordinator_mut()
            .capacity_mut()
            .write_ledger(|ledger| ledger.reserve_reclaiming(request.clone(), &mut ladder))
    };
    let report = &admission.report;
    // Rung 2 trims the KV; the costlier rungs after it, parking included, are not asked
    // for anything.
    let steps: Vec<ReclaimStep> = report.steps().iter().map(|step| step.step).collect();
    assert_eq!(steps, ReclaimStep::ORDER);
    let scratch = &report.steps()[1];
    assert_eq!(scratch.step, ReclaimStep::ReclaimUnusedScratch);
    assert_eq!(scratch.owner, Some(Requester::ModelPlacement));
    for (index, other) in report.steps().iter().enumerate() {
        if index != 1 {
            assert_eq!(other.outcome, StepOutcome::NotRegistered, "{}", other.step);
        }
    }
    let StepOutcome::Released { releasing, .. } = &scratch.outcome else {
        panic!("rung 2 trimmed nothing: {report}");
    };
    // Only what covers the shortfall, newest first.
    assert_eq!(releasing.len(), 2);
    let settlement = step
        .settle(report, &mut KvScratch::new(&mut world.governor))
        .unwrap();
    assert_eq!(settlement.stopped.len(), 2);
    let releasing_now: Vec<ReservationId> = world
        .governor
        .kv_releasing(&placement, epoch, generation)
        .unwrap()
        .into_iter()
        .map(|increment| increment.reservation)
        .collect();
    assert_eq!(
        releasing_now.iter().copied().collect::<BTreeSet<_>>(),
        settlement
            .awaiting_release()
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(usage(&world, generation), (1_280 * MIB, 128 * MIB));

    // Once the runner unmapped them, the child fits.
    if let Ok(crate::foundation::ledger::Admission::Queued { ticket, .. }) = &admission.admission {
        world
            .governor
            .coordinator_mut()
            .capacity_mut()
            .write_ledger(|ledger| ledger.cancel_queued(*ticket))
            .unwrap();
    }
    world
        .governor
        .confirm_kv_trimmed(&placement, epoch, generation, SourceClass::GuestReport)
        .unwrap();
    assert_eq!(own_room(&world), (own, room + 512 * MIB));
    let granted = world
        .governor
        .coordinator_mut()
        .capacity_mut()
        .write_ledger(|ledger| ledger.reserve(request));
    assert!(matches!(
        granted,
        Ok(crate::foundation::ledger::Admission::Granted(_))
    ));
    world.governor.release_execution_lease(first).unwrap();
}
