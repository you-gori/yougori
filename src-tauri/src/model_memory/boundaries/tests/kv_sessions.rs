//! KV of a session that stays after its lease ended (G06 follow-up; GPU §1 step 5: "release
//! leases and retain valuable state"; T08). A session the caller resumes, or one no tier
//! could take, keeps its KV in the pool's increments once its request lease ends: neither
//! trimming nor the reclamation ladder's scratch step may take them until the runner
//! dropped that KV. A session the runner released frees its KV as before.

use std::collections::BTreeSet;

use super::governor::{activation_request, authority, residency_of, DECLARED};
use super::support::*;
use crate::foundation::ledger::{
    Admission, Amounts, CostPurpose, DeclineReason, Priority, Provenance, ReclaimLadder,
    ReclaimStep, Requester, ReservationId, ReservationRequest, ReservationState, StepOutcome,
};
use crate::model_memory::boundaries::*;
use crate::model_memory::reclaim::{
    register_model_reclaimers, ModelReclaimer, ReclaimUnusedScratch,
};

const KIB: u64 = 1 << 10;

/// 128 KiB of KV per token, grown 256 MiB at a time.
const GROWING: KvLayout = KvLayout {
    bytes_per_token: 128 * KIB,
    growth: KvGrowth::Increments {
        increment_bytes: 256 * MIB,
    },
};

/// The open KV increments with their state: compute reservations carved from the
/// sandbox's children.
fn increments(world: &World) -> Vec<(ReservationId, ReservationState)> {
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
        .map(|record| (record.id(), record.state()))
        .collect()
}

/// Serves one request of 4,096 tokens through the flow on a backend that grows its KV:
/// 512 MiB in two increments.
fn serve(world: &mut World, name: &str, resume: bool) -> ServeReceipt {
    world.runner.set_kv_layout(Some(GROWING));
    let mut request = world.request(name, world.scenario.model_a);
    request.intent.policy.resume_session = resume;
    world.serve(&request).unwrap()
}

fn trimmable(world: &World, receipt: &ServeReceipt) -> usize {
    world
        .governor
        .kv_trimmable(&receipt.placement, world.epoch(), receipt.generation)
        .unwrap()
        .len()
}

#[test]
fn a_session_kept_for_resume_holds_its_kv_against_trimming_and_the_ladder() {
    let mut world = World::new();
    let receipt = serve(&mut world, "resumable", true);
    assert_eq!(receipt.session, SessionRetention::Kept);
    let (placement, epoch, generation) = (receipt.placement, world.epoch(), receipt.generation);
    // The lease ended; its KV stays committed for the session.
    assert_eq!(
        world.governor.kv_usage(&placement, epoch, generation),
        Some((512 * MIB, 0))
    );
    assert_eq!(
        world.governor.kv_sessions(&placement, epoch, generation),
        Some(vec![(op("resumable"), 512 * MIB)])
    );
    assert_eq!(trimmable(&world, &receipt), 0);
    assert!(world
        .governor
        .trim_kv(&placement, epoch, generation)
        .unwrap()
        .is_empty());

    // The ladder's scratch step finds the increments pinned by the live session.
    let mut step = ReclaimUnusedScratch::new(Requester::ModelPlacement);
    let survey = step
        .prepare(&mut KvScratch::new(&mut world.governor))
        .unwrap();
    assert_eq!((survey.free, survey.leased, survey.pinned), (0, 0, 2));
    let own = {
        let ledger = world.governor.ledger();
        let (increment, _) = increments(&world)[0];
        ledger.reservation(increment).unwrap().parent().unwrap()
    };
    let room = world
        .governor
        .ledger()
        .parent_room(own, vram_key(gpu(0)))
        .unwrap();
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
        Amounts::new().with(vram_key(gpu(0)), room + 256 * MIB),
    )
    .within(own);
    let admission = {
        let mut ladder = ReclaimLadder::new();
        register_model_reclaimers(&mut ladder, [&mut step as &mut dyn ModelReclaimer]);
        world
            .governor
            .coordinator_mut()
            .capacity_mut()
            .write_ledger(|ledger| ledger.reserve_reclaiming(request, &mut ladder))
    };
    let scratch = admission
        .report
        .steps()
        .iter()
        .find(|report| report.step == ReclaimStep::ReclaimUnusedScratch)
        .unwrap();
    assert_eq!(
        scratch.outcome,
        StepOutcome::Declined(DeclineReason::Held {
            pinned: 2,
            leased: 0
        })
    );
    if let Ok(Admission::Queued { ticket, .. }) = &admission.admission {
        world
            .governor
            .coordinator_mut()
            .capacity_mut()
            .write_ledger(|ledger| ledger.cancel_queued(*ticket))
            .unwrap();
    }
    let settlement = step
        .settle(&admission.report, &mut KvScratch::new(&mut world.governor))
        .unwrap();
    assert!(settlement.stopped.is_empty());
    assert_eq!(
        increments(&world)
            .into_iter()
            .map(|(_, state)| state)
            .collect::<Vec<_>>(),
        vec![ReservationState::InUse; 2]
    );
    assert_eq!(
        world.governor.kv_usage(&placement, epoch, generation),
        Some((512 * MIB, 0))
    );

    // Once the runner dropped the session's KV, its increments are scratch again.
    assert_eq!(
        world
            .governor
            .release_session_kv(&placement, epoch, generation, &op("resumable")),
        Some(512 * MIB)
    );
    assert_eq!(
        world
            .governor
            .release_session_kv(&placement, epoch, generation, &op("resumable")),
        None
    );
    assert_eq!(trimmable(&world, &receipt), 2);
    let survey = step
        .prepare(&mut KvScratch::new(&mut world.governor))
        .unwrap();
    assert_eq!(survey.free, 2);
}

#[test]
fn a_session_no_tier_can_take_is_parked_with_its_kv() {
    let mut world = World::new();
    world.runner.set_kv_write_back(None);
    let receipt = serve(&mut world, "parked", false);
    assert!(matches!(receipt.session, SessionRetention::Retained { .. }));
    assert_eq!(
        world
            .governor
            .kv_sessions(&receipt.placement, world.epoch(), receipt.generation),
        Some(vec![(op("parked"), 512 * MIB)])
    );
    assert_eq!(trimmable(&world, &receipt), 0);
}

#[test]
fn a_released_session_frees_its_kv_for_trimming_as_before() {
    let mut world = World::new();
    let receipt = serve(&mut world, "done", false);
    assert!(matches!(receipt.session, SessionRetention::Released { .. }));
    assert_eq!(
        world
            .governor
            .kv_sessions(&receipt.placement, world.epoch(), receipt.generation),
        Some(Vec::new())
    );
    assert_eq!(trimmable(&world, &receipt), 2);
}

#[test]
fn a_session_resumed_under_a_new_lease_hands_its_kv_to_it() {
    let mut world = World::new();
    let mut request = activation_request(&world, "activation");
    if let Some(spec) = request.spec.as_mut() {
        spec.kv = KvSpec::with_layout(GROWING, 2 * GIB);
        spec.declared = DECLARED;
    }
    let pending = world.governor.admit(&request).unwrap().activation.unwrap();
    let residency = residency_of(&world);
    let generation = world
        .governor
        .publish_activation(pending, residency)
        .unwrap();
    let placement = world.placement(world.scenario.model_a);
    let epoch = world.epoch();
    let lease = |world: &mut World, name: &str, tokens: u64| {
        let authority = authority(world, name);
        world
            .governor
            .lease_execution(&authority, &placement, generation, shape(tokens))
            .unwrap()
    };
    let mut kept = lease(&mut world, "session", 4_096);
    kept.keep_session();
    world.governor.release_execution_lease(kept).unwrap();
    let other = lease(&mut world, "other", 1_024);
    // 512 MiB kept and 128 MiB leased need every committed increment.
    assert_eq!(
        world.governor.kv_usage(&placement, epoch, generation),
        Some((512 * MIB, 128 * MIB))
    );
    assert!(world
        .governor
        .kv_trimmable(&placement, epoch, generation)
        .unwrap()
        .is_empty());

    // The same request resumes: its kept KV is its new lease's.
    let resumed = lease(&mut world, "session", 4_096);
    assert_eq!(
        world.governor.kv_sessions(&placement, epoch, generation),
        Some(Vec::new())
    );
    world.governor.release_execution_lease(resumed).unwrap();
    world.governor.release_execution_lease(other).unwrap();
    assert_eq!(
        world
            .governor
            .kv_trimmable(&placement, epoch, generation)
            .unwrap()
            .len(),
        3
    );
}
