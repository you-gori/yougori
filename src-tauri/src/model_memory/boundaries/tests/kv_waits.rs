//! KV waits first in, first out (G06: "a FIFO for KV waits"; GPU-W10 line 1305): a request
//! that must wait for room in its activation's KV pool keeps its place, a later request is
//! admitted only from what every request waiting ahead of it leaves, a shrinking shape
//! never waits, and the queue is bounded in length and in time.

use std::time::Duration;

use super::governor::{activation_request, authority, residency_of};
use super::support::*;
use crate::foundation::ids::{LeaseId, ModelActivationGeneration, MonotonicTime};
use crate::model_memory::boundaries::kv::KvPool;
use crate::model_memory::boundaries::*;
use crate::model_memory::placement::{RequestShape, SupportedShape};

const KIB: u64 = 1 << 10;

/// 128 KiB of KV per token, grown 256 MiB at a time, in a 2 GiB pool.
const GROWING: KvSpec = KvSpec {
    bytes_per_token: 128 * KIB,
    pool_bytes: 2 * GIB,
    growth: KvGrowth::Increments {
        increment_bytes: 256 * MIB,
    },
};

/// Shapes up to 8,192 tokens of one sequence: 1 GiB of KV.
const LONGER: SupportedShape = SupportedShape {
    max_context_tokens: 8_192,
    max_batch_sequences: 1,
};

fn publish(world: &mut World) -> ModelActivationGeneration {
    let mut request = activation_request(world, "activation");
    if let Some(spec) = request.spec.as_mut() {
        spec.kv = GROWING;
        spec.declared = LONGER;
    }
    let pending = world.governor.admit(&request).unwrap().activation.unwrap();
    let residency = residency_of(world);
    world
        .governor
        .publish_activation(pending, residency)
        .unwrap()
}

/// A lease for request `name`, or the KV refusal the governor gave; any other refusal
/// fails the test.
fn lease(
    world: &mut World,
    name: &str,
    generation: ModelActivationGeneration,
    shape: RequestShape,
) -> Result<ExecutionLease, KvRefusal> {
    let placement = world.placement(world.scenario.model_a);
    let authority = authority(world, name);
    match world
        .governor
        .lease_execution(&authority, &placement, generation, shape)
    {
        Ok(lease) => Ok(lease),
        Err(GovernorError::Kv { refusal }) => Err(refusal),
        Err(other) => panic!("expected a KV refusal, got {other:?}"),
    }
}

/// The requests waiting for the generation's KV, first in line first.
fn waiting(world: &mut World, generation: ModelActivationGeneration) -> Vec<String> {
    let placement = world.placement(world.scenario.model_a);
    let epoch = world.epoch();
    world
        .governor
        .kv_waiters(&placement, epoch, generation)
        .unwrap()
        .into_iter()
        .map(|waiter| waiter.key.as_str().to_owned())
        .collect()
}

#[test]
fn a_later_request_never_takes_the_kv_an_earlier_one_waits_for() {
    let mut world = World::new();
    let generation = publish(&mut world);
    let mut held = Vec::new();
    for name in ["a", "b", "c"] {
        held.push(lease(&mut world, name, generation, shape(4_096)).unwrap());
    }
    // 1.5 GiB of the 2 GiB pool is leased. A request for 1 GiB waits for a release.
    assert_eq!(
        lease(&mut world, "big", generation, shape(8_192)).unwrap_err(),
        KvRefusal::AwaitingRelease {
            requested_bytes: GIB,
            free_bytes: 512 * MIB,
        }
    );
    // A later request for 256 MiB fits what is free, but the earlier one claims it.
    assert_eq!(
        lease(&mut world, "small", generation, shape(2_048)).unwrap_err(),
        KvRefusal::QueuedBehind {
            requested_bytes: 256 * MIB,
            free_bytes: 512 * MIB,
            ahead: 1,
            claimed_bytes: GIB,
        }
    );
    assert_eq!(waiting(&mut world, generation), ["big", "small"]);

    // One release frees exactly what the first waiter needs: the later one stays behind.
    world
        .governor
        .release_execution_lease(held.remove(0))
        .unwrap();
    assert_eq!(
        lease(&mut world, "small", generation, shape(2_048)).unwrap_err(),
        KvRefusal::QueuedBehind {
            requested_bytes: 256 * MIB,
            free_bytes: GIB,
            ahead: 1,
            claimed_bytes: GIB,
        }
    );

    // With room for both, the later one backfills without delaying the first.
    world
        .governor
        .release_execution_lease(held.remove(0))
        .unwrap();
    let small = lease(&mut world, "small", generation, shape(2_048)).unwrap();
    assert_eq!(small.kv_bytes(), 256 * MIB);
    assert_eq!(waiting(&mut world, generation), ["big"]);
    let mut big = lease(&mut world, "big", generation, shape(8_192)).unwrap();
    assert_eq!(big.kv_bytes(), GIB);
    assert!(waiting(&mut world, generation).is_empty());

    // A shrinking shape takes nothing, so it never waits behind anyone.
    assert_eq!(
        lease(&mut world, "next", generation, shape(4_096)).unwrap_err(),
        KvRefusal::AwaitingRelease {
            requested_bytes: 512 * MIB,
            free_bytes: 256 * MIB,
        }
    );
    world
        .governor
        .resize_execution_lease(&mut big, shape(4_096))
        .unwrap();
    assert_eq!(big.kv_bytes(), 512 * MIB);
    let next = lease(&mut world, "next", generation, shape(4_096)).unwrap();
    assert_eq!(next.kv_bytes(), 512 * MIB);

    // A request that gives up leaves its place.
    let placement = world.placement(world.scenario.model_a);
    let epoch = world.epoch();
    assert!(matches!(
        lease(&mut world, "late", generation, shape(8_192)).unwrap_err(),
        KvRefusal::AwaitingRelease { .. }
    ));
    assert_eq!(waiting(&mut world, generation), ["late"]);
    assert!(world
        .governor
        .withdraw_kv_wait(&placement, epoch, generation, &op("late")));
    assert!(!world
        .governor
        .withdraw_kv_wait(&placement, epoch, generation, &op("late")));
    assert!(waiting(&mut world, generation).is_empty());
    for lease in held.into_iter().chain([small, big, next]) {
        world.governor.release_execution_lease(lease).unwrap();
    }
}

/// The queue of one pool, through the pool itself: a request refused for good leaves it,
/// and it is bounded in length and in time.
#[test]
fn the_kv_queue_is_bounded_and_keeps_no_request_refused_for_good() {
    let mut pool = KvPool::new(KvSpec {
        growth: KvGrowth::Fixed,
        ..GROWING
    });
    let now = MonotonicTime::ZERO;
    let full = op("full");
    assert!(pool.plan(LeaseId::new(1), &full, 2 * GIB, now).is_ok());
    pool.admit(LeaseId::new(1), &full, 2 * GIB);

    // A waiter that later asks for more than the pool can ever hold is refused outright
    // and claims nothing any more.
    let shifting = op("shifting");
    assert!(matches!(
        pool.plan(LeaseId::new(2), &shifting, MIB, now),
        Err(KvRefusal::AwaitingRelease { .. })
    ));
    assert_eq!(pool.waiters(now).len(), 1);
    assert_eq!(
        pool.plan(LeaseId::new(2), &shifting, 4 * GIB, now),
        Err(KvRefusal::ExceedsPool {
            requested_bytes: 4 * GIB,
            pool_bytes: 2 * GIB,
        })
    );
    assert!(pool.waiters(now).is_empty());

    for index in 0..KV_WAIT_LIMITS.max_waiters {
        let request = op(&format!("waiter-{index}"));
        assert!(matches!(
            pool.plan(LeaseId::new(100), &request, MIB, now),
            Err(KvRefusal::AwaitingRelease { .. })
        ));
    }
    let refused = pool.plan(LeaseId::new(100), &op("one-more"), MIB, now);
    assert_eq!(
        refused,
        Err(KvRefusal::WaitQueueFull {
            waiting: u32::try_from(KV_WAIT_LIMITS.max_waiters).unwrap(),
        })
    );
    assert!(refused.unwrap_err().to_string().contains("already wait"));
    // Every place expires one wait limit after it was taken.
    assert_eq!(pool.waiters(now).len(), KV_WAIT_LIMITS.max_waiters);
    let later = now.saturating_add(KV_WAIT_LIMITS.max_wait + Duration::from_secs(1));
    assert!(pool.waiters(later).is_empty());
    assert!(KvRefusal::QueuedBehind {
        requested_bytes: MIB,
        free_bytes: GIB,
        ahead: 2,
        claimed_bytes: GIB,
    }
    .to_string()
    .contains("2 requests waiting ahead"));
}
