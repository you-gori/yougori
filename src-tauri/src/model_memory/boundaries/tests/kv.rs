//! KV admission and growth (GPU-W10 line 182; acceptance: request shape changes cannot
//! overrun reserved memory). A backend that grows its KV commits its pool in increments,
//! each a CORE-03 reservation carved from the activation's own reservation; one that
//! cannot holds its whole pool from the start. Every request is admitted for the KV its
//! shape writes, a request past the pool waits or is refused with a typed reason, and the
//! runner writes no more than its lease admits.

use std::collections::BTreeSet;

use super::governor::{activation_request, authority, residency_of, DECLARED};
use super::support::*;
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::ModelActivationGeneration;
use crate::foundation::ledger::{CostPurpose, ReservationId};
use crate::model_memory::boundaries::*;
use crate::model_memory::placement::{RequestShape, ShapeRefusal, SupportedShape};

const KIB: u64 = 1 << 10;

/// 128 KiB of KV per token, grown 256 MiB at a time, in a 2 GiB pool.
const GROWING: KvSpec = KvSpec {
    bytes_per_token: 128 * KIB,
    pool_bytes: 2 * GIB,
    growth: KvGrowth::Increments {
        increment_bytes: 256 * MIB,
    },
};

/// Publishes model A with `kv`, checked for `declared`.
fn publish_with(
    world: &mut World,
    kv: KvSpec,
    declared: SupportedShape,
) -> ModelActivationGeneration {
    let mut request = activation_request(world, "activation");
    if let Some(spec) = request.spec.as_mut() {
        spec.kv = kv;
        spec.declared = declared;
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
) -> Result<ExecutionLease, GovernorError> {
    let placement = world.placement(world.scenario.model_a);
    let authority = authority(world, name);
    world
        .governor
        .lease_execution(&authority, &placement, generation, shape)
}

/// An order to serve one request of `shape` under `lease`.
fn order<'a>(
    lease: &'a ExecutionLease,
    shape: RequestShape,
    payload: &'a RequestPayload,
) -> ServeOrder<'a> {
    ServeOrder {
        lease,
        shape,
        payload,
        computed_ahead_groups: 0,
    }
}

/// The KV the generation's pool holds committed, and the KV admitted to leases.
fn usage(world: &World, generation: ModelActivationGeneration) -> (u64, u64) {
    let placement = world.placement(world.scenario.model_a);
    world
        .governor
        .kv_usage(&placement, world.epoch(), generation)
        .unwrap()
}

/// The KV increments carved so far: open compute reservations carved from the sandbox's
/// children, each with its VRAM.
fn increments(world: &World) -> Vec<u64> {
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
        })
        .filter(|record| record.provenance().purpose == CostPurpose::Compute)
        .map(|record| record.granted().get(vram_key(gpu(0))))
        .collect()
}

#[test]
fn kv_grows_in_increments_carved_from_the_activation_up_to_its_pool() {
    let mut world = World::new();
    let generation = publish_with(&mut world, GROWING, DECLARED);
    // Nothing is committed before a request writes KV.
    assert_eq!(usage(&world, generation), (0, 0));
    assert!(increments(&world).is_empty());

    // A request of 1,024 tokens writes 128 MiB: the pool grows by one increment, carved
    // from the activation's own reservation, so the sandbox counts nothing more.
    let first = lease(&mut world, "first", generation, shape(1_024)).unwrap();
    assert_eq!(first.kv_bytes(), 128 * MIB);
    assert_eq!(usage(&world, generation), (256 * MIB, 128 * MIB));
    assert_eq!(increments(&world), vec![256 * MIB]);
    assert_eq!(world.holdings(), model_a_holdings(1));
    assert_eq!(world.vram_room(), SANDBOX_VRAM_BYTES - MODEL_DEMAND_BYTES);

    // Three requests of 4,096 tokens, 512 MiB each, grow it to 1,792 MiB.
    let mut held = Vec::new();
    for name in ["second", "third", "fourth"] {
        held.push(lease(&mut world, name, generation, shape(4_096)).unwrap());
    }
    assert_eq!(usage(&world, generation), (1_792 * MIB, 1_664 * MIB));
    assert_eq!(increments(&world), vec![256 * MIB; 7]);

    // A fifth would pass the pool: it waits with a typed reason, and nothing grows.
    assert_eq!(
        lease(&mut world, "fifth", generation, shape(4_096)).unwrap_err(),
        GovernorError::Kv {
            refusal: KvRefusal::AwaitingRelease {
                requested_bytes: 512 * MIB,
                free_bytes: 384 * MIB,
            }
        }
    );
    assert_eq!(usage(&world, generation), (1_792 * MIB, 1_664 * MIB));
    assert_eq!(increments(&world).len(), 7);

    // Once a request releases its KV the fifth fits in what is committed.
    world
        .governor
        .release_execution_lease(held.remove(0))
        .unwrap();
    assert_eq!(usage(&world, generation), (1_792 * MIB, 1_152 * MIB));
    let fifth = lease(&mut world, "fifth", generation, shape(4_096)).unwrap();
    assert_eq!(usage(&world, generation), (1_792 * MIB, 1_664 * MIB));
    assert_eq!(increments(&world).len(), 7);

    // Reclaiming the generation hands every increment back with its memory.
    for lease in held.into_iter().chain([first, fifth]) {
        world.governor.release_execution_lease(lease).unwrap();
    }
    let placement = world.placement(world.scenario.model_a);
    let next = publish_with(&mut world, GROWING, DECLARED);
    assert!(world
        .governor
        .confirm_released(&placement, generation, SourceClass::GuestReport)
        .unwrap());
    assert!(increments(&world).is_empty());
    assert_eq!(usage(&world, next), (0, 0));
    assert_eq!(world.holdings(), model_a_holdings(1));
}

#[test]
fn a_backend_without_kv_growth_holds_its_whole_pool() {
    let mut world = World::new();
    let kv = KvSpec::bounded_by_pool(2 * GIB, &DECLARED);
    assert_eq!(kv.growth, KvGrowth::Fixed);
    let generation = publish_with(&mut world, kv, DECLARED);
    // The whole pool is committed with the activation's reservation; nothing is carved.
    assert_eq!(usage(&world, generation), (2 * GIB, 0));
    let whole = lease(&mut world, "whole", generation, shape(4_096)).unwrap();
    assert_eq!(whole.kv_bytes(), 2 * GIB);
    assert!(increments(&world).is_empty());
    assert_eq!(world.holdings(), model_a_holdings(1));
    // A request of the shape it was reserved for fills the pool; the next one waits.
    assert_eq!(
        lease(&mut world, "next", generation, shape(1_024)).unwrap_err(),
        GovernorError::Kv {
            refusal: KvRefusal::AwaitingRelease {
                requested_bytes: 512 * MIB,
                free_bytes: 0,
            }
        }
    );
}

#[test]
fn kv_past_the_pool_or_the_reservation_is_refused() {
    // A request whose KV the pool can never hold is refused, never queued.
    let mut world = World::new();
    let wide = KvSpec {
        bytes_per_token: MIB,
        ..GROWING
    };
    let generation = publish_with(&mut world, wide, DECLARED);
    assert_eq!(
        lease(&mut world, "wide", generation, shape(4_096)).unwrap_err(),
        GovernorError::Kv {
            refusal: KvRefusal::ExceedsPool {
                requested_bytes: 4 * GIB,
                pool_bytes: 2 * GIB,
            }
        }
    );
    assert_eq!(usage(&world, generation), (0, 0));

    // A pool declared larger than the activation's own memory still cannot pass it: the
    // ledger refuses the increment beyond the reservation, and nothing carved stays.
    let mut world = World::new();
    let oversold = KvSpec {
        bytes_per_token: MIB,
        pool_bytes: 8 * GIB,
        ..GROWING
    };
    let generation = publish_with(&mut world, oversold, DECLARED);
    let held = lease(&mut world, "fits", generation, shape(4_096)).unwrap();
    assert_eq!(held.kv_bytes(), 4 * GIB);
    assert_eq!(usage(&world, generation), (4 * GIB, 4 * GIB));
    let refused = lease(&mut world, "past", generation, shape(1_024)).unwrap_err();
    let GovernorError::Kv {
        refusal: KvRefusal::Ledger { refusal },
    } = refused
    else {
        panic!("the ledger refuses the increment, got {refused:?}");
    };
    assert_eq!(refusal.resource, vram_key(gpu(0)));
    assert_eq!(refusal.limit, LimitKind::ParentReservation);
    assert_eq!(usage(&world, generation), (4 * GIB, 4 * GIB));
    assert_eq!(increments(&world), vec![256 * MIB; 16]);
}

#[test]
fn request_shape_changes_cannot_overrun_reserved_memory() {
    let mut world = World::new();
    let longer = SupportedShape {
        max_context_tokens: 8_192,
        max_batch_sequences: 1,
    };
    let generation = publish_with(&mut world, GROWING, longer);
    let mut first = lease(&mut world, "first", generation, shape(1_024)).unwrap();
    let mut second = lease(&mut world, "second", generation, shape(4_096)).unwrap();
    assert_eq!(usage(&world, generation), (768 * MIB, 640 * MIB));

    // Growing shapes grow the KV each lease holds, and the pool with it.
    world
        .governor
        .resize_execution_lease(&mut first, shape(8_192))
        .unwrap();
    assert_eq!((first.kv_bytes(), first.shape()), (GIB, shape(8_192)));
    world
        .governor
        .resize_execution_lease(&mut second, shape(8_192))
        .unwrap();
    assert_eq!(usage(&world, generation), (2 * GIB, 2 * GIB));
    assert_eq!(
        lease(&mut world, "third", generation, shape(1_024)).unwrap_err(),
        GovernorError::Kv {
            refusal: KvRefusal::AwaitingRelease {
                requested_bytes: 128 * MIB,
                free_bytes: 0,
            }
        }
    );

    // A shape the generation was not checked for, or that the pool cannot hold, is
    // refused, and the lease stays as it was.
    let refused = world
        .governor
        .resize_execution_lease(&mut first, shape(16_384))
        .unwrap_err();
    assert!(matches!(
        refused,
        GovernorError::Shape {
            refusal: ShapeRefusal::ContextTooLong { .. }
        }
    ));
    let batched = RequestShape {
        context_tokens: 4_096,
        batch_sequences: 2,
    };
    assert!(matches!(
        world
            .governor
            .resize_execution_lease(&mut first, batched)
            .unwrap_err(),
        GovernorError::Shape { .. }
    ));
    assert_eq!((first.kv_bytes(), first.shape()), (GIB, shape(8_192)));
    assert_eq!(usage(&world, generation), (2 * GIB, 2 * GIB));

    // A shrinking shape frees KV for others; the committed pool stays.
    world
        .governor
        .resize_execution_lease(&mut second, shape(1_024))
        .unwrap();
    assert_eq!(usage(&world, generation), (2 * GIB, GIB + 128 * MIB));
    let third = lease(&mut world, "third", generation, shape(1_024)).unwrap();
    assert_eq!(usage(&world, generation), (2 * GIB, GIB + 256 * MIB));

    // The runner never writes past its lease: a request served at a larger shape than its
    // lease admits is refused.
    world.runner.set_kv_layout(Some(KvLayout {
        bytes_per_token: GROWING.bytes_per_token,
        growth: GROWING.growth,
    }));
    let placement = world.placement(world.scenario.model_a);
    let current = world.governor.current_residency(&placement).unwrap();
    world
        .runner
        .force_generation(world.scenario.model_a, &current, longer);
    let payload = RequestPayload::new(b"prompt".to_vec());
    assert_eq!(
        world
            .runner
            .serve(&order(&third, shape(4_096), &payload))
            .unwrap_err(),
        RunnerRefusal::KvBeyondLease {
            needed_bytes: 512 * MIB,
            leased_bytes: 128 * MIB,
        }
    );
    assert!(world
        .runner
        .serve(&order(&third, shape(1_024), &payload))
        .is_ok());
    for lease in [first, second, third] {
        world.governor.release_execution_lease(lease).unwrap();
    }
    assert_eq!(usage(&world, generation), (2 * GIB, 0));
}
