//! GPU-W09: partial-rank recovery as bounded re-planning of the failed ranks only.

use std::collections::{BTreeMap, BTreeSet};

use crate::foundation::ids::{ModelActivationGeneration, ResourceId};
use crate::model_memory::math::bounds::{BandwidthRating, ResourceTable};
use crate::model_memory::placement::Rank;

use super::super::fixtures::device;
use super::super::recovery::*;
use super::support::*;

const SHARD: u64 = 3_500_000_000;

fn rank(value: u64) -> Rank {
    Rank::new(value)
}

/// Four tensor-parallel ranks of a 14 GB model on host-a's GPUs 0–3; spares GPU 4 and
/// GPU 5 behind one 25 GB/s PCIe root; a pinned host copy of every shard read at
/// 50 GB/s; 1 s detection, 0.2 s setup and 0.5 s revalidation of every rank.
fn request(failed: &[u64]) -> RankRecoveryRequest {
    let resource = |name: &str| ResourceId::new(name).unwrap();
    let mut resources = ResourceTable::new();
    resources
        .add(
            resource("pcie-root-0"),
            BandwidthRating::measured_directional(25.0e9).unwrap(),
        )
        .unwrap();
    resources
        .add(
            resource("host-memory-read"),
            BandwidthRating::measured_directional(50.0e9).unwrap(),
        )
        .unwrap();
    RankRecoveryRequest {
        layout: (0..4)
            .map(|index| {
                (
                    rank(index),
                    RankAssignment {
                        device: device("host-a", &format!("gpu{index}")),
                        shard_bytes: SHARD,
                    },
                )
            })
            .collect(),
        generation: ModelActivationGeneration::new(7),
        failed: failed.iter().map(|index| rank(*index)).collect(),
        spares: ["gpu4", "gpu5"]
            .iter()
            .map(|name| SpareDevice {
                device: device("host-a", name),
                free_bytes: 8_000_000_000,
                ingress: resource("pcie-root-0"),
            })
            .collect(),
        holders: vec![ShardHolder {
            name: "pinned-host-copy".to_owned(),
            ranks: (0..4).map(rank).collect(),
            egress: resource("host-memory-read"),
        }],
        resources,
        detection_seconds: 1.0,
        setup_seconds: 0.2,
        revalidation_seconds: 0.5,
    }
}

fn bounds() -> RecoveryBounds {
    RecoveryBounds {
        max_attempts: 2,
        deadline_seconds: 5.0,
    }
}

#[test]
fn only_the_failed_rank_s_shard_moves_and_the_layout_republishes() {
    let request = request(&[2]);
    let plan = plan_rank_recovery(&request, bounds(), 1).unwrap();
    // 3.5 GB through the 25 GB/s root: 0.14 s; ready after 1 + 0.2 + 0.14 + 0.5 s.
    assert_eq!(plan.moved_bytes, SHARD);
    assert_close(plan.transfer_seconds, 0.14);
    assert_close(plan.ready_seconds, 1.84);
    assert_eq!(
        plan.replacements,
        BTreeMap::from([(rank(2), device("host-a", "gpu4"))])
    );
    for index in [0, 1, 3] {
        assert_eq!(plan.layout[&rank(index)], request.layout[&rank(index)]);
    }
    assert_eq!(plan.next_generation, ModelActivationGeneration::new(8));
}

#[test]
fn shards_sharing_a_root_count_it_once() {
    let plan = plan_rank_recovery(&request(&[1, 2]), bounds(), 1).unwrap();
    // 7 GB through one root: 0.28 s, half the model rather than all of it.
    assert_eq!(plan.moved_bytes, 2 * SHARD);
    assert_close(plan.transfer_seconds, 0.28);
    assert_close(plan.ready_seconds, 1.98);
    assert_eq!(plan.replacements.len(), 2);
}

#[test]
fn recovery_is_bounded_by_attempts_and_a_deadline() {
    let request = request(&[2]);
    assert_eq!(
        plan_rank_recovery(&request, bounds(), 3),
        Err(RankRecoveryRefusal::AttemptsExhausted { max_attempts: 2 })
    );
    assert!(plan_rank_recovery(&request, bounds(), 0).is_err());
    let late = plan_rank_recovery(
        &request,
        RecoveryBounds {
            max_attempts: 2,
            deadline_seconds: 1.5,
        },
        1,
    );
    let Err(RankRecoveryRefusal::DeadlineExceeded {
        ready_seconds,
        deadline_seconds,
    }) = late
    else {
        panic!("expected a missed deadline, got {late:?}");
    };
    assert_close(ready_seconds, 1.84);
    assert_eq!(deadline_seconds, 1.5);
}

#[test]
fn recovery_needs_a_spare_a_surviving_copy_and_a_failed_rank() {
    let mut small = request(&[2]);
    for spare in &mut small.spares {
        spare.free_bytes = 1_000_000_000;
    }
    assert_eq!(
        plan_rank_recovery(&small, bounds(), 1),
        Err(RankRecoveryRefusal::NoSpareDevice { rank: rank(2) })
    );
    let mut orphaned = request(&[2]);
    orphaned.holders[0].ranks = BTreeSet::from([rank(0), rank(1)]);
    assert_eq!(
        plan_rank_recovery(&orphaned, bounds(), 1),
        Err(RankRecoveryRefusal::NoShardHolder { rank: rank(2) })
    );
    assert_eq!(
        plan_rank_recovery(&request(&[]), bounds(), 1),
        Err(RankRecoveryRefusal::NoFailedRank)
    );
    assert_eq!(
        plan_rank_recovery(&request(&[9]), bounds(), 1),
        Err(RankRecoveryRefusal::UnknownRank { rank: rank(9) })
    );
    let mut last = request(&[2]);
    last.generation = ModelActivationGeneration::new(u64::MAX);
    assert_eq!(
        plan_rank_recovery(&last, bounds(), 1),
        Err(RankRecoveryRefusal::GenerationExhausted)
    );
}
