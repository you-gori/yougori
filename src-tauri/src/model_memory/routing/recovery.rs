//! GPU-W09 (line 1120): "Coordinate multi-rank activation and partial-rank recovery",
//! with the acceptance rule that a failed donor or rank "yields bounded recovery"
//! (line 1124).
//!
//! When ranks of a multi-rank placement fail, only their shards are re-planned: each
//! failed rank gets a spare device with room for its shard and a surviving holder of
//! that shard, the transfers are bounded by GPU §2.2 over the measured resources (a
//! holder or root shared by several transfers counts once), every rank re-validates, and
//! the repaired layout is published as the next activation generation (§3.6, line 599:
//! a multi-rank activation publishes only after every rank passed). Surviving ranks keep
//! their shards. Recovery is bounded by an attempt count and a deadline.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::foundation::ids::{GpuDeviceKey, ModelActivationGeneration, ResourceId};
use crate::model_memory::math::bounds::{transfer_lower_bound, ResourceTable, TransferDemand};
use crate::model_memory::math::{non_negative, InputError};
use crate::model_memory::placement::Rank;

use super::error::RoutingError;

/// One rank's device and shard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RankAssignment {
    pub device: GpuDeviceKey,
    pub shard_bytes: u64,
}

/// A device that can take a failed rank's place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpareDevice {
    pub device: GpuDeviceKey,
    pub free_bytes: u64,
    /// The resource the shard enters by, such as its PCIe root or NIC receive side.
    pub ingress: ResourceId,
}

/// A surviving copy of some ranks' shards, such as a pinned host copy or a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardHolder {
    pub name: String,
    pub ranks: BTreeSet<Rank>,
    /// The resource the shard leaves by.
    pub egress: ResourceId,
}

/// What failed and what is available to recover it.
#[derive(Clone, Debug)]
pub struct RankRecoveryRequest {
    pub layout: BTreeMap<Rank, RankAssignment>,
    /// The activation generation that lost ranks.
    pub generation: ModelActivationGeneration,
    pub failed: BTreeSet<Rank>,
    pub spares: Vec<SpareDevice>,
    pub holders: Vec<ShardHolder>,
    /// Measured usable directional bandwidth of every resource, each registered once.
    pub resources: ResourceTable,
    pub detection_seconds: f64,
    pub setup_seconds: f64,
    /// Validation of every rank before the repaired layout publishes.
    pub revalidation_seconds: f64,
}

/// The bounds on recovery (line 1124 "bounded recovery").
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RecoveryBounds {
    pub max_attempts: u32,
    pub deadline_seconds: f64,
}

/// A bounded re-plan of the failed ranks only.
#[derive(Clone, Debug, PartialEq)]
pub struct RankRecoveryPlan {
    pub attempt: u32,
    pub replacements: BTreeMap<Rank, GpuDeviceKey>,
    /// The repaired layout: failed ranks on their spares, every other rank unchanged.
    pub layout: BTreeMap<Rank, RankAssignment>,
    /// Only the failed ranks' shards.
    pub moved_bytes: u64,
    /// The GPU §2.2 bound of the shard transfers.
    pub transfer_seconds: f64,
    /// Detection, setup, transfers and revalidation of every rank.
    pub ready_seconds: f64,
    /// The generation the repaired layout publishes under.
    pub next_generation: ModelActivationGeneration,
}

/// Why recovery was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum RankRecoveryRefusal {
    NoFailedRank,
    UnknownRank {
        rank: Rank,
    },
    NoSpareDevice {
        rank: Rank,
    },
    NoShardHolder {
        rank: Rank,
    },
    DeadlineExceeded {
        ready_seconds: f64,
        deadline_seconds: f64,
    },
    AttemptsExhausted {
        max_attempts: u32,
    },
    /// The generation counter cannot advance; the placement must be replaced.
    GenerationExhausted,
    Invalid(RoutingError),
}

impl From<InputError> for RankRecoveryRefusal {
    fn from(error: InputError) -> Self {
        Self::Invalid(error.into())
    }
}

impl fmt::Display for RankRecoveryRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoFailedRank => f.write_str("no rank failed"),
            Self::UnknownRank { rank } => write!(f, "rank {rank} is not in the layout"),
            Self::NoSpareDevice { rank } => write!(f, "no spare device can hold rank {rank}"),
            Self::NoShardHolder { rank } => write!(f, "no surviving copy of rank {rank}'s shard"),
            Self::DeadlineExceeded {
                ready_seconds,
                deadline_seconds,
            } => write!(
                f,
                "recovery would be ready after {ready_seconds} s, past its {deadline_seconds} s deadline"
            ),
            Self::AttemptsExhausted { max_attempts } => {
                write!(f, "recovery already used its {max_attempts} attempts")
            }
            Self::GenerationExhausted => f.write_str("the activation generation cannot advance"),
            Self::Invalid(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for RankRecoveryRefusal {}

/// Plans attempt `attempt` (from 1) of recovering `request.failed`.
pub fn plan_rank_recovery(
    request: &RankRecoveryRequest,
    bounds: RecoveryBounds,
    attempt: u32,
) -> Result<RankRecoveryPlan, RankRecoveryRefusal> {
    non_negative("deadline_seconds", bounds.deadline_seconds)?;
    non_negative("detection_seconds", request.detection_seconds)?;
    non_negative("setup_seconds", request.setup_seconds)?;
    non_negative("revalidation_seconds", request.revalidation_seconds)?;
    if attempt == 0 || attempt > bounds.max_attempts {
        return Err(RankRecoveryRefusal::AttemptsExhausted {
            max_attempts: bounds.max_attempts,
        });
    }
    if request.failed.is_empty() {
        return Err(RankRecoveryRefusal::NoFailedRank);
    }
    let surviving_devices: BTreeSet<GpuDeviceKey> = request
        .layout
        .iter()
        .filter(|(rank, _)| !request.failed.contains(*rank))
        .map(|(_, assignment)| assignment.device)
        .collect();
    let mut used_spares: BTreeSet<GpuDeviceKey> = BTreeSet::new();
    let mut replacements = BTreeMap::new();
    let mut layout = request.layout.clone();
    let mut demands = Vec::with_capacity(request.failed.len());
    let mut moved_bytes = 0u64;
    for rank in &request.failed {
        let assignment = request
            .layout
            .get(rank)
            .ok_or(RankRecoveryRefusal::UnknownRank { rank: *rank })?;
        let spare = request
            .spares
            .iter()
            .find(|spare| {
                spare.free_bytes >= assignment.shard_bytes
                    && !used_spares.contains(&spare.device)
                    && !surviving_devices.contains(&spare.device)
                    && spare.device != assignment.device
            })
            .ok_or(RankRecoveryRefusal::NoSpareDevice { rank: *rank })?;
        let holder = request
            .holders
            .iter()
            .find(|holder| holder.ranks.contains(rank))
            .ok_or(RankRecoveryRefusal::NoShardHolder { rank: *rank })?;
        used_spares.insert(spare.device);
        replacements.insert(*rank, spare.device);
        layout.insert(
            *rank,
            RankAssignment {
                device: spare.device,
                shard_bytes: assignment.shard_bytes,
            },
        );
        moved_bytes =
            moved_bytes
                .checked_add(assignment.shard_bytes)
                .ok_or(InputError::Overflow {
                    field: "moved_bytes",
                })?;
        demands.push(TransferDemand {
            bytes: assignment.shard_bytes,
            resources: vec![holder.egress.clone(), spare.ingress.clone()],
        });
    }
    let bound = transfer_lower_bound(&request.resources, &demands, 0.0)
        .map_err(|error| RankRecoveryRefusal::Invalid(error.into()))?;
    let ready_seconds = request.detection_seconds
        + request.setup_seconds
        + bound.lower_bound_seconds
        + request.revalidation_seconds;
    if ready_seconds > bounds.deadline_seconds {
        return Err(RankRecoveryRefusal::DeadlineExceeded {
            ready_seconds,
            deadline_seconds: bounds.deadline_seconds,
        });
    }
    let next_generation = request
        .generation
        .next()
        .ok_or(RankRecoveryRefusal::GenerationExhausted)?;
    Ok(RankRecoveryPlan {
        attempt,
        replacements,
        layout,
        moved_bytes,
        transfer_seconds: bound.lower_bound_seconds,
        ready_seconds,
        next_generation,
    })
}
