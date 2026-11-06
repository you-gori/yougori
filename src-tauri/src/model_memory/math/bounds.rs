//! Physical lower bounds and honest speedup arithmetic (GPU §2.2).
//!
//! `T >= max(critical-path minimum, max_e(S_e / B_e))`, where `S_e` is every byte that
//! must cross resource `e` and `B_e` is its measured usable directional bandwidth. Each
//! resource is registered once; transfers that share it add their bytes on it.

use std::collections::BTreeMap;
use std::fmt;

use super::{non_negative, positive, probability, InputError, ResourceId};

/// How a bandwidth figure was obtained (GPU §2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BandwidthBasis {
    /// Measured usable bandwidth in one direction: the only basis bounds and plans use.
    MeasuredDirectional,
    /// A datasheet, vendor or peer advertisement rather than a measurement.
    Advertised,
    /// A rating that adds both directions of a full-duplex link together.
    AggregateBidirectional,
}

/// A bandwidth figure that is not a measured directional bandwidth (GPU §2.2, §2.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnusableBandwidth {
    pub basis: BandwidthBasis,
}

impl fmt::Display for UnusableBandwidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a {:?} rating is not a measured usable directional bandwidth",
            self.basis
        )
    }
}

impl std::error::Error for UnusableBandwidth {}

/// A bandwidth figure together with how it was obtained (GPU §2.2, §2.5).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BandwidthRating {
    bytes_per_second: f64,
    basis: BandwidthBasis,
}

impl BandwidthRating {
    /// A measured usable directional bandwidth: `B_e` of GPU §2.2.
    pub fn measured_directional(bytes_per_second: f64) -> Result<Self, InputError> {
        Self::with_basis(bytes_per_second, BandwidthBasis::MeasuredDirectional)
    }

    /// An advertised figure: kept for reports, never used as usable bandwidth.
    pub fn advertised(bytes_per_second: f64) -> Result<Self, InputError> {
        Self::with_basis(bytes_per_second, BandwidthBasis::Advertised)
    }

    /// A both-directions aggregate: never one transfer's usable bandwidth (GPU §2.2).
    pub fn aggregate_bidirectional(bytes_per_second: f64) -> Result<Self, InputError> {
        Self::with_basis(bytes_per_second, BandwidthBasis::AggregateBidirectional)
    }

    fn with_basis(bytes_per_second: f64, basis: BandwidthBasis) -> Result<Self, InputError> {
        Ok(Self {
            bytes_per_second: positive("bytes_per_second", bytes_per_second)?,
            basis,
        })
    }

    /// The figure as stated, whatever its basis.
    pub fn stated_bytes_per_second(&self) -> f64 {
        self.bytes_per_second
    }

    /// How the figure was obtained.
    pub fn basis(&self) -> BandwidthBasis {
        self.basis
    }

    /// The usable directional bandwidth; refused unless the figure was measured in one
    /// direction (GPU §2.2, §2.5).
    pub fn usable_bytes_per_second(&self) -> Result<f64, UnusableBandwidth> {
        match self.basis {
            BandwidthBasis::MeasuredDirectional => Ok(self.bytes_per_second),
            basis => Err(UnusableBandwidth { basis }),
        }
    }
}

/// Why a bound or speedup was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum BoundsError {
    Input(InputError),
    /// A resource was offered an advertised or aggregate rating (GPU §2.2).
    UnusableBandwidth {
        resource: ResourceId,
        basis: BandwidthBasis,
    },
    /// A claimed duration beats the physical bound: the same bytes cannot move faster
    /// without a different source, representation or necessity (GPU §2.2).
    BelowLowerBound {
        claimed_seconds: f64,
        lower_bound_seconds: f64,
    },
}

impl From<InputError> for BoundsError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl fmt::Display for BoundsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => error.fmt(f),
            Self::UnusableBandwidth { resource, basis } => write!(
                f,
                "{resource} has a {basis:?} rating, not a measured usable directional bandwidth"
            ),
            Self::BelowLowerBound {
                claimed_seconds,
                lower_bound_seconds,
            } => write!(
                f,
                "{claimed_seconds} s is below the physical lower bound of {lower_bound_seconds} s"
            ),
        }
    }
}

impl std::error::Error for BoundsError {}

/// The resources and directional links a load crosses, each registered once with its
/// measured usable directional bandwidth (GPU §2.2).
#[derive(Clone, Debug, Default)]
pub struct ResourceTable {
    bandwidths: BTreeMap<ResourceId, f64>,
}

impl ResourceTable {
    /// An empty table (GPU §2.2).
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a resource. A second registration is refused, so a resource shared by
    /// several transfers keeps one capacity instead of one copy per transfer.
    pub fn add(
        &mut self,
        resource: ResourceId,
        rating: BandwidthRating,
    ) -> Result<(), BoundsError> {
        let bytes_per_second = match rating.usable_bytes_per_second() {
            Ok(value) => value,
            Err(UnusableBandwidth { basis }) => {
                return Err(BoundsError::UnusableBandwidth { resource, basis })
            }
        };
        if self.bandwidths.contains_key(&resource) {
            return Err(InputError::Duplicate {
                field: "resources",
                name: resource.to_string(),
            }
            .into());
        }
        self.bandwidths.insert(resource, bytes_per_second);
        Ok(())
    }

    /// `B_e` of a registered resource.
    pub fn bandwidth_bytes_per_second(&self, resource: &ResourceId) -> Option<f64> {
        self.bandwidths.get(resource).copied()
    }

    /// How many resources are registered.
    pub fn len(&self) -> usize {
        self.bandwidths.len()
    }

    /// Whether no resource is registered.
    pub fn is_empty(&self) -> bool {
        self.bandwidths.is_empty()
    }
}

/// Bytes that one transfer step moves across each listed resource (GPU §2.2 `S_e`).
///
/// A step that crosses one resource twice, such as a copy that reads and writes host
/// memory, is written as two demands; a resource listed twice in one demand is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferDemand {
    pub bytes: u64,
    pub resources: Vec<ResourceId>,
}

/// One resource's total bytes and the time they need on it.
#[derive(Clone, Debug, PartialEq)]
pub struct ResourceLoad {
    pub resource: ResourceId,
    /// `S_e`: the sum over every demand crossing this resource.
    pub bytes: u64,
    pub bytes_per_second: f64,
    /// `S_e / B_e`.
    pub seconds: f64,
}

/// Which term sets a lower bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingTerm {
    CriticalPath,
    Resource(ResourceId),
}

/// `max(critical-path minimum, max_e(S_e / B_e))` with its terms (GPU §2.2). An
/// optimistic bound: real schedules add contention, fill and drain.
#[derive(Clone, Debug, PartialEq)]
pub struct LowerBound {
    pub critical_path_minimum_seconds: f64,
    pub loads: Vec<ResourceLoad>,
    pub lower_bound_seconds: f64,
    pub binding: BindingTerm,
}

impl LowerBound {
    /// Refuses a claimed duration that beats this bound (GPU §2.2: pipelining overlaps
    /// stages but cannot move the same bytes faster than their resources allow).
    pub fn check_claim(&self, claimed_seconds: f64) -> Result<(), BoundsError> {
        let claimed_seconds = non_negative("claimed_seconds", claimed_seconds)?;
        if claimed_seconds < self.lower_bound_seconds {
            return Err(BoundsError::BelowLowerBound {
                claimed_seconds,
                lower_bound_seconds: self.lower_bound_seconds,
            });
        }
        Ok(())
    }
}

/// The GPU §2.2 lower bound for `demands` over `table`.
pub fn transfer_lower_bound(
    table: &ResourceTable,
    demands: &[TransferDemand],
    critical_path_minimum_seconds: f64,
) -> Result<LowerBound, BoundsError> {
    let critical_path_minimum_seconds = non_negative(
        "critical_path_minimum_seconds",
        critical_path_minimum_seconds,
    )?;
    let mut bytes_on: BTreeMap<&ResourceId, (u64, f64)> = BTreeMap::new();
    for demand in demands {
        if demand.resources.is_empty() {
            return Err(InputError::Empty {
                field: "TransferDemand.resources",
            }
            .into());
        }
        for (index, resource) in demand.resources.iter().enumerate() {
            if demand.resources[..index].contains(resource) {
                return Err(InputError::Duplicate {
                    field: "TransferDemand.resources",
                    name: resource.to_string(),
                }
                .into());
            }
            let bytes_per_second =
                table
                    .bandwidth_bytes_per_second(resource)
                    .ok_or_else(|| InputError::Unknown {
                        field: "TransferDemand.resources",
                        name: resource.to_string(),
                    })?;
            let entry = bytes_on.entry(resource).or_insert((0, bytes_per_second));
            entry.0 = entry
                .0
                .checked_add(demand.bytes)
                .ok_or(InputError::Overflow { field: "S_e" })?;
        }
    }
    let loads: Vec<ResourceLoad> = bytes_on
        .into_iter()
        .map(|(resource, (bytes, bytes_per_second))| ResourceLoad {
            resource: resource.clone(),
            bytes,
            bytes_per_second,
            seconds: bytes as f64 / bytes_per_second,
        })
        .collect();
    let mut lower_bound_seconds = critical_path_minimum_seconds;
    let mut binding = BindingTerm::CriticalPath;
    for load in &loads {
        if load.seconds > lower_bound_seconds {
            lower_bound_seconds = load.seconds;
            binding = BindingTerm::Resource(load.resource.clone());
        }
    }
    Ok(LowerBound {
        critical_path_minimum_seconds,
        loads,
        lower_bound_seconds,
        binding,
    })
}

/// What a speedup describes (GPU §2.1, §2.2). Different kinds are never compared,
/// combined or relabelled, and no conversion exists between their types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpeedupKind {
    OverallWorkflow,
    ReadinessDispatch,
    GenerationThroughput,
}

impl SpeedupKind {
    /// How reports must name this kind of speedup.
    pub const fn label(self) -> &'static str {
        match self {
            Self::OverallWorkflow => "overall workflow speedup",
            Self::ReadinessDispatch => "readiness/dispatch speedup, not generation throughput",
            Self::GenerationThroughput => "generation throughput speedup",
        }
    }
}

/// Amdahl's bound (GPU §2.2): `1 / ((1 - f) + f / s)` when a fraction `f` of a
/// workflow becomes `s` times faster.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct OverallSpeedup {
    accelerated_fraction: f64,
    part_speedup: f64,
    ratio: f64,
}

impl OverallSpeedup {
    /// Refuses a fraction outside [0, 1] and a part speedup that is not positive.
    pub fn amdahl(accelerated_fraction: f64, part_speedup: f64) -> Result<Self, BoundsError> {
        let accelerated_fraction = probability("accelerated_fraction", accelerated_fraction)?;
        let part_speedup = positive("part_speedup", part_speedup)?;
        let ratio = 1.0 / ((1.0 - accelerated_fraction) + accelerated_fraction / part_speedup);
        Ok(Self {
            accelerated_fraction,
            part_speedup,
            ratio,
        })
    }

    /// `f`: the share of the workflow that became faster.
    pub fn accelerated_fraction(&self) -> f64 {
        self.accelerated_fraction
    }

    /// `s`: how much faster that share became.
    pub fn part_speedup(&self) -> f64 {
        self.part_speedup
    }

    /// The overall speedup.
    pub fn ratio(&self) -> f64 {
        self.ratio
    }

    /// Always [`SpeedupKind::OverallWorkflow`].
    pub fn kind(&self) -> SpeedupKind {
        SpeedupKind::OverallWorkflow
    }
}

/// How much sooner an engine accepts a request (GPU §2.2): a readiness/dispatch ratio,
/// never generation throughput. It carries the retained memory and the preparation that
/// make the dispatch possible, which the plan requires to be reported beside it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ReadinessDispatchSpeedup {
    baseline_ready_seconds: f64,
    dispatch_seconds: f64,
    retained_memory_bytes: u64,
    preparation_seconds: f64,
}

impl ReadinessDispatchSpeedup {
    /// Refuses a baseline or dispatch time that is not positive and a negative preparation time.
    pub fn new(
        baseline_ready_seconds: f64,
        dispatch_seconds: f64,
        retained_memory_bytes: u64,
        preparation_seconds: f64,
    ) -> Result<Self, BoundsError> {
        Ok(Self {
            baseline_ready_seconds: positive("baseline_ready_seconds", baseline_ready_seconds)?,
            dispatch_seconds: positive("dispatch_seconds", dispatch_seconds)?,
            retained_memory_bytes,
            preparation_seconds: non_negative("preparation_seconds", preparation_seconds)?,
        })
    }

    /// Baseline readiness time over dispatch time.
    pub fn ratio(&self) -> f64 {
        self.baseline_ready_seconds / self.dispatch_seconds
    }

    /// Time to readiness without the retained state, such as recreating the engine.
    pub fn baseline_ready_seconds(&self) -> f64 {
        self.baseline_ready_seconds
    }

    /// Time to dispatch with the retained state.
    pub fn dispatch_seconds(&self) -> f64 {
        self.dispatch_seconds
    }

    /// Memory kept resident to make the dispatch possible.
    pub fn retained_memory_bytes(&self) -> u64 {
        self.retained_memory_bytes
    }

    /// Preparation spent beforehand to make the dispatch possible.
    pub fn preparation_seconds(&self) -> f64 {
        self.preparation_seconds
    }

    /// Always [`SpeedupKind::ReadinessDispatch`].
    pub fn kind(&self) -> SpeedupKind {
        SpeedupKind::ReadinessDispatch
    }
}

/// A generation throughput ratio from tokens per second (GPU §2.1 inter-token work).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GenerationThroughputSpeedup {
    baseline_tokens_per_second: f64,
    candidate_tokens_per_second: f64,
}

impl GenerationThroughputSpeedup {
    /// Refuses a baseline that is not positive and a negative candidate rate.
    pub fn new(
        baseline_tokens_per_second: f64,
        candidate_tokens_per_second: f64,
    ) -> Result<Self, BoundsError> {
        Ok(Self {
            baseline_tokens_per_second: positive(
                "baseline_tokens_per_second",
                baseline_tokens_per_second,
            )?,
            candidate_tokens_per_second: non_negative(
                "candidate_tokens_per_second",
                candidate_tokens_per_second,
            )?,
        })
    }

    /// Candidate tokens per second over baseline tokens per second.
    pub fn ratio(&self) -> f64 {
        self.candidate_tokens_per_second / self.baseline_tokens_per_second
    }

    /// Always [`SpeedupKind::GenerationThroughput`].
    pub fn kind(&self) -> SpeedupKind {
        SpeedupKind::GenerationThroughput
    }
}

#[cfg(test)]
mod tests;
