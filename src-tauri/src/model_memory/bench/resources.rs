//! The resources S10 tracks through switches (line 183) and the trend rule of a short
//! repeated-switch run (BENCH-07, line 199). A short run can show a leak as a trend; it
//! never shows the absence of one (S7 line 129: "No process or snapshot mode receives a
//! no-leak claim from a short run").

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::BenchError;
use crate::foundation::ids::MonotonicTime;
use crate::foundation::report::TrackedResource;

/// One reading of every S10 resource: resident VRAM, pinned RAM, host RSS, file
/// descriptors, GPU contexts, graphs, communicators and physical allocation references.
/// Also used for per-switch amounts, such as a leaky fake's growth.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSnapshot {
    pub vram_bytes: u64,
    pub pinned_host_bytes: u64,
    pub rss_bytes: u64,
    pub file_descriptors: u64,
    pub gpu_contexts: u64,
    pub cuda_graphs: u64,
    pub communicators: u64,
    pub allocation_references: u64,
}

impl ResourceSnapshot {
    pub const ZERO: Self = Self {
        vram_bytes: 0,
        pinned_host_bytes: 0,
        rss_bytes: 0,
        file_descriptors: 0,
        gpu_contexts: 0,
        cuda_graphs: 0,
        communicators: 0,
        allocation_references: 0,
    };

    pub fn get(&self, resource: TrackedResource) -> u64 {
        match resource {
            TrackedResource::ResidentVram => self.vram_bytes,
            TrackedResource::PinnedHostMemory => self.pinned_host_bytes,
            TrackedResource::HostRss => self.rss_bytes,
            TrackedResource::FileDescriptors => self.file_descriptors,
            TrackedResource::GpuContexts => self.gpu_contexts,
            TrackedResource::CudaGraphs => self.cuda_graphs,
            TrackedResource::Communicators => self.communicators,
            TrackedResource::PhysicalAllocationReferences => self.allocation_references,
        }
    }

    fn zip(&self, other: &Self, op: impl Fn(u64, u64) -> u64) -> Self {
        Self {
            vram_bytes: op(self.vram_bytes, other.vram_bytes),
            pinned_host_bytes: op(self.pinned_host_bytes, other.pinned_host_bytes),
            rss_bytes: op(self.rss_bytes, other.rss_bytes),
            file_descriptors: op(self.file_descriptors, other.file_descriptors),
            gpu_contexts: op(self.gpu_contexts, other.gpu_contexts),
            cuda_graphs: op(self.cuda_graphs, other.cuda_graphs),
            communicators: op(self.communicators, other.communicators),
            allocation_references: op(self.allocation_references, other.allocation_references),
        }
    }

    pub fn saturating_add(&self, other: &Self) -> Self {
        self.zip(other, u64::saturating_add)
    }

    pub fn saturating_sub(&self, other: &Self) -> Self {
        self.zip(other, u64::saturating_sub)
    }

    /// The larger of each resource: a running peak.
    pub fn max(&self, other: &Self) -> Self {
        self.zip(other, u64::max)
    }
}

/// State-corruption canaries (S10): fixed requests whose expected response is known. A
/// response that cannot be compared, such as a non-deterministic one at temperature zero,
/// is counted apart and never as a pass (S13 FAST-01).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryTally {
    pub passed: u64,
    pub failed: u64,
    pub not_comparable: u64,
}

impl CanaryTally {
    pub fn add(&mut self, other: &Self) {
        self.passed = self.passed.saturating_add(other.passed);
        self.failed = self.failed.saturating_add(other.failed);
        self.not_comparable = self.not_comparable.saturating_add(other.not_comparable);
    }
}

/// A reading after one switch cycle, at a quiescent point. `segment` counts the recycles
/// before it: a recycle resets process memory, so each segment has its own trend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSample {
    pub cycle: u64,
    pub at: MonotonicTime,
    pub segment: u32,
    pub snapshot: ResourceSnapshot,
}

/// When a trend counts as a leak (BENCH-07): at least `min_samples` readings in one
/// segment, and growth above `tolerance_per_switch` for that resource. Reading a stored
/// policy goes through [`TrendPolicy::new`], so it is refused exactly as a new one is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "TrendPolicyWire")]
pub struct TrendPolicy {
    min_samples: usize,
    tolerance_per_switch: ResourceSnapshot,
}

/// The serialized form of [`TrendPolicy`], checked by its constructor when read.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrendPolicyWire {
    min_samples: usize,
    tolerance_per_switch: ResourceSnapshot,
}

impl TryFrom<TrendPolicyWire> for TrendPolicy {
    type Error = BenchError;

    fn try_from(wire: TrendPolicyWire) -> Result<Self, Self::Error> {
        Self::new(wire.min_samples, wire.tolerance_per_switch)
    }
}

impl TrendPolicy {
    /// A trend needs at least three readings.
    pub fn new(
        min_samples: usize,
        tolerance_per_switch: ResourceSnapshot,
    ) -> Result<Self, BenchError> {
        if min_samples < 3 {
            return Err(BenchError::InvalidParameter {
                field: "min_samples",
                reason: "a trend needs at least three readings",
            });
        }
        Ok(Self {
            min_samples,
            tolerance_per_switch,
        })
    }

    pub fn min_samples(&self) -> usize {
        self.min_samples
    }

    pub fn tolerance_per_switch(&self) -> ResourceSnapshot {
        self.tolerance_per_switch
    }
}

/// The least-squares trend of one resource within one recycle segment.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceTrendLine {
    pub resource: TrackedResource,
    pub segment: u32,
    pub samples: usize,
    pub first: u64,
    pub last: u64,
    pub slope_per_switch: f64,
    /// Growth above the tolerance with a net rise: a leak trend.
    pub leaking: bool,
}

/// Least-squares slope of `values` against their index.
fn slope(values: &[u64]) -> f64 {
    let count = values.len() as f64;
    let mean_x = (count - 1.0) / 2.0;
    let mean_y = values.iter().map(|value| *value as f64).sum::<f64>() / count;
    let (numerator, denominator) = values.iter().enumerate().fold(
        (0.0f64, 0.0f64),
        |(numerator, denominator), (index, value)| {
            let dx = index as f64 - mean_x;
            (
                numerator + dx * (*value as f64 - mean_y),
                denominator + dx * dx,
            )
        },
    );
    if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

/// The trend of every S10 resource in every segment with enough readings. Each cycle
/// holds `switches_per_cycle` switches (two for A/B/A), so a slope per cycle is divided
/// by it.
pub fn trend_lines(
    samples: &[ResourceSample],
    policy: &TrendPolicy,
    switches_per_cycle: u64,
) -> Result<Vec<ResourceTrendLine>, BenchError> {
    if switches_per_cycle == 0 {
        return Err(BenchError::InvalidParameter {
            field: "switches_per_cycle",
            reason: "a cycle holds at least one switch",
        });
    }
    let mut segments: BTreeMap<u32, Vec<&ResourceSample>> = BTreeMap::new();
    for sample in samples {
        segments.entry(sample.segment).or_default().push(sample);
    }
    let mut lines = Vec::new();
    for (segment, readings) in segments {
        if readings.len() < policy.min_samples {
            continue;
        }
        for resource in TrackedResource::ALL {
            let values: Vec<u64> = readings
                .iter()
                .map(|sample| sample.snapshot.get(resource))
                .collect();
            let (Some(first), Some(last)) = (values.first().copied(), values.last().copied())
            else {
                continue;
            };
            let slope_per_switch = slope(&values) / switches_per_cycle as f64;
            let tolerance = policy.tolerance_per_switch.get(resource) as f64;
            lines.push(ResourceTrendLine {
                resource,
                segment,
                samples: values.len(),
                first,
                last,
                slope_per_switch,
                leaking: slope_per_switch > tolerance && last > first,
            });
        }
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(cycle: u64, segment: u32, pinned: u64, rss: u64) -> ResourceSample {
        ResourceSample {
            cycle,
            at: MonotonicTime::from_nanos(cycle),
            segment,
            snapshot: ResourceSnapshot {
                pinned_host_bytes: pinned,
                rss_bytes: rss,
                ..ResourceSnapshot::ZERO
            },
        }
    }

    fn policy() -> TrendPolicy {
        TrendPolicy::new(
            4,
            ResourceSnapshot {
                rss_bytes: 1 << 20,
                ..ResourceSnapshot::ZERO
            },
        )
        .unwrap()
    }

    #[test]
    fn a_steady_rise_is_a_leak_and_noise_is_not() {
        let rising: Vec<_> = (0..8)
            .map(|cycle| sample(cycle, 0, cycle * 4096, 100))
            .collect();
        let lines = trend_lines(&rising, &policy(), 2).unwrap();
        let pinned = lines
            .iter()
            .find(|line| line.resource == TrackedResource::PinnedHostMemory)
            .unwrap();
        assert!(pinned.leaking);
        assert_eq!(pinned.slope_per_switch, 2048.0);

        // RSS that wobbles by up to 1 KiB around a flat level is within tolerance.
        let noisy: Vec<_> = (0..8)
            .map(|cycle| sample(cycle, 0, 0, 500_000 + (cycle * 7919) % 1024))
            .collect();
        assert!(trend_lines(&noisy, &policy(), 2)
            .unwrap()
            .iter()
            .all(|line| !line.leaking));
    }

    #[test]
    fn segments_are_assessed_apart_so_a_recycle_cannot_hide_a_rise() {
        // A sawtooth: a rise in each segment, reset by a recycle; the overall level is flat.
        let sawtooth: Vec<_> = (0..12)
            .map(|cycle| sample(cycle, (cycle / 6) as u32, (cycle % 6) * 8192, 0))
            .collect();
        let lines = trend_lines(&sawtooth, &policy(), 2).unwrap();
        let leaking: Vec<u32> = lines
            .iter()
            .filter(|line| line.resource == TrackedResource::PinnedHostMemory && line.leaking)
            .map(|line| line.segment)
            .collect();
        assert_eq!(leaking, vec![0, 1]);
    }

    #[test]
    fn too_few_readings_give_no_trend() {
        let short: Vec<_> = (0..3)
            .map(|cycle| sample(cycle, 0, cycle * 4096, 0))
            .collect();
        assert!(trend_lines(&short, &policy(), 2).unwrap().is_empty());
        assert!(TrendPolicy::new(2, ResourceSnapshot::ZERO).is_err());
        assert!(trend_lines(&short, &policy(), 0).is_err());
    }

    #[test]
    fn a_stored_policy_is_refused_as_a_new_one_is() {
        // Reading goes through `TrendPolicy::new`: a policy round-trips, and one the
        // constructor refuses, or one with an unknown field, cannot be read.
        let json = serde_json::to_string(&policy()).unwrap();
        assert_eq!(
            serde_json::from_str::<TrendPolicy>(&json).unwrap(),
            policy()
        );
        let stored: serde_json::Value = serde_json::from_str(&json).unwrap();
        for too_few in [0u64, 2] {
            let mut value = stored.clone();
            value["min_samples"] = too_few.into();
            let error = serde_json::from_value::<TrendPolicy>(value).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("min_samples: a trend needs at least three readings"),
                "{error}"
            );
        }
        let mut extra = stored;
        extra["slack"] = 1.into();
        assert!(serde_json::from_value::<TrendPolicy>(extra).is_err());
    }

    #[test]
    fn snapshots_add_subtract_and_keep_peaks() {
        let one = ResourceSnapshot {
            vram_bytes: 5,
            file_descriptors: 2,
            ..ResourceSnapshot::ZERO
        };
        let two = ResourceSnapshot {
            vram_bytes: 3,
            cuda_graphs: 4,
            ..ResourceSnapshot::ZERO
        };
        assert_eq!(one.saturating_add(&two).vram_bytes, 8);
        assert_eq!(one.saturating_sub(&two).vram_bytes, 2);
        assert_eq!(two.saturating_sub(&one).vram_bytes, 0);
        let peak = one.max(&two);
        assert_eq!(
            (peak.vram_bytes, peak.cuda_graphs, peak.file_descriptors),
            (5, 4, 2)
        );
        for resource in TrackedResource::ALL {
            assert_eq!(ResourceSnapshot::ZERO.get(resource), 0);
        }
    }
}
