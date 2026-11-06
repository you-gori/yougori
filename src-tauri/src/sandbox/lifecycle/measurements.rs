//! Kill and cleanup measurements (VM part §6.5 lines 2331–2339; §12.4 line 2851;
//! VM-W26 line 2632; BENCH-05 line 365; BENCH-06 line 366).
//!
//! Revoke-to-deny, channel close, VM stop and cleanup times are recorded as separate
//! distributions with p50/p95/p99 through the CORE-08 statistics, failures counted
//! beside them and never trimmed. The two-second stop figure is an engineering target
//! under a specified test load and is recorded as such; no type here can state a
//! guarantee. Deleting an overlay, unmapping memory or dropping a filename is logical
//! cleanup and is never reported as physical wiping.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::{ExecutionId, SandboxBootGeneration};
use crate::foundation::report::{
    percentile, resolution, FailureKind, Measured, NotMeasuredReason, PercentileMethod, Quantile,
    ReportError, Resolution,
};

/// The four stop phases measured separately (§6.5; VM-P14).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopPhase {
    /// The durable decision to the first authorization refused after it (CORE-04's first
    /// denied authorization; VM-P14 and VM-CP-14: new-request denial measured apart from
    /// the decision). A revocation that no request reached has no sample.
    RevokeToDeny,
    /// Decision to every eligible channel closed (CORE-04's all channels closed).
    ChannelClose,
    /// Decision to the VM stopped.
    VmStop,
    /// VM stopped to cleanup finished; residual, never part of the stop figure.
    Cleanup,
}

impl StopPhase {
    pub const ALL: [Self; 4] = [
        Self::RevokeToDeny,
        Self::ChannelClose,
        Self::VmStop,
        Self::Cleanup,
    ];
}

impl fmt::Display for StopPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RevokeToDeny => "revoke to deny",
            Self::ChannelClose => "channel close",
            Self::VmStop => "VM stop",
            Self::Cleanup => "cleanup",
        })
    }
}

/// One measured phase of one revocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseSample {
    pub execution: ExecutionId,
    pub phase: StopPhase,
    pub nanos: u64,
    /// The burst the sample belongs to, for the resolution rule.
    pub burst: u32,
}

/// Why a phase did not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopFailureCause {
    /// The acknowledgment never arrived by the bound.
    Unacknowledged,
    /// The handle's object was reused; nothing was stopped.
    HandleReused,
    /// The backend refused or stalled.
    BackendStalled,
    /// Cleanup did not finish within its bound.
    CleanupBound,
}

impl StopFailureCause {
    /// The S8 failure kind the cause is counted under.
    pub const fn kind(self) -> FailureKind {
        match self {
            Self::Unacknowledged | Self::CleanupBound => FailureKind::DeadlineFailure,
            Self::HandleReused => FailureKind::DuplicateIdentity,
            Self::BackendStalled => FailureKind::CommandFailure,
        }
    }
}

/// One phase that failed, counted beside the samples and never dropped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseFailure {
    pub execution: ExecutionId,
    pub phase: StopPhase,
    pub cause: StopFailureCause,
}

/// How a VM was brought up (BENCH-06).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootPath {
    Cold,
    WarmRestore,
}

/// Create initiated to the first successful command in the guest (BENCH-05; the S8 VM
/// provisioning clock).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstCommandSample {
    pub execution: ExecutionId,
    pub boot: SandboxBootGeneration,
    pub path: BootPath,
    pub nanos: u64,
    pub burst: u32,
}

/// One reported percentile of a phase.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PercentileReport {
    pub quantile: Quantile,
    pub value_nanos: Measured<f64>,
    pub resolution: Resolution,
}

/// One phase's distribution: successes with untrimmed percentiles, failures counted
/// separately (§6.5 "report p50/p95/p99, failures and separate cleanup time").
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PhaseSummary {
    pub phase: StopPhase,
    pub successes: u64,
    pub failures: u64,
    pub bursts: u64,
    pub method: PercentileMethod,
    pub percentiles: Vec<PercentileReport>,
}

impl PhaseSummary {
    pub fn percentile(&self, quantile: Quantile) -> Option<&PercentileReport> {
        self.percentiles
            .iter()
            .find(|report| report.quantile == quantile)
    }
}

/// The BENCH-06 counts of the warm-pool rules.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolCounts {
    /// Launches, cold or warm, that ran the same authority checks.
    pub authority_checks: u64,
    /// Distinct VM identities handed out.
    pub unique_identities: u64,
    pub warm_restores: u64,
    pub cold_fallbacks: u64,
    /// Restored clones that failed verification and were cleaned up before a cold boot.
    pub failed_clone_cleanups: u64,
    /// Restores whose launch rolled back after the backend was asked: nothing was
    /// exposed and the clone is not reused.
    #[serde(default)]
    pub restore_rollbacks: u64,
    pub successful_first_commands: u64,
}

/// The kill and cleanup measurements of one supervisor.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KillMeasurements {
    samples: Vec<PhaseSample>,
    failures: Vec<PhaseFailure>,
    first_commands: Vec<FirstCommandSample>,
    pool: PoolCounts,
}

impl KillMeasurements {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, sample: PhaseSample) {
        self.samples.push(sample);
    }

    pub fn record_failure(&mut self, failure: PhaseFailure) {
        self.failures.push(failure);
    }

    pub fn record_first_command(&mut self, sample: FirstCommandSample) {
        self.pool.successful_first_commands = self.pool.successful_first_commands.saturating_add(1);
        self.first_commands.push(sample);
    }

    pub fn samples(&self) -> &[PhaseSample] {
        &self.samples
    }

    pub fn failures(&self) -> &[PhaseFailure] {
        &self.failures
    }

    pub fn first_commands(&self) -> &[FirstCommandSample] {
        &self.first_commands
    }

    pub fn pool(&self) -> PoolCounts {
        self.pool
    }

    pub fn pool_mut(&mut self) -> &mut PoolCounts {
        &mut self.pool
    }

    /// The distribution of `phase`: untrimmed percentiles of every successful sample and
    /// the failure count beside them.
    pub fn summarize(&self, phase: StopPhase) -> Result<PhaseSummary, ReportError> {
        let mut sorted: Vec<u64> = self
            .samples
            .iter()
            .filter(|sample| sample.phase == phase)
            .map(|sample| sample.nanos)
            .collect();
        sorted.sort_unstable();
        let bursts: BTreeSet<u32> = self
            .samples
            .iter()
            .filter(|sample| sample.phase == phase)
            .map(|sample| sample.burst)
            .collect();
        let failures = self
            .failures
            .iter()
            .filter(|failure| failure.phase == phase)
            .count() as u64;
        let method = PercentileMethod::NearestRank;
        let mut percentiles = Vec::with_capacity(Quantile::REPORTED.len());
        for quantile in Quantile::REPORTED {
            let value_nanos = if sorted.is_empty() {
                Measured::not_measured(NotMeasuredReason::NoSuccessfulRuns)
            } else {
                Measured::measured(percentile(&sorted, quantile, method)?)
            };
            percentiles.push(PercentileReport {
                quantile,
                value_nanos,
                resolution: resolution(sorted.len() as u64, bursts.len() as u64, quantile),
            });
        }
        Ok(PhaseSummary {
            phase,
            successes: sorted.len() as u64,
            failures,
            bursts: bursts.len() as u64,
            method,
            percentiles,
        })
    }

    /// The first-command distribution of `path` (BENCH-05, BENCH-06).
    pub fn first_command_percentile(
        &self,
        path: BootPath,
        quantile: Quantile,
    ) -> Result<Measured<f64>, ReportError> {
        let mut sorted: Vec<u64> = self
            .first_commands
            .iter()
            .filter(|sample| sample.path == path)
            .map(|sample| sample.nanos)
            .collect();
        sorted.sort_unstable();
        if sorted.is_empty() {
            return Ok(Measured::not_measured(NotMeasuredReason::NoSuccessfulRuns));
        }
        Ok(Measured::measured(percentile(
            &sorted,
            quantile,
            PercentileMethod::NearestRank,
        )?))
    }
}

/// What kind of statement a stop figure is. There is no variant for a guarantee: the
/// plan records the two-second figure as a target, not a measured guarantee (§6.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetClaim {
    /// An initial local engineering target under a specified test load.
    EngineeringTarget,
    /// What was observed against the target in one run; it proves nothing beyond that
    /// run.
    ObservationUnderTestLoad,
}

/// The §6.5 stop target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopTarget {
    pub phase: StopPhase,
    pub within: Duration,
    pub claim: TargetClaim,
}

/// "Stop a disposable VM within two seconds under specified test load" (§6.5), a target.
pub const STOP_TARGET: StopTarget = StopTarget {
    phase: StopPhase::VmStop,
    within: Duration::from_secs(2),
    claim: TargetClaim::EngineeringTarget,
};

/// A summary held against the target. The claim it carries is always an observation.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TargetAssessment {
    pub target: StopTarget,
    pub observed_p99_nanos: Measured<f64>,
    pub failures: u64,
    /// Whether the observed p99 was within the target; `None` when nothing was measured.
    pub within_target: Option<bool>,
    pub claim: TargetClaim,
}

impl TargetAssessment {
    /// Holds `summary` against `target` (§6.5). Any failure means the target was not met
    /// in that run, whatever the successful samples say.
    pub fn of(summary: &PhaseSummary, target: StopTarget) -> Self {
        let observed = summary
            .percentile(Quantile::P99)
            .map(|report| report.value_nanos.clone())
            .unwrap_or_else(|| Measured::not_measured(NotMeasuredReason::NoSuccessfulRuns));
        let within_target = observed
            .value()
            .map(|p99| summary.failures == 0 && *p99 <= target.within.as_nanos() as f64);
        Self {
            target,
            observed_p99_nanos: observed,
            failures: summary.failures,
            within_target,
            claim: TargetClaim::ObservationUnderTestLoad,
        }
    }
}

/// A logical cleanup action (§6.5: "deleting an overlay, unmapping memory or dropping a
/// filename is logical cleanup").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogicalCleanupAction {
    OverlayDeleted,
    MemoryUnmapped,
    FilenameDropped,
    PerimeterRemoved,
    ReservationReleased,
}

/// A copy of sensitive state that logical cleanup leaves behind (§6.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveCopy {
    Ram,
    Swap,
    CrashDumps,
    Snapshots,
    Backups,
    SsdBlocks,
}

/// A per-generation encryption design with an explicitly managed key lifecycle (§6.5).
/// Destroying its key erases only the copies the design covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptionDesign {
    pub covered: BTreeSet<SensitiveCopy>,
    pub key_destroyed: bool,
}

/// What a cleanup proves about physical state. There is no variant claiming every copy
/// wiped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "physical", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum PhysicalWipe {
    /// Logical cleanup only; nothing physical is proven.
    NotProven,
    /// Key destruction erased the copies the encryption design covers, and only those.
    CoveredByKeyDestruction { covered: BTreeSet<SensitiveCopy> },
}

crate::foundation::strict_serde::strict_tag!(PhysicalWipe, "physical");

impl PhysicalWipe {
    /// Whether `copy` is erased by this cleanup.
    pub fn erases(&self, copy: SensitiveCopy) -> bool {
        match self {
            Self::NotProven => false,
            Self::CoveredByKeyDestruction { covered } => covered.contains(&copy),
        }
    }
}

/// A cleanup report: the logical actions taken and what, if anything, is physically
/// erased (§6.5). Only [`CleanupReport::logical`] makes one, so every report starts with
/// nothing physical proven.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupReport {
    pub actions: BTreeSet<LogicalCleanupAction>,
    pub physical: PhysicalWipe,
}

impl CleanupReport {
    /// A logical cleanup; it proves no physical wiping.
    pub fn logical(actions: impl IntoIterator<Item = LogicalCleanupAction>) -> Self {
        Self {
            actions: actions.into_iter().collect(),
            physical: PhysicalWipe::NotProven,
        }
    }

    /// Adds what an encryption design's key destruction erased: exactly the covered
    /// copies, and nothing when the key was not destroyed.
    pub fn with_key_destruction(mut self, design: &EncryptionDesign) -> Self {
        if design.key_destroyed && !design.covered.is_empty() {
            self.physical = PhysicalWipe::CoveredByKeyDestruction {
                covered: design.covered.clone(),
            };
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn execution(name: &str) -> ExecutionId {
        ExecutionId::new(name).unwrap()
    }

    fn sample(phase: StopPhase, millis: u64, burst: u32) -> PhaseSample {
        PhaseSample {
            execution: execution("exe-a"),
            phase,
            nanos: millis * 1_000_000,
            burst,
        }
    }

    #[test]
    fn phases_are_summarized_separately_with_failures_beside_them() {
        let mut measurements = KillMeasurements::new();
        for (index, millis) in [100u64, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
            .into_iter()
            .enumerate()
        {
            measurements.record(sample(StopPhase::VmStop, millis, index as u32 / 4));
        }
        measurements.record(sample(StopPhase::Cleanup, 30_000, 0));
        measurements.record_failure(PhaseFailure {
            execution: execution("exe-b"),
            phase: StopPhase::VmStop,
            cause: StopFailureCause::HandleReused,
        });
        let stop = measurements.summarize(StopPhase::VmStop).unwrap();
        assert_eq!((stop.successes, stop.failures, stop.bursts), (10, 1, 3));
        let p50 = stop.percentile(Quantile::P50).unwrap();
        assert_eq!(p50.value_nanos.value().copied(), Some(500.0 * 1_000_000.0));
        let p99 = stop.percentile(Quantile::P99).unwrap();
        assert_eq!(p99.value_nanos.value().copied(), Some(1000.0 * 1_000_000.0));
        let cleanup = measurements.summarize(StopPhase::Cleanup).unwrap();
        assert_eq!((cleanup.successes, cleanup.failures), (1, 0));
        assert_eq!(
            cleanup
                .percentile(Quantile::P95)
                .unwrap()
                .value_nanos
                .value()
                .copied(),
            Some(30_000.0 * 1_000_000.0),
            "cleanup time is reported apart from the stop"
        );
        let empty = measurements.summarize(StopPhase::ChannelClose).unwrap();
        assert_eq!(empty.successes, 0);
        assert!(!empty
            .percentile(Quantile::P50)
            .unwrap()
            .value_nanos
            .is_measured());
        assert_eq!(
            StopFailureCause::HandleReused.kind(),
            FailureKind::DuplicateIdentity
        );
    }

    #[test]
    fn the_two_second_figure_is_a_target_and_never_a_guarantee() {
        assert_eq!(STOP_TARGET.within, Duration::from_secs(2));
        assert_eq!(STOP_TARGET.claim, TargetClaim::EngineeringTarget);
        assert!(serde_json::from_value::<TargetClaim>(serde_json::json!("guarantee")).is_err());
        let mut fast = KillMeasurements::new();
        for millis in [100, 200, 300] {
            fast.record(sample(StopPhase::VmStop, millis, 0));
        }
        let within = TargetAssessment::of(&fast.summarize(StopPhase::VmStop).unwrap(), STOP_TARGET);
        assert_eq!(within.within_target, Some(true));
        assert_eq!(within.claim, TargetClaim::ObservationUnderTestLoad);
        fast.record_failure(PhaseFailure {
            execution: execution("exe-b"),
            phase: StopPhase::VmStop,
            cause: StopFailureCause::BackendStalled,
        });
        let failed = TargetAssessment::of(&fast.summarize(StopPhase::VmStop).unwrap(), STOP_TARGET);
        assert_eq!(
            failed.within_target,
            Some(false),
            "a failure means the target was not met"
        );
        let mut slow = KillMeasurements::new();
        slow.record(sample(StopPhase::VmStop, 2001, 0));
        let missed = TargetAssessment::of(&slow.summarize(StopPhase::VmStop).unwrap(), STOP_TARGET);
        assert_eq!(missed.within_target, Some(false));
        let none = TargetAssessment::of(
            &KillMeasurements::new()
                .summarize(StopPhase::VmStop)
                .unwrap(),
            STOP_TARGET,
        );
        assert_eq!(none.within_target, None);
    }

    #[test]
    fn logical_cleanup_is_never_reported_as_physical_wiping() {
        let report = CleanupReport::logical([
            LogicalCleanupAction::OverlayDeleted,
            LogicalCleanupAction::MemoryUnmapped,
            LogicalCleanupAction::FilenameDropped,
        ]);
        assert_eq!(report.physical, PhysicalWipe::NotProven);
        for copy in [
            SensitiveCopy::Ram,
            SensitiveCopy::Swap,
            SensitiveCopy::CrashDumps,
            SensitiveCopy::Snapshots,
            SensitiveCopy::Backups,
            SensitiveCopy::SsdBlocks,
        ] {
            assert!(!report.physical.erases(copy));
        }
        let undestroyed = report.clone().with_key_destruction(&EncryptionDesign {
            covered: BTreeSet::from([SensitiveCopy::SsdBlocks]),
            key_destroyed: false,
        });
        assert_eq!(undestroyed.physical, PhysicalWipe::NotProven);
        let destroyed = report.with_key_destruction(&EncryptionDesign {
            covered: BTreeSet::from([SensitiveCopy::SsdBlocks, SensitiveCopy::Snapshots]),
            key_destroyed: true,
        });
        assert!(destroyed.physical.erases(SensitiveCopy::SsdBlocks));
        assert!(
            !destroyed.physical.erases(SensitiveCopy::Ram),
            "key destruction only erases copies covered by that encryption design"
        );
        assert!(
            serde_json::from_value::<PhysicalWipe>(serde_json::json!({"physical": "all"})).is_err()
        );
    }

    #[test]
    fn first_command_samples_are_kept_per_boot_path() {
        let mut measurements = KillMeasurements::new();
        for (path, millis) in [
            (BootPath::Cold, 900),
            (BootPath::Cold, 1100),
            (BootPath::WarmRestore, 300),
        ] {
            measurements.record_first_command(FirstCommandSample {
                execution: execution("exe-a"),
                boot: SandboxBootGeneration::FIRST,
                path,
                nanos: millis * 1_000_000,
                burst: 0,
            });
        }
        assert_eq!(measurements.pool().successful_first_commands, 3);
        assert_eq!(
            measurements
                .first_command_percentile(BootPath::Cold, Quantile::P50)
                .unwrap()
                .value()
                .copied(),
            Some(900.0 * 1_000_000.0)
        );
        assert_eq!(
            measurements
                .first_command_percentile(BootPath::WarmRestore, Quantile::P99)
                .unwrap()
                .value()
                .copied(),
            Some(300.0 * 1_000_000.0)
        );
    }
}
