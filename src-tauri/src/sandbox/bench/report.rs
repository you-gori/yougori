//! What a run reports (S8 lines 311–323; S11 lines 369, 377 and 379; VM-W49 line 2672):
//! every attempt in the denominator, the conditional untrimmed first-command tails beside
//! the success rate and deadline failures, the timeout and rejection taxonomy, the
//! resolution of each percentile, the full raw records and their BENCH-13 record. The
//! denominators are the first attempts; retries are raw records of their own, linked to
//! their first attempts, and reported beside the first-attempt results in a
//! [`RetryReport`], never folded into them (S8 line 321).
//!
//! The records carry the fake substrate, so CORE-08 gives them the fake-substrate
//! provenance: they validate the format and the comparison discipline and back no
//! release or performance claim (S12 G0; rollout T02 follow-up). Every claim this report
//! offers asks CORE-08 for Yougori evidence first and is refused on the fake.

use std::collections::{BTreeMap, BTreeSet};

use chrono::NaiveDate;
use serde::Serialize;

use super::plan::RunSpec;
use super::retry::{RetryOutcomes, RetryReport};
use super::timing::InjectedFault;
use super::BenchError;
use crate::foundation::coordination::{
    CapacityLimit, CapacityRefusal, LaunchFailure, ResourceKind, VmInstanceId,
};
use crate::foundation::ids::{ExecutionId, OperationId, SandboxBootGeneration};
use crate::foundation::report::{
    AttemptLedger, BenchId, BurstScaleClaim, ClaimUnderTest, FailureCounts, FailureKind,
    IntervalKind, Label, LatencyClaim, LatencySummary, Limitation, LoadDescription, Measured,
    PercentileMethod, Provenance, Quantile, Quotient, ReproducibilityRecord, Resolution, RunRecord,
    StatisticalMethod, SuccessRate, UndefinedReason,
};
use crate::sandbox::backend::LaunchRefusal;
use crate::sandbox::lifecycle::{BootPath, CheckoutDecision, FirstCommandSample, SupervisorError};

/// The percentile method of every summary here: the observed sample at rank ⌈q·n⌉.
pub const METHOD: PercentileMethod = PercentileMethod::NearestRank;

/// The intervals a VM run summarises: the first-command clock and, apart from it, the
/// API acknowledgment (S8 line 317).
pub const INTERVALS: [IntervalKind; 2] = [
    IntervalKind::VmFirstGuestCommand,
    IntervalKind::VmApiAcknowledgement,
];

/// Why a create was rejected, by the step that refused it (S8 line 321 "rejected"; S10
/// line 351: the output identifies the limiting resource).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionKind {
    /// The host's capacity lacked a resource (CORE-03).
    HostCapacity,
    /// The tenant's budget lacked a resource.
    TenantBudget,
    /// The ledger's bounded queue was full.
    QueueFull,
    /// An owner resource-return hold denied the reservation.
    OwnerReturnHold,
    /// The host has not observed the resource, so none of it is free.
    CapacityNotObserved,
    /// Any other refusal of the ledger.
    CapacityOther,
    /// The backend refused to create or restore the VM.
    BackendRefused,
    /// The host did not observe the VM ready.
    NotReady,
    /// The restored VM failed verification.
    RestoreRefused,
    /// The runtime's category evidence no longer admitted the launch.
    RuntimeEvidence,
    /// The lifecycle refused a step.
    Transition,
    /// A step failed and undoing it stopped part-way.
    RollbackStalled,
    /// The supervisor refused the call.
    Supervisor,
}

impl RejectionKind {
    /// Every kind.
    pub const ALL: [Self; 13] = [
        Self::HostCapacity,
        Self::TenantBudget,
        Self::QueueFull,
        Self::OwnerReturnHold,
        Self::CapacityNotObserved,
        Self::CapacityOther,
        Self::BackendRefused,
        Self::NotReady,
        Self::RestoreRefused,
        Self::RuntimeEvidence,
        Self::Transition,
        Self::RollbackStalled,
        Self::Supervisor,
    ];

    /// The kind of a ledger refusal.
    pub fn of_capacity(refusal: &CapacityRefusal) -> Self {
        match refusal {
            CapacityRefusal::Insufficient {
                limit: CapacityLimit::Host,
                ..
            } => Self::HostCapacity,
            CapacityRefusal::Insufficient {
                limit: CapacityLimit::TenantBudget,
                ..
            } => Self::TenantBudget,
            CapacityRefusal::QueueFull { .. } => Self::QueueFull,
            CapacityRefusal::OwnerReturnHold { .. } => Self::OwnerReturnHold,
            CapacityRefusal::NotObserved { .. } => Self::CapacityNotObserved,
            _ => Self::CapacityOther,
        }
    }

    /// The kind of a launch that rolled back.
    pub fn of_failure(failure: &LaunchFailure) -> Self {
        match failure {
            LaunchFailure::Capacity { refusal } => Self::of_capacity(refusal),
            LaunchFailure::Port { .. } => Self::BackendRefused,
            LaunchFailure::NotReady { .. } => Self::NotReady,
            LaunchFailure::Transition { .. } => Self::Transition,
            LaunchFailure::RestoreRefused { .. } => Self::RestoreRefused,
            LaunchFailure::RuntimeEvidence { .. } | LaunchFailure::RuntimeCategory { .. } => {
                Self::RuntimeEvidence
            }
        }
    }

    /// The kind of a create the backend refused, by the backend contract's typed refusal
    /// as the integration port keeps it: a refused launch whose cleanup is incomplete is a
    /// rollback that stalled, since the boot's perimeter and reservation stay held while
    /// its VM may remain; every other refusal, a real backend's included, is the
    /// backend's. The same kinds the run reports from the launch's receipt. Every variant
    /// is named, so a new one needs a decision here.
    pub fn of_refusal(refusal: &LaunchRefusal) -> Self {
        match refusal {
            LaunchRefusal::CleanupIncomplete { .. } => Self::RollbackStalled,
            LaunchRefusal::Evidence { .. }
            | LaunchRefusal::EvidenceNotBound { .. }
            | LaunchRefusal::PerimeterNotEvidenced { .. }
            | LaunchRefusal::NoPerimeterRules { .. }
            | LaunchRefusal::HardwareVirtualizationFailed { .. }
            | LaunchRefusal::AcceleratorNotObserved { .. }
            | LaunchRefusal::NotHardwareVirtualized { .. }
            | LaunchRefusal::UnexpectedAccelerator { .. }
            | LaunchRefusal::Unsupported { .. }
            | LaunchRefusal::BackendArtifactMismatch { .. }
            | LaunchRefusal::BootGenerationUsed { .. }
            | LaunchRefusal::ObservationNotCurrent { .. }
            | LaunchRefusal::PropertiesNotSatisfied { .. }
            | LaunchRefusal::SnapshotNotRestorable { .. }
            | LaunchRefusal::RestoreRefused { .. }
            | LaunchRefusal::CreateFailed { .. }
            | LaunchRefusal::RecordNotSealed { .. }
            | LaunchRefusal::ProfileRefused { .. }
            | LaunchRefusal::LayoutRefused { .. }
            | LaunchRefusal::ConfigurationNotApproved { .. }
            | LaunchRefusal::ConfinementNotInEffect { .. }
            | LaunchRefusal::ProcessNotRunning { .. }
            | LaunchRefusal::BackendSpecific { .. } => Self::BackendRefused,
        }
    }

    /// The resource that limited a rolled-back launch, when one did.
    pub fn limiting_resource(failure: &LaunchFailure) -> Option<ResourceKind> {
        match failure {
            LaunchFailure::Capacity { refusal } => refusal.limiting_resource(),
            _ => None,
        }
    }

    /// The component a record names as the failure's provenance (CORE-08).
    pub const fn component(self) -> &'static str {
        match self {
            Self::HostCapacity
            | Self::TenantBudget
            | Self::QueueFull
            | Self::OwnerReturnHold
            | Self::CapacityNotObserved
            | Self::CapacityOther => "ledger",
            Self::BackendRefused | Self::NotReady | Self::RestoreRefused => "backend",
            Self::RuntimeEvidence | Self::Transition | Self::RollbackStalled => "coordinator",
            Self::Supervisor => "supervisor",
        }
    }

    /// The code a record names the failure with.
    pub const fn code(self) -> &'static str {
        match self {
            Self::HostCapacity => "host-capacity",
            Self::TenantBudget => "tenant-budget",
            Self::QueueFull => "queue-full",
            Self::OwnerReturnHold => "owner-return-hold",
            Self::CapacityNotObserved => "capacity-not-observed",
            Self::CapacityOther => "capacity-refused",
            Self::BackendRefused => "backend-refused",
            Self::NotReady => "not-ready",
            Self::RestoreRefused => "restore-refused",
            Self::RuntimeEvidence => "runtime-evidence",
            Self::Transition => "transition-refused",
            Self::RollbackStalled => "rollback-stalled",
            Self::Supervisor => "supervisor-refused",
        }
    }
}

/// One attempt as the runner saw it, beside its raw record.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AttemptSummary {
    /// The attempt number, from zero across every burst of the run; a retry carries its
    /// first attempt's number.
    pub index: u32,
    pub burst: u32,
    /// The sandbox the attempt created or checked out.
    pub execution: ExecutionId,
    /// The record's operation.
    pub operation: OperationId,
    pub injected: Option<InjectedFault>,
    pub boot: Option<SandboxBootGeneration>,
    pub vm: Option<VmInstanceId>,
    /// How the VM came up, when it did.
    pub path: Option<BootPath>,
    /// A BENCH-06 checkout's decision, as the lifecycle made it.
    pub decision: Option<CheckoutDecision>,
    /// The checkout cleaned up a restored clone that failed verification.
    pub failed_clone_cleaned_up: bool,
    /// How long the create waited in the ledger's queue, when it did (S10 line 351).
    pub queued_nanos: Option<u64>,
    /// Create initiated to the first successful command, when one came.
    pub first_command_nanos: Option<u64>,
    pub failure: Option<FailureKind>,
    pub rejection: Option<RejectionKind>,
    pub limiting_resource: Option<ResourceKind>,
    /// The supervisor's refusal of a call, kept as typed.
    pub supervisor_refusal: Option<SupervisorError>,
}

/// One independent burst: its first attempts, their successes, and its window from the
/// first create initiated to the last first attempt resolved; retries are not counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct BurstWindow {
    pub burst: u32,
    pub attempts: u32,
    pub successes: u32,
    pub first_create_nanos: u64,
    pub last_resolution_nanos: u64,
}

impl BurstWindow {
    pub fn elapsed_nanos(&self) -> u64 {
        self.last_resolution_nanos
            .saturating_sub(self.first_create_nanos)
    }

    /// Successful creates per second of the window; undefined for a window of no length.
    pub fn successes_per_second(&self) -> Quotient {
        Quotient::divide(
            f64::from(self.successes),
            self.elapsed_nanos() as f64 / 1e9,
            UndefinedReason::ZeroDenominator,
        )
    }
}

/// Why a percentile has weak resolution (S11 line 379; S8 line 321).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum WeakResolution {
    /// Every successful sample came from one burst: "A p99 computed from a single
    /// 100-instance burst has weak resolution."
    SingleBurst,
    /// Fewer independent bursts than CORE-08's rule needs.
    FewBursts { bursts: u64, required: u64 },
    /// Fewer samples beyond the percentile's rank than CORE-08's rule needs.
    FewTailSamples { tail_samples: u64, required: u64 },
}

/// One percentile of the first-command clock with its resolution.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "resolution", rename_all = "snake_case")]
pub enum TailResolution {
    Resolved {
        value_nanos: f64,
    },
    /// Reported, never claimed; a value is absent only when nothing succeeded.
    Weak {
        value_nanos: Measured<f64>,
        reasons: Vec<WeakResolution>,
    },
}

/// A VM run's report: the raw records and what S8 asks to show beside them.
#[derive(Clone, Debug, PartialEq)]
pub struct VmRunReport {
    pub bench: BenchId,
    pub variant: Label,
    pub load: LoadDescription,
    pub bursts: u32,
    /// Every attempt, failures included, as CORE-08 raw records (S8 line 321): the first
    /// attempts in order, then the retries in the order created.
    pub ledger: AttemptLedger,
    /// Create initiated to first command over the successful initial attempts, untrimmed,
    /// beside the overall success rate, its Wilson interval, the deadline failures and the
    /// taxonomy.
    pub first_command: LatencySummary,
    /// Create initiated to the API acknowledgment, recorded apart (S8 line 317).
    pub api_acknowledgement: LatencySummary,
    /// The first attempts, in order; `records()` holds theirs at the same positions.
    pub attempts: Vec<AttemptSummary>,
    /// Rejected first attempts by kind; every kind is present, zero included.
    pub rejections: BTreeMap<RejectionKind, u64>,
    pub windows: Vec<BurstWindow>,
    /// Launch and checkout calls the supervisor answered, calls again for queued creates
    /// and retries included; each ran one boot through the same authority checks.
    pub boot_calls: u64,
    /// The lifecycle's own first-command samples of the first attempts' boots. A retry's
    /// boot is checked against the lifecycle's clock in the same way during the run.
    pub lifecycle_first_commands: Vec<FirstCommandSample>,
    /// The retries, beside the first-attempt results above.
    pub retries: RetryReport,
}

impl VmRunReport {
    /// Builds the report from every attempt's record and summary.
    pub(crate) fn assemble(
        spec: &RunSpec,
        records: Vec<RunRecord>,
        attempts: Vec<AttemptSummary>,
        retries: RetryOutcomes,
        windows: Vec<BurstWindow>,
        boot_calls: u64,
        lifecycle_first_commands: Vec<FirstCommandSample>,
    ) -> Result<Self, BenchError> {
        let ledger = AttemptLedger::from_records(records)?;
        let retries = RetryReport::new(spec.retries().clone(), &ledger, retries)?;
        let first_command =
            LatencySummary::from_ledger(&ledger, IntervalKind::VmFirstGuestCommand, METHOD)?;
        let api_acknowledgement =
            LatencySummary::from_ledger(&ledger, IntervalKind::VmApiAcknowledgement, METHOD)?;
        let mut rejections: BTreeMap<RejectionKind, u64> =
            RejectionKind::ALL.iter().map(|kind| (*kind, 0)).collect();
        for kind in attempts.iter().filter_map(|attempt| attempt.rejection) {
            *rejections.entry(kind).or_insert(0) += 1;
        }
        Ok(Self {
            bench: spec.bench(),
            variant: spec.variant().clone(),
            load: spec.load(),
            bursts: spec.bursts(),
            ledger,
            first_command,
            api_acknowledgement,
            attempts,
            rejections,
            windows,
            boot_calls,
            lifecycle_first_commands,
            retries,
        })
    }

    /// Every raw record, failures included.
    pub fn records(&self) -> &[RunRecord] {
        self.ledger.records()
    }

    /// Successful initial attempts over every initial attempt (S8 line 321). Retries
    /// change neither number.
    pub fn success_rate(&self) -> Result<SuccessRate, BenchError> {
        Ok(self.ledger.success_rate()?)
    }

    /// First attempts that succeeded or that a retry completed, over every first attempt:
    /// reported beside [`VmRunReport::success_rate`], never in its place.
    pub fn success_with_retries(&self) -> SuccessRate {
        self.retries.success_with_retries
    }

    /// The failure taxonomy of the initial attempts.
    pub fn failures(&self) -> FailureCounts {
        self.ledger.failures()
    }

    /// Failed initial attempts over every initial attempt.
    pub fn failure_fraction(&self) -> Result<f64, BenchError> {
        Ok(1.0 - self.success_rate()?.rate())
    }

    /// The mean over the bursts of successful first attempts per second; a window of no
    /// length counts as zero.
    pub fn mean_successes_per_second(&self) -> f64 {
        let count = self.windows.len().max(1) as f64;
        self.windows
            .iter()
            .map(|window| window.successes_per_second().value().unwrap_or(0.0))
            .sum::<f64>()
            / count
    }

    /// The `quantile` of the first-command clock with its resolution (S11 line 379).
    pub fn tail(&self, quantile: Quantile) -> Result<TailResolution, BenchError> {
        let estimate =
            self.first_command
                .percentile(quantile)
                .ok_or(BenchError::InvalidParameter {
                    field: "quantile",
                    reason: "the summaries report p50, p95 and p99",
                })?;
        Ok(match estimate.resolution {
            Resolution::Resolved => match estimate.value_nanos.value() {
                Some(value) => TailResolution::Resolved {
                    value_nanos: *value,
                },
                None => TailResolution::Weak {
                    value_nanos: estimate.value_nanos.clone(),
                    reasons: Vec::new(),
                },
            },
            Resolution::LowResolution {
                tail_samples,
                required_tail_samples,
                bursts,
                required_bursts,
            } => {
                let mut reasons = Vec::new();
                if bursts == 1 {
                    reasons.push(WeakResolution::SingleBurst);
                } else if bursts < required_bursts {
                    reasons.push(WeakResolution::FewBursts {
                        bursts,
                        required: required_bursts,
                    });
                }
                if tail_samples < required_tail_samples {
                    reasons.push(WeakResolution::FewTailSamples {
                        tail_samples,
                        required: required_tail_samples,
                    });
                }
                TailResolution::Weak {
                    value_nanos: estimate.value_nanos.clone(),
                    reasons,
                }
            }
        })
    }

    /// The provenance CORE-08 gives these records: the fake substrate for every run here.
    pub fn provenance(&self) -> Result<Provenance, BenchError> {
        Ok(Provenance::of_records(self.records())?)
    }

    /// A claimed first-command percentile. The records must be Yougori evidence first, so
    /// a fake run is refused before the percentile is looked at (S12 G0).
    pub fn latency_claim(&self, quantile: Quantile) -> Result<LatencyClaim, BenchError> {
        self.provenance()?.yougori_evidence()?;
        Ok(LatencyClaim::from_summary(&self.first_command, quantile)?)
    }

    /// A claim about burst scale (S12 line 387); CORE-08 refuses a fake ledger.
    pub fn burst_scale_claim(&self, claimed: u64) -> Result<BurstScaleClaim, BenchError> {
        Ok(BurstScaleClaim::new(claimed, &self.ledger)?)
    }

    /// The BENCH-13 record of the run (S11 line 377): every raw record with its events and
    /// failures, retries included, configuration digests, the statistical method, the date, untrimmed
    /// distributions of both intervals and the limitations, which CORE-08 derives from the
    /// records (a fake runner, low-resolution tails) beside `declared` ones.
    pub fn reproducibility(
        &self,
        statement: Label,
        reproduced_on: NaiveDate,
        declared: Vec<Limitation>,
    ) -> Result<ReproducibilityRecord, BenchError> {
        let harness = self
            .records()
            .first()
            .map(|record| record.build.runner_build)
            .ok_or(BenchError::Report(
                crate::foundation::report::ReportError::NoAttempts,
            ))?;
        Ok(ReproducibilityRecord::new(
            ClaimUnderTest::Yougori {
                bench: self.bench,
                statement,
            },
            StatisticalMethod::new(METHOD, INTERVALS.to_vec()),
            reproduced_on,
            harness,
            self.records().to_vec(),
            declared,
        )?)
    }

    /// Distinct VM identities among the first attempts' boots that reached authority.
    pub fn unique_vm_identities(&self) -> u64 {
        self.attempts
            .iter()
            .filter_map(|attempt| attempt.vm)
            .collect::<BTreeSet<_>>()
            .len() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::coordination::SandboxState;
    use crate::foundation::coordination::{
        PortFailure, PortOperation, RetryProspect, StepKind, TransitionRefusal,
    };

    #[test]
    fn rejections_are_typed_by_the_step_that_refused() {
        let host = LaunchFailure::Capacity {
            refusal: CapacityRefusal::Insufficient {
                resource: ResourceKind::HostMemoryBytes,
                limit: CapacityLimit::Host,
                requested: 8,
                available: 4,
                retry: RetryProspect::CanProgress,
            },
        };
        assert_eq!(
            RejectionKind::of_failure(&host),
            RejectionKind::HostCapacity
        );
        assert_eq!(
            RejectionKind::limiting_resource(&host),
            Some(ResourceKind::HostMemoryBytes)
        );
        let full = LaunchFailure::Capacity {
            refusal: CapacityRefusal::QueueFull {
                resource: ResourceKind::CpuInitializationSlots,
            },
        };
        assert_eq!(RejectionKind::of_failure(&full), RejectionKind::QueueFull);
        let port = LaunchFailure::Port {
            failure: PortFailure {
                operation: PortOperation::CreateVm,
                detail: "injected".to_owned(),
            },
        };
        assert_eq!(
            RejectionKind::of_failure(&port),
            RejectionKind::BackendRefused
        );
        assert_eq!(RejectionKind::limiting_resource(&port), None);
        let transition = LaunchFailure::Transition {
            refusal: TransitionRefusal::InvalidTransition {
                from: SandboxState::Stopped,
                step: StepKind::CreateVm,
            },
        };
        assert_eq!(
            RejectionKind::of_failure(&transition),
            RejectionKind::Transition
        );
        // Every kind has a component and a code a record label accepts.
        let codes: BTreeSet<&str> = RejectionKind::ALL.iter().map(|kind| kind.code()).collect();
        assert_eq!(codes.len(), RejectionKind::ALL.len());
        for kind in RejectionKind::ALL {
            Label::new(kind.code()).unwrap();
            Label::new(kind.component()).unwrap();
        }
    }

    #[test]
    fn a_window_of_no_length_has_no_rate() {
        let window = BurstWindow {
            burst: 0,
            attempts: 4,
            successes: 4,
            first_create_nanos: 1_000,
            last_resolution_nanos: 2_000_001_000,
        };
        assert_eq!(window.successes_per_second().value(), Some(2.0));
        let empty = BurstWindow {
            last_resolution_nanos: 1_000,
            ..window
        };
        assert!(empty.successes_per_second().value().is_none());
    }
}
