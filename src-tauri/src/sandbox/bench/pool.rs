//! BENCH-06 on the fake substrate (S11 line 370; S10 lines 351–353; §6.6 lines
//! 2161–2178; VM-W27): cold VM, limited warm pool, clean snapshot, and pool depletion and
//! replenishment, all on the first-command clock of BENCH-05.
//!
//! The pool rules are the lifecycle's: only a certified [`GoldenSnapshot`] enters a
//! [`WarmPool`], a checkout restores only a stopped sandbox, and every cold boot instead
//! of a restore names its reason. The harness counts what the receipts say: the boots
//! on each path, cold fallbacks by reason, restored clones that failed verification and
//! were cleaned up, restores the backend refused, distinct VM identities, and whether
//! every boot, warm or cold, went through the same authority checks. Every clone
//! prepared for the pool is charged to the measured path. Backend memory and cost have no
//! instrument on the fake and are recorded as not measured.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::host::FakeVmHost;
use super::plan::{Bench06Case, Bench06Plan, BenchHost};
use super::report::{AttemptSummary, VmRunReport, METHOD};
use super::runner::{CreateSource, FakeVmRunner, PoolSource};
use super::timing::FaultPlan;
use super::BenchError;
use crate::foundation::coordination::SnapshotOrigin;
use crate::foundation::report::{
    percentile, resolution, Measured, NonNegative, NotMeasuredReason, Quantile, Quotient,
    UndefinedReason,
};
use crate::sandbox::lifecycle::{
    BootPath, CheckoutDecision, ColdFallback, GoldenSnapshot, PercentileReport, PoolCounts,
    SnapshotProvenance, WarmPool,
};

/// What preparing the pool's clones cost; all of it is charged to the measured path,
/// unused clones included (S10 line 353).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ReplenishmentCharge {
    pub clones_prepared: u64,
    pub prepare_nanos_each: u64,
    pub charged_nanos: u64,
}

impl ReplenishmentCharge {
    pub(crate) fn new(prepare_nanos_each: u64) -> Self {
        Self {
            clones_prepared: 0,
            prepare_nanos_each,
            charged_nanos: 0,
        }
    }

    pub(crate) fn add(&mut self, clones: u64, nanos: u64) -> Result<(), BenchError> {
        self.clones_prepared = self
            .clones_prepared
            .checked_add(clones)
            .ok_or(BenchError::Overflow)?;
        self.charged_nanos = self
            .charged_nanos
            .checked_add(nanos)
            .ok_or(BenchError::Overflow)?;
        Ok(())
    }

    /// The charge spread over `warm_restores`; undefined when nothing was restored.
    pub fn per_warm_restore_nanos(&self, warm_restores: u64) -> Quotient {
        Quotient::divide(
            self.charged_nanos as f64,
            warm_restores as f64,
            UndefinedReason::ZeroDenominator,
        )
    }
}

/// Why a checkout booted cold, without the backend's detail (§6.6; VM-W27).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackReason {
    RestoreUnsupported,
    StateResetUnsupported,
    PoolDepleted,
    NewExecution,
    CloneVerificationFailed,
}

impl FallbackReason {
    pub fn of(fallback: &ColdFallback) -> Self {
        match fallback {
            ColdFallback::RestoreUnsupported => Self::RestoreUnsupported,
            ColdFallback::StateResetUnsupported { .. } => Self::StateResetUnsupported,
            ColdFallback::PoolDepleted => Self::PoolDepleted,
            ColdFallback::NewExecution => Self::NewExecution,
            ColdFallback::CloneVerificationFailed => Self::CloneVerificationFailed,
        }
    }
}

/// The BENCH-06 counts of one case, from the receipts of its measured attempts: its
/// first attempts, or apart from them its retries.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PoolCaseCounts {
    pub attempts: u64,
    /// Boots that reached authority by restoring a clone.
    pub warm_restores: u64,
    /// Boots that reached authority cold, by design or as a fallback.
    pub cold_boots: u64,
    /// Checkouts that booted cold instead of restoring, by reason.
    pub cold_fallbacks: BTreeMap<FallbackReason, u64>,
    /// Restored clones that failed verification and were cleaned up before a cold boot.
    pub failed_clone_cleanups: u64,
    /// Restores the backend refused: rolled back, nothing exposed, no cold boot.
    pub restore_rollbacks: u64,
    /// Distinct VM identities among the boots that reached authority.
    pub unique_vm_identities: u64,
    /// Attempts whose first command succeeded, inside the deadline or not.
    pub successful_first_commands: u64,
}

/// The first-command distribution of one boot path over the first attempts, untrimmed,
/// with each percentile's resolution (S8 line 323: cold and warm states reported
/// separately; §12.4 line 2846).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PathDistribution {
    pub path: BootPath,
    /// Boots on this path that reached authority.
    pub boots: u64,
    /// Of those, attempts that succeeded within the deadline: the samples.
    pub successes: u64,
    pub bursts: u64,
    pub percentiles: Vec<PercentileReport>,
}

impl PathDistribution {
    pub fn percentile(&self, quantile: Quantile) -> Option<&PercentileReport> {
        self.percentiles
            .iter()
            .find(|report| report.quantile == quantile)
    }
}

/// One BENCH-06 case.
#[derive(Clone, Debug, PartialEq)]
pub struct PoolCaseReport {
    pub case: Bench06Case,
    /// The raw records and the BENCH-05 summaries of the case's attempts.
    pub run: VmRunReport,
    pub counts: PoolCaseCounts,
    /// The lifecycle's own pool counts over the measured phase, setup excluded.
    pub lifecycle: PoolCounts,
    pub by_path: Vec<PathDistribution>,
    pub replenishment: ReplenishmentCharge,
    /// Backend-specific memory per VM: no instrument on the fake substrate.
    pub backend_memory_bytes: Measured<u64>,
    /// Backend-specific cost per create: no instrument on the fake substrate.
    pub backend_cost_usd: Measured<NonNegative>,
}

impl PoolCaseReport {
    /// Whether every boot of the case, warm or cold, ran the same authority checks: the
    /// lifecycle counted one for each launch and checkout the supervisor answered, its
    /// retries' included.
    pub fn identical_authority_checks(&self) -> bool {
        self.lifecycle.authority_checks == self.run.boot_calls
    }

    /// The same counts over the case's retries, kept apart from [`PoolCaseReport::counts`]
    /// of its first attempts; the lifecycle's counts cover both.
    pub fn retry_counts(&self) -> PoolCaseCounts {
        counts(self.run.retries.attempts.iter().map(|retry| &retry.attempt))
    }

    /// The replenishment charge per warm restore (S10 line 353).
    pub fn charge_per_warm_restore_nanos(&self) -> Quotient {
        self.replenishment
            .per_warm_restore_nanos(self.counts.warm_restores)
    }

    pub fn path(&self, path: BootPath) -> Option<&PathDistribution> {
        self.by_path
            .iter()
            .find(|distribution| distribution.path == path)
    }
}

fn delta(after: PoolCounts, before: PoolCounts) -> PoolCounts {
    PoolCounts {
        authority_checks: after
            .authority_checks
            .saturating_sub(before.authority_checks),
        unique_identities: after
            .unique_identities
            .saturating_sub(before.unique_identities),
        warm_restores: after.warm_restores.saturating_sub(before.warm_restores),
        cold_fallbacks: after.cold_fallbacks.saturating_sub(before.cold_fallbacks),
        failed_clone_cleanups: after
            .failed_clone_cleanups
            .saturating_sub(before.failed_clone_cleanups),
        restore_rollbacks: after
            .restore_rollbacks
            .saturating_sub(before.restore_rollbacks),
        successful_first_commands: after
            .successful_first_commands
            .saturating_sub(before.successful_first_commands),
    }
}

fn counts<'a>(attempts: impl Iterator<Item = &'a AttemptSummary>) -> PoolCaseCounts {
    let mut counts = PoolCaseCounts::default();
    let mut identities = BTreeSet::new();
    for attempt in attempts {
        counts.attempts += 1;
        if let Some(vm) = attempt.vm {
            identities.insert(vm);
        }
        match attempt.path {
            Some(BootPath::WarmRestore) => counts.warm_restores += 1,
            Some(BootPath::Cold) => counts.cold_boots += 1,
            None => {}
        }
        match &attempt.decision {
            Some(CheckoutDecision::ColdBoot { fallback }) => {
                *counts
                    .cold_fallbacks
                    .entry(FallbackReason::of(fallback))
                    .or_insert(0) += 1;
            }
            Some(CheckoutDecision::Restore) if attempt.rejection.is_some() => {
                counts.restore_rollbacks += 1;
            }
            _ => {}
        }
        if attempt.failed_clone_cleaned_up {
            counts.failed_clone_cleanups += 1;
        }
        if attempt.first_command_nanos.is_some() {
            counts.successful_first_commands += 1;
        }
    }
    counts.unique_vm_identities = identities.len() as u64;
    counts
}

fn by_path(run: &VmRunReport) -> Result<Vec<PathDistribution>, BenchError> {
    let mut distributions = Vec::new();
    for path in [BootPath::Cold, BootPath::WarmRestore] {
        let boots: Vec<_> = run
            .attempts
            .iter()
            .filter(|attempt| attempt.path == Some(path))
            .collect();
        let mut samples: Vec<u64> = Vec::new();
        let mut bursts = BTreeSet::new();
        for attempt in &boots {
            if let (None, Some(nanos)) = (attempt.failure, attempt.first_command_nanos) {
                samples.push(nanos);
                bursts.insert(attempt.burst);
            }
        }
        samples.sort_unstable();
        let mut percentiles = Vec::with_capacity(Quantile::REPORTED.len());
        for quantile in Quantile::REPORTED {
            let value_nanos = if samples.is_empty() {
                Measured::not_measured(NotMeasuredReason::NoSuccessfulRuns)
            } else {
                Measured::measured(percentile(&samples, quantile, METHOD)?)
            };
            percentiles.push(PercentileReport {
                quantile,
                value_nanos,
                resolution: resolution(samples.len() as u64, bursts.len() as u64, quantile),
            });
        }
        distributions.push(PathDistribution {
            path,
            boots: boots.len() as u64,
            successes: samples.len() as u64,
            bursts: bursts.len() as u64,
            percentiles,
        });
    }
    Ok(distributions)
}

impl<'h, H: FakeVmHost> FakeVmRunner<'h, H> {
    /// Launches a new execution, takes a snapshot of it with the pre-tenant golden origin,
    /// certifies it under the lifecycle's pool rules and stops it. The harness sends the
    /// VM no tenant input, credential or connection before the snapshot, which is what
    /// the provenance states; the lifecycle still refuses any manifest with forbidden
    /// contents or another image profile (§6.6 line 2338).
    pub fn golden_snapshot(&mut self) -> Result<GoldenSnapshot, BenchError> {
        let execution = self.fresh_execution("golden")?;
        self.launch_setup(&execution, "golden-launch")?;
        let (manifest, expected) = {
            let drive = self.host().drive();
            let supervisor = drive.supervisor;
            let mut backend = drive.backend;
            let handle = supervisor
                .coordinator()
                .sandbox(&execution)
                .and_then(|sandbox| sandbox.vm())
                .and_then(|vm| supervisor.handles().get(&vm).cloned())
                .ok_or(BenchError::SetupFailed {
                    step: "golden-handle",
                    execution: execution.clone(),
                })?;
            let manifest = backend.snapshot(&handle, SnapshotOrigin::PreTenantGolden)?;
            (manifest, supervisor.config().expected_image_profile)
        };
        let golden = GoldenSnapshot::certify(
            manifest,
            SnapshotProvenance {
                before_tenant_inputs: true,
                before_credentials: true,
                before_external_connections: true,
            },
            expected,
        )?;
        self.stop_execution(&execution)?;
        Ok(golden)
    }

    /// Runs one BENCH-06 case. The cold VM case launches new executions; the pool cases
    /// first prepare one stopped sandbox per checkout of a burst (setup, not measured),
    /// then check them out of a pool based on `golden`.
    pub fn run_bench06(
        &mut self,
        plan: &Bench06Plan,
        golden: Option<&GoldenSnapshot>,
        faults: &FaultPlan,
    ) -> Result<PoolCaseReport, BenchError> {
        plan.spec().admit(&BenchHost::FakeTimeControlled)?;
        let prepare_nanos_each = self.config().timing.clone_prepare_nanos;
        let (run, before, replenishment) = if plan.uses_pool() {
            let golden = golden.ok_or(BenchError::InvalidParameter {
                field: "golden",
                reason: "a warm-pool case restores a certified golden snapshot",
            })?;
            let mut pool = WarmPool::new(plan.pool_capacity());
            pool.set_golden(golden.clone());
            let mut slots = Vec::new();
            for _ in 0..plan.spec().attempts_per_burst() {
                let slot = self.fresh_execution("slot")?;
                self.launch_setup(&slot, "slot-launch")?;
                self.stop_execution(&slot)?;
                slots.push(slot);
            }
            let before = self.host().drive().supervisor.measurements().pool();
            let mut source = CreateSource::Checkout(PoolSource {
                pool: &mut pool,
                slots,
                initial_clones: plan.initial_clones(),
                replenishment: plan.replenishment(),
                charge: ReplenishmentCharge::new(prepare_nanos_each),
            });
            let run = self.run(plan.spec(), &mut source, faults)?;
            let charge = match source {
                CreateSource::Checkout(pool) => pool.charge,
                CreateSource::Launch => ReplenishmentCharge::new(prepare_nanos_each),
            };
            (run, before, charge)
        } else {
            let before = self.host().drive().supervisor.measurements().pool();
            let run = self.run(plan.spec(), &mut CreateSource::Launch, faults)?;
            (run, before, ReplenishmentCharge::new(prepare_nanos_each))
        };
        let after = self.host().drive().supervisor.measurements().pool();
        Ok(PoolCaseReport {
            case: plan.case(),
            counts: counts(run.attempts.iter()),
            lifecycle: delta(after, before),
            by_path: by_path(&run)?,
            run,
            replenishment,
            backend_memory_bytes: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
            backend_cost_usd: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
        })
    }
}
