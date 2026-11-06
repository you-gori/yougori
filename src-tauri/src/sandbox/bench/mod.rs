//! The VM benchmark harness on fakes: BENCH-05 and BENCH-06 plans, a fake
//! time-controlled runner over the lifecycle supervisor, and their CORE-08 records
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: S7 lines 296–297; S8 lines 311–323;
//! S10 lines 351–353; S11 lines 361, 369–370, 377 and 379; S12 lines 383 and 387; §6.6
//! lines 2336–2353; §12.4 lines 2842–2857; VM-W49 line 2672), the EVIDENCE role of S4.
//!
//! - [`plan`]: sequential, staggered and burst create plans on one first-command clock;
//!   the 100-concurrent case exists only as a plan that needs an authorized, sized host
//!   and is refused here; the BENCH-06 cases.
//! - [`timing`]: the seeded fake timing of the first command and the injected faults.
//! - [`host`]: the port the runner drives: a lifecycle supervisor, a lifecycle backend
//!   port over a fake backend, the CORE-01 registry and a manual clock.
//! - [`runner`]: the time-controlled runner. Every attempt becomes a CORE-08
//!   [`RunRecord`](crate::foundation::report::RunRecord) on the fake substrate: successes,
//!   timeouts, rejections by type, command failures, early exits and duplicate identities.
//! - [`retry`]: a plan's explicit, bounded retry policy, off by default; every retry is
//!   its own record linked to its first attempt, reported beside the first attempts.
//! - [`report`]: all-attempt success, conditional untrimmed tails, the taxonomy, the
//!   resolution flags of S11, the BENCH-13 record, and claims that a fake run never backs.
//!   Every denominator is the first attempts (S8 line 321).
//! - [`knee`]: the saturation knee search, as a pure search and over the runner; it
//!   ignores retries.
//! - [`pool`]: BENCH-06 cold VM, limited warm pool, clean snapshot and pool depletion and
//!   replenishment, counted from the lifecycle's pool rules.
//!
//! Nothing here creates a VM, starts a process or reads a real clock. A run on the fake
//! substrate validates the record format and the comparison discipline and backs no
//! release or performance claim (S2 CORE-08; S12 G0; rollout T02 follow-up).

pub mod host;
pub mod knee;
pub mod plan;
pub mod pool;
pub mod report;
pub mod retry;
pub mod runner;
pub mod timing;

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

use std::fmt;

use crate::foundation::coordination::CapacityRefusal;
use crate::foundation::ids::{ExecutionId, IdError};
use crate::foundation::report::ReportError;
use crate::sandbox::lifecycle::{BackendFailure, PoolRefusal, SupervisorError};

pub use host::{Drive, FakeVmHost, RecordTemplate};
pub use knee::{
    knee_search, saturation_search, saturation_search_with_retries, KneePoint, KneePolicy,
    KneeReport, KneeStop,
};
pub use plan::{
    ArrivalPattern, AttemptLimits, Bench05Plan, Bench06Case, Bench06Plan, BenchHost,
    HostRequirement, ReplenishmentSchedule, RunSpec, AUTHORIZED_HOST_CONCURRENCY,
};
pub use pool::{PathDistribution, PoolCaseCounts, PoolCaseReport, ReplenishmentCharge};
pub use report::{
    AttemptSummary, BurstWindow, RejectionKind, TailResolution, VmRunReport, WeakResolution,
};
pub use retry::{
    NoRetry, RetryDecision, RetryPolicy, RetryReport, RetrySummary, MAX_RETRIES_PER_ATTEMPT,
};
pub use runner::{FakeVmRunner, RunnerConfig};
pub use timing::{FakeVmTiming, FaultPlan, InjectedFault, SeededRng};

/// Why the harness refused a plan or could not finish a run.
#[derive(Clone, Debug, PartialEq)]
pub enum BenchError {
    /// A plan or timing parameter is out of its range.
    InvalidParameter {
        field: &'static str,
        reason: &'static str,
    },
    /// S11 BENCH-05: this many concurrent creates run only on an isolated host or
    /// provider that is sized and authorized for them; never on the fake substrate.
    NeedsAuthorizedSizedHost { concurrent_creates: u32 },
    /// The authorized host is sized for fewer concurrent creates than the plan needs.
    HostUndersized {
        concurrent_creates: u32,
        sized_for: u32,
    },
    /// The supervisor's clock is not the manual clock the runner moves.
    ClockNotControlled {
        expected_nanos: u64,
        found_nanos: u64,
    },
    /// The lifecycle's first-command time and the record's disagree for one boot.
    ClockDisagreement {
        execution: ExecutionId,
        lifecycle_nanos: u64,
        harness_nanos: u64,
    },
    /// A stop did not bring the sandbox to stopped.
    StopIncomplete { execution: ExecutionId },
    /// A setup step the measured phase depends on did not reach authority.
    SetupFailed {
        step: &'static str,
        execution: ExecutionId,
    },
    /// The run ended with an attempt still open; the runner lost an event.
    UnresolvedAttempt { index: u32 },
    /// A time or count does not fit in 64 bits.
    Overflow,
    /// A shared identifier was refused.
    Id(IdError),
    /// CORE-08 refused a record, ledger, summary or claim.
    Report(ReportError),
    /// The supervisor refused a call outside an attempt, such as a stop.
    Supervisor(SupervisorError),
    /// The backend refused a setup step, such as the golden snapshot.
    Backend(BackendFailure),
    /// The lifecycle's pool rules refused the snapshot or the pool.
    Pool(PoolRefusal),
    /// The ledger refused to withdraw a queued reservation.
    Capacity(CapacityRefusal),
}

impl fmt::Display for BenchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameter { field, reason } => write!(f, "{field}: {reason}"),
            Self::NeedsAuthorizedSizedHost { concurrent_creates } => write!(
                f,
                "{concurrent_creates} concurrent creates need an isolated host or provider \
                 that is sized and authorized for them; the fake substrate cannot run them"
            ),
            Self::HostUndersized {
                concurrent_creates,
                sized_for,
            } => write!(
                f,
                "the authorized host is sized for {sized_for} concurrent creates, not \
                 {concurrent_creates}"
            ),
            Self::ClockNotControlled {
                expected_nanos,
                found_nanos,
            } => write!(
                f,
                "the supervisor reads {found_nanos} ns where the runner set {expected_nanos} \
                 ns; it is not on the runner's manual clock"
            ),
            Self::ClockDisagreement {
                execution,
                lifecycle_nanos,
                harness_nanos,
            } => write!(
                f,
                "the first command of {execution} took {lifecycle_nanos} ns by the lifecycle \
                 and {harness_nanos} ns by the harness"
            ),
            Self::StopIncomplete { execution } => {
                write!(f, "the stop of {execution} did not reach the stopped state")
            }
            Self::SetupFailed { step, execution } => {
                write!(
                    f,
                    "setup step {step} of {execution} did not reach authority"
                )
            }
            Self::UnresolvedAttempt { index } => {
                write!(f, "attempt {index} was still open when the run ended")
            }
            Self::Overflow => f.write_str("a time or count does not fit in 64 bits"),
            Self::Id(error) => error.fmt(f),
            Self::Report(error) => error.fmt(f),
            Self::Supervisor(error) => error.fmt(f),
            Self::Backend(failure) => failure.fmt(f),
            Self::Pool(refusal) => refusal.fmt(f),
            Self::Capacity(refusal) => refusal.fmt(f),
        }
    }
}

impl std::error::Error for BenchError {}

impl From<IdError> for BenchError {
    fn from(error: IdError) -> Self {
        Self::Id(error)
    }
}

impl From<ReportError> for BenchError {
    fn from(error: ReportError) -> Self {
        Self::Report(error)
    }
}

impl From<SupervisorError> for BenchError {
    fn from(error: SupervisorError) -> Self {
        Self::Supervisor(error)
    }
}

impl From<BackendFailure> for BenchError {
    fn from(failure: BackendFailure) -> Self {
        Self::Backend(failure)
    }
}

impl From<PoolRefusal> for BenchError {
    fn from(refusal: PoolRefusal) -> Self {
        Self::Pool(refusal)
    }
}

impl From<CapacityRefusal> for BenchError {
    fn from(refusal: CapacityRefusal) -> Self {
        Self::Capacity(refusal)
    }
}
