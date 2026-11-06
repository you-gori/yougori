//! GPU-N1: select preparation bundles by the delay they remove (GPU §4.14 of
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md, lines 778–837, mapped into GPU-W06 by
//! §4.17, lines 902–917).
//!
//! Useful state can be complementary: preparing one object may save no request time until
//! another is ready too, and one shared object may unlock several requests. Independent
//! per-object scores miss both effects. This module values a group of objects by the
//! weighted completion time it removes from the requests in a bounded horizon:
//!
//! ```text
//! benefit(X) = sum_r w_r * (T_r(empty) - T_r(X))
//! choose X to maximize benefit(X) - preparation_cost(X) - interference(X)
//! subject to physical memory, transient capacity and trust constraints
//! ```
//!
//! - [`horizon`]: the bounded horizon of admitted and sufficiently likely requests, the
//!   state objects they need, budgets, trust scopes and the declared objective (step 1).
//! - [`evaluate`]: T_r(X) from a resource-feasible schedule of one graph built from the
//!   horizon, through [`crate::model_memory::graph::paths::plan`] and its bounded
//!   heuristic: queues, dependency barriers, shared links, scheduled preparation and
//!   transient memory are all part of it, never bytes over nominal bandwidth.
//! - [`candidates`]: latest prerequisite branches and the bounded candidate set (steps 2–3).
//! - [`planner`]: the bundle method (steps 4–7) under an explicit work budget, the
//!   object-greedy ablation, and the exhaustive optimum for tiny horizons.
//! - [`baselines`]: LRU, cost-per-byte, marginal saved latency and GreedyDual-Size from
//!   [`crate::model_memory::residency`], shared bases charged once.
//! - [`workloads`]: the §4.14 counterexample, seeded tiny, adversarial and shared-base
//!   workloads, forecast perturbation and realization.
//! - [`experiment`]: the first-prototype comparison under equal budgets, planner overhead,
//!   forecast errors, the enumeration bound, the pass/stop rule, the claim record and the
//!   fake-substrate CORE-08 records.
//!
//! The value function is not submodular: in the §4.14 toy, a's marginal value rises from
//! zero to eight after b is retained. No submodular-greedy approximation guarantee is
//! claimed anywhere in this module; the exhaustive optimum is the only reference.
//!
//! Everything is pure, synchronous and deterministic. Time comes from
//! [`crate::foundation::ids::Clock`]; randomness only from the seeded
//! [`SplitMix64`](crate::model_memory::residency::simulator::SplitMix64). Every simulated
//! result is recorded under the fake-substrate provenance of
//! [`crate::foundation::report`], which validates schemas and comparisons and backs no
//! performance, improvement or release claim.
//!
//! # Claim record
//!
//! GPU §4.17 requires a short claim record for GPU-N1. [`experiment::claim_record`]
//! computes the result field; the text fields are fixed here and in
//! [`experiment::CLAIM_CONTRIBUTION`].
//!
//! 1. **Proposed contribution.** A bounded planner that chooses which state to retain or
//!    prepare by the weighted request delay a whole group removes under a
//!    resource-feasible schedule (queues, dependency barriers, shared links, scheduled
//!    preparation and transient memory), with candidates built from concurrent blockers,
//!    dependency closures and shared state, bounded local replacement, and a typed
//!    fallback to measured cost-per-byte or demand-only.
//! 2. **Closest prior work** (the §4.13 table): Dependency-Aware Online Caching
//!    (arXiv 2401.17146), caching with prerequisites; ELORA (IEEE 11408492), joint adapter
//!    and session-cache dependencies; Chameleon (arXiv 2411.17741), adapter caching
//!    combined with scheduling. Their papers and implementations were not compared here.
//! 3. **Difference tested.** Value is the delay removed for the actual requests of the
//!    horizon, computed by simulating the schedule with and without a group, so
//!    complementary objects are valued together and a shared object is credited for every
//!    request it unlocks; no independent per-object score is used.
//! 4. **Correctness assumptions and smallest counterexample.** The bounded heuristic
//!    schedule stands in for the true completion order; forecasts of arrivals, durations
//!    and probabilities are close enough; and greedy selection with one-group replacement
//!    approaches the optimum. The last fails on a five-object knapsack: budget 6, objects
//!    x and w (3 bytes, 10 s each) and y, z, u (2 bytes, 7 s each), one request per
//!    object. The method keeps {x, w} (20 s) while {y, z, u} removes 21 s, and replacing
//!    one group cannot reach it (test `bounded_replacement_misses_a_three_way_swap`).
//! 5. **Comparison against the strongest compatible baseline.** Object-greedy, LRU,
//!    cost-per-byte, marginal saved latency, GreedyDual-Size and retaining nothing, under
//!    equal memory and planner budgets, with planner overhead charged (100 ns per work
//!    unit, on every request) and seeded forecast errors of 15 % and 30 %
//!    ([`experiment::first_prototype`] with [`experiment::PrototypeConfig::standard`]).
//!    Counterexample: 8 s of weighted delay removed against 4 s for every baseline.
//!    Shared-base horizons: +1.08 s per instance over the strongest baseline on average,
//!    +0.91 s under both forecast errors. Adversarial horizons with a shared two-slot
//!    link: −0.79 s on average, worse on three of six instances, −1.69 s and −0.20 s
//!    under the forecast errors. There the optimum keeps cheap decoy objects whose
//!    queued loads delay everyone, while ranking groups by marginal value commits the
//!    budget to large groups first. The ablations show the gain over object-greedy comes
//!    from local replacement: single objects with replacement match or beat the full
//!    method on average in both families.
//! 6. **Result: narrowed** (computed; test `the_first_prototype_narrows_the_claim`). The
//!    improvement does not persist in the adversarial family. Even an advance would be at
//!    most inconclusive: every run is a fake-substrate simulation, and an originality
//!    claim needs a literature and implementation comparison and hardware measurements
//!    this module cannot make ([`experiment::ClaimResult`]).

use std::fmt;

use crate::foundation::ids::IdError;
use crate::foundation::report::ReportError;
use crate::model_memory::graph::{GraphError, ScheduleError};
use crate::model_memory::math::calibration::CalibrationError;
use crate::model_memory::math::prefetch::PrefetchError;
use crate::model_memory::residency::retention::CacheError;

pub mod baselines;
pub mod candidates;
pub mod evaluate;
pub mod experiment;
pub mod horizon;
pub mod planner;
pub mod workloads;

#[cfg(test)]
mod tests;

pub use candidates::{Candidate, CandidateMode, CandidateOrigin};
pub use evaluate::{Evaluation, Evaluator, Infeasibility, Outcome, WorkMeter};
pub use horizon::{
    Admission, Horizon, HorizonBounds, HorizonSpec, ObjectSpec, RequestSpec, Selection,
};
pub use planner::{BundlePlan, FallbackPolicy, FallbackReason, PlanOutcome, PlannerConfig};

/// Why the bundle planner refused an input or could not finish.
#[derive(Clone, Debug, PartialEq)]
pub enum BundleError {
    /// An object or request id is not a valid identifier of at most
    /// [`horizon::MAX_ID_LEN`] characters.
    InvalidId { field: &'static str, value: String },
    /// An id appears twice where each must be unique.
    Duplicate { field: &'static str, id: String },
    /// An id names nothing that was declared.
    Unknown { field: &'static str, id: String },
    /// A number or setting is outside its range.
    InvalidValue {
        field: &'static str,
        reason: &'static str,
    },
    /// Reconstruction requirements form a cycle through this object.
    RequirementCycle { object: String },
    /// A request or object consumes state from another trust scope without an explicit
    /// allowance naming that state (S3.3, GPU §2.3).
    CrossScope { consumer: String, object: String },
    /// Per-scope budgets are declared, but not for this object's scope.
    ScopeWithoutBudget { object: String },
    /// A preparation cost carries milliseconds: the preparation penalty prices resource
    /// consumption, never latency, which T_r already includes (GPU §4.14, line 808).
    PreparationPricesLatency { object: String },
    /// The memory capacity is an address reservation, which supplies no physical
    /// capacity (GPU §2.7); X is subject to physical memory (§4.14).
    NotPhysicalCapacity { bytes: u64 },
    /// The admitted requests alone exceed the horizon bounds; admitted work is never
    /// dropped to fit.
    HorizonTooLarge { reason: &'static str },
    /// With nothing retained or prepared the horizon has no resource-feasible schedule.
    EmptyHorizonUnschedulable(ScheduleError),
    /// The planner's explicit work budget ran out (step 7).
    BudgetExhausted { spent_units: u64, max_units: u64 },
    /// The exhaustive optimum accepts only tiny horizons.
    TooLargeForExhaustive { objects: usize, max: usize },
    /// The request graph refused the horizon (GPU §2.3).
    Graph(GraphError),
    /// The schedule failed for a reason other than infeasibility (GPU §2.3).
    Schedule(ScheduleError),
    /// The declared objective refused a cost (GPU §2.9).
    Prefetch(PrefetchError),
    /// The forecast controller or calibration refused an input (GPU §2.9).
    Calibration(CalibrationError),
    /// A residency baseline refused its configuration (GPU §2.7).
    Cache(CacheError),
    /// CORE-08 refused a record or report.
    Report(ReportError),
    /// A shared identifier was refused.
    Id(IdError),
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId { field, value } => write!(f, "{field} {value:?} is not a valid id"),
            Self::Duplicate { field, id } => write!(f, "{field} lists {id:?} twice"),
            Self::Unknown { field, id } => write!(f, "{field} names unknown {id:?}"),
            Self::InvalidValue { field, reason } => write!(f, "{field}: {reason}"),
            Self::RequirementCycle { object } => {
                write!(f, "reconstruction requirements cycle through {object:?}")
            }
            Self::CrossScope { consumer, object } => write!(
                f,
                "{consumer:?} consumes {object:?} from another trust scope without an allowance"
            ),
            Self::ScopeWithoutBudget { object } => {
                write!(f, "no budget is declared for the trust scope of {object:?}")
            }
            Self::PreparationPricesLatency { object } => write!(
                f,
                "the preparation cost of {object:?} prices latency, which T_r already includes"
            ),
            Self::NotPhysicalCapacity { bytes } => write!(
                f,
                "a reservation of {bytes} address bytes supplies no physical memory"
            ),
            Self::HorizonTooLarge { reason } => write!(f, "the horizon is too large: {reason}"),
            Self::EmptyHorizonUnschedulable(error) => {
                write!(
                    f,
                    "the horizon cannot be scheduled with nothing ready: {error}"
                )
            }
            Self::BudgetExhausted {
                spent_units,
                max_units,
            } => write!(
                f,
                "the planner spent {spent_units} of {max_units} work units and stopped"
            ),
            Self::TooLargeForExhaustive { objects, max } => write!(
                f,
                "the exhaustive optimum takes at most {max} objects, not {objects}"
            ),
            Self::Graph(error) => error.fmt(f),
            Self::Schedule(error) => error.fmt(f),
            Self::Prefetch(error) => error.fmt(f),
            Self::Calibration(error) => error.fmt(f),
            Self::Cache(error) => error.fmt(f),
            Self::Report(error) => error.fmt(f),
            Self::Id(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for BundleError {}

impl From<GraphError> for BundleError {
    fn from(error: GraphError) -> Self {
        Self::Graph(error)
    }
}

impl From<ScheduleError> for BundleError {
    fn from(error: ScheduleError) -> Self {
        Self::Schedule(error)
    }
}

impl From<PrefetchError> for BundleError {
    fn from(error: PrefetchError) -> Self {
        Self::Prefetch(error)
    }
}

impl From<CalibrationError> for BundleError {
    fn from(error: CalibrationError) -> Self {
        Self::Calibration(error)
    }
}

impl From<CacheError> for BundleError {
    fn from(error: CacheError) -> Self {
        Self::Cache(error)
    }
}

impl From<ReportError> for BundleError {
    fn from(error: ReportError) -> Self {
        Self::Report(error)
    }
}

impl From<IdError> for BundleError {
    fn from(error: IdError) -> Self {
        Self::Id(error)
    }
}
