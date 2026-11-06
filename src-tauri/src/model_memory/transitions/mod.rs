//! GPU-N2: compile memory transitions for known workflows
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md §4.15, lines 838–873, with S3.6 at
//! line 56, §1 lines 268–296, §3.9 lines 630–645, §4 lines 657–662, §4.13 lines
//! 778–795, §4.17 lines 902–917, GPU-W06 lines 1064–1078 and GPU-W11/GPU-W12 lines
//! 1141–1176).
//!
//! A [`ReadinessPlan`] is compiled alongside a declared workflow ([`WorkflowDeclaration`]).
//! It is a reusable tool contract, not a template or a grid product (§1, line 270). It
//! describes memory transitions and preparation only: no output of this module executes
//! or authorizes an external workflow action (S3.6; [`PlanAction::preparation_step`]).
//!
//! - [`declaration`]: the inputs of lines 846–852 (model, adapter and session identities
//!   with dependency edges; branches with probabilities only where evidence supports
//!   them; measured load and compute curves; GPU and host budgets, deadlines, trust scope
//!   and a maximum preparation cost; immutable artifacts and explicit session state),
//!   validated into a [`CheckedWorkflow`] and unrolled into a decision tree.
//! - [`recipes`]: recovery recipes (line 866). A recipe never promises reconstruction from
//!   a peer or from a prompt the service does not hold. Its indispensable dependencies are
//!   held explicitly: a reload's catalog object by a CORE-02 read lease checked through
//!   [`ObjectHoldAuthority`], a recompute's prompt by a CORE-04 service lease checked
//!   through [`HoldAuthority`].
//! - [`memory`]: transition peaks. Every transition is checked with the §2.7 admission
//!   check of [`crate::model_memory::residency::vram`] over three pieces of time, so a
//!   plan can never swap through a second full copy that does not fit (line 862).
//! - [`readiness`]: the readiness time of each stage, scheduled by the request graph
//!   ([`crate::model_memory::graph::paths::plan`], §2.3).
//! - [`search`]: the bounded dynamic program for linear workflows, beam search for
//!   branching ones and a small exhaustive offline oracle (line 862).
//! - [`plan`]: the outputs of lines 854–860.
//! - [`runtime`]: identity, capacity and branch validation, suffix invalidation and
//!   bounded replanning (line 864).
//! - [`online`]: the ordinary online policies (residency's retention baselines) and GPU-N1
//!   alone through the committed bundle planner ([`crate::model_memory::bundles`]).
//! - [`substrate`]: the first prototype on a fake substrate (line 870), recorded through
//!   CORE-08 under the fake-substrate provenance.
//! - [`decision`]: the pass/stop rule (line 872) and the claim record (§4.17).
//!
//! Units: bytes are `u64`, times are finite `f64` seconds unless a field says otherwise,
//! and absolute time comes from [`crate::foundation::ids::Clock`].
//!
//! # Claim record
//!
//! The §4.17 claim record of GPU-N2 (items 1–6). The outcome is computed by
//! [`decide_claim`] from the prototype comparisons and asserted by a test.
//!
//! 1. **Proposed contribution.** An ahead-of-time transition planner for model-serving
//!    state across the stages of a declared workflow: retained-state configurations over
//!    shared physical resources, transition peaks checked by the §2.7 admission rule,
//!    recovery recipes with explicit holds, and online deviation handling with exact
//!    artifact and session identities.
//! 2. **Closest prior work.** Checkmate (Jain et al., arXiv:1910.02653) formulates
//!    tensor rematerialization in one training graph as a mixed-integer program over what
//!    to keep versus recompute (§4.13). Dependency-Aware Online Caching, ELORA and
//!    Chameleon are adjacent for dependency-aware, adapter/KV and adapter-scheduling
//!    caches.
//! 3. **Difference tested.** The unit is a transition between serving tasks of a workflow
//!    (whole models, adapters and session KV of several stages, with branches), not
//!    activations inside one training graph; peaks include engine processes, staging and
//!    write-back; and deviations invalidate only the affected suffix.
//! 4. **Correctness assumptions and the smallest counterexample.** The declared identities,
//!    sizes, KV bounds and curves are exact, evictions free memory when the previous stage
//!    ends, and branch probabilities are only used where evidence supports them. The
//!    smallest counterexample: a stage whose engine allocates more than its declared KV
//!    pool; the three-piece admission check then certifies a peak that the device exceeds.
//!    The runtime's capacity validation catches the resulting pressure only at the next
//!    boundary.
//! 5. **Comparison against the strongest compatible baseline.** Four prototype workflows
//!    (A→B→A with a dead session, shared-base adapter branches, long-context continuation,
//!    a rarely taken branch) against ordinary caching (LRU), next-model prefetch and GPU-N1
//!    alone (the committed bundle planner over a history-only horizon), over eight seeded
//!    trials with ±10 % duration variation, charging planning time (10 µs per work unit),
//!    unused preparation (0.05 s per GB) and retained memory (0.01 s per GB-second), on the
//!    fake substrate only ([`compare_policies`]; test
//!    `the_first_prototype_is_recorded_on_the_fake_substrate_and_caps_the_claim`). Mean
//!    charged seconds per run, plan against the strongest baseline: A→B→A 9.40 against
//!    12.74 (next-model prefetch), shared-base branches 7.93 against 8.14 (next-model
//!    prefetch), long-context continuation 11.20 against 15.49 (GPU-N1 alone), rarely
//!    taken branch 5.42 against 5.88 (next-model prefetch). The records keep CORE-08's
//!    existing BENCH ids and its declared first-token objective; the charges above form
//!    this module's own verdict score, not a weighted CORE-08 objective, which the report
//!    owner declined. The pass/stop rule keeps compilation for the first three (expected
//!    50 runs each) and uses the online policy for the rarely taken branch, declared
//!    one-off work.
//! 6. **Result: inconclusive** (computed by [`decide_claim`]). The plan beats its
//!    strongest baseline on all four workflows, so nothing is rejected or narrowed, but
//!    every run is a fake-substrate simulation: it backs no performance claim, and an
//!    originality claim needs a literature and implementation comparison and hardware
//!    measurements this work did not make.

use std::fmt;

use serde::Serialize;

use crate::foundation::ids::IdError;
use crate::foundation::report::ReportError;
use crate::model_memory::bundles::BundleError;
use crate::model_memory::graph::{GraphError, ScheduleError};
use crate::model_memory::residency::vram::VramError;

pub mod decision;
pub mod declaration;
pub mod memory;
pub mod online;
pub mod plan;
pub mod readiness;
pub mod recipes;
pub mod runtime;
pub mod search;
pub mod substrate;

mod model;

#[cfg(test)]
mod tests;

pub use decision::{
    decide_amortization, decide_claim, AmortizationDecision, AmortizationInput, ClaimRecord,
    ClaimResult, OnlineReason, WorkflowVerdict,
};
pub use declaration::{
    Aggregation, BranchWeight, Budgets, CheckedWorkflow, CostWeights, DeclarationError, LoadCurve,
    MeasuredCurves, PlanLimits, ResourceDeclaration, ResourceKey, StageDeclaration, StageId,
    StageProcess, StateIdentity, WorkflowDeclaration, WorkflowEdge,
};
pub use memory::{Assumption, PeakEstimate, TransitionSlot};
pub use model::{Choice, EvictionHandling, Infeasibility};
pub use plan::{
    compile, compile_with, Alternative, InterruptionPoint, Materialization, OnlineFallback,
    PlanAction, PlannedNode, ReadinessPlan, RecoveryPath,
};
pub use readiness::ReadinessEstimate;
pub use recipes::{
    CatalogSource, HeldLease, HeldObject, HoldAuthority, ObjectHold, ObjectHoldAuthority,
    PromptHolding, RecipeRefusal, RecoveryRecipe,
};
pub use runtime::{
    BoundaryObservation, BoundaryOutcome, Deviation, Directive, FallbackReason, PlanRuntime,
};
pub use search::SearchMethod;
pub use substrate::{compare_policies, PolicySummary, PrototypeComparison, TrialConfig};

/// A set of declared resources by index, at most [`ResourceSet::MAX_MEMBERS`]: one
/// retained-state configuration over shared physical resources (line 862).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ResourceSet(u64);

impl ResourceSet {
    /// No resources.
    pub const EMPTY: Self = Self(0);
    /// The largest index a set can hold, plus one.
    pub const MAX_MEMBERS: usize = 64;

    /// The set holding only `index`; empty for an index past [`Self::MAX_MEMBERS`].
    pub fn single(index: usize) -> Self {
        if index < Self::MAX_MEMBERS {
            Self(1u64 << index)
        } else {
            Self::EMPTY
        }
    }

    pub fn contains(self, index: usize) -> bool {
        index < Self::MAX_MEMBERS && self.0 & (1u64 << index) != 0
    }

    #[must_use]
    pub fn with(self, index: usize) -> Self {
        self.union(Self::single(index))
    }

    #[must_use]
    pub fn without(self, index: usize) -> Self {
        self.difference(Self::single(index))
    }

    #[must_use]
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    #[must_use]
    pub fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    pub fn is_subset(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// The indices in ascending order.
    pub fn iter(self) -> impl Iterator<Item = usize> {
        (0..Self::MAX_MEMBERS).filter(move |index| self.contains(*index))
    }

    pub(crate) fn bits(self) -> u64 {
        self.0
    }

    pub(crate) fn from_bits(bits: u64) -> Self {
        Self(bits)
    }
}

/// Why compiling, replanning or comparing was refused (GPU §4.15).
#[derive(Clone, Debug, PartialEq)]
pub enum TransitionError {
    /// The declared workflow is invalid (lines 846–852).
    Declaration(DeclarationError),
    /// A recovery recipe was refused (line 866).
    Recipe {
        resource: ResourceKey,
        refusal: RecipeRefusal,
    },
    /// The §2.7 admission check refused its input (not an overcommit, which is an
    /// [`Infeasibility`]).
    Admission(VramError),
    Graph(GraphError),
    Schedule(ScheduleError),
    Report(ReportError),
    Id(IdError),
    /// The GPU-N1 bundle planner refused its horizon.
    Bundle(BundleError),
    /// No plan satisfies the hard constraints from the given state; the online policy
    /// applies (line 860).
    NoFeasiblePlan {
        stage: StageId,
        infeasibility: Infeasibility,
    },
    /// The search would exceed its explicit work bound (line 862: a bounded program).
    WorkBoundExceeded {
        limit: u64,
    },
    /// The exhaustive oracle would enumerate more policies than its limit.
    OracleTooLarge {
        policies: u128,
        limit: u64,
    },
    /// A stage has more valid configurations than the limit.
    StateLimit {
        stage: StageId,
        configurations: usize,
        limit: usize,
    },
    /// A duration does not fit the request graph's clock.
    DurationOutOfRange {
        seconds: f64,
    },
    /// An online policy found no configuration that fits.
    OnlineNoRoom {
        policy: String,
        stage: StageId,
        infeasibility: Infeasibility,
    },
    /// A comparison needs at least the stated number of independent trials.
    TooFewTrials {
        trials: u32,
        required: u32,
    },
    /// An internal invariant did not hold; nothing was changed.
    Internal {
        what: &'static str,
    },
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Declaration(error) => write!(f, "invalid workflow declaration: {error}"),
            Self::Recipe { resource, refusal } => {
                write!(f, "recovery recipe for {resource} refused: {refusal}")
            }
            Self::Admission(error) => write!(f, "admission input refused: {error}"),
            Self::Graph(error) => write!(f, "request graph refused: {error:?}"),
            Self::Schedule(error) => write!(f, "request schedule refused: {error:?}"),
            Self::Report(error) => write!(f, "report refused: {error:?}"),
            Self::Id(error) => write!(f, "identifier refused: {error}"),
            Self::Bundle(error) => write!(f, "bundle planner refused: {error:?}"),
            Self::NoFeasiblePlan {
                stage,
                infeasibility,
            } => write!(
                f,
                "no plan reaches stage {stage} within the hard constraints: {infeasibility}"
            ),
            Self::WorkBoundExceeded { limit } => {
                write!(f, "the search would exceed its bound of {limit} work units")
            }
            Self::OracleTooLarge { policies, limit } => write!(
                f,
                "the oracle would enumerate {policies} policies; the limit is {limit}"
            ),
            Self::StateLimit {
                stage,
                configurations,
                limit,
            } => write!(
                f,
                "stage {stage} has {configurations} configurations; the limit is {limit}"
            ),
            Self::DurationOutOfRange { seconds } => {
                write!(f, "{seconds} s does not fit the request graph's clock")
            }
            Self::OnlineNoRoom {
                policy,
                stage,
                infeasibility,
            } => write!(
                f,
                "online policy {policy} found no configuration for stage {stage}: {infeasibility}"
            ),
            Self::TooFewTrials { trials, required } => write!(
                f,
                "{trials} trials; a comparison needs at least {required} independent trials"
            ),
            Self::Internal { what } => write!(f, "internal invariant failed: {what}"),
        }
    }
}

impl std::error::Error for TransitionError {}

impl From<DeclarationError> for TransitionError {
    fn from(error: DeclarationError) -> Self {
        Self::Declaration(error)
    }
}

impl From<GraphError> for TransitionError {
    fn from(error: GraphError) -> Self {
        Self::Graph(error)
    }
}

impl From<ScheduleError> for TransitionError {
    fn from(error: ScheduleError) -> Self {
        Self::Schedule(error)
    }
}

impl From<ReportError> for TransitionError {
    fn from(error: ReportError) -> Self {
        Self::Report(error)
    }
}

impl From<BundleError> for TransitionError {
    fn from(error: BundleError) -> Self {
        Self::Bundle(error)
    }
}

impl From<IdError> for TransitionError {
    fn from(error: IdError) -> Self {
        Self::Id(error)
    }
}
