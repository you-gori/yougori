//! VM sandbox Tier 0: the attack graph, small formal models and contract-generated
//! mutations (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §2, §6.3, §6.6,
//! §9.3 VM-N3, §10.6 VM-W50 and VM-W52, §12.1–§12.3, VM-P44 and VM-P50).
//!
//! - [`AttackGraph`] (§2.1): domains, interfaces and privileges with the controls that
//!   guard them; prohibited paths, common dependencies and minimal sets of failed
//!   controls, found by bounded exhaustive search. No escape probability is computed:
//!   [`ProbabilityStatement`] has no numeric field, and independence of two controls is
//!   never established ([`AttackGraph::independence`]).
//! - [`statistics`] (§2.3): the zero-failure bound `1 − 0.05^(1/N)` over deduplicated
//!   independent cases, and the scope it never covers. [`objectives`] (§2.2, §2.5): the
//!   objectives table, structural ceiling reductions and the lease exposure bound.
//! - Five small models by exhaustive enumeration ([`explore`], §12.3 models 2–5 plus a
//!   perimeter and a host-boundary model for the §2.6 invariants): [`ModelKind`]. Each
//!   runs under a [`ModelConfig`] of disabled [`Guard`]s, adversary [`Injection`]s and
//!   seeded [`Defect`]s; every [`InvariantId`] is a named predicate over one model.
//! - VM-N3 ([`mutation`]): prohibited actions with their guards and enforcement points,
//!   a generator of named faults including common-cause faults, the check of every
//!   declared invariant under each fault, and the shortest counterexample with the
//!   missing enforcement assumption. VM-P44 compares single-guard predictions with
//!   observations.
//! - [`assurance`] (VM-P50, VM-W52): skipped tests, stale probes, guest-only and fake
//!   observations never become a green result; claims link assumptions, model results,
//!   observations and residual risks, with no multiplier or aggregate probability.
//! - [`experiment`] (VM-N3 experiment): seeded policy and lifecycle defects, hand-written
//!   probes against generated mutations, recorded under the fake-substrate provenance of
//!   `foundation::report`, which backs no security claim.
//!
//! A model result is about the model only (§12.3): it does not prove the Rust or Go code,
//! the operating system, the hypervisor, external providers or hardware. Everything here
//! is pure and synchronous; time comes from [`crate::foundation::ids::Clock`].

pub mod assurance;
mod attack_graph;
mod boundary;
mod budget;
mod contract;
mod effect;
mod egress;
pub mod experiment;
pub mod explore;
mod lifecycle;
pub mod mutation;
pub mod objectives;
mod snapshot;
pub mod statistics;

pub use attack_graph::{
    AttackGraph, Control, ControlId, EnablingSet, FailureUnit, NodeId, NodeKind,
    ProbabilityStatement, ProhibitedPath, MAX_SEARCH_UNITS, MAX_SET_SIZE,
};
pub use contract::{
    check_model, run_script, Defect, DefectClass, Dependency, EnforcementPoint, Guard, Injection,
    InvariantId, Location, ModelConfig, ModelKind,
};
pub use explore::{Bounds, Exploration, ScriptOutcome, ScriptStep, Trace, Violation};

use std::fmt;

use crate::foundation::report::ReportError;

/// Why a model, search, bound or record was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum ModelError {
    /// The exploration reached its state bound before exhausting the reachable states;
    /// nothing is concluded beyond the bound.
    StateBoundExceeded { model: ModelKind, max_states: usize },
    /// A subset search over more failure units or a larger set size than allowed.
    SearchBoundTooLarge { units: usize, max_size: usize },
    /// An attack-graph name was used twice.
    DuplicateName { name: String },
    /// An attack-graph node or control id that the graph does not have.
    UnknownId { id: usize },
    /// A script step the model did not offer at that point (a probe that cannot run).
    ScriptAborted { step: usize, action: String },
    /// The zero-failure bound needs at least one independent trial.
    NoTrials,
    /// The zero-failure bound applies only when no failure was observed.
    FailuresObserved { failures: u64 },
    /// A probability target outside (0, 1).
    InvalidTarget,
    /// Independence of two controls is never established by different mechanisms
    /// (§2.1); `shared` lists the dependencies they are known to share.
    IndependenceNotEstablished { shared: Vec<Dependency> },
    /// A ceiling or latency ratio is not an isolation-strength claim (§2.2).
    NotAnIsolationClaim,
    /// A ratio of two quantities with a zero or mismatched denominator.
    InvalidRatio,
    /// The lease exposure bound applies only if the remote enforcement point checks
    /// leases and cannot mint renewals (§2.5).
    LeaseBoundDoesNotApply { reason: &'static str },
    /// A risk-reduction or improvement claim without its baseline (§2.3).
    MissingBaseline,
    /// The two measurements of a comparison were made on different corpora or
    /// conditions.
    NotComparable,
    /// A pass-rate report without residual assumptions (§2.3).
    MissingResidualAssumptions,
    /// A record could not be encoded for its digest.
    Encoding,
    /// A `foundation::report` refusal.
    Report(ReportError),
}

impl From<ReportError> for ModelError {
    fn from(error: ReportError) -> Self {
        Self::Report(error)
    }
}

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StateBoundExceeded { model, max_states } => write!(
                f,
                "the {model:?} model has more than {max_states} reachable states; nothing is \
                 concluded beyond the bound"
            ),
            Self::SearchBoundTooLarge { units, max_size } => write!(
                f,
                "a search over {units} failure units with sets of up to {max_size} exceeds the \
                 search bound"
            ),
            Self::DuplicateName { name } => write!(f, "the name {name:?} is used twice"),
            Self::UnknownId { id } => write!(f, "the graph has no element {id}"),
            Self::ScriptAborted { step, action } => {
                write!(
                    f,
                    "step {step} ({action}) was not available, so the probe cannot run"
                )
            }
            Self::NoTrials => f.write_str("the zero-failure bound needs at least one trial"),
            Self::FailuresObserved { failures } => write!(
                f,
                "{failures} failures were observed, so the zero-failure bound does not apply"
            ),
            Self::InvalidTarget => f.write_str("a probability target must lie strictly in (0, 1)"),
            Self::IndependenceNotEstablished { shared } => write!(
                f,
                "different mechanisms do not establish independence (shared dependencies: \
                 {shared:?})"
            ),
            Self::NotAnIsolationClaim => f.write_str(
                "a reduction of one ceiling or latency is not a claim of stronger isolation",
            ),
            Self::InvalidRatio => f.write_str("a ratio needs positive values on one scale"),
            Self::LeaseBoundDoesNotApply { reason } => {
                write!(f, "the lease exposure bound does not apply: {reason}")
            }
            Self::MissingBaseline => {
                f.write_str("a reduction claim needs a comparable baseline with its uncertainty")
            }
            Self::NotComparable => {
                f.write_str("the two measurements were not made on the same corpus or conditions")
            }
            Self::MissingResidualAssumptions => {
                f.write_str("a pass rate is reported only beside its residual assumptions")
            }
            Self::Encoding => f.write_str("the record could not be encoded"),
            Self::Report(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ModelError {}
