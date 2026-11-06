//! P12: the readiness experiments of GPU §4 (docs/combined-gpu-memory-and-vm-sandbox-plan.md
//! lines 657–706: §4 intro, §4.1, §4.3 and §4.5), with §1 and §1.1 (lines 268–313),
//! §2.7 (436–448), §2.9 (463–472), §3.6 (576–602), §3.8 (615–629), GPU-W05 and GPU-W06
//! (1048–1078), and the claim record of §4.17 (908–915).
//!
//! - [`intent`]: §4.1's bounded prepare operation (model identity, optional adapter,
//!   deadline, cancellation token, retention TTL), strong and weak intent with
//!   rate-limited hover and selection changes, the refusals to pre-execute an external
//!   action or charge an answer before its request exists, and lifecycle accounting.
//! - [`preparation`]: demand-only, recency/Markov and workflow intent on the same traces,
//!   measured on the fake runners.
//! - [`parking`]: §4.3's clean-drop eligibility, the eviction-plus-next-wake policy, and
//!   restart, standard sleep and clean-drop parking compared on the fake runners.
//! - [`retention`] and [`artifacts`]: §4.5's per-component recreate costs, the Pareto
//!   frontier, a governor restricted to backend-supported levels, compile artifacts under
//!   an exact ABI key with no persisted device pointer, and four strategies compared over
//!   three budgets and two workloads on the fake runners.
//! - [`claim`]: the §4.17 claim record and its typed decision.
//! - [`measure`]: CORE-08 measurement of fake-runner records.
//!
//! Nothing here restates a committed module: prefetch scoring, the speculative budget,
//! calibration and the demand-only fallback are `math::{prefetch, calibration}`; clean
//! eviction is `residency::eviction`; sleep levels, sleep plans and admitted techniques
//! are `backends`; canonical-copy proofs are `vmm`; lifecycle states are `placement`'s;
//! preparation steps and external actions are `boundaries`'; lease cancellation is
//! `foundation::coordination`'s; the runners, their seeded generator and the FAST-01
//! corpus are `bench`; records, ledgers, summaries and provenance are `foundation::report`.
//!
//! GPU §4 is a research program. Every result here comes from the fake, time-controlled
//! runners and carries the fake-substrate provenance, which validates schemas and
//! comparisons and backs no performance, improvement or release claim (S12 G0; rollout
//! decision "T12 → T02"). Energy and prices are not measured.
//!
//! # Claim record
//!
//! Each experiment keeps its full claim record in its own module docs
//! ([`preparation`], [`parking`], [`retention`]) and computes its result as a typed
//! [`claim::ClaimOutcome`] that a test asserts:
//!
//! - §4.1 intent-driven preparation: inconclusive (fake substrate only) when workflow
//!   intent beats demand-only and recency/Markov; rejected when intent is always wrong.
//! - §4.3 clean-drop parking: narrowed to the reuse probabilities at which the clean drop
//!   is not more expensive than the cheaper of restart and standard sleep.
//! - §4.5 selective retention: inconclusive (fake substrate only): it ties the strongest
//!   fixed strategy where one fits and beats restart where only a weight-discarding level
//!   fits.
//!
//! No result is "useful integration" or "supported original contribution": both need
//! Yougori measurements and the literature comparison of §4.17 item 2.

use std::fmt;

pub mod adoption;
pub mod artifacts;
pub mod claim;
pub mod intent;
pub mod measure;
pub mod parking;
pub mod preparation;
pub mod retention;

#[cfg(test)]
mod test_support;

use crate::foundation::ids::IdError;
use crate::foundation::report::ReportError;
use crate::model_memory::bench::BenchError;
use crate::model_memory::math::calibration::CalibrationError;
use crate::model_memory::math::prefetch::PrefetchError;
use crate::model_memory::math::InputError;
use crate::model_memory::placement::IllegalTransition;

/// Why an experiment could not run or finish.
#[derive(Clone, Debug, PartialEq)]
pub enum ReadinessError {
    Bench(BenchError),
    Report(ReportError),
    Prefetch(PrefetchError),
    Calibration(CalibrationError),
    Prepare(intent::PrepareRefusal),
    Claim(claim::ClaimRefusal),
    Retention(retention::RetentionRefusal),
    /// A park path that placement's state diagram does not allow.
    Lifecycle(IllegalTransition),
    Id(IdError),
    Input(InputError),
    /// A parameter is out of range.
    InvalidSpec {
        field: &'static str,
        reason: &'static str,
    },
    UnknownModel {
        model: String,
    },
    /// A preparation ran past the request it was admitted for: its worst-case bound did
    /// not hold.
    PreparationOverran,
    /// An episode kept asking to be replayed.
    ReplayUnstable,
    /// A time or byte count does not fit in 64 bits.
    Overflow,
}

impl fmt::Display for ReadinessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bench(error) => error.fmt(f),
            Self::Report(error) => error.fmt(f),
            Self::Prefetch(error) => error.fmt(f),
            Self::Calibration(error) => error.fmt(f),
            Self::Prepare(error) => error.fmt(f),
            Self::Claim(error) => error.fmt(f),
            Self::Retention(error) => error.fmt(f),
            Self::Lifecycle(error) => error.fmt(f),
            Self::Id(error) => error.fmt(f),
            Self::Input(error) => error.fmt(f),
            Self::InvalidSpec { field, reason } => write!(f, "{field}: {reason}"),
            Self::UnknownModel { model } => write!(f, "no model {model}"),
            Self::PreparationOverran => {
                f.write_str("a preparation ran past the request it was admitted for")
            }
            Self::ReplayUnstable => f.write_str("an episode kept asking to be replayed"),
            Self::Overflow => f.write_str("a time or byte count does not fit in 64 bits"),
        }
    }
}

impl std::error::Error for ReadinessError {}

/// Serialization of committed types that have no serde of their own.
pub(crate) mod wire {
    use serde::Serializer;

    use crate::foundation::report::AttemptLedger;
    use crate::model_memory::math::calibration::DemandOnlyReason;
    use crate::model_memory::math::prefetch::CandidateOrigin;

    pub(crate) fn origin<S: Serializer>(
        origin: &CandidateOrigin,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match origin {
            CandidateOrigin::QueuedWork => "queued_work",
            CandidateOrigin::ExplicitUserIntent => "explicit_user_intent",
            CandidateOrigin::Recency => "recency",
            CandidateOrigin::Markov => "markov",
        })
    }

    pub(crate) fn demand_only_reason<S: Serializer>(
        reason: &DemandOnlyReason,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match reason {
            DemandOnlyReason::LowConfidence => "low_confidence",
            DemandOnlyReason::Overload => "overload",
            DemandOnlyReason::Drift => "drift",
        })
    }

    /// A ledger as its records, every attempt included.
    pub(crate) fn ledger<S: Serializer>(
        ledger: &AttemptLedger,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(ledger.records())
    }
}

crate::model_memory::from_error!(
    ReadinessError:
    BenchError => Bench,
    ReportError => Report,
    PrefetchError => Prefetch,
    CalibrationError => Calibration,
    intent::PrepareRefusal => Prepare,
    claim::ClaimRefusal => Claim,
    retention::RetentionRefusal => Retention,
    IllegalTransition => Lifecycle,
    IdError => Id,
    InputError => Input,
);
