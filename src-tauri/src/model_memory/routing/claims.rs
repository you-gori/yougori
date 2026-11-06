//! Claim records (GPU §4.17, lines 908–915) for the §4.6–§4.8 experiments.
//!
//! Every experiment ends with a record of the exact proposed contribution, the closest
//! prior work, the difference tested, the correctness assumptions with the smallest
//! counterexample, the comparison against the strongest compatible baseline and the
//! result. The result is computed by [`decide`] from the comparisons, never supplied:
//! fake-substrate evidence (S12 G0) and a missing literature comparison cap it at
//! inconclusive, a mechanism that loses to its strongest baseline in every regime is
//! rejected, and one that loses in some regimes is narrowed to the others.

use std::fmt;

use crate::foundation::report::{
    BaselineOutcome, BaselineRole, ComparisonReport, Direction, Measured, NonNegative,
    NotMeasuredReason, Provenance,
};

/// The experiments of this module (§4.6–§4.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Experiment {
    /// §4.6, lines 707–720.
    JointRoutingAndPlacement,
    /// §4.7, lines 722–730.
    TopologyAwareReplication,
    /// §4.8, lines 732–738.
    TemporaryDistributedExecution,
}

impl Experiment {
    /// The plan clause the experiment comes from.
    pub const fn clause(self) -> &'static str {
        match self {
            Self::JointRoutingAndPlacement => "GPU §4.6, lines 707–720",
            Self::TopologyAwareReplication => "GPU §4.7, lines 722–730",
            Self::TemporaryDistributedExecution => "GPU §4.8, lines 732–738",
        }
    }
}

/// The closest prior problem formulation, algorithm and implementation (§4.17 item 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PriorWork {
    pub name: &'static str,
    pub reference: &'static str,
    pub formulation: &'static str,
    pub algorithm: &'static str,
    pub implementation: &'static str,
}

/// How the candidate fared against the strongest compatible baseline in one regime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RegimeVerdict {
    Wins,
    Ties,
    Loses,
}

/// One regime's comparison on the declared objective (§4.17 item 5).
#[derive(Clone, Debug, PartialEq)]
pub struct RegimeOutcome {
    pub regime: String,
    /// The candidate's declared-objective value.
    pub candidate: f64,
    /// The best declared-objective value among the compared baselines.
    pub strongest_baseline: f64,
    pub strongest_role: BaselineRole,
    pub verdict: RegimeVerdict,
    /// The candidate side's provenance; a fake substrate backs no claim.
    pub provenance: Provenance,
}

/// Why a claim record could not be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimError {
    /// No regime was compared.
    NoComparison,
    /// A report compared no baseline at all.
    NoComparedBaseline { regime: String },
    /// The tie tolerance is negative or not finite.
    InvalidTolerance,
    /// §4.17 item 1: the contribution is stated without "first" or "unprecedented".
    ForbiddenWord { word: &'static str },
}

impl fmt::Display for ClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoComparison => f.write_str("no regime was compared"),
            Self::NoComparedBaseline { regime } => {
                write!(f, "regime {regime} compared no baseline")
            }
            Self::InvalidTolerance => {
                f.write_str("the tie tolerance is not a finite number of zero or more")
            }
            Self::ForbiddenWord { word } => {
                write!(
                    f,
                    "a claim is stated without the word {word:?} (§4.17 item 1)"
                )
            }
        }
    }
}

impl std::error::Error for ClaimError {}

/// The regime outcome of `report` on its declared objective: the candidate against the
/// best compared baseline, a tie within `tie_tolerance` of it (relative).
pub fn regime_outcome(
    regime: &str,
    report: &ComparisonReport,
    tie_tolerance: f64,
) -> Result<RegimeOutcome, ClaimError> {
    if !tie_tolerance.is_finite() || tie_tolerance < 0.0 {
        return Err(ClaimError::InvalidTolerance);
    }
    let mut strongest: Option<(f64, f64, BaselineRole, Direction)> = None;
    for (role, outcome) in [
        (BaselineRole::OrdinaryWorkflow, report.ordinary_workflow()),
        (BaselineRole::StrongestUpstream, report.strongest_upstream()),
    ] {
        if let BaselineOutcome::Compared { verdict, .. } = outcome {
            let change = &verdict.declared;
            let direction = change.objective.direction();
            let better = match (&strongest, direction) {
                (None, _) => true,
                (Some((_, best, _, _)), Direction::LowerIsBetter) => change.baseline < *best,
                (Some((_, best, _, _)), Direction::HigherIsBetter) => change.baseline > *best,
            };
            if better {
                strongest = Some((change.candidate, change.baseline, role, direction));
            }
        }
    }
    let Some((candidate, baseline, role, direction)) = strongest else {
        return Err(ClaimError::NoComparedBaseline {
            regime: regime.to_owned(),
        });
    };
    let margin = tie_tolerance * baseline.abs();
    let verdict = match direction {
        Direction::LowerIsBetter if candidate < baseline - margin => RegimeVerdict::Wins,
        Direction::LowerIsBetter if candidate > baseline + margin => RegimeVerdict::Loses,
        Direction::HigherIsBetter if candidate > baseline + margin => RegimeVerdict::Wins,
        Direction::HigherIsBetter if candidate < baseline - margin => RegimeVerdict::Loses,
        _ => RegimeVerdict::Ties,
    };
    Ok(RegimeOutcome {
        regime: regime.to_owned(),
        candidate,
        strongest_baseline: baseline,
        strongest_role: role,
        verdict,
        provenance: report.candidate().provenance.clone(),
    })
}

/// Evidence a supported result still needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MissingEvidence {
    /// Measurements on real hardware; fake-substrate runs back no claim (S12 G0).
    HardwareMeasurement,
    /// "an explicit literature and implementation comparison" (§4, line 659).
    LiteratureComparison,
}

/// The finding of an explicit literature and implementation comparison (§4, line 659).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiteratureFinding {
    /// Prior work already covers the difference tested.
    PriorArtCoversDifference,
    /// No reviewed prior work covers the difference tested.
    DifferenceNotCovered,
}

/// §4.17 item 6, with the narrowing of a mechanism that loses in some regimes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimResult {
    UsefulIntegration,
    SupportedOriginalContribution,
    Inconclusive {
        missing: Vec<MissingEvidence>,
    },
    /// Lost to its strongest baseline in `dropped`; the claim covers only `kept`, where
    /// it stays inconclusive until `missing` is supplied.
    Narrowed {
        kept: Vec<String>,
        dropped: Vec<String>,
        missing: Vec<MissingEvidence>,
    },
    /// Lost to its strongest baseline in every regime.
    Rejected {
        lost: Vec<String>,
    },
}

/// Computes the §4.17 result. Rules, in order: losing in every regime rejects; losing in
/// some narrows; otherwise fake-substrate evidence or a missing literature comparison
/// leaves it inconclusive; a candidate that never wins is at most a useful integration.
pub fn decide(
    outcomes: &[RegimeOutcome],
    literature: Option<LiteratureFinding>,
) -> Result<ClaimResult, ClaimError> {
    if outcomes.is_empty() {
        return Err(ClaimError::NoComparison);
    }
    let lost: Vec<String> = outcomes
        .iter()
        .filter(|outcome| outcome.verdict == RegimeVerdict::Loses)
        .map(|outcome| outcome.regime.clone())
        .collect();
    if lost.len() == outcomes.len() {
        return Ok(ClaimResult::Rejected { lost });
    }
    let mut missing = Vec::new();
    if outcomes
        .iter()
        .any(|outcome| outcome.provenance.yougori_evidence().is_err())
    {
        missing.push(MissingEvidence::HardwareMeasurement);
    }
    if literature.is_none() {
        missing.push(MissingEvidence::LiteratureComparison);
    }
    if !lost.is_empty() {
        let kept = outcomes
            .iter()
            .filter(|outcome| outcome.verdict != RegimeVerdict::Loses)
            .map(|outcome| outcome.regime.clone())
            .collect();
        return Ok(ClaimResult::Narrowed {
            kept,
            dropped: lost,
            missing,
        });
    }
    if !missing.is_empty() {
        return Ok(ClaimResult::Inconclusive { missing });
    }
    let wins = outcomes
        .iter()
        .any(|outcome| outcome.verdict == RegimeVerdict::Wins);
    Ok(match literature {
        Some(LiteratureFinding::DifferenceNotCovered) if wins => {
            ClaimResult::SupportedOriginalContribution
        }
        _ => ClaimResult::UsefulIntegration,
    })
}

/// The fixed text of a claim record (§4.17 items 1–4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimText {
    pub contribution: &'static str,
    pub closest_prior_work: PriorWork,
    pub difference_tested: &'static str,
    pub assumptions: &'static [&'static str],
    pub smallest_counterexample: &'static str,
    /// The strongest compatible baseline the comparison used.
    pub strongest_baseline: &'static str,
}

/// A §4.17 claim record.
#[derive(Clone, Debug, PartialEq)]
pub struct ClaimRecord {
    pub experiment: Experiment,
    pub text: ClaimText,
    pub outcomes: Vec<RegimeOutcome>,
    /// Anything that needs real hardware is not measured here.
    pub hardware_result: Measured<NonNegative>,
    /// Paths that need provisioned hardware and stay gated (§4.7, line 730).
    pub gated: Vec<&'static str>,
    pub result: ClaimResult,
}

const FORBIDDEN_WORDS: [&str; 2] = ["first", "unprecedented"];

fn check_wording(text: &str) -> Result<(), ClaimError> {
    let lower = text.to_ascii_lowercase();
    for word in FORBIDDEN_WORDS {
        if lower
            .split(|character: char| !character.is_ascii_alphanumeric())
            .any(|token| token == word)
        {
            return Err(ClaimError::ForbiddenWord { word });
        }
    }
    Ok(())
}

impl ClaimRecord {
    /// Builds the record with its result computed by [`decide`]. Refuses a contribution
    /// or difference worded with "first" or "unprecedented" (§4.17 item 1).
    pub fn new(
        experiment: Experiment,
        text: ClaimText,
        outcomes: Vec<RegimeOutcome>,
        gated: Vec<&'static str>,
        literature: Option<LiteratureFinding>,
    ) -> Result<Self, ClaimError> {
        check_wording(text.contribution)?;
        check_wording(text.difference_tested)?;
        let result = decide(&outcomes, literature)?;
        Ok(Self {
            experiment,
            text,
            outcomes,
            hardware_result: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
            gated,
            result,
        })
    }
}
