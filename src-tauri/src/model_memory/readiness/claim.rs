//! The claim record every GPU §4 experiment ends with (GPU §4.17, lines 908–915) and the
//! typed decision behind its result.
//!
//! A record states the proposed contribution without words such as "first" or
//! "unprecedented", the closest prior work the plan names, the difference tested, the
//! correctness assumptions with the smallest counterexample that breaks them, the
//! baseline, and the result. The result is computed by [`decide`] from per-cell
//! comparisons against the strongest compatible baseline and from where the evidence
//! came from: a fake-substrate run is capped at "inconclusive" (S12 G0; rollout decision
//! "T12 → T02"), because originality needs a literature comparison and hardware
//! measurements, and a mechanism that loses to its baseline even on fakes is rejected,
//! or narrowed to the cells where it does not lose.

use std::fmt;

use serde::Serialize;

use crate::foundation::report::Provenance;

/// The experiment a claim record belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Experiment {
    /// GPU §4.1: request preparation from known future work.
    IntentPreparation,
    /// GPU §4.3: preserve readiness without copying clean weights back.
    CleanDropParking,
    /// GPU §4.5: retain the smallest useful execution state.
    SmallestUsefulRetention,
}

/// How a candidate compared with the strongest compatible baseline in one cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CellVerdict {
    Better,
    /// Within the declared tie band of the baseline.
    Tie,
    Worse,
}

/// One cell of a comparison: a named condition (a baseline, budget, workload or reuse
/// level) and the verdict in it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ComparisonCell {
    pub label: String,
    pub verdict: CellVerdict,
}

/// Where the compared numbers came from, read from their CORE-08 provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    /// A fake, time-controlled runner: schema and comparison validation only (S12 G0).
    FakeSubstrate,
    /// A Yougori measurement, or a third-party claim Yougori reproduced (BENCH-13).
    YougoriMeasured,
    /// A third-party number that was not reproduced.
    ThirdPartyHistorical,
}

impl EvidenceClass {
    /// The class of `provenance`; the raw records' substrate decides it (T02 follow-up).
    pub fn of(provenance: &Provenance) -> Self {
        if provenance.is_fake_substrate() {
            Self::FakeSubstrate
        } else if provenance.yougori_evidence().is_ok() {
            Self::YougoriMeasured
        } else {
            Self::ThirdPartyHistorical
        }
    }
}

/// The literature and implementation comparison of GPU §4.17 item 2. This task makes
/// none, so its records say [`LiteratureComparison::NotDone`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiteratureComparison {
    NotDone,
    /// Prior work already covers the mechanism; at most a useful integration.
    PriorWorkCovers,
    /// The comparison found a specific difference from the closest prior work.
    DiffersFromPriorWork,
}

/// Why a result is inconclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InconclusiveReason {
    /// No comparison cell was run.
    NoComparison,
    /// The candidate tied the strongest baseline in every cell.
    NoImprovement,
    /// Only fake-substrate runs: they validate the comparison and back no claim.
    FakeSubstrateOnly,
    /// The numbers are third-party and were not reproduced.
    NotYougoriEvidence,
    /// GPU §4.17 item 2 was not done.
    NoLiteratureComparison,
}

/// The result of GPU §4.17 item 6, with "narrowed" for a mechanism that loses in some
/// cells (see the module docs of [`crate::model_memory::readiness`], decisions).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ClaimOutcome {
    UsefulIntegration,
    SupportedOriginalContribution,
    Inconclusive {
        reason: InconclusiveReason,
    },
    /// The candidate lost to the strongest compatible baseline in every cell.
    Rejected,
    /// The candidate lost in some cells; the claim keeps only the others.
    Narrowed {
        kept: Vec<String>,
        dropped: Vec<String>,
    },
}

/// Decides GPU §4.17 item 6 from the comparison cells, the evidence class and the
/// literature comparison, in this order: no cells is inconclusive; losing everywhere is
/// rejected; losing somewhere is narrowed to the cells that did not lose; never being
/// better is inconclusive; fake or unreproduced evidence and a missing literature
/// comparison are inconclusive; otherwise prior work covering the mechanism makes it a
/// useful integration and a stated difference a supported original contribution.
pub fn decide(
    evidence: EvidenceClass,
    literature: LiteratureComparison,
    cells: &[ComparisonCell],
) -> ClaimOutcome {
    let inconclusive = |reason| ClaimOutcome::Inconclusive { reason };
    if cells.is_empty() {
        return inconclusive(InconclusiveReason::NoComparison);
    }
    let worse = |cell: &&ComparisonCell| cell.verdict == CellVerdict::Worse;
    if cells.iter().all(|cell| cell.verdict == CellVerdict::Worse) {
        return ClaimOutcome::Rejected;
    }
    if cells.iter().any(|cell| cell.verdict == CellVerdict::Worse) {
        return ClaimOutcome::Narrowed {
            kept: cells
                .iter()
                .filter(|cell| !worse(cell))
                .map(|cell| cell.label.clone())
                .collect(),
            dropped: cells
                .iter()
                .filter(worse)
                .map(|cell| cell.label.clone())
                .collect(),
        };
    }
    if !cells.iter().any(|cell| cell.verdict == CellVerdict::Better) {
        return inconclusive(InconclusiveReason::NoImprovement);
    }
    match (evidence, literature) {
        (EvidenceClass::FakeSubstrate, _) => inconclusive(InconclusiveReason::FakeSubstrateOnly),
        (EvidenceClass::ThirdPartyHistorical, _) => {
            inconclusive(InconclusiveReason::NotYougoriEvidence)
        }
        (EvidenceClass::YougoriMeasured, LiteratureComparison::NotDone) => {
            inconclusive(InconclusiveReason::NoLiteratureComparison)
        }
        (EvidenceClass::YougoriMeasured, LiteratureComparison::PriorWorkCovers) => {
            ClaimOutcome::UsefulIntegration
        }
        (EvidenceClass::YougoriMeasured, LiteratureComparison::DiffersFromPriorWork) => {
            ClaimOutcome::SupportedOriginalContribution
        }
    }
}

/// The fixed text of a claim record (GPU §4.17 items 1–5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ClaimText {
    /// Item 1, without words such as "first" or "unprecedented".
    pub contribution: &'static str,
    /// Item 2: the closest prior work the plan names.
    pub closest_prior_work: &'static str,
    /// Item 3.
    pub difference_tested: &'static str,
    /// Item 4: correctness assumptions.
    pub assumptions: &'static [&'static str],
    /// Item 4: the smallest counterexample that breaks them.
    pub smallest_counterexample: &'static str,
    /// Item 5: the strongest compatible baseline.
    pub baseline: &'static str,
}

/// Words GPU §4.17 item 1 keeps out of a stated contribution, matched as whole words in
/// any case.
pub const FORBIDDEN_CONTRIBUTION_WORDS: [&str; 5] =
    ["first", "unprecedented", "novel", "unique", "pioneering"];

/// Why a claim record was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum ClaimRefusal {
    /// The contribution uses a word item 1 forbids.
    ForbiddenWord { word: &'static str },
    /// A required text field is empty.
    EmptyField { field: &'static str },
}

impl fmt::Display for ClaimRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForbiddenWord { word } => write!(
                f,
                "a claimed contribution is stated without words such as {word:?} (GPU §4.17)"
            ),
            Self::EmptyField { field } => write!(f, "the claim record's {field} is empty"),
        }
    }
}

impl std::error::Error for ClaimRefusal {}

/// A complete claim record (GPU §4.17): its text, the comparison cells, where the
/// numbers came from and the computed result.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ClaimRecord {
    experiment: Experiment,
    text: ClaimText,
    provenance_label: String,
    evidence: EvidenceClass,
    literature: LiteratureComparison,
    cells: Vec<ComparisonCell>,
    outcome: ClaimOutcome,
}

impl ClaimRecord {
    /// Builds the record and computes its result with [`decide`]. The literature
    /// comparison is [`LiteratureComparison::NotDone`]: this task cannot make one.
    pub fn new(
        experiment: Experiment,
        text: ClaimText,
        provenance: &Provenance,
        cells: Vec<ComparisonCell>,
    ) -> Result<Self, ClaimRefusal> {
        check_text(&text)?;
        let evidence = EvidenceClass::of(provenance);
        let literature = LiteratureComparison::NotDone;
        let outcome = decide(evidence, literature, &cells);
        Ok(Self {
            experiment,
            text,
            provenance_label: provenance.label(),
            evidence,
            literature,
            cells,
            outcome,
        })
    }

    pub fn experiment(&self) -> Experiment {
        self.experiment
    }

    pub fn text(&self) -> &ClaimText {
        &self.text
    }

    /// The CORE-08 provenance label of the compared numbers.
    pub fn provenance_label(&self) -> &str {
        &self.provenance_label
    }

    pub fn evidence(&self) -> EvidenceClass {
        self.evidence
    }

    pub fn literature(&self) -> LiteratureComparison {
        self.literature
    }

    pub fn cells(&self) -> &[ComparisonCell] {
        &self.cells
    }

    /// GPU §4.17 item 6.
    pub fn outcome(&self) -> &ClaimOutcome {
        &self.outcome
    }
}

/// Refuses an empty field and a forbidden word in the contribution.
pub fn check_text(text: &ClaimText) -> Result<(), ClaimRefusal> {
    for (field, value) in [
        ("contribution", text.contribution),
        ("closest_prior_work", text.closest_prior_work),
        ("difference_tested", text.difference_tested),
        ("smallest_counterexample", text.smallest_counterexample),
        ("baseline", text.baseline),
    ] {
        if value.trim().is_empty() {
            return Err(ClaimRefusal::EmptyField { field });
        }
    }
    if text.assumptions.is_empty() || text.assumptions.iter().any(|a| a.trim().is_empty()) {
        return Err(ClaimRefusal::EmptyField {
            field: "assumptions",
        });
    }
    let words: Vec<String> = text
        .contribution
        .split(|character: char| !character.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .collect();
    match FORBIDDEN_CONTRIBUTION_WORDS
        .iter()
        .find(|forbidden| words.iter().any(|word| word == *forbidden))
    {
        Some(word) => Err(ClaimRefusal::ForbiddenWord { word }),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(label: &str, verdict: CellVerdict) -> ComparisonCell {
        ComparisonCell {
            label: label.to_string(),
            verdict,
        }
    }

    const TEXT: ClaimText = ClaimText {
        contribution: "Prepare the next model from queued work",
        closest_prior_work: "recency and Markov prefetch",
        difference_tested: "explicit intent instead of statistics",
        assumptions: &["the queue names the next model"],
        smallest_counterexample: "a queue that is reordered after preparation",
        baseline: "demand-only scheduling",
    };

    #[test]
    fn every_decision_branch_follows_the_stated_order() {
        use CellVerdict::{Better, Tie, Worse};
        use EvidenceClass::*;
        use LiteratureComparison::*;
        let inconclusive = |reason| ClaimOutcome::Inconclusive { reason };
        assert_eq!(
            decide(YougoriMeasured, DiffersFromPriorWork, &[]),
            inconclusive(InconclusiveReason::NoComparison)
        );
        // Losing everywhere is rejected, even with the strongest evidence.
        assert_eq!(
            decide(
                YougoriMeasured,
                DiffersFromPriorWork,
                &[cell("a", Worse), cell("b", Worse)]
            ),
            ClaimOutcome::Rejected
        );
        // Fakes can reject: a loss on fakes is still a loss.
        assert_eq!(
            decide(FakeSubstrate, NotDone, &[cell("a", Worse)]),
            ClaimOutcome::Rejected
        );
        assert_eq!(
            decide(
                FakeSubstrate,
                NotDone,
                &[cell("low", Better), cell("mid", Tie), cell("high", Worse)]
            ),
            ClaimOutcome::Narrowed {
                kept: vec!["low".into(), "mid".into()],
                dropped: vec!["high".into()]
            }
        );
        assert_eq!(
            decide(
                YougoriMeasured,
                DiffersFromPriorWork,
                &[cell("a", Tie), cell("b", Tie)]
            ),
            inconclusive(InconclusiveReason::NoImprovement)
        );
        let winning = [cell("a", Better), cell("b", Tie)];
        assert_eq!(
            decide(FakeSubstrate, DiffersFromPriorWork, &winning),
            inconclusive(InconclusiveReason::FakeSubstrateOnly)
        );
        assert_eq!(
            decide(ThirdPartyHistorical, DiffersFromPriorWork, &winning),
            inconclusive(InconclusiveReason::NotYougoriEvidence)
        );
        assert_eq!(
            decide(YougoriMeasured, NotDone, &winning),
            inconclusive(InconclusiveReason::NoLiteratureComparison)
        );
        assert_eq!(
            decide(YougoriMeasured, PriorWorkCovers, &winning),
            ClaimOutcome::UsefulIntegration
        );
        assert_eq!(
            decide(YougoriMeasured, DiffersFromPriorWork, &winning),
            ClaimOutcome::SupportedOriginalContribution
        );
    }

    #[test]
    fn a_contribution_never_says_first_or_unprecedented() {
        assert_eq!(check_text(&TEXT), Ok(()));
        for (contribution, word) in [
            ("The first intent-driven loader", "first"),
            ("An UNPRECEDENTED combination", "unprecedented"),
            ("A novel scheme", "novel"),
        ] {
            let text = ClaimText {
                contribution,
                ..TEXT
            };
            assert_eq!(check_text(&text), Err(ClaimRefusal::ForbiddenWord { word }));
        }
        // Whole words only: "firstly" style substrings inside other words do not match.
        let text = ClaimText {
            contribution: "Thirst-free loading",
            ..TEXT
        };
        assert_eq!(check_text(&text), Ok(()));
        let text = ClaimText {
            closest_prior_work: " ",
            ..TEXT
        };
        assert_eq!(
            check_text(&text),
            Err(ClaimRefusal::EmptyField {
                field: "closest_prior_work"
            })
        );
        let text = ClaimText {
            assumptions: &[],
            ..TEXT
        };
        assert_eq!(
            check_text(&text),
            Err(ClaimRefusal::EmptyField {
                field: "assumptions"
            })
        );
    }
}
