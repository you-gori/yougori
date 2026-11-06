//! Claim records (GPU §4.17, plan lines 908–915; §4 line 661: every experiment ends in a
//! decision, and a negative result can retire a mechanism).
//!
//! A record states the contribution without "first" or "unprecedented", the closest
//! prior work, the specific difference tested, the correctness assumptions with the
//! smallest counterexample that breaks them, the strongest compatible baseline, and the
//! result. The result is computed from per-workload comparisons: a mechanism that loses
//! to its baseline somewhere is narrowed, or rejected if it wins nowhere. There is no
//! positive outcome: originality needs a literature comparison and hardware measurements
//! that a fake substrate cannot give, so the best result here is inconclusive.

use std::fmt;

use crate::foundation::report::{Measured, NonNegative, Provenance, ReportError};

/// Words a contribution must not use (GPU §4.17, §4 line 659).
pub const FORBIDDEN_CLAIM_WORDS: [&str; 2] = ["first", "unprecedented"];

/// Why a claim record was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum ClaimError {
    ForbiddenWord {
        word: &'static str,
    },
    NoComparisons,
    NotFinite {
        workload: String,
    },
    /// The comparisons have no recorded evidence behind them.
    Evidence(ReportError),
}

impl fmt::Display for ClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForbiddenWord { word } => write!(f, "a contribution may not say {word:?}"),
            Self::NoComparisons => f.write_str("a claim needs at least one comparison"),
            Self::NotFinite { workload } => write!(f, "workload {workload} has a non-finite value"),
            Self::Evidence(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ClaimError {}

/// The outcome of an experiment on the evidence available here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// It never lost to its strongest baseline, but fakes cannot support more.
    Inconclusive,
    /// It lost on some workloads and won on others: kept only where it won.
    Narrowed,
    /// It lost and never won.
    Rejected,
}

/// One workload's comparison with the strongest compatible baseline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Win,
    Tie,
    Loss,
}

/// The candidate against the strongest compatible baseline on one workload.
#[derive(Clone, Debug, PartialEq)]
pub struct WorkloadComparison {
    pub workload: String,
    pub objective: &'static str,
    pub candidate: f64,
    pub baseline: f64,
    pub baseline_name: String,
    pub verdict: Verdict,
}

impl WorkloadComparison {
    /// A comparison where lower is better; equal values tie.
    pub fn lower_is_better(
        workload: impl Into<String>,
        objective: &'static str,
        candidate: f64,
        baseline: f64,
        baseline_name: impl Into<String>,
    ) -> Self {
        let verdict = if candidate < baseline {
            Verdict::Win
        } else if candidate > baseline {
            Verdict::Loss
        } else {
            Verdict::Tie
        };
        Self {
            workload: workload.into(),
            objective,
            candidate,
            baseline,
            baseline_name: baseline_name.into(),
            verdict,
        }
    }

    /// A comparison whose verdict a mechanism-specific rule decided, such as a delta
    /// chain that must both save storage and not slow cold recovery.
    pub fn decided(
        workload: impl Into<String>,
        objective: &'static str,
        candidate: f64,
        baseline: f64,
        baseline_name: impl Into<String>,
        verdict: Verdict,
    ) -> Self {
        Self {
            workload: workload.into(),
            objective,
            candidate,
            baseline,
            baseline_name: baseline_name.into(),
            verdict,
        }
    }
}

/// The fixed text of a claim record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimText {
    pub clause: &'static str,
    pub contribution: &'static str,
    pub closest_prior_work: &'static str,
    pub difference_tested: &'static str,
    pub assumptions: &'static [&'static str],
    pub smallest_counterexample: &'static str,
    pub strongest_baseline: &'static str,
    /// What a real run of the experiment needs (GPU-W12: "required infrastructure").
    pub required_infrastructure: &'static str,
    /// When the mechanism passes, narrows or stops (GPU-W12: "pass/stop rule").
    pub pass_stop_rule: &'static str,
}

impl ClaimText {
    /// Refuses a contribution that uses a word of [`FORBIDDEN_CLAIM_WORDS`].
    pub fn check(&self) -> Result<(), ClaimError> {
        let lower = self.contribution.to_lowercase();
        let words: Vec<&str> = lower
            .split(|character: char| !character.is_alphanumeric())
            .collect();
        match FORBIDDEN_CLAIM_WORDS
            .iter()
            .find(|word| words.contains(word))
        {
            Some(word) => Err(ClaimError::ForbiddenWord { word }),
            None => Ok(()),
        }
    }
}

/// A finished claim record with its computed outcome.
#[derive(Clone, Debug, PartialEq)]
pub struct ClaimRecord {
    pub text: ClaimText,
    pub comparisons: Vec<WorkloadComparison>,
    /// The provenance label of the evidence, shown with every number (BENCH-13).
    pub provenance: String,
    /// Foreground delay the mechanism caused in active inference, in seconds (§4 line
    /// 661: every experiment produces an interference result). It needs hardware, so on
    /// fakes it is "not measured".
    pub interference_seconds: Measured<NonNegative>,
    pub result: ClaimOutcome,
}

impl ClaimRecord {
    /// Computes the outcome from `comparisons`, which `provenance` must back with
    /// comparable evidence (a fake-substrate run qualifies; it still backs no claim).
    pub fn decide(
        text: ClaimText,
        comparisons: Vec<WorkloadComparison>,
        provenance: &Provenance,
        interference_seconds: Measured<NonNegative>,
    ) -> Result<Self, ClaimError> {
        text.check()?;
        if comparisons.is_empty() {
            return Err(ClaimError::NoComparisons);
        }
        if let Some(bad) = comparisons.iter().find(|comparison| {
            !comparison.candidate.is_finite() || !comparison.baseline.is_finite()
        }) {
            return Err(ClaimError::NotFinite {
                workload: bad.workload.clone(),
            });
        }
        provenance
            .comparable_evidence()
            .map_err(ClaimError::Evidence)?;
        let lost = comparisons
            .iter()
            .any(|comparison| comparison.verdict == Verdict::Loss);
        let won = comparisons
            .iter()
            .any(|comparison| comparison.verdict == Verdict::Win);
        let result = match (lost, won) {
            (true, true) => ClaimOutcome::Narrowed,
            (true, false) => ClaimOutcome::Rejected,
            (false, _) => ClaimOutcome::Inconclusive,
        };
        Ok(Self {
            text,
            comparisons,
            provenance: provenance.label(),
            interference_seconds,
            result,
        })
    }

    /// Workloads where the candidate won, the scope a narrowed mechanism keeps.
    pub fn kept_workloads(&self) -> Vec<&str> {
        self.comparisons
            .iter()
            .filter(|comparison| comparison.verdict == Verdict::Win)
            .map(|comparison| comparison.workload.as_str())
            .collect()
    }
}

/// §4.2 exact differential materialization.
pub const DIFFERENTIAL_CLAIM: ClaimText = ClaimText {
    clause: "GPU §4.2 (plan lines 671-677)",
    contribution: "A model switch loads only the decoded extents of the target manifest that \
                   no compatible resident copy holds, verifies every extent against the target \
                   manifest, and falls back to the full loader when indexing and hashing cost \
                   at least the transfer they save.",
    closest_prior_work: "DeltaZip (delta-compressed fine-tuned variants served beside a base)",
    difference_tested: "exact reuse keyed by decoded content keys in a verified manifest, with \
                        no assumed sparse delta and a full-loader cutoff, instead of serving \
                        lossy or delta-compressed variants",
    assumptions: &[
        "equal content keys mean equal decoded bytes (SHA-256 under a domain tag and true length)",
        "a resident copy is reusable only in the consumer's trust scope and on its device",
        "the extent index of both artifacts is already built, or its cost is charged",
    ],
    smallest_counterexample: "two checkpoints with identical tensors whose file offsets differ by \
                              one byte share every tensor yet no file-aligned extent, so the \
                              differential path saves nothing and the cutoff must keep the full \
                              loader",
    strongest_baseline: "the full loader reading every required extent",
    required_infrastructure: "imported sidecar manifests of model families, a GPU with a                               resident base, and the CORE-08 harness in an authorized                               disposable environment",
    pass_stop_rule: "pass only where it beats the full loader on weight availability with                      every extent verified; a family where it never wins keeps the full loader",
};

/// §4.2 XOR delta versions against a pinned base.
pub const DELTA_CLAIM: ClaimText = ClaimText {
    clause: "GPU §4.2 (plan line 679); GPU-W12",
    contribution: "Storing a version as the zstd-encoded XOR with a pinned base, reconstructed \
                   bit-exactly under a bounded chain depth, saves storage over independent \
                   compression without slowing cold recovery.",
    closest_prior_work: "DeltaZip (delta compression of fine-tuned weights against a base model)",
    difference_tested: "a lossless XOR delta with a general-purpose codec, judged by stored \
                        bytes and cold-recovery time against independent compression of the \
                        same version",
    assumptions: &[
        "the version and its base have equal lengths and aligned tensors",
        "the base stays pinned and readable while any version depends on it",
        "cold recovery reads the base and every delta of the chain",
    ],
    smallest_counterexample: "an unrelated model of the same length: its XOR with the base is as \
                              random as the model itself, so the delta saves nothing and costs an \
                              extra read and decode",
    strongest_baseline: "independent zstd compression of each version",
    required_infrastructure: "real checkpoint families on the storage tiers cold recovery                               reads from, with measured read and decode rates",
    pass_stop_rule: "keep a chain only when it is strictly smaller and its cold recovery is                      not slower with its base pinned and readable; otherwise abandon it",
};

/// §4.9 representation selection under contention.
pub const SELECTION_CLAIM: ClaimText = ClaimText {
    clause: "GPU §4.9 (plan lines 742-746); GPU-W08",
    contribution: "Choosing raw or zstd transfer per artifact range from the current link, \
                   decoder, scratch, interference and source availability never loses to the \
                   better uniform choice under the same cost model, and keeps raw escape blocks \
                   where compression does not pay for its metadata.",
    closest_prior_work: "DFloat11 (exact BF16 compression with GPU decoding)",
    difference_tested: "a per-range raw or compressed choice under contention with an existing \
                        lossless codec, rather than one exponent-coded format for every tensor",
    assumptions: &[
        "ranges decode independently, so transfer and decoding overlap (pipelined model)",
        "link, decoder and interference rates are current estimates, not advertised figures",
        "a compressed form exists only where the source prepared it",
    ],
    smallest_counterexample: "a decoder whose real throughput is below its estimate: a range \
                              compressed on the estimate finishes later than raw transfer would",
    strongest_baseline: "the better of all-raw and all-compressed transfer for the same ranges",
    required_infrastructure: "measured link, decoder and interference rates per path (remote,                               NVMe, GPU peer) and a licensed DFloat11 or nvCOMP build for                               the weight-specific comparison",
    pass_stop_rule: "pass where it beats the better uniform choice with interference inside                      the foreground budget; stop if it loses anywhere on measured rates",
};

/// §4.12 adaptive policy with a reliable baseline.
pub const POLICY_CLAIM: ClaimText = ClaimText {
    clause: "GPU §4.12 (plan lines 770-776); GPU-W12",
    contribution: "A constrained contextual bandit over one knob, inside hard memory and \
                   authorization limits, with exploration stopped at a p99 or reserve bound and \
                   a revert on distribution shift, matches or beats the best fixed policy per \
                   workload.",
    closest_prior_work: "contextual bandits for systems configuration tuning",
    difference_tested: "a bandit restricted to a closed set of safe knob values, compared with \
                        the best fixed policy and a hand-coded rule on each workload",
    assumptions: &[
        "outcomes of one context are stationary between shifts",
        "every admitted arm is safe under the hard constraints when it is chosen",
        "realized outcomes are observed for every choice",
    ],
    smallest_counterexample: "a stationary workload with one context, where the best fixed arm is \
                              known: every exploratory choice is pure regret",
    strongest_baseline: "the best fixed policy per workload, or a hand-coded rule when stronger",
    required_infrastructure: "useful hand-tuned policies, recorded workload traces and a                               shadow evaluation with Yougori-measured evidence",
    pass_stop_rule: "act live only after beating the strongest baseline in shadow evaluation                      (LiveApproval); narrow to the workloads where it wins, stop where it loses",
};
