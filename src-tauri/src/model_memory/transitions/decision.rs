//! The pass/stop rule (GPU §4.15, line 872) and the claim record (§4.17, lines 908–915).
//!
//! - [`decide_amortization`]: compilation is kept only for a workflow whose repeated
//!   savings amortize its cost; unpredictable one-off work uses the online policy.
//!   Equality does not amortize.
//! - [`decide_claim`]: the claim outcome from the prototype comparisons. A mechanism that
//!   loses to its strongest baseline on every workflow is rejected, on some workflows
//!   narrowed to those it wins; otherwise fake-substrate evidence caps the result at
//!   inconclusive, and real evidence supports at most a useful integration. A supported
//!   original contribution needs a literature and implementation comparison that no
//!   computation here makes, so this function never returns it.

use serde::Serialize;

use super::TransitionError;

/// The inputs of the pass/stop rule (line 872).
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct AmortizationInput {
    /// The planning time of one compilation (work units times their measured cost).
    pub compile_seconds: f64,
    /// The charged seconds one run saves against the strongest online baseline, with
    /// replanning, unused preparation and retained memory charged.
    pub savings_per_run_seconds: f64,
    /// How often the same workflow is expected to run, from its history.
    pub expected_runs: u64,
}

/// Why the online policy applies instead (line 872).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum OnlineReason {
    /// One-off work: nothing repeats to amortize compilation.
    OneOff,
    /// The plan saves nothing per run.
    NoSavings,
    /// The expected runs do not reach the break-even count.
    NotAmortized { break_even_runs: u64 },
}

/// The computed pass/stop decision (line 872).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum AmortizationDecision {
    /// Keep compilation: from `break_even_runs` runs on, savings exceed its cost.
    KeepCompiled {
        break_even_runs: u64,
    },
    UseOnline {
        reason: OnlineReason,
    },
}

/// Keeps compilation only when `expected_runs × savings_per_run > compile_seconds`, with
/// at least two expected runs (line 872).
pub fn decide_amortization(
    input: &AmortizationInput,
) -> Result<AmortizationDecision, TransitionError> {
    let invalid = |what: &'static str| TransitionError::Internal { what };
    if !input.compile_seconds.is_finite() || input.compile_seconds < 0.0 {
        return Err(invalid("compile seconds must be finite and not negative"));
    }
    if !input.savings_per_run_seconds.is_finite() {
        return Err(invalid("savings per run must be finite"));
    }
    if input.expected_runs < 2 {
        return Ok(AmortizationDecision::UseOnline {
            reason: OnlineReason::OneOff,
        });
    }
    if input.savings_per_run_seconds <= 0.0 {
        return Ok(AmortizationDecision::UseOnline {
            reason: OnlineReason::NoSavings,
        });
    }
    // The smallest n with n × savings > compile: equality does not amortize.
    let ratio = (input.compile_seconds / input.savings_per_run_seconds).floor();
    let break_even_runs = if ratio >= u64::MAX as f64 {
        u64::MAX
    } else {
        (ratio as u64).saturating_add(1)
    };
    Ok(if input.expected_runs >= break_even_runs {
        AmortizationDecision::KeepCompiled { break_even_runs }
    } else {
        AmortizationDecision::UseOnline {
            reason: OnlineReason::NotAmortized { break_even_runs },
        }
    })
}

/// One workflow's comparison against its strongest baseline (§4.17 item 5).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct WorkflowVerdict {
    pub workflow: String,
    /// The plan's mean charged seconds per run, planning time included.
    pub plan_charged_seconds: f64,
    pub strongest_baseline: String,
    pub baseline_charged_seconds: f64,
    /// Whether the comparison ran on the fake substrate.
    pub fake_substrate: bool,
}

impl WorkflowVerdict {
    /// The plan wins only when strictly cheaper; a tie does not justify compiling.
    pub fn plan_wins(&self) -> bool {
        self.plan_charged_seconds < self.baseline_charged_seconds
    }
}

/// The result of §4.17 item 6, with rule 11's narrowing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum ClaimResult {
    UsefulIntegration,
    /// Never computed: it needs a literature and implementation comparison.
    SupportedOriginalContribution,
    Inconclusive,
    Rejected,
    /// Kept only for the named workflows, where it beats the strongest baseline.
    Narrowed {
        kept_for: Vec<String>,
    },
}

/// Computes the claim outcome from the comparisons (§4.17 item 6).
pub fn decide_claim(verdicts: &[WorkflowVerdict]) -> ClaimResult {
    if verdicts.is_empty() {
        return ClaimResult::Inconclusive;
    }
    let wins: Vec<String> = verdicts
        .iter()
        .filter(|verdict| verdict.plan_wins())
        .map(|verdict| verdict.workflow.clone())
        .collect();
    if wins.is_empty() {
        ClaimResult::Rejected
    } else if wins.len() < verdicts.len() {
        ClaimResult::Narrowed { kept_for: wins }
    } else if verdicts.iter().any(|verdict| verdict.fake_substrate) {
        ClaimResult::Inconclusive
    } else {
        ClaimResult::UsefulIntegration
    }
}

/// The GPU-N2 claim record (§4.17 items 1–6).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ClaimRecord {
    pub contribution: &'static str,
    pub closest_prior_work: &'static str,
    pub difference_tested: &'static str,
    pub correctness_assumptions: Vec<&'static str>,
    pub smallest_counterexample: &'static str,
    pub comparisons: Vec<WorkflowVerdict>,
    pub result: ClaimResult,
}

impl ClaimRecord {
    /// The record for GPU-N2 with its computed result; the text matches the module's
    /// `# Claim record`.
    pub fn gpu_n2(comparisons: Vec<WorkflowVerdict>) -> Self {
        let result = decide_claim(&comparisons);
        Self {
            contribution: "An ahead-of-time transition planner for model-serving state across \
                the stages of a declared workflow, with transition peaks checked by the §2.7 \
                admission rule, recovery recipes with explicit holds and online deviation \
                handling with exact artifact and session identities.",
            closest_prior_work: "Checkmate (arXiv:1910.02653): tensor rematerialization in one \
                training graph as a mixed-integer program over keep versus recompute.",
            difference_tested: "Transitions between serving tasks of a workflow (models, \
                adapters and session KV across stages and branches), with engine processes, \
                staging and write-back in the peaks, and suffix-only invalidation at runtime.",
            correctness_assumptions: vec![
                "declared identities, sizes, KV bounds and curves are exact",
                "evicted state is freed when the previous stage ends",
                "branch probabilities are used only where evidence supports them",
            ],
            smallest_counterexample: "A stage whose engine allocates more than its declared KV \
                pool: the three-piece admission check certifies a peak the device exceeds.",
            comparisons,
            result,
        }
    }
}
