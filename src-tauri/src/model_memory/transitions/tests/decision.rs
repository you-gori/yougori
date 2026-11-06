//! Line 872 and §4.17: the pass/stop rule and the claim outcome as computed decisions.

use crate::model_memory::transitions::*;

fn input(compile_seconds: f64, savings: f64, runs: u64) -> AmortizationInput {
    AmortizationInput {
        compile_seconds,
        savings_per_run_seconds: savings,
        expected_runs: runs,
    }
}

#[test]
fn compilation_is_kept_only_when_repeated_savings_amortize_it() {
    // 1 s of compilation, 0.25 s saved per run: 4 runs save exactly 1 s, which does not
    // amortize; the fifth run does.
    assert_eq!(
        decide_amortization(&input(1.0, 0.25, 4)).unwrap(),
        AmortizationDecision::UseOnline {
            reason: OnlineReason::NotAmortized { break_even_runs: 5 }
        }
    );
    assert_eq!(
        decide_amortization(&input(1.0, 0.25, 5)).unwrap(),
        AmortizationDecision::KeepCompiled { break_even_runs: 5 }
    );
    assert_eq!(
        decide_amortization(&input(1.0, 0.3, 4)).unwrap(),
        AmortizationDecision::KeepCompiled { break_even_runs: 4 }
    );
}

#[test]
fn one_off_or_unprofitable_work_uses_the_online_policy() {
    assert_eq!(
        decide_amortization(&input(0.01, 10.0, 1)).unwrap(),
        AmortizationDecision::UseOnline {
            reason: OnlineReason::OneOff
        }
    );
    assert_eq!(
        decide_amortization(&input(0.01, 0.0, 100)).unwrap(),
        AmortizationDecision::UseOnline {
            reason: OnlineReason::NoSavings
        }
    );
    assert_eq!(
        decide_amortization(&input(0.01, -0.5, 100)).unwrap(),
        AmortizationDecision::UseOnline {
            reason: OnlineReason::NoSavings
        }
    );
    assert!(decide_amortization(&input(-1.0, 1.0, 10)).is_err());
    assert!(decide_amortization(&input(1.0, f64::NAN, 10)).is_err());
}

fn verdict(workflow: &str, plan: f64, baseline: f64, fake: bool) -> WorkflowVerdict {
    WorkflowVerdict {
        workflow: workflow.to_string(),
        plan_charged_seconds: plan,
        strongest_baseline: "next-model-prefetch-lru".to_string(),
        baseline_charged_seconds: baseline,
        fake_substrate: fake,
    }
}

#[test]
fn the_claim_outcome_follows_the_comparisons() {
    // On fakes, winning everywhere is at most inconclusive.
    assert_eq!(
        decide_claim(&[verdict("w1", 1.0, 2.0, true), verdict("w2", 1.0, 1.5, true)]),
        ClaimResult::Inconclusive
    );
    // Losing (or tying) somewhere narrows the claim to where it wins.
    assert_eq!(
        decide_claim(&[verdict("w1", 1.0, 2.0, true), verdict("w2", 2.0, 2.0, true)]),
        ClaimResult::Narrowed {
            kept_for: vec!["w1".to_string()]
        }
    );
    // Losing everywhere rejects it.
    assert_eq!(
        decide_claim(&[
            verdict("w1", 3.0, 2.0, true),
            verdict("w2", 2.5, 2.0, false)
        ]),
        ClaimResult::Rejected
    );
    // Real evidence that wins everywhere supports a useful integration, never an original
    // contribution, which needs a literature comparison.
    assert_eq!(
        decide_claim(&[verdict("w1", 1.0, 2.0, false)]),
        ClaimResult::UsefulIntegration
    );
    assert_eq!(decide_claim(&[]), ClaimResult::Inconclusive);
    let record = ClaimRecord::gpu_n2(vec![verdict("w1", 1.0, 2.0, true)]);
    assert!(record.closest_prior_work.contains("Checkmate"));
    for text in [record.contribution, record.difference_tested] {
        let lower = text.to_lowercase();
        assert!(!lower.contains("first") && !lower.contains("unprecedented"));
    }
    assert_eq!(record.result, ClaimResult::Inconclusive);
}
