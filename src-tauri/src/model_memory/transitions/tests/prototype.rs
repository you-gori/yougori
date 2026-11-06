//! Lines 870–872 and §4.17: the first prototype on the fake substrate, the pass/stop
//! rule and the claim record.

use super::support::*;
use crate::foundation::report::{
    BaselineRole, ImprovementClaim, NotMeasuredReason, ReportError, RunSubstrate,
};
use crate::model_memory::residency::Capacity;
use crate::model_memory::transitions::*;

/// Charges for the comparison: 0.05 s per prepared GB, 0.01 s per retained GB-second,
/// 10 µs per planner work unit.
fn charged(mut declared: WorkflowDeclaration, usable_gb: u64) -> WorkflowDeclaration {
    declared.weights = CostWeights {
        retained_seconds_per_byte_second: 1e-11,
        preparation_seconds_per_byte: 5e-11,
    };
    declared.curves.planning_seconds_per_work_unit = 1e-5;
    declared.budgets.usable_vram = Capacity::Physical {
        bytes: usable_gb * GB,
    };
    declared
}

/// A→B→A: s1 on A produces a 6 GB session nobody resumes; s2 on B; s3 on A again.
fn a_b_a() -> WorkflowDeclaration {
    let mut first = stage("s1", &["model-a"]);
    first.produces = Some(key("session-1"));
    first.process.kv_pool_bytes = 6 * GB;
    charged(
        declaration(
            vec![
                base("model-a", 9 * GB),
                base("model-b", 7 * GB),
                session("session-1", "model-a", &[1, 2], 6 * GB, Vec::new()),
            ],
            vec![first, stage("s2", &["model-b"]), stage("s3", &["model-a"])],
            chain(&["s1", "s2", "s3"]),
        ),
        24,
    )
}

/// Shared-base adapter branches: a with adapter X on base M, then Y1 (70 of 100 runs) or
/// Y2, then X again.
fn shared_base_branches() -> WorkflowDeclaration {
    charged(
        declaration(
            vec![
                base("model-m", 12 * GB),
                adapter("adapter-x", "model-m", GB),
                adapter("adapter-y1", "model-m", GB),
                adapter("adapter-y2", "model-m", GB),
            ],
            vec![
                stage("a", &["adapter-x"]),
                stage("b1", &["adapter-y1"]),
                stage("b2", &["adapter-y2"]),
                stage("c1", &["adapter-x"]),
                stage("c2", &["adapter-x"]),
            ],
            vec![
                edge("a", "b1", evidence(70, 100)),
                edge("a", "b2", evidence(30, 100)),
                edge("b1", "c1", BranchWeight::Unknown),
                edge("b2", "c2", BranchWeight::Unknown),
            ],
        ),
        24,
    )
}

/// Long-context continuation: s1 on A builds an 8 GB context; s2 on B and s3 on C run in
/// between; s4 resumes the context on A. The service holds the prompt (3 s to recompute).
fn long_context() -> WorkflowDeclaration {
    let tokens = [11, 12, 13, 14];
    let mut first = stage("s1", &["model-a"]);
    first.produces = Some(key("session-long"));
    first.process.kv_pool_bytes = 8 * GB;
    let mut last = stage("s4", &["model-a", "session-long"]);
    last.process.kv_pool_bytes = 8 * GB;
    charged(
        declaration(
            vec![
                base("model-a", 9 * GB),
                base("model-b", 7 * GB),
                base("model-c", 6 * GB),
                session(
                    "session-long",
                    "model-a",
                    &tokens,
                    8 * GB,
                    vec![recompute(&tokens, 3.0)],
                ),
            ],
            vec![
                first,
                stage("s2", &["model-b"]),
                stage("s3", &["model-c"]),
                last,
            ],
            chain(&["s1", "s2", "s3", "s4"]),
        ),
        30,
    )
}

/// A rarely taken branch: after a on A, b on B in 95 of 100 runs, r on a 14 GB model R
/// otherwise.
fn rare_branch() -> WorkflowDeclaration {
    charged(
        declaration(
            vec![
                base("model-a", 9 * GB),
                base("model-b", 7 * GB),
                base("model-r", 14 * GB),
            ],
            vec![
                stage("a", &["model-a"]),
                stage("b", &["model-b"]),
                stage("r", &["model-r"]),
            ],
            vec![
                edge("a", "b", evidence(95, 100)),
                edge("a", "r", evidence(5, 100)),
            ],
        ),
        24,
    )
}

fn compare(name: &str, declared: &WorkflowDeclaration, expected_runs: u64) -> PrototypeComparison {
    compare_policies(
        name,
        declared,
        &FakeHolds::honoured(),
        &FakeHolds::honoured(),
        &clock(),
        &template(),
        &TrialConfig {
            trials: 8,
            seed: 0x0870,
            variation: 0.1,
            expected_runs,
        },
    )
    .unwrap()
}

#[test]
fn a_comparison_needs_independent_trials() {
    let result = compare_policies(
        "a-b-a",
        &a_b_a(),
        &FakeHolds::honoured(),
        &FakeHolds::honoured(),
        &clock(),
        &template(),
        &TrialConfig {
            trials: 3,
            seed: 1,
            variation: 0.0,
            expected_runs: 10,
        },
    );
    assert_eq!(
        result.unwrap_err(),
        TransitionError::TooFewTrials {
            trials: 3,
            required: 5
        }
    );
}

#[test]
fn the_first_prototype_is_recorded_on_the_fake_substrate_and_caps_the_claim() {
    let comparisons = vec![
        compare("a-b-a", &a_b_a(), 50),
        compare("shared-base-adapter-branches", &shared_base_branches(), 50),
        compare("long-context-continuation", &long_context(), 50),
        compare("rarely-taken-branch", &rare_branch(), 1),
    ];
    for comparison in &comparisons {
        // Every side is a fake, time-controlled run: it validates the comparison and backs
        // no claim (rule 10; rollout decision "T12 → T02").
        let sides = std::iter::once(&comparison.plan).chain(comparison.baselines.iter());
        for side in sides {
            assert!(side.provenance.is_fake_substrate(), "{}", side.policy);
            assert_eq!(
                side.provenance.yougori_evidence(),
                Err(ReportError::FakeSubstrateIsNotEvidence)
            );
            assert_eq!(side.stages % 8, 0, "{}", side.policy);
            assert!(side
                .objectives
                .energy_per_completed_request_joules
                .reason()
                .is_some_and(|reason| reason == NotMeasuredReason::InstrumentUnavailable));
            assert!(!side.objectives.peak_host_memory_bytes.is_measured());
        }
        assert_eq!(
            ImprovementClaim::from_report(&comparison.report, BaselineRole::OrdinaryWorkflow)
                .unwrap_err(),
            ReportError::FakeSubstrateIsNotEvidence
        );
        assert!(comparison.report.candidate().provenance.is_fake_substrate());
        // Planning time is charged: compile once, in the first trial.
        assert!(comparison.plan.compile_seconds > 0.0);
        assert!(close(
            comparison.plan.mean_charged_seconds
                - comparison.plan.mean_charged_seconds_without_compile,
            comparison.plan.compile_seconds / 8.0
        ));
        // GPU-N1 alone ran through the committed bundle planner and paid for it too.
        let n1 = &comparison.baselines[2];
        assert_eq!(n1.policy, "gpu-n1-alone");
        assert!(n1.replanning_seconds > 0.0);
        println!(
            "{}: plan {:.3} s (compile {:.4} s, {:?}); {}",
            comparison.workflow,
            comparison.plan.mean_charged_seconds,
            comparison.plan.compile_seconds,
            comparison.amortization,
            comparison
                .baselines
                .iter()
                .map(|side| format!("{} {:.3} s", side.policy, side.mean_charged_seconds))
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    // Even a template recorded elsewhere yields fake-substrate records.
    let mut measured = template();
    measured.substrate = RunSubstrate::AuthorizedDisposable {
        authorization: crate::foundation::report::Label::new("disposable-host").unwrap(),
    };
    let from_measured = compare_policies(
        "rarely-taken-branch",
        &rare_branch(),
        &FakeHolds::honoured(),
        &FakeHolds::honoured(),
        &clock(),
        &measured,
        &TrialConfig {
            trials: 5,
            seed: 3,
            variation: 0.0,
            expected_runs: 1,
        },
    )
    .unwrap();
    assert!(from_measured.plan.provenance.is_fake_substrate());

    // A→B→A: the plan drops the dead session and keeps A; ordinary caching keeps the
    // session by recency and reloads A.
    let a_b_a = &comparisons[0];
    assert!(a_b_a.verdict.plan_wins());
    assert!(matches!(
        a_b_a.amortization,
        AmortizationDecision::KeepCompiled { .. }
    ));
    // Long-context continuation: the plan keeps the expensive context through s3 and
    // evicts B, which no later stage needs.
    assert!(comparisons[2].verdict.plan_wins());
    // One-off work uses the online policy whatever it saves (line 872).
    assert_eq!(
        comparisons[3].amortization,
        AmortizationDecision::UseOnline {
            reason: OnlineReason::OneOff
        }
    );

    // Shared-base branches: preparing both small adapters during a beats preparing only
    // the likely one; the repeated savings amortize compilation.
    assert!(matches!(
        comparisons[1].amortization,
        AmortizationDecision::KeepCompiled { .. }
    ));
    assert!(matches!(
        comparisons[2].amortization,
        AmortizationDecision::KeepCompiled { .. }
    ));

    let verdicts: Vec<WorkflowVerdict> = comparisons
        .iter()
        .map(|comparison| comparison.verdict.clone())
        .collect();
    // On these fakes the plan beats the strongest baseline on all four workflows.
    assert!(verdicts.iter().all(WorkflowVerdict::plan_wins));
    let record = ClaimRecord::gpu_n2(verdicts.clone());
    assert_eq!(record.result, decide_claim(&verdicts));
    println!("claim result: {:?}", record.result);
    // Fakes cap the result at inconclusive (rule 11; §4.17 item 6).
    assert_eq!(record.result, ClaimResult::Inconclusive);
}
