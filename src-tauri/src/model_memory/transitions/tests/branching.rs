//! Line 862, branching workflows: beam search compared with a small exhaustive offline
//! oracle; the plan never beats the oracle.

use super::support::*;
use crate::model_memory::bench::rng::SeededRng;
use crate::model_memory::residency::Capacity;
use crate::model_memory::transitions::*;

/// a on base M with adapter X branches to b1 (adapter Y1) or b2 (adapter Y2), each of
/// which returns to X.
fn adapter_branches(weights: [BranchWeight; 2]) -> WorkflowDeclaration {
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
            edge("a", "b1", weights[0]),
            edge("a", "b2", weights[1]),
            edge("b1", "c1", BranchWeight::Unknown),
            edge("b2", "c2", BranchWeight::Unknown),
        ],
    )
}

#[test]
fn branches_aggregate_by_evidence_or_by_the_worst_case() {
    let holds = FakeHolds::honoured();
    let expected = compile(
        &adapter_branches([evidence(70, 100), evidence(30, 100)]),
        &holds,
        &holds,
        &clock(),
    )
    .unwrap();
    assert_eq!(expected.method(), SearchMethod::Beam { width: 3 });
    // Tree order: a, b1, c1, b2, c2.
    let r: Vec<f64> = expected
        .nodes()
        .iter()
        .map(|node| node.readiness.expected_seconds)
        .collect();
    assert!(close(
        expected.expected_cost_seconds(),
        r[0] + 0.7 * (r[1] + r[2]) + 0.3 * (r[3] + r[4])
    ));
    // The shared base stays through every stage; only adapters move.
    for node in expected.nodes() {
        assert!(node.config.contains(&key("model-m")));
    }
    // Both adapters are small enough to prepare during a, so neither branch waits.
    assert!(close(r[1], 0.51) && close(r[3], 0.51));

    let worst = compile(
        &adapter_branches([BranchWeight::Unknown, BranchWeight::Unknown]),
        &holds,
        &holds,
        &clock(),
    )
    .unwrap();
    let r: Vec<f64> = worst
        .nodes()
        .iter()
        .map(|node| node.readiness.expected_seconds)
        .collect();
    assert!(close(
        worst.expected_cost_seconds(),
        r[0] + (r[1] + r[2]).max(r[3] + r[4])
    ));
}

/// A seeded random branching workflow over three bases: r branches to b1 or b2, each
/// followed by one more stage.
fn random_branching(rng: &mut SeededRng) -> WorkflowDeclaration {
    let resources = (0..3)
        .map(|at| base(&format!("m{at}"), (2 + rng.below(7)) * GB))
        .collect();
    let mut stages = Vec::new();
    for name in ["r", "b1", "b2", "c1", "c2"] {
        let model = format!("m{}", rng.below(3));
        let mut declared = stage(name, &[model.as_str()]);
        declared.decode_seconds = (1 + rng.below(6)) as f64;
        stages.push(declared);
    }
    let weights = if rng.below(2) == 0 {
        let taken = 20 + rng.below(61);
        [evidence(taken, 100), evidence(100 - taken, 100)]
    } else {
        [BranchWeight::Unknown, BranchWeight::Unknown]
    };
    let mut declared = declaration(
        resources,
        stages,
        vec![
            edge("r", "b1", weights[0]),
            edge("r", "b2", weights[1]),
            edge("b1", "c1", BranchWeight::Unknown),
            edge("b2", "c2", BranchWeight::Unknown),
        ],
    );
    declared.budgets.usable_vram = Capacity::Physical {
        bytes: (13 + rng.below(8)) * GB,
    };
    declared
}

#[test]
fn beam_search_never_beats_the_oracle_and_the_exact_program_matches_it() {
    let holds = FakeHolds::honoured();
    let mut rng = SeededRng::new(0x5EED_0010);
    for _ in 0..12 {
        let declared = random_branching(&mut rng);
        let oracle = compile_with(
            &declared,
            &holds,
            &holds,
            &clock(),
            SearchMethod::ExhaustiveOracle,
        )
        .unwrap()
        .expected_cost_seconds();
        let exact = compile_with(&declared, &holds, &holds, &clock(), SearchMethod::ExactDp)
            .unwrap()
            .expected_cost_seconds();
        assert!(close(exact, oracle), "exact {exact} oracle {oracle}");
        for width in [1, 2, 3] {
            let beam = compile_with(
                &declared,
                &holds,
                &holds,
                &clock(),
                SearchMethod::Beam { width },
            )
            .unwrap()
            .expected_cost_seconds();
            assert!(
                beam >= oracle - 1e-9,
                "beam {beam} beat the oracle {oracle}"
            );
        }
    }
}

#[test]
fn the_oracle_refuses_to_enumerate_beyond_its_limit() {
    let mut declared = adapter_branches([evidence(70, 100), evidence(30, 100)]);
    declared.limits.max_oracle_policies = 10;
    assert!(matches!(
        compile_with(
            &declared,
            &FakeHolds::honoured(),
            &FakeHolds::honoured(),
            &clock(),
            SearchMethod::ExhaustiveOracle
        ),
        Err(TransitionError::OracleTooLarge { limit: 10, .. })
    ));
}
