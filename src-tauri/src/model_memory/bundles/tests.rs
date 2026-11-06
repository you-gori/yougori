//! Tests of GPU-N1 (GPU §4.14, lines 798–837; §4.17, lines 908–915).

use std::time::Duration;

use crate::foundation::ids::{digest, ExecutionCategory, ManualClock, MonotonicTime, TrustScope};
use crate::foundation::report::{
    BaselineRole, ImprovementClaim, Label, Provenance, Quantile, ReportError, RunSubstrate,
};
use crate::model_memory::graph::dag::Policy;
use crate::model_memory::graph::node::{
    CancellationBoundary, DemandSegment, DurationEstimate, NodeKind, ResourceUnit,
};
use crate::model_memory::graph::ScheduleError;
use crate::model_memory::math::calibration::{DemandOnlyReason, ModeSignals};
use crate::model_memory::math::prefetch::{Objective, RawCost};
use crate::model_memory::residency::Capacity;

use super::baselines::{cache_selection, CachePolicy};
use super::candidates::{candidate_bound, CandidateMode, CandidateOrigin};
use super::evaluate::{Evaluator, Infeasibility, Outcome, WorkMeter};
use super::experiment::*;
use super::horizon::{
    Admission, Exclusion, Horizon, HorizonBounds, HorizonSpec, ObjectSpec, RequestSpec, Selection,
};
use super::planner::{
    exhaustive_optimum, measured_cost_per_byte, plan, FallbackPolicy, FallbackReason, PlanOutcome,
    PlanStep, PlannerConfig,
};
use super::workloads::{self, Workload};
use super::BundleError;

const SECOND: u64 = 1_000;

fn clock() -> ManualClock {
    ManualClock::new(MonotonicTime::from_nanos(1_000_000_000))
}

fn horizon(workload: &Workload) -> Horizon {
    Horizon::build(workload.spec.clone()).unwrap()
}

fn outcome(horizon: &Horizon, ids: &[&str]) -> Outcome {
    let clock = clock();
    let mut meter = WorkMeter::unbounded();
    let evaluator = Evaluator::new(horizon, &clock, &mut meter).unwrap();
    let selection = horizon.selection_of(ids).unwrap();
    evaluator.evaluate(&selection, &mut meter).unwrap()
}

/// sum_r w_r * (T_r(empty) − T_r(X)) in seconds.
fn saved(horizon: &Horizon, ids: &[&str]) -> f64 {
    outcome(horizon, ids)
        .feasible()
        .unwrap()
        .saved_weighted_seconds
}

fn controller() -> crate::model_memory::math::calibration::ModeController {
    forecast_controller().unwrap()
}

fn planned(horizon: &Horizon, config: PlannerConfig) -> super::planner::BundlePlan {
    plan(horizon, &clock(), &controller(), config).unwrap()
}

fn selected_ids(horizon: &Horizon, plan: &super::planner::BundlePlan) -> Vec<String> {
    horizon
        .ids(plan.selection())
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn plan_net(plan: &super::planner::BundlePlan) -> f64 {
    match &plan.outcome {
        PlanOutcome::Selected { evaluation, .. } => evaluation.saved_weighted_seconds,
        PlanOutcome::Fallback { .. } => panic!("unexpected fallback"),
    }
}

fn millis(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn object(
    id: &str,
    kind: NodeKind,
    bytes: u64,
    load: u64,
    requires: &[&str],
    resident: bool,
) -> ObjectSpec {
    ObjectSpec {
        id: id.to_string(),
        kind,
        identity: digest("yougori/test/bundles/object/v1", &[id.as_bytes()]),
        trust_scope: workloads::workload_scope(),
        bytes,
        load: DurationEstimate::exact(millis(load)).unwrap(),
        load_demand: Vec::new(),
        cancellation: CancellationBoundary::BeforeStart,
        requires: requires.iter().map(|id| id.to_string()).collect(),
        resident,
        preparation: RawCost::default(),
        interference: RawCost::default(),
    }
}

fn request(id: &str, needs: &[&str], arrival: u64) -> RequestSpec {
    RequestSpec {
        id: id.to_string(),
        identity: digest("yougori/test/bundles/request/v1", &[id.as_bytes()]),
        trust_scope: workloads::workload_scope(),
        weight: 1.0,
        admission: Admission::Admitted,
        arrival: millis(arrival),
        needs: needs.iter().map(|id| id.to_string()).collect(),
        compute: DurationEstimate::exact(millis(SECOND)).unwrap(),
        compute_demand: Vec::new(),
        cancellation: CancellationBoundary::BeforeStart,
    }
}

fn spec(
    objects: Vec<ObjectSpec>,
    requests: Vec<RequestSpec>,
    memory: u64,
    budget: u64,
) -> HorizonSpec {
    HorizonSpec {
        objects,
        requests,
        memory: workloads::memory_resource().unwrap(),
        memory_capacity: Capacity::Physical { bytes: memory },
        retention_budget_bytes: budget,
        scope_budgets: Vec::new(),
        capacities: Vec::new(),
        policy: Policy::new(),
        objective: Objective::new(1.0, 0.0, 0.0, 0.0).unwrap(),
        bounds: HorizonBounds {
            min_probability: 0.0,
            max_requests: 64,
            max_objects: 64,
        },
    }
}

// --- The §4.14 counterexample (lines 810–818) ---

#[test]
fn counterexample_savings_match_the_plan() {
    let toy = horizon(&workloads::counterexample().unwrap());
    let empty = outcome(&toy, &[]).feasible().unwrap();
    assert_eq!(
        empty.completion,
        vec![millis(9 * SECOND), millis(5 * SECOND)]
    );
    assert_eq!(empty.net_score, 0.0);
    // Retaining a alone saves zero: b remains the barrier; likewise b alone.
    assert_eq!(saved(&toy, &["a"]), 0.0);
    assert_eq!(saved(&toy, &["b"]), 0.0);
    assert_eq!(saved(&toy, &["c"]), 4.0);
    assert_eq!(saved(&toy, &["a", "b"]), 8.0);
    assert_eq!(saved(&toy, &["c", "a"]), 4.0);
    assert_eq!(saved(&toy, &["c", "b"]), 4.0);
    // Capacity two: the three objects never fit together.
    assert_eq!(
        outcome(&toy, &["a", "b", "c"]),
        Outcome::Infeasible(Infeasibility::OverRetentionBudget {
            bytes: 3,
            budget_bytes: 2
        })
    );
}

#[test]
fn individual_greedy_picks_c_and_the_bundle_method_picks_the_pair() {
    let toy = horizon(&workloads::counterexample().unwrap());
    let greedy = planned(&toy, PlannerConfig::object_greedy(1_000_000));
    assert_eq!(selected_ids(&toy, &greedy), ["c"]);
    assert_eq!(plan_net(&greedy), 4.0);
    assert!(matches!(
        greedy.steps.first(),
        Some(PlanStep::Selected {
            origin: CandidateOrigin::Single { object: 2 },
            ..
        })
    ));

    let bundle = planned(&toy, PlannerConfig::bundles(1_000_000));
    assert_eq!(selected_ids(&toy, &bundle), ["a", "b"]);
    assert_eq!(plan_net(&bundle), 8.0);
    // The pair came from request 1's two concurrent blockers.
    assert!(matches!(
        bundle.steps.first(),
        Some(PlanStep::Selected {
            origin: CandidateOrigin::ConcurrentBlockers {
                request: 0,
                depth: 2
            },
            ..
        })
    ));
}

#[test]
fn marginal_value_rises_so_no_submodular_guarantee_applies() {
    let toy = horizon(&workloads::counterexample().unwrap());
    let alone = saved(&toy, &["a"]) - saved(&toy, &[]);
    let after_b = saved(&toy, &["a", "b"]) - saved(&toy, &["b"]);
    assert_eq!((alone, after_b), (0.0, 8.0));
    // Diminishing returns would need alone >= after_b; it fails.
    assert!(alone < after_b);
}

#[test]
fn the_exhaustive_optimum_of_the_counterexample_is_the_pair() {
    let toy = horizon(&workloads::counterexample().unwrap());
    let optimum = exhaustive_optimum(&toy, &clock()).unwrap();
    assert_eq!(toy.ids(&optimum.selection), ["a", "b"]);
    assert_eq!(optimum.evaluation.saved_weighted_seconds, 8.0);
    assert_eq!((optimum.subsets, optimum.feasible), (8, 7));
}

#[test]
fn the_exhaustive_optimum_refuses_large_horizons() {
    let items: Vec<(String, u64, u64)> = (0..13).map(|at| (format!("x{at}"), 1, SECOND)).collect();
    let borrowed: Vec<(&str, u64, u64)> = items
        .iter()
        .map(|(id, b, l)| (id.as_str(), *b, *l))
        .collect();
    let large = horizon(&workloads::independent("large", &borrowed, 4).unwrap());
    assert_eq!(
        exhaustive_optimum(&large, &clock()),
        Err(BundleError::TooLargeForExhaustive {
            objects: 13,
            max: 12
        })
    );
}

// --- Step 4: never above the optimum on seeded graphs ---

#[test]
fn the_bundle_method_never_beats_the_exhaustive_optimum_on_seeded_graphs() {
    let study = oracle_study(0..40, &ExperimentConfig::standard(), &clock()).unwrap();
    assert_eq!(study.rows.len(), 40);
    assert!(study.never_beaten());
    for row in &study.rows {
        assert!(row.ratio() <= 1.0 + 1e-9, "{row:?}");
        assert!(row.optimal_net >= 0.0, "{row:?}");
    }
    println!(
        "oracle: min ratio {:.4}, mean ratio {:.4}, optimal on {}/{}",
        study.min_ratio(),
        study.mean_ratio(),
        study.optimal_rows(),
        study.rows.len()
    );
    assert!(study.min_ratio() > 0.0);
}

#[test]
fn bounded_replacement_misses_a_three_way_swap() {
    // The claim record's counterexample: replacing one group cannot reach {y, z, u}.
    let knapsack = horizon(
        &workloads::independent(
            "knapsack",
            &[
                ("x", 3, 10 * SECOND),
                ("w", 3, 10 * SECOND),
                ("y", 2, 7 * SECOND),
                ("z", 2, 7 * SECOND),
                ("u", 2, 7 * SECOND),
            ],
            6,
        )
        .unwrap(),
    );
    let bundle = planned(&knapsack, PlannerConfig::bundles(10_000_000));
    assert_eq!(selected_ids(&knapsack, &bundle), ["x", "w"]);
    assert_eq!(plan_net(&bundle), 20.0);
    let optimum = exhaustive_optimum(&knapsack, &clock()).unwrap();
    assert_eq!(knapsack.ids(&optimum.selection), ["y", "z", "u"]);
    assert_eq!(optimum.evaluation.saved_weighted_seconds, 21.0);
}

// --- Step 6: local replacement ---

#[test]
fn local_replacement_undoes_a_bad_early_pick() {
    let case = horizon(
        &workloads::independent(
            "replacement",
            &[
                ("x", 2, 5 * SECOND),
                ("y", 1, 4 * SECOND),
                ("z", 1, 4 * SECOND),
            ],
            2,
        )
        .unwrap(),
    );
    let without = planned(
        &case,
        PlannerConfig {
            replacement_rounds: 0,
            ..PlannerConfig::bundles(10_000_000)
        },
    );
    assert_eq!(selected_ids(&case, &without), ["x"]);
    assert_eq!(plan_net(&without), 5.0);

    let with = planned(&case, PlannerConfig::bundles(10_000_000));
    assert_eq!(selected_ids(&case, &with), ["y", "z"]);
    assert_eq!(plan_net(&with), 8.0);
    let x = case.selection_of(&["x"]).unwrap();
    assert!(with.steps.iter().any(|step| matches!(
        step,
        PlanStep::Replaced { removed, net_before, net_after, .. }
            if removed == &x && *net_before == 5_000.0 && *net_after == 8_000.0
    )));
}

// --- Physical memory, transient capacity and trust constraints ---

#[test]
fn capacity_infeasibility_is_refused() {
    // An unneeded resident object d: retaining it takes transient room from r1's
    // two-unit workspace.
    let mut toy = workloads::counterexample().unwrap().spec;
    toy.objects.push(object(
        "d",
        NodeKind::ArtifactExtent,
        2,
        3 * SECOND,
        &[],
        true,
    ));
    toy.memory_capacity = Capacity::Physical { bytes: 5 };
    toy.retention_budget_bytes = 4;
    toy.requests[0].compute_demand = vec![DemandSegment::transient(
        workloads::memory_resource().unwrap(),
        ResourceUnit::Bytes,
        2,
        Duration::ZERO,
        millis(SECOND),
    )
    .unwrap()];
    let tight = Horizon::build(toy.clone()).unwrap();
    assert!(outcome(&tight, &[]).feasible().is_some());
    assert!(matches!(
        outcome(&tight, &["d"]),
        Outcome::Infeasible(Infeasibility::Unschedulable(
            ScheduleError::NoFeasiblePlacement { .. }
                | ScheduleError::CapacityExceeded { .. }
                | ScheduleError::NodeExceedsCapacity { .. }
        ))
    ));
    let chosen = planned(&tight, PlannerConfig::bundles(10_000_000));
    assert!(!chosen.selection().contains(tight.index_of("d").unwrap()));

    // The retention budget must leave transient room, and must not be zero.
    toy.retention_budget_bytes = 5;
    assert!(matches!(
        Horizon::build(toy.clone()),
        Err(BundleError::InvalidValue {
            field: "retention budget",
            ..
        })
    ));
    toy.retention_budget_bytes = 0;
    assert!(Horizon::build(toy.clone()).is_err());

    // Physical memory only: an address reservation supplies none (§2.7).
    toy.retention_budget_bytes = 4;
    toy.memory_capacity = Capacity::VirtualReservation { bytes: 1 << 40 };
    assert_eq!(
        Horizon::build(toy).err(),
        Some(BundleError::NotPhysicalCapacity { bytes: 1 << 40 })
    );
}

#[test]
fn trust_scopes_are_enforced() {
    let other = TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, "other-tenant");
    let base = workloads::counterexample().unwrap().spec;

    // State of another scope without an allowance is refused.
    let mut foreign = base.clone();
    foreign.objects[2].trust_scope = other;
    assert_eq!(
        Horizon::build(foreign.clone()).err(),
        Some(BundleError::CrossScope {
            consumer: "r2".to_string(),
            object: "c".to_string()
        })
    );
    // An allowance naming producer scope, consumer scope and exact identity admits it.
    let mut allowed = foreign.clone();
    allowed.policy = Policy::new().allow(
        other,
        workloads::workload_scope(),
        foreign.objects[2].identity,
    );
    let admitted = Horizon::build(allowed).unwrap();
    assert_eq!(saved(&admitted, &["c"]), 4.0);
    // An allowance for other state does not.
    let mut wrong = foreign.clone();
    wrong.policy = Policy::new().allow(
        other,
        workloads::workload_scope(),
        foreign.objects[0].identity,
    );
    assert!(matches!(
        Horizon::build(wrong),
        Err(BundleError::CrossScope { .. })
    ));

    // Reconstruction requirements are checked the same way.
    let mut requirement = base.clone();
    requirement.objects[0].requires = vec!["c".to_string()];
    requirement.objects[2].trust_scope = other;
    requirement.policy =
        Policy::new().allow(other, workloads::workload_scope(), base.objects[2].identity);
    requirement.requests[1].trust_scope = other;
    assert_eq!(
        Horizon::build(requirement.clone()).err(),
        None,
        "allowed requirement"
    );
    requirement.policy = Policy::new();
    assert!(matches!(
        Horizon::build(requirement),
        Err(BundleError::CrossScope { consumer, object }) if consumer == "a" && object == "c"
    ));

    // Per-scope budgets: one unit for the workload scope refuses the pair.
    let mut budgeted = base.clone();
    budgeted.scope_budgets = vec![(workloads::workload_scope(), 1)];
    let limited = Horizon::build(budgeted.clone()).unwrap();
    assert_eq!(
        outcome(&limited, &["a", "b"]),
        Outcome::Infeasible(Infeasibility::OverScopeBudget {
            scope: workloads::workload_scope(),
            bytes: 2,
            budget_bytes: 1
        })
    );
    let chosen = planned(&limited, PlannerConfig::bundles(10_000_000));
    assert_eq!(selected_ids(&limited, &chosen), ["c"]);
    // Once budgets are declared, every object's scope needs one.
    budgeted.objects[2].trust_scope = other;
    budgeted.policy =
        Policy::new().allow(other, workloads::workload_scope(), base.objects[2].identity);
    assert_eq!(
        Horizon::build(budgeted).err(),
        Some(BundleError::ScopeWithoutBudget {
            object: "c".to_string()
        })
    );
}

// --- Preparation: duration inside T_r, cost prices resources only (line 808) ---

fn preparation_case(arrival: u64) -> Horizon {
    let mut prepared = object("p", NodeKind::Adapter, 1, 8 * SECOND, &[], false);
    prepared.preparation = RawCost {
        bytes: 1.0,
        ..RawCost::default()
    };
    prepared.interference = RawCost {
        milliseconds: 50.0,
        ..RawCost::default()
    };
    let mut horizon_spec = spec(vec![prepared], vec![request("r", &["p"], arrival)], 2, 1);
    horizon_spec.objective = Objective::new(1.0, 100.0, 0.0, 0.0).unwrap();
    Horizon::build(horizon_spec).unwrap()
}

#[test]
fn preparation_cost_never_double_counts_latency() {
    // Preparation starts now; the request arrives at 4 s, so only 4 s of the 8 s load
    // is hidden. That latency is in T_r, never in the preparation penalty.
    let early = preparation_case(4 * SECOND);
    let evaluation = outcome(&early, &["p"]).feasible().unwrap();
    assert_eq!(evaluation.saved_weighted_seconds, 4.0);
    assert_eq!(evaluation.benefit_score, 4_000.0);
    assert_eq!(evaluation.preparation.milliseconds, 0.0);
    assert_eq!(evaluation.preparation_score, 100.0);
    assert_eq!(evaluation.interference_score, 50.0);
    assert_eq!(evaluation.net_score, 3_850.0);
    assert_eq!(evaluation.prepared_bytes, 1);
    // Arriving at 10 s, the whole load is hidden; the penalty is unchanged.
    let late = preparation_case(10 * SECOND);
    let evaluation = outcome(&late, &["p"]).feasible().unwrap();
    assert_eq!(evaluation.saved_weighted_seconds, 8.0);
    assert_eq!(evaluation.preparation_score, 100.0);

    // A preparation cost that prices latency is refused.
    let mut priced = spec(
        vec![object("p", NodeKind::Adapter, 1, SECOND, &[], false)],
        vec![request("r", &["p"], 0)],
        2,
        1,
    );
    priced.objects[0].preparation.milliseconds = 1.0;
    assert_eq!(
        Horizon::build(priced).err(),
        Some(BundleError::PreparationPricesLatency {
            object: "p".to_string()
        })
    );
}

// --- Step 7: fallbacks ---

#[test]
fn budget_exhaustion_falls_back_with_its_reason() {
    let toy = horizon(&workloads::counterexample().unwrap());
    let starved = planned(&toy, PlannerConfig::bundles(50));
    assert_eq!(
        starved.outcome,
        PlanOutcome::Fallback {
            policy: FallbackPolicy::MeasuredCostPerByte,
            reason: FallbackReason::PlanningBudgetExhausted {
                spent_units: 50,
                max_units: 50
            },
            selection: measured_cost_per_byte(&toy),
        }
    );
    assert!(starved.work_units <= 50);
    // Measured cost per byte keeps the 8 s objects.
    assert_eq!(toy.ids(starved.selection()), ["a", "b"]);
}

#[test]
fn low_forecast_confidence_falls_back_to_demand_only() {
    let toy = horizon(&workloads::counterexample().unwrap());
    let mut forecast = controller();
    forecast
        .observe(
            MonotonicTime::from_nanos(1),
            ModeSignals {
                confidence: 0.1,
                load_fraction: 0.1,
                calibration_error: 0.0,
            },
        )
        .unwrap();
    let fallback = plan(&toy, &clock(), &forecast, PlannerConfig::bundles(1_000_000)).unwrap();
    assert_eq!(
        fallback.fallback(),
        Some(FallbackReason::Forecast(DemandOnlyReason::LowConfidence))
    );
    assert!(matches!(
        fallback.outcome,
        PlanOutcome::Fallback {
            policy: FallbackPolicy::DemandOnly,
            ..
        }
    ));
    assert_eq!(fallback.work_units, 0);
}

#[test]
fn the_work_meter_charges_at_least_the_work_done() {
    let mut meter = WorkMeter::bounded(10);
    meter.charge(5).unwrap();
    assert_eq!(meter.remaining(), 5);
    assert_eq!(
        meter.charge(6),
        Err(BundleError::BudgetExhausted {
            spent_units: 10,
            max_units: 10
        })
    );
    let toy = horizon(&workloads::counterexample().unwrap());
    let clock = clock();
    let mut tiny = WorkMeter::bounded(1);
    assert!(matches!(
        Evaluator::new(&toy, &clock, &mut tiny),
        Err(BundleError::BudgetExhausted { .. })
    ));
    let mut meter = WorkMeter::unbounded();
    let evaluator = Evaluator::new(&toy, &clock, &mut meter).unwrap();
    let before = meter.spent();
    let evaluation = evaluator
        .evaluate(&toy.selection_of(&["c"]).unwrap(), &mut meter)
        .unwrap()
        .feasible()
        .unwrap();
    assert!(evaluation.work_units > 0);
    assert_eq!(meter.spent() - before, evaluation.work_units);
}

// --- Step 3: the candidate set and its bound (line 836) ---

#[test]
fn candidate_enumeration_stays_bounded_as_models_and_requests_grow() {
    let study = enumeration_study(
        &[(2, 2), (4, 4), (8, 8), (16, 16), (32, 32)],
        7,
        3,
        &clock(),
    )
    .unwrap();
    assert!(study.bounded());
    for row in &study.rows {
        assert!(row.candidates <= row.bound, "{row:?}");
        assert_eq!(
            row.bound,
            candidate_bound(
                row.needed_objects,
                row.included_requests,
                3,
                CandidateMode::Bundles
            )
        );
        println!("enumeration: {row:?}");
    }
    // At most max(2, B) candidates per needed object and request: linear growth.
    assert!(study.max_candidates_per_unit() <= 3.0);
    let (first, last) = (study.rows[0], study.rows[study.rows.len() - 1]);
    assert!(last.needed_objects > first.needed_objects);

    // Every round of a full plan stays within the bound too.
    let shared = horizon(&workloads::shared_base(7, 4, 6).unwrap());
    let chosen = planned(&shared, PlannerConfig::bundles(50_000_000));
    assert!(
        chosen.max_candidates_in_round
            <= candidate_bound(
                shared.needed_objects().len(),
                shared.request_count(),
                3,
                CandidateMode::Bundles
            )
    );
}

#[test]
fn dependency_closure_spans_kinds_and_excludes_descendants() {
    let objects = vec![
        object("w", NodeKind::ArtifactExtent, 4, 6 * SECOND, &[], false),
        object("l", NodeKind::RankLayout, 4, 2 * SECOND, &["w"], false),
        object("a", NodeKind::Adapter, 1, SECOND, &["l"], false),
        object("s", NodeKind::KvBlock, 2, SECOND, &["a"], false),
        object("a2", NodeKind::Adapter, 1, SECOND, &["w"], false),
    ];
    // Both requests arrive at 20 s, so preparing the chain now hides its loads.
    let requests = vec![
        request("r", &["l", "a", "s"], 20 * SECOND),
        request("r2", &["a2"], 20 * SECOND),
    ];
    let chain = Horizon::build(spec(objects, requests, 20, 12)).unwrap();
    let id = |name: &str| chain.index_of(name).unwrap();
    let group = chain.closure(id("s"), &Selection::new());
    assert_eq!(chain.ids(&group), ["w", "l", "a", "s"]);
    let kinds: Vec<NodeKind> = group.iter().map(|at| chain.object(at).kind).collect();
    assert_eq!(
        kinds,
        [
            NodeKind::ArtifactExtent,
            NodeKind::RankLayout,
            NodeKind::Adapter,
            NodeKind::KvBlock
        ]
    );
    // Closure of the base never pulls in its descendants (line 830).
    assert_eq!(chain.ids(&chain.closure(id("w"), &Selection::new())), ["w"]);
    // Requirements already selected are not repeated.
    let base = chain.selection_of(&["w"]).unwrap();
    assert_eq!(chain.ids(&chain.closure(id("l"), &base)), ["l"]);
    // An absent object without its requirements cannot be prepared.
    assert_eq!(
        outcome(&chain, &["s"]),
        Outcome::Infeasible(Infeasibility::NotDependencyClosed {
            object: "s".to_string(),
            missing: "a".to_string()
        })
    );
    assert!(outcome(&chain, &["w", "l", "a", "s"]).feasible().is_some());
    // The planner offers the closure as one candidate.
    let chosen = planned(&chain, PlannerConfig::bundles(10_000_000));
    assert!(chosen.steps.iter().any(|step| matches!(
        step,
        PlanStep::Selected { origin: CandidateOrigin::Closure { .. } | CandidateOrigin::ConcurrentBlockers { .. }, group, .. }
            if group.len() > 1
    )));
}

#[test]
fn a_shared_object_is_credited_for_every_request_it_unlocks() {
    let objects = vec![object(
        "base",
        NodeKind::ArtifactExtent,
        2,
        6 * SECOND,
        &[],
        true,
    )];
    let requests = vec![
        request("q1", &["base"], 0),
        request("q2", &["base"], 0),
        request("q3", &["base"], 0),
    ];
    let shared = Horizon::build(spec(objects, requests, 4, 2)).unwrap();
    assert_eq!(shared.requesters(0), [0, 1, 2]);
    assert_eq!(saved(&shared, &["base"]), 18.0);
}

#[test]
fn shared_links_queue_loads_rather_than_dividing_bandwidth() {
    let link = workloads::link_resource().unwrap();
    let with_link = |id: &str| {
        let mut spec = object(id, NodeKind::ArtifactExtent, 1, 4 * SECOND, &[], true);
        spec.load_demand = vec![DemandSegment::transient(
            link.clone(),
            ResourceUnit::Slots,
            1,
            Duration::ZERO,
            millis(4 * SECOND),
        )
        .unwrap()];
        spec
    };
    let build = |slots: u64| {
        let mut horizon_spec = spec(
            vec![with_link("p"), with_link("q")],
            vec![request("r", &["p", "q"], 0)],
            3,
            1,
        );
        horizon_spec.capacities = vec![(link.clone(), ResourceUnit::Slots, slots)];
        Horizon::build(horizon_spec).unwrap()
    };
    let one_slot = build(1);
    let empty = outcome(&one_slot, &[]).feasible().unwrap();
    assert_eq!(empty.completion, vec![millis(9 * SECOND)]);
    assert_eq!(saved(&one_slot, &["p"]), 4.0);
    let two_slots = build(2);
    assert_eq!(
        outcome(&two_slots, &[]).feasible().unwrap().completion,
        vec![millis(5 * SECOND)]
    );
    assert_eq!(saved(&two_slots, &["p"]), 0.0);
}

#[test]
fn demand_loads_wait_for_the_request_that_needs_them() {
    let horizon = Horizon::build(spec(
        vec![object("p", NodeKind::Adapter, 1, 2 * SECOND, &[], true)],
        vec![request("r", &["p"], 5 * SECOND)],
        2,
        1,
    ))
    .unwrap();
    let empty = outcome(&horizon, &[]).feasible().unwrap();
    // The demand load starts at arrival: T_r = 2 s + 1 s, not 1 s.
    assert_eq!(empty.completion, vec![millis(3 * SECOND)]);
    assert_eq!(empty.object_ready[0], Some(millis(7 * SECOND)));
    assert_eq!(saved(&horizon, &["p"]), 2.0);
}

// --- Baselines ---

#[test]
fn caching_baselines_follow_their_history() {
    let toy_workload = workloads::counterexample().unwrap();
    let toy = horizon(&toy_workload);
    for policy in [
        CachePolicy::Lru,
        CachePolicy::CostPerByte,
        CachePolicy::MarginalSavedLatency { half_life_steps: 8 },
        CachePolicy::GreedyDualSize,
    ] {
        let kept = cache_selection(&toy, &toy_workload.history, policy).unwrap();
        assert_eq!(toy.ids(&kept.selection), ["b", "c"], "{}", policy.label());
        assert_eq!(kept.refused_accesses, 0);
    }
    // Recency alone can land on the pair when the history happens to end with r1.
    let reversed: Vec<Vec<String>> = toy_workload.history.iter().rev().cloned().collect();
    let lucky = cache_selection(&toy, &reversed, CachePolicy::Lru).unwrap();
    assert_eq!(toy.ids(&lucky.selection), ["a", "b"]);
    assert!(matches!(
        cache_selection(&toy, &[vec!["missing".to_string()]], CachePolicy::Lru),
        Err(BundleError::Unknown { .. })
    ));
}

#[test]
fn the_counterexample_comparison_charges_planner_overhead() {
    let toy_workload = workloads::counterexample().unwrap();
    let toy = horizon(&toy_workload);
    let config = ExperimentConfig::standard();
    let run = run_instance(
        &toy,
        &toy,
        &toy_workload.history,
        &Method::ALL,
        &config,
        &clock(),
    )
    .unwrap();
    let net = |method: Method| run.run(method).unwrap().net_score;
    assert_eq!(net(Method::Bundle), 8_000.0);
    assert_eq!(net(Method::BundleWithoutReplacement), 8_000.0);
    for method in [
        Method::ObjectGreedy,
        Method::SinglesWithReplacement,
        Method::Lru,
        Method::CostPerByte,
        Method::MarginalSavedLatency,
        Method::GreedyDualSize,
    ] {
        assert_eq!(net(method), 4_000.0, "{}", method.label());
    }
    assert_eq!(net(Method::RetainNothing), 0.0);
    let bundle = run.run(Method::Bundle).unwrap();
    assert!(bundle.work_units > 0 && bundle.overhead_score > 0.0);
    assert_eq!(
        bundle.net_after_overhead,
        bundle.net_score - bundle.overhead_score
    );
    // Planner time is charged on both requests: 2 × work × 100 ns, in milliseconds.
    let expected = 2.0 * bundle.work_units as f64 * 1e-7 * 1_000.0;
    assert!((bundle.overhead_score - expected).abs() < 1e-9);
    assert_eq!(run.strongest_baseline().unwrap().method, Method::Lru);
    assert!(run.improvement().unwrap() > 3_990.0);
}

// --- Fake-substrate records and the CORE-08 comparison ---

fn adversarial_family(count: u64) -> Vec<(u64, Workload)> {
    (0..count)
        .map(|at| (100 + at, workloads::adversarial(100 + at).unwrap()))
        .collect()
}

#[test]
fn the_baseline_comparison_is_recorded_on_the_fake_substrate() {
    let clock = clock();
    let comparison = compare_family(
        "adversarial",
        &adversarial_family(5),
        &Method::ALL,
        &ExperimentConfig::standard(),
        &clock,
    )
    .unwrap();
    let recorded = record_family(&comparison, MonotonicTime::from_nanos(5_000_000_000)).unwrap();
    assert_eq!(recorded.sides.len(), Method::ALL.len());
    let requests: usize = comparison
        .instances
        .iter()
        .map(|instance| instance.horizon.request_count())
        .sum();
    for side in &recorded.sides {
        assert!(
            side.provenance.is_fake_substrate(),
            "{}",
            side.method.label()
        );
        assert_eq!(
            side.provenance.yougori_evidence(),
            Err(ReportError::FakeSubstrateIsNotEvidence)
        );
        assert_eq!(side.records.len(), requests);
        for record in &side.records {
            assert_eq!(record.substrate, RunSubstrate::FakeTimeControlled);
            record.validate().unwrap();
        }
        for quantile in Quantile::REPORTED {
            assert!(side.summary.percentile(quantile).is_some());
        }
    }
    assert_eq!(recorded.report.candidate().name.as_str(), "bundle");
    // A fake side backs no improvement claim against either baseline.
    for role in [
        BaselineRole::OrdinaryWorkflow,
        BaselineRole::StrongestUpstream,
    ] {
        assert_eq!(
            ImprovementClaim::from_report(&recorded.report, role).err(),
            Some(ReportError::FakeSubstrateIsNotEvidence)
        );
    }
    // Fewer than five independent trials make no comparison.
    let mut short = comparison.clone();
    short.instances.truncate(1);
    short.seeds.truncate(1);
    assert!(matches!(
        record_family(&short, MonotonicTime::from_nanos(5_000_000_000)),
        Err(BundleError::Report(ReportError::TooFewTrials { .. }))
    ));
}

#[test]
fn simulated_records_shift_by_planner_overhead() {
    let toy = horizon(&workloads::counterexample().unwrap());
    let evaluation = outcome(&toy, &["a", "b"]).feasible().unwrap();
    let origin = MonotonicTime::from_nanos(1_000);
    let records = simulated_records(
        "counterexample",
        Method::Bundle,
        0,
        &toy,
        &evaluation,
        millis(250),
        origin,
    )
    .unwrap();
    assert_eq!(records.len(), 2);
    let first = records[0]
        .interval(crate::foundation::report::IntervalKind::TimeToFirstToken)
        .unwrap();
    // r1: one second of compute after the 250 ms of planning.
    assert_eq!(first.elapsed(), millis(1_250));
    let ready = records[1]
        .interval(crate::foundation::report::IntervalKind::WeightAvailability)
        .unwrap();
    // r2 still waits 4 s for c, plus planning.
    assert_eq!(ready.elapsed(), millis(4_250));
}

// --- Forecast errors (line 836) ---

#[test]
fn forecast_errors_are_seeded_and_calibration_is_reported() {
    let shared = workloads::shared_base(3, 3, 6).unwrap();
    let a = workloads::perturb(&shared.spec, 9, 0.3).unwrap();
    let b = workloads::perturb(&shared.spec, 9, 0.3).unwrap();
    let c = workloads::perturb(&shared.spec, 10, 0.3).unwrap();
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_eq!(
        workloads::perturb(&shared.spec, 9, 0.0).unwrap(),
        shared.spec
    );
    assert!(workloads::perturb(&shared.spec, 9, 1.0).is_err());
    for (before, after) in shared.spec.objects.iter().zip(&a.objects) {
        assert_eq!(
            (before.bytes, &before.requires),
            (after.bytes, &after.requires)
        );
        let ratio = after.load.expected().as_secs_f64() / before.load.expected().as_secs_f64();
        assert!((0.7 - 1e-9..=1.3 + 1e-9).contains(&ratio), "{ratio}");
    }
    let predicted = shared
        .spec
        .requests
        .iter()
        .filter(|request| matches!(request.admission, Admission::Predicted { .. }))
        .count();
    let (realized, samples) = workloads::realize(&shared.spec, &a, 4).unwrap();
    assert_eq!(samples.len(), predicted);
    assert!(realized
        .requests
        .iter()
        .all(|request| request.admission == Admission::Admitted));
    let arrived = samples.iter().filter(|(_, arrived)| *arrived).count();
    assert_eq!(
        realized.requests.len(),
        shared.spec.requests.len() - predicted + arrived
    );

    let family: Vec<(u64, Workload)> = (0..5)
        .map(|at| (200 + at, workloads::shared_base(200 + at, 3, 4).unwrap()))
        .collect();
    let study = forecast_study(
        "shared-base",
        &family,
        0.3,
        &Method::COMPARED,
        &ExperimentConfig::standard(),
        &clock(),
    )
    .unwrap();
    assert!(study.predictions > 0);
    assert!(study.brier_score.is_some() && study.expected_calibration_error.is_some());
    assert_eq!(study.comparison.instances.len(), 5);
    println!(
        "forecast e=0.3: improvements {:?}, brier {:?}, ece {:?}",
        study.comparison.improvements(),
        study.brier_score,
        study.expected_calibration_error
    );
}

// --- Step 1: the bounded horizon ---

#[test]
fn the_horizon_is_bounded_and_validated() {
    let objects = || {
        vec![
            object("p", NodeKind::ArtifactExtent, 1, SECOND, &[], true),
            object("q", NodeKind::ArtifactExtent, 1, SECOND, &[], true),
        ]
    };
    let mut unlikely = request("maybe", &["q"], SECOND);
    unlikely.admission = Admission::Predicted { probability: 0.2 };
    let mut likely = request("likely", &["q"], SECOND);
    likely.admission = Admission::Predicted { probability: 0.9 };
    let mut bounded = spec(
        objects(),
        vec![request("now", &["p"], 0), unlikely, likely],
        3,
        1,
    );
    bounded.bounds.min_probability = 0.5;
    let horizon = Horizon::build(bounded.clone()).unwrap();
    assert_eq!(horizon.request_count(), 2);
    assert_eq!(
        horizon.excluded(),
        [("maybe".to_string(), Exclusion::BelowMinimumProbability)]
    );
    assert_eq!(horizon.effective_weight(1), 0.9);

    bounded.bounds.max_requests = 1;
    let one = Horizon::build(bounded.clone()).unwrap();
    assert_eq!(one.request_count(), 1);
    assert!(one
        .excluded()
        .contains(&("likely".to_string(), Exclusion::RequestBound)));
    assert!(!one.is_needed(one.index_of("q").unwrap()));

    let mut too_many = spec(
        objects(),
        vec![request("a", &["p"], 0), request("b", &["q"], 0)],
        3,
        1,
    );
    too_many.bounds.max_requests = 1;
    assert!(matches!(
        Horizon::build(too_many),
        Err(BundleError::HorizonTooLarge { .. })
    ));

    let mut duplicate = spec(objects(), vec![request("a", &["p"], 0)], 3, 1);
    duplicate
        .objects
        .push(object("p", NodeKind::Adapter, 1, SECOND, &[], true));
    assert!(matches!(
        Horizon::build(duplicate),
        Err(BundleError::Duplicate { .. })
    ));
    let unknown = spec(objects(), vec![request("a", &["zz"], 0)], 3, 1);
    assert!(matches!(
        Horizon::build(unknown),
        Err(BundleError::Unknown { .. })
    ));
    let mut cycle = spec(objects(), vec![request("a", &["p"], 0)], 3, 1);
    cycle.objects[0].requires = vec!["q".to_string()];
    cycle.objects[1].requires = vec!["p".to_string()];
    assert!(matches!(
        Horizon::build(cycle),
        Err(BundleError::RequirementCycle { .. })
    ));
    let mut empty_bytes = spec(objects(), vec![request("a", &["p"], 0)], 3, 1);
    empty_bytes.objects[0].bytes = 0;
    assert!(Horizon::build(empty_bytes).is_err());
    let mut compute = spec(objects(), vec![request("a", &["p"], 0)], 3, 1);
    compute.objects[0].kind = NodeKind::Compute;
    assert!(Horizon::build(compute).is_err());
    let bad_id = spec(objects(), vec![request("has space", &["p"], 0)], 3, 1);
    assert!(matches!(
        Horizon::build(bad_id),
        Err(BundleError::InvalidId { .. })
    ));
}

// --- The pass/stop rule and the claim record (§4.14 line 836, §4.17) ---

fn family_evidence(
    family: &'static str,
    relative_error: f64,
    mean_improvement: f64,
) -> FamilyEvidence {
    FamilyEvidence {
        family,
        relative_error,
        instances: 6,
        mean_improvement,
        min_improvement: mean_improvement,
        wins: 6,
    }
}

fn evidence(
    families: &[f64],
    forecast: &[f64],
    counterexample: f64,
    bounded: bool,
) -> PassStopEvidence {
    PassStopEvidence {
        counterexample_improvement: counterexample,
        families: families
            .iter()
            .map(|mean| family_evidence("generated", 0.0, *mean))
            .collect(),
        forecast: forecast
            .iter()
            .map(|mean| family_evidence("generated", 0.3, *mean))
            .collect(),
        enumeration_bounded: bounded,
    }
}

#[test]
fn the_pass_stop_rule_is_computed() {
    assert_eq!(
        pass_stop(&evidence(&[5.0, 3.0], &[1.0], 4.0, true)),
        PassStop::Advance
    );
    assert_eq!(
        pass_stop(&evidence(&[5.0, 3.0], &[1.0], 4.0, false)),
        PassStop::Stop(StopReason::EnumerationUnbounded)
    );
    assert_eq!(
        pass_stop(&evidence(&[-1.0, 0.0], &[1.0], 4.0, true)),
        PassStop::Narrow(NarrowReason::OnlyHandBuiltExamples)
    );
    assert_eq!(
        pass_stop(&evidence(&[-1.0, 0.0], &[-1.0], 0.0, true)),
        PassStop::Stop(StopReason::NoImprovement)
    );
    assert_eq!(
        pass_stop(&evidence(&[5.0, -1.0], &[1.0], 4.0, true)),
        PassStop::Narrow(NarrowReason::NotInFamily {
            family: "generated"
        })
    );
    assert_eq!(
        pass_stop(&evidence(&[5.0, 3.0], &[-0.5], 4.0, true)),
        PassStop::Narrow(NarrowReason::NotUnderForecastError {
            family: "generated",
            relative_error: 0.3
        })
    );
    assert_eq!(
        pass_stop(&evidence(&[], &[], 4.0, true)),
        PassStop::Narrow(NarrowReason::OnlyHandBuiltExamples)
    );
}

fn provenances() -> (Provenance, Provenance) {
    let toy = horizon(&workloads::counterexample().unwrap());
    let evaluation = outcome(&toy, &["a", "b"]).feasible().unwrap();
    let records = simulated_records(
        "counterexample",
        Method::Bundle,
        0,
        &toy,
        &evaluation,
        Duration::ZERO,
        MonotonicTime::ZERO,
    )
    .unwrap();
    let fake = Provenance::of_records(&records).unwrap();
    let mut real = records;
    for record in &mut real {
        record.substrate = RunSubstrate::AuthorizedDisposable {
            authorization: Label::new("disposable-test-host").unwrap(),
        };
    }
    (fake, Provenance::of_records(&real).unwrap())
}

#[test]
fn the_claim_result_never_exceeds_inconclusive_on_fakes() {
    let (fake, measured) = provenances();
    assert!(fake.is_fake_substrate() && !measured.is_fake_substrate());
    for literature in [
        LiteratureComparison::NotDone,
        LiteratureComparison::OverlapsPriorWork,
        LiteratureComparison::DifferenceEstablished,
    ] {
        assert_eq!(
            claim_result(&PassStop::Advance, &fake, literature),
            ClaimResult::Inconclusive
        );
    }
    assert_eq!(
        claim_result(
            &PassStop::Narrow(NarrowReason::OnlyHandBuiltExamples),
            &fake,
            LiteratureComparison::NotDone
        ),
        ClaimResult::Narrowed
    );
    assert_eq!(
        claim_result(
            &PassStop::Stop(StopReason::NoImprovement),
            &measured,
            LiteratureComparison::DifferenceEstablished
        ),
        ClaimResult::Rejected
    );
    // Only measurements plus a literature comparison go further.
    assert_eq!(
        claim_result(&PassStop::Advance, &measured, LiteratureComparison::NotDone),
        ClaimResult::Inconclusive
    );
    assert_eq!(
        claim_result(
            &PassStop::Advance,
            &measured,
            LiteratureComparison::OverlapsPriorWork
        ),
        ClaimResult::UsefulIntegration
    );
    assert_eq!(
        claim_result(
            &PassStop::Advance,
            &measured,
            LiteratureComparison::DifferenceEstablished
        ),
        ClaimResult::SupportedOriginalContribution
    );
}

#[test]
fn the_claim_text_avoids_novelty_words_and_names_the_prior_work() {
    for text in [
        CLAIM_CONTRIBUTION,
        CLAIM_DIFFERENCE,
        CLAIM_ASSUMPTIONS,
        CLAIM_COUNTEREXAMPLE,
    ] {
        let lower = text.to_ascii_lowercase();
        for word in FORBIDDEN_CLAIM_WORDS {
            assert!(
                !lower
                    .split(|c: char| !c.is_ascii_alphanumeric())
                    .any(|token| token == word),
                "{word}: {text}"
            );
        }
    }
    let names: Vec<&str> = CLOSEST_PRIOR_WORK.iter().map(|work| work.name).collect();
    assert_eq!(
        names,
        ["Dependency-Aware Online Caching", "ELORA", "Chameleon"]
    );
}

#[test]
fn the_first_prototype_narrows_the_claim() {
    let report = first_prototype(&PrototypeConfig::standard(), &clock()).unwrap();
    let claim = &report.claim;
    for family in &report.families {
        println!(
            "{}: improvements after overhead {:?}, wins {}/{}",
            family.family,
            family.improvements(),
            family.wins(),
            family.instances.len()
        );
        for method in Method::ALL {
            println!(
                "  {} mean net {:.0}",
                method.label(),
                family.mean_net(method)
            );
        }
    }
    for study in &report.forecast {
        println!(
            "{} at error {}: mean improvement {:.0}, ece {:?}",
            study.comparison.family,
            study.comparison.relative_error,
            study.comparison.mean_improvement(),
            study.expected_calibration_error
        );
    }
    println!(
        "oracle: min ratio {:.4}, mean ratio {:.4}; decision {:?}; result {:?}",
        report.oracle.min_ratio(),
        report.oracle.mean_ratio(),
        claim.decision,
        claim.result
    );
    // The hand-built counterexample improves; enumeration is bounded; the optimum is
    // never beaten; every record is a fake-substrate record.
    assert!(claim.comparison.counterexample_improvement > 3_990.0);
    assert!(claim.comparison.enumeration_bounded);
    assert!(report.oracle.never_beaten());
    assert!(report
        .recorded
        .iter()
        .flat_map(|family| family.sides.iter())
        .all(|side| side.provenance.is_fake_substrate()));
    // The adversarial family does not keep its improvement after planner overhead, so the
    // computed decision narrows the claim.
    let adversarial = &claim.comparison.families[0];
    assert_eq!(adversarial.family, "adversarial");
    assert!(!adversarial.persists());
    assert!(claim.comparison.families[1].persists());
    assert_eq!(
        claim.decision,
        PassStop::Narrow(NarrowReason::NotInFamily {
            family: "adversarial"
        })
    );
    assert_eq!(claim.result, ClaimResult::Narrowed);
}
