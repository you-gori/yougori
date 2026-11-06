//! G05's prediction half on seeded synthetic traces: the predictors, the guard and its
//! fallback, the trace-replay evaluator against the exhaustive optimum, and the
//! predeclared acceptance rule. Every result is an offline evaluation on synthetic
//! traces.

use std::sync::Arc;
use std::time::Duration;

use super::replay::{replay_all, STANDARD_GUARD, STANDARD_RECENCY};
use super::traces::{adversarial_next, STANDARD_MARKOV};
use super::*;
use crate::foundation::coordination::LeaseState;
use crate::foundation::evidence::{HostSubject, SourceClass};
use crate::foundation::ids::{
    digest, Digest, ExecutionId, GpuDeviceKey, LeaseId, ManualClock, MonotonicTime, OperationId,
    TenantId,
};
use crate::foundation::ledger::{
    Amounts, CapacityDeclaration, Ledger, LedgerConfig, QueueLimits, ResourceKey,
};
use crate::foundation::report::{Label, Quantile, Resolution};
use crate::model_memory::bench::rng::SeededRng;
use crate::model_memory::bundles::baselines::CachePolicy;
use crate::model_memory::graph::node::DurationEstimate;
use crate::model_memory::math::calibration::DemandOnlyReason;
use crate::model_memory::math::prefetch::{CandidateOrigin, Objective};
use crate::model_memory::readiness::adoption::governor::{
    DeclaredStep, DeclineReason, GovernorConfig, PreparationGovernor, RollbackCause, StepOutcome,
    WorkflowIntent,
};
use crate::model_memory::readiness::adoption::observed::{Basis, EstimateReason, Labelled};
use crate::model_memory::readiness::intent::{PrepareBounds, PrepareTarget, PrepareWork};
use crate::model_memory::readiness::test_support::target;
use crate::model_memory::residency::retention::ObjectKind;

const GB: u64 = 1_000_000_000;
const SECOND: u64 = 1_000_000_000;

fn at(seconds: u64) -> MonotonicTime {
    MonotonicTime::from_nanos(seconds * SECOND)
}

fn keys(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| name.to_string()).collect()
}

fn markov() -> MarkovPredictor<String> {
    MarkovPredictor::new(STANDARD_MARKOV).unwrap()
}

fn settings() -> ReplaySettings {
    ReplaySettings::standard().unwrap()
}

fn guarded_markov(eviction: CachePolicy, guarding: Guarding) -> ReplayPolicy {
    ReplayPolicy::PredictionAssisted {
        eviction,
        predictor: PredictorKind::Markov(STANDARD_MARKOV),
        guard: STANDARD_GUARD,
        guarding,
    }
}

/// Six seeds of the standard specification of `kind`.
fn standard_traces(kind: TraceKind) -> Vec<ReplayTrace> {
    let spec = TraceSpec::standard(kind);
    (0..6).map(|seed| spec.generate(seed).unwrap()).collect()
}

fn model(key: &str, gb: u64, seconds: u64) -> CatalogObject {
    CatalogObject {
        key: key.to_string(),
        kind: ObjectKind::BaseWeights,
        bytes: gb * GB,
        load_nanos: seconds * SECOND,
        prerequisites: Vec::new(),
    }
}

fn adapter(key: &str, gb: u64, seconds: u64, base: &str) -> CatalogObject {
    CatalogObject {
        kind: ObjectKind::Adapter,
        prerequisites: vec![base.to_string()],
        ..model(key, gb, seconds)
    }
}

/// A hand-built trace: `requests` are (target, gap seconds, declared gap seconds).
fn hand_trace(
    arrivals: ArrivalMode,
    catalog: Vec<CatalogObject>,
    declared: &[&str],
    capacity_gb: u64,
    per_gap_gb: u64,
    requests: &[(&str, u64, u64)],
) -> ReplayTrace {
    let trace = ReplayTrace {
        kind: TraceKind::Mixed,
        seed: 0,
        arrivals,
        catalog,
        declared: keys(declared),
        budget: ReplayBudget {
            capacity_bytes: capacity_gb * GB,
            max_prepared_bytes_per_gap: per_gap_gb * GB,
        },
        requests: requests
            .iter()
            .map(|(target, gap, declared_gap)| TraceRequest {
                target: target.to_string(),
                gap: Duration::from_secs(*gap),
                declared_gap: Duration::from_secs(*declared_gap),
            })
            .collect(),
    };
    trace.check().unwrap();
    trace
}

// ---------------------------------------------------------------------------------------
// Predictors.

#[test]
fn markov_learns_transitions_and_its_uncertainty_shrinks_with_evidence() {
    let mut predictor = markov();
    let candidates = keys(&["a", "b", "c"]);
    let before = predictor.forecast(&candidates);
    assert!(before.iter().all(|forecast| forecast.observations == 0));
    assert!(before
        .iter()
        .all(|forecast| (forecast.probability - 1.0 / 3.0).abs() < 1e-12));
    let mut deviations = Vec::new();
    for _ in 0..20 {
        predictor.observe(&"a".to_string());
        predictor.observe(&"b".to_string());
        let forecast = predictor.forecast(&candidates);
        // After "b" the history says "a" comes next.
        assert_eq!(forecast[0].key, "a");
        deviations.push(forecast[0].std_dev);
    }
    let forecast = predictor.forecast(&candidates);
    assert_eq!(forecast[0].origin, CandidateOrigin::Markov);
    assert!(forecast[0].probability > 0.9, "{forecast:?}");
    assert!(forecast[1].probability < 0.05 && forecast[2].probability < 0.05);
    assert!(deviations.windows(2).all(|pair| pair[1] < pair[0]));
    assert!(forecast[0].lower_bound(1.0) < forecast[0].probability);
    assert_eq!(forecast[0].lower_bound(0.0), forecast[0].probability);
    assert_eq!(predictor.count(&"b".to_string(), &"a".to_string()), 19);
}

#[test]
fn markov_halving_follows_a_phase_change() {
    let config = MarkovConfig {
        halve_at: 16,
        ..STANDARD_MARKOV
    };
    let mut predictor = MarkovPredictor::new(config).unwrap();
    let candidates = keys(&["a", "b", "c"]);
    for _ in 0..100 {
        predictor.observe(&"a".to_string());
        predictor.observe(&"b".to_string());
    }
    let mut switched_after = None;
    for step in 0..40 {
        predictor.observe(&"a".to_string());
        let forecast = predictor.forecast(&candidates);
        let p = |key: &str| {
            forecast
                .iter()
                .find(|forecast| forecast.key == key)
                .unwrap()
                .probability
        };
        if p("c") > p("b") && switched_after.is_none() {
            switched_after = Some(step);
        }
        predictor.observe(&"c".to_string());
    }
    // Halving at 16 bounds the old evidence, so the new successor wins within a bounded
    // number of transitions.
    assert!(
        switched_after.is_some_and(|step| step <= 16),
        "{switched_after:?}"
    );
}

#[test]
fn recency_learns_reuse_ranks_and_follows_a_phase_change() {
    let config = RecencyConfig {
        depth: 4,
        window: 16,
        prior: 0.5,
    };
    let mut predictor = RecencyPredictor::new(config).unwrap();
    let candidates = keys(&["a", "b", "c"]);
    for _ in 0..16 {
        predictor.observe(&"a".to_string());
        predictor.observe(&"b".to_string());
    }
    // Alternation: the next request is the one at rank 1.
    let forecast = predictor.forecast(&candidates);
    assert_eq!(predictor.rank_of(&"a".to_string()), Some(1));
    let p = |forecast: &[Forecast<String>], key: &str| {
        forecast
            .iter()
            .find(|forecast| forecast.key == key)
            .unwrap()
            .probability
    };
    assert!(p(&forecast, "a") > 0.8, "{forecast:?}");
    assert_eq!(forecast[0].origin, CandidateOrigin::Recency);
    // "c" was never requested: it shares the unseen outcome.
    assert!(p(&forecast, "c") < 0.1);
    // A run of repeats replaces the window: rank 0 takes over.
    for _ in 0..16 {
        predictor.observe(&"b".to_string());
    }
    let forecast = predictor.forecast(&candidates);
    assert!(p(&forecast, "b") > 0.8, "{forecast:?}");
}

#[test]
fn predictors_forecast_only_their_candidates_within_bounded_memory() {
    let mut recency = RecencyPredictor::new(STANDARD_RECENCY).unwrap();
    let mut markov = markov();
    let mut rng = SeededRng::new(7);
    for _ in 0..5_000 {
        let key = format!("key-{}", rng.below(1_000));
        recency.observe(&key);
        markov.observe(&key);
    }
    assert!(
        recency.footprint() <= STANDARD_RECENCY.depth + STANDARD_RECENCY.window,
        "{}",
        recency.footprint()
    );
    assert!(markov.states() <= STANDARD_MARKOV.max_states);
    assert!(
        markov.footprint() <= STANDARD_MARKOV.max_states * (1 + STANDARD_MARKOV.max_successors) + 1
    );
    let candidates = keys(&["key-1", "key-2", "never-seen"]);
    for forecasts in [recency.forecast(&candidates), markov.forecast(&candidates)] {
        assert_eq!(
            forecasts
                .iter()
                .map(|forecast| forecast.key.clone())
                .collect::<Vec<_>>(),
            candidates
        );
        assert!(forecasts.iter().all(|forecast| {
            (0.0..=1.0).contains(&forecast.probability) && forecast.std_dev >= 0.0
        }));
        let total: f64 = forecasts.iter().map(|forecast| forecast.probability).sum();
        assert!(total <= 1.0 + 1e-9);
    }
}

#[test]
fn predictor_configurations_out_of_range_are_refused() {
    for config in [
        RecencyConfig {
            depth: 0,
            ..STANDARD_RECENCY
        },
        RecencyConfig {
            window: 0,
            ..STANDARD_RECENCY
        },
        RecencyConfig {
            prior: 0.0,
            ..STANDARD_RECENCY
        },
    ] {
        assert!(matches!(
            RecencyPredictor::<String>::new(config),
            Err(PredictionError::InvalidConfig { .. })
        ));
    }
    for config in [
        MarkovConfig {
            max_states: 0,
            ..STANDARD_MARKOV
        },
        MarkovConfig {
            max_successors: 100_000,
            ..STANDARD_MARKOV
        },
        MarkovConfig {
            halve_at: 1,
            ..STANDARD_MARKOV
        },
        MarkovConfig {
            prior: f64::NAN,
            ..STANDARD_MARKOV
        },
    ] {
        assert!(matches!(
            MarkovPredictor::<String>::new(config),
            Err(PredictionError::InvalidConfig { .. })
        ));
    }
    for config in [
        GuardConfig {
            window_steps: 0,
            ..STANDARD_GUARD
        },
        GuardConfig {
            min_scored_steps: STANDARD_GUARD.window_steps + 1,
            ..STANDARD_GUARD
        },
    ] {
        assert!(matches!(
            GuardedPredictor::new(markov(), config),
            Err(PredictionError::InvalidConfig { .. })
        ));
    }
}

// ---------------------------------------------------------------------------------------
// The guard.

/// Ranks `candidates`, then observes `actual` one second later.
fn step(
    guard: &mut GuardedPredictor<String, MarkovPredictor<String>>,
    candidates: &[String],
    actual: &str,
    clock: &mut u64,
) -> Ranking<String> {
    let ranking = guard.rank(candidates);
    *clock += 1;
    guard.observe(&actual.to_string(), at(*clock), 0.0).unwrap();
    ranking
}

#[test]
fn demand_only_is_the_default_and_the_operator_rollback_stays_available() {
    let mut guard = GuardedPredictor::new(markov(), STANDARD_GUARD).unwrap();
    let candidates = keys(&["a", "b"]);
    let mut clock = 0;
    assert_eq!(
        guard.mode(),
        PredictorMode::Baseline {
            cause: BaselineCause::RolledBack(RollbackCause::Default)
        }
    );
    // Never enabled: forecasts are scored in the shadow and never actionable.
    for index in 0..20 {
        let ranking = step(
            &mut guard,
            &candidates,
            if index % 2 == 0 { "a" } else { "b" },
            &mut clock,
        );
        assert!(ranking.actionable().is_empty());
    }
    assert_eq!(guard.scored_steps(), 20);
    guard.enable();
    assert_eq!(guard.mode(), PredictorMode::Assisting);
    let ranking = step(&mut guard, &candidates, "a", &mut clock);
    assert_eq!(ranking.actionable().len(), 2);
    // The last request was "b": "a" is ranked first.
    assert_eq!(ranking.actionable()[0].key, "a");
    guard.roll_back();
    assert_eq!(
        guard.mode(),
        PredictorMode::Baseline {
            cause: BaselineCause::RolledBack(RollbackCause::Operator)
        }
    );
    assert!(guard.rank(&candidates).actionable().is_empty());
    guard.enable();
    assert_eq!(guard.mode(), PredictorMode::Assisting);

    // A fresh guard warms up before acting.
    let mut fresh = GuardedPredictor::new(markov(), STANDARD_GUARD).unwrap();
    fresh.enable();
    let ranking = step(&mut fresh, &candidates, "a", &mut clock);
    assert!(matches!(
        ranking.mode,
        PredictorMode::Baseline {
            cause: BaselineCause::WarmingUp {
                scored: 0,
                needed: 8
            }
        }
    ));
}

#[test]
fn a_ranking_orders_only_its_candidates() {
    let mut guard = GuardedPredictor::new(markov(), STANDARD_GUARD).unwrap();
    let mut clock = 0;
    for _ in 0..10 {
        step(&mut guard, &keys(&["a", "b", "c"]), "a", &mut clock);
        step(&mut guard, &keys(&["a", "b", "c"]), "c", &mut clock);
    }
    guard.enable();
    // "b" is offered twice and counts once; "c", the likeliest after "c"... is not offered.
    let ranking = guard.rank(&keys(&["b", "a", "b"]));
    let ranked: Vec<&str> = ranking
        .forecasts
        .iter()
        .map(|forecast| forecast.key.as_str())
        .collect();
    assert_eq!(ranked, vec!["a", "b"]);
    assert!(ranking
        .forecasts
        .windows(2)
        .all(|pair| pair[0].probability >= pair[1].probability));
}

#[test]
fn a_hostile_sequence_falls_back_and_calibration_recovers_with_hysteresis() {
    let mut guard = GuardedPredictor::new(markov(), STANDARD_GUARD).unwrap();
    guard.enable();
    let declared = keys(&["a", "b", "c", "d"]);
    let mut clock = 0;
    // Learn a cycle; the guard assists once warm.
    for index in 0..40 {
        step(&mut guard, &declared, &declared[index % 4], &mut clock);
    }
    assert_eq!(guard.mode(), PredictorMode::Assisting);
    assert!(guard.recent_top_hit_rate().unwrap() > 0.9);
    // Hostile alternation: never the predictor's top forecast.
    let mut rng = SeededRng::new(3);
    let mut adversary = markov();
    for index in 0..40 {
        adversary.observe(&declared[index % 4]);
    }
    let mut fell_back_after = None;
    for index in 0..40 {
        let next = adversarial_next(&adversary, &declared, &mut rng).unwrap();
        adversary.observe(&next);
        let ranking = step(&mut guard, &declared, &next, &mut clock);
        assert_ne!(ranking.forecasts[0].key, next);
        if fell_back_after.is_none() && guard.mode() != PredictorMode::Assisting {
            fell_back_after = Some(index);
        }
    }
    let fell_back_after = fell_back_after.unwrap();
    assert!(
        fell_back_after < STANDARD_GUARD.window_steps,
        "{fell_back_after}"
    );
    assert!(matches!(
        guard.mode(),
        PredictorMode::Baseline {
            cause: BaselineCause::RolledBack(RollbackCause::Controller {
                reason: DemandOnlyReason::LowConfidence | DemandOnlyReason::Drift
            })
        }
    ));
    assert_eq!(guard.fallbacks(), 1);
    // A predictable phase again: recovery needs the stricter exit thresholds held for
    // the dwell (60 s here at one request per second), not one good request.
    let mut recovered_after = None;
    for index in 0..200 {
        step(&mut guard, &declared, &declared[index % 4], &mut clock);
        if recovered_after.is_none() && guard.mode() == PredictorMode::Assisting {
            recovered_after = Some(index);
        }
    }
    let recovered_after = recovered_after.unwrap();
    assert!(recovered_after >= 60, "{recovered_after}");
    assert_eq!(guard.fallbacks(), 1);
    assert!(guard.footprint() <= 64 * 17 + 1 + 16 + 4);
}

fn governor_target(name: &str) -> PrepareTarget {
    target(name)
}

fn test_digest(part: &str) -> Digest {
    digest("yougori/test/prediction/v1", &[part.as_bytes()])
}

fn gpu() -> GpuDeviceKey {
    GpuDeviceKey {
        machine: test_digest("workstation"),
        device: test_digest("gpu-0"),
    }
}

fn tenant() -> TenantId {
    TenantId::new("tenant-a").unwrap()
}

fn workflow() -> ExecutionId {
    ExecutionId::new("exe-workflow").unwrap()
}

fn ledger(clock: &Arc<ManualClock>) -> Ledger<Arc<ManualClock>> {
    let mut ledger = Ledger::new(
        Arc::clone(clock),
        HostSubject {
            machine: test_digest("workstation"),
        },
        LedgerConfig {
            queue: QueueLimits {
                max_entries: 16,
                max_entries_per_tenant: 16,
                max_wait: Duration::from_secs(600),
            },
            grant_ttl: Duration::from_secs(600),
            unmanaged_usage_max_age: Duration::from_secs(3_600),
        },
    );
    ledger
        .declare_capacity(
            ResourceKey::vram(gpu()),
            CapacityDeclaration {
                total: 80 * GB,
                supervisor_reserve: 0,
                unmanaged_in_use: 0,
                source: SourceClass::HostProbe,
            },
        )
        .unwrap();
    ledger
        .set_tenant_budget(tenant(), ResourceKey::vram(gpu()), u64::MAX)
        .unwrap();
    ledger
}

fn declared_step(name: &str, model: &str, probability: f64) -> DeclaredStep {
    DeclaredStep {
        operation: OperationId::new(format!("op-{name}")).unwrap(),
        target: governor_target(model),
        deadline: at(300),
        retention_ttl: Duration::from_secs(60),
        work: vec![PrepareWork::Step {
            step: crate::model_memory::boundaries::PreparationStep::InboundTransfer,
        }],
        assigned_request: None,
        lease: LeaseId::new(7),
        probability,
        cost: Labelled {
            value: DurationEstimate::new(
                Duration::from_secs(4),
                Duration::from_secs(5),
                Duration::from_secs(8),
            )
            .unwrap(),
            basis: Basis::Estimated {
                source: Label::new("catalog-bytes-over-nominal-bandwidth").unwrap(),
                reason: EstimateReason::NoObservations,
            },
        },
        demand: Amounts::new().vram_bytes(gpu(), 8 * GB),
        prerequisites: Vec::new(),
    }
}

fn operations(intent: &WorkflowIntent) -> Vec<String> {
    intent
        .steps
        .iter()
        .map(|step| step.operation.as_str().to_string())
        .collect()
}

#[test]
fn declared_branches_are_ranked_inside_the_governors_gates() {
    let mut guard = GuardedPredictor::new(
        MarkovPredictor::<PrepareTarget>::new(STANDARD_MARKOV).unwrap(),
        STANDARD_GUARD,
    )
    .unwrap();
    let (planner, coder, reviewer) = (
        governor_target("planner"),
        governor_target("coder"),
        governor_target("reviewer"),
    );
    // History: after the planner, the reviewer usually follows.
    let mut clock = 0;
    for _ in 0..12 {
        guard.rank(&[planner, coder, reviewer]);
        clock += 1;
        guard.observe(&planner, at(clock), 0.0).unwrap();
        guard.rank(&[planner, coder, reviewer]);
        clock += 1;
        guard.observe(&reviewer, at(clock), 0.0).unwrap();
    }
    guard.rank(&[planner, coder, reviewer]);
    clock += 1;
    guard.observe(&planner, at(clock), 0.0).unwrap();
    let intent = || WorkflowIntent {
        execution: workflow(),
        tenant: tenant(),
        steps: vec![
            declared_step("tool-result", "planner", 1.0),
            declared_step("branch-coder", "coder", 0.5),
            declared_step("branch-reviewer", "reviewer", 0.5),
        ],
    };
    // Not enabled: the declared order stays.
    let (unranked, ranking) = rank_declared_steps(&mut guard, intent());
    assert!(ranking.actionable().is_empty());
    assert_eq!(operations(&unranked), operations(&intent()));
    // Enabled: the certain step stays first, the likelier branch moves ahead, nothing is
    // added, dropped or changed.
    guard.enable();
    let (ranked, ranking) = rank_declared_steps(&mut guard, intent());
    assert_eq!(ranking.mode, PredictorMode::Assisting);
    assert_eq!(
        operations(&ranked),
        vec!["op-tool-result", "op-branch-reviewer", "op-branch-coder"]
    );
    let mut sorted_before = intent().steps;
    let mut sorted_after = ranked.steps.clone();
    sorted_before.sort_by(|a, b| a.operation.cmp(&b.operation));
    sorted_after.sort_by(|a, b| a.operation.cmp(&b.operation));
    assert_eq!(sorted_before, sorted_after);

    // The governor still applies its own gates: with a lookahead of two, the ranked
    // branch is admitted and the other is left beyond the lookahead.
    let clock = Arc::new(ManualClock::new(at(10)));
    let mut ledger = ledger(&clock);
    let mut governor = PreparationGovernor::new(GovernorConfig {
        execution: ExecutionId::new("exe-placement-governor").unwrap(),
        prepare: PrepareBounds {
            max_lead: Duration::from_secs(900),
            max_retention_ttl: Duration::from_secs(120),
        },
        max_active: 4,
        max_lookahead: 2,
        max_speculative_bytes: 30 * GB,
        max_outcomes: 32,
        promotion_wait: Duration::from_secs(60),
        objective: Objective::new(1.0, 1e-9, 0.0, 0.0).unwrap(),
    })
    .unwrap();
    governor.enable_workflow_intent();
    let active = |_: LeaseId| Some(LeaseState::Active);
    let report = governor.declare(ranked, &mut ledger, &active, clock.as_ref());
    let outcome = |operation: &str| {
        report
            .steps
            .iter()
            .find(|decision| decision.operation.as_str() == operation)
            .map(|decision| decision.outcome.clone())
            .unwrap()
    };
    assert!(matches!(
        outcome("op-tool-result"),
        StepOutcome::Admitted { .. }
    ));
    assert!(matches!(
        outcome("op-branch-reviewer"),
        StepOutcome::Admitted { .. }
    ));
    assert_eq!(
        outcome("op-branch-coder"),
        StepOutcome::Declined {
            reason: DeclineReason::BeyondLookahead
        }
    );
}

// ---------------------------------------------------------------------------------------
// Traces.

#[test]
fn traces_are_seeded_and_keep_their_declarations() {
    for kind in TraceKind::ALL {
        for spec in [TraceSpec::standard(kind), TraceSpec::tiny(kind)] {
            let first = spec.generate(11).unwrap();
            assert_eq!(first, spec.generate(11).unwrap());
            assert_ne!(first.requests, spec.generate(12).unwrap().requests);
            assert_eq!(first.requests.len(), spec.requests);
            assert!(first
                .requests
                .iter()
                .all(|request| request.declared_gap <= request.gap));
        }
    }
    let alternating = TraceSpec::standard(TraceKind::Alternating)
        .generate(0)
        .unwrap();
    assert!(alternating
        .requests
        .windows(2)
        .all(|pair| pair[0].target != pair[1].target));
    let mixed = TraceSpec::standard(TraceKind::Mixed).generate(0).unwrap();
    assert!(mixed
        .catalog
        .iter()
        .any(|object| object.kind == ObjectKind::Adapter));
    assert_eq!(
        mixed.closure("adapter-0").unwrap(),
        keys(&["base", "adapter-0"])
    );
    // The adversarial trace defeats the Markov predictor it was built against.
    let adversarial = TraceSpec::standard(TraceKind::AdversarialToMarkov)
        .generate(0)
        .unwrap();
    let mut guard = GuardedPredictor::new(markov(), STANDARD_GUARD).unwrap();
    let mut clock = 0;
    for request in &adversarial.requests {
        let ranking = guard.rank(&adversarial.declared);
        clock += 1;
        guard.observe(&request.target, at(clock), 0.0).unwrap();
        if guard.scored_steps() > 1 {
            assert_ne!(ranking.forecasts[0].key, request.target);
        }
    }
    assert_eq!(guard.recent_top_hit_rate(), Some(0.0));
    // A malformed trace is refused.
    let mut broken = mixed.clone();
    broken.requests[1].declared_gap = broken.requests[1].gap + Duration::from_secs(1);
    assert!(broken.check().is_err());
    let mut cyclic = mixed;
    cyclic.catalog.iter_mut().for_each(|object| {
        if object.key == "base" {
            object.prerequisites = vec!["adapter-0".to_string()];
        }
    });
    assert!(cyclic.check().is_err());
}

// ---------------------------------------------------------------------------------------
// The replay and the exhaustive optimum.

#[test]
fn the_optimum_matches_hand_computed_schedules() {
    let two = || vec![model("a", 2, 2), model("b", 2, 2)];
    // Closed loop, one model fits, gaps long enough to prepare: only the first misses.
    let roomy = hand_trace(
        ArrivalMode::Closed,
        two(),
        &["a", "b"],
        2,
        2,
        &[("a", 0, 0), ("b", 3, 3), ("a", 3, 3)],
    );
    let optimal = optimal_schedule(&roomy, ExhaustiveBounds::TINY).unwrap();
    assert_eq!(optimal.waits, vec![2 * SECOND, 0, 0]);
    assert_eq!(
        optimal.prepared_before,
        vec![vec![], keys(&["b"]), keys(&["a"])]
    );
    assert_eq!(
        optimal.resident_after,
        vec![keys(&["a"]), keys(&["b"]), keys(&["a"])]
    );
    assert_eq!(optimal.hits, 2);
    assert_eq!(optimal.prepared_bytes, 4 * GB);
    // Declared gaps too short to prepare: every request loads on demand.
    let tight = hand_trace(
        ArrivalMode::Closed,
        two(),
        &["a", "b"],
        2,
        2,
        &[("a", 0, 0), ("b", 3, 1), ("a", 3, 1)],
    );
    assert_eq!(
        optimal_schedule(&tight, ExhaustiveBounds::TINY)
            .unwrap()
            .total_wait_nanos,
        6 * SECOND
    );
    // Open loop: the second request queues behind the first one's load.
    let queued = hand_trace(
        ArrivalMode::Open,
        two(),
        &["a", "b"],
        4,
        2,
        &[("a", 0, 0), ("b", 1, 1)],
    );
    let optimal = optimal_schedule(&queued, ExhaustiveBounds::TINY).unwrap();
    assert_eq!(optimal.waits, vec![2 * SECOND, 3 * SECOND]);
    let lru = replay(
        &queued,
        &ReplayPolicy::DemandOnly {
            eviction: CachePolicy::Lru,
        },
        &settings(),
    )
    .unwrap();
    assert_eq!(lru.metrics.waits, optimal.waits);
    // A shared base: the gap's byte budget decides whether the base and its adapter, or
    // only the base, can be prepared.
    let shared = |per_gap_gb| {
        hand_trace(
            ArrivalMode::Closed,
            vec![
                model("base", 4, 4),
                adapter("a1", 1, 1, "base"),
                adapter("a2", 1, 1, "base"),
                model("m", 4, 4),
            ],
            &["a1", "a2", "m"],
            6,
            per_gap_gb,
            &[("a1", 0, 0), ("m", 10, 10), ("a2", 10, 10)],
        )
    };
    let roomy = optimal_schedule(&shared(8), ExhaustiveBounds::TINY).unwrap();
    assert_eq!(roomy.waits, vec![5 * SECOND, 0, 0]);
    assert_eq!(roomy.prepared_before[2], keys(&["base", "a2"]));
    let narrow = optimal_schedule(&shared(4), ExhaustiveBounds::TINY).unwrap();
    assert_eq!(narrow.waits, vec![5 * SECOND, 0, SECOND]);
    assert_eq!(narrow.prepared_before[2], keys(&["base"]));
}

#[test]
fn the_optimum_refuses_traces_beyond_its_bounds() {
    let standard = TraceSpec::standard(TraceKind::Mixed).generate(0).unwrap();
    assert!(matches!(
        optimal_schedule(&standard, ExhaustiveBounds::TINY),
        Err(PredictionError::TooLargeForExhaustive { .. })
    ));
    let tiny = TraceSpec::tiny(TraceKind::Mixed).generate(0).unwrap();
    assert!(matches!(
        optimal_schedule(
            &tiny,
            ExhaustiveBounds {
                max_states: 3,
                ..ExhaustiveBounds::TINY
            }
        ),
        Err(PredictionError::SearchBoundExceeded { .. })
    ));
}

fn all_policies() -> Vec<ReplayPolicy> {
    let mut policies = ReplayPolicy::standard_set();
    policies.push(guarded_markov(CachePolicy::Lru, Guarding::Unguarded));
    policies.push(ReplayPolicy::PredictionAssisted {
        eviction: CachePolicy::CostPerByte,
        predictor: PredictorKind::Recency(STANDARD_RECENCY),
        guard: STANDARD_GUARD,
        guarding: Guarding::Unguarded,
    });
    policies
}

#[test]
fn the_optimum_is_a_lower_bound_and_prediction_never_beats_it() {
    let policies = all_policies();
    let mut strictly_below = 0;
    for kind in TraceKind::ALL {
        let spec = TraceSpec::tiny(kind);
        for seed in 0..8 {
            let trace = spec.generate(seed).unwrap();
            let optimal = optimal_schedule(&trace, ExhaustiveBounds::TINY).unwrap();
            assert_eq!(optimal.label, EvaluationLabel::OfflineSyntheticTraces);
            assert_eq!(optimal.budget, trace.budget);
            assert_eq!(optimal.waits.iter().sum::<u64>(), optimal.total_wait_nanos);
            let reports = replay_all(std::slice::from_ref(&trace), &policies, &settings()).unwrap();
            for report in &reports {
                assert_eq!(report.budget, optimal.budget);
                assert!(
                    optimal.total_wait_nanos <= report.metrics.total_wait_nanos,
                    "{} seed {seed}: optimal {} > {} {}",
                    kind.slug(),
                    optimal.total_wait_nanos,
                    report.policy.label(),
                    report.metrics.total_wait_nanos
                );
            }
            let best = reports
                .iter()
                .map(|report| report.metrics.total_wait_nanos)
                .min()
                .unwrap();
            if optimal.total_wait_nanos < best {
                strictly_below += 1;
            }
        }
    }
    // The bound is not vacuous: on some tiny traces no policy reaches it.
    assert!(strictly_below > 0);
}

#[test]
fn every_policy_replays_each_trace_under_the_same_budget() {
    let policies = all_policies();
    for kind in TraceKind::ALL {
        let trace = TraceSpec::standard(kind).generate(1).unwrap();
        let reports = replay_all(std::slice::from_ref(&trace), &policies, &settings()).unwrap();
        assert_eq!(reports.len(), policies.len());
        for report in &reports {
            let metrics = &report.metrics;
            assert_eq!(report.label, EvaluationLabel::OfflineSyntheticTraces);
            assert!(!report.label.is_hardware_validation());
            assert_eq!(report.budget, trace.budget);
            assert!(metrics.peak_resident_bytes <= trace.budget.capacity_bytes);
            assert!(metrics.peak_prepared_bytes_in_gap <= trace.budget.max_prepared_bytes_per_gap);
            // Every prepared byte is either used or wasted.
            assert_eq!(
                metrics.prepared_bytes,
                metrics.used_prepared_bytes + metrics.wasted_bytes
            );
            assert_eq!(metrics.requests, trace.requests.len() as u64);
            assert_eq!(metrics.waits.iter().sum::<u64>(), metrics.total_wait_nanos);
            assert!(metrics.hits <= metrics.requests && metrics.prepared_hits <= metrics.hits);
            let longest = *metrics.waits.iter().max().unwrap() as f64;
            assert!(metrics.p50_wait_nanos <= metrics.p95_wait_nanos);
            assert!(metrics.p95_wait_nanos <= metrics.p99_wait_nanos);
            assert!(metrics.p99_wait_nanos <= longest);
            match report.policy {
                ReplayPolicy::DemandOnly { .. } => {
                    assert_eq!(metrics.prepared_bytes, 0);
                    assert_eq!(metrics.wasted_bytes, 0);
                    assert!(report.calibration.is_none() && report.guard.is_none());
                }
                ReplayPolicy::PredictionAssisted { .. } => {
                    let calibration = report.calibration.as_ref().unwrap();
                    let brier = calibration.brier_score.unwrap();
                    assert!((0.0..=1.0).contains(&brier));
                    assert_eq!(
                        calibration.bins.iter().map(|bin| bin.count).sum::<u64>(),
                        calibration.forecasts
                    );
                    // One ranking per request but the last, over every declared target.
                    assert_eq!(
                        calibration.forecasts,
                        (trace.requests.len() as u64 - 1) * trace.declared.len() as u64
                    );
                    let guard = report.guard.as_ref().unwrap();
                    assert_eq!(
                        guard.assisting_gaps + guard.shadow_gaps,
                        trace.requests.len() as u64
                    );
                }
            }
        }
        // Deterministic: the same trace and policy replay identically.
        assert_eq!(
            reports[4],
            replay(&trace, &policies[4], &settings()).unwrap()
        );
    }
}

#[test]
fn adversarial_traces_trigger_the_fallback_before_anything_is_wasted() {
    let traces = standard_traces(TraceKind::AdversarialToMarkov);
    let guarded = guarded_markov(CachePolicy::Lru, Guarding::Guarded);
    let unguarded = guarded_markov(CachePolicy::Lru, Guarding::Unguarded);
    let demand = guarded.matched_baseline();
    let mut unguarded_wasted = 0;
    for trace in &traces {
        let own = replay(trace, &guarded, &settings()).unwrap();
        let guard = own.guard.as_ref().unwrap();
        // Warm-up ends at the eighth scored request, where the controller falls back.
        assert_eq!(
            guard.first_fallback_at,
            Some(STANDARD_GUARD.min_scored_steps)
        );
        assert_eq!(guard.fallbacks, 1);
        assert_eq!(guard.assisting_gaps, 0);
        assert!(matches!(
            guard.final_mode,
            PredictorMode::Baseline {
                cause: BaselineCause::RolledBack(RollbackCause::Controller { .. })
            }
        ));
        assert_eq!(own.metrics.prepared_bytes, 0);
        assert_eq!(own.metrics.wasted_bytes, 0);
        let baseline = replay(trace, &demand, &settings()).unwrap();
        assert_eq!(own.metrics.waits, baseline.metrics.waits);
        let ablation = replay(trace, &unguarded, &settings()).unwrap();
        unguarded_wasted += ablation.metrics.wasted_bytes;
    }
    // Without the guard the same predictor wastes bytes on the same traces.
    assert!(unguarded_wasted > 0);
}

#[test]
fn a_phase_change_falls_back_with_bounded_waste() {
    // A scan the Markov predictor learns, then a continuation hostile to it (GPU-T37).
    let mut trace = TraceSpec {
        requests: 64,
        ..TraceSpec::standard(TraceKind::Scan)
    }
    .generate(5)
    .unwrap();
    let mut adversary = markov();
    for request in &trace.requests {
        adversary.observe(&request.target);
    }
    let mut rng = SeededRng::new(5);
    for index in 0..64 {
        let next = adversarial_next(&adversary, &trace.declared, &mut rng).unwrap();
        adversary.observe(&next);
        trace.requests.push(TraceRequest {
            target: next,
            gap: Duration::from_secs(12 + index % 7),
            declared_gap: Duration::from_secs(12),
        });
    }
    trace.check().unwrap();
    let guarded = replay(
        &trace,
        &guarded_markov(CachePolicy::Lru, Guarding::Guarded),
        &settings(),
    )
    .unwrap();
    let unguarded = replay(
        &trace,
        &guarded_markov(CachePolicy::Lru, Guarding::Unguarded),
        &settings(),
    )
    .unwrap();
    let guard = guarded.guard.as_ref().unwrap();
    let change = 64;
    let fell_back = guard.first_fallback_at.unwrap();
    assert!(
        (change..change + STANDARD_GUARD.window_steps).contains(&fell_back),
        "{fell_back}"
    );
    // Waste is bounded by what the guard can prepare before its window turns.
    let bound = STANDARD_GUARD.window_steps as u64 * trace.budget.max_prepared_bytes_per_gap;
    assert!(
        guarded.metrics.wasted_bytes <= bound,
        "{}",
        guarded.metrics.wasted_bytes
    );
    assert!(unguarded.metrics.wasted_bytes > guarded.metrics.wasted_bytes);
    assert!(guarded.metrics.total_wait_nanos <= unguarded.metrics.total_wait_nanos);
}

#[test]
fn calibration_is_reported_and_tells_the_patterns_apart() {
    let policy = guarded_markov(CachePolicy::Lru, Guarding::Guarded);
    let brier = |kind| {
        let trace = TraceSpec::standard(kind).generate(2).unwrap();
        let report = replay(&trace, &policy, &settings()).unwrap();
        let calibration = report.calibration.unwrap();
        assert!(!calibration.bins.is_empty());
        assert!(calibration.expected_calibration_error.is_some());
        calibration.brier_score.unwrap()
    };
    let alternating = brier(TraceKind::Alternating);
    let mixed = brier(TraceKind::Mixed);
    let adversarial = brier(TraceKind::AdversarialToMarkov);
    assert!(alternating < 0.05, "{alternating}");
    assert!(
        alternating < mixed && mixed < adversarial,
        "{mixed} {adversarial}"
    );
}

// ---------------------------------------------------------------------------------------
// The predeclared acceptance rule.

fn reports_of(traces: &[ReplayTrace], policy: &ReplayPolicy) -> Vec<ReplayReport> {
    traces
        .iter()
        .map(|trace| replay(trace, policy, &settings()).unwrap())
        .collect()
}

#[test]
fn the_predeclared_rule_judges_the_synthetic_set() {
    let traces: Vec<ReplayTrace> = TraceKind::ALL
        .into_iter()
        .flat_map(standard_traces)
        .collect();
    let judge_policy = |policy: ReplayPolicy| {
        judge(
            &AcceptanceRule::PREDECLARED,
            &reports_of(&traces, &policy),
            &reports_of(&traces, &policy.matched_baseline()),
        )
        .unwrap()
    };
    let markov = judge_policy(guarded_markov(CachePolicy::Lru, Guarding::Guarded));
    assert_eq!(markov.label, EvaluationLabel::OfflineSyntheticTraces);
    assert_eq!(
        markov.acceptance,
        Acceptance::Accepted,
        "{:#?}",
        markov.patterns
    );
    assert_eq!(markov.patterns.len(), TraceKind::ALL.len());
    for pattern in &markov.patterns {
        assert_eq!(pattern.seeds, 6);
        assert_eq!(pattern.p95.resolution, Resolution::Resolved);
        assert_eq!(pattern.p99.resolution, Resolution::Resolved);
        assert_ne!(pattern.verdict, PatternVerdict::Regresses);
        assert!(pattern.candidate_brier_score.is_some());
    }
    let verdict = |report: &AcceptanceReport, kind| {
        report
            .patterns
            .iter()
            .find(|pattern| pattern.kind == kind)
            .unwrap()
            .clone()
    };
    // The alternating and scan gains are large, but they are not what is accepted on.
    let alternating = verdict(&markov, TraceKind::Alternating);
    assert_eq!(alternating.verdict, PatternVerdict::Improves);
    assert!(alternating.candidate_total_wait_nanos * 10 < alternating.baseline_total_wait_nanos);
    // Mixed: fewer total waits at a reported cost in wasted bytes; tails match.
    let mixed = verdict(&markov, TraceKind::Mixed);
    assert!(mixed.candidate_total_wait_nanos < mixed.baseline_total_wait_nanos);
    assert!(mixed.candidate_wasted_bytes > 0);
    assert!(mixed.candidate_wasted_bytes < mixed.candidate_prepared_bytes);
    // Adversarial: the guard falls back before acting, so it matches exactly.
    let adversarial = verdict(&markov, TraceKind::AdversarialToMarkov);
    assert_eq!(adversarial.verdict, PatternVerdict::Matches);
    assert_eq!(
        adversarial.candidate_total_wait_nanos,
        adversarial.baseline_total_wait_nanos
    );
    assert_eq!(adversarial.candidate_wasted_bytes, 0);
    // The other assisted policies of the standard set are judged by the same rule.
    for policy in [
        ReplayPolicy::PredictionAssisted {
            eviction: CachePolicy::Lru,
            predictor: PredictorKind::Recency(STANDARD_RECENCY),
            guard: STANDARD_GUARD,
            guarding: Guarding::Guarded,
        },
        guarded_markov(CachePolicy::GreedyDualSize, Guarding::Guarded),
    ] {
        let report = judge_policy(policy);
        assert_eq!(
            report.acceptance,
            Acceptance::Accepted,
            "{:#?}",
            report.patterns
        );
    }
}

#[test]
fn alternating_results_alone_are_never_accepted() {
    let traces = standard_traces(TraceKind::Alternating);
    let policy = guarded_markov(CachePolicy::Lru, Guarding::Guarded);
    let report = judge(
        &AcceptanceRule::PREDECLARED,
        &reports_of(&traces, &policy),
        &reports_of(&traces, &policy.matched_baseline()),
    )
    .unwrap();
    // The alternating gain is real, and still not enough.
    assert_eq!(report.patterns[0].verdict, PatternVerdict::Improves);
    let Acceptance::NotAccepted { reasons } = report.acceptance else {
        panic!("accepted on alternating traces alone");
    };
    assert!(reasons.contains(&NotAcceptedReason::AlternatingOnly));
    assert!(reasons.contains(&NotAcceptedReason::MissingPattern {
        kind: TraceKind::Mixed
    }));
    assert!(reasons.contains(&NotAcceptedReason::MissingPattern {
        kind: TraceKind::AdversarialToMarkov
    }));
}

#[test]
fn the_judgement_refuses_unmatched_thin_or_regressed_evidence() {
    let policy = guarded_markov(CachePolicy::Lru, Guarding::Guarded);
    let baseline = policy.matched_baseline();
    let mut traces = standard_traces(TraceKind::Mixed);
    traces.extend(standard_traces(TraceKind::AdversarialToMarkov));
    let candidate = reports_of(&traces, &policy);
    let matched = reports_of(&traces, &baseline);
    // Another baseline than the declared one is refused outright.
    assert!(matches!(
        judge(
            &AcceptanceRule::PREDECLARED,
            &candidate,
            &reports_of(
                &traces,
                &ReplayPolicy::DemandOnly {
                    eviction: CachePolicy::CostPerByte
                }
            ),
        ),
        Err(PredictionError::InvalidConfig { .. })
    ));
    // Unequal budgets.
    let mut unequal = matched.clone();
    unequal[0].budget.capacity_bytes += GB;
    let report = judge(&AcceptanceRule::PREDECLARED, &candidate, &unequal).unwrap();
    assert!(matches!(
        report.acceptance,
        Acceptance::NotAccepted { ref reasons }
            if reasons.contains(&NotAcceptedReason::Unmatched {
                kind: TraceKind::Mixed,
                seed: 0
            })
    ));
    // Too few seeds, and percentiles without resolution.
    let thin: Vec<ReplayReport> = candidate
        .iter()
        .filter(|report| report.seed < 2)
        .cloned()
        .collect();
    let thin_baseline: Vec<ReplayReport> = matched
        .iter()
        .filter(|report| report.seed < 2)
        .cloned()
        .collect();
    let report = judge(&AcceptanceRule::PREDECLARED, &thin, &thin_baseline).unwrap();
    let Acceptance::NotAccepted { reasons } = report.acceptance else {
        panic!("accepted on two seeds");
    };
    assert!(reasons.contains(&NotAcceptedReason::TooFewSeeds {
        kind: TraceKind::Mixed,
        seeds: 2,
        needed: 6
    }));
    assert!(reasons.contains(&NotAcceptedReason::LowResolution {
        kind: TraceKind::Mixed,
        quantile: Quantile::P99
    }));
    // A regressed tail.
    let mut regressed = candidate.clone();
    for report in regressed
        .iter_mut()
        .filter(|report| report.kind == TraceKind::Mixed)
    {
        for wait in report.metrics.waits.iter_mut().step_by(10) {
            *wait += 30 * SECOND;
        }
    }
    let report = judge(&AcceptanceRule::PREDECLARED, &regressed, &matched).unwrap();
    let Acceptance::NotAccepted { reasons } = report.acceptance else {
        panic!("accepted a regressed tail");
    };
    assert!(reasons.iter().any(|reason| matches!(
        reason,
        NotAcceptedReason::Regressed {
            kind: TraceKind::Mixed,
            quantile,
            ..
        } if *quantile == Quantile::P99
    )));
}
