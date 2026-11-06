//! The GPU-N1 first prototype (GPU §4.14 lines 834–836): a CPU-only trace simulation
//! comparing object-greedy, LRU, cost-per-byte, the dependency-aware caching baselines
//! and the bundle method under equal memory and planner budgets, on the counterexample,
//! adversarial and shared-base workloads; planner overhead charged; seeded forecast
//! errors; the enumeration bound; tiny exhaustive optima; the pass/stop rule; the GPU
//! §4.17 claim record; and CORE-08 records on the fake substrate.
//!
//! Every run here is a simulation. Its records carry [`RunSubstrate::FakeTimeControlled`],
//! so [`Provenance::of_records`] gives them the fake-substrate provenance: they validate
//! the schema and the comparison discipline and back no performance, improvement or
//! release claim.

use std::ops::Range;
use std::time::Duration;

use crate::foundation::ids::{digest, Clock, ExecutionId, ManualClock, MonotonicTime, OperationId};
use crate::foundation::report::{
    ArrivalMode, AttemptIdentity, AttemptLedger, AttemptRole, Baseline, BenchId, BuildIdentity,
    ClientDescription, ClientPlacement, ClockId, ComparisonReport, ComparisonSide, CpuDescription,
    EffectClass, EngineIdentity, EventKind, EventRecorder, ExperimentDesign, HostDescription,
    IntervalKind, Label, LatencyObjective, LatencySummary, LaunchDescription, LoadDescription,
    MatchedConfiguration, Measured, ModeFidelity, NonNegative, NotMeasuredReason,
    Objective as ReportObjective, ObjectivePlan, ObjectiveVector, Outcome as RunOutcome,
    PercentileMethod, Precision, Provenance, Quantile, RunMeasurements, RunRecord, RunSubstrate,
    Scenario, SchemaVersion, StartTemperature, StateComparison, TracePattern,
};
use crate::model_memory::math::calibration::{CalibrationTracker, ModeController, ModeThresholds};

use super::baselines::{cache_selection, CachePolicy};
use super::candidates::{candidate_bound, generate, CandidateMode};
use super::evaluate::{
    milliseconds_score, Evaluation, Evaluator, Infeasibility, Outcome, WorkMeter,
};
use super::horizon::{Horizon, Selection};
use super::planner::{self, exhaustive_optimum, improves, FallbackReason, PlannerConfig};
use super::workloads::{self, Workload};
use super::BundleError;

const PLAN_DOMAIN: &str = "yougori/model-memory/bundles/plan-clause/v1";
const SIMULATOR_DOMAIN: &str = "yougori/model-memory/bundles/simulator/v1";
const SIMULATOR_VERSION: &str = "1.0.0";

/// Claim record item 1 (GPU §4.17): the exact proposed contribution.
pub const CLAIM_CONTRIBUTION: &str = "A bounded planner that chooses which state to retain or \
prepare by the weighted request delay a whole group removes under a resource-feasible \
schedule (queues, dependency barriers, shared links, scheduled preparation and transient \
memory), with candidates built from concurrent blockers, dependency closures and shared \
state, bounded local replacement, and a typed fallback to measured cost-per-byte or \
demand-only.";

/// Claim record item 3: the specific difference being tested.
pub const CLAIM_DIFFERENCE: &str = "Value is the delay removed for the actual requests of \
the horizon, computed by simulating the schedule with and without a group, so \
complementary objects are valued together and a shared object is credited for every \
request it unlocks; no independent per-object score is used.";

/// Claim record item 4: correctness assumptions.
pub const CLAIM_ASSUMPTIONS: &str = "The bounded heuristic schedule stands in for the true \
completion order; forecasts of arrivals, durations and probabilities are close enough; and \
greedy selection with one-group replacement approaches the optimum.";

/// Claim record item 4: the smallest counterexample constructed for those assumptions.
pub const CLAIM_COUNTEREXAMPLE: &str = "Budget 6; objects x and w of 3 bytes and 10 s, y, z \
and u of 2 bytes and 7 s; one request per object. The method keeps {x, w} and removes 20 s, \
the optimum {y, z, u} removes 21 s, and replacing one group cannot reach it.";

/// Words a claim record never uses (GPU §4.17 item 1).
pub const FORBIDDEN_CLAIM_WORDS: [&str; 2] = ["first", "unprecedented"];

/// One prior system the plan names (§4.13 table).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PriorWork {
    pub name: &'static str,
    /// The primary source the §4.13 table links.
    pub reference: &'static str,
    /// The problem it studies, as the table states it.
    pub formulation: &'static str,
}

/// Claim record item 2: the closest prior work per the §4.13 table. Neither the papers
/// nor their implementations were compared here.
pub const CLOSEST_PRIOR_WORK: [PriorWork; 3] = [
    PriorWork {
        name: "Dependency-Aware Online Caching",
        reference: "https://arxiv.org/abs/2401.17146",
        formulation: "online caching where items have prerequisites",
    },
    PriorWork {
        name: "ELORA",
        reference: "https://ieeexplore.ieee.org/document/11408492/",
        formulation: "joint management of adapter and session-cache dependencies",
    },
    PriorWork {
        name: "Chameleon",
        reference: "https://arxiv.org/abs/2411.17741",
        formulation: "adapter caching combined with request scheduling",
    },
];

/// The methods of the first-prototype comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Method {
    /// The bundle method: groups and local replacement.
    Bundle,
    /// Ablation of local replacement.
    BundleWithoutReplacement,
    /// Ablation of group candidates.
    SinglesWithReplacement,
    /// Individual positive-gain greedy over single objects (§4.14).
    ObjectGreedy,
    /// LRU over the request history (§2.7).
    Lru,
    /// Cost-per-byte over the request history (§2.7).
    CostPerByte,
    /// Dependency-aware caching: marginal saved latency, shared bases charged once.
    MarginalSavedLatency,
    /// Dependency-aware caching: GreedyDual-Size, shared bases charged once.
    GreedyDualSize,
    /// X = empty: every needed object loads on demand.
    RetainNothing,
}

impl Method {
    /// Every method, the ablations included.
    pub const ALL: [Self; 9] = [
        Self::Bundle,
        Self::BundleWithoutReplacement,
        Self::SinglesWithReplacement,
        Self::ObjectGreedy,
        Self::Lru,
        Self::CostPerByte,
        Self::MarginalSavedLatency,
        Self::GreedyDualSize,
        Self::RetainNothing,
    ];

    /// The baselines the bundle method must beat; the ablations are not among them.
    pub const BASELINES: [Self; 6] = [
        Self::ObjectGreedy,
        Self::Lru,
        Self::CostPerByte,
        Self::MarginalSavedLatency,
        Self::GreedyDualSize,
        Self::RetainNothing,
    ];

    /// The bundle method and every baseline, without the ablations.
    pub const COMPARED: [Self; 7] = [
        Self::Bundle,
        Self::ObjectGreedy,
        Self::Lru,
        Self::CostPerByte,
        Self::MarginalSavedLatency,
        Self::GreedyDualSize,
        Self::RetainNothing,
    ];

    /// The name used in record variants and report sides.
    pub fn label(self) -> &'static str {
        match self {
            Self::Bundle => "bundle",
            Self::BundleWithoutReplacement => "bundle-without-replacement",
            Self::SinglesWithReplacement => "singles-with-replacement",
            Self::ObjectGreedy => "object-greedy",
            Self::Lru => "lru",
            Self::CostPerByte => "cost-per-byte",
            Self::MarginalSavedLatency => "marginal-saved-latency",
            Self::GreedyDualSize => "greedy-dual-size",
            Self::RetainNothing => "retain-nothing",
        }
    }

    fn planner(self, config: &ExperimentConfig) -> Option<PlannerConfig> {
        let base = PlannerConfig {
            max_work_units: config.max_work_units,
            max_branches: config.max_branches,
            max_rounds: config.max_rounds,
            replacement_rounds: config.replacement_rounds,
            refill_steps: config.refill_steps,
            mode: CandidateMode::Bundles,
        };
        match self {
            Self::Bundle => Some(base),
            Self::BundleWithoutReplacement => Some(PlannerConfig {
                replacement_rounds: 0,
                ..base
            }),
            Self::SinglesWithReplacement => Some(PlannerConfig {
                mode: CandidateMode::SingleObjects,
                ..base
            }),
            Self::ObjectGreedy => Some(PlannerConfig {
                mode: CandidateMode::SingleObjects,
                replacement_rounds: 0,
                ..base
            }),
            _ => None,
        }
    }

    fn cache_policy(self, config: &ExperimentConfig) -> Option<CachePolicy> {
        match self {
            Self::Lru => Some(CachePolicy::Lru),
            Self::CostPerByte => Some(CachePolicy::CostPerByte),
            Self::MarginalSavedLatency => Some(CachePolicy::MarginalSavedLatency {
                half_life_steps: config.half_life_steps,
            }),
            Self::GreedyDualSize => Some(CachePolicy::GreedyDualSize),
            _ => None,
        }
    }
}

/// Budgets and constants every method of one comparison shares (equal budgets).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ExperimentConfig {
    /// The planner-time budget of every planning method, in work units.
    pub max_work_units: u64,
    /// See [`PlannerConfig`].
    pub max_branches: usize,
    pub max_rounds: usize,
    pub replacement_rounds: usize,
    pub refill_steps: usize,
    /// Seconds one planner work unit is charged as; planner time delays every request.
    pub seconds_per_work_unit: f64,
    /// Half-life of the marginal-saved-latency baseline, in requests.
    pub half_life_steps: u64,
}

impl ExperimentConfig {
    /// 50 million work units, three branches, one replacement round of three refills, and
    /// 100 ns per work unit.
    pub fn standard() -> Self {
        Self {
            max_work_units: 50_000_000,
            max_branches: 3,
            max_rounds: 16,
            replacement_rounds: 1,
            refill_steps: 3,
            seconds_per_work_unit: 1e-7,
            half_life_steps: 8,
        }
    }

    fn check(&self) -> Result<(), BundleError> {
        if !self.seconds_per_work_unit.is_finite() || self.seconds_per_work_unit < 0.0 {
            return Err(BundleError::InvalidValue {
                field: "seconds per work unit",
                reason: "must be finite and not negative",
            });
        }
        Ok(())
    }
}

/// The demand-only controller every planning method starts with: speculative until
/// confidence falls below 0.5, load passes 0.9 or calibration error passes 0.2 (GPU §2.9).
pub fn forecast_controller() -> Result<ModeController, BundleError> {
    Ok(ModeController::new(ModeThresholds {
        enter_below_confidence: 0.5,
        exit_at_confidence: 0.6,
        enter_above_load_fraction: 0.9,
        exit_at_load_fraction: 0.8,
        enter_above_calibration_error: 0.2,
        exit_at_calibration_error: 0.1,
        recovery_dwell: Duration::from_secs(1),
    })?)
}

/// One method's choice, scored on the true horizon.
#[derive(Clone, Debug, PartialEq)]
pub struct MethodRun {
    /// The method that chose X.
    pub method: Method,
    /// X in the true horizon.
    pub selection: Selection,
    /// `None` when X is infeasible on the true horizon.
    pub evaluation: Option<Evaluation>,
    pub infeasibility: Option<Infeasibility>,
    /// The net score on the true horizon; zero for an infeasible X, which reverts to
    /// retaining nothing.
    pub net_score: f64,
    /// Planner work; zero for the caching baselines and retaining nothing.
    pub work_units: u64,
    /// Planner work times the seconds charged per unit.
    pub overhead_seconds: f64,
    /// Planner time as delay on every request, in objective units.
    pub overhead_score: f64,
    /// Net score minus planner overhead: what the comparison ranks.
    pub net_after_overhead: f64,
    /// Why a planning method fell back, if it did.
    pub fallback: Option<FallbackReason>,
}

/// Every method on one horizon.
#[derive(Clone, Debug)]
pub struct InstanceRun {
    /// The true horizon every choice was scored on.
    pub horizon: Horizon,
    /// T_r(empty) on that horizon.
    pub empty: Evaluation,
    pub runs: Vec<MethodRun>,
}

impl InstanceRun {
    /// The run of one method, if it was run.
    pub fn run(&self, method: Method) -> Option<&MethodRun> {
        self.runs.iter().find(|run| run.method == method)
    }

    /// The baseline with the highest net score after overhead (ties: declaration order).
    pub fn strongest_baseline(&self) -> Option<&MethodRun> {
        Method::BASELINES
            .iter()
            .filter_map(|&method| self.run(method))
            .fold(None, |best: Option<&MethodRun>, run| match best {
                Some(known) if !improves(run.net_after_overhead, known.net_after_overhead) => {
                    Some(known)
                }
                _ => Some(run),
            })
    }

    /// The bundle method's net score after overhead minus the strongest baseline's.
    pub fn improvement(&self) -> Option<f64> {
        let bundle = self.run(Method::Bundle)?;
        let baseline = self.strongest_baseline()?;
        Some(bundle.net_after_overhead - baseline.net_after_overhead)
    }
}

/// Runs `methods` on one instance: planning methods plan on `view`, caching baselines
/// replay `history`, and every choice is scored on `truth` (GPU §4.14 line 834).
pub fn run_instance(
    truth: &Horizon,
    view: &Horizon,
    history: &[Vec<String>],
    methods: &[Method],
    config: &ExperimentConfig,
    clock: &dyn Clock,
) -> Result<InstanceRun, BundleError> {
    config.check()?;
    let controller = forecast_controller()?;
    let mut meter = WorkMeter::unbounded();
    let evaluator = Evaluator::new(truth, clock, &mut meter)?;
    let total_weight = truth.total_effective_weight();
    let mut runs = Vec::with_capacity(methods.len());
    for &method in methods {
        let (selection, work_units, fallback) =
            match (method.planner(config), method.cache_policy(config)) {
                (Some(planner_config), _) => {
                    let plan = planner::plan(view, clock, &controller, planner_config)?;
                    (
                        view.translate(plan.selection(), truth)?,
                        plan.work_units,
                        plan.fallback(),
                    )
                }
                (None, Some(policy)) => {
                    (cache_selection(truth, history, policy)?.selection, 0, None)
                }
                (None, None) => (Selection::new(), 0, None),
            };
        let overhead_seconds = work_units as f64 * config.seconds_per_work_unit;
        let overhead_score = milliseconds_score(
            &truth.spec().objective,
            overhead_seconds * 1_000.0 * total_weight,
        )?;
        let (evaluation, infeasibility, net_score) =
            match evaluator.evaluate(&selection, &mut meter)? {
                Outcome::Feasible(evaluation) => {
                    let net = evaluation.net_score;
                    (Some(evaluation), None, net)
                }
                Outcome::Infeasible(reason) => (None, Some(reason), 0.0),
            };
        runs.push(MethodRun {
            method,
            selection,
            evaluation,
            infeasibility,
            net_score,
            work_units,
            overhead_seconds,
            overhead_score,
            net_after_overhead: net_score - overhead_score,
            fallback,
        });
    }
    Ok(InstanceRun {
        horizon: truth.clone(),
        empty: evaluator.empty().clone(),
        runs,
    })
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

/// One workload family's instances.
#[derive(Clone, Debug)]
pub struct FamilyComparison {
    pub family: &'static str,
    /// The relative forecast error the planners saw; zero for the plain comparison.
    pub relative_error: f64,
    pub seeds: Vec<u64>,
    pub instances: Vec<InstanceRun>,
}

impl FamilyComparison {
    /// Per instance: bundle minus strongest baseline, after planner overhead.
    pub fn improvements(&self) -> Vec<f64> {
        self.instances
            .iter()
            .filter_map(InstanceRun::improvement)
            .collect()
    }

    /// The mean of [`Self::improvements`]; zero without instances.
    pub fn mean_improvement(&self) -> f64 {
        mean(&self.improvements())
    }

    /// The smallest of [`Self::improvements`].
    pub fn min_improvement(&self) -> f64 {
        self.improvements()
            .into_iter()
            .fold(f64::INFINITY, f64::min)
    }

    /// Instances where the bundle method is not worse than the strongest baseline.
    pub fn wins(&self) -> usize {
        self.instances
            .iter()
            .filter(|instance| {
                match (instance.run(Method::Bundle), instance.strongest_baseline()) {
                    (Some(bundle), Some(baseline)) => {
                        !improves(baseline.net_after_overhead, bundle.net_after_overhead)
                    }
                    _ => false,
                }
            })
            .count()
    }

    /// The mean net score after overhead of one method.
    pub fn mean_net(&self, method: Method) -> f64 {
        let values: Vec<f64> = self
            .instances
            .iter()
            .filter_map(|instance| instance.run(method))
            .map(|run| run.net_after_overhead)
            .collect();
        mean(&values)
    }

    /// The pass/stop rule's summary of this family.
    pub fn evidence(&self) -> FamilyEvidence {
        FamilyEvidence {
            family: self.family,
            relative_error: self.relative_error,
            instances: self.instances.len(),
            mean_improvement: self.mean_improvement(),
            min_improvement: self.min_improvement(),
            wins: self.wins(),
        }
    }
}

/// Runs `methods` on every workload with exact forecasts.
pub fn compare_family(
    family: &'static str,
    workloads: &[(u64, Workload)],
    methods: &[Method],
    config: &ExperimentConfig,
    clock: &dyn Clock,
) -> Result<FamilyComparison, BundleError> {
    let mut instances = Vec::with_capacity(workloads.len());
    for (_, workload) in workloads {
        let horizon = Horizon::build(workload.spec.clone())?;
        instances.push(run_instance(
            &horizon,
            &horizon,
            &workload.history,
            methods,
            config,
            clock,
        )?);
    }
    Ok(FamilyComparison {
        family,
        relative_error: 0.0,
        seeds: workloads.iter().map(|(seed, _)| *seed).collect(),
        instances,
    })
}

/// A comparison under seeded forecast errors, with the calibration of the predicted
/// probabilities the planners saw (GPU §2.9, §4.14 line 836).
#[derive(Clone, Debug)]
pub struct ForecastStudy {
    pub comparison: FamilyComparison,
    /// Predicted requests whose arrival was drawn.
    pub predictions: u64,
    /// Over the probabilities the planners saw; `None` without predictions.
    pub brier_score: Option<f64>,
    pub expected_calibration_error: Option<f64>,
}

/// Planners see [`workloads::perturb`]ed horizons; every choice is scored on the
/// [`workloads::realize`]d horizon, where predicted requests arrived or not with their
/// true probabilities.
pub fn forecast_study(
    family: &'static str,
    workloads: &[(u64, Workload)],
    relative_error: f64,
    methods: &[Method],
    config: &ExperimentConfig,
    clock: &dyn Clock,
) -> Result<ForecastStudy, BundleError> {
    let mut tracker = CalibrationTracker::new(10)?;
    let mut instances = Vec::with_capacity(workloads.len());
    for (seed, workload) in workloads {
        let view_spec = workloads::perturb(&workload.spec, *seed, relative_error)?;
        let (realized, samples) = workloads::realize(&workload.spec, &view_spec, *seed)?;
        for (probability, arrived) in samples {
            tracker.record(probability, arrived)?;
        }
        let truth = Horizon::build(realized)?;
        let view = Horizon::build(view_spec)?;
        instances.push(run_instance(
            &truth,
            &view,
            &workload.history,
            methods,
            config,
            clock,
        )?);
    }
    Ok(ForecastStudy {
        comparison: FamilyComparison {
            family,
            relative_error,
            seeds: workloads.iter().map(|(seed, _)| *seed).collect(),
            instances,
        },
        predictions: tracker.count(),
        brier_score: tracker.brier_score(),
        expected_calibration_error: tracker.expected_calibration_error(),
    })
}

/// Candidates of the first round on one shared-base size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnumerationRow {
    /// Base models of the shared-base horizon.
    pub models: u64,
    /// Requests asked for; the horizon may include fewer.
    pub requests: u64,
    pub needed_objects: usize,
    pub included_requests: usize,
    /// Distinct candidates of the first round.
    pub candidates: u64,
    /// `2n + R·B` for this row.
    pub bound: u64,
}

/// Candidate counts as model and request counts grow (GPU §4.14 line 836).
#[derive(Clone, Debug, PartialEq)]
pub struct EnumerationStudy {
    pub max_branches: usize,
    pub rows: Vec<EnumerationRow>,
}

impl EnumerationStudy {
    /// Every row stays within `2n + R·B`.
    pub fn bounded(&self) -> bool {
        self.rows.iter().all(|row| row.candidates <= row.bound)
    }

    /// The largest candidates per needed object and request over all rows: bounded by
    /// `max(2, B)`, so enumeration grows at most linearly.
    pub fn max_candidates_per_unit(&self) -> f64 {
        self.rows
            .iter()
            .map(|row| {
                row.candidates as f64 / (row.needed_objects + row.included_requests).max(1) as f64
            })
            .fold(0.0, f64::max)
    }
}

/// Counts first-round candidates on shared-base horizons of each (models, requests) size.
pub fn enumeration_study(
    sizes: &[(u64, u64)],
    seed: u64,
    max_branches: usize,
    clock: &dyn Clock,
) -> Result<EnumerationStudy, BundleError> {
    let mut rows = Vec::with_capacity(sizes.len());
    for &(models, requests) in sizes {
        let workload = workloads::shared_base(seed, models, requests)?;
        let horizon = Horizon::build(workload.spec)?;
        let mut meter = WorkMeter::unbounded();
        let evaluator = Evaluator::new(&horizon, clock, &mut meter)?;
        let candidates = generate(
            &horizon,
            &Selection::new(),
            evaluator.empty(),
            CandidateMode::Bundles,
            max_branches,
            &mut meter,
        )?;
        let needed_objects = horizon.needed_objects().len();
        rows.push(EnumerationRow {
            models,
            requests,
            needed_objects,
            included_requests: horizon.request_count(),
            candidates: candidates.len() as u64,
            bound: candidate_bound(
                needed_objects,
                horizon.request_count(),
                max_branches,
                CandidateMode::Bundles,
            ),
        });
    }
    Ok(EnumerationStudy { max_branches, rows })
}

/// The bundle method against the exhaustive optimum on one seeded tiny horizon.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct OracleRow {
    /// The [`workloads::tiny`] seed.
    pub seed: u64,
    pub needed_objects: usize,
    /// The bundle method's net score, fallbacks scored like any selection.
    pub bundle_net: f64,
    /// The exhaustive optimum's net score.
    pub optimal_net: f64,
}

impl OracleRow {
    /// Bundle over optimum; 1 when both are zero, since the optimum is never negative.
    pub fn ratio(&self) -> f64 {
        if self.optimal_net > 0.0 {
            self.bundle_net / self.optimal_net
        } else {
            1.0
        }
    }

    /// Whether the bundle method scored above the optimum; never expected.
    pub fn beats_optimum(&self) -> bool {
        improves(self.bundle_net, self.optimal_net)
    }
}

/// Exhaustive comparison over seeded tiny horizons (GPU §2.3, §4.14 line 834).
#[derive(Clone, Debug, PartialEq)]
pub struct OracleStudy {
    pub rows: Vec<OracleRow>,
}

impl OracleStudy {
    /// Whether no row scored above its optimum.
    pub fn never_beaten(&self) -> bool {
        self.rows.iter().all(|row| !row.beats_optimum())
    }

    /// The worst bundle-over-optimum ratio; 1 without rows.
    pub fn min_ratio(&self) -> f64 {
        self.rows.iter().map(OracleRow::ratio).fold(1.0, f64::min)
    }

    /// The mean bundle-over-optimum ratio; 0 without rows.
    pub fn mean_ratio(&self) -> f64 {
        mean(&self.rows.iter().map(OracleRow::ratio).collect::<Vec<_>>())
    }

    /// Rows where the bundle method reached the optimum.
    pub fn optimal_rows(&self) -> usize {
        self.rows
            .iter()
            .filter(|row| !improves(row.optimal_net, row.bundle_net))
            .count()
    }
}

/// Runs the bundle method and the exhaustive optimum on [`workloads::tiny`] for each seed.
/// A fallback is scored like any selection.
pub fn oracle_study(
    seeds: Range<u64>,
    config: &ExperimentConfig,
    clock: &dyn Clock,
) -> Result<OracleStudy, BundleError> {
    let planner_config = Method::Bundle
        .planner(config)
        .ok_or(BundleError::InvalidValue {
            field: "oracle study",
            reason: "the bundle method has no planner",
        })?;
    let controller = forecast_controller()?;
    let mut rows = Vec::new();
    for seed in seeds {
        let workload = workloads::tiny(seed)?;
        let horizon = Horizon::build(workload.spec)?;
        let plan = planner::plan(&horizon, clock, &controller, planner_config)?;
        let mut meter = WorkMeter::unbounded();
        let evaluator = Evaluator::new(&horizon, clock, &mut meter)?;
        let bundle_net = evaluator
            .evaluate(plan.selection(), &mut meter)?
            .feasible()
            .map_or(0.0, |evaluation| evaluation.net_score);
        let optimum = exhaustive_optimum(&horizon, clock)?;
        rows.push(OracleRow {
            seed,
            needed_objects: horizon.needed_objects().len(),
            bundle_net,
            optimal_net: optimum.evaluation.net_score,
        });
    }
    Ok(OracleStudy { rows })
}

/// One family's improvement summary, the pass/stop rule's input.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FamilyEvidence {
    pub family: &'static str,
    /// The forecast error the planners saw.
    pub relative_error: f64,
    pub instances: usize,
    /// In objective units, after planner overhead.
    pub mean_improvement: f64,
    pub min_improvement: f64,
    /// Instances where the bundle method was not worse.
    pub wins: usize,
}

impl FamilyEvidence {
    /// The improvement persists: positive on average over the strongest baseline, after
    /// planner overhead.
    pub fn persists(&self) -> bool {
        self.instances > 0 && improves(self.mean_improvement, 0.0)
    }
}

/// Everything the pass/stop rule reads.
#[derive(Clone, Debug, PartialEq)]
pub struct PassStopEvidence {
    /// Bundle minus strongest baseline on the hand-built counterexample.
    pub counterexample_improvement: f64,
    /// Generated families with exact forecasts.
    pub families: Vec<FamilyEvidence>,
    /// Generated families under each forecast error.
    pub forecast: Vec<FamilyEvidence>,
    pub enumeration_bounded: bool,
}

/// Why the claim is narrowed.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NarrowReason {
    /// Benefits appear only in the hand-built counterexample.
    OnlyHandBuiltExamples,
    /// No persistent improvement in this generated family.
    NotInFamily { family: &'static str },
    /// The improvement does not survive this forecast error.
    NotUnderForecastError {
        family: &'static str,
        relative_error: f64,
    },
}

/// Why GPU-N1 stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    /// Candidate enumeration outgrew its bound.
    EnumerationUnbounded,
    /// No improvement anywhere, not even on the counterexample.
    NoImprovement,
}

/// The §4.14 pass/stop rule (line 836) as a computed decision.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PassStop {
    /// Improvement persists after planner overhead and forecast errors in every family.
    Advance,
    Narrow(NarrowReason),
    Stop(StopReason),
}

/// Advance only if the improvement persists in every generated family after planner
/// overhead and under every forecast error tested; narrow when benefits exist only in the
/// hand-built example or only in some families or error levels; stop when enumeration
/// is unbounded or nothing improves at all.
pub fn pass_stop(evidence: &PassStopEvidence) -> PassStop {
    if !evidence.enumeration_bounded {
        return PassStop::Stop(StopReason::EnumerationUnbounded);
    }
    let failing_family = evidence.families.iter().find(|family| !family.persists());
    let failing_forecast = evidence.forecast.iter().find(|family| !family.persists());
    let any_family = evidence.families.iter().any(FamilyEvidence::persists);
    let hand_built = improves(evidence.counterexample_improvement, 0.0);
    match (failing_family, failing_forecast) {
        _ if evidence.families.is_empty() => {
            if hand_built {
                PassStop::Narrow(NarrowReason::OnlyHandBuiltExamples)
            } else {
                PassStop::Stop(StopReason::NoImprovement)
            }
        }
        (None, None) => PassStop::Advance,
        (Some(_), _) if !any_family => {
            if hand_built {
                PassStop::Narrow(NarrowReason::OnlyHandBuiltExamples)
            } else {
                PassStop::Stop(StopReason::NoImprovement)
            }
        }
        (Some(family), _) => PassStop::Narrow(NarrowReason::NotInFamily {
            family: family.family,
        }),
        (None, Some(family)) => PassStop::Narrow(NarrowReason::NotUnderForecastError {
            family: family.family,
            relative_error: family.relative_error,
        }),
    }
}

/// Whether the literature and implementation comparison of §4.13 was made, and what it
/// found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiteratureComparison {
    /// The papers and implementations were not compared.
    NotDone,
    /// The comparison found the same problem and method.
    OverlapsPriorWork,
    /// The comparison found a specific difference.
    DifferenceEstablished,
}

/// GPU §4.17 item 6, with rule-11 narrowing for a mechanism that loses on fakes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimResult {
    /// Measured benefit, but the method overlaps prior work.
    UsefulIntegration,
    /// Measured benefit and a literature-established difference.
    SupportedOriginalContribution,
    /// Benefit on fakes only, or no literature comparison yet.
    Inconclusive,
    /// Benefit only in hand-built cases or some families (rule 11).
    Narrowed,
    /// The pass/stop rule stops the candidate.
    Rejected,
}

/// The claim result: rejected on a stop, narrowed on a narrow; on an advance, only
/// Yougori measurements together with a literature comparison can go beyond
/// inconclusive, so a fake-substrate provenance never does.
pub fn claim_result(
    decision: &PassStop,
    provenance: &Provenance,
    literature: LiteratureComparison,
) -> ClaimResult {
    match decision {
        PassStop::Stop(_) => ClaimResult::Rejected,
        PassStop::Narrow(_) => ClaimResult::Narrowed,
        PassStop::Advance => match (provenance.yougori_evidence(), literature) {
            (Err(_), _) | (_, LiteratureComparison::NotDone) => ClaimResult::Inconclusive,
            (Ok(_), LiteratureComparison::OverlapsPriorWork) => ClaimResult::UsefulIntegration,
            (Ok(_), LiteratureComparison::DifferenceEstablished) => {
                ClaimResult::SupportedOriginalContribution
            }
        },
    }
}

/// The GPU §4.17 claim record of GPU-N1.
#[derive(Clone, Debug, PartialEq)]
pub struct ClaimRecord {
    /// Item 1.
    pub contribution: &'static str,
    /// Item 2.
    pub closest_prior_work: &'static [PriorWork],
    /// Item 3.
    pub difference_tested: &'static str,
    /// Item 4: assumptions.
    pub assumptions: &'static str,
    /// Item 4: the smallest counterexample constructed.
    pub smallest_counterexample: &'static str,
    /// Item 5: improvement over the strongest compatible baseline per family.
    pub comparison: PassStopEvidence,
    /// The computed pass/stop decision.
    pub decision: PassStop,
    /// Item 6.
    pub result: ClaimResult,
}

/// Builds the GPU §4.17 claim record of GPU-N1 from the prototype's evidence.
pub fn claim_record(
    evidence: &PassStopEvidence,
    provenance: &Provenance,
    literature: LiteratureComparison,
) -> ClaimRecord {
    let decision = pass_stop(evidence);
    ClaimRecord {
        contribution: CLAIM_CONTRIBUTION,
        closest_prior_work: &CLOSEST_PRIOR_WORK,
        difference_tested: CLAIM_DIFFERENCE,
        assumptions: CLAIM_ASSUMPTIONS,
        smallest_counterexample: CLAIM_COUNTEREXAMPLE,
        comparison: evidence.clone(),
        decision,
        result: claim_result(&decision, provenance, literature),
    }
}

fn label(text: &str) -> Result<Label, BundleError> {
    Ok(Label::new(text)?)
}

fn not_applicable<T>() -> Measured<T> {
    Measured::not_measured(NotMeasuredReason::NotApplicable)
}

fn simulated_host() -> Result<HostDescription, BundleError> {
    Ok(HostDescription {
        os: label("simulated")?,
        os_version: label("none")?,
        cpu: CpuDescription {
            model: label("simulated")?,
            logical_cores: 1,
        },
        host_memory_bytes: 0,
        gpus: not_applicable(),
        gpu_driver: not_applicable(),
        gpu_power_clock: not_applicable(),
        power_source: not_applicable(),
        displays_on_gpu: not_applicable(),
    })
}

/// One fake-substrate CORE-08 record per request of a simulated run: request accepted and
/// placement requested at arrival, weights usable when its compute can start, and the
/// first token at T_r, each shifted by the planner overhead. A stage record judged on
/// weight availability; nothing on it is a measurement.
pub fn simulated_records(
    family: &str,
    method: Method,
    instance: u32,
    horizon: &Horizon,
    evaluation: &Evaluation,
    overhead: Duration,
    origin: MonotonicTime,
) -> Result<Vec<RunRecord>, BundleError> {
    let variant = label(&format!("gpu-n1-{family}-{}", method.label()))?;
    let execution = ExecutionId::new(format!("exe-gpu-n1-{family}"))?;
    let build = BuildIdentity {
        plan: digest(PLAN_DOMAIN, &[b"GPU-N1", b"4.14"]),
        runner_build: digest(SIMULATOR_DOMAIN, &[SIMULATOR_VERSION.as_bytes()]),
        runner_version: label(SIMULATOR_VERSION)?,
    };
    let clock_id = ClockId::new(label("simulated-monotonic")?);
    let overflow = BundleError::InvalidValue {
        field: "simulated time",
        reason: "does not fit the clock",
    };
    let requests = u32::try_from(horizon.request_count()).unwrap_or(u32::MAX);
    let mut records = Vec::with_capacity(horizon.request_count());
    for position in 0..horizon.request_count() {
        let request = horizon.request(position);
        let (Some(&ready), Some(&finish)) = (
            evaluation.state_ready.get(position),
            evaluation.completion.get(position),
        ) else {
            return Err(BundleError::InvalidValue {
                field: "evaluation",
                reason: "has no completion for a request",
            });
        };
        let operation = OperationId::new(format!(
            "op-gpu-n1-{family}-{}-{instance}-{}",
            method.label(),
            request.id
        ))?;
        let clock = ManualClock::new(origin);
        let mut recorder = EventRecorder::new(operation.clone(), clock_id.clone(), &clock);
        let arrival = origin
            .checked_add(request.arrival)
            .ok_or(overflow.clone())?;
        clock.advance_to(arrival);
        recorder.record(EventKind::RequestAccepted);
        recorder.record(EventKind::PlacementRequested);
        clock.advance_to(
            arrival
                .checked_add(overhead + ready)
                .ok_or(overflow.clone())?,
        );
        recorder.record(EventKind::WeightsUsable);
        clock.advance_to(
            arrival
                .checked_add(overhead + finish)
                .ok_or(overflow.clone())?,
        );
        recorder.record(EventKind::TokenEmitted);
        let record = RunRecord {
            schema_version: SchemaVersion,
            attempt: AttemptIdentity {
                bench: BenchId::Bench02,
                variant: variant.clone(),
                execution: execution.clone(),
                operation,
                role: AttemptRole::Initial,
                burst: instance,
                deadline_nanos: not_applicable(),
            },
            scenario: Scenario::Stages {
                primary: IntervalKind::WeightAvailability,
            },
            substrate: RunSubstrate::FakeTimeControlled,
            build: build.clone(),
            execution_category: request.trust_scope.category,
            model: not_applicable(),
            precision: not_applicable(),
            engine: Measured::measured(EngineIdentity {
                name: label("yougori-bundle-simulator")?,
                version: label(SIMULATOR_VERSION)?,
            }),
            host: simulated_host()?,
            workload: not_applicable(),
            client: ClientDescription {
                name: label("yougori-bundle-simulator")?,
                version: label(SIMULATOR_VERSION)?,
                region: label("same-host")?,
                placement: ClientPlacement::SameHost,
            },
            load: LoadDescription {
                concurrent_requests: requests,
                arrival: ArrivalMode::Burst { size: requests },
            },
            state: not_applicable(),
            launch: LaunchDescription {
                image: digest(SIMULATOR_DOMAIN, &[b"image"]),
                backend: label("trace-simulator")?,
            },
            price: not_applicable(),
            measurements: RunMeasurements {
                output_tokens: not_applicable(),
                prefill_tokens_per_second: not_applicable(),
                aggregate_decode_tokens_per_second: not_applicable(),
                speculative: not_applicable(),
                peak_gpu_memory_bytes: not_applicable(),
                retained_gpu_memory_bytes: not_applicable(),
                peak_host_memory_bytes: not_applicable(),
                retained_host_memory_bytes: not_applicable(),
                peak_pinned_host_memory_bytes: not_applicable(),
                transferred_bytes: not_applicable(),
                storage_read_bytes: not_applicable(),
                energy_joules: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
                offload: not_applicable(),
                first_run: not_applicable(),
                owner_return: not_applicable(),
                reasoning: not_applicable(),
            },
            events: recorder.into_events(),
            outcome: RunOutcome::Succeeded,
        };
        record.validate()?;
        records.push(record);
    }
    Ok(records)
}

/// One method's recorded side.
#[derive(Clone, Debug, PartialEq)]
pub struct RecordedSide {
    pub method: Method,
    /// One fake-substrate record per request per instance.
    pub records: Vec<RunRecord>,
    /// Always the fake-substrate provenance of those records.
    pub provenance: Provenance,
    /// Untrimmed simulated first-token percentiles over every request of every instance.
    pub summary: LatencySummary,
    /// The side's §1.3 objectives; what a simulation cannot measure says so.
    pub objectives: ObjectiveVector,
}

/// A family's fake-substrate records and its CORE-08 comparison report.
#[derive(Clone, Debug, PartialEq)]
pub struct RecordedFamily {
    pub family: &'static str,
    /// Every method's records, the ablations included.
    pub sides: Vec<RecordedSide>,
    pub report: ComparisonReport,
}

impl RecordedFamily {
    /// The recorded side of one method.
    pub fn side(&self, method: Method) -> Option<&RecordedSide> {
        self.sides.iter().find(|side| side.method == method)
    }
}

fn measured_value(value: f64) -> Result<Measured<NonNegative>, BundleError> {
    Ok(Measured::measured(NonNegative::new(value)?))
}

/// Records every method of `comparison` on the fake substrate and builds the CORE-08
/// comparison: the bundle method against LRU as the ordinary workflow and the strongest
/// of the other baselines, declared objective p50 time to first token over simulated
/// requests, with the two ablations declared (§1.1).
pub fn record_family(
    comparison: &FamilyComparison,
    origin: MonotonicTime,
) -> Result<RecordedFamily, BundleError> {
    let family = comparison.family;
    let first = comparison
        .instances
        .first()
        .ok_or(BundleError::InvalidValue {
            field: "comparison",
            reason: "has no instances",
        })?;
    let category = first.horizon.request(0).trust_scope.category;
    let configuration = MatchedConfiguration {
        model_bytes: digest(SIMULATOR_DOMAIN, &[b"family", family.as_bytes()]),
        precision: Precision {
            weight_dtype: label("not-applicable")?,
            quantization: label("none")?,
            kv_cache_dtype: label("not-applicable")?,
        },
        fixture: comparison
            .seeds
            .iter()
            .fold(
                crate::foundation::ids::DigestBuilder::new(SIMULATOR_DOMAIN).str(family),
                |builder, seed| builder.u64(*seed),
            )
            .finish(),
        max_output_tokens: 1,
        hardware: digest(SIMULATOR_DOMAIN, &[b"cpu-only-trace-simulator"]),
        client: digest(SIMULATOR_DOMAIN, &[b"client"]),
        tool_template: not_applicable(),
        execution_category: category,
    };
    let slowest_empty = comparison
        .instances
        .iter()
        .flat_map(|instance| instance.empty.completion.iter())
        .map(|completion| u64::try_from(completion.as_nanos()).unwrap_or(u64::MAX))
        .max()
        .unwrap_or(0);
    let mut sides = Vec::new();
    for method in Method::ALL {
        let mut records = Vec::new();
        let mut retained = Vec::new();
        let mut loaded = Vec::new();
        for (instance_at, instance) in comparison.instances.iter().enumerate() {
            let Some(run) = instance.run(method) else {
                continue;
            };
            let evaluation = run.evaluation.as_ref().ok_or(BundleError::InvalidValue {
                field: "comparison",
                reason: "an infeasible selection has no record",
            })?;
            records.extend(simulated_records(
                family,
                method,
                u32::try_from(instance_at).unwrap_or(u32::MAX),
                &instance.horizon,
                evaluation,
                Duration::try_from_secs_f64(run.overhead_seconds).map_err(|_| {
                    BundleError::InvalidValue {
                        field: "planner overhead",
                        reason: "does not fit a duration",
                    }
                })?,
                origin,
            )?);
            retained.push(
                evaluation
                    .retained_bytes
                    .saturating_add(evaluation.prepared_bytes) as f64,
            );
            loaded.push(evaluation.loaded_bytes as f64);
        }
        if records.is_empty() {
            continue;
        }
        let provenance = Provenance::of_records(&records)?;
        let ledger = AttemptLedger::from_records(records.iter().cloned())?;
        let summary = LatencySummary::from_ledger(
            &ledger,
            IntervalKind::TimeToFirstToken,
            PercentileMethod::NearestRank,
        )?;
        let p50 = summary
            .percentile(Quantile::P50)
            .and_then(|estimate| estimate.value_nanos.value().copied())
            .ok_or(BundleError::InvalidValue {
                field: "summary",
                reason: "has no p50",
            })?;
        let objectives = ObjectiveVector {
            time_to_first_token_quantile: Quantile::P50,
            latency_objective: LatencyObjective {
                quantile: Quantile::P50,
                max_time_to_first_token_nanos: slowest_empty,
            },
            time_to_first_token_nanos: measured_value(p50)?,
            throughput_under_latency_objective_tokens_per_second: not_applicable(),
            peak_gpu_memory_bytes: Measured::not_measured(NotMeasuredReason::NotRecorded),
            retained_gpu_memory_bytes: measured_value(mean(&retained))?,
            peak_host_memory_bytes: not_applicable(),
            retained_host_memory_bytes: not_applicable(),
            transferred_bytes: measured_value(mean(&loaded))?,
            storage_read_bytes: Measured::not_measured(NotMeasuredReason::NotRecorded),
            preparation_cost_usd: not_applicable(),
            cost_per_completed_request_usd: not_applicable(),
            energy_per_completed_request_joules: Measured::not_measured(
                NotMeasuredReason::InstrumentUnavailable,
            ),
            reliability_success_rate: not_applicable(),
        };
        sides.push(RecordedSide {
            method,
            records,
            provenance,
            summary,
            objectives,
        });
    }
    let side =
        |method: Method| -> Result<ComparisonSide, BundleError> {
            let recorded = sides.iter().find(|side| side.method == method).ok_or(
                BundleError::InvalidValue {
                    field: "comparison",
                    reason: "a compared method was not run",
                },
            )?;
            Ok(ComparisonSide {
                name: label(method.label())?,
                provenance: recorded.provenance.clone(),
                configuration: configuration.clone(),
                temperature: StartTemperature::Warm,
                fidelity: ModeFidelity::BitIdentical,
                accuracy_evaluation: not_applicable(),
                objectives: recorded.objectives.clone(),
            })
        };
    let strongest = [
        Method::ObjectGreedy,
        Method::CostPerByte,
        Method::MarginalSavedLatency,
        Method::GreedyDualSize,
        Method::RetainNothing,
    ]
    .into_iter()
    .map(side)
    .collect::<Result<Vec<_>, _>>()?;
    let components = vec![label("bundle-groups")?, label("local-replacement")?];
    let report = ComparisonReport::new(
        ObjectivePlan::new(ReportObjective::TimeToFirstToken, 0.05)?,
        StateComparison::WarmLoad,
        ExperimentDesign {
            effect: EffectClass::CacheOrPredictor,
            independent_trials: u32::try_from(comparison.instances.len()).unwrap_or(u32::MAX),
            trace: TracePattern::Mixed {
                seed: comparison.seeds.first().copied().unwrap_or(0),
            },
            components: components.clone(),
            ablated_components: components,
        },
        Vec::new(),
        side(Method::Bundle)?,
        Baseline::Measured {
            sides: vec![side(Method::Lru)?],
        },
        Baseline::Measured { sides: strongest },
    )?;
    Ok(RecordedFamily {
        family,
        sides,
        report,
    })
}

/// What [`first_prototype`] runs.
#[derive(Clone, Debug, PartialEq)]
pub struct PrototypeConfig {
    pub experiment: ExperimentConfig,
    /// The first seed; instance `i` uses `seed + i`.
    pub seed: u64,
    /// Instances per generated family; at least five for a CORE-08 comparison.
    pub instances: u64,
    /// Base models per shared-base horizon.
    pub shared_models: u64,
    /// Requests per shared-base horizon.
    pub shared_requests: u64,
    /// Forecast errors tested on top of the exact comparison.
    pub relative_errors: Vec<f64>,
    /// (models, requests) sizes of the enumeration study.
    pub enumeration_sizes: Vec<(u64, u64)>,
    /// Tiny horizons compared with their exhaustive optimum.
    pub oracle_seeds: u64,
}

impl PrototypeConfig {
    /// Six instances per family, three bases and four requests per shared-base horizon,
    /// forecast errors of 15 % and 30 %, enumeration from 2×2 to 16×16, twenty tiny
    /// horizons for the exhaustive comparison.
    pub fn standard() -> Self {
        Self {
            experiment: ExperimentConfig::standard(),
            seed: 41,
            instances: 6,
            shared_models: 3,
            shared_requests: 4,
            relative_errors: vec![0.15, 0.3],
            enumeration_sizes: vec![(2, 2), (4, 4), (8, 8), (16, 16)],
            oracle_seeds: 20,
        }
    }
}

/// Everything the first prototype produced.
#[derive(Clone, Debug)]
pub struct PrototypeReport {
    /// Every method on the §4.14 toy.
    pub counterexample: InstanceRun,
    /// Adversarial and shared-base families with exact forecasts.
    pub families: Vec<FamilyComparison>,
    /// The same families under each forecast error.
    pub forecast: Vec<ForecastStudy>,
    pub enumeration: EnumerationStudy,
    pub oracle: OracleStudy,
    /// Fake-substrate records and CORE-08 reports of the families.
    pub recorded: Vec<RecordedFamily>,
    pub claim: ClaimRecord,
}

/// Runs the whole GPU-N1 first prototype and computes its claim record.
pub fn first_prototype(
    config: &PrototypeConfig,
    clock: &dyn Clock,
) -> Result<PrototypeReport, BundleError> {
    let experiment = &config.experiment;
    let toy = workloads::counterexample()?;
    let toy_horizon = Horizon::build(toy.spec.clone())?;
    let counterexample = run_instance(
        &toy_horizon,
        &toy_horizon,
        &toy.history,
        &Method::ALL,
        experiment,
        clock,
    )?;
    let seeds: Vec<u64> = (0..config.instances)
        .map(|at| config.seed.wrapping_add(at))
        .collect();
    let adversarial = seeds
        .iter()
        .map(|&seed| Ok((seed, workloads::adversarial(seed)?)))
        .collect::<Result<Vec<_>, BundleError>>()?;
    let shared = seeds
        .iter()
        .map(|&seed| {
            Ok((
                seed,
                workloads::shared_base(seed, config.shared_models, config.shared_requests)?,
            ))
        })
        .collect::<Result<Vec<_>, BundleError>>()?;
    let families = vec![
        compare_family("adversarial", &adversarial, &Method::ALL, experiment, clock)?,
        compare_family("shared-base", &shared, &Method::ALL, experiment, clock)?,
    ];
    let mut forecast = Vec::new();
    for &relative_error in &config.relative_errors {
        forecast.push(forecast_study(
            "adversarial",
            &adversarial,
            relative_error,
            &Method::COMPARED,
            experiment,
            clock,
        )?);
        forecast.push(forecast_study(
            "shared-base",
            &shared,
            relative_error,
            &Method::COMPARED,
            experiment,
            clock,
        )?);
    }
    let enumeration = enumeration_study(
        &config.enumeration_sizes,
        config.seed,
        experiment.max_branches,
        clock,
    )?;
    let oracle = oracle_study(
        config.seed..config.seed.wrapping_add(config.oracle_seeds),
        experiment,
        clock,
    )?;
    let origin = clock.now();
    let recorded = families
        .iter()
        .map(|family| record_family(family, origin))
        .collect::<Result<Vec<_>, _>>()?;
    let evidence = PassStopEvidence {
        counterexample_improvement: counterexample.improvement().unwrap_or(0.0),
        families: families.iter().map(FamilyComparison::evidence).collect(),
        forecast: forecast
            .iter()
            .map(|study| study.comparison.evidence())
            .collect(),
        enumeration_bounded: enumeration.bounded(),
    };
    let provenance = recorded
        .first()
        .and_then(|family| family.side(Method::Bundle))
        .map(|side| side.provenance.clone())
        .ok_or(BundleError::InvalidValue {
            field: "first prototype",
            reason: "no bundle records",
        })?;
    let claim = claim_record(&evidence, &provenance, LiteratureComparison::NotDone);
    Ok(PrototypeReport {
        counterexample,
        families,
        forecast,
        enumeration,
        oracle,
        recorded,
        claim,
    })
}
