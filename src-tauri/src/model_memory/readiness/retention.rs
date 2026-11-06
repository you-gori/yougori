//! Retain the smallest useful execution state (GPU §4.5 lines 699–705; §3.8 lines
//! 615–628; §2.7 lines 436–448).
//!
//! A [`ComponentTable`] gives each component of a warm model (tokenizer/configuration,
//! CPU process, GPU context, processed weights, graphs, KV and communicators) its
//! retained bytes and its own recreate cost. A [`RetentionLevel`] keeps, offloads or
//! drops each component; a level is valid only when every kept component's
//! prerequisites are kept, so no level is an artificial state the backend could not
//! recreate. The levels the governor may use come only from the backend
//! ([`SupportedLevels::from_runtime`]): a retained process admitted by P06, each queried
//! sleep level the runtime may plan, and full restart. A sleep level keeps the process and
//! GPU context and treats weights and KV exactly as its queried semantics say; graphs and
//! communicators, which the semantics do not state, are counted as recreated.
//!
//! [`pareto_frontier`] keeps the levels no other level beats on both retained bytes and
//! resume time. [`RetentionGovernor::choose`] picks the fastest-resuming supported level
//! that fits a budget of GPU and pinned host bytes and refuses any level the backend did
//! not supply.
//!
//! The comparison runs on the fake runners with three budgets and burst and gap
//! workloads: always-hot (retained process), ordinary sleep (the backend's level that
//! offloads weights), full restart, and selective retention (the governor's choice per
//! budget). A level maps to the fake mode that behaves like it ([`runner_mode`]); a
//! level that discards weights maps to verified reload, as in the parking comparison.
//! Each cell starts in steady state: an unrecorded warm-up loads the second model and
//! parks each model once in the strategy's own way, as `start` is setup, so no cell's
//! tail is one model's first load ever.
//!
//! # Claim record
//!
//! 1. Contribution: per memory budget, choose the fastest-resuming backend-supported
//!    retention level from a per-component recreate-cost table and its Pareto frontier.
//! 2. Closest prior work named by the plan: vLLM sleep levels with queried retention
//!    semantics (GPU §3.8) and size-constrained retention with LRU, cost-per-byte and
//!    Landlord/GreedyDual-Size baselines (§2.7).
//! 3. Difference tested: selection among backend levels by measured component costs
//!    against a fixed always-hot, ordinary-sleep or full-restart choice.
//! 4. Assumptions: component recreate costs add up and are independent of the order;
//!    the backend recreates every dropped component exactly; a level's queried semantics
//!    are complete for weights and KV. Smallest counterexample: a backend whose wake
//!    after a weight-discarding sleep silently reuses stale graph addresses.
//! 5. Baseline: in each budget and workload, the best of always-hot, ordinary sleep and
//!    full restart that ran without failures and within the budget.
//! 6. Result: [`RetentionExperiment::claim`]; on the fake substrate at most inconclusive.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use serde::Serialize;

use super::claim::{CellVerdict, ClaimRecord, ClaimText, ComparisonCell, Experiment};
use super::measure::{measure, Measurement, OutsideRecords};
use super::ReadinessError;
use crate::foundation::evidence::{EvidenceRefusal, Optimization, ProbeRegistry};
use crate::foundation::ids::{Clock, ContentKey, MonotonicTime};
use crate::foundation::report::{
    ArrivalMode, BenchId, Label, LatencyObjective, LoadDescription, NoncePlacement, Provenance,
    Quantile, RunRecord,
};
use crate::model_memory::backends::{
    AdmittedTechnique, BackendRuntime, ExperimentApproval, KvRetention, LevelSemantics, SleepLevel,
    SleepPlan, SleepRefusal, Technique, TechniqueRefusal, WeightRetention,
};
use crate::model_memory::bench::corpus::{Corpus, NonceSource};
use crate::model_memory::bench::load::RunnerFactory;
use crate::model_memory::bench::profile::RunnerMode;
use crate::model_memory::bench::rng::SeededRng;
use crate::model_memory::bench::runner::{RequestPlan, RetryPolicy, Script, UserScript};
use crate::model_memory::bench::BenchError;
use crate::model_memory::residency::eviction::{Content, ReconstructibleCopy};

const GENEROUS_NANOS: u64 = 3_600 * 1_000_000_000;

/// The claim record text of this experiment (GPU §4.17).
pub const CLAIM_TEXT: ClaimText = ClaimText {
    contribution: "Per memory budget, choose the fastest-resuming backend-supported retention \
                   level from a per-component recreate-cost table and its Pareto frontier",
    closest_prior_work: "vLLM sleep levels with queried retention semantics (GPU §3.8) and \
                         size-constrained retention with LRU, cost-per-byte and \
                         Landlord/GreedyDual-Size baselines (§2.7)",
    difference_tested: "Selection among backend levels by component costs against a fixed \
                        always-hot, ordinary-sleep or full-restart choice",
    assumptions: &[
        "component recreate costs add up and do not depend on order",
        "the backend recreates every dropped component exactly",
        "a level's queried semantics are complete for weights and KV",
    ],
    smallest_counterexample: "a backend whose wake after a weight-discarding sleep silently \
                              reuses stale graph addresses",
    baseline: "the best of always-hot, ordinary sleep and full restart that ran without \
               failures and within the budget",
};

/// A component of a warm model's execution state (GPU §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    TokenizerConfig,
    CpuProcess,
    GpuContext,
    ProcessedWeights,
    Graphs,
    KvCache,
    Communicators,
}

impl Component {
    pub const ALL: [Self; 7] = [
        Self::TokenizerConfig,
        Self::CpuProcess,
        Self::GpuContext,
        Self::ProcessedWeights,
        Self::Graphs,
        Self::KvCache,
        Self::Communicators,
    ];

    /// What must stay kept for this component to stay kept. Graphs reference the
    /// weights' addresses, so they need the weights kept on the device (§1.1 line 305).
    pub const fn prerequisites(self) -> &'static [Self] {
        match self {
            Self::TokenizerConfig | Self::CpuProcess => &[],
            Self::GpuContext => &[Self::CpuProcess],
            Self::ProcessedWeights | Self::KvCache | Self::Communicators => &[Self::GpuContext],
            Self::Graphs => &[Self::GpuContext, Self::ProcessedWeights],
        }
    }

    /// Only weights and KV have a host copy to offload to.
    pub const fn can_offload(self) -> bool {
        matches!(self, Self::ProcessedWeights | Self::KvCache)
    }
}

/// One component's bytes and recreate costs.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct ComponentCost {
    /// GPU bytes while kept; moved to pinned host memory when offloaded.
    pub gpu_bytes: u64,
    /// Pageable host bytes while kept, such as process memory.
    pub host_bytes: u64,
    /// Recreating it from nothing on resume.
    pub recreate_seconds: f64,
    /// Recreating it with a reusable compile artifact under the exact ABI key.
    pub recreate_with_artifact_seconds: Option<f64>,
    /// Restoring it from its offloaded host copy.
    pub restore_from_host_seconds: Option<f64>,
}

/// Why a component table, a level or a choice was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum RetentionRefusal {
    MissingComponent {
        component: Component,
    },
    InvalidCost {
        component: Component,
        field: &'static str,
    },
    /// A kept or offloaded component whose prerequisite is not kept: a state the backend
    /// cannot safely recreate (GPU §4.5).
    ArtificialState {
        component: Component,
        missing: Component,
    },
    CannotOffload {
        component: Component,
    },
    NoRestoreCost {
        component: Component,
    },
    /// The level was not supplied by the backend; the governor never invents one.
    NotBackendSupported {
        level: String,
    },
    /// The admitted technique does not keep a serving process.
    NotARetainedProcess {
        technique: Technique,
    },
    /// No supported level fits the budget.
    NothingFits,
}

impl fmt::Display for RetentionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingComponent { component } => write!(f, "no cost for {component:?}"),
            Self::InvalidCost { component, field } => {
                write!(f, "{component:?} has an invalid {field}")
            }
            Self::ArtificialState { component, missing } => write!(
                f,
                "keeping {component:?} without {missing:?} is a state the backend cannot \
                 safely recreate"
            ),
            Self::CannotOffload { component } => {
                write!(f, "{component:?} has no host copy to offload to")
            }
            Self::NoRestoreCost { component } => {
                write!(f, "{component:?} is offloaded but has no restore cost")
            }
            Self::NotBackendSupported { level } => write!(
                f,
                "retention level {level} was not supplied by the backend, so it is never used"
            ),
            Self::NotARetainedProcess { technique } => {
                write!(f, "{technique:?} does not keep a serving process")
            }
            Self::NothingFits => f.write_str("no supported retention level fits the budget"),
        }
    }
}

impl std::error::Error for RetentionRefusal {}

/// Every component's costs (GPU §4.5: "Measure the cost of recreating ...
/// independently").
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ComponentTable {
    costs: BTreeMap<Component, ComponentCost>,
}

fn seconds_ok(value: f64) -> bool {
    value.is_finite() && value >= 0.0
}

impl ComponentTable {
    /// Requires every component, finite non-negative seconds, and restore costs only for
    /// components that can be offloaded.
    pub fn new(costs: BTreeMap<Component, ComponentCost>) -> Result<Self, RetentionRefusal> {
        for component in Component::ALL {
            let cost = costs
                .get(&component)
                .ok_or(RetentionRefusal::MissingComponent { component })?;
            let invalid = |field| RetentionRefusal::InvalidCost { component, field };
            if !seconds_ok(cost.recreate_seconds) {
                return Err(invalid("recreate_seconds"));
            }
            if cost
                .recreate_with_artifact_seconds
                .is_some_and(|seconds| !seconds_ok(seconds))
            {
                return Err(invalid("recreate_with_artifact_seconds"));
            }
            match cost.restore_from_host_seconds {
                Some(_) if !component.can_offload() => {
                    return Err(RetentionRefusal::CannotOffload { component });
                }
                Some(seconds) if !seconds_ok(seconds) => {
                    return Err(invalid("restore_from_host_seconds"))
                }
                _ => {}
            }
        }
        Ok(Self { costs })
    }

    pub fn cost(&self, component: Component) -> Result<&ComponentCost, RetentionRefusal> {
        self.costs
            .get(&component)
            .ok_or(RetentionRefusal::MissingComponent { component })
    }
}

/// What a level does with one component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    Kept,
    OffloadedToHost,
    Dropped,
}

/// Bytes a level keeps.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RetainedBytes {
    pub gpu_bytes: u64,
    pub pinned_host_bytes: u64,
    pub pageable_host_bytes: u64,
}

impl RetainedBytes {
    pub fn total(&self) -> u64 {
        self.gpu_bytes
            .saturating_add(self.pinned_host_bytes)
            .saturating_add(self.pageable_host_bytes)
    }
}

/// Where a level came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "origin", rename_all = "snake_case")]
pub enum LevelOrigin {
    /// A process-keeping technique the runtime admitted (P06).
    RetainedProcess {
        technique: Technique,
    },
    /// A queried sleep level the runtime may plan (P06).
    Sleep {
        level: SleepLevel,
        semantics: LevelSemantics,
    },
    FullRestart,
    /// Not from the backend; refused by the governor.
    Proposed,
}

/// What a warm model keeps while idle (GPU §4.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RetentionLevel {
    name: String,
    states: BTreeMap<Component, ComponentState>,
    origin: LevelOrigin,
}

impl RetentionLevel {
    fn uniform(name: &str, state: ComponentState, origin: LevelOrigin) -> Self {
        Self {
            name: name.to_string(),
            states: Component::ALL.into_iter().map(|c| (c, state)).collect(),
            origin,
        }
    }

    /// Everything kept, from a technique the runtime admitted that keeps a serving
    /// process: vLLM's normal loader in its retained process, or llama.cpp's persistent
    /// process.
    pub fn retained_process(admitted: &AdmittedTechnique) -> Result<Self, RetentionRefusal> {
        let technique = admitted.technique();
        if !matches!(
            technique,
            Technique::NormalLoader | Technique::PersistentProcess
        ) {
            return Err(RetentionRefusal::NotARetainedProcess { technique });
        }
        Ok(Self::uniform(
            "retained-process",
            ComponentState::Kept,
            LevelOrigin::RetainedProcess { technique },
        ))
    }

    /// The level a sleep plan enters: the process and GPU context stay, weights and KV
    /// follow the queried semantics, and graphs and communicators, which the semantics
    /// do not state, are recreated.
    pub fn from_sleep(plan: &SleepPlan) -> Self {
        let semantics = plan.semantics();
        let weights = match semantics.weights {
            WeightRetention::OnDevice => ComponentState::Kept,
            WeightRetention::OffloadedToHost => ComponentState::OffloadedToHost,
            WeightRetention::Discarded => ComponentState::Dropped,
        };
        let kv = match semantics.kv_cache {
            KvRetention::Retained => ComponentState::Kept,
            KvRetention::Discarded => ComponentState::Dropped,
        };
        let states = [
            (Component::TokenizerConfig, ComponentState::Kept),
            (Component::CpuProcess, ComponentState::Kept),
            (Component::GpuContext, ComponentState::Kept),
            (Component::ProcessedWeights, weights),
            (Component::Graphs, ComponentState::Dropped),
            (Component::KvCache, kv),
            (Component::Communicators, ComponentState::Dropped),
        ];
        Self {
            name: format!("sleep-level-{}", plan.level()),
            states: states.into_iter().collect(),
            origin: LevelOrigin::Sleep {
                level: plan.level(),
                semantics,
            },
        }
    }

    /// Nothing kept: the process exits and everything is recreated.
    pub fn full_restart() -> Self {
        Self::uniform(
            "full-restart",
            ComponentState::Dropped,
            LevelOrigin::FullRestart,
        )
    }

    /// A level that did not come from the backend, for analysis only; the governor
    /// refuses it.
    pub fn proposed(name: &str, states: BTreeMap<Component, ComponentState>) -> Self {
        Self {
            name: name.to_string(),
            states,
            origin: LevelOrigin::Proposed,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn origin(&self) -> &LevelOrigin {
        &self.origin
    }

    /// A component the level does not name is dropped.
    pub fn state(&self, component: Component) -> ComponentState {
        self.states
            .get(&component)
            .copied()
            .unwrap_or(ComponentState::Dropped)
    }

    /// Refuses a kept component without its kept prerequisites, and an offloaded
    /// component that cannot be offloaded or whose process is gone.
    pub fn validate(&self) -> Result<(), RetentionRefusal> {
        for component in Component::ALL {
            match self.state(component) {
                ComponentState::Kept => {
                    if let Some(missing) = component
                        .prerequisites()
                        .iter()
                        .copied()
                        .find(|prerequisite| self.state(*prerequisite) != ComponentState::Kept)
                    {
                        return Err(RetentionRefusal::ArtificialState { component, missing });
                    }
                }
                ComponentState::OffloadedToHost => {
                    if !component.can_offload() {
                        return Err(RetentionRefusal::CannotOffload { component });
                    }
                    if self.state(Component::CpuProcess) != ComponentState::Kept {
                        return Err(RetentionRefusal::ArtificialState {
                            component,
                            missing: Component::CpuProcess,
                        });
                    }
                }
                ComponentState::Dropped => {}
            }
        }
        Ok(())
    }

    /// The bytes the level keeps under `table`.
    pub fn retained(&self, table: &ComponentTable) -> Result<RetainedBytes, RetentionRefusal> {
        let mut bytes = RetainedBytes::default();
        for component in Component::ALL {
            let cost = table.cost(component)?;
            match self.state(component) {
                ComponentState::Kept => {
                    bytes.gpu_bytes = bytes.gpu_bytes.saturating_add(cost.gpu_bytes);
                    bytes.pageable_host_bytes =
                        bytes.pageable_host_bytes.saturating_add(cost.host_bytes);
                }
                ComponentState::OffloadedToHost => {
                    bytes.pinned_host_bytes =
                        bytes.pinned_host_bytes.saturating_add(cost.gpu_bytes);
                }
                ComponentState::Dropped => {}
            }
        }
        Ok(bytes)
    }

    /// Seconds to resume: each dropped component's recreate cost (with a compile
    /// artifact where `artifacts` has one) plus each offloaded component's restore cost.
    pub fn resume_seconds(
        &self,
        table: &ComponentTable,
        artifacts: &BTreeSet<Component>,
    ) -> Result<f64, RetentionRefusal> {
        let mut seconds = 0.0;
        for component in Component::ALL {
            let cost = table.cost(component)?;
            seconds += match self.state(component) {
                ComponentState::Kept => 0.0,
                ComponentState::OffloadedToHost => cost
                    .restore_from_host_seconds
                    .ok_or(RetentionRefusal::NoRestoreCost { component })?,
                ComponentState::Dropped => match cost.recreate_with_artifact_seconds {
                    Some(faster) if artifacts.contains(&component) => faster,
                    _ => cost.recreate_seconds,
                },
            };
        }
        Ok(seconds)
    }
}

/// One point of the retained-bytes/resume-time plane.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FrontierPoint {
    pub level: String,
    pub retained_bytes: u64,
    pub resume_seconds: f64,
}

/// The Pareto frontier of retained bytes against resume time (GPU §4.5): the points no
/// other point matches or beats on both, by ascending bytes. Of equal points the first
/// is kept.
pub fn pareto_frontier(points: &[FrontierPoint]) -> Vec<FrontierPoint> {
    let mut sorted: Vec<&FrontierPoint> = points.iter().collect();
    sorted.sort_by(|a, b| {
        a.retained_bytes
            .cmp(&b.retained_bytes)
            .then(a.resume_seconds.total_cmp(&b.resume_seconds))
    });
    let mut frontier: Vec<FrontierPoint> = Vec::new();
    for point in sorted {
        let dominated = frontier
            .last()
            .is_some_and(|best| best.resume_seconds <= point.resume_seconds);
        if !dominated {
            frontier.push(point.clone());
        }
    }
    frontier
}

/// Why the backend did not supply a level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "cause", rename_all = "snake_case")]
pub enum LevelRefusal {
    Sleep {
        refusal: SleepRefusal,
    },
    Technique {
        refusal: TechniqueRefusal,
    },
    /// A weight-discarding level without CORE-01 evidence for sleep weight discard.
    Evidence {
        refusal: EvidenceRefusal,
    },
}

/// The retention levels one runtime supports (P06), and why others were refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SupportedLevels {
    levels: Vec<RetentionLevel>,
    refused: Vec<(String, LevelRefusal)>,
}

impl SupportedLevels {
    /// The levels `runtime` supports for weights of content `weights`: a retained
    /// process when it admits vLLM's normal loader or llama.cpp's persistent process,
    /// each queried sleep level it may plan (a weight-discarding level only with `copy`
    /// and while CORE-01 evidence admits the sleep-weight-discard mode), and full
    /// restart, which every backend supports.
    pub fn from_runtime<C: Clock>(
        runtime: &BackendRuntime,
        approvals: &[ExperimentApproval],
        registry: &ProbeRegistry<C>,
        weights: ContentKey,
        copy: Option<ReconstructibleCopy>,
    ) -> Self {
        let mut levels = Vec::new();
        let mut refused = Vec::new();
        let mut process_refusals = Vec::new();
        let mut process = None;
        for technique in [Technique::NormalLoader, Technique::PersistentProcess] {
            match runtime.admit_with_evidence(technique, approvals, registry) {
                Ok(admitted) => {
                    process = RetentionLevel::retained_process(&admitted).ok();
                    if process.is_some() {
                        break;
                    }
                }
                Err(refusal) => process_refusals.push(refusal),
            }
        }
        match process {
            Some(level) => levels.push(level),
            None => refused.extend(process_refusals.into_iter().map(|refusal| {
                (
                    "retained-process".to_string(),
                    LevelRefusal::Technique { refusal },
                )
            })),
        }
        let content = Content::Immutable(weights);
        let discard_mode = runtime
            .plan()
            .recheck(Optimization::SleepWeightDiscard, registry);
        for (level, semantics) in runtime.pinned().levels() {
            if let (false, Err(refusal)) = (semantics.weights.is_retained(), &discard_mode) {
                refused.push((
                    format!("sleep-level-{level}"),
                    LevelRefusal::Evidence {
                        refusal: refusal.clone(),
                    },
                ));
                continue;
            }
            let copy = (!semantics.weights.is_retained()).then_some(copy).flatten();
            match runtime.plan_sleep(level, content, copy, registry) {
                Ok(plan) => levels.push(RetentionLevel::from_sleep(&plan)),
                Err(refusal) => refused.push((
                    format!("sleep-level-{level}"),
                    LevelRefusal::Sleep { refusal },
                )),
            }
        }
        levels.push(RetentionLevel::full_restart());
        Self { levels, refused }
    }

    pub fn levels(&self) -> &[RetentionLevel] {
        &self.levels
    }

    pub fn refused(&self) -> &[(String, LevelRefusal)] {
        &self.refused
    }
}

/// A budget of retained bytes for an idle model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RetentionBudget {
    pub gpu_bytes: u64,
    pub pinned_host_bytes: u64,
}

/// One supported level with its bytes and resume time.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LevelEvaluation {
    pub level: RetentionLevel,
    pub retained: RetainedBytes,
    pub resume_seconds: f64,
}

impl LevelEvaluation {
    fn fits(&self, budget: &RetentionBudget) -> bool {
        self.retained.gpu_bytes <= budget.gpu_bytes
            && self.retained.pinned_host_bytes <= budget.pinned_host_bytes
    }
}

/// Chooses among backend-supported retention levels only (GPU §4.5).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RetentionGovernor {
    table: ComponentTable,
    supported: SupportedLevels,
    artifacts: BTreeSet<Component>,
    evaluations: Vec<LevelEvaluation>,
}

impl RetentionGovernor {
    /// Validates every supported level and evaluates it under `table`; `artifacts` are
    /// the components with a reusable compile artifact under the exact ABI key.
    pub fn new(
        table: ComponentTable,
        supported: SupportedLevels,
        artifacts: BTreeSet<Component>,
    ) -> Result<Self, RetentionRefusal> {
        let mut evaluations = Vec::new();
        for level in &supported.levels {
            level.validate()?;
            evaluations.push(LevelEvaluation {
                level: level.clone(),
                retained: level.retained(&table)?,
                resume_seconds: level.resume_seconds(&table, &artifacts)?,
            });
        }
        Ok(Self {
            table,
            supported,
            artifacts,
            evaluations,
        })
    }

    pub fn supported(&self) -> &SupportedLevels {
        &self.supported
    }

    pub fn evaluations(&self) -> &[LevelEvaluation] {
        &self.evaluations
    }

    /// The Pareto frontier of the supported levels.
    pub fn frontier(&self) -> Vec<FrontierPoint> {
        pareto_frontier(
            &self
                .evaluations
                .iter()
                .map(|evaluation| FrontierPoint {
                    level: evaluation.level.name.clone(),
                    retained_bytes: evaluation.retained.total(),
                    resume_seconds: evaluation.resume_seconds,
                })
                .collect::<Vec<_>>(),
        )
    }

    /// Accepts `level` only when it is valid and exactly one the backend supplied; a
    /// proposed level or any other state is refused.
    pub fn check(&self, level: &RetentionLevel) -> Result<(), RetentionRefusal> {
        level.validate()?;
        if level.origin == LevelOrigin::Proposed || !self.supported.levels.contains(level) {
            return Err(RetentionRefusal::NotBackendSupported {
                level: level.name.clone(),
            });
        }
        Ok(())
    }

    /// The supported level that fits `budget` and resumes fastest; ties go to fewer
    /// retained bytes.
    pub fn choose(&self, budget: &RetentionBudget) -> Result<&LevelEvaluation, RetentionRefusal> {
        self.evaluations
            .iter()
            .filter(|evaluation| evaluation.fits(budget))
            .min_by(|a, b| {
                a.resume_seconds
                    .total_cmp(&b.resume_seconds)
                    .then(a.retained.total().cmp(&b.retained.total()))
            })
            .ok_or(RetentionRefusal::NothingFits)
    }

    /// The resume time of a checked level.
    pub fn resume_seconds(&self, level: &RetentionLevel) -> Result<f64, RetentionRefusal> {
        self.check(level)?;
        level.resume_seconds(&self.table, &self.artifacts)
    }
}

/// The fake runner mode that behaves like `level` (see the module docs); `None` for a
/// sleep level that keeps the weights on the device, which no fake mode models.
pub fn runner_mode(level: &RetentionLevel) -> Option<RunnerMode> {
    match &level.origin {
        LevelOrigin::RetainedProcess { .. } => Some(RunnerMode::RetainedProcess),
        LevelOrigin::Sleep { semantics, .. } => match semantics.weights {
            WeightRetention::OffloadedToHost => Some(RunnerMode::VersionSupportedSleep),
            WeightRetention::Discarded => Some(RunnerMode::VerifiedReload),
            WeightRetention::OnDevice => None,
        },
        LevelOrigin::FullRestart => Some(RunnerMode::FullProcessRestart),
        LevelOrigin::Proposed => None,
    }
}

/// The four strategies GPU §4.5 compares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    AlwaysHot,
    OrdinarySleep,
    FullRestart,
    Selective,
}

impl Strategy {
    pub const ALL: [Self; 4] = [
        Self::AlwaysHot,
        Self::OrdinarySleep,
        Self::FullRestart,
        Self::Selective,
    ];
}

/// A request pattern over two alternating models.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "workload", rename_all = "snake_case")]
pub enum Workload {
    /// Back-to-back requests, this many per model before switching.
    Burst { requests_per_model: u32 },
    /// One request per model with an idle gap before each.
    Gap { gap_nanos: u64 },
}

/// The comparison's parameters.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RetentionSpec {
    /// The two models that alternate; the first starts serving.
    pub models: [Label; 2],
    pub budgets: Vec<(String, RetentionBudget)>,
    pub workloads: Vec<(String, Workload)>,
    pub cycles: u32,
    pub trials: u32,
    /// The backend's ordinary sleep level.
    pub ordinary_sleep: SleepLevel,
    /// VRAM the active model needs beyond its weights and context.
    pub active_headroom_bytes: u64,
    pub max_output_tokens: u32,
    /// Relative p99 difference treated as a tie.
    pub tie_tolerance: f64,
    pub latency_objective: LatencyObjective,
}

/// What one strategy did in one budget and workload.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "run", rename_all = "snake_case")]
pub enum CellRun {
    Measured {
        mode: RunnerMode,
        measurement: Box<Measurement>,
        /// Whether the pinned host memory exceeded the budget.
        over_budget: bool,
    },
    NotRun {
        reason: String,
    },
}

impl CellRun {
    /// Measured, every attempt succeeded and the budget held.
    pub fn compatible(&self) -> bool {
        matches!(self, Self::Measured { measurement, over_budget: false, .. }
            if measurement.success_rate() >= 1.0)
    }

    fn p99_nanos(&self) -> Option<f64> {
        match self {
            Self::Measured { measurement, .. } => measurement.ttft_nanos(Quantile::P99),
            Self::NotRun { .. } => None,
        }
    }
}

/// One strategy in one budget and workload.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct StrategyCell {
    pub budget: String,
    pub workload: String,
    pub strategy: Strategy,
    pub level: Option<String>,
    pub run: CellRun,
}

/// The finished comparison.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RetentionExperiment {
    pub frontier: Vec<FrontierPoint>,
    pub cells: Vec<StrategyCell>,
    pub claim: ClaimRecord,
}

impl RetentionExperiment {
    pub fn cell(&self, budget: &str, workload: &str, strategy: Strategy) -> Option<&StrategyCell> {
        self.cells.iter().find(|cell| {
            cell.budget == budget && cell.workload == workload && cell.strategy == strategy
        })
    }

    /// The GPU §4.17 claim record.
    pub fn claim(&self) -> &ClaimRecord {
        &self.claim
    }
}

fn level_for<'a>(
    governor: &'a RetentionGovernor,
    strategy: Strategy,
    budget: &RetentionBudget,
    ordinary: SleepLevel,
) -> Result<&'a RetentionLevel, String> {
    let find = |matches: &dyn Fn(&LevelOrigin) -> bool| {
        governor
            .supported
            .levels
            .iter()
            .find(|level| matches(&level.origin))
    };
    match strategy {
        Strategy::AlwaysHot => {
            find(&|origin| matches!(origin, LevelOrigin::RetainedProcess { .. }))
                .ok_or_else(|| "the backend supplies no retained process".to_string())
        }
        Strategy::OrdinarySleep => {
            find(&|origin| matches!(origin, LevelOrigin::Sleep { level, .. } if *level == ordinary))
                .ok_or_else(|| format!("the backend supplies no sleep level {ordinary}"))
        }
        Strategy::FullRestart => find(&|origin| matches!(origin, LevelOrigin::FullRestart))
            .ok_or_else(|| "the backend supplies no full restart".to_string()),
        Strategy::Selective => governor
            .choose(budget)
            .map(|evaluation| &evaluation.level)
            .map_err(|refusal| refusal.to_string()),
    }
}

fn script(
    spec: &RetentionSpec,
    workload: Workload,
    nonces: &mut NonceSource,
    fixture: &crate::model_memory::bench::corpus::Fixture,
    start_at: MonotonicTime,
    burst: u32,
) -> Result<Script, ReadinessError> {
    let mut requests = Vec::new();
    let mut push = |model: &Label, gap_before_nanos: u64| -> Result<(), ReadinessError> {
        requests.push(RequestPlan {
            variant: Label::new("retention")?,
            model: model.clone(),
            request: nonces.render(fixture)?,
            max_output_tokens: spec.max_output_tokens,
            deadline_nanos: GENEROUS_NANOS,
            timeout_nanos: GENEROUS_NANOS,
            gap_before_nanos,
            switch_from_previous: false,
            burst,
            check_response: false,
        });
        Ok(())
    };
    for cycle in 0..spec.cycles {
        for model in &spec.models {
            match workload {
                Workload::Burst { requests_per_model } => {
                    for _ in 0..requests_per_model {
                        push(model, 0)?;
                    }
                }
                Workload::Gap { gap_nanos } => {
                    let first = cycle == 0 && *model == spec.models[0];
                    push(model, if first { 0 } else { gap_nanos })?;
                }
            }
        }
    }
    Ok(Script {
        bench: BenchId::Bench02,
        load: LoadDescription {
            concurrent_requests: 1,
            arrival: ArrivalMode::Sequential,
        },
        users: vec![UserScript {
            start_at,
            requests,
            retry: RetryPolicy::NONE,
        }],
        recycle_after_switches: None,
    })
}

fn run_cell(
    base: &RunnerFactory,
    spec: &RetentionSpec,
    mode: RunnerMode,
    budget: &RetentionBudget,
    workload: Workload,
    stream_base: u64,
) -> Result<(CellRun, Vec<RunRecord>), ReadinessError> {
    let [first, second] = &spec.models;
    let mut profile = base.profile.clone();
    profile.mode = mode;
    let mut active = 0u64;
    for model in &spec.models {
        active = active.max(
            profile
                .model(model)?
                .weights_bytes
                .saturating_add(profile.footprint.context_vram_bytes),
        );
    }
    profile.host.vram_capacity_bytes = active
        .saturating_add(spec.active_headroom_bytes)
        .saturating_add(budget.gpu_bytes);
    profile.host.pinned_host_capacity_bytes = budget.pinned_host_bytes.max(1);
    let factory = RunnerFactory {
        profile,
        rules: base.rules.clone(),
        clock: Arc::clone(&base.clock),
        seed: base.seed,
        execution: base.execution.clone(),
    };
    let corpus = Corpus::fast01()?;
    let fixture = corpus.get("fast01-tool-run-tests")?;
    let mut records = Vec::new();
    for trial in 0..spec.trials {
        let stream = stream_base + u64::from(trial);
        let mut runner = match factory.started(stream, first, BenchId::Bench02) {
            Ok((runner, _start)) => runner,
            Err(BenchError::Capacity {
                resource,
                required_bytes,
                available_bytes,
            }) => {
                return Ok((
                    CellRun::NotRun {
                        reason: format!(
                            "{resource} capacity: {required_bytes} bytes needed, \
                             {available_bytes} available"
                        ),
                    },
                    records,
                ))
            }
            Err(other) => return Err(other.into()),
        };
        // Every strategy's first load of the second model reuses a verified host copy.
        runner.warm_host_copy(second)?;
        let mut nonces = NonceSource::new(
            SeededRng::new(factory.stream_seed(stream)),
            NoncePlacement::PromptPrefix,
        );
        // Steady state: each model loaded and parked once the strategy's way, unrecorded.
        let warm_up = RetentionSpec {
            cycles: 1,
            ..spec.clone()
        };
        let warm_up = script(
            &warm_up,
            Workload::Burst {
                requests_per_model: 1,
            },
            &mut nonces,
            fixture,
            runner.clock().now(),
            trial,
        )?;
        runner.serve(&warm_up)?;
        let script = script(
            spec,
            workload,
            &mut nonces,
            fixture,
            runner.clock().now(),
            trial,
        )?;
        records.extend(runner.serve(&script)?.records);
    }
    let over_budget = records.iter().any(|record| {
        record
            .measurements
            .peak_pinned_host_memory_bytes
            .value()
            .is_some_and(|bytes| *bytes > budget.pinned_host_bytes)
    });
    let measurement = measure(
        records.clone(),
        spec.latency_objective,
        OutsideRecords::default(),
    )?;
    Ok((
        CellRun::Measured {
            mode,
            measurement: Box::new(measurement),
            over_budget,
        },
        records,
    ))
}

fn verdict(selective: &CellRun, baselines: &[&CellRun], tolerance: f64) -> CellVerdict {
    let Some(candidate) = selective.p99_nanos().filter(|_| selective.compatible()) else {
        return CellVerdict::Worse;
    };
    let strongest = baselines
        .iter()
        .filter(|run| run.compatible())
        .filter_map(|run| run.p99_nanos())
        .fold(None, |best: Option<f64>, p99| {
            Some(best.map_or(p99, |best| best.min(p99)))
        });
    match strongest {
        None => CellVerdict::Better,
        Some(base) if candidate < base * (1.0 - tolerance) => CellVerdict::Better,
        Some(base) if candidate <= base * (1.0 + tolerance) => CellVerdict::Tie,
        Some(_) => CellVerdict::Worse,
    }
}

/// Runs every strategy in every budget and workload on the fake runners and compares
/// selective retention with the strongest compatible fixed strategy (GPU §4.5).
pub fn run_retention(
    base: &RunnerFactory,
    governor: &RetentionGovernor,
    spec: &RetentionSpec,
) -> Result<RetentionExperiment, ReadinessError> {
    if spec.trials == 0 || spec.cycles == 0 {
        return Err(ReadinessError::InvalidSpec {
            field: "trials",
            reason: "at least one trial and one cycle",
        });
    }
    let mut cells = Vec::new();
    let mut all_records = Vec::new();
    let mut claim_cells = Vec::new();
    let mut stream_base = 0u64;
    for (budget_name, budget) in &spec.budgets {
        for (workload_name, workload) in &spec.workloads {
            let mut runs = BTreeMap::new();
            for strategy in Strategy::ALL {
                stream_base += 1_000;
                let (level, run) = match level_for(governor, strategy, budget, spec.ordinary_sleep)
                {
                    Err(reason) => (None, CellRun::NotRun { reason }),
                    Ok(level) => match runner_mode(level) {
                        None => (
                            Some(level.name.clone()),
                            CellRun::NotRun {
                                reason: "no fake runner mode behaves like this level".to_string(),
                            },
                        ),
                        Some(mode) => {
                            let (run, records) =
                                run_cell(base, spec, mode, budget, *workload, stream_base)?;
                            all_records.extend(records);
                            (Some(level.name.clone()), run)
                        }
                    },
                };
                runs.insert(strategy, run.clone());
                cells.push(StrategyCell {
                    budget: budget_name.clone(),
                    workload: workload_name.clone(),
                    strategy,
                    level,
                    run,
                });
            }
            if let Some(selective) = runs.get(&Strategy::Selective) {
                let baselines: Vec<&CellRun> = runs
                    .iter()
                    .filter(|(strategy, _)| **strategy != Strategy::Selective)
                    .map(|(_, run)| run)
                    .collect();
                claim_cells.push(ComparisonCell {
                    label: format!("{budget_name}/{workload_name}"),
                    verdict: verdict(selective, &baselines, spec.tie_tolerance),
                });
            }
        }
    }
    let provenance = Provenance::of_records(&all_records)?;
    let claim = ClaimRecord::new(
        Experiment::SmallestUsefulRetention,
        CLAIM_TEXT,
        &provenance,
        claim_cells,
    )?;
    Ok(RetentionExperiment {
        frontier: governor.frontier(),
        cells,
        claim,
    })
}

#[cfg(test)]
mod tests;
