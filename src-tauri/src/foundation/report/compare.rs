//! Comparison discipline (GPU §1.1, §1.3, §2.1; S7, S8): an objective vector, a verdict
//! that needs a declared objective and flags every other regression, matched
//! configurations, separate cold and warm states, both required baselines, no
//! multiplication of separately measured gains, and experiments with independent trials,
//! mixed traces and ablations.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::claims::Provenance;
use super::error::ReportError;
use super::fidelity::ModeFidelity;
use super::measured::{Measured, NonNegative};
use super::record::{Precision, RunRecord, StartTemperature};
use super::stats::{Quantile, Quotient, UndefinedReason};
use super::text::Label;
use crate::foundation::ids::{Digest, DigestBuilder, ExecutionCategory};

/// Domain of the hardware and client digests in [`MatchedConfiguration`].
pub const MATCHED_CONFIGURATION_DOMAIN: &str = "yougori/report/matched-configuration/v1";

/// Independent trials an effect claim needs. §1.1 replaces "three runs and predictable
/// A/B alternation" with independent trials, so three are not enough.
pub const MIN_INDEPENDENT_TRIALS: u32 = 5;

/// The objectives of §1.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Objective {
    /// Request to first token, including queueing and wake-up.
    TimeToFirstToken,
    /// Sustained throughput while meeting the declared latency objective.
    ThroughputUnderLatencyObjective,
    PeakGpuMemory,
    RetainedGpuMemory,
    PeakHostMemory,
    RetainedHostMemory,
    TransferredBytes,
    StorageReadBytes,
    PreparationCost,
    CostPerCompletedRequest,
    EnergyPerCompletedRequest,
    /// Overall success rate.
    Reliability,
}

/// Which way an objective improves (§1.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    LowerIsBetter,
    HigherIsBetter,
}

impl Objective {
    /// Every §1.3 objective; a verdict checks each of them.
    pub const ALL: [Self; 12] = [
        Self::TimeToFirstToken,
        Self::ThroughputUnderLatencyObjective,
        Self::PeakGpuMemory,
        Self::RetainedGpuMemory,
        Self::PeakHostMemory,
        Self::RetainedHostMemory,
        Self::TransferredBytes,
        Self::StorageReadBytes,
        Self::PreparationCost,
        Self::CostPerCompletedRequest,
        Self::EnergyPerCompletedRequest,
        Self::Reliability,
    ];

    pub const fn direction(self) -> Direction {
        match self {
            Self::ThroughputUnderLatencyObjective | Self::Reliability => Direction::HigherIsBetter,
            _ => Direction::LowerIsBetter,
        }
    }

    pub const fn unit(self) -> &'static str {
        match self {
            Self::TimeToFirstToken => "nanoseconds",
            Self::ThroughputUnderLatencyObjective => "tokens per second",
            Self::PeakGpuMemory
            | Self::RetainedGpuMemory
            | Self::PeakHostMemory
            | Self::RetainedHostMemory
            | Self::TransferredBytes
            | Self::StorageReadBytes => "bytes",
            Self::PreparationCost | Self::CostPerCompletedRequest => "USD",
            Self::EnergyPerCompletedRequest => "joules",
            Self::Reliability => "fraction of initial attempts",
        }
    }
}

/// The latency objective throughput is measured under (§1.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LatencyObjective {
    pub quantile: Quantile,
    pub max_time_to_first_token_nanos: u64,
}

/// One side's value for every §1.3 objective, each measured or explicitly not.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveVector {
    /// The percentile `time_to_first_token_nanos` reports.
    pub time_to_first_token_quantile: Quantile,
    pub latency_objective: LatencyObjective,
    pub time_to_first_token_nanos: Measured<NonNegative>,
    pub throughput_under_latency_objective_tokens_per_second: Measured<NonNegative>,
    pub peak_gpu_memory_bytes: Measured<NonNegative>,
    pub retained_gpu_memory_bytes: Measured<NonNegative>,
    pub peak_host_memory_bytes: Measured<NonNegative>,
    pub retained_host_memory_bytes: Measured<NonNegative>,
    pub transferred_bytes: Measured<NonNegative>,
    pub storage_read_bytes: Measured<NonNegative>,
    pub preparation_cost_usd: Measured<NonNegative>,
    pub cost_per_completed_request_usd: Measured<NonNegative>,
    pub energy_per_completed_request_joules: Measured<NonNegative>,
    pub reliability_success_rate: Measured<NonNegative>,
}

impl ObjectiveVector {
    pub fn get(&self, objective: Objective) -> &Measured<NonNegative> {
        match objective {
            Objective::TimeToFirstToken => &self.time_to_first_token_nanos,
            Objective::ThroughputUnderLatencyObjective => {
                &self.throughput_under_latency_objective_tokens_per_second
            }
            Objective::PeakGpuMemory => &self.peak_gpu_memory_bytes,
            Objective::RetainedGpuMemory => &self.retained_gpu_memory_bytes,
            Objective::PeakHostMemory => &self.peak_host_memory_bytes,
            Objective::RetainedHostMemory => &self.retained_host_memory_bytes,
            Objective::TransferredBytes => &self.transferred_bytes,
            Objective::StorageReadBytes => &self.storage_read_bytes,
            Objective::PreparationCost => &self.preparation_cost_usd,
            Objective::CostPerCompletedRequest => &self.cost_per_completed_request_usd,
            Objective::EnergyPerCompletedRequest => &self.energy_per_completed_request_joules,
            Objective::Reliability => &self.reliability_success_rate,
        }
    }

    fn check(&self) -> Result<(), ReportError> {
        match self.reliability_success_rate.value() {
            Some(rate) if rate.get() > 1.0 => Err(ReportError::InvalidNumber),
            _ => Ok(()),
        }
    }
}

/// The declared objective and the relative tolerance of every other objective (§1.3: an
/// optimization "must improve a declared objective without silently violating others").
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ObjectivePlan {
    declared: Objective,
    relative_tolerances: BTreeMap<Objective, NonNegative>,
}

impl ObjectivePlan {
    /// Declares `declared` and gives every objective `relative_tolerance`.
    pub fn new(declared: Objective, relative_tolerance: f64) -> Result<Self, ReportError> {
        let tolerance = NonNegative::new(relative_tolerance)?;
        Ok(Self {
            declared,
            relative_tolerances: Objective::ALL
                .iter()
                .map(|objective| (*objective, tolerance))
                .collect(),
        })
    }

    /// Sets one objective's relative tolerance explicitly.
    pub fn with_tolerance(
        mut self,
        objective: Objective,
        relative_tolerance: f64,
    ) -> Result<Self, ReportError> {
        self.relative_tolerances
            .insert(objective, NonNegative::new(relative_tolerance)?);
        Ok(self)
    }

    pub fn declared(&self) -> Objective {
        self.declared
    }

    pub fn tolerance(&self, objective: Objective) -> f64 {
        self.relative_tolerances
            .get(&objective)
            .map_or(0.0, |tolerance| tolerance.get())
    }
}

/// One objective's baseline and candidate values.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ObjectiveChange {
    pub objective: Objective,
    pub baseline: f64,
    pub candidate: f64,
    /// (candidate − baseline) / baseline; undefined at a zero baseline.
    pub relative_change: Quotient,
}

impl ObjectiveChange {
    fn new(objective: Objective, baseline: f64, candidate: f64) -> Self {
        Self {
            objective,
            baseline,
            candidate,
            relative_change: Quotient::divide(
                candidate - baseline,
                baseline,
                UndefinedReason::ZeroBaseline,
            ),
        }
    }

    fn improved(&self) -> bool {
        match self.objective.direction() {
            Direction::LowerIsBetter => self.candidate < self.baseline,
            Direction::HigherIsBetter => self.candidate > self.baseline,
        }
    }

    fn regressed_beyond(&self, tolerance: f64) -> bool {
        match self.objective.direction() {
            Direction::LowerIsBetter => self.candidate > self.baseline * (1.0 + tolerance),
            Direction::HigherIsBetter => self.candidate < self.baseline * (1.0 - tolerance),
        }
    }
}

/// The overall result of a verdict (§1.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictStatus {
    /// The declared objective improved, every other objective was measured on both
    /// sides, and none regressed beyond its tolerance.
    Improved,
    /// Improved, but some objectives were not measured, so violations cannot be ruled
    /// out.
    ImprovedWithUnmeasuredObjectives,
    ImprovedWithRegressions,
    NotImproved,
}

/// A candidate-versus-baseline verdict (§1.3).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Verdict {
    pub declared: ObjectiveChange,
    pub regressions: Vec<ObjectiveChange>,
    pub unmeasured: Vec<Objective>,
    pub status: VerdictStatus,
}

/// Assesses `candidate` against `baseline` under `plan`. Both vectors must use the same
/// first-token percentile and latency objective, and the declared objective must be
/// measured on both sides.
pub fn assess(
    plan: &ObjectivePlan,
    candidate: &ObjectiveVector,
    baseline: &ObjectiveVector,
) -> Result<Verdict, ReportError> {
    if candidate.time_to_first_token_quantile != baseline.time_to_first_token_quantile
        || candidate.latency_objective != baseline.latency_objective
    {
        return Err(ReportError::MismatchedObjectiveDeclarations);
    }
    candidate.check()?;
    baseline.check()?;
    let change = |objective: Objective| match (
        baseline.get(objective).value(),
        candidate.get(objective).value(),
    ) {
        (Some(base), Some(cand)) => Some(ObjectiveChange::new(objective, base.get(), cand.get())),
        _ => None,
    };
    let declared = change(plan.declared()).ok_or(ReportError::DeclaredObjectiveNotMeasured)?;
    let mut regressions = Vec::new();
    let mut unmeasured = Vec::new();
    for objective in Objective::ALL {
        if objective == plan.declared() {
            continue;
        }
        match change(objective) {
            Some(change) if change.regressed_beyond(plan.tolerance(objective)) => {
                regressions.push(change)
            }
            Some(_) => {}
            None => unmeasured.push(objective),
        }
    }
    let status = if !declared.improved() {
        VerdictStatus::NotImproved
    } else if !regressions.is_empty() {
        VerdictStatus::ImprovedWithRegressions
    } else if !unmeasured.is_empty() {
        VerdictStatus::ImprovedWithUnmeasuredObjectives
    } else {
        VerdictStatus::Improved
    };
    Ok(Verdict {
        declared,
        regressions,
        unmeasured,
        status,
    })
}

/// What two compared sides must share (S7: "matched model bytes, precision, prompt,
/// output length, hardware and client"; S8: compare local engines on the same host).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchedConfiguration {
    pub model_bytes: Digest,
    pub precision: Precision,
    pub fixture: Digest,
    pub max_output_tokens: u64,
    /// OS, driver, CPU, GPUs and memory.
    pub hardware: Digest,
    /// Client name, version, region and placement.
    pub client: Digest,
    pub tool_template: Measured<Digest>,
    pub execution_category: ExecutionCategory,
}

/// A field of [`MatchedConfiguration`]; a difference makes a cell not comparable (S7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationField {
    ModelBytes,
    Precision,
    Fixture,
    OutputLength,
    Hardware,
    Client,
    ToolTemplate,
    ExecutionCategory,
}

impl MatchedConfiguration {
    /// Extracts the matched fields of a serving record.
    pub fn from_record(record: &RunRecord) -> Result<Self, ReportError> {
        let (Some(model), Some(precision), Some(workload)) = (
            record.model.value(),
            record.precision.value(),
            record.workload.value(),
        ) else {
            return Err(ReportError::MissingConfiguration);
        };
        let host = &record.host;
        let hardware = [
            serde_json::to_vec(&host.os),
            serde_json::to_vec(&host.os_version),
            serde_json::to_vec(&host.gpu_driver),
            serde_json::to_vec(&host.cpu),
            serde_json::to_vec(&host.gpus),
            serde_json::to_vec(&host.host_memory_bytes),
        ]
        .into_iter()
        .try_fold(
            DigestBuilder::new(MATCHED_CONFIGURATION_DOMAIN).str("hardware"),
            |builder, part| part.map(|bytes| builder.bytes(&bytes)),
        )
        .map_err(|_| ReportError::Encoding)?
        .finish();
        let client = serde_json::to_vec(&record.client)
            .map(|bytes| {
                DigestBuilder::new(MATCHED_CONFIGURATION_DOMAIN)
                    .str("client")
                    .bytes(&bytes)
                    .finish()
            })
            .map_err(|_| ReportError::Encoding)?;
        Ok(Self {
            model_bytes: model.weights,
            precision: precision.clone(),
            fixture: workload.fixture.digest,
            max_output_tokens: workload.max_output_tokens,
            hardware,
            client,
            tool_template: workload.tool_schema.as_ref().map(|schema| schema.digest),
            execution_category: record.execution_category,
        })
    }

    /// The fields in which two sides differ; any of them makes a cell not comparable
    /// unless the comparison declares it varied.
    pub fn differences(&self, other: &Self) -> Vec<ConfigurationField> {
        [
            (
                ConfigurationField::ModelBytes,
                self.model_bytes == other.model_bytes,
            ),
            (
                ConfigurationField::Precision,
                self.precision == other.precision,
            ),
            (ConfigurationField::Fixture, self.fixture == other.fixture),
            (
                ConfigurationField::OutputLength,
                self.max_output_tokens == other.max_output_tokens,
            ),
            (
                ConfigurationField::Hardware,
                self.hardware == other.hardware,
            ),
            (ConfigurationField::Client, self.client == other.client),
            (
                ConfigurationField::ToolTemplate,
                self.tool_template == other.tool_template,
            ),
            (
                ConfigurationField::ExecutionCategory,
                self.execution_category == other.execution_category,
            ),
        ]
        .into_iter()
        .filter_map(|(field, same)| (!same).then_some(field))
        .collect()
    }
}

/// What start states a comparison is about (S8: "Run cold and warm states separately";
/// §2.1: "Do not call warm-versus-cold comparisons cold-load improvements").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateComparison {
    /// Both sides cold: the only label for a cold-load improvement.
    ColdLoad,
    WarmLoad,
    HotDispatch,
    /// A warm or hot candidate against a cold baseline: the benefit of retained state,
    /// labelled as such.
    WarmVersusCold,
}

impl StateComparison {
    /// Refuses start states that do not match the label; a warm or hot candidate
    /// against a cold baseline is never a cold-load improvement.
    pub fn check(
        self,
        candidate: StartTemperature,
        baseline: StartTemperature,
    ) -> Result<(), ReportError> {
        use StartTemperature::{Cold, Hot, Warm};
        let matches = match self {
            Self::ColdLoad => candidate == Cold && baseline == Cold,
            Self::WarmLoad => candidate == Warm && baseline == Warm,
            Self::HotDispatch => candidate == Hot && baseline == Hot,
            Self::WarmVersusCold => candidate != Cold && baseline == Cold,
        };
        match (matches, self) {
            (true, _) => Ok(()),
            (false, Self::ColdLoad) if baseline == Cold => Err(ReportError::WarmVersusColdMislabel),
            _ => Err(ReportError::StateMismatch),
        }
    }
}

/// One measured side of a comparison.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ComparisonSide {
    pub name: Label,
    /// A Yougori measurement, an independently reproduced claim (BENCH-13) or a
    /// fake-substrate run, which validates the comparison and backs no claim.
    pub provenance: Provenance,
    pub configuration: MatchedConfiguration,
    pub temperature: StartTemperature,
    pub fidelity: ModeFidelity,
    /// Required for a lossy side (§1.3: approximate modes "need explicit configuration
    /// and accuracy evaluation").
    pub accuracy_evaluation: Measured<Digest>,
    pub objectives: ObjectiveVector,
}

impl ComparisonSide {
    fn check(&self) -> Result<(), ReportError> {
        self.provenance.comparable_evidence()?;
        if self.fidelity == ModeFidelity::Lossy && !self.accuracy_evaluation.is_measured() {
            return Err(ReportError::LossyWithoutAccuracyEvaluation);
        }
        self.objectives.check()
    }
}

/// Which required baseline (§2.1: "Report both an ordinary user workflow baseline and the
/// strongest compatible upstream baseline").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineRole {
    OrdinaryWorkflow,
    StrongestUpstream,
}

/// Why a required baseline is unavailable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineUnavailable {
    NoCompatibleUpstreamRelease,
    UpstreamLacksRequiredCapability,
    NoOrdinaryWorkflowForThisPath,
    ReferenceNotLicensed,
    NeedsUnauthorizedEnvironment,
}

/// A required baseline as supplied: measured sides, or an explicit reason.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Baseline {
    /// The ordinary workflow takes exactly one side; for the upstream baseline every
    /// compatible candidate is supplied and the strongest is chosen.
    Measured { sides: Vec<ComparisonSide> },
    Unavailable {
        reason: BaselineUnavailable,
        detail: Label,
    },
}

/// A baseline in a finished report.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BaselineOutcome {
    Compared {
        baseline: Box<ComparisonSide>,
        verdict: Verdict,
    },
    Unavailable {
        reason: BaselineUnavailable,
        detail: Label,
    },
}

/// What an effect is about; cache and predictor effects need mixed traces (§1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    CacheOrPredictor,
    Other,
}

strict_tagged_enum! {
/// The request sequence an experiment replays (§1.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TracePattern (tag = "kind", wire = TracePatternWire, wire_name = "TracePatternWire") {
    /// Predictable A/B alternation, which overstates cache and predictor effects.
    PredictableAlternation,
    Mixed { seed: u64 },
    Recorded { trace: Digest },
}
}

/// §1.1: "Matched baselines, independent trials, mixed traces and ablations".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentDesign {
    pub effect: EffectClass,
    pub independent_trials: u32,
    pub trace: TracePattern,
    /// The optimizations the candidate enables.
    pub components: Vec<Label>,
    /// Components with an ablation run (the candidate without that component).
    pub ablated_components: Vec<Label>,
}

impl ExperimentDesign {
    /// Refuses fewer than [`MIN_INDEPENDENT_TRIALS`] trials, a predictable A/B trace for
    /// a cache or predictor effect, and a multi-component candidate without an
    /// ablation of each component.
    pub fn check(&self) -> Result<(), ReportError> {
        if self.independent_trials < MIN_INDEPENDENT_TRIALS {
            return Err(ReportError::TooFewTrials {
                trials: self.independent_trials,
                required: MIN_INDEPENDENT_TRIALS,
            });
        }
        if self.effect == EffectClass::CacheOrPredictor
            && self.trace == TracePattern::PredictableAlternation
        {
            return Err(ReportError::PredictableTrace);
        }
        if let Some(component) = self
            .ablated_components
            .iter()
            .find(|ablated| !self.components.contains(ablated))
        {
            return Err(ReportError::UnknownAblation {
                component: component.clone(),
            });
        }
        if self.components.len() > 1 {
            if let Some(component) = self
                .components
                .iter()
                .find(|component| !self.ablated_components.contains(component))
            {
                return Err(ReportError::MissingAblation {
                    component: component.clone(),
                });
            }
        }
        Ok(())
    }
}

/// A comparison report: a candidate against both required baselines (§2.1), under one
/// declared objective (§1.3), one start-state label (S8, §2.1) and an experiment design
/// (§1.1).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ComparisonReport {
    plan: ObjectivePlan,
    states: StateComparison,
    design: ExperimentDesign,
    /// Fields the comparison deliberately varies; any other difference is refused. A
    /// varied model, precision or tool template makes it a different comparison (S8,
    /// §1.3).
    varied: Vec<ConfigurationField>,
    candidate: ComparisonSide,
    ordinary_workflow: BaselineOutcome,
    strongest_upstream: BaselineOutcome,
}

impl ComparisonReport {
    /// Builds the report. Refuses an experiment design without independent trials,
    /// mixed traces or ablations; a varied execution category; a side without comparable
    /// evidence (an unreproduced third-party number) or, when lossy or non-equivalent,
    /// without an accuracy evaluation; an
    /// undeclared configuration difference; start states that do not match `states`;
    /// and a missing baseline without a stated reason. Of several upstream baselines,
    /// the strongest on the declared objective is compared.
    pub fn new(
        plan: ObjectivePlan,
        states: StateComparison,
        design: ExperimentDesign,
        varied: Vec<ConfigurationField>,
        candidate: ComparisonSide,
        ordinary_workflow: Baseline,
        strongest_upstream: Baseline,
    ) -> Result<Self, ReportError> {
        design.check()?;
        if varied.contains(&ConfigurationField::ExecutionCategory) {
            return Err(ReportError::CategoryChanged);
        }
        candidate.check()?;
        // §1.3: quantization and alternate models need explicit configuration and an
        // accuracy evaluation; S8: non-equivalent tool templates are a different
        // comparison.
        let non_equivalent = varied.iter().any(|field| {
            matches!(
                field,
                ConfigurationField::Precision
                    | ConfigurationField::ToolTemplate
                    | ConfigurationField::ModelBytes
            )
        });
        if non_equivalent
            && !(candidate.fidelity == ModeFidelity::Lossy
                && candidate.accuracy_evaluation.is_measured())
        {
            return Err(ReportError::LossyWithoutAccuracyEvaluation);
        }
        let compare =
            |role: BaselineRole, supplied: Baseline| -> Result<BaselineOutcome, ReportError> {
                let sides = match supplied {
                    Baseline::Unavailable { reason, detail } => {
                        return Ok(BaselineOutcome::Unavailable { reason, detail })
                    }
                    Baseline::Measured { sides } => sides,
                };
                if role == BaselineRole::OrdinaryWorkflow && sides.len() > 1 {
                    return Err(ReportError::AmbiguousOrdinaryBaseline);
                }
                let mut best: Option<(ComparisonSide, Verdict)> = None;
                for side in sides {
                    side.check()?;
                    let differences = candidate.configuration.differences(&side.configuration);
                    if differences.contains(&ConfigurationField::ExecutionCategory) {
                        return Err(ReportError::CategoryChanged);
                    }
                    let unexpected: Vec<ConfigurationField> = differences
                        .into_iter()
                        .filter(|field| !varied.contains(field))
                        .collect();
                    if !unexpected.is_empty() {
                        return Err(ReportError::NotComparable { fields: unexpected });
                    }
                    states.check(candidate.temperature, side.temperature)?;
                    let verdict = assess(&plan, &candidate.objectives, &side.objectives)?;
                    let stronger = match &best {
                        None => true,
                        Some((_, current)) => {
                            let challenger = ObjectiveChange::new(
                                plan.declared(),
                                current.declared.baseline,
                                verdict.declared.baseline,
                            );
                            challenger.improved()
                        }
                    };
                    if stronger {
                        best = Some((side, verdict));
                    }
                }
                match best {
                    Some((baseline, verdict)) => Ok(BaselineOutcome::Compared {
                        baseline: Box::new(baseline),
                        verdict,
                    }),
                    None => Err(ReportError::MissingBaseline { which: role }),
                }
            };
        let ordinary_workflow = compare(BaselineRole::OrdinaryWorkflow, ordinary_workflow)?;
        let strongest_upstream = compare(BaselineRole::StrongestUpstream, strongest_upstream)?;
        Ok(Self {
            plan,
            states,
            design,
            varied,
            candidate,
            ordinary_workflow,
            strongest_upstream,
        })
    }

    pub fn ordinary_workflow(&self) -> &BaselineOutcome {
        &self.ordinary_workflow
    }

    pub fn strongest_upstream(&self) -> &BaselineOutcome {
        &self.strongest_upstream
    }

    pub fn candidate(&self) -> &ComparisonSide {
        &self.candidate
    }

    pub fn states(&self) -> StateComparison {
        self.states
    }
}

/// An improvement factor on one objective, measured directly with all its components
/// enabled against one baseline. It carries the verdict's regressions and unmeasured
/// objectives, so it never silently violates the others (§1.3). Both sides must carry
/// Yougori evidence: a fake-substrate side validates the comparison and backs no claim
/// (S12 G0).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ImprovementClaim {
    objective: Objective,
    baseline: f64,
    candidate: f64,
    /// baseline / candidate when lower is better, candidate / baseline otherwise.
    factor: Quotient,
    components: Vec<Label>,
    regressions: Vec<ObjectiveChange>,
    unmeasured: Vec<Objective>,
}

impl ImprovementClaim {
    /// A claim from a report's verdict against one of its baselines. Its components are
    /// those the report's experiment design enabled, never a list supplied beside it
    /// (§1.1). The candidate and that baseline must carry Yougori evidence, and a missing
    /// baseline backs no claim.
    pub fn from_report(
        report: &ComparisonReport,
        baseline: BaselineRole,
    ) -> Result<Self, ReportError> {
        report.candidate.provenance.yougori_evidence()?;
        let outcome = match baseline {
            BaselineRole::OrdinaryWorkflow => &report.ordinary_workflow,
            BaselineRole::StrongestUpstream => &report.strongest_upstream,
        };
        let BaselineOutcome::Compared {
            baseline: side,
            verdict,
        } = outcome
        else {
            return Err(ReportError::MissingBaseline { which: baseline });
        };
        side.provenance.yougori_evidence()?;
        Self::from_verdict(verdict, report.design.components.clone())
    }

    /// A claim from a verdict whose declared objective improved.
    fn from_verdict(verdict: &Verdict, components: Vec<Label>) -> Result<Self, ReportError> {
        if !verdict.declared.improved() {
            return Err(ReportError::NotImproved);
        }
        let change = &verdict.declared;
        let factor = match change.objective.direction() {
            Direction::LowerIsBetter => Quotient::divide(
                change.baseline,
                change.candidate,
                UndefinedReason::ZeroDenominator,
            ),
            Direction::HigherIsBetter => Quotient::divide(
                change.candidate,
                change.baseline,
                UndefinedReason::ZeroBaseline,
            ),
        };
        Ok(Self {
            objective: change.objective,
            baseline: change.baseline,
            candidate: change.candidate,
            factor,
            components,
            regressions: verdict.regressions.clone(),
            unmeasured: verdict.unmeasured.clone(),
        })
    }

    /// Other objectives that regressed beyond tolerance in the measurement.
    pub fn regressions(&self) -> &[ObjectiveChange] {
        &self.regressions
    }

    /// Objectives the measurement could not check.
    pub fn unmeasured(&self) -> &[Objective] {
        &self.unmeasured
    }

    pub fn factor(&self) -> Quotient {
        self.factor
    }

    pub fn components(&self) -> &[Label] {
        &self.components
    }

    /// §2.1: "Do not multiply improvements from overlapping optimizations." Separately
    /// measured claims are never combined into a product; measure the combination
    /// directly and use [`ImprovementClaim::from_report`] instead.
    pub fn combine_by_multiplication(parts: &[ImprovementClaim]) -> Result<Self, ReportError> {
        match parts {
            [single] => Ok(single.clone()),
            _ => Err(ReportError::MultiplicationRefused { parts: parts.len() }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;
    use crate::foundation::report::claims::{ClaimConfiguration, ThirdPartyClaim};
    use crate::foundation::report::fixtures::{label, serving_record};
    use crate::foundation::report::measured::NotMeasuredReason;
    use crate::foundation::report::record::RunSubstrate;
    use crate::foundation::report::text::PublicUrl;
    use chrono::NaiveDate;

    fn value(number: f64) -> Measured<NonNegative> {
        Measured::measured(NonNegative::new(number).unwrap())
    }

    fn vector(ttft_millis: f64, peak_gpu_gib: f64) -> ObjectiveVector {
        ObjectiveVector {
            time_to_first_token_quantile: Quantile::P95,
            latency_objective: LatencyObjective {
                quantile: Quantile::P95,
                max_time_to_first_token_nanos: 500_000_000,
            },
            time_to_first_token_nanos: value(ttft_millis * 1e6),
            throughput_under_latency_objective_tokens_per_second: value(400.0),
            peak_gpu_memory_bytes: value(peak_gpu_gib * 1_073_741_824.0),
            retained_gpu_memory_bytes: value(8.0 * 1_073_741_824.0),
            peak_host_memory_bytes: value(16.0 * 1_073_741_824.0),
            retained_host_memory_bytes: value(4.0 * 1_073_741_824.0),
            transferred_bytes: value(0.0),
            storage_read_bytes: value(15.0 * 1_073_741_824.0),
            preparation_cost_usd: value(0.0),
            cost_per_completed_request_usd: value(0.002),
            energy_per_completed_request_joules: value(30.0),
            reliability_success_rate: value(0.99),
        }
    }

    #[test]
    fn a_verdict_needs_a_declared_objective_and_flags_other_regressions() {
        let plan = ObjectivePlan::new(Objective::TimeToFirstToken, 0.05).unwrap();
        let baseline = vector(300.0, 20.0);
        let clean = assess(&plan, &vector(200.0, 20.5), &baseline).unwrap();
        assert_eq!(clean.status, VerdictStatus::Improved);
        assert!(clean.regressions.is_empty());

        // Faster first token, but peak GPU memory grew 25%: flagged, not hidden.
        let regressed = assess(&plan, &vector(200.0, 25.0), &baseline).unwrap();
        assert_eq!(regressed.status, VerdictStatus::ImprovedWithRegressions);
        assert_eq!(regressed.regressions.len(), 1);
        assert_eq!(regressed.regressions[0].objective, Objective::PeakGpuMemory);
        assert_eq!(regressed.regressions[0].relative_change.value(), Some(0.25));

        let mut unmeasured = vector(200.0, 20.0);
        unmeasured.energy_per_completed_request_joules =
            Measured::not_measured(NotMeasuredReason::InstrumentUnavailable);
        let partial = assess(&plan, &unmeasured, &baseline).unwrap();
        assert_eq!(
            partial.status,
            VerdictStatus::ImprovedWithUnmeasuredObjectives
        );
        assert_eq!(
            partial.unmeasured,
            vec![Objective::EnergyPerCompletedRequest]
        );

        let slower = assess(&plan, &vector(320.0, 20.0), &baseline).unwrap();
        assert_eq!(slower.status, VerdictStatus::NotImproved);

        let mut undeclared = vector(200.0, 20.0);
        undeclared.time_to_first_token_nanos =
            Measured::not_measured(NotMeasuredReason::NotRecorded);
        assert_eq!(
            assess(&plan, &undeclared, &baseline),
            Err(ReportError::DeclaredObjectiveNotMeasured)
        );
        let mut other_quantile = vector(200.0, 20.0);
        other_quantile.time_to_first_token_quantile = Quantile::P50;
        assert_eq!(
            assess(&plan, &other_quantile, &baseline),
            Err(ReportError::MismatchedObjectiveDeclarations)
        );
        // A looser tolerance on one objective is explicit.
        let lenient = plan.with_tolerance(Objective::PeakGpuMemory, 0.30).unwrap();
        assert_eq!(
            assess(&lenient, &vector(200.0, 25.0), &baseline)
                .unwrap()
                .status,
            VerdictStatus::Improved
        );
    }

    #[test]
    fn separately_measured_improvements_are_never_multiplied() {
        let unavailable = || Baseline::Unavailable {
            reason: BaselineUnavailable::NoCompatibleUpstreamRelease,
            detail: label("none"),
        };
        // One measured candidate against the ordinary baseline of 300 ms and 20 GiB; the
        // claim's components are those the experiment design enabled.
        let claim = |candidate: ObjectiveVector, components: Vec<Label>| {
            let mut candidate_side = side("candidate", 300.0, StartTemperature::Cold);
            candidate_side.objectives = candidate;
            let report = ComparisonReport::new(
                plan(),
                StateComparison::ColdLoad,
                design_with(components),
                vec![],
                candidate_side,
                Baseline::Measured {
                    sides: vec![side("ordinary", 300.0, StartTemperature::Cold)],
                },
                unavailable(),
            )
            .unwrap();
            ImprovementClaim::from_report(&report, BaselineRole::OrdinaryWorkflow)
        };
        let loader = claim(vector(200.0, 20.0), vec![label("parallel-loader")]).unwrap();
        let cache = claim(vector(150.0, 20.0), vec![label("prefix-cache")]).unwrap();
        assert_eq!(loader.components(), [label("parallel-loader")]);
        assert_eq!(cache.components(), [label("prefix-cache")]);
        // A claim keeps the regressions of its measurement; it is never silent.
        let costly = claim(vector(150.0, 25.0), vec![label("bigger-graphs")]).unwrap();
        assert_eq!(costly.regressions().len(), 1);
        assert_eq!(costly.regressions()[0].objective, Objective::PeakGpuMemory);
        assert!(cache.regressions().is_empty() && cache.unmeasured().is_empty());
        assert_eq!(loader.factor().value(), Some(1.5));
        assert_eq!(cache.factor().value(), Some(2.0));
        assert_eq!(
            ImprovementClaim::combine_by_multiplication(&[loader.clone(), cache]),
            Err(ReportError::MultiplicationRefused { parts: 2 })
        );
        assert_eq!(
            ImprovementClaim::combine_by_multiplication(std::slice::from_ref(&loader)),
            Ok(loader)
        );
        // The combination is measured directly: 300 ms → 180 ms is 1.67×, not 3×. Its
        // design enables and ablates both components.
        let joint = claim(
            vector(180.0, 20.0),
            vec![label("parallel-loader"), label("prefix-cache")],
        )
        .unwrap();
        assert!((joint.factor().value().unwrap() - 300.0 / 180.0).abs() < 1e-12);
        assert_eq!(
            joint.components(),
            [label("parallel-loader"), label("prefix-cache")]
        );
        assert_eq!(
            claim(vector(320.0, 20.0), vec![]),
            Err(ReportError::NotImproved)
        );
    }

    #[test]
    fn a_claim_names_only_the_components_its_design_enabled() {
        // Review finding: a caller-supplied component list let a claim name "prefix-cache"
        // from a design that enabled only "parallel-loader". The components now come from
        // the design, so the claim names exactly what was measured.
        let report = ComparisonReport::new(
            plan(),
            StateComparison::ColdLoad,
            design(),
            vec![],
            side("candidate", 200.0, StartTemperature::Cold),
            Baseline::Measured {
                sides: vec![side("ordinary", 400.0, StartTemperature::Cold)],
            },
            Baseline::Unavailable {
                reason: BaselineUnavailable::NoCompatibleUpstreamRelease,
                detail: label("none"),
            },
        )
        .unwrap();
        let claim = ImprovementClaim::from_report(&report, BaselineRole::OrdinaryWorkflow).unwrap();
        assert_eq!(claim.components(), [label("parallel-loader")]);
        assert!(!claim.components().contains(&label("prefix-cache")));
    }

    #[test]
    fn warm_versus_cold_is_never_a_cold_load_improvement() {
        use StartTemperature::{Cold, Hot, Warm};
        assert_eq!(StateComparison::ColdLoad.check(Cold, Cold), Ok(()));
        assert_eq!(
            StateComparison::ColdLoad.check(Warm, Cold),
            Err(ReportError::WarmVersusColdMislabel)
        );
        assert_eq!(
            StateComparison::ColdLoad.check(Hot, Cold),
            Err(ReportError::WarmVersusColdMislabel)
        );
        assert_eq!(StateComparison::WarmVersusCold.check(Warm, Cold), Ok(()));
        assert_eq!(
            StateComparison::WarmLoad.check(Warm, Cold),
            Err(ReportError::StateMismatch)
        );
        assert_eq!(StateComparison::HotDispatch.check(Hot, Hot), Ok(()));
    }

    #[test]
    fn experiments_need_independent_trials_mixed_traces_and_ablations() {
        let design = ExperimentDesign {
            effect: EffectClass::CacheOrPredictor,
            independent_trials: MIN_INDEPENDENT_TRIALS,
            trace: TracePattern::Mixed { seed: 11 },
            components: vec![label("prefix-cache"), label("prefetch-predictor")],
            ablated_components: vec![label("prefix-cache"), label("prefetch-predictor")],
        };
        design.check().unwrap();
        let three_runs = ExperimentDesign {
            independent_trials: 3,
            ..design.clone()
        };
        assert_eq!(
            three_runs.check(),
            Err(ReportError::TooFewTrials {
                trials: 3,
                required: MIN_INDEPENDENT_TRIALS
            })
        );
        let alternating = ExperimentDesign {
            trace: TracePattern::PredictableAlternation,
            ..design.clone()
        };
        assert_eq!(alternating.check(), Err(ReportError::PredictableTrace));
        let other_effect = ExperimentDesign {
            effect: EffectClass::Other,
            ..alternating
        };
        other_effect.check().unwrap();
        let unablated = ExperimentDesign {
            ablated_components: vec![label("prefix-cache")],
            ..design.clone()
        };
        assert_eq!(
            unablated.check(),
            Err(ReportError::MissingAblation {
                component: label("prefetch-predictor")
            })
        );
        let unknown = ExperimentDesign {
            ablated_components: vec![
                label("prefix-cache"),
                label("prefetch-predictor"),
                label("other"),
            ],
            ..design
        };
        assert_eq!(
            unknown.check(),
            Err(ReportError::UnknownAblation {
                component: label("other")
            })
        );
    }

    /// The provenance of one real serving attempt.
    fn measured() -> Provenance {
        let mut record = serving_record("op-1", 100);
        record.substrate = RunSubstrate::AuthorizedDisposable {
            authorization: label("disposable-test-host"),
        };
        Provenance::of_records(&[record]).unwrap()
    }

    fn side(name: &str, ttft_millis: f64, temperature: StartTemperature) -> ComparisonSide {
        ComparisonSide {
            name: label(name),
            provenance: measured(),
            configuration: MatchedConfiguration::from_record(&serving_record("op-1", 100)).unwrap(),
            temperature,
            fidelity: ModeFidelity::BitIdentical,
            accuracy_evaluation: Measured::not_measured(NotMeasuredReason::NotApplicable),
            objectives: vector(ttft_millis, 20.0),
        }
    }

    fn design() -> ExperimentDesign {
        design_with(vec![label("parallel-loader")])
    }

    /// A design enabling `components`, each ablated when there are several (§1.1).
    fn design_with(components: Vec<Label>) -> ExperimentDesign {
        ExperimentDesign {
            effect: EffectClass::Other,
            independent_trials: 8,
            trace: TracePattern::Mixed { seed: 3 },
            ablated_components: if components.len() > 1 {
                components.clone()
            } else {
                vec![]
            },
            components,
        }
    }

    fn plan() -> ObjectivePlan {
        ObjectivePlan::new(Objective::TimeToFirstToken, 0.05).unwrap()
    }

    #[test]
    fn a_report_needs_both_baselines_or_a_reason() {
        let candidate = side("candidate", 200.0, StartTemperature::Cold);
        let ordinary = || Baseline::Measured {
            sides: vec![side("ordinary-reload", 400.0, StartTemperature::Cold)],
        };
        // No upstream baseline and no reason: refused.
        assert_eq!(
            ComparisonReport::new(
                plan(),
                StateComparison::ColdLoad,
                design(),
                vec![],
                candidate.clone(),
                ordinary(),
                Baseline::Measured { sides: vec![] },
            ),
            Err(ReportError::MissingBaseline {
                which: BaselineRole::StrongestUpstream
            })
        );
        // An explicit reason is accepted and reported.
        let report = ComparisonReport::new(
            plan(),
            StateComparison::ColdLoad,
            design(),
            vec![],
            candidate.clone(),
            ordinary(),
            Baseline::Unavailable {
                reason: BaselineUnavailable::NoCompatibleUpstreamRelease,
                detail: label("vllm-0.31-preload-needs-upgrade"),
            },
        )
        .unwrap();
        assert!(matches!(
            report.strongest_upstream(),
            BaselineOutcome::Unavailable { .. }
        ));
        // The strongest of several upstream baselines is chosen, not the weakest.
        let report = ComparisonReport::new(
            plan(),
            StateComparison::ColdLoad,
            design(),
            vec![],
            candidate.clone(),
            ordinary(),
            Baseline::Measured {
                sides: vec![
                    side("upstream-default", 380.0, StartTemperature::Cold),
                    side("upstream-tuned", 240.0, StartTemperature::Cold),
                    side("upstream-old", 500.0, StartTemperature::Cold),
                ],
            },
        )
        .unwrap();
        match report.strongest_upstream() {
            BaselineOutcome::Compared { baseline, verdict } => {
                assert_eq!(baseline.name, label("upstream-tuned"));
                assert_eq!(verdict.status, VerdictStatus::Improved);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            ComparisonReport::new(
                plan(),
                StateComparison::ColdLoad,
                design(),
                vec![],
                candidate,
                Baseline::Measured {
                    sides: vec![
                        side("a", 400.0, StartTemperature::Cold),
                        side("b", 400.0, StartTemperature::Cold)
                    ],
                },
                ordinary(),
            ),
            Err(ReportError::AmbiguousOrdinaryBaseline)
        );
    }

    #[test]
    fn a_report_refuses_mislabels_mismatches_and_unreproduced_numbers() {
        let unavailable = || Baseline::Unavailable {
            reason: BaselineUnavailable::NoCompatibleUpstreamRelease,
            detail: label("none"),
        };
        // A warm candidate against a cold baseline labelled as a cold-load improvement.
        assert_eq!(
            ComparisonReport::new(
                plan(),
                StateComparison::ColdLoad,
                design(),
                vec![],
                side("candidate", 200.0, StartTemperature::Warm),
                Baseline::Measured {
                    sides: vec![side("ordinary", 400.0, StartTemperature::Cold)]
                },
                unavailable(),
            ),
            Err(ReportError::WarmVersusColdMislabel)
        );
        // A different quantization is a different comparison, and needs an accuracy
        // evaluation.
        let mut quantized = side("candidate", 200.0, StartTemperature::Cold);
        quantized.configuration.precision.quantization = label("awq-int4");
        let ordinary = || Baseline::Measured {
            sides: vec![side("ordinary", 400.0, StartTemperature::Cold)],
        };
        assert_eq!(
            ComparisonReport::new(
                plan(),
                StateComparison::ColdLoad,
                design(),
                vec![],
                quantized.clone(),
                ordinary(),
                unavailable(),
            ),
            Err(ReportError::NotComparable {
                fields: vec![ConfigurationField::Precision]
            })
        );
        assert_eq!(
            ComparisonReport::new(
                plan(),
                StateComparison::ColdLoad,
                design(),
                vec![ConfigurationField::Precision],
                quantized.clone(),
                ordinary(),
                unavailable(),
            ),
            Err(ReportError::LossyWithoutAccuracyEvaluation)
        );
        quantized.fidelity = ModeFidelity::Lossy;
        quantized.accuracy_evaluation = Measured::measured(digest("yougori/test/v1", &[b"eval"]));
        ComparisonReport::new(
            plan(),
            StateComparison::ColdLoad,
            design(),
            vec![ConfigurationField::Precision],
            quantized,
            ordinary(),
            unavailable(),
        )
        .unwrap();
        // An alternate model cannot hide under a memory setting either (§1.3).
        let mut alternate = side("candidate", 200.0, StartTemperature::Cold);
        alternate.configuration.model_bytes = digest("yougori/test/v1", &[b"smaller-model"]);
        assert_eq!(
            ComparisonReport::new(
                plan(),
                StateComparison::ColdLoad,
                design(),
                vec![ConfigurationField::ModelBytes],
                alternate,
                ordinary(),
                unavailable(),
            ),
            Err(ReportError::LossyWithoutAccuracyEvaluation)
        );
        // The execution category can never vary.
        assert_eq!(
            ComparisonReport::new(
                plan(),
                StateComparison::ColdLoad,
                design(),
                vec![ConfigurationField::ExecutionCategory],
                side("candidate", 200.0, StartTemperature::Cold),
                ordinary(),
                unavailable(),
            ),
            Err(ReportError::CategoryChanged)
        );
        // A vendor's published number cannot be a baseline until reproduced.
        let mut vendor = side("vendor-claim", 150.0, StartTemperature::Cold);
        vendor.provenance = Provenance::ThirdPartyHistorical {
            claim: ThirdPartyClaim {
                source: PublicUrl::new("https://example.org/benchmarks/latency").unwrap(),
                published_on: NaiveDate::from_ymd_opt(2026, 5, 1).unwrap(),
                retrieved_on: NaiveDate::from_ymd_opt(2026, 10, 27).unwrap(),
                configuration: ClaimConfiguration::Unspecified,
                metric: label("ttft-p50"),
                value: NonNegative::new(150.0).unwrap(),
                unit: label("ms"),
            },
        };
        assert_eq!(
            ComparisonReport::new(
                plan(),
                StateComparison::ColdLoad,
                design(),
                vec![],
                side("candidate", 200.0, StartTemperature::Cold),
                ordinary(),
                Baseline::Measured {
                    sides: vec![vendor]
                },
            ),
            Err(ReportError::ThirdPartyNotReproduced)
        );
    }

    #[test]
    fn a_fake_substrate_side_validates_a_comparison_and_backs_no_claim() {
        // FAST-01: CPU fixtures validate schema and comparisons; S12 G0: fakes prove the
        // contract, not the performance.
        let fake = Provenance::of_records(&[serving_record("op-1", 100)]).unwrap();
        assert!(fake.is_fake_substrate());
        let unavailable = || Baseline::Unavailable {
            reason: BaselineUnavailable::NoCompatibleUpstreamRelease,
            detail: label("none"),
        };
        let report_with = |candidate: Provenance, ordinary: Provenance| {
            let mut candidate_side = side("candidate", 200.0, StartTemperature::Cold);
            candidate_side.provenance = candidate;
            let mut ordinary_side = side("ordinary", 400.0, StartTemperature::Cold);
            ordinary_side.provenance = ordinary;
            ComparisonReport::new(
                plan(),
                StateComparison::ColdLoad,
                design(),
                vec![],
                candidate_side,
                Baseline::Measured {
                    sides: vec![ordinary_side],
                },
                unavailable(),
            )
        };
        // Two fake sides: the comparison validates and the verdict is computed.
        let simulated = report_with(fake.clone(), fake.clone()).unwrap();
        let BaselineOutcome::Compared { verdict, .. } = simulated.ordinary_workflow() else {
            panic!("the fake comparison was not compared");
        };
        assert_eq!(verdict.status, VerdictStatus::Improved);
        assert_eq!(
            ImprovementClaim::from_report(&simulated, BaselineRole::OrdinaryWorkflow),
            Err(ReportError::FakeSubstrateIsNotEvidence)
        );
        // A measured candidate against a fake baseline claims nothing either.
        let half = report_with(measured(), fake).unwrap();
        assert_eq!(
            ImprovementClaim::from_report(&half, BaselineRole::OrdinaryWorkflow),
            Err(ReportError::FakeSubstrateIsNotEvidence)
        );
        // Both measured: the claim stands, and an unavailable baseline backs none.
        let real = report_with(measured(), measured()).unwrap();
        let claim = ImprovementClaim::from_report(&real, BaselineRole::OrdinaryWorkflow).unwrap();
        assert_eq!(claim.factor().value(), Some(2.0));
        assert_eq!(
            ImprovementClaim::from_report(&real, BaselineRole::StrongestUpstream),
            Err(ReportError::MissingBaseline {
                which: BaselineRole::StrongestUpstream
            })
        );
    }

    #[test]
    fn a_hand_written_provenance_backs_no_improvement_claim() {
        // Review finding (compare.rs from_report): a measured provenance written by hand
        // passed the evidence check. It is now refused when read, so a side's provenance
        // can only be rebuilt from its records.
        let zeros = "0".repeat(64);
        let written = format!(r#"{{"kind":"yougori_measured","evidence":"{zeros}"}}"#);
        assert!(serde_json::from_str::<Provenance>(&written).is_err());
        // The only usable measured provenance is rebuilt from records.
        assert!(measured().yougori_evidence().is_ok());
    }
}
