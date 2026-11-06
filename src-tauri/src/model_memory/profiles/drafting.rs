//! FAST-04 drafting control (S13 line 244).
//!
//! Drafting is enabled only for a pinned engine, model and method combination recorded
//! in the compatibility matrix; an engine upgrade is another engine, with its own matrix
//! and rollback. Each drafted setting is compared with no drafting under the same
//! hardware, driver, model and load, at single and mixed concurrency. Quality is greedy
//! exactness where the configuration promises it and the declared quality gates
//! otherwise. Drafting is turned off or lowered where verification wastes capacity or
//! harms the interactive objective. No acceptance rate is a target: the DSpark paper's
//! 60–85% is not a Yougori target.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::settings::{ComparisonConditions, EngineRef, NotComparable};
use crate::foundation::ids::{Digest, DigestBuilder};
use crate::model_memory::identity::LogicalModelIdentity;

/// A drafting method a checkpoint may support (FAST-04: MTP, EAGLE or DSpark).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DraftMethod {
    /// Multi-token prediction heads in the checkpoint.
    #[serde(rename = "mtp")]
    Mtp,
    #[serde(rename = "eagle")]
    Eagle,
    #[serde(rename = "dspark")]
    DSpark,
}

impl DraftMethod {
    /// The stable tag hashed into identities.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Mtp => "mtp",
            Self::Eagle => "eagle",
            Self::DSpark => "dspark",
        }
    }
}

/// Drafting as a profile runs it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DraftingSetting {
    pub method: DraftMethod,
    /// The drafter's logical model (T07); `None` when the drafter is part of the target, as
    /// MTP heads are.
    pub drafter: Option<LogicalModelIdentity>,
    /// Tokens drafted per verification step.
    pub speculative_tokens: u32,
}

impl DraftingSetting {
    pub(super) fn feed(&self, builder: DigestBuilder) -> DigestBuilder {
        let builder = builder.str(self.method.tag());
        let builder = match &self.drafter {
            Some(drafter) => builder.str("drafter").digest(drafter.digest()),
            None => builder.str("no_drafter"),
        };
        builder.u64(u64::from(self.speculative_tokens))
    }
}

/// One row of the pinned compatibility matrix (FAST-04 "check the pinned
/// engine/model/method combination").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DraftingCompatibility {
    pub engine: EngineRef,
    /// The target's logical model (T07).
    pub model: LogicalModelIdentity,
    pub method: DraftMethod,
    pub drafter: Option<LogicalModelIdentity>,
    /// Whether this method and configuration promise output identical to no drafting under
    /// greedy decoding; only then is greedy exactness the quality comparison.
    pub promises_greedy_exactness: bool,
    pub max_speculative_tokens: u32,
}

/// The pinned compatibility matrix. Each engine, model, method and drafter combination
/// appears at most once; anything absent is not supported.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DraftingMatrix {
    rows: Vec<DraftingCompatibility>,
}

impl DraftingMatrix {
    pub fn new(rows: Vec<DraftingCompatibility>) -> Result<Self, MatrixError> {
        for (index, row) in rows.iter().enumerate() {
            if row.max_speculative_tokens == 0 {
                return Err(MatrixError::ZeroSpeculativeTokens { method: row.method });
            }
            if rows.iter().skip(index + 1).any(|other| {
                other.engine == row.engine
                    && other.model == row.model
                    && other.method == row.method
                    && other.drafter == row.drafter
            }) {
                return Err(MatrixError::RepeatedCombination { method: row.method });
            }
        }
        Ok(Self { rows })
    }

    /// The row for exactly this combination.
    pub fn row(
        &self,
        engine: &EngineRef,
        model: &LogicalModelIdentity,
        method: DraftMethod,
        drafter: Option<&LogicalModelIdentity>,
    ) -> Option<&DraftingCompatibility> {
        self.rows.iter().find(|row| {
            row.engine == *engine
                && row.model == *model
                && row.method == method
                && row.drafter.as_ref() == drafter
        })
    }

    pub fn rows(&self) -> &[DraftingCompatibility] {
        &self.rows
    }
}

/// Why a matrix was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum MatrixError {
    RepeatedCombination { method: DraftMethod },
    ZeroSpeculativeTokens { method: DraftMethod },
}

impl fmt::Display for MatrixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RepeatedCombination { method } => write!(
                f,
                "the {} combination appears twice in the drafting matrix",
                method.tag()
            ),
            Self::ZeroSpeculativeTokens { method } => {
                write!(f, "the {} row allows no speculative tokens", method.tag())
            }
        }
    }
}

impl std::error::Error for MatrixError {}

/// Measurements at one concurrency (FAST-04: BENCH-01/04 measure accepted length,
/// steps/s, per-user speed, aggregate throughput, p95 and memory).
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadPoint {
    /// Tokens emitted per verification step, counting the token the target adds; 1.0
    /// means no drafted token was accepted. 1.0 without drafting.
    pub mean_accepted_tokens_per_step: f64,
    pub steps_per_second: f64,
    pub per_user_tokens_per_second: f64,
    pub aggregate_tokens_per_second: f64,
    pub p95_latency_seconds: f64,
    pub peak_memory_bytes: u64,
}

impl LoadPoint {
    fn is_valid(&self) -> bool {
        [
            self.mean_accepted_tokens_per_step,
            self.steps_per_second,
            self.per_user_tokens_per_second,
            self.aggregate_tokens_per_second,
            self.p95_latency_seconds,
        ]
        .iter()
        .all(|value| value.is_finite() && *value >= 0.0)
    }
}

strict_tagged_enum! {
/// Quality evidence for one drafted setting (FAST-04; line 250).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QualityEvidence (tag = "quality", wire = QualityEvidenceWire, wire_name = "QualityEvidenceWire") {
    /// Greedy outputs compared with no drafting.
    GreedyExactness { identical: bool, report: Digest },
    /// The declared quality gates, one result per layer of line 250.
    DeclaredGates {
        /// Exact protocol and tool-schema conformance (S9).
        protocol_conformance: bool,
        /// Model behaviour against a comparable reference.
        model_behavior: bool,
        /// Completed agent tasks, every attempt counted (BENCH-04).
        agent_tasks: bool,
        report: Digest,
    },
    NotMeasured,
}
}

/// A layer of quality evidence (line 250).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityLayer {
    ProtocolConformance,
    ModelBehavior,
    AgentTasks,
}

/// No drafting, measured under the conditions every trial must share.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DraftingBaseline {
    pub conditions: ComparisonConditions,
    pub single: LoadPoint,
    pub mixed: LoadPoint,
}

/// One drafted setting, measured at single and mixed concurrency.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DraftingTrial {
    pub conditions: ComparisonConditions,
    pub speculative_tokens: u32,
    pub single: LoadPoint,
    pub mixed: LoadPoint,
    pub quality: QualityEvidence,
}

impl DraftingTrial {
    /// Accepted drafted tokens per drafted token at single concurrency, for reports; no
    /// decision compares it with a target.
    pub fn acceptance_rate(&self) -> Option<f64> {
        (self.speculative_tokens > 0).then(|| {
            (self.single.mean_accepted_tokens_per_step - 1.0) / f64::from(self.speculative_tokens)
        })
    }
}

/// What drafting must serve.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftingObjective {
    /// Per-user speed and latency.
    Interactive,
    /// Aggregate throughput.
    Throughput,
}

/// One drafting decision to make.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DraftingRequest {
    pub engine: EngineRef,
    pub model: LogicalModelIdentity,
    pub method: DraftMethod,
    pub drafter: Option<LogicalModelIdentity>,
    pub objective: DraftingObjective,
    /// The speculative tokens in use now, if drafting is on.
    pub current_speculative_tokens: Option<u32>,
    /// The memory the profile may use on each GPU.
    pub memory_limit_bytes_per_device: u64,
}

/// How a decision changes the drafting in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "change", rename_all = "snake_case")]
pub enum DraftingChange {
    Enabled,
    Kept,
    Lowered { from: u32 },
    Raised { from: u32 },
}

/// The interactive measure a trial made worse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractiveMeasure {
    PerUserSpeedSingle,
    PerUserSpeedMixed,
    P95LatencySingle,
    P95LatencyMixed,
}

/// Why one drafted setting cannot be used.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "rejection", rename_all = "snake_case")]
pub enum TrialRejection {
    /// Measured under other hardware, driver, model or load than the baseline.
    NotComparable {
        difference: NotComparable,
    },
    /// A measurement is negative or not a number.
    InvalidMeasurement,
    /// Outside 1 to the matrix's maximum.
    OutsidePinnedRange {
        max_speculative_tokens: u32,
    },
    /// No drafted token was accepted, so every verification was wasted.
    NoDraftAccepted {
        mean_accepted_tokens_per_step: f64,
    },
    QualityNotMeasured,
    /// Greedy exactness was offered for a configuration that does not promise it; the
    /// declared quality gates apply instead.
    ExactnessNotPromised,
    /// The configuration promises greedy exactness, and it was not compared.
    ExactnessNotShown,
    /// Greedy outputs differed although exactness is promised.
    OutputsDiffer,
    /// A declared quality layer did not pass.
    QualityGateFailed {
        layer: QualityLayer,
    },
    ExceedsMemory {
        peak_memory_bytes: u64,
        limit_bytes: u64,
    },
    /// Verification wastes capacity: lower aggregate throughput at mixed concurrency.
    WastesCapacity {
        aggregate_tokens_per_second: f64,
        baseline_tokens_per_second: f64,
    },
    HarmsInteractive {
        measure: InteractiveMeasure,
    },
    /// No better than no drafting for the objective.
    NoGain,
}

/// One rejected drafted setting.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RejectedTrial {
    pub speculative_tokens: u32,
    pub reason: TrialRejection,
}

/// Why drafting is off.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum DraftingOff {
    /// The exact engine, model, method and drafter are not in the pinned matrix.
    NotInPinnedMatrix,
    /// The baseline was measured with another model.
    BaselineForOtherModel,
    InvalidBaseline,
    /// Every drafted setting was rejected, or none was measured.
    NoTrialHelps {
        rejected: Vec<RejectedTrial>,
    },
}

/// The FAST-04 decision.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "drafting", rename_all = "snake_case")]
pub enum DraftingDecision {
    Off {
        reason: DraftingOff,
    },
    On {
        setting: DraftingSetting,
        change: DraftingChange,
        /// Drafted settings that were not chosen because they failed.
        rejected: Vec<RejectedTrial>,
    },
}

/// Decides drafting for `request` from measured trials.
///
/// Drafting stays off unless the exact combination is in `matrix`. A trial is rejected
/// when it was measured under other conditions than `baseline`, lies outside the pinned
/// range, accepted no drafted token, lacks its quality evidence, exceeds the memory
/// limit, lowers aggregate throughput at mixed concurrency, or, for the interactive
/// objective, lowers per-user speed or raises p95 latency at either concurrency. Of the
/// rest, the one best for the objective is chosen, fewer speculative tokens on a tie, and
/// the change from the current setting is named.
pub fn decide_drafting(
    matrix: &DraftingMatrix,
    request: &DraftingRequest,
    baseline: &DraftingBaseline,
    trials: &[DraftingTrial],
) -> DraftingDecision {
    let off = |reason| DraftingDecision::Off { reason };
    let Some(row) = matrix.row(
        &request.engine,
        &request.model,
        request.method,
        request.drafter.as_ref(),
    ) else {
        return off(DraftingOff::NotInPinnedMatrix);
    };
    if baseline.conditions.model != request.model {
        return off(DraftingOff::BaselineForOtherModel);
    }
    if !baseline.single.is_valid() || !baseline.mixed.is_valid() {
        return off(DraftingOff::InvalidBaseline);
    }
    let mut rejected = Vec::new();
    let mut best: Option<&DraftingTrial> = None;
    for trial in trials {
        match judge(row, request, baseline, trial) {
            Err(reason) => rejected.push(RejectedTrial {
                speculative_tokens: trial.speculative_tokens,
                reason,
            }),
            Ok(()) if best.is_none_or(|best| better(request.objective, trial, best)) => {
                best = Some(trial);
            }
            Ok(()) => {}
        }
    }
    let Some(best) = best else {
        return off(DraftingOff::NoTrialHelps { rejected });
    };
    let chosen = best.speculative_tokens;
    let change = match request.current_speculative_tokens {
        None => DraftingChange::Enabled,
        Some(current) if current == chosen => DraftingChange::Kept,
        Some(current) if chosen < current => DraftingChange::Lowered { from: current },
        Some(current) => DraftingChange::Raised { from: current },
    };
    DraftingDecision::On {
        setting: DraftingSetting {
            method: request.method,
            drafter: request.drafter,
            speculative_tokens: chosen,
        },
        change,
        rejected,
    }
}

fn judge(
    row: &DraftingCompatibility,
    request: &DraftingRequest,
    baseline: &DraftingBaseline,
    trial: &DraftingTrial,
) -> Result<(), TrialRejection> {
    baseline
        .conditions
        .compare(&trial.conditions)
        .map_err(|difference| TrialRejection::NotComparable { difference })?;
    if !trial.single.is_valid() || !trial.mixed.is_valid() {
        return Err(TrialRejection::InvalidMeasurement);
    }
    if trial.speculative_tokens == 0 || trial.speculative_tokens > row.max_speculative_tokens {
        return Err(TrialRejection::OutsidePinnedRange {
            max_speculative_tokens: row.max_speculative_tokens,
        });
    }
    let accepted = trial
        .single
        .mean_accepted_tokens_per_step
        .min(trial.mixed.mean_accepted_tokens_per_step);
    if accepted <= 1.0 {
        return Err(TrialRejection::NoDraftAccepted {
            mean_accepted_tokens_per_step: accepted,
        });
    }
    quality(row, trial.quality)?;
    let peak_memory_bytes = trial
        .single
        .peak_memory_bytes
        .max(trial.mixed.peak_memory_bytes);
    if peak_memory_bytes > request.memory_limit_bytes_per_device {
        return Err(TrialRejection::ExceedsMemory {
            peak_memory_bytes,
            limit_bytes: request.memory_limit_bytes_per_device,
        });
    }
    if trial.mixed.aggregate_tokens_per_second < baseline.mixed.aggregate_tokens_per_second {
        return Err(TrialRejection::WastesCapacity {
            aggregate_tokens_per_second: trial.mixed.aggregate_tokens_per_second,
            baseline_tokens_per_second: baseline.mixed.aggregate_tokens_per_second,
        });
    }
    match request.objective {
        DraftingObjective::Interactive => {
            let harms = [
                (
                    trial.single.per_user_tokens_per_second
                        < baseline.single.per_user_tokens_per_second,
                    InteractiveMeasure::PerUserSpeedSingle,
                ),
                (
                    trial.mixed.per_user_tokens_per_second
                        < baseline.mixed.per_user_tokens_per_second,
                    InteractiveMeasure::PerUserSpeedMixed,
                ),
                (
                    trial.single.p95_latency_seconds > baseline.single.p95_latency_seconds,
                    InteractiveMeasure::P95LatencySingle,
                ),
                (
                    trial.mixed.p95_latency_seconds > baseline.mixed.p95_latency_seconds,
                    InteractiveMeasure::P95LatencyMixed,
                ),
            ];
            if let Some((_, measure)) = harms.into_iter().find(|(harmed, _)| *harmed) {
                return Err(TrialRejection::HarmsInteractive { measure });
            }
            if trial.single.per_user_tokens_per_second <= baseline.single.per_user_tokens_per_second
            {
                return Err(TrialRejection::NoGain);
            }
        }
        DraftingObjective::Throughput => {
            if trial.mixed.aggregate_tokens_per_second <= baseline.mixed.aggregate_tokens_per_second
            {
                return Err(TrialRejection::NoGain);
            }
        }
    }
    Ok(())
}

/// Greedy exactness only where the configuration promises it, declared gates otherwise.
fn quality(row: &DraftingCompatibility, evidence: QualityEvidence) -> Result<(), TrialRejection> {
    match (row.promises_greedy_exactness, evidence) {
        (_, QualityEvidence::NotMeasured) => Err(TrialRejection::QualityNotMeasured),
        (
            true,
            QualityEvidence::GreedyExactness {
                identical: true, ..
            },
        ) => Ok(()),
        (
            true,
            QualityEvidence::GreedyExactness {
                identical: false, ..
            },
        ) => Err(TrialRejection::OutputsDiffer),
        (true, QualityEvidence::DeclaredGates { .. }) => Err(TrialRejection::ExactnessNotShown),
        (false, QualityEvidence::GreedyExactness { .. }) => {
            Err(TrialRejection::ExactnessNotPromised)
        }
        (
            false,
            QualityEvidence::DeclaredGates {
                protocol_conformance,
                model_behavior,
                agent_tasks,
                ..
            },
        ) => match [
            (protocol_conformance, QualityLayer::ProtocolConformance),
            (model_behavior, QualityLayer::ModelBehavior),
            (agent_tasks, QualityLayer::AgentTasks),
        ]
        .into_iter()
        .find(|(passed, _)| !passed)
        {
            Some((_, layer)) => Err(TrialRejection::QualityGateFailed { layer }),
            None => Ok(()),
        },
    }
}

fn better(objective: DraftingObjective, trial: &DraftingTrial, best: &DraftingTrial) -> bool {
    let score = |trial: &DraftingTrial| match objective {
        DraftingObjective::Interactive => trial.single.per_user_tokens_per_second,
        DraftingObjective::Throughput => trial.mixed.aggregate_tokens_per_second,
    };
    let (candidate, current) = (score(trial), score(best));
    candidate > current
        || (candidate == current && trial.speculative_tokens < best.speculative_tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_memory::identity::LogicalModelSpec;
    use crate::model_memory::profiles::testkit::{
        d, engine, logical, logical_spec, single_gpu, GIB,
    };

    /// A model identity distinct from the target's, named by `label`.
    fn other_model(label: &str) -> LogicalModelIdentity {
        LogicalModelSpec {
            tokenizer: d(label),
            ..logical_spec()
        }
        .identity()
    }

    fn drafter() -> LogicalModelIdentity {
        other_model("eagle drafter")
    }

    fn conditions() -> ComparisonConditions {
        ComparisonConditions {
            hardware: single_gpu().identity(),
            driver: "580.95.05".to_owned(),
            model: logical(),
            load: d("fast-01 mixed load"),
        }
    }

    fn row(promises_greedy_exactness: bool) -> DraftingCompatibility {
        DraftingCompatibility {
            engine: engine(),
            model: logical(),
            method: DraftMethod::Eagle,
            drafter: Some(drafter()),
            promises_greedy_exactness,
            max_speculative_tokens: 4,
        }
    }

    fn matrix(promises_greedy_exactness: bool) -> DraftingMatrix {
        DraftingMatrix::new(vec![row(promises_greedy_exactness)]).unwrap()
    }

    fn request(objective: DraftingObjective) -> DraftingRequest {
        DraftingRequest {
            engine: engine(),
            model: logical(),
            method: DraftMethod::Eagle,
            drafter: Some(drafter()),
            objective,
            current_speculative_tokens: None,
            memory_limit_bytes_per_device: 20 * GIB,
        }
    }

    fn point(accepted: f64, per_user: f64, aggregate: f64, p95: f64) -> LoadPoint {
        LoadPoint {
            mean_accepted_tokens_per_step: accepted,
            steps_per_second: per_user / accepted,
            per_user_tokens_per_second: per_user,
            aggregate_tokens_per_second: aggregate,
            p95_latency_seconds: p95,
            peak_memory_bytes: 18 * GIB,
        }
    }

    fn baseline() -> DraftingBaseline {
        DraftingBaseline {
            conditions: conditions(),
            single: point(1.0, 40.0, 40.0, 4.0),
            mixed: point(1.0, 20.0, 160.0, 9.0),
        }
    }

    /// A drafted trial with the given acceptance, measured speeds and passing gates.
    fn trial(k: u32, accepted: f64, single_per_user: f64, mixed_aggregate: f64) -> DraftingTrial {
        DraftingTrial {
            conditions: conditions(),
            speculative_tokens: k,
            single: point(accepted, single_per_user, single_per_user, 3.5),
            mixed: point(accepted, mixed_aggregate / 8.0, mixed_aggregate, 8.5),
            quality: gates(true, true, true),
        }
    }

    fn gates(
        protocol_conformance: bool,
        model_behavior: bool,
        agent_tasks: bool,
    ) -> QualityEvidence {
        QualityEvidence::DeclaredGates {
            protocol_conformance,
            model_behavior,
            agent_tasks,
            report: d("gates"),
        }
    }

    #[test]
    fn helpful_drafting_is_enabled() {
        let decision = decide_drafting(
            &matrix(false),
            &request(DraftingObjective::Interactive),
            &baseline(),
            &[trial(2, 2.2, 70.0, 210.0), trial(4, 2.6, 75.0, 200.0)],
        );
        assert_eq!(
            decision,
            DraftingDecision::On {
                setting: DraftingSetting {
                    method: DraftMethod::Eagle,
                    drafter: Some(drafter()),
                    speculative_tokens: 4,
                },
                change: DraftingChange::Enabled,
                rejected: Vec::new(),
            }
        );
    }

    #[test]
    fn drafting_turns_off_at_low_acceptance() {
        // Nothing accepted: every verification step is wasted.
        let none_accepted = decide_drafting(
            &matrix(false),
            &request(DraftingObjective::Interactive),
            &baseline(),
            &[trial(4, 1.0, 41.0, 161.0)],
        );
        assert_eq!(
            none_accepted,
            DraftingDecision::Off {
                reason: DraftingOff::NoTrialHelps {
                    rejected: vec![RejectedTrial {
                        speculative_tokens: 4,
                        reason: TrialRejection::NoDraftAccepted {
                            mean_accepted_tokens_per_step: 1.0
                        },
                    }]
                }
            }
        );
        // Low acceptance: verification costs more than it saves at mixed concurrency.
        let low = decide_drafting(
            &matrix(false),
            &request(DraftingObjective::Interactive),
            &baseline(),
            &[trial(4, 1.15, 38.0, 120.0)],
        );
        assert_eq!(
            low,
            DraftingDecision::Off {
                reason: DraftingOff::NoTrialHelps {
                    rejected: vec![RejectedTrial {
                        speculative_tokens: 4,
                        reason: TrialRejection::WastesCapacity {
                            aggregate_tokens_per_second: 120.0,
                            baseline_tokens_per_second: 160.0,
                        },
                    }]
                }
            }
        );
    }

    #[test]
    fn drafting_is_lowered_when_the_current_setting_wastes_capacity() {
        let mut current = request(DraftingObjective::Interactive);
        current.current_speculative_tokens = Some(4);
        let decision = decide_drafting(
            &matrix(false),
            &current,
            &baseline(),
            &[trial(4, 1.6, 55.0, 150.0), trial(2, 1.7, 52.0, 175.0)],
        );
        let DraftingDecision::On {
            setting,
            change,
            rejected,
        } = decision
        else {
            panic!("expected drafting to stay on at a lower setting");
        };
        assert_eq!(setting.speculative_tokens, 2);
        assert_eq!(change, DraftingChange::Lowered { from: 4 });
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].speculative_tokens, 4);
    }

    #[test]
    fn drafting_that_harms_the_interactive_objective_is_off() {
        let mut slower_alone = trial(3, 1.8, 35.0, 200.0);
        slower_alone.single.p95_latency_seconds = 3.0;
        let mut worse_tail = trial(2, 2.0, 60.0, 200.0);
        worse_tail.single.p95_latency_seconds = 4.5;
        let mut slower_mixed = trial(1, 1.5, 50.0, 200.0);
        slower_mixed.mixed.per_user_tokens_per_second = 15.0;
        let decision = decide_drafting(
            &matrix(false),
            &request(DraftingObjective::Interactive),
            &baseline(),
            &[slower_alone, worse_tail, slower_mixed],
        );
        let DraftingDecision::Off {
            reason: DraftingOff::NoTrialHelps { rejected },
        } = decision
        else {
            panic!("expected drafting off");
        };
        let measures: Vec<TrialRejection> =
            rejected.into_iter().map(|trial| trial.reason).collect();
        assert_eq!(
            measures,
            vec![
                TrialRejection::HarmsInteractive {
                    measure: InteractiveMeasure::PerUserSpeedSingle
                },
                TrialRejection::HarmsInteractive {
                    measure: InteractiveMeasure::P95LatencySingle
                },
                TrialRejection::HarmsInteractive {
                    measure: InteractiveMeasure::PerUserSpeedMixed
                },
            ]
        );
    }

    #[test]
    fn throughput_drafting_needs_more_aggregate_throughput() {
        let decision = decide_drafting(
            &matrix(false),
            &request(DraftingObjective::Throughput),
            &baseline(),
            &[trial(2, 1.9, 30.0, 160.0), trial(3, 2.1, 30.0, 190.0)],
        );
        let DraftingDecision::On {
            setting, rejected, ..
        } = decision
        else {
            panic!("expected drafting on");
        };
        assert_eq!(setting.speculative_tokens, 3);
        assert_eq!(rejected[0].reason, TrialRejection::NoGain);
    }

    #[test]
    fn no_acceptance_rate_is_a_target() {
        // 50% acceptance that helps stays on; 75% acceptance, inside the paper's 60–85%,
        // that hurts is off.
        let helpful = trial(2, 2.0, 60.0, 200.0);
        assert_eq!(helpful.acceptance_rate(), Some(0.5));
        assert!(matches!(
            decide_drafting(
                &matrix(false),
                &request(DraftingObjective::Interactive),
                &baseline(),
                &[helpful]
            ),
            DraftingDecision::On { .. }
        ));
        let hurtful = trial(4, 4.0, 39.0, 150.0);
        assert_eq!(hurtful.acceptance_rate(), Some(0.75));
        assert!(matches!(
            decide_drafting(
                &matrix(false),
                &request(DraftingObjective::Interactive),
                &baseline(),
                &[hurtful]
            ),
            DraftingDecision::Off { .. }
        ));
    }

    #[test]
    fn only_the_pinned_combination_is_enabled() {
        let trials = [trial(2, 2.2, 70.0, 210.0)];
        let mut upgraded = request(DraftingObjective::Interactive);
        upgraded.engine.image = d("upgraded image");
        let mut other_release = request(DraftingObjective::Interactive);
        other_release.engine.release = crate::foundation::evidence::BackendRelease::new(
            crate::foundation::evidence::Backend::Vllm,
            "0.31.0",
        )
        .unwrap();
        let mut foreign_model = request(DraftingObjective::Interactive);
        foreign_model.model = other_model("other checkpoint");
        let mut other_method = request(DraftingObjective::Interactive);
        other_method.method = DraftMethod::DSpark;
        let mut other_drafter = request(DraftingObjective::Interactive);
        other_drafter.drafter = Some(other_model("other drafter"));
        for unpinned in [
            upgraded,
            other_release,
            foreign_model,
            other_method,
            other_drafter,
        ] {
            assert_eq!(
                decide_drafting(&matrix(false), &unpinned, &baseline(), &trials),
                DraftingDecision::Off {
                    reason: DraftingOff::NotInPinnedMatrix
                },
                "{unpinned:?}"
            );
        }
        let beyond = trial(5, 2.5, 80.0, 220.0);
        let DraftingDecision::Off {
            reason: DraftingOff::NoTrialHelps { rejected },
        } = decide_drafting(
            &matrix(false),
            &request(DraftingObjective::Interactive),
            &baseline(),
            &[beyond],
        )
        else {
            panic!("expected drafting off");
        };
        assert_eq!(
            rejected[0].reason,
            TrialRejection::OutsidePinnedRange {
                max_speculative_tokens: 4
            }
        );
    }

    #[test]
    fn greedy_exactness_only_where_promised() {
        let exact = QualityEvidence::GreedyExactness {
            identical: true,
            report: d("greedy"),
        };
        // Not promised: greedy exactness is not the comparison.
        let mut offered = trial(2, 2.2, 70.0, 210.0);
        offered.quality = exact;
        let DraftingDecision::Off {
            reason: DraftingOff::NoTrialHelps { rejected },
        } = decide_drafting(
            &matrix(false),
            &request(DraftingObjective::Interactive),
            &baseline(),
            &[offered.clone()],
        )
        else {
            panic!("expected drafting off");
        };
        assert_eq!(rejected[0].reason, TrialRejection::ExactnessNotPromised);
        // Promised: exactness is compared, and the declared gates do not replace it.
        assert!(matches!(
            decide_drafting(
                &matrix(true),
                &request(DraftingObjective::Interactive),
                &baseline(),
                &[offered]
            ),
            DraftingDecision::On { .. }
        ));
        let gates_only = trial(2, 2.2, 70.0, 210.0);
        let mut differs = trial(2, 2.2, 70.0, 210.0);
        differs.quality = QualityEvidence::GreedyExactness {
            identical: false,
            report: d("greedy"),
        };
        let with_gates = |quality: QualityEvidence| {
            let mut gated = trial(2, 2.2, 70.0, 210.0);
            gated.quality = quality;
            gated
        };
        let mut unmeasured = trial(2, 2.2, 70.0, 210.0);
        unmeasured.quality = QualityEvidence::NotMeasured;
        let reasons = |promised: bool, trial: DraftingTrial| match decide_drafting(
            &matrix(promised),
            &request(DraftingObjective::Interactive),
            &baseline(),
            &[trial],
        ) {
            DraftingDecision::Off {
                reason: DraftingOff::NoTrialHelps { rejected },
            } => rejected[0].reason.clone(),
            other => panic!("expected drafting off, got {other:?}"),
        };
        assert_eq!(reasons(true, gates_only), TrialRejection::ExactnessNotShown);
        assert_eq!(reasons(true, differs), TrialRejection::OutputsDiffer);
        // Every layer of line 250 must pass: protocol, model behaviour and agent tasks.
        for (quality, layer) in [
            (gates(false, true, true), QualityLayer::ProtocolConformance),
            (gates(true, false, true), QualityLayer::ModelBehavior),
            (gates(true, true, false), QualityLayer::AgentTasks),
        ] {
            assert_eq!(
                reasons(false, with_gates(quality)),
                TrialRejection::QualityGateFailed { layer }
            );
        }
        assert_eq!(
            reasons(false, unmeasured),
            TrialRejection::QualityNotMeasured
        );
    }

    #[test]
    fn trials_must_match_the_baseline_conditions() {
        let mut other_driver = trial(2, 2.2, 70.0, 210.0);
        other_driver.conditions.driver = "575.0".to_owned();
        let DraftingDecision::Off {
            reason: DraftingOff::NoTrialHelps { rejected },
        } = decide_drafting(
            &matrix(false),
            &request(DraftingObjective::Interactive),
            &baseline(),
            &[other_driver],
        )
        else {
            panic!("expected drafting off");
        };
        assert!(matches!(
            rejected[0].reason,
            TrialRejection::NotComparable { .. }
        ));
        let mut foreign = baseline();
        foreign.conditions.model = other_model("other checkpoint");
        assert_eq!(
            decide_drafting(
                &matrix(false),
                &request(DraftingObjective::Interactive),
                &foreign,
                &[]
            ),
            DraftingDecision::Off {
                reason: DraftingOff::BaselineForOtherModel
            }
        );
    }

    #[test]
    fn memory_and_invalid_measurements_reject() {
        let mut heavy = trial(2, 2.2, 70.0, 210.0);
        heavy.mixed.peak_memory_bytes = 21 * GIB;
        let mut broken = trial(3, 2.2, 70.0, 210.0);
        broken.single.p95_latency_seconds = f64::NAN;
        let DraftingDecision::Off {
            reason: DraftingOff::NoTrialHelps { rejected },
        } = decide_drafting(
            &matrix(false),
            &request(DraftingObjective::Interactive),
            &baseline(),
            &[heavy, broken],
        )
        else {
            panic!("expected drafting off");
        };
        assert_eq!(
            rejected[0].reason,
            TrialRejection::ExceedsMemory {
                peak_memory_bytes: 21 * GIB,
                limit_bytes: 20 * GIB
            }
        );
        assert_eq!(rejected[1].reason, TrialRejection::InvalidMeasurement);
        let mut bad_baseline = baseline();
        bad_baseline.mixed.aggregate_tokens_per_second = -1.0;
        assert_eq!(
            decide_drafting(
                &matrix(false),
                &request(DraftingObjective::Interactive),
                &bad_baseline,
                &[]
            ),
            DraftingDecision::Off {
                reason: DraftingOff::InvalidBaseline
            }
        );
    }

    #[test]
    fn the_matrix_refuses_repeats_and_empty_ranges() {
        assert_eq!(
            DraftingMatrix::new(vec![row(false), row(true)]),
            Err(MatrixError::RepeatedCombination {
                method: DraftMethod::Eagle
            })
        );
        let mut empty = row(false);
        empty.max_speculative_tokens = 0;
        assert_eq!(
            DraftingMatrix::new(vec![empty]),
            Err(MatrixError::ZeroSpeculativeTokens {
                method: DraftMethod::Eagle
            })
        );
    }

    #[test]
    fn quality_evidence_refuses_unknown_fields() {
        let unit: QualityEvidence = serde_json::from_str(r#"{"quality":"not_measured"}"#).unwrap();
        assert_eq!(unit, QualityEvidence::NotMeasured);
        assert_eq!(
            serde_json::to_string(&QualityEvidence::NotMeasured).unwrap(),
            r#"{"quality":"not_measured"}"#
        );
        assert!(serde_json::from_str::<QualityEvidence>(
            r#"{"quality":"not_measured","identical":true}"#
        )
        .is_err());
        let report = d("gates").to_hex();
        assert!(serde_json::from_str::<QualityEvidence>(&format!(
            r#"{{"quality":"declared_gates","protocol_conformance":true,"model_behavior":true,"agent_tasks":true,"report":"{report}","extra":1}}"#
        ))
        .is_err());
    }
}
