//! The bundle method (GPU §4.14 steps 4–7), its object-greedy ablation and the exhaustive
//! optimum for tiny horizons.
//!
//! Each round evaluates every candidate by scheduling the horizon with and without it
//! (step 4), adds the feasible group with the largest positive marginal net score and
//! re-evaluates the rest against the new selection (step 5). Afterwards a bounded local
//! replacement removes one selected group at a time and refills greedily without it, so
//! an early choice can be undone (step 6). When the forecast controller is in demand-only
//! mode, or the explicit work budget runs out, the planner falls back to measured
//! cost-per-byte retention or demand-only, as a typed outcome with its reason (step 7).
//!
//! Marginal values can rise as well as fall (the value function is not submodular), so
//! no approximation guarantee is claimed; [`exhaustive_optimum`] is the reference.

use crate::foundation::ids::Clock;
use crate::model_memory::math::calibration::{DemandOnlyReason, ModeController, SchedulingMode};

use super::candidates::{self, Candidate, CandidateMode, CandidateOrigin};
use super::evaluate::{Evaluation, Evaluator, Outcome, WorkMeter};
use super::horizon::{Horizon, Selection};
use super::BundleError;

/// The largest horizon, in needed objects, [`exhaustive_optimum`] accepts.
pub const EXHAUSTIVE_MAX_OBJECTS: usize = 12;

/// Whether `new` beats `old` by more than rounding.
pub(crate) fn improves(new: f64, old: f64) -> bool {
    new - old > 1e-9 * (1.0 + new.abs() + old.abs())
}

/// The planner's limits (GPU §4.14 steps 3–6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlannerConfig {
    /// The strict planner-time budget, in work units (step 5).
    pub max_work_units: u64,
    /// B: blocking branches per request offered as concurrent blockers (step 3).
    pub max_branches: usize,
    /// Greedy rounds at most (step 5).
    pub max_rounds: usize,
    /// Local replacement rounds; zero disables step 6.
    pub replacement_rounds: usize,
    /// Greedy additions after removing one group in a replacement (step 6).
    pub refill_steps: usize,
    pub mode: CandidateMode,
}

impl PlannerConfig {
    /// The bundle method with three branches, sixteen rounds and two replacement rounds.
    pub fn bundles(max_work_units: u64) -> Self {
        Self {
            max_work_units,
            max_branches: 3,
            max_rounds: 16,
            replacement_rounds: 2,
            refill_steps: 4,
            mode: CandidateMode::Bundles,
        }
    }

    /// Individual positive-gain greedy over single objects, without replacement: the
    /// object-greedy baseline of §4.14.
    pub fn object_greedy(max_work_units: u64) -> Self {
        Self {
            replacement_rounds: 0,
            mode: CandidateMode::SingleObjects,
            ..Self::bundles(max_work_units)
        }
    }

    fn check(&self) -> Result<(), BundleError> {
        if self.max_branches == 0 || self.max_rounds == 0 {
            return Err(BundleError::InvalidValue {
                field: "planner config",
                reason: "branches and rounds must be more than zero",
            });
        }
        Ok(())
    }
}

/// The policy a fallback uses (GPU §4.14 step 7, §2.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FallbackPolicy {
    /// Retain resident objects by measured reload seconds per byte; prepare nothing.
    MeasuredCostPerByte,
    /// Prepare nothing speculatively; retention as for measured cost-per-byte.
    DemandOnly,
}

/// Why the planner fell back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FallbackReason {
    /// The explicit work budget ran out before the plan was finished.
    PlanningBudgetExhausted { spent_units: u64, max_units: u64 },
    /// The forecast controller is in demand-only mode: low confidence, overload or drift.
    Forecast(DemandOnlyReason),
}

/// One decision the planner recorded.
#[derive(Clone, Debug, PartialEq)]
pub enum PlanStep {
    /// A group was added with this marginal net score (step 5).
    Selected {
        group: Selection,
        origin: CandidateOrigin,
        marginal_score: f64,
    },
    /// A selected group was removed and the selection refilled without it (step 6).
    Replaced {
        removed: Selection,
        added: Vec<Selection>,
        net_before: f64,
        net_after: f64,
    },
}

/// What the planner chose.
#[derive(Clone, Debug, PartialEq)]
pub enum PlanOutcome {
    /// The planner finished within its budget.
    Selected {
        selection: Selection,
        evaluation: Box<Evaluation>,
    },
    /// Step 7. The fallback is not evaluated: evaluating needs the budget that ran out.
    Fallback {
        policy: FallbackPolicy,
        reason: FallbackReason,
        selection: Selection,
    },
}

/// A plan with its accounting.
#[derive(Clone, Debug, PartialEq)]
pub struct BundlePlan {
    pub outcome: PlanOutcome,
    /// Selections and replacements, in order.
    pub steps: Vec<PlanStep>,
    /// Work units charged, at most the budget.
    pub work_units: u64,
    pub candidates_generated: u64,
    /// The largest candidate set of one round; never above the step-3 bound.
    pub max_candidates_in_round: u64,
    /// Schedules evaluated.
    pub evaluations: u64,
}

impl BundlePlan {
    /// The chosen X, planned or fallback.
    pub fn selection(&self) -> &Selection {
        match &self.outcome {
            PlanOutcome::Selected { selection, .. } | PlanOutcome::Fallback { selection, .. } => {
                selection
            }
        }
    }

    /// Why the planner fell back, if it did.
    pub fn fallback(&self) -> Option<FallbackReason> {
        match &self.outcome {
            PlanOutcome::Fallback { reason, .. } => Some(*reason),
            PlanOutcome::Selected { .. } => None,
        }
    }
}

/// Retains resident objects by measured reload seconds per byte, highest first, within
/// the retention and scope budgets (the §2.7 baseline the planner falls back to).
pub fn measured_cost_per_byte(horizon: &Horizon) -> Selection {
    let mut ranked: Vec<usize> = (0..horizon.objects().len())
        .filter(|&at| horizon.object(at).resident)
        .collect();
    let per_byte = |at: usize| {
        let object = horizon.object(at);
        object.load.expected().as_secs_f64() / object.bytes as f64
    };
    ranked.sort_by(|&a, &b| per_byte(b).total_cmp(&per_byte(a)).then(a.cmp(&b)));
    let budget = horizon.spec().retention_budget_bytes;
    let mut selection = Selection::new();
    let mut held = 0u64;
    for at in ranked {
        let object = horizon.object(at);
        let Some(total) = held
            .checked_add(object.bytes)
            .filter(|&total| total <= budget)
        else {
            continue;
        };
        if let Some(limit) = horizon.scope_budget(&object.trust_scope) {
            let in_scope = selection
                .iter()
                .filter(|&other| horizon.object(other).trust_scope == object.trust_scope)
                .map(|other| horizon.object(other).bytes)
                .fold(object.bytes, u64::saturating_add);
            if in_scope > limit {
                continue;
            }
        }
        held = total;
        selection.insert(at);
    }
    selection
}

/// Plans X for `horizon` (GPU §4.14 steps 1–7).
pub fn plan(
    horizon: &Horizon,
    clock: &dyn Clock,
    forecast: &ModeController,
    config: PlannerConfig,
) -> Result<BundlePlan, BundleError> {
    config.check()?;
    if forecast.mode() == SchedulingMode::DemandOnly {
        let reason = forecast.reason().unwrap_or(DemandOnlyReason::LowConfidence);
        return Ok(BundlePlan {
            outcome: PlanOutcome::Fallback {
                policy: FallbackPolicy::DemandOnly,
                reason: FallbackReason::Forecast(reason),
                selection: measured_cost_per_byte(horizon),
            },
            steps: Vec::new(),
            work_units: 0,
            candidates_generated: 0,
            max_candidates_in_round: 0,
            evaluations: 0,
        });
    }
    let mut search = Search {
        config,
        meter: WorkMeter::bounded(config.max_work_units),
        steps: Vec::new(),
        candidates_generated: 0,
        max_candidates_in_round: 0,
        evaluations: 0,
    };
    let outcome = match search.run(horizon, clock) {
        Ok((selection, evaluation)) => PlanOutcome::Selected {
            selection,
            evaluation: Box::new(evaluation),
        },
        Err(BundleError::BudgetExhausted {
            spent_units,
            max_units,
        }) => PlanOutcome::Fallback {
            policy: FallbackPolicy::MeasuredCostPerByte,
            reason: FallbackReason::PlanningBudgetExhausted {
                spent_units,
                max_units,
            },
            selection: measured_cost_per_byte(horizon),
        },
        Err(other) => return Err(other),
    };
    Ok(BundlePlan {
        outcome,
        steps: search.steps,
        work_units: search.meter.spent(),
        candidates_generated: search.candidates_generated,
        max_candidates_in_round: search.max_candidates_in_round,
        evaluations: search.evaluations,
    })
}

type Groups = Vec<(Selection, CandidateOrigin)>;

struct Filled {
    selection: Selection,
    evaluation: Evaluation,
    groups: Groups,
    steps: Vec<PlanStep>,
}

struct Search {
    config: PlannerConfig,
    meter: WorkMeter,
    steps: Vec<PlanStep>,
    candidates_generated: u64,
    max_candidates_in_round: u64,
    evaluations: u64,
}

impl Search {
    fn run(
        &mut self,
        horizon: &Horizon,
        clock: &dyn Clock,
    ) -> Result<(Selection, Evaluation), BundleError> {
        let evaluator = Evaluator::new(horizon, clock, &mut self.meter)?;
        self.evaluations = self.evaluations.saturating_add(1);
        let start = evaluator.empty().clone();
        let filled = self.fill(
            &evaluator,
            Selection::new(),
            start,
            Vec::new(),
            None,
            self.config.max_rounds,
        )?;
        self.steps.extend(filled.steps);
        let (mut selection, mut current, mut groups) =
            (filled.selection, filled.evaluation, filled.groups);

        for _ in 0..self.config.replacement_rounds {
            let mut best: Option<(Filled, Selection)> = None;
            for removed_at in 0..groups.len() {
                let removed = groups[removed_at].0.clone();
                let base = selection.difference(&removed);
                if horizon.unclosed(&base).is_some() {
                    continue;
                }
                let Some(base_evaluation) = self.evaluate(&evaluator, &base)?.feasible() else {
                    continue;
                };
                let others: Groups = groups
                    .iter()
                    .enumerate()
                    .filter(|(at, _)| *at != removed_at)
                    .map(|(_, group)| group.clone())
                    .collect();
                let alternative = self.fill(
                    &evaluator,
                    base,
                    base_evaluation,
                    others,
                    Some(&removed),
                    self.config.refill_steps,
                )?;
                let beats_current = improves(alternative.evaluation.net_score, current.net_score);
                let beats_best = best.as_ref().is_none_or(|(known, _)| {
                    improves(alternative.evaluation.net_score, known.evaluation.net_score)
                });
                if beats_current && beats_best {
                    best = Some((alternative, removed));
                }
            }
            let Some((alternative, removed)) = best else {
                break;
            };
            let added = alternative
                .steps
                .iter()
                .filter_map(|step| match step {
                    PlanStep::Selected { group, .. } => Some(group.clone()),
                    PlanStep::Replaced { .. } => None,
                })
                .collect();
            self.steps.push(PlanStep::Replaced {
                removed,
                added,
                net_before: current.net_score,
                net_after: alternative.evaluation.net_score,
            });
            selection = alternative.selection;
            current = alternative.evaluation;
            groups = alternative.groups;
        }
        Ok((selection, current))
    }

    fn evaluate(
        &mut self,
        evaluator: &Evaluator<'_>,
        selection: &Selection,
    ) -> Result<Outcome, BundleError> {
        self.evaluations = self.evaluations.saturating_add(1);
        evaluator.evaluate(selection, &mut self.meter)
    }

    /// Adds the best feasible positive-value group, up to `rounds` times, never the
    /// group equal to `exclude` (GPU §4.14 step 5).
    fn fill(
        &mut self,
        evaluator: &Evaluator<'_>,
        mut selection: Selection,
        mut current: Evaluation,
        mut groups: Groups,
        exclude: Option<&Selection>,
        rounds: usize,
    ) -> Result<Filled, BundleError> {
        let horizon = evaluator.horizon();
        let mut steps = Vec::new();
        for _ in 0..rounds {
            let round = candidates::generate(
                horizon,
                &selection,
                &current,
                self.config.mode,
                self.config.max_branches,
                &mut self.meter,
            )?;
            let generated = u64::try_from(round.len()).unwrap_or(u64::MAX);
            self.candidates_generated = self.candidates_generated.saturating_add(generated);
            self.max_candidates_in_round = self.max_candidates_in_round.max(generated);
            let mut best: Option<(Candidate, Evaluation, f64, u64)> = None;
            for candidate in round {
                if exclude == Some(&candidate.group) {
                    continue;
                }
                let union = selection.union(&candidate.group);
                let Some(evaluation) = self.evaluate(evaluator, &union)?.feasible() else {
                    continue;
                };
                let marginal = evaluation.net_score - current.net_score;
                if !improves(evaluation.net_score, current.net_score) {
                    continue;
                }
                let bytes = horizon.bytes(&candidate.group)?;
                let better = match &best {
                    None => true,
                    Some((known, _, known_marginal, known_bytes)) => {
                        improves(marginal, *known_marginal)
                            || (!improves(*known_marginal, marginal)
                                && (bytes, &candidate.group) < (*known_bytes, &known.group))
                    }
                };
                if better {
                    best = Some((candidate, evaluation, marginal, bytes));
                }
            }
            let Some((candidate, evaluation, marginal, _)) = best else {
                break;
            };
            selection = selection.union(&candidate.group);
            current = evaluation;
            steps.push(PlanStep::Selected {
                group: candidate.group.clone(),
                origin: candidate.origin,
                marginal_score: marginal,
            });
            groups.push((candidate.group, candidate.origin));
        }
        Ok(Filled {
            selection,
            evaluation: current,
            groups,
            steps,
        })
    }
}

/// The best feasible X of a tiny horizon, found by evaluating every subset of its needed
/// objects with the same evaluator (GPU §4.14 first prototype: tiny exhaustive optimal
/// solutions). Ties go to fewer bytes, then the smaller selection.
#[derive(Clone, Debug, PartialEq)]
pub struct Optimum {
    pub selection: Selection,
    pub evaluation: Evaluation,
    /// Subsets examined, the empty one included.
    pub subsets: u64,
    /// Feasible subsets among them.
    pub feasible: u64,
    pub work_units: u64,
}

/// Evaluates every subset of the needed objects; refuses more than
/// [`EXHAUSTIVE_MAX_OBJECTS`].
pub fn exhaustive_optimum(horizon: &Horizon, clock: &dyn Clock) -> Result<Optimum, BundleError> {
    let needed = horizon.needed_objects();
    if needed.len() > EXHAUSTIVE_MAX_OBJECTS {
        return Err(BundleError::TooLargeForExhaustive {
            objects: needed.len(),
            max: EXHAUSTIVE_MAX_OBJECTS,
        });
    }
    let mut meter = WorkMeter::unbounded();
    let evaluator = Evaluator::new(horizon, clock, &mut meter)?;
    let mut best = (Selection::new(), evaluator.empty().clone(), 0u64);
    let mut feasible = 0u64;
    let subsets = 1u64 << needed.len();
    for mask in 1..subsets {
        let selection = Selection::from_indices(
            needed
                .iter()
                .enumerate()
                .filter(|(bit, _)| mask & (1u64 << bit) != 0)
                .map(|(_, &at)| at),
        );
        let Some(evaluation) = evaluator.evaluate(&selection, &mut meter)?.feasible() else {
            continue;
        };
        feasible += 1;
        let bytes = horizon.bytes(&selection)?;
        let better = improves(evaluation.net_score, best.1.net_score)
            || (!improves(best.1.net_score, evaluation.net_score)
                && (bytes, &selection) < (best.2, &best.0));
        if better {
            best = (selection, evaluation, bytes);
        }
    }
    Ok(Optimum {
        selection: best.0,
        evaluation: best.1,
        subsets,
        feasible: feasible + 1,
        work_units: meter.spent(),
    })
}
