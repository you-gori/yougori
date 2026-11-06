//! A predictor behind its recent calibration (GPU §2.9 lines 642–644: "Maintain
//! uncertainty and calibration ... Low confidence, overload or drift returns to
//! demand-only scheduling"; §4.12: "Revert on distribution shift"; GPU-T37 at line 1494:
//! "Predictor sees a phase change or hostile alternation: wasted bytes bounded;
//! demand-only fallback").
//!
//! A [`GuardedPredictor`] ranks the candidates it is given and scores the last ranking
//! against the next request. Its recent record, over at most `window_steps` scored
//! requests, feeds the §2.9 [`ModeController`]: the confidence signal is the recent hit
//! rate of the top forecast, and the calibration-error signal is the recent Brier score
//! of every forecast. When either is poor, as under a pattern built to defeat the
//! predictor or after a phase change, the controller falls back to the demand-only
//! baseline, and it recovers only past its stricter exit thresholds held for its dwell.
//! The guard keeps scoring and learning in the shadow while it holds back, so recovery
//! rests on evidence.
//!
//! Forecasts are acted on only in [`PredictorMode::Assisting`]: never before the
//! predictor is enabled (demand-only is the default), never after an operator rollback
//! until it is enabled again, and never during warm-up, before `min_scored_steps`
//! requests were scored. A ranking only orders the candidates it is given and never adds
//! one, so declared intent and the budget still decide what may be prepared:
//! [`rank_declared_steps`] reorders a workflow's declared branches for the
//! [`PreparationGovernor`](super::super::PreparationGovernor), which still applies its
//! lookahead, byte, value, deadline and ledger bounds to every step.

use std::cmp::Ordering;
use std::collections::VecDeque;

use super::{Forecast, PredictionError, Predictor};
use crate::foundation::ids::MonotonicTime;
use crate::model_memory::math::calibration::{
    CalibrationTracker, DemandOnlyReason, ModeController, ModeSignals, ModeThresholds,
    SchedulingMode,
};
use crate::model_memory::readiness::adoption::governor::{RollbackCause, WorkflowIntent};
use crate::model_memory::readiness::intent::PrepareTarget;

/// The longest window accepted.
pub const MAX_GUARD_WINDOW: usize = 65_536;

/// How the guard judges its predictor.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GuardConfig {
    /// Scored requests the recent signals cover, 1 to [`MAX_GUARD_WINDOW`].
    pub window_steps: usize,
    /// Scored requests before any forecast is acted on, 1 to `window_steps`.
    pub min_scored_steps: usize,
    /// §2.9 thresholds: `confidence` is the recent top-forecast hit rate,
    /// `calibration_error` the recent Brier score, `load_fraction` the caller's.
    pub thresholds: ModeThresholds,
    /// Reliability bins of the overall calibration record.
    pub calibration_bins: usize,
}

impl GuardConfig {
    fn check(self) -> Result<Self, PredictionError> {
        let invalid = |field, reason| Err(PredictionError::InvalidConfig { field, reason });
        if self.window_steps == 0 || self.window_steps > MAX_GUARD_WINDOW {
            return invalid("guard.window_steps", "between 1 and 65536");
        }
        if self.min_scored_steps == 0 || self.min_scored_steps > self.window_steps {
            return invalid("guard.min_scored_steps", "between 1 and window_steps");
        }
        Ok(self)
    }
}

/// Why forecasts are not acted on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaselineCause {
    /// Never enabled (the default), rolled back by an operator, or the §2.9 controller
    /// fell back on low confidence, overload or drift.
    RolledBack(RollbackCause),
    /// Too few requests were scored to judge calibration.
    WarmingUp { scored: u64, needed: u64 },
}

/// Whether forecasts may rank admissible candidates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PredictorMode {
    /// Demand-only: forecasts are scored in the shadow and never acted on.
    Baseline { cause: BaselineCause },
    /// Forecasts may order the candidates that declared intent and the budget admit.
    Assisting,
}

/// One ranking: every candidate's forecast, most likely first (ties keep the candidates'
/// order), and the mode it was made in.
#[derive(Clone, Debug, PartialEq)]
pub struct Ranking<K> {
    pub mode: PredictorMode,
    pub forecasts: Vec<Forecast<K>>,
}

impl<K> Ranking<K> {
    /// The forecasts a caller may act on: all of them while assisting, none otherwise.
    pub fn actionable(&self) -> &[Forecast<K>] {
        match self.mode {
            PredictorMode::Assisting => &self.forecasts,
            PredictorMode::Baseline { .. } => &[],
        }
    }
}

/// One scored request.
#[derive(Clone, Copy, Debug, PartialEq)]
struct StepScore {
    squared_error: f64,
    forecasts: u64,
    top_hit: bool,
}

/// A predictor behind its recent calibration (see the module documentation).
#[derive(Clone, Debug)]
pub struct GuardedPredictor<K, P> {
    predictor: P,
    config: GuardConfig,
    controller: ModeController,
    /// Why forecasts are held back regardless of calibration; `None` once enabled.
    hold: Option<RollbackCause>,
    /// The last ranking, scored at the next request.
    outstanding: Vec<Forecast<K>>,
    recent: VecDeque<StepScore>,
    scored_steps: u64,
    overall: CalibrationTracker,
    fallbacks: u64,
}

impl<K: Clone + PartialEq, P: Predictor<K>> GuardedPredictor<K, P> {
    /// A guard that holds forecasts back until [`Self::enable`]: demand-only is the
    /// default.
    pub fn new(predictor: P, config: GuardConfig) -> Result<Self, PredictionError> {
        let config = config.check()?;
        Ok(Self {
            predictor,
            controller: ModeController::new(config.thresholds)?,
            overall: CalibrationTracker::new(config.calibration_bins)?,
            config,
            hold: Some(RollbackCause::Default),
            outstanding: Vec::new(),
            recent: VecDeque::new(),
            scored_steps: 0,
            fallbacks: 0,
        })
    }

    /// Lets calibrated forecasts be acted on from now on.
    pub fn enable(&mut self) {
        self.hold = None;
    }

    /// The operator rollback: forecasts are held back until enabled again. Scoring and
    /// learning go on in the shadow.
    pub fn roll_back(&mut self) {
        self.hold = Some(RollbackCause::Operator);
    }

    /// Whether forecasts are acted on now, and why not.
    pub fn mode(&self) -> PredictorMode {
        if let Some(cause) = self.hold {
            return PredictorMode::Baseline {
                cause: BaselineCause::RolledBack(cause),
            };
        }
        let needed = u64::try_from(self.config.min_scored_steps).unwrap_or(u64::MAX);
        if self.scored_steps < needed {
            return PredictorMode::Baseline {
                cause: BaselineCause::WarmingUp {
                    scored: self.scored_steps,
                    needed,
                },
            };
        }
        match self.controller.mode() {
            SchedulingMode::Speculative => PredictorMode::Assisting,
            SchedulingMode::DemandOnly => PredictorMode::Baseline {
                cause: BaselineCause::RolledBack(RollbackCause::Controller {
                    reason: self
                        .controller
                        .reason()
                        .unwrap_or(DemandOnlyReason::LowConfidence),
                }),
            },
        }
    }

    /// Ranks `candidates` (a repeated candidate counts once) and keeps the forecasts to
    /// score at the next request. Only these candidates are ever ranked.
    pub fn rank(&mut self, candidates: &[K]) -> Ranking<K> {
        let mut distinct: Vec<K> = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            if !distinct.contains(candidate) {
                distinct.push(candidate.clone());
            }
        }
        let mut forecasts: Vec<(usize, Forecast<K>)> = self
            .predictor
            .forecast(&distinct)
            .into_iter()
            .filter(|forecast| distinct.contains(&forecast.key))
            .enumerate()
            .collect();
        forecasts.sort_by(|(a_at, a), (b_at, b)| {
            b.probability.total_cmp(&a.probability).then(a_at.cmp(b_at))
        });
        let forecasts: Vec<Forecast<K>> = forecasts
            .into_iter()
            .map(|(_, forecast)| forecast)
            .collect();
        self.outstanding = forecasts.clone();
        Ranking {
            mode: self.mode(),
            forecasts,
        }
    }

    /// The next request was `actual`, at `at` on the caller's monotonic clock: scores the
    /// last ranking, teaches the predictor, and once warm feeds the §2.9 controller with
    /// the recent signals and `load_fraction`. Returns the mode from now on.
    pub fn observe(
        &mut self,
        actual: &K,
        at: MonotonicTime,
        load_fraction: f64,
    ) -> Result<PredictorMode, PredictionError> {
        let outstanding = std::mem::take(&mut self.outstanding);
        if let Some(top) = outstanding.first() {
            let mut squared_error = 0.0;
            for forecast in &outstanding {
                let hit = forecast.key == *actual;
                self.overall.record(forecast.probability, hit)?;
                let outcome = if hit { 1.0 } else { 0.0 };
                squared_error += (forecast.probability - outcome).powi(2);
            }
            if self.recent.len() == self.config.window_steps {
                self.recent.pop_front();
            }
            self.recent.push_back(StepScore {
                squared_error,
                forecasts: u64::try_from(outstanding.len()).unwrap_or(u64::MAX),
                top_hit: top.key == *actual,
            });
            self.scored_steps = self.scored_steps.saturating_add(1);
        }
        self.predictor.observe(actual);
        let needed = u64::try_from(self.config.min_scored_steps).unwrap_or(u64::MAX);
        if self.scored_steps >= needed {
            if let (Some(confidence), Some(calibration_error)) =
                (self.recent_top_hit_rate(), self.recent_brier_score())
            {
                let before = self.controller.mode();
                let after = self.controller.observe(
                    at,
                    ModeSignals {
                        confidence,
                        load_fraction,
                        calibration_error,
                    },
                )?;
                if before == SchedulingMode::Speculative && after == SchedulingMode::DemandOnly {
                    self.fallbacks = self.fallbacks.saturating_add(1);
                }
            }
        }
        Ok(self.mode())
    }

    /// The share of recent scored requests whose top forecast was right.
    pub fn recent_top_hit_rate(&self) -> Option<f64> {
        (!self.recent.is_empty()).then(|| {
            self.recent.iter().filter(|score| score.top_hit).count() as f64
                / self.recent.len() as f64
        })
    }

    /// The Brier score of every forecast of the recent scored requests.
    pub fn recent_brier_score(&self) -> Option<f64> {
        let forecasts = self
            .recent
            .iter()
            .fold(0u64, |total, score| total.saturating_add(score.forecasts));
        (forecasts > 0).then(|| {
            self.recent
                .iter()
                .map(|score| score.squared_error)
                .sum::<f64>()
                / forecasts as f64
        })
    }

    /// Every forecast scored so far: Brier score and reliability bins.
    pub fn calibration(&self) -> &CalibrationTracker {
        &self.overall
    }

    /// Requests whose ranking was scored.
    pub fn scored_steps(&self) -> u64 {
        self.scored_steps
    }

    /// Times the controller fell back from assisting to demand-only.
    pub fn fallbacks(&self) -> u64 {
        self.fallbacks
    }

    pub fn controller(&self) -> &ModeController {
        &self.controller
    }

    pub fn predictor(&self) -> &P {
        &self.predictor
    }

    /// Entries held: the predictor's, the recent window and the outstanding ranking.
    pub fn footprint(&self) -> usize {
        self.predictor.footprint() + self.recent.len() + self.outstanding.len()
    }
}

/// Orders a workflow's declared steps by the guard's forecasts of their targets, without
/// adding, dropping or changing any step (§2.9: prediction ranks after queued work and
/// explicit intent). Certain steps (declared probability 1 or more) keep their declared
/// order ahead of the uncertain ones; the uncertain ones follow, most likely target
/// first, ties in declared order. In any baseline mode the declared order is kept. The
/// returned ranking is the one the guard scores at the next request
/// ([`GuardedPredictor::observe`] at `request_arrived`).
pub fn rank_declared_steps<P: Predictor<PrepareTarget>>(
    guard: &mut GuardedPredictor<PrepareTarget, P>,
    intent: WorkflowIntent,
) -> (WorkflowIntent, Ranking<PrepareTarget>) {
    let candidates: Vec<PrepareTarget> = intent.steps.iter().map(|step| step.target).collect();
    let ranking = guard.rank(&candidates);
    if ranking.mode != PredictorMode::Assisting {
        return (intent, ranking);
    }
    let probability_of = |target: &PrepareTarget| {
        ranking
            .forecasts
            .iter()
            .find(|forecast| forecast.key == *target)
            .map_or(0.0, |forecast| forecast.probability)
    };
    let WorkflowIntent {
        execution,
        tenant,
        steps,
    } = intent;
    let mut keyed: Vec<(usize, bool, f64, _)> = steps
        .into_iter()
        .enumerate()
        .map(|(at, step)| {
            let certain = step.probability >= 1.0;
            (at, certain, probability_of(&step.target), step)
        })
        .collect();
    keyed.sort_by(|(a_at, a_certain, a_p, _), (b_at, b_certain, b_p, _)| {
        match (a_certain, b_certain) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (true, true) => a_at.cmp(b_at),
            (false, false) => b_p.total_cmp(a_p).then(a_at.cmp(b_at)),
        }
    });
    let intent = WorkflowIntent {
        execution,
        tenant,
        steps: keyed.into_iter().map(|(_, _, _, step)| step).collect(),
    };
    (intent, ranking)
}
