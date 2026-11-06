//! Uncertainty, calibration and the demand-only fallback (GPU §2.9).
//!
//! Prefetch predictions are tracked with a Brier score and reliability bins. Low
//! confidence, overload or drift switches scheduling to demand-only; it switches back
//! only past stricter thresholds held for a dwell time, so it does not flap.

use std::fmt;
use std::time::Duration;

use super::{non_negative, probability, InputError};
use crate::foundation::ids::MonotonicTime;

/// Why a calibration or mode computation was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum CalibrationError {
    Input(InputError),
    /// An observation is earlier than the previous one.
    ClockWentBack,
}

impl From<InputError> for CalibrationError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl fmt::Display for CalibrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => error.fmt(f),
            Self::ClockWentBack => f.write_str("an observation is earlier than the last one"),
        }
    }
}

impl std::error::Error for CalibrationError {}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct BinTotals {
    count: u64,
    probability_sum: f64,
    used: u64,
}

/// One reliability bin: predictions in `[lower, upper)` (the last bin includes 1).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ReliabilityBin {
    pub lower: f64,
    pub upper: f64,
    pub count: u64,
    pub mean_predicted: f64,
    pub observed_frequency: f64,
}

/// Calibration of predicted use probabilities against what was used (GPU §2.9).
#[derive(Clone, Debug, PartialEq)]
pub struct CalibrationTracker {
    bins: Vec<BinTotals>,
    squared_error_sum: f64,
    count: u64,
}

impl CalibrationTracker {
    /// A tracker with `bin_count` equal-width reliability bins over [0, 1] (GPU §2.9).
    pub fn new(bin_count: usize) -> Result<Self, CalibrationError> {
        if bin_count == 0 {
            return Err(InputError::NotPositive { field: "bin_count" }.into());
        }
        Ok(Self {
            bins: vec![BinTotals::default(); bin_count],
            squared_error_sum: 0.0,
            count: 0,
        })
    }

    /// Records one prediction and whether its bytes were used.
    pub fn record(
        &mut self,
        predicted_probability: f64,
        used: bool,
    ) -> Result<(), CalibrationError> {
        let p = probability("predicted_probability", predicted_probability)?;
        let outcome = if used { 1.0 } else { 0.0 };
        let last = self.bins.len() - 1;
        let index = ((p * self.bins.len() as f64) as usize).min(last);
        let bin = &mut self.bins[index];
        bin.count += 1;
        bin.probability_sum += p;
        bin.used += u64::from(used);
        self.squared_error_sum += (p - outcome) * (p - outcome);
        self.count += 1;
        Ok(())
    }

    /// How many predictions were recorded.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Mean of `(p - outcome)^2`; `None` before the first record.
    pub fn brier_score(&self) -> Option<f64> {
        (self.count > 0).then(|| self.squared_error_sum / self.count as f64)
    }

    /// The bins that hold at least one prediction.
    pub fn reliability_bins(&self) -> Vec<ReliabilityBin> {
        let width = 1.0 / self.bins.len() as f64;
        self.bins
            .iter()
            .enumerate()
            .filter(|(_, bin)| bin.count > 0)
            .map(|(index, bin)| ReliabilityBin {
                lower: index as f64 * width,
                upper: (index + 1) as f64 * width,
                count: bin.count,
                mean_predicted: bin.probability_sum / bin.count as f64,
                observed_frequency: bin.used as f64 / bin.count as f64,
            })
            .collect()
    }

    /// `sum_b (n_b/N) * |mean predicted_b - observed frequency_b|`; `None` before the
    /// first record.
    pub fn expected_calibration_error(&self) -> Option<f64> {
        (self.count > 0).then(|| {
            self.reliability_bins()
                .iter()
                .map(|bin| {
                    bin.count as f64 / self.count as f64
                        * (bin.mean_predicted - bin.observed_frequency).abs()
                })
                .sum()
        })
    }
}

/// How transfers are scheduled (GPU §2.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulingMode {
    /// Demand transfers plus speculative prefetch within its budget.
    Speculative,
    /// Demand transfers only.
    DemandOnly,
}

/// Why scheduling fell back to demand-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DemandOnlyReason {
    LowConfidence,
    Overload,
    Drift,
}

/// What the fallback watches.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ModeSignals {
    /// The predictor's calibrated confidence, in [0, 1].
    pub confidence: f64,
    /// Load on the shared resources as a fraction of capacity; may exceed 1.
    pub load_fraction: f64,
    /// Recent calibration error, such as the expected calibration error; drift raises
    /// it.
    pub calibration_error: f64,
}

/// Thresholds with a hysteresis band: demand-only is entered at one value and left only
/// at a stricter one, after the signals stay healthy for `recovery_dwell`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ModeThresholds {
    pub enter_below_confidence: f64,
    pub exit_at_confidence: f64,
    pub enter_above_load_fraction: f64,
    pub exit_at_load_fraction: f64,
    pub enter_above_calibration_error: f64,
    pub exit_at_calibration_error: f64,
    pub recovery_dwell: Duration,
}

/// Switches between speculative and demand-only scheduling (GPU §2.9).
#[derive(Clone, Debug, PartialEq)]
pub struct ModeController {
    thresholds: ModeThresholds,
    mode: SchedulingMode,
    reason: Option<DemandOnlyReason>,
    healthy_since: Option<MonotonicTime>,
    last_observed: Option<MonotonicTime>,
}

impl ModeController {
    /// Starts speculative. Each exit threshold must be strictly stricter than its entry
    /// threshold, so the band is never empty.
    pub fn new(thresholds: ModeThresholds) -> Result<Self, CalibrationError> {
        let enter_confidence =
            probability("enter_below_confidence", thresholds.enter_below_confidence)?;
        let exit_confidence = probability("exit_at_confidence", thresholds.exit_at_confidence)?;
        let enter_load = non_negative(
            "enter_above_load_fraction",
            thresholds.enter_above_load_fraction,
        )?;
        let exit_load = non_negative("exit_at_load_fraction", thresholds.exit_at_load_fraction)?;
        let enter_error = non_negative(
            "enter_above_calibration_error",
            thresholds.enter_above_calibration_error,
        )?;
        let exit_error = non_negative(
            "exit_at_calibration_error",
            thresholds.exit_at_calibration_error,
        )?;
        if exit_confidence <= enter_confidence {
            return Err(InputError::OutOfRange {
                field: "exit_at_confidence",
            }
            .into());
        }
        if exit_load >= enter_load {
            return Err(InputError::OutOfRange {
                field: "exit_at_load_fraction",
            }
            .into());
        }
        if exit_error >= enter_error {
            return Err(InputError::OutOfRange {
                field: "exit_at_calibration_error",
            }
            .into());
        }
        Ok(Self {
            thresholds,
            mode: SchedulingMode::Speculative,
            reason: None,
            healthy_since: None,
            last_observed: None,
        })
    }

    /// The mode in force.
    pub fn mode(&self) -> SchedulingMode {
        self.mode
    }

    /// Why scheduling is demand-only; `None` while speculative.
    pub fn reason(&self) -> Option<DemandOnlyReason> {
        self.reason
    }

    /// Feeds one observation and returns the mode that applies from `at`.
    pub fn observe(
        &mut self,
        at: MonotonicTime,
        signals: ModeSignals,
    ) -> Result<SchedulingMode, CalibrationError> {
        let confidence = probability("confidence", signals.confidence)?;
        let load = non_negative("load_fraction", signals.load_fraction)?;
        let error = non_negative("calibration_error", signals.calibration_error)?;
        if self.last_observed.is_some_and(|last| at < last) {
            return Err(CalibrationError::ClockWentBack);
        }
        self.last_observed = Some(at);
        let limits = &self.thresholds;
        match self.mode {
            SchedulingMode::Speculative => {
                let reason = if confidence < limits.enter_below_confidence {
                    Some(DemandOnlyReason::LowConfidence)
                } else if load > limits.enter_above_load_fraction {
                    Some(DemandOnlyReason::Overload)
                } else if error > limits.enter_above_calibration_error {
                    Some(DemandOnlyReason::Drift)
                } else {
                    None
                };
                if reason.is_some() {
                    self.mode = SchedulingMode::DemandOnly;
                    self.reason = reason;
                    self.healthy_since = None;
                }
            }
            SchedulingMode::DemandOnly => {
                let healthy = confidence >= limits.exit_at_confidence
                    && load <= limits.exit_at_load_fraction
                    && error <= limits.exit_at_calibration_error;
                if healthy {
                    let since = *self.healthy_since.get_or_insert(at);
                    if at.saturating_duration_since(since) >= limits.recovery_dwell {
                        self.mode = SchedulingMode::Speculative;
                        self.reason = None;
                        self.healthy_since = None;
                    }
                } else {
                    self.healthy_since = None;
                }
            }
        }
        Ok(self.mode)
    }
}

#[cfg(test)]
mod tests;
