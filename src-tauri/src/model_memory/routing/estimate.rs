//! The finish estimate of GPU §4.6 (lines 713–716):
//!
//! ```text
//! finish_at_node = queue + state_preparation_critical_path
//!                  + request_compute + client/network_tail
//! ```
//!
//! "Use uncertainty and stale-advertisement penalties": every term carries an expected
//! duration and an uncertainty, and an endpoint report observed some time ago pays a
//! penalty that grows with its age until it is too old to use at all.

use std::fmt;

use crate::foundation::ids::MonotonicTime;
use crate::model_memory::math::{non_negative, InputError};

/// A duration with its uncertainty, both in seconds (§4.6 "Use uncertainty").
///
/// The uncertainty is a non-negative spread above the expected value. Terms are not
/// assumed independent, so spreads add linearly rather than in quadrature.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SecondsEstimate {
    expected_seconds: f64,
    uncertainty_seconds: f64,
}

impl SecondsEstimate {
    /// No time and no uncertainty.
    pub const ZERO: Self = Self {
        expected_seconds: 0.0,
        uncertainty_seconds: 0.0,
    };

    /// Refuses a negative or non-finite expected value or uncertainty.
    pub fn new(expected_seconds: f64, uncertainty_seconds: f64) -> Result<Self, InputError> {
        Ok(Self {
            expected_seconds: non_negative("expected_seconds", expected_seconds)?,
            uncertainty_seconds: non_negative("uncertainty_seconds", uncertainty_seconds)?,
        })
    }

    /// A duration known without spread.
    pub fn exact(expected_seconds: f64) -> Result<Self, InputError> {
        Self::new(expected_seconds, 0.0)
    }

    pub fn expected_seconds(&self) -> f64 {
        self.expected_seconds
    }

    pub fn uncertainty_seconds(&self) -> f64 {
        self.uncertainty_seconds
    }

    /// The expected value plus the spread.
    pub fn upper_seconds(&self) -> f64 {
        self.expected_seconds + self.uncertainty_seconds
    }

    /// Two terms one after the other: expected values add, and so do spreads.
    pub fn then(self, next: Self) -> Self {
        Self {
            expected_seconds: self.expected_seconds + next.expected_seconds,
            uncertainty_seconds: self.uncertainty_seconds + next.uncertainty_seconds,
        }
    }

    /// Two terms that run side by side and are both needed: the later expected finish,
    /// with a spread reaching the later upper bound.
    pub fn alongside(self, other: Self) -> Self {
        let expected_seconds = self.expected_seconds.max(other.expected_seconds);
        let upper = self.upper_seconds().max(other.upper_seconds());
        Self {
            expected_seconds,
            uncertainty_seconds: upper - expected_seconds,
        }
    }

    /// The same estimate with `extra_seconds` more spread.
    pub fn widened(self, extra_seconds: f64) -> Result<Self, InputError> {
        Self::new(
            self.expected_seconds,
            self.uncertainty_seconds + non_negative("extra_seconds", extra_seconds)?,
        )
    }

    /// `expected + risk_weight × uncertainty`: the score of a finish estimate when each
    /// second of spread costs `risk_weight` seconds.
    pub fn risk_adjusted_seconds(&self, risk_weight: f64) -> f64 {
        self.expected_seconds + risk_weight * self.uncertainty_seconds
    }
}

/// The four terms of `finish_at_node` (§4.6, lines 713–714).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FinishComponents {
    /// Waiting behind requests already admitted at the endpoint.
    pub queue: SecondsEstimate,
    /// The critical path of making the exact state ready there: zero when it is ready.
    pub state_preparation_critical_path: SecondsEstimate,
    /// Prefill and decode of this request at the endpoint.
    pub request_compute: SecondsEstimate,
    /// Delivery of the response to the client.
    pub client_network_tail: SecondsEstimate,
}

/// `finish_at_node` with its terms (§4.6).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FinishEstimate {
    pub components: FinishComponents,
    pub finish: SecondsEstimate,
}

/// `finish_at_node = queue + state_preparation_critical_path + request_compute +
/// client/network_tail` (§4.6, lines 713–714). The terms run one after another, so their
/// spreads add.
pub fn finish_at_node(components: FinishComponents) -> FinishEstimate {
    let finish = components
        .queue
        .then(components.state_preparation_critical_path)
        .then(components.request_compute)
        .then(components.client_network_tail);
    FinishEstimate { components, finish }
}

/// How an endpoint report's age is charged (§4.6 "stale-advertisement penalties";
/// GPU-W09 "expiring residency advertisements and stale-source fallback").
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StalenessPolicy {
    penalty_seconds_per_second_of_age: f64,
    uncertainty_seconds_per_second_of_age: f64,
    max_age_seconds: f64,
}

impl StalenessPolicy {
    /// Every rate is required configuration; there are no defaults. `max_age_seconds`
    /// must be above zero: a report of that age or older is not used.
    pub fn new(
        penalty_seconds_per_second_of_age: f64,
        uncertainty_seconds_per_second_of_age: f64,
        max_age_seconds: f64,
    ) -> Result<Self, InputError> {
        let max_age_seconds = non_negative("max_age_seconds", max_age_seconds)?;
        if max_age_seconds == 0.0 {
            return Err(InputError::NotPositive {
                field: "max_age_seconds",
            });
        }
        Ok(Self {
            penalty_seconds_per_second_of_age: non_negative(
                "penalty_seconds_per_second_of_age",
                penalty_seconds_per_second_of_age,
            )?,
            uncertainty_seconds_per_second_of_age: non_negative(
                "uncertainty_seconds_per_second_of_age",
                uncertainty_seconds_per_second_of_age,
            )?,
            max_age_seconds,
        })
    }

    pub fn max_age_seconds(&self) -> f64 {
        self.max_age_seconds
    }
}

/// What an endpoint report's age costs.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StalePenalty {
    pub age_seconds: f64,
    /// Added to the score: `age × penalty_seconds_per_second_of_age`.
    pub penalty_seconds: f64,
    /// Added to the finish spread: `age × uncertainty_seconds_per_second_of_age`.
    pub added_uncertainty_seconds: f64,
}

/// Why an endpoint report may not be used at all.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StaleRefusal {
    /// The report is at or past its maximum age (GPU-W09 stale-source fallback).
    TooOld {
        age_seconds: f64,
        max_age_seconds: f64,
    },
    /// The report claims an observation after now on the same clock.
    FromTheFuture {
        observed_at: MonotonicTime,
        now: MonotonicTime,
    },
}

impl fmt::Display for StaleRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooOld {
                age_seconds,
                max_age_seconds,
            } => write!(
                f,
                "the report is {age_seconds} s old; reports of {max_age_seconds} s or older are not used"
            ),
            Self::FromTheFuture { observed_at, now } => write!(
                f,
                "the report was observed at {} ns, after now ({} ns)",
                observed_at.as_nanos(),
                now.as_nanos()
            ),
        }
    }
}

impl std::error::Error for StaleRefusal {}

/// The stale-report penalty at `now` of a report observed at `observed_at` (§4.6). A
/// report at exactly its maximum age is already refused.
pub fn stale_penalty(
    policy: &StalenessPolicy,
    observed_at: MonotonicTime,
    now: MonotonicTime,
) -> Result<StalePenalty, StaleRefusal> {
    let Some(age) = now.checked_duration_since(observed_at) else {
        return Err(StaleRefusal::FromTheFuture { observed_at, now });
    };
    let age_seconds = age.as_secs_f64();
    if age_seconds >= policy.max_age_seconds {
        return Err(StaleRefusal::TooOld {
            age_seconds,
            max_age_seconds: policy.max_age_seconds,
        });
    }
    Ok(StalePenalty {
        age_seconds,
        penalty_seconds: age_seconds * policy.penalty_seconds_per_second_of_age,
        added_uncertainty_seconds: age_seconds * policy.uncertainty_seconds_per_second_of_age,
    })
}
