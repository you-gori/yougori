//! Measured reuse (GPU §3.4 line 548: "Retain representations by measured reuse value").
//!
//! The rule of line 550 is the catalog's [`ImportAmortization`] (T05):
//!
//! ```text
//! expected_uses * per_use_saving > preparation_cost + storage/retention_penalty
//! ```
//!
//! A representation is prepared on a forecast of those terms. Whether it is kept is judged
//! on measurement instead: a [`ReuseRecord`] counts the uses and savings observed since
//! the representation was admitted, and [`MeasuredReuse`] turns them into the same
//! inequality over a declared horizon.

use crate::foundation::catalog::ImportAmortization;
use crate::foundation::ids::{Clock, MonotonicTime};
use crate::model_memory::math::{non_negative, positive, InputError};

/// Uses observed for one representation since it was admitted (line 548).
#[derive(Clone, Debug, PartialEq)]
pub struct ReuseRecord {
    since: MonotonicTime,
    uses: u64,
    saved_seconds_total: f64,
    last_used_at: Option<MonotonicTime>,
}

impl ReuseRecord {
    /// A record that starts measuring now.
    pub fn new(clock: &dyn Clock) -> Self {
        Self {
            since: clock.now(),
            uses: 0,
            saved_seconds_total: 0.0,
            last_used_at: None,
        }
    }

    pub fn since(&self) -> MonotonicTime {
        self.since
    }

    pub fn uses(&self) -> u64 {
        self.uses
    }

    pub fn last_used_at(&self) -> Option<MonotonicTime> {
        self.last_used_at
    }

    /// Records one use and the saving measured for it.
    pub fn record_use(&mut self, saved_seconds: f64, clock: &dyn Clock) -> Result<(), InputError> {
        let saved_seconds = non_negative("saved_seconds", saved_seconds)?;
        let total = non_negative(
            "saved_seconds_total",
            self.saved_seconds_total + saved_seconds,
        )?;
        let uses = self
            .uses
            .checked_add(1)
            .ok_or(InputError::Overflow { field: "uses" })?;
        self.uses = uses;
        self.saved_seconds_total = total;
        self.last_used_at = Some(clock.now());
        Ok(())
    }

    /// Measured reuse over the next `horizon_seconds`: the use rate observed since
    /// admission times the horizon, and the mean measured saving per use. Before any
    /// time has passed nothing is measured, so no uses are expected.
    pub fn measured(
        &self,
        horizon_seconds: f64,
        clock: &dyn Clock,
    ) -> Result<MeasuredReuse, InputError> {
        let horizon_seconds = positive("horizon_seconds", horizon_seconds)?;
        let observed_seconds = clock
            .now()
            .saturating_duration_since(self.since)
            .as_secs_f64();
        let expected_uses = if observed_seconds > 0.0 {
            self.uses as f64 / observed_seconds * horizon_seconds
        } else {
            0.0
        };
        let per_use_saving_seconds = if self.uses > 0 {
            self.saved_seconds_total / self.uses as f64
        } else {
            0.0
        };
        Ok(MeasuredReuse {
            uses_observed: self.uses,
            observed_seconds,
            expected_uses: non_negative("expected_uses", expected_uses)?,
            per_use_saving_seconds,
        })
    }
}

/// Reuse as a [`ReuseRecord`] measured it (line 548).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MeasuredReuse {
    pub uses_observed: u64,
    pub observed_seconds: f64,
    /// Uses expected over the horizon at the observed rate.
    pub expected_uses: f64,
    pub per_use_saving_seconds: f64,
}

impl MeasuredReuse {
    /// The terms of line 550 with measured uses and savings, for the decision to keep.
    pub fn amortization(
        &self,
        preparation_cost_seconds: f64,
        retention_penalty_seconds: f64,
    ) -> ImportAmortization {
        ImportAmortization {
            expected_uses: self.expected_uses,
            per_use_saving_seconds: self.per_use_saving_seconds,
            preparation_cost_seconds,
            retention_penalty_seconds,
        }
    }
}

#[cfg(test)]
mod tests;
