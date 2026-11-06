//! Import amortization (GPU part §3.4, lines 548–550): a representation is worth
//! preparing and retaining only when
//!
//! ```text
//! expected_uses * per_use_saving > preparation_cost + storage/retention_penalty
//! ```
//!
//! holds strictly. All costs and savings are in one unit, seconds here; equality does not
//! amortize.

use std::fmt;

/// The terms of the line 550 inequality.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ImportAmortization {
    pub expected_uses: f64,
    pub per_use_saving_seconds: f64,
    pub preparation_cost_seconds: f64,
    /// The storage/retention penalty over the representation's retained life.
    pub retention_penalty_seconds: f64,
}

/// A term that is not a finite, non-negative number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmortizationError {
    NotFinite { term: &'static str },
    Negative { term: &'static str },
}

impl fmt::Display for AmortizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFinite { term } => write!(f, "{term} is not a finite number"),
            Self::Negative { term } => write!(f, "{term} is negative"),
        }
    }
}

impl std::error::Error for AmortizationError {}

fn checked(term: &'static str, value: f64) -> Result<f64, AmortizationError> {
    if !value.is_finite() {
        return Err(AmortizationError::NotFinite { term });
    }
    if value < 0.0 {
        return Err(AmortizationError::Negative { term });
    }
    Ok(value)
}

impl ImportAmortization {
    /// `expected_uses * per_use_saving`, the left side.
    pub fn expected_saving_seconds(&self) -> Result<f64, AmortizationError> {
        let saving = checked("expected_uses", self.expected_uses)?
            * checked("per_use_saving_seconds", self.per_use_saving_seconds)?;
        checked("expected saving", saving)
    }

    /// `preparation_cost + storage/retention_penalty`, the right side.
    pub fn total_cost_seconds(&self) -> Result<f64, AmortizationError> {
        let cost = checked("preparation_cost_seconds", self.preparation_cost_seconds)?
            + checked("retention_penalty_seconds", self.retention_penalty_seconds)?;
        checked("total cost", cost)
    }

    /// Whether the import amortizes: the saving strictly exceeds the cost.
    pub fn amortizes(&self) -> Result<bool, AmortizationError> {
        Ok(self.expected_saving_seconds()? > self.total_cost_seconds()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terms(uses: f64, saving: f64, preparation: f64, penalty: f64) -> ImportAmortization {
        ImportAmortization {
            expected_uses: uses,
            per_use_saving_seconds: saving,
            preparation_cost_seconds: preparation,
            retention_penalty_seconds: penalty,
        }
    }

    #[test]
    fn the_inequality_of_line_550_is_strict() {
        // 10 uses x 3 s = 30 s > 20 s preparation + 5 s retention = 25 s.
        let worth = terms(10.0, 3.0, 20.0, 5.0);
        assert_eq!(worth.expected_saving_seconds(), Ok(30.0));
        assert_eq!(worth.total_cost_seconds(), Ok(25.0));
        assert_eq!(worth.amortizes(), Ok(true));
        // 10 x 2.5 s = 25 s equals the cost: equality does not amortize.
        assert_eq!(terms(10.0, 2.5, 20.0, 5.0).amortizes(), Ok(false));
        // A one-off use never pays for an expensive preparation.
        assert_eq!(terms(1.0, 3.0, 20.0, 0.0).amortizes(), Ok(false));
        // The retention penalty alone can tip the balance.
        assert_eq!(terms(10.0, 3.0, 20.0, 9.0).amortizes(), Ok(true));
        assert_eq!(terms(10.0, 3.0, 20.0, 10.0).amortizes(), Ok(false));
        // No expected use never amortizes, even at zero cost.
        assert_eq!(terms(0.0, 3.0, 0.0, 0.0).amortizes(), Ok(false));
    }

    #[test]
    fn invalid_terms_are_refused() {
        assert_eq!(
            terms(f64::NAN, 1.0, 1.0, 1.0).amortizes(),
            Err(AmortizationError::NotFinite {
                term: "expected_uses"
            })
        );
        assert_eq!(
            terms(1.0, -1.0, 1.0, 1.0).amortizes(),
            Err(AmortizationError::Negative {
                term: "per_use_saving_seconds"
            })
        );
        assert_eq!(
            terms(1.0, 1.0, f64::INFINITY, 1.0).amortizes(),
            Err(AmortizationError::NotFinite {
                term: "preparation_cost_seconds"
            })
        );
        assert_eq!(
            terms(1.0, 1.0, 1.0, -0.5).amortizes(),
            Err(AmortizationError::Negative {
                term: "retention_penalty_seconds"
            })
        );
        assert_eq!(
            terms(f64::MAX, f64::MAX, 0.0, 0.0).amortizes(),
            Err(AmortizationError::NotFinite {
                term: "expected saving"
            })
        );
    }
}
