//! Explicit "not measured" cells and checked non-negative numbers (S13 FAST-01:
//! "Unmeasured cells say not measured").

use std::fmt;

use serde::{Deserialize, Serialize};

use super::error::ReportError;

/// Why a cell has no value. A missing value is never written as zero or left out
/// (S13 FAST-01).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotMeasuredReason {
    /// The field does not apply to this scenario, such as model fields of a VM create.
    NotApplicable,
    /// The platform exposes no counter or sensor for it.
    InstrumentUnavailable,
    /// The runtime or backend does not report it.
    UnsupportedByBackend,
    /// The attempt ended before the event that would measure it.
    RunEndedFirst,
    /// The harness did not record it in this run.
    NotRecorded,
    /// A statistic over successful runs, and none succeeded (S8).
    NoSuccessfulRuns,
    /// No comparable reference exists or is authorized (S9, S12 BENCH-04).
    ReferenceUnavailable,
    /// A rate needs at least two emitted tokens.
    InsufficientTokens,
    /// A rate over an interval of zero length.
    ZeroElapsedTime,
    /// A spread across bursts needs at least two independent bursts (S8, S11).
    SingleBurst,
}

impl NotMeasuredReason {
    pub const fn describe(self) -> &'static str {
        match self {
            Self::NotApplicable => "not applicable",
            Self::InstrumentUnavailable => "no instrument on this platform",
            Self::UnsupportedByBackend => "not reported by the backend",
            Self::RunEndedFirst => "the run ended first",
            Self::NotRecorded => "not recorded",
            Self::NoSuccessfulRuns => "no successful runs",
            Self::ReferenceUnavailable => "no comparable reference",
            Self::InsufficientTokens => "fewer than two tokens",
            Self::ZeroElapsedTime => "zero elapsed time",
            Self::SingleBurst => "a single burst",
        }
    }
}

/// A value, or an explicit "not measured" with its reason (S8, S13 FAST-01).
///
/// Serialized as `{"status":"measured","value":…}` or
/// `{"status":"not_measured","reason":…}`; a record field of this type can be neither
/// omitted nor written as zero to mean "unknown".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum Measured<T> {
    Measured { value: T },
    NotMeasured { reason: NotMeasuredReason },
}

crate::foundation::strict_serde::strict_tag!(Measured<T>, "status");

impl<T> Measured<T> {
    /// Named after the serialized status, `measured`.
    #[allow(clippy::self_named_constructors)]
    pub const fn measured(value: T) -> Self {
        Self::Measured { value }
    }

    /// An explicit "not measured" with its reason.
    pub const fn not_measured(reason: NotMeasuredReason) -> Self {
        Self::NotMeasured { reason }
    }

    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Measured { value } => Some(value),
            Self::NotMeasured { .. } => None,
        }
    }

    pub fn into_value(self) -> Option<T> {
        match self {
            Self::Measured { value } => Some(value),
            Self::NotMeasured { .. } => None,
        }
    }

    pub fn reason(&self) -> Option<NotMeasuredReason> {
        match self {
            Self::Measured { .. } => None,
            Self::NotMeasured { reason } => Some(*reason),
        }
    }

    pub fn is_measured(&self) -> bool {
        matches!(self, Self::Measured { .. })
    }

    pub fn as_ref(&self) -> Measured<&T> {
        match self {
            Self::Measured { value } => Measured::Measured { value },
            Self::NotMeasured { reason } => Measured::NotMeasured { reason: *reason },
        }
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Measured<U> {
        match self {
            Self::Measured { value } => Measured::Measured { value: f(value) },
            Self::NotMeasured { reason } => Measured::NotMeasured { reason },
        }
    }
}

impl<T: fmt::Display> fmt::Display for Measured<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Measured { value } => value.fmt(f),
            Self::NotMeasured { reason } => write!(f, "not measured ({})", reason.describe()),
        }
    }
}

/// A finite, non-negative number such as a price, rate, energy or temperature. NaN,
/// infinities and negative values are refused, so a record never carries a value JSON
/// would print as `null`.
///
/// Written as the shortest decimal string that reads back to the same `f64` (`"0.5"`,
/// `"2048.0"`, `"1e-7"`) and read with Rust's correctly rounded parser, so a record
/// reads back bit for bit and its digests (BENCH-13) survive a round trip. A JSON
/// number would not: serde_json's default float parsing is not exact. Only the
/// canonical spelling is accepted.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct NonNegative(f64);

impl NonNegative {
    /// Zero.
    pub const ZERO: Self = Self(0.0);

    /// Refuses NaN, infinities and negative values.
    pub fn new(value: f64) -> Result<Self, ReportError> {
        if value.is_finite() && value >= 0.0 {
            // Normalises -0.0, which compares equal to 0.0.
            Ok(Self(value + 0.0))
        } else {
            Err(ReportError::InvalidNumber)
        }
    }

    pub const fn get(self) -> f64 {
        self.0
    }

    /// The canonical text: the shortest decimal that reads back exactly.
    fn canonical(self) -> String {
        format!("{:?}", self.0)
    }

    /// Reads the canonical text; any other spelling of a number is refused.
    pub fn parse(text: &str) -> Result<Self, ReportError> {
        let value = text
            .parse::<f64>()
            .map_err(|_| ReportError::InvalidNumber)
            .and_then(Self::new)?;
        if value.canonical() == text {
            Ok(value)
        } else {
            Err(ReportError::InvalidNumber)
        }
    }
}

impl Serialize for NonNegative {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.canonical())
    }
}

impl<'de> Deserialize<'de> for NonNegative {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<f64> for NonNegative {
    type Error = ReportError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<NonNegative> for f64 {
    fn from(value: NonNegative) -> Self {
        value.0
    }
}

impl fmt::Display for NonNegative {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cells_serialize_with_an_explicit_status() {
        let measured = Measured::measured(42u64);
        assert_eq!(
            serde_json::to_string(&measured).unwrap(),
            r#"{"status":"measured","value":42}"#
        );
        let missing: Measured<u64> =
            Measured::not_measured(NotMeasuredReason::InstrumentUnavailable);
        assert_eq!(
            serde_json::to_string(&missing).unwrap(),
            r#"{"status":"not_measured","reason":"instrument_unavailable"}"#
        );
        assert_eq!(
            missing.to_string(),
            "not measured (no instrument on this platform)"
        );
        assert_eq!(measured.to_string(), "42");
    }

    #[test]
    fn zero_or_absence_cannot_mean_not_measured() {
        // A bare number, null or an empty object is not a cell.
        assert!(serde_json::from_str::<Measured<u64>>("0").is_err());
        assert!(serde_json::from_str::<Measured<u64>>("null").is_err());
        assert!(serde_json::from_str::<Measured<u64>>("{}").is_err());
        assert!(serde_json::from_str::<Measured<u64>>(r#"{"status":"not_measured"}"#).is_err());
        assert!(serde_json::from_str::<Measured<u64>>(
            r#"{"status":"measured","value":1,"extra":2}"#
        )
        .is_err());
        assert_eq!(
            serde_json::from_str::<Measured<u64>>(r#"{"status":"measured","value":0}"#).unwrap(),
            Measured::measured(0)
        );
    }

    #[test]
    fn non_negative_refuses_values_json_cannot_hold() {
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
            assert_eq!(NonNegative::new(bad), Err(ReportError::InvalidNumber));
        }
        assert!(NonNegative::new(-0.0).unwrap().get().is_sign_positive());
        for bad in [
            "\"-2.5\"", "\"NaN\"", "\"inf\"", "\"0.50\"", "\"+1.0\"", "\"2\"", "2.0",
        ] {
            assert!(serde_json::from_str::<NonNegative>(bad).is_err(), "{bad}");
        }
        assert_eq!(
            serde_json::from_str::<NonNegative>("\"2.0\"")
                .unwrap()
                .get(),
            2.0
        );
    }

    #[test]
    fn non_negative_reads_back_bit_for_bit() {
        // Values with 17 significant digits that serde_json's default number parsing
        // reads back one unit in the last place off.
        for value in [
            55350.263109369596,
            1.6990709035471285e-94,
            7.568625859645095e167,
            0.1 + 0.2,
            5e-324,
            0.0,
        ] {
            let number = NonNegative::new(value).unwrap();
            let json = serde_json::to_string(&number).unwrap();
            let back: NonNegative = serde_json::from_str(&json).unwrap();
            assert_eq!(back.get().to_bits(), value.to_bits(), "{json}");
        }
        assert_eq!(
            serde_json::to_string(&NonNegative::new(0.5).unwrap()).unwrap(),
            "\"0.5\""
        );
        assert_eq!(
            serde_json::to_string(&NonNegative::new(2048.0).unwrap()).unwrap(),
            "\"2048.0\""
        );
    }
}
