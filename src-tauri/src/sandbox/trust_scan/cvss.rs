//! CVSS v3 and v4.0 base scores and their qualitative ratings, used to give scanner
//! findings a documented severity (line 2459: "Define severity"; VM-W47, line 2670: "Gate
//! by ... severity").
//!
//! A v3 base score follows the CVSS v3.1 specification (section 7.1, with the Roundup of
//! Appendix A); a `CVSS:3.0` vector is scored with the same equations. Scores are kept
//! in tenths, so records hold integers.
//!
//! A CVSS v4.0 vector is read in full by [`parse_v4`]: every base metric present once,
//! each threat, environmental and supplemental metric at most once, and every value one
//! the "CVSS v4.0 Specification Document" defines. [`CvssV4Vector::macro_vector`] gives
//! the vector's base macro vector, its levels in the specification's equivalence sets
//! EQ1 to EQ6, and [`CvssV4Vector::base_score`] its base score, CVSS-B, from FIRST's
//! published macro-vector scores and the specification's interpolation between them
//! ([`super::cvss_v4`], with the data transcribed in `cvss_v4_data`). Only the base score
//! is computed: a v4.0 vector's threat, environmental and supplemental metrics do not
//! change it, as a v3 vector's temporal and environmental metrics do not change its base
//! score. A v4.0 vector the reference data does not cover would yield
//! [`VectorScore::Unscored`], which [`super::severity`] counts as Critical, never a
//! guessed score; the data covers every base vector. Any other text is refused.

use std::fmt;

use serde::Serialize;

use super::cvss_v4::{v4_base_score, V4NotScored};

/// Longest accepted vector.
pub const MAX_VECTOR_BYTES: usize = 256;

/// A CVSS base score in tenths, 0 to 100.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct CvssScore(u8);

impl CvssScore {
    pub const MAX_TENTHS: u8 = 100;

    pub fn from_tenths(tenths: u8) -> Result<Self, CvssError> {
        if tenths > Self::MAX_TENTHS {
            return Err(CvssError::ScoreOutOfRange);
        }
        Ok(Self(tenths))
    }

    pub const fn tenths(self) -> u8 {
        self.0
    }

    /// `tenths`, or [`Self::MAX_TENTHS`] if it is more.
    pub(super) const fn saturating_from_tenths(tenths: u8) -> Self {
        if tenths > Self::MAX_TENTHS {
            Self(Self::MAX_TENTHS)
        } else {
            Self(tenths)
        }
    }

    /// Reads a decimal score as scanners print it: one or two digits and an optional
    /// single decimal, from `0` to `10.0` (`"9.8"`, `"10.0"`, `"5"`).
    pub fn parse_decimal(text: &str) -> Result<Self, CvssError> {
        let (whole, tenth) = match text.split_once('.') {
            Some((whole, fraction)) => (whole, Some(fraction)),
            None => (text, None),
        };
        let digits = |part: &str, max_len: usize| {
            !part.is_empty() && part.len() <= max_len && part.bytes().all(|b| b.is_ascii_digit())
        };
        if !digits(whole, 2) || tenth.is_some_and(|fraction| !digits(fraction, 1)) {
            return Err(CvssError::MalformedScore);
        }
        let whole: u8 = whole.parse().map_err(|_| CvssError::MalformedScore)?;
        let tenth: u8 = match tenth {
            Some(fraction) => fraction.parse().map_err(|_| CvssError::MalformedScore)?,
            None => 0,
        };
        let tenths = whole
            .checked_mul(10)
            .and_then(|value| value.checked_add(tenth))
            .ok_or(CvssError::ScoreOutOfRange)?;
        Self::from_tenths(tenths)
    }

    /// The qualitative rating of CVSS v3.1 section 5, which CVSS v4.0's Table 22 repeats:
    /// None 0.0, Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9, Critical 9.0–10.0.
    pub const fn rating(self) -> CvssRating {
        match self.0 {
            0 => CvssRating::None,
            1..=39 => CvssRating::Low,
            40..=69 => CvssRating::Medium,
            70..=89 => CvssRating::High,
            _ => CvssRating::Critical,
        }
    }
}

impl fmt::Display for CvssScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.0 / 10, self.0 % 10)
    }
}

/// The CVSS v3.1 qualitative severity rating scale (section 5), the same in CVSS v4.0
/// (Table 22).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CvssRating {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// A CVSS vector's version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CvssVersion {
    V3_0,
    V3_1,
    V4_0,
}

/// What a vector yields: a base score, or, for a recognised vector the reference data
/// does not cover, no score. No CVSS v3.0, v3.1 or v4.0 vector that is read yields
/// `Unscored` today; the variant keeps such a vector typed instead of guessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum VectorScore {
    Scored {
        version: CvssVersion,
        score: CvssScore,
    },
    Unscored {
        version: CvssVersion,
    },
}

/// Why a score or vector was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum CvssError {
    /// Not a decimal score from 0 to 10.0 with at most one decimal.
    MalformedScore,
    ScoreOutOfRange,
    /// Longer than [`MAX_VECTOR_BYTES`].
    VectorTooLong,
    /// The vector does not start with `CVSS:3.0/`, `CVSS:3.1/` or `CVSS:4.0/` (CVSS v2
    /// vectors have no prefix and are refused here).
    UnknownVersion,
    /// A part is not `NAME:VALUE`.
    MalformedPart,
    UnknownMetric,
    DuplicateMetric,
    MissingMetric {
        metric: &'static str,
    },
    BadValue {
        metric: &'static str,
    },
}

impl fmt::Display for CvssError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedScore => {
                f.write_str("a CVSS score must be 0 to 10.0 with at most one decimal")
            }
            Self::ScoreOutOfRange => f.write_str("a CVSS score is at most 10.0"),
            Self::VectorTooLong => write!(f, "a CVSS vector is at most {MAX_VECTOR_BYTES} bytes"),
            Self::UnknownVersion => {
                f.write_str("a CVSS vector must start with CVSS:3.0/, CVSS:3.1/ or CVSS:4.0/")
            }
            Self::MalformedPart => f.write_str("a CVSS vector part is not NAME:VALUE"),
            Self::UnknownMetric => f.write_str("a CVSS vector names an unknown metric"),
            Self::DuplicateMetric => f.write_str("a CVSS vector repeats a metric"),
            Self::MissingMetric { metric } => {
                write!(f, "the CVSS vector lacks the base metric {metric}")
            }
            Self::BadValue { metric } => {
                write!(f, "the CVSS vector has an invalid value for {metric}")
            }
        }
    }
}

impl std::error::Error for CvssError {}

const BASE_METRICS: [&str; 8] = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
/// Temporal and environmental metrics a v3 vector may carry; they do not change the
/// base score and are accepted without being read.
const OTHER_V3_METRICS: [&str; 14] = [
    "E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA",
];

/// The base metrics of a CVSS v4.0 vector, in the specification's order; each must be
/// present.
pub const V4_BASE_METRICS: [&str; 11] = [
    "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
];

/// Every CVSS v4.0 metric with its values: the base metrics, then the threat metric, the
/// environmental metrics and the supplemental metrics, each of which may be left out
/// (Not Defined, `X`, written or not).
const V4_METRICS: [(&str, &[&str]); 32] = [
    ("AV", &["N", "A", "L", "P"]),
    ("AC", &["L", "H"]),
    ("AT", &["N", "P"]),
    ("PR", &["N", "L", "H"]),
    ("UI", &["N", "P", "A"]),
    ("VC", &["H", "L", "N"]),
    ("VI", &["H", "L", "N"]),
    ("VA", &["H", "L", "N"]),
    ("SC", &["H", "L", "N"]),
    ("SI", &["H", "L", "N"]),
    ("SA", &["H", "L", "N"]),
    ("E", &["X", "A", "P", "U"]),
    ("CR", &["X", "H", "M", "L"]),
    ("IR", &["X", "H", "M", "L"]),
    ("AR", &["X", "H", "M", "L"]),
    ("MAV", &["X", "N", "A", "L", "P"]),
    ("MAC", &["X", "L", "H"]),
    ("MAT", &["X", "N", "P"]),
    ("MPR", &["X", "N", "L", "H"]),
    ("MUI", &["X", "N", "P", "A"]),
    ("MVC", &["X", "H", "L", "N"]),
    ("MVI", &["X", "H", "L", "N"]),
    ("MVA", &["X", "H", "L", "N"]),
    ("MSC", &["X", "H", "L", "N"]),
    ("MSI", &["X", "S", "H", "L", "N"]),
    ("MSA", &["X", "S", "H", "L", "N"]),
    ("S", &["X", "N", "P"]),
    ("AU", &["X", "N", "Y"]),
    ("R", &["X", "A", "U", "I"]),
    ("V", &["X", "D", "C"]),
    ("RE", &["X", "L", "M", "H"]),
    ("U", &["X", "Clear", "Green", "Amber", "Red"]),
];

/// A checked CVSS v4.0 vector. It keeps the base metric values; the other metrics were
/// checked and do not enter the base macro vector. Serialize only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CvssV4Vector {
    /// The values of [`V4_BASE_METRICS`], in that order.
    base: [&'static str; 11],
}

impl CvssV4Vector {
    /// The value of base metric `metric` (`"AV"`, `"VC"`, ...), or `None` for a name that is
    /// not a base metric.
    pub fn base_value(&self, metric: &str) -> Option<&'static str> {
        V4_BASE_METRICS
            .iter()
            .position(|name| *name == metric)
            .and_then(|index| self.base.get(index).copied())
    }

    fn is(&self, metric: &str, value: &str) -> bool {
        self.base_value(metric) == Some(value)
    }

    /// The vector's base score, CVSS-B, by the specification's macro vectors and
    /// interpolation (see [`super::cvss_v4`]). The threat, environmental and supplemental
    /// metrics the vector may carry take no part.
    pub fn base_score(&self) -> Result<CvssScore, V4NotScored> {
        v4_base_score(self)
    }

    /// The macro vector of the base metrics (CVSS-B): the threat metric and the
    /// environmental metrics take their Not Defined defaults, so Exploit Maturity counts
    /// as Attacked and each security requirement as High, whatever the vector says.
    ///
    /// - EQ1: 0 when AV:N, PR:N and UI:N; 1 when one or two of them hold and AV is not P;
    ///   2 otherwise.
    /// - EQ2: 0 when AC:L and AT:N; 1 otherwise.
    /// - EQ3: 0 when VC:H and VI:H; 1 when not both but one of VC, VI, VA is H; 2 otherwise.
    /// - EQ4: 0 when MSI:S or MSA:S, which only an environmental metric can state, so never
    ///   for the base; 1 when one of SC, SI, SA is H; 2 otherwise.
    /// - EQ5: 0 for E:A, also its default; 1 for E:P; 2 for E:U. For the base, 0.
    /// - EQ6: 0 when CR:H and VC:H, IR:H and VI:H, or AR:H and VA:H; 1 otherwise. With the
    ///   requirements at their default High, 0 when one of VC, VI, VA is H.
    pub fn macro_vector(&self) -> MacroVector {
        let network = [self.is("AV", "N"), self.is("PR", "N"), self.is("UI", "N")];
        let eq1 = if network.iter().all(|holds| *holds) {
            0
        } else if network.iter().any(|holds| *holds) && !self.is("AV", "P") {
            1
        } else {
            2
        };
        let eq2 = if self.is("AC", "L") && self.is("AT", "N") {
            0
        } else {
            1
        };
        let high = [self.is("VC", "H"), self.is("VI", "H"), self.is("VA", "H")];
        let eq3 = if high[0] && high[1] {
            0
        } else if high.iter().any(|holds| *holds) {
            1
        } else {
            2
        };
        let eq4 = if self.is("SC", "H") || self.is("SI", "H") || self.is("SA", "H") {
            1
        } else {
            2
        };
        let eq6 = if high.iter().any(|holds| *holds) {
            0
        } else {
            1
        };
        MacroVector {
            eq1,
            eq2,
            eq3,
            eq4,
            eq5: 0,
            eq6,
        }
    }
}

/// A CVSS v4.0 macro vector: one level per equivalence set, EQ1 to EQ6. Written as six
/// digits (`000200`), the form in which the specification's table keys its scores.
/// Serialize only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct MacroVector {
    pub eq1: u8,
    pub eq2: u8,
    pub eq3: u8,
    pub eq4: u8,
    pub eq5: u8,
    pub eq6: u8,
}

impl fmt::Display for MacroVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}{}{}{}",
            self.eq1, self.eq2, self.eq3, self.eq4, self.eq5, self.eq6
        )
    }
}

/// Reads a CVSS v4.0 vector (`CVSS:4.0/AV:N/...`): at most [`MAX_VECTOR_BYTES`], parts
/// `NAME:VALUE` in any order, every base metric exactly once, every other metric at most
/// once, and only values the specification defines (`X` only outside the base).
pub fn parse_v4(vector: &str) -> Result<CvssV4Vector, CvssError> {
    if vector.len() > MAX_VECTOR_BYTES {
        return Err(CvssError::VectorTooLong);
    }
    let metrics = vector
        .strip_prefix("CVSS:4.0/")
        .ok_or(CvssError::UnknownVersion)?;
    let mut seen = [false; V4_METRICS.len()];
    let mut base: [Option<&'static str>; 11] = [None; 11];
    for part in metrics.split('/') {
        let (name, value) = part.split_once(':').ok_or(CvssError::MalformedPart)?;
        if name.is_empty() || value.is_empty() {
            return Err(CvssError::MalformedPart);
        }
        let Some((&(metric, values), was_seen)) = V4_METRICS
            .iter()
            .zip(seen.iter_mut())
            .find(|((candidate, _), _)| *candidate == name)
        else {
            return Err(CvssError::UnknownMetric);
        };
        if std::mem::replace(was_seen, true) {
            return Err(CvssError::DuplicateMetric);
        }
        let value = values
            .iter()
            .copied()
            .find(|allowed| *allowed == value)
            .ok_or(CvssError::BadValue { metric })?;
        if let Some(slot) = V4_BASE_METRICS
            .iter()
            .position(|base_metric| *base_metric == metric)
            .and_then(|index| base.get_mut(index))
        {
            *slot = Some(value);
        }
    }
    let mut checked = [""; 11];
    for ((slot, value), metric) in checked.iter_mut().zip(base).zip(V4_BASE_METRICS) {
        *slot = value.ok_or(CvssError::MissingMetric { metric })?;
    }
    Ok(CvssV4Vector { base: checked })
}

/// Scores a vector: the base score of a CVSS v3.0 or v3.1 vector, or of a v4.0 vector
/// that [`parse_v4`] accepts, which is [`VectorScore::Unscored`] only where the v4.0
/// reference data does not cover it (see the module documentation).
pub fn score_vector(vector: &str) -> Result<VectorScore, CvssError> {
    if vector.len() > MAX_VECTOR_BYTES {
        return Err(CvssError::VectorTooLong);
    }
    let (version, metrics) = if let Some(rest) = vector.strip_prefix("CVSS:3.1/") {
        (CvssVersion::V3_1, rest)
    } else if let Some(rest) = vector.strip_prefix("CVSS:3.0/") {
        (CvssVersion::V3_0, rest)
    } else if vector.starts_with("CVSS:4.0/") {
        let version = CvssVersion::V4_0;
        return Ok(match parse_v4(vector)?.base_score() {
            Ok(score) => VectorScore::Scored { version, score },
            Err(_) => VectorScore::Unscored { version },
        });
    } else {
        return Err(CvssError::UnknownVersion);
    };
    let mut base: [Option<&str>; 8] = [None; 8];
    let mut others: Vec<&str> = Vec::new();
    for part in metrics.split('/') {
        let (name, value) = part.split_once(':').ok_or(CvssError::MalformedPart)?;
        if name.is_empty() || value.is_empty() {
            return Err(CvssError::MalformedPart);
        }
        if let Some(index) = BASE_METRICS.iter().position(|metric| *metric == name) {
            if base[index].replace(value).is_some() {
                return Err(CvssError::DuplicateMetric);
            }
        } else if OTHER_V3_METRICS.contains(&name) {
            if others.contains(&name) {
                return Err(CvssError::DuplicateMetric);
            }
            others.push(name);
        } else {
            return Err(CvssError::UnknownMetric);
        }
    }
    let value = |index: usize| {
        base[index].ok_or(CvssError::MissingMetric {
            metric: BASE_METRICS[index],
        })
    };
    let bad = |index: usize| CvssError::BadValue {
        metric: BASE_METRICS[index],
    };
    let scope_changed = match value(4)? {
        "U" => false,
        "C" => true,
        _ => return Err(bad(4)),
    };
    let attack_vector = match value(0)? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return Err(bad(0)),
    };
    let attack_complexity = match value(1)? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return Err(bad(1)),
    };
    let privileges_required = match (value(2)?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return Err(bad(2)),
    };
    let user_interaction = match value(3)? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return Err(bad(3)),
    };
    let mut impacts = [0.0_f64; 3];
    for (slot, index) in impacts.iter_mut().zip(5..8) {
        *slot = match value(index)? {
            "H" => 0.56,
            "L" => 0.22,
            "N" => 0.0,
            _ => return Err(bad(index)),
        };
    }
    let impact_sub_score = 1.0 - impacts.iter().map(|impact| 1.0 - impact).product::<f64>();
    let impact = if scope_changed {
        7.52 * (impact_sub_score - 0.029) - 3.25 * (impact_sub_score - 0.02).powi(15)
    } else {
        6.42 * impact_sub_score
    };
    let exploitability =
        8.22 * attack_vector * attack_complexity * privileges_required * user_interaction;
    let tenths = if impact <= 0.0 {
        0
    } else if scope_changed {
        roundup_tenths((1.08 * (impact + exploitability)).min(10.0))
    } else {
        roundup_tenths((impact + exploitability).min(10.0))
    };
    Ok(VectorScore::Scored {
        version,
        score: CvssScore::from_tenths(tenths)?,
    })
}

/// CVSS v3.1 Appendix A Roundup, in tenths: the smallest number of tenths at or above
/// `input`, computed on an integer scale so that floating-point noise such as
/// 4.000000000000001 rounds to 4.0.
pub fn roundup_tenths(input: f64) -> u8 {
    let scaled = (input * 100_000.0).round().clamp(0.0, 1_000_000.0) as u32;
    let tenths = if scaled % 10_000 == 0 {
        scaled / 10_000
    } else {
        scaled / 10_000 + 1
    };
    u8::try_from(tenths.min(u32::from(CvssScore::MAX_TENTHS))).unwrap_or(CvssScore::MAX_TENTHS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scored(vector: &str) -> u8 {
        match score_vector(vector).unwrap() {
            VectorScore::Scored { score, .. } => score.tenths(),
            VectorScore::Unscored { .. } => panic!("unscored"),
        }
    }

    #[test]
    fn base_scores_match_the_worked_numbers() {
        assert_eq!(scored("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 98);
        assert_eq!(scored("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 100);
        assert_eq!(scored("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"), 75);
        assert_eq!(scored("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 61);
        // PR:L weighs 0.68 when the scope changes.
        assert_eq!(scored("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"), 64);
        assert_eq!(scored("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), 55);
        assert_eq!(scored("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"), 31);
        assert_eq!(scored("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0);
        assert_eq!(scored("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N"), 0);
        // Temporal and environmental metrics do not change the base score.
        assert_eq!(
            scored("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/MAV:L"),
            98
        );
        // Metric order is free.
        assert_eq!(scored("CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N"), 98);
    }

    #[test]
    fn roundup_follows_appendix_a() {
        assert_eq!(roundup_tenths(4.02), 41);
        assert_eq!(roundup_tenths(4.0), 40);
        assert_eq!(roundup_tenths(4.000_000_000_000_001), 40);
        assert_eq!(roundup_tenths(9.760_41), 98);
        assert_eq!(roundup_tenths(0.0), 0);
        assert_eq!(roundup_tenths(10.0), 100);
        assert_eq!(roundup_tenths(17.0), 100);
    }

    #[test]
    fn ratings_follow_the_qualitative_scale() {
        let rating = |tenths| CvssScore::from_tenths(tenths).unwrap().rating();
        assert_eq!(rating(0), CvssRating::None);
        assert_eq!(rating(1), CvssRating::Low);
        assert_eq!(rating(39), CvssRating::Low);
        assert_eq!(rating(40), CvssRating::Medium);
        assert_eq!(rating(69), CvssRating::Medium);
        assert_eq!(rating(70), CvssRating::High);
        assert_eq!(rating(89), CvssRating::High);
        assert_eq!(rating(90), CvssRating::Critical);
        assert_eq!(rating(100), CvssRating::Critical);
        assert_eq!(CvssScore::from_tenths(101), Err(CvssError::ScoreOutOfRange));
    }

    #[test]
    fn decimal_scores_are_read_strictly() {
        let tenths = |text| CvssScore::parse_decimal(text).map(CvssScore::tenths);
        assert_eq!(tenths("9.8"), Ok(98));
        assert_eq!(tenths("10.0"), Ok(100));
        assert_eq!(tenths("10"), Ok(100));
        assert_eq!(tenths("0"), Ok(0));
        assert_eq!(tenths("10.1"), Err(CvssError::ScoreOutOfRange));
        assert_eq!(tenths("99"), Err(CvssError::ScoreOutOfRange));
        for malformed in [
            "", "9.85", "-1", "1e1", "nan", "9.", ".5", " 9.8", "9,8", "100",
        ] {
            assert!(tenths(malformed).is_err(), "{malformed:?} was accepted");
        }
        assert_eq!(CvssScore::parse_decimal("7.5").unwrap().to_string(), "7.5");
    }

    #[test]
    fn malformed_vectors_are_refused() {
        let error = |vector: &str| score_vector(vector).err();
        assert_eq!(
            error("AV:N/AC:L/Au:N/C:P/I:P/A:P"),
            Some(CvssError::UnknownVersion)
        );
        assert_eq!(error("CVSS:2.0/AV:N"), Some(CvssError::UnknownVersion));
        assert_eq!(
            error("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"),
            Some(CvssError::MissingMetric { metric: "A" })
        );
        assert_eq!(
            error("CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some(CvssError::DuplicateMetric)
        );
        assert_eq!(
            error("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/E:P"),
            Some(CvssError::DuplicateMetric)
        );
        assert_eq!(
            error("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some(CvssError::BadValue { metric: "AV" })
        );
        assert_eq!(
            error("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:1"),
            Some(CvssError::UnknownMetric)
        );
        assert_eq!(error("CVSS:3.1/AV:N//AC:L"), Some(CvssError::MalformedPart));
        assert_eq!(error("CVSS:3.1/"), Some(CvssError::MalformedPart));
        let long = format!("CVSS:3.1/{}", "E:X/".repeat(70));
        assert_eq!(error(&long), Some(CvssError::VectorTooLong));
    }

    #[test]
    fn a_v4_vector_is_scored_by_its_base_metrics() {
        // FIRST's CVSS v4.0 examples, CVE-2022-26134: Base 9.3.
        assert_eq!(
            score_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
            Ok(VectorScore::Scored {
                version: CvssVersion::V4_0,
                score: CvssScore::from_tenths(93).unwrap()
            })
        );
        // The threat metric does not enter the base score.
        assert_eq!(
            score_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U"),
            score_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
        );
        assert_eq!(
            parse_v4(V4_BASE).unwrap().base_score(),
            Ok(CvssScore::from_tenths(93).unwrap())
        );
    }

    const V4_BASE: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";

    #[test]
    fn v4_vectors_are_read_in_full() {
        let vector = parse_v4(V4_BASE).unwrap();
        assert_eq!(vector.base_value("AV"), Some("N"));
        assert_eq!(vector.base_value("SA"), Some("N"));
        assert_eq!(vector.base_value("E"), None);
        // Every metric group, Not Defined values and the longest supplemental value.
        let full = format!(
            "{V4_BASE}/E:U/CR:L/IR:X/AR:M/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:N/MVI:N/MVA:N/MSC:L/MSI:S/MSA:X/S:P/AU:Y/R:I/V:C/RE:H/U:Amber"
        );
        assert!(full.len() <= MAX_VECTOR_BYTES);
        assert_eq!(parse_v4(&full).unwrap(), vector);
        // Order is free, as in v3.
        assert!(
            parse_v4("CVSS:4.0/SA:N/SI:N/SC:N/VA:H/VI:H/VC:H/UI:N/PR:N/AT:N/AC:L/AV:N").is_ok()
        );
    }

    #[test]
    fn malformed_v4_vectors_are_refused() {
        let error = |vector: &str| parse_v4(vector).err();
        assert_eq!(
            error("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N"),
            Some(CvssError::MissingMetric { metric: "SA" })
        );
        assert_eq!(
            error(&format!("{V4_BASE}/AV:L")),
            Some(CvssError::DuplicateMetric)
        );
        assert_eq!(
            error(&format!("{V4_BASE}/E:A/E:P")),
            Some(CvssError::DuplicateMetric)
        );
        assert_eq!(
            error("CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
            Some(CvssError::BadValue { metric: "AV" })
        );
        // A v3 value, and a value that is only valid for the modified metric.
        assert_eq!(
            error("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
            Some(CvssError::BadValue { metric: "UI" })
        );
        assert_eq!(
            error("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:S/SA:N"),
            Some(CvssError::BadValue { metric: "SI" })
        );
        assert_eq!(
            error(&format!("{V4_BASE}/U:amber")),
            Some(CvssError::BadValue { metric: "U" })
        );
        assert_eq!(
            error(&format!("{V4_BASE}/S:U")),
            Some(CvssError::BadValue { metric: "S" })
        );
        // v3-only metrics are unknown in v4.
        assert_eq!(
            error(&format!("{V4_BASE}/RL:O")),
            Some(CvssError::UnknownMetric)
        );
        assert_eq!(error("CVSS:4.0/AV:N//AC:L"), Some(CvssError::MalformedPart));
        assert_eq!(error("CVSS:4.0/"), Some(CvssError::MalformedPart));
        assert_eq!(
            error("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some(CvssError::UnknownVersion)
        );
        let long = format!("{V4_BASE}/{}", "E:X/".repeat(60));
        assert_eq!(error(&long), Some(CvssError::VectorTooLong));
        // score_vector refuses what parse_v4 refuses, instead of scoring it.
        assert_eq!(
            score_vector("CVSS:4.0/AV:N/ZZ:1"),
            Err(CvssError::UnknownMetric)
        );
        assert_eq!(
            score_vector("CVSS:4.0/AV:N/garbage"),
            Err(CvssError::MalformedPart)
        );
        assert_eq!(
            score_vector("CVSS:4.0/AV:N"),
            Err(CvssError::MissingMetric { metric: "AC" })
        );
    }

    #[test]
    fn v4_macro_vectors_follow_the_equivalence_sets() {
        let macro_vector = |vector: &str| parse_v4(vector).unwrap().macro_vector().to_string();
        assert_eq!(macro_vector(V4_BASE), "000200");
        assert_eq!(
            macro_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"),
            "000100"
        );
        // EQ1 1: some of AV:N, PR:N, UI:N, and AV is not P.
        assert_eq!(
            macro_vector("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:N/SC:H/SI:N/SA:N"),
            "101100"
        );
        // EQ1 2: AV:P, or none of the three; EQ2 1; EQ3 2 and EQ6 1 without any H.
        assert_eq!(
            macro_vector("CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"),
            "212201"
        );
        assert_eq!(
            macro_vector("CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:A/VC:L/VI:L/VA:H/SC:L/SI:L/SA:L"),
            "211200"
        );
        // Threat and environmental metrics do not move the base macro vector.
        assert_eq!(
            macro_vector(&format!("{V4_BASE}/E:U/CR:L/IR:L/AR:L/MSI:S/MAV:P")),
            "000200"
        );
        let json = serde_json::to_value(parse_v4(V4_BASE).unwrap().macro_vector()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"eq1": 0, "eq2": 0, "eq3": 0, "eq4": 2, "eq5": 0, "eq6": 0})
        );
    }
}
