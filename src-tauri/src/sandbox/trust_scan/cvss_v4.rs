//! CVSS v4.0 base scores, to give scanner findings with a v4.0 vector a documented
//! severity (§8.3 line 2459: "Define severity"; VM-W47 line 2670: "Gate by ... severity").
//!
//! The score is the one the "CVSS v4.0 Specification Document" (FIRST, version 1.2,
//! 2024-06-18) defines in section 8.2, "CVSS v4.0 Scoring using MacroVectors and
//! Interpolation", computed as its reference implementation `cvss_score.js` computes it
//! (<https://github.com/FIRSTdotorg/cvss-v4-calculator>, main branch at commit c5b0d40),
//! from the reference data transcribed in `cvss_v4_data`:
//!
//! 1. A vector whose six impact metrics VC, VI, VA, SC, SI and SA are all None scores 0.0.
//! 2. Otherwise the vector's macro vector ([`CvssV4Vector::macro_vector`]) gives the
//!    starting score, the score of its highest severity vectors.
//! 3. For each of EQ1, EQ2, EQ3 with EQ6, EQ4 and EQ5: the maximal scoring difference is
//!    the starting score minus the score of the next lower macro vector (for EQ3 and EQ6
//!    at levels 0 and 0, the higher of the two next lower ones); without a lower macro
//!    vector the set is left out. The severity distance is the sum, over the set's
//!    metrics, of the vector's level minus the level of the first highest severity vector
//!    of its macro vector that is at or above it in every metric; divided by the depth of
//!    the level it gives the proportion, and the maximal scoring difference times the
//!    proportion is the set's proportional distance. EQ5's proportion is always 0, but EQ5
//!    still counts when its lower macro vector exists.
//! 4. The score is the starting score minus the mean proportional distance of the sets
//!    that count, clamped to 0.0–10.0 and rounded to one decimal, half up
//!    (`Math.round(value * 10) / 10`).
//!
//! The arithmetic is the reference's: the same binary floating-point operations in the
//! same order, so that a result near a rounding boundary rounds as the reference rounds.
//!
//! This is the base score, CVSS-B ("Base metrics") in the nomenclature of the
//! specification's introduction, and only that: Exploit Maturity takes its Not Defined
//! value (Attacked), the security requirements CR, IR and AR take theirs (High), and no
//! modified base metric is read, so the threat, environmental and supplemental metrics a
//! vector carries never change its score here. A threat or environmental score (CVSS-BT,
//! CVSS-BE, CVSS-BTE) is not computed.

use std::fmt;

use serde::Serialize;

use super::cvss::{CvssScore, CvssV4Vector, MacroVector};
use super::cvss_v4_data::{
    EQ1_DEPTHS, EQ1_HIGHEST, EQ2_DEPTHS, EQ2_HIGHEST, EQ3_EQ6_DEPTHS, EQ3_EQ6_HIGHEST, EQ4_DEPTHS,
    EQ4_HIGHEST, MACRO_VECTOR_SCORES, SEVERITY_LEVELS, STEP,
};

/// The metrics of each equivalence set whose severity distances the reference adds, in its
/// order of addition.
const EQ1_METRICS: [&str; 3] = ["AV", "PR", "UI"];
const EQ2_METRICS: [&str; 2] = ["AC", "AT"];
const EQ3_EQ6_METRICS: [&str; 6] = ["VC", "VI", "VA", "CR", "IR", "AR"];
const EQ4_METRICS: [&str; 3] = ["SC", "SI", "SA"];

/// The impact metrics whose values all None give 0.0.
const IMPACT_METRICS: [&str; 6] = ["VC", "VI", "VA", "SC", "SI", "SA"];

/// Why a CVSS v4.0 vector has no base score here: the reference data lacks an entry the
/// algorithm needs. The data covers every base vector (the test
/// `every_base_vector_is_scored` scores all 104,976), so this is a typed refusal kept for
/// the case the data cannot cover, never a guessed score. Serialize only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "gap", rename_all = "snake_case")]
pub enum V4NotScored {
    /// `cvssLookup_global` has no score for the vector's macro vector.
    NoMacroVectorScore { macro_vector: MacroVector },
    /// No highest severity vector of the macro vector's level in this equivalence set is
    /// at or above the vector in each of the set's metrics.
    NoHighestSeverityVector {
        macro_vector: MacroVector,
        equivalence_set: &'static str,
    },
    /// `maxSeverity` has no depth for the macro vector's level in this equivalence set.
    NoDepth {
        macro_vector: MacroVector,
        equivalence_set: &'static str,
    },
    /// A metric value has no severity level in the reference data.
    NoSeverityLevel { metric: &'static str },
}

impl fmt::Display for V4NotScored {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMacroVectorScore { macro_vector } => write!(
                f,
                "the CVSS v4.0 reference data has no score for macro vector {macro_vector}"
            ),
            Self::NoHighestSeverityVector {
                macro_vector,
                equivalence_set,
            } => write!(
                f,
                "no highest severity vector of macro vector {macro_vector} is at or above \
                 the vector in {equivalence_set}"
            ),
            Self::NoDepth {
                macro_vector,
                equivalence_set,
            } => write!(
                f,
                "the CVSS v4.0 reference data has no depth for macro vector {macro_vector} \
                 in {equivalence_set}"
            ),
            Self::NoSeverityLevel { metric } => write!(
                f,
                "the CVSS v4.0 reference data has no severity level for a value of {metric}"
            ),
        }
    }
}

impl std::error::Error for V4NotScored {}

/// The CVSS-B base score of a checked v4.0 vector (see the module documentation).
pub fn v4_base_score(vector: &CvssV4Vector) -> Result<CvssScore, V4NotScored> {
    if IMPACT_METRICS
        .iter()
        .all(|metric| vector.base_value(metric) == Some("N"))
    {
        return Ok(CvssScore::saturating_from_tenths(0));
    }
    let macro_vector = vector.macro_vector();
    let value =
        macro_vector_score(macro_vector).ok_or(V4NotScored::NoMacroVectorScore { macro_vector })?;
    let MacroVector {
        eq1,
        eq2,
        eq3,
        eq4,
        eq5,
        eq6,
    } = macro_vector;
    let score_at = |eq1, eq2, eq3, eq4, eq5, eq6| {
        macro_vector_score(MacroVector {
            eq1,
            eq2,
            eq3,
            eq4,
            eq5,
            eq6,
        })
    };
    let down = |level: u8| level.saturating_add(1);

    // Step 3a: the next lower macro vectors; None where the table has none.
    let lower_eq1 = score_at(down(eq1), eq2, eq3, eq4, eq5, eq6);
    let lower_eq2 = score_at(eq1, down(eq2), eq3, eq4, eq5, eq6);
    let lower_eq3_eq6 = match (eq3, eq6) {
        // 11 to 21 and 01 to 11.
        (1, 1) | (0, 1) => score_at(eq1, eq2, down(eq3), eq4, eq5, eq6),
        // 10 to 11.
        (1, 0) => score_at(eq1, eq2, eq3, eq4, eq5, down(eq6)),
        // 00 to 01 or to 10, whichever scores higher; on a tie, or where either is
        // missing, the reference takes the second (`left > right ? left : right`).
        (0, 0) => {
            let left = score_at(eq1, eq2, eq3, eq4, eq5, down(eq6));
            let right = score_at(eq1, eq2, down(eq3), eq4, eq5, eq6);
            match (left, right) {
                (Some(left_score), Some(right_score)) if left_score > right_score => left,
                _ => right,
            }
        }
        // 21 to 32, which does not exist.
        _ => score_at(eq1, eq2, down(eq3), eq4, eq5, down(eq6)),
    };
    let lower_eq4 = score_at(eq1, eq2, eq3, down(eq4), eq5, eq6);
    let lower_eq5 = score_at(eq1, eq2, eq3, eq4, down(eq5), eq6);

    // Step 3b: the severity distance in each set from its first highest severity vector at
    // or above the vector.
    let joint_highest = EQ3_EQ6_HIGHEST
        .iter()
        .find(|(level3, level6, _)| *level3 == eq3 && *level6 == eq6)
        .map(|(_, _, vectors)| *vectors);
    let distance_eq1 = distance(
        vector,
        macro_vector,
        "EQ1",
        &EQ1_METRICS,
        level_of(&EQ1_HIGHEST, eq1),
    )?;
    let distance_eq2 = distance(
        vector,
        macro_vector,
        "EQ2",
        &EQ2_METRICS,
        level_of(&EQ2_HIGHEST, eq2),
    )?;
    let distance_eq3_eq6 = distance(
        vector,
        macro_vector,
        "EQ3 and EQ6",
        &EQ3_EQ6_METRICS,
        joint_highest,
    )?;
    let distance_eq4 = distance(
        vector,
        macro_vector,
        "EQ4",
        &EQ4_METRICS,
        level_of(&EQ4_HIGHEST, eq4),
    )?;

    // Step 3c: the depths, in steps.
    let depth = |depth: Option<u8>, equivalence_set| {
        depth
            .map(|steps| f64::from(steps) * STEP)
            .ok_or(V4NotScored::NoDepth {
                macro_vector,
                equivalence_set,
            })
    };
    let depth_eq1 = depth(EQ1_DEPTHS.get(usize::from(eq1)).copied(), "EQ1")?;
    let depth_eq2 = depth(EQ2_DEPTHS.get(usize::from(eq2)).copied(), "EQ2")?;
    let depth_eq3_eq6 = depth(
        EQ3_EQ6_DEPTHS
            .iter()
            .find(|(level3, level6, _)| *level3 == eq3 && *level6 == eq6)
            .map(|(_, _, steps)| *steps),
        "EQ3 and EQ6",
    )?;
    let depth_eq4 = depth(EQ4_DEPTHS.get(usize::from(eq4)).copied(), "EQ4")?;

    // Step 3d: the proportional distances of the sets with a lower macro vector.
    let mut counted: u8 = 0;
    let mut proportional = |lower: Option<f64>, distance: f64, depth: f64| match lower {
        Some(lower) => {
            counted = counted.saturating_add(1);
            let available = value - lower;
            let proportion = distance / depth;
            available * proportion
        }
        None => 0.0,
    };
    let normalized_eq1 = proportional(lower_eq1, distance_eq1, depth_eq1);
    let normalized_eq2 = proportional(lower_eq2, distance_eq2, depth_eq2);
    let normalized_eq3_eq6 = proportional(lower_eq3_eq6, distance_eq3_eq6, depth_eq3_eq6);
    let normalized_eq4 = proportional(lower_eq4, distance_eq4, depth_eq4);
    // EQ5's proportion is 0: it adds nothing but counts in the mean.
    let normalized_eq5 = proportional(lower_eq5, 0.0, 1.0);

    // Step 4.
    let mean_distance = if counted == 0 {
        0.0
    } else {
        (normalized_eq1 + normalized_eq2 + normalized_eq3_eq6 + normalized_eq4 + normalized_eq5)
            / f64::from(counted)
    };
    let score = (value - mean_distance).clamp(0.0, 10.0);
    // In 0.0..=100.0 after the clamp, so the conversion neither truncates nor saturates.
    let tenths = (score * 10.0).round() as u8;
    Ok(CvssScore::saturating_from_tenths(tenths))
}

/// The score `cvssLookup_global` gives `macro_vector`, if it lists it. The table is in
/// ascending key order, as published (a test checks it), so a binary search finds a row;
/// were it not, a row would be missed and the vector not scored, never scored wrongly.
fn macro_vector_score(macro_vector: MacroVector) -> Option<f64> {
    let MacroVector {
        eq1,
        eq2,
        eq3,
        eq4,
        eq5,
        eq6,
    } = macro_vector;
    let key = [eq1, eq2, eq3, eq4, eq5, eq6].map(|level| b'0'.saturating_add(level));
    MACRO_VECTOR_SCORES
        .binary_search_by(|(digits, _)| digits.as_bytes().cmp(key.as_slice()))
        .ok()
        .and_then(|index| MACRO_VECTOR_SCORES.get(index))
        .map(|(_, score)| *score)
}

/// The highest severity vectors of `level`, if the data lists the level.
fn level_of(levels: &[&'static [&'static str]], level: u8) -> Option<&'static [&'static str]> {
    levels.get(usize::from(level)).copied()
}

/// The severity distance of `vector` in one equivalence set: the levels of its values of
/// `metrics` minus those of the first of `highest` at or above it in every one of them,
/// added in the order of `metrics`.
fn distance(
    vector: &CvssV4Vector,
    macro_vector: MacroVector,
    equivalence_set: &'static str,
    metrics: &[&'static str],
    highest: Option<&'static [&'static str]>,
) -> Result<f64, V4NotScored> {
    'highest: for &candidate in highest.unwrap_or_default() {
        let mut total = 0.0;
        for &metric in metrics {
            let own = level(metric, base_value(vector, metric))?;
            let top = level(metric, value_in(candidate, metric))?;
            let step = own - top;
            if step < 0.0 {
                continue 'highest;
            }
            total += step;
        }
        return Ok(total);
    }
    Err(V4NotScored::NoHighestSeverityVector {
        macro_vector,
        equivalence_set,
    })
}

/// The value the base score reads for `metric`: the vector's own value for a base metric,
/// and High, the Not Defined value, for the security requirements CR, IR and AR.
fn base_value(vector: &CvssV4Vector, metric: &str) -> Option<&'static str> {
    match metric {
        "CR" | "IR" | "AR" => Some("H"),
        _ => vector.base_value(metric),
    }
}

/// The value of `metric` in a highest severity vector written as `maxComposed` writes it
/// (`AV:N/PR:N/UI:N/`).
fn value_in(highest: &'static str, metric: &str) -> Option<&'static str> {
    highest
        .split('/')
        .filter_map(|part| part.split_once(':'))
        .find(|(name, _)| *name == metric)
        .map(|(_, value)| value)
}

/// The severity level of `value` of `metric`.
fn level(metric: &'static str, value: Option<&str>) -> Result<f64, V4NotScored> {
    SEVERITY_LEVELS
        .iter()
        .find(|(name, _)| *name == metric)
        .and_then(|(_, levels)| {
            levels
                .iter()
                .find(|(level_value, _)| Some(*level_value) == value)
        })
        .map(|(_, level)| *level)
        .ok_or(V4NotScored::NoSeverityLevel { metric })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::sandbox::trust_scan::cvss::{
        parse_v4, score_vector, CvssVersion, VectorScore, V4_BASE_METRICS,
    };

    fn score(vector: &str) -> String {
        v4_base_score(&parse_v4(vector).unwrap())
            .unwrap()
            .to_string()
    }

    /// FIRST's published base scores: "Common Vulnerability Scoring System v4.0: Examples"
    /// (document version 1.9, <https://www.first.org/cvss/v4.0/examples>), the v4.0 row of
    /// each example's score table, and the "CVSS v4.0 User Guide" (version 1.2,
    /// <https://www.first.org/cvss/v4.0/user-guide>), its two assessed vulnerabilities.
    /// Rows labelled Base + Threat are included only with E:A, which is also Exploit
    /// Maturity's Not Defined value, so they are base scores. Where an example's title line
    /// states another score than its table (CVE-2023-48228: 9.4, CVE-2018-3652: 8.6,
    /// CVE-2026-31431: 10.0), the table row is used; for CVE-2026-42903 the vector shown
    /// is used, its link reads AV:L.
    const FIRST_EXAMPLES: [(&str, &str, &str); 46] = [
        (
            "CVE-2022-41741",
            "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "7.3",
        ),
        (
            "CVE-2020-3549",
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "7.7",
        ),
        (
            "CVE-2023-3089",
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N",
            "8.3",
        ),
        (
            "CVE-2021-44714",
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
            "4.6",
        ),
        (
            "CVE-2022-21830",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
            "5.1",
        ),
        (
            "CVE-2022-22186",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
            "6.9",
        ),
        (
            "CVE-2023-21989",
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N",
            "5.9",
        ),
        (
            "CVE-2020-3947",
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            "9.4",
        ),
        (
            "CVE-2023-48228",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:H",
            "9.3",
        ),
        (
            "CVE-2023-30560",
            "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N/S:P/V:D",
            "8.3",
        ),
        (
            "CVE-2026-96656",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A",
            "8.6",
        ),
        (
            "CVE-2014-0160",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A",
            "8.7",
        ),
        (
            "CVE-2021-44228",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A",
            "9.3",
        ),
        (
            "CVE-2014-6271",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A",
            "9.3",
        ),
        (
            "CVE-2013-6014",
            "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:N/SA:H",
            "6.4",
        ),
        (
            "CVE-2018-3652",
            "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "7.0",
        ),
        (
            "CVE-2023-30545",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            "7.1",
        ),
        (
            "CVE-2021-23846",
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            "8.2",
        ),
        (
            "CVE-2023-22394",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L",
            "8.7",
        ),
        (
            "CVE-2022-24682",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
            "5.1",
        ),
        (
            "CVE-2022-24682 variation 1",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
            "5.1",
        ),
        (
            "CVE-2020-0926",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
            "5.1",
        ),
        (
            "CVE-2024-55228",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N",
            "8.5",
        ),
        (
            "CVE-2023-5602",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
            "5.1",
        ),
        (
            "CVE-2022-20759",
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "7.7",
        ),
        (
            "CVE-2021-34724",
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            "8.3",
        ),
        (
            "CVE-2023-28311",
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "8.5",
        ),
        (
            "CVE-2022-22965",
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A",
            "9.2",
        ),
        (
            "CVE-2022-20826",
            "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "5.4",
        ),
        (
            "CVE-2022-21500",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            "8.7",
        ),
        (
            "CVE-2021-32570",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            "6.9",
        ),
        (
            "CVE-2022-26134",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "9.3",
        ),
        (
            "CVE-2023-20245",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N",
            "6.9",
        ),
        (
            "CVE-2023-20245 variation 1",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:N/SA:H",
            "7.8",
        ),
        (
            "CVE-2024-1233",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:L",
            "6.9",
        ),
        (
            "CVE-2023-28728",
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:P",
            "8.5",
        ),
        (
            "CVE-2022-47379",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:P/AU:Y/V:C/RE:L",
            "9.4",
        ),
        (
            "CVE-2020-10627",
            "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/S:P",
            "8.6",
        ),
        (
            "CVE-2020-28196",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/V:C",
            "8.7",
        ),
        (
            "CVE-2023-20048",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:L/SA:H",
            "6.4",
        ),
        (
            "CVE-2024-23897",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            "10.0",
        ),
        (
            "CVE-2026-31431",
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "8.5",
        ),
        (
            "CVE-2026-42903",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
            "7.1",
        ),
        (
            "CVE-2026-77810",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            "9.4",
        ),
        (
            "User Guide vulnerability 1",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            "8.7",
        ),
        (
            "User Guide vulnerability 2",
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "8.5",
        ),
    ];

    #[test]
    fn first_published_examples_score_as_published() {
        for (example, vector, published) in FIRST_EXAMPLES {
            assert_eq!(score(vector), published, "{example}: {vector}");
        }
        // They span Medium, High and Critical, from 4.6 (CVE-2021-44714) to 10.0
        // (CVE-2024-23897); FIRST publishes no None or Low base example.
        let scores: BTreeSet<CvssScore> = FIRST_EXAMPLES
            .iter()
            .map(|(_, vector, _)| v4_base_score(&parse_v4(vector).unwrap()).unwrap())
            .collect();
        assert_eq!(scores.first().map(|score| score.tenths()), Some(46));
        assert_eq!(scores.last().map(|score| score.tenths()), Some(100));
    }

    /// Two published base scores that FIRST's reference implementation does not give, and
    /// which are therefore not used above: the examples' log4shell (CVE-2021-44228)
    /// Variation 1 states Base 8.2 for this vector, which is the score of the same vector
    /// with E:P (regreSSHion, CVE-2024-6387, Base + Threat 8.2), and the User Guide states
    /// CVSS-B 5.1 for CVE-2013-0375. The reference data gives 9.2 and 5.3, and so does Red
    /// Hat's list of every base vector (see `REFERENCE_VECTORS`).
    #[test]
    fn published_scores_that_disagree_with_the_reference_follow_the_reference() {
        assert_eq!(
            score("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
            "9.2"
        );
        assert_eq!(
            score("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P"),
            "9.2",
            "a base score ignores E:P"
        );
        assert_eq!(
            score("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N"),
            "5.3"
        );
    }

    /// Base vectors with the scores in `tests/vectors_base4` of Red Hat's `cvss` Python
    /// library (<https://github.com/RedHatProductSecurity/cvss>), which lists all 104,976
    /// base vectors with their scores. Not a FIRST publication: an independent cross-check,
    /// chosen to cover None and Low, for which FIRST publishes no example.
    const REFERENCE_VECTORS: [(&str, &str); 25] = [
        (
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
            "0.0",
        ),
        (
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:L",
            "1.0",
        ),
        (
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N",
            "1.0",
        ),
        (
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:H",
            "1.8",
        ),
        (
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:L/SC:N/SI:N/SA:H",
            "1.8",
        ),
        (
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:H/SI:L/SA:N",
            "2.0",
        ),
        (
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:H/SA:H",
            "2.1",
        ),
        (
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:H/SA:H",
            "2.3",
        ),
        (
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H",
            "2.4",
        ),
        (
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
            "5.3",
        ),
        (
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:L/SC:N/SI:H/SA:N",
            "6.7",
        ),
        (
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:N/SC:H/SI:L/SA:N",
            "6.8",
        ),
        (
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:L/SC:L/SI:N/SA:H",
            "6.9",
        ),
        (
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:L/SC:N/SI:H/SA:H",
            "7.0",
        ),
        (
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:N/SC:H/SI:H/SA:L",
            "7.1",
        ),
        (
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:N/SC:H/SI:H/SA:H",
            "7.2",
        ),
        (
            "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:H",
            "8.3",
        ),
        (
            "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L",
            "8.5",
        ),
        (
            "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:H",
            "8.6",
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N",
            "8.8",
        ),
        (
            "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:L",
            "9.2",
        ),
        (
            "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:H",
            "9.4",
        ),
        (
            "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:N",
            "9.5",
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:L/SA:L",
            "9.9",
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L",
            "10.0",
        ),
    ];

    #[test]
    fn independent_reference_vectors_agree_across_all_ratings() {
        for (vector, expected) in REFERENCE_VECTORS {
            assert_eq!(score(vector), expected, "{vector}");
        }
    }

    #[test]
    fn no_impact_scores_zero() {
        // cvss_score.js: "Exception for no impact on system (shortcut)".
        for exploitability in [
            "AV:N/AC:L/AT:N/PR:N/UI:N",
            "AV:P/AC:H/AT:P/PR:H/UI:A",
            "AV:A/AC:L/AT:P/PR:L/UI:P",
        ] {
            assert_eq!(
                score(&format!(
                    "CVSS:4.0/{exploitability}/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
                )),
                "0.0"
            );
        }
        // One Low impact is enough to leave 0.0.
        assert_eq!(
            score("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N"),
            "1.0"
        );
    }

    /// The base vector of each highest severity vector: its base metrics, and CR, IR and AR
    /// checked to be High, the values a base score reads for them.
    fn base_vector_of(parts: &[&str]) -> String {
        let values: BTreeMap<&str, &str> = parts
            .iter()
            .flat_map(|part| part.split('/'))
            .filter(|part| !part.is_empty())
            .map(|part| part.split_once(':').unwrap())
            .collect();
        for requirement in ["CR", "IR", "AR"] {
            assert_eq!(values.get(requirement).copied().unwrap_or("H"), "H");
        }
        let metrics: Vec<String> = V4_BASE_METRICS
            .iter()
            .map(|metric| format!("{metric}:{}", values[metric]))
            .collect();
        format!("CVSS:4.0/{}", metrics.join("/"))
    }

    #[test]
    fn every_row_a_base_vector_reaches_scores_its_published_value() {
        // A base vector reaches EQ4 1 and 2 only (0 needs MSI:S or MSA:S), EQ5 0 only (E
        // is Not Defined) and EQ6 0 whenever one of VC, VI, VA is High (CR, IR and AR are
        // Not Defined, High), so EQ3 and EQ6 are 00, 10 or 21: 3 × 2 × 3 × 2 = 36 rows. At
        // each of its highest severity vectors every severity distance is 0, so the score
        // is the row's.
        let mut rows = 0;
        for (eq1, eq1_highest) in EQ1_HIGHEST.iter().enumerate() {
            for (eq2, eq2_highest) in EQ2_HIGHEST.iter().enumerate() {
                for (eq3, eq6, joint_highest) in EQ3_EQ6_HIGHEST {
                    for (eq4, eq4_highest) in EQ4_HIGHEST.iter().enumerate() {
                        if eq4 == 0 || !matches!((eq3, eq6), (0, 0) | (1, 0) | (2, 1)) {
                            continue;
                        }
                        let key = format!("{eq1}{eq2}{eq3}{eq4}0{eq6}");
                        let published = MACRO_VECTOR_SCORES
                            .iter()
                            .find(|(digits, _)| *digits == key)
                            .map(|(_, value)| format!("{value:.1}"))
                            .unwrap();
                        for &a in *eq1_highest {
                            for &b in *eq2_highest {
                                for &c in joint_highest {
                                    for &d in *eq4_highest {
                                        let vector = base_vector_of(&[a, b, c, d]);
                                        let parsed = parse_v4(&vector).unwrap();
                                        assert_eq!(parsed.macro_vector().to_string(), key);
                                        assert_eq!(score(&vector), published, "{vector}");
                                    }
                                }
                            }
                        }
                        rows += 1;
                    }
                }
            }
        }
        assert_eq!(rows, 36);
    }

    #[test]
    fn every_base_vector_is_scored() {
        // Every combination of base metric values, in V4_BASE_METRICS order.
        let options: [&[&str]; 11] = [
            &["N", "A", "L", "P"],
            &["L", "H"],
            &["N", "P"],
            &["N", "L", "H"],
            &["N", "P", "A"],
            &["H", "L", "N"],
            &["H", "L", "N"],
            &["H", "L", "N"],
            &["H", "L", "N"],
            &["H", "L", "N"],
            &["H", "L", "N"],
        ];
        let mut choice = [0_usize; 11];
        let mut scored = 0;
        let mut reached = BTreeSet::new();
        let mut ratings = BTreeSet::new();
        'vectors: loop {
            let metrics: Vec<String> = V4_BASE_METRICS
                .iter()
                .zip(options)
                .zip(choice)
                .map(|((metric, values), index)| format!("{metric}:{}", values[index]))
                .collect();
            let vector = parse_v4(&format!("CVSS:4.0/{}", metrics.join("/"))).unwrap();
            let base = v4_base_score(&vector);
            assert!(base.is_ok(), "{metrics:?}: {base:?}");
            if let Ok(base) = base {
                ratings.insert(base.rating());
            }
            reached.insert(vector.macro_vector());
            scored += 1;
            for position in (0..choice.len()).rev() {
                choice[position] += 1;
                if choice[position] < options[position].len() {
                    continue 'vectors;
                }
                choice[position] = 0;
            }
            break;
        }
        assert_eq!(scored, 104_976);
        // Exactly the 36 rows of every_row_a_base_vector_reaches_scores_its_published_value.
        assert_eq!(reached.len(), 36);
        assert!(reached.iter().all(|row| row.eq4 != 0
            && row.eq5 == 0
            && matches!((row.eq3, row.eq6), (0, 0) | (1, 0) | (2, 1))));
        assert_eq!(ratings.len(), 5, "None, Low, Medium, High and Critical");
    }

    #[test]
    fn threat_environmental_and_supplemental_metrics_leave_the_base_score() {
        // CVE-2020-3549: Base 7.7; with E:U FIRST states Base + Threat 5.2, which is not
        // computed here.
        let base = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
        assert_eq!(score(base), "7.7");
        for other in [
            "E:U",
            "E:P",
            "CR:L/IR:L/AR:L",
            "MSI:S/MSA:S",
            "MAV:P/MAC:H/MAT:P/MPR:H/MUI:A",
            "MVC:N/MVI:N/MVA:N/MSC:N",
            "S:P/AU:Y/R:I/V:C/RE:H/U:Red",
        ] {
            assert_eq!(score(&format!("{base}/{other}")), "7.7", "{other}");
        }
        assert_eq!(
            score_vector(&format!("{base}/E:U")),
            Ok(VectorScore::Scored {
                version: CvssVersion::V4_0,
                score: CvssScore::from_tenths(77).unwrap()
            })
        );
    }

    #[test]
    fn lookups_outside_the_table_find_nothing() {
        let row = |eq1, eq2, eq3, eq4, eq5, eq6| {
            macro_vector_score(MacroVector {
                eq1,
                eq2,
                eq3,
                eq4,
                eq5,
                eq6,
            })
        };
        assert_eq!(row(0, 0, 0, 0, 0, 0), Some(10.0));
        assert_eq!(row(2, 1, 2, 2, 2, 1), Some(0.1));
        assert_eq!(row(3, 0, 0, 1, 0, 0), None);
        assert_eq!(row(0, 2, 0, 1, 0, 0), None);
        assert_eq!(row(0, 0, 2, 1, 0, 0), None, "EQ3 2 has no EQ6 0");
        assert_eq!(row(0, 0, 3, 1, 0, 2), None);
        assert_eq!(value_in("AV:N/PR:L/UI:N/", "PR"), Some("L"));
        assert_eq!(value_in("AV:N/PR:L/UI:N/", "AC"), None);
        assert_eq!(
            level("SI", Some("S")),
            Ok(0.0),
            "Safety is the highest level of SI"
        );
        assert_eq!(
            level("AV", Some("X")),
            Err(V4NotScored::NoSeverityLevel { metric: "AV" })
        );
    }

    #[test]
    fn not_scored_reasons_display_and_serialize() {
        let macro_vector = MacroVector {
            eq1: 0,
            eq2: 0,
            eq3: 0,
            eq4: 1,
            eq5: 0,
            eq6: 0,
        };
        let gap = V4NotScored::NoHighestSeverityVector {
            macro_vector,
            equivalence_set: "EQ1",
        };
        assert_eq!(
            gap.to_string(),
            "no highest severity vector of macro vector 000100 is at or above the vector in EQ1"
        );
        assert_eq!(
            serde_json::to_value(gap).unwrap(),
            serde_json::json!({
                "gap": "no_highest_severity_vector",
                "macro_vector": {"eq1": 0, "eq2": 0, "eq3": 0, "eq4": 1, "eq5": 0, "eq6": 0},
                "equivalence_set": "EQ1"
            })
        );
        assert!(V4NotScored::NoMacroVectorScore { macro_vector }
            .to_string()
            .contains("000100"));
    }
}
