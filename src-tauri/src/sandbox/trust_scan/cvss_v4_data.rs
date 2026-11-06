//! FIRST's CVSS v4.0 reference data, as [`super::cvss_v4`] reads it for base scores
//! (§8.3 line 2459: "Define severity"; VM-W47 line 2670: "Gate by ... severity").
//!
//! The "CVSS v4.0 Specification Document" (FIRST, version 1.2, 2024-06-18), section 8.2
//! "CVSS v4.0 Scoring using MacroVectors and Interpolation", states that "A complete list
//! of all MacroVectors and associated scores can be found in the cvss_lookup.js file within
//! the CVSS v4.0 calculator reference implementation available on GitHub"
//! (<https://github.com/FIRSTdotorg/cvss-v4-calculator>). Everything below is transcribed
//! from that repository's main branch, whose latest commit is c5b0d40 of 19 August 2024:
//!
//! - [`MACRO_VECTOR_SCORES`]: `cvssLookup_global` of `cvss_lookup.js`;
//! - [`EQ1_DEPTHS`], [`EQ2_DEPTHS`], [`EQ3_EQ6_DEPTHS`], [`EQ4_DEPTHS`]: `maxSeverity` of
//!   `max_severity.js`;
//! - [`EQ1_HIGHEST`], [`EQ2_HIGHEST`], [`EQ3_EQ6_HIGHEST`], [`EQ4_HIGHEST`]: `maxComposed`
//!   of `max_composed.js`;
//! - [`SEVERITY_LEVELS`] and [`STEP`]: the `*_levels` objects and `step` of `cvss_score` in
//!   `cvss_score.js`.
//!
//! These files carry the notice "Copyright FIRST, Red Hat, and contributors" and
//! "SPDX-License-Identifier: BSD-2-Clause".
//!
//! Every number and vector is the published one, in the published order; only the notation
//! is Rust's (an integer score such as `10` is written `10.0`, objects keyed by level are
//! arrays indexed by level). The lookup table was read twice, from the raw file and from the
//! repository's page for it, and the two readings agree on all 270 rows; the highest
//! severity vectors are also the ones the specification lists in its Tables 24 to 29.
//! Nothing here is derived, completed or interpolated.
//!
//! Not transcribed, because a base score never reads them: `maxComposed.eq5` and
//! `maxSeverity.eq5` (the reference gives EQ5 a proportion of 0) and `E_levels` (Exploit
//! Maturity has no severity distance).

/// `cvssLookup_global`: the score of each macro vector, keyed by its levels EQ1 to EQ6
/// written as six digits ([`super::cvss::MacroVector`]'s `Display`). The score of a macro
/// vector is the score of its highest severity vectors.
pub(super) const MACRO_VECTOR_SCORES: [(&str, f64); 270] = [
    ("000000", 10.0),
    ("000001", 9.9),
    ("000010", 9.8),
    ("000011", 9.5),
    ("000020", 9.5),
    ("000021", 9.2),
    ("000100", 10.0),
    ("000101", 9.6),
    ("000110", 9.3),
    ("000111", 8.7),
    ("000120", 9.1),
    ("000121", 8.1),
    ("000200", 9.3),
    ("000201", 9.0),
    ("000210", 8.9),
    ("000211", 8.0),
    ("000220", 8.1),
    ("000221", 6.8),
    ("001000", 9.8),
    ("001001", 9.5),
    ("001010", 9.5),
    ("001011", 9.2),
    ("001020", 9.0),
    ("001021", 8.4),
    ("001100", 9.3),
    ("001101", 9.2),
    ("001110", 8.9),
    ("001111", 8.1),
    ("001120", 8.1),
    ("001121", 6.5),
    ("001200", 8.8),
    ("001201", 8.0),
    ("001210", 7.8),
    ("001211", 7.0),
    ("001220", 6.9),
    ("001221", 4.8),
    ("002001", 9.2),
    ("002011", 8.2),
    ("002021", 7.2),
    ("002101", 7.9),
    ("002111", 6.9),
    ("002121", 5.0),
    ("002201", 6.9),
    ("002211", 5.5),
    ("002221", 2.7),
    ("010000", 9.9),
    ("010001", 9.7),
    ("010010", 9.5),
    ("010011", 9.2),
    ("010020", 9.2),
    ("010021", 8.5),
    ("010100", 9.5),
    ("010101", 9.1),
    ("010110", 9.0),
    ("010111", 8.3),
    ("010120", 8.4),
    ("010121", 7.1),
    ("010200", 9.2),
    ("010201", 8.1),
    ("010210", 8.2),
    ("010211", 7.1),
    ("010220", 7.2),
    ("010221", 5.3),
    ("011000", 9.5),
    ("011001", 9.3),
    ("011010", 9.2),
    ("011011", 8.5),
    ("011020", 8.5),
    ("011021", 7.3),
    ("011100", 9.2),
    ("011101", 8.2),
    ("011110", 8.0),
    ("011111", 7.2),
    ("011120", 7.0),
    ("011121", 5.9),
    ("011200", 8.4),
    ("011201", 7.0),
    ("011210", 7.1),
    ("011211", 5.2),
    ("011220", 5.0),
    ("011221", 3.0),
    ("012001", 8.6),
    ("012011", 7.5),
    ("012021", 5.2),
    ("012101", 7.1),
    ("012111", 5.2),
    ("012121", 2.9),
    ("012201", 6.3),
    ("012211", 2.9),
    ("012221", 1.7),
    ("100000", 9.8),
    ("100001", 9.5),
    ("100010", 9.4),
    ("100011", 8.7),
    ("100020", 9.1),
    ("100021", 8.1),
    ("100100", 9.4),
    ("100101", 8.9),
    ("100110", 8.6),
    ("100111", 7.4),
    ("100120", 7.7),
    ("100121", 6.4),
    ("100200", 8.7),
    ("100201", 7.5),
    ("100210", 7.4),
    ("100211", 6.3),
    ("100220", 6.3),
    ("100221", 4.9),
    ("101000", 9.4),
    ("101001", 8.9),
    ("101010", 8.8),
    ("101011", 7.7),
    ("101020", 7.6),
    ("101021", 6.7),
    ("101100", 8.6),
    ("101101", 7.6),
    ("101110", 7.4),
    ("101111", 5.8),
    ("101120", 5.9),
    ("101121", 5.0),
    ("101200", 7.2),
    ("101201", 5.7),
    ("101210", 5.7),
    ("101211", 5.2),
    ("101220", 5.2),
    ("101221", 2.5),
    ("102001", 8.3),
    ("102011", 7.0),
    ("102021", 5.4),
    ("102101", 6.5),
    ("102111", 5.8),
    ("102121", 2.6),
    ("102201", 5.3),
    ("102211", 2.1),
    ("102221", 1.3),
    ("110000", 9.5),
    ("110001", 9.0),
    ("110010", 8.8),
    ("110011", 7.6),
    ("110020", 7.6),
    ("110021", 7.0),
    ("110100", 9.0),
    ("110101", 7.7),
    ("110110", 7.5),
    ("110111", 6.2),
    ("110120", 6.1),
    ("110121", 5.3),
    ("110200", 7.7),
    ("110201", 6.6),
    ("110210", 6.8),
    ("110211", 5.9),
    ("110220", 5.2),
    ("110221", 3.0),
    ("111000", 8.9),
    ("111001", 7.8),
    ("111010", 7.6),
    ("111011", 6.7),
    ("111020", 6.2),
    ("111021", 5.8),
    ("111100", 7.4),
    ("111101", 5.9),
    ("111110", 5.7),
    ("111111", 5.7),
    ("111120", 4.7),
    ("111121", 2.3),
    ("111200", 6.1),
    ("111201", 5.2),
    ("111210", 5.7),
    ("111211", 2.9),
    ("111220", 2.4),
    ("111221", 1.6),
    ("112001", 7.1),
    ("112011", 5.9),
    ("112021", 3.0),
    ("112101", 5.8),
    ("112111", 2.6),
    ("112121", 1.5),
    ("112201", 2.3),
    ("112211", 1.3),
    ("112221", 0.6),
    ("200000", 9.3),
    ("200001", 8.7),
    ("200010", 8.6),
    ("200011", 7.2),
    ("200020", 7.5),
    ("200021", 5.8),
    ("200100", 8.6),
    ("200101", 7.4),
    ("200110", 7.4),
    ("200111", 6.1),
    ("200120", 5.6),
    ("200121", 3.4),
    ("200200", 7.0),
    ("200201", 5.4),
    ("200210", 5.2),
    ("200211", 4.0),
    ("200220", 4.0),
    ("200221", 2.2),
    ("201000", 8.5),
    ("201001", 7.5),
    ("201010", 7.4),
    ("201011", 5.5),
    ("201020", 6.2),
    ("201021", 5.1),
    ("201100", 7.2),
    ("201101", 5.7),
    ("201110", 5.5),
    ("201111", 4.1),
    ("201120", 4.6),
    ("201121", 1.9),
    ("201200", 5.3),
    ("201201", 3.6),
    ("201210", 3.4),
    ("201211", 1.9),
    ("201220", 1.9),
    ("201221", 0.8),
    ("202001", 6.4),
    ("202011", 5.1),
    ("202021", 2.0),
    ("202101", 4.7),
    ("202111", 2.1),
    ("202121", 1.1),
    ("202201", 2.4),
    ("202211", 0.9),
    ("202221", 0.4),
    ("210000", 8.8),
    ("210001", 7.5),
    ("210010", 7.3),
    ("210011", 5.3),
    ("210020", 6.0),
    ("210021", 5.0),
    ("210100", 7.3),
    ("210101", 5.5),
    ("210110", 5.9),
    ("210111", 4.0),
    ("210120", 4.1),
    ("210121", 2.0),
    ("210200", 5.4),
    ("210201", 4.3),
    ("210210", 4.5),
    ("210211", 2.2),
    ("210220", 2.0),
    ("210221", 1.1),
    ("211000", 7.5),
    ("211001", 5.5),
    ("211010", 5.8),
    ("211011", 4.5),
    ("211020", 4.0),
    ("211021", 2.1),
    ("211100", 6.1),
    ("211101", 5.1),
    ("211110", 4.8),
    ("211111", 1.8),
    ("211120", 2.0),
    ("211121", 0.9),
    ("211200", 4.6),
    ("211201", 1.8),
    ("211210", 1.7),
    ("211211", 0.7),
    ("211220", 0.8),
    ("211221", 0.2),
    ("212001", 5.3),
    ("212011", 2.4),
    ("212021", 1.4),
    ("212101", 2.4),
    ("212111", 1.2),
    ("212121", 0.5),
    ("212201", 1.0),
    ("212211", 0.3),
    ("212221", 0.1),
];

/// `maxSeverity.eq1`, by EQ1 level: "max severity distances in EQs MacroVectors (+1)", the
/// depth that a severity distance in EQ1 is divided by, in steps of [`STEP`].
pub(super) const EQ1_DEPTHS: [u8; 3] = [1, 4, 5];

/// `maxSeverity.eq2`, by EQ2 level.
pub(super) const EQ2_DEPTHS: [u8; 2] = [1, 2];

/// `maxSeverity.eq3eq6`, as (EQ3 level, EQ6 level, depth); EQ3 and EQ6 are scored jointly.
pub(super) const EQ3_EQ6_DEPTHS: [(u8, u8, u8); 5] =
    [(0, 0, 7), (0, 1, 6), (1, 0, 8), (1, 1, 8), (2, 1, 10)];

/// `maxSeverity.eq4`, by EQ4 level.
pub(super) const EQ4_DEPTHS: [u8; 3] = [6, 5, 4];

/// `maxComposed.eq1`, by EQ1 level: the highest severity vectors of each level, in the
/// published order (the reference uses the first one at or above the scored vector).
pub(super) const EQ1_HIGHEST: [&[&str]; 3] = [
    &["AV:N/PR:N/UI:N/"],
    &["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
    &["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
];

/// `maxComposed.eq2`, by EQ2 level.
pub(super) const EQ2_HIGHEST: [&[&str]; 2] = [&["AC:L/AT:N/"], &["AC:H/AT:N/", "AC:L/AT:P/"]];

/// `maxComposed.eq3`, as (EQ3 level, EQ6 level, highest severity vectors).
pub(super) const EQ3_EQ6_HIGHEST: [(u8, u8, &[&str]); 5] = [
    (0, 0, &["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"]),
    (
        0,
        1,
        &[
            "VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/",
            "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/",
        ],
    ),
    (
        1,
        0,
        &[
            "VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/",
            "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/",
        ],
    ),
    (
        1,
        1,
        &[
            "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
            "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
            "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
            "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
            "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
        ],
    ),
    (2, 1, &["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]),
];

/// `maxComposed.eq4`, by EQ4 level.
pub(super) const EQ4_HIGHEST: [&[&str]; 3] = [
    &["SC:H/SI:S/SA:S/"],
    &["SC:H/SI:H/SA:H/"],
    &["SC:L/SI:L/SA:L/"],
];

/// `step` of `cvss_score`: one stepwise change of a metric, the unit of [`SEVERITY_LEVELS`]
/// and of the depths.
pub(super) const STEP: f64 = 0.1;

/// The `AV_levels` to `AR_levels` objects of `cvss_score`, in the order the source defines
/// them: each metric value's severity level, so that the severity distance of a value from
/// a highest severity vector's value is the difference of their levels.
pub(super) const SEVERITY_LEVELS: [(&str, &[(&str, f64)]); 14] = [
    ("AV", &[("N", 0.0), ("A", 0.1), ("L", 0.2), ("P", 0.3)]),
    ("PR", &[("N", 0.0), ("L", 0.1), ("H", 0.2)]),
    ("UI", &[("N", 0.0), ("P", 0.1), ("A", 0.2)]),
    ("AC", &[("L", 0.0), ("H", 0.1)]),
    ("AT", &[("N", 0.0), ("P", 0.1)]),
    ("VC", &[("H", 0.0), ("L", 0.1), ("N", 0.2)]),
    ("VI", &[("H", 0.0), ("L", 0.1), ("N", 0.2)]),
    ("VA", &[("H", 0.0), ("L", 0.1), ("N", 0.2)]),
    ("SC", &[("H", 0.1), ("L", 0.2), ("N", 0.3)]),
    ("SI", &[("S", 0.0), ("H", 0.1), ("L", 0.2), ("N", 0.3)]),
    ("SA", &[("S", 0.0), ("H", 0.1), ("L", 0.2), ("N", 0.3)]),
    ("CR", &[("H", 0.0), ("M", 0.1), ("L", 0.2)]),
    ("IR", &[("H", 0.0), ("M", 0.1), ("L", 0.2)]),
    ("AR", &[("H", 0.0), ("M", 0.1), ("L", 0.2)]),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lookup_table_has_one_score_per_macro_vector() {
        // EQ1 0–2, EQ2 0–1, EQ3 and EQ6 jointly 00, 01, 10, 11 or 21, EQ4 0–2, EQ5 0–2.
        let mut expected = Vec::new();
        for eq1 in 0..3 {
            for eq2 in 0..2 {
                for (eq3, eq6) in [(0, 0), (0, 1), (1, 0), (1, 1), (2, 1)] {
                    for eq4 in 0..3 {
                        for eq5 in 0..3 {
                            expected.push(format!("{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"));
                        }
                    }
                }
            }
        }
        let mut keys: Vec<String> = MACRO_VECTOR_SCORES
            .iter()
            .map(|(key, _)| key.to_string())
            .collect();
        keys.sort();
        expected.sort();
        assert_eq!(keys, expected);
        // Published in ascending key order, as cvss_lookup.js lists them.
        assert!(MACRO_VECTOR_SCORES
            .windows(2)
            .all(|pair| pair[0].0 < pair[1].0));
        for (key, score) in MACRO_VECTOR_SCORES {
            let tenths = score * 10.0;
            assert!(
                (0.0..=100.0).contains(&tenths) && (tenths - tenths.round()).abs() < 1e-9,
                "{key}: {score}"
            );
        }
        assert_eq!(MACRO_VECTOR_SCORES[0], ("000000", 10.0));
        assert_eq!(MACRO_VECTOR_SCORES[269], ("212221", 0.1));
    }

    #[test]
    fn every_highest_severity_vector_names_each_metric_of_its_set_once() {
        let sets: [(&[&str], Vec<&[&str]>); 4] = [
            (&["AV", "PR", "UI"], EQ1_HIGHEST.to_vec()),
            (&["AC", "AT"], EQ2_HIGHEST.to_vec()),
            (
                &["VC", "VI", "VA", "CR", "IR", "AR"],
                EQ3_EQ6_HIGHEST
                    .iter()
                    .map(|(_, _, vectors)| *vectors)
                    .collect(),
            ),
            (&["SC", "SI", "SA"], EQ4_HIGHEST.to_vec()),
        ];
        for (metrics, levels) in sets {
            for vector in levels.into_iter().flatten() {
                let parts: Vec<(&str, &str)> = vector
                    .strip_suffix('/')
                    .unwrap()
                    .split('/')
                    .map(|part| part.split_once(':').unwrap())
                    .collect();
                let names: Vec<&str> = parts.iter().map(|(name, _)| *name).collect();
                assert_eq!(names, metrics, "{vector}");
                for (name, value) in parts {
                    let levels = SEVERITY_LEVELS
                        .iter()
                        .find(|(metric, _)| *metric == name)
                        .unwrap()
                        .1;
                    assert!(levels.iter().any(|(level, _)| *level == value), "{vector}");
                }
            }
        }
        // One depth per level, and per joint EQ3/EQ6 level, as listed with the vectors.
        assert_eq!(EQ1_DEPTHS.len(), EQ1_HIGHEST.len());
        assert_eq!(EQ2_DEPTHS.len(), EQ2_HIGHEST.len());
        assert_eq!(EQ4_DEPTHS.len(), EQ4_HIGHEST.len());
        let depth_levels: Vec<(u8, u8)> = EQ3_EQ6_DEPTHS
            .iter()
            .map(|(eq3, eq6, _)| (*eq3, *eq6))
            .collect();
        let vector_levels: Vec<(u8, u8)> = EQ3_EQ6_HIGHEST
            .iter()
            .map(|(eq3, eq6, _)| (*eq3, *eq6))
            .collect();
        assert_eq!(depth_levels, vector_levels);
    }

    #[test]
    fn severity_levels_cover_every_value_a_base_vector_or_requirement_takes() {
        use crate::sandbox::trust_scan::cvss::V4_BASE_METRICS;
        let names: Vec<&str> = SEVERITY_LEVELS.iter().map(|(name, _)| *name).collect();
        for metric in V4_BASE_METRICS {
            assert!(names.contains(&metric), "{metric}");
        }
        for metric in ["CR", "IR", "AR"] {
            assert!(names.contains(&metric));
        }
        // Each level is one step above the previous.
        for (metric, levels) in SEVERITY_LEVELS {
            for pair in levels.windows(2) {
                assert!(((pair[1].1 - pair[0].1) - STEP).abs() < 1e-9, "{metric}");
            }
        }
    }
}
