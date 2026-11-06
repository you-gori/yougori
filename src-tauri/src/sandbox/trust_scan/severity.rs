//! The documented mapping from what a scanner says about severity to trust's
//! [`Severity`] (line 2459: "Define severity"; VM-W47, line 2670).
//!
//! | Basis | Reported value | Severity |
//! | --- | --- | --- |
//! | Trivy label | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | the same level |
//! | CVSS base score (OSV-Scanner's group `max_severity`, or computed here from a v3.0, v3.1 or v4.0 vector) | 0.0–3.9 | Low |
//! | | 4.0–6.9 | Medium |
//! | | 7.0–8.9 | High |
//! | | 9.0–10.0 | Critical |
//! | unknown: Trivy `UNKNOWN`, no score or vector, or a vector left unscored | — | Critical |
//!
//! A score computed from a v4.0 vector is its base score, CVSS-B: the vector's threat,
//! environmental and supplemental metrics do not change it (see [`super::cvss_v4`]).
//!
//! CVSS "None" (0.0) maps to Low because trust has no lower level; the finding stays
//! visible. Unknown severity maps to Critical: a severity nobody determined never
//! softens the gate, as undetermined applicability and reachability do not (the VT1
//! decision). The basis travels with the finding, so a reader sees which row applied.

use serde::Serialize;

use super::cvss::{CvssScore, CvssVersion};
use crate::sandbox::trust::Severity;

/// A scanner's own severity label (Trivy).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerLabel {
    Low,
    Medium,
    High,
    Critical,
}

/// Why no severity could be determined.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownSeverity {
    /// The report states no score, vector or label for the finding.
    NotReported,
    /// The scanner labelled the finding `UNKNOWN`.
    ScannerSaidUnknown,
    /// The only vector is one [`super::cvss`] leaves unscored
    /// ([`VectorScore::Unscored`](super::cvss::VectorScore::Unscored)); no vector of a
    /// version it reads does so today.
    UnscoredVector { version: CvssVersion },
}

/// What a finding's severity was derived from (line 2459: "Define severity").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "basis", rename_all = "snake_case")]
pub enum SeverityBasis {
    ScannerLabel {
        label: ScannerLabel,
    },
    /// A CVSS base score the report states.
    ReportedScore {
        score: CvssScore,
    },
    /// A CVSS base score computed here from a vector the report states.
    ComputedScore {
        version: CvssVersion,
        score: CvssScore,
    },
    Unknown {
        why: UnknownSeverity,
    },
}

impl SeverityBasis {
    /// The severity per the table in this module's documentation.
    pub fn severity(&self) -> Severity {
        match self {
            Self::ScannerLabel { label } => match label {
                ScannerLabel::Low => Severity::Low,
                ScannerLabel::Medium => Severity::Medium,
                ScannerLabel::High => Severity::High,
                ScannerLabel::Critical => Severity::Critical,
            },
            Self::ReportedScore { score } | Self::ComputedScore { score, .. } => {
                severity_of_score(*score)
            }
            Self::Unknown { .. } => Severity::Critical,
        }
    }
}

/// The CVSS row of the table: the v3.1 qualitative scale, with None counted as Low.
pub fn severity_of_score(score: CvssScore) -> Severity {
    match score.tenths() {
        0..=39 => Severity::Low,
        40..=69 => Severity::Medium,
        70..=89 => Severity::High,
        _ => Severity::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::trust_scan::cvss::CvssRating;

    fn score(tenths: u8) -> CvssScore {
        CvssScore::from_tenths(tenths).unwrap()
    }

    #[test]
    fn the_table_maps_every_basis() {
        let label = |label| SeverityBasis::ScannerLabel { label }.severity();
        assert_eq!(label(ScannerLabel::Low), Severity::Low);
        assert_eq!(label(ScannerLabel::Medium), Severity::Medium);
        assert_eq!(label(ScannerLabel::High), Severity::High);
        assert_eq!(label(ScannerLabel::Critical), Severity::Critical);

        let reported = |tenths| {
            SeverityBasis::ReportedScore {
                score: score(tenths),
            }
            .severity()
        };
        assert_eq!(reported(0), Severity::Low);
        assert_eq!(reported(39), Severity::Low);
        assert_eq!(reported(40), Severity::Medium);
        assert_eq!(reported(69), Severity::Medium);
        assert_eq!(reported(70), Severity::High);
        assert_eq!(reported(89), Severity::High);
        assert_eq!(reported(90), Severity::Critical);
        assert_eq!(reported(100), Severity::Critical);
        assert_eq!(
            SeverityBasis::ComputedScore {
                version: CvssVersion::V3_1,
                score: score(98)
            }
            .severity(),
            Severity::Critical
        );
    }

    #[test]
    fn the_cvss_rows_agree_with_the_qualitative_scale() {
        for tenths in 0..=100 {
            let expected = match score(tenths).rating() {
                CvssRating::None | CvssRating::Low => Severity::Low,
                CvssRating::Medium => Severity::Medium,
                CvssRating::High => Severity::High,
                CvssRating::Critical => Severity::Critical,
            };
            assert_eq!(severity_of_score(score(tenths)), expected);
        }
    }

    #[test]
    fn an_unknown_severity_never_softens_the_gate() {
        for why in [
            UnknownSeverity::NotReported,
            UnknownSeverity::ScannerSaidUnknown,
            UnknownSeverity::UnscoredVector {
                version: CvssVersion::V4_0,
            },
        ] {
            assert_eq!(
                SeverityBasis::Unknown { why }.severity(),
                Severity::Critical
            );
        }
        let json = serde_json::to_value(SeverityBasis::Unknown {
            why: UnknownSeverity::NotReported,
        })
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({"basis": "unknown", "why": "not_reported"})
        );
    }
}
