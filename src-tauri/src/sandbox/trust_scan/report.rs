//! The common form every scanner report is read into, its bounds, and the typed
//! refusals of the three parsers (VM-W47, line 2670: "scanning is one signal"; VM-P28,
//! line 2803: malformed and oversized input stays bounded; §19, lines 3248–3249:
//! cargo-audit and Trivy are optional tools, and reading their output adds no
//! dependency).
//!
//! Nothing here runs a scanner. A parser reads bytes a scanner already wrote: at most
//! [`MAX_REPORT_BYTES`], checked before any parsing; nesting in fields a parser reads is
//! bounded by serde_json's recursion limit of 128, and fields it does not read are
//! skipped without recursion; lists are counted against the limits below after reading.
//! Fields a parser does not read may hold anything (the formats evolve); every field it
//! reads is checked for type, length, alphabet and meaning. Duplicate keys in an object
//! the parser reads are refused.

use std::collections::BTreeSet;
use std::fmt;

use chrono::{DateTime, NaiveDate};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};

use super::cvss::CvssError;
use super::package::{FixStatement, PackageRef, TargetName, TextProblem};
use super::severity::SeverityBasis;
use crate::foundation::ids::{validate_identifier, IdError};
use crate::foundation::text::is_hazardous;
use crate::sandbox::trust::{AdvisoryId, UnixSeconds};

/// Largest report accepted, checked before parsing.
pub const MAX_REPORT_BYTES: usize = 8 * 1024 * 1024;
/// Most targets (OSV-Scanner sources, Trivy results) in one report.
pub const MAX_TARGETS: usize = 256;
/// Most package entries in one report.
pub const MAX_PACKAGES: usize = 20_000;
/// Most vulnerabilities in one report, over all targets.
pub const MAX_VULNERABILITIES: usize = 10_000;
/// Most aliases of one vulnerability.
pub const MAX_ALIASES: usize = 32;
/// Most fix statements of one vulnerability.
pub const MAX_FIXES: usize = 32;
/// Most OSV `affected` entries, ranges and events of one vulnerability, counted together.
pub const MAX_RANGE_ITEMS: usize = 1024;
/// Most OSV severity entries of one vulnerability, or ids in one OSV group.
pub const MAX_SMALL_LIST: usize = 64;
/// Longest kept text of a JSON error.
pub const MAX_DETAIL_BYTES: usize = 200;
/// Longest ecosystem, class or label name echoed in a refusal.
pub const MAX_NAME_BYTES: usize = 64;

/// The scanners whose output this module reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerKind {
    /// `osv-scanner --format json`.
    OsvScanner,
    /// `cargo audit --json`.
    CargoAudit,
    /// `trivy --format json`, vulnerability results only.
    Trivy,
}

impl ScannerKind {
    pub const ALL: [Self; 3] = [Self::OsvScanner, Self::CargoAudit, Self::Trivy];

    pub const fn tag(self) -> &'static str {
        match self {
            Self::OsvScanner => "osv-scanner",
            Self::CargoAudit => "cargo-audit",
            Self::Trivy => "trivy",
        }
    }

    /// Reads a report of this scanner's format.
    pub fn parse(self, bytes: &[u8]) -> Result<ParsedReport, ParseError> {
        match self {
            Self::OsvScanner => super::osv::parse_osv_scanner(bytes),
            Self::CargoAudit => super::cargo_audit::parse_cargo_audit(bytes),
            Self::Trivy => super::trivy::parse_trivy(bytes),
        }
    }
}

impl fmt::Display for ScannerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

/// The version of the scanner that wrote a report, as the caller who ran it states it
/// (none of the three formats carries it reliably).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ScannerVersion(String);

impl ScannerVersion {
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ScannerVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ScannerVersion({})", self.0)
    }
}

impl fmt::Display for ScannerVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ScannerVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Which part of a report a target is: a named target, or the whole report for a
/// format that scans one lockfile and names none (`cargo audit`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportTarget {
    Named(TargetName),
    WholeReport,
}

impl fmt::Display for ReportTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named(name) => write!(f, "target {:?}", name.as_str()),
            Self::WholeReport => f.write_str("the whole report"),
        }
    }
}

/// One vulnerability as a report states it, checked (line 2670: "scanning is one
/// signal"). Serialize only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReportedVulnerability {
    pub advisory: AdvisoryId,
    /// Other identifiers of the same issue, as the report lists them. They are kept,
    /// not merged: an exception names one advisory exactly.
    pub aliases: BTreeSet<AdvisoryId>,
    pub package: PackageRef,
    pub severity: SeverityBasis,
    /// Fixed versions or requirements as reported; empty when the report names no fix.
    pub fixes: Vec<FixStatement>,
    /// When the advisory was published, if the report says.
    pub published_at: Option<UnixSeconds>,
}

/// What a report says about the packages it read in one target, the ground for
/// checking that a scan saw every inventoried package (coverage completeness). Serialize
/// only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "read", rename_all = "snake_case")]
pub enum PackagesRead {
    /// Every package the scanner read in the target: Trivy's `Packages`, which it writes
    /// with `--list-all-pkgs`.
    Listed { packages: BTreeSet<PackageRef> },
    /// The packages the report names in the target, which need not be all it read:
    /// OSV-Scanner names only packages with findings unless it ran in all-packages mode,
    /// and its output does not say which (the caller may state it; see
    /// [`ScanRun`](super::intake::ScanRun)).
    Named { packages: BTreeSet<PackageRef> },
    /// Only how many packages the scanner read, not which: cargo audit's
    /// `lockfile.dependency-count`.
    Counted { count: u64 },
    /// The report says nothing about the packages it read in the target.
    NotStated,
}

/// One scanned target of a report and what it found. A target present with no
/// vulnerabilities is evidence that it was scanned. Serialize only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReportedTarget {
    pub target: ReportTarget,
    pub vulnerabilities: Vec<ReportedVulnerability>,
    /// The packages read in the target, as far as the format tells.
    pub packages: PackagesRead,
}

/// A result of a report that is not a vulnerability result (Trivy secret, config or
/// licence results), listed so that skipping it is visible. Serialize only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SkippedResult {
    pub target: TargetName,
    pub class: String,
}

/// A report read into the common form (VM-W47, line 2670). Serialize only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ParsedReport {
    pub scanner: ScannerKind,
    pub targets: Vec<ReportedTarget>,
    pub skipped: Vec<SkippedResult>,
}

impl ParsedReport {
    pub fn vulnerability_count(&self) -> usize {
        self.targets
            .iter()
            .map(|target| target.vulnerabilities.len())
            .sum()
    }
}

/// Why a report was refused (VM-P28, line 2803: malformed and oversized input stays
/// bounded). Values from the report appear only after they passed their own checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum ParseError {
    TooLarge {
        scanner: ScannerKind,
        size_bytes: usize,
        max_bytes: usize,
    },
    /// Not JSON, a wrong type, a missing or duplicate field, or read nesting deeper
    /// than 128.
    Malformed {
        scanner: ScannerKind,
        detail: String,
    },
    TooMany {
        scanner: ScannerKind,
        field: &'static str,
        count: usize,
        max: usize,
    },
    BadText {
        scanner: ScannerKind,
        field: &'static str,
        problem: TextProblem,
    },
    UnsupportedEcosystem {
        scanner: ScannerKind,
        name: String,
    },
    UnsupportedSchema {
        scanner: ScannerKind,
        version: u64,
    },
    UnsupportedResultClass {
        scanner: ScannerKind,
        class: String,
    },
    BadSeverityLabel {
        scanner: ScannerKind,
        label: String,
    },
    BadCvss {
        scanner: ScannerKind,
        field: &'static str,
        problem: CvssError,
    },
    BadDate {
        scanner: ScannerKind,
        field: &'static str,
    },
    /// Two fields of the report contradict each other.
    Inconsistent {
        scanner: ScannerKind,
        detail: &'static str,
    },
    DuplicateTarget {
        scanner: ScannerKind,
        target: TargetName,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge {
                scanner,
                size_bytes,
                max_bytes,
            } => write!(
                f,
                "the {scanner} report is {size_bytes} bytes; at most {max_bytes} are read"
            ),
            Self::Malformed { scanner, detail } => {
                write!(f, "the {scanner} report is malformed: {detail}")
            }
            Self::TooMany {
                scanner,
                field,
                count,
                max,
            } => write!(
                f,
                "the {scanner} report has {count} {field}; at most {max} are read"
            ),
            Self::BadText {
                scanner,
                field,
                problem,
            } => write!(f, "the {scanner} report's {field} is refused: {problem}"),
            Self::UnsupportedEcosystem { scanner, name } => {
                write!(
                    f,
                    "the {scanner} report names the unsupported ecosystem {name:?}"
                )
            }
            Self::UnsupportedSchema { scanner, version } => {
                write!(
                    f,
                    "the {scanner} report has unsupported schema version {version}"
                )
            }
            Self::UnsupportedResultClass { scanner, class } => {
                write!(
                    f,
                    "the {scanner} report has a result of unknown class {class:?}"
                )
            }
            Self::BadSeverityLabel { scanner, label } => {
                write!(
                    f,
                    "the {scanner} report has the unknown severity label {label:?}"
                )
            }
            Self::BadCvss {
                scanner,
                field,
                problem,
            } => write!(f, "the {scanner} report's {field} is refused: {problem}"),
            Self::BadDate { scanner, field } => write!(
                f,
                "the {scanner} report's {field} is not an RFC 3339 time or a date after 1970"
            ),
            Self::Inconsistent { scanner, detail } => {
                write!(f, "the {scanner} report is inconsistent: {detail}")
            }
            Self::DuplicateTarget { scanner, target } => write!(
                f,
                "the {scanner} report lists target {:?} twice",
                target.as_str()
            ),
        }
    }
}

impl std::error::Error for ParseError {}

/// Reads `bytes` as JSON into `T` after the size check.
pub(super) fn read_json<T: DeserializeOwned>(
    scanner: ScannerKind,
    bytes: &[u8],
) -> Result<T, ParseError> {
    if bytes.len() > MAX_REPORT_BYTES {
        return Err(ParseError::TooLarge {
            scanner,
            size_bytes: bytes.len(),
            max_bytes: MAX_REPORT_BYTES,
        });
    }
    serde_json::from_slice(bytes).map_err(|error| ParseError::Malformed {
        scanner,
        detail: bounded_detail(&error.to_string()),
    })
}

/// The error text, cut to [`MAX_DETAIL_BYTES`] with hazardous characters escaped.
fn bounded_detail(text: &str) -> String {
    let mut detail = String::new();
    for character in text.chars() {
        let piece = if is_hazardous(character) {
            character.escape_unicode().to_string()
        } else {
            character.to_string()
        };
        if detail.len() + piece.len() > MAX_DETAIL_BYTES {
            break;
        }
        detail.push_str(&piece);
    }
    detail
}

/// Refuses a list longer than `max`.
pub(super) fn bounded(
    scanner: ScannerKind,
    field: &'static str,
    count: usize,
    max: usize,
) -> Result<(), ParseError> {
    if count > max {
        Err(ParseError::TooMany {
            scanner,
            field,
            count,
            max,
        })
    } else {
        Ok(())
    }
}

/// Lifts a text check into a report refusal.
pub(super) fn text<T>(
    scanner: ScannerKind,
    field: &'static str,
    checked: Result<T, TextProblem>,
) -> Result<T, ParseError> {
    checked.map_err(|problem| ParseError::BadText {
        scanner,
        field,
        problem,
    })
}

/// An advisory identifier: trust's identifier rules.
pub(super) fn advisory(
    scanner: ScannerKind,
    field: &'static str,
    value: &str,
) -> Result<AdvisoryId, ParseError> {
    AdvisoryId::new(value).map_err(|error| ParseError::BadText {
        scanner,
        field,
        problem: TextProblem::from_id_error(&error),
    })
}

/// The aliases of `own`, each checked, at most [`MAX_ALIASES`]; `own` itself is left out.
pub(super) fn aliases(
    scanner: ScannerKind,
    own: &AdvisoryId,
    values: &[String],
) -> Result<BTreeSet<AdvisoryId>, ParseError> {
    bounded(scanner, "aliases", values.len(), MAX_ALIASES)?;
    let mut set = BTreeSet::new();
    for value in values {
        let alias = advisory(scanner, "alias", value)?;
        if alias != *own {
            set.insert(alias);
        }
    }
    Ok(set)
}

/// A short name from the report (an ecosystem, class or label) that may be echoed in a
/// refusal: printable ASCII, at most [`MAX_NAME_BYTES`].
pub(super) fn echoable(
    scanner: ScannerKind,
    field: &'static str,
    value: &str,
) -> Result<String, ParseError> {
    if value.is_empty() {
        return Err(ParseError::BadText {
            scanner,
            field,
            problem: TextProblem::Empty,
        });
    }
    if value.len() > MAX_NAME_BYTES {
        return Err(ParseError::BadText {
            scanner,
            field,
            problem: TextProblem::TooLong {
                max_bytes: MAX_NAME_BYTES,
            },
        });
    }
    match value
        .chars()
        .find(|character| !(character.is_ascii_graphic() || *character == ' '))
    {
        Some(character) => Err(ParseError::BadText {
            scanner,
            field,
            problem: TextProblem::Forbidden { character },
        }),
        None => Ok(value.to_owned()),
    }
}

/// A publication time: an RFC 3339 time, or a `YYYY-MM-DD` date read as midnight UTC,
/// at or after 1970.
pub(super) fn timestamp(
    scanner: ScannerKind,
    field: &'static str,
    value: &str,
) -> Result<UnixSeconds, ParseError> {
    let seconds = if value.len() == 10 {
        NaiveDate::parse_from_str(value, "%Y-%m-%d")
            .ok()
            .and_then(|date| date.and_hms_opt(0, 0, 0))
            .map(|time| time.and_utc().timestamp())
    } else {
        DateTime::parse_from_rfc3339(value)
            .ok()
            .map(|time| time.timestamp())
    };
    seconds
        .and_then(|seconds| u64::try_from(seconds).ok())
        .map(UnixSeconds::new)
        .ok_or(ParseError::BadDate { scanner, field })
}

/// Reads a list that a scanner may write as `null` or leave out.
pub(super) fn null_as_empty<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_reports_are_refused_before_parsing() {
        let bytes = vec![b' '; MAX_REPORT_BYTES + 1];
        for scanner in ScannerKind::ALL {
            assert_eq!(
                scanner.parse(&bytes),
                Err(ParseError::TooLarge {
                    scanner,
                    size_bytes: MAX_REPORT_BYTES + 1,
                    max_bytes: MAX_REPORT_BYTES,
                })
            );
        }
    }

    #[test]
    fn malformed_json_is_refused_with_bounded_escaped_detail() {
        for scanner in ScannerKind::ALL {
            for bytes in [&b""[..], b"{", b"[]", b"null", b"\xff\xfe"] {
                assert!(matches!(
                    scanner.parse(bytes),
                    Err(ParseError::Malformed { .. })
                ));
            }
        }
        let long = "x\u{202e}".repeat(500);
        let detail = bounded_detail(&long);
        assert!(detail.len() <= MAX_DETAIL_BYTES);
        assert!(!detail.contains('\u{202e}') && detail.contains("\\u{202e}"));
    }

    #[test]
    fn deep_nesting_stays_bounded() {
        // In a field that is read, deep nesting is refused (a wrong type or the limit).
        let read = format!("{{\"results\": {}{}}}", "[".repeat(200), "]".repeat(200));
        assert!(matches!(
            ScannerKind::OsvScanner.parse(read.as_bytes()),
            Err(ParseError::Malformed { .. })
        ));
        // A field nobody reads is skipped without recursion, bounded by the byte limit.
        let unread = format!(
            "{{\"results\": [], \"unread\": {}{}}}",
            "[".repeat(10_000),
            "]".repeat(10_000)
        );
        assert!(ScannerKind::OsvScanner.parse(unread.as_bytes()).is_ok());
    }

    #[test]
    fn duplicate_keys_in_read_objects_are_refused() {
        assert!(matches!(
            ScannerKind::OsvScanner.parse(br#"{"results": [], "results": []}"#),
            Err(ParseError::Malformed { .. })
        ));
    }

    #[test]
    fn timestamps_are_rfc3339_or_dates_after_1970() {
        let read = |value| timestamp(ScannerKind::Trivy, "published", value);
        assert_eq!(read("2021-01-08"), Ok(UnixSeconds::new(1_610_064_000)));
        assert_eq!(
            read("2021-01-26T18:16:00Z"),
            Ok(UnixSeconds::new(1_611_684_960))
        );
        assert_eq!(
            read("2021-01-26T20:16:00.123+02:00"),
            Ok(UnixSeconds::new(1_611_684_960))
        );
        for bad in [
            "2021-13-01",
            "1969-12-31",
            "yesterday",
            "2021-01-08 00:00:00",
            "",
        ] {
            assert_eq!(
                read(bad),
                Err(ParseError::BadDate {
                    scanner: ScannerKind::Trivy,
                    field: "published"
                }),
                "{bad:?} was accepted"
            );
        }
    }

    #[test]
    fn aliases_are_checked_bounded_and_exclude_the_advisory_itself() {
        let own = AdvisoryId::new("RUSTSEC-2021-0003").unwrap();
        let set = aliases(
            ScannerKind::CargoAudit,
            &own,
            &["CVE-2021-25900".to_owned(), "RUSTSEC-2021-0003".to_owned()],
        )
        .unwrap();
        assert_eq!(
            set,
            BTreeSet::from([AdvisoryId::new("CVE-2021-25900").unwrap()])
        );
        assert!(matches!(
            aliases(ScannerKind::CargoAudit, &own, &["CVE 2021/1".to_owned()]),
            Err(ParseError::BadText { field: "alias", .. })
        ));
        let many: Vec<String> = (0..=MAX_ALIASES).map(|n| format!("CVE-2021-{n}")).collect();
        assert_eq!(
            aliases(ScannerKind::CargoAudit, &own, &many),
            Err(ParseError::TooMany {
                scanner: ScannerKind::CargoAudit,
                field: "aliases",
                count: MAX_ALIASES + 1,
                max: MAX_ALIASES
            })
        );
    }

    #[test]
    fn scanner_versions_follow_identifier_rules() {
        assert!(ScannerVersion::new("0.56.2").is_ok());
        assert!(ScannerVersion::new("v1.9.2").is_ok());
        assert!(ScannerVersion::new("").is_err());
        assert!(ScannerVersion::new("1.0 beta").is_err());
        assert!(serde_json::from_str::<ScannerVersion>("\"1/2\"").is_err());
        assert_eq!(
            serde_json::to_string(&ReportTarget::WholeReport).unwrap(),
            "\"whole_report\""
        );
        assert_eq!(
            serde_json::from_str::<ReportTarget>(r#"{"named":"Cargo.lock"}"#).unwrap(),
            ReportTarget::Named(TargetName::new("Cargo.lock").unwrap())
        );
    }
}
