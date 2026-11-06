//! Reads `cargo audit --json` output (VM-W47, line 2670; §19 line 3248: cargo-audit is
//! an optional tool, and reading its output adds no dependency).
//!
//! Read: `vulnerabilities.{found, count, list}`, and per entry `advisory.{id, package,
//! aliases, cvss, date}`, `versions.patched` and `package.{name, version}`, and
//! `lockfile.dependency-count`. Everything else (the database, settings, warnings for
//! unmaintained or yanked crates) is tolerated unread. The report scans one lockfile and
//! names none, so it is one target, [`ReportTarget::WholeReport`]; a parsed report is
//! evidence that the lockfile was scanned. Every package is a crate (`crates_io`). The
//! report counts the lockfile's packages without naming them, so it is
//! [`PackagesRead::Counted`], or [`PackagesRead::NotStated`] without a `lockfile`.
//!
//! Severity is the CVSS v3 or v4.0 base score computed from `advisory.cvss`; no vector
//! leaves it unknown (see [`super::severity`]). A fix is available when
//! `versions.patched` names a requirement; the requirements are kept as stated.

use serde::Deserialize;

use super::cvss::{score_vector, VectorScore};
use super::package::{Ecosystem, FixStatement, PackageName, PackageRef, PackageVersion};
use super::report::{
    advisory, aliases, bounded, null_as_empty, read_json, text, timestamp, PackagesRead,
    ParseError, ParsedReport, ReportTarget, ReportedTarget, ReportedVulnerability, ScannerKind,
    MAX_FIXES, MAX_VULNERABILITIES,
};
use super::severity::{SeverityBasis, UnknownSeverity};

const SCANNER: ScannerKind = ScannerKind::CargoAudit;

#[derive(Deserialize)]
struct Output {
    vulnerabilities: Vulnerabilities,
    #[serde(default)]
    lockfile: Option<Lockfile>,
}

#[derive(Deserialize)]
struct Lockfile {
    #[serde(rename = "dependency-count")]
    dependency_count: u64,
}

#[derive(Deserialize)]
struct Vulnerabilities {
    found: bool,
    count: usize,
    #[serde(deserialize_with = "null_as_empty")]
    list: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    advisory: Advisory,
    versions: Versions,
    package: Package,
}

#[derive(Deserialize)]
struct Advisory {
    id: String,
    package: String,
    #[serde(default, deserialize_with = "null_as_empty")]
    aliases: Vec<String>,
    #[serde(default)]
    cvss: Option<String>,
    date: String,
}

#[derive(Deserialize)]
struct Versions {
    #[serde(default, deserialize_with = "null_as_empty")]
    patched: Vec<String>,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    version: String,
}

/// Reads a `cargo audit --json` report.
pub fn parse_cargo_audit(bytes: &[u8]) -> Result<ParsedReport, ParseError> {
    let output: Output = read_json(SCANNER, bytes)?;
    let vulnerabilities = output.vulnerabilities;
    bounded(
        SCANNER,
        "vulnerabilities",
        vulnerabilities.list.len(),
        MAX_VULNERABILITIES,
    )?;
    if vulnerabilities.count != vulnerabilities.list.len() {
        return Err(ParseError::Inconsistent {
            scanner: SCANNER,
            detail: "vulnerabilities.count differs from the length of the list",
        });
    }
    if vulnerabilities.found == vulnerabilities.list.is_empty() {
        return Err(ParseError::Inconsistent {
            scanner: SCANNER,
            detail: "vulnerabilities.found disagrees with the list",
        });
    }
    let mut found = Vec::with_capacity(vulnerabilities.list.len());
    for entry in &vulnerabilities.list {
        found.push(vulnerability_of(entry)?);
    }
    Ok(ParsedReport {
        scanner: SCANNER,
        targets: vec![ReportedTarget {
            target: ReportTarget::WholeReport,
            vulnerabilities: found,
            packages: match output.lockfile {
                Some(lockfile) => PackagesRead::Counted {
                    count: lockfile.dependency_count,
                },
                None => PackagesRead::NotStated,
            },
        }],
        skipped: Vec::new(),
    })
}

fn vulnerability_of(entry: &Entry) -> Result<ReportedVulnerability, ParseError> {
    let id = advisory(SCANNER, "advisory id", &entry.advisory.id)?;
    let name = text(
        SCANNER,
        "package name",
        PackageName::new(entry.package.name.as_str()),
    )?;
    if entry.advisory.package != entry.package.name {
        return Err(ParseError::Inconsistent {
            scanner: SCANNER,
            detail: "an advisory names another crate than its package",
        });
    }
    let package = PackageRef {
        ecosystem: Ecosystem::CratesIo,
        name,
        version: text(
            SCANNER,
            "package version",
            PackageVersion::new(entry.package.version.as_str()),
        )?,
    };
    let severity = match entry.advisory.cvss.as_deref() {
        None => SeverityBasis::Unknown {
            why: UnknownSeverity::NotReported,
        },
        Some(vector) => match score_vector(vector).map_err(|problem| ParseError::BadCvss {
            scanner: SCANNER,
            field: "advisory cvss",
            problem,
        })? {
            VectorScore::Scored { version, score } => {
                SeverityBasis::ComputedScore { version, score }
            }
            VectorScore::Unscored { version } => SeverityBasis::Unknown {
                why: UnknownSeverity::UnscoredVector { version },
            },
        },
    };
    bounded(
        SCANNER,
        "patched requirements",
        entry.versions.patched.len(),
        MAX_FIXES,
    )?;
    let mut fixes = Vec::with_capacity(entry.versions.patched.len());
    for requirement in &entry.versions.patched {
        fixes.push(text(
            SCANNER,
            "patched requirement",
            FixStatement::new(requirement.as_str()),
        )?);
    }
    Ok(ReportedVulnerability {
        aliases: aliases(SCANNER, &id, &entry.advisory.aliases)?,
        advisory: id,
        package,
        severity,
        fixes,
        published_at: Some(timestamp(SCANNER, "advisory date", &entry.advisory.date)?),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;
    use crate::sandbox::trust::UnixSeconds;
    use crate::sandbox::trust_scan::cvss::{CvssScore, CvssVersion};

    fn entry(id: &str, crate_name: &str, version: &str, cvss: Value) -> Value {
        json!({
            "advisory": {
                "id": id, "package": crate_name, "title": "unread",
                "date": "2026-02-03", "aliases": ["CVE-2026-2000"], "cvss": cvss,
                "categories": ["memory-corruption"], "informational": null
            },
            "versions": {"patched": [">=2.1.1, <3.0.0", ">=3.0.2"], "unaffected": ["<1.0.0"]},
            "affected": null,
            "package": {"name": crate_name, "version": version, "source": "registry+https://github.com/rust-lang/crates.io-index"}
        })
    }

    fn report(list: Vec<Value>) -> Value {
        json!({
            "database": {"advisory-count": 1, "last-commit": "unread"},
            "lockfile": {"dependency-count": 12},
            "vulnerabilities": {"found": !list.is_empty(), "count": list.len(), "list": list},
            "warnings": {"unmaintained": []}
        })
    }

    fn parse(value: &Value) -> Result<ParsedReport, ParseError> {
        parse_cargo_audit(value.to_string().as_bytes())
    }

    #[test]
    fn a_report_is_one_target_with_computed_severity() {
        let parsed = parse(&report(vec![entry(
            "FIXTURE-2026-0002",
            "fixture-codec",
            "2.1.0",
            json!("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        )]))
        .unwrap();
        assert_eq!(parsed.targets.len(), 1);
        assert_eq!(parsed.targets[0].target, ReportTarget::WholeReport);
        let found = &parsed.targets[0].vulnerabilities[0];
        assert_eq!(found.package.to_string(), "crates_io fixture-codec 2.1.0");
        assert_eq!(
            found.severity,
            SeverityBasis::ComputedScore {
                version: CvssVersion::V3_1,
                score: CvssScore::from_tenths(98).unwrap()
            }
        );
        let fixes: Vec<&str> = found.fixes.iter().map(FixStatement::as_str).collect();
        assert_eq!(fixes, [">=2.1.1, <3.0.0", ">=3.0.2"]);
        assert_eq!(found.published_at, Some(UnixSeconds::new(1_770_076_800)));
        assert_eq!(found.aliases.len(), 1);
    }

    #[test]
    fn a_clean_report_still_names_its_one_target() {
        let parsed = parse(&report(Vec::new())).unwrap();
        assert_eq!(parsed.targets.len(), 1);
        assert!(parsed.targets[0].vulnerabilities.is_empty());
    }

    #[test]
    fn the_lockfile_is_counted_not_listed() {
        let parsed = parse(&report(Vec::new())).unwrap();
        assert_eq!(
            parsed.targets[0].packages,
            PackagesRead::Counted { count: 12 }
        );
        let mut no_lockfile = report(Vec::new());
        no_lockfile.as_object_mut().unwrap().remove("lockfile");
        assert_eq!(
            parse(&no_lockfile).unwrap().targets[0].packages,
            PackagesRead::NotStated
        );
        let mut bad = report(Vec::new());
        bad["lockfile"] = json!({"dependency-count": "twelve"});
        assert!(matches!(parse(&bad), Err(ParseError::Malformed { .. })));
        bad["lockfile"] = json!({});
        assert!(matches!(parse(&bad), Err(ParseError::Malformed { .. })));
    }

    #[test]
    fn a_missing_vector_leaves_severity_unknown_and_a_v4_vector_is_scored() {
        let severity = |cvss: Value| {
            parse(&report(vec![entry(
                "FIXTURE-2026-0002",
                "a",
                "1.0.0",
                cvss,
            )]))
            .unwrap()
            .targets[0]
                .vulnerabilities[0]
                .severity
        };
        assert_eq!(
            severity(json!(null)),
            SeverityBasis::Unknown {
                why: UnknownSeverity::NotReported
            }
        );
        assert_eq!(
            severity(json!(
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
            )),
            SeverityBasis::ComputedScore {
                version: CvssVersion::V4_0,
                score: CvssScore::from_tenths(93).unwrap()
            }
        );
        assert!(matches!(
            parse(&report(vec![entry(
                "FIXTURE-2026-0002",
                "a",
                "1.0.0",
                json!("9.8")
            )])),
            Err(ParseError::BadCvss {
                field: "advisory cvss",
                ..
            })
        ));
    }

    #[test]
    fn contradictions_are_refused() {
        let mut wrong_count = report(vec![entry("FIXTURE-2026-0002", "a", "1.0.0", json!(null))]);
        wrong_count["vulnerabilities"]["count"] = json!(2);
        assert!(matches!(
            parse(&wrong_count),
            Err(ParseError::Inconsistent { .. })
        ));
        let mut wrong_found = report(Vec::new());
        wrong_found["vulnerabilities"]["found"] = json!(true);
        assert!(matches!(
            parse(&wrong_found),
            Err(ParseError::Inconsistent { .. })
        ));
        let mut other_crate = entry("FIXTURE-2026-0002", "a", "1.0.0", json!(null));
        other_crate["advisory"]["package"] = json!("b");
        assert!(matches!(
            parse(&report(vec![other_crate])),
            Err(ParseError::Inconsistent { .. })
        ));
    }

    #[test]
    fn read_fields_are_validated() {
        assert!(matches!(
            parse(&json!({"vulnerabilities": {"found": "yes", "count": 0, "list": []}})),
            Err(ParseError::Malformed { .. })
        ));
        assert!(matches!(
            parse(&json!({"vulnerabilities": {"found": false, "count": -1, "list": []}})),
            Err(ParseError::Malformed { .. })
        ));
        assert!(matches!(
            parse(&json!({"database": {}})),
            Err(ParseError::Malformed { .. })
        ));
        let mut no_date = entry("FIXTURE-2026-0002", "a", "1.0.0", json!(null));
        no_date["advisory"].as_object_mut().unwrap().remove("date");
        assert!(matches!(
            parse(&report(vec![no_date])),
            Err(ParseError::Malformed { .. })
        ));
        let mut bad_date = entry("FIXTURE-2026-0002", "a", "1.0.0", json!(null));
        bad_date["advisory"]["date"] = json!("2026-02-30");
        assert!(matches!(
            parse(&report(vec![bad_date])),
            Err(ParseError::BadDate { .. })
        ));
        assert!(matches!(
            parse(&report(vec![entry(
                "RUSTSEC 2026",
                "a",
                "1.0.0",
                json!(null)
            )])),
            Err(ParseError::BadText {
                field: "advisory id",
                ..
            })
        ));
        assert!(matches!(
            parse(&report(vec![entry(
                "FIXTURE-2026-0002",
                "a b",
                "1.0.0",
                json!(null)
            )])),
            Err(ParseError::BadText {
                field: "package name",
                ..
            })
        ));
        let mut long_requirement = entry("FIXTURE-2026-0002", "a", "1.0.0", json!(null));
        long_requirement["versions"]["patched"] =
            json!([">=1.0.0, <2.0.0, >=3.0.0, <4.0.0, >=5.0.0"]);
        assert!(matches!(
            parse(&report(vec![long_requirement])),
            Err(ParseError::BadText {
                field: "patched requirement",
                ..
            })
        ));
        let mut many = entry("FIXTURE-2026-0002", "a", "1.0.0", json!(null));
        many["versions"]["patched"] = json!(vec![">=1.0.0"; MAX_FIXES + 1]);
        assert!(matches!(
            parse(&report(vec![many])),
            Err(ParseError::TooMany {
                field: "patched requirements",
                ..
            })
        ));
    }

    #[test]
    fn the_list_is_bounded() {
        let list =
            vec![entry("FIXTURE-2026-0002", "a", "1.0.0", json!(null)); MAX_VULNERABILITIES + 1];
        assert!(matches!(
            parse(&report(list)),
            Err(ParseError::TooMany {
                field: "vulnerabilities",
                ..
            })
        ));
    }
}
