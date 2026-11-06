//! Reads OSV-Scanner JSON output (`osv-scanner --format json`; VM-W47, line 2670).
//!
//! Read: `results[].source.path`, `results[].packages[].package.{name, version,
//! ecosystem}`, and per vulnerability `id`, `aliases`, `published`, the `fixed` events of
//! the `affected` entries for the same package, and `severity[]` entries of type
//! `CVSS_V3` or `CVSS_V4`; per package, `groups[].{ids, max_severity}`. Everything else is
//! tolerated unread.
//!
//! Severity comes from the group's `max_severity` (a CVSS score OSV-Scanner computed),
//! else from the highest base score of the CVSS v3 and v4.0 vectors, else it is unknown
//! (see [`super::severity`]). A fix is available when an `affected` entry for this
//! package names a `fixed` version: some version is then not affected. A clean source
//! does not appear in default output; only output that lists every scanned source
//! (OSV-Scanner's all-packages mode) is evidence of a clean source. Each source's
//! packages are kept as [`PackagesRead::Named`]: the output does not say whether it lists
//! every package read.

use std::collections::BTreeSet;

use serde::Deserialize;

use super::cvss::{score_vector, CvssScore, CvssVersion, VectorScore};
use super::package::{
    Ecosystem, FixStatement, PackageName, PackageRef, PackageVersion, TargetName,
};
use super::report::{
    advisory, aliases, bounded, echoable, null_as_empty, read_json, text, timestamp, PackagesRead,
    ParseError, ParsedReport, ReportTarget, ReportedTarget, ReportedVulnerability, ScannerKind,
    MAX_FIXES, MAX_PACKAGES, MAX_RANGE_ITEMS, MAX_SMALL_LIST, MAX_TARGETS, MAX_VULNERABILITIES,
};
use super::severity::{SeverityBasis, UnknownSeverity};

const SCANNER: ScannerKind = ScannerKind::OsvScanner;

#[derive(Deserialize)]
struct Output {
    #[serde(deserialize_with = "null_as_empty")]
    results: Vec<SourceResult>,
}

#[derive(Deserialize)]
struct SourceResult {
    source: Source,
    #[serde(default, deserialize_with = "null_as_empty")]
    packages: Vec<PackageEntry>,
}

#[derive(Deserialize)]
struct Source {
    path: String,
}

#[derive(Deserialize)]
struct PackageEntry {
    package: Package,
    #[serde(default, deserialize_with = "null_as_empty")]
    vulnerabilities: Vec<Vulnerability>,
    #[serde(default, deserialize_with = "null_as_empty")]
    groups: Vec<Group>,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    version: String,
    ecosystem: String,
}

#[derive(Deserialize)]
struct Vulnerability {
    id: String,
    #[serde(default, deserialize_with = "null_as_empty")]
    aliases: Vec<String>,
    #[serde(default, deserialize_with = "null_as_empty")]
    affected: Vec<Affected>,
    #[serde(default, deserialize_with = "null_as_empty")]
    severity: Vec<SeverityEntry>,
    #[serde(default)]
    published: Option<String>,
}

#[derive(Deserialize)]
struct Affected {
    #[serde(default)]
    package: Option<AffectedPackage>,
    #[serde(default, deserialize_with = "null_as_empty")]
    ranges: Vec<Range>,
}

#[derive(Deserialize)]
struct AffectedPackage {
    ecosystem: String,
    name: String,
}

#[derive(Deserialize)]
struct Range {
    #[serde(default, deserialize_with = "null_as_empty")]
    events: Vec<Event>,
}

#[derive(Deserialize)]
struct Event {
    #[serde(default)]
    fixed: Option<String>,
}

#[derive(Deserialize)]
struct SeverityEntry {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

#[derive(Deserialize)]
struct Group {
    #[serde(default, deserialize_with = "null_as_empty")]
    ids: Vec<String>,
    #[serde(default)]
    max_severity: Option<String>,
}

/// An OSV ecosystem name: `crates.io`, `Go`, `npm`, `PyPI`, and `Debian`, `Ubuntu` or
/// `Alpine` with or without a `:release` suffix.
fn ecosystem(name: &str) -> Option<Ecosystem> {
    let family = name.split(':').next().unwrap_or(name);
    match (name, family) {
        ("crates.io", _) => Some(Ecosystem::CratesIo),
        ("Go", _) => Some(Ecosystem::Go),
        ("npm", _) => Some(Ecosystem::Npm),
        ("PyPI", _) => Some(Ecosystem::Pypi),
        (_, "Debian") => Some(Ecosystem::Debian),
        (_, "Ubuntu") => Some(Ecosystem::Ubuntu),
        (_, "Alpine") => Some(Ecosystem::Alpine),
        _ => None,
    }
}

/// Reads an OSV-Scanner JSON report.
pub fn parse_osv_scanner(bytes: &[u8]) -> Result<ParsedReport, ParseError> {
    let output: Output = read_json(SCANNER, bytes)?;
    bounded(SCANNER, "results", output.results.len(), MAX_TARGETS)?;
    let mut seen = BTreeSet::new();
    let mut package_count = 0_usize;
    let mut vulnerability_count = 0_usize;
    let mut targets = Vec::with_capacity(output.results.len());
    for result in output.results {
        let name = text(SCANNER, "source path", TargetName::new(result.source.path))?;
        if !seen.insert(name.clone()) {
            return Err(ParseError::DuplicateTarget {
                scanner: SCANNER,
                target: name,
            });
        }
        package_count += result.packages.len();
        bounded(SCANNER, "packages", package_count, MAX_PACKAGES)?;
        let mut vulnerabilities = Vec::new();
        let mut packages = BTreeSet::new();
        for entry in result.packages {
            vulnerability_count += entry.vulnerabilities.len();
            bounded(
                SCANNER,
                "vulnerabilities",
                vulnerability_count,
                MAX_VULNERABILITIES,
            )?;
            let package = package_ref(&entry.package)?;
            let groups = groups(&entry.groups)?;
            for vulnerability in &entry.vulnerabilities {
                vulnerabilities.push(vulnerability_of(vulnerability, &package, &groups)?);
            }
            packages.insert(package);
        }
        targets.push(ReportedTarget {
            target: ReportTarget::Named(name),
            vulnerabilities,
            packages: PackagesRead::Named { packages },
        });
    }
    Ok(ParsedReport {
        scanner: SCANNER,
        targets,
        skipped: Vec::new(),
    })
}

fn package_ref(package: &Package) -> Result<PackageRef, ParseError> {
    let ecosystem_name = echoable(SCANNER, "package ecosystem", &package.ecosystem)?;
    let ecosystem = ecosystem(&ecosystem_name).ok_or(ParseError::UnsupportedEcosystem {
        scanner: SCANNER,
        name: ecosystem_name,
    })?;
    Ok(PackageRef {
        ecosystem,
        name: text(
            SCANNER,
            "package name",
            PackageName::new(package.name.as_str()),
        )?,
        version: text(
            SCANNER,
            "package version",
            PackageVersion::new(package.version.as_str()),
        )?,
    })
}

/// Each group's ids and its score, checked; an empty `max_severity` is no score.
fn groups(groups: &[Group]) -> Result<Vec<(Vec<String>, Option<CvssScore>)>, ParseError> {
    bounded(SCANNER, "groups", groups.len(), MAX_VULNERABILITIES)?;
    let mut checked = Vec::with_capacity(groups.len());
    for group in groups {
        bounded(SCANNER, "group ids", group.ids.len(), MAX_SMALL_LIST)?;
        for id in &group.ids {
            advisory(SCANNER, "group id", id)?;
        }
        let score = match group.max_severity.as_deref() {
            None | Some("") => None,
            Some(text) => {
                Some(
                    CvssScore::parse_decimal(text).map_err(|problem| ParseError::BadCvss {
                        scanner: SCANNER,
                        field: "max_severity",
                        problem,
                    })?,
                )
            }
        };
        checked.push((group.ids.clone(), score));
    }
    Ok(checked)
}

fn vulnerability_of(
    vulnerability: &Vulnerability,
    package: &PackageRef,
    groups: &[(Vec<String>, Option<CvssScore>)],
) -> Result<ReportedVulnerability, ParseError> {
    let id = advisory(SCANNER, "vulnerability id", &vulnerability.id)?;
    let aliases = aliases(SCANNER, &id, &vulnerability.aliases)?;
    let group_score = groups
        .iter()
        .find(|(ids, _)| ids.iter().any(|group_id| *group_id == vulnerability.id))
        .and_then(|(_, score)| *score);
    let severity = match group_score {
        Some(score) => SeverityBasis::ReportedScore { score },
        None => vector_severity(&vulnerability.severity)?,
    };
    let published_at = vulnerability
        .published
        .as_deref()
        .map(|value| timestamp(SCANNER, "published", value))
        .transpose()?;
    Ok(ReportedVulnerability {
        advisory: id,
        aliases,
        package: package.clone(),
        severity,
        fixes: fixes(&vulnerability.affected, package)?,
        published_at,
    })
}

/// The highest base score of the CVSS v3 and v4.0 vectors, the first of equal ones; only
/// vectors left unscored, or none, leave it unknown.
fn vector_severity(entries: &[SeverityEntry]) -> Result<SeverityBasis, ParseError> {
    bounded(SCANNER, "severity entries", entries.len(), MAX_SMALL_LIST)?;
    let mut best: Option<(CvssVersion, CvssScore)> = None;
    let mut unscored: Option<CvssVersion> = None;
    for entry in entries {
        if !matches!(entry.kind.as_str(), "CVSS_V3" | "CVSS_V4") {
            continue;
        }
        let scored = score_vector(&entry.score).map_err(|problem| ParseError::BadCvss {
            scanner: SCANNER,
            field: "severity score",
            problem,
        })?;
        match scored {
            VectorScore::Scored { version, score } => match best {
                Some((_, best_score)) if best_score >= score => {}
                _ => best = Some((version, score)),
            },
            VectorScore::Unscored { version } => unscored = Some(version),
        }
    }
    Ok(match (best, unscored) {
        (Some((version, score)), _) => SeverityBasis::ComputedScore { version, score },
        (None, Some(version)) => SeverityBasis::Unknown {
            why: UnknownSeverity::UnscoredVector { version },
        },
        (None, None) => SeverityBasis::Unknown {
            why: UnknownSeverity::NotReported,
        },
    })
}

/// The `fixed` events of the `affected` entries for this package, in report order and
/// without repeats.
fn fixes(affected: &[Affected], package: &PackageRef) -> Result<Vec<FixStatement>, ParseError> {
    let items: usize = affected
        .iter()
        .map(|entry| {
            1 + entry.ranges.len()
                + entry
                    .ranges
                    .iter()
                    .map(|range| range.events.len())
                    .sum::<usize>()
        })
        .sum();
    bounded(
        SCANNER,
        "affected ranges and events",
        items,
        MAX_RANGE_ITEMS,
    )?;
    let key = package.name_key();
    let mut fixes: Vec<FixStatement> = Vec::new();
    for entry in affected {
        let Some(affected_package) = &entry.package else {
            continue;
        };
        let same_ecosystem = ecosystem(&affected_package.ecosystem) == Some(package.ecosystem);
        let same_name = PackageName::new(affected_package.name.as_str())
            .is_ok_and(|name| package.ecosystem.name_key(&name) == key);
        if !(same_ecosystem && same_name) {
            continue;
        }
        for event in entry.ranges.iter().flat_map(|range| &range.events) {
            if let Some(fixed) = &event.fixed {
                let fix = text(SCANNER, "fixed version", FixStatement::new(fixed.as_str()))?;
                if !fixes.contains(&fix) {
                    fixes.push(fix);
                }
            }
        }
    }
    bounded(SCANNER, "fixes", fixes.len(), MAX_FIXES)?;
    Ok(fixes)
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;
    use crate::sandbox::trust::{AdvisoryId, UnixSeconds};
    use crate::sandbox::trust_scan::package::TextProblem;
    use crate::sandbox::trust_scan::report::MAX_ALIASES;

    fn vulnerability(id: &str) -> Value {
        json!({
            "id": id,
            "aliases": ["CVE-2026-1000"],
            "published": "2026-01-02T03:04:05Z",
            "affected": [
                {
                    "package": {"ecosystem": "crates.io", "name": "fixture_codec"},
                    "ranges": [{"type": "SEMVER", "events": [
                        {"introduced": "0"}, {"fixed": "2.1.1"},
                        {"introduced": "3.0.0"}, {"fixed": "3.0.2"}
                    ]}]
                },
                {
                    "package": {"ecosystem": "npm", "name": "fixture-codec"},
                    "ranges": [{"type": "SEMVER", "events": [{"fixed": "9.9.9"}]}]
                }
            ],
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
            "summary": "tolerated and unread",
            "database_specific": {"anything": [1, {"nested": true}]}
        })
    }

    fn report(vulnerabilities: Vec<Value>, groups: Value) -> Value {
        json!({
            "results": [{
                "source": {"path": "fixture/Cargo.lock", "type": "lockfile"},
                "packages": [{
                    "package": {"name": "fixture-codec", "version": "2.1.0", "ecosystem": "crates.io"},
                    "vulnerabilities": vulnerabilities,
                    "groups": groups
                }]
            }],
            "experimental_config": {"licenses": {"summary": false}}
        })
    }

    fn parse(value: &Value) -> Result<ParsedReport, ParseError> {
        parse_osv_scanner(value.to_string().as_bytes())
    }

    #[test]
    fn a_report_is_read_with_its_fixes_aliases_and_dates() {
        let parsed = parse(&report(
            vec![vulnerability("FIXTURE-2026-0001")],
            json!([{"ids": ["FIXTURE-2026-0001"], "aliases": ["CVE-2026-1000"], "max_severity": "8.1"}]),
        ))
        .unwrap();
        assert_eq!(parsed.scanner, ScannerKind::OsvScanner);
        assert_eq!(parsed.targets.len(), 1);
        let target = &parsed.targets[0];
        assert_eq!(
            target.target,
            ReportTarget::Named(TargetName::new("fixture/Cargo.lock").unwrap())
        );
        let found = &target.vulnerabilities[0];
        assert_eq!(found.advisory.as_str(), "FIXTURE-2026-0001");
        assert_eq!(
            found.aliases,
            BTreeSet::from([AdvisoryId::new("CVE-2026-1000").unwrap()])
        );
        assert_eq!(found.package.to_string(), "crates_io fixture-codec 2.1.0");
        // The npm entry with the same name is another package; its fix is not taken.
        let fixes: Vec<&str> = found.fixes.iter().map(FixStatement::as_str).collect();
        assert_eq!(fixes, ["2.1.1", "3.0.2"]);
        assert_eq!(
            found.severity,
            SeverityBasis::ReportedScore {
                score: CvssScore::from_tenths(81).unwrap()
            }
        );
        assert_eq!(found.published_at, Some(UnixSeconds::new(1_767_323_045)));
    }

    #[test]
    fn severity_falls_back_from_group_score_to_vector_to_unknown() {
        let read = |groups: Value, severity: Value| {
            let mut entry = vulnerability("FIXTURE-2026-0001");
            entry["severity"] = severity;
            parse(&report(vec![entry], groups)).unwrap().targets[0].vulnerabilities[0].severity
        };
        let v3 = json!([
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
            {"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}
        ]);
        assert_eq!(
            read(
                json!([{"ids": ["FIXTURE-2026-0001"], "max_severity": ""}]),
                v3.clone()
            ),
            SeverityBasis::ComputedScore {
                version: CvssVersion::V3_1,
                score: CvssScore::from_tenths(75).unwrap()
            }
        );
        let v4 = json!({"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"});
        assert_eq!(
            read(json!(null), json!([v4.clone()])),
            SeverityBasis::ComputedScore {
                version: CvssVersion::V4_0,
                score: CvssScore::from_tenths(93).unwrap()
            }
        );
        // The higher base score decides, whichever version it comes from.
        let mut both = v3.as_array().unwrap().clone();
        both.push(v4);
        assert_eq!(
            read(json!(null), Value::Array(both)),
            SeverityBasis::ComputedScore {
                version: CvssVersion::V4_0,
                score: CvssScore::from_tenths(93).unwrap()
            }
        );
        assert_eq!(
            read(json!([]), json!(null)),
            SeverityBasis::Unknown {
                why: UnknownSeverity::NotReported
            }
        );
    }

    #[test]
    fn every_id_of_a_group_stays_a_finding_of_its_own() {
        let parsed = parse(&report(
            vec![
                vulnerability("GHSA-fixt-ure0-0001"),
                vulnerability("FIXTURE-2026-0001"),
            ],
            json!([{"ids": ["GHSA-fixt-ure0-0001", "FIXTURE-2026-0001"], "max_severity": "9.8"}]),
        ))
        .unwrap();
        let ids: Vec<&str> = parsed.targets[0]
            .vulnerabilities
            .iter()
            .map(|found| found.advisory.as_str())
            .collect();
        assert_eq!(ids, ["GHSA-fixt-ure0-0001", "FIXTURE-2026-0001"]);
    }

    #[test]
    fn every_package_named_in_a_source_is_kept() {
        let parsed = parse(&json!({"results": [{
            "source": {"path": "fixture/Cargo.lock"},
            "packages": [
                {"package": {"name": "serde", "version": "1.0.210", "ecosystem": "crates.io"}},
                {"package": {"name": "fixture-codec", "version": "2.1.0", "ecosystem": "crates.io"},
                 "vulnerabilities": [vulnerability("FIXTURE-2026-0001")]}
            ]
        }]}))
        .unwrap();
        let PackagesRead::Named { packages } = &parsed.targets[0].packages else {
            panic!("not named: {:?}", parsed.targets[0].packages);
        };
        let names: Vec<String> = packages.iter().map(ToString::to_string).collect();
        assert_eq!(
            names,
            ["crates_io fixture-codec 2.1.0", "crates_io serde 1.0.210"]
        );
    }

    #[test]
    fn null_lists_and_an_empty_report_are_read() {
        let parsed = parse(&json!({"results": null})).unwrap();
        assert!(parsed.targets.is_empty());
        let clean = parse(&json!({"results": [{
            "source": {"path": "fixture/Cargo.lock"},
            "packages": [{"package": {"name": "serde", "version": "1.0.210", "ecosystem": "crates.io"},
                          "vulnerabilities": null, "groups": null}]
        }]}))
        .unwrap();
        assert_eq!(clean.targets.len(), 1);
        assert!(clean.targets[0].vulnerabilities.is_empty());
        // Debian ecosystems carry a release suffix.
        let debian = parse(&json!({"results": [{
            "source": {"path": "image"},
            "packages": [{"package": {"name": "libssl3", "version": "3.0.15-1~deb12u1", "ecosystem": "Debian:12"}}]
        }]}))
        .unwrap();
        assert_eq!(debian.targets.len(), 1);
    }

    #[test]
    fn wrong_types_and_missing_fields_are_malformed() {
        for value in [
            json!({}),
            json!({"results": {}}),
            json!({"results": [{"source": {"path": 7}}]}),
            json!({"results": [{"packages": []}]}),
            json!({"results": [{"source": {"path": "x"}, "packages": [{"package": {"name": "a", "version": "1"}}]}]}),
            json!({"results": [{"source": {"path": "x"}, "packages": [{"package": {"name": "a", "version": "1", "ecosystem": "crates.io"}, "vulnerabilities": [{"id": 5}]}]}]}),
        ] {
            assert!(
                matches!(parse(&value), Err(ParseError::Malformed { .. })),
                "{value} was accepted"
            );
        }
    }

    #[test]
    fn read_fields_are_validated() {
        let with_package = |package: Value| {
            parse(
                &json!({"results": [{"source": {"path": "x"}, "packages": [{"package": package}]}]}),
            )
        };
        assert_eq!(
            with_package(json!({"name": "a", "version": "1", "ecosystem": "Maven"})),
            Err(ParseError::UnsupportedEcosystem {
                scanner: SCANNER,
                name: "Maven".to_owned()
            })
        );
        assert!(matches!(
            with_package(json!({"name": "a", "version": "1", "ecosystem": "crates.io\u{1b}"})),
            Err(ParseError::BadText {
                field: "package ecosystem",
                ..
            })
        ));
        assert_eq!(
            with_package(json!({"name": "a", "version": "", "ecosystem": "crates.io"})),
            Err(ParseError::BadText {
                scanner: SCANNER,
                field: "package version",
                problem: TextProblem::Empty
            })
        );
        assert!(matches!(
            parse(&json!({"results": [{"source": {"path": "a\nb"}}]})),
            Err(ParseError::BadText {
                field: "source path",
                ..
            })
        ));
        assert!(matches!(
            parse(&json!({"results": [{"source": {"path": "x"}}, {"source": {"path": "x"}}]})),
            Err(ParseError::DuplicateTarget { .. })
        ));

        let mut bad_id = vulnerability("FIXTURE 2026/1");
        assert!(matches!(
            parse(&report(vec![bad_id.clone()], json!([]))),
            Err(ParseError::BadText {
                field: "vulnerability id",
                ..
            })
        ));
        bad_id["id"] = json!("FIXTURE-2026-0001");
        bad_id["published"] = json!("last tuesday");
        assert!(matches!(
            parse(&report(vec![bad_id.clone()], json!([]))),
            Err(ParseError::BadDate {
                field: "published",
                ..
            })
        ));
        bad_id["published"] = json!(null);
        bad_id["severity"] = json!([{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}]);
        assert!(matches!(
            parse(&report(vec![bad_id.clone()], json!([]))),
            Err(ParseError::BadCvss {
                field: "severity score",
                ..
            })
        ));
        assert!(matches!(
            parse(&report(
                vec![vulnerability("FIXTURE-2026-0001")],
                json!([{"ids": ["FIXTURE-2026-0001"], "max_severity": "high"}])
            )),
            Err(ParseError::BadCvss {
                field: "max_severity",
                ..
            })
        ));
        let mut long_fix = vulnerability("FIXTURE-2026-0001");
        long_fix["affected"][0]["ranges"][0]["events"][1]["fixed"] = json!("9".repeat(41));
        assert!(matches!(
            parse(&report(vec![long_fix], json!([]))),
            Err(ParseError::BadText {
                field: "fixed version",
                ..
            })
        ));
    }

    #[test]
    fn counts_are_bounded() {
        let results: Vec<Value> = (0..=MAX_TARGETS)
            .map(|n| json!({"source": {"path": format!("lock-{n}")}}))
            .collect();
        assert_eq!(
            parse(&json!({ "results": results })),
            Err(ParseError::TooMany {
                scanner: SCANNER,
                field: "results",
                count: MAX_TARGETS + 1,
                max: MAX_TARGETS
            })
        );
        let mut many_aliases = vulnerability("FIXTURE-2026-0001");
        many_aliases["aliases"] = json!((0..=MAX_ALIASES)
            .map(|n| format!("CVE-2026-{n}"))
            .collect::<Vec<_>>());
        assert!(matches!(
            parse(&report(vec![many_aliases], json!([]))),
            Err(ParseError::TooMany {
                field: "aliases",
                ..
            })
        ));
        let mut many_events = vulnerability("FIXTURE-2026-0001");
        many_events["affected"][0]["ranges"][0]["events"] =
            json!(vec![json!({"introduced": "0"}); MAX_RANGE_ITEMS]);
        assert!(matches!(
            parse(&report(vec![many_events], json!([]))),
            Err(ParseError::TooMany {
                field: "affected ranges and events",
                ..
            })
        ));
        let mut many_fixes = vulnerability("FIXTURE-2026-0001");
        many_fixes["affected"][0]["ranges"][0]["events"] = json!((0..=MAX_FIXES)
            .map(|n| json!({ "fixed": format!("2.1.{n}") }))
            .collect::<Vec<_>>());
        assert!(matches!(
            parse(&report(vec![many_fixes], json!([]))),
            Err(ParseError::TooMany { field: "fixes", .. })
        ));
    }
}
