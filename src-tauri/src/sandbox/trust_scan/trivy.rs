//! Reads Trivy JSON output (`trivy --format json`, schema version 2), vulnerability
//! results only (VM-W47, line 2670; §19 line 3249: Trivy is an optional tool, and
//! reading its output adds no dependency).
//!
//! Read: `SchemaVersion` (must be 2), and per result `Target`, `Class`, `Type`,
//! `Vulnerabilities[].{VulnerabilityID, VendorIDs, PkgName, InstalledVersion,
//! FixedVersion, Severity, PublishedDate}` and `Packages[].{Name, Version, Release,
//! Epoch}`. Everything else is tolerated unread. Results of class `os-pkgs` and
//! `lang-pkgs` are vulnerability results; Trivy lists each scanned target, so one with no
//! vulnerabilities is evidence that it was scanned. Results of class `secret`, `config`,
//! `license`, `license-file` and `custom` are listed as skipped and must carry no
//! vulnerabilities; any other class is refused.
//!
//! With `--list-all-pkgs` Trivy lists every package it read in a result as `Packages`,
//! kept as [`PackagesRead::Listed`]; each version is written as Trivy writes an installed
//! version, `[epoch:]version[-release]`. Trivy leaves out an empty list, so a result
//! without `Packages` says nothing about what was read ([`PackagesRead::NotStated`]).
//!
//! Severity is Trivy's own label (see [`super::severity`]). A fix is available when
//! `FixedVersion` is not empty; Trivy separates several fixed versions with commas.

use std::collections::BTreeSet;

use serde::Deserialize;

use super::package::{
    Ecosystem, FixStatement, PackageName, PackageRef, PackageVersion, TargetName,
};
use super::report::{
    advisory, aliases, bounded, echoable, null_as_empty, read_json, text, timestamp, PackagesRead,
    ParseError, ParsedReport, ReportTarget, ReportedTarget, ReportedVulnerability, ScannerKind,
    SkippedResult, MAX_FIXES, MAX_PACKAGES, MAX_TARGETS, MAX_VULNERABILITIES,
};
use super::severity::{ScannerLabel, SeverityBasis, UnknownSeverity};

const SCANNER: ScannerKind = ScannerKind::Trivy;

/// The only schema version read.
pub const TRIVY_SCHEMA_VERSION: u64 = 2;

#[derive(Deserialize)]
struct Output {
    #[serde(rename = "SchemaVersion")]
    schema_version: u64,
    #[serde(rename = "Results", default, deserialize_with = "null_as_empty")]
    results: Vec<TrivyResult>,
}

#[derive(Deserialize)]
struct TrivyResult {
    #[serde(rename = "Target")]
    target: String,
    #[serde(rename = "Class")]
    class: String,
    #[serde(rename = "Type", default)]
    kind: Option<String>,
    #[serde(
        rename = "Vulnerabilities",
        default,
        deserialize_with = "null_as_empty"
    )]
    vulnerabilities: Vec<Vulnerability>,
    #[serde(rename = "Packages", default)]
    packages: Option<Vec<ListedPackage>>,
}

#[derive(Deserialize)]
struct ListedPackage {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Release", default)]
    release: Option<String>,
    #[serde(rename = "Epoch", default)]
    epoch: Option<u64>,
}

#[derive(Deserialize)]
struct Vulnerability {
    #[serde(rename = "VulnerabilityID")]
    id: String,
    #[serde(rename = "VendorIDs", default, deserialize_with = "null_as_empty")]
    vendor_ids: Vec<String>,
    #[serde(rename = "PkgName")]
    name: String,
    #[serde(rename = "InstalledVersion")]
    version: String,
    #[serde(rename = "FixedVersion", default)]
    fixed: Option<String>,
    #[serde(rename = "Severity")]
    severity: String,
    #[serde(rename = "PublishedDate", default)]
    published: Option<String>,
}

/// Whether a result class holds vulnerabilities; `None` for a class this module does
/// not know.
fn is_vulnerability_class(class: &str) -> Option<bool> {
    match class {
        "os-pkgs" | "lang-pkgs" => Some(true),
        "secret" | "config" | "license" | "license-file" | "custom" => Some(false),
        _ => None,
    }
}

/// A Trivy result type mapped onto a supported ecosystem.
fn ecosystem(class: &str, kind: &str) -> Option<Ecosystem> {
    match (class, kind) {
        ("os-pkgs", "debian") => Some(Ecosystem::Debian),
        ("os-pkgs", "ubuntu") => Some(Ecosystem::Ubuntu),
        ("os-pkgs", "alpine") => Some(Ecosystem::Alpine),
        ("lang-pkgs", "cargo" | "rustbinary") => Some(Ecosystem::CratesIo),
        ("lang-pkgs", "gomod" | "gobinary") => Some(Ecosystem::Go),
        ("lang-pkgs", "npm" | "yarn" | "pnpm" | "node-pkg") => Some(Ecosystem::Npm),
        ("lang-pkgs", "pip" | "pipenv" | "poetry" | "python-pkg" | "uv") => Some(Ecosystem::Pypi),
        _ => None,
    }
}

/// Reads a Trivy JSON report.
pub fn parse_trivy(bytes: &[u8]) -> Result<ParsedReport, ParseError> {
    let output: Output = read_json(SCANNER, bytes)?;
    if output.schema_version != TRIVY_SCHEMA_VERSION {
        return Err(ParseError::UnsupportedSchema {
            scanner: SCANNER,
            version: output.schema_version,
        });
    }
    bounded(SCANNER, "results", output.results.len(), MAX_TARGETS)?;
    let mut seen = BTreeSet::new();
    let mut vulnerability_count = 0_usize;
    let mut package_count = 0_usize;
    let mut targets = Vec::new();
    let mut skipped = Vec::new();
    for result in output.results {
        let name = text(SCANNER, "result target", TargetName::new(result.target))?;
        let class = echoable(SCANNER, "result class", &result.class)?;
        let holds_vulnerabilities =
            is_vulnerability_class(&class).ok_or_else(|| ParseError::UnsupportedResultClass {
                scanner: SCANNER,
                class: class.clone(),
            })?;
        if !holds_vulnerabilities {
            if !result.vulnerabilities.is_empty() {
                return Err(ParseError::Inconsistent {
                    scanner: SCANNER,
                    detail: "a result that is not a vulnerability result lists vulnerabilities",
                });
            }
            skipped.push(SkippedResult {
                target: name,
                class,
            });
            continue;
        }
        if !seen.insert(name.clone()) {
            return Err(ParseError::DuplicateTarget {
                scanner: SCANNER,
                target: name,
            });
        }
        let kind = echoable(
            SCANNER,
            "result type",
            result.kind.as_deref().unwrap_or_default(),
        )?;
        let ecosystem = ecosystem(&class, &kind).ok_or(ParseError::UnsupportedEcosystem {
            scanner: SCANNER,
            name: kind,
        })?;
        vulnerability_count += result.vulnerabilities.len();
        bounded(
            SCANNER,
            "vulnerabilities",
            vulnerability_count,
            MAX_VULNERABILITIES,
        )?;
        let mut vulnerabilities = Vec::with_capacity(result.vulnerabilities.len());
        for vulnerability in &result.vulnerabilities {
            vulnerabilities.push(vulnerability_of(vulnerability, ecosystem)?);
        }
        let packages = match &result.packages {
            None => PackagesRead::NotStated,
            Some(listed) => {
                package_count += listed.len();
                bounded(SCANNER, "packages", package_count, MAX_PACKAGES)?;
                let mut packages = BTreeSet::new();
                for package in listed {
                    packages.insert(listed_package(package, ecosystem)?);
                }
                PackagesRead::Listed { packages }
            }
        };
        targets.push(ReportedTarget {
            target: ReportTarget::Named(name),
            vulnerabilities,
            packages,
        });
    }
    Ok(ParsedReport {
        scanner: SCANNER,
        targets,
        skipped,
    })
}

/// One entry of a result's `Packages`, its version written as Trivy writes an installed
/// version: the epoch and a colon when the epoch is not zero, the version, and a hyphen
/// and the release when there is one.
fn listed_package(package: &ListedPackage, ecosystem: Ecosystem) -> Result<PackageRef, ParseError> {
    let mut version = package.version.clone();
    if let Some(release) = package
        .release
        .as_deref()
        .filter(|release| !release.is_empty())
    {
        version = format!("{version}-{release}");
    }
    if let Some(epoch) = package.epoch.filter(|epoch| *epoch != 0) {
        version = format!("{epoch}:{version}");
    }
    Ok(PackageRef {
        ecosystem,
        name: text(
            SCANNER,
            "Packages Name",
            PackageName::new(package.name.as_str()),
        )?,
        version: text(SCANNER, "Packages Version", PackageVersion::new(version))?,
    })
}

fn vulnerability_of(
    vulnerability: &Vulnerability,
    ecosystem: Ecosystem,
) -> Result<ReportedVulnerability, ParseError> {
    let id = advisory(SCANNER, "VulnerabilityID", &vulnerability.id)?;
    let package = PackageRef {
        ecosystem,
        name: text(
            SCANNER,
            "PkgName",
            PackageName::new(vulnerability.name.as_str()),
        )?,
        version: text(
            SCANNER,
            "InstalledVersion",
            PackageVersion::new(vulnerability.version.as_str()),
        )?,
    };
    let severity = match vulnerability.severity.as_str() {
        "LOW" => SeverityBasis::ScannerLabel {
            label: ScannerLabel::Low,
        },
        "MEDIUM" => SeverityBasis::ScannerLabel {
            label: ScannerLabel::Medium,
        },
        "HIGH" => SeverityBasis::ScannerLabel {
            label: ScannerLabel::High,
        },
        "CRITICAL" => SeverityBasis::ScannerLabel {
            label: ScannerLabel::Critical,
        },
        "UNKNOWN" => SeverityBasis::Unknown {
            why: UnknownSeverity::ScannerSaidUnknown,
        },
        other => {
            return Err(ParseError::BadSeverityLabel {
                scanner: SCANNER,
                label: echoable(SCANNER, "Severity", other)?,
            })
        }
    };
    let mut fixes = Vec::new();
    if let Some(fixed) = vulnerability
        .fixed
        .as_deref()
        .filter(|fixed| !fixed.is_empty())
    {
        for part in fixed.split(',') {
            let fix = text(SCANNER, "FixedVersion", FixStatement::new(part.trim()))?;
            if !fixes.contains(&fix) {
                fixes.push(fix);
            }
        }
        bounded(SCANNER, "fixed versions", fixes.len(), MAX_FIXES)?;
    }
    let published_at = vulnerability
        .published
        .as_deref()
        .map(|value| timestamp(SCANNER, "PublishedDate", value))
        .transpose()?;
    Ok(ReportedVulnerability {
        aliases: aliases(SCANNER, &id, &vulnerability.vendor_ids)?,
        advisory: id,
        package,
        severity,
        fixes,
        published_at,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;

    fn vulnerability(id: &str, severity: &str, fixed: &str) -> Value {
        json!({
            "VulnerabilityID": id,
            "VendorIDs": ["DSA-0000-1"],
            "PkgID": "libfixture1@1.2.3-1",
            "PkgName": "libfixture1",
            "InstalledVersion": "1.2.3-1",
            "FixedVersion": fixed,
            "Status": "fixed",
            "Layer": {"Digest": "unread"},
            "Severity": severity,
            "CVSS": {"nvd": {"V3Score": 7.5}},
            "PublishedDate": "2026-03-04T05:06:07Z"
        })
    }

    fn report(results: Value) -> Value {
        json!({
            "SchemaVersion": 2,
            "CreatedAt": "2026-10-28T00:00:00Z",
            "ArtifactName": "fixture-image",
            "ArtifactType": "container_image",
            "Metadata": {"OS": {"Family": "debian", "Name": "12.7"}},
            "Results": results
        })
    }

    fn os_result(vulnerabilities: Value) -> Value {
        json!({
            "Target": "fixture-image (debian 12.7)",
            "Class": "os-pkgs",
            "Type": "debian",
            "Vulnerabilities": vulnerabilities
        })
    }

    fn parse(value: &Value) -> Result<ParsedReport, ParseError> {
        parse_trivy(value.to_string().as_bytes())
    }

    #[test]
    fn vulnerability_results_are_read_and_others_skipped_visibly() {
        let parsed = parse(&report(json!([
            os_result(json!([vulnerability("CVE-2026-3000", "HIGH", "1.2.3-2, 1.2.4")])),
            {"Target": "fixture/Cargo.lock", "Class": "lang-pkgs", "Type": "cargo"},
            {"Target": "fixture/Dockerfile", "Class": "config", "Type": "dockerfile",
             "MisconfSummary": {"Successes": 3, "Failures": 0}}
        ])))
        .unwrap();
        assert_eq!(parsed.targets.len(), 2);
        let found = &parsed.targets[0].vulnerabilities[0];
        assert_eq!(found.package.to_string(), "debian libfixture1 1.2.3-1");
        assert_eq!(
            found.severity,
            SeverityBasis::ScannerLabel {
                label: ScannerLabel::High
            }
        );
        let fixes: Vec<&str> = found.fixes.iter().map(FixStatement::as_str).collect();
        assert_eq!(fixes, ["1.2.3-2", "1.2.4"]);
        assert_eq!(found.aliases.len(), 1);
        assert!(parsed.targets[1].vulnerabilities.is_empty());
        assert_eq!(parsed.skipped.len(), 1);
        assert_eq!(parsed.skipped[0].class, "config");
    }

    #[test]
    fn package_lists_are_read_when_trivy_writes_them() {
        let parsed = parse(&report(json!([
            {
                "Target": "fixture-image (debian 12.7)", "Class": "os-pkgs", "Type": "debian",
                "Packages": [
                    {"ID": "zlib1g@1:1.2.13.dfsg-1", "Name": "zlib1g", "Version": "1.2.13.dfsg",
                     "Release": "1", "Epoch": 1, "Arch": "amd64", "Licenses": ["Zlib"]},
                    {"Name": "libssl3", "Version": "3.0.15", "Release": "1~deb12u1"},
                    {"Name": "base-files", "Version": "12.4+deb12u7"}
                ]
            },
            {"Target": "fixture/Cargo.lock", "Class": "lang-pkgs", "Type": "cargo",
             "Packages": [{"Name": "smallvec", "Version": "1.6.0", "Epoch": 0, "Release": ""}]},
            {"Target": "other/Cargo.lock", "Class": "lang-pkgs", "Type": "cargo"}
        ])))
        .unwrap();
        let listed = |index: usize| -> Vec<String> {
            match &parsed.targets[index].packages {
                PackagesRead::Listed { packages } => {
                    packages.iter().map(ToString::to_string).collect()
                }
                other => panic!("not listed: {other:?}"),
            }
        };
        assert_eq!(
            listed(0),
            [
                "debian base-files 12.4+deb12u7",
                "debian libssl3 3.0.15-1~deb12u1",
                "debian zlib1g 1:1.2.13.dfsg-1"
            ]
        );
        assert_eq!(listed(1), ["crates_io smallvec 1.6.0"]);
        assert_eq!(parsed.targets[2].packages, PackagesRead::NotStated);

        let with_packages = |packages: Value| {
            parse(&report(json!([
                {"Target": "x", "Class": "lang-pkgs", "Type": "cargo", "Packages": packages}
            ])))
        };
        assert!(matches!(
            with_packages(json!([{"Name": "a"}])),
            Err(ParseError::Malformed { .. })
        ));
        assert!(matches!(
            with_packages(json!([{"Name": "a", "Version": "1", "Epoch": -1}])),
            Err(ParseError::Malformed { .. })
        ));
        assert!(matches!(
            with_packages(json!([{"Name": "a b", "Version": "1"}])),
            Err(ParseError::BadText {
                field: "Packages Name",
                ..
            })
        ));
        assert!(matches!(
            with_packages(json!([{"Name": "a", "Version": ""}])),
            Err(ParseError::BadText {
                field: "Packages Version",
                ..
            })
        ));
        assert!(matches!(
            with_packages(json!(vec![
                json!({"Name": "a", "Version": "1"});
                MAX_PACKAGES + 1
            ])),
            Err(ParseError::TooMany {
                field: "packages",
                ..
            })
        ));
    }

    #[test]
    fn labels_map_and_unknown_labels_are_refused() {
        let severity = |label: &str| {
            parse(&report(json!([os_result(json!([vulnerability(
                "CVE-2026-3000",
                label,
                ""
            )]))])))
            .map(|parsed| parsed.targets[0].vulnerabilities[0].severity)
        };
        assert_eq!(
            severity("UNKNOWN"),
            Ok(SeverityBasis::Unknown {
                why: UnknownSeverity::ScannerSaidUnknown
            })
        );
        assert_eq!(
            severity("LOW"),
            Ok(SeverityBasis::ScannerLabel {
                label: ScannerLabel::Low
            })
        );
        assert_eq!(
            severity("SEVERE"),
            Err(ParseError::BadSeverityLabel {
                scanner: SCANNER,
                label: "SEVERE".to_owned()
            })
        );
        assert!(severity("critical").is_err());
    }

    #[test]
    fn an_empty_fixed_version_means_no_fix() {
        let parsed = parse(&report(json!([os_result(json!([
            vulnerability("CVE-2026-3000", "HIGH", ""),
            {"VulnerabilityID": "CVE-2026-3001", "PkgName": "a", "InstalledVersion": "1", "Severity": "LOW"}
        ]))])))
        .unwrap();
        assert!(parsed.targets[0].vulnerabilities[0].fixes.is_empty());
        assert!(parsed.targets[0].vulnerabilities[1].fixes.is_empty());
        assert_eq!(parsed.targets[0].vulnerabilities[1].published_at, None);
        assert!(matches!(
            parse(&report(json!([os_result(json!([vulnerability(
                "CVE-2026-3000",
                "HIGH",
                "1.0, "
            )]))]))),
            Err(ParseError::BadText {
                field: "FixedVersion",
                ..
            })
        ));
    }

    #[test]
    fn schema_classes_and_types_are_checked() {
        let mut old = report(json!([]));
        old["SchemaVersion"] = json!(1);
        assert_eq!(
            parse(&old),
            Err(ParseError::UnsupportedSchema {
                scanner: SCANNER,
                version: 1
            })
        );
        assert_eq!(
            parse(&report(json!([{"Target": "x", "Class": "sbom"}]))),
            Err(ParseError::UnsupportedResultClass {
                scanner: SCANNER,
                class: "sbom".to_owned()
            })
        );
        assert_eq!(
            parse(&report(
                json!([{"Target": "x", "Class": "os-pkgs", "Type": "redhat"}])
            )),
            Err(ParseError::UnsupportedEcosystem {
                scanner: SCANNER,
                name: "redhat".to_owned()
            })
        );
        assert_eq!(
            parse(&report(
                json!([{"Target": "x", "Class": "lang-pkgs", "Type": "debian"}])
            )),
            Err(ParseError::UnsupportedEcosystem {
                scanner: SCANNER,
                name: "debian".to_owned()
            })
        );
        assert!(matches!(
            parse(&report(json!([{"Target": "x", "Class": "lang-pkgs"}]))),
            Err(ParseError::BadText {
                field: "result type",
                ..
            })
        ));
        assert!(matches!(
            parse(&report(json!([{"Target": "x", "Class": "secret",
                "Vulnerabilities": [vulnerability("CVE-2026-3000", "HIGH", "")]}]))),
            Err(ParseError::Inconsistent { .. })
        ));
        assert!(matches!(
            parse(&report(json!([
                os_result(json!(null)),
                os_result(json!(null))
            ]))),
            Err(ParseError::DuplicateTarget { .. })
        ));
        // Two skipped results may share a target.
        assert!(parse(&report(json!([
            {"Target": "x", "Class": "secret"}, {"Target": "x", "Class": "config"}
        ])))
        .is_ok());
    }

    #[test]
    fn wrong_types_and_missing_fields_are_malformed() {
        for value in [
            json!({"Results": []}),
            json!({"SchemaVersion": "2", "Results": []}),
            report(json!([{"Class": "os-pkgs", "Type": "debian"}])),
            report(json!([os_result(json!({}))])),
            report(json!([os_result(
                json!([{"VulnerabilityID": "CVE-2026-3000", "PkgName": "a", "InstalledVersion": 1, "Severity": "LOW"}])
            )])),
            report(json!([os_result(
                json!([{"VulnerabilityID": "CVE-2026-3000", "PkgName": "a", "InstalledVersion": "1"}])
            )])),
        ] {
            assert!(
                matches!(parse(&value), Err(ParseError::Malformed { .. })),
                "{value} was accepted"
            );
        }
        assert!(matches!(
            parse(&report(json!([os_result(
                json!([{"VulnerabilityID": "CVE-2026-3000", "PkgName": "a",
                "InstalledVersion": "1", "Severity": "LOW", "PublishedDate": "soon"}])
            )]))),
            Err(ParseError::BadDate {
                field: "PublishedDate",
                ..
            })
        ));
    }

    #[test]
    fn counts_are_bounded() {
        let results: Vec<Value> = (0..=MAX_TARGETS)
            .map(|n| json!({"Target": format!("t{n}"), "Class": "secret"}))
            .collect();
        assert!(matches!(
            parse(&report(json!(results))),
            Err(ParseError::TooMany {
                field: "results",
                ..
            })
        ));
        let many = vec![vulnerability("CVE-2026-3000", "LOW", ""); MAX_VULNERABILITIES + 1];
        assert!(matches!(
            parse(&report(json!([os_result(json!(many))]))),
            Err(ParseError::TooMany {
                field: "vulnerabilities",
                ..
            })
        ));
    }
}
