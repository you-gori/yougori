//! Several scans of one pinned configuration, one gate decision (M18: "combining scans
//! into one gate decision"; VM-W47, line 2670: "Gate by applicability, reachability,
//! severity, remediation window and evidence; scanning is one signal"; line 2459: not
//! "failing every finding blindly or treating a green scan as security proof").
//!
//! [`combine`] takes the [`ScanRecord`]s of several scanners, or of several targets, and
//! judges every mapped finding with trust's [`Governance`] through [`ScanRecord::gate`],
//! so no rule of its own decides a finding. It then joins:
//!
//! - **Findings.** One issue in one component version is one [`CombinedFinding`]. Two
//!   advisory identifiers are one issue only when a combined report states one as an
//!   alias of the other, directly or through further stated aliases; nothing else (a
//!   package name, a summary, an outside database) joins them. Each report keeps its own
//!   disposition, and the strictest decides: Blocked, then Excused (it holds only while
//!   an exception runs), WithinWindow, BelowThreshold, Unreachable, NotApplicable, and
//!   ReviewedFalsePositive last; between two excused or two in-window reports the earlier
//!   end decides. An exception names one advisory exactly, so an exception for one alias
//!   does not excuse a report under another.
//! - **Coverage.** The union of what the scans covered, each covered component naming
//!   the scans that covered it, and the components none covered. Package completeness
//!   joins too: an inventoried package any scan lists was seen; one no list names stays
//!   named, with the covering scans whose format cannot tell ([`CombinedCompleteness`]).
//!
//! Every record must have been taken in against this configuration (the same CORE-01
//! fingerprint) and this inventory (the same [`ConfigurationInventory::digest`]); a record
//! of another is refused, as is the same report twice. The decision has no "clean"
//! state: no blocker means nothing known blocks.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use super::intake::{GateRefusal, ScanRecord};
use super::inventory::ConfigurationInventory;
use super::package::PackageRef;
use super::report::{ReportTarget, ScannerKind, ScannerVersion};
use crate::foundation::evidence::ConfigurationFingerprint;
use crate::foundation::ids::Digest;
use crate::sandbox::trust::{
    AdvisoryId, ComponentKind, ComponentVersion, ConfigurationKey, Disposition, GateOutcome,
    Governance, UnixSeconds,
};

/// Most scan records combined at once.
pub const MAX_COMBINED_SCANS: usize = 64;

/// One scan of a combination: what ran, when, and the digest of its report. Serialize
/// only.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ScanName {
    pub scanner: ScannerKind,
    pub scanner_version: ScannerVersion,
    pub scanned_at: UnixSeconds,
    pub report_digest: Digest,
}

impl ScanName {
    pub fn of(record: &ScanRecord) -> Self {
        Self {
            scanner: record.scanner,
            scanner_version: record.scanner_version.clone(),
            scanned_at: record.scanned_at,
            report_digest: record.report_digest,
        }
    }
}

impl fmt::Display for ScanName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} at {} (report {})",
            self.scanner, self.scanner_version, self.scanned_at, self.report_digest
        )
    }
}

/// One scan's report of an issue in one component, with the disposition governance gave
/// it. Serialize only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IssueReport {
    pub scan: ScanName,
    pub advisory: AdvisoryId,
    pub target: ReportTarget,
    pub package: PackageRef,
    pub disposition: Disposition,
}

/// One issue in one component version across the combined scans. Serialize only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CombinedFinding {
    /// The advisories the reports name, joined only through aliases a combined report
    /// states.
    pub advisories: BTreeSet<AdvisoryId>,
    pub component: ComponentKind,
    pub component_version: ComponentVersion,
    /// The strictest disposition of the reports: the first report's.
    pub disposition: Disposition,
    /// Every report of the issue, strictest first; among equally strict ones, in the
    /// order of the records and their findings.
    pub reports: Vec<IssueReport>,
}

impl CombinedFinding {
    /// The advisory of the report whose disposition decides.
    pub fn deciding_advisory(&self) -> Option<&AdvisoryId> {
        self.reports.first().map(|report| &report.advisory)
    }
}

/// What the combined scans show about the packages of one covered component. Serialize
/// only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "completeness", rename_all = "snake_case")]
pub enum CombinedCompleteness {
    /// The component has no inventory to compare with.
    NoInventory,
    Joined {
        inventoried: usize,
        /// Inventoried packages that no package list of a covering scan names.
        not_listed: Vec<PackageRef>,
        /// Covering scans whose format cannot tell which packages they read. While one is
        /// named, a package in `not_listed` may have been read; when none is, no covering
        /// scan saw it.
        undetermined_by: Vec<ScanName>,
    },
}

/// One covered component of the combination. Serialize only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ComponentCoverage {
    /// Every scan that covered the component.
    pub covered_by: Vec<ScanName>,
    pub completeness: CombinedCompleteness,
}

/// One gate decision over several scans of one pinned configuration (VM-W47, line
/// 2670). Serialize only: it is produced by [`combine`], never written by hand.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CombinedGate {
    pub configuration: ConfigurationKey,
    pub configuration_fingerprint: ConfigurationFingerprint,
    pub inventory_digest: Digest,
    pub decided_at: UnixSeconds,
    /// The combined scans, in the order given.
    pub scans: Vec<ScanName>,
    /// One entry per issue and component version, in the order first reported.
    pub findings: Vec<CombinedFinding>,
    /// The deciding advisory of every finding whose disposition blocks.
    pub blocking: Vec<AdvisoryId>,
    /// Each pinned component some scan covered.
    pub coverage: BTreeMap<ComponentKind, ComponentCoverage>,
    /// Pinned components no scan covered.
    pub not_scanned: BTreeSet<ComponentKind>,
}

impl CombinedGate {
    pub fn has_blocker(&self) -> bool {
        !self.blocking.is_empty()
    }

    /// The decision as trust's [`GateOutcome`]: each combined finding's deciding advisory
    /// and disposition, the blocking advisories, and the components no scan covered.
    pub fn outcome(&self) -> GateOutcome {
        GateOutcome {
            dispositions: self
                .findings
                .iter()
                .filter_map(|finding| {
                    finding
                        .deciding_advisory()
                        .map(|advisory| (advisory.clone(), finding.disposition.clone()))
                })
                .collect(),
            blocking: self.blocking.clone(),
            not_scanned: self.not_scanned.clone(),
        }
    }
}

/// Why scans were not combined.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum CombineRefusal {
    NoScans,
    TooManyScans {
        count: usize,
        max: usize,
    },
    /// Record `index` was taken in against another configuration row.
    OtherConfiguration {
        index: usize,
        scanned: ConfigurationFingerprint,
        gated: ConfigurationFingerprint,
    },
    /// Record `index` was taken in against another inventory of this configuration.
    OtherInventory {
        index: usize,
    },
    /// Record `index` holds the same scanner's same report as an earlier record.
    DuplicateScan {
        index: usize,
    },
    Gate {
        index: usize,
        why: GateRefusal,
    },
}

impl fmt::Display for CombineRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoScans => f.write_str("no scan was given to combine"),
            Self::TooManyScans { count, max } => {
                write!(f, "{count} scans were given; at most {max} are combined")
            }
            Self::OtherConfiguration {
                index,
                scanned,
                gated,
            } => write!(
                f,
                "scan {index} was taken against configuration {scanned}, not {gated}"
            ),
            Self::OtherInventory { index } => write!(
                f,
                "scan {index} was taken against another inventory of this configuration"
            ),
            Self::DuplicateScan { index } => {
                write!(f, "scan {index} repeats an earlier scan's report")
            }
            Self::Gate { index, why } => write!(f, "scan {index} was not gated: {why}"),
        }
    }
}

impl std::error::Error for CombineRefusal {}

/// How strict a disposition is: blocking first, then the ones that hold only for a time
/// (the earlier end stricter), then the ones that stand.
fn strictness(disposition: &Disposition) -> (u8, Reverse<u64>) {
    match disposition {
        Disposition::Blocked { .. } => (6, Reverse(0)),
        Disposition::Excused { until, .. } => (5, Reverse(until.get())),
        Disposition::WithinWindow { deadline } => (4, Reverse(deadline.get())),
        Disposition::BelowThreshold { .. } => (3, Reverse(0)),
        Disposition::Unreachable { .. } => (2, Reverse(0)),
        Disposition::NotApplicable { .. } => (1, Reverse(0)),
        Disposition::ReviewedFalsePositive { .. } => (0, Reverse(0)),
    }
}

/// The advisories joined by stated aliases: a disjoint-set forest, the smaller tree
/// joined under the larger so that every path stays short.
#[derive(Default)]
struct Aliases {
    parent: BTreeMap<AdvisoryId, AdvisoryId>,
    size: BTreeMap<AdvisoryId, usize>,
}

impl Aliases {
    fn root(&self, advisory: &AdvisoryId) -> AdvisoryId {
        let mut current = advisory;
        while let Some(parent) = self.parent.get(current) {
            current = parent;
        }
        current.clone()
    }

    fn join(&mut self, one: &AdvisoryId, other: &AdvisoryId) {
        let (first, second) = (self.root(one), self.root(other));
        if first == second {
            return;
        }
        let size_of =
            |aliases: &Self, root: &AdvisoryId| aliases.size.get(root).copied().unwrap_or(1);
        let (first_size, second_size) = (size_of(self, &first), size_of(self, &second));
        let (small, large) = if first_size < second_size {
            (first, second)
        } else {
            (second, first)
        };
        self.size
            .insert(large.clone(), first_size.saturating_add(second_size));
        self.size.remove(&small);
        self.parent.insert(small, large);
    }
}

/// Combines `records`, all taken in against `inventory`, into one gate decision at `now`
/// (VM-W47, line 2670), judging every finding with `governance`.
pub fn combine(
    inventory: &ConfigurationInventory,
    records: &[ScanRecord],
    governance: &Governance,
    now: UnixSeconds,
) -> Result<CombinedGate, CombineRefusal> {
    if records.is_empty() {
        return Err(CombineRefusal::NoScans);
    }
    if records.len() > MAX_COMBINED_SCANS {
        return Err(CombineRefusal::TooManyScans {
            count: records.len(),
            max: MAX_COMBINED_SCANS,
        });
    }
    let fingerprint = inventory.fingerprint();
    let mut reports_seen = BTreeSet::new();
    let mut outcomes = Vec::with_capacity(records.len());
    for (index, record) in records.iter().enumerate() {
        if record.configuration_fingerprint != fingerprint {
            return Err(CombineRefusal::OtherConfiguration {
                index,
                scanned: record.configuration_fingerprint,
                gated: fingerprint,
            });
        }
        if record.inventory_digest != inventory.digest() {
            return Err(CombineRefusal::OtherInventory { index });
        }
        if !reports_seen.insert((record.scanner, record.report_digest)) {
            return Err(CombineRefusal::DuplicateScan { index });
        }
        let outcome = record
            .gate(governance, inventory.configuration(), now)
            .map_err(|why| CombineRefusal::Gate { index, why })?;
        outcomes.push(outcome);
    }

    let mut aliases = Aliases::default();
    for record in records {
        for mapped in &record.findings {
            for alias in &mapped.aliases {
                aliases.join(&mapped.finding.advisory, alias);
            }
        }
    }

    let scans: Vec<ScanName> = records.iter().map(ScanName::of).collect();
    let mut findings: Vec<CombinedFinding> = Vec::new();
    let mut position: BTreeMap<(AdvisoryId, ComponentKind, ComponentVersion), usize> =
        BTreeMap::new();
    for ((record, outcome), scan) in records.iter().zip(&outcomes).zip(&scans) {
        // trust judges a scan's findings in order, one disposition each.
        for (mapped, (_, disposition)) in record.findings.iter().zip(&outcome.dispositions) {
            let finding = &mapped.finding;
            let key = (
                aliases.root(&finding.advisory),
                finding.component,
                finding.component_version.clone(),
            );
            let index = *position.entry(key).or_insert_with(|| {
                findings.push(CombinedFinding {
                    advisories: BTreeSet::new(),
                    component: finding.component,
                    component_version: finding.component_version.clone(),
                    disposition: disposition.clone(),
                    reports: Vec::new(),
                });
                findings.len() - 1
            });
            if let Some(combined) = findings.get_mut(index) {
                combined.advisories.insert(finding.advisory.clone());
                combined.reports.push(IssueReport {
                    scan: scan.clone(),
                    advisory: finding.advisory.clone(),
                    target: mapped.target.clone(),
                    package: mapped.package.clone(),
                    disposition: disposition.clone(),
                });
            }
        }
    }
    for combined in &mut findings {
        combined
            .reports
            .sort_by_key(|report| Reverse(strictness(&report.disposition)));
        if let Some(first) = combined.reports.first() {
            combined.disposition = first.disposition.clone();
        }
    }
    let blocking = findings
        .iter()
        .filter(|combined| combined.disposition.blocks())
        .filter_map(|combined| combined.deciding_advisory().cloned())
        .collect();

    let configuration = inventory.configuration();
    let mut coverage = BTreeMap::new();
    let mut not_scanned = BTreeSet::new();
    for component in configuration.components.keys() {
        let covering: Vec<(&ScanRecord, &ScanName)> = records
            .iter()
            .zip(&scans)
            .filter(|(record, _)| record.covered.contains(component))
            .collect();
        if covering.is_empty() {
            not_scanned.insert(*component);
            continue;
        }
        coverage.insert(
            *component,
            ComponentCoverage {
                covered_by: covering.iter().map(|(_, scan)| (*scan).clone()).collect(),
                completeness: joined_completeness(inventory, *component, &covering),
            },
        );
    }

    Ok(CombinedGate {
        configuration: configuration.key,
        configuration_fingerprint: fingerprint,
        inventory_digest: inventory.digest(),
        decided_at: now,
        scans,
        findings,
        blocking,
        coverage,
        not_scanned,
    })
}

/// The inventoried packages of `component` that no covering scan names, and the covering
/// scans that cannot tell.
fn joined_completeness(
    inventory: &ConfigurationInventory,
    component: ComponentKind,
    covering: &[(&ScanRecord, &ScanName)],
) -> CombinedCompleteness {
    let Some(inventoried) = inventory.packages(component) else {
        return CombinedCompleteness::NoInventory;
    };
    let mut not_listed: BTreeSet<&PackageRef> = inventoried.iter().collect();
    let mut undetermined_by = Vec::new();
    for (record, scan) in covering {
        match record.completeness.get(&component) {
            Some(completeness) => {
                if let Some(unnamed) = completeness.not_named(inventoried) {
                    let unnamed: BTreeSet<&PackageRef> = unnamed.into_iter().collect();
                    not_listed.retain(|package| unnamed.contains(package));
                }
                if completeness.undetermined() {
                    undetermined_by.push((*scan).clone());
                }
            }
            None => undetermined_by.push((*scan).clone()),
        }
    }
    CombinedCompleteness::Joined {
        inventoried: inventoried.len(),
        not_listed: not_listed.into_iter().cloned().collect(),
        undetermined_by,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::{json, Value};

    use super::*;
    use crate::foundation::ids::{ManualClock, MonotonicTime};
    use crate::sandbox::trust::{
        BlockReason, CalendarAnchor, Exception, ExceptionId, GovernancePolicy, Owner, Severity,
        TrustClock,
    };
    use crate::sandbox::trust_scan::coverage::PackageListStatement;
    use crate::sandbox::trust_scan::intake::{
        intake, ReachabilityStatements, ScanRun, Sightings, TargetBinding,
    };
    use crate::sandbox::trust_scan::inventory::tests::{configuration, runtime_inventory};
    use crate::sandbox::trust_scan::package::TargetName;

    const DAY: u64 = 86_400;
    const NOW: u64 = 1_793_232_000;

    fn clock() -> TrustClock {
        let start = MonotonicTime::from_nanos(1_000);
        TrustClock::new(
            Arc::new(ManualClock::new(start)),
            CalendarAnchor {
                monotonic: start,
                unix_seconds: UnixSeconds::new(NOW),
            },
        )
        .unwrap()
    }

    fn inventory() -> ConfigurationInventory {
        ConfigurationInventory::new(configuration(), vec![runtime_inventory()]).unwrap()
    }

    fn governance() -> Governance {
        Governance::new(GovernancePolicy {
            block_at: Severity::Medium,
            remediation_window_seconds: BTreeMap::from([
                (Severity::Low, 90 * DAY),
                (Severity::Medium, 30 * DAY),
                (Severity::High, 7 * DAY),
                (Severity::Critical, 2 * DAY),
            ]),
            max_exception_seconds: 60 * DAY,
        })
        .unwrap()
    }

    fn lockfile() -> ReportTarget {
        ReportTarget::Named(TargetName::new("rt/Cargo.lock").unwrap())
    }

    fn run(
        scanner: ScannerKind,
        target: ReportTarget,
        component: (ComponentKind, &str),
    ) -> ScanRun {
        ScanRun {
            scanner,
            scanner_version: ScannerVersion::new("1.0.0").unwrap(),
            scanned_at: UnixSeconds::new(NOW - DAY),
            targets: vec![TargetBinding {
                target,
                components: BTreeMap::from([(
                    component.0,
                    ComponentVersion::new(component.1).unwrap(),
                )]),
            }],
            package_lists: PackageListStatement::NotStated,
        }
    }

    fn take(inventory: &ConfigurationInventory, run: &ScanRun, report: &Value) -> ScanRecord {
        intake(
            inventory,
            run,
            report.to_string().as_bytes(),
            &ReachabilityStatements::none(),
            &mut Sightings::new(),
            &clock(),
        )
        .unwrap()
    }

    fn trivy(
        target: &str,
        kind: &str,
        class: &str,
        vulnerabilities: Value,
        packages: Option<Value>,
    ) -> Value {
        let mut result = json!({"Target": target, "Class": class, "Type": kind, "Vulnerabilities": vulnerabilities});
        if let Some(packages) = packages {
            result["Packages"] = packages;
        }
        json!({"SchemaVersion": 2, "Results": [result]})
    }

    fn trivy_finding(id: &str, severity: &str, fixed: &str) -> Value {
        json!({
            "VulnerabilityID": id, "PkgName": "fixture-codec", "InstalledVersion": "2.1.0",
            "FixedVersion": fixed, "Severity": severity, "PublishedDate": "2026-10-27T00:00:00Z"
        })
    }

    fn runtime_trivy(vulnerabilities: Value) -> (ScanRun, Value) {
        (
            run(
                ScannerKind::Trivy,
                lockfile(),
                (ComponentKind::Runtime, "rt-1.0.0"),
            ),
            trivy("rt/Cargo.lock", "cargo", "lang-pkgs", vulnerabilities, None),
        )
    }

    fn osv(id: &str, aliases: Value) -> (ScanRun, Value) {
        (
            run(
                ScannerKind::OsvScanner,
                lockfile(),
                (ComponentKind::Runtime, "rt-1.0.0"),
            ),
            json!({"results": [{"source": {"path": "rt/Cargo.lock"}, "packages": [{
                "package": {"name": "fixture-codec", "version": "2.1.0", "ecosystem": "crates.io"},
                "vulnerabilities": [{"id": id, "aliases": aliases, "published": "2026-10-20T00:00:00Z"}],
                "groups": [{"ids": [id], "max_severity": "7.5"}]
            }]}]}),
        )
    }

    fn cargo_audit(id: &str, aliases: Value) -> (ScanRun, Value) {
        (
            run(
                ScannerKind::CargoAudit,
                ReportTarget::WholeReport,
                (ComponentKind::Runtime, "rt-1.0.0"),
            ),
            json!({
                "vulnerabilities": {"found": true, "count": 1, "list": [{
                    "advisory": {"id": id, "package": "fixture-codec", "aliases": aliases,
                                 "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                 "date": "2026-10-20"},
                    "versions": {"patched": [">=2.1.1"]},
                    "package": {"name": "fixture-codec", "version": "2.1.0"}
                }]},
                "lockfile": {"dependency-count": 5}
            }),
        )
    }

    fn records(scans: &[(ScanRun, Value)]) -> Vec<ScanRecord> {
        let inventory = inventory();
        scans
            .iter()
            .map(|(run, report)| take(&inventory, run, report))
            .collect()
    }

    fn advisories(ids: &[&str]) -> BTreeSet<AdvisoryId> {
        ids.iter().map(|id| AdvisoryId::new(*id).unwrap()).collect()
    }

    fn exception(id: &str, advisory: &str, days: u64) -> Exception {
        Exception {
            id: ExceptionId::new(id).unwrap(),
            advisory: AdvisoryId::new(advisory).unwrap(),
            component: ComponentKind::Runtime,
            component_version: ComponentVersion::new("rt-1.0.0").unwrap(),
            owner: Owner::new("runtime-owner").unwrap(),
            justification: "the decoder path is not built into the runtime".to_owned(),
            granted_at: UnixSeconds::new(NOW - DAY),
            expires_at: UnixSeconds::new(NOW - DAY + days * DAY),
        }
    }

    #[test]
    fn aliases_join_only_what_the_reports_state() {
        let unlinked = records(&[
            osv("GHSA-aaaa-bbbb-cccc", json!([])),
            runtime_trivy(json!([trivy_finding("CVE-2026-1000", "HIGH", "2.1.1")])),
        ]);
        let gate = combine(
            &inventory(),
            &unlinked,
            &governance(),
            UnixSeconds::new(NOW),
        )
        .unwrap();
        // The same package and version, but no report says the two are one issue.
        assert_eq!(gate.findings.len(), 2);
        assert_eq!(
            gate.findings[0].advisories,
            advisories(&["GHSA-aaaa-bbbb-cccc"])
        );
        assert_eq!(gate.findings[1].advisories, advisories(&["CVE-2026-1000"]));

        // cargo audit states both as aliases of its own advisory: one issue, three reports.
        let linked = records(&[
            osv("GHSA-aaaa-bbbb-cccc", json!([])),
            runtime_trivy(json!([trivy_finding("CVE-2026-1000", "HIGH", "2.1.1")])),
            cargo_audit(
                "RUSTSEC-2026-0001",
                json!(["CVE-2026-1000", "GHSA-aaaa-bbbb-cccc"]),
            ),
        ]);
        let gate = combine(&inventory(), &linked, &governance(), UnixSeconds::new(NOW)).unwrap();
        assert_eq!(gate.findings.len(), 1);
        let issue = &gate.findings[0];
        assert_eq!(
            issue.advisories,
            advisories(&["CVE-2026-1000", "GHSA-aaaa-bbbb-cccc", "RUSTSEC-2026-0001"])
        );
        assert_eq!(issue.reports.len(), 3);
        assert_eq!(issue.component, ComponentKind::Runtime);
        // Each report keeps its own scan and package.
        let scanners: BTreeSet<ScannerKind> = issue
            .reports
            .iter()
            .map(|report| report.scan.scanner)
            .collect();
        assert_eq!(scanners.len(), 3);
        // Aliases join across chains: OSV names the GHSA, Trivy aliases it to a CVE that
        // cargo audit aliases to its own advisory.
        let chained = records(&[
            osv("GHSA-aaaa-bbbb-cccc", json!([])),
            runtime_trivy(json!([{
                "VulnerabilityID": "CVE-2026-1000", "VendorIDs": ["GHSA-aaaa-bbbb-cccc"],
                "PkgName": "fixture-codec", "InstalledVersion": "2.1.0", "Severity": "HIGH"
            }])),
            cargo_audit("RUSTSEC-2026-0001", json!(["CVE-2026-1000"])),
        ]);
        let gate = combine(&inventory(), &chained, &governance(), UnixSeconds::new(NOW)).unwrap();
        assert_eq!(gate.findings.len(), 1);
        assert_eq!(gate.findings[0].advisories.len(), 3);
    }

    #[test]
    fn the_strictest_disposition_decides() {
        let low = runtime_trivy(json!([trivy_finding("CVE-2026-1000", "LOW", "2.1.1")]));
        let medium = runtime_trivy(json!([trivy_finding("CVE-2026-1000", "MEDIUM", "2.1.1")]));
        let high = runtime_trivy(json!([trivy_finding("CVE-2026-1000", "HIGH", "2.1.1")]));
        let unfixed = runtime_trivy(json!([trivy_finding("CVE-2026-1000", "HIGH", "")]));
        let now = UnixSeconds::new(NOW);
        let published = UnixSeconds::new(NOW - 2 * DAY);

        let gate = combine(
            &inventory(),
            &records(&[low.clone(), medium.clone()]),
            &governance(),
            now,
        )
        .unwrap();
        assert_eq!(gate.findings.len(), 1);
        assert_eq!(
            gate.findings[0].disposition,
            Disposition::WithinWindow {
                deadline: published.plus_seconds(30 * DAY)
            }
        );
        assert_eq!(
            gate.findings[0].reports[1].disposition,
            Disposition::BelowThreshold {
                severity: Severity::Low,
                block_at: Severity::Medium
            }
        );
        assert!(!gate.has_blocker());

        // Of two running windows, the earlier deadline decides.
        let gate = combine(
            &inventory(),
            &records(&[medium.clone(), high]),
            &governance(),
            now,
        )
        .unwrap();
        assert_eq!(
            gate.findings[0].disposition,
            Disposition::WithinWindow {
                deadline: published.plus_seconds(7 * DAY)
            }
        );
        assert_eq!(gate.findings[0].reports[0].scan, gate.scans[1]);

        // One blocking report blocks the issue, whatever the others say.
        let gate = combine(
            &inventory(),
            &records(&[low, medium, unfixed]),
            &governance(),
            now,
        )
        .unwrap();
        assert_eq!(
            gate.findings[0].disposition,
            Disposition::Blocked {
                reason: BlockReason::NoFixWithoutException
            }
        );
        assert_eq!(
            gate.blocking,
            vec![AdvisoryId::new("CVE-2026-1000").unwrap()]
        );
        let outcome = gate.outcome();
        assert!(outcome.has_blocker());
        assert_eq!(outcome.dispositions.len(), 1);
        assert_eq!(outcome.dispositions[0].1, gate.findings[0].disposition);
        assert_eq!(
            outcome.not_scanned,
            BTreeSet::from([ComponentKind::GuestKernel, ComponentKind::GuestImage])
        );
    }

    #[test]
    fn an_exception_for_one_alias_does_not_excuse_another() {
        let scans = [
            runtime_trivy(json!([trivy_finding("CVE-2026-1000", "HIGH", "")])),
            cargo_audit("RUSTSEC-2026-0001", json!(["CVE-2026-1000"])),
        ];
        let now = UnixSeconds::new(NOW);
        let mut governance = governance();
        governance
            .grant_exception(exception("exc-rustsec", "RUSTSEC-2026-0001", 20))
            .unwrap();
        let gate = combine(&inventory(), &records(&scans), &governance, now).unwrap();
        let issue = &gate.findings[0];
        assert_eq!(issue.advisories.len(), 2);
        assert!(issue.disposition.blocks());
        assert_eq!(issue.deciding_advisory().unwrap().as_str(), "CVE-2026-1000");
        assert!(matches!(
            issue.reports[1].disposition,
            Disposition::Excused { .. }
        ));

        // With both excused, the exception that ends first decides.
        governance
            .grant_exception(exception("exc-cve", "CVE-2026-1000", 10))
            .unwrap();
        let gate = combine(&inventory(), &records(&scans), &governance, now).unwrap();
        assert!(!gate.has_blocker());
        assert_eq!(
            gate.findings[0].disposition,
            Disposition::Excused {
                exception: ExceptionId::new("exc-cve").unwrap(),
                owner: Owner::new("runtime-owner").unwrap(),
                until: UnixSeconds::new(NOW - DAY + 10 * DAY),
            }
        );
    }

    #[test]
    fn coverage_is_the_union_with_each_component_s_scans_named() {
        let inventory = inventory();
        let listed = (
            run(
                ScannerKind::Trivy,
                lockfile(),
                (ComponentKind::Runtime, "rt-1.0.0"),
            ),
            trivy(
                "rt/Cargo.lock",
                "cargo",
                "lang-pkgs",
                json!([]),
                Some(json!([
                    {"Name": "fixture-codec", "Version": "2.1.0"},
                    {"Name": "serde", "Version": "1.0.210"}
                ])),
            ),
        );
        let image = (
            run(
                ScannerKind::Trivy,
                ReportTarget::Named(TargetName::new("image (debian 12.7)").unwrap()),
                (ComponentKind::GuestImage, "img-2026.10"),
            ),
            trivy(
                "image (debian 12.7)",
                "debian",
                "os-pkgs",
                json!(null),
                None,
            ),
        );
        let named = osv("GHSA-aaaa-bbbb-cccc", json!([]));
        let records: Vec<ScanRecord> = [listed, image, named]
            .iter()
            .map(|(run, report)| take(&inventory, run, report))
            .collect();
        let gate = combine(&inventory, &records, &governance(), UnixSeconds::new(NOW)).unwrap();
        assert_eq!(
            gate.not_scanned,
            BTreeSet::from([ComponentKind::GuestKernel])
        );
        let runtime = &gate.coverage[&ComponentKind::Runtime];
        assert_eq!(
            runtime.covered_by,
            vec![gate.scans[0].clone(), gate.scans[2].clone()]
        );
        // Trivy listed two of the three crates and OSV-Scanner named one of them: the third
        // is named, with OSV-Scanner as the scan that cannot tell.
        match &runtime.completeness {
            CombinedCompleteness::Joined {
                inventoried,
                not_listed,
                undetermined_by,
            } => {
                assert_eq!(*inventoried, 3);
                let names: Vec<String> = not_listed.iter().map(ToString::to_string).collect();
                assert_eq!(names, ["crates_io fixture_codec 1.0.0"]);
                assert_eq!(undetermined_by, &vec![gate.scans[2].clone()]);
            }
            other => panic!("not joined: {other:?}"),
        }
        let image = &gate.coverage[&ComponentKind::GuestImage];
        assert_eq!(image.covered_by, vec![gate.scans[1].clone()]);
        assert_eq!(image.completeness, CombinedCompleteness::NoInventory);
        let json = serde_json::to_value(&gate).unwrap();
        for claim in ["clean", "secure", "passed", "score"] {
            assert!(json.get(claim).is_none());
        }
    }

    #[test]
    fn records_of_another_configuration_or_inventory_are_refused() {
        let scans = [runtime_trivy(json!([]))];
        let record = records(&scans).remove(0);
        let now = UnixSeconds::new(NOW);
        assert_eq!(
            combine(&inventory(), &[], &governance(), now),
            Err(CombineRefusal::NoScans)
        );
        assert_eq!(
            combine(
                &inventory(),
                &[record.clone(), record.clone()],
                &governance(),
                now
            ),
            Err(CombineRefusal::DuplicateScan { index: 1 })
        );
        assert_eq!(
            combine(
                &inventory(),
                &vec![record.clone(); MAX_COMBINED_SCANS + 1],
                &governance(),
                now
            ),
            Err(CombineRefusal::TooManyScans {
                count: MAX_COMBINED_SCANS + 1,
                max: MAX_COMBINED_SCANS
            })
        );
        // Another inventory of the same configuration judged applicability differently.
        let bare = ConfigurationInventory::new(configuration(), Vec::new()).unwrap();
        assert_eq!(
            combine(&bare, &[record.clone()], &governance(), now),
            Err(CombineRefusal::OtherInventory { index: 0 })
        );
        // A record of another configuration row.
        let mut other = configuration();
        other.devices.clear();
        let other = ConfigurationInventory::new(other, vec![runtime_inventory()]).unwrap();
        let foreign = take(&other, &scans[0].0, &scans[0].1);
        assert!(matches!(
            combine(&inventory(), &[record, foreign], &governance(), now),
            Err(CombineRefusal::OtherConfiguration { index: 1, .. })
        ));
        assert!(CombineRefusal::OtherInventory { index: 0 }
            .to_string()
            .contains("another inventory"));
    }
}
