//! Scan intake: a parsed report mapped onto trust findings against one pinned
//! configuration, with a record of what the scan covered (VM-W47, line 2670: "Gate by
//! applicability, reachability, severity, remediation window and evidence; scanning is
//! one signal"; line 2459: "instead of failing every finding blindly or treating a
//! green scan as security proof").
//!
//! The caller states what it ran ([`ScanRun`]): the scanner and its version, when, and
//! which pinned components each report target was built into ([`TargetBinding`]). Every
//! target of a report must be bound; every reported vulnerability becomes one trust
//! [`Finding`] per component its target is bound to, so nothing reported is dropped. Per
//! finding:
//!
//! - applicability comes from the component inventory ([`ConfigurationInventory`]); a
//!   target bound to a component the configuration does not pin, or pins at another
//!   version, yields a finding trust judges not applicable, and it stays in the record;
//! - reachability is undetermined, which trust counts as reachable, unless a
//!   [`ReachabilityStatement`] names the advisory, component and version;
//! - severity follows the documented table in [`super::severity`];
//! - a fix is available when the report names one; the finding's remediation is trust's
//!   [`Remediation::PackageFixAvailable`] with the package and every statement exactly as
//!   reported, since a scanner names a package release, not a component version;
//! - `reported_at`, from which the remediation window runs, is the earliest of the
//!   advisory's publication, an earlier scan's report of the same finding
//!   ([`Sightings`]) and this scan, so scanning again never restarts a window. Kept on a
//!   durable stream, sightings also survive a restart ([`super::sightings`]).
//!
//! A component counts as covered only when a target the report names is bound to it at
//! its pinned version. The [`ScanRecord`] lists covered and uncovered components and
//! every declared target with whether the report names it, and for each covered
//! component whether the scan saw every inventoried package, as far as the format tells
//! ([`super::coverage`]); it has no "clean" state.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use super::coverage::{completeness, PackageCompleteness, PackageListStatement};
use super::inventory::ConfigurationInventory;
use super::package::{FixStatement, PackageRef};
use super::report::{
    ParseError, ReportTarget, ScannerKind, ScannerVersion, SkippedResult, MAX_TARGETS,
};
use super::severity::SeverityBasis;
use crate::foundation::evidence::ConfigurationFingerprint;
use crate::foundation::ids::{digest, Digest, IdError};
use crate::sandbox::trust::{
    AdvisoryId, ComponentKind, ComponentVersion, ConfigurationKey, Finding, GateOutcome,
    Governance, PackageFix, PinnedConfiguration, Reachability, Remediation, ScanReport, Signal,
    TrustClock, UnixSeconds,
};

/// Domain of [`ScanRecord::report_digest`], the digest of the report's exact bytes.
pub const REPORT_DOMAIN: &str = "yougori/sandbox/trust-scan/report/v1";
/// Most target bindings of one run.
pub const MAX_BINDINGS: usize = MAX_TARGETS;
/// Most reachability statements read at once.
pub const MAX_STATEMENTS: usize = 10_000;
/// Most findings [`Sightings`] remembers.
pub const MAX_SIGHTINGS: usize = 100_000;

/// The pinned components built from one report target, each at the version that was
/// scanned. Input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetBinding {
    pub target: ReportTarget,
    pub components: BTreeMap<ComponentKind, ComponentVersion>,
}

/// What the caller ran: the scanner, its version, when, the target bindings, and what it
/// states about the report's package lists. Input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanRun {
    pub scanner: ScannerKind,
    pub scanner_version: ScannerVersion,
    pub scanned_at: UnixSeconds,
    pub targets: Vec<TargetBinding>,
    /// Absent in older inputs, which read as [`PackageListStatement::NotStated`].
    #[serde(default)]
    pub package_lists: PackageListStatement,
}

/// A reachability judgement for one advisory in one component version, with evidence
/// when it says unreachable (trust's [`Reachability`]). Input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReachabilityStatement {
    pub advisory: AdvisoryId,
    pub component: ComponentKind,
    pub component_version: ComponentVersion,
    pub reachability: Reachability,
}

/// One finding: advisory, component and component version.
pub(super) type FindingKey = (AdvisoryId, ComponentKind, ComponentVersion);

/// Checked reachability statements, at most one per advisory, component and version.
#[derive(Debug, Default)]
pub struct ReachabilityStatements {
    statements: BTreeMap<FindingKey, Reachability>,
}

impl ReachabilityStatements {
    /// No statement: every finding stays undetermined.
    pub fn none() -> Self {
        Self::default()
    }

    pub fn new(statements: Vec<ReachabilityStatement>) -> Result<Self, IntakeRefusal> {
        if statements.len() > MAX_STATEMENTS {
            return Err(IntakeRefusal::TooManyStatements {
                count: statements.len(),
                max: MAX_STATEMENTS,
            });
        }
        let mut checked = BTreeMap::new();
        for statement in statements {
            let key = (
                statement.advisory,
                statement.component,
                statement.component_version,
            );
            if checked.contains_key(&key) {
                let (advisory, component, component_version) = key;
                return Err(IntakeRefusal::DuplicateStatement {
                    advisory,
                    component,
                    component_version,
                });
            }
            checked.insert(key, statement.reachability);
        }
        Ok(Self {
            statements: checked,
        })
    }

    fn reachability(&self, key: &FindingKey) -> Reachability {
        self.statements
            .get(key)
            .cloned()
            .unwrap_or(Reachability::Undetermined)
    }
}

/// The earliest time each finding (advisory, component, version) was reported by a scan
/// taken in through [`intake`] (line 2459 "patch deadlines"). It lets a later scan keep
/// an earlier start of the remediation window. In memory; a
/// [`SightingsLog`](super::sightings::SightingsLog) keeps it on a durable stream so that a
/// restart neither forgets nor restarts a window.
#[derive(Debug, Default)]
pub struct Sightings {
    first_reported: BTreeMap<FindingKey, UnixSeconds>,
}

impl Sightings {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn first_reported(
        &self,
        advisory: &AdvisoryId,
        component: ComponentKind,
        version: &ComponentVersion,
    ) -> Option<UnixSeconds> {
        self.first_reported
            .get(&(advisory.clone(), component, version.clone()))
            .copied()
    }

    pub fn len(&self) -> usize {
        self.first_reported.len()
    }

    pub fn is_empty(&self) -> bool {
        self.first_reported.is_empty()
    }

    /// Every finding and its earliest report, in finding order.
    pub fn iter(&self) -> impl Iterator<Item = (&FindingKey, UnixSeconds)> {
        self.first_reported.iter().map(|(key, time)| (key, *time))
    }

    /// The reports of `seen` these sightings lack or hold later, in finding order, once
    /// there is room for every new finding.
    pub(super) fn changes(
        &self,
        seen: &BTreeMap<FindingKey, UnixSeconds>,
    ) -> Result<Vec<(FindingKey, UnixSeconds)>, IntakeRefusal> {
        let new_keys = seen
            .keys()
            .filter(|key| !self.first_reported.contains_key(*key))
            .count();
        if self.first_reported.len() + new_keys > MAX_SIGHTINGS {
            return Err(IntakeRefusal::SightingsFull { max: MAX_SIGHTINGS });
        }
        Ok(seen
            .iter()
            .filter(|(key, time)| {
                self.first_reported
                    .get(*key)
                    .is_none_or(|known| **time < *known)
            })
            .map(|(key, time)| (key.clone(), *time))
            .collect())
    }

    /// Keeps the earlier of each report and the one held.
    pub(super) fn merge(&mut self, reports: impl IntoIterator<Item = (FindingKey, UnixSeconds)>) {
        for (key, time) in reports {
            let entry = self.first_reported.entry(key).or_insert(time);
            *entry = (*entry).min(time);
        }
    }
}

/// Where a finding's `reported_at` came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportedAtBasis {
    AdvisoryPublished,
    EarlierScan,
    ThisScan,
}

/// One reported vulnerability mapped onto one component, with what the report said.
/// Serialize only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MappedFinding {
    pub target: ReportTarget,
    pub package: PackageRef,
    pub aliases: BTreeSet<AdvisoryId>,
    pub severity_basis: SeverityBasis,
    /// Every fix statement as reported; the finding's [`PackageFix`] holds the same.
    pub fixes: Vec<FixStatement>,
    pub reported_at_basis: ReportedAtBasis,
    pub finding: Finding,
}

/// One declared target and whether the report names it. Serialize only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TargetCoverage {
    pub target: ReportTarget,
    pub components: BTreeMap<ComponentKind, ComponentVersion>,
    /// A target the report does not name was not shown to be scanned.
    pub in_report: bool,
}

/// What one scan covered and found, against one configuration (line 2459: a scan is
/// not "security proof"; line 2670: "scanning is one signal"). Serialize only: it is
/// produced by [`intake`], never written by hand.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScanRecord {
    pub scanner: ScannerKind,
    pub scanner_version: ScannerVersion,
    pub report_digest: Digest,
    pub report_bytes: u64,
    pub scanned_at: UnixSeconds,
    pub recorded_at: UnixSeconds,
    pub configuration: ConfigurationKey,
    pub configuration_fingerprint: ConfigurationFingerprint,
    /// The inventory the findings' applicability and the completeness were judged against
    /// ([`ConfigurationInventory::digest`]).
    pub inventory_digest: Digest,
    pub targets: Vec<TargetCoverage>,
    /// Pinned components a target named in the report is bound to at the pinned version.
    pub covered: BTreeSet<ComponentKind>,
    /// Every other pinned component.
    pub not_covered: BTreeSet<ComponentKind>,
    /// What the caller stated about the report's package lists.
    pub package_lists: PackageListStatement,
    /// For each covered component, whether the scan saw every inventoried package, as far
    /// as the format tells ([`super::coverage`]).
    pub completeness: BTreeMap<ComponentKind, PackageCompleteness>,
    pub findings: Vec<MappedFinding>,
    pub skipped: Vec<SkippedResult>,
}

impl ScanRecord {
    /// The scan as trust's one-signal [`ScanReport`]: the covered components and every
    /// mapped finding.
    pub fn trust_report(&self) -> ScanReport {
        ScanReport {
            scanner: signal_name(self.scanner, &self.scanner_version),
            scanned_at: self.scanned_at,
            components_scanned: self.covered.clone(),
            findings: self
                .findings
                .iter()
                .map(|mapped| mapped.finding.clone())
                .collect(),
        }
    }

    /// Runs trust's gate over this scan at `now`. The configuration must be the one the
    /// scan was taken in against (same CORE-01 fingerprint).
    pub fn gate(
        &self,
        governance: &Governance,
        configuration: &PinnedConfiguration,
        now: UnixSeconds,
    ) -> Result<GateOutcome, GateRefusal> {
        let gated = configuration
            .fingerprint()
            .map_err(|error| GateRefusal::Fingerprint {
                detail: error.to_string(),
            })?;
        if gated != self.configuration_fingerprint {
            return Err(GateRefusal::OtherConfiguration {
                scanned: self.configuration_fingerprint,
                gated,
            });
        }
        Ok(governance.assess_scan(&self.trust_report(), configuration, now))
    }
}

/// Why a scan was not taken in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum IntakeRefusal {
    Parse {
        error: ParseError,
    },
    TooManyBindings {
        count: usize,
        max: usize,
    },
    EmptyBinding {
        target: ReportTarget,
    },
    DuplicateBinding {
        target: ReportTarget,
    },
    /// A named binding for `cargo audit`, or a whole-report binding for a format that
    /// names its targets.
    BindingForm {
        scanner: ScannerKind,
        target: ReportTarget,
    },
    /// The report names a target no binding covers.
    UnboundTarget {
        target: ReportTarget,
    },
    ScannedInFuture {
        scanned_at: UnixSeconds,
        now: UnixSeconds,
    },
    DuplicateStatement {
        advisory: AdvisoryId,
        component: ComponentKind,
        component_version: ComponentVersion,
    },
    TooManyStatements {
        count: usize,
        max: usize,
    },
    SightingsFull {
        max: usize,
    },
    /// The fix statements do not fit trust's [`PackageFix`] bounds.
    FixNotRepresentable {
        advisory: AdvisoryId,
    },
    /// A statement about package lists that the scanner's format does not take: only an
    /// OSV-Scanner run states all-packages mode.
    StatementNotForScanner {
        scanner: ScannerKind,
        statement: PackageListStatement,
    },
}

impl fmt::Display for IntakeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse { error } => write!(f, "{error}"),
            Self::TooManyBindings { count, max } => {
                write!(f, "the run binds {count} targets; at most {max} are read")
            }
            Self::EmptyBinding { target } => write!(f, "{target} is bound to no component"),
            Self::DuplicateBinding { target } => write!(f, "{target} is bound twice"),
            Self::BindingForm { scanner, target } => {
                write!(f, "a {scanner} report cannot have {target}")
            }
            Self::UnboundTarget { target } => {
                write!(f, "the report names {target}, which no binding covers")
            }
            Self::ScannedInFuture { scanned_at, now } => write!(
                f,
                "the scan is dated {scanned_at}, after the time of intake {now}"
            ),
            Self::DuplicateStatement {
                advisory,
                component,
                component_version,
            } => write!(
                f,
                "two reachability statements name {advisory} in {component} {component_version}"
            ),
            Self::TooManyStatements { count, max } => write!(
                f,
                "{count} reachability statements were given; at most {max} are read"
            ),
            Self::SightingsFull { max } => {
                write!(f, "the sightings already hold {max} findings")
            }
            Self::FixNotRepresentable { advisory } => {
                write!(f, "the fix of {advisory} cannot be kept as a package fix")
            }
            Self::StatementNotForScanner { scanner, statement } => match statement {
                PackageListStatement::OsvAllPackages => write!(
                    f,
                    "only an osv-scanner run can state all-packages mode, and this is a {scanner} run"
                ),
                PackageListStatement::NotStated => {
                    write!(f, "a {scanner} run cannot state this about its package lists")
                }
            },
        }
    }
}

impl std::error::Error for IntakeRefusal {}

/// Why a scan record was not gated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum GateRefusal {
    /// The scan was taken in against another configuration row.
    OtherConfiguration {
        scanned: ConfigurationFingerprint,
        gated: ConfigurationFingerprint,
    },
    Fingerprint {
        detail: String,
    },
}

impl fmt::Display for GateRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherConfiguration { scanned, gated } => write!(
                f,
                "the scan was taken against configuration {scanned}, not {gated}"
            ),
            Self::Fingerprint { detail } => {
                write!(f, "the configuration cannot be fingerprinted: {detail}")
            }
        }
    }
}

impl std::error::Error for GateRefusal {}

fn signal_name(scanner: ScannerKind, version: &ScannerVersion) -> String {
    format!("{} {}", scanner.tag(), version)
}

/// A component-version label for a reported fix (line 2459 "available fixes"), for a
/// caller that needs one: the statement itself when it is a valid component version,
/// otherwise `fix-` followed by the statement with every byte other than a letter,
/// digit, `.` or `-` written as `_` and two uppercase hexadecimal digits (`>=1.6.1`
/// becomes `fix-_3E_3D1.6.1`). [`intake`] no longer uses it: a finding's remediation
/// keeps the statements exactly, as a [`PackageFix`].
pub fn fixed_in_label(statement: &FixStatement) -> Result<ComponentVersion, IdError> {
    if let Ok(version) = ComponentVersion::new(statement.as_str()) {
        return Ok(version);
    }
    let mut label = String::from("fix-");
    for byte in statement.as_str().bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-') {
            label.push(char::from(byte));
        } else {
            let _ = write!(label, "_{byte:02X}");
        }
    }
    ComponentVersion::new(label)
}

/// Takes in one scanner report (VM-W47, line 2670): checks the run, parses the report,
/// maps every reported vulnerability onto trust findings and records what the scan
/// covered. `sightings` is updated only when the whole intake succeeds.
pub fn intake(
    inventory: &ConfigurationInventory,
    run: &ScanRun,
    report: &[u8],
    reachability: &ReachabilityStatements,
    sightings: &mut Sightings,
    clock: &TrustClock,
) -> Result<ScanRecord, IntakeRefusal> {
    let (record, seen) = take_in(inventory, run, report, reachability, sightings, clock)?;
    let changes = sightings.changes(&seen)?;
    sightings.merge(changes);
    Ok(record)
}

/// [`intake`] without updating `sightings`: the record, and the earliest report of each
/// finding the scan holds, for the caller to keep.
pub(super) fn take_in(
    inventory: &ConfigurationInventory,
    run: &ScanRun,
    report: &[u8],
    reachability: &ReachabilityStatements,
    sightings: &Sightings,
    clock: &TrustClock,
) -> Result<(ScanRecord, BTreeMap<FindingKey, UnixSeconds>), IntakeRefusal> {
    let recorded_at = clock.now();
    if run.scanned_at > recorded_at {
        return Err(IntakeRefusal::ScannedInFuture {
            scanned_at: run.scanned_at,
            now: recorded_at,
        });
    }
    if run.package_lists == PackageListStatement::OsvAllPackages
        && run.scanner != ScannerKind::OsvScanner
    {
        return Err(IntakeRefusal::StatementNotForScanner {
            scanner: run.scanner,
            statement: run.package_lists,
        });
    }
    let bindings = check_bindings(run)?;
    let parsed = run
        .scanner
        .parse(report)
        .map_err(|error| IntakeRefusal::Parse { error })?;
    let named: BTreeSet<&ReportTarget> =
        parsed.targets.iter().map(|target| &target.target).collect();
    let signal = Signal::Scanner {
        name: signal_name(run.scanner, &run.scanner_version),
    };

    let mut findings = Vec::new();
    let mut first_reported: BTreeMap<FindingKey, UnixSeconds> = BTreeMap::new();
    for target in &parsed.targets {
        let binding = bindings
            .get(&target.target)
            .ok_or_else(|| IntakeRefusal::UnboundTarget {
                target: target.target.clone(),
            })?;
        for reported in &target.vulnerabilities {
            let remediation = if reported.fixes.is_empty() {
                Remediation::NoFix
            } else {
                let statements = reported
                    .fixes
                    .iter()
                    .map(|fix| fix.as_str().to_owned())
                    .collect();
                Remediation::PackageFixAvailable {
                    fix: PackageFix::new(reported.package.name.as_str(), statements).map_err(
                        |_| IntakeRefusal::FixNotRepresentable {
                            advisory: reported.advisory.clone(),
                        },
                    )?,
                }
            };
            for (component, version) in &binding.components {
                let key = (reported.advisory.clone(), *component, version.clone());
                let earlier = sightings.first_reported.get(&key).copied();
                let (reported_at, reported_at_basis) = [
                    (reported.published_at, ReportedAtBasis::AdvisoryPublished),
                    (earlier, ReportedAtBasis::EarlierScan),
                    (Some(run.scanned_at), ReportedAtBasis::ThisScan),
                ]
                .into_iter()
                .filter_map(|(time, basis)| time.map(|time| (time, basis)))
                .min_by_key(|(time, _)| *time)
                .unwrap_or((run.scanned_at, ReportedAtBasis::ThisScan));
                let entry = first_reported.entry(key.clone()).or_insert(reported_at);
                *entry = (*entry).min(reported_at);
                findings.push(MappedFinding {
                    target: target.target.clone(),
                    package: reported.package.clone(),
                    aliases: reported.aliases.clone(),
                    severity_basis: reported.severity,
                    fixes: reported.fixes.clone(),
                    reported_at_basis,
                    finding: Finding {
                        advisory: reported.advisory.clone(),
                        component: *component,
                        component_version: version.clone(),
                        severity: reported.severity.severity(),
                        applicability: inventory.applicability(
                            *component,
                            version,
                            &reported.package,
                        ),
                        reachability: reachability.reachability(&key),
                        remediation: remediation.clone(),
                        reported_at,
                        signal: signal.clone(),
                    },
                });
            }
        }
    }

    // Refused here, as before any record exists, when the sightings have no room.
    sightings.changes(&first_reported)?;

    let configuration = inventory.configuration();
    let targets: Vec<TargetCoverage> = run
        .targets
        .iter()
        .map(|binding| TargetCoverage {
            target: binding.target.clone(),
            components: binding.components.clone(),
            in_report: named.contains(&binding.target),
        })
        .collect();
    let covered: BTreeSet<ComponentKind> = configuration
        .components
        .iter()
        .filter(|(kind, pin)| {
            targets.iter().any(|coverage| {
                coverage.in_report && coverage.components.get(*kind) == Some(&pin.version)
            })
        })
        .map(|(kind, _)| *kind)
        .collect();
    let not_covered = configuration
        .components
        .keys()
        .filter(|kind| !covered.contains(kind))
        .copied()
        .collect();
    let completeness = covered
        .iter()
        .map(|kind| {
            let pinned = configuration.component(*kind).map(|pin| &pin.version);
            let reads: Vec<_> = parsed
                .targets
                .iter()
                .filter(|target| {
                    bindings
                        .get(&target.target)
                        .is_some_and(|binding| binding.components.get(kind) == pinned)
                })
                .map(|target| &target.packages)
                .collect();
            (
                *kind,
                completeness(inventory, *kind, &reads, run.package_lists),
            )
        })
        .collect();
    let record = ScanRecord {
        scanner: run.scanner,
        scanner_version: run.scanner_version.clone(),
        report_digest: digest(REPORT_DOMAIN, &[report]),
        report_bytes: report.len() as u64,
        scanned_at: run.scanned_at,
        recorded_at,
        configuration: configuration.key,
        configuration_fingerprint: inventory.fingerprint(),
        inventory_digest: inventory.digest(),
        targets,
        covered,
        not_covered,
        package_lists: run.package_lists,
        completeness,
        findings,
        skipped: parsed.skipped,
    };
    Ok((record, first_reported))
}

/// Bindings by target: at most [`MAX_BINDINGS`], each naming a component, none twice,
/// and of the form the scanner's format uses.
fn check_bindings(run: &ScanRun) -> Result<BTreeMap<ReportTarget, &TargetBinding>, IntakeRefusal> {
    if run.targets.len() > MAX_BINDINGS {
        return Err(IntakeRefusal::TooManyBindings {
            count: run.targets.len(),
            max: MAX_BINDINGS,
        });
    }
    let mut bindings = BTreeMap::new();
    for binding in &run.targets {
        let whole = matches!(binding.target, ReportTarget::WholeReport);
        if whole != (run.scanner == ScannerKind::CargoAudit) {
            return Err(IntakeRefusal::BindingForm {
                scanner: run.scanner,
                target: binding.target.clone(),
            });
        }
        if binding.components.is_empty() {
            return Err(IntakeRefusal::EmptyBinding {
                target: binding.target.clone(),
            });
        }
        if bindings.insert(binding.target.clone(), binding).is_some() {
            return Err(IntakeRefusal::DuplicateBinding {
                target: binding.target.clone(),
            });
        }
    }
    Ok(bindings)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::{json, Value};

    use super::*;
    use crate::foundation::ids::{ManualClock, MonotonicTime};
    use crate::sandbox::trust::{
        Applicability, BlockReason, CalendarAnchor, Disposition, GovernancePolicy, Severity,
    };
    use crate::sandbox::trust_scan::coverage::NotTellable;
    use crate::sandbox::trust_scan::inventory::tests::{configuration, runtime_inventory};
    use crate::sandbox::trust_scan::package::TargetName;

    const DAY: u64 = 86_400;
    const NOW: u64 = 1_793_232_000;

    fn clock_at(seconds: u64) -> TrustClock {
        let start = MonotonicTime::from_nanos(1_000);
        TrustClock::new(
            Arc::new(ManualClock::new(start)),
            CalendarAnchor {
                monotonic: start,
                unix_seconds: UnixSeconds::new(seconds),
            },
        )
        .unwrap()
    }

    fn inventory() -> ConfigurationInventory {
        ConfigurationInventory::new(configuration(), vec![runtime_inventory()]).unwrap()
    }

    fn named(name: &str) -> ReportTarget {
        ReportTarget::Named(TargetName::new(name).unwrap())
    }

    fn bind(target: ReportTarget, components: &[(ComponentKind, &str)]) -> TargetBinding {
        TargetBinding {
            target,
            components: components
                .iter()
                .map(|(kind, version)| (*kind, ComponentVersion::new(*version).unwrap()))
                .collect(),
        }
    }

    fn run(scanner: ScannerKind, scanned_at: u64, targets: Vec<TargetBinding>) -> ScanRun {
        ScanRun {
            scanner,
            scanner_version: ScannerVersion::new("0.56.2").unwrap(),
            scanned_at: UnixSeconds::new(scanned_at),
            targets,
            package_lists: PackageListStatement::NotStated,
        }
    }

    fn runtime_lock() -> TargetBinding {
        bind(
            named("rt/Cargo.lock"),
            &[(ComponentKind::Runtime, "rt-1.0.0")],
        )
    }

    fn vulnerability(id: &str, name: &str, version: &str, fixed: &str, severity: &str) -> Value {
        json!({
            "VulnerabilityID": id, "PkgName": name, "InstalledVersion": version,
            "FixedVersion": fixed, "Severity": severity
        })
    }

    fn trivy(results: Value) -> Vec<u8> {
        json!({"SchemaVersion": 2, "Results": results})
            .to_string()
            .into_bytes()
    }

    fn lang(target: &str, vulnerabilities: Value) -> Value {
        json!({"Target": target, "Class": "lang-pkgs", "Type": "cargo", "Vulnerabilities": vulnerabilities})
    }

    fn take(
        run: &ScanRun,
        report: &[u8],
        sightings: &mut Sightings,
    ) -> Result<ScanRecord, IntakeRefusal> {
        intake(
            &inventory(),
            run,
            report,
            &ReachabilityStatements::none(),
            sightings,
            &clock_at(NOW),
        )
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

    #[test]
    fn bindings_are_checked() {
        let report = trivy(json!([lang("rt/Cargo.lock", json!([]))]));
        let mut sightings = Sightings::new();
        let other = run(
            ScannerKind::Trivy,
            NOW,
            vec![bind(
                named("other"),
                &[(ComponentKind::Runtime, "rt-1.0.0")],
            )],
        );
        assert_eq!(
            take(&other, &report, &mut sightings),
            Err(IntakeRefusal::UnboundTarget {
                target: named("rt/Cargo.lock")
            })
        );
        let twice = run(
            ScannerKind::Trivy,
            NOW,
            vec![runtime_lock(), runtime_lock()],
        );
        assert_eq!(
            take(&twice, &report, &mut sightings),
            Err(IntakeRefusal::DuplicateBinding {
                target: named("rt/Cargo.lock")
            })
        );
        let empty = run(
            ScannerKind::Trivy,
            NOW,
            vec![bind(named("rt/Cargo.lock"), &[])],
        );
        assert_eq!(
            take(&empty, &report, &mut sightings),
            Err(IntakeRefusal::EmptyBinding {
                target: named("rt/Cargo.lock")
            })
        );
        let whole = run(
            ScannerKind::Trivy,
            NOW,
            vec![bind(
                ReportTarget::WholeReport,
                &[(ComponentKind::Runtime, "rt-1.0.0")],
            )],
        );
        assert!(matches!(
            take(&whole, &report, &mut sightings),
            Err(IntakeRefusal::BindingForm { .. })
        ));
        let named_audit = run(ScannerKind::CargoAudit, NOW, vec![runtime_lock()]);
        assert!(matches!(
            take(&named_audit, b"{}", &mut sightings),
            Err(IntakeRefusal::BindingForm { .. })
        ));
        let many = run(
            ScannerKind::Trivy,
            NOW,
            (0..=MAX_BINDINGS)
                .map(|n| {
                    bind(
                        named(&format!("t{n}")),
                        &[(ComponentKind::Runtime, "rt-1.0.0")],
                    )
                })
                .collect(),
        );
        assert!(matches!(
            take(&many, &report, &mut sightings),
            Err(IntakeRefusal::TooManyBindings { .. })
        ));
        assert!(matches!(
            take(
                &run(ScannerKind::Trivy, NOW, vec![runtime_lock()]),
                b"{",
                &mut sightings
            ),
            Err(IntakeRefusal::Parse { .. })
        ));
        assert!(sightings.is_empty());
    }

    #[test]
    fn a_scan_dated_after_intake_is_refused() {
        let report = trivy(json!([lang("rt/Cargo.lock", json!([]))]));
        assert_eq!(
            take(
                &run(ScannerKind::Trivy, NOW + 1, vec![runtime_lock()]),
                &report,
                &mut Sightings::new()
            ),
            Err(IntakeRefusal::ScannedInFuture {
                scanned_at: UnixSeconds::new(NOW + 1),
                now: UnixSeconds::new(NOW)
            })
        );
    }

    #[test]
    fn a_clean_scan_claims_only_what_it_covered() {
        let report = trivy(json!([
            lang("rt/Cargo.lock", json!(null)),
            {"Target": "image (debian 12.7)", "Class": "os-pkgs", "Type": "debian"}
        ]));
        let scan = run(
            ScannerKind::Trivy,
            NOW,
            vec![
                runtime_lock(),
                // The image was scanned at another build than the pinned one.
                bind(
                    named("image (debian 12.7)"),
                    &[(ComponentKind::GuestImage, "img-2026.09")],
                ),
                // Declared, but the report does not name it.
                bind(
                    named("kernel/.config"),
                    &[(ComponentKind::GuestKernel, "6.6.52")],
                ),
            ],
        );
        let record = take(&scan, &report, &mut Sightings::new()).unwrap();
        assert!(record.findings.is_empty());
        assert_eq!(record.covered, BTreeSet::from([ComponentKind::Runtime]));
        assert_eq!(
            record.not_covered,
            BTreeSet::from([ComponentKind::GuestKernel, ComponentKind::GuestImage])
        );
        let in_report: Vec<bool> = record
            .targets
            .iter()
            .map(|target| target.in_report)
            .collect();
        assert_eq!(in_report, [true, true, false]);
        let outcome = record
            .gate(&governance(), &configuration(), UnixSeconds::new(NOW))
            .unwrap();
        assert!(!outcome.has_blocker());
        assert_eq!(outcome.not_scanned, record.not_covered);
        let json = serde_json::to_value(&record).unwrap();
        for claim in ["clean", "secure", "passed", "score"] {
            assert!(json.get(claim).is_none());
        }
        assert_eq!(
            record.report_digest,
            digest(REPORT_DOMAIN, &[report.as_slice()])
        );
        assert_eq!(record.report_bytes, report.len() as u64);
        assert_eq!(record.recorded_at, UnixSeconds::new(NOW));
    }

    #[test]
    fn every_reported_vulnerability_is_mapped_to_every_bound_component() {
        let report = trivy(json!([lang(
            "rt/Cargo.lock",
            json!([
                vulnerability("FIXTURE-2026-0001", "fixture-codec", "2.1.0", "", "HIGH"),
                vulnerability(
                    "FIXTURE-2026-0002",
                    "fixture-build-helper",
                    "0.3.0",
                    "",
                    "CRITICAL"
                )
            ])
        )]));
        let scan = run(
            ScannerKind::Trivy,
            NOW,
            vec![bind(
                named("rt/Cargo.lock"),
                &[
                    (ComponentKind::Runtime, "rt-1.0.0"),
                    (ComponentKind::Helper, "helper-1.0"),
                ],
            )],
        );
        let record = take(&scan, &report, &mut Sightings::new()).unwrap();
        assert_eq!(record.findings.len(), 4);
        let applicability: Vec<(&str, ComponentKind, &Applicability)> = record
            .findings
            .iter()
            .map(|mapped| {
                (
                    mapped.finding.advisory.as_str(),
                    mapped.finding.component,
                    &mapped.finding.applicability,
                )
            })
            .collect();
        assert_eq!(
            applicability[0],
            (
                "FIXTURE-2026-0001",
                ComponentKind::Runtime,
                &Applicability::Applicable
            )
        );
        assert!(matches!(
            applicability[2],
            ("FIXTURE-2026-0002", ComponentKind::Runtime, Applicability::NotApplicable { reason })
                if reason.contains("lists no crates_io fixture-build-helper 0.3.0")
        ));
        // The helper is not part of the configuration: undetermined here, judged not
        // applicable by trust, and still recorded.
        assert_eq!(applicability[1].2, &Applicability::Undetermined);
        let outcome = record
            .gate(&governance(), &configuration(), UnixSeconds::new(NOW))
            .unwrap();
        assert_eq!(outcome.dispositions.len(), 4);
        assert!(matches!(
            &outcome.dispositions[1].1,
            Disposition::NotApplicable { reason } if reason.contains("helper is not part of")
        ));
        assert!(matches!(
            &outcome.dispositions[2].1,
            Disposition::NotApplicable { .. }
        ));
        assert_eq!(
            outcome.blocking,
            vec![AdvisoryId::new("FIXTURE-2026-0001").unwrap()]
        );
        // Undetermined reachability counts as reachable.
        assert_eq!(
            record.findings[0].finding.reachability,
            Reachability::Undetermined
        );
        assert_eq!(
            outcome.dispositions[0].1,
            Disposition::Blocked {
                reason: BlockReason::NoFixWithoutException
            }
        );
        assert_eq!(
            record.findings[0].finding.signal,
            Signal::Scanner {
                name: "trivy 0.56.2".to_owned()
            }
        );
    }

    #[test]
    fn rescanning_never_restarts_a_remediation_window() {
        let report = trivy(json!([lang(
            "rt/Cargo.lock",
            json!([vulnerability(
                "FIXTURE-2026-0001",
                "fixture-codec",
                "2.1.0",
                "2.1.1",
                "HIGH"
            )])
        )]));
        let mut sightings = Sightings::new();
        let first_scan = NOW - 10 * DAY;
        let first = take(
            &run(ScannerKind::Trivy, first_scan, vec![runtime_lock()]),
            &report,
            &mut sightings,
        )
        .unwrap();
        assert_eq!(
            first.findings[0].reported_at_basis,
            ReportedAtBasis::ThisScan
        );
        assert_eq!(
            first.findings[0].finding.reported_at,
            UnixSeconds::new(first_scan)
        );

        // A refused intake leaves the sightings as they were.
        assert!(take(
            &run(ScannerKind::Trivy, NOW, vec![]),
            &report,
            &mut sightings
        )
        .is_err());
        assert_eq!(sightings.len(), 1);

        let second = take(
            &run(ScannerKind::Trivy, NOW - DAY, vec![runtime_lock()]),
            &report,
            &mut sightings,
        )
        .unwrap();
        assert_eq!(
            second.findings[0].reported_at_basis,
            ReportedAtBasis::EarlierScan
        );
        assert_eq!(
            second.findings[0].finding.reported_at,
            UnixSeconds::new(first_scan)
        );
        // High has a 7-day window from the first report: past it, although the latest
        // scan is one day old.
        let outcome = second
            .gate(&governance(), &configuration(), UnixSeconds::new(NOW))
            .unwrap();
        assert_eq!(
            outcome.dispositions[0].1,
            Disposition::Blocked {
                reason: BlockReason::PastDeadline {
                    deadline: UnixSeconds::new(first_scan + 7 * DAY)
                }
            }
        );
        assert_eq!(
            sightings.first_reported(
                &AdvisoryId::new("FIXTURE-2026-0001").unwrap(),
                ComponentKind::Runtime,
                &ComponentVersion::new("rt-1.0.0").unwrap()
            ),
            Some(UnixSeconds::new(first_scan))
        );

        // A publication date earlier than any scan starts the window.
        let published = trivy(json!([lang(
            "rt/Cargo.lock",
            json!([{
                "VulnerabilityID": "FIXTURE-2026-0003", "PkgName": "serde", "InstalledVersion": "1.0.210",
                "FixedVersion": "1.0.211", "Severity": "MEDIUM", "PublishedDate": "2026-01-01T00:00:00Z"
            }])
        )]));
        let record = take(
            &run(ScannerKind::Trivy, NOW, vec![runtime_lock()]),
            &published,
            &mut sightings,
        )
        .unwrap();
        assert_eq!(
            record.findings[0].reported_at_basis,
            ReportedAtBasis::AdvisoryPublished
        );
        assert_eq!(
            record.findings[0].finding.reported_at,
            UnixSeconds::new(1_767_225_600)
        );
    }

    #[test]
    fn reachability_statements_apply_to_their_finding_only() {
        let report = trivy(json!([lang(
            "rt/Cargo.lock",
            json!([
                vulnerability("FIXTURE-2026-0001", "fixture-codec", "2.1.0", "", "HIGH"),
                vulnerability("FIXTURE-2026-0004", "serde", "1.0.210", "", "HIGH")
            ])
        )]));
        let evidence = digest("yougori/test/reachability/v1", &[b"call graph"]);
        let statement = ReachabilityStatement {
            advisory: AdvisoryId::new("FIXTURE-2026-0001").unwrap(),
            component: ComponentKind::Runtime,
            component_version: ComponentVersion::new("rt-1.0.0").unwrap(),
            reachability: Reachability::Unreachable { evidence },
        };
        let statements = ReachabilityStatements::new(vec![statement.clone()]).unwrap();
        let record = intake(
            &inventory(),
            &run(ScannerKind::Trivy, NOW, vec![runtime_lock()]),
            &report,
            &statements,
            &mut Sightings::new(),
            &clock_at(NOW),
        )
        .unwrap();
        assert_eq!(
            record.findings[0].finding.reachability,
            Reachability::Unreachable { evidence }
        );
        assert_eq!(
            record.findings[1].finding.reachability,
            Reachability::Undetermined
        );
        let outcome = record
            .gate(&governance(), &configuration(), UnixSeconds::new(NOW))
            .unwrap();
        assert_eq!(
            outcome.dispositions[0].1,
            Disposition::Unreachable { evidence }
        );
        assert!(outcome.dispositions[1].1.blocks());

        assert_eq!(
            ReachabilityStatements::new(vec![statement.clone(), statement]).err(),
            Some(IntakeRefusal::DuplicateStatement {
                advisory: AdvisoryId::new("FIXTURE-2026-0001").unwrap(),
                component: ComponentKind::Runtime,
                component_version: ComponentVersion::new("rt-1.0.0").unwrap()
            })
        );
        let json = json!({
            "advisory": "FIXTURE-2026-0001", "component": "runtime",
            "component_version": "rt-1.0.0", "reachability": "undetermined", "extra": 1
        });
        assert!(serde_json::from_value::<ReachabilityStatement>(json).is_err());
    }

    #[test]
    fn fixes_become_trust_remediation() {
        let label = |text: &str| fixed_in_label(&FixStatement::new(text).unwrap()).unwrap();
        assert_eq!(label("1.6.1").as_str(), "1.6.1");
        assert_eq!(label("1:2.3").as_str(), "1:2.3");
        assert_eq!(label(">=1.6.1").as_str(), "fix-_3E_3D1.6.1");
        assert_eq!(
            label(">=0.6.14, <1.0.0").as_str(),
            "fix-_3E_3D0.6.14_2C_20_3C1.0.0"
        );
        assert_eq!(label("3.0.13-1~deb12u1").as_str(), "fix-3.0.13-1_7Edeb12u1");
        // The longest statement still fits trust's identifier length.
        assert_eq!(label(&">".repeat(40)).as_str().len(), 124);

        let report = trivy(json!([lang(
            "rt/Cargo.lock",
            json!([
                vulnerability("FIXTURE-2026-0001", "fixture-codec", "2.1.0", "", "HIGH"),
                vulnerability(
                    "FIXTURE-2026-0004",
                    "serde",
                    "1.0.210",
                    "1.0.211, 2.0.0",
                    "HIGH"
                )
            ])
        )]));
        let record = take(
            &run(ScannerKind::Trivy, NOW, vec![runtime_lock()]),
            &report,
            &mut Sightings::new(),
        )
        .unwrap();
        assert_eq!(record.findings[0].finding.remediation, Remediation::NoFix);
        // The package and every statement, exactly as reported, not a component version.
        assert_eq!(
            record.findings[1].finding.remediation,
            Remediation::PackageFixAvailable {
                fix: PackageFix::new("serde", vec!["1.0.211".to_owned(), "2.0.0".to_owned()])
                    .unwrap()
            }
        );
        assert_eq!(record.findings[1].fixes.len(), 2);
    }

    #[test]
    fn findings_are_not_failed_blindly() {
        let report = trivy(json!([lang(
            "rt/Cargo.lock",
            json!([
                vulnerability("FIXTURE-2026-0005", "fixture-codec", "2.1.0", "", "LOW"),
                vulnerability("FIXTURE-2026-0006", "serde", "1.0.210", "1.0.211", "MEDIUM")
            ])
        )]));
        let record = take(
            &run(ScannerKind::Trivy, NOW, vec![runtime_lock()]),
            &report,
            &mut Sightings::new(),
        )
        .unwrap();
        let outcome = record
            .gate(&governance(), &configuration(), UnixSeconds::new(NOW))
            .unwrap();
        assert_eq!(
            outcome.dispositions[0].1,
            Disposition::BelowThreshold {
                severity: Severity::Low,
                block_at: Severity::Medium
            }
        );
        assert_eq!(
            outcome.dispositions[1].1,
            Disposition::WithinWindow {
                deadline: UnixSeconds::new(NOW + 30 * DAY)
            }
        );
        assert!(!outcome.has_blocker());
    }

    #[test]
    fn a_record_is_gated_only_against_its_own_configuration() {
        let report = trivy(json!([lang("rt/Cargo.lock", json!([]))]));
        let record = take(
            &run(ScannerKind::Trivy, NOW, vec![runtime_lock()]),
            &report,
            &mut Sightings::new(),
        )
        .unwrap();
        let mut other = configuration();
        other.devices.clear();
        assert!(matches!(
            record.gate(&governance(), &other, UnixSeconds::new(NOW)),
            Err(GateRefusal::OtherConfiguration { .. })
        ));
    }

    #[test]
    fn sightings_are_bounded() {
        let mut sightings = Sightings::new();
        for n in 0..MAX_SIGHTINGS {
            sightings.first_reported.insert(
                (
                    AdvisoryId::new(format!("FIXTURE-{n}")).unwrap(),
                    ComponentKind::Runtime,
                    ComponentVersion::new("rt-1.0.0").unwrap(),
                ),
                UnixSeconds::new(1),
            );
        }
        let report = trivy(json!([lang(
            "rt/Cargo.lock",
            json!([vulnerability(
                "FIXTURE-2026-0001",
                "fixture-codec",
                "2.1.0",
                "",
                "HIGH"
            )])
        )]));
        assert_eq!(
            take(
                &run(ScannerKind::Trivy, NOW, vec![runtime_lock()]),
                &report,
                &mut sightings
            ),
            Err(IntakeRefusal::SightingsFull { max: MAX_SIGHTINGS })
        );
        assert_eq!(sightings.len(), MAX_SIGHTINGS);
        // A finding already remembered needs no room.
        let known = trivy(json!([lang(
            "rt/Cargo.lock",
            json!([vulnerability(
                "FIXTURE-7",
                "fixture-codec",
                "2.1.0",
                "",
                "HIGH"
            )])
        )]));
        let record = take(
            &run(ScannerKind::Trivy, NOW, vec![runtime_lock()]),
            &known,
            &mut sightings,
        )
        .unwrap();
        assert_eq!(record.findings[0].finding.reported_at, UnixSeconds::new(1));
    }

    #[test]
    fn scan_runs_are_read_strictly() {
        let value = json!({
            "scanner": "cargo_audit", "scanner_version": "0.21.0", "scanned_at": NOW,
            "targets": [{"target": "whole_report", "components": {"runtime": "rt-1.0.0"}}]
        });
        let scan: ScanRun = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(scan.targets[0].target, ReportTarget::WholeReport);
        let mut extra = value.clone();
        extra["approved"] = json!(true);
        assert!(serde_json::from_value::<ScanRun>(extra).is_err());
        let mut bad_version = value.clone();
        bad_version["scanner_version"] = json!("0.21 beta");
        assert!(serde_json::from_value::<ScanRun>(bad_version).is_err());
        let mut bad_scanner = value;
        bad_scanner["scanner"] = json!("grype");
        assert!(serde_json::from_value::<ScanRun>(bad_scanner).is_err());
    }

    #[test]
    fn completeness_is_recorded_for_each_covered_component() {
        let report = json!({"SchemaVersion": 2, "Results": [
            {"Target": "rt/Cargo.lock", "Class": "lang-pkgs", "Type": "cargo",
             "Packages": [{"Name": "serde", "Version": "1.0.210"}, {"Name": "smallvec", "Version": "1.6.0"}]},
            {"Target": "image (debian 12.7)", "Class": "os-pkgs", "Type": "debian"}
        ]})
        .to_string()
        .into_bytes();
        let scan = run(
            ScannerKind::Trivy,
            NOW,
            vec![
                runtime_lock(),
                bind(
                    named("image (debian 12.7)"),
                    &[(ComponentKind::GuestImage, "img-2026.10")],
                ),
            ],
        );
        let record = take(&scan, &report, &mut Sightings::new()).unwrap();
        assert_eq!(record.package_lists, PackageListStatement::NotStated);
        assert_eq!(record.inventory_digest, inventory().digest());
        let runtime = &record.completeness[&ComponentKind::Runtime];
        let PackageCompleteness::Compared {
            inventoried,
            not_seen,
        } = runtime
        else {
            panic!("not compared: {runtime:?}");
        };
        assert_eq!(*inventoried, 3);
        let names: Vec<String> = not_seen.iter().map(ToString::to_string).collect();
        assert_eq!(
            names,
            [
                "crates_io fixture-codec 2.1.0",
                "crates_io fixture_codec 1.0.0"
            ]
        );
        assert_eq!(
            record.completeness[&ComponentKind::GuestImage],
            PackageCompleteness::NoInventory
        );
        // Only covered components are judged.
        assert_eq!(record.completeness.len(), 2);
    }

    #[test]
    fn only_an_osv_scanner_run_states_all_packages_mode() {
        let mut trivy_run = run(ScannerKind::Trivy, NOW, vec![runtime_lock()]);
        trivy_run.package_lists = PackageListStatement::OsvAllPackages;
        let refusal = take(
            &trivy_run,
            &trivy(json!([lang("rt/Cargo.lock", json!([]))])),
            &mut Sightings::new(),
        )
        .unwrap_err();
        assert_eq!(
            refusal,
            IntakeRefusal::StatementNotForScanner {
                scanner: ScannerKind::Trivy,
                statement: PackageListStatement::OsvAllPackages
            }
        );
        assert!(refusal.to_string().contains("all-packages mode"));

        let osv = json!({"results": [{"source": {"path": "rt/Cargo.lock"}, "packages": [
            {"package": {"name": "smallvec", "version": "1.6.0", "ecosystem": "crates.io"}},
            {"package": {"name": "serde", "version": "1.0.210", "ecosystem": "crates.io"}}
        ]}]})
        .to_string()
        .into_bytes();
        let mut osv_run = run(ScannerKind::OsvScanner, NOW, vec![runtime_lock()]);
        let default = take(&osv_run, &osv, &mut Sightings::new()).unwrap();
        assert!(matches!(
            &default.completeness[&ComponentKind::Runtime],
            PackageCompleteness::CannotTell {
                why: NotTellable::NamesFindingsOnly,
                not_listed,
                ..
            } if not_listed.len() == 2
        ));
        osv_run.package_lists = PackageListStatement::OsvAllPackages;
        let stated = take(&osv_run, &osv, &mut Sightings::new()).unwrap();
        assert!(matches!(
            &stated.completeness[&ComponentKind::Runtime],
            PackageCompleteness::Compared { not_seen, .. } if not_seen.len() == 2
        ));

        let value = json!({
            "scanner": "osv_scanner", "scanner_version": "1.9.2", "scanned_at": NOW,
            "targets": [{"target": {"named": "rt/Cargo.lock"}, "components": {"runtime": "rt-1.0.0"}}],
            "package_lists": "osv_all_packages"
        });
        let read: ScanRun = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(read.package_lists, PackageListStatement::OsvAllPackages);
        let mut unknown = value;
        unknown["package_lists"] = json!("everything");
        assert!(serde_json::from_value::<ScanRun>(unknown).is_err());
    }
}
