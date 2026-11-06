//! Scanner report intake for the VM sandbox's vulnerability gate
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, §8.3 line 2459: "Vulnerability
//! scanning is supporting evidence. Define severity, reachability, available fixes,
//! time-limited exceptions and patch deadlines instead of failing every finding blindly
//! or treating a green scan as security proof"; §10.6 VM-W47 line 2670: "Gate by
//! applicability, reachability, severity, remediation window and evidence; scanning is
//! one signal ... Deliberately vulnerable fixture exercises the gate; expiring exceptions
//! cannot become permanent silent bypasses; false-positive review documented"; VM-W46
//! line 2669; VM-P28 line 2803; §19 lines 3248–3249: cargo-audit,
//! cargo-deny and Trivy are optional tools, and reading their output adds no
//! dependency).
//!
//! The scanning part of M18. Nothing here runs a scanner or touches the network: it reads
//! reports a scanner already wrote and maps them onto `sandbox::trust`'s findings, whose
//! [`Governance`](crate::sandbox::trust::Governance) is the one gate. Pure and
//! synchronous; calendar time comes from trust's [`TrustClock`](crate::sandbox::trust::TrustClock).
//!
//! - [`report`], [`osv`], [`cargo_audit`], [`trivy`]: strict, bounded parsers for
//!   OSV-Scanner JSON, `cargo audit --json` and Trivy JSON (vulnerability results only)
//!   into one [`ParsedReport`]. Sizes and counts are bounded, malformed or oversized
//!   input is a typed [`ParseError`], unknown fields of a scanner's own output are
//!   tolerated, and every field read is validated.
//! - [`severity`], [`cvss`] and [`cvss_v4`]: the documented severity mapping, with CVSS
//!   v3 and CVSS v4.0 base scores computed from vectors. A v4.0 score is the base score
//!   (CVSS-B) of FIRST's specification, from its published macro-vector scores
//!   (transcribed in `cvss_v4_data`) and its interpolation; threat, environmental and
//!   supplemental metrics do not change it. A vector the reference data does not cover
//!   stays unscored rather than guessed, and an unknown severity counts as Critical.
//! - [`inventory`]: which packages each pinned component contains, bound to its exact
//!   version and content key; a finding for a package the inventory does not list is
//!   recorded as not applicable, never dropped.
//! - [`intake`]: a [`ScanRun`] and a report become a [`ScanRecord`]: one trust
//!   [`Finding`](crate::sandbox::trust::Finding) per reported vulnerability and bound
//!   component, reachability undetermined unless a [`ReachabilityStatement`] is given,
//!   the remediation window running from the earliest known report, and the components
//!   covered and not covered, so a scan with no findings never claims more than it
//!   covered. [`ScanRecord::gate`] runs trust's gate over it. A reported fix becomes
//!   trust's [`PackageFix`](crate::sandbox::trust::PackageFix), kept as reported.
//! - [`coverage`]: whether a scan saw every inventoried package of a component it
//!   covered, where the format lists what it read; where it cannot tell, it says so.
//! - [`combine`]: several scan records of one configuration and inventory as one gate
//!   decision: each finding judged by trust's governance, the strictest disposition of
//!   an issue deciding, advisories joined only through aliases the reports state, and
//!   coverage joined with each component's covering scans named.
//! - [`sightings`]: the earliest report of each finding on a CORE-06 durable stream, so
//!   a restart neither forgets a sighting nor restarts a remediation window.
//!
//! The deliberately vulnerable fixture (a configuration whose runtime ships smallvec
//! 1.6.0, RUSTSEC-2021-0003, with reports in all three formats) lives in `fixtures/` and
//! is exercised by the tests.

pub mod cargo_audit;
pub mod combine;
pub mod coverage;
pub mod cvss;
pub mod cvss_v4;
mod cvss_v4_data;
pub mod intake;
pub mod inventory;
pub mod osv;
pub mod package;
pub mod report;
pub mod severity;
pub mod sightings;
pub mod trivy;

#[cfg(test)]
mod fixture;
#[cfg(test)]
mod tests;

pub use cargo_audit::parse_cargo_audit;
pub use combine::{
    combine, CombineRefusal, CombinedCompleteness, CombinedFinding, CombinedGate,
    ComponentCoverage, IssueReport, ScanName, MAX_COMBINED_SCANS,
};
pub use coverage::{NotTellable, PackageCompleteness, PackageListStatement};
pub use cvss::{
    parse_v4, roundup_tenths, score_vector, CvssError, CvssRating, CvssScore, CvssV4Vector,
    CvssVersion, MacroVector, VectorScore, MAX_VECTOR_BYTES, V4_BASE_METRICS,
};
pub use cvss_v4::{v4_base_score, V4NotScored};
pub use intake::{
    fixed_in_label, intake, GateRefusal, IntakeRefusal, MappedFinding, ReachabilityStatement,
    ReachabilityStatements, ReportedAtBasis, ScanRecord, ScanRun, Sightings, TargetBinding,
    TargetCoverage, MAX_BINDINGS, MAX_SIGHTINGS, MAX_STATEMENTS, REPORT_DOMAIN,
};
pub use inventory::{
    ComponentInventory, ConfigurationInventory, InventoryRefusal, INVENTORY_DOMAIN,
    MAX_INVENTORY_PACKAGES,
};
pub use osv::parse_osv_scanner;
pub use package::{
    Ecosystem, FixStatement, PackageName, PackageRef, PackageVersion, TargetName, TextProblem,
    MAX_FIX_BYTES, MAX_PACKAGE_NAME_BYTES, MAX_PACKAGE_VERSION_BYTES, MAX_TARGET_BYTES,
};
pub use report::{
    PackagesRead, ParseError, ParsedReport, ReportTarget, ReportedTarget, ReportedVulnerability,
    ScannerKind, ScannerVersion, SkippedResult, MAX_ALIASES, MAX_DETAIL_BYTES, MAX_FIXES,
    MAX_NAME_BYTES, MAX_PACKAGES, MAX_RANGE_ITEMS, MAX_REPORT_BYTES, MAX_SMALL_LIST, MAX_TARGETS,
    MAX_VULNERABILITIES,
};
pub use severity::{severity_of_score, ScannerLabel, SeverityBasis, UnknownSeverity};
pub use sightings::{
    LostRange, Sighting, SightingRecord, SightingsError, SightingsLog, MAX_LOSSES,
    MAX_SIGHTINGS_PER_RECORD,
};
pub use trivy::{parse_trivy, TRIVY_SCHEMA_VERSION};
