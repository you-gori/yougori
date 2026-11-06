//! The deliberately vulnerable fixture (VM-W47 acceptance, line 2670: "Deliberately
//! vulnerable fixture exercises the gate"). Test-only data, kept as files beside this
//! module and compiled in with `include_str!`.
//!
//! - `fixtures/configuration.json`: a pinned Linux x86_64 Firecracker configuration
//!   whose runtime `fixture-runtime-0.1.0` is built with the crate smallvec 1.6.0, which
//!   RUSTSEC-2021-0003 (CVE-2021-25900, a buffer overflow in `SmallVec::insert_many`,
//!   fixed in 0.6.14 and 1.6.1) affects.
//! - `fixtures/inventory.json`: the runtime's crates and the guest image's Debian
//!   packages; the guest kernel has no inventory.
//! - `fixtures/cargo-audit.json`, `fixtures/osv-scanner.json`, `fixtures/trivy.json`: the
//!   three formats reporting the vulnerable crate in the runtime's lockfile. cargo audit
//!   also reports a fixture advisory (the RustSec placeholder id) for a build-time crate
//!   the runtime does not ship; Trivy also reports a fixture finding on
//!   `fixture-codec`, matched by name only, for the false-positive review, and a
//!   configuration result it skips.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::foundation::ids::{ManualClock, MonotonicTime};
use crate::sandbox::trust::{
    CalendarAnchor, ComponentKind, ComponentVersion, Governance, GovernancePolicy,
    PinnedConfiguration, Severity, TrustClock, UnixSeconds,
};
use crate::sandbox::trust_scan::coverage::PackageListStatement;
use crate::sandbox::trust_scan::intake::{ScanRun, TargetBinding};
use crate::sandbox::trust_scan::inventory::{ComponentInventory, ConfigurationInventory};
use crate::sandbox::trust_scan::package::TargetName;
use crate::sandbox::trust_scan::report::{ReportTarget, ScannerKind, ScannerVersion};

pub(crate) const CONFIGURATION: &str = include_str!("fixtures/configuration.json");
pub(crate) const INVENTORY: &str = include_str!("fixtures/inventory.json");
pub(crate) const CARGO_AUDIT: &str = include_str!("fixtures/cargo-audit.json");
pub(crate) const OSV_SCANNER: &str = include_str!("fixtures/osv-scanner.json");
pub(crate) const TRIVY: &str = include_str!("fixtures/trivy.json");

pub(crate) const DAY: u64 = 86_400;
/// 2026-10-29T00:00:00Z.
pub(crate) const NOW: u64 = 1_793_232_000;
pub(crate) const SCANNED_AT: u64 = NOW - 3_600;
pub(crate) const LOCKFILE: &str = "fixture/runtime/Cargo.lock";
pub(crate) const RUNTIME_VERSION: &str = "fixture-runtime-0.1.0";

pub(crate) fn configuration() -> PinnedConfiguration {
    serde_json::from_str(CONFIGURATION).unwrap()
}

pub(crate) fn inventory() -> ConfigurationInventory {
    let inventories: Vec<ComponentInventory> = serde_json::from_str(INVENTORY).unwrap();
    ConfigurationInventory::new(configuration(), inventories).unwrap()
}

pub(crate) fn runtime_version() -> ComponentVersion {
    ComponentVersion::new(RUNTIME_VERSION).unwrap()
}

/// Each fixture report with the run that produced it: the lockfile bound to the runtime.
pub(crate) fn runs() -> Vec<(ScanRun, &'static str)> {
    let runtime = BTreeMap::from([(ComponentKind::Runtime, runtime_version())]);
    let run = |scanner, version: &str, target| ScanRun {
        scanner,
        scanner_version: ScannerVersion::new(version).unwrap(),
        scanned_at: UnixSeconds::new(SCANNED_AT),
        targets: vec![TargetBinding {
            target,
            components: runtime.clone(),
        }],
        package_lists: PackageListStatement::NotStated,
    };
    let lockfile = || ReportTarget::Named(TargetName::new(LOCKFILE).unwrap());
    vec![
        (
            run(ScannerKind::CargoAudit, "0.21.0", ReportTarget::WholeReport),
            CARGO_AUDIT,
        ),
        (
            run(ScannerKind::OsvScanner, "1.9.2", lockfile()),
            OSV_SCANNER,
        ),
        (run(ScannerKind::Trivy, "0.56.2", lockfile()), TRIVY),
    ]
}

/// The policy of trust's own tests: Medium and above block; windows of 90, 30, 7 and 2
/// days; exceptions of at most 60 days.
pub(crate) fn governance() -> Governance {
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

/// A calendar clock at [`NOW`] and the monotonic clock that drives it.
pub(crate) fn clock() -> (Arc<ManualClock>, TrustClock) {
    let start = MonotonicTime::from_nanos(1_000_000);
    let manual = Arc::new(ManualClock::new(start));
    let clock = TrustClock::new(
        manual.clone(),
        CalendarAnchor {
            monotonic: start,
            unix_seconds: UnixSeconds::new(NOW),
        },
    )
    .unwrap();
    (manual, clock)
}
