//! VM-CP-12's host check runner: a fixture credential appears only in the executor's
//! outbound request, within the stated coverage
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: §17, lines 3145–3188, VM-CP-12 at
//! line 3162; VM-P12, line 2787; §8.1, lines 2433–2439; VM-R47, VM-R48 and VM-R53, lines
//! 2912–2918; leftover entry M08).
//!
//! - [`fixture`]: the [`FixtureCredential`], never printed or serialized, and the forms it
//!   is searched in: its exact bytes, base64 in both alphabets at every alignment,
//!   hexadecimal and percent-encoding, each in both cases ([`Encoding`]).
//! - [`search`]: a bounded streaming search for every form at once, linear in the bytes
//!   read.
//! - [`port`]: the read-only [`ScanReader`] port over the named locations and
//!   [`HostFiles`], which serves it from the host's file system.
//! - [`plan`]: a [`ScanPlan`]: the launch, the fixture and the files and directories the
//!   caller names for each place the row lists ([`LocationRole`]), whose digest the
//!   CORE-01 subject carries.
//! - [`scan`]: one bounded run over a plan, and the [`ScanReport`] stating per location
//!   the files and bytes read, each finding and each gap, with [`COVERAGE_NOTICE`].
//! - [`runner`]: [`CredentialScanRunner`], a `sandbox::probes` [`HostCheckRunner`] that
//!   maps a run onto exactly VM-CP-12's typed observations, for the CORE-01 adapter
//!   `CredentialAbsentFromScannedLocationsProbe`.
//!
//! Coverage is never claimed past what was read: a location with a gap leaves the
//! coverage statement out, and leaves its place's observation out unless the fixture was
//! found in what was read, so the run is inconclusive and never a pass. The row has no
//! positive control; the executor's outbound request, which must hold the fixture, is one
//! of its observations. The guest overlay is not among the locations: the plan inspects
//! it from a disposable inspection VM, never mounted on the host (line 3162), and nothing
//! here mounts or reads guest storage. The port has reads only and nothing here changes
//! the host; the tests read temporary directories only.
//!
//! [`HostCheckRunner`]: crate::sandbox::probes::HostCheckRunner

pub mod fixture;
pub mod plan;
pub mod port;
pub mod runner;
pub mod scan;
pub mod search;

#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod tests;

pub use fixture::{
    Encoding, FixtureCredential, FixtureError, MAX_FIXTURE_BYTES, MIN_FIXTURE_BYTES,
};
pub use plan::{LocationRole, NamedLocation, PlanError, ScanPlan, LOCATIONS_DOMAIN, MAX_LOCATIONS};
pub use port::{EntryKind, HostFiles, ScanReader};
pub use runner::{
    CredentialScanRunner, ScanSettings, ScanSettingsError, COVERAGE_STATED,
    CREDENTIAL_SCAN_CHECK_NUMBER, MAX_PLANS,
};
pub use scan::{
    scan, Finding, Gap, GapReason, LimitError, LocationReport, ScanLimits, ScanReport, CHUNK_BYTES,
    COVERAGE_NOTICE, MAX_DEPTH_CEILING, MAX_ENTRIES_CEILING, MAX_LISTED,
};
pub use search::{Matcher, Search};
