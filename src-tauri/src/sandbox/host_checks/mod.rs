//! Real host check runners for `sandbox::probes`
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: §17, lines 3145–3188; leftover entry
//! M08): VM-CP-31's host part on Linux, GPU device assignment read from sysfs (§7.5 GPU
//! VMs, lines 2396–2409; VM-W18, line 2617; VM-P39, line 2814; VM-R26, line 2891;
//! VM-CP-31 at line 3181), in the files below, and VM-CP-12, a fixture credential found
//! only in the executor's outbound request within the stated coverage (line 3162), in
//! [`credential_scan`].
//!
//! - [`address`]: PCI function addresses, root buses and IOMMU group numbers, parsed only
//!   in the kernel's own spelling.
//! - [`node`]: the closed set of sysfs entries read: `bus/pci/devices/<address>` with
//!   its `class`, `boot_vga`, `reset_method`, `config`, `driver` and `iommu_group`, and
//!   `kernel/iommu_groups/<group>/devices`.
//! - [`reader`]: the read-only [`SysfsReader`] port and [`SysfsDir`], which serves it
//!   from a directory: a mounted sysfs in the kernel's layout, or a recording in a
//!   portable layout that any file system can hold.
//! - [`attributes`]: strict parsers of the attribute values and link targets.
//! - [`config`]: a strict reader of a bridge's configuration space, its PCI Express port
//!   type and its ACS capability as the hardware reports it.
//! - [`assess`]: the four guards of one GPU, IOMMU group completeness, host display and
//!   other users, reset capability and ACS state, each clear, a named [`Hazard`] or
//!   undecided with the fact that could not be read; an [`Assessment`] also gives the
//!   backend's checks it shows passing, which a GPU backend stamps before assignment for
//!   its launch record ([`Assessment::checks_before_assignment`]).
//! - [`runner`]: [`GpuAssignmentRunner`], a `sandbox::probes` [`HostCheckRunner`]
//!   that maps the guards onto exactly VM-CP-31's typed observations and its positive
//!   control, for the CORE-01 adapter `DeviceAssignmentIsolatedProbe`.
//! - [`credential_scan`]: [`CredentialScanRunner`], VM-CP-12's runner, which scans the
//!   files and directories a [`ScanPlan`] names through the read-only [`ScanReader`] port
//!   for a fixture credential and its common encodings, states exactly what it covered
//!   and where the credential was found, and maps that onto VM-CP-12's observations, for
//!   the CORE-01 adapter `CredentialAbsentFromScannedLocationsProbe`.
//!
//! In both runners, missing, unreadable or malformed facts leave their observation out,
//! so the run is inconclusive and never a pass. VM-CP-31 is scoped to Linux hosts in the
//! probes catalog (§7.5 lines 2398 and 2411), so on a host that is not Linux the CORE-01
//! adapter reports not tested without running the runner and the judge reads the check
//! not tested; the runner itself observes and reads nothing there either. Both ports have
//! reads only and nothing here changes the host. Nothing here names or reads `/sys`: the
//! caller roots a [`SysfsDir`] there, and the tests read recorded trees in temporary
//! directories only. Reading a bridge's full configuration space needs a privileged
//! reader; the 64 bytes an unprivileged one gets leave ACS undecided.
//!
//! [`HostCheckRunner`]: crate::sandbox::probes::HostCheckRunner

pub mod address;
pub mod assess;
pub mod attributes;
pub mod config;
pub mod credential_scan;
pub mod node;
pub mod reader;
pub mod runner;

#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod tests;

pub use address::{AddressError, IommuGroup, PciAddress, RootBus, MAX_DEVICE, MAX_FUNCTION};
pub use assess::{
    assess, Assessment, FactProblem, Hazard, Problem, Unassessable, Verdict, ASSIGNMENT_DRIVER,
    MAX_ATTRIBUTE_BYTES,
};
pub use attributes::{
    parse_boot_vga, parse_class, parse_device_path, parse_driver_link, parse_group_link,
    parse_group_members, parse_reset_methods, DriverName, ParseError, PciClass, ResetMethod,
    MAX_DRIVER_NAME_BYTES, MAX_UPSTREAM_PORTS,
};
pub use config::{
    parse_config, AcsRegisters, ConfigError, ConfigSpace, HeaderLayout, PortType,
    ACS_COMPLETION_REDIRECT, ACS_REQUEST_REDIRECT, ACS_REQUIRED, ACS_SOURCE_VALIDATION,
    ACS_TRANSLATION_BLOCKING, ACS_UPSTREAM_FORWARDING, CONFIG_BYTES, EXTENDED_CONFIG_BYTES,
    HEADER_BYTES,
};
pub use credential_scan::{
    CredentialScanRunner, FixtureCredential, FixtureError, HostFiles, LocationRole, NamedLocation,
    PlanError, ScanLimits, ScanPlan, ScanReader, ScanReport, ScanSettings, ScanSettingsError,
};
pub use node::{Attribute, NodeKind, SysfsNode};
pub use reader::{
    decode_component, encode_component, Layout, ReadError, SysfsDir, SysfsReader, MAX_ENTRIES,
    MAX_LINK_BYTES, RECORDED_LINK_SUFFIX,
};
pub use runner::{
    GpuAssignmentRunner, RunnerSettings, SettingsError, ACS_CHECKED, DISPLAY_OWNING,
    GPU_ASSIGNMENT_CHECK_NUMBER, INCOMPLETE_GROUP, MAX_GPUS, QUALIFYING_ASSIGNS, RESET_CHECKED,
};
