//! The host's observations of the hypervisor configuration a launch runs with, beside the
//! §1.3 facts, for the launch record (§8.1 lines 2433–2439; §17 lines 3145–3188):
//!
//! - [`ConfigurationComparison`] (VM-CP-02, line 3152): the configuration the host
//!   observed (Firecracker API calls or QEMU argv) compared with the approved profile's
//!   golden file, and the devices the row names that the configuration has although the
//!   device profile does not declare them;
//! - [`HostInterfaceListing`] (VM-CP-03, line 3153): what the host found of the
//!   hypervisor's host interfaces in its process listing or API description;
//! - [`GpuAssignmentOrder`] (VM-CP-31, line 3181): one assigned GPU's isolation as the host
//!   checked it before assigning the device, and the assignment, each stamped when the
//!   host made it, so the record shows the order.
//!
//! A backend that has them hands them to admission in [`ConfigurationFacts`]; admission
//! judges them and the record binds them. Each is optional: a backend that does not pass
//! one seals a record without it, and such a record keeps the identity it had before
//! these facts existed. Nothing here touches the host.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::facets::{GpuIsolation, GpuIsolationCheck, ObservedGpu, UnsafeDeviceSetting};
use super::observation::HostObserved;
use crate::foundation::ids::{Digest, GpuDeviceKey};

/// The §7.5 checks VM-CP-31 requires before assignment (line 3181: "IOMMU group
/// completeness, reset capability, host display ownership and ACS state are checked
/// before assignment").
pub const CHECKED_BEFORE_ASSIGNMENT: [GpuIsolationCheck; 4] = [
    GpuIsolationCheck::CompleteIsolationGroup,
    GpuIsolationCheck::SafeResetAndReassignment,
    GpuIsolationCheck::NoHostDisplayOrOtherUsers,
    GpuIsolationCheck::NoUnsafeAcsOrIommuBypass,
];

/// The unsafe settings that defeat the ACS state VM-CP-31 checks (§7.5 line 2407: no
/// unsafe ACS/IOMMU bypass settings).
pub const ACS_BYPASS_SETTINGS: [UnsafeDeviceSetting; 2] = [
    UnsafeDeviceSetting::AcsOverride,
    UnsafeDeviceSetting::IommuBypass,
];

/// VM-CP-02 (line 3152): how the hypervisor configuration the host observed compares with
/// the approved profile's golden file, and which of the devices the row names the
/// configuration has although the device profile does not declare them. The golden file
/// is versioned with the backend (the row's note): its digest covers the backend version,
/// and the record binds the backend build beside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationComparison {
    /// The digest of the approved golden file.
    pub golden: Digest,
    /// The digest of the configuration the host observed, in the golden file's
    /// canonical form; equal to `golden` exactly when the configuration is the golden
    /// file's.
    pub observed: Digest,
    pub network_device: bool,
    pub console: bool,
    pub balloon: bool,
    /// A PCI transport the device profile does not declare.
    pub undeclared_pci_transport: bool,
}

impl ConfigurationComparison {
    /// The observed configuration is the golden file's.
    pub fn matches(&self) -> bool {
        self.golden == self.observed
    }

    /// The configuration is the golden file's and has none of the devices the row names.
    pub fn approved(&self) -> bool {
        self.findings().is_empty()
    }

    /// Every reason the configuration is not the approved one, in the row's order.
    pub fn findings(&self) -> Vec<String> { self.findings_with_internet(false) }

    pub fn findings_with_internet(&self, internet: bool) -> Vec<String> {
        let mut findings = Vec::new();
        if !self.matches() {
            findings.push(format!(
                "the observed configuration {} is not the golden file {}",
                self.observed, self.golden
            ));
        }
        for (found, what) in [
            (self.network_device && !internet, "a network device"),
            (self.console, "a console"),
            (self.balloon, "a balloon"),
            (
                self.undeclared_pci_transport,
                "a PCI transport the device profile does not declare",
            ),
        ] {
            if found {
                findings.push(format!("the configuration has {what}"));
            }
        }
        findings
    }
}

/// VM-CP-03 (line 3153): what the host found of the hypervisor's host interfaces in its
/// process listing (QEMU's argv) or its API description (Firecracker's). A listing is one
/// check of all four facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostInterfaceListing {
    /// A host filesystem share device: 9p, virtiofs, HGFS or an equivalent.
    pub share_device: bool,
    /// A monitor or management interface (QMP, HMP or the hypervisor's API) on a TCP or
    /// other network listener.
    pub management_listener: bool,
    /// The monitor's or API's socket is in the host-created private directory of the
    /// launch.
    pub monitor_socket_private: bool,
    /// A host port forward to the old agent port.
    pub old_agent_port_forward: bool,
}

impl HostInterfaceListing {
    /// No share device, no management listener, the monitor socket private and no port
    /// forward.
    pub const fn clean() -> Self {
        Self {
            share_device: false,
            management_listener: false,
            monitor_socket_private: true,
            old_agent_port_forward: false,
        }
    }

    /// The listing shows the restrictions of VM-CP-03.
    pub fn approved(&self) -> bool {
        self.findings().is_empty()
    }

    /// Every restriction the listing shows broken, in the row's order.
    pub fn findings(&self) -> Vec<String> {
        [
            (self.share_device, "a host filesystem share device"),
            (self.management_listener, "a monitor on a network listener"),
            (
                !self.monitor_socket_private,
                "the monitor socket outside the launch's private directory",
            ),
            (
                self.old_agent_port_forward,
                "a host port forward to the old agent port",
            ),
        ]
        .into_iter()
        .filter(|(found, _)| *found)
        .map(|(_, what)| format!("the listing shows {what}"))
        .collect()
    }
}

/// VM-CP-31 (line 3181): one assigned GPU's isolation as the host checked it before it
/// assigned the device, and the host's observation of the assignment. Both are stamped
/// on the evidence clock when the host made them, so the record shows the order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GpuAssignmentOrder {
    /// The device and its §7.5 checks, as the host observed them before assignment.
    pub checked: HostObserved<ObservedGpu>,
    /// The device the host assigned to the VM, observed when it did.
    pub assigned: HostObserved<GpuDeviceKey>,
}

impl GpuAssignmentOrder {
    /// The device the checks are about.
    pub fn device(&self) -> GpuDeviceKey {
        self.checked.value().device
    }

    /// What the host observed of the device's isolation before assignment.
    pub fn isolation(&self) -> &GpuIsolation {
        &self.checked.value().isolation
    }

    /// Whether the stamps show the checks made before the assignment of the same device:
    /// both on one clock session, the checks strictly earlier. Equal times do not show an
    /// order.
    pub fn checked_before_assignment(&self) -> bool {
        *self.assigned.value() == self.device()
            && self.checked.clock() == self.assigned.clock()
            && self.checked.observed_at() < self.assigned.observed_at()
    }

    /// The checks of [`CHECKED_BEFORE_ASSIGNMENT`] the pre-assignment observation does not
    /// show passing.
    pub fn missing_before_assignment(&self) -> BTreeSet<GpuIsolationCheck> {
        CHECKED_BEFORE_ASSIGNMENT
            .into_iter()
            .filter(|check| !self.isolation().checks.contains(check))
            .collect()
    }

    /// Whether the order shows `check` made, and passing, before assignment; for the ACS
    /// state, also no ACS or IOMMU bypass setting.
    pub fn shows_before_assignment(&self, check: GpuIsolationCheck) -> bool {
        let isolation = self.isolation();
        let bypassed = check == GpuIsolationCheck::NoUnsafeAcsOrIommuBypass
            && ACS_BYPASS_SETTINGS
                .iter()
                .any(|setting| isolation.unsafe_settings.contains(setting));
        self.checked_before_assignment() && isolation.checks.contains(&check) && !bypassed
    }
}

/// The host's observations of the hypervisor configuration that a backend hands to
/// admission beside the [`LaunchFacts`](super::LaunchFacts), each optional. What each
/// backend passes in is in the module documentation of `sandbox::backend`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConfigurationFacts {
    /// VM-CP-02: the golden comparison of the running configuration.
    pub comparison: Option<HostObserved<ConfigurationComparison>>,
    /// VM-CP-03: the listing check of the running hypervisor.
    pub listing: Option<HostObserved<HostInterfaceListing>>,
    /// VM-CP-31: one order per assigned GPU; empty when the backend passes none.
    pub gpu_assignments: Vec<GpuAssignmentOrder>,
}

impl ConfigurationFacts {
    /// No configuration facts: what [`admit`](super::admit) passes.
    pub fn none() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.comparison.is_none() && self.listing.is_none() && self.gpu_assignments.is_empty()
    }
}

/// A configuration fact of a launch record, by name, for the stamps read from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConfigurationFact {
    /// The VM-CP-02 golden comparison.
    Comparison,
    /// The VM-CP-03 listing check.
    Listing,
    /// An assigned GPU's checks before assignment (VM-CP-31).
    GpuChecked { device: GpuDeviceKey },
    /// An assigned GPU's assignment (VM-CP-31).
    GpuAssigned { device: GpuDeviceKey },
}

impl fmt::Display for ConfigurationFact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Comparison => f.write_str("golden configuration comparison"),
            Self::Listing => f.write_str("host interface listing"),
            Self::GpuChecked { device } => {
                write!(f, "checks of GPU {} before assignment", device.device)
            }
            Self::GpuAssigned { device } => write!(f, "assignment of GPU {}", device.device),
        }
    }
}
