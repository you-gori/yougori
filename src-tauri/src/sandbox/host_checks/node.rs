//! The closed set of sysfs entries VM-CP-31's host part reads (§17, line 3181; §7.5,
//! lines 2396–2409): per PCI device `bus/pci/devices/<address>` and its `class`,
//! `boot_vga`, `reset_method`, `config`, `driver` and `iommu_group`, and per IOMMU group
//! `kernel/iommu_groups/<group>/devices`. A reader is asked for nothing else, so no
//! implementation of the port can be steered to another path.

use std::fmt;

use serde::{Serialize, Serializer};

use super::address::{IommuGroup, PciAddress};

/// One attribute of a PCI device directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Attribute {
    /// `class`: the 24-bit class code, written `0x%06x`.
    Class,
    /// `boot_vga`: whether firmware booted the display on this device; the kernel gives
    /// it only to VGA-compatible display controllers.
    BootVga,
    /// `reset_method`: the reset methods the kernel will use, in order (Linux 5.15 and
    /// later); hidden when the device has none, empty when an administrator disabled them.
    ResetMethod,
    /// `config`: the configuration space; a reader without `CAP_SYS_ADMIN` gets only its
    /// first 64 bytes.
    Config,
    /// `driver`: a link to the bound driver, absent while no driver is bound.
    Driver,
    /// `iommu_group`: a link to the device's IOMMU group, absent when it has none.
    IommuGroup,
}

impl Attribute {
    /// The attribute's file name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Class => "class",
            Self::BootVga => "boot_vga",
            Self::ResetMethod => "reset_method",
            Self::Config => "config",
            Self::Driver => "driver",
            Self::IommuGroup => "iommu_group",
        }
    }

    /// What kind of entry the attribute is.
    pub const fn kind(self) -> NodeKind {
        match self {
            Self::Class | Self::BootVga | Self::ResetMethod | Self::Config => NodeKind::File,
            Self::Driver | Self::IommuGroup => NodeKind::Link,
        }
    }
}

/// What kind of entry a node is, and so which read of the port it takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    /// An attribute file: [`SysfsReader::read`](super::reader::SysfsReader::read).
    File,
    /// A symbolic link: [`SysfsReader::link`](super::reader::SysfsReader::link).
    Link,
    /// A directory: [`SysfsReader::list`](super::reader::SysfsReader::list).
    Directory,
}

/// One entry this module reads, relative to the sysfs root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SysfsNode {
    /// `bus/pci/devices/<address>`: the link to the device's directory in the device tree,
    /// whose path names every bridge between the device and its root bus.
    Device { address: PciAddress },
    /// `bus/pci/devices/<address>/<attribute>`.
    Attribute {
        address: PciAddress,
        attribute: Attribute,
    },
    /// `kernel/iommu_groups/<group>/devices`: one link per member of the group.
    GroupDevices { group: IommuGroup },
}

impl SysfsNode {
    pub const fn attribute(address: PciAddress, attribute: Attribute) -> Self {
        Self::Attribute { address, attribute }
    }

    /// The path components below the sysfs root.
    pub fn components(&self) -> Vec<String> {
        match self {
            Self::Device { address } => device_components(*address),
            Self::Attribute { address, attribute } => {
                let mut components = device_components(*address);
                components.push(attribute.name().to_owned());
                components
            }
            Self::GroupDevices { group } => vec![
                "kernel".to_owned(),
                "iommu_groups".to_owned(),
                group.to_string(),
                "devices".to_owned(),
            ],
        }
    }

    /// What kind of entry the node is.
    pub const fn kind(&self) -> NodeKind {
        match self {
            Self::Device { .. } => NodeKind::Link,
            Self::Attribute { attribute, .. } => attribute.kind(),
            Self::GroupDevices { .. } => NodeKind::Directory,
        }
    }
}

fn device_components(address: PciAddress) -> Vec<String> {
    vec![
        "bus".to_owned(),
        "pci".to_owned(),
        "devices".to_owned(),
        address.to_string(),
    ]
}

impl fmt::Display for SysfsNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.components().join("/"))
    }
}

impl Serialize for SysfsNode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
