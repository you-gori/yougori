//! Strict parsers of what the sysfs port returns for VM-CP-31 (§17, line 3181): each
//! accepts only the exact form the kernel writes and refuses anything else, so a
//! malformed, truncated or foreign value leaves its fact undecided and never passes.
//! Errors name the rule that was broken, never the raw value.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Serialize, Serializer};

use super::address::{IommuGroup, PciAddress, RootBus};

/// The most bridges accepted between a device and its root bus.
pub const MAX_UPSTREAM_PORTS: usize = 32;

/// The longest driver name accepted.
pub const MAX_DRIVER_NAME_BYTES: usize = 64;

/// The PCI base class of display controllers.
const DISPLAY_BASE_CLASS: u8 = 0x03;

/// The PCI display subclass of VGA-compatible controllers.
const VGA_SUBCLASS: u8 = 0x00;

/// A device's 24-bit class code (`class`, written `0x%06x\n`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PciClass(u32);

impl PciClass {
    pub const fn code(self) -> u32 {
        self.0
    }

    pub const fn base(self) -> u8 {
        ((self.0 >> 16) & 0xff) as u8
    }

    pub const fn subclass(self) -> u8 {
        ((self.0 >> 8) & 0xff) as u8
    }

    /// A display controller (base class 0x03): a GPU.
    pub const fn is_display(self) -> bool {
        self.base() == DISPLAY_BASE_CLASS
    }

    /// A VGA-compatible display controller (class 0x0300), the only kind the kernel
    /// gives a `boot_vga` attribute.
    pub const fn is_vga(self) -> bool {
        self.is_display() && self.subclass() == VGA_SUBCLASS
    }
}

impl fmt::Display for PciClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:06x}", self.0)
    }
}

impl fmt::Debug for PciClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for PciClass {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// A reset method as `reset_method` names it (Linux `pci_reset_fn_methods`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResetMethod {
    DeviceSpecific,
    Acpi,
    Flr,
    AfFlr,
    Pm,
    Bus,
    CxlBus,
}

impl ResetMethod {
    pub const ALL: [Self; 7] = [
        Self::DeviceSpecific,
        Self::Acpi,
        Self::Flr,
        Self::AfFlr,
        Self::Pm,
        Self::Bus,
        Self::CxlBus,
    ];

    /// The name the kernel writes.
    pub const fn name(self) -> &'static str {
        match self {
            Self::DeviceSpecific => "device_specific",
            Self::Acpi => "acpi",
            Self::Flr => "flr",
            Self::AfFlr => "af_flr",
            Self::Pm => "pm",
            Self::Bus => "bus",
            Self::CxlBus => "cxl_bus",
        }
    }

    fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|method| method.name() == name)
    }
}

/// The name of a bound driver, the last component of the `driver` link.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct DriverName(String);

impl DriverName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DriverName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for DriverName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Which rule a value broke.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseError {
    /// `class` is not `0x`, six lowercase hexadecimal digits and a newline.
    Class,
    /// `boot_vga` is not `0` or `1` and a newline.
    BootVga,
    /// `reset_method` is not names separated by single spaces and ended by a newline.
    ResetMethods,
    /// `reset_method` names a method the kernel does not have.
    UnknownResetMethod,
    /// `reset_method` names one method twice.
    RepeatedResetMethod,
    /// `iommu_group` does not point to `kernel/iommu_groups/<group>`.
    GroupLink,
    /// `driver` does not point to `bus/pci/drivers/<name>`.
    DriverLink,
    /// The device link does not point to `devices/pciDDDD:BB/` and a chain of PCI
    /// addresses.
    DevicePath,
    /// The device link's chain ends at another device.
    DevicePathElsewhere,
    /// A device on the chain is in another domain than its root bus, or the first one is
    /// not on the root bus.
    DevicePathDomain,
    /// More than [`MAX_UPSTREAM_PORTS`] bridges.
    TooManyPorts,
    /// An entry of a group's `devices` directory is not a PCI address.
    GroupMember,
    /// A group's `devices` directory is empty.
    EmptyGroup,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Class => "the class is not 0x and six lowercase hexadecimal digits",
            Self::BootVga => "boot_vga is not 0 or 1",
            Self::ResetMethods => "reset_method is not a list of names separated by single spaces",
            Self::UnknownResetMethod => "reset_method names a method the kernel does not have",
            Self::RepeatedResetMethod => "reset_method names a method twice",
            Self::GroupLink => "iommu_group does not point to an IOMMU group",
            Self::DriverLink => "driver does not point to a PCI driver",
            Self::DevicePath => "the device link does not point into a PCI root bus",
            Self::DevicePathElsewhere => "the device link ends at another device",
            Self::DevicePathDomain => "the device link crosses into another domain or bus",
            Self::TooManyPorts => "the device link names too many bridges",
            Self::GroupMember => "an IOMMU group member is not a PCI address",
            Self::EmptyGroup => "the IOMMU group lists no device",
        })
    }
}

impl std::error::Error for ParseError {}

/// `class`: `0x` and six lowercase hexadecimal digits, then a newline.
pub fn parse_class(bytes: &[u8]) -> Result<PciClass, ParseError> {
    let text = line(bytes).ok_or(ParseError::Class)?;
    let digits = text.strip_prefix("0x").ok_or(ParseError::Class)?;
    let lowercase_hex = digits
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if digits.len() != 6 || !lowercase_hex {
        return Err(ParseError::Class);
    }
    u32::from_str_radix(digits, 16)
        .map(PciClass)
        .map_err(|_| ParseError::Class)
}

/// `boot_vga`: `0` or `1`, then a newline.
pub fn parse_boot_vga(bytes: &[u8]) -> Result<bool, ParseError> {
    match line(bytes) {
        Some("0") => Ok(false),
        Some("1") => Ok(true),
        _ => Err(ParseError::BootVga),
    }
}

/// `reset_method`: empty when every method was disabled, otherwise known names, each
/// once, separated by single spaces and ended by a newline.
pub fn parse_reset_methods(bytes: &[u8]) -> Result<Vec<ResetMethod>, ParseError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let text = line(bytes).ok_or(ParseError::ResetMethods)?;
    let mut methods = Vec::new();
    for name in text.split(' ') {
        if name.is_empty() {
            return Err(ParseError::ResetMethods);
        }
        let method = ResetMethod::named(name).ok_or(ParseError::UnknownResetMethod)?;
        if methods.contains(&method) {
            return Err(ParseError::RepeatedResetMethod);
        }
        methods.push(method);
    }
    Ok(methods)
}

/// `iommu_group`: one or more `..`, then `kernel/iommu_groups/<group>`.
pub fn parse_group_link(target: &str) -> Result<IommuGroup, ParseError> {
    match up_then(target).ok_or(ParseError::GroupLink)?.as_slice() {
        ["kernel", "iommu_groups", group] => {
            IommuGroup::parse(group).map_err(|_| ParseError::GroupLink)
        }
        _ => Err(ParseError::GroupLink),
    }
}

/// `driver`: one or more `..`, then `bus/pci/drivers/<name>`, the name made of ASCII
/// letters, digits, `_` and `-`.
pub fn parse_driver_link(target: &str) -> Result<DriverName, ParseError> {
    match up_then(target).ok_or(ParseError::DriverLink)?.as_slice() {
        ["bus", "pci", "drivers", name] => {
            let well_formed = !name.is_empty()
                && name.len() <= MAX_DRIVER_NAME_BYTES
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
            if well_formed {
                Ok(DriverName((*name).to_owned()))
            } else {
                Err(ParseError::DriverLink)
            }
        }
        _ => Err(ParseError::DriverLink),
    }
}

/// The device link `bus/pci/devices/<device>`: exactly `../../../devices/`, a root bus
/// `pciDDDD:BB`, then the PCI address of every bridge in order and `device` last. Returns
/// the bridges, the root bus's first. Every address is in the root bus's domain and the
/// first is on the root bus. A device under any other parent (a platform or virtual bus)
/// is refused.
pub fn parse_device_path(target: &str, device: PciAddress) -> Result<Vec<PciAddress>, ParseError> {
    let components: Vec<&str> = target.split('/').collect();
    let ["..", "..", "..", "devices", root, chain @ ..] = components.as_slice() else {
        return Err(ParseError::DevicePath);
    };
    let root = RootBus::parse(root).map_err(|_| ParseError::DevicePath)?;
    let addresses = chain
        .iter()
        .map(|name| PciAddress::parse(name).map_err(|_| ParseError::DevicePath))
        .collect::<Result<Vec<_>, _>>()?;
    let Some((last, ports)) = addresses.split_last() else {
        return Err(ParseError::DevicePath);
    };
    if *last != device {
        return Err(ParseError::DevicePathElsewhere);
    }
    if ports.len() > MAX_UPSTREAM_PORTS {
        return Err(ParseError::TooManyPorts);
    }
    let first_bus = addresses.first().map(|address| address.bus());
    if first_bus != Some(root.bus())
        || addresses
            .iter()
            .any(|address| address.domain() != root.domain())
    {
        return Err(ParseError::DevicePathDomain);
    }
    Ok(ports.to_vec())
}

/// The entries of `kernel/iommu_groups/<group>/devices`: one PCI address each, at least
/// one.
pub fn parse_group_members(names: &[String]) -> Result<BTreeSet<PciAddress>, ParseError> {
    let members = names
        .iter()
        .map(|name| PciAddress::parse(name).map_err(|_| ParseError::GroupMember))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if members.is_empty() {
        return Err(ParseError::EmptyGroup);
    }
    Ok(members)
}

/// The text of a one-line attribute: UTF-8 ended by exactly one newline, with no other
/// newline or carriage return.
fn line(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes).ok()?;
    let body = text.strip_suffix('\n')?;
    (!body.contains(['\n', '\r'])).then_some(body)
}

/// The components of a relative link target after its leading `..` steps: at least one
/// `..`, no empty component and no `.` or `..` after the first other component.
fn up_then(target: &str) -> Option<Vec<&str>> {
    let components: Vec<&str> = target.split('/').collect();
    let ups = components
        .iter()
        .take_while(|component| **component == "..")
        .count();
    let rest = &components[ups..];
    let well_formed = ups > 0
        && rest
            .iter()
            .all(|component| !component.is_empty() && *component != "." && *component != "..");
    well_formed.then(|| rest.to_vec())
}
