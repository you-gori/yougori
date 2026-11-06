//! PCI function addresses, root buses and IOMMU groups exactly as Linux names them in
//! sysfs (§7.5, lines 2396–2409: Cloud Hypervisor assigns a device by its PCI sysfs
//! path). Each parser accepts only the kernel's own spelling: a value parses when it
//! prints back to the same text.

use std::fmt;

use serde::{Serialize, Serializer};

/// The highest device number on a PCI bus.
pub const MAX_DEVICE: u8 = 0x1f;

/// The highest function number of a PCI device.
pub const MAX_FUNCTION: u8 = 7;

/// The most hexadecimal digits of a PCI domain (a 32-bit number).
const MAX_DOMAIN_DIGITS: usize = 8;

/// One PCI function as sysfs names it, `DDDD:BB:DD.F`: the domain in at least four
/// lowercase hexadecimal digits (more above `0xffff`, as for VMD domains), the bus and
/// device in two each and the function as one decimal digit (Linux
/// `pci_setup_device`: `"%04x:%02x:%02x.%d"`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PciAddress {
    domain: u32,
    bus: u8,
    device: u8,
    function: u8,
}

impl PciAddress {
    /// The function `function` of device `device` on bus `bus` of domain `domain`.
    pub const fn new(domain: u32, bus: u8, device: u8, function: u8) -> Result<Self, AddressError> {
        if device > MAX_DEVICE {
            return Err(AddressError::DeviceOutOfRange);
        }
        if function > MAX_FUNCTION {
            return Err(AddressError::FunctionOutOfRange);
        }
        Ok(Self {
            domain,
            bus,
            device,
            function,
        })
    }

    /// Parses the kernel's spelling of an address; any other spelling is refused.
    pub fn parse(text: &str) -> Result<Self, AddressError> {
        let mut parts = text.split(':');
        let (Some(domain), Some(bus), Some(slot), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(AddressError::Malformed);
        };
        let Some((device, function)) = slot.split_once('.') else {
            return Err(AddressError::Malformed);
        };
        if !function.bytes().all(|byte| byte.is_ascii_digit()) || function.len() != 1 {
            return Err(AddressError::Malformed);
        }
        let address = Self::new(
            hex(domain, MAX_DOMAIN_DIGITS)?,
            narrow(hex(bus, 2)?)?,
            narrow(hex(device, 2)?)?,
            narrow(hex(function, 1)?)?,
        )?;
        canonical(address, text)
    }

    pub const fn domain(self) -> u32 {
        self.domain
    }

    pub const fn bus(self) -> u8 {
        self.bus
    }

    pub const fn device(self) -> u8 {
        self.device
    }

    pub const fn function(self) -> u8 {
        self.function
    }

    /// Whether `other` is a function of the same physical device: the same domain, bus
    /// and device number. An ARI function above 7 has another device number and is
    /// therefore not counted as one of this device's functions.
    pub const fn same_device(self, other: Self) -> bool {
        self.domain == other.domain && self.bus == other.bus && self.device == other.device
    }
}

impl fmt::Display for PciAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04x}:{:02x}:{:02x}.{}",
            self.domain, self.bus, self.device, self.function
        )
    }
}

impl fmt::Debug for PciAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for PciAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// A PCI root bus as sysfs names its directory under `/sys/devices`: `pciDDDD:BB`
/// (Linux `pci_register_host_bridge`: `"pci%04x:%02x"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RootBus {
    domain: u32,
    bus: u8,
}

impl RootBus {
    /// Parses the kernel's spelling of a root bus; any other spelling is refused.
    pub fn parse(text: &str) -> Result<Self, AddressError> {
        let Some(rest) = text.strip_prefix("pci") else {
            return Err(AddressError::Malformed);
        };
        let Some((domain, bus)) = rest.split_once(':') else {
            return Err(AddressError::Malformed);
        };
        let root = Self {
            domain: hex(domain, MAX_DOMAIN_DIGITS)?,
            bus: narrow(hex(bus, 2)?)?,
        };
        canonical(root, text)
    }

    pub const fn domain(self) -> u32 {
        self.domain
    }

    pub const fn bus(self) -> u8 {
        self.bus
    }
}

impl fmt::Display for RootBus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pci{:04x}:{:02x}", self.domain, self.bus)
    }
}

/// An IOMMU group number, the name of a directory under `/sys/kernel/iommu_groups`, in
/// decimal without leading zeros.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IommuGroup(u32);

impl IommuGroup {
    pub const fn new(number: u32) -> Self {
        Self(number)
    }

    /// Parses a group directory name; any other spelling is refused.
    pub fn parse(text: &str) -> Result<Self, AddressError> {
        if text.is_empty() || text.len() > 10 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(AddressError::Malformed);
        }
        let number = text.parse::<u32>().map_err(|_| AddressError::Malformed)?;
        canonical(Self(number), text)
    }

    pub const fn number(self) -> u32 {
        self.0
    }
}

impl fmt::Display for IommuGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for IommuGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for IommuGroup {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(self.0)
    }
}

/// Why a name is not a PCI address, root bus or IOMMU group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressError {
    /// It does not have the parts and digits the kernel writes.
    Malformed,
    /// It parses, but the kernel would write it differently (case, padding, signs).
    NotCanonical,
    /// The device number is above 0x1f.
    DeviceOutOfRange,
    /// The function number is above 7.
    FunctionOutOfRange,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "the name does not have the parts and digits the kernel writes",
            Self::NotCanonical => "the name is not spelled as the kernel spells it",
            Self::DeviceOutOfRange => "the device number is above 0x1f",
            Self::FunctionOutOfRange => "the function number is above 7",
        })
    }
}

impl std::error::Error for AddressError {}

/// Lowercase hexadecimal digits only, at most `max_digits` of them.
fn hex(text: &str, max_digits: usize) -> Result<u32, AddressError> {
    let digits = text
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if text.is_empty() || text.len() > max_digits || !digits {
        return Err(AddressError::Malformed);
    }
    u32::from_str_radix(text, 16).map_err(|_| AddressError::Malformed)
}

fn narrow(value: u32) -> Result<u8, AddressError> {
    u8::try_from(value).map_err(|_| AddressError::Malformed)
}

/// `value` when it prints back exactly as `text`.
fn canonical<T: fmt::Display>(value: T, text: &str) -> Result<T, AddressError> {
    if value.to_string() == text {
        Ok(value)
    } else {
        Err(AddressError::NotCanonical)
    }
}
