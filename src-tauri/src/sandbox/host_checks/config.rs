//! A strict reader of the PCI configuration space the host reports in a bridge's
//! `config` file: its header layout, its PCI Express port type and its ACS capability
//! (§7.5, line 2407: "lack of unsafe ACS/IOMMU bypass settings"; VM-R26, line 2891: no
//! ACS workaround qualifies as equivalent isolation).
//!
//! The ACS registers are read from the hardware's own capability, so a kernel option that
//! makes the kernel treat a port as isolated without changing the port is not mistaken
//! for ACS. Every pointer is bounds-checked and every capability walk is bounded as the
//! kernel bounds it; a space too short for what it declares is refused as truncated, as
//! is the 64-byte view an unprivileged reader gets.

use std::fmt;

use serde::Serialize;

/// The standard header every function has.
pub const HEADER_BYTES: usize = 64;

/// The conventional configuration space, where the capability list lives.
pub const CONFIG_BYTES: usize = 256;

/// The PCI Express extended configuration space, where ACS lives.
pub const EXTENDED_CONFIG_BYTES: usize = 4096;

/// ACS Source Validation.
pub const ACS_SOURCE_VALIDATION: u16 = 0x0001;
/// ACS Translation Blocking.
pub const ACS_TRANSLATION_BLOCKING: u16 = 0x0002;
/// ACS P2P Request Redirect.
pub const ACS_REQUEST_REDIRECT: u16 = 0x0004;
/// ACS P2P Completion Redirect.
pub const ACS_COMPLETION_REDIRECT: u16 = 0x0008;
/// ACS Upstream Forwarding.
pub const ACS_UPSTREAM_FORWARDING: u16 = 0x0010;

/// The controls a port must have on for isolation, as Linux requires them for IOMMU
/// groups (`REQ_ACS_FLAGS`).
pub const ACS_REQUIRED: u16 = ACS_SOURCE_VALIDATION
    | ACS_REQUEST_REDIRECT
    | ACS_COMPLETION_REDIRECT
    | ACS_UPSTREAM_FORWARDING;

const VENDOR_ABSENT: u16 = 0xffff;
const STATUS: usize = 0x06;
const STATUS_CAPABILITIES: u8 = 0x10;
const HEADER_TYPE: usize = 0x0e;
const MULTIFUNCTION: u8 = 0x80;
const SECONDARY_BUS: usize = 0x19;
const CAPABILITY_POINTER: usize = 0x34;
const CARDBUS_CAPABILITY_POINTER: usize = 0x14;
const EXPRESS_CAPABILITY: u8 = 0x10;
const ACS_EXTENDED_CAPABILITY: u16 = 0x000d;
/// The ACS capability's header, Capability and Control registers.
const ACS_REGISTERS_END: usize = 8;
/// Linux `PCI_FIND_CAP_TTL`.
const MAX_CAPABILITIES: usize = 48;
/// Linux bounds the extended walk to `(4096 - 256) / 8` steps.
const MAX_EXTENDED_CAPABILITIES: usize = (EXTENDED_CONFIG_BYTES - CONFIG_BYTES) / 8;

/// The layout of the configuration header (header type bits 0–6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderLayout {
    /// Type 0: a function that is not a bridge.
    Function,
    /// Type 1: a PCI-to-PCI bridge, which includes every PCI Express port.
    Bridge,
    /// Type 2: a CardBus bridge.
    CardBus,
}

/// The PCI Express device or port type (PCI Express Capabilities register, bits 4–7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum PortType {
    Endpoint,
    LegacyEndpoint,
    RootPort,
    /// A switch's upstream port.
    UpstreamPort,
    /// A switch's downstream port.
    DownstreamPort,
    /// A PCI Express to PCI or PCI-X bridge.
    PcieToPciBridge,
    /// A PCI or PCI-X to PCI Express bridge.
    PciToPcieBridge,
    IntegratedEndpoint,
    EventCollector,
    Reserved(u8),
}

impl PortType {
    const fn of(value: u8) -> Self {
        match value {
            0x0 => Self::Endpoint,
            0x1 => Self::LegacyEndpoint,
            0x4 => Self::RootPort,
            0x5 => Self::UpstreamPort,
            0x6 => Self::DownstreamPort,
            0x7 => Self::PcieToPciBridge,
            0x8 => Self::PciToPcieBridge,
            0x9 => Self::IntegratedEndpoint,
            0xa => Self::EventCollector,
            other => Self::Reserved(other),
        }
    }
}

/// The ACS Capability and Control registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct AcsRegisters {
    pub capability: u16,
    pub control: u16,
}

impl AcsRegisters {
    /// The required controls the port implements and has off. A required control the
    /// capability does not list is fixed on by the port (Linux `pci_acs_flags_enabled`).
    pub const fn missing_controls(self) -> u16 {
        ACS_REQUIRED & self.capability & !self.control
    }
}

/// What a configuration space shows about one function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ConfigSpace {
    pub layout: HeaderLayout,
    pub multifunction: bool,
    /// The bus directly below a PCI-to-PCI bridge; `None` for any other layout.
    pub secondary_bus: Option<u8>,
    /// The PCI Express capability's port type; `None` for a conventional function.
    pub express: Option<PortType>,
    /// The ACS extended capability, the first one; `None` when it has none.
    pub acs: Option<AcsRegisters>,
}

/// Why a configuration space could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "config", rename_all = "snake_case")]
pub enum ConfigError {
    /// Shorter than what it declares needs: `needed` bytes.
    Truncated { length: usize, needed: usize },
    /// Longer than a PCI Express configuration space.
    TooLong { length: usize },
    /// The vendor id reads all ones: no function answered.
    NoFunction,
    /// The header type is not 0, 1 or 2.
    UnknownLayout,
    /// A capability pointer points into the header or past the space.
    BadPointer { offset: usize },
    /// A capability list does not end within the kernel's bound.
    CapabilityLoop,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { length, needed } => write!(
                f,
                "the configuration space has {length} bytes and needs {needed}; a full read needs a privileged reader"
            ),
            Self::TooLong { length } => {
                write!(f, "the configuration space has {length} bytes, more than 4096")
            }
            Self::NoFunction => f.write_str("no function answered (the vendor id reads all ones)"),
            Self::UnknownLayout => f.write_str("the header type is not one PCI defines"),
            Self::BadPointer { offset } => {
                write!(f, "a capability pointer at {offset:#x} points outside the space")
            }
            Self::CapabilityLoop => f.write_str("a capability list does not end"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Parses a configuration space as the `config` file returns it.
pub fn parse_config(bytes: &[u8]) -> Result<ConfigSpace, ConfigError> {
    if bytes.len() > EXTENDED_CONFIG_BYTES {
        return Err(ConfigError::TooLong {
            length: bytes.len(),
        });
    }
    need(bytes, HEADER_BYTES)?;
    if word(bytes, 0)? == VENDOR_ABSENT {
        return Err(ConfigError::NoFunction);
    }
    let header = byte(bytes, HEADER_TYPE)?;
    let layout = match header & !MULTIFUNCTION {
        0 => HeaderLayout::Function,
        1 => HeaderLayout::Bridge,
        2 => HeaderLayout::CardBus,
        _ => return Err(ConfigError::UnknownLayout),
    };
    let secondary_bus = match layout {
        HeaderLayout::Bridge => Some(byte(bytes, SECONDARY_BUS)?),
        HeaderLayout::Function | HeaderLayout::CardBus => None,
    };
    let mut space = ConfigSpace {
        layout,
        multifunction: header & MULTIFUNCTION != 0,
        secondary_bus,
        express: None,
        acs: None,
    };
    if byte(bytes, STATUS)? & STATUS_CAPABILITIES == 0 {
        return Ok(space);
    }
    need(bytes, CONFIG_BYTES)?;
    let pointer = match layout {
        HeaderLayout::CardBus => CARDBUS_CAPABILITY_POINTER,
        HeaderLayout::Function | HeaderLayout::Bridge => CAPABILITY_POINTER,
    };
    let Some(express) = find_capability(bytes, pointer, EXPRESS_CAPABILITY)? else {
        return Ok(space);
    };
    space.express = Some(PortType::of((byte(bytes, express + 2)? >> 4) & 0x0f));
    need(bytes, EXTENDED_CONFIG_BYTES)?;
    if let Some(acs) = find_extended_capability(bytes, ACS_EXTENDED_CAPABILITY)? {
        if acs + ACS_REGISTERS_END > EXTENDED_CONFIG_BYTES {
            return Err(ConfigError::BadPointer { offset: acs });
        }
        space.acs = Some(AcsRegisters {
            capability: word(bytes, acs + 4)?,
            control: word(bytes, acs + 6)?,
        });
    }
    Ok(space)
}

/// The offset of the first standard capability `id`, walking from the pointer at
/// `pointer`.
fn find_capability(bytes: &[u8], pointer: usize, id: u8) -> Result<Option<usize>, ConfigError> {
    let mut at = usize::from(byte(bytes, pointer)? & 0xfc);
    for _ in 0..MAX_CAPABILITIES {
        if at == 0 {
            return Ok(None);
        }
        if !(HEADER_BYTES..CONFIG_BYTES - 1).contains(&at) {
            return Err(ConfigError::BadPointer { offset: at });
        }
        if byte(bytes, at)? == id {
            return Ok(Some(at));
        }
        at = usize::from(byte(bytes, at + 1)? & 0xfc);
    }
    Err(ConfigError::CapabilityLoop)
}

/// The offset of the first extended capability `id`, walking from 0x100. A header of all
/// zeros or all ones ends the list.
fn find_extended_capability(bytes: &[u8], id: u16) -> Result<Option<usize>, ConfigError> {
    let mut at = CONFIG_BYTES;
    for _ in 0..MAX_EXTENDED_CAPABILITIES {
        let header = dword(bytes, at)?;
        if header == 0 || header == u32::MAX {
            return Ok(None);
        }
        if header & 0xffff == u32::from(id) {
            return Ok(Some(at));
        }
        let next = usize::try_from((header >> 20) & 0xffc)
            .map_err(|_| ConfigError::BadPointer { offset: at })?;
        if next == 0 {
            return Ok(None);
        }
        if !(CONFIG_BYTES..EXTENDED_CONFIG_BYTES - 3).contains(&next) {
            return Err(ConfigError::BadPointer { offset: next });
        }
        at = next;
    }
    Err(ConfigError::CapabilityLoop)
}

fn need(bytes: &[u8], needed: usize) -> Result<(), ConfigError> {
    if bytes.len() < needed {
        Err(ConfigError::Truncated {
            length: bytes.len(),
            needed,
        })
    } else {
        Ok(())
    }
}

fn byte(bytes: &[u8], at: usize) -> Result<u8, ConfigError> {
    bytes.get(at).copied().ok_or(ConfigError::Truncated {
        length: bytes.len(),
        needed: at + 1,
    })
}

fn word(bytes: &[u8], at: usize) -> Result<u16, ConfigError> {
    Ok(u16::from_le_bytes([byte(bytes, at)?, byte(bytes, at + 1)?]))
}

fn dword(bytes: &[u8], at: usize) -> Result<u32, ConfigError> {
    Ok(u32::from_le_bytes([
        byte(bytes, at)?,
        byte(bytes, at + 1)?,
        byte(bytes, at + 2)?,
        byte(bytes, at + 3)?,
    ]))
}
