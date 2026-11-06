//! The four facts VM-CP-31 checks before a GPU is assigned (§17, line 3181: "IOMMU group
//! completeness, reset capability, host display ownership and ACS state are checked
//! before assignment; an incomplete group or a display-owning GPU is refused"; §7.5,
//! lines 2398–2407; VM-P39, line 2814), read from Linux sysfs through the port and judged
//! one guard at a time.
//!
//! Each guard ends in a [`Verdict`]: clear when the facts rule its hazard out, a
//! [`Hazard`] when they show it, undecided when a fact it needs is missing, unreadable
//! or malformed. A hazard a guard has shown stands even when another of its facts could
//! not be read; undecided is never clear. The guards, in this module's strict reading:
//!
//! - IOMMU group: the device has a group (`iommu_group`), the group lists it, and every
//!   member is one of its own functions (same domain, bus and device number). Any other
//!   member, a bridge included, makes the group incomplete for this device; a device
//!   without a group has no IOMMU translating its DMA.
//! - Host display and other users (§7.5, line 2402: "host display/other users of the
//!   device"): the device is not the firmware's boot display (`boot_vga`, which the
//!   kernel gives only VGA-compatible controllers), and neither it nor any of its own
//!   functions in its group is bound to a driver other than `vfio-pci`; an unbound
//!   function has no host user.
//! - Reset: `reset_method` lists at least one method the kernel has. An empty list (all
//!   methods disabled) shows the hazard; a missing attribute (a kernel before 5.15, or a
//!   device without any method) leaves it undecided.
//! - ACS: every bridge between the device and its root bus, read from its own
//!   configuration space, is a PCI Express port; every root port and switch downstream
//!   port, and a multifunction switch upstream port, has the ACS capability with Source
//!   Validation, Request Redirect, Completion Redirect and Upstream Forwarding on where
//!   it implements them; and at least one root or downstream port isolates the path. A
//!   conventional PCI or PCI-X bridge on the path shows the hazard. Kernel quirks that
//!   treat a port without the capability as isolated are not visible here and do not
//!   count.

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

use super::address::{IommuGroup, PciAddress};
use super::attributes::{
    parse_boot_vga, parse_class, parse_device_path, parse_driver_link, parse_group_link,
    parse_group_members, parse_reset_methods, DriverName, ParseError, PciClass,
};
use super::config::{parse_config, ConfigError, HeaderLayout, PortType, EXTENDED_CONFIG_BYTES};
use super::node::{Attribute, SysfsNode};
use super::reader::{ReadError, SysfsReader};
use crate::sandbox::backend::{GpuIsolation, GpuIsolationCheck};

/// The most bytes read from any attribute but `config`.
pub const MAX_ATTRIBUTE_BYTES: usize = 4096;

/// The one driver a function may be bound to while it waits for assignment.
pub const ASSIGNMENT_DRIVER: &str = "vfio-pci";

/// What one guard decided.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// The facts rule the hazard out.
    Clear,
    /// The facts show the hazard.
    Hazard { hazard: Hazard },
    /// A fact the guard needs is missing, unreadable or malformed.
    Undecided { problem: FactProblem },
}

impl Verdict {
    pub const fn is_clear(&self) -> bool {
        matches!(self, Self::Clear)
    }
}

/// A reason the device must not be assigned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "hazard", rename_all = "snake_case")]
pub enum Hazard {
    /// The device has no IOMMU group, so no IOMMU translates its DMA.
    NoIommuGroup,
    /// Its IOMMU group holds devices that are not its own functions.
    SharedGroup {
        group: IommuGroup,
        others: Vec<PciAddress>,
    },
    /// Firmware booted the host display on it.
    BootDisplay,
    /// A host driver holds one of its functions.
    HostDriver {
        function: PciAddress,
        driver: DriverName,
    },
    /// The kernel will use no reset method for it.
    NoResetMethod,
    /// No root or switch downstream port sits between it and its root bus.
    NoIsolatingPort,
    /// A port on its path has no ACS capability.
    NoAcs { port: PciAddress },
    /// A port on its path leaves these required ACS controls off.
    AcsControlsOff { port: PciAddress, missing: u16 },
    /// A bridge on its path is not a PCI Express port, so it carries no ACS.
    BridgeWithoutAcs { port: PciAddress },
}

impl fmt::Display for Hazard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoIommuGroup => f.write_str("the device has no IOMMU group"),
            Self::SharedGroup { group, others } => {
                write!(f, "IOMMU group {group} also holds")?;
                for other in others {
                    write!(f, " {other}")?;
                }
                Ok(())
            }
            Self::BootDisplay => f.write_str("firmware booted the host display on the device"),
            Self::HostDriver { function, driver } => {
                write!(f, "the host driver {driver} holds {function}")
            }
            Self::NoResetMethod => f.write_str("the kernel lists no reset method"),
            Self::NoIsolatingPort => {
                f.write_str("no root or downstream port isolates the device from its root bus")
            }
            Self::NoAcs { port } => write!(f, "port {port} has no ACS capability"),
            Self::AcsControlsOff { port, missing } => {
                write!(f, "port {port} leaves ACS controls {missing:#06x} off")
            }
            Self::BridgeWithoutAcs { port } => {
                write!(
                    f,
                    "bridge {port} is not a PCI Express port and carries no ACS"
                )
            }
        }
    }
}

/// A fact that could not be decided: the node it comes from and what was wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FactProblem {
    pub node: SysfsNode,
    pub problem: Problem,
}

impl fmt::Display for FactProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.node, self.problem)
    }
}

impl std::error::Error for FactProblem {}

/// What was wrong with a fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum Problem {
    Read {
        error: ReadError,
    },
    Parse {
        error: ParseError,
    },
    Config {
        error: ConfigError,
    },
    /// The device's group does not list it.
    NotInItsGroup,
    /// A device on the path to the root bus is not a bridge.
    NotABridge,
    /// A bridge on the path does not lead to the next device on it.
    PathBroken,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { error } => fmt::Display::fmt(error, f),
            Self::Parse { error } => fmt::Display::fmt(error, f),
            Self::Config { error } => fmt::Display::fmt(error, f),
            Self::NotInItsGroup => f.write_str("the IOMMU group does not list the device"),
            Self::NotABridge => f.write_str("a device on the path is not a bridge"),
            Self::PathBroken => f.write_str("the bridge does not lead to the next device"),
        }
    }
}

/// The four guards for one device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Assessment {
    pub device: PciAddress,
    pub group: Verdict,
    pub display: Verdict,
    pub reset: Verdict,
    pub acs: Verdict,
}

impl Assessment {
    /// Whether every guard is clear: the device's facts qualify it for assignment.
    pub const fn qualifies(&self) -> bool {
        self.group.is_clear()
            && self.display.is_clear()
            && self.reset.is_clear()
            && self.acs.is_clear()
    }

    /// The backend's §7.5 checks these guards show passing, as a GPU backend stamps them
    /// before assignment for its launch record (`sandbox::backend::GpuAssignmentOrder`,
    /// VM-CP-31): a clear group is the complete isolation group, a clear display guard no
    /// host display or other user, a clear reset guard safe reset, and a clear ACS guard
    /// no unsafe ACS state. A hazard or an undecided guard leaves its check out. The other
    /// §7.5 checks are not sysfs facts, and no unsafe setting is read here, so none is
    /// listed.
    pub fn checks_before_assignment(&self) -> GpuIsolation {
        let checks = [
            (&self.group, GpuIsolationCheck::CompleteIsolationGroup),
            (&self.display, GpuIsolationCheck::NoHostDisplayOrOtherUsers),
            (&self.reset, GpuIsolationCheck::SafeResetAndReassignment),
            (&self.acs, GpuIsolationCheck::NoUnsafeAcsOrIommuBypass),
        ];
        GpuIsolation {
            checks: checks
                .into_iter()
                .filter(|(verdict, _)| verdict.is_clear())
                .map(|(_, check)| check)
                .collect(),
            unsafe_settings: BTreeSet::new(),
        }
    }
}

/// Why a device could not be assessed at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "unassessable", rename_all = "snake_case")]
pub enum Unassessable {
    /// The host has no PCI device at this address.
    Absent { device: PciAddress },
    /// The device is not a display controller.
    NotAGpu { device: PciAddress, class: PciClass },
}

impl fmt::Display for Unassessable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent { device } => write!(f, "the host has no PCI device {device}"),
            Self::NotAGpu { device, class } => {
                write!(f, "{device} is not a display controller (class {class})")
            }
        }
    }
}

impl std::error::Error for Unassessable {}

/// Reads and judges the four facts of the GPU at `device`. A device the host does not
/// have, or one that is not a display controller, is not assessed.
pub fn assess<R: SysfsReader + ?Sized>(
    reader: &R,
    device: PciAddress,
) -> Result<Assessment, Unassessable> {
    let class_node = SysfsNode::attribute(device, Attribute::Class);
    let class = match reader.read(&class_node, MAX_ATTRIBUTE_BYTES) {
        Err(ReadError::Missing) => return Err(Unassessable::Absent { device }),
        Err(error) => Err(problem(class_node, Problem::Read { error })),
        Ok(bytes) => {
            parse_class(&bytes).map_err(|error| problem(class_node, Problem::Parse { error }))
        }
    };
    if let Ok(class) = class {
        if !class.is_display() {
            return Err(Unassessable::NotAGpu { device, class });
        }
    }
    let group = read_group(reader, device);
    Ok(Assessment {
        device,
        group: group_verdict(device, &group),
        display: display_verdict(reader, device, &class, &group),
        reset: reset_verdict(reader, device),
        acs: acs_verdict(reader, device),
    })
}

/// The device's IOMMU group as sysfs shows it.
enum GroupRead {
    /// No `iommu_group` link: the device has no group.
    NoGroup,
    Members {
        group: IommuGroup,
        members: BTreeSet<PciAddress>,
    },
}

/// Who holds a function.
enum Binding {
    Unbound,
    Assignment,
    Host(DriverName),
}

const fn problem(node: SysfsNode, problem: Problem) -> FactProblem {
    FactProblem { node, problem }
}

const fn undecided(node: SysfsNode, what: Problem) -> Verdict {
    Verdict::Undecided {
        problem: problem(node, what),
    }
}

const fn hazard(hazard: Hazard) -> Verdict {
    Verdict::Hazard { hazard }
}

fn read_group<R: SysfsReader + ?Sized>(
    reader: &R,
    device: PciAddress,
) -> Result<GroupRead, FactProblem> {
    let link = SysfsNode::attribute(device, Attribute::IommuGroup);
    let target = match reader.link(&link) {
        Err(ReadError::Missing) => return Ok(GroupRead::NoGroup),
        Err(error) => return Err(problem(link, Problem::Read { error })),
        Ok(target) => target,
    };
    let group =
        parse_group_link(&target).map_err(|error| problem(link, Problem::Parse { error }))?;
    let listing = SysfsNode::GroupDevices { group };
    let names = reader
        .list(&listing)
        .map_err(|error| problem(listing, Problem::Read { error }))?;
    let members =
        parse_group_members(&names).map_err(|error| problem(listing, Problem::Parse { error }))?;
    if !members.contains(&device) {
        return Err(problem(listing, Problem::NotInItsGroup));
    }
    Ok(GroupRead::Members { group, members })
}

fn group_verdict(device: PciAddress, group: &Result<GroupRead, FactProblem>) -> Verdict {
    match group {
        Err(problem) => Verdict::Undecided { problem: *problem },
        Ok(GroupRead::NoGroup) => hazard(Hazard::NoIommuGroup),
        Ok(GroupRead::Members { group, members }) => {
            let others: Vec<PciAddress> = members
                .iter()
                .copied()
                .filter(|member| !device.same_device(*member))
                .collect();
            if others.is_empty() {
                Verdict::Clear
            } else {
                hazard(Hazard::SharedGroup {
                    group: *group,
                    others,
                })
            }
        }
    }
}

fn display_verdict<R: SysfsReader + ?Sized>(
    reader: &R,
    device: PciAddress,
    class: &Result<PciClass, FactProblem>,
    group: &Result<GroupRead, FactProblem>,
) -> Verdict {
    // A device whose class cannot be read is not shown to be a GPU at all.
    let mut first_undecided = class.as_ref().err().copied();
    let boot = SysfsNode::attribute(device, Attribute::BootVga);
    match reader.read(&boot, MAX_ATTRIBUTE_BYTES) {
        Ok(bytes) => match parse_boot_vga(&bytes) {
            Ok(true) => return hazard(Hazard::BootDisplay),
            Ok(false) => {}
            Err(error) => {
                first_undecided.get_or_insert(problem(boot, Problem::Parse { error }));
            }
        },
        // The kernel gives `boot_vga` only to VGA-compatible controllers.
        Err(ReadError::Missing) => match class {
            Ok(class) if !class.is_vga() => {}
            Ok(_) => {
                first_undecided.get_or_insert(problem(
                    boot,
                    Problem::Read {
                        error: ReadError::Missing,
                    },
                ));
            }
            Err(_) => {}
        },
        Err(error) => {
            first_undecided.get_or_insert(problem(boot, Problem::Read { error }));
        }
    }
    let mut functions = vec![device];
    match group {
        Ok(GroupRead::Members { members, .. }) => functions.extend(
            members
                .iter()
                .copied()
                .filter(|member| *member != device && device.same_device(*member)),
        ),
        // Without a group, the device's other functions are not known.
        Ok(GroupRead::NoGroup) => {
            first_undecided.get_or_insert(problem(
                SysfsNode::attribute(device, Attribute::IommuGroup),
                Problem::Read {
                    error: ReadError::Missing,
                },
            ));
        }
        Err(problem) => {
            first_undecided.get_or_insert(*problem);
        }
    }
    for function in functions {
        match binding(reader, function) {
            Ok(Binding::Host(driver)) => return hazard(Hazard::HostDriver { function, driver }),
            Ok(Binding::Unbound | Binding::Assignment) => {}
            Err(problem) => {
                first_undecided.get_or_insert(problem);
            }
        }
    }
    match first_undecided {
        Some(problem) => Verdict::Undecided { problem },
        None => Verdict::Clear,
    }
}

fn binding<R: SysfsReader + ?Sized>(
    reader: &R,
    function: PciAddress,
) -> Result<Binding, FactProblem> {
    let node = SysfsNode::attribute(function, Attribute::Driver);
    match reader.link(&node) {
        Err(ReadError::Missing) => Ok(Binding::Unbound),
        Err(error) => Err(problem(node, Problem::Read { error })),
        Ok(target) => {
            let driver = parse_driver_link(&target)
                .map_err(|error| problem(node, Problem::Parse { error }))?;
            Ok(if driver.as_str() == ASSIGNMENT_DRIVER {
                Binding::Assignment
            } else {
                Binding::Host(driver)
            })
        }
    }
}

fn reset_verdict<R: SysfsReader + ?Sized>(reader: &R, device: PciAddress) -> Verdict {
    let node = SysfsNode::attribute(device, Attribute::ResetMethod);
    match reader.read(&node, MAX_ATTRIBUTE_BYTES) {
        Err(error) => undecided(node, Problem::Read { error }),
        Ok(bytes) => match parse_reset_methods(&bytes) {
            Ok(methods) if methods.is_empty() => hazard(Hazard::NoResetMethod),
            Ok(_) => Verdict::Clear,
            Err(error) => undecided(node, Problem::Parse { error }),
        },
    }
}

/// What one bridge on the path contributes.
enum PortVerdict {
    /// A root or downstream port with the required ACS controls on.
    Isolates,
    /// A bridge that needs no ACS of its own (a single-function switch upstream port) or
    /// a multifunction upstream port with them on.
    Passes,
    Hazard(Hazard),
    Undecided(FactProblem),
}

fn acs_verdict<R: SysfsReader + ?Sized>(reader: &R, device: PciAddress) -> Verdict {
    let node = SysfsNode::Device { address: device };
    let target = match reader.link(&node) {
        Ok(target) => target,
        Err(error) => return undecided(node, Problem::Read { error }),
    };
    let ports = match parse_device_path(&target, device) {
        Ok(ports) => ports,
        Err(error) => return undecided(node, Problem::Parse { error }),
    };
    let mut first_undecided = None;
    let mut isolated = false;
    for (index, port) in ports.iter().copied().enumerate() {
        let below = ports.get(index + 1).copied().unwrap_or(device);
        match port_verdict(reader, port, below) {
            PortVerdict::Isolates => isolated = true,
            PortVerdict::Passes => {}
            PortVerdict::Hazard(found) => return hazard(found),
            PortVerdict::Undecided(problem) => {
                first_undecided.get_or_insert(problem);
            }
        }
    }
    match first_undecided {
        Some(problem) => Verdict::Undecided { problem },
        None if isolated => Verdict::Clear,
        None => hazard(Hazard::NoIsolatingPort),
    }
}

/// Judges the bridge `port`, whose secondary bus must be the bus of `below`, the next
/// device on the path.
fn port_verdict<R: SysfsReader + ?Sized>(
    reader: &R,
    port: PciAddress,
    below: PciAddress,
) -> PortVerdict {
    let node = SysfsNode::attribute(port, Attribute::Config);
    let space = match reader
        .read(&node, EXTENDED_CONFIG_BYTES)
        .map_err(|error| Problem::Read { error })
        .and_then(|bytes| parse_config(&bytes).map_err(|error| Problem::Config { error }))
    {
        Ok(space) => space,
        Err(what) => return PortVerdict::Undecided(problem(node, what)),
    };
    match space.layout {
        HeaderLayout::Bridge => {}
        HeaderLayout::CardBus => return PortVerdict::Hazard(Hazard::BridgeWithoutAcs { port }),
        HeaderLayout::Function => {
            return PortVerdict::Undecided(problem(node, Problem::NotABridge))
        }
    }
    if space.secondary_bus != Some(below.bus()) {
        return PortVerdict::Undecided(problem(node, Problem::PathBroken));
    }
    let (needs_acs, role) = match space.express {
        None | Some(PortType::PcieToPciBridge | PortType::PciToPcieBridge) => {
            return PortVerdict::Hazard(Hazard::BridgeWithoutAcs { port })
        }
        Some(PortType::RootPort | PortType::DownstreamPort) => (true, PortVerdict::Isolates),
        Some(PortType::UpstreamPort) => (space.multifunction, PortVerdict::Passes),
        Some(_) => return PortVerdict::Undecided(problem(node, Problem::NotABridge)),
    };
    if !needs_acs {
        return role;
    }
    match space.acs {
        None => PortVerdict::Hazard(Hazard::NoAcs { port }),
        Some(acs) if acs.missing_controls() != 0 => PortVerdict::Hazard(Hazard::AcsControlsOff {
            port,
            missing: acs.missing_controls(),
        }),
        Some(_) => role,
    }
}
