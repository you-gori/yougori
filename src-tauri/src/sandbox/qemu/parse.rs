//! Reading an observed QEMU argument vector, as the host's process listing shows it,
//! strictly back into the typed profile (VM-CP-01, line 3151: no hypervisor runs with a
//! TCG argument; VM-CP-03, line 3153: no 9p, virtiofs or HGFS device, no QMP or HMP TCP
//! listener, QMP socket in a private directory, no host port forward to the old agent
//! port; VM-CP-33, line 3183; VM-P03, line 2778: no undeclared host filesystem,
//! clipboard, USB, agent socket or management endpoint).
//!
//! Every argument is classified; the dangerous classes get their own typed finding, and
//! a TCG argument anywhere is found by a scan of every argument before anything else.
//! The per-launch values are then read, the profile they make is rendered, and the
//! observed vector must equal that rendering exactly: whatever a typed finding did not
//! already name shows as an unexpected, missing or changed argument. HGFS is VMware's
//! share device; QEMU has none, so it can only appear as an unknown argument here.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use super::argv::{compare, is_positional, split_items, ArgumentDifference, ObservedArgv, Pair};
use super::argv::{FLAG_OPTIONS, VALUE_OPTIONS};
use super::platform::{hypervisor_named, platform_of, Machine};
use super::profile::{ProfileParts, QemuProfile};
use super::values::{
    GuestCid, GuestResources, HostPath, InstanceName, KernelArguments, PrivateDirectory, MIB_BYTES,
    QMP_SOCKET_NAME,
};

/// The guest port of the old in-guest agent that today's microVMs forward a host port
/// to (`hostfwd=tcp:127.0.0.1:<port>-:7443` in runtime/vm.rs).
pub const OLD_AGENT_GUEST_PORT: u16 = 7443;

/// A host filesystem share.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareKind {
    NineP,
    Virtiofs,
    /// A host directory presented as a FAT disk.
    Vvfat,
    /// The user-mode network's SMB export of a host directory.
    Smb,
}

/// A management interface of QEMU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagementInterface {
    Qmp,
    Hmp,
}

/// One reason an observed vector is not a profile's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "finding", rename_all = "snake_case")]
pub enum ArgvFinding {
    /// An argument names TCG: no sandbox runs in emulation (VM-W22, line 2621).
    TcgAccelerator {
        argument: String,
    },
    /// An accelerator chosen other than by one `-accel`: a second `-accel`, a machine
    /// `accel=` list or `-enable-kvm`. QEMU would fall back along such a list.
    AcceleratorSelection {
        argument: String,
    },
    UnsupportedAccelerator {
        argument: String,
    },
    ShareDevice {
        kind: ShareKind,
        argument: String,
    },
    /// QMP or HMP on a TCP, UDP, telnet or websocket listener.
    ManagementListener {
        interface: ManagementInterface,
        argument: String,
    },
    ForwardToOldAgentPort {
        argument: String,
    },
    NetworkDevice {
        argument: String,
    },
    /// A character device on a network socket.
    NetworkChardev {
        argument: String,
    },
    UsbDevice {
        argument: String,
    },
    DisplayDevice {
        argument: String,
    },
    ConsoleDevice {
        argument: String,
    },
    ClipboardChannel {
        argument: String,
    },
    BalloonDevice {
        argument: String,
    },
    PciTransport {
        argument: String,
    },
    HostDeviceAssignment {
        argument: String,
    },
    DebugInterface {
        argument: String,
    },
    /// A named pipe QEMU creates itself, so not an endpoint the host created.
    PipeEndpoint {
        argument: String,
    },
    /// Secret material written into the arguments, which any host process can read
    /// (§3.2 line 2075). Only the option is named, never its value.
    SecretInArguments {
        option: String,
    },
    /// The Linux profile without QEMU's seccomp sandbox.
    SandboxMissing,
    SandboxWeakened {
        argument: String,
    },
    MissingOption {
        option: String,
    },
    InvalidValue {
        argument: String,
        reason: String,
    },
    UnknownOption {
        argument: String,
    },
    /// An argument where an option belongs, which QEMU reads as a disk image.
    PositionalArgument {
        argument: String,
    },
    /// The vector differs from the profile its values make, or from the launch.
    NotThisProfile {
        difference: ArgumentDifference,
    },
    /// The profile's arguments in another order; QEMU applies some options in order.
    Reordered,
}

impl fmt::Display for ArgvFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TcgAccelerator { argument } => {
                write!(f, "`{argument}` names TCG emulation")
            }
            Self::AcceleratorSelection { argument } => write!(
                f,
                "`{argument}` selects an accelerator other than by one -accel"
            ),
            Self::UnsupportedAccelerator { argument } => {
                write!(
                    f,
                    "`{argument}` is not a hardware accelerator this profile uses"
                )
            }
            Self::ShareDevice { kind, argument } => {
                write!(f, "`{argument}` shares a host filesystem ({kind:?})")
            }
            Self::ManagementListener {
                interface,
                argument,
            } => write!(f, "`{argument}` puts {interface:?} on a network listener"),
            Self::ForwardToOldAgentPort { argument } => write!(
                f,
                "`{argument}` forwards a host port to the old agent port {OLD_AGENT_GUEST_PORT}"
            ),
            Self::NetworkDevice { argument } => write!(f, "`{argument}` is a network device"),
            Self::NetworkChardev { argument } => {
                write!(f, "`{argument}` is a character device on a network socket")
            }
            Self::UsbDevice { argument } => write!(f, "`{argument}` adds USB"),
            Self::DisplayDevice { argument } => write!(f, "`{argument}` adds a display"),
            Self::ConsoleDevice { argument } => write!(f, "`{argument}` adds a console"),
            Self::ClipboardChannel { argument } => {
                write!(f, "`{argument}` shares the clipboard")
            }
            Self::BalloonDevice { argument } => write!(f, "`{argument}` adds a balloon"),
            Self::PciTransport { argument } => write!(f, "`{argument}` adds PCI"),
            Self::HostDeviceAssignment { argument } => {
                write!(f, "`{argument}` passes a host device through")
            }
            Self::DebugInterface { argument } => {
                write!(f, "`{argument}` opens a debug interface")
            }
            Self::PipeEndpoint { argument } => write!(
                f,
                "`{argument}` uses a named pipe QEMU creates, not a host-created socket"
            ),
            Self::SecretInArguments { option } => {
                write!(f, "{option} carries secret material in the arguments")
            }
            Self::SandboxMissing => f.write_str("QEMU's seccomp sandbox is not enabled"),
            Self::SandboxWeakened { argument } => {
                write!(f, "`{argument}` weakens QEMU's seccomp sandbox")
            }
            Self::MissingOption { option } => write!(f, "{option} is missing"),
            Self::InvalidValue { argument, reason } => {
                write!(f, "`{argument}` is invalid: {reason}")
            }
            Self::UnknownOption { argument } => write!(f, "`{argument}` is not in the profile"),
            Self::PositionalArgument { argument } => {
                write!(f, "`{argument}` would be read as a disk image")
            }
            Self::NotThisProfile { difference } => write!(f, "{difference}"),
            Self::Reordered => f.write_str("the profile's arguments appear in another order"),
        }
    }
}

/// Why an observed vector is not a profile's: every finding, in argument order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ArgvRefusal {
    findings: Vec<ArgvFinding>,
}

impl ArgvRefusal {
    pub fn findings(&self) -> &[ArgvFinding] {
        &self.findings
    }

    /// Whether any argument names TCG (VM-CP-01).
    pub fn names_tcg(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| matches!(finding, ArgvFinding::TcgAccelerator { .. }))
    }
}

impl fmt::Display for ArgvRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the hypervisor's arguments are not the profile's ({} finding{})",
            self.findings.len(),
            if self.findings.len() == 1 { "" } else { "s" }
        )?;
        for (index, finding) in self.findings.iter().enumerate() {
            f.write_str(if index == 0 { ": " } else { "; " })?;
            write!(f, "{finding}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ArgvRefusal {}

/// Reads an observed vector into the profile it is, or refuses with every finding.
pub fn parse_observed(observed: &ObservedArgv) -> Result<QemuProfile, ArgvRefusal> {
    let pairs = observed.pairs();
    let mut findings = tcg_scan(observed.arguments());
    let mut flagged = BTreeSet::new();
    let monitors = monitor_chardevs(&pairs);
    let accelerators = pairs
        .iter()
        .filter(|pair| pair.normalized_option() == "-accel")
        .count();
    for (index, pair) in pairs.iter().enumerate() {
        let allowed_internet = (pair.normalized_option() == "-netdev" && pair.value.as_deref() == Some(super::profile::INTERNET_BACKEND))
            || (pair.normalized_option() == "-device" && pair.value.as_deref() == Some(super::profile::INTERNET_DEVICE))
            // This fixed public mode flag is not bootstrap secret material. Every
            // other inline fw_cfg string remains forbidden.
            || (pair.normalized_option() == "-fw_cfg" && pair.value.as_deref() == Some(super::profile::INTERNET_BOOT_MODE));
        let mut found = if allowed_internet { Vec::new() } else { classify(pair, &monitors) };
        let later_accelerator = pair.normalized_option() == "-accel"
            && accelerators > 1
            && index > first_index(&pairs, "-accel");
        if later_accelerator {
            found.push(ArgvFinding::AcceleratorSelection {
                argument: pair.text(),
            });
        }
        if !found.is_empty() {
            flagged.insert(index);
            findings.extend(found);
        }
    }
    match extract(&pairs) {
        Err(more) => findings.extend(more),
        Ok(profile) => {
            let sandbox_missing = profile.fixed().seccomp_sandbox().is_some()
                && !pairs
                    .iter()
                    .any(|pair| pair.normalized_option() == "-sandbox");
            if sandbox_missing {
                findings.push(ArgvFinding::SandboxMissing);
            }
            let unflagged: Vec<Pair> = pairs
                .iter()
                .enumerate()
                .filter(|(index, _)| !flagged.contains(index))
                .map(|(_, pair)| pair.clone())
                .collect();
            let (differences, reordered) = compare(&profile.pairs(), &unflagged);
            findings.extend(
                differences
                    .into_iter()
                    .filter(|difference| {
                        !(sandbox_missing
                            && matches!(difference, ArgumentDifference::Missing { argument }
                                if argument.starts_with("-sandbox ")))
                    })
                    .map(|difference| ArgvFinding::NotThisProfile { difference }),
            );
            if reordered {
                findings.push(ArgvFinding::Reordered);
            }
            if findings.is_empty() {
                return Ok(profile);
            }
        }
    }
    Err(ArgvRefusal { findings })
}

/// Checks an observed process against the profile it was launched from: it must read
/// back into exactly that profile, so the QMP socket is the one in this launch's private
/// directory and every path is this launch's.
pub fn check_observed(observed: &ObservedArgv, launch: &QemuProfile) -> Result<(), ArgvRefusal> {
    let profile = parse_observed(observed)?;
    if &profile == launch {
        return Ok(());
    }
    let (differences, _) = compare(&launch.pairs(), &observed.pairs());
    let mut findings: Vec<ArgvFinding> = differences
        .into_iter()
        .map(|difference| ArgvFinding::NotThisProfile { difference })
        .collect();
    if findings.is_empty() {
        findings.push(ArgvFinding::InvalidValue {
            argument: "profile".into(),
            reason: "the process runs another profile than the launch".into(),
        });
    }
    Err(ArgvRefusal { findings })
}

fn first_index(pairs: &[Pair], option: &str) -> usize {
    pairs
        .iter()
        .position(|pair| pair.normalized_option() == option)
        .unwrap_or(usize::MAX)
}

/// Every argument with a `tcg` word, split at commas, equals signs, colons and spaces.
fn tcg_scan(arguments: &[String]) -> Vec<ArgvFinding> {
    arguments
        .iter()
        .filter(|argument| {
            argument
                .split([',', '=', ':', ' '])
                .any(|word| word.eq_ignore_ascii_case("tcg"))
        })
        .map(|argument| ArgvFinding::TcgAccelerator {
            argument: argument.clone(),
        })
        .collect()
}

/// The chardev ids monitors use, with the interface each one carries.
fn monitor_chardevs(pairs: &[Pair]) -> BTreeMap<String, ManagementInterface> {
    pairs
        .iter()
        .filter(|pair| pair.normalized_option() == "-mon")
        .filter_map(|pair| {
            let items = split_items(pair.value.as_deref()?);
            let chardev = item(&items, "chardev")?.to_owned();
            let interface = match item(&items, "mode") {
                Some("control") => ManagementInterface::Qmp,
                _ => ManagementInterface::Hmp,
            };
            Some((chardev, interface))
        })
        .collect()
}

fn item<'a>(items: &'a [(Option<String>, String)], key: &str) -> Option<&'a str> {
    items
        .iter()
        .find(|(name, _)| name.as_deref() == Some(key))
        .map(|(_, value)| value.as_str())
}

fn implied(items: &[(Option<String>, String)]) -> Option<&str> {
    match items.first() {
        Some((None, value)) => Some(value.as_str()),
        _ => None,
    }
}

/// Whether a legacy character device spec (`-qmp`, `-monitor`, `-serial`) listens on
/// the network.
fn network_spec(spec: &str) -> bool {
    let backend = spec.split(':').next().unwrap_or(spec);
    matches!(backend, "tcp" | "telnet" | "websocket" | "udp")
}

fn classify(pair: &Pair, monitors: &BTreeMap<String, ManagementInterface>) -> Vec<ArgvFinding> {
    let argument = pair.text();
    if is_positional(&pair.option) {
        return vec![ArgvFinding::PositionalArgument { argument }];
    }
    let option = pair.normalized_option();
    let value = pair.value.as_deref().unwrap_or("");
    let items = split_items(value);
    let lower = |text: &str| text.to_ascii_lowercase();
    let mut found = Vec::new();
    match option.as_str() {
        "-accel" => {
            let name = implied(&items).map(lower).unwrap_or_default();
            if hypervisor_named(&name).is_none() && name != "tcg" {
                found.push(ArgvFinding::UnsupportedAccelerator { argument });
            }
        }
        "-enable-kvm" => found.push(ArgvFinding::AcceleratorSelection { argument }),
        "-machine" => {
            if item(&items, "accel").is_some() {
                found.push(ArgvFinding::AcceleratorSelection {
                    argument: argument.clone(),
                });
            }
            let machine = implied(&items)
                .or_else(|| item(&items, "type"))
                .unwrap_or("");
            let on = |key: &str| item(&items, key).is_some_and(|value| value != "off");
            if matches!(machine, "pc" | "q35" | "isapc") || machine.starts_with("pc-") || on("pcie")
            {
                found.push(ArgvFinding::PciTransport {
                    argument: argument.clone(),
                });
            }
            if on("usb") {
                found.push(ArgvFinding::UsbDevice {
                    argument: argument.clone(),
                });
            }
            if on("graphics") {
                found.push(ArgvFinding::DisplayDevice {
                    argument: argument.clone(),
                });
            }
            if on("isa-serial") {
                found.push(ArgvFinding::ConsoleDevice { argument });
            }
        }
        "-device" => {
            let driver = implied(&items)
                .or_else(|| item(&items, "driver"))
                .map(lower)
                .unwrap_or_default();
            if let Some(finding) = device_finding(&driver, argument) {
                found.push(finding);
            }
        }
        "-netdev" | "-nic" | "-net" => {
            if implied(&items) != Some("none") {
                for (key, text) in &items {
                    match key.as_deref() {
                        Some("hostfwd") if forwards_to_old_agent(text) => {
                            found.push(ArgvFinding::ForwardToOldAgentPort {
                                argument: argument.clone(),
                            })
                        }
                        Some("smb") => found.push(ArgvFinding::ShareDevice {
                            kind: ShareKind::Smb,
                            argument: argument.clone(),
                        }),
                        _ => {}
                    }
                }
                found.push(ArgvFinding::NetworkDevice { argument });
            }
        }
        "-fsdev" | "-virtfs" => found.push(ArgvFinding::ShareDevice {
            kind: ShareKind::NineP,
            argument,
        }),
        "-drive" | "-hda" | "-hdb" | "-hdc" | "-hdd" | "-cdrom" | "-fda" | "-fdb" | "-sd"
        | "-mtdblock" | "-pflash" => {
            if value.contains("fat:") || item(&items, "driver") == Some("vvfat") {
                found.push(ArgvFinding::ShareDevice {
                    kind: ShareKind::Vvfat,
                    argument,
                });
            }
        }
        "-blockdev" => match item(&items, "driver").unwrap_or("") {
            "vvfat" => found.push(ArgvFinding::ShareDevice {
                kind: ShareKind::Vvfat,
                argument,
            }),
            "nbd" | "http" | "https" | "ftp" | "ftps" | "ssh" | "iscsi" | "gluster" | "rbd"
            | "nfs" => found.push(ArgvFinding::NetworkDevice { argument }),
            "host_device" | "host_cdrom" | "nvme" => {
                found.push(ArgvFinding::HostDeviceAssignment { argument })
            }
            _ => {}
        },
        "-qmp" | "-qmp-pretty" | "-monitor" => {
            let interface = if option == "-monitor" {
                ManagementInterface::Hmp
            } else {
                ManagementInterface::Qmp
            };
            if network_spec(value) {
                found.push(ArgvFinding::ManagementListener {
                    interface,
                    argument,
                });
            } else if value.starts_with("pipe:") {
                found.push(ArgvFinding::PipeEndpoint { argument });
            }
        }
        "-chardev" => {
            let backend = implied(&items)
                .or_else(|| item(&items, "backend"))
                .unwrap_or("");
            let network = backend == "udp"
                || (backend == "socket"
                    && (item(&items, "host").is_some() || item(&items, "port").is_some()));
            let id = item(&items, "id").unwrap_or("");
            if network {
                match monitors.get(id) {
                    Some(interface) => found.push(ArgvFinding::ManagementListener {
                        interface: *interface,
                        argument,
                    }),
                    None => found.push(ArgvFinding::NetworkChardev { argument }),
                }
            } else if backend == "pipe" {
                found.push(ArgvFinding::PipeEndpoint { argument });
            } else if matches!(backend, "qemu-vdagent" | "spicevmc" | "spiceport") {
                found.push(ArgvFinding::ClipboardChannel { argument });
            }
        }
        "-fw_cfg" if item(&items, "string").is_some() => {
            found.push(ArgvFinding::SecretInArguments {
                option: option.clone(),
            })
        }
        "-object"
            if implied(&items) == Some("secret") || item(&items, "qom-type") == Some("secret") =>
        {
            found.push(ArgvFinding::SecretInArguments {
                option: option.clone(),
            })
        }
        "-serial" | "-parallel" | "-debugcon" => {
            if value != "none" {
                found.push(ArgvFinding::ConsoleDevice { argument });
            }
        }
        "-nographic" => found.push(ArgvFinding::ConsoleDevice { argument }),
        "-display" => {
            if implied(&items) != Some("none") {
                found.push(ArgvFinding::DisplayDevice { argument });
            }
        }
        "-vga" => {
            if value != "none" {
                found.push(ArgvFinding::DisplayDevice { argument });
            }
        }
        "-vnc" | "-spice" => found.push(ArgvFinding::DisplayDevice { argument }),
        "-usb" | "-usbdevice" => found.push(ArgvFinding::UsbDevice { argument }),
        "-gdb" | "-s" => found.push(ArgvFinding::DebugInterface { argument }),
        "-sandbox" => {
            let required = ["obsolete", "elevateprivileges", "spawn", "resourcecontrol"];
            let weakened = implied(&items) != Some("on")
                || required.iter().any(|key| item(&items, key) != Some("deny"));
            if weakened {
                found.push(ArgvFinding::SandboxWeakened { argument });
            }
        }
        name if !VALUE_OPTIONS.contains(&name) && !FLAG_OPTIONS.contains(&name) => {
            found.push(ArgvFinding::UnknownOption { argument })
        }
        _ => {}
    }
    found
}

/// Whether a `hostfwd` rule (`[tcp|udp]:[addr]:port-[addr]:port`) targets the old agent
/// port in the guest.
fn forwards_to_old_agent(rule: &str) -> bool {
    rule.split_once('-')
        .and_then(|(_, guest)| guest.rsplit(':').next())
        .and_then(|port| port.parse::<u16>().ok())
        == Some(OLD_AGENT_GUEST_PORT)
}

fn device_finding(driver: &str, argument: String) -> Option<ArgvFinding> {
    let network = driver.starts_with("virtio-net")
        || driver.starts_with("e1000")
        || driver.starts_with("rtl8139")
        || driver.starts_with("ne2k")
        || driver.starts_with("i825")
        || driver.starts_with("pcnet")
        || driver.starts_with("vmxnet")
        || matches!(driver, "igb" | "tulip" | "usb-net");
    let usb = driver.starts_with("usb-")
        || ["xhci", "ehci", "ohci", "uhci"]
            .iter()
            .any(|controller| driver.contains(controller));
    let display = driver.contains("vga")
        || driver.starts_with("virtio-gpu")
        || matches!(driver, "ramfb" | "bochs-display" | "qxl");
    let console = matches!(
        driver,
        "virtconsole"
            | "isa-serial"
            | "isa-debugcon"
            | "isa-parallel"
            | "pci-serial"
            | "pci-serial-2x"
            | "pci-serial-4x"
    );
    let pci = driver.ends_with("-pci")
        || driver.contains("-pci-")
        || driver.starts_with("pcie-")
        || matches!(driver, "pci-bridge" | "pxb" | "pxb-pcie" | "ioh3420");
    if driver.starts_with("virtio-9p") {
        Some(ArgvFinding::ShareDevice {
            kind: ShareKind::NineP,
            argument,
        })
    } else if driver.starts_with("vhost-user-fs") || driver.contains("virtiofs") {
        Some(ArgvFinding::ShareDevice {
            kind: ShareKind::Virtiofs,
            argument,
        })
    } else if driver.starts_with("vfio") {
        Some(ArgvFinding::HostDeviceAssignment { argument })
    } else if driver.contains("balloon") {
        Some(ArgvFinding::BalloonDevice { argument })
    } else if network {
        Some(ArgvFinding::NetworkDevice { argument })
    } else if usb {
        Some(ArgvFinding::UsbDevice { argument })
    } else if display {
        Some(ArgvFinding::DisplayDevice { argument })
    } else if console {
        Some(ArgvFinding::ConsoleDevice { argument })
    } else if pci {
        Some(ArgvFinding::PciTransport { argument })
    } else {
        None
    }
}

/// Reads the per-launch values and assembles the profile they make.
fn extract(pairs: &[Pair]) -> Result<QemuProfile, Vec<ArgvFinding>> {
    let mut findings = Vec::new();
    let find = |option: &str| pairs.iter().find(|pair| pair.normalized_option() == option);
    let mut required = |option: &str| -> Option<&Pair> {
        let found = find(option);
        if found.is_none() {
            findings.push(ArgvFinding::MissingOption {
                option: option.to_owned(),
            });
        }
        found
    };
    let accel = required("-accel");
    let machine = required("-machine");
    let name = required("-name");
    let smp = required("-smp");
    let memory = required("-m");
    let firmware = required("-L");
    let kernel = required("-kernel");
    let append = required("-append");
    let initrd = find("-initrd");
    let (
        Some(accel),
        Some(machine),
        Some(name),
        Some(smp),
        Some(memory),
        Some(firmware),
        Some(kernel),
        Some(append),
    ) = (accel, machine, name, smp, memory, firmware, kernel, append)
    else {
        return Err(findings);
    };
    let invalid = |pair: &Pair, reason: String| ArgvFinding::InvalidValue {
        argument: pair.text(),
        reason,
    };
    let value = |pair: &Pair| pair.value.clone().unwrap_or_default();
    let accel_items = split_items(&value(accel));
    let Some(hypervisor) = implied(&accel_items).and_then(hypervisor_named) else {
        findings.push(invalid(
            accel,
            "no hardware accelerator this profile uses".into(),
        ));
        return Err(findings);
    };
    let machine_items = split_items(&value(machine));
    let machine_type = match implied(&machine_items) {
        Some("microvm") => Machine::Microvm,
        Some("virt") => Machine::Virt,
        _ => {
            findings.push(invalid(
                machine,
                "the machine is neither microvm nor virt".into(),
            ));
            return Err(findings);
        }
    };
    let Some(platform) = platform_of(hypervisor, machine_type) else {
        findings.push(invalid(
            accel,
            "no QEMU platform uses this accelerator".into(),
        ));
        return Err(findings);
    };
    let fixed = match platform.profile() {
        Ok(fixed) => fixed,
        Err(refusal) => {
            findings.push(invalid(machine, refusal.to_string()));
            return Err(findings);
        }
    };
    let style = fixed.path_style;
    let path = |pair: &Pair, text: &str, findings: &mut Vec<ArgvFinding>| {
        HostPath::new(style, text)
            .map_err(|error| findings.push(invalid(pair, error.to_string())))
            .ok()
    };
    let name = InstanceName::parse(&value(name))
        .map_err(|error| findings.push(invalid(name, error.to_string())))
        .ok();
    let smp_items = split_items(&value(smp));
    let vcpus = item(&smp_items, "cpus").and_then(|count| count.parse::<u16>().ok());
    let memory_mib = value(memory)
        .strip_suffix('M')
        .and_then(|count| count.parse::<u64>().ok());
    let resources = match (vcpus, memory_mib.and_then(|mib| mib.checked_mul(MIB_BYTES))) {
        (Some(vcpus), Some(bytes)) => GuestResources::new(vcpus, bytes)
            .map_err(|error| findings.push(invalid(memory, error.to_string())))
            .ok(),
        (None, _) => {
            findings.push(invalid(smp, "no vCPU count".into()));
            None
        }
        (_, None) => {
            findings.push(invalid(memory, "not a size in MiB".into()));
            None
        }
    };
    let firmware_directory = path(firmware, &value(firmware), &mut findings);
    let kernel_path = path(kernel, &value(kernel), &mut findings);
    let initrd = match initrd {
        Some(pair) => match path(pair, &value(pair), &mut findings) {
            Some(path) => Some(Some(path)),
            None => None,
        },
        None => Some(None),
    };
    let kernel_arguments = KernelArguments::parse(&value(append))
        .map_err(|error| findings.push(invalid(append, error.to_string())))
        .ok();
    let blockdev = |node: &str| {
        pairs.iter().find_map(|pair| {
            if pair.normalized_option() != "-blockdev" {
                return None;
            }
            let items = split_items(pair.value.as_deref()?);
            (item(&items, "node-name") == Some(node))
                .then(|| item(&items, "filename").map(|file| (pair, file.to_owned())))
                .flatten()
        })
    };
    let root_image = match blockdev("root-file") {
        Some((pair, file)) => path(pair, &file, &mut findings),
        None => {
            findings.push(ArgvFinding::MissingOption {
                option: "-blockdev node-name=root-file".into(),
            });
            None
        }
    };
    let mut volumes = Vec::new();
    while let Some((pair, file)) = blockdev(&format!("vol{}-file", volumes.len())) {
        match path(pair, &file, &mut findings) {
            Some(volume) => volumes.push(volume),
            None => break,
        }
    }
    let qmp = pairs.iter().find_map(|pair| {
        if pair.normalized_option() != "-chardev" {
            return None;
        }
        let items = split_items(pair.value.as_deref()?);
        (item(&items, "id") == Some("qmp")).then(|| (pair, item(&items, "path").map(str::to_owned)))
    });
    let control = match qmp {
        Some((pair, Some(socket))) => {
            path(pair, &socket, &mut findings).and_then(|socket| match socket.split_last() {
                Some((directory, QMP_SOCKET_NAME)) => PrivateDirectory::new(directory)
                    .map_err(|error| findings.push(invalid(pair, error.to_string())))
                    .ok(),
                _ => {
                    findings.push(invalid(
                        pair,
                        format!("the QMP socket is not {QMP_SOCKET_NAME} in a private directory"),
                    ));
                    None
                }
            })
        }
        Some((pair, None)) => {
            findings.push(invalid(pair, "QMP is not on a socket path".into()));
            None
        }
        None => {
            findings.push(ArgvFinding::MissingOption {
                option: "-chardev id=qmp".into(),
            });
            None
        }
    };
    let cid = pairs.iter().find_map(|pair| {
        if pair.normalized_option() != "-device" {
            return None;
        }
        let items = split_items(pair.value.as_deref()?);
        (implied(&items) == Some("vhost-vsock-device"))
            .then(|| (pair, item(&items, "guest-cid").map(str::to_owned)))
    });
    let cid = match cid {
        None => Some(None),
        Some((pair, text)) => match text.and_then(|text| text.parse::<u32>().ok()) {
            Some(number) => GuestCid::new(number)
                .map_err(|error| findings.push(invalid(pair, error.to_string())))
                .ok()
                .map(Some),
            None => {
                findings.push(invalid(pair, "no guest context id".into()));
                None
            }
        },
    };
    let (
        Some(name),
        Some(resources),
        Some(firmware_directory),
        Some(kernel),
        Some(initrd),
        Some(kernel_arguments),
        Some(root_image),
        Some(control),
        Some(cid),
    ) = (
        name,
        resources,
        firmware_directory,
        kernel_path,
        initrd,
        kernel_arguments,
        root_image,
        control,
        cid,
    )
    else {
        return Err(findings);
    };
    if !findings.is_empty() {
        return Err(findings);
    }
    QemuProfile::assemble(ProfileParts {
        internet: pairs.iter().any(|p| p.normalized_option() == "-netdev" && p.value.as_deref() == Some(super::profile::INTERNET_BACKEND)),
        platform,
        name,
        resources,
        firmware_directory,
        kernel,
        initrd,
        kernel_arguments,
        root_image,
        volumes,
        control,
        cid,
    })
    .map_err(|refusal| {
        vec![ArgvFinding::InvalidValue {
            argument: "profile".into(),
            reason: refusal.to_string(),
        }]
    })
}
