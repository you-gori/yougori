//! Which hosts the QEMU profile runs on and what each host fixes: the hardware
//! accelerator (WHPX on Windows, KVM on Linux, HVF on macOS; never TCG), the machine
//! type, the CPU model, the link channel and the confinement controls the profile and
//! its launcher apply (VM-W19 row, line 2618; §7.2 line 2374; §7.3 lines 2378–2386;
//! VM-CP-01, line 3151).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::values::PathStyle;
use crate::foundation::evidence::{HypervisorKind, OsKind};
use crate::sandbox::backend::{Architecture, ConfinementControl};
use crate::sandbox::trust::SandboxBackend;

/// A host OS and CPU architecture. The guest runs the host's architecture: a guest of
/// another architecture needs emulation, which no sandbox uses (§7.3 line 2386).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct QemuPlatform {
    pub os: OsKind,
    pub architecture: Architecture,
}

impl fmt::Display for QemuPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} on {}", self.os, self.architecture.tag())
    }
}

/// The two profiles VM-W19 names (line 2618), and QEMU on macOS from §19 (line 3224).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    /// The current QEMU/WHPX path, hardened: the Windows fallback under VM-D2 (line 3196).
    HardenedWhpx,
    /// The minimal compatible QEMU Linux profile on KVM, a compatibility option beside
    /// Firecracker (§7.2 line 2374).
    MinimalLinuxKvm,
    /// QEMU on Hypervisor.framework, rebuilt as `qemu-secure` (§19 line 3224).
    HardenedHvf,
}

impl ProfileKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::HardenedWhpx => "hardened_whpx",
            Self::MinimalLinuxKvm => "minimal_linux_kvm",
            Self::HardenedHvf => "hardened_hvf",
        }
    }
}

impl fmt::Display for ProfileKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HardenedWhpx => "hardened QEMU/WHPX profile",
            Self::MinimalLinuxKvm => "minimal compatible QEMU Linux profile",
            Self::HardenedHvf => "QEMU/HVF profile",
        })
    }
}

/// The QEMU machine type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Machine {
    /// The x86 microvm board: no PCI, virtio-mmio devices only.
    Microvm,
    /// The Arm virt board, with virtio-mmio devices only. The x86 microvm board is never
    /// an Arm strategy (§7.3 line 2384).
    Virt,
}

impl Machine {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Microvm => "microvm",
            Self::Virt => "virt",
        }
    }

    pub const fn architecture(self) -> Architecture {
        match self {
            Self::Microvm => Architecture::X86_64,
            Self::Virt => Architecture::Aarch64,
        }
    }
}

/// How the guest reaches the host's link endpoint (§3.2 line 2061: a supported
/// point-to-point transport per backend): vsock where the host kernel offers
/// vhost-vsock, a dedicated virtio-serial port elsewhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    VirtioSerial,
    Vsock,
}

/// Why no QEMU profile exists for a host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum PlatformRefusal {
    /// WSL2 shares one kernel among its distributions; it is never a sandbox host and
    /// never a fallback (§7.3 line 2386; VM-D4).
    SharedKernel,
    /// QEMU's WHPX accelerator drives x86 guests only, and emulating x86 is refused.
    WhpxNotOnArchitecture { architecture: Architecture },
    /// No machine type both runs on HVF and has no PCI transport on Intel Macs: the
    /// microvm board's interrupt and timer devices are not assumed to work with HVF (as
    /// the current launcher records), and q35 brings PCI (VM-CP-02, line 3152).
    NoMinimalMachineOnIntelMac,
}

impl fmt::Display for PlatformRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SharedKernel => f.write_str(
                "WSL2 shares one kernel and is never a sandbox host; use a hardware VM on the \
                 Windows host or a remote VM",
            ),
            Self::WhpxNotOnArchitecture { architecture } => write!(
                f,
                "QEMU's WHPX accelerator does not run {} guests, and emulation is refused",
                architecture.tag()
            ),
            Self::NoMinimalMachineOnIntelMac => {
                f.write_str("no machine type without PCI is known to work with HVF on Intel Macs")
            }
        }
    }
}

impl std::error::Error for PlatformRefusal {}

/// The fixed choices of one host's profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct PlatformProfile {
    pub platform: QemuPlatform,
    pub kind: ProfileKind,
    /// The one hardware accelerator; QEMU is never given a list to fall back along.
    pub hypervisor: HypervisorKind,
    pub machine: Machine,
    pub link: LinkKind,
    pub path_style: PathStyle,
}

impl QemuPlatform {
    /// The profile of this host, or why there is none. The accelerator per OS is the one
    /// the pinned-configuration matrix records for `qemu-secure`.
    pub fn profile(self) -> Result<PlatformProfile, PlatformRefusal> {
        let hypervisor = SandboxBackend::QemuSecure
            .hypervisor_on(self.os)
            .ok_or(PlatformRefusal::SharedKernel)?;
        let path_style = PathStyle::of(self.os).ok_or(PlatformRefusal::SharedKernel)?;
        let (kind, machine, link) = match (self.os, self.architecture) {
            (OsKind::Windows, Architecture::X86_64) => (
                ProfileKind::HardenedWhpx,
                Machine::Microvm,
                LinkKind::VirtioSerial,
            ),
            (OsKind::Windows, architecture) => {
                return Err(PlatformRefusal::WhpxNotOnArchitecture { architecture })
            }
            // The pinned guest speaks its link over virtio-serial, as on Windows.
            (OsKind::Linux, Architecture::X86_64) => (
                ProfileKind::MinimalLinuxKvm,
                Machine::Microvm,
                LinkKind::VirtioSerial,
            ),
            (OsKind::Linux, Architecture::Aarch64) => {
                (ProfileKind::MinimalLinuxKvm, Machine::Virt, LinkKind::Vsock)
            }
            (OsKind::MacOs, Architecture::Aarch64) => (
                ProfileKind::HardenedHvf,
                Machine::Virt,
                LinkKind::VirtioSerial,
            ),
            (OsKind::MacOs, Architecture::X86_64) => {
                return Err(PlatformRefusal::NoMinimalMachineOnIntelMac)
            }
            (OsKind::Wsl2, _) => return Err(PlatformRefusal::SharedKernel),
        };
        Ok(PlatformProfile {
            platform: self,
            kind,
            hypervisor,
            machine,
            link,
            path_style,
        })
    }
}

impl PlatformProfile {
    /// The `-machine` options after the type, in order. Every PCI, USB, graphics and
    /// serial facility the board offers is off (VM-CP-02, line 3152). ACPI is on for
    /// microvm because the guest kernel finds fw_cfg, and with it the link secret, through
    /// ACPI; the legacy PIC, PIT and RTC stay on under KVM and HVF for hosts without
    /// TSC-deadline timers and stay off under WHPX, as the current launcher sets them.
    pub fn machine_options(&self) -> Vec<(&'static str, &'static str)> {
        match self.machine {
            Machine::Microvm => {
                let legacy = if self.hypervisor == HypervisorKind::Whpx {
                    "off"
                } else {
                    "on"
                };
                vec![
                    ("acpi", "on"),
                    ("pcie", "off"),
                    ("usb", "off"),
                    ("graphics", "off"),
                    ("isa-serial", "off"),
                    ("pic", legacy),
                    ("pit", legacy),
                    ("rtc", legacy),
                ]
            }
            // Direct kernel boot on virt finds fw_cfg in the device tree; no EL3 or EL2 is
            // emulated for the guest.
            Machine::Virt => vec![
                ("acpi", "off"),
                ("secure", "off"),
                ("virtualization", "off"),
                ("graphics", "off"),
            ],
        }
    }

    /// The `-accel` options after the accelerator. WHPX leaves interrupt-controller
    /// emulation to QEMU, as the current launcher does.
    pub fn accelerator_options(&self) -> Vec<(&'static str, &'static str)> {
        match self.hypervisor {
            HypervisorKind::Whpx => vec![("kernel-irqchip", "off")],
            _ => Vec::new(),
        }
    }

    /// The `-cpu` model with nested virtualization masked (§3.4 line 2095). WHPX cannot
    /// pass the host CPU through, so it takes `max`.
    pub fn cpu_model(&self) -> &'static str {
        match (self.machine, self.hypervisor) {
            (Machine::Virt, _) => "host",
            (Machine::Microvm, HypervisorKind::Whpx) => "max,vmx=off,svm=off",
            (Machine::Microvm, _) => "host,vmx=off,svm=off",
        }
    }

    /// The `-sandbox` setting: QEMU's seccomp filter, Linux only, with every optional
    /// denial on. An unsupported QEMU fails to start rather than dropping the filter.
    pub fn seccomp_sandbox(&self) -> Option<&'static [(&'static str, &'static str)]> {
        match self.platform.os {
            OsKind::Linux => Some(&[
                ("obsolete", "deny"),
                ("elevateprivileges", "deny"),
                ("spawn", "deny"),
                ("resourcecontrol", "deny"),
            ]),
            _ => None,
        }
    }

    /// The confinement controls this profile's argument vector and launcher data apply
    /// to the hypervisor process (§1.3 line 1900; §3.4 line 2101). On Windows the
    /// restricted low-integrity token and the Job ([`WindowsHostRestrictions`]) give a
    /// restricted process identity, filesystem limits (no write up), OS restrictions and
    /// resource controls, but no separate account and no syscall filter. On Linux the
    /// host's start ([`LinuxHostRestrictions`]) gives an account of its own, no new
    /// privileges and no capability, a network namespace of its own, a cgroup with its
    /// limits, and QEMU's seccomp filter; no filesystem limits (that needs a mount or
    /// Landlock profile). On macOS the helper's profile belongs to VM-W21. A control not
    /// listed is refused, never assumed.
    ///
    /// [`WindowsHostRestrictions`]: super::WindowsHostRestrictions
    /// [`LinuxHostRestrictions`]: super::LinuxHostRestrictions
    pub fn confinement_applied(&self) -> BTreeSet<ConfinementControl> {
        match self.platform.os {
            OsKind::Windows => [
                ConfinementControl::ProcessIdentity,
                ConfinementControl::FilesystemLimits,
                ConfinementControl::OsRestrictions,
                ConfinementControl::ResourceControls,
            ]
            .into_iter()
            .collect(),
            OsKind::Linux => super::LINUX_CONTROLS.into_iter().collect(),
            OsKind::MacOs | OsKind::Wsl2 => BTreeSet::new(),
        }
    }
}

/// The platform an accelerator and machine type imply, for reading an observed argument
/// vector back.
pub(super) fn platform_of(hypervisor: HypervisorKind, machine: Machine) -> Option<QemuPlatform> {
    let os = match hypervisor {
        HypervisorKind::Whpx => OsKind::Windows,
        HypervisorKind::Kvm => OsKind::Linux,
        HypervisorKind::Hvf => OsKind::MacOs,
        HypervisorKind::Hcs | HypervisorKind::Vz => return None,
    };
    Some(QemuPlatform {
        os,
        architecture: machine.architecture(),
    })
}

/// The accelerator a `-accel` name selects, if it is one this profile can use.
pub(super) fn hypervisor_named(name: &str) -> Option<HypervisorKind> {
    match name {
        "whpx" => Some(HypervisorKind::Whpx),
        "kvm" => Some(HypervisorKind::Kvm),
        "hvf" => Some(HypervisorKind::Hvf),
        _ => None,
    }
}

/// The QEMU accelerator name of a hypervisor this profile uses.
pub(super) fn accelerator_name(hypervisor: HypervisorKind) -> &'static str {
    hypervisor.tag()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn platform(os: OsKind, architecture: Architecture) -> QemuPlatform {
        QemuPlatform { os, architecture }
    }

    #[test]
    fn each_os_has_its_one_hardware_accelerator_and_never_tcg() {
        let windows = platform(OsKind::Windows, Architecture::X86_64)
            .profile()
            .unwrap();
        assert_eq!(windows.hypervisor, HypervisorKind::Whpx);
        assert_eq!(windows.kind, ProfileKind::HardenedWhpx);
        assert_eq!(windows.machine, Machine::Microvm);
        assert_eq!(windows.link, LinkKind::VirtioSerial);
        let linux = platform(OsKind::Linux, Architecture::X86_64)
            .profile()
            .unwrap();
        assert_eq!(linux.hypervisor, HypervisorKind::Kvm);
        assert_eq!(linux.kind, ProfileKind::MinimalLinuxKvm);
        assert_eq!(linux.link, LinkKind::VirtioSerial);
        let arm_linux = platform(OsKind::Linux, Architecture::Aarch64)
            .profile()
            .unwrap();
        assert_eq!(arm_linux.link, LinkKind::Vsock);
        let mac = platform(OsKind::MacOs, Architecture::Aarch64)
            .profile()
            .unwrap();
        assert_eq!(mac.hypervisor, HypervisorKind::Hvf);
        assert_eq!(mac.machine, Machine::Virt);
        for os in [OsKind::Windows, OsKind::Linux, OsKind::MacOs, OsKind::Wsl2] {
            for architecture in [Architecture::X86_64, Architecture::Aarch64] {
                if let Ok(profile) = platform(os, architecture).profile() {
                    assert!(profile.hypervisor.tag() != "tcg");
                    assert!(hypervisor_named(accelerator_name(profile.hypervisor)).is_some());
                    assert_eq!(
                        platform_of(profile.hypervisor, profile.machine),
                        Some(profile.platform)
                    );
                    assert!(!profile.cpu_model().contains("tcg"));
                }
            }
        }
        assert_eq!(hypervisor_named("tcg"), None);
        assert_eq!(hypervisor_named("tcg,thread=multi"), None);
    }

    #[test]
    fn unsupported_hosts_are_refused_by_reason() {
        for architecture in [Architecture::X86_64, Architecture::Aarch64] {
            assert_eq!(
                platform(OsKind::Wsl2, architecture).profile(),
                Err(PlatformRefusal::SharedKernel)
            );
        }
        assert_eq!(
            platform(OsKind::Windows, Architecture::Aarch64).profile(),
            Err(PlatformRefusal::WhpxNotOnArchitecture {
                architecture: Architecture::Aarch64
            })
        );
        assert_eq!(
            platform(OsKind::MacOs, Architecture::X86_64).profile(),
            Err(PlatformRefusal::NoMinimalMachineOnIntelMac)
        );
        assert!(PlatformRefusal::SharedKernel.to_string().contains("WSL2"));
    }

    #[test]
    fn arm_hosts_never_use_the_x86_microvm_board() {
        for os in [OsKind::Linux, OsKind::MacOs] {
            let profile = platform(os, Architecture::Aarch64).profile().unwrap();
            assert_eq!(profile.machine, Machine::Virt);
            assert_eq!(profile.cpu_model(), "host");
        }
    }

    #[test]
    fn machine_options_turn_off_pci_usb_graphics_and_serial() {
        for os in [OsKind::Windows, OsKind::Linux] {
            let profile = platform(os, Architecture::X86_64).profile().unwrap();
            let options = profile.machine_options();
            for off in ["pcie", "usb", "graphics", "isa-serial"] {
                assert!(options.contains(&(off, "off")), "{os} {off}");
            }
            assert!(profile.cpu_model().contains("vmx=off,svm=off"));
        }
        let whpx = platform(OsKind::Windows, Architecture::X86_64)
            .profile()
            .unwrap();
        assert!(whpx.machine_options().contains(&("pit", "off")));
        assert_eq!(whpx.accelerator_options(), vec![("kernel-irqchip", "off")]);
        assert!(whpx.cpu_model().starts_with("max,"));
        let kvm = platform(OsKind::Linux, Architecture::X86_64)
            .profile()
            .unwrap();
        assert!(kvm.machine_options().contains(&("pit", "on")));
        assert!(kvm.accelerator_options().is_empty());
        let virt = platform(OsKind::Linux, Architecture::Aarch64)
            .profile()
            .unwrap();
        assert!(virt.machine_options().contains(&("virtualization", "off")));
    }

    #[test]
    fn only_linux_gets_the_seccomp_sandbox_and_controls_are_per_os() {
        let linux = platform(OsKind::Linux, Architecture::X86_64)
            .profile()
            .unwrap();
        let sandbox = linux.seccomp_sandbox().unwrap();
        for setting in ["obsolete", "elevateprivileges", "spawn", "resourcecontrol"] {
            assert!(sandbox.contains(&(setting, "deny")));
        }
        assert_eq!(
            linux.confinement_applied(),
            super::super::LINUX_CONTROLS.into_iter().collect()
        );
        assert!(!linux
            .confinement_applied()
            .contains(&ConfinementControl::FilesystemLimits));
        let windows = platform(OsKind::Windows, Architecture::X86_64)
            .profile()
            .unwrap();
        assert!(windows.seccomp_sandbox().is_none());
        let controls = windows.confinement_applied();
        assert!(!controls.contains(&ConfinementControl::AccountIdentity));
        assert!(!controls.contains(&ConfinementControl::SyscallRestrictions));
        assert_eq!(controls.len(), 4);
        let mac = platform(OsKind::MacOs, Architecture::Aarch64)
            .profile()
            .unwrap();
        assert!(mac.confinement_applied().is_empty());
        assert!(mac.seccomp_sandbox().is_none());
    }
}
