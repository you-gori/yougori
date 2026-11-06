//! The approved Firecracker launch profile: the versioned minimal device profile of one
//! VM plus the machine shape and the jail's resource limits (§0.1 line 1825: "a versioned
//! minimal device profile and a confined hypervisor"; §3.4 line 2101: minimize devices
//! and network access, resource limits apply before workload execution; §7.2 line 2368:
//! "only required block/link/entropy and platform devices").
//!
//! What a profile cannot express is fixed by construction: SMT is off, dirty-page tracking
//! is off, the root drive is read-only, the boot arguments have no console, logger and
//! metrics go only to the host-created sinks and the link is vsock to a host-created
//! socket. A network interface exists only when the profile declares one (VM-CP-02 line
//! 2977). The identity digest covers every field, so a changed limit or an added device is
//! a new profile, never a silent re-enable (§3.4 line 2097).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::names::{ApiId, InterfaceName, MacAddress};
use crate::foundation::ids::{Digest, DigestBuilder};
use crate::sandbox::backend::{DeviceExposure, DeviceProfile};

/// Digest domain of [`FirecrackerProfile::identity`].
pub const PROFILE_DOMAIN: &str = "yougori/sandbox/firecracker/profile/v1";
/// The most vCPUs one Firecracker VM takes.
pub const MAX_VCPUS: u8 = 32;
/// Firecracker's threads besides one per vCPU: the API thread and the VMM thread.
pub const VMM_SERVICE_THREADS: u32 = 2;
/// One mebibyte, in bytes.
pub const MIB_BYTES: u64 = 1 << 20;
/// The shortest cgroup v2 CPU period the kernel accepts, in microseconds.
pub const MIN_CPU_PERIOD_MICROS: u64 = 1_000;
/// The longest cgroup v2 CPU period the kernel accepts, in microseconds.
pub const MAX_CPU_PERIOD_MICROS: u64 = 1_000_000;
/// The smallest cgroup v2 CPU quota the kernel accepts, in microseconds.
pub const MIN_CPU_QUOTA_MICROS: u64 = 1_000;
/// The most open descriptors a profile may allow (the kernel's default `nr_open`).
pub const MAX_OPEN_DESCRIPTORS: u32 = 1 << 20;
/// The longest profile text accepted, in bytes.
pub const MAX_PROFILE_BYTES: usize = 64 * 1024;

/// The guest's CPUs and memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineShape {
    pub vcpu_count: u8,
    pub guest_memory_mib: u32,
}

/// The cgroup v2 CPU bandwidth limit, `cpu.max`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpuLimit {
    pub quota_micros: u64,
    pub period_micros: u64,
}

/// The limits the jail places on the Firecracker process before it runs (§3.4 line 2101;
/// VM-CP-04 line 3154: cgroup limits present, descriptor count at or below the profile's
/// number).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailLimits {
    /// Memory the VMM may use beyond the guest's, in whole mebibytes so the cgroup limit
    /// is page-aligned on every page size and reads back exactly.
    pub vmm_overhead_bytes: u64,
    pub cpu: CpuLimit,
    /// `pids.max`: at least one task per vCPU plus [`VMM_SERVICE_THREADS`].
    pub max_tasks: u32,
    /// The open-descriptor limit (`RLIMIT_NOFILE`) and the VM-CP-04 bound.
    pub max_open_descriptors: u32,
    /// The largest file the process may write (`RLIMIT_FSIZE`), in bytes.
    pub max_file_bytes: u64,
}

/// A network interface the profile declares. Without one the VM has no network device
/// (§4.1 lines 2107–2111; VM-CP-02 line 3152).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterfaceDeclaration {
    /// The interface's Firecracker id.
    pub iface_id: ApiId,
    /// The tap device the launcher creates in the jail's network namespace.
    pub host_device: InterfaceName,
    pub guest_mac: MacAddress,
}

/// One approved Firecracker profile (§0.1 line 1825; VM-P02 line 2777).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirecrackerProfile {
    pub machine: MachineShape,
    /// Declared network interfaces, strictly ascending by id; usually none.
    pub network_interfaces: Vec<NetworkInterfaceDeclaration>,
    /// A virtio entropy device, for guest randomness (§6.6 line 2342).
    pub entropy_device: bool,
    pub limits: JailLimits,
}

/// Why a profile was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum ProfileError {
    /// The text is not a profile: malformed JSON, an unknown field or a bad name.
    Unreadable {
        detail: String,
    },
    TooLarge {
        bytes: usize,
        max_bytes: usize,
    },
    VcpuCount {
        vcpu_count: u8,
    },
    NoGuestMemory,
    /// The VMM overhead is zero or not a whole number of mebibytes.
    VmmOverhead {
        vmm_overhead_bytes: u64,
    },
    /// Guest memory plus VMM overhead does not fit in 64 bits.
    MemoryOverflow,
    CpuPeriod {
        period_micros: u64,
    },
    CpuQuota {
        quota_micros: u64,
    },
    TooFewTasks {
        max_tasks: u32,
        minimum: u32,
    },
    OpenDescriptors {
        max_open_descriptors: u32,
    },
    NoFileSize,
    /// Interfaces must be strictly ascending by id, which also refuses duplicates.
    InterfacesNotAscending {
        iface_id: ApiId,
    },
    DuplicateHostDevice {
        host_device: InterfaceName,
    },
    DuplicateGuestMac {
        guest_mac: MacAddress,
    },
    /// A tap device may not be named `lo`.
    LoopbackHostDevice,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { detail } => write!(f, "the profile cannot be read: {detail}"),
            Self::TooLarge { bytes, max_bytes } => {
                write!(f, "the profile is {bytes} bytes, more than {max_bytes}")
            }
            Self::VcpuCount { vcpu_count } => {
                write!(
                    f,
                    "{vcpu_count} vCPUs; a Firecracker VM has 1 to {MAX_VCPUS}"
                )
            }
            Self::NoGuestMemory => f.write_str("the guest has no memory"),
            Self::VmmOverhead { vmm_overhead_bytes } => write!(
                f,
                "a VMM overhead of {vmm_overhead_bytes} bytes; it must be a positive whole \
                 number of mebibytes"
            ),
            Self::MemoryOverflow => f.write_str("guest memory plus VMM overhead overflows"),
            Self::CpuPeriod { period_micros } => write!(
                f,
                "a CPU period of {period_micros} µs is outside {MIN_CPU_PERIOD_MICROS}–\
                 {MAX_CPU_PERIOD_MICROS} µs"
            ),
            Self::CpuQuota { quota_micros } => write!(
                f,
                "a CPU quota of {quota_micros} µs is below {MIN_CPU_QUOTA_MICROS} µs"
            ),
            Self::TooFewTasks { max_tasks, minimum } => write!(
                f,
                "a task limit of {max_tasks} is below the {minimum} the VMM's threads need"
            ),
            Self::OpenDescriptors {
                max_open_descriptors,
            } => write!(
                f,
                "an open-descriptor limit of {max_open_descriptors} is outside 1–\
                 {MAX_OPEN_DESCRIPTORS}"
            ),
            Self::NoFileSize => f.write_str("the file-size limit is zero"),
            Self::InterfacesNotAscending { iface_id } => write!(
                f,
                "network interface {iface_id} is out of order or repeated; ids must be \
                 strictly ascending"
            ),
            Self::DuplicateHostDevice { host_device } => {
                write!(f, "tap device {host_device} is declared twice")
            }
            Self::DuplicateGuestMac { guest_mac } => {
                write!(f, "guest MAC {guest_mac} is declared twice")
            }
            Self::LoopbackHostDevice => f.write_str("a tap device may not be named lo"),
        }
    }
}

impl std::error::Error for ProfileError {}

impl FirecrackerProfile {
    /// Parses and checks a profile; unknown fields, including any that would turn on SMT,
    /// a writable root or a console, are refused.
    pub fn from_json(text: &str) -> Result<Self, ProfileError> {
        if text.len() > MAX_PROFILE_BYTES {
            return Err(ProfileError::TooLarge {
                bytes: text.len(),
                max_bytes: MAX_PROFILE_BYTES,
            });
        }
        let profile: Self =
            serde_json::from_str(text).map_err(|error| ProfileError::Unreadable {
                detail: error.to_string(),
            })?;
        profile.validate()?;
        Ok(profile)
    }

    /// Checks every rule of the profile.
    pub fn validate(&self) -> Result<(), ProfileError> {
        let machine = self.machine;
        if machine.vcpu_count == 0 || machine.vcpu_count > MAX_VCPUS {
            return Err(ProfileError::VcpuCount {
                vcpu_count: machine.vcpu_count,
            });
        }
        if machine.guest_memory_mib == 0 {
            return Err(ProfileError::NoGuestMemory);
        }
        let limits = self.limits;
        if limits.vmm_overhead_bytes == 0 || limits.vmm_overhead_bytes % MIB_BYTES != 0 {
            return Err(ProfileError::VmmOverhead {
                vmm_overhead_bytes: limits.vmm_overhead_bytes,
            });
        }
        self.memory_max_bytes()?;
        if !(MIN_CPU_PERIOD_MICROS..=MAX_CPU_PERIOD_MICROS).contains(&limits.cpu.period_micros) {
            return Err(ProfileError::CpuPeriod {
                period_micros: limits.cpu.period_micros,
            });
        }
        if limits.cpu.quota_micros < MIN_CPU_QUOTA_MICROS {
            return Err(ProfileError::CpuQuota {
                quota_micros: limits.cpu.quota_micros,
            });
        }
        let minimum = self.minimum_tasks();
        if limits.max_tasks < minimum {
            return Err(ProfileError::TooFewTasks {
                max_tasks: limits.max_tasks,
                minimum,
            });
        }
        if limits.max_open_descriptors == 0 || limits.max_open_descriptors > MAX_OPEN_DESCRIPTORS {
            return Err(ProfileError::OpenDescriptors {
                max_open_descriptors: limits.max_open_descriptors,
            });
        }
        if limits.max_file_bytes == 0 {
            return Err(ProfileError::NoFileSize);
        }
        self.check_interfaces()
    }

    fn check_interfaces(&self) -> Result<(), ProfileError> {
        let mut devices = BTreeSet::new();
        let mut macs = BTreeSet::new();
        let mut previous: Option<&ApiId> = None;
        for interface in &self.network_interfaces {
            if previous.is_some_and(|previous| previous >= &interface.iface_id) {
                return Err(ProfileError::InterfacesNotAscending {
                    iface_id: interface.iface_id.clone(),
                });
            }
            previous = Some(&interface.iface_id);
            if interface.host_device.is_loopback() {
                return Err(ProfileError::LoopbackHostDevice);
            }
            if !devices.insert(&interface.host_device) {
                return Err(ProfileError::DuplicateHostDevice {
                    host_device: interface.host_device.clone(),
                });
            }
            if !macs.insert(interface.guest_mac) {
                return Err(ProfileError::DuplicateGuestMac {
                    guest_mac: interface.guest_mac,
                });
            }
        }
        Ok(())
    }

    /// The fewest tasks the VMM needs: one per vCPU plus the API and VMM threads.
    pub fn minimum_tasks(&self) -> u32 {
        u32::from(self.machine.vcpu_count) + VMM_SERVICE_THREADS
    }

    /// The guest's memory, in bytes.
    pub fn guest_memory_bytes(&self) -> u64 {
        u64::from(self.machine.guest_memory_mib) * MIB_BYTES
    }

    /// The cgroup memory limit: guest memory plus VMM overhead, in bytes.
    pub fn memory_max_bytes(&self) -> Result<u64, ProfileError> {
        self.guest_memory_bytes()
            .checked_add(self.limits.vmm_overhead_bytes)
            .ok_or(ProfileError::MemoryOverflow)
    }

    /// Whether the profile declares any network interface.
    pub fn declares_network(&self) -> bool {
        !self.network_interfaces.is_empty()
    }

    /// The identity digest over every field, in a fixed order.
    pub fn identity(&self) -> Digest {
        let machine = self.machine;
        let limits = self.limits;
        let mut builder = DigestBuilder::new(PROFILE_DOMAIN)
            .u64(u64::from(machine.vcpu_count))
            .u64(u64::from(machine.guest_memory_mib))
            .u64(u64::from(self.entropy_device))
            .u64(limits.vmm_overhead_bytes)
            .u64(limits.cpu.quota_micros)
            .u64(limits.cpu.period_micros)
            .u64(u64::from(limits.max_tasks))
            .u64(u64::from(limits.max_open_descriptors))
            .u64(limits.max_file_bytes)
            .u64(self.network_interfaces.len() as u64);
        for interface in &self.network_interfaces {
            builder = builder
                .str(interface.iface_id.as_str())
                .str(interface.host_device.as_str())
                .bytes(&interface.guest_mac.octets());
        }
        builder.finish()
    }

    /// The backend device profile a launch request names to use this profile: its
    /// identity, and CPU only, since a Firecracker VM has no display or assigned GPU.
    pub fn device_profile(&self) -> DeviceProfile {
        DeviceProfile {
            identity: self.identity(),
            devices: DeviceExposure::cpu_only(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::fixtures;
    use super::*;

    #[test]
    fn the_fixture_profile_is_valid_and_round_trips() {
        let profile = fixtures::profile();
        assert_eq!(profile.validate(), Ok(()));
        let text = serde_json::to_string(&profile).unwrap();
        assert_eq!(FirecrackerProfile::from_json(&text), Ok(profile.clone()));
        assert_eq!(
            profile.memory_max_bytes(),
            Ok(1024 * MIB_BYTES + 64 * MIB_BYTES)
        );
        assert_eq!(profile.minimum_tasks(), 4);
        assert!(!profile.declares_network());
        assert_eq!(profile.device_profile().identity, profile.identity());
        assert!(profile.device_profile().devices.is_cpu_only());
    }

    #[test]
    fn fields_that_would_weaken_the_fixed_settings_are_refused() {
        let text = serde_json::to_value(fixtures::profile()).unwrap();
        for (path, field, value) in [
            ("machine", "smt", serde_json::json!(true)),
            ("machine", "track_dirty_pages", serde_json::json!(true)),
            ("", "root_read_only", serde_json::json!(false)),
            ("", "console", serde_json::json!(true)),
            ("", "balloon", serde_json::json!({"amount_mib": 64})),
            ("", "boot_args", serde_json::json!("console=ttyS0")),
            ("", "log_path", serde_json::json!("/tmp/fc.log")),
            ("limits", "seccomp", serde_json::json!("none")),
        ] {
            let mut widened = text.clone();
            let target = if path.is_empty() {
                &mut widened
            } else {
                &mut widened[path]
            };
            target[field] = value;
            let result = FirecrackerProfile::from_json(&widened.to_string());
            assert!(
                matches!(result, Err(ProfileError::Unreadable { .. })),
                "{path}.{field}"
            );
        }
    }

    #[test]
    fn every_limit_rule_refuses_its_violation() {
        let base = fixtures::profile();
        let cases: Vec<(Box<dyn Fn(&mut FirecrackerProfile)>, ProfileError)> = vec![
            (
                Box::new(|p| p.machine.vcpu_count = 0),
                ProfileError::VcpuCount { vcpu_count: 0 },
            ),
            (
                Box::new(|p| p.machine.vcpu_count = 33),
                ProfileError::VcpuCount { vcpu_count: 33 },
            ),
            (
                Box::new(|p| p.machine.guest_memory_mib = 0),
                ProfileError::NoGuestMemory,
            ),
            (
                Box::new(|p| p.limits.vmm_overhead_bytes = 0),
                ProfileError::VmmOverhead {
                    vmm_overhead_bytes: 0,
                },
            ),
            (
                Box::new(|p| p.limits.vmm_overhead_bytes = MIB_BYTES + 4096),
                ProfileError::VmmOverhead {
                    vmm_overhead_bytes: MIB_BYTES + 4096,
                },
            ),
            (
                Box::new(|p| {
                    p.machine.guest_memory_mib = u32::MAX;
                    p.limits.vmm_overhead_bytes = u64::MAX - (u64::MAX % MIB_BYTES);
                }),
                ProfileError::MemoryOverflow,
            ),
            (
                Box::new(|p| p.limits.cpu.period_micros = 999),
                ProfileError::CpuPeriod { period_micros: 999 },
            ),
            (
                Box::new(|p| p.limits.cpu.period_micros = 1_000_001),
                ProfileError::CpuPeriod {
                    period_micros: 1_000_001,
                },
            ),
            (
                Box::new(|p| p.limits.cpu.quota_micros = 999),
                ProfileError::CpuQuota { quota_micros: 999 },
            ),
            (
                Box::new(|p| p.limits.max_tasks = 3),
                ProfileError::TooFewTasks {
                    max_tasks: 3,
                    minimum: 4,
                },
            ),
            (
                Box::new(|p| p.limits.max_open_descriptors = 0),
                ProfileError::OpenDescriptors {
                    max_open_descriptors: 0,
                },
            ),
            (
                Box::new(|p| p.limits.max_open_descriptors = MAX_OPEN_DESCRIPTORS + 1),
                ProfileError::OpenDescriptors {
                    max_open_descriptors: MAX_OPEN_DESCRIPTORS + 1,
                },
            ),
            (
                Box::new(|p| p.limits.max_file_bytes = 0),
                ProfileError::NoFileSize,
            ),
        ];
        for (change, error) in cases {
            let mut profile = base.clone();
            change(&mut profile);
            assert_eq!(profile.validate(), Err(error.clone()));
            assert!(!error.to_string().is_empty());
        }
        let mut thirty_two = base;
        thirty_two.machine.vcpu_count = 32;
        thirty_two.limits.max_tasks = 34;
        assert_eq!(thirty_two.validate(), Ok(()));
    }

    #[test]
    fn interfaces_are_ascending_unique_and_never_loopback() {
        let one = fixtures::network_profile();
        assert_eq!(one.validate(), Ok(()));
        assert!(one.declares_network());

        let mut twice = one.clone();
        twice
            .network_interfaces
            .push(twice.network_interfaces[0].clone());
        assert!(matches!(
            twice.validate(),
            Err(ProfileError::InterfacesNotAscending { .. })
        ));

        let mut descending = one.clone();
        let mut second = descending.network_interfaces[0].clone();
        second.iface_id = ApiId::new("eth").unwrap();
        second.host_device = InterfaceName::new("tap9").unwrap();
        second.guest_mac = MacAddress::parse("02:fc:00:00:00:09").unwrap();
        descending.network_interfaces.push(second.clone());
        assert!(matches!(
            descending.validate(),
            Err(ProfileError::InterfacesNotAscending { .. })
        ));

        let mut same_tap = one.clone();
        let mut other = same_tap.network_interfaces[0].clone();
        other.iface_id = ApiId::new("eth1").unwrap();
        other.guest_mac = MacAddress::parse("02:fc:00:00:00:09").unwrap();
        same_tap.network_interfaces.push(other);
        assert!(matches!(
            same_tap.validate(),
            Err(ProfileError::DuplicateHostDevice { .. })
        ));

        let mut same_mac = one.clone();
        let mut other = same_mac.network_interfaces[0].clone();
        other.iface_id = ApiId::new("eth1").unwrap();
        other.host_device = InterfaceName::new("tap1").unwrap();
        same_mac.network_interfaces.push(other);
        assert!(matches!(
            same_mac.validate(),
            Err(ProfileError::DuplicateGuestMac { .. })
        ));

        let mut loopback = one;
        loopback.network_interfaces[0].host_device = InterfaceName::loopback();
        assert_eq!(loopback.validate(), Err(ProfileError::LoopbackHostDevice));
    }

    #[test]
    fn the_identity_changes_with_every_field() {
        let base = fixtures::profile();
        let identity = base.identity();
        assert_eq!(fixtures::profile().identity(), identity);
        let changes: Vec<Box<dyn Fn(&mut FirecrackerProfile)>> = vec![
            Box::new(|p| p.machine.vcpu_count += 1),
            Box::new(|p| p.machine.guest_memory_mib += 1),
            Box::new(|p| p.entropy_device = !p.entropy_device),
            Box::new(|p| p.limits.vmm_overhead_bytes += MIB_BYTES),
            Box::new(|p| p.limits.cpu.quota_micros += 1),
            Box::new(|p| p.limits.cpu.period_micros += 1),
            Box::new(|p| p.limits.max_tasks += 1),
            Box::new(|p| p.limits.max_open_descriptors += 1),
            Box::new(|p| p.limits.max_file_bytes += 1),
            Box::new(|p| {
                p.network_interfaces = fixtures::network_profile().network_interfaces;
            }),
        ];
        let mut seen = BTreeSet::new();
        seen.insert(identity);
        for change in changes {
            let mut profile = base.clone();
            change(&mut profile);
            assert!(seen.insert(profile.identity()), "{profile:?}");
        }
        let network = fixtures::network_profile();
        for change in [
            |i: &mut NetworkInterfaceDeclaration| i.iface_id = ApiId::new("eth9").unwrap(),
            |i: &mut NetworkInterfaceDeclaration| {
                i.host_device = InterfaceName::new("tap9").unwrap()
            },
            |i: &mut NetworkInterfaceDeclaration| {
                i.guest_mac = MacAddress::parse("02:fc:00:00:00:09").unwrap()
            },
        ] {
            let mut profile = network.clone();
            change(&mut profile.network_interfaces[0]);
            assert_ne!(profile.identity(), network.identity());
        }
    }

    #[test]
    fn oversized_profiles_are_refused_before_parsing() {
        let text = " ".repeat(MAX_PROFILE_BYTES + 1);
        assert_eq!(
            FirecrackerProfile::from_json(&text),
            Err(ProfileError::TooLarge {
                bytes: MAX_PROFILE_BYTES + 1,
                max_bytes: MAX_PROFILE_BYTES
            })
        );
    }
}
