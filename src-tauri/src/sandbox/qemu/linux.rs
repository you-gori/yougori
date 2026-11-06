//! What the host must apply to the QEMU/KVM process on Linux, and VM-CP-04's Linux comparator
//! for the QEMU profile (line 3154: the hypervisor runs as an unprivileged identity with
//! `NoNewPrivs: 1` and `Seccomp: 2`, cgroup limits present; §7.3 lines 2378–2386: a
//! low-privilege identity, resource limits, a syscall filter; VM-W19's minimal compatible
//! QEMU Linux profile). Nothing here starts a process or writes a cgroup; the observed state
//! comes from the host (`/proc/<pid>/status` through the strict parser of
//! [`parse_status`](crate::sandbox::firecracker::parse_status), the process's own cgroup and
//! its network namespace), never from the guest.
//!
//! What is checked, and the control each shows: an account other than root and other than
//! the host's own, its four ids equal (account identity); no new privileges and no capability in any set (process
//! identity: what a restricted token is on Windows); seccomp in filter mode, which QEMU's
//! `-sandbox on,...` installs (syscall restrictions); a network namespace of its own holding
//! only `lo` (OS restrictions: the hypervisor has no network, the guest's egress goes
//! through the link); a cgroup of its own with the reservation as `memory.max` and a task
//! bound as `pids.max` (resource controls). Filesystem limits are not claimed: the account
//! still reads what any account may, so that control needs a mount or Landlock profile.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use serde::Serialize;

use super::profile::QemuProfile;
use crate::foundation::evidence::{ClockReading, ConfigurationFingerprint};
use crate::sandbox::backend::{ConfinementControl, HostObserved, ObservationProblem};
use crate::sandbox::firecracker::{ProcStatus, SeccompMode};

/// The most tasks (processes and threads: `pids.max` counts both) the QEMU process's group
/// may hold: its vCPU, I/O, RCU and worker threads, with room.
pub const MAX_QEMU_TASKS: u32 = 64;

/// What the host applies to one launch's QEMU process on Linux.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LinuxHostRestrictions {
    pub internet: bool,
    /// The group's `memory.max`: the launch's whole reservation.
    pub memory_limit_bytes: u64,
    /// The group's `pids.max`.
    pub max_tasks: u32,
}

impl LinuxHostRestrictions {
    /// The restrictions of one launch.
    pub fn for_profile(profile: &QemuProfile, reserved_ram_bytes: u64) -> Self {
        Self {
            internet: profile.internet(),
            memory_limit_bytes: reserved_ram_bytes,
            max_tasks: MAX_QEMU_TASKS,
        }
    }
}

/// What the host observed about the QEMU process on Linux.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LinuxObservedState {
    /// The parsed `/proc/<pid>/status`.
    pub status: ProcStatus,
    /// The process's cgroup v2 path as `/proc/<pid>/cgroup` shows it, with a leading '/'.
    pub cgroup: String,
    /// The group's `memory.max`; `None` for `max` (no limit).
    pub memory_max: Option<u64>,
    /// The group's `pids.max`; `None` for `max`.
    pub pids_max: Option<u64>,
    /// The interface names of the process's network namespace (`/proc/<pid>/net/dev`).
    pub network_interfaces: BTreeSet<String>,
    /// The effective user id of the host that observed it (the engine's own account).
    pub host_uid: u32,
}

/// One restriction the observation shows not in effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "finding", rename_all = "snake_case")]
pub enum LinuxFinding {
    /// The process runs as root.
    RunsAsRoot,
    /// The process runs as the host's own account: no account of its own.
    SharesTheHostAccount {
        uid: u32,
    },
    /// Its real, effective, saved and filesystem ids differ: it could switch back.
    IdentitiesDiffer,
    NewPrivilegesAllowed,
    NoSeccompFilter {
        mode: SeccompMode,
    },
    CapabilitiesHeld {
        permitted: u64,
        effective: u64,
        ambient: u64,
    },
    /// The process is in the root cgroup or no group of its own.
    NoGroupOfItsOwn {
        cgroup: String,
    },
    MemoryLimit {
        expected_bytes: u64,
        observed_bytes: Option<u64>,
    },
    TaskLimit {
        expected: u32,
        observed: Option<u64>,
    },
    /// The process's network namespace holds interfaces besides `lo`.
    NetworkInterfaces {
        found: BTreeSet<String>,
    },
}

impl LinuxFinding {
    /// The controls this finding shows not in effect.
    fn breaks(&self) -> Vec<ConfinementControl> {
        match self {
            Self::RunsAsRoot | Self::SharesTheHostAccount { .. } | Self::IdentitiesDiffer => {
                vec![ConfinementControl::AccountIdentity]
            }
            Self::NewPrivilegesAllowed | Self::CapabilitiesHeld { .. } => {
                vec![ConfinementControl::ProcessIdentity]
            }
            Self::NoSeccompFilter { .. } => vec![ConfinementControl::SyscallRestrictions],
            Self::NoGroupOfItsOwn { .. } | Self::MemoryLimit { .. } | Self::TaskLimit { .. } => {
                vec![ConfinementControl::ResourceControls]
            }
            Self::NetworkInterfaces { .. } => vec![ConfinementControl::OsRestrictions],
        }
    }
}

impl fmt::Display for LinuxFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunsAsRoot => f.write_str("QEMU runs as root"),
            Self::SharesTheHostAccount { uid } => {
                write!(f, "QEMU runs as the host's own account (uid {uid})")
            }
            Self::IdentitiesDiffer => f.write_str("QEMU's real, effective and saved ids differ"),
            Self::NewPrivilegesAllowed => f.write_str("QEMU may gain new privileges"),
            Self::NoSeccompFilter { mode } => {
                write!(f, "QEMU's seccomp mode is {}, not the filter", mode.number())
            }
            Self::CapabilitiesHeld {
                permitted,
                effective,
                ambient,
            } => write!(
                f,
                "QEMU holds capabilities (permitted {permitted:#x}, effective {effective:#x}, ambient {ambient:#x})"
            ),
            Self::NoGroupOfItsOwn { cgroup } => write!(f, "QEMU is in no group of its own ({cgroup})"),
            Self::MemoryLimit {
                expected_bytes,
                observed_bytes,
            } => write!(f, "QEMU's memory limit is {observed_bytes:?}, not {expected_bytes}"),
            Self::TaskLimit { expected, observed } => {
                write!(f, "QEMU's task limit is {observed:?}, not {expected}")
            }
            Self::NetworkInterfaces { found } => {
                write!(f, "QEMU's network namespace holds {found:?}, not only lo")
            }
        }
    }
}

/// The outcome of one comparison.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LinuxCheck {
    findings: Vec<LinuxFinding>,
}

impl LinuxCheck {
    pub fn findings(&self) -> &[LinuxFinding] {
        &self.findings
    }

    /// Every restriction was observed in place.
    pub fn passed(&self) -> bool {
        self.findings.is_empty()
    }

    /// The controls the observation shows in place, for the backend's host-observed
    /// confinement fact; a control any finding breaks is left out.
    pub fn controls_observed(&self) -> BTreeSet<ConfinementControl> {
        let broken: BTreeSet<ConfinementControl> = self
            .findings
            .iter()
            .flat_map(LinuxFinding::breaks)
            .collect();
        [
            ConfinementControl::AccountIdentity,
            ConfinementControl::ProcessIdentity,
            ConfinementControl::SyscallRestrictions,
            ConfinementControl::OsRestrictions,
            ConfinementControl::ResourceControls,
        ]
        .into_iter()
        .filter(|control| !broken.contains(control))
        .collect()
    }
}

/// The controls a Linux launch applies (the profile's `confinement_applied` on Linux).
pub const LINUX_CONTROLS: [ConfinementControl; 5] = [
    ConfinementControl::AccountIdentity,
    ConfinementControl::ProcessIdentity,
    ConfinementControl::SyscallRestrictions,
    ConfinementControl::OsRestrictions,
    ConfinementControl::ResourceControls,
];

/// Compares what the host observed of the QEMU process with `expected`, the observation
/// first checked current (same configuration, within `max_age` of `now`).
pub fn check_linux(
    expected: &LinuxHostRestrictions,
    observed: &HostObserved<LinuxObservedState>,
    now: ClockReading,
    max_age: Duration,
    configuration: ConfigurationFingerprint,
) -> Result<LinuxCheck, ObservationProblem> {
    observed.current_at(now, max_age, configuration)?;
    let state = observed.value();
    let mut findings = Vec::new();
    let uid = state.status.uid;
    if uid.effective == 0 || uid.real == 0 {
        findings.push(LinuxFinding::RunsAsRoot);
    } else if uid.effective == state.host_uid || uid.real == state.host_uid {
        findings.push(LinuxFinding::SharesTheHostAccount {
            uid: state.host_uid,
        });
    }
    if !uid.all_equal(uid.real) || !state.status.gid.all_equal(state.status.gid.real) {
        findings.push(LinuxFinding::IdentitiesDiffer);
    }
    if !state.status.no_new_privs {
        findings.push(LinuxFinding::NewPrivilegesAllowed);
    }
    if state.status.seccomp != SeccompMode::Filter {
        findings.push(LinuxFinding::NoSeccompFilter {
            mode: state.status.seccomp,
        });
    }
    if state.status.cap_permitted != 0
        || state.status.cap_effective != 0
        || state.status.cap_ambient != 0
    {
        findings.push(LinuxFinding::CapabilitiesHeld {
            permitted: state.status.cap_permitted,
            effective: state.status.cap_effective,
            ambient: state.status.cap_ambient,
        });
    }
    if state.cgroup.trim_matches('/').is_empty() {
        findings.push(LinuxFinding::NoGroupOfItsOwn {
            cgroup: state.cgroup.clone(),
        });
    }
    if state.memory_max != Some(expected.memory_limit_bytes) {
        findings.push(LinuxFinding::MemoryLimit {
            expected_bytes: expected.memory_limit_bytes,
            observed_bytes: state.memory_max,
        });
    }
    if state.pids_max != Some(u64::from(expected.max_tasks)) {
        findings.push(LinuxFinding::TaskLimit {
            expected: expected.max_tasks,
            observed: state.pids_max,
        });
    }
    let others: BTreeSet<String> = state
        .network_interfaces
        .iter()
        .filter(|name| name.as_str() != "lo")
        .cloned()
        .collect();
    if !expected.internet && !others.is_empty() {
        findings.push(LinuxFinding::NetworkInterfaces { found: others });
    }
    Ok(LinuxCheck { findings })
}

/// The interface names `/proc/<pid>/net/dev` lists: the lines after its two headers, each
/// name before its colon.
pub fn interfaces_of(net_dev: &str) -> BTreeSet<String> {
    net_dev
        .lines()
        .skip(2)
        .filter_map(|line| line.split_once(':').map(|(name, _)| name.trim().to_owned()))
        .filter(|name| !name.is_empty())
        .collect()
}

/// A cgroup limit file's value: `None` for `max`.
pub fn limit_of(text: &str) -> Option<u64> {
    match text.trim() {
        "max" => None,
        value => value.parse().ok(),
    }
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod tests;
