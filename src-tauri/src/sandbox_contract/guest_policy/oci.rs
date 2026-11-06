//! The OCI runtime-spec fragment the guest's inner runtime takes (VM-W07; VM-R66
//! "Non-root workloads, capabilities and seccomp"; VM-CP-05 "the capability set equals the
//! profile"). Field names are the runtime spec's (`config.md`, `config-linux.md`), as the
//! guest agent's `hardenedContainerSpec` reads and writes them.
//!
//! A fragment, not a whole `config.json`: it names only the process settings and the
//! read-only paths V15 governs, and the installer sets each field it names to the value
//! here.
//! - `process.capabilities`: all five sets replaced by exactly V15's set. With
//!   no_new_privs and a non-root uid, file capabilities never add to a process, so a
//!   capability reaches a required tool after execve only through the ambient set, which
//!   needs it in the permitted and inheritable sets too; the bounding set equal to V15's
//!   is what VM-CP-05 checks. A capability no profile may hold is refused when read.
//! - `process.noNewPrivileges`: set to V15's value.
//! - `process.user`: present only when V15 fixes the uid and gid, both non-zero by type,
//!   so uid or gid 0 is refused when read. Under `UidPolicy::AnyNonRoot` the image's user
//!   stays, and the installer refuses uid 0 at launch (the policy carries V15's uid policy
//!   for that).
//! - `linux.readonlyPaths`: added to the runtime's list. runc skips a listed path that
//!   does not exist, which would leave it creatable, so the installer creates a missing
//!   one first ([`super::sections::PathProtection`]).
//!
//! No seccomp here. The seccomp layer only refuses and needs the runtime's base filter
//! beneath it, so it lives in its own section ([`super::seccomp`]) that is not shaped as
//! an OCI `linux.seccomp` object: this fragment on its own can never be installed as an
//! allow-by-default seccomp profile, and `linux` refuses a `seccomp` member when read.
//!
//! Absent on purpose: `root.readonly`, `process.rlimits` and `linux.maskedPaths`. V15 has
//! no field for them, so the runtime's values (the agent sets `RLIMIT_CORE` to 0 and its
//! pids limit) stay as they are; an empty list or a `false` here could read as a widening.

use std::collections::BTreeSet;
use std::fmt;
use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use super::paths::AbsoluteGuestPath;
use crate::sandbox_contract::confinement::LinuxCapability;

/// The fragment of the container's OCI specification this policy sets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciFragment {
    pub process: OciProcess,
    pub linux: OciLinux,
}

/// `process`: the workload's user, capabilities and no_new_privs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciProcess {
    /// The fixed uid and gid; absent when V15 admits any non-root uid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<OciUser>,
    pub capabilities: OciCapabilities,
    pub no_new_privileges: bool,
}

/// `process.user`: a uid and gid, both non-zero by type because V15's are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciUser {
    pub uid: NonZeroU32,
    pub gid: NonZeroU32,
}

/// One capability, serialized with its kernel name, such as `CAP_NET_BIND_SERVICE`. A
/// capability in V15's `NEVER_GRANTED` is refused when read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OciCapability(LinuxCapability);

impl OciCapability {
    /// Wraps a V15 capability. The compiler wraps only V15's set, which never holds a
    /// never-granted capability.
    pub const fn new(capability: LinuxCapability) -> Self {
        Self(capability)
    }

    /// The V15 capability.
    pub const fn capability(self) -> LinuxCapability {
        self.0
    }
}

/// Why a capability name was refused when read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityRefusal {
    /// Not one of [`LinuxCapability::ALL`]'s kernel names.
    Unknown,
    /// A capability no workload profile may hold (V15 `NEVER_GRANTED`).
    NeverGranted { capability: LinuxCapability },
}

impl fmt::Display for CapabilityRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => f.write_str("not a Linux capability name such as CAP_CHOWN"),
            Self::NeverGranted { capability } => {
                write!(f, "no workload profile may hold {capability}")
            }
        }
    }
}

impl std::error::Error for CapabilityRefusal {}

impl TryFrom<String> for OciCapability {
    type Error = CapabilityRefusal;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        let capability = LinuxCapability::ALL
            .into_iter()
            .find(|capability| capability.kernel_name() == text)
            .ok_or(CapabilityRefusal::Unknown)?;
        if capability.never_granted() {
            return Err(CapabilityRefusal::NeverGranted { capability });
        }
        Ok(Self(capability))
    }
}

impl From<OciCapability> for String {
    fn from(capability: OciCapability) -> Self {
        capability.0.kernel_name().to_owned()
    }
}

/// `process.capabilities`: the five sets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciCapabilities {
    pub bounding: Vec<OciCapability>,
    pub effective: Vec<OciCapability>,
    pub inheritable: Vec<OciCapability>,
    pub permitted: Vec<OciCapability>,
    pub ambient: Vec<OciCapability>,
}

impl OciCapabilities {
    /// Every set exactly `set`, in kernel number order.
    pub fn exactly(set: &BTreeSet<LinuxCapability>) -> Self {
        let list: Vec<OciCapability> = set.iter().copied().map(OciCapability).collect();
        Self {
            bounding: list.clone(),
            effective: list.clone(),
            inheritable: list.clone(),
            permitted: list.clone(),
            ambient: list,
        }
    }

    /// The five sets, in field order.
    pub fn sets(&self) -> [&[OciCapability]; 5] {
        [
            &self.bounding,
            &self.effective,
            &self.inheritable,
            &self.permitted,
            &self.ambient,
        ]
    }
}

/// `linux`: the read-only paths. Nothing else; a `seccomp` member is refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciLinux {
    /// Protected paths V15 hands to a read-only mount, resolved in the guest.
    pub readonly_paths: Vec<AbsoluteGuestPath>,
}
