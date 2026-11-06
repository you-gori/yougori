//! The LSM section: Yama for the ptrace rules V15 hands to the LSM, and Landlock for the
//! protected-path rules (VM-W07 "seccomp/LSM responsibilities separated"; §3.4 "Enforce
//! that through credentials/namespaces/LSM or deny ptrace for the relevant profile").
//!
//! Yama. `kernel.yama.ptrace_scope` is one guest-wide setting the guest agent writes
//! before the workload starts, not a per-container one; changing it needs
//! `CAP_SYS_PTRACE`, which no profile that relies on it holds. Scope 1 (relational) lets
//! a process attach only to its own descendants: ptrace of another user's process fails
//! with `EPERM`, and a debugger still traces the program it started (V15's `ptrace` probe
//! is "of a child it started"). It is narrower than "this user's processes": attaching to
//! an unrelated process of the same user fails too. Scope 2 (admin only) refuses every
//! attach and `PTRACE_TRACEME` without `CAP_SYS_PTRACE`, which V15 never lets a profile
//! that forbids ptrace hold, so it refuses ptrace of other users' processes as well. Both
//! refuse with `EPERM`; V15 also types `EACCES` for the LSM on ptrace, which AppArmor and
//! SELinux produce and Yama never does, so the plan expects `EPERM` alone. Yama's hook
//! gates every ptrace access check in attach mode, so it also refuses process_vm_readv(2),
//! process_vm_writev(2), pidfd_getfd(2) and opening `/proc/<pid>/mem`; seccomp refuses the
//! first three by number but cannot name the `/proc` path. V15 therefore requires the LSM
//! for every forbidden ptrace (M07B), so whenever ptrace is refused this section writes
//! the admin-only scope; what the guest verifies before the workload starts is in
//! `super::boot`.
//!
//! Landlock. A ruleset only grants: every access it handles is refused except beneath a
//! rule's path, and a rule covers the whole hierarchy beneath it. So Landlock cannot
//! refuse a path inside a hierarchy it grants, and an LSM path rule has one exact form
//! here: the ruleset handles every write right of [`LANDLOCK_ABI`] and grants writes
//! beneath the layout's writable roots, to the standard devices a working guest needs
//! ([`STANDARD_DEVICES`] and [`SHARED_MEMORY_DIRECTORY`]) and to the device nodes the
//! layout declares, and every protected path lies outside every grant and contains none.
//! A protected path a grant covers, or that covers one, is refused
//! ([`GuestPolicyRefusal::LandlockCannotCarveOut`]) by the grant rule of `super::grants`,
//! which reading a policy applies as well. The ruleset then refuses every other
//! write, not only the protected paths: a narrowing the layout declares, never a widening.
//! Every V15 protected path lies in the home or the workspace, so this fits only a layout
//! that does not let the workload write there; a profile that needs `.git/hooks/` refused
//! beneath a writable workspace needs the read-only mount V15's strict profile uses.
//! Landlock refuses with `EACCES`, the errno V15 types for the LSM on a path write.
//!
//! A rule on a file may hold only file rights; the kernel refuses a directory-only right
//! on a non-directory with `EINVAL`. So a device grant holds [`LandlockFsAccess::FILE`]
//! (writing and truncating), which is valid on a device file and on a directory of them
//! such as `/dev/dri`, and a directory where files are created (a writable root,
//! `/dev/shm`) holds every write right.
//!
//! ABI 3 is the floor: before it, truncate(2) is not a handled right and a protected file
//! could be emptied. An installer on an older kernel refuses rather than downgrade, since
//! Landlock's best-effort mode would drop a right silently. landlock_restrict_self(2)
//! needs no_new_privs or `CAP_SYS_ADMIN`; [`LandlockRestriction`] records which one the
//! installer relies on, so a profile with no_new_privs off is installable only by a
//! runtime that applies the ruleset before it drops `CAP_SYS_ADMIN`.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::compile::GuestPolicyRefusal;
use super::grants::layout_grants;
use super::paths::{AbsoluteGuestPath, GuestLayout};
use crate::sandbox_contract::confinement::{ForbiddenInterface, Interface, Mechanism};

/// The devices beneath `/dev` every Landlock ruleset grants writes to: the OCI runtime
/// spec's default devices and the terminals (`/dev/pts`), in name order.
pub const STANDARD_DEVICES: [&str; 7] = ["full", "null", "pts", "random", "tty", "urandom", "zero"];

/// The shared-memory directory beneath `/dev` every Landlock ruleset grants, where
/// shm_open(3) creates and removes files.
pub const SHARED_MEMORY_DIRECTORY: &str = "shm";

/// The Landlock ABI version every compiled ruleset needs, at least.
pub const LANDLOCK_ABI: u32 = 3;

/// What the LSM carries for one profile. Each part is absent when V15 hands it nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LsmSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yama: Option<YamaPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub landlock: Option<LandlockRuleset>,
}

impl LsmSection {
    /// Whether Yama or Landlock, as compiled, refuses `interface`.
    pub fn refuses(&self, interface: Interface) -> bool {
        let yama = self
            .yama
            .is_some_and(|policy| policy.ptrace_scope.refuses(interface));
        let landlock = self.landlock.is_some() && interface == Interface::ProtectedPathWrite;
        yama || landlock
    }
}

/// A Yama ptrace scope this compiler writes, serialized as the sysctl's number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub enum YamaPtraceScope {
    /// `1`: attach only to one's own descendants.
    Relational,
    /// `2`: attach only with `CAP_SYS_PTRACE`.
    AdminOnly,
}

impl YamaPtraceScope {
    /// The value written to `kernel.yama.ptrace_scope`.
    pub const fn value(self) -> u8 {
        match self {
            Self::Relational => 1,
            Self::AdminOnly => 2,
        }
    }

    /// Whether the scope refuses `interface` for a workload without `CAP_SYS_PTRACE`.
    pub const fn refuses(self, interface: Interface) -> bool {
        matches!(
            (self, interface),
            (Self::Relational, Interface::PtraceOtherUsers)
                | (
                    Self::AdminOnly,
                    Interface::Ptrace | Interface::PtraceOtherUsers
                )
        )
    }
}

/// A Yama scope this compiler never writes: 0 restricts nothing, and 3 is not needed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct YamaScopeRefusal {
    pub found: u8,
}

impl fmt::Display for YamaScopeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Yama ptrace scope {} is not one this policy writes (1 or 2)",
            self.found
        )
    }
}

impl std::error::Error for YamaScopeRefusal {}

impl TryFrom<u8> for YamaPtraceScope {
    type Error = YamaScopeRefusal;

    fn try_from(found: u8) -> Result<Self, Self::Error> {
        match found {
            1 => Ok(Self::Relational),
            2 => Ok(Self::AdminOnly),
            _ => Err(YamaScopeRefusal { found }),
        }
    }
}

impl From<YamaPtraceScope> for u8 {
    fn from(scope: YamaPtraceScope) -> Self {
        scope.value()
    }
}

/// The guest-wide Yama setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YamaPolicy {
    pub ptrace_scope: YamaPtraceScope,
}

impl YamaPolicy {
    /// The weakest scope that refuses every ptrace rule `forbidden` hands to the LSM:
    /// admin only when `ptrace` itself is, relational when only `ptrace_other_users` is;
    /// `None` when the LSM carries no ptrace rule.
    pub fn for_forbidden(forbidden: &[ForbiddenInterface]) -> Option<Self> {
        let lsm = |interface| {
            forbidden
                .iter()
                .any(|entry| entry.interface == interface && entry.uses(Mechanism::Lsm))
        };
        let ptrace_scope = if lsm(Interface::Ptrace) {
            YamaPtraceScope::AdminOnly
        } else if lsm(Interface::PtraceOtherUsers) {
            YamaPtraceScope::Relational
        } else {
            return None;
        };
        Some(Self { ptrace_scope })
    }
}

/// The pinned Landlock ABI; any other is refused when read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct LandlockAbi(u32);

impl LandlockAbi {
    pub const CURRENT: Self = Self(LANDLOCK_ABI);

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for LandlockAbi {
    type Error = String;

    fn try_from(found: u32) -> Result<Self, Self::Error> {
        if found == LANDLOCK_ABI {
            Ok(Self(found))
        } else {
            Err(format!(
                "Landlock ABI {found} is not supported; this build writes only ABI {LANDLOCK_ABI}"
            ))
        }
    }
}

impl From<LandlockAbi> for u32 {
    fn from(abi: LandlockAbi) -> Self {
        abi.0
    }
}

/// A Landlock filesystem access right that writes, by its kernel name
/// (`include/uapi/linux/landlock.h`). Declared in bit order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LandlockFsAccess {
    #[serde(rename = "LANDLOCK_ACCESS_FS_WRITE_FILE")]
    WriteFile,
    #[serde(rename = "LANDLOCK_ACCESS_FS_REMOVE_DIR")]
    RemoveDir,
    #[serde(rename = "LANDLOCK_ACCESS_FS_REMOVE_FILE")]
    RemoveFile,
    #[serde(rename = "LANDLOCK_ACCESS_FS_MAKE_CHAR")]
    MakeChar,
    #[serde(rename = "LANDLOCK_ACCESS_FS_MAKE_DIR")]
    MakeDir,
    #[serde(rename = "LANDLOCK_ACCESS_FS_MAKE_REG")]
    MakeReg,
    #[serde(rename = "LANDLOCK_ACCESS_FS_MAKE_SOCK")]
    MakeSock,
    #[serde(rename = "LANDLOCK_ACCESS_FS_MAKE_FIFO")]
    MakeFifo,
    #[serde(rename = "LANDLOCK_ACCESS_FS_MAKE_BLOCK")]
    MakeBlock,
    #[serde(rename = "LANDLOCK_ACCESS_FS_MAKE_SYM")]
    MakeSym,
    /// Linking or renaming into another directory (ABI 2).
    #[serde(rename = "LANDLOCK_ACCESS_FS_REFER")]
    Refer,
    /// truncate(2) and `O_TRUNC` (ABI 3).
    #[serde(rename = "LANDLOCK_ACCESS_FS_TRUNCATE")]
    Truncate,
}

impl LandlockFsAccess {
    /// Every write right up to ABI 3, in bit order.
    pub const WRITE: [Self; 12] = [
        Self::WriteFile,
        Self::RemoveDir,
        Self::RemoveFile,
        Self::MakeChar,
        Self::MakeDir,
        Self::MakeReg,
        Self::MakeSock,
        Self::MakeFifo,
        Self::MakeBlock,
        Self::MakeSym,
        Self::Refer,
        Self::Truncate,
    ];

    /// The write rights a rule on a file may hold (the kernel's `ACCESS_FILE`), in bit
    /// order.
    pub const FILE: [Self; 2] = [Self::WriteFile, Self::Truncate];

    /// The right's bit in `handled_access_fs` and `allowed_access`.
    pub const fn bit(self) -> u64 {
        match self {
            Self::WriteFile => 1 << 1,
            Self::RemoveDir => 1 << 4,
            Self::RemoveFile => 1 << 5,
            Self::MakeChar => 1 << 6,
            Self::MakeDir => 1 << 7,
            Self::MakeReg => 1 << 8,
            Self::MakeSock => 1 << 9,
            Self::MakeFifo => 1 << 10,
            Self::MakeBlock => 1 << 11,
            Self::MakeSym => 1 << 12,
            Self::Refer => 1 << 13,
            Self::Truncate => 1 << 14,
        }
    }

    /// The first ABI version that has the right.
    pub const fn minimum_abi(self) -> u32 {
        match self {
            Self::Refer => 2,
            Self::Truncate => 3,
            _ => 1,
        }
    }
}

/// Why a Landlock rule grants, and what the installer does when its path is missing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LandlockGrant {
    /// A writable root of the layout: a directory that must exist, or the installer
    /// refuses.
    WritableRoot,
    /// A standard device or the shared-memory directory: skipped when the guest lacks it,
    /// which only narrows.
    StandardDevice,
    /// A device node the layout declares: it must exist, or the installer refuses.
    DeclaredDevice,
}

/// One `LANDLOCK_RULE_PATH_BENEATH` rule: `allowed_access` beneath `path`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LandlockRule {
    pub path: AbsoluteGuestPath,
    pub grant: LandlockGrant,
    /// Every write right for a directory where files are created, [`LandlockFsAccess::FILE`]
    /// for a device.
    pub allowed_access: Vec<LandlockFsAccess>,
}

/// What landlock_restrict_self(2) relies on: no_new_privs, or `CAP_SYS_ADMIN` in the
/// caller's user namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LandlockRestriction {
    /// V15 sets no_new_privs, so the workload's process restricts itself after setting it.
    NoNewPrivileges,
    /// V15 leaves no_new_privs off, so the runtime must apply the ruleset while it still
    /// holds `CAP_SYS_ADMIN`, before it reduces the capability sets to V15's. An installer
    /// that cannot refuses; the workload never holds `CAP_SYS_ADMIN` itself.
    CapSysAdminBeforeCapabilityDrop,
}

impl LandlockRestriction {
    /// The restriction for a profile whose no_new_privs is `no_new_privs`.
    pub const fn for_no_new_privs(no_new_privs: bool) -> Self {
        if no_new_privs {
            Self::NoNewPrivileges
        } else {
            Self::CapSysAdminBeforeCapabilityDrop
        }
    }
}

/// A Landlock ruleset for the protected-path rules V15 hands to the LSM (see the module
/// notes for its one exact form).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LandlockRuleset {
    /// The ABI the installer needs at least, with no best-effort downgrade.
    pub abi: LandlockAbi,
    /// What restricting the workload relies on.
    pub restriction: LandlockRestriction,
    /// Every write right; each is refused except beneath a rule.
    pub handled_access_fs: Vec<LandlockFsAccess>,
    /// The grants, in path order.
    pub rules: Vec<LandlockRule>,
    /// The protected paths, beneath no rule, so a write to them fails with `EACCES`.
    pub refused_paths: Vec<AbsoluteGuestPath>,
}

impl LandlockRuleset {
    /// The ruleset refusing writes to every path in `protected` and granting them as the
    /// module notes say, passed through the grant rule (`super::grants`). Refuses when a
    /// grant covers a protected path or lies beneath one: Landlock cannot refuse inside
    /// what it grants.
    pub fn refusing(
        protected: &[AbsoluteGuestPath],
        layout: &GuestLayout,
        no_new_privs: bool,
    ) -> Result<Self, GuestPolicyRefusal> {
        let ruleset = Self {
            abi: LandlockAbi::CURRENT,
            restriction: LandlockRestriction::for_no_new_privs(no_new_privs),
            handled_access_fs: LandlockFsAccess::WRITE.to_vec(),
            rules: layout_grants(layout),
            refused_paths: protected.to_vec(),
        };
        ruleset.check_grants(protected, layout)?;
        Ok(ruleset)
    }
}
