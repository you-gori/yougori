//! The parts of a guest policy outside the OCI fragment and the LSM: the protected paths
//! as resolved in the guest, the kernel build requirements the host verifies, and V15's
//! recorded exceptions (VM-W07; VM-CP-05; VM-R57 "explicit supported exceptions"; §3.4
//! "documented compatibility handling" and "a configured boot argument is not evidence
//! the kernel enforced it").
//!
//! An exception appears with its target, tool, reason and owner exactly as V15 recorded
//! it, and with what it leaves available: an interface exception keeps the interface's
//! seccomp rules out of the seccomp layer and no other mechanism refuses it; a capability
//! exception puts the capability in all five sets. Nothing else in the compiled policy
//! changes because of it, but an interface left available can reach what another rule
//! refuses: io_uring's `IORING_OP_SOCKET` creates a socket without socket(2), so with an
//! io_uring exception the seccomp rule for `AF_VSOCK` no longer holds. Nothing but seccomp
//! can refuse `AF_VSOCK` (V15's enforcement table), so the compiler refuses every profile
//! with an io_uring exception
//! ([`GuestPolicyRefusal::InterfaceReopensAnother`](super::compile::GuestPolicyRefusal)).

use serde::{Deserialize, Serialize};

use super::paths::AbsoluteGuestPath;
use super::seccomp::SeccompRule;
use super::syscalls::seccomp_matches;
use crate::sandbox_contract::confinement::{
    ConfinementException, ExceptionTarget, KernelOption, KernelSetting, LinuxCapability,
    ProtectedPath,
};

/// Whether a protected path is one file or a directory and everything under it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    File,
    Directory,
}

impl PathKind {
    /// The kind V15's path names: a trailing `/` is a directory.
    pub const fn of(path: &ProtectedPath) -> Self {
        if path.is_directory() {
            Self::Directory
        } else {
            Self::File
        }
    }
}

/// One protected path, as V15 names it and as it lies in the guest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedPathPlan {
    pub path: ProtectedPath,
    pub guest_path: AbsoluteGuestPath,
    /// What the installer creates when the path is missing and a read-only mount is
    /// declared: runc skips a missing read-only path, which would leave it creatable.
    pub kind: PathKind,
}

/// The ownership rule credential separation needs on a protected path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipRule {
    /// Root owns the path, and everything under a directory, and neither group nor other
    /// may write it, so the non-root workload's write fails with `EACCES` (V15
    /// `namespace_credentials`, which also keeps every capability that would bypass it
    /// out of the profile).
    RootOwnedNoGroupOrOtherWrite,
}

/// The protected paths of a profile that forbids protected-path writes. Which mechanism
/// carries them is V15's assignment: a read-only mount lists them in
/// `linux.readonlyPaths`, credential separation sets [`PathProtection::ownership`], and
/// the LSM puts them in the Landlock ruleset's refused paths.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathProtection {
    /// In V15's order.
    pub paths: Vec<ProtectedPathPlan>,
    /// Present when V15 declares credential separation for protected-path writes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership: Option<OwnershipRule>,
    /// The paths bind-mounted onto themselves so that no protected path can be renamed
    /// away, in path order (`super::pins`); empty under the LSM alone.
    pub pinned: Vec<AbsoluteGuestPath>,
}

/// What the guest kernel's build must show; the host verifies it from the build record
/// bound to the booted kernel image, never from the guest (VM-CP-05; §3.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelRequirements {
    /// Options built out, for the interfaces V15 refuses by an absent option.
    pub absent_options: Vec<KernelOption>,
    /// Settings forced at build time; a boot argument does not count.
    pub settings: Vec<KernelSetting>,
}

strict_guest_policy_enum! {
    /// What one recorded exception leaves available.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ExceptionEffect tag "effect" {
        /// No compiled mechanism refuses the interface; these seccomp rules stay out of
        /// the seccomp layer (none for an interface seccomp cannot refuse).
        InterfaceLeftAvailable { rules: Vec<SeccompRule> },
        /// The capability is in all five capability sets.
        CapabilityInEverySet { capability: LinuxCapability },
    }
}

/// One of V15's recorded exceptions, as recorded, with its effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionRecord {
    pub exception: ConfinementException,
    pub effect: ExceptionEffect,
}

impl ExceptionRecord {
    /// The record of `exception`.
    pub fn of(exception: &ConfinementException) -> Self {
        let effect = match exception.target {
            ExceptionTarget::Interface { interface } => ExceptionEffect::InterfaceLeftAvailable {
                rules: seccomp_matches(interface)
                    .iter()
                    .copied()
                    .map(SeccompRule::of)
                    .collect(),
            },
            ExceptionTarget::Capability { capability } => {
                ExceptionEffect::CapabilityInEverySet { capability }
            }
        };
        Self {
            exception: exception.clone(),
            effect,
        }
    }
}
