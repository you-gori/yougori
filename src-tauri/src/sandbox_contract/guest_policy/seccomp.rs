//! The seccomp restrictions: what the guest's seccomp layer refuses, kept out of the OCI
//! fragment on purpose (VM-W07 "seccomp/LSM responsibilities separated"; VM-R55, VM-R57;
//! §3.4).
//!
//! The layer only refuses. It names no default action because it is not a filter on its
//! own: [`BaseFilterRequirement`] travels inside it and says the runtime's base filter, an
//! allow list whose default refuses, must stay installed beneath it. So no part of a
//! policy is an OCI `linux.seccomp` object, and nothing taken from it alone can be
//! installed as an allow-by-default profile. The installer either stacks the layer as a
//! second filter (the kernel applies the most restrictive result) or merges it into the
//! base by removing the listed names from the base's allow rules, covering the other
//! values of a filtered argument with masked rules as the agent already does for ioctl,
//! and keeping only the ABIs listed here; it never installs the layer alone.
//!
//! Each [`SeccompRefusal`] is one interface V15 hands to seccomp, with V15's seccomp errno
//! (`EPERM`, so a seccomp refusal is told apart from an absent kernel option's `ENOSYS`)
//! and every rule [`seccomp_matches`] gives it. A rule refuses every call of its system
//! calls, or, with an [`ArgumentMatch`], the calls whose argument masked by `mask` equals
//! `value`. In libseccomp and OCI terms a rule is `SCMP_ACT_ERRNO` with the refusal's
//! errno, its argument `SCMP_CMP_MASKED_EQ` with `value` = mask and `valueTwo` = value.
//!
//! Only the x86_64 and aarch64 ABIs are listed: a call from an ABI a filter does not list
//! takes libseccomp's bad-architecture action, which kills, so a 32-bit compat call cannot
//! slip past a rule. That matters for `AF_VSOCK`: i386 reaches socket(2) through
//! socketcall(2), whose arguments sit behind a pointer seccomp cannot read.

use serde::{Deserialize, Serialize};

use super::syscalls::{seccomp_matches, IntegerArgument, SeccompMatch, Syscall};
use crate::sandbox_contract::confinement::{enforcement, Enforcement, Errno, Interface, Mechanism};

/// The seccomp section of a policy (see the module notes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeccompRestrictions {
    /// The filter the layer needs beneath it.
    pub base_filter: BaseFilterRequirement,
    /// The ABIs the layer covers: exactly [`SeccompArchitecture::ALL`].
    pub architectures: Vec<SeccompArchitecture>,
    /// One per interface V15 hands to seccomp, in interface order.
    pub refusals: Vec<SeccompRefusal>,
}

/// What must stay installed beneath the layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaseFilterRequirement {
    /// The runtime's base filter, whose default action refuses, stays installed, and every
    /// call a rule here matches returns the rule's errno whatever the base allows. The
    /// layer is never installed as the only filter.
    RuntimeDenyByDefault,
}

/// An ABI the layer covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SeccompArchitecture {
    #[serde(rename = "x86_64")]
    X86_64,
    #[serde(rename = "aarch64")]
    Aarch64,
}

impl SeccompArchitecture {
    /// The 64-bit ABIs of the guests this contract supports.
    pub const ALL: [Self; 2] = [Self::X86_64, Self::Aarch64];
}

/// One interface refused by seccomp.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeccompRefusal {
    pub interface: Interface,
    /// What every rule returns: the one errno V15 types for seccomp on the interface.
    pub errno: Errno,
    /// Every rule of [`seccomp_matches`] for the interface, in that order.
    pub rules: Vec<SeccompRule>,
}

impl SeccompRefusal {
    /// The refusal this compiler writes for `interface`; `None` when V15 does not type one
    /// seccomp errno for it or seccomp has no rule for it.
    pub fn compiled(interface: Interface) -> Option<Self> {
        let errno = match enforcement(Mechanism::Seccomp, interface) {
            Enforcement::Enforces([errno]) => *errno,
            _ => return None,
        };
        let matches = seccomp_matches(interface);
        if matches.is_empty() {
            return None;
        }
        Some(Self {
            interface,
            errno,
            rules: matches.iter().copied().map(SeccompRule::of).collect(),
        })
    }
}

/// One rule: every call of `syscalls`, or only those whose argument matches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeccompRule {
    /// In name order.
    pub syscalls: Vec<Syscall>,
    /// Absent for a rule that refuses every call of its system calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argument: Option<ArgumentMatch>,
}

impl SeccompRule {
    /// The rule for `matcher`.
    pub fn of(matcher: SeccompMatch) -> Self {
        let argument = match matcher {
            SeccompMatch::Calls(_) => None,
            SeccompMatch::Argument { argument, value } => {
                Some(ArgumentMatch::int_equals(argument, value))
            }
        };
        Self {
            syscalls: matcher.syscalls(),
            argument,
        }
    }

    /// A system call this rule refuses that `other` also matches: they share the system
    /// call, and either refuses every call of it or both compare the same argument value.
    pub fn refuses_some_of(&self, other: &Self) -> Option<Syscall> {
        let argument_overlaps = match (self.argument, other.argument) {
            (Some(mine), Some(theirs)) => mine == theirs,
            _ => true,
        };
        self.syscalls
            .iter()
            .copied()
            .find(|syscall| argument_overlaps && other.syscalls.contains(syscall))
    }
}

/// `(argument & mask) == value` on one integer argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgumentMatch {
    /// The argument's position, from 0.
    pub index: u32,
    pub mask: u64,
    pub value: u64,
}

impl ArgumentMatch {
    /// `argument`, read as the kernel reads a 32-bit argument, equals `value`.
    pub fn int_equals(argument: IntegerArgument, value: u32) -> Self {
        Self {
            index: argument.index,
            mask: IntegerArgument::INT_MASK,
            value: u64::from(value),
        }
    }
}
