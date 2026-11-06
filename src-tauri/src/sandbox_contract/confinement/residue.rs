//! What remains after guest root or a guest kernel compromise (VM-P05 "guest-root test
//! also demonstrates which host boundaries remain"; VM-R08 "Adopt as defense in depth
//! with its weaker status after guest-root compromise explicit"; VM-W07 "No claim that
//! guest seccomp survives guest-root/kernel compromise"; §1.1, §1.2).
//!
//! §1.1 assumes the attacker runs code as root in the guest and controls guest kernel
//! behavior, so guest root and a guest kernel compromise leave the same residue: the
//! host-side boundaries alone. Every inner control of the profile, the kernel build
//! included, is listed as defense in depth and not counted. The types make the split
//! structural: [`CompromiseResidue::remaining`] holds only [`HostBoundary`] values, and an
//! [`InnerControl`] can appear only in [`CompromiseResidue::defense_in_depth`].
//!
//! The residue names the boundaries that remain by design; whether each one holds is
//! shown by its own host-side checks (VM-P04, VM-P11 and the broker's tests), not here.

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

use super::interfaces::Mechanism;
use super::profile::ConfinementProfile;
use crate::foundation::ids::Digest;

/// What the attacker has gained inside the guest (§1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Compromise {
    /// Root inside the guest.
    GuestRoot,
    /// Control of the guest kernel.
    GuestKernel,
}

impl Compromise {
    pub const ALL: [Self; 2] = [Self::GuestRoot, Self::GuestKernel];
}

/// A boundary on the host side of the VM, outside the guest's reach by design.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostBoundary {
    /// The hardware virtualization boundary and the confined hypervisor process
    /// (`sandbox::backend::facets::ConfinementControl`, VM-P04, VM-CP-04).
    Hypervisor,
    /// The host's independent network perimeter (VM-P11).
    HostPerimeter,
    /// The host broker that authorizes every operation leaving the guest (§3.1).
    Broker,
}

impl HostBoundary {
    pub const ALL: [Self; 3] = [Self::Hypervisor, Self::HostPerimeter, Self::Broker];

    /// The user-facing label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Hypervisor => {
                "hypervisor boundary (host side): hardware virtualization and the confined \
                 hypervisor process"
            }
            Self::HostPerimeter => "host perimeter (host side): the independent network barrier",
            Self::Broker => "broker (host side): authorizes every operation leaving the guest",
        }
    }
}

impl fmt::Display for HostBoundary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A control inside the guest (VM-R08, VM-R66). Defense in depth only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InnerControl {
    NonRootUid,
    NoNewPrivs,
    CapabilityBoundingSet,
    KernelOptionsAbsent,
    SeccompFilter,
    LsmPolicy,
    ReadOnlyMounts,
    CredentialSeparation,
}

impl InnerControl {
    pub const ALL: [Self; 8] = [
        Self::NonRootUid,
        Self::NoNewPrivs,
        Self::CapabilityBoundingSet,
        Self::KernelOptionsAbsent,
        Self::SeccompFilter,
        Self::LsmPolicy,
        Self::ReadOnlyMounts,
        Self::CredentialSeparation,
    ];

    /// The inner control a mechanism is.
    pub const fn from_mechanism(mechanism: Mechanism) -> Self {
        match mechanism {
            Mechanism::KernelOptionAbsent => Self::KernelOptionsAbsent,
            Mechanism::Seccomp => Self::SeccompFilter,
            Mechanism::CapabilityAbsence => Self::CapabilityBoundingSet,
            Mechanism::Lsm => Self::LsmPolicy,
            Mechanism::ReadOnlyMount => Self::ReadOnlyMounts,
            Mechanism::NamespaceCredentials => Self::CredentialSeparation,
        }
    }

    /// The user-facing label; each states that the control is defense in depth.
    pub const fn label(self) -> &'static str {
        match self {
            Self::NonRootUid => "non-root uid (defense in depth inside the guest)",
            Self::NoNewPrivs => "no_new_privs (defense in depth inside the guest)",
            Self::CapabilityBoundingSet => {
                "capability bounding set (defense in depth inside the guest)"
            }
            Self::KernelOptionsAbsent => {
                "kernel options built out (defense in depth inside the guest)"
            }
            Self::SeccompFilter => "seccomp filter (defense in depth inside the guest)",
            Self::LsmPolicy => "LSM policy (defense in depth inside the guest)",
            Self::ReadOnlyMounts => "read-only mounts (defense in depth inside the guest)",
            Self::CredentialSeparation => {
                "credential separation (defense in depth inside the guest)"
            }
        }
    }
}

impl fmt::Display for InnerControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Any protection layer, host side or inner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "side", content = "layer", rename_all = "snake_case")]
pub enum ProtectionLayer {
    Host(HostBoundary),
    Inner(InnerControl),
}

impl ProtectionLayer {
    pub const fn is_host_side(self) -> bool {
        matches!(self, Self::Host(_))
    }
}

/// The residue of one compromise for one profile (VM-P05).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CompromiseResidue {
    pub compromise: Compromise,
    pub profile: Digest,
    /// The boundaries that remain: host side only.
    pub remaining: Vec<HostBoundary>,
    /// Every inner control of the profile, none of which is counted after the
    /// compromise.
    pub defense_in_depth: Vec<InnerControl>,
}

impl CompromiseResidue {
    /// The remaining boundaries as protection layers.
    pub fn remaining_layers(&self) -> Vec<ProtectionLayer> {
        self.remaining
            .iter()
            .copied()
            .map(ProtectionLayer::Host)
            .collect()
    }
}

/// Lists what remains of `profile`'s protection after `compromise` (VM-P05, VM-R08).
pub fn after_compromise(profile: &ConfinementProfile, compromise: Compromise) -> CompromiseResidue {
    let mut inner: BTreeSet<InnerControl> = BTreeSet::new();
    inner.insert(InnerControl::NonRootUid);
    inner.insert(InnerControl::CapabilityBoundingSet);
    if profile.no_new_privs() {
        inner.insert(InnerControl::NoNewPrivs);
    }
    inner.extend(
        profile
            .mechanisms()
            .into_iter()
            .map(InnerControl::from_mechanism),
    );
    CompromiseResidue {
        compromise,
        profile: profile.digest(),
        remaining: HostBoundary::ALL.to_vec(),
        defense_in_depth: inner.into_iter().collect(),
    }
}
