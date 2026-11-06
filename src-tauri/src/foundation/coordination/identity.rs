//! Identities the coordination protocol binds to (S3.1; VM part §6.1): the generations
//! each of the two state machines owns, and the host-created handles a launch produces.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::{
    AuthorizationEpoch, Digest, GpuAllocationGeneration, ModelActivationGeneration, PolicyEpoch,
    SandboxBootGeneration,
};

/// The generations a VM sandbox's authority binds to (S3.1). The sandbox lifecycle owns
/// them; each moves on its own, and changing one never refreshes another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxGenerations {
    /// Raised by every boot or snapshot restore.
    pub boot: SandboxBootGeneration,
    /// Raised by a policy change.
    pub policy: PolicyEpoch,
    /// Raised by revocation, by recovery and by every new boot; nothing bound to an older
    /// epoch is honoured again.
    pub authorization: AuthorizationEpoch,
}

impl SandboxGenerations {
    /// Where a new sandbox starts.
    pub const FIRST: Self = Self {
        boot: SandboxBootGeneration::FIRST,
        policy: PolicyEpoch::FIRST,
        authorization: AuthorizationEpoch::FIRST,
    };
}

impl fmt::Display for SandboxGenerations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "boot generation {}, policy epoch {}, authorization epoch {}",
            self.boot, self.policy, self.authorization
        )
    }
}

/// The generations of one model activation (S3.1). The model side owns them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelGenerations {
    /// Raised by every activation; requests keep the one that admitted them (INT-03).
    pub activation: ModelActivationGeneration,
    /// Raised by every GPU allocation; pointers into an older one are stale (INT-04).
    pub gpu_allocation: GpuAllocationGeneration,
}

impl ModelGenerations {
    /// Where a model's first activation starts.
    pub const FIRST: Self = Self {
        activation: ModelActivationGeneration::FIRST,
        gpu_allocation: GpuAllocationGeneration::FIRST,
    };
}

impl fmt::Display for ModelGenerations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "activation generation {}, GPU allocation generation {}",
            self.activation, self.gpu_allocation
        )
    }
}

macro_rules! handle {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Digest);

        impl $name {
            /// The handle a digest names.
            pub const fn new(digest: Digest) -> Self {
                Self(digest)
            }

            /// The digest of the handle.
            pub const fn digest(self) -> Digest {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

handle!(
    /// A model, by the digest of its identity. The model identity layers supply the
    /// digest; this module only compares it.
    ModelId
);
handle!(
    /// A VM the host created, by its stable handle identity, never a PID (VM part §6.4).
    VmInstanceId
);
handle!(
    /// The perimeter (network and channel policy) the host prepared for one boot (VM part
    /// §6.1 perimeter_ready).
    PerimeterId
);
handle!(
    /// A VM snapshot (VM part §6.6).
    SnapshotId
);
