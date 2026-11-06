//! M07A: compiles a V15 confinement profile into the concrete configuration the guest
//! installs, the host half of VM-W07's installation (docs/combined-gpu-memory-and-vm-
//! sandbox-plan.md, VM part: the VM-W07 row "Inner confinement and guest hardening per
//! workload profile. No claim that guest seccomp survives guest-root/kernel compromise",
//! acceptance "Required tools work; forbidden interfaces fail by intended mechanism;
//! seccomp/LSM responsibilities separated"; §3.4 "Guest and hypervisor hardening";
//! VM-CP-05; VM-R55, VM-R56, VM-R57, VM-R66).
//!
//! [`compile()`] turns one [`ConfinementProfile`](super::confinement::ConfinementProfile)
//! and a [`GuestLayout`] into a [`GuestPolicy`]: strict, versioned data sealed under a
//! domain-separated digest. It is deterministic: one profile and one layout give one
//! policy and one digest. Every value comes from V15; the compiler adds no rule V15 does
//! not state and drops none it does.
//!
//! - [`oci`]: the OCI runtime-spec fragment, with the spec's field names. The capability
//!   sets (bounding, effective, permitted, inheritable and ambient) are exactly V15's set,
//!   `noNewPrivileges` is V15's value, `user` is the fixed uid and gid when V15 fixes them,
//!   and `readonlyPaths` holds the protected paths V15 hands to a read-only mount. It holds
//!   no seccomp object. V15 has no read-only root, rlimit or masked-path field, so the
//!   fragment sets none of them and the runtime's values stay.
//! - [`seccomp`]: the seccomp restrictions, a section of its own that is not OCI-shaped
//!   and carries its base-filter requirement inside it: built only from what V15's
//!   responsibility map hands to seccomp, one refusal per interface with V15's errno
//!   (`EPERM`) and every rule [`syscalls`] has for it, with an argument filter only on an
//!   integer argument. A syscall a required tool needs is never in it.
//! - [`lsm`]: Yama's ptrace scope for the ptrace rules V15 hands to the LSM, and a
//!   Landlock ruleset (ABI version, restriction prerequisite, handled access, grants) for
//!   the path rules. Landlock only grants, so a protected path inside a granted path
//!   cannot be expressed and is refused; nothing an LSM carries is ever moved into seccomp.
//! - [`sections`]: the resolved protected paths and their ownership rule, the kernel
//!   build requirements the host verifies, and V15's recorded exceptions, each with its
//!   reason and exactly what it leaves available.
//! - [`plan`]: the verification plan. For each forbidden interface: the mechanisms, the
//!   exact errnos each produces as V15 types them, and who verifies it (the guest's probe,
//!   and the host's kernel build record where an absent option is relied on), named as
//!   the VM-CP-05 checks of `confinement::evaluate`.
//! - [`document`]: the sealed policy and its strict reading: unknown fields, another
//!   version, a digest that is not the digest of the content, or a broken
//!   profile-independent invariant ([`PolicyInvariant`]) are refused, and
//!   [`GuestPolicy::check_against`] recompiles, so any other re-sealed edit is caught too.
//! - [`compile()`] refuses, with a typed [`GuestPolicyRefusal`], a profile it cannot
//!   express exactly, including one whose recorded io_uring exception would reopen
//!   `AF_VSOCK` past its seccomp rule.
//!
//! The M07B gaps, closed:
//! - `/proc/<pid>/mem` when ptrace is refused: V15 now requires the LSM for every
//!   forbidden ptrace, so the policy always writes Yama's admin-only scope then, which
//!   refuses the procfs open in the kernel's ptrace access check; [`boot`] lists what the
//!   guest verifies (Yama active, the scope read back, the open refused with `EACCES`).
//! - Landlock grants: [`grants`] is one typed rule ([`LandlockGrantRefusal`]) that
//!   compiling applies to the ruleset it builds and reading applies to the ruleset it
//!   reads, against the layout and protected paths of the same body.
//! - Repository hooks: V15 protects the whole `.git/` with the user-level git
//!   configuration; [`pins`] keeps every protected path from being renamed away, and
//!   [`repository`] neutralizes every git configuration value that could point hooks or
//!   other commands elsewhere. What returns to the host stays M12's promotion review.
//!
//! What a policy does not claim. Every control here is inside the guest: seccomp,
//! capabilities, no_new_privs, read-only mounts, ownership, Yama and Landlock are defense
//! in depth (§1.2, VM-R08). Guest root or a guest kernel compromise can remove any of
//! them, the seccomp layer included; only host-side boundaries remain then
//! (`confinement::residue`). [`PolicyMeaning`] states this in every policy, and nothing
//! here claims that guest seccomp survives guest-root or kernel compromise.
//!
//! What is outside. Tier 0 only (§12.1): pure, synchronous code. Nothing here installs a
//! filter, drops a capability, mounts, changes ownership, writes a sysctl or loads a
//! ruleset, and a policy is not evidence that any of that happened. Installing it in the
//! guest is the Go guest agent's (`appliance/agent/container_security.go`, M01/M06),
//! untouched here; running the probes and judging them is VM-CP-05's evaluator
//! (`confinement::evaluate`).
//!
//! Matching the guest agent. The agent reads and writes `process.capabilities` (five
//! sets of `CAP_` names), `process.noNewPrivileges` and `linux.seccomp` rules of
//! `names`, `action`, `errnoRet` and `args` (`index`, `value`, `valueTwo`, `op`), and
//! it refuses a container profile whose default action allows. The seccomp section here
//! has no default action and is no `linux.seccomp` object: the installer turns each rule
//! into a `SCMP_ACT_ERRNO` rule of the runtime's base profile or of a second filter
//! stacked on it, never into a filter of its own ([`BaseFilterRequirement`]).

/// Defines an internally tagged, snake_case enum whose deserialization refuses unknown
/// fields for every variant, unit variants included. serde ignores unknown fields beside
/// the tag of a unit variant even with `deny_unknown_fields`, so reading goes through a
/// twin enum whose unit variants are empty struct variants. Copied from
/// `strict_confinement_enum!` in `sandbox_contract/confinement/mod.rs`, kept local.
macro_rules! strict_guest_policy_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident tag $tag:literal {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident $({
                    $(
                        $(#[$field_meta:meta])*
                        $field:ident : $ty:ty
                    ),* $(,)?
                })?
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(serde::Serialize)]
        #[serde(tag = $tag, rename_all = "snake_case")]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant $({ $($(#[$field_meta])* $field : $ty),* })?
            ),*
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                #[derive(serde::Deserialize)]
                #[serde(tag = $tag, rename_all = "snake_case", deny_unknown_fields)]
                enum Strict {
                    $($variant { $($($field : $ty),*)? }),*
                }
                let record = crate::foundation::strict_serde::read_tagged(deserializer, $tag)?;
                let strict = <Strict as serde::Deserialize>::deserialize(record)
                    .map_err(serde::de::Error::custom)?;
                Ok(match strict {
                    $(Strict::$variant { $($($field),*)? } => Self::$variant $({ $($field),* })?),*
                })
            }
        }
    };
}

pub mod boot;
pub mod compile;
pub mod document;
pub mod grants;
pub mod lsm;
pub mod oci;
pub mod paths;
pub mod pins;
pub mod plan;
pub mod repository;
pub mod seccomp;
pub mod sections;
pub mod syscalls;

#[cfg(test)]
mod tests;

pub use boot::{BootCheck, ProcessMemoryTarget};
pub use compile::{compile, GuestPolicyRefusal};
pub use document::{
    GuestPolicy, GuestPolicyBody, GuestPolicyVersion, PolicyInvariant, PolicyMeaning,
    PolicyReadRefusal, GUEST_POLICY_DOMAIN, GUEST_POLICY_VERSION, MAX_GUEST_POLICY_BYTES,
};
pub use grants::{layout_grants, LandlockGrantRefusal};
pub use lsm::{
    LandlockAbi, LandlockFsAccess, LandlockGrant, LandlockRestriction, LandlockRule,
    LandlockRuleset, LsmSection, YamaPolicy, YamaPtraceScope, YamaScopeRefusal, LANDLOCK_ABI,
    SHARED_MEMORY_DIRECTORY, STANDARD_DEVICES,
};
pub use oci::{
    CapabilityRefusal, OciCapabilities, OciCapability, OciFragment, OciLinux, OciProcess, OciUser,
};
pub use paths::{
    AbsoluteGuestPath, GuestLayout, GuestPathRefusal, LayoutDocument, LayoutRefusal,
    MAX_DEVICE_NODES, MAX_GUEST_PATH_BYTES, MAX_GUEST_PATH_COMPONENTS, MAX_WRITABLE_ROOTS,
};
pub use pins::pinned_paths;
pub use plan::{PlannedMechanism, Verification, VerificationStep};
pub use repository::{GitConfigKey, GitConfigSetting, RepositoryProtection, KEPT_GIT_CONFIG_KEYS};
pub use seccomp::{
    ArgumentMatch, BaseFilterRequirement, SeccompArchitecture, SeccompRefusal, SeccompRestrictions,
    SeccompRule,
};
pub use sections::{
    ExceptionEffect, ExceptionRecord, KernelRequirements, OwnershipRule, PathKind, PathProtection,
    ProtectedPathPlan,
};
pub use syscalls::{
    seccomp_matches, IntegerArgument, SeccompBypass, SeccompMatch, Syscall, AF_VSOCK,
    IOCTL_REQUEST, SECCOMP_BYPASSES, SOCKET_DOMAIN, USERFAULTFD_IOC_NEW,
};
