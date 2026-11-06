//! The compiler: one V15 profile and one guest layout to one sealed guest policy
//! (VM-W07 "Required tools work; forbidden interfaces fail by intended mechanism;
//! seccomp/LSM responsibilities separated"; §3.4; VM-CP-05).
//!
//! The steps, each reading only V15:
//! 1. Every declared (interface, mechanism) pair must be one [`enforcement`] says the
//!    mechanism refuses; anything else is refused, never approximated.
//! 2. No interface left available may get past another's seccomp rule
//!    ([`SECCOMP_BYPASSES`]): with io_uring available, `AF_VSOCK` resting on seccomp alone
//!    is refused.
//! 3. The seccomp restrictions: one refusal per interface in the profile's responsibility
//!    map for seccomp, with the single errno V15 types for it and every rule seccomp has
//!    for it.
//! 4. The OCI process: exactly V15's capability set in all five sets, V15's no_new_privs,
//!    and the uid and gid when V15 fixes them.
//! 5. The protected paths, resolved against the layout; a read-only mount lists them in
//!    `linux.readonlyPaths`, credential separation adds the ownership rule, either one
//!    pins what keeps them in place ([`super::pins`]), and the LSM builds the Landlock
//!    ruleset, whose grants pass the grant rule ([`super::grants`]).
//! 6. Yama's scope for the ptrace rules V15 hands to the LSM.
//! 7. Every required tool's interfaces must stay usable: no seccomp rule may refuse a call
//!    of an interface a tool uses, and neither Yama nor Landlock may refuse it.
//! 8. The kernel requirements, the exceptions and the verification plan; the repository
//!    section when V15 protects `.git/` ([`super::repository`]); the boot checks derived
//!    from all of it ([`super::boot`]); then the seal.
//!
//! The mechanisms with nothing of their own to install are covered by what is: the
//! capability absence V15 relies on is the capability sets, credential separation for
//! ptrace is the uid policy with no setuid capability, and an absent kernel option is the
//! guest kernel's build, which the host verifies.

use std::collections::BTreeSet;
use std::fmt;

use super::boot::BootCheck;
use super::document::{GuestPolicy, GuestPolicyBody, GuestPolicyVersion, PolicyMeaning};
use super::grants::LandlockGrantRefusal;
use super::lsm::{LandlockRuleset, LsmSection, YamaPolicy};
use super::oci::{OciCapabilities, OciFragment, OciLinux, OciProcess, OciUser};
use super::paths::{AbsoluteGuestPath, GuestLayout, GuestPathRefusal};
use super::pins::pinned_paths;
use super::plan::VerificationStep;
use super::repository::RepositoryProtection;
use super::seccomp::{
    BaseFilterRequirement, SeccompArchitecture, SeccompRefusal, SeccompRestrictions, SeccompRule,
};
use super::sections::{
    ExceptionRecord, KernelRequirements, OwnershipRule, PathKind, PathProtection, ProtectedPathPlan,
};
use super::syscalls::{seccomp_matches, Syscall, SECCOMP_BYPASSES};
use crate::sandbox_contract::confinement::{
    enforcement, ConfinementProfile, Enforcement, Errno, Interface, Mechanism, ProtectedPath,
    RequiredTool, ToolName, UidPolicy, Unenforceable,
};

/// Why a profile could not be compiled exactly (M07A item 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuestPolicyRefusal {
    /// The profile hands an interface to a mechanism that cannot refuse it.
    MechanismCannotEnforce {
        interface: Interface,
        mechanism: Mechanism,
        reason: Unenforceable,
    },
    /// `available` is left available (a recorded exception), and its `operation` reaches
    /// `refused` without the system call `refused`'s seccomp rule matches, while no other
    /// declared mechanism refuses `refused`.
    InterfaceReopensAnother {
        available: Interface,
        operation: &'static str,
        refused: Interface,
    },
    /// Seccomp is assigned an interface this compiler has no rule for.
    NoSeccompRule { interface: Interface },
    /// A seccomp refusal returns one errno, and V15 types several or none for it.
    SeccompErrnoNotSingle {
        interface: Interface,
        failures: Vec<Errno>,
    },
    /// A protected path does not resolve to a normal guest path under the layout.
    UnresolvablePath {
        path: ProtectedPath,
        refusal: GuestPathRefusal,
    },
    /// Two protected paths resolve to one guest path.
    ProtectedPathsCollide { guest_path: AbsoluteGuestPath },
    /// Landlock only grants: it cannot refuse a protected path inside, or containing, a
    /// path it grants (a writable root or a device).
    LandlockCannotCarveOut {
        path: AbsoluteGuestPath,
        granted: AbsoluteGuestPath,
    },
    /// The Landlock ruleset breaks the grant rule another way (`super::grants`).
    LandlockGrantExceedsProfile { refusal: LandlockGrantRefusal },
    /// A seccomp rule would refuse a system call a required tool needs.
    ToolSyscallRefused {
        tool: ToolName,
        interface: Interface,
        syscall: Syscall,
    },
    /// The Yama scope or the Landlock ruleset would refuse an interface a required tool
    /// needs.
    ToolInterfaceRefusedByLsm {
        tool: ToolName,
        interface: Interface,
    },
    /// The policy could not be serialized for its digest.
    Unserializable { detail: String },
}

impl fmt::Display for GuestPolicyRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MechanismCannotEnforce {
                interface,
                mechanism,
                reason,
            } => write!(f, "{mechanism} cannot enforce {interface}: {reason}"),
            Self::InterfaceReopensAnother {
                available,
                operation,
                refused,
            } => write!(
                f,
                "{available} is left available, and its {operation} reaches {refused} past \
                 the seccomp rule that is the only mechanism refusing {refused}"
            ),
            Self::NoSeccompRule { interface } => {
                write!(f, "no seccomp rule expresses {interface}")
            }
            Self::SeccompErrnoNotSingle {
                interface,
                failures,
            } => write!(
                f,
                "a seccomp refusal of {interface} returns one errno, not {failures:?}"
            ),
            Self::UnresolvablePath { path, refusal } => {
                write!(f, "the protected path {path} does not resolve: {refusal}")
            }
            Self::ProtectedPathsCollide { guest_path } => {
                write!(f, "two protected paths resolve to {guest_path}")
            }
            Self::LandlockCannotCarveOut { path, granted } => write!(
                f,
                "Landlock cannot refuse writes to {path} while it grants writes beneath \
                 {granted}; the path rule needs a read-only mount"
            ),
            Self::LandlockGrantExceedsProfile { refusal } => write!(f, "{refusal}"),
            Self::ToolSyscallRefused {
                tool,
                interface,
                syscall,
            } => write!(
                f,
                "the seccomp layer would refuse {syscall}, which {tool} needs for {interface}"
            ),
            Self::ToolInterfaceRefusedByLsm { tool, interface } => write!(
                f,
                "the LSM section would refuse {interface}, which {tool} needs"
            ),
            Self::Unserializable { detail } => {
                write!(f, "the guest policy cannot be serialized: {detail}")
            }
        }
    }
}

impl std::error::Error for GuestPolicyRefusal {}

/// Compiles `profile` against `layout` into the sealed policy the guest installs; see the
/// module notes for the steps. Deterministic: the same inputs give the same digest.
pub fn compile(
    profile: &ConfinementProfile,
    layout: &GuestLayout,
) -> Result<GuestPolicy, GuestPolicyRefusal> {
    for entry in profile.forbidden() {
        for mechanism in entry.mechanisms() {
            if let Enforcement::CannotEnforce(reason) = enforcement(mechanism, entry.interface) {
                return Err(GuestPolicyRefusal::MechanismCannotEnforce {
                    interface: entry.interface,
                    mechanism,
                    reason,
                });
            }
        }
    }
    check_bypasses(profile)?;
    let seccomp = seccomp_restrictions(profile)?;
    let user = match profile.uid() {
        UidPolicy::Fixed { uid, gid } => Some(OciUser { uid, gid }),
        UidPolicy::AnyNonRoot => None,
    };
    let path_entry = profile.assignment(Interface::ProtectedPathWrite);
    let protected_paths = match path_entry {
        Some(entry) => Some(PathProtection {
            paths: resolve_paths(profile.protected_paths(), layout)?,
            ownership: entry
                .uses(Mechanism::NamespaceCredentials)
                .then_some(OwnershipRule::RootOwnedNoGroupOrOtherWrite),
            pinned: pinned_paths(profile.protected_paths(), layout, &entry.mechanisms())?,
        }),
        None => None,
    };
    let repository = match &protected_paths {
        Some(protection) => RepositoryProtection::for_paths(
            profile.protected_paths(),
            layout,
            protection.ownership.is_some(),
        )?,
        None => None,
    };
    let guest_paths: Vec<AbsoluteGuestPath> = protected_paths
        .iter()
        .flat_map(|protection| protection.paths.iter())
        .map(|plan| plan.guest_path.clone())
        .collect();
    let uses = |mechanism| path_entry.is_some_and(|entry| entry.uses(mechanism));
    let readonly_paths = if uses(Mechanism::ReadOnlyMount) {
        guest_paths.clone()
    } else {
        Vec::new()
    };
    let landlock = if uses(Mechanism::Lsm) {
        Some(LandlockRuleset::refusing(
            &guest_paths,
            layout,
            profile.no_new_privs(),
        )?)
    } else {
        None
    };
    let lsm = LsmSection {
        yama: YamaPolicy::for_forbidden(profile.forbidden()),
        landlock,
    };
    check_tools(profile.required_tools(), &seccomp, &lsm)?;
    let boot_checks = BootCheck::for_policy(&lsm, protected_paths.as_ref(), repository.as_ref());
    let body = GuestPolicyBody {
        version: GuestPolicyVersion::CURRENT,
        meaning: PolicyMeaning::InnerControlsDefenseInDepth,
        profile: profile.digest(),
        workload: profile.workload(),
        uid: profile.uid(),
        layout: layout.clone(),
        oci: OciFragment {
            process: OciProcess {
                user,
                capabilities: OciCapabilities::exactly(&profile.capabilities()),
                no_new_privileges: profile.no_new_privs(),
            },
            linux: OciLinux { readonly_paths },
        },
        seccomp,
        protected_paths,
        lsm,
        kernel: KernelRequirements {
            absent_options: profile.required_absent_options().into_iter().collect(),
            settings: profile.kernel_settings().to_vec(),
        },
        exceptions: profile
            .exceptions()
            .iter()
            .map(ExceptionRecord::of)
            .collect(),
        host_corroboration_required: profile.requires_host_corroboration(),
        verification: profile
            .forbidden()
            .iter()
            .map(|entry| VerificationStep::for_entry(entry, profile.protected_paths()))
            .collect(),
        repository,
        boot_checks,
    };
    GuestPolicy::seal(body)
}

/// Refuses a profile that leaves an interface available whose operation gets past the
/// seccomp rule of an interface no other declared mechanism refuses. Every mechanism
/// other than seccomp acts on the kernel object with the submitter's credentials, so one
/// of them still holds.
fn check_bypasses(profile: &ConfinementProfile) -> Result<(), GuestPolicyRefusal> {
    for bypass in SECCOMP_BYPASSES {
        if profile.assignment(bypass.through).is_some() {
            continue;
        }
        let Some(entry) = profile.assignment(bypass.bypassed) else {
            continue;
        };
        if entry
            .mechanisms()
            .iter()
            .all(|mechanism| *mechanism == Mechanism::Seccomp)
        {
            return Err(GuestPolicyRefusal::InterfaceReopensAnother {
                available: bypass.through,
                operation: bypass.operation,
                refused: bypass.bypassed,
            });
        }
    }
    Ok(())
}

/// One refusal per interface the profile hands to seccomp, in interface order.
fn seccomp_restrictions(
    profile: &ConfinementProfile,
) -> Result<SeccompRestrictions, GuestPolicyRefusal> {
    let responsibilities = profile.responsibilities();
    let mut refusals = Vec::new();
    for responsibility in responsibilities.responsibilities(Mechanism::Seccomp) {
        let interface = responsibility.interface;
        if let failures @ ([] | [_, _, ..]) = responsibility.failures.as_slice() {
            return Err(GuestPolicyRefusal::SeccompErrnoNotSingle {
                interface,
                failures: failures.to_vec(),
            });
        }
        let refusal = SeccompRefusal::compiled(interface)
            .ok_or(GuestPolicyRefusal::NoSeccompRule { interface })?;
        refusals.push(refusal);
    }
    Ok(SeccompRestrictions {
        base_filter: BaseFilterRequirement::RuntimeDenyByDefault,
        architectures: SeccompArchitecture::ALL.to_vec(),
        refusals,
    })
}

/// Each protected path under the layout, refusing a path that does not resolve and two
/// that resolve to one guest path.
fn resolve_paths(
    paths: &[ProtectedPath],
    layout: &GuestLayout,
) -> Result<Vec<ProtectedPathPlan>, GuestPolicyRefusal> {
    let mut seen = BTreeSet::new();
    let mut plans = Vec::new();
    for path in paths {
        let guest_path =
            layout
                .resolve(path)
                .map_err(|refusal| GuestPolicyRefusal::UnresolvablePath {
                    path: path.clone(),
                    refusal,
                })?;
        if !seen.insert(guest_path.clone()) {
            return Err(GuestPolicyRefusal::ProtectedPathsCollide { guest_path });
        }
        plans.push(ProtectedPathPlan {
            path: path.clone(),
            guest_path,
            kind: PathKind::of(path),
        });
    }
    Ok(plans)
}

/// Refuses when a compiled mechanism would refuse something a required tool uses: a
/// seccomp rule sharing a system call with one of the tool's interfaces, or the Yama scope
/// or the Landlock ruleset refusing one (VM-W07 "Required tools work").
pub(super) fn check_tools(
    tools: &[RequiredTool],
    seccomp: &SeccompRestrictions,
    lsm: &LsmSection,
) -> Result<(), GuestPolicyRefusal> {
    let rules: Vec<&SeccompRule> = seccomp
        .refusals
        .iter()
        .flat_map(|refusal| refusal.rules.iter())
        .collect();
    for tool in tools {
        for interface in &tool.interfaces {
            for needed in seccomp_matches(*interface)
                .iter()
                .copied()
                .map(SeccompRule::of)
            {
                if let Some(syscall) = rules.iter().find_map(|rule| rule.refuses_some_of(&needed)) {
                    return Err(GuestPolicyRefusal::ToolSyscallRefused {
                        tool: tool.name.clone(),
                        interface: *interface,
                        syscall,
                    });
                }
            }
            if lsm.refuses(*interface) {
                return Err(GuestPolicyRefusal::ToolInterfaceRefusedByLsm {
                    tool: tool.name.clone(),
                    interface: *interface,
                });
            }
        }
    }
    Ok(())
}
