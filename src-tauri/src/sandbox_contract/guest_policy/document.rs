//! The sealed guest policy and its strict reading (M07A item 6; the sealing of
//! `sandbox_contract::views::record`: a body sealed under a domain-separated digest of its
//! serialized form).
//!
//! A [`GuestPolicy`] is a [`GuestPolicyBody`] sealed under [`GUEST_POLICY_DOMAIN`], so a
//! change to anything it says changes the digest. Reading one back is strict: more than
//! [`MAX_GUEST_POLICY_BYTES`] is refused unread, and unknown fields at any level, another
//! version, another meaning, a value outside a closed set (a capability or system call
//! name, an architecture, a base-filter requirement, a Yama scope, a Landlock ABI, right,
//! grant or restriction, a boot check, a process-memory target, a kept git key or a written
//! git setting), uid or gid 0, a capability V15 never grants, and a digest that
//! is not the digest of the content are refused.
//!
//! A digest alone cannot stop someone who re-seals an edited body, so reading also holds
//! every invariant that needs no profile ([`PolicyInvariant`]): the user agrees with the
//! uid policy; the five capability sets are one sorted set, each capability within the
//! workload's ceiling or covered by a recorded capability exception; the strict tool
//! profile keeps no_new_privs; the seccomp section lists exactly both ABIs, each refusal
//! is exactly the one this compiler writes for its interface, in interface order, one per
//! verification step that declares seccomp, and the interfaces every profile must refuse
//! by seccomp alone (`AF_VSOCK`) are present; a Landlock ruleset's restriction agrees with
//! no_new_privs. Since M07B also: every interface the workload's baseline names has a step
//! or a recorded exception; a ptrace step declares the LSM (V15's `/proc/<pid>/mem` rule)
//! and Yama's scope is the one the plan's LSM steps call for; a Landlock ruleset is
//! present exactly when the path step declares the LSM and passes the grant rule
//! (`super::grants`) against the layout and protected paths of the same body; the
//! repository protection is complete; and the pins, the repository section and the boot
//! checks are exactly the ones derived from the rest of the body. [`GuestPolicy::check_against`]
//! then recompiles from the profile and layout and refuses any difference.
//!
//! Version 2 (M07B) added the pins, the repository section and the boot checks, under a
//! new digest domain; a version 1 policy is refused.
//!
//! The digest bytes. The digest is `foundation::ids::digest(GUEST_POLICY_DOMAIN, [B])`:
//! SHA-256 over the domain's length as a big-endian u64, the domain's UTF-8 bytes, `B`'s
//! length as a big-endian u64 and `B`, written as 64 lowercase hex digits. `B` is the
//! compact serde_json serialization of `body`: no insignificant whitespace, members in the
//! declaration order of these types (the order they appear in the stored file), optional
//! members omitted when absent, integers in decimal, and strings with only `"`, `\` and
//! U+0000 to U+001F escaped. The stored file is serde_json's pretty form of the same
//! value, so for every policy this compiler writes `B` is exactly the raw bytes of the
//! stored `body` member with insignificant whitespace removed (Go's `json.Compact`, which
//! does not re-escape). It is also Go's `encoding/json` encoding of the same structs with
//! HTML escaping off: no string in a policy can hold a character the two escape
//! differently, since every text field refuses control and line-separator characters.
//! The Go side hashes those bytes and applies the same strict schema and invariants; a
//! body spelled any other way fails one side's digest check.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::boot::BootCheck;
use super::compile::{compile, GuestPolicyRefusal};
use super::grants::LandlockGrantRefusal;
use super::lsm::{LandlockRestriction, LsmSection, YamaPolicy};
use super::oci::OciFragment;
use super::paths::{AbsoluteGuestPath, GuestLayout};
use super::pins::pinned_paths;
use super::plan::VerificationStep;
use super::repository::RepositoryProtection;
use super::seccomp::{SeccompArchitecture, SeccompRefusal, SeccompRestrictions};
use super::sections::{ExceptionEffect, ExceptionRecord, KernelRequirements, PathProtection};
use crate::foundation::ids::{digest, Digest};
use crate::sandbox_contract::confinement::{
    enforcement, ConfinementProfile, Enforcement, ExceptionTarget, ForbiddenInterface, Interface,
    LinuxCapability, Mechanism, ProtectedPath, UidPolicy, WorkloadProfile, REPOSITORY_PROTECTION,
};

/// The digest domain of a guest policy; a new field layout needs a new domain.
pub const GUEST_POLICY_DOMAIN: &str = "yougori/sandbox/guest-policy/v2";

/// The policy schema version this build writes and reads.
pub const GUEST_POLICY_VERSION: u32 = 2;

/// Largest policy read from JSON. A larger one is refused unread.
pub const MAX_GUEST_POLICY_BYTES: usize = 256 * 1024;

/// The pinned policy version; any other is refused when read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct GuestPolicyVersion(u32);

impl GuestPolicyVersion {
    pub const CURRENT: Self = Self(GUEST_POLICY_VERSION);

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for GuestPolicyVersion {
    type Error = String;

    fn try_from(found: u32) -> Result<Self, Self::Error> {
        if found == GUEST_POLICY_VERSION {
            Ok(Self(found))
        } else {
            Err(format!(
                "guest policy version {found} is not supported; this build reads only version \
                 {GUEST_POLICY_VERSION}"
            ))
        }
    }
}

impl From<GuestPolicyVersion> for u32 {
    fn from(version: GuestPolicyVersion) -> Self {
        version.0
    }
}

/// What a guest policy means, stated in every policy (VM-W07 "No claim that guest seccomp
/// survives guest-root/kernel compromise"; §1.2; VM-R08).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMeaning {
    /// Every control in the policy is inside the guest and defense in depth: guest root
    /// or a guest kernel compromise can remove any of them, the seccomp layer included,
    /// and only host-side boundaries remain then (`confinement::residue`).
    InnerControlsDefenseInDepth,
}

/// Everything a guest policy says; its digest covers all of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestPolicyBody {
    pub version: GuestPolicyVersion,
    pub meaning: PolicyMeaning,
    /// The V15 profile compiled, by its digest; the guest's probe report names it.
    pub profile: Digest,
    pub workload: WorkloadProfile,
    /// V15's uid policy. Under `any_non_root` the installer refuses uid 0 at launch.
    pub uid: UidPolicy,
    pub layout: GuestLayout,
    pub oci: OciFragment,
    /// The seccomp layer, outside the OCI fragment (see `super::seccomp`).
    pub seccomp: SeccompRestrictions,
    /// Present when the profile forbids protected-path writes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected_paths: Option<PathProtection>,
    pub lsm: LsmSection,
    pub kernel: KernelRequirements,
    /// V15's recorded exceptions, in V15's order.
    pub exceptions: Vec<ExceptionRecord>,
    /// Whether VM-CP-05 needs the host's corroboration for this profile (V15).
    pub host_corroboration_required: bool,
    /// One step per forbidden interface, in interface order.
    pub verification: Vec<VerificationStep>,
    /// Present when V15 protects the workspace repository (`super::repository`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<RepositoryProtection>,
    /// What the installer verifies before it starts the workload (`super::boot`).
    pub boot_checks: Vec<BootCheck>,
}

/// Why a stored policy was refused when read or checked. No variant carries the stored
/// text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyReadRefusal {
    TooLarge {
        bytes: usize,
        max: usize,
    },
    /// Not a well-formed policy: unknown fields, another version, a value outside a
    /// closed set. Only the position is kept.
    Malformed {
        line: usize,
        column: usize,
    },
    /// The read body could not be serialized again for its digest.
    Unserializable,
    /// The stored digest is not the digest of the content.
    DigestMismatch {
        stored: Digest,
        computed: Digest,
    },
    /// The policy breaks an invariant that holds for every compiled policy.
    Invariant(PolicyInvariant),
    /// The policy is of another profile.
    OtherProfile {
        policy: Digest,
        profile: Digest,
    },
    /// The profile no longer compiles against the layout.
    NotCompilable(GuestPolicyRefusal),
    /// The policy differs from what the profile and layout compile to.
    DiffersFromCompilation,
}

impl fmt::Display for PolicyReadRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { bytes, max } => {
                write!(f, "the guest policy has {bytes} bytes; at most {max}")
            }
            Self::Malformed { line, column } => write!(
                f,
                "the guest policy is malformed at line {line}, column {column}"
            ),
            Self::Unserializable => f.write_str("the guest policy cannot be serialized again"),
            Self::DigestMismatch { stored, computed } => write!(
                f,
                "the guest policy's digest {stored} is not the digest {computed} of its \
                 content; it was changed after it was sealed"
            ),
            Self::Invariant(invariant) => write!(f, "{invariant}"),
            Self::OtherProfile { policy, profile } => write!(
                f,
                "the guest policy is of profile {policy}, not profile {profile}"
            ),
            Self::NotCompilable(refusal) => write!(f, "{refusal}"),
            Self::DiffersFromCompilation => {
                f.write_str("the guest policy differs from what its profile and layout compile to")
            }
        }
    }
}

impl std::error::Error for PolicyReadRefusal {}

/// An invariant every compiled policy holds whatever its profile, broken by a policy read
/// back (see the module notes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyInvariant {
    /// `process.user` is absent under a fixed uid policy, present under any non-root, or
    /// another uid or gid.
    UserDisagreesWithUidPolicy,
    /// The five capability sets are not one sorted set without repeats.
    CapabilitySetsDiffer,
    /// A capability above the workload's ceiling with no recorded capability exception.
    CapabilityWithoutException { capability: LinuxCapability },
    /// The strict tool profile without no_new_privs.
    NoNewPrivilegesRequired,
    /// The seccomp section does not list exactly [`SeccompArchitecture::ALL`].
    SeccompArchitectures,
    /// A seccomp refusal that is not exactly the one this compiler writes for its
    /// interface, or out of interface order.
    SeccompRefusalNotCompiled { interface: Interface },
    /// An interface refused by seccomp in the plan, or one every profile must refuse by
    /// seccomp alone, with no seccomp refusal.
    SeccompRefusalMissing { interface: Interface },
    /// A seccomp refusal for an interface no verification step hands to seccomp.
    SeccompRefusalUndeclared { interface: Interface },
    /// A Landlock ruleset whose restriction does not follow no_new_privs.
    LandlockRestrictionDisagrees,
    /// An interface the workload's baseline names with neither a step nor a recorded
    /// exception.
    BaselineInterfaceUnaccounted { interface: Interface },
    /// A ptrace step that does not declare the LSM, which V15 requires for
    /// `/proc/<pid>/mem`.
    PtraceWithoutLsm,
    /// Yama's scope is not the one the plan's LSM ptrace steps call for.
    YamaDisagreesWithPlan,
    /// A Landlock ruleset present without the path step declaring the LSM, or absent with
    /// it.
    LandlockDisagreesWithPlan,
    /// The Landlock ruleset breaks the grant rule against this body's layout and protected
    /// paths.
    LandlockGrant(LandlockGrantRefusal),
    /// A path in the workspace repository is protected, but this one of V15's repository
    /// protection is not.
    RepositoryProtectionIncomplete { path: &'static str },
    /// The pinned paths are not the ones the protected paths and their mechanisms call for.
    PinsNotCompiled,
    /// The repository section is not the one the protected paths call for.
    RepositoryNotCompiled,
    /// The boot checks are not the ones the rest of the policy calls for.
    BootChecksNotCompiled,
}

impl fmt::Display for PolicyInvariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserDisagreesWithUidPolicy => {
                f.write_str("the process user disagrees with the uid policy")
            }
            Self::CapabilitySetsDiffer => {
                f.write_str("the five capability sets are not one sorted set")
            }
            Self::CapabilityWithoutException { capability } => write!(
                f,
                "{capability} is above the workload's ceiling and has no recorded exception"
            ),
            Self::NoNewPrivilegesRequired => {
                f.write_str("the strict tool profile requires no_new_privs")
            }
            Self::SeccompArchitectures => {
                f.write_str("the seccomp section does not list exactly x86_64 and aarch64")
            }
            Self::SeccompRefusalNotCompiled { interface } => write!(
                f,
                "the seccomp refusal of {interface} is not the one this compiler writes"
            ),
            Self::SeccompRefusalMissing { interface } => {
                write!(f, "no seccomp refusal of {interface}")
            }
            Self::SeccompRefusalUndeclared { interface } => write!(
                f,
                "a seccomp refusal of {interface} that no verification step declares"
            ),
            Self::LandlockRestrictionDisagrees => {
                f.write_str("the Landlock restriction does not follow no_new_privs")
            }
            Self::BaselineInterfaceUnaccounted { interface } => write!(
                f,
                "{interface} has neither a verification step nor a recorded exception"
            ),
            Self::PtraceWithoutLsm => f.write_str(
                "the ptrace step does not declare the LSM, so /proc/<pid>/mem stays open",
            ),
            Self::YamaDisagreesWithPlan => {
                f.write_str("the Yama scope is not the one the plan's LSM steps call for")
            }
            Self::LandlockDisagreesWithPlan => f.write_str(
                "the Landlock ruleset is present or absent against the plan's path step",
            ),
            Self::LandlockGrant(refusal) => write!(f, "{refusal}"),
            Self::RepositoryProtectionIncomplete { path } => write!(
                f,
                "a path in the workspace repository is protected but {path} is not"
            ),
            Self::PinsNotCompiled => {
                f.write_str("the pinned paths are not the ones the protected paths call for")
            }
            Self::RepositoryNotCompiled => {
                f.write_str("the repository section is not the one the protected paths call for")
            }
            Self::BootChecksNotCompiled => {
                f.write_str("the boot checks are not the ones the policy calls for")
            }
        }
    }
}

impl std::error::Error for PolicyInvariant {}

/// A sealed guest policy (M07A). Only [`compile`] seals one; reading one back checks its
/// digest and every invariant of [`PolicyInvariant`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PolicyWire")]
pub struct GuestPolicy {
    digest: Digest,
    body: GuestPolicyBody,
}

/// A policy as read, before its digest and invariants are checked.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyWire {
    digest: Digest,
    body: GuestPolicyBody,
}

impl TryFrom<PolicyWire> for GuestPolicy {
    type Error = PolicyReadRefusal;

    fn try_from(wire: PolicyWire) -> Result<Self, Self::Error> {
        let computed = body_digest(&wire.body).map_err(|_| PolicyReadRefusal::Unserializable)?;
        if computed != wire.digest {
            return Err(PolicyReadRefusal::DigestMismatch {
                stored: wire.digest,
                computed,
            });
        }
        check_invariants(&wire.body).map_err(PolicyReadRefusal::Invariant)?;
        Ok(Self {
            digest: wire.digest,
            body: wire.body,
        })
    }
}

fn body_digest(body: &GuestPolicyBody) -> Result<Digest, serde_json::Error> {
    let bytes = serde_json::to_vec(body)?;
    Ok(digest(GUEST_POLICY_DOMAIN, &[&bytes]))
}

/// Every invariant of [`PolicyInvariant`], in its order.
fn check_invariants(body: &GuestPolicyBody) -> Result<(), PolicyInvariant> {
    let process = &body.oci.process;
    let user_agrees = match (body.uid, process.user) {
        (UidPolicy::Fixed { uid, gid }, Some(user)) => user.uid == uid && user.gid == gid,
        (UidPolicy::AnyNonRoot, None) => true,
        _ => false,
    };
    if !user_agrees {
        return Err(PolicyInvariant::UserDisagreesWithUidPolicy);
    }
    let [bounding, others @ ..] = process.capabilities.sets();
    let sorted = bounding.windows(2).all(|pair| match pair {
        [first, second] => first < second,
        _ => true,
    });
    if !sorted || others.iter().any(|set| *set != bounding) {
        return Err(PolicyInvariant::CapabilitySetsDiffer);
    }
    let ceiling = body.workload.capability_ceiling();
    for capability in bounding.iter().map(|capability| capability.capability()) {
        let excepted = body.exceptions.iter().any(|record| {
            record.effect == ExceptionEffect::CapabilityInEverySet { capability }
                && record.exception.target == ExceptionTarget::Capability { capability }
        });
        if !ceiling.contains(&capability) && !excepted {
            return Err(PolicyInvariant::CapabilityWithoutException { capability });
        }
    }
    if body.workload == WorkloadProfile::StrictTool && !process.no_new_privileges {
        return Err(PolicyInvariant::NoNewPrivilegesRequired);
    }
    check_seccomp(body)?;
    if let Some(landlock) = &body.lsm.landlock {
        if landlock.restriction != LandlockRestriction::for_no_new_privs(process.no_new_privileges)
        {
            return Err(PolicyInvariant::LandlockRestrictionDisagrees);
        }
    }
    check_lsm(body)?;
    check_derived(body)
}

/// The step of `interface`, if the plan has one.
fn step_of(body: &GuestPolicyBody, interface: Interface) -> Option<&VerificationStep> {
    body.verification
        .iter()
        .find(|step| step.interface == interface)
}

/// Every baseline interface accounted for, V15's ptrace rule, Yama against the plan, and
/// the Landlock ruleset against the plan and the grant rule.
fn check_lsm(body: &GuestPolicyBody) -> Result<(), PolicyInvariant> {
    for interface in body.workload.baseline_forbidden() {
        let excepted = body
            .exceptions
            .iter()
            .any(|record| record.exception.target == ExceptionTarget::Interface { interface });
        if step_of(body, interface).is_none() && !excepted {
            return Err(PolicyInvariant::BaselineInterfaceUnaccounted { interface });
        }
    }
    let declares_lsm = |interface| {
        step_of(body, interface).is_some_and(|step| step.declared().contains(&Mechanism::Lsm))
    };
    if step_of(body, Interface::Ptrace).is_some() && !declares_lsm(Interface::Ptrace) {
        return Err(PolicyInvariant::PtraceWithoutLsm);
    }
    let forbidden: Vec<ForbiddenInterface> = body
        .verification
        .iter()
        .filter_map(|step| {
            let declared = step.declared();
            let (primary, backup) = declared.split_first()?;
            Some(ForbiddenInterface {
                interface: step.interface,
                primary: *primary,
                backup: backup.first().copied(),
            })
        })
        .collect();
    if body.lsm.yama != YamaPolicy::for_forbidden(&forbidden) {
        return Err(PolicyInvariant::YamaDisagreesWithPlan);
    }
    if body.lsm.landlock.is_some() != declares_lsm(Interface::ProtectedPathWrite) {
        return Err(PolicyInvariant::LandlockDisagreesWithPlan);
    }
    if let Some(landlock) = &body.lsm.landlock {
        let protected: Vec<AbsoluteGuestPath> = body
            .protected_paths
            .iter()
            .flat_map(|protection| protection.paths.iter())
            .map(|plan| plan.guest_path.clone())
            .collect();
        landlock
            .check_grants(&protected, &body.layout)
            .map_err(PolicyInvariant::LandlockGrant)?;
    }
    Ok(())
}

/// The repository protection complete, and the pins, the repository section and the boot
/// checks exactly as derived from the rest of the body.
fn check_derived(body: &GuestPolicyBody) -> Result<(), PolicyInvariant> {
    let paths: Vec<ProtectedPath> = body
        .protected_paths
        .iter()
        .flat_map(|protection| protection.paths.iter())
        .map(|plan| plan.path.clone())
        .collect();
    if paths.iter().any(ProtectedPath::in_repository) {
        if let Some(path) = REPOSITORY_PROTECTION
            .into_iter()
            .find(|text| !paths.iter().any(|path| path.to_text() == *text))
        {
            return Err(PolicyInvariant::RepositoryProtectionIncomplete { path });
        }
    }
    if let Some(protection) = &body.protected_paths {
        let mechanisms = step_of(body, Interface::ProtectedPathWrite)
            .map(VerificationStep::declared)
            .unwrap_or_default();
        let pins = pinned_paths(&paths, &body.layout, &mechanisms)
            .map_err(|_| PolicyInvariant::PinsNotCompiled)?;
        if pins != protection.pinned {
            return Err(PolicyInvariant::PinsNotCompiled);
        }
    }
    let repository = match &body.protected_paths {
        Some(protection) => {
            RepositoryProtection::for_paths(&paths, &body.layout, protection.ownership.is_some())
                .map_err(|_| PolicyInvariant::RepositoryNotCompiled)?
        }
        None => None,
    };
    if repository != body.repository {
        return Err(PolicyInvariant::RepositoryNotCompiled);
    }
    let boot = BootCheck::for_policy(
        &body.lsm,
        body.protected_paths.as_ref(),
        body.repository.as_ref(),
    );
    if boot != body.boot_checks {
        return Err(PolicyInvariant::BootChecksNotCompiled);
    }
    Ok(())
}

/// The seccomp invariants: both ABIs, every refusal exactly compiled and in order, one per
/// step that declares seccomp, and the interfaces every profile refuses by seccomp alone.
fn check_seccomp(body: &GuestPolicyBody) -> Result<(), PolicyInvariant> {
    let seccomp = &body.seccomp;
    if seccomp.architectures != SeccompArchitecture::ALL {
        return Err(PolicyInvariant::SeccompArchitectures);
    }
    let mut previous: Option<Interface> = None;
    for refusal in &seccomp.refusals {
        let interface = refusal.interface;
        let ordered = previous.is_none_or(|before| before < interface);
        if !ordered || SeccompRefusal::compiled(interface).as_ref() != Some(refusal) {
            return Err(PolicyInvariant::SeccompRefusalNotCompiled { interface });
        }
        previous = Some(interface);
    }
    let refused: BTreeSet<Interface> = seccomp
        .refusals
        .iter()
        .map(|refusal| refusal.interface)
        .collect();
    let declared: BTreeSet<Interface> = body
        .verification
        .iter()
        .filter(|step| step.declared().contains(&Mechanism::Seccomp))
        .map(|step| step.interface)
        .collect();
    let always = always_refused_by_seccomp(body.workload);
    if let Some(interface) = declared.union(&always).find(|i| !refused.contains(i)) {
        return Err(PolicyInvariant::SeccompRefusalMissing {
            interface: *interface,
        });
    }
    if let Some(interface) = refused.difference(&declared).next() {
        return Err(PolicyInvariant::SeccompRefusalUndeclared {
            interface: *interface,
        });
    }
    Ok(())
}

/// The interfaces `workload` must refuse, admits no exception for, and only seccomp can
/// refuse (V15's enforcement table): `AF_VSOCK` for every workload.
fn always_refused_by_seccomp(workload: WorkloadProfile) -> BTreeSet<Interface> {
    workload
        .baseline_forbidden()
        .into_iter()
        .filter(|interface| {
            !workload.admits_exception(ExceptionTarget::Interface {
                interface: *interface,
            })
        })
        .filter(|interface| {
            Mechanism::ALL.into_iter().all(|mechanism| {
                mechanism == Mechanism::Seccomp
                    || matches!(
                        enforcement(mechanism, *interface),
                        Enforcement::CannotEnforce(_)
                    )
            })
        })
        .collect()
}

impl GuestPolicy {
    /// Seals `body` under the digest of its serialized form.
    pub(super) fn seal(body: GuestPolicyBody) -> Result<Self, GuestPolicyRefusal> {
        let digest = body_digest(&body).map_err(|error| GuestPolicyRefusal::Unserializable {
            detail: error.to_string(),
        })?;
        Ok(Self { digest, body })
    }

    /// The policy's own digest.
    pub const fn digest(&self) -> Digest {
        self.digest
    }

    pub const fn body(&self) -> &GuestPolicyBody {
        &self.body
    }

    /// The step for `interface`, if the profile forbids it.
    pub fn step(&self, interface: Interface) -> Option<&VerificationStep> {
        self.body
            .verification
            .iter()
            .find(|step| step.interface == interface)
    }

    /// The interfaces the seccomp layer refuses; reading holds each refusal to exactly the
    /// rules compiled for its interface.
    pub fn seccomp_interfaces(&self) -> BTreeSet<Interface> {
        self.body
            .seccomp
            .refusals
            .iter()
            .map(|refusal| refusal.interface)
            .collect()
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Reads a policy strictly; see the module notes for what is refused.
    pub fn from_json(text: &str) -> Result<Self, PolicyReadRefusal> {
        if text.len() > MAX_GUEST_POLICY_BYTES {
            return Err(PolicyReadRefusal::TooLarge {
                bytes: text.len(),
                max: MAX_GUEST_POLICY_BYTES,
            });
        }
        let wire: PolicyWire =
            serde_json::from_str(text).map_err(|error| PolicyReadRefusal::Malformed {
                line: error.line(),
                column: error.column(),
            })?;
        Self::try_from(wire)
    }

    /// Refuses unless the policy is exactly what `profile` compiles to against `layout`.
    pub fn check_against(
        &self,
        profile: &ConfinementProfile,
        layout: &GuestLayout,
    ) -> Result<(), PolicyReadRefusal> {
        if self.body.profile != profile.digest() {
            return Err(PolicyReadRefusal::OtherProfile {
                policy: self.body.profile,
                profile: profile.digest(),
            });
        }
        let expected = compile(profile, layout).map_err(PolicyReadRefusal::NotCompilable)?;
        if expected != *self {
            return Err(PolicyReadRefusal::DiffersFromCompilation);
        }
        Ok(())
    }
}
