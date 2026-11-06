//! V15: guest inner confinement and hardening per workload profile, the pure (Tier 0)
//! half of VM-W07 (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part: the VM-W07
//! row "Inner confinement and guest hardening per workload profile. No claim that guest
//! seccomp survives guest-root/kernel compromise", acceptance "Required tools work;
//! forbidden interfaces fail by intended mechanism; seccomp/LSM responsibilities
//! separated"; §1.1, §1.2, §3.4 "Guest and hypervisor hardening", §8.1, §17 and VM-CP-05;
//! VM-P05; VM-R08, VM-R55, VM-R57, VM-R65, VM-R66, VM-R71).
//!
//! Tier 0 only (§12.1): pure, synchronous library code over fakes. Nothing here installs a
//! seccomp filter, drops a capability, mounts anything, loads an LSM policy or builds a
//! kernel, and nothing here is evidence that any of that happened. The production half of
//! VM-W07 is the guest agent's inner container (`appliance/agent/container_security.go`,
//! `workload_options.go`, `microvm_workload.go`, `main.go`) and the signed guest images
//! of VM-W05; neither is touched here.
//!
//! - [`profile`]: the closed set of [`WorkloadProfile`]s VM-R65 and VM-CP-05 name (the
//!   strict tool profile, developer, service and device), each with a
//!   [`ConfinementProfile`]: a non-root uid policy, the exact typed capability set,
//!   no_new_privs, the forbidden interfaces with their mechanisms, the protected
//!   read-only paths, the required tools and the recorded exceptions. The profile is
//!   strict, bounded input, and its domain-separated digest covers every field, so an
//!   exception is a new identity, never a silent re-enable (§3.4).
//! - [`interfaces`] and [`responsibility`]: the typed [`Interface`] and [`Mechanism`]
//!   sets, the exact failure each mechanism produces for each interface, and the
//!   refusal of an assignment the mechanism cannot enforce. Seccomp matches syscall
//!   numbers and integer arguments only: it cannot dereference a path pointer or tell
//!   whose process a ptrace targets (§3.4), so path rules go to read-only mounts, the LSM
//!   or credentials, and "ptrace only this user's processes" goes to credentials or the
//!   LSM, or ptrace is denied outright. [`ResponsibilityMap`] is the separated view.
//! - [`evaluate()`]: the VM-CP-05 evaluator. The guest's probe results stay labelled
//!   [`SourceClass::GuestReport`](crate::foundation::evidence::SourceClass); host
//!   corroboration (the booted root image digest and the guest kernel build record) is
//!   compared with the signed manifest's expected values. A guest report never satisfies
//!   a host-only requirement (§8.1, §17), a missing result is inconclusive and fails a
//!   required check, and a kernel setting claimed only by a configured boot argument is
//!   never accepted as enforced (§3.4).
//! - [`residue`]: what remains after guest root or a guest kernel compromise. Only
//!   host-side boundaries remain; every inner control is defense in depth (§1.2, VM-R08,
//!   VM-P05).
//!
//! Relation to the hypervisor's confinement. `sandbox::backend::facets::ConfinementControl`
//! is the confinement of the hypervisor process on the host (VM-P04, VM-CP-04): a host
//! boundary that the host observes itself. This module is the guest's inner confinement
//! (VM-P05, VM-CP-05): restrictions inside the guest, reported by the guest and only
//! partly corroborated by the host. The two are deliberately not merged; the hypervisor
//! side appears here only as [`HostBoundary::Hypervisor`], one of the boundaries that
//! remain after a guest compromise. The policy predicate
//! `SecurityPredicate::InnerGuestConfinement` (`sandbox_contract::policy`) is the
//! requirement this contract will later back.

/// Defines an internally tagged, snake_case enum whose deserialization refuses unknown
/// fields for every variant, unit variants included. serde ignores unknown fields beside
/// the tag of a unit variant even with `deny_unknown_fields`, so reading goes through a
/// twin enum whose unit variants are empty struct variants. Copied from
/// `strict_policy_enum!` in `sandbox_contract/policy/mod.rs`, kept local.
macro_rules! strict_confinement_enum {
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

pub mod capability;
pub mod evaluate;
pub mod interfaces;
pub mod kernel;
pub mod profile;
pub mod residue;
pub mod responsibility;
pub mod text;

#[cfg(test)]
mod tests;

pub use capability::{LinuxCapability, NEVER_GRANTED};
pub use evaluate::{
    evaluate, Check, CheckOutcome, CheckVerdict, ConfinementVerdict, FailureReason,
    GuestProbeDocument, GuestReport, GuestReportRefusal, HostCorroboration, InconclusiveReason,
    InterfaceProbe, ManifestExpectation, ObservedCapabilities, PathProbe, ProbeOutcome, ReportList,
    VerdictMeaning, VerdictOutcome, MAX_GUEST_REPORT_BYTES,
};
pub use interfaces::{
    enforcement, Enforcement, Errno, ErrnoRefusal, Interface, Mechanism, RuleKind, Unenforceable,
};
pub use kernel::{
    KernelBuildRecord, KernelOption, KernelOptionEntry, KernelRecordDocument, KernelRecordRefusal,
    KernelSetting, OptionState,
};
pub use profile::{
    ConfinementException, ConfinementProfile, ExceptionTarget, PathRefusal, PathRoot,
    ProfileDocument, ProfileList, ProfileRefusal, ProtectedPath, RequiredTool, UidPolicy,
    WorkloadProfile, CONFINEMENT_PROFILE_VERSION, MAX_EXCEPTIONS, MAX_PATH_COMPONENTS,
    MAX_PROTECTED_PATHS, MAX_PROTECTED_PATH_BYTES, MAX_REQUIRED_TOOLS, REPOSITORY_PROTECTION,
};
pub use residue::{
    after_compromise, Compromise, CompromiseResidue, HostBoundary, InnerControl, ProtectionLayer,
};
pub use responsibility::{
    check_assignment, AssignmentContext, ForbiddenInterface, Responsibility, ResponsibilityMap,
    ResponsibilityRefusal, Role,
};
pub use text::{OwnerName, RecordedReason, TextRefusal, ToolName, MAX_REASON_BYTES};
