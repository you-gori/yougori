//! The verification plan: for each forbidden interface, the mechanisms that refuse it,
//! the exact errnos each one produces and who verifies it, so VM-CP-05 can be run
//! against the installed result (VM-W07 "forbidden interfaces fail by intended
//! mechanism"; VM-CP-05; §8.1 "Separate host-observed facts from guest assertions"; §17).
//!
//! Every value comes from V15: the mechanisms and their roles from the profile's
//! assignment, the errnos from [`enforcement`] narrowed to what the compiled mechanism
//! produces, and the checks from what
//! [`evaluate`](crate::sandbox_contract::confinement::evaluate()) runs. A forbidden
//! interface is verified by the guest's probe inside the inner container (one probe per
//! protected path for path writes), which stays guest-reported; an interface refused by
//! an absent kernel option is also verified by the host's kernel build record, which the
//! guest's probe can never stand in for. A step names its V15 [`Check`]s, so a caller
//! finds each one in a [`ConfinementVerdict`](crate::sandbox_contract::confinement::ConfinementVerdict).
//!
//! The errnos are the ones V15 types per mechanism, not an order of evaluation, with one
//! exception V15 states: seccomp runs at system call entry, so where it is declared the
//! probe sees its `EPERM` first. V15 types the LSM on ptrace as `EPERM` or `EACCES`
//! because AppArmor and SELinux refuse with `EACCES`; the LSM compiled here is Yama, which
//! refuses with `EPERM` only, so the plan expects `EPERM` and an `EACCES` fails the probe.
//! On a path write the compiled LSM is Landlock, with V15's `EACCES`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::foundation::evidence::SourceClass;
use crate::sandbox_contract::confinement::{
    enforcement, Check, Enforcement, Errno, ForbiddenInterface, Interface, KernelOption, Mechanism,
    ProtectedPath, Role,
};

/// One declared mechanism of a forbidden interface and the errnos its refusal produces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedMechanism {
    pub mechanism: Mechanism,
    pub role: Role,
    /// What the guest's probe sees when this mechanism refuses, as V15 types it.
    pub failures: Vec<Errno>,
}

strict_guest_policy_enum! {
    /// Who verifies a forbidden interface, and how (VM-CP-05).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Verification tag "by" {
        /// The guest probes the interface inside the inner container; guest-reported
        /// (V15 `Check::ForbiddenInterface`).
        GuestProbe,
        /// The guest probes a write to one protected path; guest-reported (V15
        /// `Check::ProtectedPathWrite`).
        GuestPathProbe { path: ProtectedPath },
        /// The host's kernel build record, agreeing with the signed manifest, shows the
        /// option absent; host-observed (V15 `Check::HostKernelOptionAbsent`).
        HostKernelRecord { option: KernelOption },
    }
}

impl Verification {
    /// Where the evidence comes from: the guest's report or the host's own observation.
    pub const fn source(&self) -> SourceClass {
        match self {
            Self::GuestProbe | Self::GuestPathProbe { .. } => SourceClass::GuestReport,
            Self::HostKernelRecord { .. } => SourceClass::HostProbe,
        }
    }

    /// The V15 check that carries this verification for `interface`.
    pub fn check(&self, interface: Interface) -> Check {
        match self {
            Self::GuestProbe => Check::ForbiddenInterface { interface },
            Self::GuestPathProbe { path } => Check::ProtectedPathWrite { path: path.clone() },
            Self::HostKernelRecord { option } => Check::HostKernelOptionAbsent { option: *option },
        }
    }
}

/// How one forbidden interface is refused and verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStep {
    pub interface: Interface,
    /// The declared mechanisms, primary first.
    pub mechanisms: Vec<PlannedMechanism>,
    /// Every errno a declared mechanism produces as compiled, sorted: the probe passes only
    /// on one of them, and success or any other errno fails it.
    pub expected_failures: Vec<Errno>,
    /// Who verifies it, guest probes first.
    pub verified_by: Vec<Verification>,
}

impl VerificationStep {
    /// The step for `entry`; `paths` are the profile's protected paths, probed one by one
    /// when `entry` is the protected-path write.
    pub fn for_entry(entry: &ForbiddenInterface, paths: &[ProtectedPath]) -> Self {
        let interface = entry.interface;
        let roles = std::iter::once((entry.primary, Role::Primary))
            .chain(entry.backup.map(|backup| (backup, Role::Backup)));
        let mechanisms: Vec<PlannedMechanism> = roles
            .map(|(mechanism, role)| PlannedMechanism {
                mechanism,
                role,
                failures: compiled_failures(mechanism, interface),
            })
            .collect();
        let expected_failures: BTreeSet<Errno> = mechanisms
            .iter()
            .flat_map(|planned| planned.failures.iter().copied())
            .collect();
        let mut verified_by: Vec<Verification> = if interface == Interface::ProtectedPathWrite {
            paths
                .iter()
                .map(|path| Verification::GuestPathProbe { path: path.clone() })
                .collect()
        } else {
            vec![Verification::GuestProbe]
        };
        if entry.uses(Mechanism::KernelOptionAbsent) {
            verified_by.extend(
                interface
                    .kernel_options()
                    .iter()
                    .map(|option| Verification::HostKernelRecord { option: *option }),
            );
        }
        Self {
            interface,
            mechanisms,
            expected_failures: expected_failures.into_iter().collect(),
            verified_by,
        }
    }

    /// The V15 checks of this step, in order.
    pub fn checks(&self) -> Vec<Check> {
        self.verified_by
            .iter()
            .map(|verification| verification.check(self.interface))
            .collect()
    }

    /// The declared mechanisms, primary first.
    pub fn declared(&self) -> Vec<Mechanism> {
        self.mechanisms
            .iter()
            .map(|planned| planned.mechanism)
            .collect()
    }
}

/// The errnos V15 types for `mechanism` refusing `interface`, narrowed to those the
/// compiled mechanism produces: Yama refuses ptrace with `EPERM` only (see the module
/// notes). Never an errno V15 does not type.
fn compiled_failures(mechanism: Mechanism, interface: Interface) -> Vec<Errno> {
    let Enforcement::Enforces(failures) = enforcement(mechanism, interface) else {
        return Vec::new();
    };
    let yama = mechanism == Mechanism::Lsm
        && matches!(interface, Interface::Ptrace | Interface::PtraceOtherUsers);
    failures
        .iter()
        .copied()
        .filter(|errno| !yama || *errno == Errno::EPERM)
        .collect()
}
