//! The guest kernel build record and the kernel settings it can force (VM-CP-05 "the
//! kernel build record (`CONFIG_IO_URING` absent) match the signed manifest"; §3.4 "a
//! configured boot argument is not evidence the kernel enforced it"; VM-R71 "Kernel
//! lockdown and securebits").
//!
//! A build record states, option by option, how one kernel image was built. It is bound
//! to that image's digest: the host computes the digest of the kernel it hands to the
//! hypervisor, so the record is host-side evidence about the guest kernel. An option the
//! record does not list is unknown, never assumed absent.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::Digest;

/// A kernel build option this contract reads (VM-CP-05; §3.4; VM-R55, VM-R57, VM-R71).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum KernelOption {
    /// io_uring (VM-R55).
    #[serde(rename = "CONFIG_IO_URING")]
    IoUring,
    /// The bpf(2) system call (VM-R57).
    #[serde(rename = "CONFIG_BPF_SYSCALL")]
    BpfSyscall,
    /// userfaultfd(2) (VM-R57).
    #[serde(rename = "CONFIG_USERFAULTFD")]
    Userfaultfd,
    /// perf_event_open(2) (VM-R57).
    #[serde(rename = "CONFIG_PERF_EVENTS")]
    PerfEvents,
    /// kexec_load(2) (VM-R57).
    #[serde(rename = "CONFIG_KEXEC")]
    Kexec,
    /// kexec_file_load(2) (VM-R57).
    #[serde(rename = "CONFIG_KEXEC_FILE")]
    KexecFile,
    /// Loadable modules (§3.4 "unneeded modules").
    #[serde(rename = "CONFIG_MODULES")]
    Modules,
    /// AF_VSOCK sockets, which the trusted guest agent's host channel needs (VM-R56).
    #[serde(rename = "CONFIG_VSOCKETS")]
    Vsockets,
    /// Lockdown forced to integrity mode at build time (VM-R71).
    #[serde(rename = "CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY")]
    LockDownForceIntegrity,
    /// Lockdown forced to confidentiality mode at build time (VM-R71).
    #[serde(rename = "CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY")]
    LockDownForceConfidentiality,
    /// Module signatures enforced at build time (§3.4 "controlled signed-module profile").
    #[serde(rename = "CONFIG_MODULE_SIG_FORCE")]
    ModuleSigForce,
}

impl KernelOption {
    /// Every option.
    pub const ALL: [Self; 11] = [
        Self::IoUring,
        Self::BpfSyscall,
        Self::Userfaultfd,
        Self::PerfEvents,
        Self::Kexec,
        Self::KexecFile,
        Self::Modules,
        Self::Vsockets,
        Self::LockDownForceIntegrity,
        Self::LockDownForceConfidentiality,
        Self::ModuleSigForce,
    ];

    /// The Kconfig name, such as `CONFIG_IO_URING`.
    pub const fn config_name(self) -> &'static str {
        match self {
            Self::IoUring => "CONFIG_IO_URING",
            Self::BpfSyscall => "CONFIG_BPF_SYSCALL",
            Self::Userfaultfd => "CONFIG_USERFAULTFD",
            Self::PerfEvents => "CONFIG_PERF_EVENTS",
            Self::Kexec => "CONFIG_KEXEC",
            Self::KexecFile => "CONFIG_KEXEC_FILE",
            Self::Modules => "CONFIG_MODULES",
            Self::Vsockets => "CONFIG_VSOCKETS",
            Self::LockDownForceIntegrity => "CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY",
            Self::LockDownForceConfidentiality => "CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY",
            Self::ModuleSigForce => "CONFIG_MODULE_SIG_FORCE",
        }
    }
}

impl fmt::Display for KernelOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.config_name())
    }
}

/// How one option was built.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionState {
    /// `# CONFIG_... is not set`: the feature is absent from the kernel.
    NotSet,
    /// `=y`: built into the kernel.
    BuiltIn,
    /// `=m`: built as a loadable module.
    Module,
}

impl OptionState {
    /// Whether the feature is absent from the kernel.
    pub const fn is_absent(self) -> bool {
        matches!(self, Self::NotSet)
    }
}

/// One option and its state, as written in a record or a guest's claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelOptionEntry {
    pub option: KernelOption,
    pub state: OptionState,
}

/// Why a build record was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelRecordRefusal {
    /// One option listed twice; a record states each option once.
    DuplicateOption { option: KernelOption },
}

impl fmt::Display for KernelRecordRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateOption { option } => {
                write!(f, "the kernel build record lists {option} more than once")
            }
        }
    }
}

impl std::error::Error for KernelRecordRefusal {}

/// The serialized form of a [`KernelBuildRecord`]: options as a list, so a duplicate is
/// refused rather than silently overwritten.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelRecordDocument {
    pub kernel_image: Digest,
    pub options: Vec<KernelOptionEntry>,
}

/// How one guest kernel image was built (VM-CP-05 "kernel build record"), bound to the
/// image's digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "KernelRecordDocument", into = "KernelRecordDocument")]
pub struct KernelBuildRecord {
    kernel_image: Digest,
    options: BTreeMap<KernelOption, OptionState>,
}

impl KernelBuildRecord {
    /// A record for the kernel image with digest `kernel_image`. Each option may be
    /// listed once.
    pub fn new(
        kernel_image: Digest,
        options: impl IntoIterator<Item = (KernelOption, OptionState)>,
    ) -> Result<Self, KernelRecordRefusal> {
        let mut map = BTreeMap::new();
        for (option, state) in options {
            if map.insert(option, state).is_some() {
                return Err(KernelRecordRefusal::DuplicateOption { option });
            }
        }
        Ok(Self {
            kernel_image,
            options: map,
        })
    }

    /// The digest of the kernel image the record describes.
    pub const fn kernel_image(&self) -> Digest {
        self.kernel_image
    }

    /// How `option` was built; `None` when the record does not list it (unknown, never
    /// assumed absent).
    pub fn state(&self, option: KernelOption) -> Option<OptionState> {
        self.options.get(&option).copied()
    }

    /// Every listed option, in order.
    pub fn options(&self) -> impl Iterator<Item = (KernelOption, OptionState)> + '_ {
        self.options.iter().map(|(option, state)| (*option, *state))
    }
}

impl TryFrom<KernelRecordDocument> for KernelBuildRecord {
    type Error = KernelRecordRefusal;

    fn try_from(document: KernelRecordDocument) -> Result<Self, Self::Error> {
        Self::new(
            document.kernel_image,
            document
                .options
                .into_iter()
                .map(|entry| (entry.option, entry.state)),
        )
    }
}

impl From<KernelBuildRecord> for KernelRecordDocument {
    fn from(record: KernelBuildRecord) -> Self {
        Self {
            kernel_image: record.kernel_image,
            options: record
                .options
                .into_iter()
                .map(|(option, state)| KernelOptionEntry { option, state })
                .collect(),
        }
    }
}

/// A kernel setting a profile may require (VM-R71; §3.4 "Document whether lockdown mode
/// changes behavior; a configured boot argument is not evidence the kernel enforced it").
///
/// A setting counts as enforced only when the host's build record shows it forced at
/// build time ([`KernelSetting::forced_by`]). A `lockdown=` boot argument the host
/// configured, or a guest's report of `/sys/kernel/security/lockdown`, is never accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelSetting {
    /// Lockdown in integrity mode, or stronger.
    LockdownIntegrity,
    /// Lockdown in confidentiality mode.
    LockdownConfidentiality,
    /// Only signed modules load.
    ModuleSignaturesEnforced,
    /// Locked securebits (`SECBIT_NOROOT` and friends) on the workload's processes. They
    /// are per-process state the inner runtime sets; no build record shows them, so a
    /// profile cannot require them here (VM-R71: evaluate and record).
    SecurebitsLocked,
}

impl KernelSetting {
    /// Every setting.
    pub const ALL: [Self; 4] = [
        Self::LockdownIntegrity,
        Self::LockdownConfidentiality,
        Self::ModuleSignaturesEnforced,
        Self::SecurebitsLocked,
    ];

    /// The build options any one of which, built in, forces the setting. Empty when no
    /// host-side build fact can establish it.
    pub const fn forced_by(self) -> &'static [KernelOption] {
        match self {
            Self::LockdownIntegrity => &[
                KernelOption::LockDownForceIntegrity,
                KernelOption::LockDownForceConfidentiality,
            ],
            Self::LockdownConfidentiality => &[KernelOption::LockDownForceConfidentiality],
            Self::ModuleSignaturesEnforced => &[KernelOption::ModuleSigForce],
            Self::SecurebitsLocked => &[],
        }
    }

    /// The snake_case label used in records.
    pub const fn label(self) -> &'static str {
        match self {
            Self::LockdownIntegrity => "lockdown_integrity",
            Self::LockdownConfidentiality => "lockdown_confidentiality",
            Self::ModuleSignaturesEnforced => "module_signatures_enforced",
            Self::SecurebitsLocked => "securebits_locked",
        }
    }
}

impl fmt::Display for KernelSetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}
