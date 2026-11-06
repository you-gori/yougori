//! Forbidden interfaces, the mechanisms that can refuse them, and the exact failure each
//! mechanism produces (VM-W07 "forbidden interfaces fail by intended mechanism;
//! seccomp/LSM responsibilities separated"; §3.4; VM-CP-05; VM-R55, VM-R56, VM-R57).
//!
//! [`enforcement`] is the one table. For each (mechanism, interface) pair it states
//! either the errno the guest's probe sees when that mechanism refuses the interface, or
//! why the mechanism cannot enforce it. The VM-CP-05 values are pinned: `io_uring_setup`
//! fails with `ENOSYS` when the option is absent from the kernel and `EPERM` from seccomp,
//! `socket(AF_VSOCK)` with `EPERM`, and a protected-path write with `EROFS` or `EACCES`.
//!
//! Seccomp's denial is fixed to `SCMP_ACT_ERRNO(EPERM)` here, the errno VM-CP-05 expects
//! from seccomp, so a seccomp refusal is attributable: a rule returning `ENOSYS` would
//! look like an absent kernel option. Seccomp runs at system call entry, before the
//! kernel looks the call up, so when both an absent option and a seccomp rule cover one
//! interface the probe sees seccomp's `EPERM`. The host's kernel build record, not the
//! errno, shows the option absent.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::capability::LinuxCapability;
use super::kernel::KernelOption;

/// An interface a workload profile can forbid (VM-R55, VM-R56, VM-R57; §3.4; VM-CP-05).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Interface {
    /// `io_uring_setup`, `io_uring_enter` and `io_uring_register` (VM-R55).
    IoUring,
    /// The bpf(2) system call (VM-R57).
    Bpf,
    /// userfaultfd(2) (VM-R57).
    Userfaultfd,
    /// perf_event_open(2) (VM-R57).
    PerfEventOpen,
    /// `kexec_load` and `kexec_file_load` (VM-R57).
    Kexec,
    /// `init_module` and `finit_module` (§3.4 "unneeded modules").
    ModuleLoading,
    /// ptrace(2) of any process, the profile's own included: "deny ptrace for the
    /// relevant profile" (§3.4).
    Ptrace,
    /// ptrace(2) of a process owned by another user: the policy "ptrace only processes
    /// owned by this user" (§3.4), which seccomp cannot express.
    PtraceOtherUsers,
    /// `socket(AF_VSOCK, ...)` from the workload (VM-R56, VM-CP-05).
    VsockSocket,
    /// A write to a protected read-only path such as `~/.bashrc` or `.git/hooks/`
    /// (VM-CP-05).
    ProtectedPathWrite,
}

impl Interface {
    /// Every interface.
    pub const ALL: [Self; 10] = [
        Self::IoUring,
        Self::Bpf,
        Self::Userfaultfd,
        Self::PerfEventOpen,
        Self::Kexec,
        Self::ModuleLoading,
        Self::Ptrace,
        Self::PtraceOtherUsers,
        Self::VsockSocket,
        Self::ProtectedPathWrite,
    ];

    /// The snake_case label used in records and digests.
    pub const fn label(self) -> &'static str {
        match self {
            Self::IoUring => "io_uring",
            Self::Bpf => "bpf",
            Self::Userfaultfd => "userfaultfd",
            Self::PerfEventOpen => "perf_event_open",
            Self::Kexec => "kexec",
            Self::ModuleLoading => "module_loading",
            Self::Ptrace => "ptrace",
            Self::PtraceOtherUsers => "ptrace_other_users",
            Self::VsockSocket => "vsock_socket",
            Self::ProtectedPathWrite => "protected_path_write",
        }
    }

    /// The call the guest's probe makes inside the inner container (VM-CP-05).
    pub const fn probe(self) -> &'static str {
        match self {
            Self::IoUring => "io_uring_setup(1, &params)",
            Self::Bpf => "bpf(BPF_PROG_LOAD, ...)",
            Self::Userfaultfd => "userfaultfd(O_CLOEXEC)",
            Self::PerfEventOpen => "perf_event_open(&attr, 0, -1, -1, 0)",
            Self::Kexec => "kexec_file_load(...)",
            Self::ModuleLoading => "finit_module(...)",
            Self::Ptrace => "ptrace(PTRACE_ATTACH) of a child it started",
            Self::PtraceOtherUsers => "ptrace(PTRACE_ATTACH) of a process another uid owns",
            Self::VsockSocket => "socket(AF_VSOCK, SOCK_STREAM, 0)",
            Self::ProtectedPathWrite => "open(path, O_WRONLY | O_CREAT) on each protected path",
        }
    }

    /// The build options whose absence removes the interface from the kernel; empty when
    /// no build option does.
    pub const fn kernel_options(self) -> &'static [KernelOption] {
        match self {
            Self::IoUring => &[KernelOption::IoUring],
            Self::Bpf => &[KernelOption::BpfSyscall],
            Self::Userfaultfd => &[KernelOption::Userfaultfd],
            Self::PerfEventOpen => &[KernelOption::PerfEvents],
            Self::Kexec => &[KernelOption::Kexec, KernelOption::KexecFile],
            Self::ModuleLoading => &[KernelOption::Modules],
            Self::VsockSocket => &[KernelOption::Vsockets],
            Self::Ptrace | Self::PtraceOtherUsers | Self::ProtectedPathWrite => &[],
        }
    }

    /// Capabilities that exist to grant this interface. A profile that forbids the
    /// interface may not hold one: that would grant and forbid the same thing.
    pub const fn granting_capabilities(self) -> &'static [LinuxCapability] {
        match self {
            Self::Bpf => &[LinuxCapability::Bpf, LinuxCapability::SysAdmin],
            Self::PerfEventOpen => &[LinuxCapability::Perfmon, LinuxCapability::SysAdmin],
            Self::Kexec => &[LinuxCapability::SysBoot],
            Self::ModuleLoading => &[LinuxCapability::SysModule],
            Self::Ptrace | Self::PtraceOtherUsers | Self::Userfaultfd => {
                &[LinuxCapability::SysPtrace]
            }
            Self::IoUring | Self::VsockSocket | Self::ProtectedPathWrite => &[],
        }
    }
}

impl fmt::Display for Interface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A mechanism inside the guest that can refuse an interface (§3.4: "Guest seccomp,
/// capabilities and LSM restrictions are layered controls"). Every one is an inner
/// control: defense in depth that guest root or a guest kernel compromise can bypass
/// (§1.2, VM-R08; see [`super::residue`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mechanism {
    /// The guest kernel was built without the feature. Only this one has host-side
    /// evidence: the kernel build record bound to the booted kernel image (VM-CP-05).
    KernelOptionAbsent,
    /// A seccomp filter on system call numbers and integer arguments.
    Seccomp,
    /// The workload lacks the capability the kernel checks.
    CapabilityAbsence,
    /// A Linux security module policy (AppArmor, SELinux, Landlock, Yama).
    Lsm,
    /// The path is on a read-only mount.
    ReadOnlyMount,
    /// Credential and namespace separation: another uid owns the object, and the
    /// workload cannot become that uid.
    NamespaceCredentials,
}

impl Mechanism {
    /// Every mechanism.
    pub const ALL: [Self; 6] = [
        Self::KernelOptionAbsent,
        Self::Seccomp,
        Self::CapabilityAbsence,
        Self::Lsm,
        Self::ReadOnlyMount,
        Self::NamespaceCredentials,
    ];

    /// The snake_case label used in records and digests.
    pub const fn label(self) -> &'static str {
        match self {
            Self::KernelOptionAbsent => "kernel_option_absent",
            Self::Seccomp => "seccomp",
            Self::CapabilityAbsence => "capability_absence",
            Self::Lsm => "lsm",
            Self::ReadOnlyMount => "read_only_mount",
            Self::NamespaceCredentials => "namespace_credentials",
        }
    }

    /// What kind of rule the mechanism expresses; the basis of the separation of
    /// responsibilities (§3.4).
    pub const fn rule_kind(self) -> RuleKind {
        match self {
            Self::KernelOptionAbsent => RuleKind::KernelBuild,
            Self::Seccomp => RuleKind::SyscallNumberAndIntegerArguments,
            Self::CapabilityAbsence => RuleKind::CapabilityCheck,
            Self::Lsm => RuleKind::ObjectAndPathPolicy,
            Self::ReadOnlyMount => RuleKind::MountFlags,
            Self::NamespaceCredentials => RuleKind::CredentialsAndOwnership,
        }
    }

    /// Capabilities that would let the workload lift this mechanism for `interface`. A
    /// profile that relies on the mechanism may not hold any of them.
    pub const fn defeating_capabilities(self, interface: Interface) -> &'static [LinuxCapability] {
        use LinuxCapability as C;
        match (self, interface) {
            // A loaded module can add kernel code back.
            (Self::KernelOptionAbsent, _) => &[C::SysModule],
            // No capability removes an installed filter.
            (Self::Seccomp, _) => &[],
            (Self::CapabilityAbsence, Interface::Kexec) => &[C::SysBoot],
            (Self::CapabilityAbsence, Interface::ModuleLoading) => &[C::SysModule],
            // Becoming the target's uid sidesteps the missing CAP_SYS_PTRACE.
            (Self::CapabilityAbsence, Interface::PtraceOtherUsers) => {
                &[C::SysPtrace, C::Setuid, C::Setgid]
            }
            (Self::CapabilityAbsence, _) => &[],
            (Self::Lsm, _) => &[C::MacAdmin, C::MacOverride, C::SysAdmin],
            // Remounting read-write needs CAP_SYS_ADMIN.
            (Self::ReadOnlyMount, _) => &[C::SysAdmin],
            (Self::NamespaceCredentials, Interface::PtraceOtherUsers) => {
                &[C::SysPtrace, C::Setuid, C::Setgid]
            }
            // DAC bypass, ownership changes, or becoming the owner.
            (Self::NamespaceCredentials, Interface::ProtectedPathWrite) => {
                &[C::DacOverride, C::Fowner, C::Chown, C::Setuid, C::Setgid]
            }
            (Self::NamespaceCredentials, _) => &[],
        }
    }

    /// Whether the mechanism depends on the workload's credentials staying fixed, so a
    /// setuid or file-capability program could undo it unless no_new_privs is set.
    pub const fn needs_no_new_privs(self) -> bool {
        matches!(self, Self::NamespaceCredentials)
    }
}

impl fmt::Display for Mechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// What a mechanism's rules can look at (§3.4: seccomp "cannot generally dereference
/// pointers or express policies such as 'ptrace only processes owned by this user'").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    /// Whether code exists in the kernel at all.
    KernelBuild,
    /// The system call number and its integer arguments; never memory a pointer names.
    SyscallNumberAndIntegerArguments,
    /// A capability check the kernel makes inside the call.
    CapabilityCheck,
    /// Paths, labels and target processes.
    ObjectAndPathPolicy,
    /// Mount flags of the filesystem holding a path.
    MountFlags,
    /// The uid and namespaces that own an object.
    CredentialsAndOwnership,
}

/// A Linux errno in the asm-generic numbering that x86_64 and aarch64 guests share. Any
/// number in 1–4095 is representable, so a guest's unexpected errno is kept, not refused.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct Errno(u16);

impl Errno {
    pub const EPERM: Self = Self(1);
    pub const ENOENT: Self = Self(2);
    pub const EBADF: Self = Self(9);
    pub const EACCES: Self = Self(13);
    pub const EFAULT: Self = Self(14);
    pub const EBUSY: Self = Self(16);
    pub const EINVAL: Self = Self(22);
    pub const EROFS: Self = Self(30);
    pub const ENOSYS: Self = Self(38);
    pub const EPROTONOSUPPORT: Self = Self(93);
    pub const EOPNOTSUPP: Self = Self(95);
    pub const EAFNOSUPPORT: Self = Self(97);
    /// The largest errno the kernel returns (`MAX_ERRNO`).
    pub const MAX: u16 = 4095;

    /// An errno number in 1–[`Errno::MAX`].
    pub fn new(number: u16) -> Result<Self, ErrnoRefusal> {
        if number == 0 || number > Self::MAX {
            return Err(ErrnoRefusal { number });
        }
        Ok(Self(number))
    }

    /// The number.
    pub const fn number(self) -> u16 {
        self.0
    }

    /// The symbolic name of the errnos this contract names.
    pub const fn name(self) -> Option<&'static str> {
        match self.0 {
            1 => Some("EPERM"),
            2 => Some("ENOENT"),
            9 => Some("EBADF"),
            13 => Some("EACCES"),
            14 => Some("EFAULT"),
            16 => Some("EBUSY"),
            22 => Some("EINVAL"),
            30 => Some("EROFS"),
            38 => Some("ENOSYS"),
            93 => Some("EPROTONOSUPPORT"),
            95 => Some("EOPNOTSUPP"),
            97 => Some("EAFNOSUPPORT"),
            _ => None,
        }
    }
}

impl fmt::Debug for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} ({})", self.0),
            None => write!(f, "errno {}", self.0),
        }
    }
}

impl TryFrom<u16> for Errno {
    type Error = ErrnoRefusal;

    fn try_from(number: u16) -> Result<Self, Self::Error> {
        Self::new(number)
    }
}

impl From<Errno> for u16 {
    fn from(errno: Errno) -> Self {
        errno.0
    }
}

/// A number that is not an errno: zero, or above [`Errno::MAX`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrnoRefusal {
    pub number: u16,
}

impl fmt::Display for ErrnoRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} is not an errno; errnos are 1 to {}",
            self.number,
            Errno::MAX
        )
    }
}

impl std::error::Error for ErrnoRefusal {}

/// Whether a mechanism can refuse an interface, and how the refusal looks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enforcement {
    /// The mechanism refuses the interface; the probe sees one of these errnos.
    Enforces(&'static [Errno]),
    /// The mechanism cannot enforce the interface.
    CannotEnforce(Unenforceable),
}

/// Why a mechanism cannot enforce an interface (§3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unenforceable {
    /// The rule needs a path, which a system call passes as a pointer seccomp cannot
    /// dereference (§3.4).
    SeccompCannotDereferencePointers,
    /// The rule depends on who owns the target process, which a syscall-number list
    /// cannot express (§3.4 "ptrace only processes owned by this user").
    SeccompCannotInspectTarget,
    /// No kernel build option removes the interface.
    NoKernelOption,
    /// Removing the option removes the interface for every process, the trusted guest
    /// agent's AF_VSOCK channel included; the workload restriction must be per process
    /// (VM-R56).
    KernelOptionNotPerProcess,
    /// The kernel checks no capability for the interface.
    NoCapabilityGate,
    /// Unprivileged use stays available under kernel sysctls, so a missing capability
    /// alone does not refuse it (VM-R57).
    UnprivilegedUseRemains,
    /// Tracing one's own processes needs neither a capability nor another uid.
    SameUserNeedsNoCapability,
    /// The mechanism does not cover this kind of interface, such as a mount for a system
    /// call.
    NotApplicable,
    /// Syscall-number rules are seccomp's responsibility, not the LSM's (§3.4: the
    /// responsibilities are separated).
    NotAssigned,
}

impl fmt::Display for Unenforceable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SeccompCannotDereferencePointers => {
                "seccomp cannot dereference the path pointer a system call passes"
            }
            Self::SeccompCannotInspectTarget => {
                "seccomp cannot tell which user owns the process a ptrace targets"
            }
            Self::NoKernelOption => "no kernel build option removes this interface",
            Self::KernelOptionNotPerProcess => {
                "removing the kernel option also removes the guest agent's AF_VSOCK channel"
            }
            Self::NoCapabilityGate => "the kernel checks no capability for this interface",
            Self::UnprivilegedUseRemains => {
                "unprivileged use remains available without the capability"
            }
            Self::SameUserNeedsNoCapability => {
                "tracing one's own processes needs no capability or other uid"
            }
            Self::NotApplicable => "the mechanism does not cover this kind of interface",
            Self::NotAssigned => "syscall-number rules are seccomp's responsibility",
        })
    }
}

const EPERM: &[Errno] = &[Errno::EPERM];
const ENOSYS: &[Errno] = &[Errno::ENOSYS];
const EACCES: &[Errno] = &[Errno::EACCES];
const EROFS: &[Errno] = &[Errno::EROFS];
/// Yama refuses ptrace with `EPERM`; AppArmor and SELinux with `EACCES`.
const EPERM_OR_EACCES: &[Errno] = &[Errno::EPERM, Errno::EACCES];

/// Whether `mechanism` can refuse `interface`, and the errnos its refusal produces
/// (§3.4; VM-CP-05).
pub const fn enforcement(mechanism: Mechanism, interface: Interface) -> Enforcement {
    use Enforcement::{CannotEnforce, Enforces};
    use Interface as I;
    use Mechanism as M;
    use Unenforceable as U;
    match (mechanism, interface) {
        (
            M::KernelOptionAbsent,
            I::IoUring | I::Bpf | I::Userfaultfd | I::PerfEventOpen | I::Kexec | I::ModuleLoading,
        ) => Enforces(ENOSYS),
        (M::KernelOptionAbsent, I::VsockSocket) => CannotEnforce(U::KernelOptionNotPerProcess),
        (M::KernelOptionAbsent, I::Ptrace | I::PtraceOtherUsers | I::ProtectedPathWrite) => {
            CannotEnforce(U::NoKernelOption)
        }
        (
            M::Seccomp,
            I::IoUring
            | I::Bpf
            | I::Userfaultfd
            | I::PerfEventOpen
            | I::Kexec
            | I::ModuleLoading
            | I::Ptrace
            | I::VsockSocket,
        ) => Enforces(EPERM),
        (M::Seccomp, I::PtraceOtherUsers) => CannotEnforce(U::SeccompCannotInspectTarget),
        (M::Seccomp, I::ProtectedPathWrite) => CannotEnforce(U::SeccompCannotDereferencePointers),
        (M::CapabilityAbsence, I::Kexec | I::ModuleLoading | I::PtraceOtherUsers) => {
            Enforces(EPERM)
        }
        (M::CapabilityAbsence, I::Bpf | I::Userfaultfd | I::PerfEventOpen) => {
            CannotEnforce(U::UnprivilegedUseRemains)
        }
        (M::CapabilityAbsence, I::Ptrace) => CannotEnforce(U::SameUserNeedsNoCapability),
        (M::CapabilityAbsence, I::IoUring | I::VsockSocket | I::ProtectedPathWrite) => {
            CannotEnforce(U::NoCapabilityGate)
        }
        (M::Lsm, I::Ptrace | I::PtraceOtherUsers) => Enforces(EPERM_OR_EACCES),
        (M::Lsm, I::ProtectedPathWrite) => Enforces(EACCES),
        (M::Lsm, _) => CannotEnforce(U::NotAssigned),
        (M::ReadOnlyMount, I::ProtectedPathWrite) => Enforces(EROFS),
        (M::ReadOnlyMount, _) => CannotEnforce(U::NotApplicable),
        (M::NamespaceCredentials, I::PtraceOtherUsers) => Enforces(EPERM),
        (M::NamespaceCredentials, I::ProtectedPathWrite) => Enforces(EACCES),
        (M::NamespaceCredentials, I::Ptrace) => CannotEnforce(U::SameUserNeedsNoCapability),
        (M::NamespaceCredentials, _) => CannotEnforce(U::NotApplicable),
    }
}
