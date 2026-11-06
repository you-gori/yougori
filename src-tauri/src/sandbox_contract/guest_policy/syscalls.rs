//! The system calls behind each interface V15 can hand to seccomp, the integer arguments
//! the seccomp layer filters on, and the one way around a seccomp rule this compiler knows
//! (VM-W07 "seccomp/LSM responsibilities separated"; §3.4 "Seccomp cannot generally
//! dereference pointers"; VM-R55, VM-R56, VM-R57).
//!
//! The calls are the ones V15's [`Interface`] notes name, by their kernel names, which
//! libseccomp resolves per architecture; x86_64 and aarch64 both have every one. Two more
//! entry points reach the same kernel objects and are refused with them:
//! - ptrace: process_vm_readv(2), process_vm_writev(2) and pidfd_getfd(2) read another
//!   process's memory or take its file descriptors under the same ptrace access check
//!   (`PTRACE_MODE_ATTACH_REALCREDS`), so refusing ptrace(2) alone would leave them.
//! - userfaultfd: since Linux 6.1 `/dev/userfaultfd` hands out a userfaultfd through
//!   `ioctl(fd, USERFAULTFD_IOC_NEW, flags)` without userfaultfd(2), so that ioctl request
//!   is refused too. The device path itself cannot be named in seccomp.
//!
//! Two rules need an argument: socket(2)'s `int domain` equal to `AF_VSOCK`, and ioctl(2)'s
//! request equal to `USERFAULTFD_IOC_NEW` (the kernel declares it `unsigned int cmd`). For
//! both the kernel reads only the low 32 bits of the register, so the rule masks the upper
//! half (mask `0xffffffff`), as the guest agent's ioctl rules do; an unmasked comparison
//! would let a caller set upper bits the kernel ignores and pass.
//!
//! No rule here reads memory a pointer names. A path, or the owner of the process a
//! ptrace targets, cannot be expressed, so [`seccomp_matches`] has nothing for
//! `ptrace_other_users` or `protected_path_write`; V15 already refuses those assignments.
//!
//! Around seccomp. io_uring submissions run in the kernel without passing system call
//! entry, so seccomp never sees them. Of the calls above only socket(2) has an io_uring
//! operation (`IORING_OP_SOCKET`, Linux 5.19); nothing in io_uring loads a BPF program,
//! creates a userfaultfd, opens a perf event, loads a kernel or a module, or traces a
//! process, and an ioctl still goes through ioctl(2). [`SECCOMP_BYPASSES`] records it,
//! and the compiler refuses a profile that leaves io_uring available while AF_VSOCK rests
//! on seccomp alone. Mechanisms other than seccomp act on the kernel object with the
//! submitter's credentials, so io_uring does not get past them.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::sandbox_contract::confinement::Interface;

/// A system call the seccomp layer can refuse, serialized as its kernel name, such as
/// `io_uring_setup`. Declared in name order, so sorting sorts by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Syscall {
    /// bpf(2).
    Bpf,
    /// finit_module(2).
    FinitModule,
    /// init_module(2).
    InitModule,
    /// io_uring_enter(2).
    IoUringEnter,
    /// io_uring_register(2).
    IoUringRegister,
    /// io_uring_setup(2).
    IoUringSetup,
    /// ioctl(2), refused only for one request.
    Ioctl,
    /// kexec_file_load(2).
    KexecFileLoad,
    /// kexec_load(2).
    KexecLoad,
    /// perf_event_open(2).
    PerfEventOpen,
    /// pidfd_getfd(2).
    PidfdGetfd,
    /// process_vm_readv(2).
    ProcessVmReadv,
    /// process_vm_writev(2).
    ProcessVmWritev,
    /// ptrace(2).
    Ptrace,
    /// socket(2), refused only for one domain.
    Socket,
    /// userfaultfd(2).
    Userfaultfd,
}

impl Syscall {
    /// Every system call this contract names.
    pub const ALL: [Self; 16] = [
        Self::Bpf,
        Self::FinitModule,
        Self::InitModule,
        Self::IoUringEnter,
        Self::IoUringRegister,
        Self::IoUringSetup,
        Self::Ioctl,
        Self::KexecFileLoad,
        Self::KexecLoad,
        Self::PerfEventOpen,
        Self::PidfdGetfd,
        Self::ProcessVmReadv,
        Self::ProcessVmWritev,
        Self::Ptrace,
        Self::Socket,
        Self::Userfaultfd,
    ];

    /// The kernel's name, as libseccomp and the OCI runtime spec spell it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bpf => "bpf",
            Self::FinitModule => "finit_module",
            Self::InitModule => "init_module",
            Self::IoUringEnter => "io_uring_enter",
            Self::IoUringRegister => "io_uring_register",
            Self::IoUringSetup => "io_uring_setup",
            Self::Ioctl => "ioctl",
            Self::KexecFileLoad => "kexec_file_load",
            Self::KexecLoad => "kexec_load",
            Self::PerfEventOpen => "perf_event_open",
            Self::PidfdGetfd => "pidfd_getfd",
            Self::ProcessVmReadv => "process_vm_readv",
            Self::ProcessVmWritev => "process_vm_writev",
            Self::Ptrace => "ptrace",
            Self::Socket => "socket",
            Self::Userfaultfd => "userfaultfd",
        }
    }
}

impl fmt::Display for Syscall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A 32-bit integer argument of a system call: never a pointer, so seccomp sees its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IntegerArgument {
    /// The system call it belongs to.
    pub syscall: Syscall,
    /// Its position, from 0.
    pub index: u32,
    /// The C parameter name, for messages.
    pub name: &'static str,
}

impl IntegerArgument {
    /// The bits of the argument register the kernel reads for a 32-bit argument.
    pub const INT_MASK: u64 = 0xffff_ffff;
}

/// socket(2)'s `int domain`.
pub const SOCKET_DOMAIN: IntegerArgument = IntegerArgument {
    syscall: Syscall::Socket,
    index: 0,
    name: "domain",
};

/// ioctl(2)'s request, `unsigned int cmd` in the kernel's `SYSCALL_DEFINE3(ioctl, ...)`.
pub const IOCTL_REQUEST: IntegerArgument = IntegerArgument {
    syscall: Syscall::Ioctl,
    index: 1,
    name: "request",
};

/// `AF_VSOCK`, the same on every Linux architecture (`include/linux/socket.h`).
pub const AF_VSOCK: u32 = 40;

/// `_IO(type, nr)` of `include/uapi/asm-generic/ioctl.h`, which x86_64 and arm64 both
/// use: `_IOC(_IOC_NONE, type, nr, 0)`, that is `(dir << 30) | (size << 16) | (type << 8)
/// | nr` with `_IOC_NONE` 0 and size 0.
const fn ioctl_none(kind: u32, number: u32) -> u32 {
    const IOC_NONE: u32 = 0;
    const SIZE: u32 = 0;
    (IOC_NONE << 30) | (SIZE << 16) | (kind << 8) | number
}

/// `USERFAULTFD_IOC_NEW`, from `include/uapi/linux/userfaultfd.h` (Linux 6.1):
/// `#define USERFAULTFD_IOC 0xAA` and `#define USERFAULTFD_IOC_NEW _IO(USERFAULTFD_IOC,
/// 0x00)`, so `0xAA00`. Another driver's ioctl with this number would be refused too,
/// which narrows and never widens.
pub const USERFAULTFD_IOC_NEW: u32 = ioctl_none(0xAA, 0x00);

/// One rule shape the seccomp layer matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeccompMatch {
    /// Every call of these system calls, in name order.
    Calls(&'static [Syscall]),
    /// Calls whose 32-bit integer `argument` equals `value`.
    Argument {
        argument: IntegerArgument,
        value: u32,
    },
}

impl SeccompMatch {
    /// The system calls the match names, in name order.
    pub fn syscalls(self) -> Vec<Syscall> {
        match self {
            Self::Calls(calls) => calls.to_vec(),
            Self::Argument { argument, .. } => vec![argument.syscall],
        }
    }
}

/// What seccomp matches to refuse `interface`, one entry per rule; empty for an interface
/// seccomp cannot refuse, because the rule needs a pointer dereferenced or a target
/// process's owner.
pub const fn seccomp_matches(interface: Interface) -> &'static [SeccompMatch] {
    use Syscall as S;
    match interface {
        Interface::IoUring => &[SeccompMatch::Calls(&[
            S::IoUringEnter,
            S::IoUringRegister,
            S::IoUringSetup,
        ])],
        Interface::Bpf => &[SeccompMatch::Calls(&[S::Bpf])],
        Interface::Userfaultfd => &[
            SeccompMatch::Calls(&[S::Userfaultfd]),
            SeccompMatch::Argument {
                argument: IOCTL_REQUEST,
                value: USERFAULTFD_IOC_NEW,
            },
        ],
        Interface::PerfEventOpen => &[SeccompMatch::Calls(&[S::PerfEventOpen])],
        Interface::Kexec => &[SeccompMatch::Calls(&[S::KexecFileLoad, S::KexecLoad])],
        Interface::ModuleLoading => &[SeccompMatch::Calls(&[S::FinitModule, S::InitModule])],
        Interface::Ptrace => &[SeccompMatch::Calls(&[
            S::PidfdGetfd,
            S::ProcessVmReadv,
            S::ProcessVmWritev,
            S::Ptrace,
        ])],
        Interface::VsockSocket => &[SeccompMatch::Argument {
            argument: SOCKET_DOMAIN,
            value: AF_VSOCK,
        }],
        Interface::PtraceOtherUsers | Interface::ProtectedPathWrite => &[],
    }
}

/// An interface that, when left available, reaches another interface's kernel object
/// without the system call the other's seccomp rule matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeccompBypass {
    /// The interface left available.
    pub through: Interface,
    /// What it offers in place of the refused system call.
    pub operation: &'static str,
    /// The interface whose seccomp rule it gets past.
    pub bypassed: Interface,
}

/// Every way around a seccomp rule of [`seccomp_matches`] (see the module notes).
pub const SECCOMP_BYPASSES: [SeccompBypass; 1] = [SeccompBypass {
    through: Interface::IoUring,
    operation: "IORING_OP_SOCKET",
    bypassed: Interface::VsockSocket,
}];
