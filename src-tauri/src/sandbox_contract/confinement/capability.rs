//! Linux capabilities as a closed, typed set (VM-R66 "Non-root workloads, capabilities and
//! seccomp"; VM-CP-05 "the capability set equals the profile").
//!
//! A profile names capabilities by variant, never by string, so a misspelled name cannot
//! silently grant or drop nothing. The numbers are the kernel's (`include/uapi/linux/
//! capability.h`, through `CAP_CHECKPOINT_RESTORE`).

use std::fmt;

use serde::{Deserialize, Serialize};

macro_rules! linux_capabilities {
    ($($(#[$doc:meta])* $variant:ident = $number:literal, $kernel:literal;)*) => {
        /// One Linux capability (VM-R66). Serialized in snake_case without the `CAP_`
        /// prefix, such as `dac_override`.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum LinuxCapability {
            $($(#[$doc])* $variant),*
        }

        impl LinuxCapability {
            /// Every capability, in kernel number order.
            pub const ALL: [Self; 41] = [$(Self::$variant),*];

            /// The kernel's capability number.
            pub const fn number(self) -> u8 {
                match self {
                    $(Self::$variant => $number),*
                }
            }

            /// The kernel's name, such as `CAP_DAC_OVERRIDE`.
            pub const fn kernel_name(self) -> &'static str {
                match self {
                    $(Self::$variant => $kernel),*
                }
            }
        }
    };
}

linux_capabilities! {
    Chown = 0, "CAP_CHOWN";
    DacOverride = 1, "CAP_DAC_OVERRIDE";
    DacReadSearch = 2, "CAP_DAC_READ_SEARCH";
    Fowner = 3, "CAP_FOWNER";
    Fsetid = 4, "CAP_FSETID";
    Kill = 5, "CAP_KILL";
    Setgid = 6, "CAP_SETGID";
    Setuid = 7, "CAP_SETUID";
    Setpcap = 8, "CAP_SETPCAP";
    LinuxImmutable = 9, "CAP_LINUX_IMMUTABLE";
    NetBindService = 10, "CAP_NET_BIND_SERVICE";
    NetBroadcast = 11, "CAP_NET_BROADCAST";
    NetAdmin = 12, "CAP_NET_ADMIN";
    NetRaw = 13, "CAP_NET_RAW";
    IpcLock = 14, "CAP_IPC_LOCK";
    IpcOwner = 15, "CAP_IPC_OWNER";
    SysModule = 16, "CAP_SYS_MODULE";
    SysRawio = 17, "CAP_SYS_RAWIO";
    SysChroot = 18, "CAP_SYS_CHROOT";
    SysPtrace = 19, "CAP_SYS_PTRACE";
    SysPacct = 20, "CAP_SYS_PACCT";
    SysAdmin = 21, "CAP_SYS_ADMIN";
    SysBoot = 22, "CAP_SYS_BOOT";
    SysNice = 23, "CAP_SYS_NICE";
    SysResource = 24, "CAP_SYS_RESOURCE";
    SysTime = 25, "CAP_SYS_TIME";
    SysTtyConfig = 26, "CAP_SYS_TTY_CONFIG";
    Mknod = 27, "CAP_MKNOD";
    Lease = 28, "CAP_LEASE";
    AuditWrite = 29, "CAP_AUDIT_WRITE";
    AuditControl = 30, "CAP_AUDIT_CONTROL";
    Setfcap = 31, "CAP_SETFCAP";
    MacOverride = 32, "CAP_MAC_OVERRIDE";
    MacAdmin = 33, "CAP_MAC_ADMIN";
    Syslog = 34, "CAP_SYSLOG";
    WakeAlarm = 35, "CAP_WAKE_ALARM";
    BlockSuspend = 36, "CAP_BLOCK_SUSPEND";
    AuditRead = 37, "CAP_AUDIT_READ";
    Perfmon = 38, "CAP_PERFMON";
    Bpf = 39, "CAP_BPF";
    CheckpointRestore = 40, "CAP_CHECKPOINT_RESTORE";
}

/// Capabilities no workload profile may hold, with or without an exception (VM-R66,
/// §3.4). Each lifts several inner controls at once: `sys_admin` remounts read-only paths
/// and administers namespaces, `sys_module` loads kernel code, `sys_rawio` reaches devices
/// and memory directly, `sys_boot` loads a new kernel, `mac_admin` and `mac_override`
/// change or bypass the LSM policy, and `bpf` loads BPF programs.
pub const NEVER_GRANTED: [LinuxCapability; 7] = [
    LinuxCapability::SysAdmin,
    LinuxCapability::SysModule,
    LinuxCapability::SysRawio,
    LinuxCapability::SysBoot,
    LinuxCapability::MacAdmin,
    LinuxCapability::MacOverride,
    LinuxCapability::Bpf,
];

impl LinuxCapability {
    /// Whether no profile may ever hold this capability ([`NEVER_GRANTED`]).
    pub fn never_granted(self) -> bool {
        NEVER_GRANTED.contains(&self)
    }
}

impl fmt::Display for LinuxCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kernel_name())
    }
}
