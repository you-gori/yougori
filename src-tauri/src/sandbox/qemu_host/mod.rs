//! The QEMU backend's host I/O on Windows and Linux: the building blocks the `QemuHost`
//! implementations and the link session call (M02, M04;
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md: VM-W16 row, line 2615; VM-W19 row,
//! line 2618; §7.3 lines 2378–2386; VM-CP-01, line 3151). `sandbox::qemu` renders QMP and
//! the guest link as QEMU AF_UNIX server sockets named `qmp.sock` and `link.sock` in the
//! launch's private directory, passes the link bootstrap file `link-secret` through
//! fw_cfg, and asks a [`QemuMonitor`](crate::sandbox::qemu::QemuMonitor) port and a
//! [`LaunchLayout`](crate::sandbox::qemu::LaunchLayout) port for what it needs; this
//! module implements those ports' I/O.
//!
//! - [`socket`]: an AF_UNIX stream client over Winsock (the standard library's on Unix),
//!   with bounded, typed timeouts, shutdown per direction and the peer's process id
//!   (`SIO_AF_UNIX_GETPEERPID`; `SO_PEERCRED` on Linux), for `qmp.sock` and `link.sock`.
//! - [`qmp`]: a strict, bounded QMP client over any `Read + Write`, and [`QmpMonitor`],
//!   the `QemuMonitor` port over it: run state, the accelerator QEMU actually runs on
//!   (`query-accelerators`), quit.
//! - [`bootstrap`]: the 77-byte link bootstrap file v1 (magic, version, a fresh secret,
//!   the VM handle and boot generation of the `ProcessRole::VmHost`), its strict decoder
//!   and a create-new writer.
//! - [`layout`]: [`RuntimeLayout`], the `LaunchLayout` port over a configured runtime
//!   directory: the pinned executable, firmware and boot inputs looked up without creating
//!   anything, never through a link or reparse point, and readable by the restricted
//!   QEMU's restricting SIDs as each path's DACL shows ([`acl`]); on Unix, readable by
//!   others, as QEMU runs as an account of its own.
//! - [`early_exit`]: QEMU's own report when it ends before QMP answers, read the same way
//!   on every host: a hardware hypervisor error refuses the launch, never into emulation.
//! - [`network_filter`]: the host's judge of every frame of a VM's network card, started by
//!   each host beside a QEMU with a card: the public internet only, or the launch's targets
//!   alone with the VM's DNS answered by the filter itself; never this computer.
//!
//! - [`windows_host`]: [`WindowsQemuHost`], the `QemuHost` port itself on Windows: the
//!   private directory and bootstrap file ([`private_dir`]), the restricted low-integrity
//!   start on a desktop of its own through `foundation::process`, the wait for QMP, the
//!   read-back of the process's restrictions ([`host_map`]) and the termination with the
//!   host's proof. It is also the VM service's host port
//!   (`sandbox::vm_service::VmHostPort`): the private directory, the bootstrap secret once
//!   and the directory's absence.
//! - `linux_host`: `LinuxQemuHost`, the same two ports on Linux: a private directory of
//!   mode 0700 owned by QEMU's account, the start through `foundation::process` in a
//!   cgroup of its own with the plan's memory and task limits, a network namespace of its
//!   own, an unprivileged account and no new privileges, the wait for QMP with its peer
//!   checked, the read-back from `/proc` and the group, and the termination with the
//!   host's proof (M03 by the QEMU route, 31 October 2026).
//!
//! Windows code is under `cfg(windows)`, Linux code under `cfg(target_os = "linux")`;
//! elsewhere what cannot work is a typed `Unsupported`.

pub mod acl;
pub mod bootstrap;
pub mod early_exit;
#[cfg(windows)]
pub mod host_map;
pub mod layout;
#[cfg(target_os = "linux")]
pub mod linux_host;
pub mod network_filter;
#[cfg(windows)]
pub mod private_dir;
pub mod qmp;
pub mod socket;
#[cfg(windows)]
pub mod windows_host;

#[cfg(test)]
pub(crate) mod launch_fixture;
#[cfg(test)]
mod layout_tests;
#[cfg(all(test, windows))]
mod qemu_run_tests;
#[cfg(test)]
mod qmp_tests;

pub use acl::{
    restricted_access, AccessOutcome, AclError, LogonSid, LogonSidError, PathAccess, Trustees,
};
pub use bootstrap::{
    decode_bootstrap, encode_bootstrap, write_bootstrap_file, BootstrapError, BootstrapFile,
    DecodedBootstrap, WriteStep, BOOTSTRAP_FILE_BYTES, BOOTSTRAP_MAGIC, BOOTSTRAP_VERSION,
    MAX_SECRET_DRAWS,
};
pub use early_exit::{classify_report, log_tail, MAX_FAILURE_TEXT_BYTES, MAX_STDERR_TAIL_BYTES};
#[cfg(windows)]
pub use host_map::{
    classify_early_exit, observed_state, start_restrictions, MappingRefusal, ObservationError,
    StandardStream, StartRestrictions, MAX_REPORTED_EXTRA_HANDLES,
};
pub use layout::{
    executable_name, GuestImageFiles, LayoutError, LayoutPath, LayoutSettings, PathGrant, PathKind,
    RuntimeLayout, CONTROL_NAME_HEX_DIGITS, FIRMWARE_DIRECTORY, QEMU_DATA_DIRECTORY,
    QEMU_SECURE_DIRECTORY,
};
#[cfg(target_os = "linux")]
pub use linux_host::{LinuxCleanupFailure, LinuxHostSettings, LinuxQemuHost};
#[cfg(windows)]
pub use private_dir::{
    bootstrap_sddl, create_private_directory, directory_sddl, read_sddl, remove_private_directory,
    restrict_bootstrap_file, DirectoryError, HostSids, BOOTSTRAP_RESTRICTED_ACCESS,
    DIRECTORY_RESTRICTED_ACCESS, STDERR_LOG_NAME,
};
pub use qmp::{
    accelerator_from_qmp, accelerator_name, QemuVersion, QmpCommand, QmpConnect, QmpError,
    QmpMonitor, QmpSession, QmpStep, UnixSocketConnect, DEFAULT_QMP_EXCHANGE_BUDGET,
    MAX_EVENT_NAME_BYTES, MAX_QMP_EVENTS_PER_REPLY, MAX_QMP_LINE_BYTES, MAX_QMP_TEXT_BYTES,
    MAX_RUN_STATE_BYTES,
};
pub use socket::{
    connect, socket_path_bytes, Direction, LinkSocketConnector, SocketError, SocketOperation,
    SocketTimeouts, UnixStream, MAX_SOCKET_PATH_BYTES, MAX_SOCKET_TIMEOUT, MIN_SOCKET_TIMEOUT,
};
#[cfg(windows)]
pub use windows_host::{
    CleanupFailure, WindowsHostSettings, WindowsQemuHost, DEFAULT_GRACE, DEFAULT_KILL_WAIT,
    DEFAULT_POLL_INTERVAL, DEFAULT_PROBE_TIMEOUT, DEFAULT_QMP_WAIT,
};
