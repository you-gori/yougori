//! The QEMU launch profile and backend of the VM sandbox part: the pure half of M04 and
//! the library half of M02 (docs/combined-gpu-memory-and-vm-sandbox-plan.md: VM-W16 row,
//! line 2615; VM-W19 row, line 2618, "Validate and harden current QEMU/WHPX profile and
//! the minimal compatible QEMU Linux profile", and VM-W22, line 2621; §3.4 lines
//! 2093–2102; §6.4 line 2322; §7.1 line 2364; §7.2 lines 2368 and 2374; §7.3 lines
//! 2378–2386; VM-P01 to VM-P04, lines 2776–2779; VM-P42, line 2817; VM-CP-01 to VM-CP-04,
//! lines 3151–3154; VM-CP-33, line 3183; VM-D2, line 3196; §19 line 3224). Tier 0 (line
//! 2762): nothing here starts QEMU, opens a socket, creates a token or a job, or touches a
//! host setting. It builds and checks typed launch plans on the backend contract of
//! `sandbox::backend`, and runs them through host ports it does not implement.
//!
//! - [`plan_launch`]: a [`QemuLaunchPlan`] from a backend [`LaunchRequest`], or a typed
//!   [`ProfileRefusal`] naming what the profile cannot provide. The backend's precheck
//!   runs first, so a host without fresh host-probed CORE-01 evidence that its hardware
//!   hypervisor is available gets no plan, and there is no emulated alternative.
//! - [`QemuProfile`]: one accelerator (WHPX on Windows, KVM on Linux, HVF on macOS;
//!   never TCG), the microvm board on x86 and virt on Arm, `-nodefaults` and
//!   `-no-user-config`, a read-only root drive, declared volumes only, one entropy device,
//!   the link channel of the platform (virtio-serial, which the pinned guest speaks; vsock
//!   on Linux on Arm, for which no guest is built), the link secret
//!   through fw_cfg, QMP only on a socket in the host-created private directory, no
//!   network, share, USB, display, console or balloon device and no PCI transport, and
//!   QEMU's seccomp sandbox on Linux. [`QemuProfile::argv`] is the exact vector.
//! - [`GoldenFile`]: VM-CP-02's golden file, the canonical vector and the backend version
//!   under one digest, with a comparison of an observed process or a launch plan
//!   reporting unexpected, missing and changed arguments.
//! - [`parse_observed`] and [`check_observed`]: VM-CP-01, VM-CP-03 and VM-CP-33 on an
//!   [`ObservedArgv`] from the process listing: strict reading back into the profile,
//!   with typed findings for TCG, share devices, network management listeners and a port
//!   forward to the old agent port.
//! - [`WindowsHostRestrictions`] and [`check_windows`]: the restricted low-integrity
//!   token, Job limits, explicit handle inheritance and mitigations the launcher must
//!   apply, and VM-CP-04's Windows comparator over a host-observed process state.
//! - [`QemuBackend`]: the backend contract's [`VmBackend`] over host ports (M02): a
//!   [`QemuHost`] that starts the exact vector under the plan's restrictions as a CORE-04
//!   host process, observes it and ends it with the host's proof, a [`QemuMonitor`] for
//!   QMP on the private socket, and a [`LaunchLayout`] of the host inputs. It runs the
//!   precheck before anything exists, refuses a plan that is not the configuration of the
//!   release's golden file in its [`QemuSettings`] before QEMU starts, observes the
//!   accelerator, the vector and the Windows restrictions through the host, admits with
//!   the golden comparison and the listing (VM-CP-02, VM-CP-03) and seals the launch
//!   record, which binds them, and stops and removes the VM on any refusal after it
//!   started. Its refusals reach the contract by what the host observed, and one whose VM
//!   is not shown stopped as an incomplete cleanup naming what may remain; a running VM is
//!   observed again through the same ports (`VmBackend::reobserve`), its configuration
//!   facts included. The port implementations that spawn QEMU and speak QMP are not here.
//!
//! A profile is not evidence that a build boots with it. §7.1 (line 2364) and §7.3
//! (line 2384) require each machine, device set, build and token or Job combination to
//! be validated together on real hosts; until a `sandbox::backend` evidence row records
//! that, the combination is experimental or unavailable.
//!
//! [`LaunchRequest`]: crate::sandbox::backend::LaunchRequest
//! [`VmBackend`]: crate::sandbox::backend::VmBackend

mod argv;
mod backend;
mod golden;
mod linux;
mod parse;
mod platform;
mod ports;
mod profile;
mod values;
mod windows;

#[cfg(test)]
mod backend_tests;
#[cfg(test)]
mod tests;

pub use argv::{
    ArgumentDifference, ObservedArgv, ObservedArgvError, Role, MAX_OBSERVED_ARGUMENTS,
    MAX_OBSERVED_ARGUMENT_BYTES,
};
pub use backend::{EndNotProven, QemuBackend, QemuRefusal, QemuSettings};
pub use golden::{
    golden_digest, GoldenComparison, GoldenFile, GoldenRefusal, GOLDEN_DOMAIN, GOLDEN_FORMAT,
};
pub use linux::{
    check_linux, interfaces_of, limit_of, LinuxCheck, LinuxFinding, LinuxHostRestrictions,
    LinuxObservedState, LINUX_CONTROLS, MAX_QEMU_TASKS,
};
pub use parse::{
    check_observed, parse_observed, ArgvFinding, ArgvRefusal, ManagementInterface, ShareKind,
    OLD_AGENT_GUEST_PORT,
};
pub use platform::{
    LinkKind, Machine, PlatformProfile, PlatformRefusal, ProfileKind, QemuPlatform,
};
pub use ports::{
    HostInputs, LaunchLayout, LayoutRefusal, MonitorFailure, ObserveFailure, ProcessInspection,
    ProcessState, QemuHost, QemuMonitor, RunState, StartFailure, TerminationEvidence,
};
pub use profile::{
    plan_launch, qemu_features, LinkChannel, PathRole, ProfileRefusal, QemuLaunchInputs,
    QemuLaunchPlan, QemuProfile, ReservationView, ReservedVm, EGRESS_ENDPOINTS_FW_CFG_NAME,
    LINK_PORT_NAME, LINK_SECRET_FW_CFG_NAME, MAX_VOLUMES,
};
pub use values::{
    CidError, GuestCid, GuestResources, HostPath, InstanceName, KernelArgumentError,
    KernelArguments, NameError, PathError, PathStyle, PrivateDirectory, ResourceError,
    EGRESS_ENDPOINTS_NAME, INSTANCE_NAME_PREFIX, LINK_SECRET_NAME, LINK_SOCKET_NAME,
    MAX_GUEST_MEMORY_BYTES, MAX_HOST_PATH_BYTES, MAX_KERNEL_ARGUMENT_BYTES,
    MAX_KERNEL_COMMAND_LINE_BYTES, MAX_UNIX_SOCKET_PATH_BYTES, MAX_VCPU_COUNT,
    MAX_WINDOWS_SOCKET_PATH_BYTES, MIB_BYTES, QMP_SOCKET_NAME, WORKLOAD_NAME,
};
pub use windows::{
    check_windows, GroupState, HandleKind, InheritedHandles, IntegrityLevel, JobLimit, JobLimits,
    Mitigation, ObservedJob, RestrictingSid, TokenRestrictions, UiRestriction, WindowsCheck,
    WindowsFinding, WindowsHostRestrictions, WindowsObservedState, WindowsRefusal,
    CHANGE_NOTIFY_PRIVILEGE, LOW_INTEGRITY_RID,
};
