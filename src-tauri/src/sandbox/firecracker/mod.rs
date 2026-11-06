//! The Firecracker and jailer launch profile, the pure half of the Linux reference backend
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: VM-W17 row, line 2616, "Linux
//! reference backend with supported Firecracker jailer/privileged setup; rootless
//! alternative only after separate validation"; §7.2 Linux CPU sandboxes, lines 2366–2375;
//! §3.4 hypervisor hardening, lines 2093–2102; VM-D15, line 3209; §19, line 3223; VM-CP-02
//! to VM-CP-04, lines 3152–3154; VM-P01 to VM-P04, lines 2776–2779; S3.4 role RUNTIME;
//! leftover entry M03).
//!
//! Tier 0 only (§12.1, line 2762): nothing here starts Firecracker, the jailer or any
//! process, creates a namespace, touches a cgroup or reads `/proc`. It builds typed launch
//! plans, checks them, compares what a host observed with what the plan expects, and
//! drives a launch through ports whose real implementations live with the host side;
//! VM-W17's acceptance ("observed on real KVM") needs those implementations on a KVM host.
//!
//! - [`LaunchPlan::build`]: from a backend [`LaunchRequest`](crate::sandbox::backend::LaunchRequest),
//!   the approved [`FirecrackerProfile`], the pinned configuration row of
//!   `sandbox::trust` (Firecracker and its jailer from one release, VM-P23), the host's
//!   [`JailHost`] settings, the launch's [`JailIdentity`] and its CORE-03 reservation
//!   record, the plan of one launch, or a typed [`PlanRefusal`] for anything this backend
//!   cannot provide: a display, an assigned GPU, a confidential VM, data volumes, another
//!   host configuration, device profile or artifact than the row's, a network interface
//!   without a declared transport, a device model the row lacks, or a reservation that
//!   does not cover the plan.
//! - [`ApiPlan`]: the typed Firecracker API requests and their canonical JSON sequence:
//!   logger and metrics to host-owned sinks, machine config with SMT off, the pinned
//!   kernel with no console, the read-only root drive, declared interfaces only, the vsock
//!   link at a host-created socket path, the entropy device when declared, then start.
//! - [`JailerPlan`]: the official jailer's run, with its exact argument vector (id, exec
//!   file, uid and gid, chroot base, network namespace, cgroup v2 limits, resource limits,
//!   new PID namespace), executed without a shell; Firecracker keeps its default seccomp
//!   filters.
//! - [`LauncherPlan`] and [`LauncherSession`]: VM-D15's narrow privileged launcher, the
//!   closed set of privileged operations one launch may perform and the refusal of any
//!   other operation, order, repeat or parameter.
//! - [`GoldenFile`] and [`GoldenCheck`]: VM-CP-02's golden file over the API plan,
//!   Firecracker's arguments and the pinned version, with a comparison that reports
//!   unexpected, missing and changed entries and names forbidden configuration.
//! - [`parse_status`] and [`compare_linux_state`]: VM-CP-04's Linux expected state as a
//!   comparator over a typed observed state, and a strict parser of `/proc/<pid>/status`.
//! - [`FirecrackerBackend`]: the backend contract's [`VmBackend`](crate::sandbox::backend::VmBackend)
//!   over a privileged [`LauncherPort`], Firecracker's [`ApiPort`], the host's own
//!   [`HostObservationPort`] and the ledger's [`ReservationBook`]. A launch runs the
//!   contract's precheck before any privileged operation, performs the launcher's
//!   operations in the order the launch's session authorizes, sends the API sequence,
//!   observes KVM, the VM-CP-04 state, the chroot and the VM-CP-02 configuration through
//!   the host, and admits with the contract's `admit_with_configuration`, so the launch
//!   record binds VM-CP-02's golden comparison and VM-CP-03's listing of the API socket in
//!   the jail's socket directory; any refusal after the first privileged operation runs
//!   the launcher's own cleanup and returns the typed [`FirecrackerRefusal`] with its
//!   [`CleanupReport`]; the contract hears it by what the host observed, and an
//!   incomplete cleanup with what may remain. Handles are bound to the jail and to the
//!   process's `foundation::process` identity; a stop kills through the launch's own
//!   cgroup and ends on the host's [`JailTermination`]; a running VM is observed again
//!   through the same ports (`VmBackend::reobserve`).
//!
//! A plan is a cold boot. Its jail id derives from the boot generation, so every boot has
//! its own jail directory, cgroup, network namespace and sockets, and it carries no
//! snapshot load or dirty-page tracking (§6.6, lines 2336–2353). Snapshot and restore stay
//! with the backend contract's own refusal until a restore plan exists.

mod api;
mod backend;
mod canonical;
mod golden;
mod host;
mod jail;
mod jailer;
mod launcher;
mod layout;
mod linux_state;
mod names;
mod observe;
mod plan;
mod ports;
mod profile;
mod proof;
mod refusal;
mod status;

#[cfg(test)]
mod backend_tests;
#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod scripted;
#[cfg(test)]
mod tests;

pub use api::{
    ApiCall, ApiPlan, ApiRequest, API_PLAN_DOMAIN, BOOT_ARGUMENTS, GUEST_CID, LOG_LEVEL, METHOD,
    ROOT_DRIVE_ID,
};
pub use backend::{FirecrackerBackend, FirecrackerSettings, JailBinding, JailStop, SettingsError};
pub use canonical::canonical_json;
pub use golden::{
    compare as compare_golden, forbidden, ChangedEntry, ForbiddenItem, GoldenCheck, GoldenDiff,
    GoldenEntry, GoldenError, GoldenFile, ARGS_KEY, GOLDEN_DOMAIN, GOLDEN_SCHEMA,
    MAX_ENTRY_KEY_BYTES, MAX_GOLDEN_BYTES, SEQUENCE_KEY, VERSION_KEY,
};
pub use host::{HostError, HostOwner, IdRange, JailHost, EXEC_FILE_MARKER};
pub use jail::{CleanupEntry, CleanupOutcome, CleanupReport, JailEnd};
pub use jailer::{CgroupFile, CgroupLimit, JailerPlan, ResourceLimit, CGROUP_VERSION};
pub use launcher::{
    ArtifactRole, Authorized, CleanupStep, LauncherPlan, LauncherRefusal, LauncherSession,
    PrivilegedOperation, SinkKind, ARTIFACT_MODE, MAX_REQUEST_BYTES, OPERATION_TAGS,
    ROOT_DIRECTORY_MODE, SINK_DIRECTORY_MODE, SINK_MODE, SOCKET_DIRECTORY_MODE,
};
pub use layout::{
    API_SOCKET, IMAGE_DIRECTORY, KERNEL_IMAGE, LINK_SOCKET, LOG_SINK, METRICS_SINK, ROOT_IMAGE,
    SINK_DIRECTORY, SOCKET_DIRECTORY,
};
pub use linux_state::{
    check_observation, compare as compare_linux_state, ExpectedLinuxState, LinuxStateReport,
    ObservedLinuxState, StateCheck, StateItem,
};
pub use names::{
    ApiId, CgroupPath, HostPath, InterfaceName, JailId, JailIdentity, JailPath, MacAddress,
    NameError, NameKind, JAIL_ID_DOMAIN, MAX_API_ID_BYTES, MAX_COMPONENT_BYTES,
    MAX_INTERFACE_NAME_BYTES, MAX_JAIL_ID_BYTES, MAX_PATH_BYTES,
};
pub use observe::{cgroup_path, holds_kvm_vm, KVM_VM_DESCRIPTOR, RUNNING_STATE};
pub use plan::{LaunchPlan, PinnedArtifact, PlanInputs, PlanRefusal, ReservationProblem};
pub use ports::{
    ApiFailure, ApiPort, ApiReply, CgroupState, HostObservationPort, HostState, InstanceInfo,
    LauncherFailure, LauncherPort, LauncherReport, ObservationFailure, ProcessObservation,
    ReservationBook,
};
pub use profile::{
    CpuLimit, FirecrackerProfile, JailLimits, MachineShape, NetworkInterfaceDeclaration,
    ProfileError, MAX_CPU_PERIOD_MICROS, MAX_OPEN_DESCRIPTORS, MAX_PROFILE_BYTES, MAX_VCPUS,
    MIB_BYTES, MIN_CPU_PERIOD_MICROS, MIN_CPU_QUOTA_MICROS, PROFILE_DOMAIN, VMM_SERVICE_THREADS,
};
pub use proof::{JailTermination, NoJailProof};
pub use refusal::{FirecrackerRefusal, LaunchFailure};
pub use status::{
    parse_status, IdQuad, ProcStatus, SeccompMode, StatusError, MAX_STATUS_BYTES, NEEDED_KEYS,
};
