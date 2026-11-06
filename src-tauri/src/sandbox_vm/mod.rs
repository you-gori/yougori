//! The engine's restricted VM sandbox path: the production composition of the VM service
//! (`sandbox::vm_service`) over the real host ports, and its automation method
//! `sandbox_vm` (M02, M04, M06, M13 and S03/S04 at the first production boundary;
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md: §6.1–§6.4 lines 2284–2337, §8.1 lines
//! 2433–2450, §11.1 step 3 "one verified VM launch"; VM-W16, VM-W19, VM-W24–VM-W26; the
//! integration queue's step 4).
//!
//! What the composition binds together, each a committed component used as it is:
//!
//! - the pinned guest artifacts ([`artifacts`]): the initrd and read-only root image built
//!   by `scripts/build-guest.sh` from `guest/`, shipped under `runtime/sandbox-guest` with
//!   the build's `artifacts.json`, and the pinned appliance kernel; every file is hashed
//!   and compared with the record before anything may boot it, and the root image's
//!   SHA-256 is the guest image identity every launch pins;
//! - the pinned QEMU build (`runtime/qemu-secure`), whose executable is hashed and
//!   compared with its checksum list, the release's golden file of the Windows x86-64
//!   profile ([`artifacts`]), and the host layout that checks the restricted QEMU can read
//!   each path (`sandbox::qemu_host::RuntimeLayout`);
//! - the host's one CORE-03 ledger (`model_runner::refresh_host_capacity`: host RAM and
//!   CPU initialization slots, GPU accounting identity kept) and its clock, which the
//!   supervisor, the registry and every lease share;
//! - CORE-01 evidence from host probes ([`probes`]): the Windows Hypervisor Platform's own
//!   capability report for `HypervisorAvailable`, and the pinned executable's identity on
//!   disk for the runtime's category, both on the host's machine digest and configuration
//!   fingerprint from `host_evidence`'s inventory;
//! - the Windows host ports: the restricted low-integrity start on a desktop of its own
//!   (`foundation::process`), the private directory and bootstrap file, QMP over the
//!   private socket, the link socket admitted only when its peer is the QEMU process the
//!   host started, carried by a non-blocking stream ([`ports`]);
//! - a durable, spooled audit stream and the supervisor's persisted state under the
//!   engine's data directory, so a restart recovers rather than trusts (`VmService::recover`).
//!
//! The automation method `sandbox_vm` (and `yougori sandbox ...`, and the desktop's VM
//! sandbox panel through the `sandbox_vm` command) exposes launch, status, exec, cancel,
//! stop, revoke, confinement, cleanup, credential, workspace and plan over the service's
//! typed DTOs; every refusal is the service's own. A launch with a workspace folder stages
//! a copy of it ([`workspace`]) that the guest reads and writes over its file channel; the
//! user's folder changes only through a reviewed promotion of approved files. The method runs the blocking
//! service calls off the async runtime and persists the supervisor's state after each call
//! that changed it.
//!
//! Beside the calls, a poller asks the sandbox executor every two seconds what its relays
//! refused and which ended: violations go to the response path ([`responses`]), whose
//! decisions are audited in the supervisor's durable stream and then enforced (a violation
//! revokes the sandbox and stops its relay), and the relay of a sandbox that lost its
//! authority on its own (an expired lease, a powered-off guest) is stopped. `confinement`
//! runs the guest's probe and evaluates it against the strict tool profile with the host's
//! own corroboration; the doctor (`runtime::doctor`) reads the launch records and the
//! latest verdict on this service's evidence clock.
//!
//! **Platform.** The production composition exists for Windows (QEMU on WHPX, the profile
//! `sandbox::qemu` builds) and for Linux (QEMU on KVM, M03 by the QEMU route, 31 October
//! 2026): the same service and method over `sandbox::qemu_host::LinuxQemuHost` (QEMU as an
//! account of its own, `yougori-vm` unless `YOUGORI_VM_ACCOUNT` names another, in a cgroup
//! and network namespace of its own, ending with the engine by its parent-death signal), the
//! KVM device's own answer as the hypervisor probe ([`probes`]), the pinned Linux QEMU in
//! `runtime/qemu-secure` with its golden file, and the lifetime supervisor on a private
//! control socket with pidfds of its own. On Linux the engine must run as root (QEMU's
//! account switch; VM-D15's narrower launcher is open), and routes and credentials are
//! refused before anything starts: the executor and its confined relay run on Windows
//! only (their Unix sockets and confinement are open). On macOS the method answers that the
//! path is not implemented: the helper (M05) is open scope, not a fallback of this one.
//!
//! **Recorded limits of the Windows profile.** The restricted token's second access check
//! includes Everyone (USER32's initialization needs it) and Authenticated Users (the
//! Windows Hypervisor Platform's device grants it and nothing narrower of the set;
//! measured 30 October 2026, `foundation::process::restricted`), so it also passes what
//! those two are granted, while the low integrity label still denies every write to a
//! medium-integrity object; the clipboard and the global atom table stay shared with the
//! logon session, since a
//! non-elevated session may not create a window station (`foundation::process::station`);
//! the runtime directory must grant read and execute to the restricting SIDs, which the
//! source checkout's does not and an installed copy does (the layout refuses otherwise,
//! naming the path); the audit stream is not anchored outside the host.

#[cfg(any(windows, target_os = "linux"))]
mod artifacts;
#[cfg(any(windows, target_os = "linux"))]
mod engine;
#[cfg(any(windows, target_os = "linux"))]
mod host_access;
// On Linux only the executor's protocol is used (route declarations), and the response
// path waits for its relays.
#[cfg(any(windows, target_os = "linux"))]
#[cfg_attr(not(windows), allow(dead_code))]
mod executor;
#[cfg(any(windows, target_os = "linux"))]
mod lifetimes;
#[cfg(any(windows, target_os = "linux"))]
mod ports;
#[cfg(any(windows, target_os = "linux"))]
mod preview;
#[cfg(any(windows, target_os = "linux"))]
pub(crate) mod probes;
#[cfg(any(windows, target_os = "linux"))]
mod process_scan;
#[cfg(any(windows, target_os = "linux"))]
mod remote_agent;
#[cfg(any(windows, target_os = "linux"))]
mod remote_call;
#[cfg(any(windows, target_os = "linux"))]
#[cfg_attr(not(windows), allow(dead_code))]
mod responses;
#[cfg(any(windows, target_os = "linux"))]
mod supervisor;
#[cfg(any(windows, target_os = "linux"))]
mod workspace;

#[cfg(any(windows, target_os = "linux"))]
pub(crate) use engine::{dispatch, doctor_records};

#[cfg(not(test))]
pub(crate) fn start_remote_recovery(app: &crate::AppHandle) {
    #[cfg(any(windows, target_os = "linux"))]
    engine::start_remote_recovery(app);
    #[cfg(not(any(windows, target_os = "linux")))]
    let _ = app;
}

/// What this engine run's VM sandboxes give the doctor (`runtime::doctor`): the backend
/// build, its sealed launch records, its controlled negative launches (acceptance builds
/// plant their faults), the latest confinement verdict and the service's evidence clock now.
pub(crate) struct DoctorRecords {
    pub backend: crate::sandbox::backend::BackendIdentity,
    pub records: Vec<crate::sandbox::backend::LaunchRecord>,
    pub negatives: Vec<(
        crate::sandbox::probes::ControlledFault,
        crate::sandbox::probes::NegativeOutcome,
    )>,
    /// The host's scans of its process list: one taken now for the examination, and one
    /// after each refused negative launch (`sandbox::probes::process_scan`).
    pub scans: Vec<crate::sandbox::backend::HostObserved<crate::sandbox::probes::ProcessScan>>,
    /// The host's observations of the latest VM-CP-29 connection drills.
    pub drills: Vec<crate::sandbox::backend::HostObserved<crate::sandbox::probes::ConnectionDrill>>,
    pub confinement: Option<crate::sandbox::probes::Vm05Evaluation>,
    pub now: Option<crate::foundation::evidence::ClockReading>,
}

/// The `sandbox_vm` desktop command, for the VM sandbox panel
/// (`src/components/sandbox-vm/sandbox-vm-panel.tsx`): the same answer as the automation
/// method, `params` its request (`status` when no action is given).
#[tauri::command]
pub async fn sandbox_vm(
    app: crate::AppHandle,
    action: Option<String>,
    params: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let mut params = params.unwrap_or_else(|| serde_json::json!({}));
    if !params.is_object() {
        return Err("The request must be an object.".to_owned());
    }
    if let Some(action) = &action {
        params["action"] = serde_json::json!(action);
    }
    dispatch(app, action, params).await
}

/// The engine binary's hidden modes of this path, checked before anything else of the
/// engine starts: `--sandbox-executor PIPE ENGINE_PID` runs the sandbox executor process
/// ([`executor::process`]), `--sandbox-relay` the confined guest relay
/// ([`executor::relay_mode`]) and `--sandbox-supervisor PIPE ENGINE_PID JOURNAL_DIR` the
/// lifetime supervisor ([`supervisor::process`]). `Some(code)` is the process's exit code; `None` means this
/// is an ordinary engine start.
#[cfg(any(windows, target_os = "linux"))]
pub(crate) fn hidden_mode() -> Option<i32> {
    let arguments: Vec<String> = std::env::args_os()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    match arguments.get(1).map(String::as_str) {
        #[cfg(windows)]
        Some(crate::sandbox::hcs::broker::MODE) => Some(crate::sandbox::hcs::broker::run(&arguments[2..], false)),
        #[cfg(windows)]
        Some(crate::sandbox::hcs::broker::ELEVATED_MODE) => Some(crate::sandbox::hcs::broker::run(&arguments[2..], true)),
        #[cfg(windows)]
        Some(executor::EXECUTOR_MODE) => Some(executor::process::run_executor(&arguments[2..])),
        #[cfg(windows)]
        Some(executor::RELAY_MODE) => Some(executor::relay_mode::run_relay()),
        Some(supervisor::SUPERVISOR_MODE) => {
            Some(supervisor::process::run_supervisor(&arguments[2..]))
        }
        Some(remote_agent::MODE) => Some(remote_agent::run(&arguments[2..])),
        Some(remote_call::MODE) => Some(remote_call::run(&arguments[2..])),
        _ => None,
    }
}

/// A route as the sandbox executor reads it (`executor::protocol::RouteDeclaration`): its
/// name, or why it is not one. For the setup handler's tests, which build routes from a
/// template's declaration.
#[cfg(all(test, windows))]
pub(crate) fn route_name_for_tests(route: serde_json::Value) -> Result<String, String> {
    serde_json::from_value::<executor::RouteDeclaration>(route)
        .map(|route| route.name)
        .map_err(|error| error.to_string())
}

/// Whether this computer can run the VM sandbox: the pinned QEMU build and the guest are
/// installed beside the engine and the platform reports a hypervisor (the Windows Hypervisor
/// Platform, or KVM). Cheap, so the setup catalogue can ask it on every request; a launch
/// still verifies every pinned file and refuses with the reason when one does not match.
#[cfg(any(windows, target_os = "linux"))]
pub(crate) fn available(app: &crate::AppHandle) -> bool {
    let Ok(resources) = crate::resource_dir(app) else {
        return false;
    };
    let Ok(runtime) = crate::runtime::bundled_runtime_root(&resources) else {
        return false;
    };
    artifacts::installed(&runtime) && probes::platform_report() == probes::PlatformReport::Present
}

/// No VM sandbox runs on a platform without the production composition.
#[cfg(not(any(windows, target_os = "linux")))]
pub(crate) fn available(_app: &crate::AppHandle) -> bool {
    false
}

/// No launch record exists on a platform without the production composition.
#[cfg(not(any(windows, target_os = "linux")))]
pub(crate) async fn doctor_records() -> Option<DoctorRecords> {
    None
}

/// No hidden mode exists on a platform without the production composition.
#[cfg(not(any(windows, target_os = "linux")))]
pub(crate) fn hidden_mode() -> Option<i32> {
    None
}

/// The automation method on a platform without the production composition: a refusal
/// that names the open scope rather than a fallback.
#[cfg(not(any(windows, target_os = "linux")))]
pub(crate) async fn dispatch(
    _app: crate::AppHandle,
    _action: Option<String>,
    _params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    Err("The restricted VM sandbox runs on Windows (QEMU on the Windows Hypervisor Platform) and Linux (QEMU on KVM) in this build; the macOS helper (M05) is open work, not a fallback.".to_owned())
}
