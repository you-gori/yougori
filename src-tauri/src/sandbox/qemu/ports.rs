//! The host ports the QEMU backend runs a launch plan through (M02; VM-W16 row, line
//! 2615; VM-W19 row, line 2618; VM part §6.4, line 2322: stable process handles, never a
//! PID). Each is a trait: nothing in this module starts a process, opens a socket or
//! reads a file. The implementations that spawn QEMU and speak QMP come later; tests
//! drive the backend through scripted ports.
//!
//! - [`QemuHost`]: the host process port. It prepares what the plan names on the host
//!   (the private directory, the link secret file), starts the exact argument vector
//!   under the plan's restrictions without a shell, and returns the CORE-04 process
//!   identity of `foundation::process` (PID with creation time, bound at start to the VM
//!   boot it runs for). It observes the process through the host (state, process
//!   listing, and on Windows the token, Job, handles and mitigations) and ends it with
//!   the host's proof ([`TerminationEvidence`], in production
//!   [`TerminationProof`](crate::foundation::process::TerminationProof)).
//! - [`QemuMonitor`]: QMP over the socket in the launch's private directory: the
//!   accelerator QEMU runs on, its run state, and a request to quit.
//! - [`LaunchLayout`]: the host inputs of one launch (pinned paths, guest resources, the
//!   private directory's path, declared volumes), looked up without creating anything.

use std::fmt;

use serde::Serialize;

use super::profile::{QemuLaunchInputs, QemuLaunchPlan};
use super::values::HostPath;
use super::windows::WindowsObservedState;
use crate::foundation::coordination::VmInstanceId;
use crate::foundation::ids::Digest;
use crate::foundation::process::{
    NoProof, ProcessError, ProcessIdentity, ProcessRole, TerminationProof,
};
use crate::sandbox::backend::{HostBuild, LaunchRequest};

/// The host's proof that a process and every process of its job ended. In production it
/// is CORE-04's [`TerminationProof`], which only a held host process produces; the
/// backend accepts a proof only when it names the process it holds, under the role bound
/// at start.
pub trait TerminationEvidence: Clone + fmt::Debug {
    /// The process that ended.
    fn identity(&self) -> ProcessIdentity;

    /// What it ran for, as bound when it started.
    fn role(&self) -> &ProcessRole;
}

impl TerminationEvidence for TerminationProof {
    fn identity(&self) -> ProcessIdentity {
        TerminationProof::identity(self)
    }

    fn role(&self) -> &ProcessRole {
        TerminationProof::role(self)
    }
}

/// Why the host process port could not start QEMU. In every case the port leaves nothing
/// behind: no process, and none of the host files it prepared.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "failure", rename_all = "snake_case")]
pub enum StartFailure {
    /// The hypervisor's hardware virtualization failed while QEMU started, as the port
    /// read it from QEMU's own report (VM-W22: a forced hardware failure refuses the
    /// launch, with no retry into emulation).
    HardwareVirtualization { detail: String },
    /// The process could not be started or confined (CORE-04's process errors).
    Process { error: ProcessError },
    /// The host files the plan names (the private directory, the link secret) could not
    /// be prepared.
    Prepare { detail: String },
}

impl fmt::Display for StartFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HardwareVirtualization { detail } => {
                write!(
                    f,
                    "hardware virtualization failed while QEMU started: {detail}"
                )
            }
            Self::Process { error } => write!(f, "{error}"),
            Self::Prepare { detail } => {
                write!(f, "the launch's host files could not be prepared: {detail}")
            }
        }
    }
}

impl std::error::Error for StartFailure {}

/// Why the host could not observe a process it started.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "failure", rename_all = "snake_case")]
pub enum ObserveFailure {
    /// The port holds no process with this identity.
    NotHeld { process: ProcessIdentity },
    /// The port holds it but could not read what was asked.
    Unreadable { detail: String },
}

impl fmt::Display for ObserveFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotHeld { process } => write!(f, "the host holds no {process}"),
            Self::Unreadable { detail } => {
                write!(f, "the host could not observe the process: {detail}")
            }
        }
    }
}

impl std::error::Error for ObserveFailure {}

/// A held process's state, as the host observes it through its handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProcessState {
    Running,
    /// The process ended with this exit code. Only [`QemuHost::terminate`] proves that
    /// its whole job ended.
    Ended {
        exit_code: u32,
    },
}

/// What the host observed of a started QEMU process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProcessInspection {
    pub state: ProcessState,
    /// The process listing's vector: the executable, then the arguments.
    pub command_line: Vec<String>,
    /// On Windows, the token, Job, inherited handles and mitigations as the host queried
    /// them from the process and its job object (VM-CP-04); `None` elsewhere or when the
    /// host could not query them.
    pub windows: Option<WindowsObservedState>,
    /// On Linux, the process's status, cgroup and network namespace as the host read them
    /// (VM-CP-04); `None` elsewhere or when the host could not read them.
    pub linux: Option<super::LinuxObservedState>,
}

/// The host process port of the QEMU backend.
///
/// A started process is held by the port for its whole life and named by its CORE-04
/// [`ProcessIdentity`], never a bare PID (VM part §6.4). Observations come from the host,
/// never from the guest.
pub trait QemuHost {
    /// The proof [`terminate`](Self::terminate) returns.
    type Proof: TerminationEvidence;

    /// Prepares the host files `plan` names (the private directory, owner-only and on
    /// Windows labelled for the low-integrity process, and the link secret file), then
    /// starts `executable` with exactly `plan`'s argument vector, without a shell, for
    /// `role`. On Windows the process runs under the plan's restricted low-integrity
    /// token and Job, with only the listed handles inherited, before it runs anything.
    /// Returns once QEMU runs with its QMP socket listening. A failure leaves nothing
    /// behind.
    fn start(
        &mut self,
        role: &ProcessRole,
        executable: &HostPath,
        plan: &QemuLaunchPlan,
    ) -> Result<ProcessIdentity, StartFailure>;

    /// The process's state now, looking once without waiting.
    fn state(&self, process: &ProcessIdentity) -> Result<ProcessState, ObserveFailure>;

    /// The process's state, its process listing and, on Windows, its restrictions.
    fn inspect(&self, process: &ProcessIdentity) -> Result<ProcessInspection, ObserveFailure>;

    /// The host's operating system, build and architecture.
    fn host_build(&self) -> Result<HostBuild, ObserveFailure>;

    /// Ends the process and every process of its job (a grace period, then the job is
    /// killed) and returns the host's proof, then removes the host files `start`
    /// prepared. A process that already ended yields its proof at once. Without the
    /// host's observation of the end there is no proof and nothing is removed.
    fn terminate(&mut self, process: &ProcessIdentity) -> Result<Self::Proof, NoProof>;
}

/// QEMU's run state as QMP reports it (`query-status`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RunState {
    Running,
    /// Any other state, in QEMU's own word (such as `paused`, `shutdown` or
    /// `internal-error`).
    NotRunning {
        status: String,
    },
}

/// Why QMP could not be used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "failure", rename_all = "snake_case")]
pub enum MonitorFailure {
    /// The socket could not be reached.
    Unreachable { detail: String },
    /// QEMU's answer was an error or not what QMP specifies.
    Protocol { detail: String },
}

impl fmt::Display for MonitorFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable { detail } => write!(f, "QMP could not be reached: {detail}"),
            Self::Protocol { detail } => write!(f, "QMP answered unexpectedly: {detail}"),
        }
    }
}

impl std::error::Error for MonitorFailure {}

/// The QMP port: the monitor QEMU serves on the socket in the launch's host-created
/// private directory, and nowhere else (VM-CP-03, line 3153). QMP is the hypervisor
/// process on the host reporting on itself; the guest cannot reach it.
pub trait QemuMonitor {
    /// The name of the accelerator the running QEMU reports it uses (such as `whpx`,
    /// `kvm`, `hvf` or `tcg`), not the one it was asked for.
    fn accelerator(&self, socket: &HostPath) -> Result<String, MonitorFailure>;

    /// QEMU's run state.
    fn status(&self, socket: &HostPath) -> Result<RunState, MonitorFailure>;

    /// Asks QEMU to quit. Only the host process port's proof shows that it ended.
    fn quit(&mut self, socket: &HostPath) -> Result<(), MonitorFailure>;
}

/// Why the host layout has no inputs for a launch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum LayoutRefusal {
    /// The pinned guest image is not available on this host.
    ImageNotAvailable { image: Digest },
    /// A declared data volume is not available on this host.
    VolumeNotAvailable { volume: Digest },
    /// The layout could not be read.
    Unavailable { detail: String },
}

impl fmt::Display for LayoutRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ImageNotAvailable { image } => {
                write!(
                    f,
                    "the pinned guest image {image} is not available on this host"
                )
            }
            Self::VolumeNotAvailable { volume } => {
                write!(f, "data volume {volume} is not available on this host")
            }
            Self::Unavailable { detail } => {
                write!(f, "the launch's host inputs could not be read: {detail}")
            }
        }
    }
}

impl std::error::Error for LayoutRefusal {}

/// The host inputs of one launch, and the catalog identity of the image at
/// [`QemuLaunchInputs::root_image`], as the image store verified it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostInputs {
    pub inputs: QemuLaunchInputs,
    pub guest_image: Digest,
}

/// The host layout of launches: where the pinned QEMU data, kernel and guest image are,
/// the guest's resources, the path of the private directory for the VM (the host
/// process port creates it at start) and the host path of every declared data volume.
/// A lookup: it creates nothing.
pub trait LaunchLayout {
    fn inputs(
        &self,
        request: &LaunchRequest,
        vm: VmInstanceId,
    ) -> Result<HostInputs, LayoutRefusal>;

    /// Size this launch within its ledger reservation. Fixed layouts keep their
    /// configured size; production layouts can give the guest the reserved RAM
    /// minus hypervisor overhead. The profile still verifies reservation ownership,
    /// state and the resulting memory limit before any process starts.
    fn inputs_with_reserved_resources(
        &self,
        request: &LaunchRequest,
        vm: VmInstanceId,
        _reserved_bytes: u64,
        _reserved_cpu_slots: u64,
    ) -> Result<HostInputs, LayoutRefusal> {
        self.inputs(request, vm)
    }
}
