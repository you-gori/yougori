//! Why a call of the service was refused or failed (module docs in `mod.rs`). Every error
//! is typed and `Serialize`; none carries a secret, and the texts it carries are the
//! committed errors' own `Display`, which name no secret either.

use std::fmt;
use std::time::Duration;

use serde::Serialize;

use crate::foundation::coordination::{LaunchFailure, SandboxState, TerminationStalled};
use crate::sandbox::host::{CommandRefusal, HostError};
use crate::sandbox::lifecycle::SupervisorError;
use crate::sandbox::link::{CloseCause, NonceRefusal};
use crate::sandbox::link_transport::{EndpointRefusal, TransportEnd};

use super::dto::{BootPhase, CommandId, DirectoryRemoval, SandboxId, VmStop};

/// A request outside its bounds; nothing was done.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum RequestProblem {
    /// A launch must reserve some host memory.
    NoMemory,
    /// A launch must hold at least one CPU initialization slot.
    NoCpuSlots,
    WorkloadImage {
        detail: String,
    },
    /// A command's deadline must be from 1 ms to the maximum.
    DeadlineOutOfRange {
        deadline_ms: u128,
        max_ms: u128,
    },
    /// A lease limit the launch asked for was refused (raised above its default, or zero).
    LeaseLimit {
        detail: String,
    },
}

impl RequestProblem {
    pub(super) fn deadline(deadline: Duration, max: Duration) -> Self {
        Self::DeadlineOutOfRange {
            deadline_ms: deadline.as_millis(),
            max_ms: max.as_millis(),
        }
    }
}

/// The sandbox host's refusal, in a form a caller can read: the supervisor's and the
/// command path's refusals stay typed, and the host's own setup refusals keep their
/// `Display`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostRefusal {
    Supervisor {
        error: SupervisorError,
    },
    Command {
        refusal: CommandRefusal,
    },
    UnknownSandbox,
    /// The boot holds no authority in this state.
    NoAuthority {
        state: SandboxState,
    },
    /// The host closed the boot's channels.
    ChannelsClosed,
    /// The host holds no channels of the sandbox.
    NoChannels,
    /// The boot's link has not completed its handshake, or closed.
    LinkNotOpen,
    /// Any other refusal of the host, by its own text.
    Other {
        detail: String,
    },
}

impl From<HostError> for HostRefusal {
    fn from(error: HostError) -> Self {
        match error {
            HostError::Supervisor(error) => Self::Supervisor { error },
            HostError::Command(refusal) => Self::Command { refusal },
            HostError::UnknownSandbox { .. } => Self::UnknownSandbox,
            HostError::NoAuthority { state, .. } => Self::NoAuthority { state },
            HostError::ChannelsClosed { .. } => Self::ChannelsClosed,
            HostError::NoChannels { .. } => Self::NoChannels,
            HostError::LinkNotOpen { .. } => Self::LinkNotOpen,
            other => Self::Other {
                detail: other.to_string(),
            },
        }
    }
}

impl fmt::Display for HostRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Supervisor { error } => write!(f, "{error}"),
            Self::Command { refusal } => write!(f, "{refusal}"),
            Self::UnknownSandbox => f.write_str("the sandbox is unknown to the host"),
            Self::NoAuthority { state } => write!(f, "the boot holds no authority while {state}"),
            Self::ChannelsClosed => f.write_str("the host closed the boot's channels"),
            Self::NoChannels => f.write_str("the host holds no channels of the sandbox"),
            Self::LinkNotOpen => f.write_str("the boot's link is not open"),
            Self::Other { detail } => f.write_str(detail),
        }
    }
}

/// The step of a launch that failed after the VM existed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum LaunchStep {
    /// The backend holds no process for the VM the supervisor recorded.
    NoProcess,
    /// The host port knows no private directory of the QEMU process.
    NoPrivateDirectory,
    /// The link socket was not connected, or its peer is not the QEMU process the backend
    /// started (then the sandbox is revoked as a violation).
    LinkSocket { refusal: EndpointRefusal },
    /// The host port gave no bootstrap secret for the process (it gives it once).
    NoSecret,
    /// No connection nonce could be drawn from the OS generator.
    Nonce { refusal: NonceRefusal },
    /// The host refused to open the boot's channels.
    Channels { refusal: HostRefusal },
    /// The session pump was refused, by its own text.
    Pump { detail: String },
    /// The boot's transport driver thread could not be started.
    Driver { detail: String },
    /// The link closed before the guest's hello completed its handshake.
    NoHello { cause: CloseCause },
    /// The stream ended before the guest's hello.
    TransportEnded { end: Option<TransportEnd> },
    /// The host closed the boot's channels before the guest's hello (a revocation or a
    /// lost authority meanwhile).
    ChannelsClosed,
    /// The service shut down during the launch.
    ShutDown,
    /// The connection gate did not attach the sandbox with its declared services.
    Publications { detail: String },
}

/// How far the cleanup of a failed launch got: the VM's stop through its handle and the
/// private directory, each as observed, and whether any channel of the boot is still open.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LaunchCleanup {
    /// The supervisor's refusal of the revocation that stops the VM, if it refused.
    pub revocation_refused: Option<HostRefusal>,
    pub vm_stop: VmStop,
    pub directory: DirectoryRemoval,
    /// Whether the host still holds an open channel of the boot (it should not).
    pub channels_open: bool,
}

impl LaunchCleanup {
    /// Whether the failed launch left nothing: the VM stopped with the host's proof, its
    /// directory gone and no channel open.
    pub fn left_nothing(&self) -> bool {
        matches!(self.vm_stop, VmStop::Stopped { .. })
            && self.directory.is_removed()
            && !self.channels_open
    }
}

/// Why a call of the service was refused or failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VmServiceError {
    /// The request is outside its bounds; nothing was done.
    InvalidRequest { problem: RequestProblem },
    /// The service knows no such sandbox.
    UnknownSandbox { sandbox: SandboxId },
    /// The sandbox is not ready for this call: still starting, stopping or ended.
    NotReady {
        sandbox: SandboxId,
        phase: BootPhase,
    },
    /// The sandbox's link is gone (the guest closed it, the stream ended, a timeout); no
    /// command runs over it.
    LinkLost {
        sandbox: SandboxId,
        cause: Option<CloseCause>,
    },
    /// The sandbox was revoked or stopped; new work is denied.
    Revoked { sandbox: SandboxId },
    /// The sandbox has no such command, running or ended and unclaimed.
    UnknownCommand {
        sandbox: SandboxId,
        command: CommandId,
    },
    /// The host's CORE-01 evidence for a launch could not be refreshed, or does not admit
    /// the runtime as a VM sandbox; nothing was launched.
    Evidence { step: EvidenceStep, detail: String },
    /// The launch transaction gave no authority: every completed step was undone and no
    /// capability was exposed (§6.1 line 2304).
    LaunchRolledBack { failure: LaunchFailure },
    /// The launch's rollback stalled; what it could not undo is in `stall`.
    LaunchRollbackStalled {
        failure: LaunchFailure,
        stall: TerminationStalled,
    },
    /// The capacity port queued the launch; the service does not queue.
    LaunchQueued { position: u32 },
    /// A step after the VM existed failed. The sandbox was revoked through the supervisor
    /// to stop the VM through its handle; `cleanup` says how far that got.
    LaunchFailed {
        sandbox: SandboxId,
        step: LaunchStep,
        cleanup: LaunchCleanup,
    },
    /// The supervisor refused.
    Supervisor { error: SupervisorError },
    /// The terminal command path refused.
    Command { refusal: CommandRefusal },
    /// The sandbox host refused otherwise.
    Host { refusal: HostRefusal },
    /// The staged workspace could not be attached: its folder, grant or dispatcher was
    /// refused, by that refusal's text.
    Workspace { detail: String },
    /// A caller's ingress stream was refused: a listener name of another form, or the
    /// sandbox's bound on streams.
    Ingress { detail: String },
    /// A sandbox connection's endpoints or grant were refused (M14), by the refusal's text.
    Connection { detail: String },
    /// A remote control session or its real parent-bound delegation was refused.
    RemoteControl { detail: String },
    /// The service is shutting down or shut down.
    ShuttingDown,
}

/// Which evidence step of a launch failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStep {
    /// Refreshing the hypervisor's availability through the host's probe.
    Hypervisor,
    /// Refreshing the runtime's category through the host's probe.
    RuntimeCategory,
    /// Offering the runtime on that evidence.
    Offer,
    /// Admitting the offer as a VM sandbox.
    Admission,
}

impl VmServiceError {
    /// The error of a host call made for `sandbox`: a revocation, an unknown sandbox and a
    /// lost link are said as such; `link_closed` is how the boot's link closed, if it did.
    pub(super) fn of_host(
        sandbox: &SandboxId,
        error: HostError,
        link_closed: Option<CloseCause>,
    ) -> Self {
        match error {
            HostError::Supervisor(SupervisorError::Revoked { .. }) => Self::Revoked {
                sandbox: sandbox.clone(),
            },
            HostError::Supervisor(SupervisorError::UnknownSandbox { .. })
            | HostError::UnknownSandbox { .. } => Self::UnknownSandbox {
                sandbox: sandbox.clone(),
            },
            HostError::Supervisor(error) => Self::Supervisor { error },
            HostError::Command(refusal) => Self::Command { refusal },
            HostError::LinkNotOpen { .. } | HostError::ChannelsClosed { .. } => Self::LinkLost {
                sandbox: sandbox.clone(),
                cause: link_closed,
            },
            other => Self::Host {
                refusal: HostRefusal::from(other),
            },
        }
    }
}

impl fmt::Display for VmServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RemoteControl { detail } => write!(f, "remote VM control: {detail}"),
            Self::InvalidRequest { problem } => match problem {
                RequestProblem::NoMemory => f.write_str("a launch must reserve host memory"),
                RequestProblem::WorkloadImage { detail } => {
                    write!(f, "image declaration: {detail}")
                }
                RequestProblem::NoCpuSlots => {
                    f.write_str("a launch must hold a CPU initialization slot")
                }
                RequestProblem::DeadlineOutOfRange {
                    deadline_ms,
                    max_ms,
                } => write!(
                    f,
                    "a deadline of {deadline_ms} ms is not between 1 ms and {max_ms} ms"
                ),
                RequestProblem::LeaseLimit { detail } => {
                    write!(f, "the lease limits were refused: {detail}")
                }
            },
            Self::UnknownSandbox { sandbox } => write!(f, "sandbox {sandbox} is unknown"),
            Self::NotReady { sandbox, phase } => {
                write!(f, "sandbox {sandbox} is not ready ({phase:?})")
            }
            Self::LinkLost { sandbox, cause } => match cause {
                Some(cause) => write!(f, "the link of sandbox {sandbox} closed: {cause}"),
                None => write!(f, "the link of sandbox {sandbox} is gone"),
            },
            Self::Revoked { sandbox } => {
                write!(f, "sandbox {sandbox} was revoked; new work is denied")
            }
            Self::UnknownCommand { sandbox, command } => {
                write!(f, "sandbox {sandbox} has no {command}")
            }
            Self::Evidence { step, detail } => {
                write!(f, "the launch's host evidence ({step:?}) failed: {detail}")
            }
            Self::LaunchRolledBack { failure } => {
                write!(f, "the launch was rolled back: {failure:?}")
            }
            Self::LaunchRollbackStalled { failure, stall } => write!(
                f,
                "the launch failed ({failure:?}) and its rollback stalled: {stall:?}"
            ),
            Self::LaunchQueued { position } => write!(
                f,
                "the launch was queued at position {position}; the service does not queue"
            ),
            Self::LaunchFailed {
                sandbox,
                step,
                cleanup,
            } => write!(
                f,
                "the launch of sandbox {sandbox} failed at {step:?}; its VM {} and it left \
                 {}",
                if cleanup.vm_stop.is_stopped() {
                    "was stopped"
                } else {
                    "is not shown stopped"
                },
                if cleanup.left_nothing() {
                    "nothing"
                } else {
                    "something behind"
                }
            ),
            Self::Supervisor { error } => write!(f, "{error}"),
            Self::Command { refusal } => write!(f, "{refusal}"),
            Self::Host { refusal } => write!(f, "{refusal}"),
            Self::Workspace { detail } => {
                write!(f, "the workspace could not be attached: {detail}")
            }
            Self::Ingress { detail } => write!(f, "the ingress stream was refused: {detail}"),
            Self::Connection { detail } => {
                write!(f, "the sandbox connection was refused: {detail}")
            }
            Self::ShuttingDown => f.write_str("the VM service is shutting down"),
        }
    }
}

impl std::error::Error for VmServiceError {}
