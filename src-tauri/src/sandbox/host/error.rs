//! Why the host refused a call (module docs in `mod.rs`).

use std::fmt;

use crate::foundation::coordination::SandboxState;
use crate::foundation::ids::{ExecutionId, IdError, SandboxBootGeneration};
use crate::sandbox::guest_files::{GrantError, LinkMismatch, SetupError};
use crate::sandbox::lifecycle::SupervisorError;
use crate::sandbox::link::{Channel, GrantHandle, LimitsError, SendRefusal};

use super::terminal::CommandRefusal;

/// Why a host call was refused. A refused call changed nothing of its own; the closing of
/// channels and the recording to audit that follow every supervisor call still happened
/// and are in the host's log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostError {
    /// The supervisor refused.
    Supervisor(SupervisorError),
    /// The coordinator knows no sandbox of this execution.
    UnknownSandbox { execution: ExecutionId },
    /// Channels open only for a boot that holds authority (§6.1 line 2292).
    NoAuthority {
        execution: ExecutionId,
        state: SandboxState,
    },
    /// The supervisor keeps no handle of the current boot's VM.
    NoHandle {
        execution: ExecutionId,
        boot: SandboxBootGeneration,
    },
    /// This boot's channels are open already.
    ChannelsOpen {
        execution: ExecutionId,
        boot: SandboxBootGeneration,
    },
    /// The host closed this boot's channels; they never open again.
    ChannelsClosed {
        execution: ExecutionId,
        boot: SandboxBootGeneration,
    },
    /// The host holds no channels of this execution.
    NoChannels { execution: ExecutionId },
    /// The boot's link is still open; only a closed link is replaced.
    LinkOpen {
        execution: ExecutionId,
        boot: SandboxBootGeneration,
    },
    /// The boot's link has not completed its handshake, so no guest command ran over it.
    LinkNotOpen { execution: ExecutionId },
    /// The link's limits were refused.
    Link(LimitsError),
    /// The guest-file adapter could not be set up.
    Files(SetupError),
    /// A grant could not be attached to the file channel.
    Grant {
        grant: GrantHandle,
        error: GrantError,
    },
    /// The file channel holds no such grant.
    UnknownGrant { grant: GrantHandle },
    /// The adapter refused the boot's own link; the host never hands it another.
    Mismatch(LinkMismatch),
    /// The channel's operation identity could not be formed.
    Identifier(IdError),
    /// Teardown waits for the VM to stop.
    NotStopped {
        execution: ExecutionId,
        state: SandboxState,
    },
    /// A command could not be started or cancelled.
    Command(CommandRefusal),
    /// The egress port's write, end or cancel was refused.
    Egress {
        execution: ExecutionId,
        refusal: super::egress::EgressRefusal,
    },
    /// An ingress open, write, end or cancel was refused.
    Ingress {
        execution: ExecutionId,
        refusal: super::ingress::IngressRefusal,
    },
    /// A link of this boot was bound to this connection nonce already; every connection
    /// draws a fresh one.
    ConnectionReused {
        execution: ExecutionId,
        boot: SandboxBootGeneration,
    },
    /// A bulk channel's receive window is not the protocol's default, which the guest
    /// assumes (the welcome carries no windows).
    NonProtocolWindow {
        channel: Channel,
        window_bytes: u64,
        protocol_bytes: u64,
    },
    /// The link did not take a host message (a shutdown request).
    Unsent(SendRefusal),
    /// A transport carries this boot's link already; a second one attaches only after the
    /// first ended.
    TransportAttached {
        execution: ExecutionId,
        boot: SandboxBootGeneration,
    },
    /// No transport carries this boot's link, so none can end.
    NoTransport {
        execution: ExecutionId,
        boot: SandboxBootGeneration,
    },
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Supervisor(error) => write!(f, "{error}"),
            Self::UnknownSandbox { execution } => write!(f, "sandbox {execution} is unknown"),
            Self::NoAuthority { execution, state } => write!(
                f,
                "sandbox {execution} holds no authority while {state}, so its channels do not \
                 open"
            ),
            Self::NoHandle { execution, boot } => write!(
                f,
                "no handle is kept for the VM of boot generation {boot} of sandbox {execution}"
            ),
            Self::ChannelsOpen { execution, boot } => write!(
                f,
                "the channels of boot generation {boot} of sandbox {execution} are open already"
            ),
            Self::ChannelsClosed { execution, boot } => write!(
                f,
                "the host closed the channels of boot generation {boot} of sandbox {execution}"
            ),
            Self::NoChannels { execution } => {
                write!(f, "the host holds no channels of sandbox {execution}")
            }
            Self::LinkOpen { execution, boot } => write!(
                f,
                "the link of boot generation {boot} of sandbox {execution} is still open"
            ),
            Self::LinkNotOpen { execution } => write!(
                f,
                "the link of sandbox {execution} has not completed its handshake"
            ),
            Self::Link(error) => write!(f, "the link's limits were refused: {error}"),
            Self::Files(error) => write!(f, "{error}"),
            Self::Grant { grant, error } => {
                write!(f, "grant {} was not attached: {error}", grant.0)
            }
            Self::UnknownGrant { grant } => {
                write!(f, "the file channel holds no grant {}", grant.0)
            }
            Self::Mismatch(mismatch) => write!(f, "{mismatch}"),
            Self::Identifier(error) => write!(f, "{error}"),
            Self::NotStopped { execution, state } => write!(
                f,
                "sandbox {execution} is {state}; its boot is torn down once its VM stopped"
            ),
            Self::Command(refusal) => write!(f, "{refusal}"),
            Self::Egress { execution, refusal } => {
                write!(f, "sandbox {execution}: the egress port's call was refused: {refusal}")
            }
            Self::Ingress { execution, refusal } => {
                write!(f, "sandbox {execution}: the ingress call was refused: {refusal}")
            }
            Self::ConnectionReused { execution, boot } => write!(
                f,
                "a link of boot generation {boot} of sandbox {execution} used this connection \
                 nonce already"
            ),
            Self::NonProtocolWindow {
                channel,
                window_bytes,
                protocol_bytes,
            } => write!(
                f,
                "the {channel} window of {window_bytes} bytes is not the protocol's \
                 {protocol_bytes}, which the guest assumes"
            ),
            Self::Unsent(refusal) => write!(f, "the link did not take the message: {refusal}"),
            Self::TransportAttached { execution, boot } => write!(
                f,
                "a transport carries the link of boot generation {boot} of sandbox {execution} \
                 already"
            ),
            Self::NoTransport { execution, boot } => write!(
                f,
                "no transport carries the link of boot generation {boot} of sandbox {execution}"
            ),
        }
    }
}

impl std::error::Error for HostError {}

impl From<SupervisorError> for HostError {
    fn from(error: SupervisorError) -> Self {
        Self::Supervisor(error)
    }
}
