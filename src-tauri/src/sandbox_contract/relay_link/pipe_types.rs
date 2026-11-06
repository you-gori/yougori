//! What the relay link's adapters share on every platform (M09C; VM part §6.4 and VM-CP-19):
//! the host calls their errors name, why a peer was refused, the adapters' errors, and the
//! PX1 judgement of the process at the other end ([`judge_peer`]). The Windows named pipes
//! (`pipe`, `control_pipe`) and the Linux control socket (`control_unix`) use them alike.

use std::fmt;

use super::session::LinkRefusal;
use crate::foundation::process::{IdentityCheck, ProcessError, ProcessIdentity};

/// The local pipe namespace on Windows; a name on another computer is refused.
pub(super) const LOCAL_PIPE_PREFIX: &str = r"\\.\pipe\";

/// The longest pipe name after [`LOCAL_PIPE_PREFIX`].
pub(super) const MAX_PIPE_NAME_CHARS: usize = 200;

/// The longest path of a Unix control socket: a socket address holds 108 bytes with the
/// terminating NUL.
pub(super) const MAX_SOCKET_PATH_BYTES: usize = 107;

/// A host call of the adapter, for errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipeCall {
    ReadUser,
    BuildDacl,
    CreatePipe,
    CreateEvent,
    Connect,
    ClientProcess,
    ServerProcess,
    OpenPipe,
    Read,
    Write,
}

impl fmt::Display for PipeCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReadUser => "read the current user",
            Self::BuildDacl => "build the pipe's DACL",
            Self::CreatePipe => "create the pipe",
            Self::CreateEvent => "create an event",
            Self::Connect => "wait for a client",
            Self::ClientProcess => "read the client's process",
            Self::ServerProcess => "read the server's process",
            Self::OpenPipe => "open the pipe",
            Self::Read => "read from the pipe",
            Self::Write => "write to the pipe",
        })
    }
}

/// Why a peer was refused before any frame was read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerRefusal {
    /// A process other than the registered one is at the other end.
    OtherProcess { pid: u32 },
    /// The registered PID names another process now (VM-CP-19).
    PidReused { registered: ProcessIdentity },
    /// The registered process is gone.
    Gone { registered: ProcessIdentity },
}

impl fmt::Display for PeerRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherProcess { pid } => {
                write!(f, "process {pid} is not the registered process")
            }
            Self::PidReused { registered } => {
                write!(f, "the PID of {registered} names another process now")
            }
            Self::Gone { registered } => write!(f, "{registered} is gone"),
        }
    }
}

/// Why the adapter failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PipeError {
    /// The name is not a local pipe name of the accepted form.
    InvalidName,
    HostCall {
        call: PipeCall,
        os_error: u32,
    },
    TimedOut,
    /// The other end closed or was disconnected.
    Disconnected,
    /// The listener's instance went to an admitted connection or was closed.
    Spent,
    Peer(PeerRefusal),
    /// PX1 could not look the peer's PID up; the peer was refused.
    Identity(ProcessError),
    Link(LinkRefusal),
}

impl fmt::Display for PipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName if cfg!(windows) => write!(
                f,
                "a link pipe is named {LOCAL_PIPE_PREFIX} and 1 to {MAX_PIPE_NAME_CHARS} \
                 letters, digits, '-', '_' or '.'"
            ),
            Self::InvalidName => write!(
                f,
                "a control socket is named by an absolute path of at most \
                 {MAX_SOCKET_PATH_BYTES} bytes of letters, digits, '/', '-', '_' or '.'"
            ),
            Self::HostCall { call, os_error } => {
                write!(f, "could not {call} (OS error {os_error})")
            }
            Self::TimedOut => f.write_str("the pipe did not answer in time"),
            Self::Disconnected => f.write_str("the other end of the pipe is gone"),
            Self::Spent => f.write_str("the listener has no instance left"),
            Self::Peer(refusal) => write!(f, "the peer was refused: {refusal}"),
            Self::Identity(error) => write!(f, "the peer could not be identified: {error}"),
            Self::Link(refusal) => fmt::Display::fmt(refusal, f),
        }
    }
}

impl std::error::Error for PipeError {}

impl From<LinkRefusal> for PipeError {
    fn from(refusal: LinkRefusal) -> Self {
        Self::Link(refusal)
    }
}

/// Whether the process with `pid` at the other end is exactly `registered`: the same PID,
/// which `check` (PX1's [`ProcessIdentity::check`] in the adapter) finds still naming the
/// same process, creation time included.
pub(super) fn judge_peer(
    registered: &ProcessIdentity,
    pid: u32,
    check: impl FnOnce(&ProcessIdentity) -> Result<IdentityCheck, ProcessError>,
) -> Result<(), PipeError> {
    if pid != registered.pid {
        return Err(PipeError::Peer(PeerRefusal::OtherProcess { pid }));
    }
    match check(registered).map_err(PipeError::Identity)? {
        IdentityCheck::Same => Ok(()),
        IdentityCheck::Reused => Err(PipeError::Peer(PeerRefusal::PidReused {
            registered: *registered,
        })),
        IdentityCheck::Gone => Err(PipeError::Peer(PeerRefusal::Gone {
            registered: *registered,
        })),
    }
}
