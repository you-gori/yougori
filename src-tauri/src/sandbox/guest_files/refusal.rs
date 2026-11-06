//! What the adapter refuses beyond what the file protocol and the link refuse themselves
//! (VM part §3.2 line 2068: "parser rejection of unknown privileged operations and invalid
//! states"; §2.6 line 2004; VM-R58 and VM-R59 lines 2923–2924).
//!
//! A refusal of the dispatcher reaches the guest as the file protocol's own response. A
//! refusal of this adapter cancels the stream with the link's cause code
//! ([`FilesRefusal::cancel_cause`]) and is reported to the host; it never names a host
//! path, a key or anything of the granted tree.

use std::fmt;

use crate::foundation::ids::{ContentKey, IdError};
use crate::foundation::transfer::{StopReason, TransferRefusal};
use crate::sandbox::link::{CancelCause, Channel, GrantHandle, LimitsError, StreamId};
use crate::sandbox_contract::file_protocol::{EncodeError, RequestId, MIN_MESSAGE_BYTES};

use super::body::{AuthorityRefusal, BindingField};
use super::declaration::DeclarationRefusal;

/// Why the adapter refused an event, a stream or a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilesRefusal {
    /// A stream or credit event of another channel than the file channel.
    WrongChannel { channel: Channel },
    /// An event of the link that is not about files, such as a guest report.
    NotFileEvent,
    /// The guest answered an open on the file channel; this adapter opens no stream.
    UnexpectedAnswer { stream: StreamId },
    /// The open names a grant that is not attached to this channel.
    UnknownGrant { grant: GrantHandle },
    /// The open's declaration, or the request against it, was refused.
    Declaration(DeclarationRefusal),
    /// A message for a stream the adapter does not hold.
    UnknownStream { stream: StreamId },
    /// The link dropped a stream the host had not answered in time.
    OpenTimedOut { stream: StreamId },
    /// A message after the stream's request was answered.
    AfterAnswer,
    /// A second request on a stream that carries one.
    SecondRequest,
    /// A part of another request than the stream's.
    OtherRequest {
        expected: RequestId,
        claimed: RequestId,
    },
    /// A later part with no request of this stream, nor an interrupted body it resumes.
    NoRequest { claimed: RequestId },
    /// A part sent again on a resuming stream that is not after the one before it.
    PartNotIncreasing { part: u32, last: u32 },
    /// The guest ended the stream before its body was whole.
    BodyEndedEarly {
        held_bytes: u64,
        declared_bytes: u64,
    },
    /// The content is not the object the stream declared.
    ContentMismatch {
        declared: ContentKey,
        received: ContentKey,
    },
    /// The content runs past or falls short of its declared length.
    BodyLength { declared: u64, seen: u64 },
    /// The host's issuer refused the body.
    Authority(AuthorityRefusal),
    /// The grant the issuer returned is not bound to the body.
    NotBound { field: BindingField },
    /// CORE-05 refused or stopped the body's transfer.
    Transfer(TransferRefusal),
    /// The body's transfer operation could not be named.
    OperationName(IdError),
    /// The answer could not be written as messages.
    Encode(EncodeError),
    /// The channel's byte window is spent and the dispatcher dropped the message.
    WindowSpent,
    /// The dispatcher read the message otherwise than this adapter did; never expected.
    Disagreement,
}

impl FilesRefusal {
    /// The cause the link's cancel carries for this refusal.
    pub fn cancel_cause(&self) -> CancelCause {
        match self {
            Self::Transfer(TransferRefusal::Stopped { reason }) => stop_cause(reason),
            Self::Transfer(
                TransferRefusal::ReservationRefused { .. }
                | TransferRefusal::NetworkSlotRefused { .. }
                | TransferRefusal::BudgetExhausted { .. }
                | TransferRefusal::InFlightLimit { .. },
            )
            | Self::Authority(AuthorityRefusal::Unavailable)
            | Self::WindowSpent => CancelCause::QuotaExceeded,
            _ => CancelCause::Failed,
        }
    }
}

/// The cause a stop of the body's transfer is reported to the guest with.
pub(super) fn stop_cause(reason: &StopReason) -> CancelCause {
    if reason.is_revocation() {
        return CancelCause::Revoked;
    }
    match reason {
        StopReason::Expired { .. } | StopReason::AuthorityExpired { .. } => CancelCause::TimedOut,
        StopReason::AuthorityNotCurrent { .. }
        | StopReason::ParentWithoutAuthority { .. }
        | StopReason::ReservationWithdrawn => CancelCause::Revoked,
        StopReason::Cancelled => CancelCause::Requested,
        StopReason::EnvelopeOnOtherClock
        | StopReason::AuthorityOnOtherClock
        | StopReason::Abandoned => CancelCause::Failed,
    }
}

impl fmt::Display for FilesRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongChannel { channel } => write!(
                f,
                "a {channel} channel event was given to the file channel's adapter"
            ),
            Self::NotFileEvent => f.write_str("the link event is not about files"),
            Self::UnexpectedAnswer { stream } => write!(
                f,
                "the guest answered file stream {stream}, which this adapter did not open"
            ),
            Self::UnknownGrant { grant } => {
                write!(f, "grant {} is not attached to this channel", grant.0)
            }
            Self::Declaration(refusal) => fmt::Display::fmt(refusal, f),
            Self::UnknownStream { stream } => {
                write!(f, "file stream {stream} is not held by this channel")
            }
            Self::OpenTimedOut { stream } => {
                write!(f, "file stream {stream} was not answered in time")
            }
            Self::AfterAnswer => f.write_str("a message came after the stream's request"),
            Self::SecondRequest => f.write_str("a stream carries one request only"),
            Self::OtherRequest { expected, claimed } => write!(
                f,
                "a part of request {claimed} came on the stream of request {expected}"
            ),
            Self::NoRequest { claimed } => write!(
                f,
                "a part of request {claimed} continues no request of this stream"
            ),
            Self::PartNotIncreasing { part, last } => write!(
                f,
                "part {part} was sent again after part {last} on a resuming stream"
            ),
            Self::BodyEndedEarly {
                held_bytes,
                declared_bytes,
            } => write!(
                f,
                "the guest ended the stream after {held_bytes} of {declared_bytes} declared bytes"
            ),
            Self::ContentMismatch { declared, received } => write!(
                f,
                "the content's key is {received}, not the declared {declared}"
            ),
            Self::BodyLength { declared, seen } => {
                write!(
                    f,
                    "{seen} content bytes do not match the declared {declared}"
                )
            }
            Self::Authority(refusal) => fmt::Display::fmt(refusal, f),
            Self::NotBound { field } => write!(f, "the body's grant is not bound to it: {field}"),
            Self::Transfer(refusal) => write!(f, "the body's transfer was refused: {refusal}"),
            Self::OperationName(error) => {
                write!(
                    f,
                    "the body's transfer operation could not be named: {error}"
                )
            }
            Self::Encode(error) => write!(f, "the answer could not be written: {error}"),
            Self::WindowSpent => f.write_str("the channel's byte window is spent"),
            Self::Disagreement => {
                f.write_str("the dispatcher read the message otherwise than the channel did")
            }
        }
    }
}

impl std::error::Error for FilesRefusal {}

/// Why the adapter could not be set up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetupError {
    /// The link limits do not validate.
    Link(LimitsError),
    /// A data frame of the file channel cannot carry the shortest message bound the file
    /// protocol accepts.
    MessageRoom { room_bytes: u64, minimum: u64 },
    /// Answers could never wait for credit.
    ZeroPending,
}

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Link(error) => write!(f, "the link limits are refused: {error}"),
            Self::MessageRoom {
                room_bytes,
                minimum,
            } => write!(
                f,
                "a file channel data frame carries {room_bytes} bytes; the file protocol needs \
                 at least {minimum}"
            ),
            Self::ZeroPending => f.write_str("the bound on answers waiting for credit is zero"),
        }
    }
}

impl std::error::Error for SetupError {}

/// The least room a data frame must leave for one file protocol message.
pub(super) const MIN_ROOM_BYTES: u64 = MIN_MESSAGE_BYTES;

/// Why a grant could not be attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantError {
    /// The handle is attached already.
    Duplicate { grant: GrantHandle },
    /// The dispatcher's scope is not the channel's.
    ScopeMismatch,
    /// The dispatcher's messages do not fit one data frame of the file channel.
    MessageBound { bound_bytes: u64, room_bytes: u64 },
}

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate { grant } => write!(f, "grant {} is attached already", grant.0),
            Self::ScopeMismatch => f.write_str("the dispatcher's scope is not the channel's"),
            Self::MessageBound {
                bound_bytes,
                room_bytes,
            } => write!(
                f,
                "messages of {bound_bytes} bytes do not fit the {room_bytes} bytes a file \
                 channel data frame carries"
            ),
        }
    }
}

impl std::error::Error for GrantError {}
