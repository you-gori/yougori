//! Protocol refusals: what the file channel refuses before the file service is consulted
//! (VM part §3.2: "parser rejection of unknown privileged operations and invalid states",
//! "fixed maximum frame, message, stream and buffered-byte counts"; VM-W14).
//!
//! A [`ProtocolRefusal`] never comes from the service. A message the protocol refuses is
//! answered without a [`RequestContext`](crate::sandbox_contract::files::RequestContext)
//! being built, so it learns nothing about the granted tree. What the service refuses is
//! its own [`ServiceRefusal`](crate::sandbox_contract::files::ServiceRefusal).
//!
//! A protocol refusal names no request. The request id a refused message claimed travels
//! beside it as `claimed_request_id`, never as the response's `request_id`, because the
//! guest chooses it and can name a request in flight. Host code must never match a
//! protocol refusal to a request by id.

use std::fmt;

use serde::Serialize;

use crate::sandbox_contract::files::NameRefusal;
use crate::sandbox_contract::untrusted::{DisplayBound, GuestText, GuestTextKind};

/// Which name of a request a [`ProtocolRefusal::InvalidName`] concerns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NameField {
    /// The `name` of every operation but a rename.
    Name,
    /// A rename's source.
    From,
    /// A rename's destination.
    To,
}

impl NameField {
    /// The field as the header spells it.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::From => "from",
            Self::To => "to",
        }
    }
}

/// Why the file channel refused a message without consulting the file service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProtocolRefusal {
    /// The message is longer than the channel's message bound; none of it was read.
    MessageTooLarge {
        /// The message's length.
        bytes: u64,
        /// The channel's bound.
        limit: u64,
    },
    /// No newline ends the header within [`MAX_HEADER_BYTES`](super::MAX_HEADER_BYTES).
    HeaderTooLarge {
        /// [`MAX_HEADER_BYTES`](super::MAX_HEADER_BYTES).
        limit: u64,
    },
    /// The header is not one strict JSON request part: not JSON, no terminating newline,
    /// a missing, unknown or duplicate field, a field of the wrong type, or a part that
    /// names the request when it must not or does not when it must.
    Malformed {
        /// The parser's message, escaped and bounded as untrusted text, since it can quote
        /// the guest's input.
        detail: String,
    },
    /// The header names another protocol version; it is refused, never reinterpreted.
    UnsupportedVersion {
        /// The version the header named.
        version: u64,
        /// [`FILE_PROTOCOL_VERSION`](super::FILE_PROTOCOL_VERSION).
        supported: u32,
    },
    /// The operation is not one this protocol defines.
    UnknownOperation,
    /// A name failed the guest name rules.
    InvalidName {
        /// Which name.
        field: NameField,
        /// The name rule it failed.
        refusal: NameRefusal,
    },
    /// A read asked for more than one request may carry on this channel.
    ReadLimitTooLarge {
        /// The read's limit.
        max_bytes: u64,
        /// The most content one request carries here.
        limit: u64,
    },
    /// A create or write declared more content than one request may carry on this
    /// channel.
    ContentTooLarge {
        /// The declared length.
        length: u64,
        /// The most content one request carries here.
        limit: u64,
    },
    /// The content received is not the length the header declares; an operation without
    /// content declares none.
    LengthMismatch {
        /// The declared length.
        declared: u64,
        /// The length received so far.
        actual: u64,
    },
    /// A request with the claimed id is already being received or in flight.
    DuplicateRequestId,
    /// The channel already holds its most requests being received or in flight.
    TooManyInFlight {
        /// The channel's bound.
        limit: u32,
    },
    /// Counting these bytes would pass the channel's bytes per window.
    ByteWindowExceeded {
        /// Bytes counted in the window.
        used_bytes: u64,
        /// Bytes this message or reservation needed.
        requested_bytes: u64,
        /// The channel's bytes per window.
        limit_bytes: u64,
        /// Until the window ends, rounded up.
        retry_after_ms: u64,
    },
    /// The channel's buffer cannot hold the declared content beside what it holds already.
    BufferFull {
        /// The declared length.
        declared: u64,
        /// Bytes the buffer holds for other requests being received.
        buffered: u64,
        /// The channel's buffer bound.
        limit: u64,
    },
    /// A later part names no request being received.
    UnexpectedPart,
    /// A later part came out of order; the request it continued was discarded.
    PartOutOfOrder {
        /// The part number awaited.
        expected: u32,
        /// The part number received.
        received: u32,
    },
    /// A later part carried no content.
    EmptyPart,
    /// The admission was not made on this channel or was already finished. A host error:
    /// the service is not consulted.
    NotAdmitted,
}

impl ProtocolRefusal {
    /// A [`ProtocolRefusal::Malformed`] whose detail is escaped and bounded as untrusted
    /// text (VM part §4.7; §8.2 "bound attacker-controlled log fields").
    pub(super) fn malformed(detail: &str) -> Self {
        Self::Malformed {
            detail: GuestText::new(GuestTextKind::Other, detail, DisplayBound::DEFAULT)
                .escaped_content()
                .to_owned(),
        }
    }
}

impl fmt::Display for ProtocolRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageTooLarge { bytes, limit } => write!(
                f,
                "the message has {bytes} bytes; at most {limit} are accepted"
            ),
            Self::HeaderTooLarge { limit } => {
                write!(f, "no newline ends the header within {limit} bytes")
            }
            Self::Malformed { detail } => write!(f, "the request is malformed: {detail}"),
            Self::UnsupportedVersion { version, supported } => write!(
                f,
                "file protocol version {version} is not supported; this host reads {supported}"
            ),
            Self::UnknownOperation => f.write_str("the operation is not a file protocol operation"),
            Self::InvalidName { field, refusal } => {
                write!(f, "the {} is refused: {refusal}", field.label())
            }
            Self::ReadLimitTooLarge { max_bytes, limit } => write!(
                f,
                "a read of up to {max_bytes} bytes was asked for; one request carries at most \
                 {limit}"
            ),
            Self::ContentTooLarge { length, limit } => write!(
                f,
                "{length} content bytes were declared; one request carries at most {limit}"
            ),
            Self::LengthMismatch { declared, actual } => write!(
                f,
                "the header declares {declared} content bytes but {actual} came"
            ),
            Self::DuplicateRequestId => {
                f.write_str("a request with this id is already being received or in flight")
            }
            Self::TooManyInFlight { limit } => {
                write!(f, "the channel already has its {limit} requests in flight")
            }
            Self::ByteWindowExceeded {
                used_bytes,
                requested_bytes,
                limit_bytes,
                retry_after_ms,
            } => write!(
                f,
                "{requested_bytes} more bytes would pass the channel's {limit_bytes} bytes per \
                 window ({used_bytes} counted); the window ends in {retry_after_ms} ms"
            ),
            Self::BufferFull {
                declared,
                buffered,
                limit,
            } => write!(
                f,
                "{declared} content bytes do not fit the channel's {limit}-byte buffer beside \
                 the {buffered} it holds"
            ),
            Self::UnexpectedPart => f.write_str("the part continues no request being received"),
            Self::PartOutOfOrder { expected, received } => write!(
                f,
                "part {received} came where part {expected} was awaited; the request was \
                 discarded"
            ),
            Self::EmptyPart => f.write_str("a later part carried no content"),
            Self::NotAdmitted => f.write_str("the request was not admitted on this channel"),
        }
    }
}

impl std::error::Error for ProtocolRefusal {}
