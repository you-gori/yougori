//! Numbered parts: every message within the channel's message bound (VM part §3.2: "fixed
//! maximum frame, message, stream and buffered-byte counts"; VM-W14).
//!
//! A request or response whose content does not fit one message continues in later
//! messages under the same request id, numbered from 1 in order: a header line such as
//! `{"version":1,"request_id":7,"part":1}`, then the next content bytes (a listing's
//! continuation carries its next `entries` in the header instead). The first part declares
//! the exact total, a content `length` or a listing's `entry_count`, so the receiver knows
//! which part is the last.

use std::fmt;

use serde::Serialize;

use super::request::{bytes_of, FileProtocolVersion, RequestId};

/// Why a request or response could not be written as messages within the bound.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EncodeError {
    /// A header line, or a listing page with its first entry, does not fit one message.
    DoesNotFit { bytes: u64, limit: u64 },
    /// More parts than a part number holds.
    TooManyParts,
    /// A header could not be serialized.
    Serialize { detail: String },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DoesNotFit { bytes, limit } => write!(
                f,
                "a header of {bytes} bytes does not fit a message of at most {limit}"
            ),
            Self::TooManyParts => f.write_str("the content needs more parts than are numbered"),
            Self::Serialize { detail } => write!(f, "a header could not be written: {detail}"),
        }
    }
}

impl std::error::Error for EncodeError {}

impl From<serde_json::Error> for EncodeError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialize {
            detail: error.to_string(),
        }
    }
}

/// The header of a later part of content, for requests and responses alike.
#[derive(Serialize)]
pub(super) struct ContinuationWire {
    pub(super) version: FileProtocolVersion,
    pub(super) request_id: RequestId,
    pub(super) part: u32,
}

/// `value` as one header line: compact JSON and its newline.
pub(super) fn header_line(value: &impl Serialize) -> Result<Vec<u8>, EncodeError> {
    let mut line = serde_json::to_vec(value)?;
    line.push(b'\n');
    Ok(line)
}

/// Refuses a message longer than `limit`.
pub(super) fn fits(message_bytes: u64, limit: u64) -> Result<(), EncodeError> {
    if message_bytes > limit {
        return Err(EncodeError::DoesNotFit {
            bytes: message_bytes,
            limit,
        });
    }
    Ok(())
}

/// Writes the header line `first` and `content` as messages of at most `limit` bytes: the
/// first carries as much content as fits after `first`, each later one a continuation
/// header and the next content. `emit` gets each message's header line and content.
pub(super) fn split_content(
    request_id: RequestId,
    first: Vec<u8>,
    content: &[u8],
    limit: u64,
    emit: &mut dyn FnMut(&[u8], &[u8]),
) -> Result<(), EncodeError> {
    let mut header = first;
    let mut rest = content;
    let mut part: u32 = 0;
    loop {
        let header_bytes = bytes_of(header.len());
        fits(header_bytes, limit)?;
        let room = usize::try_from(limit.saturating_sub(header_bytes)).unwrap_or(usize::MAX);
        let take = room.min(rest.len());
        if part > 0 && take == 0 {
            // A continuation that carries nothing would never end.
            return Err(EncodeError::DoesNotFit {
                bytes: header_bytes.saturating_add(1),
                limit,
            });
        }
        let Some((chunk, remaining)) = rest.split_at_checked(take) else {
            return Err(EncodeError::DoesNotFit {
                bytes: header_bytes,
                limit,
            });
        };
        emit(&header, chunk);
        rest = remaining;
        if rest.is_empty() {
            return Ok(());
        }
        part = part.checked_add(1).ok_or(EncodeError::TooManyParts)?;
        header = header_line(&ContinuationWire {
            version: FileProtocolVersion::CURRENT,
            request_id,
            part,
        })?;
    }
}
