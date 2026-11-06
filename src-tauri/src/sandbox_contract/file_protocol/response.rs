//! Responses: what the host sends back (VM part §3.2, §5.1; VM-W14).
//!
//! The answer to an admitted request is one or more messages under its id. The first is a
//! header line of compact JSON and a newline, followed by the content a read returned as
//! far as it fits; the header declares the content's exact total `length`:
//!
//! ```text
//! {"version":1,"request_id":7,"part":0,"outcome":{"kind":"read","length":5}}
//! hello
//! ```
//!
//! The rest of the content follows in numbered parts (`parts.rs`). A
//! listing declares its `entry_count` and carries its entries in pages: the first page in
//! the first header's `entries`, later pages as `{"version":1,"request_id":7,"part":1,
//! "entries":[...]}`. Every other answer is one message. Listings and refusals are the file
//! service's own [`Listing`] entries and [`ServiceRefusal`].
//!
//! A [`ProtocolRefusal`] is attributed to no request: its top-level `request_id` is
//! `null`, and the id the refused message claimed travels as `claimed_request_id` inside
//! the outcome. Host code must never match a protocol refusal to a request by id.
//!
//! Every message is at most the channel's message bound; [`FileResponse::encode`] refuses
//! with an [`EncodeError`] rather than write a longer one. Responses are written by the
//! host and never read back by it.

use serde::Serialize;

use super::parts::{fits, header_line, split_content, EncodeError};
use super::refusal::ProtocolRefusal;
use super::request::{bytes_of, FileProtocolVersion, RequestId};
use crate::foundation::ids::ContentKey;
use crate::sandbox_contract::files::{ListedEntry, Listing, ServiceRefusal};

/// The longest a [`ListedEntry`] serializes to: a 255-byte name and the longest kind, a
/// file of `u64::MAX` bytes.
pub const MAX_LISTED_ENTRY_BYTES: u64 = 384;

/// What a performed request achieved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Completed {
    /// A read's content.
    Read { content: Vec<u8> },
    /// A ranged read's bytes, with the file's size and version.
    RangeRead {
        content: Vec<u8>,
        size_bytes: u64,
        version: String,
    },
    /// An upload was begun: its number and size.
    UploadBegun { upload: u64, size_bytes: u64 },
    /// An upload's size after a write or a truncation.
    UploadWritten { size_bytes: u64 },
    /// An upload was put over its file: its size and content key.
    UploadCommitted { size_bytes: u64, content: ContentKey },
    /// An upload was given up.
    UploadAborted,
    /// A listing.
    Listed { listing: Listing },
    /// A create's file exists.
    Created,
    /// A directory was created.
    DirectoryCreated,
    /// A write replaced the file's content.
    Written,
    /// The entry was deleted.
    Deleted,
    /// The entry was renamed.
    Renamed,
    /// The execute bits were set or cleared.
    ExecutableSet,
}

/// How an admitted request ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponseOutcome {
    /// The service performed it.
    Completed(Completed),
    /// The service refused it.
    ServiceRefused(ServiceRefusal),
    /// The host gave it back unperformed, such as after a timeout.
    Cancelled,
}

/// One response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileResponse {
    /// The answer to an admitted request, under its id, which was in flight and unique on
    /// the channel.
    Answer {
        /// The admitted request's id.
        request_id: RequestId,
        /// How it ended.
        outcome: ResponseOutcome,
    },
    /// A refused message. It names no request; `claimed_request_id` is only what the
    /// message claimed.
    Refusal {
        /// The id the refused message claimed, if it showed one; never proof of a request.
        claimed_request_id: Option<RequestId>,
        /// Why it was refused.
        refusal: ProtocolRefusal,
    },
}

#[derive(Serialize)]
struct ResponseHeaderWire<'a> {
    version: FileProtocolVersion,
    request_id: Option<RequestId>,
    part: u32,
    outcome: OutcomeWire<'a>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum OutcomeWire<'a> {
    Read {
        length: u64,
    },
    ReadRange {
        length: u64,
        size_bytes: u64,
        version: &'a str,
    },
    UploadBegun {
        upload: u64,
        size_bytes: u64,
    },
    UploadWritten {
        size_bytes: u64,
    },
    UploadCommitted {
        size_bytes: u64,
        content: String,
    },
    UploadAborted,
    Listed {
        entry_count: u64,
        unaddressable: u64,
        truncated: bool,
        entries: &'a [ListedEntry],
    },
    Created,
    DirectoryCreated,
    Written,
    Deleted,
    Renamed,
    ExecutableSet,
    Cancelled,
    ServiceRefused {
        refusal: &'a ServiceRefusal,
    },
    ProtocolRefused {
        claimed_request_id: Option<RequestId>,
        refusal: &'a ProtocolRefusal,
    },
}

/// A later page of a listing.
#[derive(Serialize)]
struct EntriesContinuationWire<'a> {
    version: FileProtocolVersion,
    request_id: RequestId,
    part: u32,
    entries: &'a [ListedEntry],
}

fn answer_header(request_id: RequestId, outcome: OutcomeWire<'_>) -> Result<Vec<u8>, EncodeError> {
    header_line(&ResponseHeaderWire {
        version: FileProtocolVersion::CURRENT,
        request_id: Some(request_id),
        part: 0,
        outcome,
    })
}

/// Writes a single-message header line.
fn single(
    header: Vec<u8>,
    limit: u64,
    emit: &mut dyn FnMut(&[u8], &[u8]),
) -> Result<(), EncodeError> {
    fits(bytes_of(header.len()), limit)?;
    emit(&header, &[]);
    Ok(())
}

/// Writes `listing` in pages of at most `limit` bytes, each holding as many entries as fit.
fn split_listing(
    request_id: RequestId,
    listing: &Listing,
    limit: u64,
    emit: &mut dyn FnMut(&[u8], &[u8]),
) -> Result<(), EncodeError> {
    let entries = listing.entries.as_slice();
    let sizes = entries
        .iter()
        .map(|entry| serde_json::to_vec(entry).map(|bytes| bytes_of(bytes.len())))
        .collect::<Result<Vec<u64>, _>>()?;
    let page = |part: u32, slice: &[ListedEntry]| {
        if part == 0 {
            answer_header(
                request_id,
                OutcomeWire::Listed {
                    entry_count: bytes_of(entries.len()),
                    unaddressable: listing.unaddressable,
                    truncated: listing.truncated,
                    entries: slice,
                },
            )
        } else {
            header_line(&EntriesContinuationWire {
                version: FileProtocolVersion::CURRENT,
                request_id,
                part,
                entries: slice,
            })
        }
    };
    let mut start = 0;
    let mut part: u32 = 0;
    loop {
        // An empty page's length, then each entry and its comma while they fit.
        let mut total = bytes_of(page(part, &[])?.len());
        let mut end = start;
        while let Some(size) = sizes.get(end) {
            let added = size.saturating_add(u64::from(end > start));
            if total.saturating_add(added) > limit {
                break;
            }
            total = total.saturating_add(added);
            end += 1;
        }
        if end == start {
            if let Some(size) = sizes.get(start) {
                return Err(EncodeError::DoesNotFit {
                    bytes: total.saturating_add(*size),
                    limit,
                });
            }
        }
        let bytes = page(part, entries.get(start..end).unwrap_or_default())?;
        fits(bytes_of(bytes.len()), limit)?;
        emit(&bytes, &[]);
        start = end;
        if start >= entries.len() {
            return Ok(());
        }
        part = part.checked_add(1).ok_or(EncodeError::TooManyParts)?;
    }
}

impl FileResponse {
    /// A refusal of a message that claimed `claimed_request_id`.
    pub fn refusal(claimed_request_id: Option<RequestId>, refusal: ProtocolRefusal) -> Self {
        Self::Refusal {
            claimed_request_id,
            refusal,
        }
    }

    /// Hands each message's header line and content to `emit`.
    fn write(&self, limit: u64, emit: &mut dyn FnMut(&[u8], &[u8])) -> Result<(), EncodeError> {
        match self {
            Self::Refusal {
                claimed_request_id,
                refusal,
            } => {
                let header = header_line(&ResponseHeaderWire {
                    version: FileProtocolVersion::CURRENT,
                    request_id: None,
                    part: 0,
                    outcome: OutcomeWire::ProtocolRefused {
                        claimed_request_id: *claimed_request_id,
                        refusal,
                    },
                })?;
                single(header, limit, emit)
            }
            Self::Answer {
                request_id,
                outcome,
            } => {
                let small = match outcome {
                    ResponseOutcome::Completed(Completed::Read { content }) => {
                        let first = answer_header(
                            *request_id,
                            OutcomeWire::Read {
                                length: bytes_of(content.len()),
                            },
                        )?;
                        return split_content(*request_id, first, content, limit, emit);
                    }
                    ResponseOutcome::Completed(Completed::RangeRead {
                        content,
                        size_bytes,
                        version,
                    }) => {
                        let first = answer_header(
                            *request_id,
                            OutcomeWire::ReadRange {
                                length: bytes_of(content.len()),
                                size_bytes: *size_bytes,
                                version,
                            },
                        )?;
                        return split_content(*request_id, first, content, limit, emit);
                    }
                    ResponseOutcome::Completed(Completed::UploadBegun { upload, size_bytes }) => {
                        OutcomeWire::UploadBegun {
                            upload: *upload,
                            size_bytes: *size_bytes,
                        }
                    }
                    ResponseOutcome::Completed(Completed::UploadWritten { size_bytes }) => {
                        OutcomeWire::UploadWritten {
                            size_bytes: *size_bytes,
                        }
                    }
                    ResponseOutcome::Completed(Completed::UploadCommitted {
                        size_bytes,
                        content,
                    }) => OutcomeWire::UploadCommitted {
                        size_bytes: *size_bytes,
                        content: content.digest().to_hex(),
                    },
                    ResponseOutcome::Completed(Completed::UploadAborted) => {
                        OutcomeWire::UploadAborted
                    }
                    ResponseOutcome::Completed(Completed::Listed { listing }) => {
                        return split_listing(*request_id, listing, limit, emit);
                    }
                    ResponseOutcome::Completed(Completed::Created) => OutcomeWire::Created,
                    ResponseOutcome::Completed(Completed::DirectoryCreated) => {
                        OutcomeWire::DirectoryCreated
                    }
                    ResponseOutcome::Completed(Completed::Written) => OutcomeWire::Written,
                    ResponseOutcome::Completed(Completed::Deleted) => OutcomeWire::Deleted,
                    ResponseOutcome::Completed(Completed::Renamed) => OutcomeWire::Renamed,
                    ResponseOutcome::Completed(Completed::ExecutableSet) => {
                        OutcomeWire::ExecutableSet
                    }
                    ResponseOutcome::Cancelled => OutcomeWire::Cancelled,
                    ResponseOutcome::ServiceRefused(refusal) => {
                        OutcomeWire::ServiceRefused { refusal }
                    }
                };
                single(answer_header(*request_id, small)?, limit, emit)
            }
        }
    }

    /// The messages the host sends, each at most `max_message_bytes`.
    pub fn encode(&self, max_message_bytes: u64) -> Result<Vec<Vec<u8>>, EncodeError> {
        let mut messages = Vec::new();
        self.write(max_message_bytes, &mut |header, content| {
            let mut message = Vec::with_capacity(header.len().saturating_add(content.len()));
            message.extend_from_slice(header);
            message.extend_from_slice(content);
            messages.push(message);
        })?;
        Ok(messages)
    }

    /// The total length of [`FileResponse::encode`]'s messages, counted without copying
    /// the content.
    pub fn encoded_len(&self, max_message_bytes: u64) -> Result<u64, EncodeError> {
        let mut total: u64 = 0;
        self.write(max_message_bytes, &mut |header, content| {
            total = total
                .saturating_add(bytes_of(header.len()))
                .saturating_add(bytes_of(content.len()));
        })?;
        Ok(total)
    }
}
