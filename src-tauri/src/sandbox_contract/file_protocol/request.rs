//! Guest requests: the typed, versioned request a file channel carries, and its strict
//! wire form (VM part §3.2: "one versioned protocol", "typed operations", "parser
//! rejection of unknown privileged operations"; §5.1; VM-W14; VM-R58: "typed bounded
//! parsing").
//!
//! A request is one or more messages. The first (part 0) is a header line of compact JSON
//! naming the operation, a newline, then the content bytes that fit:
//!
//! ```text
//! {"version":1,"request_id":7,"part":0,"request":{"operation":"write","name":"a.txt","length":5}}
//! hello
//! ```
//!
//! Only a create's and a write's header declare a `length`, the content's exact total; the
//! content that does not fit the first message follows in numbered parts (`parts.rs`).
//! Every other request is one message ending with the newline.
//! Names are [`GuestName`] strings, checked by the name rules before the request exists.
//! The header names no trust scope, time, clock session or root, and an unknown field
//! refuses the whole message, so a guest cannot claim any of them: the dispatcher takes
//! them from the channel and the host clock.
//!
//! Decoding is bounded before it parses: the message length first, then the header length,
//! then the version and the operation name, then the strict header, the names and the
//! content. Each step that fails gives a typed [`ProtocolRefusal`], with the request id the
//! header claimed, if it showed one, kept apart as a claim.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::parts::{header_line, split_content, EncodeError};
use super::refusal::{NameField, ProtocolRefusal};
use crate::sandbox_contract::files::{GuestName, MAX_RANGE_BYTES, MAX_READ_BYTES};

/// The file protocol version this build reads and writes.
pub const FILE_PROTOCOL_VERSION: u32 = 1;
/// The longest request header, in bytes, before the newline that ends it. Two names of
/// [`MAX_NAME_BYTES`](crate::sandbox_contract::files::MAX_NAME_BYTES), every character
/// written as a six-byte JSON escape, fit with room left.
pub const MAX_HEADER_BYTES: u64 = 16 * 1024;
/// The smallest message bound a channel may set: the longest header and its newline.
pub const MIN_MESSAGE_BYTES: u64 = MAX_HEADER_BYTES + 1;
/// The default bound on one message: 65,472 bytes, the host/guest link's file channel
/// message limit (`sandbox/link/limits.rs`, `DEFAULT_MAX_MESSAGE_BYTES`: a 65,536-byte
/// frame less its overhead). It is stated by value; this module does not depend on the
/// link.
pub const DEFAULT_MAX_MESSAGE_BYTES: u64 = 65_472;
/// The largest message bound a channel may set, and the longest message
/// [`RequestPart::decode`] reads.
pub const MAX_MESSAGE_BYTES: u64 = 1024 * 1024;
/// The most content one request carries: a create's or write's file content, or what a
/// read returns. A channel's buffer can bound it lower.
pub const MAX_CONTENT_BYTES: u64 = MAX_READ_BYTES;

/// The operation names a header may carry, as [`OperationWire`] spells them.
const OPERATION_NAMES: [&str; 14] = [
    "read",
    "read_range",
    "list",
    "create",
    "create_directory",
    "write",
    "upload_begin",
    "upload_write",
    "upload_truncate",
    "upload_commit",
    "upload_abort",
    "delete",
    "rename",
    "set_executable",
];

pub(super) fn bytes_of(length: usize) -> u64 {
    u64::try_from(length).unwrap_or(u64::MAX)
}

/// The pinned protocol version. Any other version is refused, never reinterpreted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct FileProtocolVersion(u32);

impl FileProtocolVersion {
    /// The version this build reads and writes.
    pub const CURRENT: Self = Self(FILE_PROTOCOL_VERSION);

    /// The version number.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for FileProtocolVersion {
    type Error = ProtocolRefusal;

    fn try_from(version: u32) -> Result<Self, Self::Error> {
        if version == FILE_PROTOCOL_VERSION {
            Ok(Self::CURRENT)
        } else {
            Err(ProtocolRefusal::UnsupportedVersion {
                version: u64::from(version),
                supported: FILE_PROTOCOL_VERSION,
            })
        }
    }
}

impl From<FileProtocolVersion> for u32 {
    fn from(version: FileProtocolVersion) -> Self {
        version.0
    }
}

/// The id the guest gives a request; the answer to an admitted request carries it back.
/// At most one request with an id is received or in flight on a channel at a time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(u64);

impl RequestId {
    /// The id `value`.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The id's number.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One [`FileService`](crate::sandbox_contract::files::FileService) operation as the guest
/// asks for it. Names are relative to the channel's granted root; which root that is
/// stays with the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuestOperation {
    /// Reads the whole regular file, at most `max_bytes`.
    Read { name: GuestName, max_bytes: u64 },
    /// Reads at most `max_bytes` (at most [`MAX_RANGE_BYTES`]) of the regular file from
    /// `offset`, with its size and version; of the open upload `upload` for it when given.
    ReadRange {
        name: GuestName,
        offset: u64,
        max_bytes: u64,
        upload: Option<u64>,
    },
    /// Begins an upload that will replace the regular file, empty or from its content.
    UploadBegin { name: GuestName, from_existing: bool },
    /// Writes `content` (at most [`MAX_RANGE_BYTES`]) into the upload at `offset`.
    UploadWrite {
        name: GuestName,
        upload: u64,
        offset: u64,
        content: Vec<u8>,
    },
    /// Sets the upload's length.
    UploadTruncate { name: GuestName, upload: u64, length: u64 },
    /// Puts the upload over the file in one atomic rename.
    UploadCommit { name: GuestName, upload: u64 },
    /// Gives the upload up; the file is untouched.
    UploadAbort { name: GuestName, upload: u64 },
    /// Lists a directory, or the root for `None`.
    List { name: Option<GuestName> },
    /// Creates a regular file holding `content`.
    Create { name: GuestName, content: Vec<u8> },
    /// Creates a directory.
    CreateDirectory { name: GuestName },
    /// Replaces the whole content of a regular file.
    Write { name: GuestName, content: Vec<u8> },
    /// Deletes a regular file or an empty directory.
    Delete { name: GuestName },
    /// Renames to a free name; an existing name is never replaced unless `replace`, which
    /// puts a regular file over a regular file in one atomic step (POSIX `rename`).
    Rename {
        from: GuestName,
        to: GuestName,
        replace: bool,
    },
    /// Sets or clears a regular file's execute bits.
    SetExecutable { name: GuestName, executable: bool },
}

impl GuestOperation {
    /// The content a create or write carries; `None` for every other operation.
    pub fn content(&self) -> Option<&[u8]> {
        match self {
            Self::Create { content, .. }
            | Self::Write { content, .. }
            | Self::UploadWrite { content, .. } => Some(content),
            _ => None,
        }
    }

    pub(super) fn content_mut(&mut self) -> Option<&mut Vec<u8>> {
        match self {
            Self::Create { content, .. }
            | Self::Write { content, .. }
            | Self::UploadWrite { content, .. } => Some(content),
            _ => None,
        }
    }
}

/// One whole guest request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestRequest {
    /// The id the guest gave it.
    pub id: RequestId,
    /// What it asks for, with all of its content.
    pub operation: GuestOperation,
}

/// One decoded request message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestPart {
    /// Part 0: the operation. A create's or write's `content` holds the bytes this message
    /// carried and `declared_length` the exact total; every other operation declares 0.
    Opening {
        /// The id the guest gave the request.
        id: RequestId,
        /// The operation, with the content this message carried.
        operation: GuestOperation,
        /// The content's exact total; 0 for an operation without content.
        declared_length: u64,
    },
    /// A later part of a create's or write's content; `part` counts from 1 and `content`
    /// is never empty.
    Continuation {
        /// The id of the request it continues, as the message claims it.
        id: RequestId,
        /// The part's number, from 1.
        part: u32,
        /// The next content bytes.
        content: Vec<u8>,
    },
}

/// A message that did not decode. `claimed_request_id` is the id its header claimed, if
/// it showed one; nothing proves the message belongs to that request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UndecodedRequest {
    /// The id the header claimed, if it showed one.
    pub claimed_request_id: Option<RequestId>,
    /// Why the message was refused.
    pub refusal: ProtocolRefusal,
}

impl UndecodedRequest {
    fn anonymous(refusal: ProtocolRefusal) -> Self {
        Self {
            claimed_request_id: None,
            refusal,
        }
    }
}

/// The strict header. Part 0 names the request; later parts name nothing else.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestHeaderWire {
    version: FileProtocolVersion,
    request_id: RequestId,
    part: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request: Option<OperationWire>,
}

/// The strict operation. Every variant has fields, so `deny_unknown_fields` holds for each
/// of them; a unit variant would let unknown fields beside the tag through.
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
enum OperationWire {
    Read {
        name: String,
        max_bytes: u64,
    },
    ReadRange {
        name: String,
        offset: u64,
        max_bytes: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        upload: Option<u64>,
    },
    List {
        name: Option<String>,
    },
    Create {
        name: String,
        length: u64,
    },
    CreateDirectory {
        name: String,
    },
    Write {
        name: String,
        length: u64,
    },
    UploadBegin {
        name: String,
        from_existing: bool,
    },
    UploadWrite {
        name: String,
        upload: u64,
        offset: u64,
        length: u64,
    },
    UploadTruncate {
        name: String,
        upload: u64,
        length: u64,
    },
    UploadCommit {
        name: String,
        upload: u64,
    },
    UploadAbort {
        name: String,
        upload: u64,
    },
    Delete {
        name: String,
    },
    Rename {
        from: String,
        to: String,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        replace: bool,
    },
    SetExecutable {
        name: String,
        executable: bool,
    },
}

crate::foundation::strict_serde::strict_tag!(OperationWire, "operation");

/// Reads the header as a JSON value before the strict parse, so an unsupported version and
/// an unknown operation are told apart from a malformed header, and so the header and its
/// request are JSON objects (serde would also read a struct written as an array). It
/// refuses nothing the strict parse accepts; duplicate fields, of which a value keeps the
/// last, are the strict parse's to refuse. Returns the claimed request id.
fn probe(header: &[u8]) -> Result<Option<RequestId>, UndecodedRequest> {
    let value: Value = serde_json::from_slice(header).map_err(|error| {
        UndecodedRequest::anonymous(ProtocolRefusal::malformed(&error.to_string()))
    })?;
    let Value::Object(fields) = &value else {
        return Err(UndecodedRequest::anonymous(ProtocolRefusal::malformed(
            "the header is not a JSON object",
        )));
    };
    let claimed_request_id = fields
        .get("request_id")
        .and_then(Value::as_u64)
        .map(RequestId::new);
    let refused = |refusal| UndecodedRequest {
        claimed_request_id,
        refusal,
    };
    match fields.get("version").map(Value::as_u64) {
        None => {
            return Err(refused(ProtocolRefusal::malformed(
                "missing field `version`",
            )))
        }
        Some(None) => {
            return Err(refused(ProtocolRefusal::malformed(
                "the version is not an unsigned integer",
            )))
        }
        Some(Some(version)) if version != u64::from(FILE_PROTOCOL_VERSION) => {
            return Err(refused(ProtocolRefusal::UnsupportedVersion {
                version,
                supported: FILE_PROTOCOL_VERSION,
            }))
        }
        Some(Some(_)) => {}
    }
    let request = match fields.get("request") {
        // A later part; the strict parse checks the rest.
        None | Some(Value::Null) => return Ok(claimed_request_id),
        Some(Value::Object(request)) => request,
        Some(_) => {
            return Err(refused(ProtocolRefusal::malformed(
                "the request is not a JSON object",
            )))
        }
    };
    match request.get("operation") {
        Some(Value::String(operation)) if OPERATION_NAMES.contains(&operation.as_str()) => {
            Ok(claimed_request_id)
        }
        Some(Value::String(_)) => Err(refused(ProtocolRefusal::UnknownOperation)),
        _ => Err(refused(ProtocolRefusal::malformed(
            "the request names no operation",
        ))),
    }
}

fn guest_name(text: &str, field: NameField) -> Result<GuestName, ProtocolRefusal> {
    GuestName::parse(text).map_err(|refusal| ProtocolRefusal::InvalidName { field, refusal })
}

fn no_content(content: &[u8]) -> Result<(), ProtocolRefusal> {
    if content.is_empty() {
        Ok(())
    } else {
        Err(ProtocolRefusal::LengthMismatch {
            declared: 0,
            actual: bytes_of(content.len()),
        })
    }
}

/// The first content bytes of a create or write declaring `length` in all.
fn first_content(length: u64, content: &[u8]) -> Result<Vec<u8>, ProtocolRefusal> {
    if length > MAX_CONTENT_BYTES {
        return Err(ProtocolRefusal::ContentTooLarge {
            length,
            limit: MAX_CONTENT_BYTES,
        });
    }
    let actual = bytes_of(content.len());
    if actual > length {
        return Err(ProtocolRefusal::LengthMismatch {
            declared: length,
            actual,
        });
    }
    Ok(content.to_vec())
}

impl OperationWire {
    /// The typed operation and its declared content length: names through the name rules,
    /// then the content checks.
    fn into_opening(self, content: &[u8]) -> Result<(GuestOperation, u64), ProtocolRefusal> {
        let bodiless = |operation: GuestOperation| no_content(content).map(|()| (operation, 0));
        match self {
            Self::Read { name, max_bytes } => {
                let name = guest_name(&name, NameField::Name)?;
                if max_bytes > MAX_READ_BYTES {
                    return Err(ProtocolRefusal::ReadLimitTooLarge {
                        max_bytes,
                        limit: MAX_READ_BYTES,
                    });
                }
                bodiless(GuestOperation::Read { name, max_bytes })
            }
            Self::ReadRange {
                name,
                offset,
                max_bytes,
                upload,
            } => {
                let name = guest_name(&name, NameField::Name)?;
                if max_bytes > MAX_RANGE_BYTES {
                    return Err(ProtocolRefusal::ReadLimitTooLarge {
                        max_bytes,
                        limit: MAX_RANGE_BYTES,
                    });
                }
                bodiless(GuestOperation::ReadRange {
                    name,
                    offset,
                    max_bytes,
                    upload,
                })
            }
            Self::UploadBegin {
                name,
                from_existing,
            } => {
                let name = guest_name(&name, NameField::Name)?;
                bodiless(GuestOperation::UploadBegin {
                    name,
                    from_existing,
                })
            }
            Self::UploadWrite {
                name,
                upload,
                offset,
                length,
            } => {
                let name = guest_name(&name, NameField::Name)?;
                if length > MAX_RANGE_BYTES {
                    return Err(ProtocolRefusal::ContentTooLarge {
                        length,
                        limit: MAX_RANGE_BYTES,
                    });
                }
                let content = first_content(length, content)?;
                Ok((
                    GuestOperation::UploadWrite {
                        name,
                        upload,
                        offset,
                        content,
                    },
                    length,
                ))
            }
            Self::UploadTruncate {
                name,
                upload,
                length,
            } => {
                let name = guest_name(&name, NameField::Name)?;
                bodiless(GuestOperation::UploadTruncate {
                    name,
                    upload,
                    length,
                })
            }
            Self::UploadCommit { name, upload } => {
                let name = guest_name(&name, NameField::Name)?;
                bodiless(GuestOperation::UploadCommit { name, upload })
            }
            Self::UploadAbort { name, upload } => {
                let name = guest_name(&name, NameField::Name)?;
                bodiless(GuestOperation::UploadAbort { name, upload })
            }
            Self::List { name } => {
                let name = name
                    .map(|name| guest_name(&name, NameField::Name))
                    .transpose()?;
                bodiless(GuestOperation::List { name })
            }
            Self::Create { name, length } => {
                let name = guest_name(&name, NameField::Name)?;
                let content = first_content(length, content)?;
                Ok((GuestOperation::Create { name, content }, length))
            }
            Self::CreateDirectory { name } => {
                let name = guest_name(&name, NameField::Name)?;
                bodiless(GuestOperation::CreateDirectory { name })
            }
            Self::Write { name, length } => {
                let name = guest_name(&name, NameField::Name)?;
                let content = first_content(length, content)?;
                Ok((GuestOperation::Write { name, content }, length))
            }
            Self::Delete { name } => {
                let name = guest_name(&name, NameField::Name)?;
                bodiless(GuestOperation::Delete { name })
            }
            Self::Rename { from, to, replace } => {
                let from = guest_name(&from, NameField::From)?;
                let to = guest_name(&to, NameField::To)?;
                bodiless(GuestOperation::Rename { from, to, replace })
            }
            Self::SetExecutable { name, executable } => {
                let name = guest_name(&name, NameField::Name)?;
                bodiless(GuestOperation::SetExecutable { name, executable })
            }
        }
    }
}

impl RequestPart {
    /// Decodes one message, refusing it with a typed [`ProtocolRefusal`] unless it is
    /// exactly one strict, current-version part with valid names and content within its
    /// declaration. Whether a later part belongs to a request being received is the
    /// dispatcher's to check.
    pub fn decode(payload: &[u8]) -> Result<Self, UndecodedRequest> {
        let length = bytes_of(payload.len());
        if length > MAX_MESSAGE_BYTES {
            return Err(UndecodedRequest::anonymous(
                ProtocolRefusal::MessageTooLarge {
                    bytes: length,
                    limit: MAX_MESSAGE_BYTES,
                },
            ));
        }
        let header_window = usize::try_from(MAX_HEADER_BYTES)
            .unwrap_or(usize::MAX)
            .saturating_add(1);
        let Some(end) = payload
            .iter()
            .take(header_window)
            .position(|byte| *byte == b'\n')
        else {
            return Err(UndecodedRequest::anonymous(if length > MAX_HEADER_BYTES {
                ProtocolRefusal::HeaderTooLarge {
                    limit: MAX_HEADER_BYTES,
                }
            } else {
                ProtocolRefusal::malformed("no newline ends the header")
            }));
        };
        let header = payload.get(..end).unwrap_or_default();
        let content = payload.get(end.saturating_add(1)..).unwrap_or_default();

        let claimed_request_id = probe(header)?;
        let refused = |refusal| UndecodedRequest {
            claimed_request_id,
            refusal,
        };
        let wire: RequestHeaderWire = serde_json::from_slice(header)
            .map_err(|error| refused(ProtocolRefusal::malformed(&error.to_string())))?;
        match (wire.part, wire.request) {
            (0, Some(request)) => {
                let (operation, declared_length) =
                    request.into_opening(content).map_err(refused)?;
                Ok(Self::Opening {
                    id: wire.request_id,
                    operation,
                    declared_length,
                })
            }
            (0, None) => Err(refused(ProtocolRefusal::malformed(
                "the first part names no request",
            ))),
            (_, Some(_)) => Err(refused(ProtocolRefusal::malformed(
                "only the first part names the request",
            ))),
            (_, None) if content.is_empty() => Err(refused(ProtocolRefusal::EmptyPart)),
            (part, None) => Ok(Self::Continuation {
                id: wire.request_id,
                part,
                content: content.to_vec(),
            }),
        }
    }
}

impl GuestRequest {
    /// The messages the guest sends for this request, each at most `max_message_bytes`:
    /// one, or for content that does not fit, the first and its numbered parts. The
    /// content is not checked against the bounds; the dispatcher does that.
    pub fn encode(&self, max_message_bytes: u64) -> Result<Vec<Vec<u8>>, EncodeError> {
        let text = |name: &GuestName| name.as_str().to_owned();
        let request = match &self.operation {
            GuestOperation::Read { name, max_bytes } => OperationWire::Read {
                name: text(name),
                max_bytes: *max_bytes,
            },
            GuestOperation::ReadRange {
                name,
                offset,
                max_bytes,
                upload,
            } => OperationWire::ReadRange {
                name: text(name),
                offset: *offset,
                max_bytes: *max_bytes,
                upload: *upload,
            },
            GuestOperation::UploadBegin {
                name,
                from_existing,
            } => OperationWire::UploadBegin {
                name: text(name),
                from_existing: *from_existing,
            },
            GuestOperation::UploadWrite {
                name,
                upload,
                offset,
                content,
            } => OperationWire::UploadWrite {
                name: text(name),
                upload: *upload,
                offset: *offset,
                length: bytes_of(content.len()),
            },
            GuestOperation::UploadTruncate {
                name,
                upload,
                length,
            } => OperationWire::UploadTruncate {
                name: text(name),
                upload: *upload,
                length: *length,
            },
            GuestOperation::UploadCommit { name, upload } => OperationWire::UploadCommit {
                name: text(name),
                upload: *upload,
            },
            GuestOperation::UploadAbort { name, upload } => OperationWire::UploadAbort {
                name: text(name),
                upload: *upload,
            },
            GuestOperation::List { name } => OperationWire::List {
                name: name.as_ref().map(text),
            },
            GuestOperation::Create { name, content } => OperationWire::Create {
                name: text(name),
                length: bytes_of(content.len()),
            },
            GuestOperation::CreateDirectory { name } => {
                OperationWire::CreateDirectory { name: text(name) }
            }
            GuestOperation::Write { name, content } => OperationWire::Write {
                name: text(name),
                length: bytes_of(content.len()),
            },
            GuestOperation::Delete { name } => OperationWire::Delete { name: text(name) },
            GuestOperation::Rename { from, to, replace } => OperationWire::Rename {
                from: text(from),
                to: text(to),
                replace: *replace,
            },
            GuestOperation::SetExecutable { name, executable } => OperationWire::SetExecutable {
                name: text(name),
                executable: *executable,
            },
        };
        let first = header_line(&RequestHeaderWire {
            version: FileProtocolVersion::CURRENT,
            request_id: self.id,
            part: 0,
            request: Some(request),
        })?;
        let mut messages = Vec::new();
        split_content(
            self.id,
            first,
            self.operation.content().unwrap_or_default(),
            max_message_bytes,
            &mut |header, chunk| {
                let mut message = Vec::with_capacity(header.len().saturating_add(chunk.len()));
                message.extend_from_slice(header);
                message.extend_from_slice(chunk);
                messages.push(message);
            },
        )?;
        Ok(messages)
    }
}
