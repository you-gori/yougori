//! What a guest file stream declares when it is opened, and the check of its request
//! against that declaration (VM part §3.2 line 2064: "typed operations and per-channel
//! directionality"; §2.6 line 2004; VM-R58 line 2923: typed bounded parsing).
//!
//! The link opens a file stream with a grant handle, one entry name and a mode
//! (`sandbox::link` `StreamOpen::File`). On this channel the entry and the mode say what the
//! stream will carry, so the host knows before any message what may follow and refuses a
//! request that is something else:
//!
//! - the mode is [`FileMode::Read`] for `read` and `list`, and [`FileMode::Write`] for every
//!   operation that changes the tree;
//! - the entry of a `create` or `write` is [`CONTENT_ENTRY_PREFIX`] followed by the
//!   lowercase hex of the content's [`ContentKey`]: the digest the content is verified
//!   against before the file service is called;
//! - the entry of every other operation is its wire name, such as `create_directory`.

use std::fmt;

use serde::Serialize;

use crate::foundation::ids::{ContentKey, Digest, IdError};
use crate::sandbox::link::{FileMode, LinkName};
use crate::sandbox_contract::file_protocol::GuestOperation;

/// What the entry of a create or write stream starts with, before the content key's hex.
pub const CONTENT_ENTRY_PREFIX: &str = "content-";

/// A file protocol operation, as the protocol names it on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Read,
    ReadRange,
    List,
    Create,
    CreateDirectory,
    Write,
    UploadBegin,
    UploadWrite,
    UploadTruncate,
    UploadCommit,
    UploadAbort,
    Delete,
    Rename,
    SetExecutable,
}

impl OperationKind {
    pub const ALL: [Self; 14] = [
        Self::Read,
        Self::ReadRange,
        Self::List,
        Self::Create,
        Self::CreateDirectory,
        Self::Write,
        Self::UploadBegin,
        Self::UploadWrite,
        Self::UploadTruncate,
        Self::UploadCommit,
        Self::UploadAbort,
        Self::Delete,
        Self::Rename,
        Self::SetExecutable,
    ];

    /// The name the file protocol header uses.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::ReadRange => "read_range",
            Self::List => "list",
            Self::Create => "create",
            Self::CreateDirectory => "create_directory",
            Self::Write => "write",
            Self::UploadBegin => "upload_begin",
            Self::UploadWrite => "upload_write",
            Self::UploadTruncate => "upload_truncate",
            Self::UploadCommit => "upload_commit",
            Self::UploadAbort => "upload_abort",
            Self::Delete => "delete",
            Self::Rename => "rename",
            Self::SetExecutable => "set_executable",
        }
    }

    /// The kind of `operation`.
    pub const fn of(operation: &GuestOperation) -> Self {
        match operation {
            GuestOperation::Read { .. } => Self::Read,
            GuestOperation::ReadRange { .. } => Self::ReadRange,
            GuestOperation::List { .. } => Self::List,
            GuestOperation::Create { .. } => Self::Create,
            GuestOperation::CreateDirectory { .. } => Self::CreateDirectory,
            GuestOperation::Write { .. } => Self::Write,
            GuestOperation::UploadBegin { .. } => Self::UploadBegin,
            GuestOperation::UploadWrite { .. } => Self::UploadWrite,
            GuestOperation::UploadTruncate { .. } => Self::UploadTruncate,
            GuestOperation::UploadCommit { .. } => Self::UploadCommit,
            GuestOperation::UploadAbort { .. } => Self::UploadAbort,
            GuestOperation::Delete { .. } => Self::Delete,
            GuestOperation::Rename { .. } => Self::Rename,
            GuestOperation::SetExecutable { .. } => Self::SetExecutable,
        }
    }

    /// The mode a stream carrying this operation is opened with.
    pub const fn mode(self) -> FileMode {
        match self {
            Self::Read | Self::ReadRange | Self::List => FileMode::Read,
            _ => FileMode::Write,
        }
    }

    /// Whether the operation carries content to the host, and so declares its key.
    pub const fn carries_content(self) -> bool {
        matches!(self, Self::Create | Self::Write | Self::UploadWrite)
    }

    /// The kind whose wire name is `name` among those without content.
    fn bodiless(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| !kind.carries_content() && kind.name() == name)
    }
}

impl fmt::Display for OperationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What a stream declared when it was opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "declaration", rename_all = "snake_case")]
pub enum Declaration {
    /// A create or write whose whole content is the object `content`.
    Content { content: ContentKey },
    /// One operation without content.
    Operation { kind: OperationKind },
}

/// Why a stream's declaration, or a request against it, was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "declaration_refusal", rename_all = "snake_case")]
pub enum DeclarationRefusal {
    /// The entry names neither a content key nor an operation without content.
    UnknownEntry { entry: LinkName },
    /// The mode does not fit what the entry declares.
    ModeMismatch {
        declared: FileMode,
        needed: FileMode,
    },
    /// The request is not the operation the stream declared.
    OperationMismatch {
        declared: Declaration,
        received: OperationKind,
    },
}

impl fmt::Display for DeclarationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownEntry { entry } => write!(
                f,
                "entry {entry} names neither {CONTENT_ENTRY_PREFIX}<content key> nor an operation \
                 without content"
            ),
            Self::ModeMismatch { declared, needed } => write!(
                f,
                "the stream was opened for {declared:?} but its entry needs {needed:?}"
            ),
            Self::OperationMismatch { declared, received } => match declared {
                Declaration::Content { .. } => write!(
                    f,
                    "the stream declared content for a create or write but carries {received}"
                ),
                Declaration::Operation { kind } => {
                    write!(f, "the stream declared {kind} but carries {received}")
                }
            },
        }
    }
}

impl std::error::Error for DeclarationRefusal {}

/// The lowercase hex of a key, if `text` is exactly that.
fn content_key(text: &str) -> Option<ContentKey> {
    let canonical = text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !canonical {
        return None;
    }
    Digest::from_hex(text).ok().map(ContentKey::from_digest)
}

impl Declaration {
    /// Reads what an open declares, refusing an entry that names neither a content key nor
    /// an operation without content, and a mode that does not fit it.
    pub fn parse(entry: &LinkName, mode: FileMode) -> Result<Self, DeclarationRefusal> {
        let text = entry.as_str();
        let declaration = match text.strip_prefix(CONTENT_ENTRY_PREFIX).map(content_key) {
            Some(Some(content)) => Self::Content { content },
            Some(None) => {
                return Err(DeclarationRefusal::UnknownEntry {
                    entry: entry.clone(),
                })
            }
            None => match OperationKind::bodiless(text) {
                Some(kind) => Self::Operation { kind },
                None => {
                    return Err(DeclarationRefusal::UnknownEntry {
                        entry: entry.clone(),
                    })
                }
            },
        };
        let needed = declaration.mode();
        if mode != needed {
            return Err(DeclarationRefusal::ModeMismatch {
                declared: mode,
                needed,
            });
        }
        Ok(declaration)
    }

    /// The mode the stream must be opened with.
    pub const fn mode(&self) -> FileMode {
        match self {
            Self::Content { .. } => FileMode::Write,
            Self::Operation { kind } => kind.mode(),
        }
    }

    /// The entry a guest opens the stream with.
    pub fn entry(&self) -> Result<LinkName, IdError> {
        match self {
            Self::Content { content } => LinkName::new(format!(
                "{CONTENT_ENTRY_PREFIX}{}",
                content.digest().to_hex()
            )),
            Self::Operation { kind } => LinkName::new(kind.name()),
        }
    }

    /// Whether `operation` is what the stream declared.
    pub fn admits(&self, operation: &GuestOperation) -> Result<(), DeclarationRefusal> {
        let received = OperationKind::of(operation);
        let fits = match self {
            Self::Content { .. } => received.carries_content(),
            Self::Operation { kind } => *kind == received,
        };
        if fits {
            Ok(())
        } else {
            Err(DeclarationRefusal::OperationMismatch {
                declared: *self,
                received,
            })
        }
    }
}
