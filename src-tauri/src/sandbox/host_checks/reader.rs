//! The read-only sysfs port of VM-CP-31's host part (§17, line 3181; §8.1, line 2437:
//! host-observed facts) and its one implementation over a directory tree.
//!
//! [`SysfsReader`] has three reads and no other operation: an attribute file's bytes up
//! to a limit, a link's target and a directory's entry names, each for one
//! [`SysfsNode`] of the closed set. [`SysfsDir`] serves them from a directory in one of
//! two layouts:
//!
//! - [`Layout::Native`]: a mounted sysfs, such as `/sys`, or a copy that keeps the
//!   kernel's names and symbolic links. The caller chooses the root; nothing in this
//!   module names `/sys` or reads it.
//! - [`Layout::Recorded`]: a recording of the same entries that any file system can
//!   hold: every `:` in a name is stored as `%3A` (and `%` as `%25`), and every link is a
//!   regular file named after it with `.link` appended, holding the target as the kernel
//!   wrote it, optionally followed by one newline. A link that names a directory keeps
//!   that directory beside it, so `bus/pci/devices/0000%3A01%3A00.0.link` holds the
//!   device's path and `bus/pci/devices/0000%3A01%3A00.0/` its attributes.
//!
//! Both layouts read through the same bounded file and directory code; they differ only
//! in where a node is stored and how a link is read.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::node::{NodeKind, SysfsNode};

/// The longest link target accepted (Linux `PATH_MAX`).
pub const MAX_LINK_BYTES: usize = 4096;

/// The most entries one directory read accepts.
pub const MAX_ENTRIES: usize = 256;

/// The suffix of a recorded link's file.
pub const RECORDED_LINK_SUFFIX: &str = ".link";

/// The read-only port to the host's sysfs. Implementations observe and never change the
/// host; every read is of one node of the closed set, by the method its kind takes.
pub trait SysfsReader: Send + Sync {
    /// The bytes of the attribute file `node`; more than `limit` bytes is refused.
    fn read(&self, node: &SysfsNode, limit: usize) -> Result<Vec<u8>, ReadError>;
    /// The target of the link `node`, as the kernel wrote it.
    fn link(&self, node: &SysfsNode) -> Result<String, ReadError>;
    /// The entry names of the directory `node`, sorted.
    fn list(&self, node: &SysfsNode) -> Result<Vec<String>, ReadError>;
}

/// Why a read returned nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "read", rename_all = "snake_case")]
pub enum ReadError {
    /// Nothing is there.
    Missing,
    /// It is there and the host refused the read.
    Denied,
    /// It holds more than the read accepts.
    TooLong { limit: usize },
    /// It is not the kind of entry the read is for, or the read is not the one its node
    /// takes.
    WrongKind,
    /// Its name or target is not text, or not in the recorded layout's encoding.
    Undecodable,
    /// The host's read failed in another way.
    Failed,
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => f.write_str("it does not exist"),
            Self::Denied => f.write_str("the host refused the read"),
            Self::TooLong { limit } => write!(f, "it holds more than {limit} bytes or entries"),
            Self::WrongKind => f.write_str("it is not the kind of entry the read is for"),
            Self::Undecodable => f.write_str("its name or target cannot be decoded"),
            Self::Failed => f.write_str("the read failed"),
        }
    }
}

impl std::error::Error for ReadError {}

/// How a [`SysfsDir`] stores links and names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Layout {
    /// The kernel's names and symbolic links.
    Native,
    /// Names with `:` encoded and links as `.link` files.
    Recorded,
}

/// A sysfs tree in a directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SysfsDir {
    root: PathBuf,
    layout: Layout,
}

impl SysfsDir {
    /// A mounted sysfs or a copy in the kernel's own layout, rooted at `root`.
    pub fn native(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            layout: Layout::Native,
        }
    }

    /// A recording in the portable layout, rooted at `root`.
    pub fn recorded(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            layout: Layout::Recorded,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub const fn layout(&self) -> Layout {
        self.layout
    }

    /// Where `node` is stored under this tree: in the recorded layout, a link's `.link`
    /// file.
    pub fn location(&self, node: &SysfsNode) -> PathBuf {
        let components = node.components();
        match self.layout {
            Layout::Native => components
                .iter()
                .fold(self.root.clone(), |path, component| path.join(component)),
            Layout::Recorded => {
                let last = components.len().saturating_sub(1);
                components
                    .iter()
                    .enumerate()
                    .fold(self.root.clone(), |path, (index, component)| {
                        let mut name = encode_component(component);
                        if index == last && node.kind() == NodeKind::Link {
                            name.push_str(RECORDED_LINK_SUFFIX);
                        }
                        path.join(name)
                    })
            }
        }
    }
}

impl SysfsReader for SysfsDir {
    fn read(&self, node: &SysfsNode, limit: usize) -> Result<Vec<u8>, ReadError> {
        if node.kind() != NodeKind::File {
            return Err(ReadError::WrongKind);
        }
        read_bounded(&self.location(node), limit)
    }

    fn link(&self, node: &SysfsNode) -> Result<String, ReadError> {
        if node.kind() != NodeKind::Link {
            return Err(ReadError::WrongKind);
        }
        let location = self.location(node);
        match self.layout {
            Layout::Native => {
                let metadata = fs::symlink_metadata(&location).map_err(io_error)?;
                if !metadata.file_type().is_symlink() {
                    return Err(ReadError::WrongKind);
                }
                let target = fs::read_link(&location).map_err(io_error)?;
                target
                    .to_str()
                    .map(str::to_owned)
                    .ok_or(ReadError::Undecodable)
            }
            Layout::Recorded => {
                let bytes = read_bounded(&location, MAX_LINK_BYTES)?;
                let text = String::from_utf8(bytes).map_err(|_| ReadError::Undecodable)?;
                Ok(text.strip_suffix('\n').unwrap_or(&text).to_owned())
            }
        }
    }

    fn list(&self, node: &SysfsNode) -> Result<Vec<String>, ReadError> {
        if node.kind() != NodeKind::Directory {
            return Err(ReadError::WrongKind);
        }
        let location = self.location(node);
        if !fs::metadata(&location).map_err(io_error)?.is_dir() {
            return Err(ReadError::WrongKind);
        }
        let mut names = BTreeSet::new();
        for entry in fs::read_dir(&location).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(ReadError::Undecodable)?;
            let name = match self.layout {
                Layout::Native => name.to_owned(),
                Layout::Recorded => {
                    let stored = name.strip_suffix(RECORDED_LINK_SUFFIX).unwrap_or(name);
                    decode_component(stored).ok_or(ReadError::Undecodable)?
                }
            };
            names.insert(name);
            if names.len() > MAX_ENTRIES {
                return Err(ReadError::TooLong { limit: MAX_ENTRIES });
            }
        }
        Ok(names.into_iter().collect())
    }
}

/// A name as the recorded layout stores it: `%` as `%25` and `:` as `%3A`.
pub fn encode_component(name: &str) -> String {
    let mut encoded = String::with_capacity(name.len());
    for character in name.chars() {
        match character {
            '%' => encoded.push_str("%25"),
            ':' => encoded.push_str("%3A"),
            other => encoded.push(other),
        }
    }
    encoded
}

/// The name a recorded entry stands for; `None` for any `%` that is not `%25` or `%3A`.
pub fn decode_component(stored: &str) -> Option<String> {
    let mut decoded = String::with_capacity(stored.len());
    let mut rest = stored;
    while let Some(index) = rest.find('%') {
        decoded.push_str(&rest[..index]);
        let escape = rest.get(index..index + 3)?;
        decoded.push(match escape {
            "%25" => '%',
            "%3A" => ':',
            _ => return None,
        });
        rest = &rest[index + 3..];
    }
    decoded.push_str(rest);
    Some(decoded)
}

/// The bytes of the regular file at `path`, refusing more than `limit`.
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, ReadError> {
    if !fs::metadata(path).map_err(io_error)?.is_file() {
        return Err(ReadError::WrongKind);
    }
    let file = File::open(path).map_err(io_error)?;
    let bound = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    file.take(bound).read_to_end(&mut bytes).map_err(io_error)?;
    if bytes.len() > limit {
        return Err(ReadError::TooLong { limit });
    }
    Ok(bytes)
}

/// The read error an I/O error stands for.
pub(super) fn io_error(error: io::Error) -> ReadError {
    match error.kind() {
        io::ErrorKind::NotFound => ReadError::Missing,
        io::ErrorKind::PermissionDenied => ReadError::Denied,
        _ => ReadError::Failed,
    }
}
