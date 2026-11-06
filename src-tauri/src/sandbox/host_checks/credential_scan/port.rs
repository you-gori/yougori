//! The read-only port VM-CP-12's scan reads the named locations through (§17, line 3162;
//! §8.1, line 2437: host-observed facts) and its implementation over the host's file
//! system.
//!
//! [`ScanReader`] has three reads and no other operation: what an entry is, without
//! following a link; a directory's entry names, bounded; and a regular file's bytes as a
//! stream. The scan asks only for the locations its plan lists and the entries it found
//! under them, joined one listed name at a time. [`HostFiles`] serves the reads from the
//! host's file system with `std::fs`; it opens files for reading only and changes
//! nothing. A file replaced between the entry read and the open is read as it is at the
//! open; the scan runs after the launch it checks, on locations the host wrote, and does
//! not defend against a concurrent writer.

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use serde::Serialize;

use super::super::reader::{io_error, ReadError};

/// What an entry is, read without following a link.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link or, on Windows, a junction or other name surrogate.
    Link,
    /// Anything else, such as a device, a socket or a pipe.
    Other,
}

/// The read-only port to the named locations. Implementations observe and never change
/// the host.
pub trait ScanReader: Send + Sync {
    /// A regular file opened for reading.
    type File: Read;
    /// What the entry at `path` is, without following a link.
    fn entry(&self, path: &Path) -> Result<EntryKind, ReadError>;
    /// The entry names of the directory at `path`, sorted; more than `limit` is refused
    /// as [`ReadError::TooLong`].
    fn list(&self, path: &Path, limit: usize) -> Result<Vec<String>, ReadError>;
    /// The regular file at `path`, opened for reading.
    fn open(&self, path: &Path) -> Result<Self::File, ReadError>;
}

/// The host's file system, read through `std::fs`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostFiles;

impl ScanReader for HostFiles {
    type File = File;

    fn entry(&self, path: &Path) -> Result<EntryKind, ReadError> {
        let kind = fs::symlink_metadata(path).map_err(io_error)?.file_type();
        Ok(if kind.is_symlink() {
            EntryKind::Link
        } else if kind.is_dir() {
            EntryKind::Directory
        } else if kind.is_file() {
            EntryKind::File
        } else {
            EntryKind::Other
        })
    }

    fn list(&self, path: &Path, limit: usize) -> Result<Vec<String>, ReadError> {
        let mut names = Vec::new();
        for entry in fs::read_dir(path).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| ReadError::Undecodable)?;
            names.push(name);
            if names.len() > limit {
                return Err(ReadError::TooLong { limit });
            }
        }
        names.sort();
        Ok(names)
    }

    fn open(&self, path: &Path) -> Result<File, ReadError> {
        let file = File::open(path).map_err(io_error)?;
        if !file.metadata().map_err(io_error)?.is_file() {
            return Err(ReadError::WrongKind);
        }
        Ok(file)
    }
}
