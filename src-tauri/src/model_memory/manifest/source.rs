//! Source listings, the source files an import reads, and the one pass over each file
//! (GPU part §3.3 importer: "bounded source verification"; Appendix C).
//!
//! An import reads every source file exactly once, front to back. The same bytes feed the
//! header indexer, the content key of every integrity extent and the content key of the
//! whole file, so the index, the proofs and the verified file key always describe the same
//! bytes. Nothing reads a source again: read-back validation reads the staged sidecar.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::foundation::ids::ContentHasher;

use super::derive::listing_digest;
use super::digests::ContentKey;
use super::groups::{FileRole, SourceOrigin, SourceRevision};
use super::importer::CancellationToken;
use super::index::{index_weights, IndexError, IndexedFile, IndexerBounds};
use super::ports::ExtentSpan;
use super::types::RelativePath;

/// A source as listed for import: origin, immutable revision and every file with its
/// expected length, content key and role (§3.2 layer 1; Appendix C).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceListing {
    pub origin: SourceOrigin,
    pub revision: SourceRevision,
    pub files: Vec<ListedFile>,
}

/// One listed file, with the content key of the whole file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedFile {
    pub path: RelativePath,
    pub length_bytes: u64,
    pub content: ContentKey,
    pub role: FileRole,
}

impl SourceListing {
    /// The content-derived revision of `files`, for sources without a commit such as a
    /// local folder: the digest of paths, lengths and content keys in path order.
    pub fn content_revision(files: &[ListedFile]) -> SourceRevision {
        let mut sorted: Vec<&ListedFile> = files.iter().collect();
        sorted.sort_by(|left, right| left.path.cmp(&right.path));
        SourceRevision::ContentListing(listing_digest(
            sorted
                .iter()
                .map(|file| (&file.path, file.length_bytes, file.content)),
        ))
    }

    /// The files in path order.
    pub fn sorted_files(&self) -> Vec<&ListedFile> {
        let mut sorted: Vec<&ListedFile> = self.files.iter().collect();
        sorted.sort_by(|left, right| left.path.cmp(&right.path));
        sorted
    }
}

/// Why a source failed verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceError {
    TooManyFiles {
        count: u64,
        max: u64,
    },
    TooManyBytes {
        max_bytes: u64,
    },
    /// Two listed paths are equal, or equal up to ASCII case.
    DuplicateFile {
        path: RelativePath,
    },
    /// A content-listing revision that is not the listing's digest.
    RevisionMismatch,
    MissingFile {
        path: RelativePath,
    },
    /// A symlink, directory or other non-regular file on the path.
    NotARegularFile {
        path: RelativePath,
    },
    LengthMismatch {
        path: RelativePath,
        listed_bytes: u64,
        found_bytes: u64,
    },
    /// The file's bytes do not have the listed content key.
    DigestMismatch {
        path: RelativePath,
    },
    /// The file changed while it was read.
    Changed {
        path: RelativePath,
    },
    Io {
        path: RelativePath,
        kind: io::ErrorKind,
    },
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyFiles { count, max } => {
                write!(
                    f,
                    "the source lists {count} files; at most {max} are imported"
                )
            }
            Self::TooManyBytes { max_bytes } => {
                write!(f, "the source is larger than the {max_bytes}-byte bound")
            }
            Self::DuplicateFile { path } => write!(f, "file {path} is listed twice"),
            Self::RevisionMismatch => {
                f.write_str("the content revision does not match the listed files")
            }
            Self::MissingFile { path } => write!(f, "file {path} is missing"),
            Self::NotARegularFile { path } => write!(f, "{path} is not a regular file"),
            Self::LengthMismatch {
                path,
                listed_bytes,
                found_bytes,
            } => write!(
                f,
                "file {path} has {found_bytes} bytes; {listed_bytes} were listed"
            ),
            Self::DigestMismatch { path } => {
                write!(f, "file {path} does not match its content key")
            }
            Self::Changed { path } => write!(f, "file {path} changed while it was read"),
            Self::Io { path, kind } => write!(f, "reading {path} failed: {kind}"),
        }
    }
}

impl std::error::Error for SourceError {}

/// Where an import reads its source files from (Appendix C: a local folder, a registry
/// download, a pod's cache). Paths are relative to the source, and nothing outside it can
/// be named.
pub trait SourceFiles {
    /// Opens `path` for one sequential read and returns the reader with the file's
    /// current length.
    fn open(&self, path: &RelativePath) -> Result<(Box<dyn Read + '_>, u64), SourceError>;
}

/// Source files in a directory of this machine. Every path is resolved under the root;
/// a component that is a symlink, or a final component that is not a regular file, is
/// refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectorySource {
    root: PathBuf,
}

impl DirectorySource {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

fn io_error(path: &RelativePath, error: &io::Error) -> SourceError {
    SourceError::Io {
        path: path.clone(),
        kind: error.kind(),
    }
}

impl SourceFiles for DirectorySource {
    fn open(&self, path: &RelativePath) -> Result<(Box<dyn Read + '_>, u64), SourceError> {
        let mut full = self.root.clone();
        let mut components = path.components().peekable();
        while let Some(component) = components.next() {
            full.push(component);
            let metadata = match fs::symlink_metadata(&full) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Err(SourceError::MissingFile { path: path.clone() })
                }
                Err(error) => return Err(io_error(path, &error)),
            };
            let file_type = metadata.file_type();
            let last = components.peek().is_none();
            if file_type.is_symlink()
                || (last && !file_type.is_file())
                || (!last && !file_type.is_dir())
            {
                return Err(SourceError::NotARegularFile { path: path.clone() });
            }
        }
        let file = File::open(&full).map_err(|error| io_error(path, &error))?;
        let length_bytes = file
            .metadata()
            .map_err(|error| io_error(path, &error))?
            .len();
        Ok((Box::new(file), length_bytes))
    }
}

/// Why a scan stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ScanError {
    Source(SourceError),
    Index {
        path: RelativePath,
        error: IndexError,
    },
    Cancelled,
}

impl From<SourceError> for ScanError {
    fn from(error: SourceError) -> Self {
        Self::Source(error)
    }
}

/// The one pass over a file: the content key of the whole file and of every integrity
/// extent, each streamed through a [`ContentHasher`] that declares its true length first,
/// so nothing is buffered.
struct Pass<'s> {
    file: ContentHasher,
    consumed_bytes: u64,
    spans: &'s [ExtentSpan],
    next_span: usize,
    /// The extent being hashed and its bytes still to come.
    current: Option<(ContentHasher, u64)>,
    content_keys: Vec<ContentKey>,
    overrun: bool,
}

impl<'s> Pass<'s> {
    fn new(length_bytes: u64, spans: &'s [ExtentSpan]) -> Self {
        Self {
            file: ContentHasher::new(length_bytes),
            consumed_bytes: 0,
            spans,
            next_span: 0,
            current: None,
            content_keys: Vec::new(),
            overrun: false,
        }
    }

    fn feed(&mut self, mut data: &[u8]) {
        self.consumed_bytes = self.consumed_bytes.saturating_add(data.len() as u64);
        if self.file.update(data).is_err() {
            self.overrun = true;
            return;
        }
        while !data.is_empty() {
            if self.current.is_none() {
                let Some(span) = self.spans.get(self.next_span) else {
                    self.overrun = true;
                    return;
                };
                self.current = Some((
                    ContentHasher::new(span.true_length_bytes),
                    span.true_length_bytes,
                ));
            }
            let Some((extent, remaining_bytes)) = &mut self.current else {
                return;
            };
            let take = usize::try_from(*remaining_bytes)
                .unwrap_or(usize::MAX)
                .min(data.len());
            let (head, tail) = data.split_at(take);
            if extent.update(head).is_err() {
                self.overrun = true;
                return;
            }
            *remaining_bytes -= take as u64;
            data = tail;
            if *remaining_bytes == 0 {
                match self.current.take().map(|(extent, _)| extent.finish()) {
                    Some(Ok(key)) => self.content_keys.push(key),
                    _ => {
                        self.overrun = true;
                        return;
                    }
                }
                self.next_span += 1;
            }
        }
    }

    /// The whole file's key and every extent's key, once every planned byte arrived.
    fn finish(self) -> Option<(ContentKey, Vec<ContentKey>)> {
        if self.overrun || self.current.is_some() || self.next_span != self.spans.len() {
            return None;
        }
        let file = self.file.finish().ok()?;
        Some((file, self.content_keys))
    }
}

/// Reads at most `remaining_bytes` from `inner`, feeding every byte read to the pass.
struct Tee<'a, 's> {
    inner: &'a mut dyn Read,
    pass: &'a mut Pass<'s>,
    remaining_bytes: u64,
}

impl Read for Tee<'_, '_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let cap = usize::try_from(self.remaining_bytes)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let Some(window) = buffer.get_mut(..cap) else {
            return Ok(0);
        };
        if window.is_empty() {
            return Ok(0);
        }
        let read = self.inner.read(window)?.min(window.len());
        if let Some(data) = window.get(..read) {
            self.pass.feed(data);
        }
        self.remaining_bytes = self.remaining_bytes.saturating_sub(read as u64);
        Ok(read)
    }
}

/// Reads into `buffer`, retrying when interrupted.
fn read_once(reader: &mut dyn Read, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

/// What the one pass over a file found.
pub(super) struct FileScan {
    pub content: ContentKey,
    pub content_keys: Vec<ContentKey>,
    pub index: Option<IndexedFile>,
}

/// The one pass over `listed`: indexes its header when it holds weights, hashes every
/// extent of `spans` and the whole file, and checks the length and the content key.
pub(super) fn scan_file(
    source: &dyn SourceFiles,
    listed: &ListedFile,
    spans: &[ExtentSpan],
    indexer: &IndexerBounds,
    chunk_bytes: usize,
    cancel: &CancellationToken,
) -> Result<FileScan, ScanError> {
    let path = &listed.path;
    let (mut reader, found_bytes) = source.open(path)?;
    if found_bytes != listed.length_bytes {
        return Err(SourceError::LengthMismatch {
            path: path.clone(),
            listed_bytes: listed.length_bytes,
            found_bytes,
        }
        .into());
    }
    let mut pass = Pass::new(listed.length_bytes, spans);
    let index = {
        let mut tee = Tee {
            inner: &mut *reader,
            pass: &mut pass,
            remaining_bytes: listed.length_bytes,
        };
        let index = match listed.role {
            FileRole::Weights { format, .. } => Some(
                index_weights(format, &mut tee, listed.length_bytes, indexer).map_err(|error| {
                    ScanError::Index {
                        path: path.clone(),
                        error,
                    }
                })?,
            ),
            _ => None,
        };
        let mut chunk = vec![0u8; chunk_bytes.max(1)];
        loop {
            if cancel.is_cancelled() {
                return Err(ScanError::Cancelled);
            }
            if read_once(&mut tee, &mut chunk).map_err(|error| io_error(path, &error))? == 0 {
                break;
            }
        }
        index
    };
    let mut probe = [0u8; 1];
    let beyond = read_once(&mut *reader, &mut probe).map_err(|error| io_error(path, &error))?;
    let consumed_bytes = pass.consumed_bytes;
    let finished = pass.finish();
    let Some((content, content_keys)) =
        finished.filter(|_| beyond == 0 && consumed_bytes == listed.length_bytes)
    else {
        return Err(SourceError::Changed { path: path.clone() }.into());
    };
    if content != listed.content {
        return Err(SourceError::DigestMismatch { path: path.clone() }.into());
    }
    Ok(FileScan {
        content,
        content_keys,
        index,
    })
}

/// Limits of bounded source verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ListingLimits {
    pub max_files: u64,
    pub max_bytes: u64,
}

/// The bounded checks of a listing, before any file is opened: within bounds, paths
/// distinct even without case, and a content revision that matches the listing.
pub(super) fn check_listing(
    listing: &SourceListing,
    limits: &ListingLimits,
) -> Result<(), SourceError> {
    let count = listing.files.len() as u64;
    if count > limits.max_files {
        return Err(SourceError::TooManyFiles {
            count,
            max: limits.max_files,
        });
    }
    let total_bytes = listing
        .files
        .iter()
        .try_fold(0u64, |total, file| total.checked_add(file.length_bytes));
    if total_bytes.is_none_or(|total| total > limits.max_bytes) {
        return Err(SourceError::TooManyBytes {
            max_bytes: limits.max_bytes,
        });
    }
    let mut folded = std::collections::BTreeSet::new();
    for file in &listing.files {
        if !folded.insert(file.path.folded()) {
            return Err(SourceError::DuplicateFile {
                path: file.path.clone(),
            });
        }
    }
    if let SourceRevision::ContentListing(_) = listing.revision {
        if listing.revision != SourceListing::content_revision(&listing.files) {
            return Err(SourceError::RevisionMismatch);
        }
    }
    Ok(())
}
