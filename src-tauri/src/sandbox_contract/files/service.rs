//! The host file service over one grant (VM part §5.1: "A grant binds a host-selected root
//! handle, permitted operations, trust scope, expiry and quota"; VM-W14; M12).
//!
//! A [`FileService`] pairs a [`FileGrant`] with the [`GrantedRoot`] the host opened for it
//! and refuses a grant for any other root. Every request is checked against the grant
//! (clock session, expiry, root, trust scope and operation) before any name is looked at,
//! so a request the grant does not permit learns nothing about the tree; the quota is
//! checked once the sizes involved are known. The request is then performed through the
//! root's handles: names are resolved one component at a time, links, reparse points,
//! hard-linked files, devices, mount crossings and case aliases are refused and never
//! followed, new files and directories are created exclusively, a rename never replaces an
//! existing name, and a write replaces the whole file atomically by a rename from a staging
//! file beside it. The service counts what the root holds when it opens and keeps the count
//! as it changes the tree; a root it cannot count within the quota (too many entries, or an
//! entry it cannot read) refuses every change until a recount succeeds.
//!
//! The modes keep their meaning (§5.1): a read-only snapshot's grant permits no change, a
//! quarantine output reaches the host only through promotion ([`super::apply_in`]), and a
//! live workspace is writable by the workload, so its host-state claim stays the weaker one.
//! The guest reaches this service only over the host/guest transport (VM-W06), which is not
//! part of this module.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::Duration;

use cap_std::fs::{Dir, File};

use serde::Serialize;

use super::fsutil::{self, HandleInfo, HandleKind, ReadProblem};
use super::grant::{
    FileGrant, FileOperation, FileQuota, FileRequest, GrantRefusal, HostStateClaim, QuotaUsage,
};
use super::names::GuestName;
use super::resolve::{LinkKind, ResolveIntent, ResolveRefusal, Resolved};
use super::root::{EntryProblem, GrantedRoot, Walk};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{ContentKey, MonotonicTime, TrustScope};

/// The most bytes one read returns.
pub const MAX_READ_BYTES: u64 = 64 * 1024 * 1024;
/// The most bytes one ranged read returns, and one upload chunk carries: a file of any size
/// moves in pieces of at most this, so neither side holds more of it at once.
pub const MAX_RANGE_BYTES: u64 = 1024 * 1024;
/// The most uploads one grant has open at once.
pub const MAX_UPLOADS: usize = 8;
/// How long an upload may go untouched before it is given up.
pub const UPLOAD_IDLE: Duration = Duration::from_secs(15 * 60);
/// The most entries one listing returns.
pub const MAX_LISTED_ENTRIES: usize = 4096;
/// Attempts at a free staging name before a write gives up.
const STAGING_ATTEMPTS: u32 = 16;

/// Who asks and when: the requester's trust scope and the host clock's reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestContext {
    pub scope: TrustScope,
    pub now: MonotonicTime,
    pub session: ClockSession,
}

/// What a listed entry is. Links and devices are listed as what they are, never followed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ListedKind {
    File { size_bytes: u64, executable: bool },
    Directory,
    Link { link: LinkKind },
    Device,
}

/// One entry of a listing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ListedEntry {
    /// The entry's name, a single valid guest component.
    pub name: GuestName,
    pub kind: ListedKind,
}

/// A directory listing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Listing {
    pub entries: Vec<ListedEntry>,
    /// Entries whose names are not valid guest names; the guest could not address them.
    pub unaddressable: u64,
    /// More than [`MAX_LISTED_ENTRIES`] entries were present.
    pub truncated: bool,
}

/// Why a request was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServiceRefusal {
    /// The grant names another root than the one opened.
    RootMismatch,
    Grant {
        refusal: GrantRefusal,
    },
    Resolve {
        refusal: ResolveRefusal,
    },
    /// The name is a directory where a regular file is needed. A regular file where a
    /// directory is needed is the resolver's `NotADirectory`.
    NotAFile {
        name: GuestName,
    },
    AlreadyExists {
        name: GuestName,
    },
    DirectoryNotEmpty {
        name: GuestName,
    },
    ReadTooLarge {
        name: GuestName,
        size_bytes: u64,
        limit: u64,
    },
    /// The entry changed while the service worked on it.
    Changed {
        name: GuestName,
    },
    /// The service could not count what the root holds within the quota (more entries than
    /// it allows, or an entry it cannot read), so it cannot know the usage a change would
    /// reach; changes are refused until a recount succeeds.
    UsageUnknown,
    /// This grant has no upload area: its files move whole.
    UploadsUnavailable,
    /// No upload of that number is open: committed, aborted, given up after
    /// [`UPLOAD_IDLE`], or never begun.
    UnknownUpload { upload: u64 },
    /// The grant has [`MAX_UPLOADS`] open already.
    TooManyUploads { limit: usize },
    /// The upload is for another file than the request names.
    UploadNameMismatch { upload: u64 },
    Io {
        operation: FileOperation,
        name: Option<GuestName>,
        detail: String,
    },
}

impl fmt::Display for ServiceRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootMismatch => f.write_str("the grant is for another root"),
            Self::Grant { refusal } => write!(f, "{refusal}"),
            Self::Resolve { refusal } => write!(f, "{refusal}"),
            Self::NotAFile { name } => write!(f, "{name} is not a regular file"),
            Self::AlreadyExists { name } => write!(f, "{name} already exists"),
            Self::DirectoryNotEmpty { name } => write!(f, "{name} is not empty"),
            Self::ReadTooLarge {
                name,
                size_bytes,
                limit,
            } => write!(
                f,
                "{name} has {size_bytes} bytes; one read returns at most {limit}"
            ),
            Self::Changed { name } => write!(f, "{name} changed during the request"),
            Self::UsageUnknown => f.write_str(
                "what the root holds could not be counted within the quota; changes are refused",
            ),
            Self::UploadsUnavailable => f.write_str("this grant moves files whole; it has no uploads"),
            Self::UnknownUpload { upload } => write!(f, "upload {upload} is not open"),
            Self::TooManyUploads { limit } => write!(f, "the grant has {limit} uploads open already"),
            Self::UploadNameMismatch { upload } => write!(f, "upload {upload} is for another file"),
            Self::Io {
                operation,
                name: Some(name),
                detail,
            } => write!(f, "{operation:?} of {name} failed: {detail}"),
            Self::Io {
                operation,
                name: None,
                detail,
            } => write!(f, "{operation:?} failed: {detail}"),
        }
    }
}

impl std::error::Error for ServiceRefusal {}

fn io_refusal(
    operation: FileOperation,
    name: &GuestName,
    error: &std::io::Error,
) -> ServiceRefusal {
    ServiceRefusal::Io {
        operation,
        name: Some(name.clone()),
        detail: format!("{:?}", error.kind()),
    }
}

/// The refusal for a failed handle step of `operation` on `name`.
fn entry_refusal(
    operation: FileOperation,
    name: &GuestName,
    problem: EntryProblem,
) -> ServiceRefusal {
    match problem {
        EntryProblem::Refused(refusal) => ServiceRefusal::Resolve { refusal },
        EntryProblem::NotAFile => ServiceRefusal::NotAFile { name: name.clone() },
        EntryProblem::Changed => ServiceRefusal::Changed { name: name.clone() },
        EntryProblem::Io(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            ServiceRefusal::AlreadyExists { name: name.clone() }
        }
        EntryProblem::Io(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
            ServiceRefusal::DirectoryNotEmpty { name: name.clone() }
        }
        EntryProblem::Io(error) => io_refusal(operation, name, &error),
    }
}

fn bytes_of(length: usize) -> u64 {
    u64::try_from(length).unwrap_or(u64::MAX)
}

/// What the root holds, or `None` when it cannot be counted within `quota`: more entries
/// than it allows, or an entry or directory the service cannot read, whose size would
/// otherwise escape the total. Each entry is read without following it and without the
/// right to read its content, so a file another process holds locked still counts, and so
/// does an entry no guest name can address.
fn count_usage(root: &GrantedRoot, quota: FileQuota) -> std::io::Result<Option<QuotaUsage>> {
    let mut usage = QuotaUsage::default();
    let mut pending = VecDeque::from([root.dir().try_clone()?]);
    while let Some(directory) = pending.pop_front() {
        let Ok(entries) = fsutil::read_directory(&directory) else {
            return Ok(None);
        };
        for entry in entries {
            let Ok(entry) = entry else {
                return Ok(None);
            };
            let name = entry.name;
            let info = match fsutil::entry_info(&directory, &name) {
                Ok(info) => info,
                // Removed since it was listed.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Ok(None),
            };
            usage.entries = usage.entries.saturating_add(1);
            if usage.entries > quota.max_entries {
                return Ok(None);
            }
            if info.volume != root.volume() {
                continue;
            }
            match info.kind {
                HandleKind::File => usage.total_bytes = usage.total_bytes.saturating_add(info.size),
                HandleKind::Directory => {
                    let opened = fsutil::open_entry(&directory, &name)
                        .and_then(|file| Ok((fsutil::file_info(&file)?, file)));
                    match opened {
                        Ok((opened_info, file)) if opened_info.is(&info) => {
                            pending.push_back(fsutil::into_dir(file));
                        }
                        _ => return Ok(None),
                    }
                }
                HandleKind::Link(_) | HandleKind::Device => {}
            }
        }
    }
    Ok(Some(usage))
}

/// The host file service for one grant.
#[derive(Debug)]
pub struct FileService {
    grant: FileGrant,
    root: GrantedRoot,
    usage: Option<QuotaUsage>,
    staging: u64,
    /// Where uploads are assembled, for a grant that has them ([`FileService::with_uploads`]).
    uploads: Option<Uploads>,
}

/// What a ranged read returns: the bytes from the offset asked, the file's size, and its
/// version, which changes when the file is replaced or its size changes, so a reader that
/// reads a file in ranges can tell it read one file throughout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeRead {
    pub content: Vec<u8>,
    pub size_bytes: u64,
    pub version: String,
}

/// The version of the open file `info` describes.
fn version_of(info: &HandleInfo) -> String {
    format!("{:x}-{:x}-{:x}-{:x}", info.volume, info.index, info.created, info.size)
}

/// Reads at most `max_bytes` of `file` from `offset`.
fn read_at(file: &mut File, offset: u64, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))?;
    let mut content = Vec::with_capacity(usize::try_from(max_bytes.min(MAX_RANGE_BYTES)).unwrap_or(0));
    file.take(max_bytes.min(MAX_RANGE_BYTES)).read_to_end(&mut content)?;
    Ok(content)
}

/// A grant's uploads: a host directory outside the granted root on the root's volume, so an
/// upload in progress is under no guest name, and its commit is one rename into the tree.
#[derive(Debug)]
struct Uploads {
    dir: Dir,
    next: u64,
    open: BTreeMap<u64, Upload>,
}

/// One file being assembled for `name` in the upload area.
#[derive(Debug)]
struct Upload {
    name: GuestName,
    component: String,
    file: File,
    info: HandleInfo,
    size: u64,
    touched: MonotonicTime,
}

impl Uploads {
    /// Removes the upload `number`'s file.
    fn drop_upload(&mut self, number: u64) -> bool {
        let Some(upload) = self.open.remove(&number) else {
            return false;
        };
        let Upload { component, file, info, .. } = upload;
        drop(file);
        let _ = fsutil::remove_host_owned(&self.dir, &component, &info);
        true
    }

    /// Gives up the uploads untouched for [`UPLOAD_IDLE`].
    fn sweep(&mut self, now: MonotonicTime) {
        let stale: Vec<u64> = self
            .open
            .iter()
            .filter(|(_, upload)| now.saturating_duration_since(upload.touched) > UPLOAD_IDLE)
            .map(|(number, _)| *number)
            .collect();
        for number in stale {
            self.drop_upload(number);
        }
    }
}

impl Drop for Uploads {
    /// The grant's end takes every upload with it: nothing half assembled is left.
    fn drop(&mut self) {
        let numbers: Vec<u64> = self.open.keys().copied().collect();
        for number in numbers {
            self.drop_upload(number);
        }
    }
}

impl FileService {
    /// Serves `grant` beneath `root`, refusing a grant for another root, and counts what the
    /// root holds.
    pub fn new(grant: FileGrant, root: GrantedRoot) -> Result<Self, ServiceRefusal> {
        if grant.root() != root.handle() {
            return Err(ServiceRefusal::RootMismatch);
        }
        let usage = count_usage(&root, grant.quota()).map_err(|error| ServiceRefusal::Io {
            operation: FileOperation::List,
            name: None,
            detail: format!("{:?}", error.kind()),
        })?;
        Ok(Self {
            grant,
            root,
            usage,
            staging: 0,
            uploads: None,
        })
    }

    /// Gives this grant an upload area at `dir`, a host directory outside the granted root on
    /// its volume that only the host writes: what a crash left there is removed first. A
    /// file of any size then moves in ranges and chunks of at most [`MAX_RANGE_BYTES`].
    pub fn with_uploads(mut self, dir: &Path) -> Result<Self, ServiceRefusal> {
        let io = |error: std::io::Error| ServiceRefusal::Io {
            operation: FileOperation::Write,
            name: None,
            detail: format!("{:?}", error.kind()),
        };
        let opened = fsutil::open_root(dir).map_err(io)?;
        let info = fsutil::dir_info(&opened).map_err(io)?;
        if info.volume != self.root.volume() {
            return Err(ServiceRefusal::Io {
                operation: FileOperation::Write,
                name: None,
                detail: "the upload area is on another volume than the root".to_owned(),
            });
        }
        let mut leftovers = Vec::new();
        for entry in fsutil::read_directory(&opened).map_err(io)? {
            leftovers.push(entry.map_err(io)?.name);
        }
        for name in leftovers {
            if let (Some(text), Ok(info)) = (name.to_str(), fsutil::entry_info(&opened, &name)) {
                if info.kind == HandleKind::File {
                    let _ = fsutil::remove_host_owned(&opened, text, &info);
                }
            }
        }
        self.uploads = Some(Uploads {
            dir: opened,
            next: 1,
            open: BTreeMap::new(),
        });
        Ok(self)
    }

    /// The uploads open now.
    pub fn uploads_open(&self) -> usize {
        self.uploads.as_ref().map_or(0, |uploads| uploads.open.len())
    }

    pub fn grant(&self) -> &FileGrant {
        &self.grant
    }

    pub fn root(&self) -> &GrantedRoot {
        &self.root
    }

    /// What the root holds as the service counts it; `None` when it could not be counted
    /// within the quota.
    pub fn usage(&self) -> Option<QuotaUsage> {
        self.usage
    }

    /// What the product may claim about host files under this grant (§5.1 line 2057).
    pub fn host_state_claim(&self) -> HostStateClaim {
        self.grant.host_state_claim()
    }

    /// Counts the root again, such as after the user changed a live workspace.
    pub fn recount(&mut self) -> Result<Option<QuotaUsage>, ServiceRefusal> {
        self.usage =
            count_usage(&self.root, self.grant.quota()).map_err(|error| ServiceRefusal::Io {
                operation: FileOperation::List,
                name: None,
                detail: format!("{:?}", error.kind()),
            })?;
        Ok(self.usage)
    }

    /// The grant's checks that need no name: clock session, expiry, root, trust scope and
    /// operation. They run before any name is looked at.
    fn permit(
        &self,
        context: &RequestContext,
        operation: FileOperation,
    ) -> Result<(), ServiceRefusal> {
        self.grant
            .authorize_operation(
                operation,
                self.grant.root(),
                context.scope,
                context.now,
                context.session,
            )
            .map_err(|refusal| ServiceRefusal::Grant { refusal })
    }

    fn authorize(
        &self,
        context: &RequestContext,
        operation: FileOperation,
        name: &GuestName,
        previous_file_bytes: u64,
        resulting_file_bytes: u64,
    ) -> Result<QuotaUsage, ServiceRefusal> {
        self.permit(context, operation)?;
        let usage = match (self.usage, operation.mutates()) {
            (Some(usage), _) => usage,
            (None, false) => QuotaUsage::default(),
            (None, true) => return Err(ServiceRefusal::UsageUnknown),
        };
        let request = FileRequest {
            root: self.grant.root(),
            scope: context.scope,
            operation,
            name: name.clone(),
            previous_file_bytes,
            resulting_file_bytes,
        };
        self.grant
            .authorize(&request, context.now, context.session, usage)
            .map_err(|refusal| ServiceRefusal::Grant { refusal })?;
        Ok(usage)
    }

    /// Reads the whole regular file `name`, at most `max_bytes` (and never more than
    /// [`MAX_READ_BYTES`]).
    pub fn read(
        &self,
        context: &RequestContext,
        name: &GuestName,
        max_bytes: u64,
    ) -> Result<Vec<u8>, ServiceRefusal> {
        self.authorize(context, FileOperation::Read, name, 0, 0)?;
        let mut opened = self
            .root
            .open_file(name)
            .map_err(|problem| entry_refusal(FileOperation::Read, name, problem))?;
        let limit = max_bytes.min(MAX_READ_BYTES);
        let size_bytes = opened.info.size;
        fsutil::read_open(&mut opened.file, size_bytes, limit).map_err(|problem| match problem {
            ReadProblem::TooLarge { size_bytes } => ServiceRefusal::ReadTooLarge {
                name: name.clone(),
                size_bytes,
                limit,
            },
            ReadProblem::Changed => ServiceRefusal::Changed { name: name.clone() },
            ReadProblem::Io(error) => io_refusal(FileOperation::Read, name, &error),
        })
    }

    /// Lists the directory `name`, or the root for `None`.
    pub fn list(
        &self,
        context: &RequestContext,
        name: Option<&GuestName>,
    ) -> Result<Listing, ServiceRefusal> {
        match name {
            Some(name) => {
                self.authorize(context, FileOperation::List, name, 0, 0)?;
            }
            None => self.permit(context, FileOperation::List)?,
        }
        let directory = self
            .root
            .directory(name)
            .map_err(|problem| match (name, problem) {
                (Some(name), problem) => entry_refusal(FileOperation::List, name, problem),
                (None, EntryProblem::Io(error)) => ServiceRefusal::Io {
                    operation: FileOperation::List,
                    name: None,
                    detail: format!("{:?}", error.kind()),
                },
                (None, _) => ServiceRefusal::Io {
                    operation: FileOperation::List,
                    name: None,
                    detail: "root".to_owned(),
                },
            })?;
        let list_error = |error: std::io::Error| ServiceRefusal::Io {
            operation: FileOperation::List,
            name: name.cloned(),
            detail: format!("{:?}", error.kind()),
        };
        let mut listing = Listing {
            entries: Vec::new(),
            unaddressable: 0,
            truncated: false,
        };
        for entry in fsutil::read_directory(&directory).map_err(list_error)? {
            let file_name = entry.map_err(list_error)?.name;
            let Some(guest) = file_name
                .to_str()
                .and_then(|text| GuestName::parse(text).ok())
                .filter(|guest| guest.component_count() == 1)
            else {
                listing.unaddressable = listing.unaddressable.saturating_add(1);
                continue;
            };
            if listing.entries.len() >= MAX_LISTED_ENTRIES {
                listing.truncated = true;
                break;
            }
            // Read without following and without the right to read the content, so an entry
            // another process holds locked is still listed.
            let info = match fsutil::entry_info(&directory, guest.as_str()) {
                Ok(info) => info,
                // Removed since it was listed.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(list_error(error)),
            };
            let kind =
                if info.volume != self.root.volume() && !matches!(info.kind, HandleKind::Link(_)) {
                    ListedKind::Link {
                        link: LinkKind::MountCrossing,
                    }
                } else {
                    match info.kind {
                        HandleKind::File if info.links > 1 => ListedKind::Link {
                            link: LinkKind::HardLink,
                        },
                        HandleKind::File => ListedKind::File {
                            size_bytes: info.size,
                            executable: info.executable,
                        },
                        HandleKind::Directory => ListedKind::Directory,
                        HandleKind::Link(link) => ListedKind::Link { link },
                        HandleKind::Device => ListedKind::Device,
                    }
                };
            listing.entries.push(ListedEntry { name: guest, kind });
        }
        listing
            .entries
            .sort_by(|left, right| left.name.cmp(&right.name));
        Ok(listing)
    }

    /// Creates the regular file `name` holding `bytes`; its parent must exist and the name
    /// must be free.
    pub fn create(
        &mut self,
        context: &RequestContext,
        name: &GuestName,
        bytes: &[u8],
    ) -> Result<(), ServiceRefusal> {
        let resulting = bytes_of(bytes.len());
        let usage = self.authorize(context, FileOperation::Create, name, 0, resulting)?;
        self.require_absent(name)?;
        self.root
            .create_file(name, bytes, false)
            .map_err(|problem| entry_refusal(FileOperation::Create, name, problem))?;
        self.usage = Some(QuotaUsage {
            total_bytes: usage.total_bytes.saturating_add(resulting),
            entries: usage.entries.saturating_add(1),
        });
        Ok(())
    }

    /// Creates the directory `name`, authorized as a create; its parent must exist and the
    /// name must be free.
    pub fn create_directory(
        &mut self,
        context: &RequestContext,
        name: &GuestName,
    ) -> Result<(), ServiceRefusal> {
        let usage = self.authorize(context, FileOperation::Create, name, 0, 0)?;
        self.require_absent(name)?;
        self.root
            .create_directory(name)
            .map_err(|problem| entry_refusal(FileOperation::Create, name, problem))?;
        self.usage = Some(QuotaUsage {
            total_bytes: usage.total_bytes,
            entries: usage.entries.saturating_add(1),
        });
        Ok(())
    }

    /// `name` is free in an existing parent.
    fn require_absent(&self, name: &GuestName) -> Result<(), ServiceRefusal> {
        match self.root.resolve(name, ResolveIntent::Create) {
            Ok(Resolved::Absent) => Ok(()),
            Ok(_) => Err(ServiceRefusal::AlreadyExists { name: name.clone() }),
            Err(refusal) => Err(ServiceRefusal::Resolve { refusal }),
        }
    }

    /// Replaces the whole content of the regular file `name` with `bytes`, atomically,
    /// keeping its execute bit.
    pub fn write(
        &mut self,
        context: &RequestContext,
        name: &GuestName,
        bytes: &[u8],
    ) -> Result<(), ServiceRefusal> {
        // The quota needs the current size, so the name is opened before the full check,
        // but never before the grant permits writing at all.
        self.permit(context, FileOperation::Write)?;
        let opened = self
            .root
            .open_file(name)
            .map_err(|problem| entry_refusal(FileOperation::Write, name, problem))?;
        let previous = opened.info.size;
        let executable = opened.info.executable;
        drop(opened);
        let resulting = bytes_of(bytes.len());
        let usage = self.authorize(context, FileOperation::Write, name, previous, resulting)?;
        let mut attempt = 0;
        loop {
            self.staging = self.staging.wrapping_add(1);
            let staging = format!(".yougori-write-{}.tmp", self.staging);
            match self.root.replace_file(name, bytes, executable, &staging) {
                Ok(()) => break,
                Err(EntryProblem::Io(error))
                    if error.kind() == std::io::ErrorKind::AlreadyExists
                        && attempt < STAGING_ATTEMPTS =>
                {
                    attempt += 1;
                }
                Err(problem) => return Err(entry_refusal(FileOperation::Write, name, problem)),
            }
        }
        self.usage = Some(QuotaUsage {
            total_bytes: usage
                .total_bytes
                .saturating_sub(previous)
                .saturating_add(resulting),
            entries: usage.entries,
        });
        Ok(())
    }

    /// Deletes the regular file or empty directory `name`. A link is refused, not removed.
    pub fn delete(
        &mut self,
        context: &RequestContext,
        name: &GuestName,
    ) -> Result<(), ServiceRefusal> {
        let usage = self.authorize(context, FileOperation::Delete, name, 0, 0)?;
        let walked = self
            .root
            .walk(name)
            .map_err(|error| io_refusal(FileOperation::Delete, name, &error))?;
        let freed = match walked {
            Walk::Found(opened) if opened.is_single_file() => {
                let size = opened.info.size;
                drop(opened);
                self.root
                    .remove_file(name)
                    .map_err(|problem| entry_refusal(FileOperation::Delete, name, problem))?;
                size
            }
            Walk::Found(opened) if opened.info.kind == HandleKind::Directory => {
                drop(opened);
                self.root
                    .remove_directory(name)
                    .map_err(|problem| entry_refusal(FileOperation::Delete, name, problem))?;
                0
            }
            _ => {
                return Err(match self.root.resolve(name, ResolveIntent::Open) {
                    Err(refusal) => ServiceRefusal::Resolve { refusal },
                    Ok(_) => ServiceRefusal::Changed { name: name.clone() },
                })
            }
        };
        self.usage = Some(QuotaUsage {
            total_bytes: usage.total_bytes.saturating_sub(freed),
            entries: usage.entries.saturating_sub(1),
        });
        Ok(())
    }

    /// Renames the regular file or directory `from` to the free name `to`, whose parent
    /// must exist. A name taken meanwhile is never replaced.
    pub fn rename(
        &mut self,
        context: &RequestContext,
        from: &GuestName,
        to: &GuestName,
    ) -> Result<(), ServiceRefusal> {
        self.authorize(context, FileOperation::Rename, from, 0, 0)?;
        self.authorize(context, FileOperation::Rename, to, 0, 0)?;
        match self.root.resolve(from, ResolveIntent::Open) {
            Ok(Resolved::File { .. } | Resolved::Directory) => {}
            Ok(Resolved::Absent) => return Err(ServiceRefusal::Changed { name: from.clone() }),
            Err(refusal) => return Err(ServiceRefusal::Resolve { refusal }),
        }
        self.require_absent(to)?;
        self.root
            .rename_entry(from, to)
            .map_err(|problem| match problem {
                EntryProblem::Io(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    ServiceRefusal::AlreadyExists { name: to.clone() }
                }
                problem => entry_refusal(FileOperation::Rename, from, problem),
            })
    }

    /// Reads at most `max_bytes` (and never more than [`MAX_RANGE_BYTES`]) of the regular
    /// file `name` from `offset`, with its size and version; an offset at or past the end
    /// returns no bytes.
    pub fn read_range(
        &self,
        context: &RequestContext,
        name: &GuestName,
        offset: u64,
        max_bytes: u64,
    ) -> Result<RangeRead, ServiceRefusal> {
        self.authorize(context, FileOperation::Read, name, 0, 0)?;
        let mut opened = self
            .root
            .open_file(name)
            .map_err(|problem| entry_refusal(FileOperation::Read, name, problem))?;
        let content = if offset >= opened.info.size {
            Vec::new()
        } else {
            read_at(&mut opened.file, offset, max_bytes.min(opened.info.size - offset))
                .map_err(|error| io_refusal(FileOperation::Read, name, &error))?
        };
        let after = fsutil::file_info(&opened.file).map_err(|error| io_refusal(FileOperation::Read, name, &error))?;
        if !after.is(&opened.info) || after.size != opened.info.size {
            return Err(ServiceRefusal::Changed { name: name.clone() });
        }
        Ok(RangeRead {
            content,
            size_bytes: opened.info.size,
            version: version_of(&opened.info),
        })
    }

    /// The upload area, and the open upload `number` for `name` in it, after giving up
    /// stale uploads.
    fn upload(
        &mut self,
        context: &RequestContext,
        name: &GuestName,
        number: u64,
    ) -> Result<(&mut Upload, &Dir), ServiceRefusal> {
        let uploads = self.uploads.as_mut().ok_or(ServiceRefusal::UploadsUnavailable)?;
        uploads.sweep(context.now);
        let Uploads { dir, open, .. } = uploads;
        let upload = open.get_mut(&number).ok_or(ServiceRefusal::UnknownUpload { upload: number })?;
        if upload.name != *name {
            return Err(ServiceRefusal::UploadNameMismatch { upload: number });
        }
        upload.touched = context.now;
        Ok((upload, &*dir))
    }

    /// The size of the regular file `name` now: what an upload's quota check counts as
    /// replaced.
    fn current_size(&self, name: &GuestName) -> Result<u64, ServiceRefusal> {
        self.root
            .open_file(name)
            .map(|opened| opened.info.size)
            .map_err(|problem| entry_refusal(FileOperation::Write, name, problem))
    }

    /// Reads at most `max_bytes` of upload `number` for `name` from `offset`: what a
    /// writer reads back of what it wrote before committing it.
    pub fn read_upload_range(
        &mut self,
        context: &RequestContext,
        name: &GuestName,
        number: u64,
        offset: u64,
        max_bytes: u64,
    ) -> Result<RangeRead, ServiceRefusal> {
        self.authorize(context, FileOperation::Read, name, 0, 0)?;
        let (upload, _) = self.upload(context, name, number)?;
        let content = if offset >= upload.size {
            Vec::new()
        } else {
            read_at(&mut upload.file, offset, max_bytes.min(upload.size - offset))
                .map_err(|error| io_refusal(FileOperation::Read, name, &error))?
        };
        Ok(RangeRead {
            content,
            size_bytes: upload.size,
            version: format!("upload-{number}-{:x}", upload.size),
        })
    }

    /// Begins an upload that will replace the regular file `name`: its file starts empty,
    /// or with `name`'s content when `from_existing`, copied in bounded chunks. Returns the
    /// upload's number and its size.
    pub fn upload_begin(
        &mut self,
        context: &RequestContext,
        name: &GuestName,
        from_existing: bool,
    ) -> Result<(u64, u64), ServiceRefusal> {
        self.permit(context, FileOperation::Write)?;
        if self.uploads.is_none() {
            return Err(ServiceRefusal::UploadsUnavailable);
        }
        let mut opened = self
            .root
            .open_file(name)
            .map_err(|problem| entry_refusal(FileOperation::Write, name, problem))?;
        let previous = opened.info.size;
        let base = if from_existing { previous } else { 0 };
        self.authorize(context, FileOperation::Write, name, previous, base)?;
        let Some(uploads) = self.uploads.as_mut() else {
            return Err(ServiceRefusal::UploadsUnavailable);
        };
        uploads.sweep(context.now);
        if uploads.open.len() >= MAX_UPLOADS {
            return Err(ServiceRefusal::TooManyUploads { limit: MAX_UPLOADS });
        }
        let number = uploads.next;
        uploads.next = uploads.next.wrapping_add(1).max(1);
        let component = format!("upload-{number}.part");
        let io = |error: std::io::Error| io_refusal(FileOperation::Write, name, &error);
        let mut file = fsutil::create_new_read_write(&uploads.dir, &component).map_err(io)?;
        let info = fsutil::file_info(&file).map_err(io)?;
        if from_existing {
            let copied = std::io::copy(&mut (&mut opened.file).take(previous), &mut file);
            match copied {
                Ok(copied) if copied == previous => {}
                Ok(_) => {
                    drop(file);
                    let _ = fsutil::remove_host_owned(&uploads.dir, &component, &info);
                    return Err(ServiceRefusal::Changed { name: name.clone() });
                }
                Err(error) => {
                    drop(file);
                    let _ = fsutil::remove_host_owned(&uploads.dir, &component, &info);
                    return Err(io(error));
                }
            }
        }
        uploads.open.insert(
            number,
            Upload {
                name: name.clone(),
                component,
                file,
                info,
                size: base,
                touched: context.now,
            },
        );
        Ok((number, base))
    }

    /// Writes `bytes` (at most [`MAX_RANGE_BYTES`]) into upload `number` for `name` at
    /// `offset`, within the grant's quota as if it were committed; returns its size.
    pub fn upload_write(
        &mut self,
        context: &RequestContext,
        name: &GuestName,
        number: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<u64, ServiceRefusal> {
        self.permit(context, FileOperation::Write)?;
        let previous = self.current_size(name)?;
        let size = self.upload(context, name, number)?.0.size;
        let resulting = size.max(offset.saturating_add(bytes_of(bytes.len())));
        self.authorize(context, FileOperation::Write, name, previous, resulting)?;
        let (upload, _) = self.upload(context, name, number)?;
        let written = upload
            .file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| upload.file.write_all(bytes));
        written.map_err(|error| io_refusal(FileOperation::Write, name, &error))?;
        upload.size = resulting;
        Ok(resulting)
    }

    /// Sets upload `number`'s length to `length`, cutting or extending it with zeros.
    pub fn upload_truncate(
        &mut self,
        context: &RequestContext,
        name: &GuestName,
        number: u64,
        length: u64,
    ) -> Result<u64, ServiceRefusal> {
        self.permit(context, FileOperation::Write)?;
        let previous = self.current_size(name)?;
        self.upload(context, name, number)?;
        self.authorize(context, FileOperation::Write, name, previous, length)?;
        let (upload, _) = self.upload(context, name, number)?;
        upload
            .file
            .set_len(length)
            .map_err(|error| io_refusal(FileOperation::Write, name, &error))?;
        upload.size = length;
        Ok(length)
    }

    /// Commits upload `number`: its content key is read in bounded chunks, the quota is
    /// checked against `name` as it is now, and one atomic rename puts it over `name`,
    /// keeping `name`'s execute bit. Returns its size and content key.
    pub fn upload_commit(
        &mut self,
        context: &RequestContext,
        name: &GuestName,
        number: u64,
    ) -> Result<(u64, ContentKey), ServiceRefusal> {
        self.permit(context, FileOperation::Write)?;
        let opened = self
            .root
            .open_file(name)
            .map_err(|problem| entry_refusal(FileOperation::Write, name, problem))?;
        let previous = opened.info.size;
        let executable = opened.info.executable;
        let size = self.upload(context, name, number)?.0.size;
        let usage = self.authorize(context, FileOperation::Write, name, previous, size)?;
        self.upload(context, name, number)?;
        let io = |error: std::io::Error| io_refusal(FileOperation::Write, name, &error);
        // The upload is taken out: a commit that fails gives it up, and its handle and the
        // file's close before the rename (Windows renames no file open without delete
        // sharing).
        let uploads = self.uploads.as_mut().ok_or(ServiceRefusal::UploadsUnavailable)?;
        let Upload {
            component,
            mut file,
            info,
            ..
        } = uploads
            .open
            .remove(&number)
            .ok_or(ServiceRefusal::UnknownUpload { upload: number })?;
        let hashed = (|| -> std::io::Result<Option<ContentKey>> {
            file.flush()?;
            file.seek(SeekFrom::Start(0))?;
            let content = fsutil::hash_open(&mut file, size)?;
            fsutil::set_executable(&file, executable)?;
            file.sync_all()?;
            Ok(content)
        })();
        drop(file);
        let given_up = |uploads: &Uploads| {
            let _ = fsutil::remove_host_owned(&uploads.dir, &component, &info);
        };
        let content = match hashed {
            Ok(Some(content)) => content,
            Ok(None) => {
                given_up(uploads);
                return Err(ServiceRefusal::Changed { name: name.clone() });
            }
            Err(error) => {
                given_up(uploads);
                return Err(io(error));
            }
        };
        let super::root::Opened {
            parent,
            component: target,
            file: target_file,
            ..
        } = opened;
        drop(target_file);
        match fsutil::rename(&uploads.dir, &component, &info, &parent, &target, true) {
            Ok(true) => {}
            Ok(false) => {
                given_up(uploads);
                return Err(ServiceRefusal::Changed { name: name.clone() });
            }
            Err(error) => {
                given_up(uploads);
                return Err(io(error));
            }
        }
        self.usage = Some(QuotaUsage {
            total_bytes: usage.total_bytes.saturating_sub(previous).saturating_add(size),
            entries: usage.entries,
        });
        Ok((size, content))
    }

    /// Gives up upload `number`: its file is removed and `name` is untouched.
    pub fn upload_abort(
        &mut self,
        context: &RequestContext,
        name: &GuestName,
        number: u64,
    ) -> Result<(), ServiceRefusal> {
        self.permit(context, FileOperation::Write)?;
        self.upload(context, name, number)?;
        if let Some(uploads) = self.uploads.as_mut() {
            uploads.drop_upload(number);
        }
        Ok(())
    }

    /// Renames the regular file `from` over `to` in one atomic step, replacing a regular
    /// file there (POSIX `rename`); a directory there refuses, and a directory is never
    /// renamed this way.
    pub fn rename_replacing(
        &mut self,
        context: &RequestContext,
        from: &GuestName,
        to: &GuestName,
    ) -> Result<(), ServiceRefusal> {
        self.authorize(context, FileOperation::Rename, from, 0, 0)?;
        let usage = self.authorize(context, FileOperation::Rename, to, 0, 0)?;
        let replaced = self
            .root
            .rename_file_replacing(from, to)
            .map_err(|problem| match problem {
                EntryProblem::NotAFile => ServiceRefusal::NotAFile { name: to.clone() },
                problem => entry_refusal(FileOperation::Rename, from, problem),
            })?;
        if let Some(size) = replaced {
            self.usage = Some(QuotaUsage {
                total_bytes: usage.total_bytes.saturating_sub(size),
                entries: usage.entries.saturating_sub(1),
            });
        }
        Ok(())
    }

    /// Sets or clears the execute bits of the regular file `name` where the platform has
    /// them.
    pub fn set_executable(
        &mut self,
        context: &RequestContext,
        name: &GuestName,
        executable: bool,
    ) -> Result<(), ServiceRefusal> {
        self.authorize(context, FileOperation::SetExecutable, name, 0, 0)?;
        let opened = self
            .root
            .open_file(name)
            .map_err(|problem| entry_refusal(FileOperation::SetExecutable, name, problem))?;
        fsutil::set_executable(&opened.file, executable)
            .map_err(|error| io_refusal(FileOperation::SetExecutable, name, &error))
    }
}
