//! The granted root and race-resistant resolution beneath it (VM part §5.1 "A grant binds a
//! host-selected root handle"; "Resolve them beneath the opened root using platform-safe
//! handle-relative operations"; VM-P15; M12).
//!
//! A [`GrantedRoot`] is a directory the host selected and opened once. Its identity is the
//! opened object's volume and index, so a root that is renamed or replaced after opening is
//! recognisably another root, and every later step works on the opened object, never on its
//! path again. A guest name is resolved one component at a time, each opened relative to the
//! handle of the directory before it ([`super::fsutil`]): symlinks, junctions, other reparse
//! points, hard-linked files, mount crossings, devices and case aliases are refused at every
//! component and never followed, with the same results as the [`RootModel`] specification.
//! Because each step holds the handle it checked, a link planted after a check can only be
//! met as itself and refused. Changes are made relative to the checked parent's handle and,
//! where they act on an existing entry (rename, remove), only while that entry is still the
//! object the walk checked; a rename never replaces an existing name.
//!
//! Case variants are refused on every volume, as [`RootModel`] specifies with case folding
//! on: whether a directory folds case (NTFS, default APFS, ext4 casefold, SMB shares) cannot
//! be read reliably per directory, and a tree free of case variants also promotes safely to
//! a case-insensitive host. Guest names are ASCII, so the ASCII comparison is exact.
//!
//! What this does not do: it does not stop a host user with rights to both sides from moving
//! a directory out of the root while it is open, and a live workspace remains writable by the
//! workload by grant (§5.1 line 2057). On Unix, a directory renamed by `renameat` may still
//! replace an empty directory created at the target in the instant after the check.
//!
//! [`RootModel`]: super::RootModel

use std::fmt;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use cap_std::fs::{Dir, File};

use super::fsutil::{self, HandleInfo, HandleKind, Spelling};
use super::grant::RootHandle;
use super::names::GuestName;
use super::resolve::{LinkKind, ResolveIntent, ResolveRefusal, Resolved};
use super::review::{PathBlock, RootIdentity};
use crate::foundation::ids::{ContentHasher, ContentKey, DigestBuilder};

/// Domain of a granted root's identity digest.
pub const GRANTED_ROOT_DOMAIN: &str = "yougori/sandbox/files/granted-root/v1";

/// The identity of the object `info` describes: its volume, index and, on Windows,
/// creation time. A root opened on a directory has the identity this gives the directory.
pub(super) fn identity_of(info: &HandleInfo) -> RootIdentity {
    RootIdentity::from_digest(
        DigestBuilder::new(GRANTED_ROOT_DOMAIN)
            .u64(info.volume)
            .u64(info.index)
            .u64(info.created)
            .finish(),
    )
}

/// Why a host directory could not be opened as a root.
#[derive(Debug)]
pub enum RootOpenError {
    /// A link, reparse point or anything but a real directory.
    NotARealDirectory,
    /// The path named another directory once the opened one was checked.
    Changed,
    Io(io::Error),
}

impl fmt::Display for RootOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotARealDirectory => f.write_str("the root is not a real directory"),
            Self::Changed => f.write_str("the root's path changed while it was opened"),
            Self::Io(error) => write!(f, "the root could not be opened: {:?}", error.kind()),
        }
    }
}

impl std::error::Error for RootOpenError {}

impl From<io::Error> for RootOpenError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Why a walk stopped at a component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Stop {
    /// An ancestor is a regular file.
    File,
    Link(LinkKind),
    /// A device, FIFO or socket.
    Device,
    /// The directory holds the entry under another spelling.
    CaseAlias {
        stored: String,
    },
}

impl Stop {
    pub fn block(&self) -> PathBlock {
        match self {
            Self::File => PathBlock::File,
            Self::Link(_) => PathBlock::Link,
            Self::Device => PathBlock::Other,
            Self::CaseAlias { .. } => PathBlock::CaseAlias,
        }
    }
}

/// The opened last component of a name, with the handle of the directory holding it.
pub(super) struct Opened {
    pub parent: Dir,
    pub component: String,
    pub file: File,
    pub info: HandleInfo,
}

impl Opened {
    /// A regular file with no other name.
    pub fn is_single_file(&self) -> bool {
        self.info.kind == HandleKind::File && self.info.links <= 1
    }
}

/// What walking a name found.
pub(super) enum Walk {
    /// Every ancestor is a real directory on the root's volume, and the last component was
    /// opened as itself; the caller judges what it is.
    Found(Opened),
    /// The last `missing` components do not exist.
    Missing { missing: usize },
    /// Component `component` (0 for the first) stops the walk.
    Blocked { component: usize, stop: Stop },
}

/// A host-selected directory, opened once (§5.1).
#[derive(Debug)]
pub struct GrantedRoot {
    dir: Dir,
    identity: RootIdentity,
    volume: u64,
    origin: PathBuf,
}

impl GrantedRoot {
    /// Opens the host-selected directory at `path`, refusing a link, reparse point or
    /// anything but a real directory. Only the host calls this; a guest never supplies a
    /// host path.
    pub fn open(path: &Path) -> Result<Self, RootOpenError> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(RootOpenError::NotARealDirectory);
        }
        // Opened as itself, so a link swapped in after the check above is met as the link.
        let dir = fsutil::open_root(path)?;
        let info = fsutil::dir_info(&dir)?;
        if info.kind != HandleKind::Directory {
            return Err(RootOpenError::NotARealDirectory);
        }
        // The canonical path must name the opened directory, or the origin shown and checked
        // for the backup root's containment would be another place.
        let origin = std::fs::canonicalize(path)?;
        if !fsutil::dir_info(&fsutil::open_root(&origin)?)?.is(&info) {
            return Err(RootOpenError::Changed);
        }
        Ok(Self {
            dir,
            identity: identity_of(&info),
            volume: info.volume,
            origin,
        })
    }

    /// The opened object's identity: volume, index and, on Windows, creation time.
    pub fn identity(&self) -> RootIdentity {
        self.identity
    }

    /// The root handle a [`FileGrant`](super::FileGrant) binds.
    pub fn handle(&self) -> RootHandle {
        RootHandle::from_host(self.identity.digest())
    }

    /// The canonical path the host opened, for display and the containment check of the
    /// backup root only; nothing resolves through it again.
    pub fn origin(&self) -> &Path {
        &self.origin
    }

    /// The opened root directory.
    pub(super) fn dir(&self) -> &Dir {
        &self.dir
    }

    /// The opened root's volume; an entry on another one is a mount crossing.
    pub(super) fn volume(&self) -> u64 {
        self.volume
    }

    /// Resolves `name` beneath the opened root one handle-relative component at a time,
    /// refusing every link kind, device, mount crossing and case alias on the way (VM-P15),
    /// with the results [`RootModel::resolve`](super::RootModel::resolve) specifies.
    pub fn resolve(
        &self,
        name: &GuestName,
        intent: ResolveIntent,
    ) -> Result<Resolved, ResolveRefusal> {
        let walked = self.walk(name).map_err(|error| io_refusal(name, &error))?;
        judge(name, walked, intent)
    }

    pub(super) fn walk(&self, name: &GuestName) -> io::Result<Walk> {
        self.walk_with(name, &mut |_| {})
    }

    /// Walks `name`, calling `after_open` with each component's index once it is open and
    /// checked. The hook exists so tests can change the tree between steps; production
    /// passes a no-op.
    pub(super) fn walk_with(
        &self,
        name: &GuestName,
        after_open: &mut dyn FnMut(usize),
    ) -> io::Result<Walk> {
        let components: Vec<&str> = name.components().collect();
        let count = components.len();
        let mut current = self.dir.try_clone()?;
        for (index, component) in components.iter().copied().enumerate() {
            match fsutil::spelling(&current, component)? {
                Spelling::Exact => {}
                Spelling::Alias(stored) => {
                    return Ok(Walk::Blocked {
                        component: index,
                        stop: Stop::CaseAlias { stored },
                    })
                }
                Spelling::Absent => {
                    return Ok(Walk::Missing {
                        missing: count - index,
                    })
                }
            }
            let file = match fsutil::open_entry(&current, component) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Ok(Walk::Missing {
                        missing: count - index,
                    })
                }
                Err(error) => {
                    // On Unix an open that does not follow fails with ELOOP for a symlink:
                    // the component was one when it was opened, whatever a later read of a
                    // name a rename races finds (found on Linux, 31 October 2026).
                    #[cfg(unix)]
                    if error.raw_os_error() == Some(libc::ELOOP) {
                        return Ok(Walk::Blocked {
                            component: index,
                            stop: Stop::Link(LinkKind::Symlink),
                        });
                    }
                    // A symlink the platform refused to open, or a device: classify the
                    // name from a read that neither follows nor reads it.
                    return match fsutil::entry_info(&current, component).map(|info| info.kind) {
                        Ok(HandleKind::Link(link)) => Ok(Walk::Blocked {
                            component: index,
                            stop: Stop::Link(link),
                        }),
                        Ok(HandleKind::Device) => Ok(Walk::Blocked {
                            component: index,
                            stop: Stop::Device,
                        }),
                        // Gone since the open: it does not exist now.
                        Err(gone) if gone.kind() == io::ErrorKind::NotFound => Ok(Walk::Missing {
                            missing: count - index,
                        }),
                        _ => Err(error),
                    };
                }
            };
            let info = fsutil::file_info(&file)?;
            let confirmed = match fsutil::confirm(&current, component, &info) {
                Ok(confirmed) => confirmed,
                // The name went after the open (a rename racing the walk): it does not
                // exist now.
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Ok(Walk::Missing {
                        missing: count - index,
                    })
                }
                Err(error) => return Err(error),
            };
            if !confirmed {
                // The name no longer names the opened object, or is a symlink the open
                // resolved: the race this check exists for.
                return Ok(Walk::Blocked {
                    component: index,
                    stop: Stop::Link(LinkKind::Symlink),
                });
            }
            after_open(index);
            let is_last = index + 1 == count;
            // A link at the last component is returned as itself for the caller to judge;
            // anywhere else, and anything on another volume, stops the walk.
            let stop = match info.kind {
                HandleKind::Link(_) if is_last => None,
                HandleKind::Link(link) => Some(Stop::Link(link)),
                _ if info.volume != self.volume => Some(Stop::Link(LinkKind::MountCrossing)),
                _ if is_last => None,
                HandleKind::Directory => None,
                HandleKind::File if info.links > 1 => Some(Stop::Link(LinkKind::HardLink)),
                HandleKind::File => Some(Stop::File),
                HandleKind::Device => Some(Stop::Device),
            };
            if let Some(stop) = stop {
                return Ok(Walk::Blocked {
                    component: index,
                    stop,
                });
            }
            if is_last {
                return Ok(Walk::Found(Opened {
                    parent: current,
                    component: component.to_owned(),
                    file,
                    info,
                }));
            }
            current = fsutil::into_dir(file);
        }
        // A guest name has at least one component, so the loop always returns.
        Ok(Walk::Missing { missing: 0 })
    }

    /// The directory handle of `name`, or of the root itself for `None`.
    pub(super) fn directory(&self, name: Option<&GuestName>) -> Result<Dir, EntryProblem> {
        let Some(name) = name else {
            return Ok(self.dir.try_clone()?);
        };
        match self.walk(name)? {
            Walk::Found(opened) if opened.info.kind == HandleKind::Directory => {
                Ok(fsutil::into_dir(opened.file))
            }
            walked => Err(EntryProblem::Refused(refusal_of(
                name,
                walked,
                ResolveIntent::Open,
            ))),
        }
    }

    /// The whole regular file `name`, at most `max_bytes`: opened beneath the root one
    /// handle-relative component at a time (no link, device, mount crossing or case alias),
    /// read through the open handle and refused if its length changes meanwhile. The host's
    /// own read of a root it opened, such as a normalization job's raw bytes in a sandbox's
    /// staged workspace (VM-W58); nothing here parses them.
    pub fn read_whole(&self, name: &GuestName, max_bytes: u64) -> Result<Vec<u8>, String> {
        let mut opened = self.open_file(name).map_err(|problem| match problem {
            EntryProblem::Refused(refusal) => format!("{name} was refused: {refusal}"),
            EntryProblem::NotAFile => format!("{name} is not a regular file"),
            EntryProblem::Changed => format!("{name} changed while it was opened"),
            EntryProblem::Io(error) => format!("{name} could not be opened: {error}"),
        })?;
        let size_bytes = opened.info.size;
        fsutil::read_open(&mut opened.file, size_bytes, max_bytes).map_err(|problem| match problem {
            fsutil::ReadProblem::TooLarge { size_bytes } => {
                format!("{name} holds {size_bytes} bytes; at most {max_bytes} are read")
            }
            fsutil::ReadProblem::Changed => format!("{name} changed while it was read"),
            fsutil::ReadProblem::Io(error) => format!("{name} could not be read: {error}"),
        })
    }

    /// Writes one explicitly authorized host path using the same non-following,
    /// handle-relative and atomic primitives as FileService. Authorization belongs
    /// to the host-access broker; a guest must never call this without its grant.
    pub(crate) fn write_authorized(&self, name: &GuestName, bytes: &[u8]) -> Result<(), String> {
        let resolved = self.resolve(name, ResolveIntent::Create).map_err(|e| e.to_string())?;
        let staging = format!(".yougori-access-{}.tmp", uuid::Uuid::new_v4().simple());
        match resolved {
            Resolved::Absent => self.create_file_from(
                name, &mut std::io::Cursor::new(bytes), bytes.len() as u64, false, &staging, None,
            ).map(|_| ()),
            Resolved::File { executable, .. } => self.replace_file(
                name, bytes, executable, &staging,
            ),
            Resolved::Directory => return Err("Choose a file inside the approved folder.".into()),
        }.map_err(|e| format!("Host write refused: {e:?}"))
    }

    /// Names and types only. Listing never opens file contents and never follows
    /// links. The cursor is a name, not an offset into a mutable directory.
    pub(crate) fn tree_page(
        &self, name: Option<&GuestName>, after: Option<&str>,
    ) -> Result<serde_json::Value, String> {
        let directory = self.directory(name).map_err(|e| format!("Directory unavailable: {e:?}"))?;
        let mut entries = std::collections::BTreeMap::new();
        let mut more = false;
        let mut unaddressable = 0u64;
        for entry in fsutil::read_directory(&directory).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let Some(text) = entry.name.to_str() else { unaddressable += 1; continue };
            if after.is_some_and(|after| text <= after) { continue; }
            let addressable = GuestName::parse(text).is_ok();
            let kind = match fsutil::entry_info(&directory, text) {
                Ok(info) if info.volume != self.volume => "mount",
                Ok(info) => match info.kind {
                    HandleKind::File if info.links > 1 => "link",
                    HandleKind::File => "file",
                    HandleKind::Directory => "folder",
                    HandleKind::Link(_) => "link",
                    HandleKind::Device => "device",
                },
                Err(_) => "unavailable",
            };
            entries.insert(text.to_owned(), serde_json::json!({
                "name": text, "kind": kind, "addressable": addressable,
            }));
            if entries.len() > 256 { entries.pop_last(); more = true; }
        }
        let next = if more { entries.last_key_value().map(|(name, _)| name.clone()) } else { None };
        Ok(serde_json::json!({"entries": entries.into_values().collect::<Vec<_>>(),
            "next": next, "unaddressable": unaddressable}))
    }

    /// The open regular file `name`, with no other name.
    pub(super) fn open_file(&self, name: &GuestName) -> Result<Opened, EntryProblem> {
        match self.walk(name)? {
            Walk::Found(opened) if opened.is_single_file() => Ok(opened),
            Walk::Found(opened) if opened.info.kind == HandleKind::Directory => {
                Err(EntryProblem::NotAFile)
            }
            walked => Err(EntryProblem::Refused(refusal_of(
                name,
                walked,
                ResolveIntent::Open,
            ))),
        }
    }

    /// The regular single-name file or the directory `name`, for a change to the entry
    /// itself.
    fn open_entry_for_change(&self, name: &GuestName) -> Result<Opened, EntryProblem> {
        match self.walk(name)? {
            Walk::Found(opened)
                if opened.is_single_file() || opened.info.kind == HandleKind::Directory =>
            {
                Ok(opened)
            }
            walked => Err(EntryProblem::Refused(refusal_of(
                name,
                walked,
                ResolveIntent::Open,
            ))),
        }
    }

    /// Creates the directory `name`, whose parent must exist; an existing entry of any kind
    /// fails with `AlreadyExists`.
    pub(super) fn create_directory(&self, name: &GuestName) -> Result<(), EntryProblem> {
        let parent = self.directory(name.parent().as_ref())?;
        let created = fsutil::create_directory(&parent, name.file_name())?;
        let opened = fsutil::open_entry(&parent, name.file_name())?;
        let info = fsutil::file_info(&opened)?;
        if info.kind != HandleKind::Directory
            || !info.is(&created)
            || !fsutil::confirm(&parent, name.file_name(), &info)?
        {
            return Err(EntryProblem::Changed);
        }
        Ok(())
    }

    /// Creates the regular file `name` exclusively, in an existing parent, holding exactly
    /// `bytes`, synced; `executable` sets the execute bits where the platform has them.
    pub(super) fn create_file(
        &self,
        name: &GuestName,
        bytes: &[u8],
        executable: bool,
    ) -> Result<(), EntryProblem> {
        let parent = self.directory(name.parent().as_ref())?;
        write_new(&parent, name.file_name(), bytes, executable).map(|_| ())
    }

    /// Creates the regular file `name` in an existing parent by copying exactly
    /// `size_bytes` from `source` into a staging file `staging` beside it as they are
    /// hashed, then renaming it to the free name: the name never holds a partial copy, and
    /// with `expected` a copy of other content never takes it. Returns the content key of
    /// what was written. The staging name must not exist; a taken name fails with
    /// `AlreadyExists` and is never replaced.
    pub(super) fn create_file_from(
        &self,
        name: &GuestName,
        source: &mut dyn Read,
        size_bytes: u64,
        executable: bool,
        staging: &str,
        expected: Option<ContentKey>,
    ) -> Result<ContentKey, EntryProblem> {
        let parent = self.directory(name.parent().as_ref())?;
        let (staged, content) = write_new_from(&parent, staging, source, size_bytes, executable)?;
        if expected.is_some_and(|expected| expected != content) {
            let _ = fsutil::remove(&parent, staging, &staged);
            return Err(EntryProblem::Changed);
        }
        match fsutil::rename(&parent, staging, &staged, &parent, name.file_name(), false) {
            Ok(true) => Ok(content),
            Ok(false) => Err(EntryProblem::Changed),
            Err(error) => {
                let _ = fsutil::remove(&parent, staging, &staged);
                Err(EntryProblem::Io(error))
            }
        }
    }

    /// Replaces the regular file `name` by copying exactly `size_bytes` from `source` into
    /// a staging file `staging` beside it as they are hashed, then an atomic rename over the
    /// name; with `expected`, a copy of other content is removed and never replaces it.
    /// Returns the content key of what was written. The staging name must not exist.
    pub(super) fn replace_file_from(
        &self,
        name: &GuestName,
        source: &mut dyn Read,
        size_bytes: u64,
        executable: bool,
        staging: &str,
        expected: Option<ContentKey>,
    ) -> Result<ContentKey, EntryProblem> {
        let Opened {
            parent,
            component,
            file,
            ..
        } = self.open_file(name)?;
        drop(file);
        let (staged, content) = write_new_from(&parent, staging, source, size_bytes, executable)?;
        if expected.is_some_and(|expected| expected != content) {
            let _ = fsutil::remove(&parent, staging, &staged);
            return Err(EntryProblem::Changed);
        }
        match fsutil::rename(&parent, staging, &staged, &parent, &component, true) {
            Ok(true) => Ok(content),
            Ok(false) => Err(EntryProblem::Changed),
            Err(error) => {
                let _ = fsutil::remove(&parent, staging, &staged);
                Err(EntryProblem::Io(error))
            }
        }
    }

    /// Replaces the regular file `name` with exactly `bytes` by an atomic rename from a
    /// staging file `staging` beside it. The staging name must not exist.
    pub(super) fn replace_file(
        &self,
        name: &GuestName,
        bytes: &[u8],
        executable: bool,
        staging: &str,
    ) -> Result<(), EntryProblem> {
        let Opened {
            parent,
            component,
            file,
            ..
        } = self.open_file(name)?;
        drop(file);
        let staged = write_new(&parent, staging, bytes, executable)?;
        match fsutil::rename(&parent, staging, &staged, &parent, &component, true) {
            Ok(true) => Ok(()),
            // The staging name holds something else now; it is not ours to remove.
            Ok(false) => Err(EntryProblem::Changed),
            Err(error) => {
                let _ = fsutil::remove(&parent, staging, &staged);
                Err(EntryProblem::Io(error))
            }
        }
    }

    /// Removes the regular file `name`.
    pub(super) fn remove_file(&self, name: &GuestName) -> Result<(), EntryProblem> {
        let Opened {
            parent,
            component,
            file,
            info,
        } = self.open_file(name)?;
        drop(file);
        changed_unless(fsutil::remove(&parent, &component, &info)?)
    }

    /// Removes the empty directory `name`.
    pub(super) fn remove_directory(&self, name: &GuestName) -> Result<(), EntryProblem> {
        match self.walk(name)? {
            Walk::Found(Opened {
                parent,
                component,
                file,
                info,
            }) if info.kind == HandleKind::Directory => {
                drop(file);
                changed_unless(fsutil::remove(&parent, &component, &info)?)
            }
            walked => Err(EntryProblem::Refused(refusal_of(
                name,
                walked,
                ResolveIntent::Open,
            ))),
        }
    }

    /// Renames the regular single-name file or directory `from` to `to`, whose parent must
    /// exist. An existing `to` of any kind fails with `AlreadyExists` and is never replaced.
    pub(super) fn rename_entry(
        &self,
        from: &GuestName,
        to: &GuestName,
    ) -> Result<(), EntryProblem> {
        let Opened {
            parent,
            component,
            file,
            info,
        } = self.open_entry_for_change(from)?;
        let target_parent = self.directory(to.parent().as_ref())?;
        drop(file);
        changed_unless(fsutil::rename(
            &parent,
            &component,
            &info,
            &target_parent,
            to.file_name(),
            false,
        )?)
    }

    /// Renames the regular single-name file `from` over `to`, whose parent must exist, in
    /// one atomic step: an existing `to` must be a regular single-name file and is
    /// replaced (POSIX `rename`); a directory, link or device there refuses. Returns the
    /// size of the file replaced, if one was.
    pub(super) fn rename_file_replacing(
        &self,
        from: &GuestName,
        to: &GuestName,
    ) -> Result<Option<u64>, EntryProblem> {
        let Opened {
            parent,
            component,
            file,
            info,
        } = self.open_file(from)?;
        drop(file);
        let replaced = match self.walk(to)? {
            Walk::Found(opened) if opened.is_single_file() => Some(opened.info.size),
            Walk::Found(opened) if opened.info.kind == HandleKind::Directory => {
                return Err(EntryProblem::NotAFile)
            }
            Walk::Missing { missing: 1, .. } => None,
            walked => return Err(EntryProblem::Refused(refusal_of(to, walked, ResolveIntent::Create))),
        };
        let target_parent = self.directory(to.parent().as_ref())?;
        changed_unless(fsutil::rename(
            &parent,
            &component,
            &info,
            &target_parent,
            to.file_name(),
            true,
        )?)?;
        Ok(replaced)
    }

    /// Copies the regular file `name` into a new file `target` beneath `target_root`'s
    /// existing directory `directory`, synced; returns the bytes copied.
    pub(super) fn copy_file_to(
        &self,
        name: &GuestName,
        target_root: &GrantedRoot,
        directory: &str,
        target: &str,
    ) -> Result<u64, EntryProblem> {
        let mut opened = self.open_file(name)?;
        let target_directory = fsutil::into_dir(fsutil::open_entry(&target_root.dir, directory)?);
        let info = fsutil::dir_info(&target_directory)?;
        if info.kind != HandleKind::Directory
            || !fsutil::confirm(&target_root.dir, directory, &info)?
        {
            return Err(EntryProblem::Changed);
        }
        let mut copy = fsutil::create_new(&target_directory, target)?;
        let copied = io::copy(&mut opened.file, &mut copy)?;
        copy.sync_all()?;
        Ok(copied)
    }

    /// Creates the directory `component` directly in the root.
    pub(super) fn create_top_directory(&self, component: &str) -> io::Result<()> {
        fsutil::create_directory(&self.dir, component).map(|_| ())
    }

    /// Opens `directory/file` directly beneath the root as a regular single-link file.
    pub(super) fn open_top_file(
        &self,
        directory: &str,
        file: &str,
    ) -> Result<Opened, EntryProblem> {
        let parent = fsutil::into_dir(fsutil::open_entry(&self.dir, directory)?);
        let parent_info = fsutil::dir_info(&parent)?;
        if parent_info.kind != HandleKind::Directory
            || !fsutil::confirm(&self.dir, directory, &parent_info)?
        {
            return Err(EntryProblem::Changed);
        }
        let opened = fsutil::open_entry(&parent, file)?;
        let info = fsutil::file_info(&opened)?;
        if info.kind != HandleKind::File
            || info.links > 1
            || !fsutil::confirm(&parent, file, &info)?
        {
            return Err(EntryProblem::Changed);
        }
        Ok(Opened {
            parent,
            component: file.to_owned(),
            file: opened,
            info,
        })
    }
}

/// Why a handle-relative step on a named entry did not happen.
#[derive(Debug)]
pub(super) enum EntryProblem {
    /// The name does not resolve to what the step needs.
    Refused(ResolveRefusal),
    /// The name is a directory where the step needs a regular file.
    NotAFile,
    /// What was created or opened is not what the step expected.
    Changed,
    Io(io::Error),
}

impl From<io::Error> for EntryProblem {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// A change that found its entry no longer the object checked is `Changed`.
fn changed_unless(done: bool) -> Result<(), EntryProblem> {
    if done {
        Ok(())
    } else {
        Err(EntryProblem::Changed)
    }
}

/// Creates `component` in `parent` exclusively with exactly `bytes`, synced, and checks the
/// created handle is a regular single-link file; returns what the handle says of it. A
/// failed write removes the new file again.
fn write_new(
    parent: &Dir,
    component: &str,
    bytes: &[u8],
    executable: bool,
) -> Result<HandleInfo, EntryProblem> {
    let mut source = bytes;
    write_new_from(parent, component, &mut source, bytes.len() as u64, executable).map(|(info, _)| info)
}

/// The most bytes a streaming copy holds at once.
pub(super) const COPY_CHUNK_BYTES: usize = 256 * 1024;

/// Creates `component` in `parent` exclusively and copies exactly `size_bytes` from
/// `source` into it in bounded chunks, hashing them, synced; checks the created handle is a
/// regular single-link file of that length. Returns what the handle says of it and the
/// content key of what was written. A source shorter or longer than `size_bytes` is
/// `Changed`; a failed or refused copy removes the new file again.
pub(super) fn write_new_from(
    parent: &Dir,
    component: &str,
    source: &mut dyn Read,
    size_bytes: u64,
    executable: bool,
) -> Result<(HandleInfo, ContentKey), EntryProblem> {
    let mut file = fsutil::create_new(parent, component)?;
    let created = fsutil::file_info(&file)?;
    let mut hasher = ContentHasher::new(size_bytes);
    let mut buffer = vec![0u8; COPY_CHUNK_BYTES];
    let mut limited = source.take(size_bytes.saturating_add(1));
    let mut copied = 0u64;
    let written = (|| -> Result<(), EntryProblem> {
        loop {
            let read = limited.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            let chunk = buffer.get(..read).ok_or(EntryProblem::Changed)?;
            hasher.update(chunk).map_err(|_| EntryProblem::Changed)?;
            file.write_all(chunk)?;
            copied = copied.saturating_add(read as u64);
        }
        if copied != size_bytes {
            return Err(EntryProblem::Changed);
        }
        if executable {
            fsutil::set_executable(&file, true)?;
        }
        file.sync_all()?;
        Ok(())
    })();
    let info = written.and_then(|()| Ok(fsutil::file_info(&file)?));
    match info {
        Ok(info) if info.kind == HandleKind::File && info.links <= 1 && info.size == size_bytes => {
            match hasher.finish() {
                Ok(content) => Ok((info, content)),
                Err(_) => {
                    drop(file);
                    let _ = fsutil::remove(parent, component, &created);
                    Err(EntryProblem::Changed)
                }
            }
        }
        Ok(_) => {
            drop(file);
            let _ = fsutil::remove(parent, component, &created);
            Err(EntryProblem::Changed)
        }
        Err(problem) => {
            drop(file);
            let _ = fsutil::remove(parent, component, &created);
            Err(problem)
        }
    }
}

fn io_refusal(at: &GuestName, error: &io::Error) -> ResolveRefusal {
    ResolveRefusal::Io {
        at: at.clone(),
        detail: format!("{:?}", error.kind()),
    }
}

/// The name of component `index` of `name`: its first `index + 1` components.
fn prefix(name: &GuestName, index: usize) -> GuestName {
    let mut prefixes = name.ancestors();
    prefixes.push(name.clone());
    prefixes
        .into_iter()
        .nth(index)
        .unwrap_or_else(|| name.clone())
}

/// The stored spelling `stored` of component `index` of `name`, as a guest name.
fn stored_name(name: &GuestName, index: usize, stored: &str) -> GuestName {
    let requested = prefix(name, index);
    let Ok(component) = GuestName::parse(stored) else {
        return requested;
    };
    match requested.parent() {
        Some(parent) => parent.join(&component).unwrap_or(requested),
        None => component,
    }
}

/// The refusal for a walk that did not find what an open needs.
fn refusal_of(name: &GuestName, walked: Walk, intent: ResolveIntent) -> ResolveRefusal {
    match judge(name, walked, intent) {
        Err(refusal) => refusal,
        // Found, but a regular file where a directory is needed; callers that need a file
        // refuse a directory themselves.
        Ok(_) => ResolveRefusal::NotADirectory { at: name.clone() },
    }
}

/// The [`RootModel`](super::RootModel) result for a walk.
fn judge(
    name: &GuestName,
    walked: Walk,
    intent: ResolveIntent,
) -> Result<Resolved, ResolveRefusal> {
    let count = name.component_count();
    match walked {
        Walk::Missing { missing, .. } => {
            if missing == 1 && intent == ResolveIntent::Create {
                Ok(Resolved::Absent)
            } else {
                Err(ResolveRefusal::NotFound {
                    at: prefix(name, count.saturating_sub(missing)),
                })
            }
        }
        Walk::Blocked { component, stop } => {
            let at = prefix(name, component);
            Err(match stop {
                Stop::CaseAlias { stored } => ResolveRefusal::CaseAlias {
                    stored: stored_name(name, component, &stored),
                    requested: at,
                },
                Stop::Link(link) => ResolveRefusal::LinkRefused { at, link },
                Stop::Device => ResolveRefusal::DeviceRefused { at },
                Stop::File => ResolveRefusal::NotADirectory { at },
            })
        }
        Walk::Found(opened) => match opened.info.kind {
            HandleKind::Directory => Ok(Resolved::Directory),
            HandleKind::File if opened.info.links > 1 => Err(ResolveRefusal::LinkRefused {
                at: name.clone(),
                link: LinkKind::HardLink,
            }),
            HandleKind::File => Ok(Resolved::File {
                size_bytes: opened.info.size,
                executable: opened.info.executable,
            }),
            HandleKind::Link(link) => Err(ResolveRefusal::LinkRefused {
                at: name.clone(),
                link,
            }),
            HandleKind::Device => Err(ResolveRefusal::DeviceRefused { at: name.clone() }),
        },
    }
}
