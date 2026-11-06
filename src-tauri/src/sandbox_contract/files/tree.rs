//! Removing a managed directory tree through handles (VM part §6.4: "Cleanup uses
//! host-created object handles and verified managed roots, resists reparse/symlink races";
//! §2.6: cleanup cannot follow guest-created paths outside the supervisor's managed roots;
//! VM-W24 "teardown cannot escape managed roots"; VM-P49).
//!
//! [`remove_tree`] deletes one directory depth-first. Every entry is classified from a read
//! that does not follow it ([`fsutil::entry_info`]) and removed relative to the handle of the
//! directory holding it, only while its name still names the object classified
//! ([`fsutil::remove_host_owned`]: the tree is the host's, so a read-only attribute does not
//! keep an entry). Only real directories on the tree's volume are descended into, each
//! opened as itself and checked to be the object classified. A symlink, junction or other
//! reparse point is removed as the link itself; its target is never opened, listed or
//! changed.
//!
//! Left in place, and counted by reason ([`LeftBehind`]), are: an entry the caller spares
//! (kept and preserved objects, by identity wherever they are met and by name directly
//! beneath the top; and objects whose own removal is unfinished), a directory on another
//! volume, a name the platform's string form cannot carry, an entry that was no longer the
//! object checked when its removal came, a removed entry whose name still lingers (pending)
//! and an entry a filesystem step failed on. A failure never stops the removal: the rest of
//! the tree is still worked through, and the first error's kind is kept. Every directory
//! holding a left entry stays with it, so a directory is removed only when it is empty.
//!
//! A directory is listed through the handle already held ([`fsutil::read_directory`]), and
//! the listing only proposes names: each is opened again relative to that handle and
//! classified there, so whatever a listing says, only entries of the tree itself are
//! touched. A listing is read again after a pass that deleted something, until a pass
//! deletes nothing, so names a listing missed while entries went are still met; memory
//! holds only the names left in place and one listing batch per level.
//!
//! A removal goes at once on Windows volumes with POSIX delete semantics, even while another
//! process holds the entry open with delete sharing. Elsewhere (FAT) a name another handle
//! holds lingers, delete-pending and impossible to open, until that handle closes: after
//! every removal the name is read again, and one still there is counted pending; a later run
//! finishes it. A name that was already delete-pending before the run cannot be opened at
//! all and counts as a failure.
//!
//! On Unix, [`fsutil::remove`] refuses links, so a symlink is removed by `unlinkat` relative
//! to its directory's descriptor once a non-following stat names the same link again;
//! `unlinkat` never follows its last component.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io;

use cap_std::fs::Dir;

use super::fsutil::{self, DirectoryEntries, HandleInfo, HandleKind};
use super::review::RootIdentity;
use super::root::identity_of;
use super::teardown::LeftBehind;
use crate::foundation::ids::Digest;

/// What a tree removal leaves alone.
#[derive(Clone, Debug, Default)]
pub(super) struct Spare {
    /// Kept and preserved objects, by identity wherever they are met.
    pub identities: BTreeSet<Digest>,
    /// Kept and preserved objects' names directly beneath the tree's top.
    pub top_names: BTreeSet<String>,
    /// Objects whose own removal is unfinished, by identity, left with what they hold.
    pub unfinished: BTreeSet<Digest>,
}

/// What working through a tree did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct TreeRemoval {
    /// Entries deleted, the top included when it went.
    pub deleted: u64,
    pub left: LeftBehind,
    /// Whether the top itself is gone.
    pub removed: bool,
    /// The kind of the first filesystem error met, if any.
    pub first_error: Option<io::ErrorKind>,
}

/// How a tree removal ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TreeOutcome {
    /// Nothing has the top's name.
    Gone,
    /// The name names another object now; nothing was touched.
    NotTheObject,
    Worked(TreeRemoval),
}

/// The deletion hook asked to stop after `deleted` deletions, as a crash would stop the
/// removal. What was deleted stays deleted; a later run continues from what is there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Interrupted {
    pub deleted: u64,
}

/// Removes the directory `name` of `parent` and everything beneath it that is not spared,
/// if `name` still names the directory with identity `expected`. `after_delete` is called
/// after every deletion and stops the removal when it returns false; production passes a
/// hook that always continues.
pub(super) fn remove_tree(
    parent: &Dir,
    name: &str,
    expected: RootIdentity,
    spare: &Spare,
    after_delete: &mut dyn FnMut() -> bool,
) -> Result<TreeOutcome, Interrupted> {
    let mut removal = Removal {
        spare,
        after_delete,
        volume: 0,
        deleted: 0,
        left: LeftBehind::default(),
        first_error: None,
    };
    let info = match fsutil::entry_info(parent, name) {
        Ok(info) => info,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(TreeOutcome::Gone),
        Err(error) => {
            removal.fail(&error);
            return Ok(TreeOutcome::Worked(removal.finish(false)));
        }
    };
    if info.kind != HandleKind::Directory || identity_of(&info) != expected {
        return Ok(TreeOutcome::NotTheObject);
    }
    removal.volume = info.volume;
    let top = match open_directory(parent, name, &info) {
        Ok(Opening::Frame(frame)) => frame,
        Ok(Opening::Vanished) => return Ok(TreeOutcome::Gone),
        Ok(Opening::Changed) => return Ok(TreeOutcome::NotTheObject),
        Err(error) => {
            removal.fail(&error);
            return Ok(TreeOutcome::Worked(removal.finish(false)));
        }
    };
    let removed = removal.run(Some(parent), top)?;
    Ok(TreeOutcome::Worked(removal.finish(removed)))
}

/// Empties the directory `top`, which the caller opened as itself and checked (a root opened
/// by its file ID, with no name to remove it by), of everything not spared, as
/// [`remove_tree`] empties its top; `top` itself stays, for the caller to remove through a
/// handle of its own, and `removed` says whether it was emptied. Its handle is closed on
/// return.
pub(super) fn empty_tree(
    top: Dir,
    spare: &Spare,
    after_delete: &mut dyn FnMut() -> bool,
) -> Result<TreeRemoval, Interrupted> {
    let mut removal = Removal {
        spare,
        after_delete,
        volume: 0,
        deleted: 0,
        left: LeftBehind::default(),
        first_error: None,
    };
    let opened = fsutil::dir_info(&top)
        .and_then(|info| fsutil::read_directory(&top).map(|listing| (info, listing)));
    let (info, listing) = match opened {
        Ok(opened) => opened,
        Err(error) => {
            removal.fail(&error);
            return Ok(removal.finish(false));
        }
    };
    removal.volume = info.volume;
    let frame = Frame {
        dir: top,
        name: String::new(),
        info,
        listing,
        left_names: BTreeSet::new(),
        progressed: false,
        blocked: false,
    };
    let emptied = removal.run(None, frame)?;
    Ok(removal.finish(emptied))
}

/// One directory being emptied: its handle, its name in the directory above, what was
/// checked of it, and its listing.
struct Frame {
    dir: Dir,
    name: String,
    info: HandleInfo,
    listing: DirectoryEntries,
    /// Names left in place in this directory, so it stays.
    left_names: BTreeSet<OsString>,
    /// Whether this pass over the listing deleted anything.
    progressed: bool,
    /// Whether its listing failed, so it stays.
    blocked: bool,
}

impl Frame {
    /// The next name to handle, reading the listing again after a pass that deleted
    /// something; `None` once a pass deletes nothing.
    fn next_name(&mut self) -> io::Result<Option<OsString>> {
        loop {
            match self.listing.next() {
                Some(entry) => {
                    let name = entry?.name;
                    if self.left_names.contains(&name) {
                        continue;
                    }
                    return Ok(Some(name));
                }
                None if self.progressed => {
                    self.progressed = false;
                    self.listing = fsutil::read_directory(&self.dir)?;
                }
                None => return Ok(None),
            }
        }
    }
}

enum Opening {
    Frame(Frame),
    /// Nothing has the name any more.
    Vanished,
    /// The name names another object than the one classified.
    Changed,
}

/// Opens the directory `name` of `parent` as itself, if it is still the object `info`
/// describes.
fn open_directory(parent: &Dir, name: &str, info: &HandleInfo) -> io::Result<Opening> {
    let file = match fsutil::open_entry(parent, name) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Opening::Vanished),
        Err(error) => return Err(error),
    };
    let opened = fsutil::file_info(&file)?;
    if !opened.is(info) || !fsutil::confirm(parent, name, &opened)? {
        return Ok(Opening::Changed);
    }
    let dir = fsutil::into_dir(file);
    let listing = fsutil::read_directory(&dir)?;
    Ok(Opening::Frame(Frame {
        dir,
        name: name.to_owned(),
        info: opened,
        listing,
        left_names: BTreeSet::new(),
        progressed: false,
        blocked: false,
    }))
}

struct Removal<'a> {
    spare: &'a Spare,
    after_delete: &'a mut dyn FnMut() -> bool,
    /// The tree's volume; a directory on another one is never entered.
    volume: u64,
    deleted: u64,
    left: LeftBehind,
    first_error: Option<io::ErrorKind>,
}

/// What became of one entry of a directory being emptied.
enum Handled {
    Deleted,
    Left,
    Descend(Frame),
    /// Nothing has the name any more.
    Vanished,
}

impl Removal<'_> {
    fn finish(&self, removed: bool) -> TreeRemoval {
        TreeRemoval {
            deleted: self.deleted,
            left: self.left,
            removed,
            first_error: self.first_error,
        }
    }

    /// Counts an entry left because a filesystem step on it failed.
    fn fail(&mut self, error: &io::Error) {
        self.left.failed = self.left.failed.saturating_add(1);
        self.first_error.get_or_insert(error.kind());
    }

    fn count_deletion(&mut self) -> Result<(), Interrupted> {
        self.deleted = self.deleted.saturating_add(1);
        if (self.after_delete)() {
            Ok(())
        } else {
            Err(Interrupted {
                deleted: self.deleted,
            })
        }
    }

    /// Removes `name` of `dir` as itself if it is still the object `info` describes;
    /// whether it is gone. One whose name lingers is pending, one that changed or failed
    /// is left; each is counted.
    fn remove_counted(
        &mut self,
        dir: &Dir,
        name: &str,
        info: &HandleInfo,
    ) -> Result<bool, Interrupted> {
        match remove_entry(dir, name, info) {
            Ok(true) if lingers(dir, name, info) => {
                self.left.pending = self.left.pending.saturating_add(1);
                Ok(false)
            }
            Ok(true) => {
                self.count_deletion()?;
                Ok(true)
            }
            Ok(false) => {
                self.left.changed = self.left.changed.saturating_add(1);
                Ok(false)
            }
            Err(error) => {
                self.fail(&error);
                Ok(false)
            }
        }
    }

    /// Empties and removes `top`, depth-first, holding one handle per level; whether the
    /// top went. Without a `parent` the top is only emptied, and whether it was is returned.
    fn run(&mut self, parent: Option<&Dir>, top: Frame) -> Result<bool, Interrupted> {
        let mut stack = vec![top];
        loop {
            let at_top = stack.len() == 1;
            let Some(frame) = stack.last_mut() else {
                return Ok(false);
            };
            match frame.next_name() {
                Ok(Some(name)) => {
                    match self.handle(frame, &name, at_top)? {
                        Handled::Deleted => frame.progressed = true,
                        Handled::Left => {
                            frame.left_names.insert(name);
                        }
                        Handled::Descend(child) => stack.push(child),
                        Handled::Vanished => {}
                    }
                    continue;
                }
                Ok(None) => {}
                Err(error) => {
                    frame.blocked = true;
                    self.fail(&error);
                }
            }
            let Some(done) = stack.pop() else {
                return Ok(false);
            };
            let Frame {
                dir,
                listing,
                name,
                info,
                left_names,
                blocked,
                ..
            } = done;
            // Handles to a directory are closed before it is removed.
            drop(listing);
            drop(dir);
            let removed = left_names.is_empty() && !blocked && {
                match stack.last().map(|above| &above.dir).or(parent) {
                    Some(holder) => self.remove_counted(holder, &name, &info)?,
                    // A top with no holder is only emptied.
                    None => true,
                }
            };
            match stack.last_mut() {
                None => return Ok(removed),
                Some(above) if removed => above.progressed = true,
                Some(above) => {
                    above.left_names.insert(OsString::from(name));
                }
            }
        }
    }

    /// Deletes, leaves or descends into the entry `name` of `frame`'s directory.
    fn handle(
        &mut self,
        frame: &Frame,
        name: &OsString,
        at_top: bool,
    ) -> Result<Handled, Interrupted> {
        let Some(text) = name.to_str() else {
            self.left.unrepresentable_names = self.left.unrepresentable_names.saturating_add(1);
            return Ok(Handled::Left);
        };
        if at_top && self.spare.top_names.contains(text) {
            self.left.spared = self.left.spared.saturating_add(1);
            return Ok(Handled::Left);
        }
        let info = match fsutil::entry_info(&frame.dir, text) {
            Ok(info) => info,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Handled::Vanished),
            Err(error) => {
                self.fail(&error);
                return Ok(Handled::Left);
            }
        };
        let identity = identity_of(&info).digest();
        if self.spare.identities.contains(&identity) {
            self.left.spared = self.left.spared.saturating_add(1);
            return Ok(Handled::Left);
        }
        if self.spare.unfinished.contains(&identity) {
            self.left.unfinished = self.left.unfinished.saturating_add(1);
            return Ok(Handled::Left);
        }
        match info.kind {
            // A mount is recognised by its volume only. On Unix that is the device number,
            // so a bind mount of a directory from the tree's own filesystem, which keeps the
            // device number, is not recognised: it is entered and emptied as part of the
            // tree. On Windows a mounted volume folder is a reparse point, removed as a link.
            HandleKind::Directory if info.volume != self.volume => {
                self.left.mount_crossings = self.left.mount_crossings.saturating_add(1);
                Ok(Handled::Left)
            }
            HandleKind::Directory => match open_directory(&frame.dir, text, &info) {
                Ok(Opening::Frame(child)) => Ok(Handled::Descend(child)),
                Ok(Opening::Vanished) => Ok(Handled::Vanished),
                Ok(Opening::Changed) => {
                    self.left.changed = self.left.changed.saturating_add(1);
                    Ok(Handled::Left)
                }
                Err(error) => {
                    self.fail(&error);
                    Ok(Handled::Left)
                }
            },
            HandleKind::File | HandleKind::Link(_) | HandleKind::Device => {
                if self.remove_counted(&frame.dir, text, &info)? {
                    Ok(Handled::Deleted)
                } else {
                    Ok(Handled::Left)
                }
            }
        }
    }
}

/// Whether the name of `removed`, just removed from `dir`, still lingers: it still names
/// the object, or names something that cannot be opened, as a delete-pending name cannot.
/// A new object at the name is not the removed one; the next pass meets it.
fn lingers(dir: &Dir, name: &str, removed: &HandleInfo) -> bool {
    match fsutil::entry_info(dir, name) {
        Ok(info) => info.same_object(removed),
        Err(error) => error.kind() != io::ErrorKind::NotFound,
    }
}

/// Removes `name` of `dir` as itself, if it is still the object `info` describes: an empty
/// directory, a file name (another name of a hard-linked file keeps its content), a link
/// (never its target) or a device node.
#[cfg(windows)]
fn remove_entry(dir: &Dir, name: &str, info: &HandleInfo) -> io::Result<bool> {
    // The open behind the removal does not follow a reparse point, so a link goes as itself.
    fsutil::remove_host_owned(dir, name, info)
}

/// Removes `name` of `dir` as itself, if it is still the object `info` describes: an empty
/// directory, a file name (another name of a hard-linked file keeps its content), a link
/// (never its target) or a device node.
#[cfg(unix)]
fn remove_entry(dir: &Dir, name: &str, info: &HandleInfo) -> io::Result<bool> {
    if !matches!(info.kind, HandleKind::Link(_)) {
        return fsutil::remove_host_owned(dir, name, info);
    }
    // `fsutil::remove` refuses links; `unlinkat` without `AT_REMOVEDIR` removes the link
    // itself once a non-following stat names the same link again.
    if !fsutil::entry_info(dir, name)?.is(info) {
        return Ok(false);
    }
    dir.remove_file(name)?;
    Ok(true)
}
