//! Recovering the teardown of a sandbox root whose name holds something else (VM part §6.1:
//! "Every transition is idempotent and records its generation ... Recovery reconciles actual
//! VM objects and resources"; §6.4: "Cleanup uses host-created object handles and verified
//! managed roots, resists reparse/symlink races, and preserves user source data"; VM-W24,
//! VM-W29; VM-P49).
//!
//! [`teardown`] refuses a sandbox root whose name no longer holds the directory created
//! (renamed away, with another directory, a junction or a file put at the name), with
//! nothing deleted and the journal unchanged. [`recover_teardown`] is that recovery. It
//! opens the directory created by the raw file identity journaled beside its identity
//! ([`RawFileIdentity`]), with `OpenFileById` through the managed parent's handle, so on the
//! parent's volume and never by a path, and accepts it only when its handle gives the whole
//! raw identity and the recorded identity digest. From that handle it runs teardown's own
//! sequence: every entry is observed relative to the handle and put to V05 with the handle
//! it was registered under before anything is deleted, removable volumes go through the
//! same handle-relative removal, and kept and preserved volumes are never deleted. The root,
//! once empty, is deleted by the name its own handle says it has now, relative to the handle
//! of the directory holding it, opened by that directory's file ID, and only while the name
//! still names the root ([`file_id`]'s `delete_by_id`; NTFS deletes nothing through a handle
//! opened by file ID). What is at the root's name is observed once, as teardown observes it,
//! never opened for writing, entered or deleted, and reported left in place
//! ([`LeftAtName`]).
//!
//! Recovery journals its progress as teardown does, so a run after a crash continues, and a
//! run after recovery finished reports what is already gone. It refuses, typed, with nothing
//! deleted and the journal unchanged ([`RecoveryRefusal`]): when the name holds the created
//! root (teardown applies), when the journal holds no raw identity (one written before it was
//! recorded, or a volume that gives none), when the managed parent is not on the volume the
//! root was created on, and when nothing on the volume has the file ID any more or the ID
//! names another object. Only an earlier run's own journal makes a root gone from its file
//! ID already gone: one that recorded the root deleted, or every entry removed, so that the
//! root's deletion may be that run's, unjournaled when a crash came, and nothing of the
//! layout is left to look for. On Unix no open by file ID exists, and recovery refuses.
//!
//! Limits: only the managed parent's volume is searched. A replacement on another volume (a
//! junction or mount point at the name) is only observed as itself, never followed, and is
//! left in place; an original moved to another volume was copied and deleted, so its file ID
//! is gone here, and recovery refuses. The original is found wherever it lies on the volume,
//! inside the replacement included, and is emptied and deleted there.
//!
//! [`teardown`]: super::teardown

use std::fmt;

use cap_std::fs::Dir;
use serde::Serialize;

use super::cleanup::{ManagedObjects, ObservedIdentities};
use super::file_id::{self, ById, Deletion, RawFileIdentity, OPENS_BY_ID};
use super::fresh_root::{observe_at, AtName};
use super::fsutil;
use super::names::GuestName;
use super::review::RootIdentity;
use super::root::GrantedRoot;
use super::root_journal::{RootJournal, RootJournalStore, RootPhase};
use super::teardown::{
    root_step, work_through, ObservedRoot, TeardownError, TeardownFailure, TeardownOutcome,
    TeardownReport,
};
use super::tree::{empty_tree, Interrupted, Spare};
use super::vm_processes::{ended_vm_processes, VmProcessEnds};

/// What recovery found at the sandbox root's name, observed as teardown observes it, never
/// opened for writing, entered or deleted, and left in place.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeftAtName {
    /// Nothing has the name.
    Nothing,
    /// Another real directory.
    Directory,
    /// A link, a file, a device or a case alias.
    Other,
}

/// Why recovery did not run: nothing was deleted and the journal is unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum RecoveryRefusal {
    /// This platform opens nothing by file ID (Unix): recovery exists on Windows only.
    NoOpenByFileId,
    /// The journal holds no raw file identity of the root: it was written before one was
    /// recorded, or the root's volume gives none.
    NoRawIdentity,
    /// The name holds the root created; [`teardown`](super::teardown) removes it.
    NotReplaced,
    /// The managed parent is not on the volume the root was created on.
    OtherVolume,
    /// Nothing on the volume has the root's file ID any more.
    OriginalGone,
    /// The root's file ID names another object: no real directory, or not the root's
    /// identity.
    IdentityChanged,
}

impl fmt::Display for RecoveryRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoOpenByFileId => "this platform opens nothing by file ID",
            Self::NoRawIdentity => "the journal holds no raw file identity of the root",
            Self::NotReplaced => "the root's name holds the root created; tear it down instead",
            Self::OtherVolume => "the managed parent is not on the root's volume",
            Self::OriginalGone => "nothing on the volume has the root's file ID any more",
            Self::IdentityChanged => "the root's file ID names another object",
        })
    }
}

impl std::error::Error for RecoveryRefusal {}

/// Why a recovery run stopped.
#[derive(Debug)]
pub enum RecoveryError {
    /// Recovery does not apply, or cannot find the root created; nothing was deleted and the
    /// journal is unchanged.
    Refused(RecoveryRefusal),
    /// Stopped as teardown stops, with what teardown's error says.
    Teardown(TeardownError),
}

impl From<TeardownError> for RecoveryError {
    fn from(error: TeardownError) -> Self {
        Self::Teardown(error)
    }
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refusal) => write!(f, "recovery refused: {refusal}"),
            Self::Teardown(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for RecoveryError {}

/// What one recovery run did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecoveryReport {
    /// What is at the root's name, left in place.
    pub left_at_name: LeftAtName,
    /// What the run did with each object, through the root opened by its file ID.
    pub teardown: TeardownReport,
}

/// Recovers the teardown of the committed fresh root `journal` records when its name holds
/// something else, as [`teardown`](super::teardown) does but through the root opened by its
/// journaled file ID on the volume of the managed parent the host opened now, with the V05
/// `registry` holding its registrations, journaling progress in `store`, once `ends` shows
/// every VM host process journaled for the boot ended.
pub fn recover_teardown<J: RootJournalStore>(
    parent: &GrantedRoot,
    registry: &ManagedObjects,
    journal: &mut RootJournal,
    store: &mut J,
    ends: &dyn VmProcessEnds,
) -> Result<RecoveryReport, RecoveryError> {
    recover_teardown_with(parent, registry, journal, store, ends, &mut || true)
}

/// [`recover_teardown`], calling `after_delete` after every deletion; when it returns false
/// the run stops there as a crash would. The hook exists so tests can stop a recovery after
/// any deletion; production passes one that always continues.
pub(super) fn recover_teardown_with<J: RootJournalStore>(
    parent: &GrantedRoot,
    registry: &ManagedObjects,
    journal: &mut RootJournal,
    store: &mut J,
    ends: &dyn VmProcessEnds,
    after_delete: &mut dyn FnMut() -> bool,
) -> Result<RecoveryReport, RecoveryError> {
    if !journal.phase().is_committed() {
        return Err(TeardownError::NotCommitted.into());
    }
    if !OPENS_BY_ID {
        return Err(RecoveryError::Refused(RecoveryRefusal::NoOpenByFileId));
    }
    let Some(raw) = journal.root_raw_identity() else {
        return Err(RecoveryError::Refused(RecoveryRefusal::NoRawIdentity));
    };
    // The VMs' host processes first, as for teardown.
    let vm_processes = ended_vm_processes(journal.vm_processes(), ends)
        .map_err(|(identity, refusal)| TeardownError::VmProcess { identity, refusal })?;
    let root_name = journal.root_name().clone();
    let (Some(root_identity), Some(root_handle)) =
        (journal.root().identity(), journal.root().handle())
    else {
        return Err(TeardownError::NotCommitted.into());
    };
    let dispositions = journal.dispositions().map_err(TeardownError::Renewal)?;
    let io = |error: std::io::Error| TeardownError::Io {
        name: journal.root_name().clone(),
        error,
    };

    // The name, observed as teardown observes it, and only classified.
    let left_at_name = match observe_at(parent, &root_name).map_err(io)? {
        AtName::Directory { identity, .. } if identity == root_identity => {
            return Err(RecoveryError::Refused(RecoveryRefusal::NotReplaced))
        }
        AtName::Absent => LeftAtName::Nothing,
        AtName::Directory { .. } => LeftAtName::Directory,
        AtName::Other => LeftAtName::Other,
    };
    if file_id::volume_serial(parent.dir()).map_err(io)? != raw.volume_serial {
        return Err(RecoveryError::Refused(RecoveryRefusal::OtherVolume));
    }
    let root_dir = match file_id::open_by_id(parent.dir(), &raw, root_identity).map_err(io)? {
        ById::Found(file) => Some(fsutil::into_dir(file)),
        ById::Gone | ById::Other if emptied_by_journal(journal) => None,
        ById::Gone => return Err(RecoveryError::Refused(RecoveryRefusal::OriginalGone)),
        ById::Other => return Err(RecoveryError::Refused(RecoveryRefusal::IdentityChanged)),
    };

    let mut observed = ObservedIdentities::default();
    observed
        .roots
        .insert(journal.parent_root(), parent.identity().digest());
    if root_dir.is_some() {
        observed.objects_present.insert(root_identity.digest());
    }
    // V05 verifies the managed parent with the root object.
    let step = root_step(registry, &root_name, root_handle, root_identity, &observed)?;
    if root_dir.is_some() {
        observed
            .roots
            .insert(journal.boot().managed_root(), root_identity.digest());
    }
    let root = ObservedRoot {
        vm_processes,
        name: root_name,
        step,
        dir: root_dir,
        observed,
        dispositions,
    };
    let by_id = RootById {
        volume: parent.dir(),
        raw,
    };
    let teardown = work_through(
        registry,
        journal,
        store,
        root,
        after_delete,
        |dir, name, identity, spare, after_delete, failures| {
            remove_by_id(&by_id, dir, name, identity, spare, after_delete, failures)
        },
    )?;
    Ok(RecoveryReport {
        left_at_name,
        teardown,
    })
}

/// Whether an earlier run's journal shows the root emptied of the layout: teardown began,
/// and recorded the root deleted or already gone, or every entry so. The root's deletion
/// may then be that run's, which a crash left unjournaled, and nothing of the layout is
/// left to look for.
fn emptied_by_journal(journal: &RootJournal) -> bool {
    let finished = journal.phase().finished();
    let removed = |name: &GuestName| {
        finished.iter().any(|done| {
            &done.name == name
                && matches!(
                    done.outcome,
                    TeardownOutcome::Deleted { .. } | TeardownOutcome::AlreadyGone
                )
        })
    };
    matches!(
        journal.phase(),
        RootPhase::TearingDown { .. } | RootPhase::TornDown { .. }
    ) && (removed(journal.root_name())
        || journal.entries().iter().all(|entry| removed(&entry.name)))
}

/// The root as recovery opened it: by its raw identity, on the volume `volume` is a handle on.
struct RootById<'a> {
    volume: &'a Dir,
    raw: RawFileIdentity,
}

/// Empties the root `dir` through its own handle of everything `spare` does not spare,
/// closing the handle, then, once it is empty, deletes it by its file ID
/// ([`file_id::delete_by_id`]); a filesystem error is noted in `failures` under `name`.
fn remove_by_id(
    root: &RootById<'_>,
    dir: Option<Dir>,
    name: &GuestName,
    identity: RootIdentity,
    spare: &Spare,
    after_delete: &mut dyn FnMut() -> bool,
    failures: &mut Vec<TeardownFailure>,
) -> Result<TeardownOutcome, TeardownError> {
    let Some(dir) = dir else {
        return Ok(TeardownOutcome::AlreadyGone);
    };
    let emptied = empty_tree(dir, spare, after_delete)
        .map_err(|Interrupted { deleted }| TeardownError::Interrupted { deleted })?;
    let mut deleted = emptied.deleted;
    let mut left = emptied.left;
    let mut first_error = emptied.first_error;
    let mut removed = false;
    if emptied.removed {
        match file_id::delete_by_id(root.volume, &root.raw, identity) {
            Ok(Deletion::Deleted) => {
                deleted = deleted.saturating_add(1);
                if !after_delete() {
                    return Err(TeardownError::Interrupted { deleted });
                }
                removed = true;
            }
            Ok(Deletion::Pending) => left.pending = left.pending.saturating_add(1),
            Ok(Deletion::Changed) => left.changed = left.changed.saturating_add(1),
            Ok(Deletion::Unrepresentable) => {
                left.unrepresentable_names = left.unrepresentable_names.saturating_add(1);
            }
            // Gone, or another object has its file ID: the root is gone from where it was.
            Ok(Deletion::Gone | Deletion::Other) => return Ok(TeardownOutcome::AlreadyGone),
            Err(error) => {
                left.failed = left.failed.saturating_add(1);
                first_error.get_or_insert(error.kind());
            }
        }
    }
    if let Some(kind) = first_error {
        failures.push(TeardownFailure {
            name: name.clone(),
            error: format!("{kind:?}"),
        });
    }
    Ok(if removed {
        TeardownOutcome::Deleted { entries: deleted }
    } else {
        TeardownOutcome::Incomplete { deleted, left }
    })
}
