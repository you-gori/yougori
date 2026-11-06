//! Tearing a committed fresh root down through handles (VM part §6.4: "Cleanup uses
//! host-created object handles and verified managed roots, resists reparse/symlink races,
//! and preserves user source data"; §6.5: deletion is logical cleanup, never physical
//! wiping; VM-W24 "idempotent cleanup", acceptance "user data preserved; teardown cannot
//! escape managed roots"; VM-P49).
//!
//! This carries out what V05's cleanup safety check
//! ([`ManagedObjects::validate_cleanup`]) accepts, and is the runtime part that check
//! leaves open: the file-touching half of the lifecycle supervisor's cleanup, opening as
//! its plan's `OpenMode::RootHandleNoFollowVerified` says (relative to the root's handle,
//! never following a link, identity verified after opening).
//!
//! [`teardown`] first requires the host's evidence that every VM host process journaled for
//! the boot ended ([`super::vm_processes`]): a proof from the table that held its handle, or
//! its PID no longer naming it. A process still running, a proof of another process or a
//! process the host cannot observe stops teardown before anything is observed or deleted,
//! with the journal unchanged; ending the VM is the coordinator's part. It then observes,
//! through handles and without following anything, the sandbox root at its name, before
//! anything the layout says. The managed parent is verified by V05
//! with the root object, and a sandbox root that is not the directory created (replaced by
//! another directory, swapped for a junction or a file) is refused, with nothing deleted
//! and the journal unchanged, so recovery stays open
//! ([`recover_teardown`](super::recover_teardown) opens the directory created by its file
//! ID and works through it as below, [`work_through`]). Each object in the root is then
//! observed with the identity read from its handle and put to V05 with the handle it was
//! registered under, before anything is deleted; a stale handle or any other refusal stops
//! teardown with nothing deleted. What is kept is V05's renewal plan, made again from the
//! journal: kept and preserved volumes were registered as a kind V05's cleanup check refuses
//! to delete, so that check itself keeps them, and teardown never deletes them.
//!
//! The journal enters teardown before the first deletion. Overlay, scratch and removable
//! volumes go first, last created first, each through [`remove_tree`]'s handle-relative
//! depth-first removal, which deletes only while the object still has its registered
//! identity, removes links as themselves and never enters their targets, and spares kept and
//! preserved objects wherever they are met; the sandbox root goes last, and only once it is
//! empty: kept and preserved volumes stay at their names, and with them the root. A
//! filesystem error on one entry never stops the run: every other object is still worked
//! through, and each object that could not be removed is reported with what was left and
//! why ([`LeftBehind`]) and the first error's kind. Each object's outcome is journaled, and
//! the journal records the teardown finished only once every removable object is gone.
//! Teardown is idempotent: a run after a crash, a failure or a partial run observes again,
//! continues every tree still there with its identity, and reports what is already gone; a
//! root that is gone takes what it held with it, and nothing is looked for elsewhere.
//! Deletion is logical cleanup (the lifecycle's `LogicalCleanupAction`s, such as
//! `OverlayDeleted`), never a proof of physical wiping.
//!
//! V05's registry has no removal, so the registrations of deleted objects stay; V05 then
//! reports them already gone.

use std::collections::BTreeSet;
use std::fmt;
use std::io;

use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};

use super::cleanup::{
    CleanupPlan, CleanupRefusal, CleanupTarget, ManagedObjects, ObjectHandle, ObservedIdentities,
};
use super::fresh_root::{observe_at, AtName, TeardownDisposition};
use super::fsutil::{self, HandleKind};
use super::names::GuestName;
use super::review::RootIdentity;
use super::root::{identity_of, GrantedRoot};
use super::root_journal::{RootJournal, RootJournalFailure, RootJournalStore, RootPhase};
use super::tree::{remove_tree, Interrupted, Spare, TreeOutcome};
use super::vm_processes::{ended_vm_processes, EndedVmProcess, VmProcessEnds, VmProcessRefusal};
use super::volumes::{RenewalRefusal, VolumeClass};
use crate::foundation::process::ProcessIdentity;

/// What a tree removal left in place, by reason.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeftBehind {
    /// Kept and preserved objects, spared.
    pub spared: u64,
    /// Objects of the layout whose own teardown is unfinished, left with what they hold.
    pub unfinished: u64,
    /// Directories on another volume, never entered.
    pub mount_crossings: u64,
    /// Names the platform's string form cannot carry.
    pub unrepresentable_names: u64,
    /// Entries that were no longer the object checked when their removal came.
    pub changed: u64,
    /// Entries removed whose names linger until another process closes them (a volume
    /// without POSIX delete semantics); a later run finishes them.
    pub pending: u64,
    /// Entries a filesystem step failed on; a later run tries them again.
    pub failed: u64,
}

impl LeftBehind {
    /// Whether nothing but spared objects was left.
    pub const fn only_spared(&self) -> bool {
        self.unfinished == 0
            && self.mount_crossings == 0
            && self.unrepresentable_names == 0
            && self.changed == 0
            && self.pending == 0
            && self.failed == 0
    }
}

strict_tagged_enum! {
    /// What teardown did with one object.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TeardownOutcome (tag = "outcome", wire = TeardownOutcomeWire, wire_name = "TeardownOutcomeWire") {
        /// Deleted now: `entries` filesystem entries went, the object itself included. A
        /// logical deletion only (§6.5).
        Deleted { entries: u64 },
        /// Nothing with its registered identity is at its name.
        AlreadyGone,
        /// Kept: V05's renewal plan carries its bytes past the boot (§5.5).
        Kept { class: VolumeClass },
        /// User source data, which V05 refuses to clean up.
        Preserved,
        /// Worked through, but entries stay, so the object stays too.
        Incomplete { deleted: u64, left: LeftBehind },
    }
}

impl TeardownOutcome {
    /// Whether teardown is done with the object: it is gone, kept or preserved, or stays
    /// only because it holds kept or preserved objects.
    pub const fn is_finished(&self) -> bool {
        match self {
            Self::Incomplete { left, .. } => left.only_spared(),
            Self::Deleted { .. } | Self::AlreadyGone | Self::Kept { .. } | Self::Preserved => true,
        }
    }
}

/// One object teardown finished, by its name: the sandbox root's name in the managed
/// parent, or a layout entry's in the root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishedObject {
    pub name: GuestName,
    pub outcome: TeardownOutcome,
}

/// An object whose removal met a filesystem error, with the kind of the first one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TeardownFailure {
    pub name: GuestName,
    pub error: String,
}

/// What one teardown run did, in the order it did it: entries last created first, the
/// root last.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TeardownReport {
    /// Each VM host process journaled for the boot, and how the host knows it ended.
    pub vm_processes: Vec<EndedVmProcess>,
    pub objects: Vec<FinishedObject>,
    /// Every object whose removal met a filesystem error this run.
    pub failures: Vec<TeardownFailure>,
    /// Whether the journal now records the teardown finished.
    pub torn_down: bool,
}

/// Why a teardown run stopped.
#[derive(Debug)]
pub enum TeardownError {
    /// The root never committed; a launch is undone by
    /// [`compensate_launch`](super::compensate_launch) instead.
    NotCommitted,
    /// V05's renewal plan refuses a volume of the journal; nothing was deleted.
    Renewal(RenewalRefusal),
    /// A VM host process journaled for the boot has no host evidence of its end; nothing
    /// was observed or deleted and the journal is unchanged.
    VmProcess {
        identity: ProcessIdentity,
        refusal: VmProcessRefusal,
    },
    /// The cleanup of `name` was refused, by V05 or because the sandbox root at its name is
    /// not the directory created; nothing was deleted and the journal is unchanged.
    Refused {
        name: GuestName,
        refusal: CleanupRefusal,
    },
    /// V05 planned something other than deleting a directory, or accepted deleting a kept
    /// volume; nothing was deleted.
    UnexpectedPlan { name: GuestName, plan: CleanupPlan },
    /// The journal could not be written; nothing further was deleted.
    Journal(RootJournalFailure),
    /// The sandbox root could not be observed at its name; nothing was deleted.
    Io { name: GuestName, error: io::Error },
    /// Stopped after `deleted` deletions in the object under way, as a crash would stop it
    /// (tests only); a later run continues.
    Interrupted { deleted: u64 },
}

impl fmt::Display for TeardownError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCommitted => f.write_str("the root never committed; compensate the launch"),
            Self::Renewal(refusal) => write!(f, "the journal's renewal is refused: {refusal}"),
            Self::VmProcess { identity, refusal } => {
                write!(f, "the VM host {identity} has not ended: {refusal}")
            }
            Self::Refused { name, refusal } => write!(f, "cleanup of {name} refused: {refusal}"),
            Self::UnexpectedPlan { name, plan } => {
                write!(f, "cleanup of {name} was planned as {plan:?}")
            }
            Self::Journal(failure) => write!(f, "{failure}"),
            Self::Io { name, error } => {
                write!(f, "{name} could not be observed: {:?}", error.kind())
            }
            Self::Interrupted { deleted } => {
                write!(f, "teardown was interrupted after {deleted} deletions")
            }
        }
    }
}

impl std::error::Error for TeardownError {}

/// Tears down the committed fresh root `journal` records, beneath the managed parent the
/// host opened now, with the V05 `registry` holding its registrations (restored from the
/// journal after a restart), journaling progress in `store`, once `ends` shows every VM host
/// process journaled for the boot ended.
pub fn teardown<J: RootJournalStore>(
    parent: &GrantedRoot,
    registry: &ManagedObjects,
    journal: &mut RootJournal,
    store: &mut J,
    ends: &dyn VmProcessEnds,
) -> Result<TeardownReport, TeardownError> {
    teardown_with(parent, registry, journal, store, ends, &mut || true)
}

/// A validated step of one object.
pub(super) enum Step {
    Delete(RootIdentity),
    Gone,
    Keep(VolumeClass),
    Preserve,
}

/// [`teardown`], calling `after_delete` after every deletion; when it returns false the
/// run stops there as a crash would. The hook exists so tests can stop a teardown after
/// any deletion; production passes one that always continues.
pub(super) fn teardown_with<J: RootJournalStore>(
    parent: &GrantedRoot,
    registry: &ManagedObjects,
    journal: &mut RootJournal,
    store: &mut J,
    ends: &dyn VmProcessEnds,
    after_delete: &mut dyn FnMut() -> bool,
) -> Result<TeardownReport, TeardownError> {
    if !journal.phase().is_committed() {
        return Err(TeardownError::NotCommitted);
    }
    // The VMs' host processes first: nothing of a root goes while one may still use it.
    let vm_processes = ended_vm_processes(journal.vm_processes(), ends)
        .map_err(|(identity, refusal)| TeardownError::VmProcess { identity, refusal })?;
    let root_name = journal.root_name().clone();
    let (Some(root_identity), Some(root_handle)) =
        (journal.root().identity(), journal.root().handle())
    else {
        return Err(TeardownError::NotCommitted);
    };
    let dispositions = journal.dispositions().map_err(TeardownError::Renewal)?;

    // The sandbox root first, before anything the layout says.
    let at_root = observe_at(parent, &root_name).map_err(|error| TeardownError::Io {
        name: root_name.clone(),
        error,
    })?;
    let mut observed = ObservedIdentities::default();
    observed
        .roots
        .insert(journal.parent_root(), parent.identity().digest());
    if matches!(&at_root, AtName::Directory { identity, .. } if *identity == root_identity) {
        observed.objects_present.insert(root_identity.digest());
    }
    // V05 verifies the managed parent with the root object.
    let root_step = root_step(registry, &root_name, root_handle, root_identity, &observed)?;
    let sandbox_root = journal.boot().managed_root();
    let root_dir = match at_root {
        AtName::Absent => None,
        AtName::Directory { dir, identity } if identity == root_identity => Some(dir),
        AtName::Directory { .. } | AtName::Other => {
            return Err(TeardownError::Refused {
                name: root_name,
                refusal: CleanupRefusal::RootIdentityChanged { root: sandbox_root },
            })
        }
    };
    if root_dir.is_some() {
        observed.roots.insert(sandbox_root, root_identity.digest());
    }
    let root = ObservedRoot {
        vm_processes,
        name: root_name,
        step: root_step,
        dir: root_dir,
        observed,
        dispositions,
    };
    work_through(
        registry,
        journal,
        store,
        root,
        after_delete,
        |dir, name, identity, spare, after_delete, failures| {
            // Every handle to the root is closed before it is removed.
            drop(dir);
            delete(parent.dir(), name, identity, spare, after_delete, failures)
        },
    )
}

/// V05's plan for the sandbox root as an object of the managed parent, which verifies the
/// parent: deleted when `observed` holds it, already gone when not.
pub(super) fn root_step(
    registry: &ManagedObjects,
    name: &GuestName,
    handle: ObjectHandle,
    identity: RootIdentity,
    observed: &ObservedIdentities,
) -> Result<Step, TeardownError> {
    match validate(registry, name, handle, observed)? {
        CleanupPlan::Delete { .. } => Ok(Step::Delete(identity)),
        CleanupPlan::AlreadyGone { .. } => Ok(Step::Gone),
        plan @ CleanupPlan::Terminate { .. } => Err(TeardownError::UnexpectedPlan {
            name: name.clone(),
            plan,
        }),
    }
}

/// The sandbox root once a run observed it and put it to V05, which [`work_through`] goes
/// on from.
pub(super) struct ObservedRoot {
    /// Each VM host process journaled for the boot, shown ended.
    pub vm_processes: Vec<EndedVmProcess>,
    /// The root's name in the managed parent.
    pub name: GuestName,
    pub step: Step,
    /// The root opened as itself, with its recorded identity; `None` when it is gone.
    pub dir: Option<Dir>,
    /// The managed parent, and the root with its managed root when present.
    pub observed: ObservedIdentities,
    /// What teardown does with each entry, from V05's renewal plan.
    pub dispositions: Vec<TeardownDisposition>,
}

/// Teardown from the observed root on: puts every entry to V05 through the root's handle
/// before anything is deleted, enters teardown in the journal, removes the entries last
/// created first and journals each, then has `remove_root` remove the root (with its
/// handle, which it closes, and what to spare) when V05 planned its deletion, and records
/// the teardown finished once every object is.
pub(super) fn work_through<J, R>(
    registry: &ManagedObjects,
    journal: &mut RootJournal,
    store: &mut J,
    root: ObservedRoot,
    after_delete: &mut dyn FnMut() -> bool,
    remove_root: R,
) -> Result<TeardownReport, TeardownError>
where
    J: RootJournalStore,
    R: FnOnce(
        Option<Dir>,
        &GuestName,
        RootIdentity,
        &Spare,
        &mut dyn FnMut() -> bool,
        &mut Vec<TeardownFailure>,
    ) -> Result<TeardownOutcome, TeardownError>,
{
    let ObservedRoot {
        vm_processes,
        name: root_name,
        step: root_step,
        dir: root_dir,
        mut observed,
        dispositions,
    } = root;

    // Every object is put to V05 before anything is deleted.
    let mut spare = Spare::default();
    let mut steps = Vec::with_capacity(journal.entries().len());
    for (entry, disposition) in journal.entries().iter().zip(dispositions) {
        let (Some(identity), Some(handle)) = (entry.state.identity(), entry.state.handle()) else {
            return Err(TeardownError::NotCommitted);
        };
        if disposition != TeardownDisposition::Remove {
            spare.identities.insert(identity.digest());
            spare.top_names.insert(entry.name.as_str().to_owned());
        }
        // A root that is gone took what it held with it.
        let Some(dir) = &root_dir else {
            steps.push((entry.name.clone(), identity, Step::Gone));
            continue;
        };
        // An entry that cannot be observed is taken as present; its removal observes again.
        let present = holds(dir, &entry.name, identity).unwrap_or(true);
        if present {
            observed.objects_present.insert(identity.digest());
        }
        let plan = registry.validate_cleanup(&CleanupTarget::Object { handle }, &observed);
        let step = match (disposition, plan) {
            (TeardownDisposition::Keep { .. }, Err(CleanupRefusal::RetainedByRenewal { .. }))
            | (
                TeardownDisposition::PreserveUserData,
                Err(CleanupRefusal::PreservesUserData { .. }),
            ) if !present => Step::Gone,
            (
                TeardownDisposition::Keep { class },
                Err(CleanupRefusal::RetainedByRenewal { .. }),
            ) => Step::Keep(class),
            (
                TeardownDisposition::PreserveUserData,
                Err(CleanupRefusal::PreservesUserData { .. }),
            ) => Step::Preserve,
            (_, Err(refusal)) => {
                return Err(TeardownError::Refused {
                    name: entry.name.clone(),
                    refusal,
                })
            }
            (TeardownDisposition::Remove, Ok(CleanupPlan::Delete { .. })) => Step::Delete(identity),
            (TeardownDisposition::Remove, Ok(CleanupPlan::AlreadyGone { .. })) => Step::Gone,
            (_, Ok(plan)) => {
                return Err(TeardownError::UnexpectedPlan {
                    name: entry.name.clone(),
                    plan,
                })
            }
        };
        steps.push((entry.name.clone(), identity, step));
    }

    // Written ahead of the first deletion.
    journal.enter_teardown();
    store.persist(journal).map_err(TeardownError::Journal)?;
    let entry_spare = Spare {
        identities: spare.identities.clone(),
        top_names: BTreeSet::new(),
        unfinished: BTreeSet::new(),
    };
    let mut objects = Vec::with_capacity(steps.len().saturating_add(1));
    let mut failures = Vec::new();
    for (name, identity, step) in steps.into_iter().rev() {
        let outcome = match (step, &root_dir) {
            (Step::Delete(identity), Some(dir)) => delete(
                dir,
                &name,
                identity,
                &entry_spare,
                after_delete,
                &mut failures,
            )?,
            (Step::Delete(_) | Step::Gone, _) => TeardownOutcome::AlreadyGone,
            (Step::Keep(class), _) => TeardownOutcome::Kept { class },
            (Step::Preserve, _) => TeardownOutcome::Preserved,
        };
        // An object that stays unfinished stays with what it holds when the root goes.
        if !outcome.is_finished() {
            spare.unfinished.insert(identity.digest());
        }
        finish(journal, store, &name, outcome)?;
        objects.push(FinishedObject { name, outcome });
    }
    let root_outcome = match root_step {
        Step::Delete(identity) => remove_root(
            root_dir,
            &root_name,
            identity,
            &spare,
            after_delete,
            &mut failures,
        )?,
        Step::Gone | Step::Keep(_) | Step::Preserve => TeardownOutcome::AlreadyGone,
    };
    finish(journal, store, &root_name, root_outcome)?;
    objects.push(FinishedObject {
        name: root_name,
        outcome: root_outcome,
    });
    if journal.teardown_finished() {
        journal.finish_teardown();
        store.persist(journal).map_err(TeardownError::Journal)?;
    }
    Ok(TeardownReport {
        vm_processes,
        objects,
        failures,
        torn_down: matches!(journal.phase(), RootPhase::TornDown { .. }),
    })
}

/// Whether `dir` holds, at `name`, the directory with `identity`, read without following.
fn holds(dir: &Dir, name: &GuestName, identity: RootIdentity) -> io::Result<bool> {
    match fsutil::entry_info(dir, name.as_str()) {
        Ok(info) => Ok(info.kind == HandleKind::Directory && identity_of(&info) == identity),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn validate(
    registry: &ManagedObjects,
    name: &GuestName,
    handle: ObjectHandle,
    observed: &ObservedIdentities,
) -> Result<CleanupPlan, TeardownError> {
    registry
        .validate_cleanup(&CleanupTarget::Object { handle }, observed)
        .map_err(|refusal| TeardownError::Refused {
            name: name.clone(),
            refusal,
        })
}

/// Deletes the tree `name` of `holder` if it still has `identity`, noting a filesystem
/// error in `failures`.
fn delete(
    holder: &Dir,
    name: &GuestName,
    identity: RootIdentity,
    spare: &Spare,
    after_delete: &mut dyn FnMut() -> bool,
    failures: &mut Vec<TeardownFailure>,
) -> Result<TeardownOutcome, TeardownError> {
    let removal = match remove_tree(holder, name.as_str(), identity, spare, after_delete) {
        // Another object at the name now is not the one registered; the registered one is
        // gone from its place.
        Ok(TreeOutcome::Gone | TreeOutcome::NotTheObject) => {
            return Ok(TeardownOutcome::AlreadyGone)
        }
        Ok(TreeOutcome::Worked(removal)) => removal,
        Err(Interrupted { deleted }) => return Err(TeardownError::Interrupted { deleted }),
    };
    if let Some(kind) = removal.first_error {
        failures.push(TeardownFailure {
            name: name.clone(),
            error: format!("{kind:?}"),
        });
    }
    Ok(if removal.removed {
        TeardownOutcome::Deleted {
            entries: removal.deleted,
        }
    } else {
        TeardownOutcome::Incomplete {
            deleted: removal.deleted,
            left: removal.left,
        }
    })
}

/// Journals `outcome` for `name`.
fn finish<J: RootJournalStore>(
    journal: &mut RootJournal,
    store: &mut J,
    name: &GuestName,
    outcome: TeardownOutcome,
) -> Result<(), TeardownError> {
    journal.record(name, outcome);
    store.persist(journal).map_err(TeardownError::Journal)
}
