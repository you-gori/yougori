//! Fresh per-sandbox roots and the undo of a failed launch (VM part §5.5 "Persistent state
//! is not automatically clean"; §6.1 launch transaction: "Failure before authority
//! activation exposes no external capability"; §6.4; VM-W24 "Fresh roots/overlays, explicit
//! data classification, launch transaction and idempotent cleanup", acceptance "Failed
//! starts leave no authority; user data preserved; teardown cannot escape managed roots";
//! VM-P49).
//!
//! This is the file-touching half of the lifecycle supervisor's launch and cleanup
//! (`sandbox::lifecycle`, which touches no file and on which `files` does not depend). The
//! host selects a managed parent and opens it as a [`GrantedRoot`]. [`create_fresh_root`]
//! creates one root in it per sandbox identity and boot generation ([`SandboxBoot`]),
//! exclusively: a name that exists, of any kind, is refused and never reused, and so is a
//! boot the journal store already holds. In the root it creates the layout's directories,
//! each a volume with an explicit V05 class ([`VolumeRenewal`]) or a per-boot overlay or
//! scratch directory, every one relative to the handle of the directory just created, with
//! the identity read from the handle that created it. A write-ahead [`RootJournal`] records
//! each creation before it happens and that identity after; only when every object exists
//! are they registered with V05 ([`ManagedObjects`]), in a staged copy that replaces the
//! caller's registry once the committed journal is durable.
//!
//! What becomes of each volume is V05's renewal plan ([`plan_renewal`]) under the layout's
//! persistence profile, never a table of its own: a layout with a volume V05 refuses
//! (copied long-lived credentials in the strict profile, an environment kept without the
//! weaker claim acknowledged, application data without a validation or a backup) is
//! refused before anything is created. A volume whose bytes the plan carries past the boot
//! (retained into the next sandbox, or quarantined) is kept by teardown, a source workspace
//! as user source data; one it rebuilds from a pinned manifest or leaves to the external
//! broker is deleted with the overlay and scratch directories. Kept volumes are registered
//! with V05 as `RetainedVolume` and preserved ones as `UserSourceData`, the two kinds V05's
//! cleanup check itself refuses to delete.
//!
//! A launch that fails part way is undone at once by compensation, and one a crash
//! interrupted is undone from its journal by [`compensate_launch`]. Compensation removes, in
//! reverse order, exactly the empty directories the launch created, each only while it still
//! has the identity recorded for it; a directory whose creation was journaled but whose
//! identity never was is removed only if it is an empty real directory at its name (inside
//! the verified root, or at the boot's unique root name), since nothing can have entered it.
//! Nothing was registered, so a failed start leaves no authority, and whatever the launch
//! did not create is never touched. Teardown of a committed root is [`teardown`].
//!
//! [`teardown`]: super::teardown

use std::collections::BTreeMap;
use std::fmt;
use std::io;

use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};

use super::cleanup::{CleanupRefusal, ManagedObjectKind, ManagedObjects, ManagedRootId};
use super::file_id;
use super::fsutil::{self, HandleKind};
use super::names::{CollisionRefusal, EntryRole, GuestName, NameRefusal, NameSet};
use super::review::RootIdentity;
use super::root::{identity_of, GrantedRoot, Walk};
use super::root_journal::{
    ObjectState, RegistrationError, RootJournal, RootJournalFailure, RootJournalStore, RootPhase,
};
use super::volumes::{
    plan_renewal, MountDisposition, PersistenceProfile, RenewalPlan, RenewalRefusal,
    RenewalRequest, VolumeClass, VolumeRenewal,
};
use crate::foundation::ids::{Digest, DigestBuilder, ExecutionId, SandboxBootGeneration, TenantId};

/// Domain of a sandbox boot's root key.
pub const FRESH_ROOT_DOMAIN: &str = "yougori/sandbox/files/fresh-root/v1";
/// Domain of a layout volume's identity in V05's renewal plan.
pub const LAYOUT_VOLUME_DOMAIN: &str = "yougori/sandbox/files/layout-volume/v1";
/// Most directories one root layout creates.
pub const MAX_ROOT_ENTRIES: usize = 64;

/// The sandbox boot a fresh root belongs to (§6.1: "Separate stable sandbox identity from
/// boot generation"). `execution` and `tenant` mirror the lifecycle supervisor's
/// `SandboxIdentity` (`sandbox::lifecycle`), which `files` does not depend on; `boot` is
/// the CORE-04 boot generation, so every boot and restore gets a root of its own.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxBoot {
    pub execution: ExecutionId,
    pub tenant: TenantId,
    pub boot: SandboxBootGeneration,
}

impl SandboxBoot {
    /// The host-assigned key of this boot's root: a digest of the tenant, the execution and
    /// the boot generation, never of anything a guest supplied.
    pub fn key(&self) -> Digest {
        DigestBuilder::new(FRESH_ROOT_DOMAIN)
            .str(self.tenant.as_str())
            .str(self.execution.as_str())
            .u64(self.boot.get())
            .finish()
    }

    /// The managed root V05 registers this boot's root under.
    pub fn managed_root(&self) -> ManagedRootId {
        ManagedRootId::from_host(self.key())
    }

    /// The root's name in the managed parent: `sandbox-` and the key in hexadecimal, so two
    /// boots never share a name.
    pub fn root_name(&self) -> Result<GuestName, NameRefusal> {
        GuestName::parse(&format!("sandbox-{}", self.key().to_hex()))
    }
}

strict_tagged_enum! {
    /// One directory of a fresh root's layout.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum RootEntry (tag = "entry", wire = RootEntryWire, wire_name = "RootEntryWire") {
        /// A persisted volume with its explicit V05 class and renewal choice (§5.5).
        Volume { renewal: VolumeRenewal },
        /// Where the VM backend keeps the boot's writable overlay; never persisted.
        Overlay,
        /// The boot's scratch space; never persisted.
        Scratch,
    }
}

/// What teardown does with a layout directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub enum TeardownDisposition {
    /// Deleted, once V05 accepts its cleanup.
    Remove,
    /// Kept: V05's renewal plan carries its bytes past the boot.
    Keep { class: VolumeClass },
    /// User source data, which V05 refuses to clean up (§6.4).
    PreserveUserData,
}

impl TeardownDisposition {
    /// What teardown does with a volume V05 planned as `plan`: kept when its bytes go into
    /// the next sandbox or into quarantine, a source workspace as user source data, and
    /// deleted when it is rebuilt from a pinned manifest or not mounted (broker-owned).
    pub fn of_plan(plan: &RenewalPlan) -> Self {
        match plan.mount {
            MountDisposition::RebuiltIntoNextSandbox | MountDisposition::NotMounted => Self::Remove,
            MountDisposition::RetainedIntoNextSandbox | MountDisposition::QuarantineOnly
                if plan.class == VolumeClass::SourceWorkspace =>
            {
                Self::PreserveUserData
            }
            MountDisposition::RetainedIntoNextSandbox | MountDisposition::QuarantineOnly => {
                Self::Keep { class: plan.class }
            }
        }
    }

    /// The kind V05 registers `entry` with this disposition as. Kept entries are
    /// `RetainedVolume` and preserved ones `UserSourceData`, the two kinds V05's cleanup
    /// check itself refuses to delete; the rest are overlays and scratch directories, which
    /// it accepts.
    pub const fn object_kind(self, entry: RootEntry) -> ManagedObjectKind {
        match (self, entry) {
            (Self::Keep { .. }, _) => ManagedObjectKind::RetainedVolume,
            (Self::PreserveUserData, _) => ManagedObjectKind::UserSourceData,
            (Self::Remove, RootEntry::Overlay) => ManagedObjectKind::Overlay,
            (Self::Remove, RootEntry::Scratch | RootEntry::Volume { .. }) => {
                ManagedObjectKind::ScratchDirectory
            }
        }
    }
}

/// The identity a layout volume has in V05's renewal plan: a digest of its name, which is
/// unique in the layout.
pub(super) fn layout_volume_id(name: &GuestName) -> Digest {
    DigestBuilder::new(LAYOUT_VOLUME_DOMAIN)
        .str(name.as_str())
        .finish()
}

/// What teardown does with each of `entries`, in order, from V05's renewal plan of their
/// volumes under `profile` (`base_image` is the plan's base); V05's refusal of any volume
/// refuses them all. Overlay and scratch directories are deleted.
pub(super) fn plan_dispositions<'a>(
    base_image: Digest,
    profile: PersistenceProfile,
    entries: impl Iterator<Item = (&'a GuestName, RootEntry)> + Clone,
) -> Result<Vec<TeardownDisposition>, RenewalRefusal> {
    let volumes = entries
        .clone()
        .filter_map(|(name, entry)| match entry {
            RootEntry::Volume { renewal } => Some((layout_volume_id(name), renewal)),
            RootEntry::Overlay | RootEntry::Scratch => None,
        })
        .collect();
    let summary = plan_renewal(
        &RenewalRequest {
            base_image,
            keep_guest_root_changes: false,
            volumes,
            bytes_verified_identical: false,
        },
        profile,
    )?;
    let plans: BTreeMap<Digest, RenewalPlan> = summary
        .plans
        .into_iter()
        .map(|plan| (plan.volume, plan))
        .collect();
    Ok(entries
        .map(|(name, entry)| match entry {
            RootEntry::Overlay | RootEntry::Scratch => TeardownDisposition::Remove,
            // V05 plans every volume it does not refuse; one without a plan is kept.
            RootEntry::Volume { renewal } => plans.get(&layout_volume_id(name)).map_or(
                TeardownDisposition::Keep {
                    class: renewal.class(),
                },
                TeardownDisposition::of_plan,
            ),
        })
        .collect())
}

/// One directory to create in a fresh root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutEntry {
    /// A single component, created directly in the root.
    pub name: GuestName,
    pub entry: RootEntry,
}

/// The directories a fresh root starts with, in creation order, and what V05 plans their
/// volumes' renewal by.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootLayout {
    /// The pinned trusted base image the boot starts from, the base of V05's plan.
    pub base_image: Digest,
    /// The persistence profile V05 plans the volumes' renewal under.
    pub profile: PersistenceProfile,
    pub entries: Vec<LayoutEntry>,
}

impl RootLayout {
    /// What teardown does with each entry, in order, from V05's renewal plan; V05's refusal
    /// of a volume refuses the layout.
    pub fn dispositions(&self) -> Result<Vec<TeardownDisposition>, RenewalRefusal> {
        plan_dispositions(
            self.base_image,
            self.profile,
            self.entries.iter().map(|entry| (&entry.name, entry.entry)),
        )
    }
}

/// Why a layout's names were refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LayoutProblem {
    TooManyEntries {
        entries: usize,
        limit: usize,
    },
    /// Layout directories sit directly in the root.
    NotOneComponent {
        name: GuestName,
    },
    Collision(CollisionRefusal),
}

impl fmt::Display for LayoutProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyEntries { entries, limit } => {
                write!(
                    f,
                    "the layout has {entries} entries; at most {limit} are accepted"
                )
            }
            Self::NotOneComponent { name } => write!(f, "{name} is not a single component"),
            Self::Collision(collision) => write!(f, "{collision}"),
        }
    }
}

/// Checks a layout's names: at most [`MAX_ROOT_ENTRIES`], each a single component, none
/// twice and none differing from another only in case.
pub(super) fn check_entry_names<'a>(
    names: impl Iterator<Item = &'a GuestName>,
) -> Result<(), LayoutProblem> {
    let names: Vec<&GuestName> = names.collect();
    if names.len() > MAX_ROOT_ENTRIES {
        return Err(LayoutProblem::TooManyEntries {
            entries: names.len(),
            limit: MAX_ROOT_ENTRIES,
        });
    }
    let mut set = NameSet::new();
    for name in names {
        if name.component_count() != 1 {
            return Err(LayoutProblem::NotOneComponent { name: name.clone() });
        }
        set.insert(name, EntryRole::Directory)
            .map_err(LayoutProblem::Collision)?;
    }
    Ok(())
}

/// Why a launch did not start: nothing was created and nothing journaled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaunchRefusal {
    RootName(NameRefusal),
    Layout(LayoutProblem),
    /// V05's renewal plan refuses a volume of the layout in its profile.
    Renewal(RenewalRefusal),
    /// The store holds a journal for the boot already, or could not store one: a boot's
    /// root is never reused.
    JournalNotBegun(RootJournalFailure),
}

impl fmt::Display for LaunchRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootName(refusal) => write!(f, "the root name is refused: {refusal}"),
            Self::Layout(problem) => write!(f, "the layout is refused: {problem}"),
            Self::Renewal(refusal) => write!(f, "the layout is refused: {refusal}"),
            Self::JournalNotBegun(failure) => write!(f, "{failure}; the boot is not launched"),
        }
    }
}

/// Why a launch failed once creation began.
#[derive(Debug)]
pub enum LaunchCause {
    /// Something already has the root's name; it is never reused.
    RootExists,
    /// The directory `name` could not be created.
    CreateFailed {
        name: GuestName,
        error: io::Error,
    },
    /// What was created at `name` could not be confirmed, from its handle, as the new
    /// directory.
    Unconfirmed {
        name: GuestName,
        error: Option<io::Error>,
    },
    Journal(RootJournalFailure),
    Registration(RegistrationError),
}

impl fmt::Display for LaunchCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootExists => f.write_str("the root's name exists already and is never reused"),
            Self::CreateFailed { name, error } => {
                write!(f, "{name} could not be created: {:?}", error.kind())
            }
            Self::Unconfirmed { name, .. } => {
                write!(f, "{name} could not be confirmed as the new directory")
            }
            Self::Journal(failure) => write!(f, "{failure}"),
            Self::Registration(error) => write!(f, "registration failed: {error}"),
        }
    }
}

/// How a launch failed.
#[derive(Debug)]
pub enum LaunchFailure {
    /// Nothing was created and nothing journaled.
    NotStarted(LaunchRefusal),
    /// A step failed once creation began. Compensation removed what the launch created,
    /// and nothing was registered.
    RolledBack {
        cause: LaunchCause,
        compensation: CompensationReport,
    },
    /// Stopped as a crash would stop it (tests only): nothing was undone, and the journal
    /// last persisted is what [`compensate_launch`] reads.
    Interrupted,
}

impl fmt::Display for LaunchFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotStarted(refusal) => write!(f, "{refusal}"),
            Self::RolledBack { cause, .. } => write!(f, "the launch was rolled back: {cause}"),
            Self::Interrupted => f.write_str("the launch was interrupted"),
        }
    }
}

impl std::error::Error for LaunchFailure {}

/// What compensation did with one object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CompensationOutcome {
    /// Removed: the empty directory the launch created, with its recorded identity.
    Removed,
    /// Removed: an empty real directory at the name of a creation whose identity was never
    /// recorded.
    RemovedUnconfirmed,
    /// Its identity was recorded, and nothing has its name any more.
    AlreadyGone,
    /// It was never created.
    NeverCreated,
    /// Its name, or the root holding it, names another object; nothing was touched.
    Changed,
    /// Something entered it; it was left.
    NotEmpty,
    Failed {
        detail: String,
    },
}

impl CompensationOutcome {
    /// Whether nothing the launch created is left for this object.
    pub const fn is_complete(&self) -> bool {
        matches!(
            self,
            Self::Removed | Self::RemovedUnconfirmed | Self::AlreadyGone | Self::NeverCreated
        )
    }
}

/// One object compensation handled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CompensatedObject {
    pub name: GuestName,
    pub outcome: CompensationOutcome,
}

/// What undoing a launch did, in the order it was done: entries last created first, the
/// root last.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CompensationReport {
    pub objects: Vec<CompensatedObject>,
    /// Whether every journal write succeeded. Removal goes on without one: removing what the
    /// launch created needs no record to be safe, and a later run observes again.
    pub journal_written: bool,
}

impl CompensationReport {
    /// Whether nothing the launch created is left.
    pub fn complete(&self) -> bool {
        self.objects
            .iter()
            .all(|object| object.outcome.is_complete())
    }
}

/// Why compensation did not run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompensationError {
    /// The launch committed; a committed root is torn down instead.
    Committed,
    /// The managed parent is not the directory the root was created in.
    Refused(CleanupRefusal),
}

impl fmt::Display for CompensationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Committed => f.write_str("the launch committed; tear the root down instead"),
            Self::Refused(refusal) => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for CompensationError {}

/// Creates the fresh root of `boot` in the opened managed parent, with `layout`'s
/// directories, journaling each step in `store`, and registers every object in `registry`
/// once all exist. On failure what was created is removed again and `registry` is
/// unchanged. Returns the committed journal, which teardown takes.
pub fn create_fresh_root<J: RootJournalStore>(
    parent: &GrantedRoot,
    boot: &SandboxBoot,
    layout: &RootLayout,
    registry: &mut ManagedObjects,
    store: &mut J,
) -> Result<RootJournal, LaunchFailure> {
    create_fresh_root_with(parent, boot, layout, registry, store, &mut || true)
}

/// [`create_fresh_root`], calling `after_step` after every journal write and every
/// creation; when it returns false the launch stops there as a crash would, undoing
/// nothing. The hook exists so tests can stop a launch at every step; production passes
/// one that always continues.
pub(super) fn create_fresh_root_with<J: RootJournalStore>(
    parent: &GrantedRoot,
    boot: &SandboxBoot,
    layout: &RootLayout,
    registry: &mut ManagedObjects,
    store: &mut J,
    after_step: &mut dyn FnMut() -> bool,
) -> Result<RootJournal, LaunchFailure> {
    let root_name = boot
        .root_name()
        .map_err(|refusal| LaunchFailure::NotStarted(LaunchRefusal::RootName(refusal)))?;
    check_entry_names(layout.entries.iter().map(|entry| &entry.name))
        .map_err(|problem| LaunchFailure::NotStarted(LaunchRefusal::Layout(problem)))?;
    layout
        .dispositions()
        .map_err(|refusal| LaunchFailure::NotStarted(LaunchRefusal::Renewal(refusal)))?;
    let mut journal = RootJournal::begin(boot.clone(), parent.identity(), root_name, layout);
    store
        .begin(&journal)
        .map_err(|failure| LaunchFailure::NotStarted(LaunchRefusal::JournalNotBegun(failure)))?;
    if let Err(stop) = build(parent, &mut journal, layout, store, after_step) {
        return Err(match stop {
            BuildStop::Interrupted => LaunchFailure::Interrupted,
            BuildStop::Failed(cause) => LaunchFailure::RolledBack {
                cause,
                compensation: compensate(parent, &mut journal, store),
            },
        });
    }
    // Registrations go into a staged copy, published only once the committed journal is
    // durable, so a failure here leaves the caller's registry as it was.
    let mut staged = registry.clone();
    let mut committed = journal.clone();
    let commit = committed
        .register(&mut staged)
        .map_err(LaunchCause::Registration)
        .and_then(|()| {
            committed.set_phase(RootPhase::Committed);
            store.persist(&committed).map_err(LaunchCause::Journal)
        });
    if let Err(cause) = commit {
        return Err(LaunchFailure::RolledBack {
            cause,
            compensation: compensate(parent, &mut journal, store),
        });
    }
    *registry = staged;
    Ok(committed)
}

/// Undoes a launch that never committed, from its journal: after a failure, or after a
/// crash with the journal read back from the store. Running it again is harmless and
/// reports what is already gone. Nothing is registered or unregistered. The name follows
/// CORE-04's launch `Compensation` steps, of which this is the file-touching kind.
pub fn compensate_launch<J: RootJournalStore>(
    parent: &GrantedRoot,
    journal: &mut RootJournal,
    store: &mut J,
) -> Result<CompensationReport, CompensationError> {
    if !journal.phase().is_compensable() {
        return Err(CompensationError::Committed);
    }
    if parent.identity() != journal.parent() {
        return Err(CompensationError::Refused(
            CleanupRefusal::RootIdentityChanged {
                root: journal.parent_root(),
            },
        ));
    }
    Ok(compensate(parent, journal, store))
}

enum BuildStop {
    Interrupted,
    Failed(LaunchCause),
}

fn step(after_step: &mut dyn FnMut() -> bool) -> Result<(), BuildStop> {
    if after_step() {
        Ok(())
    } else {
        Err(BuildStop::Interrupted)
    }
}

fn journaled<J: RootJournalStore>(store: &mut J, journal: &RootJournal) -> Result<(), BuildStop> {
    store
        .persist(journal)
        .map_err(|failure| BuildStop::Failed(LaunchCause::Journal(failure)))
}

/// Creates the root and the layout's directories, journaling each creation before and
/// after it.
fn build<J: RootJournalStore>(
    parent: &GrantedRoot,
    journal: &mut RootJournal,
    layout: &RootLayout,
    store: &mut J,
    after_step: &mut dyn FnMut() -> bool,
) -> Result<(), BuildStop> {
    // The journal begun in the store already says the root is being created.
    step(after_step)?;
    let root_name = journal.root_name().clone();
    let (root_dir, identity) = match make_directory(parent.dir(), &root_name, parent.volume()) {
        Ok(made) => made,
        Err(MakeError::NotMade(error)) => {
            journal.set_root(ObjectState::NotCreated);
            return Err(BuildStop::Failed(
                if error.kind() == io::ErrorKind::AlreadyExists {
                    LaunchCause::RootExists
                } else {
                    LaunchCause::CreateFailed {
                        name: root_name,
                        error,
                    }
                },
            ));
        }
        Err(MakeError::Unconfirmed(error)) => {
            return Err(BuildStop::Failed(LaunchCause::Unconfirmed {
                name: root_name,
                error,
            }))
        }
    };
    step(after_step)?;
    journal.set_root(ObjectState::Created { identity });
    // Beside it, the raw file identity recovery opens the root by.
    journal.set_root_raw_identity(file_id::recorded_identity(&root_dir, identity));
    journaled(store, journal)?;
    step(after_step)?;
    for LayoutEntry { name, entry } in &layout.entries {
        journal.push_entry(name.clone(), *entry);
        journaled(store, journal)?;
        step(after_step)?;
        match make_directory(&root_dir, name, parent.volume()) {
            Ok((_, identity)) => journal.set_last_entry(ObjectState::Created { identity }),
            Err(MakeError::NotMade(error)) => {
                journal.set_last_entry(ObjectState::NotCreated);
                return Err(BuildStop::Failed(LaunchCause::CreateFailed {
                    name: name.clone(),
                    error,
                }));
            }
            Err(MakeError::Unconfirmed(error)) => {
                return Err(BuildStop::Failed(LaunchCause::Unconfirmed {
                    name: name.clone(),
                    error,
                }))
            }
        }
        step(after_step)?;
        journaled(store, journal)?;
        step(after_step)?;
    }
    Ok(())
}

enum MakeError {
    /// The create failed, so nothing was made.
    NotMade(io::Error),
    /// The create succeeded, but the new directory could not be confirmed from its handle.
    Unconfirmed(Option<io::Error>),
}

/// Creates the directory `name` in `holder` exclusively, relative to `holder`'s handle,
/// and opens it as itself: it must be the directory created, on `volume`, and the name
/// must still name it. Returns its handle and the identity read from the creating handle.
fn make_directory(
    holder: &Dir,
    name: &GuestName,
    volume: u64,
) -> Result<(Dir, RootIdentity), MakeError> {
    let component = name.as_str();
    let created = fsutil::create_directory(holder, component).map_err(MakeError::NotMade)?;
    let unconfirmed = |error| MakeError::Unconfirmed(Some(error));
    let file = fsutil::open_entry(holder, component).map_err(unconfirmed)?;
    let info = fsutil::file_info(&file).map_err(unconfirmed)?;
    let confirmed = fsutil::confirm(holder, component, &info).map_err(unconfirmed)?;
    if created.kind != HandleKind::Directory
        || created.volume != volume
        || !info.is(&created)
        || !confirmed
    {
        return Err(MakeError::Unconfirmed(None));
    }
    Ok((fsutil::into_dir(file), identity_of(&created)))
}

/// What the managed parent holds at a sandbox root's name, read through its handles
/// without following anything.
pub(super) enum AtName {
    Absent,
    /// A real directory on the parent's volume, opened as itself.
    Directory {
        dir: Dir,
        identity: RootIdentity,
    },
    /// A link, a file, a device or a case alias.
    Other,
}

pub(super) fn observe_at(parent: &GrantedRoot, name: &GuestName) -> io::Result<AtName> {
    Ok(match parent.walk(name)? {
        Walk::Missing { .. } => AtName::Absent,
        Walk::Found(opened) if opened.info.kind == HandleKind::Directory => AtName::Directory {
            identity: identity_of(&opened.info),
            dir: fsutil::into_dir(opened.file),
        },
        Walk::Found(_) | Walk::Blocked { .. } => AtName::Other,
    })
}

/// Removes, in reverse creation order, the empty directories the launch created, then
/// marks the journal compensated when nothing it created is left.
fn compensate<J: RootJournalStore>(
    parent: &GrantedRoot,
    journal: &mut RootJournal,
    store: &mut J,
) -> CompensationReport {
    journal.set_phase(RootPhase::Compensating);
    let mut journal_written = store.persist(journal).is_ok();
    let root_name = journal.root_name().clone();
    let root = journal.root();
    let volume = parent.volume();
    // The root as it is now; nothing inside a root that is not the one created is touched.
    let mut root_dir = None;
    let mut root_absent = false;
    let mut root_failure = None;
    match observe_at(parent, &root_name) {
        Ok(AtName::Directory { dir, identity }) if root.identity() == Some(identity) => {
            root_dir = Some(dir);
        }
        Ok(AtName::Absent) => root_absent = true,
        Ok(_) => {}
        Err(error) => root_failure = Some(format!("{:?}", error.kind())),
    }
    let mut objects = Vec::with_capacity(journal.entries().len().saturating_add(1));
    for entry in journal.entries().iter().rev() {
        let outcome = match (&root_dir, entry.state) {
            (_, ObjectState::NotCreated) => CompensationOutcome::NeverCreated,
            (Some(dir), state) => remove_empty(dir, &entry.name, state.identity(), volume),
            (None, _) if root_absent => CompensationOutcome::AlreadyGone,
            (None, _) => match &root_failure {
                Some(detail) => CompensationOutcome::Failed {
                    detail: detail.clone(),
                },
                None => CompensationOutcome::Changed,
            },
        };
        objects.push(CompensatedObject {
            name: entry.name.clone(),
            outcome,
        });
    }
    // Every handle to the root is closed before it is removed.
    drop(root_dir);
    let root_outcome = match root {
        ObjectState::NotCreated => CompensationOutcome::NeverCreated,
        state => remove_empty(parent.dir(), &root_name, state.identity(), volume),
    };
    objects.push(CompensatedObject {
        name: root_name,
        outcome: root_outcome,
    });
    let mut report = CompensationReport {
        objects,
        journal_written,
    };
    if report.complete() {
        journal.set_phase(RootPhase::Compensated);
        journal_written &= store.persist(journal).is_ok();
        report.journal_written = journal_written;
    }
    report
}

/// Removes the empty directory `name` of `holder` if it is a real directory on `volume`
/// with the identity `expected`, or, with no recorded identity, any empty real directory
/// there.
fn remove_empty(
    holder: &Dir,
    name: &GuestName,
    expected: Option<RootIdentity>,
    volume: u64,
) -> CompensationOutcome {
    try_remove_empty(holder, name.as_str(), expected, volume).unwrap_or_else(|error| {
        CompensationOutcome::Failed {
            detail: format!("{:?}", error.kind()),
        }
    })
}

fn try_remove_empty(
    holder: &Dir,
    name: &str,
    expected: Option<RootIdentity>,
    volume: u64,
) -> io::Result<CompensationOutcome> {
    let info = match fsutil::entry_info(holder, name) {
        Ok(info) => info,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(if expected.is_some() {
                CompensationOutcome::AlreadyGone
            } else {
                CompensationOutcome::NeverCreated
            })
        }
        Err(error) => return Err(error),
    };
    let ours = expected.is_none_or(|identity| identity_of(&info) == identity);
    if info.kind != HandleKind::Directory || info.volume != volume || !ours {
        return Ok(CompensationOutcome::Changed);
    }
    let file = fsutil::open_entry(holder, name)?;
    let opened = fsutil::file_info(&file)?;
    if !opened.is(&info) || !fsutil::confirm(holder, name, &opened)? {
        return Ok(CompensationOutcome::Changed);
    }
    let dir = fsutil::into_dir(file);
    let empty = is_empty(&dir)?;
    drop(dir);
    if !empty {
        return Ok(CompensationOutcome::NotEmpty);
    }
    Ok(match fsutil::remove_host_owned(holder, name, &opened)? {
        true if expected.is_some() => CompensationOutcome::Removed,
        true => CompensationOutcome::RemovedUnconfirmed,
        false => CompensationOutcome::Changed,
    })
}

/// Whether `dir`'s own listing holds no entry (it never holds `.` or `..`).
fn is_empty(dir: &Dir) -> io::Result<bool> {
    match fsutil::read_directory(dir)?.next() {
        Some(entry) => entry.map(|_| false),
        None => Ok(true),
    }
}
