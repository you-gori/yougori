//! The write-ahead journal of one sandbox boot's fresh root (VM part §6.1: "Every
//! transition is idempotent and records its generation ... Recovery reconciles actual VM
//! objects and resources rather than trusting old PID numbers"; §6.4; VM-W24; VM-P49).
//!
//! The journal is written before every filesystem step that creates a managed object and
//! after each one, and through teardown after each object it finishes, so after a crash the
//! host knows exactly which objects it created, by the identity read from each one's handle,
//! which creation may have been under way, and how far a teardown came. A launch that never
//! committed is undone from it ([`compensate_launch`]), a committed root is torn down from
//! it ([`teardown`]), and the registrations a restarted supervisor lost are restored from it
//! ([`RootJournal::restore_registrations`]). It holds the layout's base image and
//! persistence profile, so what teardown keeps is planned by V05 again from the journal
//! alone, and the host process of each VM started on the committed root
//! ([`RootJournal::record_vm_process`]), so teardown after a restart still waits for the
//! host's evidence that each ended ([`super::vm_processes`]). It is read back strictly:
//! unknown fields, a root name that is not the boot's, entry names that are not single
//! components or collide, object states that do not fit their order or the phase, volumes
//! V05's renewal plan refuses, and VM processes of another boot, journaled twice or before
//! the commit are refused.
//!
//! Beside the root's identity it holds, where the volume gives one, the root's raw file
//! identity ([`RawFileIdentity`]), by which recovery opens the root when its name holds
//! something else ([`recover_teardown`]). A journal without it still reads, and recovery then
//! refuses; one whose raw identity does not give the root's recorded identity is refused.
//!
//! [`compensate_launch`]: super::compensate_launch
//! [`teardown`]: super::teardown
//! [`recover_teardown`]: super::recover_teardown

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::cleanup::{
    CleanupRefusal, ManagedObjectKind, ManagedObjects, ManagedProcess, ManagedRootId, ObjectHandle,
};
use super::file_id::RawFileIdentity;
use super::fresh_root::{
    check_entry_names, plan_dispositions, LayoutProblem, RootEntry, RootLayout, SandboxBoot,
    TeardownDisposition,
};
use super::names::GuestName;
use super::review::RootIdentity;
use super::teardown::{FinishedObject, TeardownOutcome};
use super::vm_processes::{check_journalable, VmProcessProblem, VmProcessRecordError};
use super::volumes::{PersistenceProfile, RenewalRefusal};
use crate::foundation::ids::Digest;
use crate::foundation::process::ProcessIdentity;

strict_tagged_enum! {
    /// Where the creation of one managed object stands.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ObjectState (tag = "state", wire = ObjectStateWire, wire_name = "ObjectStateWire") {
        /// Its creation was journaled and may have happened; no identity was recorded.
        Creating,
        /// Its creation failed; nothing was made.
        NotCreated,
        /// Created, with the identity read from its handle.
        Created { identity: RootIdentity },
        /// Created and registered with V05 under `handle`.
        Registered { identity: RootIdentity, handle: ObjectHandle },
    }
}

impl ObjectState {
    /// The identity read from the object's handle, once one was recorded.
    pub const fn identity(self) -> Option<RootIdentity> {
        match self {
            Self::Created { identity } | Self::Registered { identity, .. } => Some(identity),
            Self::Creating | Self::NotCreated => None,
        }
    }

    /// The V05 handle, once registered.
    pub const fn handle(self) -> Option<ObjectHandle> {
        match self {
            Self::Registered { handle, .. } => Some(handle),
            _ => None,
        }
    }

    const fn is_registered(self) -> bool {
        matches!(self, Self::Registered { .. })
    }

    const fn is_created(self) -> bool {
        matches!(self, Self::Created { .. } | Self::Registered { .. })
    }
}

strict_tagged_enum! {
    /// Where a fresh root stands in its life (the file-touching steps of the lifecycle's
    /// launch transaction and cleanup, VM part §6.1).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum RootPhase (tag = "phase", wire = RootPhaseWire, wire_name = "RootPhaseWire") {
        /// Objects are being created; nothing is registered yet.
        Creating,
        /// The launch failed or was interrupted, and what it created is being removed.
        Compensating,
        /// Everything the launch created was removed again; nothing was registered.
        Compensated,
        /// Every object was created and registered.
        Committed,
        /// Teardown started (the lifecycle's `cleanup_pending`); `finished` holds each
        /// object it finished, first outcome kept.
        TearingDown { finished: Vec<FinishedObject> },
        /// Teardown finished: every object is gone, kept or preserved.
        TornDown { finished: Vec<FinishedObject> },
    }
}

impl RootPhase {
    /// A phase of a launch that never committed, which compensation undoes.
    pub const fn is_compensable(&self) -> bool {
        matches!(
            self,
            Self::Creating | Self::Compensating | Self::Compensated
        )
    }

    /// A phase of a committed root, which teardown removes.
    pub const fn is_committed(&self) -> bool {
        matches!(
            self,
            Self::Committed | Self::TearingDown { .. } | Self::TornDown { .. }
        )
    }

    /// What teardown finished so far.
    pub fn finished(&self) -> &[FinishedObject] {
        match self {
            Self::TearingDown { finished } | Self::TornDown { finished } => finished,
            _ => &[],
        }
    }
}

/// One object of the layout, as journaled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootJournalEntry {
    /// A single component, directly in the sandbox root.
    pub name: GuestName,
    pub entry: RootEntry,
    pub state: ObjectState,
}

/// Why a journal was refused on reading.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RootJournalError {
    /// The root name is not the one the boot derives.
    RootNameMismatch,
    Layout(LayoutProblem),
    /// An object is journaled before the one that must precede it was created: an entry
    /// before the root, or after an entry whose creation did not complete.
    OutOfOrder,
    /// An object's state does not fit the phase: a registration before commit, or an
    /// unregistered object after it.
    PhaseMismatch,
    /// Teardown lists an object the journal does not hold, or one object twice.
    UnknownFinished {
        name: GuestName,
    },
    /// V05's renewal plan refuses a volume in the journal's profile.
    Renewal(RenewalRefusal),
    /// A VM host process does not fit the journal.
    VmProcess {
        identity: ProcessIdentity,
        problem: VmProcessProblem,
    },
    /// The root's raw file identity does not give the identity recorded for the root, or is
    /// recorded for a root with no identity.
    RawIdentityMismatch,
}

impl fmt::Display for RootJournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootNameMismatch => f.write_str("the root name is not the boot's"),
            Self::Layout(problem) => write!(f, "{problem}"),
            Self::OutOfOrder => f.write_str("an object is journaled out of creation order"),
            Self::PhaseMismatch => f.write_str("an object's state does not fit the phase"),
            Self::UnknownFinished { name } => {
                write!(
                    f,
                    "teardown lists {name}, which the journal does not hold once"
                )
            }
            Self::Renewal(refusal) => write!(f, "{refusal}"),
            Self::VmProcess { identity, problem } => write!(f, "{identity}: {problem}"),
            Self::RawIdentityMismatch => {
                f.write_str("the root's raw file identity does not give its recorded identity")
            }
        }
    }
}

impl std::error::Error for RootJournalError {}

/// Why registrations could not be made from a journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistrationError {
    /// Only a committed root's journal is restored.
    NotCommitted,
    /// The object's identity was never recorded.
    Unconfirmed {
        name: GuestName,
    },
    /// V05's renewal plan refuses a volume, so no kind can be chosen for it.
    Renewal(RenewalRefusal),
    Refused(CleanupRefusal),
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCommitted => f.write_str("the root never committed"),
            Self::Unconfirmed { name } => write!(f, "{name} has no recorded identity"),
            Self::Renewal(refusal) => write!(f, "{refusal}"),
            Self::Refused(refusal) => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for RegistrationError {}

/// The journal could not be written. A launch then stops creating, since it could not
/// record what it does, and teardown stops deleting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootJournalFailure;

impl fmt::Display for RootJournalFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the fresh-root journal could not be written")
    }
}

impl std::error::Error for RootJournalFailure {}

/// Where the journals are kept, one per sandbox boot.
pub trait RootJournalStore {
    /// Stores the first journal of `journal.boot()`, durably. A store already holding a
    /// journal for that boot refuses: a boot's root is never reused, and an earlier journal
    /// is never replaced by a new launch.
    fn begin(&mut self, journal: &RootJournal) -> Result<(), RootJournalFailure>;

    /// Replaces the boot's journal; returns only once it is durable.
    fn persist(&mut self, journal: &RootJournal) -> Result<(), RootJournalFailure>;
}

/// The write-ahead journal of one sandbox boot's fresh root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RootJournalWire")]
pub struct RootJournal {
    boot: SandboxBoot,
    /// The managed parent's identity when the root was created in it.
    parent: RootIdentity,
    /// The layout's base image and profile, which V05's renewal plan is made from.
    base_image: Digest,
    profile: PersistenceProfile,
    root_name: GuestName,
    root: ObjectState,
    /// The root's raw file identity, read from its handle beside `root`'s identity; absent
    /// in a journal written before it was recorded and where the volume gives none.
    #[serde(skip_serializing_if = "Option::is_none")]
    root_raw_identity: Option<RawFileIdentity>,
    entries: Vec<RootJournalEntry>,
    phase: RootPhase,
    /// The host process of each VM started on the committed root, in start order.
    vm_processes: Vec<ManagedProcess>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootJournalWire {
    boot: SandboxBoot,
    parent: RootIdentity,
    base_image: Digest,
    profile: PersistenceProfile,
    root_name: GuestName,
    root: ObjectState,
    #[serde(default)]
    root_raw_identity: Option<RawFileIdentity>,
    entries: Vec<RootJournalEntry>,
    phase: RootPhase,
    vm_processes: Vec<ManagedProcess>,
}

impl TryFrom<RootJournalWire> for RootJournal {
    type Error = RootJournalError;

    fn try_from(wire: RootJournalWire) -> Result<Self, Self::Error> {
        if wire.boot.root_name().ok().as_ref() != Some(&wire.root_name) {
            return Err(RootJournalError::RootNameMismatch);
        }
        check_entry_names(wire.entries.iter().map(|entry| &entry.name))
            .map_err(RootJournalError::Layout)?;
        if !wire.entries.is_empty() && !wire.root.is_created() {
            return Err(RootJournalError::OutOfOrder);
        }
        let incomplete_before_last = wire
            .entries
            .iter()
            .rev()
            .skip(1)
            .any(|entry| !entry.state.is_created());
        if incomplete_before_last {
            return Err(RootJournalError::OutOfOrder);
        }
        let mut states = std::iter::once(wire.root).chain(wire.entries.iter().map(|e| e.state));
        let fits = if wire.phase.is_committed() {
            states.all(ObjectState::is_registered)
        } else {
            !states.any(ObjectState::is_registered)
        };
        if !fits {
            return Err(RootJournalError::PhaseMismatch);
        }
        let mut seen = BTreeSet::new();
        for finished in wire.phase.finished() {
            let known = finished.name == wire.root_name
                || wire.entries.iter().any(|entry| entry.name == finished.name);
            if !known || !seen.insert(&finished.name) {
                return Err(RootJournalError::UnknownFinished {
                    name: finished.name.clone(),
                });
            }
        }
        plan_dispositions(
            wire.base_image,
            wire.profile,
            wire.entries.iter().map(|entry| (&entry.name, entry.entry)),
        )
        .map_err(RootJournalError::Renewal)?;
        for (index, process) in wire.vm_processes.iter().enumerate() {
            let problem = if wire.phase.is_committed() {
                check_journalable(
                    process,
                    &wire.boot.execution,
                    wire.boot.boot,
                    &wire.vm_processes[..index],
                )
                .err()
            } else {
                Some(VmProcessProblem::NotLaunchable)
            };
            if let Some(problem) = problem {
                return Err(RootJournalError::VmProcess {
                    identity: process.identity,
                    problem,
                });
            }
        }
        if let Some(raw) = &wire.root_raw_identity {
            if wire.root.identity() != Some(raw.identity()) {
                return Err(RootJournalError::RawIdentityMismatch);
            }
        }
        Ok(Self {
            boot: wire.boot,
            parent: wire.parent,
            base_image: wire.base_image,
            profile: wire.profile,
            root_name: wire.root_name,
            root: wire.root,
            root_raw_identity: wire.root_raw_identity,
            entries: wire.entries,
            phase: wire.phase,
            vm_processes: wire.vm_processes,
        })
    }
}

impl RootJournal {
    /// The journal of a launch about to create `root_name` for `boot` in the managed parent
    /// whose identity is `parent`, from `layout`, whose volumes V05 accepted.
    pub(super) fn begin(
        boot: SandboxBoot,
        parent: RootIdentity,
        root_name: GuestName,
        layout: &RootLayout,
    ) -> Self {
        Self {
            boot,
            parent,
            base_image: layout.base_image,
            profile: layout.profile,
            root_name,
            root: ObjectState::Creating,
            root_raw_identity: None,
            entries: Vec::new(),
            phase: RootPhase::Creating,
            vm_processes: Vec::new(),
        }
    }

    pub fn boot(&self) -> &SandboxBoot {
        &self.boot
    }

    /// The managed parent's identity when the root was created in it.
    pub const fn parent(&self) -> RootIdentity {
        self.parent
    }

    /// The managed root V05 registers the managed parent under.
    pub const fn parent_root(&self) -> ManagedRootId {
        ManagedRootId::from_host(self.parent.digest())
    }

    /// The sandbox root's name in the managed parent.
    pub fn root_name(&self) -> &GuestName {
        &self.root_name
    }

    pub const fn root(&self) -> ObjectState {
        self.root
    }

    /// The sandbox root's raw file identity, when one was recorded; it gives the root's
    /// recorded identity.
    pub const fn root_raw_identity(&self) -> Option<RawFileIdentity> {
        self.root_raw_identity
    }

    /// The layout's objects, in creation order.
    pub fn entries(&self) -> &[RootJournalEntry] {
        &self.entries
    }

    pub fn phase(&self) -> &RootPhase {
        &self.phase
    }

    /// The pinned base image of the layout.
    pub const fn base_image(&self) -> Digest {
        self.base_image
    }

    /// The persistence profile V05 plans the volumes' renewal under.
    pub const fn profile(&self) -> PersistenceProfile {
        self.profile
    }

    /// What teardown does with each entry, in order, from V05's renewal plan made again
    /// from the journal.
    pub fn dispositions(&self) -> Result<Vec<TeardownDisposition>, RenewalRefusal> {
        plan_dispositions(
            self.base_image,
            self.profile,
            self.entries.iter().map(|entry| (&entry.name, entry.entry)),
        )
    }

    /// The recorded identity of the sandbox root (`name` is its root name) or of the entry
    /// `name`, which a root the host opens on it later must have.
    pub fn identity_of(&self, name: &GuestName) -> Option<RootIdentity> {
        if name == &self.root_name {
            return self.root.identity();
        }
        self.entries
            .iter()
            .find(|entry| &entry.name == name)
            .and_then(|entry| entry.state.identity())
    }

    /// The host process of each VM started on the committed root, in start order.
    pub fn vm_processes(&self) -> &[ManagedProcess] {
        &self.vm_processes
    }

    /// Journals the host process of a VM the host just started on this committed root, as
    /// [`ManagedProcess::of`] read it from the handle, then registers it with V05 under the
    /// sandbox root. The journal is durable before the registration, so a restarted
    /// supervisor restores it and teardown waits for its end. Refused, with nothing
    /// journaled, for a root not committed or being torn down, for a process that is not a
    /// VM's host process of this boot, and for a process or VM journaled already.
    pub fn record_vm_process<J: RootJournalStore>(
        &mut self,
        registry: &mut ManagedObjects,
        store: &mut J,
        process: ManagedProcess,
    ) -> Result<ObjectHandle, VmProcessRecordError> {
        if self.phase != RootPhase::Committed {
            return Err(VmProcessRecordError::Problem(
                VmProcessProblem::NotLaunchable,
            ));
        }
        check_journalable(
            &process,
            &self.boot.execution,
            self.boot.boot,
            &self.vm_processes,
        )
        .map_err(VmProcessRecordError::Problem)?;
        self.vm_processes.push(process.clone());
        if let Err(failure) = store.persist(self) {
            self.vm_processes.pop();
            return Err(VmProcessRecordError::Journal(failure));
        }
        registry
            .register_vm_process(self.boot.managed_root(), process)
            .map_err(VmProcessRecordError::Refused)
    }

    /// Registers this committed root's managed roots and objects again in `registry`, as a
    /// restarted supervisor must before teardown, with the identities recorded at
    /// creation, and keeps the handles the registry hands out; the journaled VM host
    /// processes are registered again too. Nothing is registered when any identity is
    /// missing.
    pub fn restore_registrations(
        &mut self,
        registry: &mut ManagedObjects,
    ) -> Result<(), RegistrationError> {
        if !self.phase.is_committed() {
            return Err(RegistrationError::NotCommitted);
        }
        self.register(registry)
    }

    /// Registers the managed parent, the sandbox root and every object, the sandbox root
    /// itself as an object of the parent and the entries as objects of the sandbox root,
    /// each of the kind its disposition gives; every state becomes `Registered`.
    pub(super) fn register(
        &mut self,
        registry: &mut ManagedObjects,
    ) -> Result<(), RegistrationError> {
        let Some(root_identity) = self.root.identity() else {
            return Err(RegistrationError::Unconfirmed {
                name: self.root_name.clone(),
            });
        };
        let dispositions = self.dispositions().map_err(RegistrationError::Renewal)?;
        let mut identities = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let identity = entry
                .state
                .identity()
                .ok_or(RegistrationError::Unconfirmed {
                    name: entry.name.clone(),
                })?;
            identities.push(identity);
        }
        let parent_root = self.parent_root();
        let sandbox_root = self.boot.managed_root();
        registry.register_root(parent_root, self.parent.digest());
        registry.register_root(sandbox_root, root_identity.digest());
        let handle = registry
            .register_object(
                parent_root,
                ManagedObjectKind::ScratchDirectory,
                root_identity.digest(),
                None,
            )
            .map_err(RegistrationError::Refused)?;
        self.root = ObjectState::Registered {
            identity: root_identity,
            handle,
        };
        for ((entry, identity), disposition) in
            self.entries.iter_mut().zip(identities).zip(dispositions)
        {
            let handle = registry
                .register_object(
                    sandbox_root,
                    disposition.object_kind(entry.entry),
                    identity.digest(),
                    None,
                )
                .map_err(RegistrationError::Refused)?;
            entry.state = ObjectState::Registered { identity, handle };
        }
        for process in &self.vm_processes {
            registry
                .register_vm_process(sandbox_root, process.clone())
                .map_err(RegistrationError::Refused)?;
        }
        Ok(())
    }

    pub(super) fn set_root(&mut self, state: ObjectState) {
        self.root = state;
    }

    pub(super) fn set_root_raw_identity(&mut self, raw: Option<RawFileIdentity>) {
        self.root_raw_identity = raw;
    }

    /// Journals the creation of `name` as under way.
    pub(super) fn push_entry(&mut self, name: GuestName, entry: RootEntry) {
        self.entries.push(RootJournalEntry {
            name,
            entry,
            state: ObjectState::Creating,
        });
    }

    /// Sets the state of the last entry.
    pub(super) fn set_last_entry(&mut self, state: ObjectState) {
        if let Some(last) = self.entries.last_mut() {
            last.state = state;
        }
    }

    pub(super) fn set_phase(&mut self, phase: RootPhase) {
        self.phase = phase;
    }

    /// Enters teardown, keeping what an earlier teardown finished.
    pub(super) fn enter_teardown(&mut self) {
        let finished = self.phase.finished().to_vec();
        self.phase = RootPhase::TearingDown { finished };
    }

    /// Records that teardown finished `name` with `outcome`: a finished outcome is kept once
    /// recorded, and an unfinished one is replaced by the next. Only while tearing down.
    pub(super) fn record(&mut self, name: &GuestName, outcome: TeardownOutcome) {
        let RootPhase::TearingDown { finished } = &mut self.phase else {
            return;
        };
        match finished.iter_mut().find(|done| &done.name == name) {
            Some(done) if done.outcome.is_finished() => {}
            Some(done) => done.outcome = outcome,
            None => finished.push(FinishedObject {
                name: name.clone(),
                outcome,
            }),
        }
    }

    /// Whether teardown finished every object.
    pub(super) fn teardown_finished(&self) -> bool {
        let finished = self.phase.finished();
        std::iter::once(&self.root_name)
            .chain(self.entries.iter().map(|entry| &entry.name))
            .all(|name| {
                finished
                    .iter()
                    .any(|done| &done.name == name && done.outcome.is_finished())
            })
    }

    /// Ends teardown once every object is finished.
    pub(super) fn finish_teardown(&mut self) {
        if let RootPhase::TearingDown { finished } = &mut self.phase {
            let finished = std::mem::take(finished);
            self.phase = RootPhase::TornDown { finished };
        }
    }
}
