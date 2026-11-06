//! The durable authority store (S2 CORE-04; VM part §6.1 "a single durable state machine";
//! §6.2 "Persist enough state to prevent clock rollback or snapshot restore from reviving
//! expired rights"; §6.3 step 1; VM-W29; docs/combined-plan-leftover-tasks.md S04, the
//! remainder of "Durable lifecycle authority": store the state, then seal and store the
//! floor separately, then confirm, passing the revocation stream's last sequence).
//!
//! An [`AuthorityStore`] keeps one coordination authority's persisted state and its
//! [`AuthorityFloor`] in one directory of the caller's choosing, as two files, `state.json`
//! and `floor.json`, and implements the floor's protocol (floor.rs):
//!
//! - Persist ([`AuthorityStore::persist`]): the holder's state ([`Coordinator::persist`], or
//!   a record that holds it, such as a supervisor's; [`AuthorityHolder`]) and the receiver's
//!   replay record are taken, and the next floor is sealed from them with the durable
//!   revocation stream's last sequence. The state is stored with the stream's end cursor,
//!   then the floor apart from it, and only then are the holder and the receiver
//!   confirmed. A refused seal stores and confirms nothing; a failed write confirms
//!   nothing. Either is a typed [`StoreError`].
//! - Restore ([`AuthorityStore::load`], then [`StoreRestore::recover`]): both files are read
//!   strictly; the revocation stream is replayed from the cursor stored with the state and
//!   adopted ([`PersistedState::adopt_revocations`]); the state is raised to the floor
//!   ([`AuthorityFloor::restore`]); the coordinator recovers ([`Coordinator::recover`]);
//!   and the sandboxes below the floor end ([`Coordinator::end_stale`]), as do those whose
//!   revocation the state predates ([`Coordinator::complete_revocations`]). What the floor
//!   raised is a [`RecoveryEvent::FloorRaised`] on the recovery stream
//!   ([`StoreRecovery::publish`]).
//!
//! The state records the sequence of the floor sealed from it, so every combination of the
//! two files is decided:
//!
//! - Neither file: nothing was persisted; a fresh start ([`StoreLoad::Fresh`]).
//! - The state and the floor sealed from it: the newest durable state, which recovers as it
//!   is ([`StateStanding::Sealed`]).
//! - A state one floor ahead of the stored floor, or the first state with no floor yet: the
//!   process stopped between the two stores. The state is above the floor and recovers as
//!   it is; the standing reports it ([`StateStanding::Unsealed`]), and the next persist
//!   seals the floor it names.
//! - A state behind the stored floor: a restored backup or VM snapshot of the engine's data,
//!   or an older `state.json` copied back. It is raised to the floor, never trusted, and
//!   its sandboxes below the floor end after recovery ([`StateStanding::Older`]).
//! - A floor without a state: the state was removed or rolled back past its first store.
//!   Refused ([`StoreError::StateMissing`]).
//! - A state that names a floor the directory lacks, or a floor more than one behind it:
//!   the floor was removed or rolled back. Refused ([`StoreError::FloorMissing`],
//!   [`StoreError::FloorBehindState`]).
//! - Another authority's floor or state: refused ([`FloorRefusal::ForeignFloor`],
//!   [`StoreError::ForeignState`]).
//! - A revocation stream behind the floor: refused ([`FloorRefusal::RevocationLogBehind`]);
//!   one that no longer continues the cursor stored with the state, replaced or cut back,
//!   is refused as well ([`StoreError::Revocations`]): revocations it held may be missing.
//! - A torn, edited or foreign file: refused and named ([`StoreError::Unreadable`]).
//!
//! Each file is a header line, a JSON object naming the file, its format and the digest of
//! the body, then the body, JSON read strictly. A torn file, an edited one, the other file
//! under this one's name and another format are each refused with the file named, and
//! nothing is ever replaced silently. Writes go through the durable streams' atomic write
//! (`events::owner`), so after a crash each file holds its old or its new content.
//!
//! One writer per directory: the store holds the directory's [`StreamOwner`], the lock every
//! durable stream uses, so a second store on the directory, in this process or another, is
//! refused. The directory is the store's alone; a durable stream's directory is not one.
//!
//! Limits: the digest guards against tearing and accidental edits, not against someone who
//! rewrites a file with a matching digest; and, as floor.rs says, rolling back the state,
//! the floor and the revocation stream together is caught only by a monotonic counter
//! outside the host's storage.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::capacity::CapacityPort;
use super::coordinator::{Compensation, CoordinationError, Coordinator};
use super::floor::{AuthorityFloor, FloorRefusal, FloorRegression, FloorRestore, StaleEnded};
use super::port::SandboxPort;
use super::recovery::{PersistedState, RecoveryFailure, RecoveryReport};
use super::recovery_events::{
    publish_recovery_events, RecoveryEvent, RecoveryLog, RecoveryPublished,
};
use super::replay::{ReplayRecord, ReplayState};
use super::scope::AuthorityIssuer;
use crate::foundation::events::{
    write_atomic, EventSequence, LogCursor, LogError, OwnerError, ProducerId, RebuiltRevocations,
    RevocationLog, RevocationReplay, StreamOwner, Takeover,
};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{Clock, Digest, DigestBuilder, ExecutionId, OperationId};

/// The persisted state and what it was stored with.
const STATE_FILE: &str = "state.json";
/// The floor sealed from the latest state stored, kept apart from it.
const FLOOR_FILE: &str = "floor.json";
/// The format of both files; each header carries it.
const FORMAT_VERSION: u32 = 1;
/// Domain of a file body's digest, which binds the file's kind and format too.
const BODY_DOMAIN: &str = "yougori/coordination/authority-store/v1";

/// What an [`AuthorityStore`] keeps as the state: the coordinator's persisted state, alone
/// or inside a record that holds it, such as a supervisor's.
pub trait AuthorityState: Serialize + DeserializeOwned {
    /// The coordinator's persisted state inside it.
    fn coordination(&self) -> &PersistedState;

    /// The same, for a restore to adopt revocations into and raise to the floor.
    fn coordination_mut(&mut self) -> &mut PersistedState;
}

impl AuthorityState for PersistedState {
    fn coordination(&self) -> &PersistedState {
        self
    }

    fn coordination_mut(&mut self) -> &mut PersistedState {
        self
    }
}

/// What persists an [`AuthorityState`] and is confirmed once it is durable: the coordinator
/// itself, or a holder of one that persists more with it.
pub trait AuthorityHolder {
    type State: AuthorityState;

    /// What to store now ([`Coordinator::persist`]).
    fn persist(&self) -> Self::State;

    /// `state`, and the floor sealed from it, are stored durably
    /// ([`Coordinator::confirm_persisted`]).
    fn confirm_persisted(&mut self, state: &Self::State);
}

impl<C: Clock, P: CapacityPort> AuthorityHolder for Coordinator<C, P> {
    type State = PersistedState;

    fn persist(&self) -> PersistedState {
        Coordinator::persist(self)
    }

    fn confirm_persisted(&mut self, state: &PersistedState) {
        Coordinator::confirm_persisted(self, state);
    }
}

/// One of the store's two files.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreFile {
    /// `state.json`: the persisted state, the receiver's replay record and the revocation
    /// stream's cursor.
    State,
    /// `floor.json`: the floor sealed from the latest state stored.
    Floor,
}

impl StoreFile {
    /// The file's name in the store's directory.
    pub fn name(self) -> &'static str {
        match self {
            Self::State => STATE_FILE,
            Self::Floor => FLOOR_FILE,
        }
    }

    fn tag(self) -> &'static str {
        match self {
            Self::State => "state",
            Self::Floor => "floor",
        }
    }
}

impl fmt::Display for StoreFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the {} file", self.tag())
    }
}

/// Why a file cannot be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileProblem {
    /// The header line is missing or does not read as one: the file is torn or is no store
    /// file.
    Header { message: String },
    /// The store's other file is under this one's name.
    OtherFile { found: StoreFile },
    /// A format this build does not read.
    Format { found: u32 },
    /// The body does not match the header's digest: the file is torn or was edited.
    Digest,
    /// The body matches its digest but does not read as the record it should hold.
    Body { message: String },
}

impl fmt::Display for FileProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header { message } => write!(f, "its header cannot be read ({message})"),
            Self::OtherFile { found } => write!(f, "it is {found}"),
            Self::Format { found } => write!(
                f,
                "it has format {found}; this build reads format {FORMAT_VERSION}"
            ),
            Self::Digest => f.write_str("its body does not match its digest: torn or edited"),
            Self::Body { message } => write!(f, "its body cannot be read ({message})"),
        }
    }
}

/// Why the store refused. A refusal before a write leaves both files as they were; a failed
/// write confirms nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The directory's owner could not be taken: another store holds it, in this process
    /// or another one.
    Owner(OwnerError),
    /// A file could not be read or written.
    Io {
        file: StoreFile,
        action: &'static str,
        path: PathBuf,
        kind: io::ErrorKind,
        message: String,
    },
    /// A file cannot be used. It is left as it is, never replaced silently.
    Unreadable {
        file: StoreFile,
        path: PathBuf,
        problem: FileProblem,
    },
    /// A file could not be encoded; nothing was written.
    Encoding { file: StoreFile, message: String },
    /// The floor of sequence `floor` is stored but no state is: the state was removed or
    /// rolled back past its first store.
    StateMissing { floor: u64 },
    /// The state was sealed into floor `sealed_into`, but no floor is stored: it was
    /// removed.
    FloorMissing { sealed_into: u64 },
    /// The stored floor, `floor`, is more than one behind the floor the state was sealed
    /// into: it was rolled back or replaced.
    FloorBehindState { floor: u64, sealed_into: u64 },
    /// The state is `state`'s, not the authority's that opened the store.
    ForeignState { state: AuthorityIssuer },
    /// The floor refused the restore: it is another authority's, or the revocation stream
    /// is behind it.
    Floor(FloorRefusal),
    /// The seal was refused: the state is below the floor, which never moves back.
    Regression(FloorRegression),
    /// The revocation stream could not be replayed after the cursor stored with the state:
    /// it was replaced or cut back, so revocations it held may be missing, or it could not
    /// be read.
    Revocations(LogError),
    /// [`AuthorityStore::persist`] before [`AuthorityStore::load`]: the store stores nothing
    /// before it knows what its directory holds.
    NotLoaded,
}

impl StoreError {
    fn io(file: StoreFile, action: &'static str, path: &Path, error: &io::Error) -> Self {
        Self::Io {
            file,
            action,
            path: path.to_path_buf(),
            kind: error.kind(),
            message: error.to_string(),
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Owner(error) => write!(f, "the authority store is held: {error}"),
            Self::Io {
                file,
                action,
                path,
                message,
                ..
            } => write!(
                f,
                "could not {action} {file}, {}: {message}",
                path.display()
            ),
            Self::Unreadable {
                file,
                path,
                problem,
            } => write!(
                f,
                "{file}, {}, cannot be used: {problem}; it is left as it is",
                path.display()
            ),
            Self::Encoding { file, message } => {
                write!(f, "{file} could not be encoded: {message}")
            }
            Self::StateMissing { floor } => write!(
                f,
                "floor {floor} is stored but no state is: the state was removed or rolled back"
            ),
            Self::FloorMissing { sealed_into } => write!(
                f,
                "the state was sealed into floor {sealed_into}, but no floor is stored"
            ),
            Self::FloorBehindState { floor, sealed_into } => write!(
                f,
                "the stored floor {floor} is behind floor {sealed_into}, which the state was \
                 sealed into: the floor was rolled back or replaced"
            ),
            Self::ForeignState { state } => {
                write!(f, "the state is {state}'s, not the restarting authority's")
            }
            Self::Floor(refusal) => write!(f, "{refusal}"),
            Self::Regression(regression) => write!(f, "{regression}"),
            Self::Revocations(error) => write!(
                f,
                "the revocation stream does not continue the one the state was stored \
                 against: {error}"
            ),
            Self::NotLoaded => {
                f.write_str("the store's files must be loaded before anything is stored")
            }
        }
    }
}

impl std::error::Error for StoreError {}

/// How the stored state stood against the stored floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "standing", rename_all = "snake_case")]
pub enum StateStanding {
    /// The newest durable state: the stored floor was sealed from it.
    Sealed,
    /// The state was stored, but the floor sealed from it was not: the process stopped
    /// between the two stores. `floor` is the stored floor's sequence, 0 for none. The
    /// state is above it and recovers as it is.
    Unsealed { floor: u64 },
    /// An older state than the stored floor's, sealed into floor `sealed_into`: a restored
    /// backup or VM snapshot, or an older file copied back. It is raised to floor `floor`.
    Older { sealed_into: u64, floor: u64 },
}

/// What [`AuthorityStore::persist`] stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorePersisted {
    /// The sequence of the floor sealed and stored.
    pub floor: u64,
    /// The revocation stream's last sequence, which the floor recorded.
    pub revocation_log: Option<EventSequence>,
}

/// What a restore found and did before recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreRestore {
    pub standing: StateStanding,
    /// The sequence of the floor the state was raised to, 0 when none was stored.
    pub floor: u64,
    /// The revocations from the stream that the state lacked, now adopted into it.
    pub rebuilt: RebuiltRevocations,
    /// What the floor raised, the executions whose records were below it, and the replay
    /// record to restore the receiver from ([`ReplayState::restore`]).
    pub restore: FloorRestore,
}

impl StoreRestore {
    /// The receiver's replay record to restore from: the one stored with the state, raised
    /// to the floor's.
    pub fn replay(&self) -> &ReplayRecord {
        &self.restore.replay
    }

    /// The events of a restart that recovered as `report` says: the revocations adopted,
    /// what the floor raised when it raised anything, then `report`'s events
    /// ([`RecoveryReport::events`]), the last of them the closing summary.
    pub fn events(&self, report: &RecoveryReport) -> Vec<RecoveryEvent> {
        std::iter::once(RecoveryEvent::adopted(&self.rebuilt))
            .chain(RecoveryEvent::raised(self.floor, &self.restore))
            .chain(report.events())
            .collect()
    }

    /// Recovers the coordinator from `state`, the state [`AuthorityStore::load`] returned
    /// with this restore ([`Coordinator::recover`]), then ends each sandbox whose record
    /// was below the floor ([`Coordinator::end_stale`]) and each whose revocation the state
    /// predates ([`Coordinator::complete_revocations`]). On a failed recovery the capacity
    /// port comes back as [`Coordinator::recover`] returns it. The recovered coordinator
    /// hands out no lease id and no incarnation until its state is persisted again
    /// ([`AuthorityStore::persist`]).
    pub fn recover<C: Clock, P: CapacityPort>(
        self,
        state: PersistedState,
        clock: C,
        session: ClockSession,
        capacity: P,
        port: &mut dyn SandboxPort,
    ) -> Result<StoreRecovery<C, P>, RecoveryFailure<P>> {
        let (mut coordinator, report) =
            Coordinator::recover(state, clock, session, capacity, port)?;
        let stale_ended = coordinator.end_stale(&self.restore, port);
        let revocations_completed = coordinator.complete_revocations(&self.rebuilt, port);
        Ok(StoreRecovery {
            coordinator,
            report,
            restore: self,
            stale_ended,
            revocations_completed,
        })
    }
}

/// What [`AuthorityStore::load`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreLoad<S> {
    /// Neither file: nothing was persisted yet.
    Fresh,
    /// A state to recover from, with the revocations adopted and raised to the floor, and
    /// what the restore found and did.
    Restored { state: S, restore: StoreRestore },
}

/// A coordinator recovered through the store ([`StoreRestore::recover`]).
pub struct StoreRecovery<C: Clock, P: CapacityPort> {
    pub coordinator: Coordinator<C, P>,
    /// What recovery found and did.
    pub report: RecoveryReport,
    /// What the restore before it found and did.
    pub restore: StoreRestore,
    /// How ending each sandbox below the floor went.
    pub stale_ended: BTreeMap<ExecutionId, Result<StaleEnded, CoordinationError>>,
    /// How ending each sandbox whose revocation the state predates went.
    pub revocations_completed: BTreeMap<ExecutionId, Result<Vec<Compensation>, CoordinationError>>,
}

impl<C: Clock, P: CapacityPort> StoreRecovery<C, P> {
    /// Every event of the restart: the restore's and recovery's ([`StoreRestore::events`]),
    /// then how each revocation the state predates was completed.
    pub fn events(&self) -> Vec<RecoveryEvent> {
        let mut events = self.restore.events(&self.report);
        events.extend(
            self.revocations_completed
                .iter()
                .map(|(execution, ended)| RecoveryEvent::completed(execution, ended)),
        );
        events
    }

    /// Publishes [`StoreRecovery::events`] on the recovery stream `log` under `operation`,
    /// stamped on the recovered coordinator's clock. A refused event is reported; the
    /// recovery stands either way.
    pub fn publish(&self, operation: &OperationId, log: &mut RecoveryLog) -> RecoveryPublished {
        publish_recovery_events(
            log,
            operation,
            self.coordinator.monotonic_now(),
            self.events(),
        )
    }
}

/// The header line of a store file.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileHeader {
    file: StoreFile,
    format: u32,
    digest: Digest,
}

/// The body of `state.json`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredState<S> {
    /// The authority whose state it is.
    issuer: AuthorityIssuer,
    /// The sequence of the floor sealed from it.
    floor: u64,
    /// The receiver's replay record, persisted with the state.
    replay: ReplayRecord,
    /// The revocation stream's end when the state was taken; a restore replays after it.
    revocations: LogCursor,
    state: S,
}

/// One coordination authority's durable state and floor in one directory (S2 CORE-04; VM
/// part §6.1–§6.3). `S` is what it keeps as the state: the coordinator's persisted state,
/// or a record that holds it ([`AuthorityState`]).
#[derive(Debug)]
pub struct AuthorityStore<S = PersistedState> {
    owner: StreamOwner,
    issuer: AuthorityIssuer,
    /// The floor last stored or read; `None` before the first.
    floor: Option<AuthorityFloor>,
    /// Whether the directory's files were loaded.
    loaded: bool,
    state: PhantomData<fn() -> S>,
}

impl<S: AuthorityState> AuthorityStore<S> {
    /// Takes the store in `directory`, created if needed, for `issuer`, with `owner` as the
    /// directory's one writer (say `coordinator.authority`). Refused at once, without
    /// waiting, while another store holds the directory, in this process or another; the
    /// takeover says how the previous one left it. Nothing is read yet.
    pub fn open(
        directory: &Path,
        issuer: AuthorityIssuer,
        owner: ProducerId,
    ) -> Result<(Self, Takeover), StoreError> {
        let (owner, takeover) =
            StreamOwner::acquire(directory, owner).map_err(StoreError::Owner)?;
        let store = Self {
            owner,
            issuer,
            floor: None,
            loaded: false,
            state: PhantomData,
        };
        Ok((store, takeover))
    }

    /// The store's directory, resolved.
    pub fn directory(&self) -> &Path {
        self.owner.directory()
    }

    /// The authority whose state the store keeps.
    pub fn issuer(&self) -> AuthorityIssuer {
        self.issuer
    }

    /// The floor last stored or loaded.
    pub fn floor(&self) -> Option<&AuthorityFloor> {
        self.floor.as_ref()
    }

    /// Reads both files strictly at a restart and restores the state against the floor,
    /// with `revocations`, the durable revocation stream, replayed after the cursor stored
    /// with the state and adopted first. See the module documentation for each combination
    /// of the files. On `Ok` the store persists from the floor it read; on a refusal
    /// nothing changes and nothing can be persisted.
    pub fn load(&mut self, revocations: &RevocationLog) -> Result<StoreLoad<S>, StoreError> {
        let floor: Option<AuthorityFloor> = self.read(StoreFile::Floor)?;
        let Some(mut stored) = self.read::<StoredState<S>>(StoreFile::State)? else {
            if let Some(floor) = floor {
                return Err(StoreError::StateMissing {
                    floor: floor.sequence(),
                });
            }
            self.floor = None;
            self.loaded = true;
            return Ok(StoreLoad::Fresh);
        };
        if stored.issuer != self.issuer {
            return Err(StoreError::ForeignState {
                state: stored.issuer,
            });
        }
        let below = floor.as_ref().map_or(0, AuthorityFloor::sequence);
        let standing = if stored.floor == below {
            StateStanding::Sealed
        } else if below.checked_add(1) == Some(stored.floor) {
            StateStanding::Unsealed { floor: below }
        } else if stored.floor < below {
            StateStanding::Older {
                sealed_into: stored.floor,
                floor: below,
            }
        } else if floor.is_none() {
            return Err(StoreError::FloorMissing {
                sealed_into: stored.floor,
            });
        } else {
            return Err(StoreError::FloorBehindState {
                floor: below,
                sealed_into: stored.floor,
            });
        };
        // A stream that refuses the stored cursor was replaced or cut back. It is refused
        // after the floor has judged it, so a stream behind the floor is named as such.
        let (replay, moved) = match revocations.replay(&stored.revocations) {
            Ok(replay) => (replay, None),
            Err(LogError::Cursor(problem)) => (
                RevocationReplay::new(revocations.log().start()),
                Some(problem),
            ),
            Err(error) => return Err(StoreError::Revocations(error)),
        };
        let rebuilt = stored.state.coordination_mut().adopt_revocations(&replay);
        let empty;
        let against = match &floor {
            Some(floor) => floor,
            None => {
                empty = AuthorityFloor::new(self.issuer);
                &empty
            }
        };
        let restore = against
            .restore(
                self.issuer,
                stored.state.coordination_mut(),
                &stored.replay,
                revocations.log().last(),
            )
            .map_err(StoreError::Floor)?;
        if let Some(problem) = moved {
            return Err(StoreError::Revocations(LogError::Cursor(problem)));
        }
        self.floor = floor;
        self.loaded = true;
        Ok(StoreLoad::Restored {
            state: stored.state,
            restore: StoreRestore {
                standing,
                floor: below,
                rebuilt,
                restore,
            },
        })
    }

    /// Persists `holder`'s state with `receiver`'s replay record, when there is a receiver:
    /// seals the next floor from them with `revocations`' last sequence, stores the state
    /// with the stream's end cursor, then the floor apart from it, and only then confirms
    /// the holder and the receiver. A refused seal stores nothing; a failed write confirms
    /// nothing, and a retry seals from the same floor again. Refused before
    /// [`AuthorityStore::load`].
    pub fn persist<H: AuthorityHolder<State = S>>(
        &mut self,
        holder: &mut H,
        receiver: Option<&mut ReplayState>,
        revocations: &RevocationLog,
    ) -> Result<StorePersisted, StoreError> {
        if !self.loaded {
            return Err(StoreError::NotLoaded);
        }
        let state = holder.persist();
        let record = receiver
            .as_ref()
            .map(|receiver| receiver.persist())
            .unwrap_or_default();
        let last = revocations.log().last();
        let empty;
        let current = match &self.floor {
            Some(floor) => floor,
            None => {
                empty = AuthorityFloor::new(self.issuer);
                &empty
            }
        };
        let next = current
            .seal(state.coordination(), &record, last)
            .map_err(StoreError::Regression)?;
        let stored = StoredState {
            issuer: self.issuer,
            floor: next.sequence(),
            replay: record.clone(),
            revocations: revocations.log().end(),
            state: &state,
        };
        self.write(StoreFile::State, &stored)?;
        self.write(StoreFile::Floor, &next)?;
        let persisted = StorePersisted {
            floor: next.sequence(),
            revocation_log: last,
        };
        self.floor = Some(next);
        holder.confirm_persisted(&state);
        if let Some(receiver) = receiver {
            receiver.confirm_persisted(&record);
        }
        Ok(persisted)
    }

    /// Gives the directory up, recording a clean release for the next store.
    pub fn release(self) -> Result<(), StoreError> {
        self.owner.release().map_err(StoreError::Owner)
    }

    fn path(&self, file: StoreFile) -> PathBuf {
        self.owner.directory().join(file.name())
    }

    /// `file`'s body, if the file exists.
    fn read<T: DeserializeOwned>(&self, file: StoreFile) -> Result<Option<T>, StoreError> {
        let path = self.path(file);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(StoreError::io(file, "read", &path, &error)),
        };
        decode(file, &bytes)
            .map(Some)
            .map_err(|problem| StoreError::Unreadable {
                file,
                path,
                problem,
            })
    }

    fn write<T: Serialize>(&self, file: StoreFile, body: &T) -> Result<(), StoreError> {
        let bytes = encode(file, body)?;
        let path = self.path(file);
        write_atomic(&path, &bytes).map_err(|error| StoreError::io(file, "write", &path, &error))
    }
}

/// The digest of `file`'s `body` in the current format.
fn body_digest(file: StoreFile, body: &[u8]) -> Digest {
    DigestBuilder::new(BODY_DOMAIN)
        .str(file.tag())
        .u64(u64::from(FORMAT_VERSION))
        .bytes(body)
        .finish()
}

/// `body` as `file`'s bytes: the header line, then the body.
fn encode<T: Serialize>(file: StoreFile, body: &T) -> Result<Vec<u8>, StoreError> {
    let encoding = |error: serde_json::Error| StoreError::Encoding {
        file,
        message: error.to_string(),
    };
    let body = serde_json::to_vec_pretty(body).map_err(encoding)?;
    let header = FileHeader {
        file,
        format: FORMAT_VERSION,
        digest: body_digest(file, &body),
    };
    let mut bytes = serde_json::to_vec(&header).map_err(encoding)?;
    bytes.push(b'\n');
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

/// `file`'s body from its bytes, checked against its header.
fn decode<T: DeserializeOwned>(file: StoreFile, bytes: &[u8]) -> Result<T, FileProblem> {
    let mut parts = bytes.splitn(2, |byte| *byte == b'\n');
    let (Some(header), Some(body)) = (parts.next(), parts.next()) else {
        return Err(FileProblem::Header {
            message: "the file has no header line".to_owned(),
        });
    };
    let header: FileHeader =
        serde_json::from_slice(header).map_err(|error| FileProblem::Header {
            message: error.to_string(),
        })?;
    if header.file != file {
        return Err(FileProblem::OtherFile { found: header.file });
    }
    if header.format != FORMAT_VERSION {
        return Err(FileProblem::Format {
            found: header.format,
        });
    }
    if body_digest(file, body) != header.digest {
        return Err(FileProblem::Digest);
    }
    serde_json::from_slice(body).map_err(|error| FileProblem::Body {
        message: error.to_string(),
    })
}
