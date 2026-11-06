//! The update client's trusted metadata kept on a CORE-06 durable stream, replayed on
//! restart and again when the trust roots are reloaded
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: VM-W45, line 2668: "trust roots, key
//! rotation, expiry/version checks, rollback resistance, offline behavior and emergency
//! revocation"; the update threat-model paragraph, line 2677; VM-P23, line 2798; VM-P48,
//! line 2823; VM-D13, line 3207; VM-CP-22 "a truncated file, a rewritten record and a
//! restart are detected"; M18 in docs/combined-plan-leftover-tasks.md, lines 214–218, and
//! the S08 note "a reloaded key revocation reaching an already running update client").
//!
//! The trust client in `sandbox::trust` holds its trusted metadata in memory, so a restart
//! would start it from the pinned root again and forget every version it trusted: a
//! rollback. [`PersistedUpdateClient`] wraps the client and keeps, on one [`DurableLog`] of
//! [`TrustRecord`]s, every metadata file the client accepted exactly as it was offered
//! (the signed payload and its signatures, [`AcceptedMetadata`]), with its role, version
//! and the time it was accepted, every update-root key a bootstrap pinned
//! ([`PinnedKeys`]), and every torn tail an open found past the log's synced mark
//! ([`TornTailPastMark`]). It writes no file format of its own.
//!
//! - **One owner.** The stream has its own directory and its one appender is this wrapper,
//!   through the [`StreamOwner`] the log holds: the caller names the owner (the engine's
//!   update-trust component, say `engine.update-trust`) and the stream (say
//!   `sandbox.update-trust`) in a [`TrustStream`]. A second owner, in this process or
//!   another, is refused. The directory holds what `foundation::events` writes:
//!   `owner.lock`, `owner.json` (with `owner-stale-<n>.json` kept after a crash),
//!   `stream.json`, `high-water.bin`, `segment-<first sequence, 20 digits>.jsonl` (one line
//!   per entry: the line's digest, a space, then the JSON of its sequence, owner
//!   incarnation and record) and `torn-<incarnation>.bin` for a quarantined torn tail.
//! - **Updates.** Each update runs through the client first. On success its record is
//!   appended, and synced, before success is returned. Before the client sees it, a file
//!   below a floor is refused ([`PersistedUpdateError::BelowFloor`]), as is one whose
//!   record would not fit ([`NoRoom`]). If the append fails, the update is in force in this
//!   process but not kept: the error carries what the client did
//!   ([`PersistedUpdateError::NotPersisted`]), and the wrapper refuses every further update
//!   ([`Halt::NotKept`]) until a reload or a new open rebuilds the client from the log,
//!   which does not hold that file, so the caller offers it again then.
//! - **Opening** starts the client from the pinned root ([`PinnedRoots::bootstrap`] at the
//!   trust clock's time) and replays the stream through the client's own update calls:
//!   every root in order, every revocation list at its place between them (so revocations
//!   accumulate exactly as they did), and the newest timestamp, snapshot and targets with
//!   the files they were accepted under (the `replay` module). The client ends with the
//!   versions, references and revocations it had.
//! - **Expiry.** A stored timestamp, snapshot or targets file the client refuses only as
//!   expired is not loaded, nor anything accepted under it, and its version stays as a
//!   floor; such files must be fetched again. [`PersistedUpdateClient::floors`] lists the
//!   floors in force.
//! - **Reloaded trust roots.** [`PersistedUpdateClient::reload`] bootstraps again from the
//!   trust roots in force now and replays the stream into a new client. An update-root key
//!   an earlier bootstrap of this stream pinned and the roots no longer pin (revoked,
//!   expired, or replaced in its rotation chain) is distrusted from then on, after a
//!   restart too, since the stream records every pinned set: its signatures are left off
//!   every root and revocation file shown to the client, on replay and in later updates.
//!   A stored root that no longer verifies is not trusted, nor any root after it until the
//!   custodians sign that version anew; while the chain is short of the newest stored root
//!   no online file is loaded and online updates wait, since the older root may list
//!   online keys a later rotation retired. A revocation list that no longer verifies keeps
//!   its revoked releases revoked. Each keeps a floor, and [`ReloadReport`] lists what was
//!   dropped, by role. The reload completes, or the old client stays and refuses to
//!   verify, admit or update ([`Halt::ReloadFailed`]); it never runs on part of the
//!   stream.
//! - **Fail closed.** Any other refusal on replay, an expired root among them, damage the
//!   log reports, any sequence it lost (a truncated tail or a removed segment, which the
//!   high-water mark exposes, or a retention drop) and a record whose file is not what it
//!   claims refuse the open with a typed [`RecoveryRefusal`]; no client is returned, so
//!   nothing starts from part of the stream. One consequence, by design: a start from
//!   another root than the stream continues (re-provisioned trust roots) meets a stored
//!   root the client refuses, and recovery is a new stream started from the new root by
//!   the operator, keeping none of the old versions.
//! - **Torn tails.** A crash in the middle of an append leaves a torn last line, which the
//!   log quarantines, burning its sequence, and describes ([`TornTailFound`]). Past the
//!   synced high-water mark, its append never returned a sequence, so nothing acknowledged
//!   was lost: the open records it ([`TornTailPastMark`]) before the replay, the replay
//!   resumes from the records before it, here and on every later open (a gap is accepted
//!   only where such a record and the log's own truncation and torn-tail entries name the
//!   same sequence), and [`RecoveredTrust::torn_tails`] reports it. The update it held was
//!   never reported kept and is offered again. Otherwise the torn line may have held an
//!   acknowledged entry, and its gap refuses the open ([`RecoveryRefusal::Lost`]), on every
//!   later open too. If the record cannot be appended, the open is refused, and later
//!   opens, which no longer see the log's report, refuse the gap as well.
//! - **Retention** must never drop a record, since the replay needs every root and
//!   revocation list. A record that would take the stream past its bounds, with room left
//!   for the markers of a few later opens, is refused before anything changes. No
//!   compaction is done yet, so the bounds decide how many updates the stream can keep.
//! - **Running launches.** [`PersistedUpdateClient::admit_launch`] registers each launch
//!   it admits, by execution, until [`PersistedUpdateClient::end_launch`], and
//!   [`PersistedUpdateClient::update_revocation`] reports every running launch the list
//!   newly revokes (the `running` module).
//!
//! Time comes from the caller's [`TrustClock`], never from a system calendar read here.
//!
//! [`StreamOwner`]: crate::foundation::events::StreamOwner
//! [`TornTailFound`]: crate::foundation::events::TornTailFound

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::replay::{present, read_stream, replay, Floors, View};
use super::roots::{BootstrapRefusal, PinnedRoots};
use super::running::{RevocationReport, RunningLaunches};
use crate::foundation::catalog::ArtifactClass;
use crate::foundation::events::{
    DurableLog, DurableStreamId, EventSequence, GapReason, LogConfig, LogEntry, LogError,
    LogMarker, OpenReport, ProducerId, SequenceRange,
};
use crate::foundation::ids::{ContentKey, ExecutionId};
use crate::sandbox::trust::{
    KeyId, LaunchAdmission, MetadataError, MetadataFile, MetadataVersion, OpenedArtifact,
    RevocationApplied, Role, RootRotation, SchemeRegistry, TargetName, TrustClock, TrustedVersions,
    UnixSeconds, UpdateClient, UpdateRefusal, VerifiedTarget,
};

/// Bytes added to a record's encoding for its stored line: the line digest, the sequence,
/// the owner incarnation, the entry tag and the newline take less.
const LINE_MARGIN_BYTES: u64 = 192;
/// Entries kept free for the markers later opens append (a stale owner, a lost owner
/// record, a truncation and a torn tail), so that they never make retention drop a record.
const OPEN_HEADROOM_ENTRIES: u64 = 4;
/// Bytes kept free for those markers.
const OPEN_HEADROOM_BYTES: u64 = 4 * 1_024;

/// Where the trust stream lives and who owns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustStream {
    /// The stream's own directory.
    pub directory: PathBuf,
    pub stream: DurableStreamId,
    /// The one appender: the engine's update-trust component.
    pub owner: ProducerId,
    /// The log's bounds. Retention must never drop a record, so updates stop at them.
    pub config: LogConfig,
}

/// One record of the trust stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TrustRecord {
    /// A metadata file the client accepted.
    Accepted(AcceptedMetadata),
    /// The update-root keys a bootstrap pinned, written when they include a key no earlier
    /// record names.
    Pinned(PinnedKeys),
    /// A torn tail the log found past its synced high-water mark, written by the open that
    /// found it, so every later replay knows the sequence it burned held nothing
    /// acknowledged.
    TornTailPastMark(TornTailPastMark),
}

/// A torn last line the log quarantined that lay past its synced high-water mark (the
/// log's `TornTailFound::past_synced_mark`): its append never returned a sequence, so
/// nothing acknowledged was lost with it, and the update it held was never reported kept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TornTailPastMark {
    /// The sequence the torn line burned, as the log's [`LogMarker::Truncated`] entry of the
    /// same open states it.
    pub missing: SequenceRange,
    /// The sequence of the log's [`LogMarker::TornTail`] entry that records the line.
    pub marker: EventSequence,
    /// The highest sequence the synced mark acknowledged when the open found the line.
    pub synced_through: Option<EventSequence>,
    /// When, on the trust clock.
    pub at: UnixSeconds,
}

/// A metadata file the update client accepted, as the stream keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedMetadata {
    /// The role the client accepted it as.
    pub role: Role,
    /// Its version, as its payload declares.
    pub version: MetadataVersion,
    /// When the client accepted it, on the trust clock. For the record: a replay checks
    /// expiry at the time it runs.
    pub accepted_at: UnixSeconds,
    /// The file exactly as it was offered: the signed payload and its signatures,
    /// distrusted ones included.
    pub file: MetadataFile,
}

/// The update-root keys one bootstrap pinned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedKeys {
    pub keys: BTreeSet<KeyId>,
    /// When, on the trust clock.
    pub at: UnixSeconds,
}

/// What is wrong with a stored record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum RecordProblem {
    /// The file's payload does not parse as the role it is stored under.
    Payload { error: MetadataError },
    /// The file declares another version than the record.
    Version {
        stored: MetadataVersion,
        file: MetadataVersion,
    },
}

/// Why a record does not fit the trust stream without retention dropping a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "bound", rename_all = "snake_case")]
pub enum NoRoom {
    /// The record's line, estimated, is larger than a segment may be.
    Segment { bytes: u64, limit: u64 },
    /// Keeping it, with room for the markers of later opens, takes the stream past its
    /// bounds.
    Bounds {
        entries: u64,
        bytes: u64,
        max_entries: u64,
        max_bytes: u64,
    },
}

impl fmt::Display for NoRoom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Segment { bytes, limit } => write!(
                f,
                "the record takes about {bytes} bytes; a segment of the trust stream holds at most {limit}"
            ),
            Self::Bounds {
                entries,
                bytes,
                max_entries,
                max_bytes,
            } => write!(
                f,
                "keeping the record would take the trust stream to {entries} entries and about {bytes} bytes; it keeps at most {max_entries} entries and {max_bytes} bytes"
            ),
        }
    }
}

/// Why the persisted client was not opened or reloaded. Every case fails closed: an open
/// returns no client and releases the stream; a reload leaves the old client refusing
/// every use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryRefusal {
    /// The stream could not be opened, read or appended to: held by another owner,
    /// damaged (a line that does not verify, a missing high-water mark, two writers), or
    /// storage failed.
    Log(LogError),
    /// The client could not be started from the pinned root.
    Bootstrap(BootstrapRefusal),
    /// The stream lost these sequences: cut off its end or removed (the high-water mark
    /// exposes it), burned with a torn tail no record shows past the synced mark (so it may
    /// have held an acknowledged entry), or dropped by retention. The versions trusted there
    /// are unknown.
    Lost {
        missing: SequenceRange,
        reason: GapReason,
    },
    /// A record's file is not what the record claims.
    BadRecord {
        sequence: EventSequence,
        role: Role,
        problem: RecordProblem,
    },
    /// The client refused a stored file on replay, other than an online file refused only
    /// as expired or a file that needed a distrusted key.
    Replay {
        sequence: EventSequence,
        role: Role,
        version: MetadataVersion,
        reason: UpdateRefusal,
    },
    /// The record of newly pinned keys does not fit the stream.
    NoRoom(NoRoom),
}

impl fmt::Display for RecoveryRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Log(error) => write!(f, "the trust stream cannot be recovered: {error}"),
            Self::Bootstrap(refusal) => {
                write!(f, "the update client cannot start from the pinned root: {refusal}")
            }
            Self::Lost { missing, reason } => {
                let how = match reason {
                    GapReason::Retention => "dropped by retention",
                    GapReason::Truncated => "lost from its end",
                };
                write!(
                    f,
                    "the trust stream's sequences {missing} were {how}; the versions trusted there are unknown"
                )
            }
            Self::BadRecord {
                sequence,
                role,
                problem,
            } => match problem {
                RecordProblem::Payload { error } => write!(
                    f,
                    "trust record {sequence} is not {role} metadata: {error}"
                ),
                RecordProblem::Version { stored, file } => write!(
                    f,
                    "trust record {sequence} names {role} version {stored}, but its file is version {file}"
                ),
            },
            Self::Replay {
                sequence,
                role,
                version,
                reason,
            } => write!(
                f,
                "the update client refused stored {role} version {version} (record {sequence}) on replay: {reason}"
            ),
            Self::NoRoom(no_room) => write!(f, "the pinned keys cannot be recorded: {no_room}"),
        }
    }
}

impl std::error::Error for RecoveryRefusal {}

/// What opening the trust stream found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredTrust {
    /// What opening the log found and did: the takeover, and the markers it appended.
    pub report: OpenReport,
    /// Every marker the stream holds, in order, as the replay read them.
    pub markers: Vec<(EventSequence, LogMarker)>,
    /// Metadata files read.
    pub records: u64,
    /// The floors stored files left, by role.
    pub floors: BTreeMap<Role, MetadataVersion>,
    /// Update-root keys an earlier bootstrap pinned that the trust roots no longer pin.
    pub distrusted: BTreeSet<KeyId>,
    /// Releases that stay revoked though no list the client verifies revokes them.
    pub kept_revoked: BTreeSet<ContentKey>,
    /// Every torn tail past the synced mark the stream records, this open's included: the
    /// replay resumed from the records before each.
    pub torn_tails: Vec<TornTailPastMark>,
}

/// What a reload of the trust roots did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReloadReport {
    /// Update-root keys an earlier bootstrap pinned that the reloaded roots no longer pin:
    /// their signatures no longer count.
    pub distrusted: BTreeSet<KeyId>,
    /// By role, the version the client trusted before the reload and trusts no longer.
    /// Such a role is fetched again; the floors keep refusing what is older.
    pub dropped: BTreeMap<Role, MetadataVersion>,
    /// The floors in force after the reload, by role.
    pub floors: BTreeMap<Role, MetadataVersion>,
    /// Releases that stay revoked though no list the client verifies revokes them.
    pub kept_revoked: BTreeSet<ContentKey>,
}

/// Why the persisted client takes no update now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Halt {
    /// An update is in force but the stream did not keep it. Verification and admission
    /// go on; updates wait for a reload or a new open, which rebuild the client from the
    /// stream.
    NotKept { error: LogError },
    /// A reload of the trust roots failed. The client's trust predates the reloaded roots,
    /// so the wrapper verifies, admits and updates nothing until a reload or a new open
    /// succeeds.
    ReloadFailed { refusal: RecoveryRefusal },
}

impl fmt::Display for Halt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotKept { error } => write!(
                f,
                "an update is in force but the trust stream did not keep it ({error}); reload or open the stream again"
            ),
            Self::ReloadFailed { refusal } => write!(
                f,
                "the trust roots were reloaded but the update client could not be rebuilt ({refusal}); it trusts nothing until it is"
            ),
        }
    }
}

/// Why the persisted client refused an update. `T` is what the client returns for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PersistedUpdateError<T> {
    /// Below the floor of a stored file the client no longer holds; the client never saw
    /// it. The reason is the client's own refusal for the same comparison.
    BelowFloor { reason: UpdateRefusal },
    /// The client refused it; nothing changed and nothing was kept.
    Refused { reason: UpdateRefusal },
    /// Its record would not fit the stream. Nothing changed.
    NoRoom(NoRoom),
    /// The client accepted it, and it is in force in this process, but the stream did not
    /// keep it. The wrapper takes no update until a reload or a new open, which do not
    /// hold this file.
    NotPersisted { error: LogError, applied: T },
    /// The wrapper takes no update now.
    Halted { halt: Halt },
}

impl<T> PersistedUpdateError<T> {
    fn map_applied<U>(self, map: impl FnOnce(T) -> U) -> PersistedUpdateError<U> {
        match self {
            Self::BelowFloor { reason } => PersistedUpdateError::BelowFloor { reason },
            Self::Refused { reason } => PersistedUpdateError::Refused { reason },
            Self::NoRoom(no_room) => PersistedUpdateError::NoRoom(no_room),
            Self::NotPersisted { error, applied } => PersistedUpdateError::NotPersisted {
                error,
                applied: map(applied),
            },
            Self::Halted { halt } => PersistedUpdateError::Halted { halt },
        }
    }
}

impl<T> fmt::Display for PersistedUpdateError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BelowFloor { reason } => {
                write!(f, "refused below the floor a stored file left: {reason}")
            }
            Self::Refused { reason } => write!(f, "{reason}"),
            Self::NoRoom(no_room) => write!(f, "{no_room}"),
            Self::NotPersisted { error, .. } => write!(
                f,
                "the update is in force but the trust stream did not keep it: {error}; reload or open the stream again"
            ),
            Self::Halted { halt } => write!(f, "{halt}"),
        }
    }
}

impl<T: fmt::Debug> std::error::Error for PersistedUpdateError<T> {}

/// Why the persisted client did not verify a target or admit a launch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustRefusal {
    /// The client refused it, or the release stays revoked though the list that revoked
    /// it no longer verifies.
    Refused { reason: UpdateRefusal },
    /// The execution already has a running launch registered; nothing was admitted.
    AlreadyRunning { execution: ExecutionId },
    /// A reload failed, so the client is trusted for nothing.
    Halted { halt: Halt },
}

impl fmt::Display for TrustRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused { reason } => write!(f, "{reason}"),
            Self::AlreadyRunning { execution } => {
                write!(f, "execution {execution} already has a running launch")
            }
            Self::Halted { halt } => write!(f, "{halt}"),
        }
    }
}

impl std::error::Error for TrustRefusal {}

/// The update client with its trusted metadata on a durable stream, and the launches it
/// admitted that are still running (VM-W45).
#[derive(Debug)]
pub struct PersistedUpdateClient {
    log: DurableLog<TrustRecord>,
    client: UpdateClient,
    clock: TrustClock,
    config: LogConfig,
    floors: Floors,
    /// Revoked releases no list the client verifies revokes any more.
    kept_revoked: BTreeMap<ContentKey, String>,
    /// Update-root keys whose signatures no longer count.
    distrusted: BTreeSet<KeyId>,
    running: RunningLaunches,
    halt: Option<Halt>,
}

/// A client rebuilt from the stream, not yet in force.
struct Rebuilt {
    client: UpdateClient,
    floors: Floors,
    kept_revoked: BTreeMap<ContentKey, String>,
    distrusted: BTreeSet<KeyId>,
    /// The record of the keys pinned now, when they include one no record names.
    pinned: Option<TrustRecord>,
    markers: Vec<(EventSequence, LogMarker)>,
    records: u64,
    torn_tails: Vec<TornTailPastMark>,
}

impl Rebuilt {
    /// Reads the stream, pins the update roots at `now`, and replays the stream into a
    /// client bootstrapped from `trusted_root`, without the signatures of the keys earlier
    /// bootstraps pinned and the roots no longer pin.
    fn from_stream(
        log: &DurableLog<TrustRecord>,
        config: &LogConfig,
        roots: &PinnedRoots,
        schemes: &dyn Fn() -> SchemeRegistry,
        trusted_root: &MetadataFile,
        now: UnixSeconds,
    ) -> Result<Self, RecoveryRefusal> {
        let contents = read_stream(log)?;
        let pinned: BTreeSet<KeyId> = roots
            .at(now)
            .map_err(|reason| RecoveryRefusal::Bootstrap(BootstrapRefusal::Roots { reason }))?
            .keys()
            .keys()
            .copied()
            .collect();
        let distrusted: BTreeSet<KeyId> = contents.pinned.difference(&pinned).copied().collect();
        let (root, _) = present(Role::Root, trusted_root, &distrusted);
        let start = || {
            roots
                .bootstrap(schemes(), &root, now)
                .map_err(RecoveryRefusal::Bootstrap)
        };
        let replayed = replay(&contents.records, &start, &distrusted, now)?;
        let pinned = if pinned.is_subset(&contents.pinned) {
            None
        } else {
            let record = TrustRecord::Pinned(PinnedKeys {
                keys: pinned,
                at: now,
            });
            room(log, config, &record).map_err(RecoveryRefusal::NoRoom)?;
            Some(record)
        };
        Ok(Self {
            client: replayed.client,
            floors: replayed.floors,
            kept_revoked: replayed.kept_revoked,
            distrusted,
            pinned,
            markers: contents.markers,
            records: u64::try_from(contents.records.len()).unwrap_or(u64::MAX),
            torn_tails: contents.torn_tails,
        })
    }
}

impl PersistedUpdateClient {
    /// Takes ownership of the trust stream, creating it if its directory holds none,
    /// starts the client from `trusted_root` through `roots` at the clock's time, and
    /// replays the stream into it. `schemes` makes the registry for each start; the
    /// replay starts over when it leaves a file out. Refuses, releasing the stream, as
    /// [`RecoveryRefusal`] lists.
    pub fn open(
        stream: &TrustStream,
        roots: &PinnedRoots,
        schemes: &dyn Fn() -> SchemeRegistry,
        trusted_root: &MetadataFile,
        clock: TrustClock,
    ) -> Result<(Self, RecoveredTrust), RecoveryRefusal> {
        let (mut log, report) = DurableLog::open(
            &stream.directory,
            stream.stream.clone(),
            stream.owner.clone(),
            stream.config,
        )
        .map_err(RecoveryRefusal::Log)?;
        // On a refusal the log is dropped here, which releases the stream. A torn tail past
        // the synced mark is recorded before the replay reads the stream.
        if let Some(record) = torn_tail_past_mark(&report, clock.now()) {
            room(&log, &stream.config, &record).map_err(RecoveryRefusal::NoRoom)?;
            log.append(record).map_err(RecoveryRefusal::Log)?;
        }
        let rebuilt = Rebuilt::from_stream(
            &log,
            &stream.config,
            roots,
            schemes,
            trusted_root,
            clock.now(),
        )?;
        if let Some(record) = rebuilt.pinned {
            log.append(record).map_err(RecoveryRefusal::Log)?;
        }
        let recovered = RecoveredTrust {
            report,
            markers: rebuilt.markers,
            records: rebuilt.records,
            floors: rebuilt.floors.versions(),
            distrusted: rebuilt.distrusted.clone(),
            kept_revoked: rebuilt.kept_revoked.keys().copied().collect(),
            torn_tails: rebuilt.torn_tails,
        };
        Ok((
            Self {
                log,
                client: rebuilt.client,
                clock,
                config: stream.config,
                floors: rebuilt.floors,
                kept_revoked: rebuilt.kept_revoked,
                distrusted: rebuilt.distrusted,
                running: RunningLaunches::new(),
                halt: None,
            },
            recovered,
        ))
    }

    /// Rebuilds the client after the trust roots were reloaded: bootstraps from
    /// `trusted_root` through `roots` at the clock's time, replays the stream into the new
    /// client without the signatures of keys an earlier bootstrap pinned and `roots` no
    /// longer pins, and puts it in force with every release the old client held revoked
    /// still revoked. Running launches stay registered. On a refusal the old client stays,
    /// verifying, admitting and updating nothing ([`Halt::ReloadFailed`]); a later
    /// successful reload, or a new open, lifts that. A successful reload also lifts
    /// [`Halt::NotKept`], since the new client holds only what the stream kept.
    pub fn reload(
        &mut self,
        roots: &PinnedRoots,
        schemes: &dyn Fn() -> SchemeRegistry,
        trusted_root: &MetadataFile,
    ) -> Result<ReloadReport, RecoveryRefusal> {
        let rebuilt = Rebuilt::from_stream(
            &self.log,
            &self.config,
            roots,
            schemes,
            trusted_root,
            self.clock.now(),
        )
        .and_then(|rebuilt| match &rebuilt.pinned {
            Some(record) => self
                .log
                .append(record.clone())
                .map(|_| rebuilt)
                .map_err(RecoveryRefusal::Log),
            None => Ok(rebuilt),
        });
        let rebuilt = match rebuilt {
            Ok(rebuilt) => rebuilt,
            Err(refusal) => {
                self.halt = Some(Halt::ReloadFailed {
                    refusal: refusal.clone(),
                });
                return Err(refusal);
            }
        };
        let before = self.client.trusted_versions();
        let mut kept_revoked = rebuilt.kept_revoked;
        for (content_key, reason) in self.client.revoked().iter().chain(&self.kept_revoked) {
            if !rebuilt.client.revoked().contains_key(content_key) {
                kept_revoked
                    .entry(*content_key)
                    .or_insert_with(|| reason.clone());
            }
        }
        self.client = rebuilt.client;
        self.floors = rebuilt.floors;
        self.kept_revoked = kept_revoked;
        self.distrusted = rebuilt.distrusted;
        self.halt = None;
        Ok(ReloadReport {
            distrusted: self.distrusted.clone(),
            dropped: dropped(&before, &self.client.trusted_versions()),
            floors: self.floors.versions(),
            kept_revoked: self.kept_revoked.keys().copied().collect(),
        })
    }

    /// Rotates the root as [`UpdateClient::update_root`] does, and keeps the file. The
    /// online floors kept under other online keys than the new root's lapse.
    pub fn update_root(
        &mut self,
        file: &MetadataFile,
    ) -> Result<RootRotation, PersistedUpdateError<RootRotation>> {
        self.apply(Role::Root, file, |client, presented, now| {
            client.update_root(presented, now)
        })
    }

    /// Trusts a new timestamp as [`UpdateClient::update_timestamp`] does, and keeps it.
    pub fn update_timestamp(
        &mut self,
        file: &MetadataFile,
    ) -> Result<(), PersistedUpdateError<()>> {
        self.apply(Role::Timestamp, file, |client, presented, now| {
            client.update_timestamp(presented, now)
        })
    }

    /// Trusts a new snapshot as [`UpdateClient::update_snapshot`] does, and keeps it.
    pub fn update_snapshot(&mut self, file: &MetadataFile) -> Result<(), PersistedUpdateError<()>> {
        self.apply(Role::Snapshot, file, |client, presented, now| {
            client.update_snapshot(presented, now)
        })
    }

    /// Trusts new targets as [`UpdateClient::update_targets`] does, and keeps them.
    pub fn update_targets(&mut self, file: &MetadataFile) -> Result<(), PersistedUpdateError<()>> {
        self.apply(Role::Targets, file, |client, presented, now| {
            client.update_targets(presented, now)
        })
    }

    /// Applies a revocation list as [`UpdateClient::update_revocation`] does, keeps it,
    /// and reports every running launch whose artifact it newly revokes. A list in force
    /// but not kept still reports them ([`PersistedUpdateError::NotPersisted`]).
    pub fn update_revocation(
        &mut self,
        file: &MetadataFile,
    ) -> Result<RevocationReport, PersistedUpdateError<RevocationReport>> {
        match self.apply(Role::Revocation, file, |client, presented, _| {
            client.update_revocation(presented)
        }) {
            Ok(applied) => Ok(self.report(applied)),
            Err(error) => Err(error.map_applied(|applied| self.report(applied))),
        }
    }

    /// The verified handle for target `name` of `class` now, as
    /// [`UpdateClient::verify_target`] gives it, unless the release stays revoked.
    pub fn verify_target(
        &self,
        name: &TargetName,
        class: ArtifactClass,
    ) -> Result<VerifiedTarget, TrustRefusal> {
        self.usable()?;
        let verified = self
            .client
            .verify_target(name, class, self.clock.now())
            .map_err(|reason| TrustRefusal::Refused { reason })?;
        self.check_kept_revoked(verified.content_key())?;
        Ok(verified)
    }

    /// Admits the launch of `opened` for `execution` now, as [`UpdateClient::admit_launch`]
    /// does unless the release stays revoked, and registers it as running until
    /// [`Self::end_launch`]. An execution has one running launch at a time.
    pub fn admit_launch(
        &mut self,
        execution: ExecutionId,
        opened: &OpenedArtifact,
    ) -> Result<LaunchAdmission, TrustRefusal> {
        self.usable()?;
        if self.running.get(&execution).is_some() {
            return Err(TrustRefusal::AlreadyRunning { execution });
        }
        self.check_kept_revoked(opened.content_key())?;
        let admission = self
            .client
            .admit_launch(opened, self.clock.now())
            .map_err(|reason| TrustRefusal::Refused { reason })?;
        self.running
            .register(execution, admission.clone())
            .map_err(|refused| TrustRefusal::AlreadyRunning {
                execution: refused.execution,
            })?;
        Ok(admission)
    }

    /// Removes the launch of `execution`, which ended, and returns its admission.
    pub fn end_launch(&mut self, execution: &ExecutionId) -> Option<LaunchAdmission> {
        self.running.end(execution)
    }

    /// The launches admitted and not yet ended.
    pub fn running(&self) -> &RunningLaunches {
        &self.running
    }

    /// The running launches, for the launch-set admission (the `launch_set` module).
    pub(super) fn running_mut(&mut self) -> &mut RunningLaunches {
        &mut self.running
    }

    /// The time now on the trust clock, so the launch-set admission verifies and admits
    /// every component of one launch at one time.
    pub(super) fn now(&self) -> UnixSeconds {
        self.clock.now()
    }

    /// The client, for its trusted versions, revocations and root.
    pub fn client(&self) -> &UpdateClient {
        &self.client
    }

    /// Every revoked release with its reason: the client's, and those that stay revoked
    /// though the list that revoked them no longer verifies.
    pub fn revoked(&self) -> BTreeMap<ContentKey, String> {
        let mut revoked = self.kept_revoked.clone();
        revoked.extend(
            self.client
                .revoked()
                .iter()
                .map(|(content_key, reason)| (*content_key, reason.clone())),
        );
        revoked
    }

    /// The floors in force, by role: versions below which a file is refused before the
    /// client sees it.
    pub fn floors(&self) -> BTreeMap<Role, MetadataVersion> {
        self.floors.versions()
    }

    /// The update-root keys whose signatures no longer count.
    pub fn distrusted(&self) -> &BTreeSet<KeyId> {
        &self.distrusted
    }

    /// Why the wrapper takes no update now, if it does not.
    pub fn halt(&self) -> Option<&Halt> {
        self.halt.as_ref()
    }

    /// The stream itself, for reads, cursors, retention and totals. Only the updates and
    /// the records of pinned keys append to it.
    pub fn log(&self) -> &DurableLog<TrustRecord> {
        &self.log
    }

    /// Releases the stream, as [`DurableLog::close`] does.
    pub fn close(self) -> Result<(), LogError> {
        self.log.close()
    }

    /// Runs one update: refused while halted, below a floor or without room, then shown to
    /// the client without distrusted signatures, then kept before it returns.
    fn apply<T>(
        &mut self,
        role: Role,
        file: &MetadataFile,
        run: impl FnOnce(&mut UpdateClient, &MetadataFile, UnixSeconds) -> Result<T, UpdateRefusal>,
    ) -> Result<T, PersistedUpdateError<T>> {
        if let Some(halt) = &self.halt {
            return Err(PersistedUpdateError::Halted { halt: halt.clone() });
        }
        let now = self.clock.now();
        let view = View::parse(role, file).map_err(|error| PersistedUpdateError::Refused {
            reason: UpdateRefusal::Metadata { error },
        })?;
        self.floors
            .check(&view, self.client.root().version)
            .map_err(|reason| PersistedUpdateError::BelowFloor { reason })?;
        let record = TrustRecord::Accepted(AcceptedMetadata {
            role,
            version: view.version(),
            accepted_at: now,
            file: file.clone(),
        });
        room(&self.log, &self.config, &record).map_err(PersistedUpdateError::NoRoom)?;
        let (presented, _) = present(role, file, &self.distrusted);
        let applied = run(&mut self.client, &presented, now)
            .map_err(|reason| PersistedUpdateError::Refused { reason })?;
        if role == Role::Root {
            self.floors.rotated(self.client.root());
        }
        self.floors.settle(&self.client.trusted_versions());
        if let Err(error) = self.log.append(record) {
            self.halt = Some(Halt::NotKept {
                error: error.clone(),
            });
            return Err(PersistedUpdateError::NotPersisted { error, applied });
        }
        Ok(applied)
    }

    /// The report for `applied`: the running launches whose artifact it newly revoked,
    /// with the reason the client recorded. A release kept revoked from a list that no
    /// longer verifies was revoked before, so it is not newly revoked; the client holds it
    /// from now on.
    fn report(&mut self, applied: RevocationApplied) -> RevocationReport {
        let newly: BTreeMap<ContentKey, String> = self
            .client
            .revoked()
            .iter()
            .filter(|(content_key, _)| {
                applied.newly_revoked.contains(content_key)
                    && !self.kept_revoked.contains_key(content_key)
            })
            .map(|(content_key, reason)| (*content_key, reason.clone()))
            .collect();
        let client = &self.client;
        self.kept_revoked
            .retain(|content_key, _| !client.revoked().contains_key(content_key));
        RevocationReport {
            running: self.running.revoked_by(&newly),
            applied,
        }
    }

    /// Refuses every use while a reload has failed.
    fn usable(&self) -> Result<(), TrustRefusal> {
        match &self.halt {
            Some(halt @ Halt::ReloadFailed { .. }) => {
                Err(TrustRefusal::Halted { halt: halt.clone() })
            }
            Some(Halt::NotKept { .. }) | None => Ok(()),
        }
    }

    /// Refuses a release that stays revoked though its list no longer verifies, as the
    /// client refuses a revoked one.
    fn check_kept_revoked(&self, content_key: ContentKey) -> Result<(), TrustRefusal> {
        match self.kept_revoked.get(&content_key) {
            Some(reason) => Err(TrustRefusal::Refused {
                reason: UpdateRefusal::RevokedRelease {
                    content_key,
                    reason: reason.clone(),
                },
            }),
            None => Ok(()),
        }
    }
}

/// Refuses `record` if it would not fit a segment, or if keeping it, with room for the
/// markers of later opens, would let retention drop a record.
fn room(
    log: &DurableLog<TrustRecord>,
    config: &LogConfig,
    record: &TrustRecord,
) -> Result<(), NoRoom> {
    let bytes = serde_json::to_vec(&LogEntry::Record(record))
        .map_or(u64::MAX, |encoded| {
            u64::try_from(encoded.len()).unwrap_or(u64::MAX)
        })
        .saturating_add(LINE_MARGIN_BYTES);
    if bytes > config.segment_bytes {
        return Err(NoRoom::Segment {
            bytes,
            limit: config.segment_bytes,
        });
    }
    let retention = log.retention();
    let entries = retention
        .retained_entries
        .saturating_add(1)
        .saturating_add(OPEN_HEADROOM_ENTRIES);
    let total = retention
        .retained_bytes
        .saturating_add(bytes)
        .saturating_add(OPEN_HEADROOM_BYTES);
    if entries > config.max_entries || total > config.max_bytes {
        return Err(NoRoom::Bounds {
            entries,
            bytes: total,
            max_entries: config.max_entries,
            max_bytes: config.max_bytes,
        });
    }
    Ok(())
}

/// The record of the torn tail the open `report` describes, if the log found it past the
/// synced mark: the sequence it burned, as the open's truncation marker states it. Any
/// other torn tail gets no record, so its gap refuses the replay.
fn torn_tail_past_mark(report: &OpenReport, now: UnixSeconds) -> Option<TrustRecord> {
    let torn = report.torn_tail.filter(|torn| torn.past_synced_mark)?;
    let missing = report.markers.iter().find_map(|(_, marker)| match marker {
        LogMarker::Truncated { missing } => Some(*missing),
        _ => None,
    })?;
    Some(TrustRecord::TornTailPastMark(TornTailPastMark {
        missing,
        marker: torn.marker,
        synced_through: torn.synced_through,
        at: now,
    }))
}

/// By role, the version `before` trusted that `after` does not.
fn dropped(before: &TrustedVersions, after: &TrustedVersions) -> BTreeMap<Role, MetadataVersion> {
    let mut dropped = BTreeMap::new();
    if after.root < before.root {
        dropped.insert(Role::Root, before.root);
    }
    for (role, was, is) in [
        (Role::Timestamp, before.timestamp, after.timestamp),
        (Role::Snapshot, before.snapshot, after.snapshot),
        (Role::Targets, before.targets, after.targets),
        (Role::Revocation, before.revocation, after.revocation),
    ] {
        if let Some(was) = was {
            if is.is_none_or(|is| is < was) {
                dropped.insert(role, was);
            }
        }
    }
    dropped
}
