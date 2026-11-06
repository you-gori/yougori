//! The trust state kept on a CORE-06 durable stream with one owner, so that a restart
//! never accepts older metadata, an expired role or a frozen snapshot the client had
//! moved past (VM-W45, line 2668: "rollback resistance, offline behavior"; line 2677:
//! "freeze, rollback and mix-and-match attacks"; VM-W42, line 2665: "one append authority
//! per stream"; VM-CP-22, line 3172: "a truncated file, a rewritten record and a restart
//! are detected").
//!
//! A [`TrustStore`] is a [`DurableLog`] of [`TrustState`] records in a directory of its
//! own, appended only by the one [`StreamOwner`] the log holds (the caller names the owner,
//! say `engine.update-trust`, and the stream, say `sandbox.update-trust`). Each record is
//! a whole state, so only the newest matters, and retention may drop older ones. The
//! directory holds what `foundation::events` writes; this module adds no file format.
//!
//! - **Kept before it counts.** [`UpdateClient::keep_update`] runs an update and appends
//!   the resulting state before returning; if the append fails, the update is undone in
//!   memory, so what the client trusts is always what the store holds. The `fetch`
//!   module's refresh keeps every step this way.
//! - **Monotonic.** A state that trusts less than the one before it (an older root, a
//!   lower time floor or revocation version, a lower floor under the same root, a
//!   revocation gone, another profile) is refused when kept and, found in the stream,
//!   refuses the open ([`StoreRefusal::Regressed`]).
//! - **Torn, truncated or rewritten state is refused, never reset.** The log verifies
//!   every line when it opens. A line that does not verify in the middle of the stream is
//!   damage and refuses the open; a last line that does not verify (a torn tail) is
//!   quarantined by the log, and because the log cannot show that it was never
//!   acknowledged, the open is refused, as for any sequence lost from the end of the
//!   stream ([`StoreRefusal::Lost`], [`StoreRefusal::LastStateLost`]). Recovery is the
//!   operator's: a new store started from the pinned root.
//!
//! What it cannot detect (§8.2, line 2447: "a same-user local log is not WORM"): the
//! directory replaced as a whole by an older copy, or deleted.
//!
//! [`StreamOwner`]: crate::foundation::events::StreamOwner

use std::fmt;
use std::path::PathBuf;

use super::client::{UpdateClient, UpdateRefusal};
use super::metadata::Role;
use super::state::TrustState;
use crate::foundation::events::{
    DurableLog, DurableStreamId, EventSequence, GapReason, LogConfig, LogEntry, LogError,
    LogMarker, OpenReport, ProducerId, ReadItem, SequenceRange,
};

/// Items read from the stream per batch when it opens.
const READ_BATCH: usize = 64;

/// Where the trust store lives and who owns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustStoreConfig {
    /// The store's own directory.
    pub directory: PathBuf,
    pub stream: DurableStreamId,
    /// The one appender: the engine's update-trust component.
    pub owner: ProducerId,
    /// The log's bounds. A segment must hold one whole state.
    pub log: LogConfig,
}

/// How a state trusts less than the one kept before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Regression {
    Profile,
    /// An older root is in force.
    Root,
    TimeFloor,
    /// A lower floor, under the same root, or a lower revocation list version.
    Floor {
        role: Role,
    },
    /// A revocation present before is gone.
    Revocation,
}

impl fmt::Display for Regression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Profile => f.write_str("it was kept under another profile"),
            Self::Root => f.write_str("an older root is in force"),
            Self::TimeFloor => f.write_str("its time floor is lower"),
            Self::Floor { role } => write!(f, "its {role} floor is lower"),
            Self::Revocation => f.write_str("a revocation is gone"),
        }
    }
}

/// Why the trust store refused to open or to keep a state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreRefusal {
    /// The stream could not be opened, read or appended to: held by another owner,
    /// damaged (a line that does not verify, a missing high-water mark), too large for a
    /// segment, or storage failed.
    Log(LogError),
    /// The stream lost these sequences from its end, a torn tail among them: the newest
    /// state may be gone, and an older one would be a rollback.
    Lost { missing: SequenceRange },
    /// The last state appended is gone from the stream: cut off its end, or every state
    /// dropped by retention.
    LastStateLost,
    /// The state at `sequence` (or the one offered, when `sequence` is `None`) trusts less
    /// than the one before it.
    Regressed {
        sequence: Option<EventSequence>,
        regression: Regression,
    },
}

impl fmt::Display for StoreRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Log(error) => write!(f, "the trust store cannot be used: {error}"),
            Self::Lost { missing } => write!(
                f,
                "the trust store lost sequences {missing} from its end; the newest trust state may be gone"
            ),
            Self::LastStateLost => f.write_str("the last trust state kept is gone from the store"),
            Self::Regressed {
                sequence: Some(sequence),
                regression,
            } => write!(
                f,
                "trust state {sequence} trusts less than the one before it: {regression}"
            ),
            Self::Regressed {
                sequence: None,
                regression,
            } => write!(
                f,
                "the trust state trusts less than the one kept: {regression}"
            ),
        }
    }
}

impl std::error::Error for StoreRefusal {}

/// The port through which the client keeps its state before an update counts.
pub trait StateKeeper {
    fn keep(&mut self, state: &TrustState) -> Result<(), StoreRefusal>;
}

/// Keeps nothing: for a client that is not to survive a restart.
#[derive(Clone, Copy, Debug, Default)]
pub struct MemoryOnly;

impl StateKeeper for MemoryOnly {
    fn keep(&mut self, _state: &TrustState) -> Result<(), StoreRefusal> {
        Ok(())
    }
}

/// What opening the store found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreOpened {
    /// What opening the log found and did.
    pub report: OpenReport,
    /// Every marker the stream holds, in order.
    pub markers: Vec<(EventSequence, LogMarker)>,
    /// States read.
    pub states: u64,
    /// The sequence of the newest state.
    pub latest: Option<EventSequence>,
}

/// The trust state on a durable stream with one owner.
#[derive(Debug)]
pub struct TrustStore {
    log: DurableLog<TrustState>,
    last: Option<TrustState>,
}

impl TrustStore {
    /// Takes ownership of the stream, creating it if the directory holds none, and reads
    /// it: the newest state, if any, for [`UpdateClient::restore`]. Refuses, releasing
    /// the stream, as [`StoreRefusal`] lists.
    pub fn open(
        config: &TrustStoreConfig,
    ) -> Result<(Self, Option<TrustState>, StoreOpened), StoreRefusal> {
        let (log, report) = DurableLog::open(
            &config.directory,
            config.stream.clone(),
            config.owner.clone(),
            config.log,
        )
        .map_err(StoreRefusal::Log)?;
        // On a refusal the log is dropped here, which releases the stream.
        if log.record_lost() {
            return Err(StoreRefusal::LastStateLost);
        }
        let mut cursor = log.start();
        let mut markers = Vec::new();
        let mut states = 0u64;
        let mut latest = None;
        let mut last: Option<TrustState> = None;
        loop {
            let batch = log.read(&cursor, READ_BATCH).map_err(StoreRefusal::Log)?;
            for item in batch.items {
                match item {
                    ReadItem::Gap {
                        missing,
                        reason: GapReason::Truncated,
                    } => return Err(StoreRefusal::Lost { missing }),
                    // Retention drops older states, which a newer one supersedes.
                    ReadItem::Gap {
                        reason: GapReason::Retention,
                        ..
                    } => {}
                    ReadItem::Entry {
                        sequence,
                        entry: LogEntry::Marker(marker),
                        ..
                    } => {
                        if let LogMarker::Truncated { missing } = marker {
                            return Err(StoreRefusal::Lost { missing });
                        }
                        markers.push((sequence, marker));
                    }
                    ReadItem::Entry {
                        sequence,
                        entry: LogEntry::Record(state),
                        ..
                    } => {
                        if let Some(previous) = &last {
                            regression(previous, &state).map_err(|regression| {
                                StoreRefusal::Regressed {
                                    sequence: Some(sequence),
                                    regression,
                                }
                            })?;
                        }
                        states = states.saturating_add(1);
                        latest = Some(sequence);
                        last = Some(state);
                    }
                }
            }
            cursor = batch.cursor;
            if batch.caught_up {
                break;
            }
        }
        // Retention drops the oldest entries first, so a retained state includes the newest;
        // with none left, the newest may have gone with the rest.
        if last.is_none() && log.retention().dropped_entries > 0 {
            return Err(StoreRefusal::LastStateLost);
        }
        let opened = StoreOpened {
            report,
            markers,
            states,
            latest,
        };
        Ok((
            Self {
                log,
                last: last.clone(),
            },
            last,
            opened,
        ))
    }

    /// Appends `state` and returns its sequence once it is durable. A state that trusts
    /// less than the last one kept is refused before anything is written.
    pub fn keep_state(&mut self, state: &TrustState) -> Result<EventSequence, StoreRefusal> {
        if let Some(previous) = &self.last {
            regression(previous, state).map_err(|regression| StoreRefusal::Regressed {
                sequence: None,
                regression,
            })?;
        }
        let sequence = self.log.append(state.clone()).map_err(StoreRefusal::Log)?;
        self.last = Some(state.clone());
        Ok(sequence)
    }

    /// The newest state kept.
    pub fn last(&self) -> Option<&TrustState> {
        self.last.as_ref()
    }

    /// The stream itself, for reads, retention and totals.
    pub fn log(&self) -> &DurableLog<TrustState> {
        &self.log
    }

    /// Releases the stream, as [`DurableLog::close`] does.
    pub fn close(self) -> Result<(), StoreRefusal> {
        self.log.close().map_err(StoreRefusal::Log)
    }
}

impl StateKeeper for TrustStore {
    fn keep(&mut self, state: &TrustState) -> Result<(), StoreRefusal> {
        self.keep_state(state).map(|_| ())
    }
}

/// Why `next` trusts less than `previous`, if it does.
fn regression(previous: &TrustState, next: &TrustState) -> Result<(), Regression> {
    if next.profile != previous.profile {
        return Err(Regression::Profile);
    }
    let root = |state: &TrustState| state.version(Role::Root);
    if root(next) < root(previous) {
        return Err(Regression::Root);
    }
    if next.time_floor < previous.time_floor {
        return Err(Regression::TimeFloor);
    }
    if next.version(Role::Revocation) < previous.version(Role::Revocation) {
        return Err(Regression::Floor {
            role: Role::Revocation,
        });
    }
    // A rotation may lapse the floors of roles whose keys changed; under the same root
    // no floor goes down.
    if root(next) == root(previous) {
        for (role, floor) in &previous.floors {
            if next.floors.get(role).is_none_or(|next| next < floor) {
                return Err(Regression::Floor { role: *role });
            }
        }
    }
    let kept = previous
        .revoked
        .keys()
        .all(|content_key| next.revoked.contains_key(content_key));
    if !kept || !next.host.covers(&previous.host) {
        return Err(Regression::Revocation);
    }
    Ok(())
}

/// Why an update kept through a [`StateKeeper`] did not count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeptRefusal {
    /// The client refused it; nothing changed and nothing was kept.
    Refused(UpdateRefusal),
    /// The client accepted it, but its state was not kept, so the update was undone.
    NotKept(StoreRefusal),
}

impl fmt::Display for KeptRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refusal) => write!(f, "{refusal}"),
            Self::NotKept(refusal) => write!(
                f,
                "the update was accepted but its state was not kept, so it was undone: {refusal}"
            ),
        }
    }
}

impl std::error::Error for KeptRefusal {}

impl UpdateClient {
    /// Runs `update` and keeps the resulting state through `keeper` before returning. If
    /// the update is refused, whatever it changed is undone and nothing is kept; if it is
    /// accepted but the state is not kept, it is undone too, so the client never trusts
    /// what the store does not hold.
    pub fn keep_update<T>(
        &mut self,
        keeper: &mut dyn StateKeeper,
        update: impl FnOnce(&mut Self) -> Result<T, UpdateRefusal>,
    ) -> Result<T, KeptRefusal> {
        let before = self.trusted.clone();
        let applied = match update(self) {
            Ok(applied) => applied,
            Err(refusal) => {
                self.trusted = before;
                return Err(KeptRefusal::Refused(refusal));
            }
        };
        if let Err(refusal) = keeper.keep(&self.state()) {
            self.trusted = before;
            return Err(KeptRefusal::NotKept(refusal));
        }
        Ok(applied)
    }
}
