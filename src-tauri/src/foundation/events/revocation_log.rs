//! The durable revocation stream (docs/combined-gpu-memory-and-vm-sandbox-plan.md: S2
//! CORE-06 "metrics floods cannot suppress revocation"; S6 INT-02 and INT-10; VM part §6.3
//! step 1 and §8.2 "never block the revocation channel"; docs/combined-plan-leftover-tasks.md
//! S06 "give each durable stream a clear append owner" and "retention/reconnect handling
//! without blocking revocation behind metrics or audit overload").
//!
//! The priority lane delivers a revocation at once and keeps nothing, so a restart forgets
//! every revocation the coordinator had not yet persisted. A [`RevocationLog`] keeps each
//! one on its own [`DurableLog`] under its one [`StreamOwner`]: the revoking authority, the
//! only appender. It is neither the audit journal nor a hub stream. It has its own
//! directory, owner, bounds and retention, so audit overload (a slow or full store, a full
//! spool, failing closed) and a metrics or progress flood never reach it. A publisher emits
//! on the lane first and records here second, so delivery never waits for this stream's
//! sync either ([`DurablyPublished`]).
//!
//! Each record is an [`EventEnvelope`] that the stream's owner seals under the context the
//! revocation was published with: its operation, the authorization epoch in force and the
//! phase `Revoked`. It correlates with the lane's notice and the audit record by that
//! operation ([`DurableLog::correlate`]). The envelope's producer is the stream's owner and
//! its incarnation the owner's, so its sequence space is never a hub producer's; a
//! publisher refuses to record under its own lane issuer's name
//! ([`RecordError::SharedProducer`]). A refused record uses no sequence of either kind.
//!
//! Reconnect and restart: a reader keeps the [`LogCursor`] of its last read and resumes
//! from it. [`RevocationLog::replay`] folds what follows into a [`RevocationReplay`]: the
//! highest epoch revoked per execution and every revoked grant, with the markers owners
//! left and every gap explicit. The coordinator's restart recovery adopts a replay into its
//! persisted state and completes the revocations that state predates
//! (`PersistedState::adopt_revocations` and `Coordinator::complete_revocations`, in
//! foundation/coordination/event_plane.rs), as [`RebuiltRevocations`].
//!
//! [`StreamOwner`]: super::StreamOwner

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::durable::{
    Correlated, DurableLog, DurableStreamId, GapReason, LogConfig, LogCursor, LogEntry, LogError,
    LogMarker, OpenReport, ReadBatch, ReadItem,
};
use super::envelope::{
    EmitError, EventContext, EventEnvelope, EventSequence, Phase, ProducerCore, ProducerId,
    ProducerIncarnation, StreamKey, StreamKind,
};
use super::owner::OwnerError;
use super::reconcile::SequenceRange;
use super::revocation::{GrantRevocation, Revocation};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{ExecutionId, GrantId, MonotonicTime, OperationId};

/// Items one read of a replay asks for; a replay reads until it is caught up.
const REPLAY_BATCH_ITEMS: usize = 1_024;

/// One revocation as the durable stream keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RevocationRecord {
    /// An execution's authorization epoch advanced: nothing bound to an earlier epoch is
    /// honoured again.
    Execution(EventEnvelope<Revocation>),
    /// One grant under an execution's authority was revoked, its epoch left in force.
    Grant(EventEnvelope<GrantRevocation>),
}

impl RevocationRecord {
    /// The execution whose authority the revocation took.
    pub fn execution(&self) -> &ExecutionId {
        match self {
            Self::Execution(revocation) => &revocation.payload().execution,
            Self::Grant(revocation) => &revocation.payload().execution,
        }
    }

    /// The sequence space of the owner incarnation that sealed the record.
    pub fn key(&self) -> StreamKey {
        match self {
            Self::Execution(revocation) => revocation.key(),
            Self::Grant(revocation) => revocation.key(),
        }
    }

    /// The record's sequence in its owner incarnation's space.
    pub fn sequence(&self) -> EventSequence {
        match self {
            Self::Execution(revocation) => revocation.sequence(),
            Self::Grant(revocation) => revocation.sequence(),
        }
    }
}

impl Correlated for RevocationRecord {
    fn operation(&self) -> &OperationId {
        match self {
            Self::Execution(revocation) => revocation.operation(),
            Self::Grant(revocation) => revocation.operation(),
        }
    }
}

/// Why a revocation was not recorded. The revocation is in force all the same, and was
/// delivered on the lane all the same.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// The stream's owner is also the publisher's lane issuer: two different envelopes
    /// would share one sequence space, and a receiver could take one for a duplicate of the
    /// other. The stream needs an owner of its own.
    SharedProducer { producer: ProducerId },
    /// The record could not be sealed: its phase is not `Revoked`, or the owner incarnation
    /// used its last sequence.
    Seal(EmitError),
    /// Storage refused it; nothing of it is stored.
    Log(LogError),
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SharedProducer { producer } => write!(
                f,
                "{producer} issues revocations on the lane, so it cannot also own their durable stream"
            ),
            Self::Seal(error) => write!(f, "the revocation could not be sealed: {error}"),
            Self::Log(error) => write!(f, "the revocation could not be recorded: {error}"),
        }
    }
}

impl std::error::Error for RecordError {}

/// What a publisher did with one revocation: what the event plane did, and the durable
/// stream's answer. The revocation is in force either way, and the lane never waited for
/// the stream, nor the stream for the audit journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurablyPublished<T> {
    /// The lane's admission and the audit journal's receipt.
    pub published: T,
    /// Where the durable stream keeps the record, or why it does not.
    pub recorded: Result<EventSequence, RecordError>,
}

/// The durable revocation stream of one revoking authority (CORE-06; S06).
#[derive(Debug)]
pub struct RevocationLog {
    log: DurableLog<RevocationRecord>,
    core: ProducerCore,
}

impl RevocationLog {
    /// Takes ownership of the revocation stream `stream` in `directory` for `owner`,
    /// creating it if the directory holds none, and recovers it as [`DurableLog::open`]
    /// does. `owner` seals the records, so it must not be a producer registered on a hub:
    /// the coordinator issues revocations on the lane as `coordinator`, and owns its
    /// stream as, say, `coordinator.revocations`. Refuses while any owner, in this process
    /// or another, holds the stream.
    pub fn open(
        directory: &Path,
        stream: DurableStreamId,
        owner: ProducerId,
        config: LogConfig,
    ) -> Result<(Self, OpenReport), LogError> {
        let (log, report) = DurableLog::open(directory, stream, owner.clone(), config)?;
        // An owner's incarnation is never zero: acquisition starts at one and only rises.
        // Should a record claim zero anyway, refuse instead of sealing under one.
        let Some(incarnation) = ProducerIncarnation::new(log.owner().incarnation().get()) else {
            log.close()?;
            return Err(LogError::Owner(OwnerError::IncarnationExhausted));
        };
        let core = ProducerCore::new(
            owner,
            incarnation,
            StreamKind::Revocation,
            SourceClass::HostProbe,
        );
        Ok((Self { log, core }, report))
    }

    /// Records the revocation of an execution, published under `context` at `at` on the
    /// revoking authority's clock, and returns its sequence in the stream once it is
    /// durable. The context's phase must be `Revoked`.
    pub fn record(
        &mut self,
        context: EventContext,
        at: MonotonicTime,
        revocation: Revocation,
    ) -> Result<EventSequence, RecordError> {
        self.keep(context, at, revocation, RevocationRecord::Execution)
    }

    /// Records the revocation of one grant, as [`RevocationLog::record`] records the
    /// revocation of an execution.
    pub fn record_grant(
        &mut self,
        context: EventContext,
        at: MonotonicTime,
        revocation: GrantRevocation,
    ) -> Result<EventSequence, RecordError> {
        self.keep(context, at, revocation, RevocationRecord::Grant)
    }

    /// Seals `payload` with the next envelope sequence and appends it; the sequence is used
    /// only once the record is durable.
    fn keep<P>(
        &mut self,
        context: EventContext,
        at: MonotonicTime,
        payload: P,
        wrap: fn(EventEnvelope<P>) -> RevocationRecord,
    ) -> Result<EventSequence, RecordError> {
        if context.phase != Phase::Revoked {
            return Err(RecordError::Seal(EmitError::WrongPhase {
                expected: Phase::Revoked,
                found: context.phase,
            }));
        }
        let envelope = self
            .core
            .draft(SourceClass::HostProbe, context, at, payload)
            .map_err(RecordError::Seal)?;
        let sealed = envelope.sequence();
        let stored = self.log.append(wrap(envelope)).map_err(RecordError::Log)?;
        self.core.commit(sealed);
        Ok(stored)
    }

    /// Everything after `from`, folded into one [`RevocationReplay`] whose cursor is the
    /// end of the stream. Refuses a cursor of another stream or past the last sequence.
    pub fn replay(&self, from: &LogCursor) -> Result<RevocationReplay, LogError> {
        let mut replay = RevocationReplay::new(from.clone());
        loop {
            let batch = self.log.read(&replay.cursor, REPLAY_BATCH_ITEMS)?;
            let finished = batch.caught_up || batch.items.is_empty();
            replay.fold(batch);
            if finished {
                return Ok(replay);
            }
        }
    }

    /// The stream itself, for reads, cursors, correlation, retention and totals. Only
    /// [`RevocationLog::record`] and [`RevocationLog::record_grant`] append to it.
    pub fn log(&self) -> &DurableLog<RevocationRecord> {
        &self.log
    }

    /// The stream's owner, the producer of every record it seals.
    pub fn owner(&self) -> &ProducerId {
        self.core.producer()
    }

    /// The sequence space of the records this owner incarnation seals.
    pub fn key(&self) -> StreamKey {
        self.core.key()
    }

    /// Releases the stream, as [`DurableLog::close`] does.
    pub fn close(self) -> Result<(), LogError> {
        self.log.close()
    }

    /// Gives the stream up as a crashing process would.
    #[cfg(test)]
    pub(super) fn crash(self) {
        self.log.crash();
    }

    #[cfg(test)]
    pub(super) fn inject(&mut self, fault: super::durable::WriteFault) {
        self.log.inject(fault);
    }
}

/// What a reader rebuilt from a durable revocation stream after one cursor: the latest
/// revocation of each execution and each grant, the markers owners left, and every gap,
/// with the cursor to resume from (CORE-06 reconnect; S7 restart recovery).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationReplay {
    /// Per execution, the revocation read with the highest epoch: the epoch in force.
    pub executions: BTreeMap<ExecutionId, EventEnvelope<Revocation>>,
    /// Per execution, every grant revoked under its authority, each with the revocation
    /// read with the highest epoch.
    pub grants: BTreeMap<ExecutionId, BTreeMap<GrantId, EventEnvelope<GrantRevocation>>>,
    /// Records read.
    pub records: u64,
    /// What owners found when they opened the stream: a stale owner, a torn tail or a
    /// truncation, in order.
    pub markers: Vec<(EventSequence, LogMarker)>,
    /// Sequences the reader will never get, and why. A revocation there is unknown.
    pub gaps: Vec<(SequenceRange, GapReason)>,
    /// Where the reader resumes.
    pub cursor: LogCursor,
}

impl RevocationReplay {
    /// Nothing read yet after `cursor`.
    pub fn new(cursor: LogCursor) -> Self {
        Self {
            executions: BTreeMap::new(),
            grants: BTreeMap::new(),
            records: 0,
            markers: Vec::new(),
            gaps: Vec::new(),
            cursor,
        }
    }

    /// Folds one read of the stream in, in order, and resumes after it.
    pub fn fold(&mut self, batch: ReadBatch<RevocationRecord>) {
        for item in batch.items {
            match item {
                ReadItem::Entry {
                    entry: LogEntry::Record(record),
                    ..
                } => self.apply(record),
                ReadItem::Entry {
                    sequence,
                    entry: LogEntry::Marker(marker),
                    ..
                } => self.markers.push((sequence, marker)),
                ReadItem::Gap { missing, reason } => self.gaps.push((missing, reason)),
            }
        }
        self.cursor = batch.cursor;
    }

    fn apply(&mut self, record: RevocationRecord) {
        self.records = self.records.saturating_add(1);
        match record {
            RevocationRecord::Execution(revocation) => {
                match self
                    .executions
                    .entry(revocation.payload().execution.clone())
                {
                    Entry::Vacant(slot) => {
                        slot.insert(revocation);
                    }
                    Entry::Occupied(mut slot) => {
                        if revocation.payload().epoch > slot.get().payload().epoch {
                            slot.insert(revocation);
                        }
                    }
                }
            }
            RevocationRecord::Grant(revocation) => {
                let grants = self
                    .grants
                    .entry(revocation.payload().execution.clone())
                    .or_default();
                match grants.entry(revocation.payload().grant) {
                    Entry::Vacant(slot) => {
                        slot.insert(revocation);
                    }
                    Entry::Occupied(mut slot) => {
                        if revocation.payload().epoch > slot.get().payload().epoch {
                            slot.insert(revocation);
                        }
                    }
                }
            }
        }
    }

    /// The grants revoked under each execution's authority: the tombstones the replay
    /// read.
    pub fn tombstones(&self) -> BTreeMap<ExecutionId, BTreeSet<GrantId>> {
        self.grants
            .iter()
            .map(|(execution, grants)| (execution.clone(), grants.keys().copied().collect()))
            .collect()
    }

    /// Whether the replay read every sequence after the cursor it started from.
    pub fn is_complete(&self) -> bool {
        self.gaps.is_empty()
    }
}

/// What the coordinator's restart recovery rebuilt from a [`RevocationReplay`]: what its
/// persisted state lacked (S06; VM part §6.3 step 1; S7 restart recovery).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RebuiltRevocations {
    /// Grant tombstones the persisted state lacked, now restored into it.
    pub tombstones_restored: BTreeMap<ExecutionId, BTreeSet<GrantId>>,
    /// Revocations of executions the persisted state predates. Recovery would keep such a
    /// sandbox's live VM for a fresh grant; these sandboxes end instead.
    pub unpersisted: BTreeMap<ExecutionId, EventEnvelope<Revocation>>,
    /// The replay's gaps: revocations there are unknown, so the rebuild may be incomplete.
    pub gaps: Vec<(SequenceRange, GapReason)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::events::durable::WriteFault;
    use crate::foundation::events::fakes::{context, execution, operation, producer};
    use crate::foundation::events::revocation::RevocationReason;
    use crate::foundation::events::Takeover;
    use crate::foundation::ids::{digest, AuthorizationEpoch, Incarnation};

    fn stream_id() -> DurableStreamId {
        DurableStreamId::new("coordinator.revocations").unwrap()
    }

    fn config(segment_entries: u64, max_entries: u64) -> LogConfig {
        LogConfig {
            max_entries,
            max_bytes: 1 << 20,
            segment_entries,
            segment_bytes: 1 << 16,
        }
    }

    fn open(directory: &Path, config: LogConfig) -> (RevocationLog, OpenReport) {
        RevocationLog::open(
            directory,
            stream_id(),
            producer("coordinator.revocations"),
            config,
        )
        .unwrap()
    }

    fn sequence(value: u64) -> EventSequence {
        EventSequence::new(value).unwrap()
    }

    fn range(first: u64, last: u64) -> SequenceRange {
        SequenceRange::new(sequence(first), sequence(last)).unwrap()
    }

    fn at(nanos: u64) -> MonotonicTime {
        MonotonicTime::from_nanos(nanos)
    }

    fn grant(name: &str) -> GrantId {
        GrantId::from_digest(digest("yougori/test/grant/v1", &[name.as_bytes()]))
    }

    fn revoke(log: &mut RevocationLog, op: &str, name: &str, epoch: u64) -> EventSequence {
        log.record(
            context(op, Phase::Revoked),
            at(epoch),
            Revocation {
                execution: execution(name),
                epoch: AuthorizationEpoch::new(epoch),
                reason: RevocationReason::UserRequested,
            },
        )
        .unwrap()
    }

    fn revoke_grant(
        log: &mut RevocationLog,
        op: &str,
        name: &str,
        granted: &str,
        epoch: u64,
    ) -> EventSequence {
        log.record_grant(
            context(op, Phase::Revoked),
            at(epoch),
            GrantRevocation {
                execution: execution(name),
                grant: grant(granted),
                epoch: AuthorizationEpoch::new(epoch),
                reason: RevocationReason::SecurityEvent,
            },
        )
        .unwrap()
    }

    /// What a read returned, compactly: a record's execution and epoch with its owner
    /// incarnation and envelope sequence, a marker, or a gap.
    #[derive(Debug, PartialEq, Eq)]
    enum Seen {
        Revoked {
            at: u64,
            execution: String,
            epoch: u64,
            owner: u64,
            sealed: (u64, u64),
        },
        Granted {
            at: u64,
            execution: String,
        },
        Marker(u64),
        Gap(SequenceRange, GapReason),
    }

    fn seen(items: Vec<ReadItem<RevocationRecord>>) -> Vec<Seen> {
        items
            .into_iter()
            .map(|item| match item {
                ReadItem::Entry {
                    sequence,
                    owner,
                    entry: LogEntry::Record(RevocationRecord::Execution(revocation)),
                } => Seen::Revoked {
                    at: sequence.get(),
                    execution: revocation.payload().execution.to_string(),
                    epoch: revocation.payload().epoch.get(),
                    owner: owner.get(),
                    sealed: (
                        revocation.key().incarnation.get(),
                        revocation.sequence().get(),
                    ),
                },
                ReadItem::Entry {
                    sequence,
                    entry: LogEntry::Record(RevocationRecord::Grant(revocation)),
                    ..
                } => Seen::Granted {
                    at: sequence.get(),
                    execution: revocation.payload().execution.to_string(),
                },
                ReadItem::Entry { sequence, .. } => Seen::Marker(sequence.get()),
                ReadItem::Gap { missing, reason } => Seen::Gap(missing, reason),
            })
            .collect()
    }

    fn revoked(at: u64, name: &str, epoch: u64, owner: u64, sealed: (u64, u64)) -> Seen {
        Seen::Revoked {
            at,
            execution: name.to_owned(),
            epoch,
            owner,
            sealed,
        }
    }

    /// S06, the restart: revocations are recorded, the owner releases the stream, a new
    /// owner reacquires it and records more, and a reader resumes from the cursor it kept
    /// with exactly the entries after it, retention's loss as an explicit gap.
    #[test]
    fn revocations_survive_a_release_and_a_reader_resumes_from_its_cursor_with_explicit_gaps() {
        let directory = tempfile::tempdir().unwrap();
        let (mut log, report) = open(directory.path(), config(2, 4));
        assert_eq!(report.takeover, Takeover::Fresh);
        assert_eq!(revoke(&mut log, "op-1", "exe-1", 2), sequence(1));
        assert_eq!(revoke(&mut log, "op-2", "exe-2", 2), sequence(2));
        assert_eq!(
            revoke_grant(&mut log, "op-3", "exe-1", "route-a", 2),
            sequence(3)
        );

        // A reader takes two items and keeps its cursor, as across a reconnect.
        let first = log.log().read(&log.log().start(), 2).unwrap();
        assert_eq!(
            seen(first.items),
            [
                revoked(1, "exe-1", 2, 1, (1, 1)),
                revoked(2, "exe-2", 2, 1, (1, 2))
            ]
        );
        assert!(!first.caught_up);
        let kept = first.cursor;

        revoke(&mut log, "op-4", "exe-1", 3);
        revoke(&mut log, "op-5", "exe-3", 2);
        revoke(&mut log, "op-6", "exe-2", 4);
        // Retention keeps four entries in segments of two: the first segment is gone.
        assert_eq!(log.log().retention().low_water, Some(sequence(2)));
        log.close().unwrap();

        // The owner released the stream; the next one reacquires it and continues.
        let (mut log, report) = open(directory.path(), config(2, 4));
        assert!(matches!(report.takeover, Takeover::Released { .. }));
        assert!(report.markers.is_empty());
        assert_eq!(log.log().owner().incarnation(), Incarnation::new(2));
        assert_eq!(log.key().incarnation.get(), 2);
        assert_eq!(revoke(&mut log, "op-7", "exe-4", 2), sequence(7));
        assert_eq!(log.log().retention().low_water, Some(sequence(4)));

        // The reader resumes after its cursor: the entries it had not read, with what
        // retention dropped meanwhile as an explicit gap, never silently skipped. The new
        // owner's record starts its own envelope sequence.
        let resumed = log.log().read(&kept, usize::MAX).unwrap();
        assert!(resumed.caught_up);
        assert_eq!(
            seen(resumed.items),
            [
                Seen::Gap(range(3, 4), GapReason::Retention),
                revoked(5, "exe-3", 2, 1, (1, 5)),
                revoked(6, "exe-2", 4, 1, (1, 6)),
                revoked(7, "exe-4", 2, 2, (2, 1)),
            ]
        );
        assert_eq!(resumed.cursor, log.log().end());

        // A reader from the start sees everything retention dropped as one gap.
        let all = log.log().read(&log.log().start(), usize::MAX).unwrap();
        assert_eq!(
            seen(all.items).first(),
            Some(&Seen::Gap(range(1, 4), GapReason::Retention))
        );

        // The replay from the kept cursor rebuilds what it read and names what it could
        // not: the grant revoked in the gap is unknown to it.
        let replay = log.replay(&kept).unwrap();
        assert_eq!(replay.records, 3);
        assert_eq!(replay.gaps, [(range(3, 4), GapReason::Retention)]);
        assert!(!replay.is_complete());
        assert!(replay.grants.is_empty());
        let epochs: Vec<(String, u64)> = replay
            .executions
            .iter()
            .map(|(execution, revocation)| {
                (execution.to_string(), revocation.payload().epoch.get())
            })
            .collect();
        assert_eq!(
            epochs,
            [
                ("exe-2".to_owned(), 4),
                ("exe-3".to_owned(), 2),
                ("exe-4".to_owned(), 2)
            ]
        );
        assert_eq!(replay.cursor, log.log().end());
        // Resuming from the replay's own cursor finds nothing new and no gap.
        let again = log.replay(&replay.cursor).unwrap();
        assert_eq!((again.records, again.is_complete()), (0, true));
    }

    #[test]
    fn a_crashed_owner_is_recorded_in_the_stream_and_the_replay_reports_it() {
        let directory = tempfile::tempdir().unwrap();
        let (mut log, _) = open(directory.path(), config(4, 64));
        revoke(&mut log, "op-1", "exe-1", 2);
        let kept = log.log().end();
        revoke_grant(&mut log, "op-2", "exe-1", "route-a", 2);
        log.crash();

        let (mut log, report) = open(directory.path(), config(4, 64));
        assert!(report.takeover.is_stale());
        assert_eq!(
            report.markers,
            [(
                sequence(3),
                LogMarker::StaleOwner {
                    owner: producer("coordinator.revocations"),
                    incarnation: Incarnation::FIRST,
                }
            )]
        );
        // Everything the crashed owner made durable is kept, and the sequence continues
        // after the marker.
        assert_eq!(revoke(&mut log, "op-3", "exe-2", 2), sequence(4));
        let replay = log.replay(&kept).unwrap();
        assert_eq!(replay.records, 2);
        assert_eq!(replay.markers.len(), 1);
        assert_eq!(replay.markers[0].0, sequence(3));
        assert!(replay.is_complete());
        assert_eq!(
            replay.tombstones(),
            BTreeMap::from([(execution("exe-1"), BTreeSet::from([grant("route-a")]))])
        );
        assert_eq!(
            seen(log.log().read(&kept, usize::MAX).unwrap().items),
            [
                Seen::Granted {
                    at: 2,
                    execution: "exe-1".to_owned()
                },
                Seen::Marker(3),
                revoked(4, "exe-2", 2, 2, (2, 1)),
            ]
        );
    }

    #[test]
    fn a_refused_record_uses_no_sequence_and_stores_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let (mut log, _) = open(directory.path(), config(4, 64));
        let wrong = log.record(
            context("op-1", Phase::Running),
            at(1),
            Revocation {
                execution: execution("exe-1"),
                epoch: AuthorizationEpoch::new(2),
                reason: RevocationReason::UserRequested,
            },
        );
        assert_eq!(
            wrong,
            Err(RecordError::Seal(EmitError::WrongPhase {
                expected: Phase::Revoked,
                found: Phase::Running
            }))
        );
        log.inject(WriteFault::Partial(std::io::ErrorKind::StorageFull));
        let full = log.record_grant(
            context("op-2", Phase::Revoked),
            at(2),
            GrantRevocation {
                execution: execution("exe-1"),
                grant: grant("route-a"),
                epoch: AuthorizationEpoch::new(2),
                reason: RevocationReason::SecurityEvent,
            },
        );
        assert!(matches!(
            full,
            Err(RecordError::Log(LogError::Io {
                kind: std::io::ErrorKind::StorageFull,
                ..
            }))
        ));
        assert!(full
            .unwrap_err()
            .to_string()
            .contains("could not be recorded"));
        assert_eq!(log.log().last(), None);
        // The next record takes the first sequence of both kinds.
        assert_eq!(revoke(&mut log, "op-3", "exe-1", 2), sequence(1));
        assert_eq!(
            seen(
                log.log()
                    .read(&log.log().start(), usize::MAX)
                    .unwrap()
                    .items
            ),
            [revoked(1, "exe-1", 2, 1, (1, 1))]
        );
    }

    #[test]
    fn the_replay_keeps_the_highest_epoch_and_records_correlate_by_operation() {
        let directory = tempfile::tempdir().unwrap();
        let (mut log, _) = open(directory.path(), config(4, 64));
        revoke(&mut log, "op-1", "exe-1", 3);
        // A notice published again later, or out of order, never lowers the epoch.
        revoke(&mut log, "op-2", "exe-1", 2);
        revoke_grant(&mut log, "op-1", "exe-1", "route-a", 3);
        revoke_grant(&mut log, "op-2", "exe-1", "route-a", 2);
        revoke_grant(&mut log, "op-2", "exe-1", "route-b", 2);
        let replay = log.replay(&log.log().start()).unwrap();
        assert_eq!(replay.records, 5);
        let latest = &replay.executions[&execution("exe-1")];
        assert_eq!(latest.payload().epoch, AuthorizationEpoch::new(3));
        assert_eq!(latest.operation(), &operation("op-1"));
        assert_eq!(
            replay.grants[&execution("exe-1")][&grant("route-a")]
                .payload()
                .epoch,
            AuthorizationEpoch::new(3)
        );
        assert_eq!(
            replay.tombstones(),
            BTreeMap::from([(
                execution("exe-1"),
                BTreeSet::from([grant("route-a"), grant("route-b")])
            )])
        );

        let correlated = log.log().correlate(&operation("op-2")).unwrap();
        let sequences: Vec<u64> = correlated
            .records
            .iter()
            .map(|(sequence, _)| sequence.get())
            .collect();
        assert_eq!(sequences, [2, 4, 5]);
        assert!(correlated.gaps.is_empty());
        assert!(correlated
            .records
            .iter()
            .all(|(_, record)| record.execution() == &execution("exe-1")
                && record.key() == log.key()));
        // Every record carries the context it was published under.
        let (_, first) = &correlated.records[0];
        let RevocationRecord::Execution(envelope) = first else {
            panic!("{first:?}");
        };
        assert_eq!(envelope.phase(), Phase::Revoked);
        assert_eq!(envelope.provenance().source(), SourceClass::HostProbe);
        assert_eq!(envelope.emitted_at(), at(2));
    }

    #[test]
    fn records_read_back_refuse_unknown_fields_and_variants() {
        let directory = tempfile::tempdir().unwrap();
        let (mut log, _) = open(directory.path(), config(4, 64));
        revoke(&mut log, "op-1", "exe-1", 2);
        let batch = log.log().read(&log.log().start(), 1).unwrap();
        let ReadItem::Entry {
            entry: LogEntry::Record(record),
            ..
        } = &batch.items[0]
        else {
            panic!("{:?}", batch.items);
        };
        let json = serde_json::to_value(record).unwrap();
        assert_eq!(
            serde_json::from_value::<RevocationRecord>(json.clone()).unwrap(),
            *record
        );
        let mut extra = json.clone();
        extra["execution"]["note"] = serde_json::json!("x");
        assert!(serde_json::from_value::<RevocationRecord>(extra).is_err());
        let mut payload = json.clone();
        payload["execution"]["payload"]["note"] = serde_json::json!("x");
        assert!(serde_json::from_value::<RevocationRecord>(payload).is_err());
        let other = serde_json::json!({ "revoke_everything": json["execution"].clone() });
        assert!(serde_json::from_value::<RevocationRecord>(other).is_err());
    }

    #[test]
    fn one_owner_per_stream() {
        let directory = tempfile::tempdir().unwrap();
        let (log, _) = open(directory.path(), config(4, 64));
        assert!(matches!(
            RevocationLog::open(
                directory.path(),
                stream_id(),
                producer("warden"),
                config(4, 64)
            ),
            Err(LogError::Owner(OwnerError::HeldInProcess { .. }))
        ));
        assert_eq!(log.owner(), &producer("coordinator.revocations"));
        assert_eq!(log.key().stream, StreamKind::Revocation);
    }
}
