//! A durable CORE-06 stream on local storage: one owner, a persisted sequence, bounded
//! retention and reconnecting readers (docs/combined-gpu-memory-and-vm-sandbox-plan.md: S2
//! CORE-06 "separate retention/backpressure"; VM part §8.2; VM-W42 "one append authority per
//! stream, bounded queues ... rotation" and "restart/truncation, disk full ... tested";
//! VM-CP-22 "a truncated file, a rewritten record and a restart are detected"; S7 restart
//! recovery; docs/combined-plan-leftover-tasks.md S06).
//!
//! A [`DurableLog`] is one stream's append-only log in one directory. Only the
//! [`StreamOwner`] it holds appends, so no two writers ever share it. Each entry takes the
//! stream's next [`EventSequence`]: 1, 2, 3, … persisted with the entry, continued after a
//! release, a crash or a takeover from a stale owner, and never used twice.
//!
//! - Format. Segment files hold one line per entry: the hex digest of the line's JSON,
//!   bound to the stream and its instance, a space, then the JSON (sequence, owner
//!   incarnation, entry). An append is acknowledged once its line and the stream's
//!   high-water mark are synced; a failed append is cut back off before the error
//!   returns, so storage holds a whole entry or none of it.
//! - No sequence is given out twice. The high-water mark, in a file of its own, holds the
//!   highest sequence the stream used and its last record's, and every append persists it
//!   before it returns (the `high_water` module). Opening continues after the mark, the
//!   segments, everything retention dropped, the owner record's durable sequence and the
//!   line of a torn tail, which may have been acknowledged. Whatever of that the segments
//!   no longer hold, such as a segment cut back or deleted after a crash or a last line
//!   that no longer verifies, a [`LogMarker::Truncated`] entry records, and readers get it
//!   as an explicit gap. Segments without their mark are refused ([`LogDamage`]).
//! - Opening verifies every line. A last line that is incomplete or does not verify is a
//!   torn tail: its bytes are moved to a quarantine file, never deleted, the line is cut
//!   off, and a [`LogMarker::TornTail`] entry records it in the stream. Any other line that
//!   does not verify, a sequence out of order, or an entry of an earlier owner after a
//!   later one (two writers) is damage: the log refuses to open. A stale owner is recorded
//!   as a [`LogMarker::StaleOwner`] entry, and a missing owner record as a
//!   [`LogMarker::OwnerRecordLost`] entry, the new owner's incarnation raised past every
//!   owner the stream shows. Markers are entries, so every reader meets them in order. An
//!   open refused before it wrote an entry leaves the owner record as it found it; one that
//!   wrote an entry leaves the stream to the next owner as a stale owner.
//! - Retention is bounded by entries and bytes. It drops whole segments, oldest first,
//!   never the one being written, and persists its low-water mark and the dropped counts
//!   before a file goes, so no dropped entry comes back and every one is counted.
//! - Reconnect. A reader resumes from its [`LogCursor`] and gets the remainder, with an
//!   explicit [`ReadItem::Gap`] wherever retention or a truncation removed entries. A
//!   cursor of another stream, or past the last sequence, is refused ([`CursorError`]).
//! - Correlation uses the envelope's own identities: [`DurableLog::correlate`] finds an
//!   operation's records by their [`OperationId`].
//!
//! A [`DurableLog`] of [`AuditRecord`]s is an [`AuditStore`], so an
//! [`AuditJournal`](super::AuditJournal) keeps its chain on it, with one owner per journal.
//! The store takes only the record that continues the last one appended, which the
//! stream's state keeps when retention drops its segment. When the last record appended is
//! lost from the stream, no record can be shown to continue it, and the store refuses
//! every record ([`DurableLog::record_lost`]). Revocations never wait on it: the revocation
//! lane touches no storage.

use std::collections::VecDeque;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::audit::{AuditRecord, AuditStore, StoreRefusal};
use super::envelope::{ConfigError, EventEnvelope, EventSequence, ProducerId};
use super::high_water::{HighWater, MarkProblem, Marks};
use super::owner::{
    sync_dir, write_atomic, OwnerError, StreamOwner, Takeover, TEMPORARY_EXTENSION,
};
use super::reconcile::SequenceRange;
use crate::foundation::ids::{Digest, DigestBuilder, Incarnation, OperationId};

const STATE_FILE: &str = "stream.json";
const SEGMENT_PREFIX: &str = "segment-";
const SEGMENT_EXTENSION: &str = "jsonl";
const QUARANTINE_PREFIX: &str = "torn-";
const LINE_DOMAIN: &str = "yougori/events/durable-line/v1";
const INSTANCE_DOMAIN: &str = "yougori/events/durable-stream/v1";
/// 64 hexadecimal digits of the line digest, then one space.
const CHECK_BYTES: usize = 65;

name_type!(
    /// One durable stream, such as `engine.audit` or `warden.audit`.
    DurableStreamId
);

/// Which stream a sequence belongs to: its name and the instance drawn when it was
/// created. A stream deleted and created again is another instance, so a cursor from
/// before is refused instead of being read against new sequences.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamInstance {
    pub stream: DurableStreamId,
    pub instance: Digest,
}

impl StreamInstance {
    pub(super) fn create(stream: DurableStreamId) -> Self {
        let instance = DigestBuilder::new(INSTANCE_DOMAIN)
            .str(stream.as_str())
            .bytes(uuid::Uuid::new_v4().as_bytes())
            .finish();
        Self { stream, instance }
    }
}

impl fmt::Display for StreamInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (instance {})", self.stream, self.instance)
    }
}

/// Bounds of one durable log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogConfig {
    /// Entries retained at most; older ones are dropped, counted and read as a gap.
    pub max_entries: u64,
    /// Bytes retained at most, counting each entry's stored line.
    pub max_bytes: u64,
    /// Entries per segment before the log starts the next one; retention drops whole
    /// segments.
    pub segment_entries: u64,
    /// Bytes per segment before the log starts the next one; also the largest entry.
    pub segment_bytes: u64,
}

impl LogConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        for (setting, value) in [
            ("max_entries", self.max_entries),
            ("max_bytes", self.max_bytes),
            ("segment_entries", self.segment_entries),
            ("segment_bytes", self.segment_bytes),
        ] {
            if value == 0 {
                return Err(ConfigError::Zero { setting });
            }
        }
        if self.segment_entries > self.max_entries {
            return Err(ConfigError::Exceeds {
                setting: "segment_entries",
                limit: "max_entries",
            });
        }
        if self.segment_bytes > self.max_bytes {
            return Err(ConfigError::Exceeds {
                setting: "segment_bytes",
                limit: "max_bytes",
            });
        }
        Ok(())
    }
}

/// One entry of a durable stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum LogEntry<P> {
    /// A record the stream's owner appended.
    Record(P),
    /// What an owner found when it opened the stream.
    Marker(LogMarker),
}

strict_tagged_enum! {
    /// What an owner found when it opened the stream, recorded in the stream itself so
    /// that every reader meets it in order.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum LogMarker (tag = "kind", wire = LogMarkerWire, wire_name = "LogMarkerWire") {
        /// The previous owner stopped without releasing the stream, such as a crashed
        /// process. Everything it made durable is kept; nothing it had not is.
        StaleOwner { owner: ProducerId, incarnation: Incarnation },
        /// The stream ended in a line that is incomplete or does not verify: an append
        /// that never completed, or an entry damaged since. Its `bytes` were moved to the
        /// file `quarantine` in the stream's directory, and the line was cut off. Its
        /// sequence is in the [`LogMarker::Truncated`] entry before this one.
        TornTail { bytes: u64, quarantine: String },
        /// Sequences the stream used are gone from its end: entries an owner acknowledged,
        /// and the line of a torn tail. The stream continues after them, so they are never
        /// used again.
        Truncated { missing: SequenceRange },
        /// The stream's owner record was missing, so who owned the stream last, and whether
        /// it released it, is unknown. `last_owner` is the latest owner incarnation the
        /// stream and the kept owner records show; the new owner continues after it, and
        /// after every sequence the stream shows used.
        OwnerRecordLost { last_owner: Option<Incarnation> },
    }
}

/// Why a reader will never get some sequences.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapReason {
    /// Retention dropped them, and counted them.
    Retention,
    /// They were lost from the end of the stream, or burned with a torn tail; a
    /// [`LogMarker::Truncated`] entry recorded it.
    Truncated,
}

/// One item of a read, in sequence order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadItem<P> {
    /// One retained entry and the owner incarnation that appended it.
    Entry {
        sequence: EventSequence,
        owner: Incarnation,
        entry: LogEntry<P>,
    },
    /// Sequences the reader will never get, and why; never skipped silently.
    Gap {
        missing: SequenceRange,
        reason: GapReason,
    },
}

/// Where a reader stands in one stream: after `after`, or before everything when `None`.
/// A reader keeps the cursor of its last batch and resumes from it after a reconnect.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogCursor {
    pub stream: StreamInstance,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<EventSequence>,
}

/// What one read returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadBatch<P> {
    pub items: Vec<ReadItem<P>>,
    /// The cursor to resume from: after the last item.
    pub cursor: LogCursor,
    /// Whether the batch reached the end of the stream.
    pub caught_up: bool,
}

/// Why a cursor cannot be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CursorError {
    /// The cursor belongs to another stream, or to an earlier instance of this one.
    WrongStream {
        expected: StreamInstance,
        found: StreamInstance,
    },
    /// The cursor is past the last sequence the stream reached.
    Future {
        after: EventSequence,
        last: Option<EventSequence>,
    },
}

impl fmt::Display for CursorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongStream { expected, found } => {
                write!(f, "the cursor belongs to {found}, not {expected}")
            }
            Self::Future {
                after,
                last: Some(last),
            } => write!(
                f,
                "the cursor is after sequence {after}, but the stream ends at {last}"
            ),
            Self::Future { after, last: None } => write!(
                f,
                "the cursor is after sequence {after}, but the stream is empty"
            ),
        }
    }
}

impl std::error::Error for CursorError {}

/// What retention removed and keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retention {
    /// The retention low-water mark: every sequence up to here was dropped. `None` while
    /// nothing was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub low_water: Option<EventSequence>,
    pub retained_entries: u64,
    pub retained_bytes: u64,
    /// Entries dropped over the stream's life, persisted across restarts.
    pub dropped_entries: u64,
    pub dropped_bytes: u64,
}

/// Counts of what this log did since it was opened.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogTotals {
    pub records: u64,
    pub markers: u64,
    /// Appends refused by storage; none used a sequence.
    pub failed_appends: u64,
    pub segments_started: u64,
    /// Times retention could not persist its low-water mark and kept the segment.
    pub retention_failures: u64,
    /// Times the owner record could not take the durable sequence at a segment's start.
    pub checkpoint_failures: u64,
    /// Dropped segment files that could not be removed; the next open removes them.
    pub leftover_files: u64,
}

/// What opening a log found and did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenReport {
    pub takeover: Takeover,
    /// Whether this open created the stream.
    pub created: bool,
    /// The markers this open appended, in order, with their sequences.
    pub markers: Vec<(EventSequence, LogMarker)>,
    /// Dropped segments a crash had left behind, removed now.
    pub leftover_segments: u64,
    /// The torn last line this open quarantined, if it found one, and whether an append
    /// may have acknowledged it.
    pub torn_tail: Option<TornTailFound>,
}

/// A torn last line an open quarantined and recorded with a [`LogMarker::TornTail`] entry,
/// and whether it may have held an acknowledged entry. Every append syncs the high-water
/// mark before it returns its sequence, so only a sequence up to the synced mark was ever
/// acknowledged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TornTailFound {
    /// The sequence of the [`LogMarker::TornTail`] entry that records it.
    pub marker: EventSequence,
    /// The highest sequence the synced high-water mark acknowledged when the open found
    /// the line.
    pub synced_through: Option<EventSequence>,
    /// Whether the line lay past the synced mark: whole lines, or retention, account for
    /// every sequence up to the mark, so the line's append never returned a sequence and
    /// nothing acknowledged was lost with it; the [`LogMarker::Truncated`] entry of the
    /// same open then covers only the sequence the line burned. When `false`, sequences up
    /// to the mark have no whole line, and the torn line may be an entry an append
    /// acknowledged: a caller that must not lose one fails closed.
    pub past_synced_mark: bool,
}

/// What is wrong with one stored line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineProblem {
    /// The line's digest is missing or does not match.
    Checksum,
    /// The line does not decode as an entry of this stream.
    Encoding,
    /// The line has no end before its segment does.
    Unterminated,
    /// The line's sequence does not follow the one before it, and no truncation marker
    /// accounts for the difference.
    Sequence {
        expected: EventSequence,
        found: EventSequence,
    },
    /// An earlier owner's line follows a later owner's: two writers shared the stream.
    OwnerOrder {
        previous: Incarnation,
        found: Incarnation,
    },
    /// The line claims an owner incarnation no earlier owner had.
    UnknownOwner { found: Incarnation },
}

impl fmt::Display for LineProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Checksum => f.write_str("its digest does not match"),
            Self::Encoding => f.write_str("it is not an entry of this stream"),
            Self::Unterminated => f.write_str("it has no end"),
            Self::Sequence { expected, found } => {
                write!(f, "it carries sequence {found} where {expected} was due")
            }
            Self::OwnerOrder { previous, found } => write!(
                f,
                "owner incarnation {found} wrote it after incarnation {previous}"
            ),
            Self::UnknownOwner { found } => {
                write!(f, "no earlier owner had incarnation {found}")
            }
        }
    }
}

/// Damage an interrupted append cannot explain. The log refuses to open, or the read
/// fails, rather than guess: fail closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogDamage {
    /// Segments exist, but the stream's state file does not.
    StateMissing,
    /// Segments exist, but the stream's high-water mark does not, so entries lost from the
    /// end of the stream could not be told from entries never written.
    HighWaterMissing,
    /// The high-water mark file does not have its length.
    HighWaterLength { found: u64 },
    /// Neither slot of the high-water mark verifies.
    HighWaterSpoiled,
    /// The directory holds another stream.
    OtherStream { found: StreamInstance },
    /// Line `line` (from 1) of the segment starting at `segment` is not the entry it should
    /// be, and it is not the last line of the stream.
    Line {
        segment: EventSequence,
        line: u64,
        problem: LineProblem,
    },
    /// A segment's name does not match its first entry.
    SegmentName {
        segment: EventSequence,
        first: EventSequence,
    },
    /// A retained entry no longer verifies: its file changed after the log was opened.
    Entry {
        sequence: EventSequence,
        problem: LineProblem,
    },
}

impl fmt::Display for LogDamage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StateMissing => f.write_str("segments exist without the stream's state file"),
            Self::HighWaterMissing => {
                f.write_str("segments exist without the stream's high-water mark")
            }
            Self::HighWaterLength { found } => {
                write!(f, "the high-water mark file holds {found} bytes")
            }
            Self::HighWaterSpoiled => f.write_str("neither slot of the high-water mark verifies"),
            Self::OtherStream { found } => write!(f, "the directory holds {found}"),
            Self::Line {
                segment,
                line,
                problem,
            } => write!(
                f,
                "line {line} of the segment starting at {segment} is damaged: {problem}"
            ),
            Self::SegmentName { segment, first } => write!(
                f,
                "the segment named {segment} starts with sequence {first}"
            ),
            Self::Entry { sequence, problem } => {
                write!(f, "entry {sequence} changed on disk: {problem}")
            }
        }
    }
}

/// Why a log could not be opened, appended to or read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogError {
    Config(ConfigError),
    Owner(OwnerError),
    Damaged(LogDamage),
    Cursor(CursorError),
    Io {
        action: &'static str,
        kind: io::ErrorKind,
        message: String,
    },
    /// The entry's line is longer than a segment may be.
    TooLarge {
        bytes: u64,
        limit: u64,
    },
    Encoding {
        message: String,
    },
    /// The stream used its last sequence.
    SequenceExhausted,
    /// An append failed and could not be cut back off. The log takes no appends until it
    /// is opened again, which quarantines the torn line.
    Poisoned,
}

impl LogError {
    pub(super) fn io(action: &'static str, error: &io::Error) -> Self {
        Self::Io {
            action,
            kind: error.kind(),
            message: error.to_string(),
        }
    }

    /// The refusal an audit journal sees for this error.
    pub fn store_refusal(&self) -> StoreRefusal {
        match self {
            Self::Io {
                kind: io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded,
                ..
            } => StoreRefusal::Full,
            Self::Io {
                kind: io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock,
                ..
            } => StoreRefusal::Slow,
            _ => StoreRefusal::Failed,
        }
    }
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(f, "{error}"),
            Self::Owner(error) => write!(f, "{error}"),
            Self::Damaged(damage) => write!(f, "the durable stream is damaged: {damage}"),
            Self::Cursor(error) => write!(f, "{error}"),
            Self::Io {
                action, message, ..
            } => write!(f, "could not {action}: {message}"),
            Self::TooLarge { bytes, limit } => write!(
                f,
                "the entry takes {bytes} bytes; a segment holds at most {limit}"
            ),
            Self::Encoding { message } => write!(f, "the entry could not be encoded: {message}"),
            Self::SequenceExhausted => f.write_str("the durable stream used its last sequence"),
            Self::Poisoned => f.write_str(
                "an append could not be undone; open the stream again to recover its tail",
            ),
        }
    }
}

impl std::error::Error for LogError {}

/// Records that belong to an operation, by the envelope identity they carry (CORE-06
/// operation identity).
pub trait Correlated {
    fn operation(&self) -> &OperationId;
}

impl<P> Correlated for EventEnvelope<P> {
    fn operation(&self) -> &OperationId {
        EventEnvelope::operation(self)
    }
}

impl Correlated for AuditRecord {
    fn operation(&self) -> &OperationId {
        self.event().operation()
    }
}

/// One operation's retained records, and what the stream lost that may have held more.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Correlation<P> {
    pub records: Vec<(EventSequence, P)>,
    /// Every gap of the stream before its end; records of the operation may have been
    /// there.
    pub gaps: Vec<(SequenceRange, GapReason)>,
}

/// The persisted state of a stream: its identity, what retention dropped, and the last
/// record when retention dropped it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StateFile {
    pub(super) stream: StreamInstance,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) dropped_through: Option<EventSequence>,
    dropped_entries: u64,
    dropped_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_record: Option<KeptRecord>,
}

/// The last record appended as of a retention pass, kept in the state before its segment
/// can go, so the audit store's continuity check never depends on what retention kept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeptRecord {
    sequence: EventSequence,
    record: serde_json::Value,
}

/// One line as stored.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredLine<P> {
    pub(super) sequence: EventSequence,
    pub(super) owner: Incarnation,
    entry: LogEntry<P>,
}

/// One line as written; the same fields as [`StoredLine`].
#[derive(Serialize)]
struct LineRef<'a, P> {
    sequence: EventSequence,
    owner: Incarnation,
    entry: &'a LogEntry<P>,
}

/// One segment file.
#[derive(Clone, Copy, Debug)]
struct Segment {
    first: EventSequence,
    /// The last line's sequence, retained or not.
    last: Option<EventSequence>,
    /// Retained entries and their bytes.
    entries: u64,
    bytes: u64,
    /// The file's length: where the next line goes.
    length: u64,
}

/// Where one retained entry is.
#[derive(Clone, Copy, Debug)]
pub(super) struct IndexEntry {
    pub(super) sequence: EventSequence,
    pub(super) segment: EventSequence,
    pub(super) offset: u64,
    pub(super) length: u64,
}

/// A torn last line found while opening.
struct Torn {
    segment: PathBuf,
    offset: u64,
    bytes: Vec<u8>,
}

/// A failure the tests inject into the next append.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(super) enum WriteFault {
    /// Half the line is written, then the append fails as `kind`; the half is cut back off.
    Partial(io::ErrorKind),
    /// As `Partial`, and cutting the half back off fails too.
    Unrecoverable,
    /// The whole line is written, then the high-water mark cannot be, as `kind`.
    HighWater(io::ErrorKind),
}

/// One durable stream, owned by this process (CORE-06; S06).
#[derive(Debug)]
pub struct DurableLog<P> {
    owner: StreamOwner,
    stream: StreamInstance,
    config: LogConfig,
    state: StateFile,
    high_water: HighWater,
    segments: VecDeque<Segment>,
    index: VecDeque<IndexEntry>,
    /// The last segment's file, open while it takes entries.
    active: Option<File>,
    /// `None` once the stream used its last sequence.
    next: Option<EventSequence>,
    /// The last record known and its sequence, for the audit store's continuity check.
    last_record: Option<(EventSequence, P)>,
    /// The last record appended is gone from the stream: `last_record` is an earlier one.
    record_lost: bool,
    poisoned: bool,
    totals: LogTotals,
    #[cfg(test)]
    fault: Option<WriteFault>,
}

impl<P: Serialize + DeserializeOwned + Clone> DurableLog<P> {
    /// Takes ownership of the stream `stream` in `directory` for `owner`, creating it if
    /// the directory holds none, and recovers it as the module documentation describes.
    /// Refuses while any owner, in this process or another, holds it.
    pub fn open(
        directory: &Path,
        stream: DurableStreamId,
        owner: ProducerId,
        config: LogConfig,
    ) -> Result<(Self, OpenReport), LogError> {
        config.validate().map_err(LogError::Config)?;
        let (owner, takeover) = StreamOwner::acquire(directory, owner).map_err(LogError::Owner)?;
        // An open refused before it wrote an entry leaves the owner record as it found it,
        // so refusals never raise the incarnation or wear away the durable sequence. One
        // that wrote an entry under its incarnation leaves the stream unreleased, and the
        // next owner recovers it as after a stale owner.
        let prepared = match prepare(owner.directory(), stream) {
            Ok(prepared) => prepared,
            Err(error) => {
                owner.withdraw(&takeover);
                return Err(error);
            }
        };
        // A stream without its owner record lost the record.
        let takeover = match takeover {
            Takeover::Fresh if !prepared.created => Takeover::Lost { kept: None },
            takeover => takeover,
        };
        let Prepared {
            state,
            created,
            listing,
            high_water,
        } = prepared;
        let mut log = Self {
            owner,
            stream: state.stream.clone(),
            config,
            state,
            high_water,
            segments: VecDeque::new(),
            index: VecDeque::new(),
            active: None,
            next: Some(EventSequence::FIRST),
            last_record: None,
            record_lost: false,
            poisoned: false,
            totals: LogTotals::default(),
            #[cfg(test)]
            fault: None,
        };
        match log.recover(&takeover, created, &listing) {
            Ok(report) => Ok((log, report)),
            Err(error) => {
                let wrote = log.totals.markers > 0;
                let Self { owner, .. } = log;
                if wrote {
                    owner.abandon();
                } else {
                    owner.withdraw(&takeover);
                }
                Err(error)
            }
        }
    }

    /// Verifies and indexes the stream, records what the previous owner left as markers,
    /// and continues the sequence after everything any owner used.
    fn recover(
        &mut self,
        takeover: &Takeover,
        created: bool,
        listing: &Listing,
    ) -> Result<OpenReport, LogError> {
        // Without its owner record, the stream itself shows which owners wrote it.
        let lost = matches!(takeover, Takeover::Lost { .. });
        let scan = self.scan(&listing.segments, lost)?;
        if let Some(latest) = scan.max_owner.filter(|_| lost) {
            let above = latest
                .next()
                .ok_or(LogError::Owner(OwnerError::IncarnationExhausted))?;
            self.owner.raise(above).map_err(LogError::Owner)?;
        }
        let marks = self.high_water.marks();
        self.settle_last_record(marks)?;
        // Past everything on disk, everything dropped, everything acknowledged and
        // everything any owner recorded durable; past a torn line too, which may have been
        // acknowledged, or held the sequence after all of them: no sequence is used twice.
        let reached = scan.last.max(self.state.dropped_through);
        // A torn line comes after every whole line, so it lies past the synced mark when
        // those lines, or retention, reach the mark and everything recorded durable.
        let past_synced_mark = marks.through.max(self.owner.record().durable_through) <= reached;
        let mut used = reached
            .max(marks.through)
            .max(self.owner.record().durable_through);
        if scan.torn.is_some() {
            used = Some(after(used).ok_or(LogError::SequenceExhausted)?);
        }
        // Persisted before anything else changes, so that whatever fails from here on,
        // these sequences are never given out again.
        if used > marks.through {
            self.record_high_water(Marks {
                through: used,
                last_record: marks.last_record,
            })
            .map_err(|error| LogError::io("record the high-water mark", &error))?;
        }
        let mut report = OpenReport {
            takeover: takeover.clone(),
            created,
            markers: Vec::new(),
            leftover_segments: scan.leftover,
            torn_tail: None,
        };
        let quarantined = match &scan.torn {
            Some(torn) => Some(self.quarantine(torn)?),
            None => None,
        };
        let mut markers = Vec::new();
        if let Some(missing) = after(reached)
            .zip(used)
            .and_then(|(first, last)| SequenceRange::new(first, last))
        {
            markers.push(LogMarker::Truncated { missing });
        }
        self.next = after(used);
        match takeover {
            Takeover::Stale { previous } => markers.push(LogMarker::StaleOwner {
                owner: previous.owner.clone(),
                incarnation: previous.incarnation,
            }),
            Takeover::Lost { kept } => markers.push(LogMarker::OwnerRecordLost {
                last_owner: scan
                    .max_owner
                    .max(kept.as_ref().map(|kept| kept.incarnation)),
            }),
            Takeover::Fresh | Takeover::Released { .. } => {}
        }
        if let Some((bytes, quarantine)) = quarantined {
            markers.push(LogMarker::TornTail { bytes, quarantine });
        }
        self.reopen_last()?;
        for marker in markers {
            let sequence = self.write(LogEntry::Marker(marker.clone()))?;
            if matches!(marker, LogMarker::TornTail { .. }) {
                report.torn_tail = Some(TornTailFound {
                    marker: sequence,
                    synced_through: marks.through,
                    past_synced_mark,
                });
            }
            report.markers.push((sequence, marker));
        }
        self.enforce_retention();
        if let Some(last) = self.last() {
            self.owner.advance(last);
        }
        self.owner.checkpoint().map_err(LogError::Owner)?;
        Ok(report)
    }

    /// Appends `record` and returns its sequence once it is durable. A refusal uses no
    /// sequence and leaves nothing of the record in storage.
    pub fn append(&mut self, record: P) -> Result<EventSequence, LogError> {
        self.write(LogEntry::Record(record))
    }

    /// Reads at most `max_items` items after `cursor`: the retained entries in order, with
    /// a gap item wherever sequences are gone. Refuses a cursor of another stream or past
    /// the last sequence.
    pub fn read(&self, cursor: &LogCursor, max_items: usize) -> Result<ReadBatch<P>, LogError> {
        if cursor.stream != self.stream {
            return Err(LogError::Cursor(CursorError::WrongStream {
                expected: self.stream.clone(),
                found: cursor.stream.clone(),
            }));
        }
        let last = self.last();
        if let Some(after) = cursor.after {
            if last.is_none_or(|last| after > last) {
                return Err(LogError::Cursor(CursorError::Future { after, last }));
            }
        }
        let (items, reached) = read_items(
            self.owner.directory(),
            &self.stream,
            &self.index,
            self.state.dropped_through,
            cursor.after,
            last,
            max_items,
        )?;
        Ok(ReadBatch {
            items,
            caught_up: reached == last,
            cursor: LogCursor {
                stream: self.stream.clone(),
                after: reached,
            },
        })
    }

    /// The cursor before every entry.
    pub fn start(&self) -> LogCursor {
        LogCursor {
            stream: self.stream.clone(),
            after: None,
        }
    }

    /// The cursor after the last entry, for a reader that wants only what comes next.
    pub fn end(&self) -> LogCursor {
        LogCursor {
            stream: self.stream.clone(),
            after: self.last(),
        }
    }

    /// The last sequence the stream used.
    pub fn last(&self) -> Option<EventSequence> {
        match self.next {
            Some(next) => next.previous(),
            None => EventSequence::new(u64::MAX),
        }
    }

    pub fn stream(&self) -> &StreamInstance {
        &self.stream
    }

    pub fn owner(&self) -> &StreamOwner {
        &self.owner
    }

    pub fn retention(&self) -> Retention {
        Retention {
            low_water: self.state.dropped_through,
            retained_entries: self.retained_entries(),
            retained_bytes: self.retained_bytes(),
            dropped_entries: self.state.dropped_entries,
            dropped_bytes: self.state.dropped_bytes,
        }
    }

    pub fn totals(&self) -> LogTotals {
        self.totals
    }

    /// Whether the last record appended is gone from the stream, cut off with its end or
    /// quarantined as a torn tail. The last record still held is an earlier one, so no
    /// record can be shown to continue the stream's records; the audit store refuses them.
    pub fn record_lost(&self) -> bool {
        self.record_lost
    }

    /// Releases the stream: its owner record says how far it is durable and that it was
    /// left cleanly.
    pub fn close(self) -> Result<(), LogError> {
        let Self { owner, .. } = self;
        owner.release().map_err(LogError::Owner)
    }

    /// Gives the stream up as a crashing process would: no release is recorded.
    #[cfg(test)]
    pub(super) fn crash(self) {
        let Self { owner, .. } = self;
        owner.abandon();
    }

    #[cfg(test)]
    pub(super) fn inject(&mut self, fault: WriteFault) {
        self.fault = Some(fault);
    }

    fn write(&mut self, entry: LogEntry<P>) -> Result<EventSequence, LogError> {
        if self.poisoned {
            return Err(LogError::Poisoned);
        }
        let sequence = self.next.ok_or(LogError::SequenceExhausted)?;
        let line = encode_line(&self.stream, sequence, self.owner.incarnation(), &entry)?;
        let length = u64::try_from(line.len()).unwrap_or(u64::MAX);
        if length > self.config.segment_bytes {
            return Err(LogError::TooLarge {
                bytes: length,
                limit: self.config.segment_bytes,
            });
        }
        let written = self.prepare_segment(sequence, length).and_then(|()| {
            let offset = self.segments.back().map_or(0, |segment| segment.length);
            self.write_line(offset, &line)
                .map_err(|error| LogError::io("append to the durable stream", &error))
                .map(|()| offset)
        });
        let offset = match written {
            Ok(offset) => offset,
            Err(error) => {
                self.totals.failed_appends = self.totals.failed_appends.saturating_add(1);
                return Err(error);
            }
        };
        // The mark is persisted before the sequence is returned, so a later open finds any
        // acknowledged entry the segments lose. Without it the entry is not acknowledged,
        // and it is cut back off as a failed write is.
        let marks = Marks {
            through: Some(sequence),
            last_record: match &entry {
                LogEntry::Record(_) => Some(sequence),
                LogEntry::Marker(_) => self.high_water.marks().last_record,
            },
        };
        if let Err(error) = self.record_high_water(marks) {
            if !self
                .active
                .as_ref()
                .is_some_and(|file| cut_back(file, offset))
            {
                self.poisoned = true;
            }
            self.totals.failed_appends = self.totals.failed_appends.saturating_add(1);
            return Err(LogError::io("record the high-water mark", &error));
        }
        if let Some(segment) = self.segments.back_mut() {
            segment.last = Some(sequence);
            segment.entries = segment.entries.saturating_add(1);
            segment.bytes = segment.bytes.saturating_add(length);
            segment.length = segment.length.saturating_add(length);
            self.index.push_back(IndexEntry {
                sequence,
                segment: segment.first,
                offset,
                length,
            });
        }
        self.next = sequence.next();
        self.owner.advance(sequence);
        match entry {
            LogEntry::Record(record) => {
                self.last_record = Some((sequence, record));
                self.record_lost = false;
                self.totals.records = self.totals.records.saturating_add(1);
            }
            LogEntry::Marker(_) => self.totals.markers = self.totals.markers.saturating_add(1),
        }
        self.enforce_retention();
        Ok(sequence)
    }

    /// Writes `line` at `offset` of the open segment and syncs it. On failure the line is
    /// cut back off; if that fails too, the log is poisoned.
    fn write_line(&mut self, offset: u64, line: &[u8]) -> io::Result<()> {
        #[cfg(test)]
        {
            if let Some(fault @ (WriteFault::Partial(_) | WriteFault::Unrecoverable)) = self.fault {
                self.fault = None;
                return self.fail_write(offset, line, fault);
            }
        }
        let Some(file) = self.active.as_mut() else {
            return Err(io::Error::other("no segment is open"));
        };
        let written = write_at(file, offset, line);
        if written.is_err() && !cut_back(file, offset) {
            self.poisoned = true;
        }
        written
    }

    #[cfg(test)]
    fn fail_write(&mut self, offset: u64, line: &[u8], fault: WriteFault) -> io::Result<()> {
        let Some(file) = self.active.as_mut() else {
            return Err(io::Error::other("no segment is open"));
        };
        let half = line.get(..line.len() / 2).unwrap_or_default();
        write_at(file, offset, half)?;
        match fault {
            WriteFault::Partial(kind) => {
                if !cut_back(file, offset) {
                    self.poisoned = true;
                }
                Err(io::Error::from(kind))
            }
            WriteFault::Unrecoverable => {
                self.poisoned = true;
                Err(io::Error::other("the device stopped answering"))
            }
            WriteFault::HighWater(kind) => Err(io::Error::from(kind)),
        }
    }

    fn record_high_water(&mut self, marks: Marks) -> io::Result<()> {
        #[cfg(test)]
        {
            if let Some(WriteFault::HighWater(kind)) = self.fault {
                self.fault = None;
                return Err(io::Error::from(kind));
            }
        }
        self.high_water.record(&self.stream, marks)
    }

    /// Settles the last record known: the later of the last one retained and the one the
    /// state kept when retention dropped it. The last record appended is lost when the
    /// high-water mark names a later one than both.
    fn settle_last_record(&mut self, marks: Marks) -> Result<(), LogError> {
        if let Some(kept) = &self.state.last_record {
            let later = self
                .last_record
                .as_ref()
                .is_none_or(|(sequence, _)| *sequence < kept.sequence);
            if later {
                let record =
                    serde_json::from_value(kept.record.clone()).map_err(|error| LogError::Io {
                        action: "read the stream state",
                        kind: io::ErrorKind::InvalidData,
                        message: error.to_string(),
                    })?;
                self.last_record = Some((kept.sequence, record));
            }
        }
        self.record_lost =
            marks.last_record > self.last_record.as_ref().map(|(sequence, _)| *sequence);
        Ok(())
    }

    /// Makes sure an open segment has room for a line of `length` bytes, starting the next
    /// segment at `sequence` when the last one is full or closed. Starting one persists the
    /// durable sequence in the owner record first.
    fn prepare_segment(&mut self, sequence: EventSequence, length: u64) -> Result<(), LogError> {
        let room = self.active.is_some()
            && self.segments.back().is_some_and(|segment| {
                segment.entries < self.config.segment_entries
                    && segment.length.saturating_add(length) <= self.config.segment_bytes
            });
        if room {
            return Ok(());
        }
        self.active = None;
        if self.owner.checkpoint().is_err() {
            self.totals.checkpoint_failures = self.totals.checkpoint_failures.saturating_add(1);
        }
        let directory = self.owner.directory();
        let path = segment_path(directory, sequence);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| LogError::io("start a segment", &error))?;
        // The file exists from here on, so it is the segment the next attempt writes to,
        // whether or not its directory entry could be flushed yet.
        self.segments.push_back(Segment {
            first: sequence,
            last: None,
            entries: 0,
            bytes: 0,
            length: 0,
        });
        self.active = Some(file);
        self.totals.segments_started = self.totals.segments_started.saturating_add(1);
        sync_dir(self.owner.directory()).map_err(|error| LogError::io("start a segment", &error))
    }

    /// Drops whole segments, oldest first and never the last, until the retained entries
    /// and bytes are within bounds. The low-water mark and counts are persisted before a
    /// file is removed; if they cannot be, the segment stays.
    fn enforce_retention(&mut self) {
        while self.segments.len() > 1
            && (self.retained_entries() > self.config.max_entries
                || self.retained_bytes() > self.config.max_bytes)
        {
            let Some(oldest) = self.segments.front().copied() else {
                break;
            };
            if let Some(last) = oldest.last {
                // The last record goes into the state before its segment can go.
                let kept = match &self.last_record {
                    Some((sequence, record)) => match serde_json::to_value(record) {
                        Ok(record) => Some(KeptRecord {
                            sequence: *sequence,
                            record,
                        }),
                        Err(_) => {
                            self.totals.retention_failures =
                                self.totals.retention_failures.saturating_add(1);
                            return;
                        }
                    },
                    None => self.state.last_record.clone(),
                };
                let state = StateFile {
                    stream: self.stream.clone(),
                    dropped_through: self.state.dropped_through.max(Some(last)),
                    dropped_entries: self.state.dropped_entries.saturating_add(oldest.entries),
                    dropped_bytes: self.state.dropped_bytes.saturating_add(oldest.bytes),
                    last_record: kept,
                };
                if write_state(self.owner.directory(), &state).is_err() {
                    self.totals.retention_failures =
                        self.totals.retention_failures.saturating_add(1);
                    return;
                }
                self.state = state;
                while self
                    .index
                    .front()
                    .is_some_and(|entry| entry.sequence <= last)
                {
                    self.index.pop_front();
                }
            }
            self.segments.pop_front();
            if fs::remove_file(segment_path(self.owner.directory(), oldest.first)).is_err() {
                self.totals.leftover_files = self.totals.leftover_files.saturating_add(1);
            }
        }
    }

    fn retained_entries(&self) -> u64 {
        self.segments
            .iter()
            .fold(0, |sum, segment| sum.saturating_add(segment.entries))
    }

    fn retained_bytes(&self) -> u64 {
        self.segments
            .iter()
            .fold(0, |sum, segment| sum.saturating_add(segment.bytes))
    }

    /// Verifies every segment in order and indexes the retained entries. Returns the last
    /// sequence on disk, the latest owner incarnation, a torn last line and the count of
    /// dropped segments removed. Without the owner record (`record_lost`), entries of any
    /// incarnation are taken; the owner then raises its own past them.
    fn scan(
        &mut self,
        files: &[(EventSequence, PathBuf)],
        record_lost: bool,
    ) -> Result<Scan, LogError> {
        let dropped = self.state.dropped_through;
        let current = Some(self.owner.incarnation()).filter(|_| !record_lost);
        let mut previous: Option<(EventSequence, Incarnation)> = None;
        let mut torn = None;
        let mut leftover = 0u64;
        for (position, (first, path)) in files.iter().enumerate() {
            let is_last = position + 1 == files.len();
            let bytes = fs::read(path).map_err(|error| LogError::io("read a segment", &error))?;
            if bytes.is_empty() {
                // A segment started for an append that failed: it holds nothing.
                let _ = fs::remove_file(path);
                continue;
            }
            let mut segment = Segment {
                first: *first,
                last: None,
                entries: 0,
                bytes: 0,
                length: 0,
            };
            let mut offset = 0usize;
            let mut line_number = 0u64;
            while let Some(rest) = bytes.get(offset..).filter(|rest| !rest.is_empty()) {
                line_number = line_number.saturating_add(1);
                let (consumed, decoded) = match rest.iter().position(|byte| *byte == b'\n') {
                    Some(end) => (
                        end + 1,
                        decode_line::<P>(&self.stream, rest.get(..end).unwrap_or_default()),
                    ),
                    None => (rest.len(), Err(LineProblem::Unterminated)),
                };
                let at_end = offset + consumed == bytes.len();
                let checked = decoded.and_then(|stored| {
                    check_order(previous, &stored, dropped, current)?;
                    Ok(stored)
                });
                // Only an append that never completed can leave a line unterminated or
                // unverified, and only at the very end. A line that verifies was written
                // whole, so a problem with its order is damage wherever it is.
                let incomplete = matches!(
                    checked,
                    Err(LineProblem::Unterminated | LineProblem::Checksum)
                );
                let stored = match checked {
                    Ok(stored) => stored,
                    Err(_) if incomplete && is_last && at_end => {
                        torn = Some(Torn {
                            segment: path.clone(),
                            offset: u64::try_from(offset).unwrap_or(u64::MAX),
                            bytes: rest.to_vec(),
                        });
                        break;
                    }
                    Err(problem) => {
                        return Err(LogError::Damaged(LogDamage::Line {
                            segment: *first,
                            line: line_number,
                            problem,
                        }))
                    }
                };
                if segment.last.is_none() && stored.sequence != *first {
                    return Err(LogError::Damaged(LogDamage::SegmentName {
                        segment: *first,
                        first: stored.sequence,
                    }));
                }
                let length = u64::try_from(consumed).unwrap_or(u64::MAX);
                if dropped.is_none_or(|dropped| stored.sequence > dropped) {
                    self.index.push_back(IndexEntry {
                        sequence: stored.sequence,
                        segment: *first,
                        offset: u64::try_from(offset).unwrap_or(u64::MAX),
                        length,
                    });
                    segment.entries = segment.entries.saturating_add(1);
                    segment.bytes = segment.bytes.saturating_add(length);
                    if let LogEntry::Record(record) = stored.entry {
                        self.last_record = Some((stored.sequence, record));
                    }
                }
                segment.last = Some(stored.sequence);
                previous = Some((stored.sequence, stored.owner));
                offset += consumed;
            }
            segment.length = u64::try_from(offset).unwrap_or(u64::MAX);
            let wholly_dropped = torn.is_none()
                && segment.entries == 0
                && segment
                    .last
                    .is_some_and(|last| dropped.is_some_and(|dropped| last <= dropped));
            if wholly_dropped {
                // Retention dropped it, then a crash kept the file; it was counted then.
                if fs::remove_file(path).is_ok() {
                    leftover = leftover.saturating_add(1);
                }
                continue;
            }
            self.segments.push_back(segment);
        }
        Ok(Scan {
            last: previous.map(|(sequence, _)| sequence),
            max_owner: previous.map(|(_, owner)| owner),
            torn,
            leftover,
        })
    }

    /// Moves a torn line's bytes to a quarantine file and cuts them off their segment.
    /// Returns how many bytes moved and the quarantine file's name.
    fn quarantine(&mut self, torn: &Torn) -> Result<(u64, String), LogError> {
        let directory = self.owner.directory();
        let name = format!("{QUARANTINE_PREFIX}{}.bin", self.owner.incarnation());
        let path = directory.join(&name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| LogError::io("quarantine a torn tail", &error))?;
        file.write_all(&torn.bytes)
            .and_then(|()| file.sync_all())
            .and_then(|()| sync_dir(directory))
            .map_err(|error| LogError::io("quarantine a torn tail", &error))?;
        OpenOptions::new()
            .write(true)
            .open(&torn.segment)
            .and_then(|segment| {
                segment.set_len(torn.offset)?;
                segment.sync_all()
            })
            .map_err(|error| LogError::io("cut off a torn tail", &error))?;
        if let Some(segment) = self.segments.back_mut() {
            segment.length = torn.offset;
        }
        Ok((u64::try_from(torn.bytes.len()).unwrap_or(u64::MAX), name))
    }

    /// Opens the last segment for further entries, or removes it when it holds none, so
    /// that every segment's first entry is the one its name gives.
    fn reopen_last(&mut self) -> Result<(), LogError> {
        let Some(last) = self.segments.back().copied() else {
            return Ok(());
        };
        let path = segment_path(self.owner.directory(), last.first);
        if last.length == 0 {
            self.segments.pop_back();
            return fs::remove_file(&path)
                .map_err(|error| LogError::io("remove an empty segment", &error));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|error| LogError::io("open the last segment", &error))?;
        self.active = Some(file);
        Ok(())
    }
}

impl<P: Correlated + Serialize + DeserializeOwned + Clone> DurableLog<P> {
    /// The retained records of `operation`, in order, and the stream's gaps, where earlier
    /// records of it may have been (CORE-06 operation identity; VM-W44 incident
    /// reconstruction).
    pub fn correlate(&self, operation: &OperationId) -> Result<Correlation<P>, LogError> {
        let batch = self.read(&self.start(), usize::MAX)?;
        Ok(correlation_of(operation, batch.items))
    }
}

/// The records of `operation` among `items`, in order, and every gap among them.
pub(super) fn correlation_of<P: Correlated>(
    operation: &OperationId,
    items: Vec<ReadItem<P>>,
) -> Correlation<P> {
    let mut correlation = Correlation {
        records: Vec::new(),
        gaps: Vec::new(),
    };
    for item in items {
        match item {
            ReadItem::Entry {
                sequence,
                entry: LogEntry::Record(record),
                ..
            } if record.operation() == operation => {
                correlation.records.push((sequence, record));
            }
            ReadItem::Gap { missing, reason } => correlation.gaps.push((missing, reason)),
            ReadItem::Entry { .. } => {}
        }
    }
    correlation
}

impl AuditStore for DurableLog<AuditRecord> {
    /// Stores `record` after the last record stored, which it must continue: the next
    /// sequence of the same journal, naming that record's digest. A record already stored
    /// is `Ok` and stores nothing; any other record is refused, and every record is while
    /// the last record appended is lost ([`DurableLog::record_lost`]).
    fn append(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        if self.record_lost {
            return Err(StoreRefusal::Failed);
        }
        if let Some((_, last)) = &self.last_record {
            if record.sequence() <= last.sequence() {
                return if self.holds(record) {
                    Ok(())
                } else {
                    Err(StoreRefusal::Failed)
                };
            }
            if record.journal() != last.journal()
                || last.sequence().next() != Some(record.sequence())
                || record.previous() != last.digest()
            {
                return Err(StoreRefusal::Failed);
            }
        }
        self.write(LogEntry::Record(record.clone()))
            .map(drop)
            .map_err(|error| error.store_refusal())
    }
}

impl DurableLog<AuditRecord> {
    /// Whether `record` is stored and retained.
    fn holds(&self, record: &AuditRecord) -> bool {
        if self.last_record.as_ref().map(|(_, last)| last) == Some(record) {
            return true;
        }
        self.read(&self.start(), usize::MAX).is_ok_and(|batch| {
            batch.items.iter().any(|item| {
                matches!(item, ReadItem::Entry { entry: LogEntry::Record(stored), .. } if stored == record)
            })
        })
    }
}

/// What a scan found.
struct Scan {
    last: Option<EventSequence>,
    /// The incarnation of the last line, the latest: incarnations never fall along the
    /// stream.
    max_owner: Option<Incarnation>,
    torn: Option<Torn>,
    leftover: u64,
}

/// What opening found in a stream's directory.
struct Prepared {
    state: StateFile,
    created: bool,
    listing: Listing,
    high_water: HighWater,
}

/// A gap item and its last sequence.
struct Gap<P> {
    last: EventSequence,
    item: ReadItem<P>,
}

/// The files of a stream's directory.
pub(super) struct Listing {
    pub(super) segments: Vec<(EventSequence, PathBuf)>,
    temporary: Vec<PathBuf>,
}

/// Reads entries, keeping the last segment file open.
struct SegmentReader<'a> {
    directory: &'a Path,
    open: Option<(EventSequence, File)>,
}

impl<'a> SegmentReader<'a> {
    fn new(directory: &'a Path) -> Self {
        Self {
            directory,
            open: None,
        }
    }

    fn read<P: DeserializeOwned>(
        &mut self,
        stream: &StreamInstance,
        entry: &IndexEntry,
    ) -> Result<StoredLine<P>, LogError> {
        let file = match &mut self.open {
            Some((segment, file)) if *segment == entry.segment => file,
            open => {
                let file = File::open(segment_path(self.directory, entry.segment))
                    .map_err(|error| LogError::io("read a segment", &error))?;
                &mut open.insert((entry.segment, file)).1
            }
        };
        let length = usize::try_from(entry.length).map_err(|_| LogError::Io {
            action: "read a segment",
            kind: io::ErrorKind::InvalidData,
            message: "the entry is longer than this platform can address".to_owned(),
        })?;
        let mut line = vec![0; length];
        file.seek(SeekFrom::Start(entry.offset))
            .and_then(|_| file.read_exact(&mut line))
            .map_err(|error| LogError::io("read a segment", &error))?;
        let damaged = |problem| {
            LogError::Damaged(LogDamage::Entry {
                sequence: entry.sequence,
                problem,
            })
        };
        let body = line
            .strip_suffix(b"\n")
            .ok_or_else(|| damaged(LineProblem::Unterminated))?;
        let stored: StoredLine<P> = decode_line(stream, body).map_err(damaged)?;
        if stored.sequence != entry.sequence {
            return Err(damaged(LineProblem::Sequence {
                expected: entry.sequence,
                found: stored.sequence,
            }));
        }
        Ok(stored)
    }
}

/// Reads at most `max_items` items after `from`: the entries of `index`, verified again as
/// they are read, with a gap item wherever sequences up to `last` are gone. Returns them
/// and the last sequence they reach. The owner's reads and a reader's both go through it.
pub(super) fn read_items<P: DeserializeOwned>(
    directory: &Path,
    stream: &StreamInstance,
    index: &VecDeque<IndexEntry>,
    dropped: Option<EventSequence>,
    from: Option<EventSequence>,
    last: Option<EventSequence>,
    max_items: usize,
) -> Result<(Vec<ReadItem<P>>, Option<EventSequence>), LogError> {
    let mut items = Vec::new();
    let mut reached = from;
    let mut files = SegmentReader::new(directory);
    let start = index.partition_point(|entry| Some(entry.sequence) <= from);
    'entries: for entry in index.range(start..) {
        if items.len() >= max_items {
            break;
        }
        if let Some(gap_end) = entry.sequence.previous() {
            for gap in gaps_in(dropped, after(reached), Some(gap_end)) {
                if items.len() >= max_items {
                    break 'entries;
                }
                reached = Some(gap.last);
                items.push(gap.item);
            }
            if items.len() >= max_items {
                break;
            }
        }
        let stored = files.read(stream, entry)?;
        items.push(ReadItem::Entry {
            sequence: entry.sequence,
            owner: stored.owner,
            entry: stored.entry,
        });
        reached = Some(entry.sequence);
    }
    // Sequences after the last retained entry can only be gone.
    if index
        .back()
        .is_none_or(|entry| reached >= Some(entry.sequence))
    {
        for gap in gaps_in(dropped, after(reached), last) {
            if items.len() >= max_items {
                break;
            }
            reached = Some(gap.last);
            items.push(gap.item);
        }
    }
    Ok((items, reached))
}

/// The gap items for `first` to `last`, split where retention's part, up to `dropped`,
/// ends.
fn gaps_in<P>(
    dropped: Option<EventSequence>,
    first: Option<EventSequence>,
    last: Option<EventSequence>,
) -> Vec<Gap<P>> {
    let (Some(first), Some(last)) = (first, last) else {
        return Vec::new();
    };
    let mut gaps = Vec::new();
    if let Some(dropped) = dropped.filter(|dropped| first <= *dropped) {
        gaps.extend(
            SequenceRange::new(first, last.min(dropped)).map(|missing| Gap {
                last: missing.last(),
                item: ReadItem::Gap {
                    missing,
                    reason: GapReason::Retention,
                },
            }),
        );
    }
    let from = match dropped {
        Some(dropped) if dropped >= first => dropped.next(),
        _ => Some(first),
    };
    gaps.extend(
        from.and_then(|from| SequenceRange::new(from, last))
            .map(|missing| Gap {
                last: missing.last(),
                item: ReadItem::Gap {
                    missing,
                    reason: GapReason::Truncated,
                },
            }),
    );
    gaps
}

/// The sequence after `reached`, or the first.
pub(super) fn after(reached: Option<EventSequence>) -> Option<EventSequence> {
    reached.map_or(Some(EventSequence::FIRST), EventSequence::next)
}

/// Checks that `line` may follow `previous`, the line before it on disk: its owner is no
/// earlier than the previous line's and earlier than the current one, if known, and its
/// sequence is the next one, unless the sequences in between are explained. Retention
/// explains those up to its low-water mark, whose files may be gone; a truncation marker
/// explains exactly the rest.
pub(super) fn check_order<P>(
    previous: Option<(EventSequence, Incarnation)>,
    line: &StoredLine<P>,
    dropped: Option<EventSequence>,
    current: Option<Incarnation>,
) -> Result<(), LineProblem> {
    if current.is_some_and(|current| line.owner >= current) {
        return Err(LineProblem::UnknownOwner { found: line.owner });
    }
    let expected = match previous {
        Some((sequence, owner)) => {
            if line.owner < owner {
                return Err(LineProblem::OwnerOrder {
                    previous: owner,
                    found: line.owner,
                });
            }
            sequence.next()
        }
        None => Some(EventSequence::FIRST),
    };
    let out_of_order = |expected| LineProblem::Sequence {
        expected,
        found: line.sequence,
    };
    let Some(expected) = expected else {
        return Err(out_of_order(line.sequence));
    };
    if line.sequence == expected {
        return Ok(());
    }
    let Some(last_missing) = line
        .sequence
        .previous()
        .filter(|_| line.sequence > expected)
    else {
        return Err(out_of_order(expected));
    };
    if dropped.is_some_and(|dropped| last_missing <= dropped) {
        return Ok(());
    }
    let first_unexplained = match dropped {
        Some(dropped) if dropped >= expected => dropped.next(),
        _ => Some(expected),
    };
    let explained = matches!(
        &line.entry,
        LogEntry::Marker(LogMarker::Truncated { missing })
            if Some(*missing)
                == first_unexplained.and_then(|first| SequenceRange::new(first, last_missing))
    );
    if explained {
        Ok(())
    } else {
        Err(out_of_order(expected))
    }
}

fn line_digest(stream: &StreamInstance, json: &[u8]) -> Digest {
    DigestBuilder::new(LINE_DOMAIN)
        .str(stream.stream.as_str())
        .digest(&stream.instance)
        .bytes(json)
        .finish()
}

fn encode_line<P: Serialize>(
    stream: &StreamInstance,
    sequence: EventSequence,
    owner: Incarnation,
    entry: &LogEntry<P>,
) -> Result<Vec<u8>, LogError> {
    let json = serde_json::to_vec(&LineRef {
        sequence,
        owner,
        entry,
    })
    .map_err(|error| LogError::Encoding {
        message: error.to_string(),
    })?;
    let mut line = Vec::with_capacity(json.len().saturating_add(CHECK_BYTES + 1));
    line.extend_from_slice(line_digest(stream, &json).to_hex().as_bytes());
    line.push(b' ');
    line.extend_from_slice(&json);
    line.push(b'\n');
    Ok(line)
}

/// Decodes one line without its newline.
pub(super) fn decode_line<P: DeserializeOwned>(
    stream: &StreamInstance,
    line: &[u8],
) -> Result<StoredLine<P>, LineProblem> {
    let (Some(check), Some(b' '), Some(json)) = (
        line.get(..CHECK_BYTES - 1),
        line.get(CHECK_BYTES - 1),
        line.get(CHECK_BYTES..),
    ) else {
        return Err(LineProblem::Checksum);
    };
    let check = std::str::from_utf8(check)
        .ok()
        .and_then(|text| Digest::from_hex(text).ok())
        .ok_or(LineProblem::Checksum)?;
    if line_digest(stream, json) != check {
        return Err(LineProblem::Checksum);
    }
    serde_json::from_slice(json).map_err(|_| LineProblem::Encoding)
}

fn write_at(file: &mut File, offset: u64, bytes: &[u8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(bytes)?;
    file.sync_data()
}

/// Cuts `file` back to `length`; whether that worked.
fn cut_back(file: &File, length: u64) -> bool {
    file.set_len(length).and_then(|()| file.sync_all()).is_ok()
}

pub(super) fn segment_path(directory: &Path, first: EventSequence) -> PathBuf {
    directory.join(format!(
        "{SEGMENT_PREFIX}{:020}.{SEGMENT_EXTENSION}",
        first.get()
    ))
}

/// The stream's state, whether this open creates it, its files and its high-water mark. A
/// directory without state or segments becomes a new stream; one with segments but no
/// state or no mark, or with another stream's state, is refused.
fn prepare(directory: &Path, stream: DurableStreamId) -> Result<Prepared, LogError> {
    let listing = list(directory)?;
    for temporary in &listing.temporary {
        let _ = fs::remove_file(temporary);
    }
    let create_mark = |directory: &Path| {
        HighWater::create(directory)
            .map_err(|error| LogError::io("create the high-water mark", &error))
    };
    match read_state(directory)? {
        Some(state) if state.stream.stream == stream => {
            let high_water = match HighWater::open(directory, &state.stream).map_err(mark_damage)? {
                Some(high_water) => high_water,
                None if listing.segments.is_empty() => create_mark(directory)?,
                None => return Err(LogError::Damaged(LogDamage::HighWaterMissing)),
            };
            Ok(Prepared {
                state,
                created: false,
                listing,
                high_water,
            })
        }
        Some(state) => Err(LogError::Damaged(LogDamage::OtherStream {
            found: state.stream,
        })),
        None if listing.segments.is_empty() => {
            // The mark first, so that a stream with state always has one.
            let high_water = create_mark(directory)?;
            let state = StateFile {
                stream: StreamInstance::create(stream),
                dropped_through: None,
                dropped_entries: 0,
                dropped_bytes: 0,
                last_record: None,
            };
            write_state(directory, &state)?;
            Ok(Prepared {
                state,
                created: true,
                listing,
                high_water,
            })
        }
        None => Err(LogError::Damaged(LogDamage::StateMissing)),
    }
}

pub(super) fn mark_damage(problem: MarkProblem) -> LogError {
    match problem {
        MarkProblem::Length { found } => LogError::Damaged(LogDamage::HighWaterLength { found }),
        MarkProblem::Spoiled => LogError::Damaged(LogDamage::HighWaterSpoiled),
        MarkProblem::Io { kind, message } => LogError::Io {
            action: "read the high-water mark",
            kind,
            message,
        },
    }
}

pub(super) fn list(directory: &Path) -> Result<Listing, LogError> {
    let mut listing = Listing {
        segments: Vec::new(),
        temporary: Vec::new(),
    };
    let entries =
        fs::read_dir(directory).map_err(|error| LogError::io("list the stream", &error))?;
    for entry in entries {
        let entry = entry.map_err(|error| LogError::io("list the stream", &error))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if path.extension().and_then(|extension| extension.to_str()) == Some(TEMPORARY_EXTENSION) {
            listing.temporary.push(path.clone());
            continue;
        }
        let first = name
            .strip_prefix(SEGMENT_PREFIX)
            .and_then(|rest| rest.strip_suffix(SEGMENT_EXTENSION))
            .and_then(|rest| rest.strip_suffix('.'))
            .and_then(|digits| digits.parse::<u64>().ok())
            .and_then(EventSequence::new);
        if let Some(first) = first {
            listing.segments.push((first, path));
        }
    }
    listing.segments.sort();
    Ok(listing)
}

pub(super) fn read_state(directory: &Path) -> Result<Option<StateFile>, LogError> {
    let path = directory.join(STATE_FILE);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(LogError::io("read the stream state", &error)),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| LogError::Io {
            action: "read the stream state",
            kind: io::ErrorKind::InvalidData,
            message: error.to_string(),
        })
}

fn write_state(directory: &Path, state: &StateFile) -> Result<(), LogError> {
    let bytes = serde_json::to_vec_pretty(state).map_err(|error| LogError::Encoding {
        message: error.to_string(),
    })?;
    write_atomic(&directory.join(STATE_FILE), &bytes)
        .map_err(|error| LogError::io("write the stream state", &error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::events::envelope::{
        Phase, ProducerCore, ProducerIncarnation, StreamKind,
    };
    use crate::foundation::events::fakes::{context, operation, producer};
    use crate::foundation::events::high_water::HIGH_WATER_FILE;
    use crate::foundation::events::owner::OwnerRecord;
    use crate::foundation::evidence::SourceClass;
    use crate::foundation::ids::MonotonicTime;

    type Event = EventEnvelope<u64>;
    type Log = DurableLog<Event>;

    fn stream_id() -> DurableStreamId {
        DurableStreamId::new("engine.events").unwrap()
    }

    fn config(segment_entries: u64, max_entries: u64) -> LogConfig {
        LogConfig {
            max_entries,
            max_bytes: 1 << 20,
            segment_entries,
            segment_bytes: 1 << 16,
        }
    }

    fn open(directory: &Path, config: LogConfig) -> (Log, OpenReport) {
        DurableLog::open(directory, stream_id(), producer("engine"), config).unwrap()
    }

    fn sequence(value: u64) -> EventSequence {
        EventSequence::new(value).unwrap()
    }

    fn range(first: u64, last: u64) -> SequenceRange {
        SequenceRange::new(sequence(first), sequence(last)).unwrap()
    }

    /// Seals events as one producer in the engine would.
    struct Source(ProducerCore);

    impl Source {
        fn new() -> Self {
            Self(ProducerCore::new(
                producer("loader"),
                ProducerIncarnation::FIRST,
                StreamKind::Progress,
                SourceClass::HostProbe,
            ))
        }

        fn event(&mut self, operation: &str, value: u64) -> Event {
            self.0
                .seal(
                    context(operation, Phase::Loading),
                    MonotonicTime::from_nanos(value),
                    value,
                )
                .unwrap()
        }
    }

    fn append(log: &mut Log, source: &mut Source, count: u64) -> Vec<u64> {
        (0..count)
            .map(|value| log.append(source.event("op-1", value)).unwrap().get())
            .collect()
    }

    /// What a read shows, compactly.
    #[derive(Debug, PartialEq, Eq)]
    enum Seen {
        Record(u64),
        Marker(u64, &'static str),
        Gap(u64, u64, GapReason),
    }

    fn seen(items: &[ReadItem<Event>]) -> Vec<Seen> {
        items
            .iter()
            .map(|item| match item {
                ReadItem::Entry {
                    sequence,
                    entry: LogEntry::Record(_),
                    ..
                } => Seen::Record(sequence.get()),
                ReadItem::Entry {
                    sequence,
                    entry: LogEntry::Marker(marker),
                    ..
                } => Seen::Marker(
                    sequence.get(),
                    match marker {
                        LogMarker::StaleOwner { .. } => "stale_owner",
                        LogMarker::TornTail { .. } => "torn_tail",
                        LogMarker::Truncated { .. } => "truncated",
                        LogMarker::OwnerRecordLost { .. } => "owner_record_lost",
                    },
                ),
                ReadItem::Gap { missing, reason } => {
                    Seen::Gap(missing.first().get(), missing.last().get(), *reason)
                }
            })
            .collect()
    }

    fn read_all(log: &Log) -> Vec<Seen> {
        let batch = log.read(&log.start(), usize::MAX).unwrap();
        assert!(batch.caught_up);
        assert_eq!(batch.cursor, log.end());
        seen(&batch.items)
    }

    fn records(range: std::ops::RangeInclusive<u64>) -> Vec<Seen> {
        range.map(Seen::Record).collect()
    }

    fn segment_files(directory: &Path) -> Vec<PathBuf> {
        list(directory)
            .unwrap()
            .segments
            .into_iter()
            .map(|(_, path)| path)
            .collect()
    }

    fn last_segment(directory: &Path) -> PathBuf {
        segment_files(directory).pop().unwrap()
    }

    fn append_bytes(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(bytes).unwrap();
    }

    /// Cuts the file at `path` back to its first `lines` lines.
    fn keep_lines(path: &Path, lines: usize) {
        let bytes = fs::read(path).unwrap();
        let end = bytes
            .iter()
            .enumerate()
            .filter(|(_, byte)| **byte == b'\n')
            .nth(lines - 1)
            .map(|(position, _)| position + 1)
            .unwrap();
        fs::write(path, &bytes[..end]).unwrap();
    }

    /// Flips one bit in the middle of the last line of the file at `path`.
    fn flip_last_line(path: &Path) -> u64 {
        let mut bytes = fs::read(path).unwrap();
        let body = bytes.len() - 1;
        let start = bytes[..body]
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |position| position + 1);
        bytes[(start + body) / 2] ^= 0x01;
        fs::write(path, &bytes).unwrap();
        u64::try_from(bytes.len() - start).unwrap()
    }

    fn owner_record(directory: &Path) -> Option<OwnerRecord> {
        fs::read(directory.join("owner.json"))
            .ok()
            .map(|bytes| serde_json::from_slice(&bytes).unwrap())
    }

    fn cursor(log: &Log, after: u64) -> LogCursor {
        LogCursor {
            stream: log.stream().clone(),
            after: Some(sequence(after)),
        }
    }

    #[test]
    fn the_sequence_is_persisted_and_continues_after_a_release() {
        let directory = tempfile::tempdir().unwrap();
        let mut source = Source::new();
        let (mut log, report) = open(directory.path(), config(4, 100));
        assert!(report.created);
        assert_eq!(report.takeover, Takeover::Fresh);
        assert!(report.markers.is_empty());
        assert_eq!(log.last(), None);
        assert_eq!(append(&mut log, &mut source, 6), [1, 2, 3, 4, 5, 6]);
        assert_eq!(segment_files(directory.path()).len(), 2);
        let instance = log.stream().clone();
        log.close().unwrap();

        let (mut log, report) = open(directory.path(), config(4, 100));
        assert!(!report.created);
        assert!(matches!(report.takeover, Takeover::Released { .. }));
        assert!(report.markers.is_empty());
        assert_eq!(log.stream(), &instance);
        assert_eq!(log.owner().record().durable_through, Some(sequence(6)));
        assert_eq!(log.append(source.event("op-1", 6)).unwrap(), sequence(7));
        assert_eq!(read_all(&log), records(1..=7));
        // Each entry reads back as appended, with the owner incarnation that wrote it.
        let tail = log
            .read(
                &LogCursor {
                    stream: instance.clone(),
                    after: Some(sequence(5)),
                },
                usize::MAX,
            )
            .unwrap();
        let written: Vec<(u64, u64, u64)> = tail
            .items
            .iter()
            .map(|item| match item {
                ReadItem::Entry {
                    sequence,
                    owner,
                    entry: LogEntry::Record(event),
                } => (sequence.get(), owner.get(), *event.payload()),
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(written, [(6, 1, 5), (7, 2, 6)]);
        assert_eq!(log.totals().records, 1);
    }

    #[test]
    fn a_second_owner_is_refused_while_the_first_holds_the_stream() {
        let directory = tempfile::tempdir().unwrap();
        let (log, _) = open(directory.path(), config(4, 100));
        assert!(matches!(
            DurableLog::<Event>::open(
                directory.path(),
                stream_id(),
                producer("warden"),
                config(4, 100)
            ),
            Err(LogError::Owner(OwnerError::HeldInProcess { .. }))
        ));
        drop(log);
        // The directory holds one stream; another name is refused, never mixed in.
        assert!(matches!(
            DurableLog::<Event>::open(
                directory.path(),
                DurableStreamId::new("warden.events").unwrap(),
                producer("warden"),
                config(4, 100)
            ),
            Err(LogError::Damaged(LogDamage::OtherStream { .. }))
        ));
        let (_, report) = open(directory.path(), config(4, 100));
        assert!(matches!(report.takeover, Takeover::Released { .. }));
    }

    #[test]
    fn a_stale_owner_is_recorded_and_the_sequence_continues() {
        let directory = tempfile::tempdir().unwrap();
        let mut source = Source::new();
        let (mut log, _) = open(directory.path(), config(4, 100));
        append(&mut log, &mut source, 3);
        log.crash();

        let (mut log, report) = open(directory.path(), config(4, 100));
        assert!(report.takeover.is_stale());
        assert_eq!(
            report.markers,
            [(
                sequence(4),
                LogMarker::StaleOwner {
                    owner: producer("engine"),
                    incarnation: Incarnation::FIRST
                }
            )]
        );
        assert_eq!(append(&mut log, &mut source, 1), [5]);
        assert_eq!(
            read_all(&log),
            [
                Seen::Record(1),
                Seen::Record(2),
                Seen::Record(3),
                Seen::Marker(4, "stale_owner"),
                Seen::Record(5)
            ]
        );
        log.close().unwrap();
        let (log, report) = open(directory.path(), config(4, 100));
        assert!(report.markers.is_empty());
        assert_eq!(log.last(), Some(sequence(5)));
    }

    #[test]
    fn a_torn_tail_is_quarantined_cut_off_and_recorded() {
        let directory = tempfile::tempdir().unwrap();
        let mut source = Source::new();
        let (mut log, _) = open(directory.path(), config(8, 100));
        append(&mut log, &mut source, 3);
        let segment = last_segment(directory.path());
        let intact = fs::metadata(&segment).unwrap().len();
        log.close().unwrap();
        // An append that stopped part way: no end of line.
        let torn = b"5f3a {\"sequence\":4,\"owner\":1,\"entry\":{\"rec";
        append_bytes(&segment, torn);

        let (mut log, report) = open(directory.path(), config(8, 100));
        // The torn line may have held sequence 4: it is burned, never given out again.
        assert_eq!(
            report.markers,
            [
                (
                    sequence(5),
                    LogMarker::Truncated {
                        missing: range(4, 4)
                    }
                ),
                (
                    sequence(6),
                    LogMarker::TornTail {
                        bytes: u64::try_from(torn.len()).unwrap(),
                        quarantine: "torn-2.bin".to_owned()
                    }
                )
            ]
        );
        // The bytes are kept aside, never deleted, and cut off the segment.
        assert_eq!(
            fs::read(directory.path().join("torn-2.bin")).unwrap(),
            torn.to_vec()
        );
        let markers: u64 = log
            .index
            .iter()
            .rev()
            .take(2)
            .map(|entry| entry.length)
            .sum();
        assert_eq!(fs::metadata(&segment).unwrap().len(), intact + markers);
        assert_eq!(append(&mut log, &mut source, 1), [7]);
        log.close().unwrap();

        // A last line that ends but does not verify is torn too, never taken as an entry.
        append_bytes(&segment, b"not an entry\n");
        let (log, report) = open(directory.path(), config(8, 100));
        assert!(matches!(
            report.markers.as_slice(),
            [
                (_, LogMarker::Truncated { missing }),
                (found, LogMarker::TornTail { bytes: 13, quarantine })
            ] if *missing == range(8, 8) && *found == sequence(10) && quarantine == "torn-3.bin"
        ));
        assert_eq!(
            read_all(&log),
            [
                Seen::Record(1),
                Seen::Record(2),
                Seen::Record(3),
                Seen::Gap(4, 4, GapReason::Truncated),
                Seen::Marker(5, "truncated"),
                Seen::Marker(6, "torn_tail"),
                Seen::Record(7),
                Seen::Gap(8, 8, GapReason::Truncated),
                Seen::Marker(9, "truncated"),
                Seen::Marker(10, "torn_tail")
            ]
        );
        log.close().unwrap();
        let (_, report) = open(directory.path(), config(8, 100));
        assert!(report.markers.is_empty());
    }

    #[test]
    fn damage_before_the_end_refuses_to_open() {
        let directory = tempfile::tempdir().unwrap();
        let mut source = Source::new();
        let (mut log, _) = open(directory.path(), config(8, 100));
        append(&mut log, &mut source, 3);
        log.close().unwrap();
        // Two more owners come and go, so the next is the fourth.
        for _ in 0..2 {
            open(directory.path(), config(8, 100)).0.close().unwrap();
        }
        let before = owner_record(directory.path());
        let segment = last_segment(directory.path());
        let original = fs::read(&segment).unwrap();

        // A rewritten record in the middle.
        let text = String::from_utf8(original.clone()).unwrap();
        let rewritten = text.replacen("\"payload\":1", "\"payload\":9", 1);
        assert_ne!(rewritten, text);
        fs::write(&segment, rewritten).unwrap();
        let refused = DurableLog::<Event>::open(
            directory.path(),
            stream_id(),
            producer("engine"),
            config(8, 100),
        )
        .unwrap_err();
        assert_eq!(
            refused,
            LogError::Damaged(LogDamage::Line {
                segment: sequence(1),
                line: 2,
                problem: LineProblem::Checksum
            })
        );
        assert!(refused.to_string().contains("line 2"));

        // Valid lines out of order, or written by an earlier owner after a later one: two
        // writers shared the stream.
        let state = read_state(directory.path()).unwrap().unwrap();
        let line = |value: u64, owner: u64| {
            encode_line(
                &state.stream,
                sequence(value),
                Incarnation::new(owner),
                &LogEntry::Record(
                    source
                        .0
                        .draft(
                            SourceClass::HostProbe,
                            context("op-1", Phase::Loading),
                            MonotonicTime::ZERO,
                            value,
                        )
                        .unwrap(),
                ),
            )
            .unwrap()
        };
        let cases = [
            (
                [line(1, 1), line(3, 1), line(4, 1)],
                LineProblem::Sequence {
                    expected: sequence(2),
                    found: sequence(3),
                },
            ),
            (
                [line(1, 2), line(2, 1), line(3, 2)],
                LineProblem::OwnerOrder {
                    previous: Incarnation::new(2),
                    found: Incarnation::new(1),
                },
            ),
            (
                [line(1, 1), line(2, 90), line(3, 1)],
                LineProblem::UnknownOwner {
                    found: Incarnation::new(90),
                },
            ),
        ];
        for (lines, problem) in cases {
            fs::write(&segment, lines.concat()).unwrap();
            assert_eq!(
                DurableLog::<Event>::open(
                    directory.path(),
                    stream_id(),
                    producer("engine"),
                    config(8, 100)
                )
                .err(),
                Some(LogError::Damaged(LogDamage::Line {
                    segment: sequence(1),
                    line: 2,
                    problem
                }))
            );
        }
        // A last line that verifies was written whole: out of order, it is damage, never a
        // torn tail to cut off.
        fs::write(&segment, [line(1, 1), line(2, 1), line(4, 1)].concat()).unwrap();
        assert_eq!(
            DurableLog::<Event>::open(
                directory.path(),
                stream_id(),
                producer("engine"),
                config(8, 100)
            )
            .err(),
            Some(LogError::Damaged(LogDamage::Line {
                segment: sequence(1),
                line: 3,
                problem: LineProblem::Sequence {
                    expected: sequence(3),
                    found: sequence(4)
                }
            }))
        );
        // No refused open raised the incarnation or changed the owner record.
        assert_eq!(owner_record(directory.path()), before);
        // Segments without the stream's state are refused, never adopted as a new stream.
        fs::write(&segment, original).unwrap();
        fs::remove_file(directory.path().join(STATE_FILE)).unwrap();
        assert_eq!(
            DurableLog::<Event>::open(
                directory.path(),
                stream_id(),
                producer("engine"),
                config(8, 100)
            )
            .err(),
            Some(LogError::Damaged(LogDamage::StateMissing))
        );
    }

    #[test]
    fn a_refused_open_leaves_the_owner_record_as_it_found_it() {
        let directory = tempfile::tempdir().unwrap();
        let mut source = Source::new();
        let (mut log, _) = open(directory.path(), config(8, 100));
        append(&mut log, &mut source, 3);
        log.close().unwrap();
        let before = owner_record(directory.path());
        let segment = last_segment(directory.path());
        let original = fs::read(&segment).unwrap();
        let text = String::from_utf8(original.clone()).unwrap();
        fs::write(&segment, text.replacen("\"payload\":1", "\"payload\":9", 1)).unwrap();
        for _ in 0..3 {
            assert!(matches!(
                DurableLog::<Event>::open(
                    directory.path(),
                    stream_id(),
                    producer("engine"),
                    config(8, 100)
                ),
                Err(LogError::Damaged(_))
            ));
            assert_eq!(owner_record(directory.path()), before);
        }
        // Once repaired, the stream opens as if the refused attempts never happened.
        fs::write(&segment, original).unwrap();
        let (log, report) = open(directory.path(), config(8, 100));
        assert_eq!(
            report.takeover,
            Takeover::Released {
                previous: before.unwrap()
            }
        );
        assert_eq!(log.owner().incarnation().get(), 2);
        assert!(report.markers.is_empty());
        assert_eq!(read_all(&log), records(1..=3));
    }

    #[test]
    fn an_open_that_wrote_an_entry_and_failed_leaves_a_stale_owner() {
        let directory = tempfile::tempdir().unwrap();
        let mut source = Source::new();
        let name = "engine.with.a.producer.name.longer.than.any.marker.field";
        let open_as = |config: LogConfig| {
            DurableLog::<Event>::open(directory.path(), stream_id(), producer(name), config)
        };
        let (mut log, _) = open_as(config(8, 100)).unwrap();
        append(&mut log, &mut source, 3);
        log.crash();
        append_bytes(&last_segment(directory.path()), b"5f3a {\"sequence\":4,");
        // A segment bound that takes the truncation marker but not the stale owner's.
        let stream = read_state(directory.path()).unwrap().unwrap().stream;
        let marker_length = |marker: LogMarker| {
            let entry = LogEntry::<u64>::Marker(marker);
            u64::try_from(
                encode_line(&stream, sequence(5), Incarnation::new(2), &entry)
                    .unwrap()
                    .len(),
            )
            .unwrap()
        };
        let truncated = marker_length(LogMarker::Truncated {
            missing: range(4, 4),
        });
        let stale = marker_length(LogMarker::StaleOwner {
            owner: producer(name),
            incarnation: Incarnation::FIRST,
        });
        assert!(stale > truncated);
        let tight = LogConfig {
            segment_bytes: truncated,
            ..config(8, 100)
        };
        assert_eq!(
            open_as(tight).err(),
            Some(LogError::TooLarge {
                bytes: stale,
                limit: truncated
            })
        );
        // It wrote the truncation marker under its own incarnation, so it is the stale
        // owner now; the torn line's sequence stays burned.
        let (log, report) = open_as(config(8, 100)).unwrap();
        assert!(matches!(
            &report.takeover,
            Takeover::Stale { previous } if previous.incarnation.get() == 2
        ));
        assert_eq!(
            read_all(&log),
            [
                Seen::Record(1),
                Seen::Record(2),
                Seen::Record(3),
                Seen::Gap(4, 4, GapReason::Truncated),
                Seen::Marker(5, "truncated"),
                Seen::Marker(6, "stale_owner")
            ]
        );
    }

    #[test]
    fn a_crash_then_a_deleted_segment_never_gives_its_sequences_out_again() {
        let directory = tempfile::tempdir().unwrap();
        let mut source = Source::new();
        let (mut log, _) = open(directory.path(), config(8, 100));
        append(&mut log, &mut source, 3);
        let kept = log.end();
        log.crash();
        fs::remove_file(last_segment(directory.path())).unwrap();

        let (mut log, report) = open(directory.path(), config(8, 100));
        assert_eq!(
            report.markers,
            [
                (
                    sequence(4),
                    LogMarker::Truncated {
                        missing: range(1, 3)
                    }
                ),
                (
                    sequence(5),
                    LogMarker::StaleOwner {
                        owner: producer("engine"),
                        incarnation: Incarnation::FIRST
                    }
                )
            ]
        );
        assert_eq!(append(&mut log, &mut source, 1), [6]);
        // A reader's cursor from before the crash stays valid and skips nothing.
        let resumed = log.read(&kept, usize::MAX).unwrap();
        assert!(resumed.caught_up);
        assert_eq!(
            seen(&resumed.items),
            [
                Seen::Marker(4, "truncated"),
                Seen::Marker(5, "stale_owner"),
                Seen::Record(6)
            ]
        );
        assert_eq!(read_all(&log)[0], Seen::Gap(1, 3, GapReason::Truncated));
    }

    #[test]
    fn a_crash_then_a_cut_segment_is_reported_as_truncated() {
        let directory = tempfile::tempdir().unwrap();
        let mut source = Source::new();
        let (mut log, _) = open(directory.path(), config(8, 100));
        append(&mut log, &mut source, 3);
        log.crash();
        keep_lines(&last_segment(directory.path()), 1);

        let (mut log, report) = open(directory.path(), config(8, 100));
        assert!(matches!(
            report.markers.as_slice(),
            [
                (_, LogMarker::Truncated { missing }),
                (_, LogMarker::StaleOwner { .. })
            ] if *missing == range(2, 3)
        ));
        assert!(log.record_lost());
        assert_eq!(append(&mut log, &mut source, 1), [6]);
        assert!(!log.record_lost());
        assert_eq!(
            read_all(&log),
            [
                Seen::Record(1),
                Seen::Gap(2, 3, GapReason::Truncated),
                Seen::Marker(4, "truncated"),
                Seen::Marker(5, "stale_owner"),
                Seen::Record(6)
            ]
        );
    }

    #[test]
    fn a_bit_flipped_last_line_is_quarantined_and_its_sequence_never_reused() {
        let directory = tempfile::tempdir().unwrap();
        let mut source = Source::new();
        let (mut log, _) = open(directory.path(), config(8, 100));
        append(&mut log, &mut source, 3);
        log.close().unwrap();
        let flipped = flip_last_line(&last_segment(directory.path()));

        let (mut log, report) = open(directory.path(), config(8, 100));
        // Sequence 3 was acknowledged; the line after it may have been taken too.
        assert_eq!(
            report.markers,
            [
                (
                    sequence(5),
                    LogMarker::Truncated {
                        missing: range(3, 4)
                    }
                ),
                (
                    sequence(6),
                    LogMarker::TornTail {
                        bytes: flipped,
                        quarantine: "torn-2.bin".to_owned()
                    }
                )
            ]
        );
        assert!(log.record_lost());
        assert_eq!(append(&mut log, &mut source, 1), [7]);
        assert_eq!(
            read_all(&log),
            [
                Seen::Record(1),
                Seen::Record(2),
                Seen::Gap(3, 4, GapReason::Truncated),
                Seen::Marker(5, "truncated"),
                Seen::Marker(6, "torn_tail"),
                Seen::Record(7)
            ]
        );
    }

    #[test]
    fn a_torn_tail_says_whether_an_append_may_have_acknowledged_it() {
        // A crash in the middle of an append: half a line, never acknowledged.
        let directory = tempfile::tempdir().unwrap();
        let mut source = Source::new();
        let (mut log, report) = open(directory.path(), config(8, 100));
        assert_eq!(report.torn_tail, None);
        append(&mut log, &mut source, 3);
        log.inject(WriteFault::Unrecoverable);
        assert!(log.append(source.event("op-1", 3)).is_err());
        log.crash();
        let (log, report) = open(directory.path(), config(8, 100));
        assert_eq!(
            report.torn_tail,
            Some(TornTailFound {
                marker: sequence(7),
                synced_through: Some(sequence(3)),
                past_synced_mark: true,
            })
        );
        // Its truncation covers only the sequence the torn line burned.
        assert_eq!(
            report.markers[0],
            (
                sequence(5),
                LogMarker::Truncated {
                    missing: range(4, 4)
                }
            )
        );
        assert!(matches!(
            report.markers[2],
            (marker, LogMarker::TornTail { .. }) if marker == sequence(7)
        ));
        assert!(!log.record_lost());
        log.close().unwrap();
        // A clean reopen finds no torn tail.
        let (log, report) = open(directory.path(), config(8, 100));
        assert_eq!(report.torn_tail, None);
        log.close().unwrap();

        // The last acknowledged line torn since: it may have held an entry an append
        // returned, so the caller fails closed.
        let directory = tempfile::tempdir().unwrap();
        let (mut log, _) = open(directory.path(), config(8, 100));
        append(&mut log, &mut source, 3);
        log.close().unwrap();
        flip_last_line(&last_segment(directory.path()));
        let (log, report) = open(directory.path(), config(8, 100));
        assert_eq!(
            report.torn_tail,
            Some(TornTailFound {
                marker: sequence(6),
                synced_through: Some(sequence(3)),
                past_synced_mark: false,
            })
        );
        assert!(log.record_lost());
    }

    #[test]
    fn segments_without_a_whole_high_water_mark_are_refused() {
        let directory = tempfile::tempdir().unwrap();
        let mut source = Source::new();
        let (mut log, _) = open(directory.path(), config(8, 100));
        append(&mut log, &mut source, 2);
        log.close().unwrap();
        let mark = directory.path().join(HIGH_WATER_FILE);
        let original = fs::read(&mark).unwrap();
        let before = owner_record(directory.path());
        let refused = |directory: &Path| {
            DurableLog::<Event>::open(directory, stream_id(), producer("engine"), config(8, 100))
                .err()
        };
        fs::write(&mark, vec![0x5a; original.len()]).unwrap();
        assert_eq!(
            refused(directory.path()),
            Some(LogError::Damaged(LogDamage::HighWaterSpoiled))
        );
        fs::write(&mark, &original[..100]).unwrap();
        assert_eq!(
            refused(directory.path()),
            Some(LogError::Damaged(LogDamage::HighWaterLength { found: 100 }))
        );
        fs::remove_file(&mark).unwrap();
        assert_eq!(
            refused(directory.path()),
            Some(LogError::Damaged(LogDamage::HighWaterMissing))
        );
        assert_eq!(owner_record(directory.path()), before);
        fs::write(&mark, original).unwrap();
        let (log, report) = open(directory.path(), config(8, 100));
        assert!(report.markers.is_empty());
        assert_eq!(log.last(), Some(sequence(2)));
    }

    #[test]
    fn a_lost_owner_record_is_derived_from_the_stream_and_never_wears_away() {
        let directory = tempfile::tempdir().unwrap();
        let mut source = Source::new();
        let (mut log, _) = open(directory.path(), config(8, 100));
        append(&mut log, &mut source, 3);
        log.close().unwrap();
        let (mut log, _) = open(directory.path(), config(8, 100));
        append(&mut log, &mut source, 2);
        log.crash();
        // The owner record goes, and with it the durable sequence; the tail goes too.
        fs::remove_file(directory.path().join("owner.json")).unwrap();
        let segment = last_segment(directory.path());
        keep_lines(&segment, 4);
        let original = fs::read(&segment).unwrap();

        // Refused opens leave no owner record behind, so none can wear the next one down.
        let text = String::from_utf8(original.clone()).unwrap();
        fs::write(&segment, text.replacen("\"payload\":1", "\"payload\":9", 1)).unwrap();
        for _ in 0..3 {
            assert!(matches!(
                DurableLog::<Event>::open(
                    directory.path(),
                    stream_id(),
                    producer("engine"),
                    config(8, 100)
                ),
                Err(LogError::Damaged(LogDamage::Line { line: 2, .. }))
            ));
            assert_eq!(owner_record(directory.path()), None);
        }
        fs::write(&segment, original).unwrap();

        let (mut log, report) = open(directory.path(), config(8, 100));
        assert_eq!(report.takeover, Takeover::Lost { kept: None });
        // Past every owner the stream shows, and past the high-water mark.
        assert_eq!(log.owner().incarnation().get(), 3);
        assert_eq!(
            report.markers,
            [
                (
                    sequence(6),
                    LogMarker::Truncated {
                        missing: range(5, 5)
                    }
                ),
                (
                    sequence(7),
                    LogMarker::OwnerRecordLost {
                        last_owner: Some(Incarnation::new(2))
                    }
                )
            ]
        );
        assert_eq!(append(&mut log, &mut source, 1), [8]);
        let tail = log.read(&cursor(&log, 4), usize::MAX).unwrap();
        assert_eq!(
            seen(&tail.items),
            [
                Seen::Gap(5, 5, GapReason::Truncated),
                Seen::Marker(6, "truncated"),
                Seen::Marker(7, "owner_record_lost"),
                Seen::Record(8)
            ]
        );
        log.close().unwrap();
        let (log, report) = open(directory.path(), config(8, 100));
        assert!(matches!(report.takeover, Takeover::Released { .. }));
        assert!(report.markers.is_empty());
        assert_eq!(log.owner().incarnation().get(), 4);
    }

    #[test]
    fn a_truncated_tail_never_gives_its_sequences_out_again() {
        let directory = tempfile::tempdir().unwrap();
        let mut source = Source::new();
        let (mut log, _) = open(directory.path(), config(4, 100));
        append(&mut log, &mut source, 7);
        log.close().unwrap();
        // The file loses its last two whole lines: an intact-looking but truncated file.
        let segment = last_segment(directory.path());
        let bytes = fs::read(&segment).unwrap();
        let first_line = bytes.iter().position(|byte| *byte == b'\n').unwrap() + 1;
        fs::write(&segment, &bytes[..first_line]).unwrap();

        let (mut log, report) = open(directory.path(), config(4, 100));
        assert_eq!(
            report.markers,
            [(
                sequence(8),
                LogMarker::Truncated {
                    missing: range(6, 7)
                }
            )]
        );
        assert_eq!(append(&mut log, &mut source, 1), [9]);
        let after_four = log
            .read(
                &LogCursor {
                    stream: log.stream().clone(),
                    after: Some(sequence(4)),
                },
                usize::MAX,
            )
            .unwrap();
        assert_eq!(
            seen(&after_four.items),
            [
                Seen::Record(5),
                Seen::Gap(6, 7, GapReason::Truncated),
                Seen::Marker(8, "truncated"),
                Seen::Record(9)
            ]
        );
        // The marker explains the gap, so the stream opens cleanly from now on.
        log.close().unwrap();
        let (log, report) = open(directory.path(), config(4, 100));
        assert!(report.markers.is_empty());
        assert_eq!(log.last(), Some(sequence(9)));

        // A whole segment gone from the end is a truncation too.
        log.close().unwrap();
        fs::remove_file(last_segment(directory.path())).unwrap();
        let (log, report) = open(directory.path(), config(4, 100));
        assert_eq!(
            report.markers,
            [(
                sequence(10),
                LogMarker::Truncated {
                    missing: range(5, 9)
                }
            )]
        );
        assert_eq!(
            read_all(&log),
            [
                Seen::Record(1),
                Seen::Record(2),
                Seen::Record(3),
                Seen::Record(4),
                Seen::Gap(5, 9, GapReason::Truncated),
                Seen::Marker(10, "truncated")
            ]
        );
    }

    #[test]
    fn retention_drops_whole_segments_counts_them_and_reads_them_as_a_gap() {
        let directory = tempfile::tempdir().unwrap();
        let mut source = Source::new();
        let (mut log, _) = open(directory.path(), config(2, 4));
        let events: Vec<Event> = (0..9).map(|value| source.event("op-1", value)).collect();
        let first_segment = {
            log.append(events[0].clone()).unwrap();
            fs::read(last_segment(directory.path())).unwrap()
        };
        for event in &events[1..] {
            log.append(event.clone()).unwrap();
        }
        let lengths: Vec<u64> = events
            .iter()
            .zip(1..)
            .map(|(event, value)| {
                let line = encode_line(
                    log.stream(),
                    sequence(value),
                    Incarnation::FIRST,
                    &LogEntry::Record(event.clone()),
                )
                .unwrap();
                u64::try_from(line.len()).unwrap()
            })
            .collect();
        let retention = log.retention();
        assert_eq!(
            retention,
            Retention {
                low_water: Some(sequence(6)),
                retained_entries: 3,
                retained_bytes: lengths[6..].iter().sum(),
                dropped_entries: 6,
                dropped_bytes: lengths[..6].iter().sum(),
            }
        );
        assert_eq!(segment_files(directory.path()).len(), 2);
        let expected = [
            Seen::Gap(1, 6, GapReason::Retention),
            Seen::Record(7),
            Seen::Record(8),
            Seen::Record(9),
        ];
        assert_eq!(read_all(&log), expected);
        let after_three = log
            .read(
                &LogCursor {
                    stream: log.stream().clone(),
                    after: Some(sequence(3)),
                },
                2,
            )
            .unwrap();
        assert_eq!(
            seen(&after_three.items),
            [Seen::Gap(4, 6, GapReason::Retention), Seen::Record(7)]
        );
        assert!(!after_three.caught_up);
        log.close().unwrap();

        // A crash between persisting the low-water mark and removing a file leaves the
        // file behind; it never comes back as entries.
        fs::write(segment_path(directory.path(), sequence(1)), first_segment).unwrap();
        let (mut log, report) = open(directory.path(), config(2, 4));
        assert_eq!(report.leftover_segments, 1);
        assert_eq!(log.retention(), retention);
        assert_eq!(read_all(&log), expected);
        assert_eq!(append(&mut log, &mut source, 1), [10]);
    }

    #[test]
    fn retention_bounds_bytes_too() {
        let directory = tempfile::tempdir().unwrap();
        let mut source = Source::new();
        let bounds = LogConfig {
            max_entries: 1_000,
            max_bytes: 2_048,
            segment_entries: 1_000,
            segment_bytes: 512,
        };
        let (mut log, _) = open(directory.path(), bounds);
        append(&mut log, &mut source, 40);
        let retention = log.retention();
        assert!(retention.retained_bytes <= 2_048, "{retention:?}");
        assert!(retention.dropped_entries > 0);
        assert_eq!(retention.dropped_entries + retention.retained_entries, 40);
        assert_eq!(
            retention.low_water.map(EventSequence::get),
            Some(retention.dropped_entries)
        );
    }

    #[test]
    fn cursors_resume_without_gaps_and_refuse_other_streams_and_the_future() {
        let directory = tempfile::tempdir().unwrap();
        let mut source = Source::new();
        let (mut log, _) = open(directory.path(), config(3, 100));
        append(&mut log, &mut source, 7);
        // A reader that reconnects after every two items still gets everything, once.
        let mut cursor = log.start();
        let mut resumed = Vec::new();
        loop {
            let batch = log.read(&cursor, 2).unwrap();
            resumed.extend(seen(&batch.items));
            cursor = batch.cursor;
            if batch.caught_up {
                break;
            }
        }
        assert_eq!(resumed, records(1..=7));
        let encoded = serde_json::to_value(&cursor).unwrap();
        assert_eq!(
            serde_json::from_value::<LogCursor>(encoded.clone()).unwrap(),
            cursor
        );
        let mut extra = encoded;
        extra["note"] = serde_json::json!("x");
        assert!(serde_json::from_value::<LogCursor>(extra).is_err());
        let end = log.read(&log.end(), 10).unwrap();
        assert!(end.items.is_empty() && end.caught_up);

        // A cursor past the end is refused.
        let future = LogCursor {
            stream: log.stream().clone(),
            after: Some(sequence(8)),
        };
        assert_eq!(
            log.read(&future, 10).err(),
            Some(LogError::Cursor(CursorError::Future {
                after: sequence(8),
                last: Some(sequence(7))
            }))
        );
        // So is one of another stream with the same name.
        let elsewhere = tempfile::tempdir().unwrap();
        let (other, _) = open(elsewhere.path(), config(3, 100));
        assert!(matches!(
            other.read(&cursor, 10),
            Err(LogError::Cursor(CursorError::WrongStream { .. }))
        ));
        // And one from before the stream was deleted and created again.
        log.close().unwrap();
        fs::remove_dir_all(directory.path()).unwrap();
        let (log, report) = open(directory.path(), config(3, 100));
        assert!(report.created);
        assert!(matches!(
            log.read(&cursor, 10),
            Err(LogError::Cursor(CursorError::WrongStream { .. }))
        ));
        assert_eq!(
            log.read(
                &LogCursor {
                    stream: log.stream().clone(),
                    after: Some(sequence(1)),
                },
                10
            )
            .err(),
            Some(LogError::Cursor(CursorError::Future {
                after: sequence(1),
                last: None
            }))
        );
    }

    #[test]
    fn operations_correlate_by_their_envelope_identity() {
        let directory = tempfile::tempdir().unwrap();
        let mut source = Source::new();
        let (mut log, _) = open(directory.path(), config(2, 4));
        for value in 0..6 {
            let name = if value % 2 == 0 { "op-a" } else { "op-b" };
            log.append(source.event(name, value)).unwrap();
        }
        let correlation = log.correlate(&operation("op-a")).unwrap();
        let found: Vec<(u64, u64)> = correlation
            .records
            .iter()
            .map(|(sequence, event)| (sequence.get(), *event.payload()))
            .collect();
        assert_eq!(found, [(3, 2), (5, 4)]);
        // Retention dropped the first two entries, so earlier records may be gone.
        assert_eq!(correlation.gaps, [(range(1, 2), GapReason::Retention)]);
        assert!(log
            .correlate(&operation("op-c"))
            .unwrap()
            .records
            .is_empty());
    }

    #[test]
    fn a_failed_append_is_cut_back_off_and_uses_no_sequence() {
        let directory = tempfile::tempdir().unwrap();
        let mut source = Source::new();
        let (mut log, _) = open(directory.path(), config(8, 100));
        append(&mut log, &mut source, 2);
        log.inject(WriteFault::Partial(io::ErrorKind::StorageFull));
        let refused = log.append(source.event("op-1", 2)).unwrap_err();
        assert!(matches!(
            refused,
            LogError::Io {
                kind: io::ErrorKind::StorageFull,
                ..
            }
        ));
        assert_eq!(refused.store_refusal(), StoreRefusal::Full);
        assert_eq!(append(&mut log, &mut source, 1), [3]);
        assert_eq!(log.totals().failed_appends, 1);
        log.close().unwrap();
        let (mut log, report) = open(directory.path(), config(8, 100));
        assert!(report.markers.is_empty());
        assert_eq!(read_all(&log), records(1..=3));

        // When the partial line cannot be cut off either, the log stops taking appends;
        // opening it again quarantines the torn line.
        log.inject(WriteFault::Unrecoverable);
        assert!(log.append(source.event("op-1", 3)).is_err());
        assert_eq!(
            log.append(source.event("op-1", 4)).err(),
            Some(LogError::Poisoned)
        );
        log.close().unwrap();
        let (mut log, report) = open(directory.path(), config(8, 100));
        assert!(matches!(
            report.markers.as_slice(),
            [
                (_, LogMarker::Truncated { missing }),
                (found, LogMarker::TornTail { .. })
            ] if *missing == range(4, 4) && *found == sequence(6)
        ));
        assert_eq!(log.last(), Some(sequence(6)));

        // When the high-water mark cannot be persisted, the append is not acknowledged:
        // its line is cut back off and its sequence is the next append's.
        log.inject(WriteFault::HighWater(io::ErrorKind::StorageFull));
        assert!(matches!(
            log.append(source.event("op-1", 5)),
            Err(LogError::Io {
                kind: io::ErrorKind::StorageFull,
                ..
            })
        ));
        assert_eq!(append(&mut log, &mut source, 1), [7]);
        log.close().unwrap();
        let (log, report) = open(directory.path(), config(8, 100));
        assert!(report.markers.is_empty());
        assert_eq!(read_all(&log).last(), Some(&Seen::Record(7)));
    }

    #[test]
    fn configuration_and_oversized_entries_are_refused() {
        let zero = LogConfig {
            max_bytes: 0,
            ..config(2, 4)
        };
        assert_eq!(
            zero.validate(),
            Err(ConfigError::Zero {
                setting: "max_bytes"
            })
        );
        assert_eq!(
            config(5, 4).validate(),
            Err(ConfigError::Exceeds {
                setting: "segment_entries",
                limit: "max_entries"
            })
        );
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(
            DurableLog::<Event>::open(directory.path(), stream_id(), producer("engine"), zero)
                .err(),
            Some(LogError::Config(ConfigError::Zero {
                setting: "max_bytes"
            }))
        );
        let small = LogConfig {
            segment_bytes: 64,
            ..config(2, 4)
        };
        let (mut log, _) = open(directory.path(), small);
        let mut source = Source::new();
        assert!(matches!(
            log.append(source.event("op-1", 1)),
            Err(LogError::TooLarge { limit: 64, .. })
        ));
        assert_eq!(log.last(), None);
    }

    #[test]
    fn stored_entries_refuse_unknown_fields() {
        let marker = serde_json::to_value(LogMarker::Truncated {
            missing: range(2, 3),
        })
        .unwrap();
        assert_eq!(marker["kind"], "truncated");
        let mut extra = marker.clone();
        extra["note"] = serde_json::json!("x");
        assert!(serde_json::from_value::<LogMarker>(extra).is_err());
        assert!(serde_json::from_value::<LogEntry<u64>>(serde_json::json!({"other": 1})).is_err());

        let stream = StreamInstance::create(stream_id());
        let json = br#"{"sequence":1,"owner":1,"entry":{"record":7},"note":"x"}"#;
        let line = [
            line_digest(&stream, json).to_hex().as_bytes(),
            b" ".as_slice(),
            json.as_slice(),
        ]
        .concat();
        assert_eq!(
            decode_line::<u64>(&stream, &line).err(),
            Some(LineProblem::Encoding)
        );
        // A line of another stream, or another instance of this one, does not verify.
        let good = encode_line(
            &stream,
            sequence(1),
            Incarnation::FIRST,
            &LogEntry::Record(7u64),
        )
        .unwrap();
        let body = &good[..good.len() - 1];
        assert_eq!(
            decode_line::<u64>(&stream, body).unwrap().sequence,
            sequence(1)
        );
        let recreated = StreamInstance::create(stream_id());
        assert_eq!(
            decode_line::<u64>(&recreated, body).err(),
            Some(LineProblem::Checksum)
        );
    }
}
