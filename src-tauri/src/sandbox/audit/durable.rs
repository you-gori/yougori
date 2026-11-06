//! Audit segments on a durable CORE-06 stream (docs/combined-gpu-memory-and-vm-sandbox-plan.md:
//! the CORE-06 row at line 215; VM-W42 at line 2665: "one append authority per stream,
//! bounded queues ... rotation" and "restart/truncation, disk full ... tested"; §8.2 at
//! lines 2441–2450; docs/combined-plan-leftover-tasks.md S06: "give each durable stream a
//! clear append owner").
//!
//! [`DurableSegments`] is the [`SegmentStorage`] of a stream whose segments live in a
//! CORE-06 [`DurableLog`]: one line per header, record and seal ([`SegmentLine`]), in the
//! order the stream wrote them. What the log does, the stream keeps:
//!
//! - One owner. Opening the log acquires its stream owner, so a second owner, in this
//!   process or in another one on the host, is refused at once with a typed error that
//!   names the holder when its record is readable. A
//!   [`StreamDirectory::durable`](super::StreamDirectory::durable) keeps one directory per
//!   stream under its root.
//! - A sequence that continues. Each line takes the log's next sequence, acknowledged only
//!   once it is flushed; after a release, a crash or a stale owner the log continues after
//!   everything it used, and the stream resumes its chain from the segments read back.
//! - A torn tail reported. A last line that an interrupted append left incomplete is moved
//!   to a quarantine file, and the log records that and the sequence it burned as markers.
//!   Nothing the log acknowledged is lost that way, so the stream resumes after the last
//!   whole line, and the markers and gaps come back in a [`DurableOpening`]. When lines the
//!   log acknowledged are gone from its end, no record can be shown to continue the chain:
//!   the stream does not open ([`DurableError::TailLost`]), as the CORE-06 audit store
//!   refuses every record then.
//! - Retention reported. The log drops whole log segments, oldest first, under its entry
//!   and byte bounds, and its reads show what it dropped as a gap. The storage declares
//!   that ([`SegmentRetention`]), and the stream verifies its chain from the first segment
//!   whose header is still held; lines of a segment whose header was dropped count as
//!   dropped too. [`check_retention`] refuses bounds under which retention could drop the
//!   header of the segment being written, so a resume finds where to continue.
//!
//! - Released with its outcome. [`AuditStream::release`](super::AuditStream::release) closes
//!   the stream and releases the log, returning whether its owner record could say so.
//!   Dropping the storage releases the log too, as far as it can, but cannot report a
//!   record it failed to write; the next owner then finds a stale owner.
//!
//! The log's line digests detect damage, not tampering: whoever can write the directory can
//! rewrite the lines. The segment chain and an anchor are what detect that, under the
//! custody assumptions of [`CUSTODY_STATEMENT`](super::CUSTODY_STATEMENT).

use std::fmt;
use std::path::Path;

use super::segment::{
    SegmentConfig, SegmentHeader, SegmentRetention, SegmentSeal, SegmentStorage, StoredSegment,
};
use super::stream::StreamResume;
use crate::foundation::events::{
    AuditRecord, ConfigError, DurableLog, DurableStreamId, EventSequence, GapReason, JournalId,
    LogConfig, LogEntry, LogError, OpenReport, ProducerId, ReadItem, SequenceRange, StoreRefusal,
};
use crate::foundation::ids::IdError;

/// Markers one open of the log can append before the stream writes its next header: a
/// truncation, a stale or lost owner, and a torn tail.
const MARKERS_PER_OPEN: u64 = 3;
/// Opens whose markers the retention bound leaves room for after the last header: the one
/// that resumes, and one that stopped before it could write a header.
const OPENS_AFTER_HEADER: u64 = 2;

strict_tagged_enum! {
    /// One line of an audit stream in its durable log.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum SegmentLine (tag = "line", wire = SegmentLineWire, wire_name = "SegmentLineWire") {
        /// The start of a segment.
        Header { header: SegmentHeader },
        /// One record of the open segment, boxed: a record is many times the size of a
        /// seal.
        Record { record: Box<AuditRecord> },
        /// The close of the open segment.
        Seal { seal: SegmentSeal },
    }
}

/// Why lines of the log do not form segments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutProblem {
    /// A record or seal comes before any segment header, and retention dropped nothing
    /// that could have held it.
    BeforeHeader,
    /// A record or a second seal follows the seal of its segment.
    AfterSeal,
}

impl fmt::Display for LayoutProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BeforeHeader => "it comes before any segment header",
            Self::AfterSeal => "it follows the seal of its segment",
        })
    }
}

/// Why a durable stream could not be opened. Each refusal fails closed: no stream, no
/// appends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurableError {
    /// The stream directory keeps no durable streams; make it with
    /// [`StreamDirectory::durable`](super::StreamDirectory::durable).
    NoRoot,
    Identifier(IdError),
    Config(ConfigError),
    /// Under these bounds retention could drop the header of the segment being written.
    /// `needed` is the least value of `setting` that keeps it.
    RetentionTooSmall {
        setting: &'static str,
        needed: u64,
        configured: u64,
    },
    /// The durable log could not be opened or read: another owner holds it, it is
    /// damaged, or storage refused.
    Log(LogError),
    /// Lines the log acknowledged are gone from its end; `truncated` are the log's
    /// sequences it records as gone. No record can be shown to continue the chain, so the
    /// stream does not open until someone looks at the log.
    TailLost {
        truncated: Vec<SequenceRange>,
    },
    /// The log's line `sequence` does not fit the segments before it.
    Layout {
        sequence: EventSequence,
        problem: LayoutProblem,
    },
    /// Retention left no segment header, so where the chain continues is unknown.
    NothingRetained {
        dropped_entries: u64,
    },
    /// The stream's storage was still held elsewhere when it was to be released, so its
    /// release was left to drop, which cannot report a failure.
    StillShared,
}

impl DurableError {
    /// The refusal an audit journal sees for this error.
    pub fn store_refusal(&self) -> StoreRefusal {
        match self {
            Self::Log(error) => error.store_refusal(),
            _ => StoreRefusal::Failed,
        }
    }
}

impl fmt::Display for DurableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRoot => f.write_str("this stream directory keeps no durable streams"),
            Self::Identifier(error) => write!(f, "{error}"),
            Self::Config(error) => write!(f, "{error}"),
            Self::RetentionTooSmall {
                setting,
                needed,
                configured,
            } => write!(
                f,
                "the log's {setting} is {configured}; retention could drop the header of the \
                 segment being written below {needed}"
            ),
            Self::Log(error) => write!(f, "{error}"),
            Self::TailLost { truncated } => {
                f.write_str(
                    "lines the durable log acknowledged are gone from its end, so no record \
                     can be shown to continue the chain",
                )?;
                for range in truncated {
                    write!(
                        f,
                        "; log sequences {} to {} are gone",
                        range.first(),
                        range.last()
                    )?;
                }
                Ok(())
            }
            Self::Layout { sequence, problem } => {
                write!(
                    f,
                    "line {sequence} of the durable log is out of place: {problem}"
                )
            }
            Self::NothingRetained { dropped_entries } => write!(
                f,
                "retention dropped {dropped_entries} entries and left no segment header to \
                 continue from"
            ),
            Self::StillShared => f.write_str(
                "the stream's storage was still held elsewhere, so its release was left to \
                 drop, which cannot report a failure",
            ),
        }
    }
}

impl std::error::Error for DurableError {}

/// What opening a durable stream found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableOpening {
    /// How the previous owner left the log and the markers this open appended to it, such
    /// as a stale owner or a torn tail moved to quarantine.
    pub log: OpenReport,
    /// Every gap a reader of the log meets, in order: sequences retention dropped, and
    /// sequences a truncation or a torn tail burned.
    pub gaps: Vec<(SequenceRange, GapReason)>,
    /// What resuming found; `None` when the stream started at genesis.
    pub resume: Option<StreamResume>,
}

/// What opening the log found, before the stream starts or resumes on it.
#[derive(Debug)]
pub(super) struct Found {
    report: OpenReport,
    gaps: Vec<(SequenceRange, GapReason)>,
    /// The log holds no segment and dropped nothing: the stream starts at genesis.
    pub(super) fresh: bool,
}

impl Found {
    pub(super) fn into_opening(self, resume: Option<StreamResume>) -> DurableOpening {
        DurableOpening {
            log: self.report,
            gaps: self.gaps,
            resume,
        }
    }
}

/// The segments of one audit stream in its CORE-06 durable log, which this storage owns
/// alone: the log's stream owner refuses any other appender while it lives.
/// [`AuditStream::release`](super::AuditStream::release) releases the stream with how far
/// it was durable and reports the outcome; dropping the storage releases it as far as it
/// can, without a report.
#[derive(Debug)]
pub struct DurableSegments {
    log: DurableLog<SegmentLine>,
    journal: JournalId,
    /// The last header stored, and the seal that closed its segment, if any.
    last_header: Option<SegmentHeader>,
    last_seal: Option<SegmentSeal>,
    /// The last record stored.
    last_record: Option<AuditRecord>,
    /// The last error the log returned, which the journal sees only as a store refusal.
    last_error: Option<LogError>,
}

impl DurableSegments {
    /// Opens the log of `journal` in `directory` for `owner` and reads its segments back.
    /// Refuses while another owner holds the log, when lines it acknowledged are gone from
    /// its end, when its lines do not form segments, and when retention left no header.
    pub(super) fn open(
        directory: &Path,
        journal: &JournalId,
        owner: ProducerId,
        config: LogConfig,
    ) -> Result<(Self, Found), DurableError> {
        let stream = DurableStreamId::new(journal.as_str()).map_err(DurableError::Identifier)?;
        let (log, report) =
            DurableLog::open(directory, stream, owner, config).map_err(DurableError::Log)?;
        let layout = read_layout(&log)?;
        if log.record_lost() {
            return Err(DurableError::TailLost {
                truncated: layout
                    .gaps
                    .iter()
                    .filter(|(_, reason)| *reason == GapReason::Truncated)
                    .map(|(range, _)| *range)
                    .collect(),
            });
        }
        let dropped = log.retention();
        let retained = dropped.low_water.is_some() || layout.headless > 0;
        if layout.segments.is_empty() && retained {
            return Err(DurableError::NothingRetained {
                dropped_entries: dropped.dropped_entries,
            });
        }
        let last = layout.segments.last();
        let storage = Self {
            journal: journal.clone(),
            last_header: last.map(|segment| segment.header.clone()),
            last_seal: last.and_then(|segment| segment.seal.clone()),
            last_record: layout
                .segments
                .iter()
                .rev()
                .find_map(|segment| segment.records.last().cloned()),
            last_error: None,
            log,
        };
        let found = Found {
            fresh: layout.segments.is_empty() && !retained,
            report,
            gaps: layout.gaps,
        };
        Ok((storage, found))
    }

    /// The durable log, to read: a reader resumes from its cursor and meets every gap.
    pub fn log(&self) -> &DurableLog<SegmentLine> {
        &self.log
    }

    pub fn journal(&self) -> &JournalId {
        &self.journal
    }

    /// The last error the log returned on an append, which the journal saw only as a store
    /// refusal.
    pub fn last_error(&self) -> Option<&LogError> {
        self.last_error.as_ref()
    }

    /// Releases the log: its owner record says how far the stream is durable and that its
    /// owner left cleanly. On `Err` the lock is given up anyway, and the next owner finds a
    /// stale owner.
    pub(super) fn release(self) -> Result<(), DurableError> {
        self.log.close().map_err(DurableError::Log)
    }

    fn write(&mut self, line: SegmentLine) -> Result<(), StoreRefusal> {
        match self.log.append(line) {
            Ok(_) => Ok(()),
            Err(error) => {
                let refusal = error.store_refusal();
                self.last_error = Some(error);
                Err(refusal)
            }
        }
    }
}

impl SegmentStorage for DurableSegments {
    fn begin_segment(&mut self, header: &SegmentHeader) -> Result<(), StoreRefusal> {
        if self.last_header.as_ref() == Some(header) {
            return Ok(());
        }
        let expected = self
            .last_header
            .as_ref()
            .map_or(0, |last| last.index().saturating_add(1));
        if header.stream() != &self.journal || header.index() != expected {
            return Err(StoreRefusal::Failed);
        }
        self.write(SegmentLine::Header {
            header: header.clone(),
        })?;
        self.last_header = Some(header.clone());
        self.last_seal = None;
        Ok(())
    }

    fn append(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        if self.last_record.as_ref() == Some(record) {
            return Ok(());
        }
        if let Some(last) = &self.last_record {
            if record.sequence() <= last.sequence() {
                return if self.record(record.sequence())?.as_ref() == Some(record) {
                    Ok(())
                } else {
                    Err(StoreRefusal::Failed)
                };
            }
        }
        if self.last_header.is_none() || self.last_seal.is_some() {
            return Err(StoreRefusal::Failed);
        }
        self.write(SegmentLine::Record {
            record: Box::new(record.clone()),
        })?;
        self.last_record = Some(record.clone());
        Ok(())
    }

    fn seal_segment(&mut self, seal: &SegmentSeal) -> Result<(), StoreRefusal> {
        match (&self.last_header, &self.last_seal) {
            (_, Some(existing)) if existing == seal => return Ok(()),
            (Some(header), None)
                if seal.index() == header.index() && seal.header() == header.digest() => {}
            _ => return Err(StoreRefusal::Failed),
        }
        self.write(SegmentLine::Seal { seal: seal.clone() })?;
        self.last_seal = Some(seal.clone());
        Ok(())
    }

    fn segments(&self) -> Result<Vec<StoredSegment>, StoreRefusal> {
        read_layout(&self.log)
            .map(|layout| layout.segments)
            .map_err(|error| error.store_refusal())
    }

    fn record(&self, sequence: EventSequence) -> Result<Option<AuditRecord>, StoreRefusal> {
        Ok(self
            .segments()?
            .into_iter()
            .flat_map(|segment| segment.records)
            .find(|record| record.sequence() == sequence))
    }

    fn retention(&self) -> Result<Option<SegmentRetention>, StoreRefusal> {
        let dropped = self.log.retention();
        if dropped.low_water.is_none() {
            return Ok(None);
        }
        let layout = read_layout(&self.log).map_err(|error| error.store_refusal())?;
        Ok(Some(SegmentRetention {
            dropped_entries: dropped.dropped_entries,
            dropped_bytes: dropped.dropped_bytes,
            headless_entries: layout.headless,
        }))
    }
}

/// The log read back as segments.
#[derive(Debug, Default)]
struct Layout {
    segments: Vec<StoredSegment>,
    /// Lines before the first header retention left.
    headless: u64,
    gaps: Vec<(SequenceRange, GapReason)>,
}

/// Reads every line the log holds and files it into its segment; markers are the log's
/// own and belong to no segment.
fn read_layout(log: &DurableLog<SegmentLine>) -> Result<Layout, DurableError> {
    let batch = log
        .read(&log.start(), usize::MAX)
        .map_err(DurableError::Log)?;
    let dropped = log.retention().low_water.is_some();
    let mut layout = Layout::default();
    for item in batch.items {
        let (sequence, line) = match item {
            ReadItem::Gap { missing, reason } => {
                layout.gaps.push((missing, reason));
                continue;
            }
            ReadItem::Entry {
                entry: LogEntry::Marker(_),
                ..
            } => continue,
            ReadItem::Entry {
                sequence,
                entry: LogEntry::Record(line),
                ..
            } => (sequence, line),
        };
        let line = match line {
            SegmentLine::Header { header } => {
                layout.segments.push(StoredSegment {
                    header,
                    records: Vec::new(),
                    seal: None,
                });
                continue;
            }
            other => other,
        };
        match (line, layout.segments.last_mut()) {
            (SegmentLine::Record { record }, Some(segment)) if segment.seal.is_none() => {
                segment.records.push(*record);
            }
            (SegmentLine::Seal { seal }, Some(segment)) if segment.seal.is_none() => {
                segment.seal = Some(seal);
            }
            (_, Some(_)) => {
                return Err(DurableError::Layout {
                    sequence,
                    problem: LayoutProblem::AfterSeal,
                })
            }
            (_, None) if dropped => layout.headless = layout.headless.saturating_add(1),
            (_, None) => {
                return Err(DurableError::Layout {
                    sequence,
                    problem: LayoutProblem::BeforeHeader,
                })
            }
        }
    }
    Ok(layout)
}

/// Checks that retention under `log` keeps the header of the segment being written:
/// after any pass it keeps more entries than one segment's lines (its header, at most
/// `max_records_per_segment` records and its seal) and the markers of two opens, whether
/// the entry bound or the byte bound made it drop. Each line takes at most
/// `segment_bytes`, and the log drops at most one log segment more than its bounds ask.
pub fn check_retention(segment: &SegmentConfig, log: &LogConfig) -> Result<(), DurableError> {
    segment.validate().map_err(DurableError::Config)?;
    log.validate().map_err(DurableError::Config)?;
    let keep = segment
        .max_records_per_segment
        .saturating_add(2)
        .saturating_add(MARKERS_PER_OPEN.saturating_mul(OPENS_AFTER_HEADER));
    let entries = log.segment_entries.saturating_add(keep);
    if log.max_entries < entries {
        return Err(DurableError::RetentionTooSmall {
            setting: "max_entries",
            needed: entries,
            configured: log.max_entries,
        });
    }
    let bytes = log.segment_bytes.saturating_mul(keep.saturating_add(1));
    if log.max_bytes < bytes {
        return Err(DurableError::RetentionTooSmall {
            setting: "max_bytes",
            needed: bytes,
            configured: log.max_bytes,
        });
    }
    Ok(())
}

/// The name of a stream's directory under the root of a durable stream directory:
/// `audit-` and the stream's name, with ':' written `%3A` and a final '.' written `%2E`, so
/// that every name the identifier grammar allows is a plain directory name on Windows and
/// Unix, and distinct names stay distinct. On a file system that ignores case, two names
/// that differ only in case share a directory, and the log refuses the second as another
/// stream.
pub fn stream_directory_name(stream: &JournalId) -> String {
    let mut name = String::from("audit-");
    for character in stream.as_str().chars() {
        match character {
            ':' => name.push_str("%3A"),
            other => name.push(other),
        }
    }
    if name.ends_with('.') {
        name.pop();
        name.push_str("%2E");
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::audit::fakes::journal_id;

    fn config(max_entries: u64, max_bytes: u64) -> LogConfig {
        LogConfig {
            max_entries,
            max_bytes,
            segment_entries: 4,
            segment_bytes: 1_000,
        }
    }

    #[test]
    fn retention_bounds_keep_the_header_being_written() {
        let segment = SegmentConfig {
            max_records_per_segment: 3,
        };
        // One segment: a header, three records and a seal, then the markers of two opens.
        assert_eq!(check_retention(&segment, &config(15, 12_000)), Ok(()));
        assert_eq!(
            check_retention(&segment, &config(14, 12_000)),
            Err(DurableError::RetentionTooSmall {
                setting: "max_entries",
                needed: 15,
                configured: 14
            })
        );
        assert_eq!(
            check_retention(&segment, &config(15, 11_999)),
            Err(DurableError::RetentionTooSmall {
                setting: "max_bytes",
                needed: 12_000,
                configured: 11_999
            })
        );
        assert_eq!(
            check_retention(
                &SegmentConfig {
                    max_records_per_segment: 0
                },
                &config(15, 12_000)
            ),
            Err(DurableError::Config(ConfigError::Zero {
                setting: "max_records_per_segment"
            }))
        );
        assert!(matches!(
            check_retention(&segment, &config(0, 12_000)),
            Err(DurableError::Config(_))
        ));
    }

    #[test]
    fn directory_names_are_plain_and_distinct() {
        assert_eq!(stream_directory_name(&journal_id("engine")), "audit-engine");
        assert_eq!(
            stream_directory_name(&journal_id("host:warden.v1")),
            "audit-host%3Awarden.v1"
        );
        assert_eq!(stream_directory_name(&journal_id("a.")), "audit-a%2E");
        assert_ne!(
            stream_directory_name(&journal_id("a.")),
            stream_directory_name(&journal_id("a"))
        );
        for name in ["engine", "host:warden.v1", "a.", "x_y-z"] {
            let directory = stream_directory_name(&journal_id(name));
            assert!(
                !directory.contains(':') && !directory.ends_with('.'),
                "{directory}"
            );
        }
    }

    #[test]
    fn errors_describe_themselves() {
        assert!(serde_json::from_str::<SegmentLine>(r#"{"line":"other"}"#).is_err());
        let range = SequenceRange::single(EventSequence::FIRST);
        for error in [
            DurableError::NoRoot,
            DurableError::Config(ConfigError::Zero { setting: "x" }),
            DurableError::RetentionTooSmall {
                setting: "max_entries",
                needed: 2,
                configured: 1,
            },
            DurableError::TailLost {
                truncated: vec![range],
            },
            DurableError::Layout {
                sequence: EventSequence::FIRST,
                problem: LayoutProblem::BeforeHeader,
            },
            DurableError::Layout {
                sequence: EventSequence::FIRST,
                problem: LayoutProblem::AfterSeal,
            },
            DurableError::NothingRetained { dropped_entries: 3 },
            DurableError::StillShared,
        ] {
            assert!(!error.to_string().is_empty());
            assert_eq!(error.store_refusal(), StoreRefusal::Failed);
        }
        assert!(DurableError::TailLost {
            truncated: vec![range]
        }
        .to_string()
        .contains("log sequences 1 to 1 are gone"));
    }
}
