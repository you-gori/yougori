//! The journal of §3.10 line 652: job intent, artifact commits, resumable verified
//! extents and the import state they belong to, plus the incarnation of every start and
//! the CORE-04 coordinator's clock session it started on. A later start on the same
//! session finds that the coordinator never restarted, so everything it holds is from
//! before that start. Objects and extents are named as the CORE-02 catalog names them
//! (T05).
//!
//! It never persists device pointers, allocation handles, GPU leases, generations,
//! prompts or paths: no record has a field for them, and a line is read only if it
//! writes back exactly as read, so a field no record names is refused at any depth.
//! Generations and leases belong to the CORE-04 coordinator, which persists and recovers
//! them itself. No monotonic time is stored either, because it means nothing after a
//! restart.
//!
//! The file is append-only, one record per line: the hexadecimal domain-separated
//! digest of the JSON, a space, the JSON and a newline. A record counts once it is
//! written and synced; a torn or unchecked final line, which was never acknowledged, is
//! cut off when the journal opens. Any other damage refuses to open: a journal is never
//! read past a corrupt record.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::job::{ArtifactCommit, ImportState, JobIntent, JobOutcome, VerifiedExtent};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{digest, Digest, Incarnation, OperationId};

/// The journal's file name inside the directory the caller gives.
pub const JOURNAL_FILE_NAME: &str = "model-memory-progress.journal";

/// The journal format this build writes and reads. Format 2 records the coordinator's
/// clock session with every start's incarnation; format 1 did not.
pub const JOURNAL_FORMAT_VERSION: u32 = 2;

const LINE_DOMAIN: &str = "yougori/model-memory/progress/journal-line/v1";

/// One persisted record. Every variant has fields, so `deny_unknown_fields` refuses an
/// extra field next to any tag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
enum JournalRecord {
    Header {
        format: u32,
    },
    Incarnation {
        incarnation: Incarnation,
        session: ClockSession,
    },
    Intent {
        intent: JobIntent,
    },
    ArtifactCommitted {
        operation: OperationId,
        commit: ArtifactCommit,
    },
    ExtentVerified {
        operation: OperationId,
        extent: VerifiedExtent,
    },
    ImportReached {
        operation: OperationId,
        state: ImportState,
    },
    Finished {
        operation: OperationId,
        outcome: JobOutcome,
    },
}

crate::foundation::strict_serde::strict_tag!(JournalRecord, "type");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalLine {
    sequence: u64,
    record: JournalRecord,
}

#[derive(Serialize)]
struct JournalLineRef<'a> {
    sequence: u64,
    record: &'a JournalRecord,
}

/// Whether a write added a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recorded {
    Written,
    /// The same record is in the journal already; repeating it changes nothing.
    AlreadyPresent,
}

/// Why a record cannot be applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordRefusal {
    UnknownOperation,
    /// The job ended; only a repeat of a record it already has is accepted.
    JobFinished {
        outcome: JobOutcome,
    },
    /// Another intent is recorded under the same operation ID.
    IntentConflict,
    ZeroTotalBytes,
    /// The commit names another object or size than the intent, or another commit is
    /// recorded.
    ArtifactMismatch,
    /// The object is committed whole; no extents or import state follow.
    ArtifactAlreadyCommitted,
    EmptyExtent,
    ExtentOutOfRange,
    /// Another entry is recorded under the same extent number.
    ExtentConflict {
        extent: u32,
    },
    ExtentOverlap {
        extent: u32,
    },
    /// An incarnation is used once: each start's is above every earlier one, and the
    /// first is at least [`Incarnation::FIRST`].
    IncarnationNotAfter {
        last: Option<Incarnation>,
        found: Incarnation,
    },
    /// The job ended with another outcome.
    OutcomeConflict {
        recorded: JobOutcome,
    },
    /// A job completes only after its artifact is committed.
    CompletedWithoutArtifact,
    HeaderOutOfPlace,
}

/// The file operation that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalAction {
    Read,
    Truncate,
    Open,
    Append,
    Sync,
    Encode,
}

/// Why a journal line cannot be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorruptReason {
    /// The line lacks its checksum or the checksum does not match.
    BadCheck,
    /// The checksum matches but the record does not read back exactly as written, for
    /// example because it has a field no record names.
    Unparseable,
    SequenceOutOfOrder {
        expected: u64,
        found: u64,
    },
    MissingHeader,
    DuplicateRecord,
    Refused(RecordRefusal),
}

/// Why the journal refused an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalError {
    Io {
        action: JournalAction,
        kind: ErrorKind,
    },
    /// Line `line` (from 1) is damaged and lines after it exist, or it parses but is not
    /// a valid record.
    Corrupt {
        line: u64,
        reason: CorruptReason,
    },
    UnsupportedFormat {
        found: u32,
    },
    /// A write failed part-way; reopen the journal, which cuts the torn line off.
    Poisoned,
    SequenceExhausted,
    Refused(RecordRefusal),
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { action, kind } => write!(f, "journal {action:?} failed: {kind:?}"),
            Self::Corrupt { line, reason } => {
                write!(f, "journal line {line} is damaged: {reason:?}")
            }
            Self::UnsupportedFormat { found } => write!(
                f,
                "journal format {found} is not supported; this build reads format \
                 {JOURNAL_FORMAT_VERSION}"
            ),
            Self::Poisoned => f.write_str("a journal write failed; reopen the journal"),
            Self::SequenceExhausted => f.write_str("the journal sequence is exhausted"),
            Self::Refused(refusal) => write!(f, "the journal refused the record: {refusal:?}"),
        }
    }
}

impl std::error::Error for JournalError {}

/// What opening the journal found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JournalOpened {
    /// Records replayed, the header included.
    pub records: u64,
    /// Bytes of a torn final line that were cut off.
    pub discarded_tail_bytes: u64,
}

/// What the journal knows about one job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobRecord {
    intent: JobIntent,
    artifact: Option<ArtifactCommit>,
    extents: BTreeMap<u32, VerifiedExtent>,
    /// Extent ends by start offset, for the overlap check.
    ranges: BTreeMap<u64, u64>,
    import: Option<ImportState>,
    outcome: Option<JobOutcome>,
}

impl JobRecord {
    pub fn intent(&self) -> &JobIntent {
        &self.intent
    }

    pub fn artifact(&self) -> Option<&ArtifactCommit> {
        self.artifact.as_ref()
    }

    /// Verified extents by extent number.
    pub fn verified_extents(&self) -> impl Iterator<Item = &VerifiedExtent> {
        self.extents.values()
    }

    /// Where the job's import last stood.
    pub fn import_state(&self) -> Option<&ImportState> {
        self.import.as_ref()
    }

    pub fn outcome(&self) -> Option<JobOutcome> {
        self.outcome
    }

    fn overlaps(&self, start: u64, end: u64) -> bool {
        let before = self
            .ranges
            .range(..=start)
            .next_back()
            .is_some_and(|(_, &previous_end)| previous_end > start);
        let after = self
            .ranges
            .range(start..)
            .next()
            .is_some_and(|(&next_start, _)| next_start < end);
        before || after
    }

    /// Repeats of what the job holds are accepted after it ended; anything new is not,
    /// and nothing about the import follows a committed artifact.
    fn open_for_import(&self) -> Result<(), RecordRefusal> {
        if let Some(outcome) = self.outcome {
            return Err(RecordRefusal::JobFinished { outcome });
        }
        if self.artifact.is_some() {
            return Err(RecordRefusal::ArtifactAlreadyCommitted);
        }
        Ok(())
    }
}

/// The state a journal replays to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JournalState {
    /// Every start's incarnation and the coordinator's clock session it started on, in
    /// order.
    starts: Vec<(Incarnation, ClockSession)>,
    jobs: BTreeMap<OperationId, JobRecord>,
}

enum Effect {
    Apply,
    AlreadyPresent,
}

impl JournalState {
    /// The incarnation of the latest start.
    pub fn incarnation(&self) -> Option<Incarnation> {
        self.starts.last().map(|&(incarnation, _)| incarnation)
    }

    /// The latest start that ran on the coordinator's clock `session`, if any did.
    pub fn started_on(&self, session: ClockSession) -> Option<Incarnation> {
        self.starts
            .iter()
            .rev()
            .find(|&&(_, started)| started == session)
            .map(|&(incarnation, _)| incarnation)
    }

    pub fn job(&self, operation: &OperationId) -> Option<&JobRecord> {
        self.jobs.get(operation)
    }

    pub fn jobs(&self) -> impl Iterator<Item = &JobRecord> {
        self.jobs.values()
    }

    /// Jobs without an outcome, in operation ID order.
    pub fn unfinished(&self) -> impl Iterator<Item = &JobRecord> {
        self.jobs.values().filter(|job| job.outcome.is_none())
    }

    fn job_for(&self, operation: &OperationId) -> Result<&JobRecord, RecordRefusal> {
        self.jobs
            .get(operation)
            .ok_or(RecordRefusal::UnknownOperation)
    }

    fn check(&self, record: &JournalRecord) -> Result<Effect, RecordRefusal> {
        match record {
            JournalRecord::Header { .. } => Err(RecordRefusal::HeaderOutOfPlace),
            JournalRecord::Incarnation { incarnation, .. } => {
                let last = self.incarnation();
                let after = match last {
                    None => *incarnation >= Incarnation::FIRST,
                    Some(last) => *incarnation > last,
                };
                if after {
                    Ok(Effect::Apply)
                } else {
                    Err(RecordRefusal::IncarnationNotAfter {
                        last,
                        found: *incarnation,
                    })
                }
            }
            JournalRecord::Intent { intent } => match self.jobs.get(&intent.operation) {
                Some(job) if job.intent == *intent => Ok(Effect::AlreadyPresent),
                Some(_) => Err(RecordRefusal::IntentConflict),
                None if intent.total_bytes == 0 => Err(RecordRefusal::ZeroTotalBytes),
                None => Ok(Effect::Apply),
            },
            JournalRecord::ArtifactCommitted { operation, commit } => {
                let job = self.job_for(operation)?;
                match job.artifact {
                    Some(existing) if existing == *commit => return Ok(Effect::AlreadyPresent),
                    Some(_) => return Err(RecordRefusal::ArtifactMismatch),
                    None => {}
                }
                if let Some(outcome) = job.outcome {
                    return Err(RecordRefusal::JobFinished { outcome });
                }
                if commit.object != job.intent.object()
                    || commit.total_bytes != job.intent.total_bytes
                {
                    return Err(RecordRefusal::ArtifactMismatch);
                }
                Ok(Effect::Apply)
            }
            JournalRecord::ExtentVerified { operation, extent } => {
                let job = self.job_for(operation)?;
                match job.extents.get(&extent.extent) {
                    Some(existing) if existing == extent => return Ok(Effect::AlreadyPresent),
                    Some(_) => {
                        return Err(RecordRefusal::ExtentConflict {
                            extent: extent.extent,
                        })
                    }
                    None => {}
                }
                job.open_for_import()?;
                if extent.entry.length_bytes == 0 {
                    return Err(RecordRefusal::EmptyExtent);
                }
                let end = extent
                    .end_bytes()
                    .filter(|&end| end <= job.intent.total_bytes)
                    .ok_or(RecordRefusal::ExtentOutOfRange)?;
                if job.overlaps(extent.entry.offset_bytes, end) {
                    return Err(RecordRefusal::ExtentOverlap {
                        extent: extent.extent,
                    });
                }
                Ok(Effect::Apply)
            }
            JournalRecord::ImportReached { operation, state } => {
                let job = self.job_for(operation)?;
                if job.import.as_ref() == Some(state) {
                    return Ok(Effect::AlreadyPresent);
                }
                job.open_for_import()?;
                Ok(Effect::Apply)
            }
            JournalRecord::Finished { operation, outcome } => {
                let job = self.job_for(operation)?;
                match job.outcome {
                    Some(recorded) if recorded == *outcome => Ok(Effect::AlreadyPresent),
                    Some(recorded) => Err(RecordRefusal::OutcomeConflict { recorded }),
                    None if *outcome == JobOutcome::Completed && job.artifact.is_none() => {
                        Err(RecordRefusal::CompletedWithoutArtifact)
                    }
                    None => Ok(Effect::Apply),
                }
            }
        }
    }

    /// Applies a record that [`JournalState::check`] accepted.
    fn apply(&mut self, record: JournalRecord) {
        match record {
            JournalRecord::Header { .. } => {}
            JournalRecord::Incarnation {
                incarnation,
                session,
            } => self.starts.push((incarnation, session)),
            JournalRecord::Intent { intent } => {
                self.jobs.insert(
                    intent.operation.clone(),
                    JobRecord {
                        intent,
                        artifact: None,
                        extents: BTreeMap::new(),
                        ranges: BTreeMap::new(),
                        import: None,
                        outcome: None,
                    },
                );
            }
            JournalRecord::ArtifactCommitted { operation, commit } => {
                if let Some(job) = self.jobs.get_mut(&operation) {
                    job.artifact = Some(commit);
                }
            }
            JournalRecord::ExtentVerified { operation, extent } => {
                if let Some(job) = self.jobs.get_mut(&operation) {
                    if let Some(end) = extent.end_bytes() {
                        job.ranges.insert(extent.entry.offset_bytes, end);
                    }
                    job.extents.insert(extent.extent, extent);
                }
            }
            JournalRecord::ImportReached { operation, state } => {
                if let Some(job) = self.jobs.get_mut(&operation) {
                    job.import = Some(state);
                }
            }
            JournalRecord::Finished { operation, outcome } => {
                if let Some(job) = self.jobs.get_mut(&operation) {
                    job.outcome = Some(outcome);
                }
            }
        }
    }
}

/// The append-only journal in one directory (§3.10 line 652). Only [`super::JobControl`]
/// opens and writes it, so every start goes through restart reconciliation.
pub struct Journal {
    file: File,
    state: JournalState,
    next_sequence: u64,
    poisoned: bool,
}

impl Journal {
    /// Opens or creates the journal in `dir` and replays it.
    pub(super) fn open(dir: &Path) -> Result<(Self, JournalOpened), JournalError> {
        let path = dir.join(JOURNAL_FILE_NAME);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(io_error(JournalAction::Read, &error)),
        };
        let replay = replay(&bytes)?;
        let discarded_tail_bytes = (bytes.len() - replay.kept_bytes) as u64;
        if discarded_tail_bytes > 0 {
            let file = OpenOptions::new()
                .write(true)
                .open(&path)
                .map_err(|error| io_error(JournalAction::Truncate, &error))?;
            file.set_len(replay.kept_bytes as u64)
                .map_err(|error| io_error(JournalAction::Truncate, &error))?;
            file.sync_all()
                .map_err(|error| io_error(JournalAction::Sync, &error))?;
        }
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)
            .map_err(|error| io_error(JournalAction::Open, &error))?;
        let mut journal = Self {
            file,
            state: replay.state,
            next_sequence: replay.records.saturating_add(1),
            poisoned: false,
        };
        let mut records = replay.records;
        if records == 0 {
            journal.append(&JournalRecord::Header {
                format: JOURNAL_FORMAT_VERSION,
            })?;
            sync_directory(dir)?;
            records = 1;
        }
        Ok((
            journal,
            JournalOpened {
                records,
                discarded_tail_bytes,
            },
        ))
    }

    pub fn state(&self) -> &JournalState {
        &self.state
    }

    /// Records this start's incarnation durably, with the coordinator's clock `session`
    /// it starts on. The incarnation must be above every one recorded before, so none is
    /// ever used twice.
    pub(super) fn begin_incarnation(
        &mut self,
        incarnation: Incarnation,
        session: ClockSession,
    ) -> Result<(), JournalError> {
        self.write(JournalRecord::Incarnation {
            incarnation,
            session,
        })
        .map(drop)
    }

    pub(super) fn record_intent(&mut self, intent: JobIntent) -> Result<Recorded, JournalError> {
        self.write(JournalRecord::Intent { intent })
    }

    pub(super) fn record_artifact_commit(
        &mut self,
        operation: &OperationId,
        commit: ArtifactCommit,
    ) -> Result<Recorded, JournalError> {
        self.write(JournalRecord::ArtifactCommitted {
            operation: operation.clone(),
            commit,
        })
    }

    pub(super) fn record_verified_extent(
        &mut self,
        operation: &OperationId,
        extent: VerifiedExtent,
    ) -> Result<Recorded, JournalError> {
        self.write(JournalRecord::ExtentVerified {
            operation: operation.clone(),
            extent,
        })
    }

    pub(super) fn record_import_state(
        &mut self,
        operation: &OperationId,
        state: ImportState,
    ) -> Result<Recorded, JournalError> {
        self.write(JournalRecord::ImportReached {
            operation: operation.clone(),
            state,
        })
    }

    pub(super) fn record_finished(
        &mut self,
        operation: &OperationId,
        outcome: JobOutcome,
    ) -> Result<Recorded, JournalError> {
        self.write(JournalRecord::Finished {
            operation: operation.clone(),
            outcome,
        })
    }

    fn write(&mut self, record: JournalRecord) -> Result<Recorded, JournalError> {
        match self.state.check(&record).map_err(JournalError::Refused)? {
            Effect::AlreadyPresent => Ok(Recorded::AlreadyPresent),
            Effect::Apply => {
                self.append(&record)?;
                self.state.apply(record);
                Ok(Recorded::Written)
            }
        }
    }

    /// Writes and syncs one line; the record counts only after both succeed.
    fn append(&mut self, record: &JournalRecord) -> Result<(), JournalError> {
        if self.poisoned {
            return Err(JournalError::Poisoned);
        }
        let following = self
            .next_sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceExhausted)?;
        let json = serde_json::to_string(&JournalLineRef {
            sequence: self.next_sequence,
            record,
        })
        .map_err(|_| JournalError::Io {
            action: JournalAction::Encode,
            kind: ErrorKind::InvalidData,
        })?;
        let line = format!("{} {json}\n", line_check(json.as_bytes()).to_hex());
        if let Err(error) = self.file.write_all(line.as_bytes()) {
            self.poisoned = true;
            return Err(io_error(JournalAction::Append, &error));
        }
        if let Err(error) = self.file.sync_data() {
            self.poisoned = true;
            return Err(io_error(JournalAction::Sync, &error));
        }
        self.next_sequence = following;
        Ok(())
    }
}

fn line_check(json: &[u8]) -> Digest {
    digest(LINE_DOMAIN, &[json])
}

fn io_error(action: JournalAction, error: &std::io::Error) -> JournalError {
    JournalError::Io {
        action,
        kind: error.kind(),
    }
}

/// Makes a new journal file's directory entry durable where the platform allows it.
#[cfg(unix)]
fn sync_directory(dir: &Path) -> Result<(), JournalError> {
    File::open(dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error(JournalAction::Sync, &error))
}

/// Windows cannot open a directory as a file; NTFS journals the new entry itself.
#[cfg(not(unix))]
fn sync_directory(_dir: &Path) -> Result<(), JournalError> {
    Ok(())
}

struct Replay {
    state: JournalState,
    records: u64,
    kept_bytes: usize,
}

/// How a line failed: a torn line may only be the last one.
enum LineFailure {
    Torn,
    Corrupt(CorruptReason),
}

fn replay(bytes: &[u8]) -> Result<Replay, JournalError> {
    let mut state = JournalState::default();
    let mut records = 0_u64;
    let mut offset = 0_usize;
    let mut line_number = 0_u64;
    while let Some(rest) = bytes.get(offset..).filter(|rest| !rest.is_empty()) {
        line_number += 1;
        // No newline: the write never completed, so the record never counted.
        let Some(newline) = rest.iter().position(|&byte| byte == b'\n') else {
            break;
        };
        let consumed = newline + 1;
        let is_last = offset + consumed >= bytes.len();
        let line = rest.get(..newline).unwrap_or_default();
        let corrupt = |reason| JournalError::Corrupt {
            line: line_number,
            reason,
        };
        let parsed = match parse_line(line) {
            Ok(parsed) => parsed,
            Err(LineFailure::Torn) if is_last => break,
            Err(LineFailure::Torn) => return Err(corrupt(CorruptReason::BadCheck)),
            Err(LineFailure::Corrupt(reason)) => return Err(corrupt(reason)),
        };
        let expected = records + 1;
        if parsed.sequence != expected {
            return Err(corrupt(CorruptReason::SequenceOutOfOrder {
                expected,
                found: parsed.sequence,
            }));
        }
        match (records, parsed.record) {
            (0, JournalRecord::Header { format }) if format == JOURNAL_FORMAT_VERSION => {}
            (0, JournalRecord::Header { format }) => {
                return Err(JournalError::UnsupportedFormat { found: format })
            }
            (0, _) => return Err(corrupt(CorruptReason::MissingHeader)),
            (_, record) => match state.check(&record) {
                Ok(Effect::Apply) => state.apply(record),
                Ok(Effect::AlreadyPresent) => return Err(corrupt(CorruptReason::DuplicateRecord)),
                Err(refusal) => return Err(corrupt(CorruptReason::Refused(refusal))),
            },
        }
        records = expected;
        offset += consumed;
    }
    Ok(Replay {
        state,
        records,
        kept_bytes: offset,
    })
}

/// Reads one line. A checksum failure is a torn write; a line whose checksum matches
/// must also write back exactly as read, so a field no record names, at any depth, is
/// refused rather than dropped.
fn parse_line(line: &[u8]) -> Result<JournalLine, LineFailure> {
    let text = std::str::from_utf8(line).map_err(|_| LineFailure::Torn)?;
    let (check, json) = text.split_once(' ').ok_or(LineFailure::Torn)?;
    let check = Digest::from_hex(check).map_err(|_| LineFailure::Torn)?;
    if check != line_check(json.as_bytes()) {
        return Err(LineFailure::Torn);
    }
    let unparseable = |_| LineFailure::Corrupt(CorruptReason::Unparseable);
    let value: Value = serde_json::from_str(json).map_err(unparseable)?;
    let parsed: JournalLine = serde_json::from_value(value.clone()).map_err(unparseable)?;
    let written = serde_json::to_value(JournalLineRef {
        sequence: parsed.sequence,
        record: &parsed.record,
    })
    .map_err(unparseable)?;
    if written != value {
        return Err(LineFailure::Corrupt(CorruptReason::Unparseable));
    }
    Ok(parsed)
}
