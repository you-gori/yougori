//! The bounded local spool of a durable audit stream, kept on file
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: §8.2 at lines 2441–2450, line 2445
//! "deny new high-impact operations or use a bounded local spool; never block the
//! revocation channel"; VM-W42 at line 2665 "bounded queues" and "restart/truncation, disk
//! full ... tested"; VM-W43 at line 2666 "audit overload cannot block emergency
//! revocation"; docs/combined-plan-leftover-tasks.md S06 "a file-backed `AuditSpool`").
//!
//! A [`FileSpool`] is the CORE-06 [`AuditSpool`] of one durable stream: the records the
//! journal accepted while the stream's log refused them, kept in order until the log takes
//! them. It lives in the `spool` directory inside the stream's own directory
//! ([`StreamDirectory::spool_path`](super::StreamDirectory::spool_path)) and is opened only
//! by [`AuditStream::open_durable_spooled`](super::AuditStream::open_durable_spooled),
//! after the log, so the owner that holds the log's lock is the spool's only writer too.
//!
//! - Bounded. It holds at most the journal's `spool_records` and refuses a record past
//!   that as full. It refuses nothing else the journal allows, so the revocation reserve
//!   is kept exactly as an in-memory spool keeps it: the journal decides which records may
//!   use the reserve, and the spool never takes that room away. A file that holds more
//!   records than the bound was written under a larger one; opening it under this bound
//!   would leave revocations less than the reserve, so the spool refuses to open
//!   ([`SpoolError::OverBound`]) until the bound is at least what it holds. Its file stays
//!   short: once the spool is empty the file is cut to nothing, and once its removal lines
//!   reach the bound it is rewritten with only the records still held, so while those
//!   succeed it holds fewer than three times the bound in lines.
//! - Durable and ordered. One line per record taken and per record removed: the hex digest
//!   of the line's JSON, bound to the journal, a space, then the JSON. A push or a removal
//!   returns `Ok` once its line is synced; a failed write is cut back off before the
//!   refusal returns, so the file holds a whole line or none of it. A record must continue
//!   the newest record held, by sequence and by digest, and only the oldest can be removed.
//!   Opening replays the lines in order, so after a restart the spool holds exactly the
//!   records it took and had not removed, and the journal resumes after the last of them.
//! - Torn tail reported. A last line that is incomplete or does not verify is a write that
//!   never completed: an acknowledged line was synced whole before its `Ok`. Its bytes are
//!   moved to a quarantine file beside the spool, never deleted, the line is cut off, and
//!   the opening reports both ([`SpoolTornTail`]). Any other line that does not verify, a
//!   record that does not continue the one before it, or a removal of a record that is not
//!   the oldest is damage: the spool refuses to open ([`SpoolError::Damaged`]) and the
//!   stream with it, until someone looks at the file.
//!
//! The line digests detect damage, not tampering: whoever can write the directory can
//! rewrite the lines. The journal verifies the spooled records as a continuation of its
//! chain when it resumes and refuses records that are not one.

use std::collections::VecDeque;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::durable::DurableOpening;
use crate::foundation::events::{
    AuditConfig, AuditRecord, AuditSpool, ConfigError, EventSequence, JournalId, SequenceRange,
    StoreRefusal,
};
use crate::foundation::ids::{Digest, DigestBuilder};

/// The spool's directory inside its stream's directory.
pub(super) const SPOOL_DIRECTORY: &str = "spool";
/// The spool's lines.
pub(super) const SPOOL_FILE: &str = "spool.jsonl";
/// A rewrite of the spool's lines before it is renamed into place.
const REWRITE_FILE: &str = "spool.tmp";
const QUARANTINE_PREFIX: &str = "torn-";
const QUARANTINE_EXTENSION: &str = "bin";
/// Quarantine names tried before an open is refused.
const MAX_QUARANTINE_NAMES: u32 = 1_000;
const LINE_DOMAIN: &str = "yougori/sandbox/audit/spool-line/v1";
/// 64 hexadecimal digits of the line digest, then one space.
const CHECK_BYTES: usize = 65;

strict_tagged_enum! {
    /// One line of a spool file.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(super) enum SpoolLine (tag = "line", wire = SpoolLineWire, wire_name = "SpoolLineWire") {
        /// A record the spool took, after every record it holds.
        Spooled { record: Box<AuditRecord> },
        /// The oldest record left the spool once storage held it.
        Removed { sequence: EventSequence, digest: Digest },
    }
}

/// What is wrong with one line of a spool file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpoolProblem {
    /// The line's digest is missing or does not match: it is damaged, or it was written
    /// for another journal.
    Checksum,
    /// The line verifies but is not a spool line.
    Encoding,
    /// The line holds a record of another journal.
    OtherJournal { sequence: EventSequence },
    /// The record does not continue `previous`, the newest record held, by sequence or by
    /// digest.
    OutOfOrder {
        previous: EventSequence,
        found: EventSequence,
    },
    /// The line removes `found` while `expected` is the oldest record held, or none is.
    Removal {
        expected: Option<EventSequence>,
        found: EventSequence,
    },
}

impl fmt::Display for SpoolProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Checksum => f.write_str("its digest does not match"),
            Self::Encoding => f.write_str("it is not a spool line"),
            Self::OtherJournal { sequence } => {
                write!(f, "it holds record {sequence} of another journal")
            }
            Self::OutOfOrder { previous, found } => {
                write!(f, "record {found} does not continue record {previous}")
            }
            Self::Removal {
                expected: Some(expected),
                found,
            } => write!(
                f,
                "it removes record {found} while {expected} is the oldest"
            ),
            Self::Removal {
                expected: None,
                found,
            } => write!(f, "it removes record {found} from an empty spool"),
        }
    }
}

/// Why a spool could not be opened. Each refusal fails closed: no spool, no stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpoolError {
    Config(ConfigError),
    Io {
        action: &'static str,
        kind: io::ErrorKind,
        message: String,
    },
    /// Line `line` (from 1) is not what it should be, and it is not a torn last line.
    Damaged {
        line: u64,
        problem: SpoolProblem,
    },
    /// The spool holds `held` records, more than its `bound`: it was written under a larger
    /// `spool_records`. Under this bound the records it holds would take slots of the
    /// revocation reserve, so it does not open until the bound is at least `held`.
    OverBound {
        held: usize,
        bound: usize,
    },
}

impl SpoolError {
    fn io(action: &'static str, error: &io::Error) -> Self {
        Self::Io {
            action,
            kind: error.kind(),
            message: error.to_string(),
        }
    }
}

impl fmt::Display for SpoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(f, "{error}"),
            Self::Io {
                action, message, ..
            } => write!(f, "could not {action}: {message}"),
            Self::Damaged { line, problem } => {
                write!(f, "line {line} of the audit spool is damaged: {problem}")
            }
            Self::OverBound { held, bound } => write!(
                f,
                "the audit spool holds {held} records, more than its bound of {bound}; it opens \
                 under a bound of at least {held}"
            ),
        }
    }
}

impl std::error::Error for SpoolError {}

/// A torn last line found when the spool was opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpoolTornTail {
    /// The line's bytes, moved to `quarantine`.
    pub bytes: u64,
    /// The quarantine file's name in the spool's directory.
    pub quarantine: String,
}

/// What opening a spool found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpoolOpening {
    /// The sequences of the records the spool holds, oldest to newest; `None` when it holds
    /// none.
    pub held: Option<SequenceRange>,
    /// The torn last line moved to quarantine, if the file ended in one.
    pub torn_tail: Option<SpoolTornTail>,
    /// A stop interrupted a rewrite of the file: its temporary file was removed, and the
    /// spool kept the lines it had before.
    pub interrupted_rewrite: bool,
}

/// What opening a durable stream with its spool on file found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpooledOpening {
    /// What the log held and what resuming found, as
    /// [`AuditStream::open_durable`](super::AuditStream::open_durable) reports it.
    pub durable: DurableOpening,
    /// What the spool held when it was opened, before the stream offered its records to
    /// the log again.
    pub spool: SpoolOpening,
}

/// A failure the tests inject into the next write.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(super) enum SpoolFault {
    /// The write fails as `kind` before anything is written.
    Refuse(io::ErrorKind),
    /// Half the line is written, then the write fails and cannot be cut back off, as when
    /// the process stops in the middle of it.
    Torn,
}

/// The bounded spool of one durable audit stream on file. Not `Clone`: one spool per
/// stream, opened under the stream's owner.
#[derive(Debug)]
pub struct FileSpool {
    journal: JournalId,
    directory: PathBuf,
    capacity: usize,
    records: VecDeque<AuditRecord>,
    /// The file, open for writing; `None` after a rewrite closed it, until the next write.
    file: Option<File>,
    /// The length of the file's whole lines: where the next line goes.
    length: u64,
    /// Removal lines in the file.
    removals: usize,
    /// A failed write could not be cut back off: the file may hold part of a line past
    /// `length`, which goes before anything else is written.
    torn: bool,
    #[cfg(test)]
    fault: Option<SpoolFault>,
}

impl FileSpool {
    /// Opens the spool of `journal` in `directory`, creating it if needed, with the bound
    /// of `audit`. Replays its lines, quarantines a torn last line, and refuses damage and
    /// more records than the bound. The caller holds the owner of the stream the spool
    /// belongs to.
    pub(super) fn open(
        directory: &Path,
        journal: &JournalId,
        audit: &AuditConfig,
    ) -> Result<(Self, SpoolOpening), SpoolError> {
        audit.validate().map_err(SpoolError::Config)?;
        fs::create_dir_all(directory)
            .map_err(|error| SpoolError::io("create the spool directory", &error))?;
        let interrupted_rewrite = match fs::remove_file(directory.join(REWRITE_FILE)) {
            Ok(()) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(SpoolError::io(
                    "remove an interrupted rewrite of the spool",
                    &error,
                ))
            }
        };
        let path = directory.join(SPOOL_FILE);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(SpoolError::io("read the spool", &error)),
        };
        let replay = replay(journal, &bytes)?;
        if replay.records.len() > audit.spool_records {
            return Err(SpoolError::OverBound {
                held: replay.records.len(),
                bound: audit.spool_records,
            });
        }
        let torn_tail = match bytes.get(replay.length..).filter(|torn| !torn.is_empty()) {
            Some(torn) => Some(quarantine(directory, &path, torn, replay.length)?),
            None => None,
        };
        let file = open_lines(&path).map_err(|error| SpoolError::io("open the spool", &error))?;
        let mut spool = Self {
            journal: journal.clone(),
            directory: directory.to_path_buf(),
            capacity: audit.spool_records,
            records: replay.records,
            file: Some(file),
            length: u64::try_from(replay.length).unwrap_or(u64::MAX),
            removals: replay.removals,
            torn: false,
            #[cfg(test)]
            fault: None,
        };
        spool.compact();
        let opening = SpoolOpening {
            held: spool.held(),
            torn_tail,
            interrupted_rewrite,
        };
        Ok((spool, opening))
    }

    /// The sequences of the records held, oldest to newest.
    pub fn held(&self) -> Option<SequenceRange> {
        let first = self.records.front()?.sequence();
        let last = self.records.back()?.sequence();
        SequenceRange::new(first, last)
    }

    /// The records the spool holds at most: the journal's `spool_records`.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn journal(&self) -> &JournalId {
        &self.journal
    }

    #[cfg(test)]
    pub(super) fn inject(&mut self, fault: SpoolFault) {
        self.fault = Some(fault);
    }

    fn path(&self) -> PathBuf {
        self.directory.join(SPOOL_FILE)
    }

    fn file(&mut self) -> Result<&mut File, StoreRefusal> {
        if self.file.is_none() {
            let file = open_lines(&self.path()).map_err(|error| refusal(&error))?;
            self.file = Some(file);
        }
        self.file.as_mut().ok_or(StoreRefusal::Failed)
    }

    /// Cuts off what a failed write left past the whole lines, before anything else.
    fn heal(&mut self) -> Result<(), StoreRefusal> {
        if !self.torn {
            return Ok(());
        }
        let length = self.length;
        if cut_back(self.file()?, length) {
            self.torn = false;
            Ok(())
        } else {
            Err(StoreRefusal::Failed)
        }
    }

    /// Writes `line` after the whole lines and syncs it; on failure it is cut back off.
    fn write(&mut self, line: &SpoolLine) -> Result<(), StoreRefusal> {
        self.heal()?;
        let bytes = encode_line(&self.journal, line).map_err(|_| StoreRefusal::Failed)?;
        let offset = self.length;
        #[cfg(test)]
        if let Some(fault) = self.fault.take() {
            return self.fail(offset, &bytes, fault);
        }
        let file = self.file()?;
        match write_at(file, offset, &bytes) {
            Ok(()) => {
                let written = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                self.length = offset.saturating_add(written);
                Ok(())
            }
            Err(error) => {
                if !cut_back(file, offset) {
                    self.torn = true;
                }
                Err(refusal(&error))
            }
        }
    }

    #[cfg(test)]
    fn fail(&mut self, offset: u64, bytes: &[u8], fault: SpoolFault) -> Result<(), StoreRefusal> {
        match fault {
            SpoolFault::Refuse(kind) => Err(refusal(&io::Error::from(kind))),
            SpoolFault::Torn => {
                let half = bytes.get(..bytes.len() / 2).unwrap_or_default();
                let file = self.file()?;
                write_at(file, offset, half).map_err(|error| refusal(&error))?;
                self.torn = true;
                Err(StoreRefusal::Failed)
            }
        }
    }

    /// Keeps the file short: cut to nothing once the spool is empty, rewritten with only
    /// the records held once its removal lines reach the bound. A failure changes nothing
    /// the lines say, and the next removal tries again.
    fn compact(&mut self) {
        if self.torn {
            return;
        }
        if self.records.is_empty() {
            if self.length > 0 && self.file().is_ok_and(|file| cut_back(file, 0)) {
                self.length = 0;
                self.removals = 0;
            }
            return;
        }
        if self.removals >= self.capacity {
            // The lines still say the same if the rewrite fails.
            let _unchanged = self.rewrite();
        }
    }

    /// Replaces the file with one line per record held: written to a temporary file,
    /// synced and renamed over it, so a stop leaves the old lines or the new ones.
    fn rewrite(&mut self) -> io::Result<()> {
        let mut bytes = Vec::new();
        for record in &self.records {
            let line = SpoolLine::Spooled {
                record: Box::new(record.clone()),
            };
            bytes.extend(encode_line(&self.journal, &line).map_err(io::Error::other)?);
        }
        let temporary = self.directory.join(REWRITE_FILE);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        // The spool's own handle closes first: a platform may refuse to replace an open
        // file. The next write opens it again.
        self.file = None;
        fs::rename(&temporary, self.path())?;
        self.length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.removals = 0;
        sync_dir(&self.directory)
    }
}

impl AuditSpool for FileSpool {
    /// Keeps `record` after every record held, durably before `Ok`. Refused as full at the
    /// bound, and as failed when the record belongs to another journal or does not
    /// continue the newest record held.
    fn push(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        if self.records.len() >= self.capacity {
            return Err(StoreRefusal::Full);
        }
        if record.journal() != &self.journal {
            return Err(StoreRefusal::Failed);
        }
        if let Some(newest) = self.records.back() {
            if !continues(newest, record) {
                return Err(StoreRefusal::Failed);
            }
        }
        self.write(&SpoolLine::Spooled {
            record: Box::new(record.clone()),
        })?;
        self.records.push_back(record.clone());
        Ok(())
    }

    fn front(&self) -> Result<Option<AuditRecord>, StoreRefusal> {
        Ok(self.records.front().cloned())
    }

    /// Removes the oldest record, durably before `Ok`; an empty spool removes nothing.
    fn pop_front(&mut self) -> Result<(), StoreRefusal> {
        let Some(oldest) = self.records.front() else {
            return Ok(());
        };
        let line = SpoolLine::Removed {
            sequence: oldest.sequence(),
            digest: oldest.digest(),
        };
        self.write(&line)?;
        self.records.pop_front();
        self.removals = self.removals.saturating_add(1);
        self.compact();
        Ok(())
    }

    fn len(&self) -> usize {
        self.records.len()
    }

    fn records(&self) -> Result<Vec<AuditRecord>, StoreRefusal> {
        Ok(self.records.iter().cloned().collect())
    }
}

/// Whether `record` is the one after `newest` in the chain.
fn continues(newest: &AuditRecord, record: &AuditRecord) -> bool {
    newest.sequence().next() == Some(record.sequence()) && record.previous() == newest.digest()
}

/// The lines of a spool file replayed.
#[derive(Debug, Default)]
struct Replay {
    records: VecDeque<AuditRecord>,
    removals: usize,
    /// The length of the whole lines that verified; a torn last line starts here.
    length: usize,
}

/// Replays the lines of a spool file in order. A last line that is incomplete or does not
/// verify ends the replay; any other problem is damage.
fn replay(journal: &JournalId, bytes: &[u8]) -> Result<Replay, SpoolError> {
    let mut replay = Replay::default();
    let mut line_number: u64 = 0;
    while let Some(rest) = bytes.get(replay.length..).filter(|rest| !rest.is_empty()) {
        line_number = line_number.saturating_add(1);
        let Some(end) = rest.iter().position(|byte| *byte == b'\n') else {
            break;
        };
        let line = rest.get(..end).unwrap_or_default();
        let last = end.saturating_add(1) == rest.len();
        let decoded = match decode_line(journal, line) {
            Ok(decoded) => decoded,
            Err(_) if last => break,
            Err(problem) => {
                return Err(SpoolError::Damaged {
                    line: line_number,
                    problem,
                })
            }
        };
        apply(journal, &mut replay, decoded).map_err(|problem| SpoolError::Damaged {
            line: line_number,
            problem,
        })?;
        replay.length = replay.length.saturating_add(end).saturating_add(1);
    }
    Ok(replay)
}

/// Applies one verified line, by the rules a push and a removal follow.
fn apply(journal: &JournalId, replay: &mut Replay, line: SpoolLine) -> Result<(), SpoolProblem> {
    match line {
        SpoolLine::Spooled { record } => {
            if record.journal() != journal {
                return Err(SpoolProblem::OtherJournal {
                    sequence: record.sequence(),
                });
            }
            if let Some(newest) = replay.records.back() {
                if !continues(newest, &record) {
                    return Err(SpoolProblem::OutOfOrder {
                        previous: newest.sequence(),
                        found: record.sequence(),
                    });
                }
            }
            replay.records.push_back(*record);
        }
        SpoolLine::Removed { sequence, digest } => match replay.records.front() {
            Some(oldest) if oldest.sequence() == sequence && oldest.digest() == digest => {
                replay.records.pop_front();
                replay.removals = replay.removals.saturating_add(1);
            }
            oldest => {
                return Err(SpoolProblem::Removal {
                    expected: oldest.map(AuditRecord::sequence),
                    found: sequence,
                })
            }
        },
    }
    Ok(())
}

/// Moves a torn last line to a new quarantine file and cuts it off the spool.
fn quarantine(
    directory: &Path,
    path: &Path,
    torn: &[u8],
    offset: usize,
) -> Result<SpoolTornTail, SpoolError> {
    let action = "quarantine a torn tail of the spool";
    let (name, mut file) = quarantine_file(directory)?;
    file.write_all(torn)
        .and_then(|()| file.sync_all())
        .and_then(|()| sync_dir(directory))
        .map_err(|error| SpoolError::io(action, &error))?;
    let length = u64::try_from(offset).unwrap_or(u64::MAX);
    OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|spool| {
            spool.set_len(length)?;
            spool.sync_all()
        })
        .map_err(|error| SpoolError::io("cut off a torn tail of the spool", &error))?;
    Ok(SpoolTornTail {
        bytes: u64::try_from(torn.len()).unwrap_or(u64::MAX),
        quarantine: name,
    })
}

/// A new quarantine file, never one that exists.
fn quarantine_file(directory: &Path) -> Result<(String, File), SpoolError> {
    let action = "quarantine a torn tail of the spool";
    for attempt in 1..=MAX_QUARANTINE_NAMES {
        let name = format!("{QUARANTINE_PREFIX}{attempt}.{QUARANTINE_EXTENSION}");
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(&name))
        {
            Ok(file) => return Ok((name, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(SpoolError::io(action, &error)),
        }
    }
    Err(SpoolError::Io {
        action,
        kind: io::ErrorKind::AlreadyExists,
        message: format!("{MAX_QUARANTINE_NAMES} quarantine files exist already"),
    })
}

fn line_digest(journal: &JournalId, json: &[u8]) -> Digest {
    DigestBuilder::new(LINE_DOMAIN)
        .str(journal.as_str())
        .bytes(json)
        .finish()
}

pub(super) fn encode_line(
    journal: &JournalId,
    line: &SpoolLine,
) -> Result<Vec<u8>, serde_json::Error> {
    let json = serde_json::to_vec(line)?;
    let mut bytes = Vec::with_capacity(json.len().saturating_add(CHECK_BYTES + 1));
    bytes.extend_from_slice(line_digest(journal, &json).to_hex().as_bytes());
    bytes.push(b' ');
    bytes.extend_from_slice(&json);
    bytes.push(b'\n');
    Ok(bytes)
}

/// Decodes one line without its newline.
fn decode_line(journal: &JournalId, line: &[u8]) -> Result<SpoolLine, SpoolProblem> {
    let (Some(check), Some(b' '), Some(json)) = (
        line.get(..CHECK_BYTES - 1),
        line.get(CHECK_BYTES - 1),
        line.get(CHECK_BYTES..),
    ) else {
        return Err(SpoolProblem::Checksum);
    };
    let check = std::str::from_utf8(check)
        .ok()
        .and_then(|text| Digest::from_hex(text).ok())
        .ok_or(SpoolProblem::Checksum)?;
    if line_digest(journal, json) != check {
        return Err(SpoolProblem::Checksum);
    }
    serde_json::from_slice(json).map_err(|_| SpoolProblem::Encoding)
}

/// The refusal the journal sees for a failed write.
fn refusal(error: &io::Error) -> StoreRefusal {
    match error.kind() {
        io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded => StoreRefusal::Full,
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => StoreRefusal::Slow,
        _ => StoreRefusal::Failed,
    }
}

fn open_lines(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
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

/// Flushes a directory's entries where the platform allows it. Windows offers no directory
/// flush through std; NTFS journals the rename itself.
fn sync_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::events::{Field, HostFact, Phase};
    use crate::sandbox::audit::fakes::{
        context, journal_id, manual_clock, producer, stream_config, FakeAnchor, FakeSegmentStorage,
        FakeSpool,
    };
    use crate::sandbox::audit::stream::{AuditEvent, AuditStream, StreamDirectory};

    /// `count` chained records of journal `name`, made by a real stream.
    fn chain(name: &str, count: u64) -> Vec<AuditRecord> {
        let storage = FakeSegmentStorage::new(100);
        let (mut stream, mut authority) = AuditStream::open(
            &mut StreamDirectory::new(),
            journal_id(name),
            producer(&format!("{name}.audit")),
            storage.clone(),
            FakeSpool::new(),
            FakeAnchor::new(),
            manual_clock(),
            stream_config(4, 1, 100),
        )
        .unwrap();
        for step in 1..=count {
            let event = AuditEvent::HostFact {
                fact: HostFact::Lease,
                fields: vec![Field::metadata("step", step)],
            };
            let _ = stream
                .record(&mut authority, context("op-1", Phase::Running), event)
                .unwrap();
        }
        storage.all_records()
    }

    fn audit(spool_records: usize) -> AuditConfig {
        stream_config(spool_records, 1, 10).audit
    }

    fn open(directory: &Path, spool_records: usize) -> (FileSpool, SpoolOpening) {
        FileSpool::open(directory, &journal_id("engine"), &audit(spool_records)).unwrap()
    }

    fn sequences(spool: &FileSpool) -> Vec<u64> {
        spool
            .records()
            .unwrap()
            .iter()
            .map(|record| record.sequence().get())
            .collect()
    }

    fn range(first: u64, last: u64) -> Option<SequenceRange> {
        SequenceRange::new(EventSequence::new(first)?, EventSequence::new(last)?)
    }

    fn file_bytes(directory: &Path) -> Vec<u8> {
        fs::read(directory.join(SPOOL_FILE)).unwrap()
    }

    fn lines(directory: &Path) -> usize {
        file_bytes(directory)
            .iter()
            .filter(|byte| **byte == b'\n')
            .count()
    }

    fn write_lines(directory: &Path, journal: &str, lines: &[SpoolLine]) {
        let mut bytes = Vec::new();
        for line in lines {
            bytes.extend(encode_line(&journal_id(journal), line).unwrap());
        }
        fs::create_dir_all(directory).unwrap();
        fs::write(directory.join(SPOOL_FILE), bytes).unwrap();
    }

    fn spooled(record: &AuditRecord) -> SpoolLine {
        SpoolLine::Spooled {
            record: Box::new(record.clone()),
        }
    }

    /// A restart resumes with exactly the records taken and not removed, in order; an
    /// emptied spool cuts its file to nothing.
    #[test]
    fn records_survive_a_restart_in_order() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("spool");
        let records = chain("engine", 4);
        let (mut spool, opening) = open(&directory, 4);
        assert_eq!(
            opening,
            SpoolOpening {
                held: None,
                torn_tail: None,
                interrupted_rewrite: false
            }
        );
        assert!(spool.is_empty());
        for record in &records[..3] {
            spool.push(record).unwrap();
        }
        spool.pop_front().unwrap();
        assert_eq!(sequences(&spool), [2, 3]);
        drop(spool);

        let (mut spool, opening) = open(&directory, 4);
        assert_eq!(opening.held, range(2, 3));
        assert_eq!(opening.torn_tail, None);
        assert_eq!(spool.front().unwrap().as_ref(), Some(&records[1]));
        assert_eq!(spool.records().unwrap(), records[1..3]);
        assert_eq!(
            (spool.capacity(), spool.journal()),
            (4, &journal_id("engine"))
        );
        spool.push(&records[3]).unwrap();
        for _ in 0..3 {
            spool.pop_front().unwrap();
        }
        // Removing from an empty spool removes nothing.
        spool.pop_front().unwrap();
        assert!(spool.is_empty() && spool.held().is_none());
        assert!(file_bytes(&directory).is_empty());
        drop(spool);
        let (spool, opening) = open(&directory, 4);
        assert_eq!((opening.held, spool.len()), (None, 0));
    }

    /// The bound is the journal's `spool_records`; a record of another journal, or one
    /// that does not continue the newest record held, is refused and nothing is written.
    #[test]
    fn the_bound_order_and_journal_are_kept() {
        let root = tempfile::tempdir().unwrap();
        let records = chain("engine", 5);
        let (mut spool, _) = open(root.path(), 2);
        spool.push(&records[0]).unwrap();
        spool.push(&records[1]).unwrap();
        assert_eq!(spool.push(&records[2]), Err(StoreRefusal::Full));
        spool.pop_front().unwrap();
        assert_eq!(spool.push(&records[3]), Err(StoreRefusal::Failed));
        assert_eq!(spool.push(&records[1]), Err(StoreRefusal::Failed));
        let warden = chain("warden", 3);
        assert_eq!(spool.push(&warden[2]), Err(StoreRefusal::Failed));
        spool.push(&records[2]).unwrap();
        assert_eq!(sequences(&spool), [2, 3]);
        let written = lines(root.path());
        // Emptied, the spool takes any record of its journal next.
        spool.pop_front().unwrap();
        spool.pop_front().unwrap();
        spool.push(&records[4]).unwrap();
        assert_eq!(sequences(&spool), [5]);
        assert_eq!((written, lines(root.path())), (4, 1));
        assert!(matches!(
            FileSpool::open(root.path(), &journal_id("engine"), &audit(0)),
            Err(SpoolError::Config(_))
        ));
    }

    /// A last line that is incomplete, or whole but does not verify, is moved to a new
    /// quarantine file and cut off; the records before it stay and the spool goes on.
    #[test]
    fn a_torn_last_line_is_quarantined_and_reported() {
        let root = tempfile::tempdir().unwrap();
        let records = chain("engine", 3);
        let (mut spool, _) = open(root.path(), 4);
        spool.push(&records[0]).unwrap();
        spool.push(&records[1]).unwrap();
        drop(spool);
        let whole = file_bytes(root.path());
        let torn = b"0123456789abcdef {\"line\":\"spooled\",\"rec";
        let mut bytes = whole.clone();
        bytes.extend_from_slice(torn);
        fs::write(root.path().join(SPOOL_FILE), bytes).unwrap();

        let (mut spool, opening) = open(root.path(), 4);
        let tail = opening.torn_tail.unwrap();
        assert_eq!(
            (tail.bytes, tail.quarantine.as_str()),
            (torn.len() as u64, "torn-1.bin")
        );
        assert_eq!(fs::read(root.path().join(&tail.quarantine)).unwrap(), torn);
        assert_eq!(file_bytes(root.path()), whole);
        assert_eq!(opening.held, range(1, 2));
        spool.push(&records[2]).unwrap();
        drop(spool);

        // A whole last line that does not verify is torn too; a second quarantine file
        // never replaces the first.
        let mut bytes = file_bytes(root.path());
        let at = bytes.len() - 10;
        bytes[at] ^= 0x01;
        fs::write(root.path().join(SPOOL_FILE), &bytes).unwrap();
        let (spool, opening) = open(root.path(), 4);
        let tail = opening.torn_tail.unwrap();
        assert_eq!(tail.quarantine, "torn-2.bin");
        assert_eq!(file_bytes(root.path()), whole);
        assert_eq!(sequences(&spool), [1, 2]);
        drop(spool);
        let (_, opening) = open(root.path(), 4);
        assert_eq!(opening.torn_tail, None);
    }

    /// Damage anywhere but the last line refuses the spool: a line that does not verify,
    /// a record out of order or of another journal, a removal of a record that is not the
    /// oldest, and a line of another journal's spool.
    #[test]
    fn damage_before_the_last_line_refuses_to_open() {
        let records = chain("engine", 3);
        let warden = chain("warden", 1);
        let removed = |record: &AuditRecord| SpoolLine::Removed {
            sequence: record.sequence(),
            digest: record.digest(),
        };
        let cases = [
            (
                "engine",
                vec![
                    spooled(&records[0]),
                    spooled(&records[2]),
                    removed(&records[0]),
                ],
                2,
                SpoolProblem::OutOfOrder {
                    previous: EventSequence::new(1).unwrap(),
                    found: EventSequence::new(3).unwrap(),
                },
            ),
            (
                "engine",
                vec![
                    spooled(&records[0]),
                    removed(&records[1]),
                    spooled(&records[1]),
                ],
                2,
                SpoolProblem::Removal {
                    expected: EventSequence::new(1),
                    found: EventSequence::new(2).unwrap(),
                },
            ),
            (
                "engine",
                vec![removed(&records[0]), spooled(&records[0])],
                1,
                SpoolProblem::Removal {
                    expected: None,
                    found: EventSequence::FIRST,
                },
            ),
            (
                "engine",
                vec![spooled(&warden[0]), spooled(&records[0])],
                1,
                SpoolProblem::OtherJournal {
                    sequence: EventSequence::FIRST,
                },
            ),
            (
                "warden",
                vec![spooled(&records[0]), spooled(&records[1])],
                1,
                SpoolProblem::Checksum,
            ),
        ];
        for (journal, lines, line, problem) in cases {
            let root = tempfile::tempdir().unwrap();
            write_lines(root.path(), journal, &lines);
            let refused = FileSpool::open(root.path(), &journal_id("engine"), &audit(4))
                .err()
                .unwrap();
            assert_eq!(refused, SpoolError::Damaged { line, problem });
            assert!(refused.to_string().starts_with(&format!("line {line} ")));
        }

        // A changed byte in the first of three lines.
        let root = tempfile::tempdir().unwrap();
        write_lines(
            root.path(),
            "engine",
            &[
                spooled(&records[0]),
                spooled(&records[1]),
                spooled(&records[2]),
            ],
        );
        let mut bytes = file_bytes(root.path());
        bytes[70] ^= 0x01;
        fs::write(root.path().join(SPOOL_FILE), &bytes).unwrap();
        assert_eq!(
            FileSpool::open(root.path(), &journal_id("engine"), &audit(4)).err(),
            Some(SpoolError::Damaged {
                line: 1,
                problem: SpoolProblem::Checksum
            })
        );
        // The refused file is left as it was.
        assert_eq!(file_bytes(root.path()), bytes);

        // A line reads back as written, and an unknown field next to it is refused.
        let line = removed(&records[0]);
        let mut json = serde_json::to_value(&line).unwrap();
        assert_eq!(json["line"], "removed");
        assert_eq!(
            serde_json::from_value::<SpoolLine>(json.clone()).unwrap(),
            line
        );
        json["note"] = serde_json::json!("x");
        assert!(serde_json::from_value::<SpoolLine>(json).is_err());
        for problem in [
            SpoolProblem::Encoding,
            SpoolProblem::Removal {
                expected: None,
                found: EventSequence::FIRST,
            },
        ] {
            assert!(!problem.to_string().is_empty());
        }
    }

    /// A refused write leaves nothing; a write that stops half way and cannot be cut back
    /// is cut off before the next write, or, after a stop, quarantined at the next open.
    #[test]
    fn a_failed_write_leaves_no_part_of_its_line() {
        let root = tempfile::tempdir().unwrap();
        let records = chain("engine", 3);
        let (mut spool, _) = open(root.path(), 4);
        spool.inject(SpoolFault::Refuse(io::ErrorKind::StorageFull));
        assert_eq!(spool.push(&records[0]), Err(StoreRefusal::Full));
        spool.inject(SpoolFault::Refuse(io::ErrorKind::TimedOut));
        assert_eq!(spool.push(&records[0]), Err(StoreRefusal::Slow));
        assert!(spool.is_empty() && file_bytes(root.path()).is_empty());

        spool.inject(SpoolFault::Torn);
        assert_eq!(spool.push(&records[0]), Err(StoreRefusal::Failed));
        assert!(spool.is_empty() && !file_bytes(root.path()).is_empty());
        spool.push(&records[0]).unwrap();
        assert_eq!(lines(root.path()), 1);
        spool.push(&records[1]).unwrap();
        spool.inject(SpoolFault::Torn);
        assert_eq!(spool.pop_front(), Err(StoreRefusal::Failed));
        assert_eq!(sequences(&spool), [1, 2]);
        drop(spool);

        let (mut spool, opening) = open(root.path(), 4);
        assert!(opening.torn_tail.is_some());
        assert_eq!(opening.held, range(1, 2));
        spool.push(&records[2]).unwrap();
        assert_eq!(sequences(&spool), [1, 2, 3]);
        let error = SpoolError::io("read the spool", &io::Error::from(io::ErrorKind::Other));
        assert!(error.to_string().starts_with("could not read the spool"));
    }

    /// Removal lines are dropped from the file once they reach the bound; a rewrite a stop
    /// interrupted leaves the old lines, and its temporary file is removed.
    #[test]
    fn removal_lines_are_rewritten_away_at_the_bound() {
        let root = tempfile::tempdir().unwrap();
        let records = chain("engine", 4);
        let (mut spool, _) = open(root.path(), 2);
        spool.push(&records[0]).unwrap();
        spool.push(&records[1]).unwrap();
        spool.pop_front().unwrap();
        spool.push(&records[2]).unwrap();
        assert_eq!(lines(root.path()), 4);
        spool.pop_front().unwrap();
        // Two removal lines reached the bound of two: one line per record held is left.
        assert_eq!(lines(root.path()), 1);
        spool.push(&records[3]).unwrap();
        assert_eq!(lines(root.path()), 2);
        drop(spool);
        fs::write(root.path().join(REWRITE_FILE), b"half a rewrite").unwrap();

        let (spool, opening) = open(root.path(), 2);
        assert!(opening.interrupted_rewrite);
        assert_eq!(opening.held, range(3, 4));
        assert!(!root.path().join(REWRITE_FILE).exists());
        assert_eq!(sequences(&spool), [3, 4]);
    }

    /// `foundation::strict_serde` (the S06 item "Strict tags of read-back tagged enums" of
    /// docs/combined-plan-leftover-tasks.md): a line that verifies but whose tag, or a tag
    /// nested in its record, is a number, or that writes a key twice, does not decode: the
    /// spool is damaged at that line and does not open. As the last line it is a torn tail,
    /// cut off and never read. The lines as written open.
    #[test]
    fn a_stored_line_with_a_number_tag_or_a_repeated_key_is_refused() {
        use crate::sandbox::audit::strict_tests::{shown, variant_names, Document};
        let records = chain("engine", 2);
        let lines = [
            spooled(&records[0]),
            spooled(&records[1]),
            SpoolLine::Removed {
                sequence: records[0].sequence(),
                digest: records[0].digest(),
            },
        ];
        // A spool file of `texts`, each a line that verifies, opened: the sequences it
        // holds and whether its last line was cut off.
        let open_texts = |texts: &[String]| {
            let root = tempfile::tempdir().unwrap();
            let mut bytes = Vec::new();
            for text in texts {
                let check = line_digest(&journal_id("engine"), text.as_bytes());
                bytes.extend_from_slice(check.to_hex().as_bytes());
                bytes.push(b' ');
                bytes.extend_from_slice(text.as_bytes());
                bytes.push(b'\n');
            }
            fs::write(root.path().join(SPOOL_FILE), bytes).unwrap();
            FileSpool::open(root.path(), &journal_id("engine"), &audit(4))
                .map(|(spool, opening)| (sequences(&spool), opening.torn_tail.is_some()))
        };
        let written: Vec<String> = lines
            .iter()
            .map(|line| serde_json::to_string(line).unwrap())
            .collect();
        assert_eq!(open_texts(&written), Ok((vec![2], false)));

        let mut checked = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            let value = serde_json::to_value(line).unwrap();
            for name in variant_names::<SpoolLine>(&value) {
                let mut cases = vec![Document::new(name.swapped(&value))];
                if let Some((object, key)) = name.key() {
                    cases.push(Document::repeating(value.clone(), object, key));
                }
                for tampered in cases {
                    let mut texts = written.clone();
                    texts[index] = tampered.text();
                    let opened = open_texts(&texts);
                    let path = shown(&name.path);
                    if index + 1 < texts.len() {
                        assert_eq!(
                            opened,
                            Err(SpoolError::Damaged {
                                line: u64::try_from(index).unwrap() + 1,
                                problem: SpoolProblem::Encoding
                            }),
                            "line {index}, `{path}`"
                        );
                    } else {
                        // The removal is never applied: both records are still held.
                        assert_eq!(opened, Ok((vec![1, 2], true)), "last line, `{path}`");
                    }
                }
                checked.push(shown(&name.path));
            }
        }
        assert!(checked.iter().any(|path| path == "line"));
        assert!(checked.len() > lines.len(), "{checked:?}");
    }
}
