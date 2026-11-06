//! A bounded, crash-safe audit spool on local files (docs/combined-gpu-memory-and-vm-sandbox-plan.md:
//! S2 CORE-06; VM part §8.2 "a bounded local spool"; VM-W42 "one append authority per stream,
//! bounded queues ... disk full"; VM-CP-22 "disk-full, a truncated file, a rewritten record
//! and a restart are detected"; docs/combined-plan-leftover-tasks.md S06 "a file-backed
//! AuditSpool").
//!
//! A [`FileAuditSpool`] is the [`AuditSpool`] port on durable local storage. It keeps the
//! records an [`AuditJournal`](super::AuditJournal) accepted while its store refused them,
//! one file per record in its own directory, under one [`StreamOwner`]: a second spool on
//! the directory, in this process or another, is refused.
//!
//! - Crash-safe. A record is written to a temporary file, synced and renamed into place,
//!   and the directory is flushed before `push` returns, so after a crash a record is whole
//!   or absent; an interrupted write leaves only a temporary file, which the next open
//!   removes. `pop_front` returns once the oldest file is removed and the directory flushed.
//!   A push that fails takes back whatever it wrote, so storage never keeps part of one.
//! - Bounded. It holds at most [`SpoolConfig::max_records`] records and
//!   [`SpoolConfig::max_bytes`] bytes; past either, `push` refuses with
//!   [`StoreRefusal::Full`] and the journal fails closed, visibly. A full spool never drops
//!   or overwrites a record to make room.
//! - In order. Each file is named by its record's sequence, and the spool takes only a
//!   record that continues the chain of the last one it holds, so `front`, `records` and
//!   the journal's flush hand the records to storage in sequence order, and
//!   [`AuditJournal::resume`](super::AuditJournal::resume) continues after the last.
//! - Damage is reported, never dropped. Opening verifies every file: its record must read
//!   strictly, carry the sequence its name gives, and the records together must form one
//!   unbroken chain ([`verify_chain`]). A file that does not is reported as
//!   [`SpoolDamage`] and the spool refuses to open, keeping every file as it found it.

use std::collections::VecDeque;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use super::audit::{verify_chain, AuditRecord, AuditSpool, ChainError, JournalHead, StoreRefusal};
use super::durable::LogError;
use super::envelope::{ConfigError, EventSequence, ProducerId};
use super::owner::{sync_dir, OwnerError, StreamOwner, Takeover, TEMPORARY_EXTENSION};

const RECORD_PREFIX: &str = "spooled-";
const RECORD_EXTENSION: &str = "json";

/// Bounds of one spool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpoolConfig {
    /// Records held at most; at least the journal's own `spool_records`.
    pub max_records: usize,
    /// Bytes held at most, counting each record's file.
    pub max_bytes: u64,
}

impl SpoolConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_records == 0 {
            return Err(ConfigError::Zero {
                setting: "max_records",
            });
        }
        if self.max_bytes == 0 {
            return Err(ConfigError::Zero {
                setting: "max_bytes",
            });
        }
        Ok(())
    }
}

/// What is wrong with a spool's files. The spool refuses to open and leaves them as they
/// are, for someone to look at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpoolDamage {
    /// The file does not read as one audit record.
    Unreadable { file: String, message: String },
    /// The file's name gives another sequence than its record carries.
    Misnamed { file: String, record: EventSequence },
    /// The records do not form one unbroken chain: one is missing, repeated, reordered,
    /// edited or of another journal.
    Chain(ChainError),
}

impl fmt::Display for SpoolDamage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { file, message } => {
                write!(f, "{file} is not an audit record: {message}")
            }
            Self::Misnamed { file, record } => write!(f, "{file} holds record {record}"),
            Self::Chain(error) => write!(f, "the spooled records do not chain: {error}"),
        }
    }
}

/// Why a spool could not be opened or released.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpoolError {
    Config(ConfigError),
    Owner(OwnerError),
    Damaged(SpoolDamage),
    Io {
        action: &'static str,
        kind: io::ErrorKind,
        message: String,
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
            Self::Owner(error) => write!(f, "{error}"),
            Self::Damaged(damage) => write!(f, "the audit spool is damaged: {damage}"),
            Self::Io {
                action, message, ..
            } => write!(f, "could not {action}: {message}"),
        }
    }
}

impl std::error::Error for SpoolError {}

/// What opening a spool found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpoolOpened {
    pub takeover: Takeover,
    /// Records found, oldest first by sequence; the journal resumes after the last.
    pub records: usize,
    pub bytes: u64,
    /// Temporary files of pushes a crash interrupted, removed: none was acknowledged.
    pub interrupted: u64,
    /// Whether what was found already exceeds the bounds. Nothing is dropped; pushes are
    /// refused until storage takes enough.
    pub over_bounds: bool,
}

/// Counts of what a spool did since it was opened.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SpoolTotals {
    pub pushed: u64,
    pub popped: u64,
    /// Pushes refused because the spool was full.
    pub refused_full: u64,
    /// Pushes refused because the record does not continue the last one held.
    pub refused_out_of_order: u64,
    /// Pushes and removals storage refused; none changed what the spool holds.
    pub failed_writes: u64,
    /// Removals that found the oldest file already gone.
    pub already_removed: u64,
}

/// One record held, and its file's size.
#[derive(Clone, Debug)]
struct Held {
    record: AuditRecord,
    bytes: u64,
}

/// A journal's bounded spool on local files, with one owner (CORE-06; S06).
#[derive(Debug)]
pub struct FileAuditSpool {
    owner: StreamOwner,
    config: SpoolConfig,
    held: VecDeque<Held>,
    bytes: u64,
    /// A failed push could not take back its file: refuse everything until reopened, which
    /// reads the file, if any, as the record it is.
    poisoned: bool,
    totals: SpoolTotals,
}

impl FileAuditSpool {
    /// Takes ownership of the spool in `directory` for `owner`, creating it if needed,
    /// removes the temporary files of interrupted pushes, and verifies every record held.
    /// Refuses while another owner holds it, and refuses a spool it cannot verify.
    pub fn open(
        directory: &Path,
        owner: ProducerId,
        config: SpoolConfig,
    ) -> Result<(Self, SpoolOpened), SpoolError> {
        config.validate().map_err(SpoolError::Config)?;
        let (owner, takeover) =
            StreamOwner::acquire(directory, owner).map_err(SpoolError::Owner)?;
        // A refused open leaves the owner record as it found it.
        let (held, interrupted) = match load(owner.directory()) {
            Ok(loaded) => loaded,
            Err(error) => {
                owner.withdraw(&takeover);
                return Err(error);
            }
        };
        let bytes = held
            .iter()
            .fold(0u64, |sum, held| sum.saturating_add(held.bytes));
        let opened = SpoolOpened {
            takeover,
            records: held.len(),
            bytes,
            interrupted,
            over_bounds: held.len() > config.max_records || bytes > config.max_bytes,
        };
        Ok((
            Self {
                owner,
                config,
                held,
                bytes,
                poisoned: false,
                totals: SpoolTotals::default(),
            },
            opened,
        ))
    }

    /// Bytes held.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn totals(&self) -> SpoolTotals {
        self.totals
    }

    pub fn owner(&self) -> &StreamOwner {
        &self.owner
    }

    /// Releases the spool. Its records stay for the next owner.
    pub fn close(self) -> Result<(), SpoolError> {
        let Self { owner, .. } = self;
        owner.release().map_err(SpoolError::Owner)
    }

    /// Gives the spool up as a crashing process would: no release is recorded.
    #[cfg(test)]
    pub(super) fn crash(self) {
        let Self { owner, .. } = self;
        owner.abandon();
    }

    fn refuse(&mut self, error: &io::Error) -> StoreRefusal {
        self.totals.failed_writes = self.totals.failed_writes.saturating_add(1);
        LogError::io("write the audit spool", error).store_refusal()
    }

    /// Writes `encoded` as the file of `sequence`, durably; on failure takes back whatever
    /// it wrote.
    fn write(&mut self, sequence: EventSequence, encoded: &[u8]) -> Result<(), StoreRefusal> {
        let directory = self.owner.directory().to_path_buf();
        let path = record_path(&directory, sequence);
        let temporary = path.with_extension(TEMPORARY_EXTENSION);
        let written = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temporary)
            .and_then(|mut file| {
                file.write_all(encoded)?;
                file.sync_all()
            });
        if let Err(error) = written {
            let _ = fs::remove_file(&temporary);
            return Err(self.refuse(&error));
        }
        if let Err(error) = fs::rename(&temporary, &path) {
            let _ = fs::remove_file(&temporary);
            return Err(self.refuse(&error));
        }
        if let Err(error) = sync_dir(&directory) {
            // The record may or may not survive a crash now: take it back.
            let taken_back = fs::remove_file(&path).and_then(|()| sync_dir(&directory));
            if taken_back.is_err() {
                self.poisoned = true;
            }
            return Err(self.refuse(&error));
        }
        Ok(())
    }
}

impl AuditSpool for FileAuditSpool {
    fn push(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        if self.poisoned {
            return Err(StoreRefusal::Failed);
        }
        // Only the record that continues the last one held: the chain, and the order of
        // the files, never break.
        if let Some(last) = self.held.back() {
            if verify_chain(&head_of(&last.record), std::slice::from_ref(record)).is_err() {
                self.totals.refused_out_of_order =
                    self.totals.refused_out_of_order.saturating_add(1);
                return Err(StoreRefusal::Failed);
            }
        }
        let encoded = serde_json::to_vec(record).map_err(|_| StoreRefusal::Failed)?;
        let size = u64::try_from(encoded.len()).unwrap_or(u64::MAX);
        if self.held.len() >= self.config.max_records
            || self.bytes.saturating_add(size) > self.config.max_bytes
        {
            self.totals.refused_full = self.totals.refused_full.saturating_add(1);
            return Err(StoreRefusal::Full);
        }
        self.write(record.sequence(), &encoded)?;
        self.held.push_back(Held {
            record: record.clone(),
            bytes: size,
        });
        self.bytes = self.bytes.saturating_add(size);
        self.totals.pushed = self.totals.pushed.saturating_add(1);
        Ok(())
    }

    fn front(&self) -> Result<Option<AuditRecord>, StoreRefusal> {
        Ok(self.held.front().map(|held| held.record.clone()))
    }

    fn pop_front(&mut self) -> Result<(), StoreRefusal> {
        if self.poisoned {
            return Err(StoreRefusal::Failed);
        }
        let Some(front) = self.held.front() else {
            return Ok(());
        };
        let directory = self.owner.directory().to_path_buf();
        match fs::remove_file(record_path(&directory, front.record.sequence())) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.totals.already_removed = self.totals.already_removed.saturating_add(1);
            }
            Err(error) => return Err(self.refuse(&error)),
        }
        if let Err(error) = sync_dir(&directory) {
            return Err(self.refuse(&error));
        }
        if let Some(popped) = self.held.pop_front() {
            self.bytes = self.bytes.saturating_sub(popped.bytes);
        }
        self.totals.popped = self.totals.popped.saturating_add(1);
        Ok(())
    }

    fn len(&self) -> usize {
        self.held.len()
    }

    fn records(&self) -> Result<Vec<AuditRecord>, StoreRefusal> {
        Ok(self.held.iter().map(|held| held.record.clone()).collect())
    }
}

/// The chain head `record` ends: what the next record must continue.
fn head_of(record: &AuditRecord) -> JournalHead {
    JournalHead {
        journal: record.journal().clone(),
        owner: record.event().provenance().producer().clone(),
        last: Some(record.sequence()),
        digest: record.digest(),
    }
}

fn record_path(directory: &Path, sequence: EventSequence) -> PathBuf {
    directory.join(format!(
        "{RECORD_PREFIX}{:020}.{RECORD_EXTENSION}",
        sequence.get()
    ))
}

/// The records in `directory`, verified, oldest first, and the count of temporary files
/// of interrupted pushes, removed.
fn load(directory: &Path) -> Result<(VecDeque<Held>, u64), SpoolError> {
    let entries =
        fs::read_dir(directory).map_err(|error| SpoolError::io("list the audit spool", &error))?;
    let mut files = Vec::new();
    let mut interrupted = 0u64;
    for entry in entries {
        let entry = entry.map_err(|error| SpoolError::io("list the audit spool", &error))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(rest) = name.strip_prefix(RECORD_PREFIX) else {
            continue;
        };
        if rest
            .strip_suffix(TEMPORARY_EXTENSION)
            .is_some_and(|stem| stem.ends_with('.'))
        {
            fs::remove_file(&path)
                .map_err(|error| SpoolError::io("remove an interrupted push", &error))?;
            interrupted = interrupted.saturating_add(1);
            continue;
        }
        let named = rest
            .strip_suffix(RECORD_EXTENSION)
            .and_then(|stem| stem.strip_suffix('.'))
            .and_then(|digits| digits.parse::<u64>().ok())
            .and_then(EventSequence::new);
        match named {
            Some(sequence) => files.push((sequence, name.to_owned(), path)),
            None => {
                return Err(SpoolError::Damaged(SpoolDamage::Unreadable {
                    file: name.to_owned(),
                    message: "the name gives no sequence".to_owned(),
                }))
            }
        }
    }
    if interrupted > 0 {
        sync_dir(directory)
            .map_err(|error| SpoolError::io("remove an interrupted push", &error))?;
    }
    files.sort();
    let mut held = VecDeque::with_capacity(files.len());
    for (sequence, name, path) in files {
        let bytes =
            fs::read(&path).map_err(|error| SpoolError::io("read the audit spool", &error))?;
        let record: AuditRecord = serde_json::from_slice(&bytes).map_err(|error| {
            SpoolError::Damaged(SpoolDamage::Unreadable {
                file: name.clone(),
                message: error.to_string(),
            })
        })?;
        if record.sequence() != sequence {
            return Err(SpoolError::Damaged(SpoolDamage::Misnamed {
                file: name,
                record: record.sequence(),
            }));
        }
        held.push_back(Held {
            record,
            bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        });
    }
    if let Some(first) = held.front() {
        let start = JournalHead {
            journal: first.record.journal().clone(),
            owner: first.record.event().provenance().producer().clone(),
            last: first.record.sequence().previous(),
            digest: first.record.previous(),
        };
        let records: Vec<AuditRecord> = held.iter().map(|held| held.record.clone()).collect();
        verify_chain(&start, &records)
            .map_err(|error| SpoolError::Damaged(SpoolDamage::Chain(error)))?;
    }
    Ok((held, interrupted))
}
