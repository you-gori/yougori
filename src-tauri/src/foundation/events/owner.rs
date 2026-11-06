//! One append owner per durable CORE-06 stream (docs/combined-gpu-memory-and-vm-sandbox-plan.md:
//! S2 CORE-06; VM part §8.2 "the engine and warden must not concurrently append to a hash
//! chain without coordination"; VM-W42 "one append authority per stream"; §16.3 "EVIDENCE
//! owns durable audit"; docs/combined-plan-leftover-tasks.md S06 "give each durable stream a
//! clear append owner").
//!
//! A durable stream lives in one directory. [`StreamOwner::acquire`] makes its caller the
//! stream's only appender: inside this process through a registry of owned directories,
//! and across the processes of the host through an exclusive lock on the directory's lock
//! file, which the operating system releases when the owning process ends, however it
//! ends. A second owner is refused with a typed [`OwnerError`] that names the holder when
//! its record is readable; it never waits for the holder.
//!
//! On Windows the owner opens the lock file without delete sharing, so nobody can delete
//! or rename it while it is held, and nobody can lock a fresh file in its place. On Unix an
//! advisory lock belongs to the file, not to its name: a process that unlinks the held lock
//! file lets another create and lock a new one at the same path. On Unix the stream's
//! directory must therefore be writable only by the stream's owners.
//!
//! The owner record says who owns the stream, under which [`Incarnation`], and how far the
//! stream was durable when its owner last checkpointed or released it. A record still
//! marked open while the lock is free belongs to a stale owner: one that stopped without
//! releasing, such as a crashed process. The next owner reports it
//! ([`Takeover::Stale`]), keeps its record beside the stream without overwriting it or any
//! record kept before, takes the next incarnation and continues after everything the stale
//! owner made durable; it never starts the stream over. A missing owner record is reported
//! as lost ([`Takeover::Lost`]) when stale records were kept, and the new owner continues
//! after every one of them; the stream itself derives the rest.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};

use super::envelope::{EventSequence, ProducerId};
use crate::foundation::ids::Incarnation;

/// The file whose exclusive lock makes a process the stream's owner. It holds no data, so
/// a platform whose locks also bar reading never hides anything.
const LOCK_FILE: &str = "owner.lock";
/// The owner record.
const RECORD_FILE: &str = "owner.json";
/// A stale owner's record, kept when the next owner takes over: `owner-stale-<n>.json`, or
/// `owner-stale-<n>-<k>.json` when a different record of incarnation `n` was kept before.
const STALE_PREFIX: &str = "owner-stale-";
const RECORD_EXTENSION: &str = "json";
/// Names tried for one stale record before the takeover is refused.
const MAX_KEPT_NAMES: u32 = 1_000;
/// `FILE_SHARE_READ | FILE_SHARE_WRITE`, without `FILE_SHARE_DELETE`.
#[cfg(windows)]
const LOCK_SHARE_MODE: u32 = 0x1 | 0x2;
/// Extension of a file written before it is renamed into place.
pub(super) const TEMPORARY_EXTENSION: &str = "tmp";

/// Who owns a durable stream, as its directory records it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerRecord {
    /// The producer that appends to the stream.
    pub owner: ProducerId,
    /// Rises by one on every acquisition, so each owner's entries are told apart.
    pub incarnation: Incarnation,
    /// The owning process, for diagnostics only: the lock, not this number, decides.
    pub process: u32,
    /// Whether the owner released the stream; still `false` after a crash.
    pub released: bool,
    /// The last sequence the owner made durable, as of its last checkpoint or release. A
    /// later owner never reuses a sequence up to here, even if the stream lost it since.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durable_through: Option<EventSequence>,
}

/// How the stream's previous owner, if any, left it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Takeover {
    /// The stream had no owner before.
    Fresh,
    /// The previous owner released the stream.
    Released { previous: OwnerRecord },
    /// The previous owner stopped without releasing the stream: it crashed or was killed,
    /// and the operating system released its lock. Whatever it made durable stays.
    Stale { previous: OwnerRecord },
    /// The directory holds a stream but no owner record: it was deleted or lost. Who owned
    /// the stream last, and how far it was durable, is unknown. `kept` is the newest stale
    /// record kept beside the stream, if any; the new owner continues after every kept
    /// record, and after whatever the stream itself shows.
    Lost { kept: Option<OwnerRecord> },
}

impl Takeover {
    /// The previous owner's record, or the newest one kept when the record was lost.
    pub fn previous(&self) -> Option<&OwnerRecord> {
        match self {
            Self::Fresh => None,
            Self::Released { previous } | Self::Stale { previous } => Some(previous),
            Self::Lost { kept } => kept.as_ref(),
        }
    }

    pub fn is_stale(&self) -> bool {
        matches!(self, Self::Stale { .. })
    }
}

/// Why a stream could not be owned. Each refusal leaves the stream and its owner as they
/// were.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerError {
    /// This process already owns the stream.
    HeldInProcess { directory: PathBuf },
    /// Another process holds the stream's lock; `holder` is its record when readable.
    HeldElsewhere {
        directory: PathBuf,
        holder: Option<OwnerRecord>,
    },
    /// The owner record cannot be read as one. The stream fails closed until someone
    /// looks at it, rather than guessing who owned it and how far.
    RecordUnreadable { path: PathBuf, message: String },
    /// The stream used its last incarnation.
    IncarnationExhausted,
    Io {
        action: &'static str,
        path: PathBuf,
        kind: io::ErrorKind,
        message: String,
    },
}

impl OwnerError {
    pub(super) fn io(action: &'static str, path: &Path, error: &io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            kind: error.kind(),
            message: error.to_string(),
        }
    }
}

impl fmt::Display for OwnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeldInProcess { directory } => write!(
                f,
                "this process already owns the stream in {}",
                directory.display()
            ),
            Self::HeldElsewhere {
                directory,
                holder: Some(holder),
            } => write!(
                f,
                "{} owns the stream in {} (incarnation {}, process {})",
                holder.owner,
                directory.display(),
                holder.incarnation,
                holder.process
            ),
            Self::HeldElsewhere {
                directory,
                holder: None,
            } => write!(
                f,
                "another process owns the stream in {}",
                directory.display()
            ),
            Self::RecordUnreadable { path, message } => write!(
                f,
                "the owner record {} cannot be read: {message}",
                path.display()
            ),
            Self::IncarnationExhausted => f.write_str("the stream used its last owner incarnation"),
            Self::Io {
                action,
                path,
                message,
                ..
            } => write!(f, "could not {action} {}: {message}", path.display()),
        }
    }
}

impl std::error::Error for OwnerError {}

/// The directories this process owns. A directory leaves when its owner is dropped.
fn owned() -> MutexGuard<'static, BTreeSet<PathBuf>> {
    static OWNED: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());
    OWNED.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One directory's place in the registry, removed on drop on every path.
#[derive(Debug)]
struct Registration(PathBuf);

impl Registration {
    fn claim(directory: &Path) -> Result<Self, OwnerError> {
        if owned().insert(directory.to_path_buf()) {
            Ok(Self(directory.to_path_buf()))
        } else {
            Err(OwnerError::HeldInProcess {
                directory: directory.to_path_buf(),
            })
        }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        owned().remove(&self.0);
    }
}

/// The exclusive append ownership of one durable stream's directory. It is not `Clone`,
/// `Default` or deserializable. Dropping it releases the stream as
/// [`StreamOwner::release`] does, as far as it can; a process that ends without dropping
/// it leaves a stale owner record, which the next owner detects.
#[derive(Debug)]
pub struct StreamOwner {
    directory: PathBuf,
    record: OwnerRecord,
    /// The highest sequence made durable so far, persisted at the next checkpoint.
    through: Option<EventSequence>,
    /// Set once nothing is left for drop to record.
    finished: bool,
    lock: File,
    _registration: Registration,
}

impl StreamOwner {
    /// Takes ownership of the stream in `directory` for `owner`, creating the directory
    /// if needed. Refuses at once, without waiting, while this process or another one
    /// owns it.
    pub fn acquire(directory: &Path, owner: ProducerId) -> Result<(Self, Takeover), OwnerError> {
        fs::create_dir_all(directory)
            .map_err(|error| OwnerError::io("create the stream directory", directory, &error))?;
        let directory = fs::canonicalize(directory)
            .map_err(|error| OwnerError::io("resolve the stream directory", directory, &error))?;
        let registration = Registration::claim(&directory)?;
        let lock_path = directory.join(LOCK_FILE);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // Without delete sharing, nobody can delete or rename the lock file while this
            // handle is open, so nobody can lock a fresh file in its place.
            options.share_mode(LOCK_SHARE_MODE);
        }
        let lock = options
            .open(&lock_path)
            .map_err(|error| OwnerError::io("open the owner lock", &lock_path, &error))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(OwnerError::HeldElsewhere {
                    holder: read_record(&directory).ok().flatten(),
                    directory,
                })
            }
            Err(TryLockError::Error(error)) => {
                return Err(OwnerError::io("lock the stream", &lock_path, &error))
            }
        }
        let previous = read_record(&directory)?;
        // Without a record, the stale records kept beside the stream are what is known of
        // its owners: continue after every one of them.
        let kept = match previous {
            Some(_) => Vec::new(),
            None => read_kept(&directory)?,
        };
        let newest = kept.iter().max_by_key(|record| record.incarnation).cloned();
        let incarnation = match previous.as_ref().or(newest.as_ref()) {
            None => Incarnation::FIRST,
            Some(previous) => previous
                .incarnation
                .next()
                .ok_or(OwnerError::IncarnationExhausted)?,
        };
        let durable_through = match &previous {
            Some(previous) => previous.durable_through,
            None => kept
                .iter()
                .filter_map(|record| record.durable_through)
                .max(),
        };
        let record = OwnerRecord {
            owner,
            incarnation,
            process: std::process::id(),
            released: false,
            durable_through,
        };
        if let Some(stale) = previous.as_ref().filter(|previous| !previous.released) {
            keep_stale(&directory, stale)?;
        }
        write_record(&directory, &record)?;
        let takeover = match previous {
            None if newest.is_some() => Takeover::Lost { kept: newest },
            None => Takeover::Fresh,
            Some(previous) if previous.released => Takeover::Released { previous },
            Some(previous) => Takeover::Stale { previous },
        };
        Ok((
            Self {
                directory,
                through: record.durable_through,
                record,
                finished: false,
                lock,
                _registration: registration,
            },
            takeover,
        ))
    }

    /// The stream's directory, resolved.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// The record as last written.
    pub fn record(&self) -> &OwnerRecord {
        &self.record
    }

    pub fn incarnation(&self) -> Incarnation {
        self.record.incarnation
    }

    pub fn owner(&self) -> &ProducerId {
        &self.record.owner
    }

    /// The highest sequence noted durable, persisted or not.
    pub fn durable_through(&self) -> Option<EventSequence> {
        self.through
    }

    /// Notes that everything up to `through` is durable. It is persisted at the next
    /// checkpoint or release; a lower value changes nothing.
    pub fn advance(&mut self, through: EventSequence) {
        self.through = self.through.max(Some(through));
    }

    /// Persists the sequence noted durable, so that a later owner never reuses it even if
    /// the stream loses entries up to it.
    pub fn checkpoint(&mut self) -> Result<(), OwnerError> {
        if self.record.durable_through == self.through {
            return Ok(());
        }
        let record = OwnerRecord {
            durable_through: self.through,
            ..self.record.clone()
        };
        write_record(&self.directory, &record)?;
        self.record = record;
        Ok(())
    }

    /// Releases the stream: records how far it is durable and that its owner left
    /// cleanly, then gives up the lock. On `Err` the lock is given up anyway, and the
    /// next owner finds a stale record.
    pub fn release(mut self) -> Result<(), OwnerError> {
        self.finished = true;
        let record = OwnerRecord {
            released: true,
            durable_through: self.through,
            ..self.record.clone()
        };
        write_record(&self.directory, &record)?;
        self.record = record;
        Ok(())
    }

    /// Gives up the lock without recording a release, as a process that crashes does, so
    /// the next owner recovers the stream as after a stale owner. An owner that could not
    /// finish recovering a stream it already wrote to leaves it this way rather than claim
    /// a clean release.
    pub(super) fn abandon(mut self) {
        self.finished = true;
    }

    /// Gives the stream up as `takeover` found it: the previous record restored, or none
    /// when there was none. For an owner refused before it wrote anything under its own
    /// incarnation, so that refused attempts never raise the incarnation or wear away what
    /// the record said. If the record cannot be restored, it names this owner as stopped
    /// without a release, and the next owner recovers as after a stale owner.
    pub(super) fn withdraw(mut self, takeover: &Takeover) {
        self.finished = true;
        let _ = match takeover {
            Takeover::Fresh | Takeover::Lost { .. } => {
                fs::remove_file(self.directory.join(RECORD_FILE))
                    .and_then(|()| sync_dir(&self.directory))
                    .map_err(|error| OwnerError::io("withdraw from", &self.directory, &error))
            }
            Takeover::Released { previous } | Takeover::Stale { previous } => {
                write_record(&self.directory, previous)
            }
        };
    }

    /// Raises the incarnation to `at_least` when the stream shows owners the record did not
    /// know of, so that this owner's entries follow every earlier owner's.
    pub(super) fn raise(&mut self, at_least: Incarnation) -> Result<(), OwnerError> {
        if self.record.incarnation >= at_least {
            return Ok(());
        }
        let record = OwnerRecord {
            incarnation: at_least,
            ..self.record.clone()
        };
        write_record(&self.directory, &record)?;
        self.record = record;
        Ok(())
    }
}

impl Drop for StreamOwner {
    fn drop(&mut self) {
        if !self.finished {
            self.finished = true;
            let record = OwnerRecord {
                released: true,
                durable_through: self.through,
                ..self.record.clone()
            };
            // Best effort: if the record cannot be written, the next owner finds a stale
            // record and recovers, which is safe.
            let _ = write_record(&self.directory, &record);
        }
        let _ = self.lock.unlock();
    }
}

/// The owner record in `directory`, if any.
fn read_record(directory: &Path) -> Result<Option<OwnerRecord>, OwnerError> {
    let path = directory.join(RECORD_FILE);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(OwnerError::io("read the owner record", &path, &error)),
        Ok(_) => parse_record(&path).map(Some),
    }
}

/// Keeps a stale owner's record beside the stream, never overwriting or dropping one kept
/// before: the same record kept already is kept once, and a different one under the same
/// incarnation gets a name of its own. The lock is held, so no other owner names files.
fn keep_stale(directory: &Path, stale: &OwnerRecord) -> Result<(), OwnerError> {
    for attempt in 1..=MAX_KEPT_NAMES {
        let name = match attempt {
            1 => format!("{STALE_PREFIX}{}.{RECORD_EXTENSION}", stale.incarnation),
            _ => format!(
                "{STALE_PREFIX}{}-{attempt}.{RECORD_EXTENSION}",
                stale.incarnation
            ),
        };
        let path = directory.join(name);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let bytes = encode_record(&path, stale)?;
                return write_atomic(&path, &bytes)
                    .map_err(|error| OwnerError::io("keep the stale owner record", &path, &error));
            }
            Err(error) => return Err(OwnerError::io("keep the stale owner record", &path, &error)),
            // Kept by an earlier attempt at this takeover, which stopped before it could
            // replace the owner record.
            Ok(_) if parse_record(&path).ok().as_ref() == Some(stale) => return Ok(()),
            Ok(_) => {}
        }
    }
    Err(OwnerError::Io {
        action: "keep the stale owner record",
        path: directory.to_path_buf(),
        kind: io::ErrorKind::AlreadyExists,
        message: format!(
            "{MAX_KEPT_NAMES} records of incarnation {} are kept already",
            stale.incarnation
        ),
    })
}

/// The stale records kept beside the stream. One that cannot be read fails closed, as an
/// unreadable owner record does.
fn read_kept(directory: &Path) -> Result<Vec<OwnerRecord>, OwnerError> {
    let entries = fs::read_dir(directory)
        .map_err(|error| OwnerError::io("list the kept owner records", directory, &error))?;
    let mut kept = Vec::new();
    for entry in entries {
        let entry = entry
            .map_err(|error| OwnerError::io("list the kept owner records", directory, &error))?;
        let path = entry.path();
        let is_kept = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(STALE_PREFIX))
            && path.extension().and_then(|extension| extension.to_str()) == Some(RECORD_EXTENSION);
        if is_kept {
            kept.push(parse_record(&path)?);
        }
    }
    Ok(kept)
}

fn parse_record(path: &Path) -> Result<OwnerRecord, OwnerError> {
    let bytes =
        fs::read(path).map_err(|error| OwnerError::io("read the owner record", path, &error))?;
    serde_json::from_slice(&bytes).map_err(|error| OwnerError::RecordUnreadable {
        path: path.to_path_buf(),
        message: error.to_string(),
    })
}

fn encode_record(path: &Path, record: &OwnerRecord) -> Result<Vec<u8>, OwnerError> {
    serde_json::to_vec_pretty(record).map_err(|error| OwnerError::Io {
        action: "encode the owner record",
        path: path.to_path_buf(),
        kind: io::ErrorKind::InvalidData,
        message: error.to_string(),
    })
}

fn write_record(directory: &Path, record: &OwnerRecord) -> Result<(), OwnerError> {
    let path = directory.join(RECORD_FILE);
    let bytes = encode_record(&path, record)?;
    write_atomic(&path, &bytes).map_err(|error| OwnerError::io("write", &path, &error))
}

/// Writes `bytes` to a temporary sibling, syncs it and renames it over `path`, so `path`
/// holds either its old or its new content after a crash, never a mix.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temporary = path.with_extension(TEMPORARY_EXTENSION);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    if let Some(parent) = path.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

/// Flushes a directory's entries where the platform allows it. Windows offers no directory
/// flush through std; NTFS journals the rename itself.
pub(super) fn sync_dir(path: &Path) -> io::Result<()> {
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
    use crate::foundation::events::fakes::producer;

    fn record_in(directory: &Path) -> OwnerRecord {
        read_record(directory).unwrap().unwrap()
    }

    #[test]
    fn a_second_owner_in_this_process_is_refused_until_the_first_is_dropped() {
        let directory = tempfile::tempdir().unwrap();
        let (first, takeover) = StreamOwner::acquire(directory.path(), producer("engine")).unwrap();
        assert_eq!(takeover, Takeover::Fresh);
        assert_eq!(first.incarnation(), Incarnation::FIRST);
        assert!(matches!(
            StreamOwner::acquire(directory.path(), producer("warden")),
            Err(OwnerError::HeldInProcess { .. })
        ));
        // Another path to the same directory is the same stream.
        let alias = directory.path().join(".");
        assert!(matches!(
            StreamOwner::acquire(&alias, producer("engine")),
            Err(OwnerError::HeldInProcess { .. })
        ));
        drop(first);
        let (second, takeover) =
            StreamOwner::acquire(directory.path(), producer("engine")).unwrap();
        assert_eq!(second.incarnation().get(), 2);
        assert!(matches!(takeover, Takeover::Released { .. }));
    }

    #[test]
    fn an_owner_in_another_process_is_refused_and_named() {
        let directory = tempfile::tempdir().unwrap();
        let (first, _) = StreamOwner::acquire(directory.path(), producer("warden")).unwrap();
        let expected = first.record().clone();
        // Another process holds the lock: it releases this process's registration, so only
        // the operating system's lock stands between the two, as across processes. A lock
        // through a second handle conflicts with the first on every platform std supports.
        first.abandon();
        let foreign = OpenOptions::new()
            .read(true)
            .write(true)
            .open(directory.path().join(LOCK_FILE))
            .unwrap();
        foreign.try_lock().unwrap();
        let refused = StreamOwner::acquire(directory.path(), producer("engine")).unwrap_err();
        assert!(matches!(
            &refused,
            OwnerError::HeldElsewhere { holder: Some(holder), .. } if *holder == expected
        ));
        assert!(refused.to_string().starts_with("warden owns the stream"));
        // The refused attempt changed nothing and holds nothing.
        assert_eq!(record_in(directory.path()), expected);
        drop(foreign);
        let (_, takeover) = StreamOwner::acquire(directory.path(), producer("engine")).unwrap();
        assert_eq!(takeover, Takeover::Stale { previous: expected });
    }

    #[test]
    fn a_stale_owner_is_detected_and_its_durable_mark_is_kept() {
        let directory = tempfile::tempdir().unwrap();
        let (mut first, _) = StreamOwner::acquire(directory.path(), producer("engine")).unwrap();
        first.advance(EventSequence::new(7).unwrap());
        first.checkpoint().unwrap();
        // Noted but never checkpointed: a crash loses only the note.
        first.advance(EventSequence::new(9).unwrap());
        first.advance(EventSequence::new(8).unwrap());
        assert_eq!(first.durable_through(), EventSequence::new(9));
        first.abandon();
        let stale = record_in(directory.path());
        assert!(!stale.released);
        assert_eq!(stale.durable_through, EventSequence::new(7));

        let (second, takeover) =
            StreamOwner::acquire(directory.path(), producer("engine")).unwrap();
        assert!(takeover.is_stale());
        assert_eq!(takeover.previous(), Some(&stale));
        // The stale owner's record is kept beside the new one, not overwritten.
        let kept: OwnerRecord =
            serde_json::from_slice(&fs::read(directory.path().join("owner-stale-1.json")).unwrap())
                .unwrap();
        assert_eq!(kept, stale);
        assert_eq!(second.incarnation().get(), 2);
        // The new owner continues after the stale owner's mark; it never starts over.
        assert_eq!(second.durable_through(), EventSequence::new(7));
        assert_eq!(second.record().durable_through, EventSequence::new(7));
        second.release().unwrap();
        let released = record_in(directory.path());
        assert!(released.released);
        assert_eq!(released.incarnation.get(), 2);
    }

    #[test]
    fn dropping_an_owner_releases_it_with_its_durable_mark() {
        let directory = tempfile::tempdir().unwrap();
        let (mut owner, _) = StreamOwner::acquire(directory.path(), producer("engine")).unwrap();
        owner.advance(EventSequence::new(3).unwrap());
        drop(owner);
        let record = record_in(directory.path());
        assert!(record.released);
        assert_eq!(record.durable_through, EventSequence::new(3));
    }

    #[test]
    fn an_unreadable_owner_record_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join(RECORD_FILE), b"{\"owner\": 1}").unwrap();
        assert!(matches!(
            StreamOwner::acquire(directory.path(), producer("engine")),
            Err(OwnerError::RecordUnreadable { .. })
        ));
        // Unknown fields are refused too.
        let (owner, _) = {
            fs::remove_file(directory.path().join(RECORD_FILE)).unwrap();
            StreamOwner::acquire(directory.path(), producer("engine")).unwrap()
        };
        drop(owner);
        let mut json: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.path().join(RECORD_FILE)).unwrap()).unwrap();
        json["note"] = serde_json::json!("x");
        fs::write(
            directory.path().join(RECORD_FILE),
            serde_json::to_vec(&json).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            StreamOwner::acquire(directory.path(), producer("engine")),
            Err(OwnerError::RecordUnreadable { .. })
        ));
    }

    #[test]
    fn the_last_incarnation_is_never_wrapped() {
        let directory = tempfile::tempdir().unwrap();
        let record = OwnerRecord {
            owner: producer("engine"),
            incarnation: Incarnation::new(u64::MAX),
            process: 1,
            released: true,
            durable_through: None,
        };
        write_record(directory.path(), &record).unwrap();
        assert_eq!(
            StreamOwner::acquire(directory.path(), producer("engine")).err(),
            Some(OwnerError::IncarnationExhausted)
        );
    }

    fn record(incarnation: u64, released: bool, durable_through: u64) -> OwnerRecord {
        OwnerRecord {
            owner: producer("engine"),
            incarnation: Incarnation::new(incarnation),
            process: 1,
            released,
            durable_through: EventSequence::new(durable_through),
        }
    }

    fn kept_names(directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.starts_with(STALE_PREFIX))
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_missing_record_continues_after_every_kept_record() {
        let directory = tempfile::tempdir().unwrap();
        keep_stale(directory.path(), &record(3, false, 7)).unwrap();
        keep_stale(directory.path(), &record(5, false, 4)).unwrap();
        let (owner, takeover) = StreamOwner::acquire(directory.path(), producer("engine")).unwrap();
        assert_eq!(
            takeover,
            Takeover::Lost {
                kept: Some(record(5, false, 4))
            }
        );
        assert!(!takeover.is_stale());
        // After the latest incarnation kept, and after the highest durable sequence kept.
        assert_eq!(owner.incarnation().get(), 6);
        assert_eq!(owner.durable_through(), EventSequence::new(7));
        // A kept record that cannot be read fails closed, as the owner record does.
        owner.withdraw(&takeover);
        fs::write(directory.path().join("owner-stale-9.json"), b"{}").unwrap();
        assert!(matches!(
            StreamOwner::acquire(directory.path(), producer("engine")),
            Err(OwnerError::RecordUnreadable { .. })
        ));
    }

    #[test]
    fn a_stale_record_is_never_dropped_for_one_kept_before() {
        let directory = tempfile::tempdir().unwrap();
        let first = record(1, false, 3);
        keep_stale(directory.path(), &first).unwrap();
        // The same record again, as when a takeover is retried, is kept once.
        keep_stale(directory.path(), &first).unwrap();
        assert_eq!(kept_names(directory.path()), ["owner-stale-1.json"]);
        // A different record of the same incarnation gets a name of its own.
        let second = record(1, false, 9);
        keep_stale(directory.path(), &second).unwrap();
        keep_stale(directory.path(), &second).unwrap();
        assert_eq!(
            kept_names(directory.path()),
            ["owner-stale-1-2.json", "owner-stale-1.json"]
        );
        let mut kept = read_kept(directory.path()).unwrap();
        kept.sort_by_key(|record| record.durable_through);
        assert_eq!(kept, [first, second]);
    }

    #[test]
    fn a_withdrawn_owner_leaves_the_record_as_it_found_it() {
        let directory = tempfile::tempdir().unwrap();
        let (owner, takeover) = StreamOwner::acquire(directory.path(), producer("engine")).unwrap();
        owner.withdraw(&takeover);
        assert_eq!(read_record(directory.path()).unwrap(), None);

        let (mut owner, _) = StreamOwner::acquire(directory.path(), producer("engine")).unwrap();
        owner.advance(EventSequence::new(4).unwrap());
        owner.release().unwrap();
        let released = record_in(directory.path());
        for _ in 0..3 {
            let (owner, takeover) =
                StreamOwner::acquire(directory.path(), producer("engine")).unwrap();
            assert_eq!(owner.incarnation().get(), 2);
            owner.withdraw(&takeover);
            assert_eq!(record_in(directory.path()), released);
        }

        let (owner, _) = StreamOwner::acquire(directory.path(), producer("engine")).unwrap();
        owner.abandon();
        let stale = record_in(directory.path());
        let (mut owner, takeover) =
            StreamOwner::acquire(directory.path(), producer("engine")).unwrap();
        owner.raise(Incarnation::new(9)).unwrap();
        assert_eq!(record_in(directory.path()).incarnation.get(), 9);
        owner.withdraw(&takeover);
        assert_eq!(record_in(directory.path()), stale);
    }

    #[cfg(windows)]
    #[test]
    fn the_held_lock_file_can_be_neither_deleted_nor_renamed() {
        let directory = tempfile::tempdir().unwrap();
        let lock = directory.path().join(LOCK_FILE);
        let (owner, _) = StreamOwner::acquire(directory.path(), producer("engine")).unwrap();
        assert!(fs::remove_file(&lock).is_err());
        assert!(fs::rename(&lock, directory.path().join("moved.lock")).is_err());
        // Another process can still open it, and is refused by the lock itself.
        let foreign = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock)
            .unwrap();
        assert!(matches!(foreign.try_lock(), Err(TryLockError::WouldBlock)));
        drop(foreign);
        drop(owner);
        fs::remove_file(&lock).unwrap();
    }
}
