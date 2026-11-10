//! Engine-private replay checkpoint. Report durability must precede this cursor.
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAX_CURSOR_BYTES: u64 = 131_072;
/// How long a taken lock may still free up before the store is reported busy.
pub(super) const LOCK_GRACE: std::time::Duration = std::time::Duration::from_millis(250);
pub(super) const MAX_ACTIVE: usize = 4096;

pub(super) fn opaque_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Cursor {
    pub version: u8,
    pub environment_id: String,
    pub session_id: String,
    pub after: u64,
    pub observed_next: u64,
    pub instance_id: Option<String>,
    pub sealed: bool,
    pub last_started: u64,
    pub completed: u64,
    pub active: BTreeMap<u64, String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CursorError {
    Invalid,
    Busy,
    Storage,
    Identity,
    Regression,
}

/// The directory is an engine-owned private directory, never supplied by the
/// runner. A kernel lock survives cancellation and is released on process exit.
/// Atomically replaced cursors recover from process interruption; storage-device
/// power-loss guarantees still depend on the filesystem's durability contract.
pub(crate) struct CursorStore {
    directory: PathBuf,
    _lock: File,
    current: Cursor,
}

impl CursorStore {
    pub(crate) fn open(
        directory: &Path,
        environment_id: &str,
        session_id: &str,
    ) -> Result<Self, CursorError> {
        if !opaque_id(session_id)
            || environment_id.is_empty()
            || environment_id.len() > 128
            || !environment_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err(CursorError::Identity);
        }
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(directory)
            .map_err(|_| CursorError::Storage)?;
        if fs::symlink_metadata(directory)
            .map_err(|_| CursorError::Storage)?
            .file_type()
            .is_symlink()
        {
            return Err(CursorError::Invalid);
        }
        let lock_path = directory.join("collector.lock");
        regular_if_present(&lock_path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let lock = options.open(lock_path).map_err(|_| CursorError::Storage)?;
        // A child this process spawned a moment ago still holds its open file descriptions,
        // this lock among them, until it execs (close-on-exec), so on Unix the lock can look
        // taken for an instant after its holder let go. Busy means held beyond that instant.
        let started = std::time::Instant::now();
        loop {
            match lock.try_lock() {
                Ok(()) => break,
                Err(fs::TryLockError::WouldBlock) if started.elapsed() < LOCK_GRACE => {
                    std::thread::sleep(std::time::Duration::from_millis(10))
                }
                Err(_) => return Err(CursorError::Busy),
            }
        }
        let path = directory.join("cursor.json");
        regular_if_present(&path)?;
        let current = match File::open(&path) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(MAX_CURSOR_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| CursorError::Storage)?;
                if bytes.len() as u64 > MAX_CURSOR_BYTES {
                    return Err(CursorError::Invalid);
                }
                let value: Cursor =
                    serde_json::from_slice(&bytes).map_err(|_| CursorError::Invalid)?;
                if value.version != 1
                    || value.after > (1u64 << 53) - 1
                    || value
                        .instance_id
                        .as_deref()
                        .is_some_and(|id| !opaque_id(id))
                    || (value.after == 0) != value.instance_id.is_none()
                    || (value.sealed && value.after == 0)
                    || !accounting_valid(&value)
                {
                    return Err(CursorError::Invalid);
                }
                if value.environment_id != environment_id || value.session_id != session_id {
                    return Err(CursorError::Identity);
                }
                value
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Cursor {
                version: 1,
                environment_id: environment_id.into(),
                session_id: session_id.into(),
                after: 0,
                observed_next: 1,
                instance_id: None,
                sealed: false,
                last_started: 0,
                completed: 0,
                active: BTreeMap::new(),
            },
            Err(_) => return Err(CursorError::Storage),
        };
        Ok(Self {
            directory: directory.to_owned(),
            _lock: lock,
            current,
        })
    }

    pub(crate) fn current(&self) -> &Cursor {
        &self.current
    }

    /// Call only after a matching durable sink acknowledgement. A stale cursor
    /// after interruption replays records; the sink must deduplicate by identity.
    pub(super) fn commit(&mut self, next: Cursor) -> Result<(), CursorError> {
        if next.version != 1
            || next.environment_id != self.current.environment_id
            || next.session_id != self.current.session_id
        {
            return Err(CursorError::Identity);
        }
        if next.after < self.current.after
            || next.after > (1u64 << 53) - 1
            || (self.current.sealed && next != self.current)
            || next.instance_id.as_deref().is_some_and(|id| !opaque_id(id))
            || (next.after == 0) != next.instance_id.is_none()
            || !accounting_valid(&next)
        {
            return Err(CursorError::Regression);
        }
        let bytes = serde_json::to_vec(&next).map_err(|_| CursorError::Invalid)?;
        if bytes.len() as u64 > MAX_CURSOR_BYTES {
            return Err(CursorError::Invalid);
        }
        regular_if_present(&self.directory.join("cursor.json"))?;
        let mut file =
            tempfile::NamedTempFile::new_in(&self.directory).map_err(|_| CursorError::Storage)?;
        file.write_all(&bytes)
            .and_then(|_| file.as_file().sync_all())
            .map_err(|_| CursorError::Storage)?;
        file.persist(self.directory.join("cursor.json"))
            .map_err(|_| CursorError::Storage)?;
        #[cfg(unix)]
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| CursorError::Storage)?;
        self.current = next;
        Ok(())
    }
}

fn accounting_valid(cursor: &Cursor) -> bool {
    cursor.observed_next > cursor.after
        && cursor.observed_next <= (1u64 << 53) - 1
        && cursor.active.len() <= MAX_ACTIVE
        && cursor.completed <= cursor.last_started
        && cursor.last_started <= cursor.after
        && cursor.last_started - cursor.completed == cursor.active.len() as u64
        && (!cursor.sealed || cursor.active.is_empty())
        && cursor.active.iter().all(|(id, kind)| {
            *id > 0 && *id <= cursor.last_started && matches!(kind.as_str(), "load" | "request")
        })
}

fn regular_if_present(path: &Path) -> Result<(), CursorError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => Ok(()),
        Ok(_) => Err(CursorError::Invalid),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CursorError::Storage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cursor_is_locked_identity_bound_bounded_and_recovered_after_process_style_drop() {
        let dir = tempfile::tempdir().unwrap();
        let session = "a".repeat(32);
        let mut first = CursorStore::open(dir.path(), "env-1", &session).unwrap();
        assert!(matches!(
            CursorStore::open(dir.path(), "env-1", &session),
            Err(CursorError::Busy)
        ));
        let mut next = first.current().clone();
        next.after = 3;
        next.observed_next = 4;
        next.instance_id = Some("b".repeat(32));
        first.commit(next.clone()).unwrap();
        drop(first);
        let mut recovered = open_settled(dir.path(), "env-1", &session).unwrap();
        assert_eq!(recovered.current(), &next);
        next.after = 2;
        assert_eq!(recovered.commit(next), Err(CursorError::Regression));
        drop(recovered);
        assert!(matches!(
            open_settled(dir.path(), "env-2", &session),
            Err(CursorError::Identity)
        ));
        fs::write(
            dir.path().join("cursor.json"),
            vec![b' '; MAX_CURSOR_BYTES as usize + 1],
        )
        .unwrap();
        assert!(matches!(
            open_settled(dir.path(), "env-1", &session),
            Err(CursorError::Invalid)
        ));
    }

    /// Opens once the dropped holder's lock is really gone. On Unix a child that a sibling
    /// test spawned at that moment still holds this process's open file descriptions, the
    /// lock's among them, until it execs; the store reports that as Busy for an instant.
    fn open_settled(
        directory: &Path,
        environment_id: &str,
        session_id: &str,
    ) -> Result<CursorStore, CursorError> {
        let started = std::time::Instant::now();
        loop {
            match CursorStore::open(directory, environment_id, session_id) {
                Err(CursorError::Busy) if started.elapsed() < std::time::Duration::from_secs(5) => {
                    std::thread::sleep(std::time::Duration::from_millis(20))
                }
                outcome => return outcome,
            }
        }
    }
}
