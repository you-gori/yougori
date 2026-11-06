//! The engine's setup registry file. One versioned JSON document holds instances, resources,
//! operations and tombstones, so a receipt and the ownership it proves are saved in one atomic
//! write. A file that is corrupt or comes from a newer Yougori is refused and left exactly as it is.
use super::journal::Operation;
use super::model::{Diagnostic, Instance, Tombstone};
use super::schedules::Schedule;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, ErrorKind, Write},
    path::{Path, PathBuf},
    time::Duration,
};

/// Bump this with any change to the stored shape. An older engine then refuses the file instead
/// of rewriting it without the fields it does not know.
/// 2 added `schedules`, the backup times a setup keeps.
pub(crate) const SCHEMA: u32 = 2;
const FILE: &str = "registry.json";
const SIZE_LIMIT: u64 = 32 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Registry {
    pub schema: u32,
    /// Moves on with every saved change, so two writers can never both believe they are current.
    pub revision: u64,
    pub instances: BTreeMap<String, Instance>,
    pub operations: BTreeMap<String, Operation>,
    /// `setup` or `setup/resource` keys of everything removed.
    pub tombstones: BTreeMap<String, Tombstone>,
    /// The backup times a setup's volumes keep, by `setup/resource`. They are here rather than
    /// in a file of their own so a schedule and the setup it belongs to are saved in one write:
    /// a setup can never come back from a restart without its backups, or keep times for a
    /// setup that is gone. A registry written before schedules existed simply has none.
    #[serde(default)]
    pub schedules: BTreeMap<String, Schedule>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            schema: SCHEMA,
            revision: 0,
            instances: BTreeMap::new(),
            operations: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            schedules: BTreeMap::new(),
        }
    }
}

/// Reads only the schema number, so a newer file is recognised before its body is parsed.
#[derive(Deserialize)]
struct Header {
    schema: u32,
}

pub(crate) struct Store {
    path: PathBuf,
    #[cfg(test)]
    pub(crate) faults: std::sync::Arc<Faults>,
}

/// Test-only failure injection: after `allow` more successful writes, every write fails as a
/// full or read-only disk would.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct Faults {
    allow: std::sync::Mutex<Option<u32>>,
    /// A smaller size limit, to reach "full" without writing megabytes.
    pub(crate) size_limit: std::sync::Mutex<Option<u64>>,
}

#[cfg(test)]
impl Faults {
    pub(crate) fn fail_after(&self, writes: u32) {
        *self.allow.lock().unwrap() = Some(writes);
    }
    pub(crate) fn heal(&self) {
        *self.allow.lock().unwrap() = None;
    }
    fn check(&self) -> Result<(), Diagnostic> {
        let mut allow = self.allow.lock().unwrap();
        match allow.as_mut() {
            Some(0) => Err(unwritable("the disk is full", "Free some disk space, then try again.")),
            Some(remaining) => {
                *remaining -= 1;
                Ok(())
            }
            None => Ok(()),
        }
    }
}

/// Windows reports a file another program holds open as a sharing or lock violation, or as
/// access denied while a scanner or sync tool has it.
fn held_open(error: &io::Error) -> bool {
    cfg!(windows) && matches!(error.raw_os_error(), Some(5 | 32 | 33))
}

fn failed(error: &io::Error) -> Diagnostic {
    let disk_full = if cfg!(windows) { matches!(error.raw_os_error(), Some(39 | 112)) } else { error.raw_os_error() == Some(28) };
    if disk_full {
        unwritable("the disk is full", "Free some disk space, then try again.")
    } else if held_open(error) {
        unwritable("another program is using the setup file", "Close programs that may have it open, such as a backup or sync tool, then try again.")
    } else if error.kind() == ErrorKind::PermissionDenied {
        unwritable("Yougori may not write to its data folder", "Check that folder's permissions, then try again.")
    } else {
        unwritable("the drive reported an error", "Check the drive, then try again.")
    }
}

fn unwritable(reason: &str, advice: &str) -> Diagnostic {
    Diagnostic::new(
        "durable_storage_unavailable",
        format!("Yougori could not save setup progress because {reason}, so nothing further was done. {advice}"),
    )
    .retryable()
}

impl Store {
    pub(crate) fn new(folder: &Path) -> Self {
        Self {
            path: folder.join(FILE),
            #[cfg(test)]
            faults: Default::default(),
        }
    }

    /// The saved registry, an empty one when there is none yet, or the reason it was refused.
    pub(crate) fn load(&self) -> Result<Registry, Diagnostic> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Registry::default()),
            Err(error) => return Err(refused(&format!("it could not be read: {error}"))),
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(refused("it is not a regular file"));
        }
        if metadata.len() > SIZE_LIMIT {
            return Err(refused("it is larger than Yougori allows"));
        }
        let bytes = fs::read(&self.path).map_err(|error| refused(&format!("it could not be read: {error}")))?;
        let header: Header = serde_json::from_slice(&bytes).map_err(|_| refused("it is damaged"))?;
        if header.schema > SCHEMA {
            return Err(Diagnostic::new(
                "registry_from_newer_version",
                "Your setups were saved by a newer version of Yougori. Update Yougori to manage them; nothing was changed.",
            ));
        }
        if header.schema < 1 {
            return Err(refused("its version is not one Yougori knows"));
        }
        serde_json::from_slice::<Registry>(&bytes).map_err(|_| refused("it is damaged"))
    }

    /// Writes the whole registry to a temporary file beside it, flushes it to disk and renames
    /// it into place. The previous file stays intact until the rename.
    pub(crate) fn save(&self, registry: &Registry) -> Result<(), Diagnostic> {
        #[cfg(test)]
        self.faults.check()?;
        let folder = self.path.parent().ok_or_else(|| failed(&io::Error::from(ErrorKind::NotFound)))?;
        fs::create_dir_all(folder).map_err(|error| failed(&error))?;
        let bytes = serde_json::to_vec(registry).map_err(|error| failed(&io::Error::other(error)))?;
        #[cfg(test)]
        let limit = self.faults.size_limit.lock().unwrap().unwrap_or(SIZE_LIMIT);
        #[cfg(not(test))]
        let limit = SIZE_LIMIT;
        if bytes.len() as u64 > limit {
            return Err(Diagnostic::new(
                "registry_full",
                "Your setup records have reached their size limit. Remove setups you no longer need, then try again.",
            ));
        }
        let mut file = tempfile::NamedTempFile::new_in(folder).map_err(|error| failed(&error))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|error| failed(&error))?;
        }
        file.write_all(&bytes).map_err(|error| failed(&error))?;
        file.write_all(b"\n").map_err(|error| failed(&error))?;
        file.as_file().sync_all().map_err(|error| failed(&error))?;
        // A scanner or sync tool may hold the old file open for a moment on Windows.
        let mut attempts = 0;
        loop {
            match file.persist(&self.path) {
                Ok(_) => break,
                Err(error) if held_open(&error.error) && attempts < 10 => {
                    attempts += 1;
                    file = error.file;
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(error) => return Err(failed(&error.error)),
            }
        }
        // The rename itself is durable only once the folder entry is flushed too.
        #[cfg(unix)]
        if let Ok(directory) = fs::File::open(folder) {
            let _ = directory.sync_all();
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

fn refused(reason: &str) -> Diagnostic {
    Diagnostic::new(
        "registry_unreadable",
        format!("Yougori can't read your saved setups because {reason}. The file was left untouched, and nothing your setups run was stopped. Restore the file from a backup to manage them here again."),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_registry_starts_empty_and_round_trips() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::new(folder.path());
        let mut registry = store.load().unwrap();
        assert_eq!(registry, Registry::default());
        registry.revision = 7;
        store.save(&registry).unwrap();
        assert_eq!(store.load().unwrap().revision, 7);
    }

    #[test]
    fn a_damaged_or_newer_registry_is_refused_and_never_overwritten() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::new(folder.path());
        for (content, code) in [
            (&b"{not json"[..], "registry_unreadable"),
            (&br#"{"schema":99,"whatever":true}"#[..], "registry_from_newer_version"),
            (&br#"{"schema":1,"revision":1,"instances":{},"operations":{},"tombstones":{},"extra":1}"#[..], "registry_unreadable"),
        ] {
            fs::write(store.path(), content).unwrap();
            assert_eq!(store.load().unwrap_err().code, code);
            assert_eq!(fs::read(store.path()).unwrap(), content);
        }
    }

    #[test]
    fn a_registry_written_before_schedules_existed_still_reads() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::new(folder.path());
        fs::write(store.path(), br#"{"schema":1,"revision":4,"instances":{},"operations":{},"tombstones":{}}"#).unwrap();
        let loaded = store.load().expect("an older registry still reads");
        assert_eq!(loaded.revision, 4);
        assert!(loaded.schedules.is_empty(), "it simply has no backup times yet");
        // Saved again, it carries them, and this engine reads its own file back.
        store.save(&loaded).unwrap();
        assert_eq!(store.load().unwrap(), loaded);
    }

    #[test]
    fn a_failed_write_keeps_the_previous_file() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::new(folder.path());
        let mut registry = Registry::default();
        registry.revision = 1;
        store.save(&registry).unwrap();
        store.faults.fail_after(0);
        registry.revision = 2;
        assert_eq!(store.save(&registry).unwrap_err().code, "durable_storage_unavailable");
        store.faults.heal();
        assert_eq!(store.load().unwrap().revision, 1);
    }
}
