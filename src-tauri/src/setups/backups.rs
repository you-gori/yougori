//! Backups of a setup's volumes, and putting one back.
//!
//! A backup is a copy of everything on one named volume, read out through a sandbox of the same
//! setup that mounts it, with a checksum of every file and of the whole set. Backups live in
//! Yougori's own data folder (`<data>/setups/backups/<setup>/<volume>/<backup>`), never in a
//! folder a template names, and the oldest beyond the setup's `backup_keep` are deleted once a
//! newer one is complete.
//!
//! Consistency is the setup's choice and is said plainly in the review:
//!
//! - `stop` (the default): the setup's other sandboxes that mount the volume are stopped while it
//!   is copied and started again straight after, so nothing is writing to it. The sandbox the
//!   backup reads through keeps running.
//! - `live`: everything keeps running, and a file being written at that moment can be copied
//!   half-written. A database above all may not open from such a copy. Nothing pretends
//!   otherwise.
//!
//! What a backup cannot carry is said in `schedules::LIMITS`: a value sealed to this computer in
//! the credential store is not in it, and a copy kept on this computer's own disk is no help if
//! this computer is lost.
//!
//! Putting one back has two forms. Into a **disposable copy** is the default: the files land in a
//! fresh folder inside the sandbox, nothing already there is touched, and the person looks before
//! deciding. Into the **original** replaces what is on the volume, and is only done when the
//! caller asks for it by name after a review that says exactly what it replaces.
use super::handler::{HandlerError, Outcome};
use super::ordinary::BoxFuture;
use super::schedules::{self, Schedule};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio_util::sync::CancellationToken;
use yougori_setup::resource::BackupConsistency;

/// The manifest shape. Bumped if what a backup holds changes.
const MANIFEST_VERSION: u32 = 1;
const MANIFEST: &str = "manifest.json";
const FILES: &str = "files";
/// The most files one backup may hold, so a runaway volume cannot fill the disk unnoticed.
const MAX_FILES: usize = 200_000;
const MAX_BYTES: u64 = 200 * 1024 * 1024 * 1024;

/// One backup, as the registry records it. It holds no path of this computer: the folder is
/// worked out from the setup, the volume and this id, so moving Yougori's data folder is safe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Backup {
    /// `backup-<uuid>`.
    pub id: String,
    /// When it finished, in Unix seconds.
    pub at: i64,
    pub files: u64,
    pub bytes: u64,
    /// SHA-256 over every file's path, size and contents, in path order.
    pub checksum: String,
    /// How the copy was taken, so a `live` one is never shown as if it were quiet.
    pub consistency: BackupConsistency,
}

impl Backup {
    /// What the setup page and the CLI show for one backup.
    pub(crate) fn describe(&self) -> String {
        let quiet = match self.consistency {
            BackupConsistency::Stop => "taken with its sandboxes stopped",
            BackupConsistency::Live => "taken while everything kept running, so a file being written then may be half-written",
        };
        format!("{} — {} files, {}, {quiet}", schedules::stamp(self.at), self.files, bytes(self.bytes))
    }
}

/// What is written beside a backup's files, so a folder on its own is still readable.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    version: u32,
    setup: String,
    volume: String,
    /// The sandbox resource it was read through, and where that sandbox mounts the volume.
    through: String,
    path: String,
    at: i64,
    consistency: BackupConsistency,
    files: u64,
    bytes: u64,
    checksum: String,
    /// Every file, in path order.
    entries: Vec<Entry>,
    /// What this backup does not hold, in the words a person reads.
    note: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Entry {
    path: String,
    size: u64,
    sha256: String,
}

/// Where a restore puts the files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    /// A fresh folder inside the sandbox. Nothing already there is touched.
    Copy,
    /// The volume itself: what is on it is replaced by what the backup holds.
    Original,
}

/// What backups need of the setup registry.
pub(crate) trait Setups: Send + Sync {
    /// The runtime id of one of a setup's sandbox resources, when it exists.
    fn sandbox(&self, setup: &str, resource: &str) -> Option<String>;
    /// The setup's sandbox resources that mount `volume`, by resource id, in order.
    fn mounting(&self, setup: &str, volume: &str) -> Vec<String>;
}

/// What backups need of the sandboxes themselves. The engine calls its own methods; tests use a
/// fake, so no real sandbox is started, read or written.
pub(crate) trait Sandboxes: Send + Sync {
    fn running<'a>(&'a self, sandbox: &'a str) -> BoxFuture<'a, Result<bool, String>>;
    fn set_running<'a>(&'a self, sandbox: &'a str, running: bool) -> BoxFuture<'a, Result<(), String>>;
    /// Copies everything under `path` in the sandbox into `into` on this computer, which exists
    /// and is empty. Returns the folder the files landed in.
    fn copy_out<'a>(&'a self, sandbox: &'a str, path: &'a str, into: &'a Path) -> BoxFuture<'a, Result<PathBuf, String>>;
    /// Copies the folder `from` on this computer into the sandbox under `into`, which it makes.
    /// Returns the folder inside the sandbox the files landed in.
    fn copy_in<'a>(&'a self, sandbox: &'a str, from: &'a Path, into: &'a str) -> BoxFuture<'a, Result<String, String>>;
    /// Runs one shell line in the sandbox and gives its exit code.
    fn exec<'a>(&'a self, sandbox: &'a str, command: &'a str) -> BoxFuture<'a, Result<i32, String>>;
}

/// The backup worker: what the scheduler runs, and what a restore goes through.
pub(crate) struct Backups {
    setups: Arc<dyn Setups>,
    sandboxes: Arc<dyn Sandboxes>,
    /// `<data>/setups/backups`.
    folder: PathBuf,
}

/// A guest path a backup may read or write: absolute, no `..`, no backslash.
fn guest_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 512
        && !path.contains(['\0', '\\'])
        && path.split('/').all(|part| part != ".." && part != ".")
        && path.split('/').filter(|part| !part.is_empty()).count() >= 1
}

fn quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn bytes(count: u64) -> String {
    const UNITS: [(&str, u64); 4] = [("GB", 1_073_741_824), ("MB", 1_048_576), ("KB", 1024), ("bytes", 1)];
    for (name, size) in UNITS {
        if count >= size {
            return if size == 1 { format!("{count} bytes") } else { format!("{:.1} {name}", count as f64 / size as f64) };
        }
    }
    "0 bytes".into()
}

fn failed(message: impl Into<String>) -> String {
    crate::lifecycle::safe_diagnostic(&message.into())
}

/// Every file under `root`, by its path relative to it with `/`, in path order.
fn walk(root: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    fn inside(root: &Path, at: &Path, found: &mut Vec<(String, PathBuf)>) -> Result<(), String> {
        let listing = std::fs::read_dir(at).map_err(|error| failed(format!("A backup folder could not be read: {error}")))?;
        for entry in listing {
            let entry = entry.map_err(|error| failed(format!("A backup folder could not be read: {error}")))?;
            let path = entry.path();
            let kind = std::fs::symlink_metadata(&path).map_err(|error| failed(format!("A backup file could not be read: {error}")))?.file_type();
            if kind.is_symlink() {
                // A copy out never makes one; one here would point somewhere this is not meant
                // to reach, so it is refused rather than followed.
                return Err("A backup folder holds a link, which Yougori does not copy.".into());
            }
            if kind.is_dir() {
                inside(root, &path, found)?;
            } else if kind.is_file() {
                let relative = path.strip_prefix(root).map_err(|_| "A backup file is outside its folder.".to_owned())?;
                found.push((relative.to_string_lossy().replace('\\', "/"), path));
            }
            if found.len() > MAX_FILES {
                return Err(format!("This volume holds more than {MAX_FILES} files, which is more than one backup can carry."));
            }
        }
        Ok(())
    }
    let mut found = Vec::new();
    inside(root, root, &mut found)?;
    found.sort();
    Ok(found)
}

/// The checksum of every file under `root`, and the whole set's: the SHA-256 over each file's
/// path, size and contents, in path order. Two folders with the same files have the same one.
fn checksums(root: &Path) -> Result<(Vec<Entry>, u64, String), String> {
    let mut entries = Vec::new();
    let mut total = 0u64;
    let mut whole = Sha256::new();
    for (relative, path) in walk(root)? {
        let mut file = std::fs::File::open(&path).map_err(|error| failed(format!("A backup file could not be read: {error}")))?;
        let mut hash = Sha256::new();
        let size = std::io::copy(&mut file, &mut hash).map_err(|error| failed(format!("A backup file could not be read: {error}")))?;
        total = total.checked_add(size).ok_or("This volume holds more data than one backup can carry.")?;
        if total > MAX_BYTES {
            return Err(format!("This volume holds more than {}, which is more than one backup can carry.", bytes(MAX_BYTES)));
        }
        let sha256 = hex::encode(hash.finalize());
        whole.update(relative.as_bytes());
        whole.update(b"\0");
        whole.update(size.to_le_bytes());
        whole.update(sha256.as_bytes());
        whole.update(b"\n");
        entries.push(Entry { path: relative, size, sha256 });
    }
    Ok((entries, total, hex::encode(whole.finalize())))
}

impl Backups {
    pub(crate) fn new(setups: Arc<dyn Setups>, sandboxes: Arc<dyn Sandboxes>, folder: PathBuf) -> Arc<Backups> {
        Arc::new(Backups { setups, sandboxes, folder })
    }

    fn volume_folder(&self, setup: &str, volume: &str) -> PathBuf {
        self.folder.join(setup).join(volume)
    }

    fn backup_folder(&self, setup: &str, volume: &str, id: &str) -> PathBuf {
        self.volume_folder(setup, volume).join(id)
    }

    /// Where a backup's files are, for the setup page to show. Nothing outside the engine's own
    /// data folder is ever returned.
    pub(crate) fn location(&self, setup: &str, volume: &str, id: &str) -> PathBuf {
        self.backup_folder(setup, volume, id).join(FILES)
    }

    /// Deletes every backup a setup kept.
    ///
    /// Not called, and not to be: a removal deletes backups one volume at a time, and only the
    /// volumes the person ticked on its review ([`Backups::forget_volume`]). Nothing deletes all
    /// of a setup's backups in one go.
    #[allow(dead_code)]
    pub(crate) async fn forget_setup(&self, setup: &str) {
        let folder = self.folder.join(setup);
        let _ = tokio::task::spawn_blocking(move || std::fs::remove_dir_all(folder)).await;
    }

    /// Deletes every backup kept of one volume: its whole folder in Yougori's data folder.
    ///
    /// Only a removal calls this, for a volume whose template says `retention.onRemove: ask` and
    /// whose deletion the person ticked on the reviewed removal (`delete_data:VOLUME`). By then
    /// the volume's schedule is gone and no copy of it is being written, so nothing lands after
    /// the folder is deleted. A folder that is already gone is not an error: a retry after a
    /// partial failure finishes the job.
    pub(crate) async fn forget_volume(&self, setup: &str, volume: &str) -> Result<(), String> {
        let plain = |part: &str| !part.is_empty() && part.len() <= 128 && part.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'));
        if !plain(setup) || !plain(volume) {
            return Err("That is not a setup and volume Yougori keeps backups for, so nothing was deleted.".into());
        }
        let folder = self.volume_folder(setup, volume);
        tokio::task::spawn_blocking(move || match std::fs::remove_dir_all(&folder) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.to_string()),
            _ => Ok(()),
        })
        .await
        .map_err(|_| "The backups could not be deleted.".to_owned())?
    }

    /// The sandboxes this backup stops while it copies: the setup's own, except the one it reads
    /// through, and only those that are running.
    async fn quiet(&self, schedule: &Schedule) -> Result<Vec<String>, String> {
        if schedule.consistency != BackupConsistency::Stop {
            return Ok(Vec::new());
        }
        let mut stopping = Vec::new();
        for resource in self.setups.mounting(&schedule.setup, &schedule.resource) {
            if resource == schedule.through {
                continue;
            }
            let Some(id) = self.setups.sandbox(&schedule.setup, &resource) else { continue };
            if self.sandboxes.running(&id).await.unwrap_or(false) {
                stopping.push(id);
            }
        }
        Ok(stopping)
    }

    /// Makes one backup. Whatever happens, every sandbox this stopped is started again.
    pub(crate) async fn back_up(&self, schedule: &Schedule, cancel: &CancellationToken) -> Result<(String, Backup), String> {
        if !guest_path(&schedule.path) {
            return Err("This volume's place inside its sandbox is not a path Yougori can read.".into());
        }
        let through = self
            .setups
            .sandbox(&schedule.setup, &schedule.through)
            .ok_or_else(|| format!("{} isn't there yet, so {} can't be read. It is backed up once the setup is running.", schedule.through, schedule.resource))?;
        if !self.sandboxes.running(&through).await.map_err(failed)? {
            // The reading sandbox is started for the copy; it is left running, as the setup's
            // own start and stop decide that, not a backup.
            self.sandboxes.set_running(&through, true).await.map_err(|error| failed(format!("{} could not be started to read the backup: {error}", schedule.through)))?;
        }
        let stopped = self.quiet(schedule).await?;
        for sandbox in &stopped {
            if let Err(error) = self.sandboxes.set_running(sandbox, false).await {
                self.start_again(&stopped).await;
                return Err(failed(format!("A sandbox that writes to {} could not be stopped, so no backup was taken: {error}", schedule.resource)));
            }
        }
        let result = self.copy(schedule, &through, cancel).await;
        self.start_again(&stopped).await;
        result
    }

    async fn start_again(&self, stopped: &[String]) {
        for sandbox in stopped {
            if let Err(error) = self.sandboxes.set_running(sandbox, true).await {
                eprintln!("A sandbox stopped for a backup could not be started again: {}", crate::lifecycle::safe_diagnostic(&error));
            }
        }
    }

    /// The copy itself: out of the sandbox into a folder of this engine's, checksummed, then
    /// moved into place. A copy that does not finish leaves nothing behind.
    async fn copy(&self, schedule: &Schedule, through: &str, cancel: &CancellationToken) -> Result<(String, Backup), String> {
        let id = format!("backup-{}", uuid::Uuid::new_v4());
        let volume_folder = self.volume_folder(&schedule.setup, &schedule.resource);
        let staging = volume_folder.join(format!("{id}.partial"));
        let staging_files = staging.join(FILES);
        let prepare = staging_files.clone();
        tokio::task::spawn_blocking(move || std::fs::create_dir_all(&prepare))
            .await
            .map_err(|_| "Yougori could not prepare a folder for the backup.".to_owned())?
            .map_err(|error| failed(format!("Yougori could not prepare a folder for the backup: {error}")))?;
        let made = self.write(schedule, through, &id, &staging, &staging_files, cancel).await;
        match made {
            Ok(backup) => {
                let final_folder = self.backup_folder(&schedule.setup, &schedule.resource, &id);
                let moved = tokio::task::spawn_blocking(move || std::fs::rename(&staging, &final_folder)).await;
                match moved {
                    Ok(Ok(())) => Ok((id, backup)),
                    _ => {
                        self.discard(&self.backup_folder(&schedule.setup, &schedule.resource, &format!("{id}.partial"))).await;
                        Err("The backup was copied but could not be saved. Nothing kept before is affected; it runs again at its next time.".into())
                    }
                }
            }
            Err(error) => {
                self.discard(&staging).await;
                Err(error)
            }
        }
    }

    async fn write(&self, schedule: &Schedule, through: &str, id: &str, staging: &Path, files: &Path, cancel: &CancellationToken) -> Result<Backup, String> {
        let copied = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err("Yougori was closing, so this backup was stopped.".into()),
            result = self.sandboxes.copy_out(through, &schedule.path, files) => result.map_err(|error| failed(format!("{} could not be copied out of {}: {error}", schedule.resource, schedule.through)))?,
        };
        if cancel.is_cancelled() {
            return Err("Yougori was closing, so this backup was stopped.".into());
        }
        let root = copied;
        let measured = root.clone();
        let (entries, total, checksum) = tokio::task::spawn_blocking(move || checksums(&measured))
            .await
            .map_err(|_| "The backup could not be checked.".to_owned())??;
        let backup = Backup {
            id: id.to_owned(),
            at: schedules::now(),
            files: entries.len() as u64,
            bytes: total,
            checksum: checksum.clone(),
            consistency: schedule.consistency,
        };
        let manifest = Manifest {
            version: MANIFEST_VERSION,
            setup: schedule.setup.clone(),
            volume: schedule.resource.clone(),
            through: schedule.through.clone(),
            path: schedule.path.clone(),
            at: backup.at,
            consistency: schedule.consistency,
            files: backup.files,
            bytes: total,
            checksum,
            entries,
            note: schedules::LIMITS.to_owned(),
        };
        // The files landed in a folder of their own inside the staging folder; the manifest sits
        // beside them, and the folder is named `files` so a person finds it without this code.
        let settle = (staging.to_owned(), root, files.to_owned());
        tokio::task::spawn_blocking(move || {
            let (staging, root, files) = settle;
            if root != files {
                let moved = files.with_extension("moving");
                std::fs::rename(&root, &moved).map_err(|error| format!("The backup could not be tidied: {error}"))?;
                let _ = std::fs::remove_dir_all(&files);
                std::fs::rename(&moved, &files).map_err(|error| format!("The backup could not be tidied: {error}"))?;
            }
            let text = serde_json::to_vec_pretty(&manifest).map_err(|error| format!("The backup's manifest could not be written: {error}"))?;
            std::fs::write(staging.join(MANIFEST), text).map_err(|error| format!("The backup's manifest could not be written: {error}"))
        })
        .await
        .map_err(|_| "The backup could not be finished.".to_owned())?
        .map_err(failed)?;
        Ok(backup)
    }

    async fn discard(&self, folder: &Path) {
        let folder = folder.to_owned();
        let _ = tokio::task::spawn_blocking(move || std::fs::remove_dir_all(folder)).await;
    }

    /// Deletes the backups beyond `keep`, oldest first, and says which went. Only called once a
    /// newer one is complete, so the kept count is never briefly short.
    pub(crate) async fn prune(&self, setup: &str, volume: &str, kept: &[Backup], keep: u32) -> Vec<String> {
        let excess = kept.len().saturating_sub(keep.max(1) as usize);
        let mut gone = Vec::new();
        for backup in kept.iter().take(excess) {
            self.discard(&self.backup_folder(setup, volume, &backup.id)).await;
            gone.push(backup.id.clone());
        }
        gone
    }

    /// Checks a kept backup against its own manifest: every file still there, the same size and
    /// the same contents. A backup that does not match is never restored.
    pub(crate) async fn verify(&self, setup: &str, volume: &str, id: &str) -> Result<Value, String> {
        let folder = self.backup_folder(setup, volume, id);
        tokio::task::spawn_blocking(move || {
            let text = std::fs::read(folder.join(MANIFEST)).map_err(|_| "This backup's record is missing, so Yougori won't restore from it.".to_owned())?;
            let manifest: Manifest = serde_json::from_slice(&text).map_err(|_| "This backup's record can't be read, so Yougori won't restore from it.".to_owned())?;
            if manifest.version > MANIFEST_VERSION {
                return Err("This backup was made by a newer Yougori. Update Yougori to restore from it.".into());
            }
            let (entries, bytes, checksum) = checksums(&folder.join(FILES))?;
            if checksum != manifest.checksum || entries != manifest.entries {
                return Err("This backup's files have changed since it was made, so Yougori won't restore from it. Choose another backup.".into());
            }
            Ok(json!({
                "files": manifest.files, "bytes": bytes, "checksum": checksum,
                "at": manifest.at, "consistency": manifest.consistency, "note": manifest.note,
            }))
        })
        .await
        .map_err(|_| "This backup could not be checked.".to_owned())?
    }

    /// What restoring this backup would do, in plain words, for the review before it happens.
    pub(crate) fn restore_review(&self, schedule: &Schedule, backup: &Backup, target: Target) -> Vec<String> {
        let mut said = vec![format!("The backup from {} holds {} files, {}.", schedules::stamp(backup.at), backup.files, bytes(backup.bytes))];
        match target {
            Target::Copy => said.push(format!(
                "The files are put in a new folder inside {}, which nothing uses yet. {} itself is not changed, so you can look at them first and copy across what you need.",
                schedule.through, schedule.resource
            )),
            Target::Original => {
                said.push(format!(
                    "Everything now on {} is replaced by what this backup holds. Anything written to it since {} is gone, and this cannot be undone.",
                    schedule.resource,
                    schedules::stamp(backup.at)
                ));
                said.push(format!("The setup's sandboxes that use {} are stopped while the files are put back, and started again after.", schedule.resource));
            }
        }
        if backup.consistency == BackupConsistency::Live {
            said.push("This backup was taken while everything was running, so a file being written at that moment may be half-written. Check what you restore.".into());
        }
        said.push(schedules::LIMITS.to_owned());
        said
    }

    /// Puts a backup back. `Target::Copy` leaves the volume alone; `Target::Original` replaces
    /// what is on it, after the caller has shown `restore_review`.
    pub(crate) async fn restore(&self, schedule: &Schedule, backup: &Backup, target: Target) -> Result<Value, String> {
        if !guest_path(&schedule.path) {
            return Err("This volume's place inside its sandbox is not a path Yougori can write.".into());
        }
        let checked = self.verify(&schedule.setup, &schedule.resource, &backup.id).await?;
        let through = self
            .setups
            .sandbox(&schedule.setup, &schedule.through)
            .ok_or_else(|| format!("{} isn't running, so the backup can't be put back. Start the setup, then try again.", schedule.through))?;
        if !self.sandboxes.running(&through).await.map_err(failed)? {
            self.sandboxes.set_running(&through, true).await.map_err(|error| failed(format!("{} could not be started to put the backup back: {error}", schedule.through)))?;
        }
        let files = self.location(&schedule.setup, &schedule.resource, &backup.id);
        // Into a folder of its own either way: nothing is replaced until the swap below, which
        // only runs for the original.
        let staging = format!("/tmp/yougori-restore-{}", &backup.id[backup.id.len().saturating_sub(12)..]);
        // The copy lands in a new folder inside this one, which the sandbox has to have first.
        match self.sandboxes.exec(&through, &format!("mkdir -p -- {}", quoted(&staging))).await {
            Ok(0) => {}
            Ok(code) => return Err(failed(format!("A folder for the backup could not be made inside {} (it answered {code}), so nothing was put back.", schedule.through))),
            Err(error) => return Err(failed(format!("A folder for the backup could not be made inside {}: {error}. Nothing was put back.", schedule.through))),
        }
        let landed = self
            .sandboxes
            .copy_in(&through, &files, &staging)
            .await
            .map_err(|error| failed(format!("The backup could not be copied into {}: {error}", schedule.through)))?;
        if !guest_path(&landed) || !landed.starts_with(&format!("{staging}/")) {
            let _ = self.sandboxes.exec(&through, &format!("rm -rf -- {}", quoted(&staging))).await;
            return Err("The backup was copied somewhere unexpected inside the sandbox, so nothing was put back.".into());
        }
        // A copy into a sandbox brings the folder it was given under its own name, so the
        // backup's files are in its `files` folder inside the new one, not loose in it.
        let landed = format!("{landed}/{FILES}");
        if target == Target::Copy {
            return Ok(json!({
                "restoredTo": "copy", "folder": landed, "sandbox": schedule.through, "checked": checked,
                "next": format!("The files are in {landed} inside {}. {} is unchanged. Copy across what you need, then delete that folder.", schedule.through, schedule.resource),
            }));
        }
        let stopped = self.quiet(schedule).await?;
        for sandbox in &stopped {
            if let Err(error) = self.sandboxes.set_running(sandbox, false).await {
                self.start_again(&stopped).await;
                let _ = self.sandboxes.exec(&through, &format!("rm -rf -- {}", quoted(&staging))).await;
                return Err(failed(format!("A sandbox that writes to {} could not be stopped, so nothing was put back: {error}", schedule.resource)));
            }
        }
        let swap = self.swap(&through, &landed, &schedule.path).await;
        self.start_again(&stopped).await;
        let _ = self.sandboxes.exec(&through, &format!("rm -rf -- {}", quoted(&staging))).await;
        swap?;
        Ok(json!({
            "restoredTo": "original", "volume": schedule.resource, "sandbox": schedule.through, "checked": checked,
            "next": format!("{} now holds what the backup from {} held. The setup's sandboxes are running again.", schedule.resource, schedules::stamp(backup.at)),
        }))
    }

    /// Replaces the contents of `path` in the sandbox with what is in `from`. The old contents
    /// are moved aside first and deleted only once the new ones are in place, so a failure
    /// halfway leaves the volume as it was.
    async fn swap(&self, sandbox: &str, from: &str, path: &str) -> Result<(), String> {
        let aside = format!("{path}.yougori-previous");
        let (from, path, aside) = (quoted(from), quoted(path), quoted(&aside));
        let script = format!(
            "set -eu; test -d {path}; rm -rf -- {aside}; mkdir -p -- {aside}; \
             find {path} -mindepth 1 -maxdepth 1 -exec mv -t {aside} -- {{}} +; \
             find {from} -mindepth 1 -maxdepth 1 -exec mv -t {path} -- {{}} +; \
             rm -rf -- {aside}"
        );
        match self.sandboxes.exec(sandbox, &script).await {
            Ok(0) => Ok(()),
            Ok(_) => Err(format!(
                "Putting the files back did not finish. What was there before was moved to {} inside the sandbox; nothing was deleted. Look there before trying again.",
                crate::lifecycle::safe_diagnostic(&format!("{}.yougori-previous", path.trim_matches('\'')))
            )),
            Err(error) => Err(failed(format!("Putting the files back did not finish, and nothing was deleted: {error}"))),
        }
    }

    /// The handler refusal for a backup action that cannot be done here. Kept next to the code
    /// that would raise it: every refusal this module reaches today is raised closer to its cause,
    /// with the cause in the message, so nothing calls this shape yet.
    #[allow(dead_code)]
    pub(crate) fn refusal(message: impl Into<String>) -> HandlerError {
        HandlerError::new(Outcome::Failed, "backup_failed", message)
    }
}

/// What the scheduler runs for a `volume_backup`: one backup, written into the schedule's
/// records, then the oldest beyond `keep` deleted — in that order, so the kept count is never
/// briefly short of what the setup asked for.
pub(crate) struct Work {
    records: Arc<dyn schedules::Records>,
    backups: Arc<Backups>,
}

impl Work {
    pub(crate) fn new(records: Arc<dyn schedules::Records>, backups: Arc<Backups>) -> Arc<Work> {
        Arc::new(Work { records, backups })
    }
}

impl schedules::Runner for Work {
    fn run<'a>(&'a self, schedule: &'a Schedule, cancel: &'a CancellationToken) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(async move {
            let (_, backup) = self.backups.back_up(schedule, cancel).await?;
            let kept = std::sync::Mutex::new(None);
            self.records.change(&schedule.id, &mut |saved| {
                saved.backups.push(backup.clone());
                *kept.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(saved.backups.clone());
            });
            let Some(kept) = kept.into_inner().unwrap_or_else(|poisoned| poisoned.into_inner()) else {
                // The setup stopped backing this volume up while the copy was being taken: it was
                // removed, perhaps with the person asking for its backups to go. A copy that no
                // schedule records sits where nobody sees it, and it could outlive a deletion the
                // person asked for, so it goes too.
                self.backups.discard(&self.backups.backup_folder(&schedule.setup, &schedule.resource, &backup.id)).await;
                return Ok(format!("{} is no longer backed up, so the copy just taken was not kept.", schedule.resource));
            };
            let gone = self.backups.prune(&schedule.setup, &schedule.resource, &kept, schedule.keep).await;
            if !gone.is_empty() {
                self.records.change(&schedule.id, &mut |saved| saved.backups.retain(|each| !gone.contains(&each.id)));
            }
            let older = match gone.len() {
                0 => String::new(),
                1 => " The oldest backup was deleted, so only the number you asked for is kept.".to_owned(),
                count => format!(" The {count} oldest backups were deleted, so only the number you asked for is kept."),
            };
            Ok(format!("Backed up {} ({} files, {}).{older}", schedule.resource, backup.files, bytes(backup.bytes)))
        })
    }
}

/// The engine's own sandboxes, through the same calls the desktop and the CLI use.
pub(crate) struct EngineSandboxes {
    app: crate::AppHandle,
}

impl EngineSandboxes {
    pub(crate) fn new(app: crate::AppHandle) -> EngineSandboxes {
        EngineSandboxes { app }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        crate::automation::dispatch::dispatch(&self.app, method, &params).await
    }
}

impl Sandboxes for EngineSandboxes {
    fn running<'a>(&'a self, sandbox: &'a str) -> BoxFuture<'a, Result<bool, String>> {
        Box::pin(async move {
            use tauri::Manager;
            let state = self.app.state::<crate::store::PlatformStore>().snapshot()?;
            Ok(state.environments.iter().any(|environment| environment.id == sandbox && environment.status == crate::models::EnvironmentStatus::Running))
        })
    }

    fn set_running<'a>(&'a self, sandbox: &'a str, running: bool) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.call("set_environment_status", json!({"environmentId": sandbox, "status": if running { "running" } else { "stopped" }}))
                .await
                .map(|_| ())
        })
    }

    fn copy_out<'a>(&'a self, sandbox: &'a str, path: &'a str, into: &'a Path) -> BoxFuture<'a, Result<PathBuf, String>> {
        Box::pin(async move {
            let copied = self
                .call("copy_files_from_environment", json!({"environmentId": sandbox, "path": path, "destination": into.to_string_lossy()}))
                .await?;
            let folder = copied["folder"].as_str().ok_or("The copy didn't say where it put the files.")?;
            let folder = PathBuf::from(folder);
            // Never outside the folder this backup was given, whatever the copy reported.
            if !folder.starts_with(into) {
                return Err("The copy put the files outside the backup folder, so nothing was kept.".into());
            }
            Ok(folder)
        })
    }

    fn copy_in<'a>(&'a self, sandbox: &'a str, from: &'a Path, into: &'a str) -> BoxFuture<'a, Result<String, String>> {
        Box::pin(async move {
            let copied = self
                .call("copy_files_to_environment", json!({"environmentId": sandbox, "paths": [from.to_string_lossy()], "destination": into}))
                .await?;
            copied["destination"].as_str().map(str::to_owned).ok_or_else(|| "The copy didn't say where it put the files.".into())
        })
    }

    fn exec<'a>(&'a self, sandbox: &'a str, command: &'a str) -> BoxFuture<'a, Result<i32, String>> {
        Box::pin(async move {
            let result = self.call("execute_environment_command", json!({"request": {"environmentId": sandbox, "command": command}})).await?;
            // What the sandbox printed is never repeated: it can print anything.
            Ok(result["exitCode"].as_i64().unwrap_or(1) as i32)
        })
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! Sandboxes in memory, whose files are real files in a temporary folder, so the copies, the
    //! checksums and the swap are the ones the engine runs.
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    #[derive(Default)]
    pub(crate) struct State {
        /// Sandbox id to whether it runs.
        pub running: BTreeMap<String, bool>,
        /// The sandbox's own file tree on this computer: sandbox id to its root folder.
        pub roots: BTreeMap<String, PathBuf>,
        pub starts: Vec<(String, bool)>,
        /// The next copy out fails.
        pub fail_copy_out: bool,
        /// The next stop fails.
        pub fail_stop: bool,
    }

    pub(crate) struct FakeSandboxes {
        pub state: Mutex<State>,
    }

    impl FakeSandboxes {
        pub(crate) fn new() -> FakeSandboxes {
            FakeSandboxes { state: Mutex::new(State::default()) }
        }

        /// The folder on this computer that stands for `path` inside the sandbox.
        fn at(&self, sandbox: &str, path: &str) -> Result<PathBuf, String> {
            let state = self.state.lock().unwrap();
            let root = state.roots.get(sandbox).ok_or("No such sandbox")?.clone();
            Ok(root.join(path.trim_start_matches('/')))
        }
    }

    fn copy_tree(from: &Path, to: &Path) -> Result<(), String> {
        std::fs::create_dir_all(to).map_err(|error| error.to_string())?;
        for entry in std::fs::read_dir(from).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let target = to.join(entry.file_name());
            if entry.path().is_dir() {
                copy_tree(&entry.path(), &target)?;
            } else {
                std::fs::copy(entry.path(), &target).map_err(|error| error.to_string())?;
            }
        }
        Ok(())
    }

    impl Sandboxes for FakeSandboxes {
        fn running<'a>(&'a self, sandbox: &'a str) -> BoxFuture<'a, Result<bool, String>> {
            Box::pin(async move { Ok(self.state.lock().unwrap().running.get(sandbox).copied().unwrap_or(false)) })
        }

        fn set_running<'a>(&'a self, sandbox: &'a str, running: bool) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                if !running && std::mem::take(&mut state.fail_stop) {
                    return Err("the sandbox would not stop".into());
                }
                state.running.insert(sandbox.to_owned(), running);
                state.starts.push((sandbox.to_owned(), running));
                Ok(())
            })
        }

        fn copy_out<'a>(&'a self, sandbox: &'a str, path: &'a str, into: &'a Path) -> BoxFuture<'a, Result<PathBuf, String>> {
            Box::pin(async move {
                if std::mem::take(&mut self.state.lock().unwrap().fail_copy_out) {
                    return Err("the sandbox stopped answering".into());
                }
                let from = self.at(sandbox, path)?;
                // As the engine's own copy does: into a folder named after the last part.
                let folder = into.join(path.rsplit('/').next().unwrap_or("copy"));
                copy_tree(&from, &folder)?;
                Ok(folder)
            })
        }

        fn copy_in<'a>(&'a self, sandbox: &'a str, from: &'a Path, into: &'a str) -> BoxFuture<'a, Result<String, String>> {
            Box::pin(async move {
                // As the guest agent does: a new folder in `into`, holding the folder given by its
                // own name. A destination folder that isn't there is refused, as it is there.
                let parent = self.at(sandbox, into)?;
                if !parent.is_dir() {
                    return Err("The selected shared folder is unavailable".into());
                }
                let name = from.file_name().ok_or("The copy has no folder name")?;
                copy_tree(from, &parent.join("yougori-import").join(name))?;
                Ok(format!("{into}/yougori-import"))
            })
        }

        fn exec<'a>(&'a self, sandbox: &'a str, command: &'a str) -> BoxFuture<'a, Result<i32, String>> {
            Box::pin(async move {
                // The one script the fake understands is the swap, read back as its three paths,
                // so the test exercises the real ordering rather than a shell.
                let paths = command.split('\'').skip(1).step_by(2).collect::<Vec<_>>();
                if command.starts_with("mkdir -p -- ") {
                    let folder = self.at(sandbox, paths.first().copied().unwrap_or_default())?;
                    return Ok(if std::fs::create_dir_all(folder).is_ok() { 0 } else { 1 });
                }
                if command.starts_with("rm -rf -- ") {
                    let folder = self.at(sandbox, paths.first().copied().unwrap_or_default())?;
                    let _ = std::fs::remove_dir_all(folder);
                    return Ok(0);
                }
                // The swap names three folders, each more than once: the volume, the one the old
                // contents are moved aside to, and the one the new contents come from, in that
                // order of first mention.
                let mut distinct: Vec<&str> = Vec::new();
                for path in paths {
                    if !distinct.contains(&path) {
                        distinct.push(path);
                    }
                }
                let [path, aside, from] = distinct.as_slice() else { return Ok(1) };
                let (path, aside, from) = (*path, *aside, *from);
                let (path, aside, from) = (self.at(sandbox, path)?, self.at(sandbox, aside)?, self.at(sandbox, from)?);
                if !path.is_dir() {
                    return Ok(1);
                }
                let _ = std::fs::remove_dir_all(&aside);
                std::fs::rename(&path, &aside).map_err(|error| error.to_string())?;
                std::fs::create_dir_all(&path).map_err(|error| error.to_string())?;
                copy_tree(&from, &path)?;
                let _ = std::fs::remove_dir_all(&aside);
                Ok(0)
            })
        }
    }

    #[derive(Default)]
    pub(crate) struct FakeSetups {
        /// `<setup>/<resource>` to the runtime id, when the sandbox exists.
        pub sandboxes: BTreeMap<String, String>,
        /// `<setup>/<volume>` to the resources that mount it.
        pub mounts: BTreeMap<String, Vec<String>>,
    }

    impl Setups for FakeSetups {
        fn sandbox(&self, setup: &str, resource: &str) -> Option<String> {
            self.sandboxes.get(&format!("{setup}/{resource}")).cloned()
        }
        fn mounting(&self, setup: &str, volume: &str) -> Vec<String> {
            self.mounts.get(&format!("{setup}/{volume}")).cloned().unwrap_or_default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setups::schedules::tests::schedule as a_schedule;
    use std::collections::BTreeMap;

    struct World {
        _temp: tempfile::TempDir,
        backups: Arc<Backups>,
        sandboxes: Arc<fake::FakeSandboxes>,
        /// Where the `app` sandbox keeps its files on this computer.
        app_root: PathBuf,
        through_root: PathBuf,
    }

    /// A setup with a `data` volume mounted at /data by two sandboxes: `app`, which writes to
    /// it, and `backup`, which the backup is read through.
    fn world() -> World {
        let temp = tempfile::tempdir().unwrap();
        let app_root = temp.path().join("sandbox-app");
        let through_root = temp.path().join("sandbox-backup");
        for root in [&app_root, &through_root] {
            std::fs::create_dir_all(root.join("data")).unwrap();
            std::fs::create_dir_all(root.join("tmp")).unwrap();
        }
        let sandboxes = Arc::new(fake::FakeSandboxes::new());
        {
            let mut state = sandboxes.state.lock().unwrap();
            state.roots.insert("env-app".into(), app_root.clone());
            // The two sandboxes share the volume, so what one writes the other reads.
            state.roots.insert("env-backup".into(), app_root.clone());
            state.running.insert("env-app".into(), true);
            state.running.insert("env-backup".into(), true);
        }
        let setups = Arc::new(fake::FakeSetups {
            sandboxes: BTreeMap::from([("setup-1/app".to_owned(), "env-app".to_owned()), ("setup-1/backup".to_owned(), "env-backup".to_owned())]),
            mounts: BTreeMap::from([("setup-1/data".to_owned(), vec!["app".to_owned(), "backup".to_owned()])]),
        });
        let backups = Backups::new(setups, sandboxes.clone(), temp.path().join("backups"));
        World { _temp: temp, backups, sandboxes, app_root, through_root }
    }

    fn write(root: &Path, path: &str, text: &str) {
        let at = root.join(path);
        std::fs::create_dir_all(at.parent().unwrap()).unwrap();
        std::fs::write(at, text).unwrap();
    }

    fn read(root: &Path, path: &str) -> Option<String> {
        std::fs::read_to_string(root.join(path)).ok()
    }

    #[tokio::test]
    async fn a_backup_is_checksummed_and_its_sandboxes_are_stopped_while_it_is_copied() {
        let world = world();
        write(&world.app_root, "data/notes.txt", "first");
        write(&world.app_root, "data/inner/more.txt", "second");
        let schedule = a_schedule("setup-1/data", "daily 02:00", 0);
        let (id, backup) = world.backups.back_up(&schedule, &CancellationToken::new()).await.expect("the backup is made");
        assert_eq!(backup.files, 2);
        assert_eq!(backup.bytes, "first".len() as u64 + "second".len() as u64);
        assert_eq!(backup.consistency, BackupConsistency::Stop);
        // The writing sandbox stopped and started again; the one it was read through did not.
        let starts = world.sandboxes.state.lock().unwrap().starts.clone();
        assert_eq!(starts, vec![("env-app".to_owned(), false), ("env-app".to_owned(), true)]);
        // The files and the manifest are in the engine's own folder, under this backup's id.
        let files = world.backups.location("setup-1", "data", &id);
        assert!(files.starts_with(world._temp.path().join("backups")), "{}", files.display());
        assert_eq!(read(&files, "notes.txt").as_deref(), Some("first"));
        assert_eq!(read(&files, "inner/more.txt").as_deref(), Some("second"));
        let checked = world.backups.verify("setup-1", "data", &id).await.expect("it checks out");
        assert_eq!(checked["checksum"], backup.checksum);
        assert!(checked["note"].as_str().unwrap_or_default().contains("credential store"), "the record says what it cannot carry");
        // The same files give the same checksum; a change gives another.
        let (second_id, second) = world.backups.back_up(&schedule, &CancellationToken::new()).await.unwrap();
        assert_eq!(second.checksum, backup.checksum);
        write(&world.app_root, "data/notes.txt", "changed");
        let (_, third) = world.backups.back_up(&schedule, &CancellationToken::new()).await.unwrap();
        assert_ne!(third.checksum, backup.checksum);
        assert_ne!(second_id, id);
    }

    #[tokio::test]
    async fn a_live_backup_leaves_everything_running_and_says_so() {
        let world = world();
        write(&world.app_root, "data/notes.txt", "first");
        let mut schedule = a_schedule("setup-1/data", "daily 02:00", 0);
        schedule.consistency = BackupConsistency::Live;
        let (_, backup) = world.backups.back_up(&schedule, &CancellationToken::new()).await.unwrap();
        assert!(world.sandboxes.state.lock().unwrap().starts.is_empty(), "nothing was stopped");
        assert_eq!(backup.consistency, BackupConsistency::Live);
        assert!(backup.describe().contains("half-written"), "{}", backup.describe());
        let review = world.backups.restore_review(&schedule, &backup, Target::Copy);
        assert!(review.iter().any(|line| line.contains("half-written")), "{review:?}");
    }

    #[tokio::test]
    async fn a_backup_that_fails_leaves_nothing_behind_and_starts_its_sandboxes_again() {
        let world = world();
        write(&world.app_root, "data/notes.txt", "first");
        let schedule = a_schedule("setup-1/data", "daily 02:00", 0);
        world.sandboxes.state.lock().unwrap().fail_copy_out = true;
        let error = world.backups.back_up(&schedule, &CancellationToken::new()).await.unwrap_err();
        assert!(error.contains("could not be copied out"), "{error}");
        let starts = world.sandboxes.state.lock().unwrap().starts.clone();
        assert_eq!(starts.last(), Some(&("env-app".to_owned(), true)), "the sandbox is running again");
        let folder = world._temp.path().join("backups/setup-1/data");
        let left = std::fs::read_dir(&folder).map(|entries| entries.count()).unwrap_or(0);
        assert_eq!(left, 0, "no half-made backup is kept");
        // A sandbox that will not stop means no backup is taken at all.
        world.sandboxes.state.lock().unwrap().fail_stop = true;
        let error = world.backups.back_up(&schedule, &CancellationToken::new()).await.unwrap_err();
        assert!(error.contains("no backup was taken"), "{error}");
    }

    #[tokio::test]
    async fn the_restore_drill_puts_back_exactly_what_was_there() {
        let world = world();
        write(&world.app_root, "data/notes.txt", "before");
        write(&world.app_root, "data/inner/more.txt", "also before");
        let schedule = a_schedule("setup-1/data", "daily 02:00", 0);
        let (id, backup) = world.backups.back_up(&schedule, &CancellationToken::new()).await.unwrap();

        // Everything changes: one file edited, one deleted, one added.
        write(&world.app_root, "data/notes.txt", "after");
        std::fs::remove_file(world.app_root.join("data/inner/more.txt")).unwrap();
        write(&world.app_root, "data/new.txt", "added later");

        // Into a disposable copy first: the volume is untouched.
        let copy = world.backups.restore(&schedule, &backup, Target::Copy).await.expect("the copy is made");
        assert_eq!(copy["restoredTo"], "copy");
        assert_eq!(read(&world.app_root, "data/notes.txt").as_deref(), Some("after"), "the volume is unchanged");
        let landed = copy["folder"].as_str().unwrap().trim_start_matches('/');
        assert_eq!(read(&world.through_root.parent().unwrap().join("sandbox-app"), &format!("{landed}/notes.txt")).as_deref(), Some("before"));

        // Then into the original, after the review.
        let review = world.backups.restore_review(&schedule, &backup, Target::Original);
        assert!(review.iter().any(|line| line.contains("cannot be undone")), "{review:?}");
        let done = world.backups.restore(&schedule, &backup, Target::Original).await.expect("it is put back");
        assert_eq!(done["restoredTo"], "original");
        assert_eq!(read(&world.app_root, "data/notes.txt").as_deref(), Some("before"), "the edited file is back as it was");
        assert_eq!(read(&world.app_root, "data/inner/more.txt").as_deref(), Some("also before"), "the deleted file is back");
        assert_eq!(read(&world.app_root, "data/new.txt"), None, "what was added after the backup is gone");

        // Backing up again gives the same checksum as the backup that was restored.
        let (_, again) = world.backups.back_up(&schedule, &CancellationToken::new()).await.unwrap();
        assert_eq!(again.checksum, backup.checksum, "the volume holds exactly what the backup held");
        assert!(world.backups.verify("setup-1", "data", &id).await.is_ok());
    }

    #[tokio::test]
    async fn a_backup_whose_files_changed_is_never_restored() {
        let world = world();
        write(&world.app_root, "data/notes.txt", "before");
        let schedule = a_schedule("setup-1/data", "daily 02:00", 0);
        let (id, backup) = world.backups.back_up(&schedule, &CancellationToken::new()).await.unwrap();
        // Something outside Yougori edits a kept backup.
        write(&world.backups.location("setup-1", "data", &id), "notes.txt", "tampered");
        let error = world.backups.verify("setup-1", "data", &id).await.unwrap_err();
        assert!(error.contains("have changed since it was made"), "{error}");
        let refused = world.backups.restore(&schedule, &backup, Target::Original).await.unwrap_err();
        assert!(refused.contains("have changed since it was made"), "{refused}");
        assert_eq!(read(&world.app_root, "data/notes.txt").as_deref(), Some("before"), "nothing was replaced");
        // A backup whose record is gone is refused too, rather than restored from the files.
        std::fs::remove_file(world.backups.location("setup-1", "data", &id).parent().unwrap().join(MANIFEST)).unwrap();
        assert!(world.backups.verify("setup-1", "data", &id).await.unwrap_err().contains("record is missing"));
    }

    #[tokio::test]
    async fn only_the_newest_backups_are_kept() {
        let world = world();
        write(&world.app_root, "data/notes.txt", "one");
        let schedule = a_schedule("setup-1/data", "daily 02:00", 0);
        let mut kept = Vec::new();
        for round in 0..4 {
            write(&world.app_root, "data/notes.txt", &format!("round {round}"));
            let (_, backup) = world.backups.back_up(&schedule, &CancellationToken::new()).await.unwrap();
            kept.push(backup);
        }
        let gone = world.backups.prune("setup-1", "data", &kept, 3).await;
        assert_eq!(gone, vec![kept[0].id.clone()], "the oldest goes first");
        assert!(world.backups.verify("setup-1", "data", &kept[0].id).await.is_err(), "it is really deleted");
        for backup in &kept[1..] {
            assert!(world.backups.verify("setup-1", "data", &backup.id).await.is_ok());
        }
        // Keeping fewer deletes more; keeping zero still keeps one, so a schedule never leaves
        // the person with nothing.
        let gone = world.backups.prune("setup-1", "data", &kept[1..], 0).await;
        assert_eq!(gone.len(), 2);
        assert!(world.backups.verify("setup-1", "data", &kept[3].id).await.is_ok());
    }

    /// PROVES that deleting a volume's backups takes that volume's and nothing else: not another
    /// volume of the same setup, not another setup's. It is only ever called for a volume the
    /// person ticked on a removal they reviewed.
    #[tokio::test]
    async fn forgetting_a_volume_deletes_its_backups_and_nothing_else() {
        let world = world();
        write(&world.app_root, "data/notes.txt", "first");
        let schedule = a_schedule("setup-1/data", "daily 02:00", 0);
        let (id, _) = world.backups.back_up(&schedule, &CancellationToken::new()).await.unwrap();
        let root = world._temp.path().join("backups");
        for (setup, volume) in [("setup-1", "cache"), ("setup-2", "data")] {
            std::fs::create_dir_all(root.join(setup).join(volume).join("backup-x").join(FILES)).unwrap();
        }
        world.backups.forget_volume("setup-1", "data").await.expect("deleted");
        assert!(world.backups.verify("setup-1", "data", &id).await.is_err(), "the backup is really gone");
        assert!(!root.join("setup-1").join("data").exists());
        assert!(root.join("setup-1").join("cache").join("backup-x").exists(), "another volume of the same setup keeps its backups");
        assert!(root.join("setup-2").join("data").join("backup-x").exists(), "another setup keeps its backups");
        // Already gone is not an error, so a retry after a partial failure finishes the job.
        world.backups.forget_volume("setup-1", "data").await.expect("nothing left to delete is fine");
        // A name that could reach outside its own folder is refused, and nothing is deleted.
        for (setup, volume) in [("..", "data"), ("setup-1", ".."), ("setup-1", "a/b"), ("", "data"), ("setup-1", "c:")] {
            assert!(world.backups.forget_volume(setup, volume).await.is_err(), "{setup}/{volume}");
        }
        assert!(root.join("setup-1").join("cache").join("backup-x").exists());
        assert!(root.join("setup-2").join("data").join("backup-x").exists());
    }

    /// PROVES that a copy finishing after its schedule was dropped (the setup was removed while it
    /// ran) is not left in the data folder where nobody sees it, and where it would outlive a
    /// deletion the person asked for.
    #[tokio::test]
    async fn a_copy_whose_schedule_went_while_it_ran_is_not_kept() {
        use crate::setups::schedules::{tests::Memory, Runner};
        let world = world();
        write(&world.app_root, "data/notes.txt", "first");
        let schedule = a_schedule("setup-1/data", "daily 02:00", 0);
        // The registry no longer has the schedule: the removal dropped it while this ran.
        let work = Work::new(Arc::new(Memory::default()), world.backups.clone());
        let said = work.run(&schedule, &CancellationToken::new()).await.expect("not an error, so it is not retried");
        assert!(said.contains("no longer backed up"), "{said}");
        let folder = world._temp.path().join("backups").join("setup-1").join("data");
        let left = std::fs::read_dir(&folder).map(|entries| entries.count()).unwrap_or(0);
        assert_eq!(left, 0, "no copy is left behind");
        // With the schedule still there, the copy is kept and recorded as before.
        let records = Arc::new(Memory { saved: std::sync::Mutex::new(vec![schedule.clone()]) });
        let work = Work::new(records.clone(), world.backups.clone());
        work.run(&schedule, &CancellationToken::new()).await.expect("backed up");
        let recorded = records.saved.lock().unwrap()[0].backups.clone();
        assert_eq!(recorded.len(), 1);
        assert!(world.backups.verify("setup-1", "data", &recorded[0].id).await.is_ok());
    }

    #[test]
    fn only_safe_paths_inside_a_sandbox_are_read_or_written() {
        for good in ["/data", "/var/lib/postgresql/data", "/a"] {
            assert!(guest_path(good), "{good}");
        }
        for bad in ["data", "", "/data/../etc", "/data/./x", "C:\\data", "/data\0x", "/"] {
            assert!(!guest_path(bad), "{bad}");
        }
        assert_eq!(bytes(0), "0 bytes");
        assert_eq!(bytes(1536), "1.5 KB");
        assert_eq!(quoted("it's"), "'it'\"'\"'s'");
    }
}
