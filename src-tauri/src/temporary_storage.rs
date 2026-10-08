//! Crash-recoverable private transfer staging. OS locks protect live workers,
//! including workers that outlive a cancelled request. Unmarked data is kept.
use std::{fs::{self, File, OpenOptions}, io::{Read, Write}, path::{Path, PathBuf}};

const LEASE: &str = ".yougori-staging-v1";
const OWNER: &[u8] = b"yougori-private-transfer-v1";

pub(crate) struct Staging {
    directory: Option<tempfile::TempDir>,
    lease: Option<File>,
}

fn plain(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() { return false; }
    #[cfg(windows)] {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 { return false; }
    }
    true
}

fn root_lock(root: &Path) -> Result<File, String> {
    let path = root.with_extension("staging-lock");
    if let Ok(meta) = fs::symlink_metadata(&path) {
        if !plain(&meta) || !meta.is_file() { return Err("Temporary storage lock was redirected".into()); }
    }
    OpenOptions::new().create(true).truncate(false).read(true).write(true).open(path).map_err(|e| e.to_string())
}

impl Staging {
    pub(crate) fn new(root: &Path) -> Result<Self, String> {
        fs::create_dir_all(root).map_err(|e| e.to_string())?;
        if !plain(&fs::symlink_metadata(root).map_err(|e| e.to_string())?) { return Err("Temporary storage was redirected".into()); }
        let root = root.canonicalize().map_err(|e| e.to_string())?;
        let gate = root_lock(&root)?;
        gate.lock().map_err(|e| e.to_string())?;
        let directory = tempfile::Builder::new().prefix("copy-").tempdir_in(root).map_err(|e| e.to_string())?;
        let mut lease = OpenOptions::new().create_new(true).read(true).write(true).open(directory.path().join(LEASE)).map_err(|e| e.to_string())?;
        lease.lock().map_err(|e| e.to_string())?;
        lease.write_all(OWNER).and_then(|_| lease.sync_all()).map_err(|e| e.to_string())?;
        Ok(Self { directory: Some(directory), lease: Some(lease) })
    }
    pub(crate) fn path(&self) -> &Path { self.directory.as_ref().unwrap().path() }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if let Some(directory) = self.directory.take() {
            let path = directory.keep();
            // The marker must be removed last. A locked payload may prevent
            // cleanup on Windows; keep ownership evidence for a later retry.
            let cleanup = remove_payload(&path);
            drop(self.lease.take());
            if cleanup.is_ok() {
                let _ = fs::remove_file(path.join(LEASE));
                let _ = fs::remove_dir(path);
            }
        }
        drop(self.lease.take());
    }
}

fn remove_payload(path: &Path) -> Result<(), String> {
    tree_size(path)?;
    for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_name() == LEASE { continue; }
        let result = if entry.file_type().map_err(|e| e.to_string())?.is_dir() { fs::remove_dir_all(entry.path()) } else { fs::remove_file(entry.path()) };
        result.map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn tree_size(path: &Path) -> Result<u64, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !plain(&meta) { return Err("Temporary tree contains a redirected path; kept for inspection".into()); }
    if meta.is_file() { return Ok(meta.len()); }
    if !meta.is_dir() { return Err("Temporary tree contains a special file".into()); }
    fs::read_dir(path).map_err(|e| e.to_string())?.try_fold(0u64, |bytes, entry| {
        Ok(bytes.saturating_add(tree_size(&entry.map_err(|e| e.to_string())?.path())?))
    })
}

pub(crate) fn sweep(root: &Path) -> Result<u64, String> {
    let meta = match fs::symlink_metadata(root) { Ok(meta) => meta, Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0), Err(e) => return Err(e.to_string()) };
    if !meta.is_dir() || !plain(&meta) { return Err("Temporary storage is not an owned directory".into()); }
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let gate = root_lock(&root)?;
    if gate.try_lock().is_err() { return Ok(0); }
    let mut bytes = 0u64;
    for entry in fs::read_dir(&root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if !entry.file_name().to_string_lossy().starts_with("copy-") || !meta.is_dir() || !plain(&meta) { continue; }
        if path.canonicalize().map_err(|e| e.to_string())?.parent() != Some(root.as_path()) { continue; }
        let marker = path.join(LEASE);
        if !fs::symlink_metadata(&marker).is_ok_and(|m| plain(&m) && m.is_file() && m.len() == OWNER.len() as u64) { continue; }
        let mut lease = OpenOptions::new().read(true).write(true).open(&marker).map_err(|e| e.to_string())?;
        if lease.try_lock().is_err() { continue; }
        let mut owner = Vec::new();
        lease.read_to_end(&mut owner).map_err(|e| e.to_string())?;
        if owner != OWNER { continue; }
        let size = tree_size(&path)?;
        remove_payload(&path)?;
        drop(lease);
        fs::remove_file(marker).map_err(|e| e.to_string())?;
        fs::remove_dir(&path).map_err(|e| e.to_string())?;
        bytes = bytes.saturating_add(size);
    }
    Ok(bytes)
}

impl crate::runtime::RuntimeManager {
    pub(crate) fn clean_temporary_storage(&self) -> crate::models::StorageCleanupResult {
        let mut result = crate::models::StorageCleanupResult::default();
        // Verify secondary-drive identities before inspecting any owned paths.
        let mut roots = vec![self.storage_root().to_path_buf()];
        for engine in self.registered_storage_runtimes() {
            match engine { Ok(engine) => roots.push(engine.storage_root().to_path_buf()), Err(error) => result.warnings.push(error) }
        }
        for root in roots {
            let mut folders: Vec<PathBuf> = ["file-imports", "cross-environment-transfers"].into_iter().map(|p| root.join(p)).collect();
            let cloud = root.join("cloud-imports");
            if fs::symlink_metadata(&cloud).is_ok_and(|m| m.is_dir() && plain(&m)) {
                if let Ok(entries) = fs::read_dir(cloud) {
                    folders.extend(entries.flatten().filter(|e| e.file_name().to_string_lossy().starts_with("env-") && e.file_type().is_ok_and(|kind| kind.is_dir())).map(|e| e.path()));
                }
            }
            for folder in folders {
                match sweep(&folder) { Ok(bytes) => result.reclaimed_cache_bytes = result.reclaimed_cache_bytes.saturating_add(bytes), Err(error) => result.warnings.push(format!("Temporary transfer cleanup: {error}")) }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repeated_cloud_cleanup_ignores_its_own_lock_file() {
        let root = tempfile::tempdir().unwrap();
        let runtime = crate::runtime::RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), root.path()).unwrap();
        let stage = Staging::new(&runtime.storage_root().join("cloud-imports/env-test")).unwrap();
        for _ in 0..2 {
            let result = runtime.clean_temporary_storage();
            assert!(result.warnings.is_empty(), "{:?}", result.warnings);
            assert!(stage.path().exists());
        }
    }
    #[cfg(windows)]
    #[test]
    fn locked_payload_keeps_ownership_evidence_for_a_later_retry() {
        use std::os::windows::fs::OpenOptionsExt;
        let root = tempfile::tempdir().unwrap();
        let stage = Staging::new(root.path()).unwrap();
        let path = stage.path().to_owned();
        fs::write(path.join("archive"), vec![1; 1024]).unwrap();
        let held = OpenOptions::new().read(true).share_mode(0).open(path.join("archive")).unwrap();
        drop(stage);
        assert!(path.join(LEASE).exists());
        assert!(sweep(root.path()).is_err());
        assert!(path.join(LEASE).exists());
        drop(held);
        assert!(sweep(root.path()).unwrap() >= 1024);
        assert!(!path.exists());
    }
    #[test]
    fn abandoned_transfers_are_reclaimed_but_live_and_unmarked_data_survive() {
        let root = tempfile::tempdir().unwrap();
        let live = Staging::new(root.path()).unwrap();
        fs::write(live.path().join("archive"), b"active transfer").unwrap();
        let mut abandoned = Staging::new(root.path()).unwrap();
        fs::write(abandoned.path().join("archive"), vec![3; 4096]).unwrap();
        let dead = abandoned.directory.take().unwrap().keep();
        drop(abandoned); // emulate process death: OS lease released, files left
        let unmarked = root.path().join("copy-personal");
        fs::create_dir(&unmarked).unwrap();
        fs::write(unmarked.join("data"), b"keep").unwrap();
        assert_eq!(sweep(root.path()).unwrap(), 4096 + OWNER.len() as u64);
        assert!(!dead.exists());
        assert_eq!(fs::read(live.path().join("archive")).unwrap(), b"active transfer");
        assert_eq!(fs::read(unmarked.join("data")).unwrap(), b"keep");
        assert_eq!(sweep(root.path()).unwrap(), 0);
    }
    #[test]
    fn redirected_trees_are_not_followed() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("keep"), b"personal data").unwrap();
        let mut stage = Staging::new(root.path()).unwrap();
        let dead = stage.directory.take().unwrap().keep();
        drop(stage);
        #[cfg(unix)] std::os::unix::fs::symlink(outside.path(), dead.join("external")).unwrap();
        #[cfg(windows)] {
            if std::os::windows::fs::symlink_dir(outside.path(), dead.join("external")).is_err() { return; }
        }
        assert!(sweep(root.path()).is_err());
        assert_eq!(fs::read(outside.path().join("keep")).unwrap(), b"personal data");
        assert!(dead.exists());
    }
}
