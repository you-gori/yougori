//! The old launcher's leftover per-environment settings under ~/.yougori/launch. The launcher is
//! gone; what remains is forgetting these with the environment they belonged to, which the engine
//! does through `forget_environment`. The file keeps its name because the engine calls it by it.
use serde_json::Value;
use std::{fs, io, path::{Path, PathBuf}};

pub fn directory() -> Result<PathBuf, String> {
    std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))
        .map(|home| PathBuf::from(home).join(".yougori").join("launch"))
        .ok_or_else(|| "Cannot find your user profile".into())
}

/// Keep the lock inode: an older launcher still running may hold it during deletion.
pub fn clear(path: &Path) -> Result<(), String> {
    for file in [path.with_extension("sync.json"), path.to_path_buf()] {
        match fs::remove_file(&file) {
            Ok(()) => {},
            Err(e) if e.kind() == io::ErrorKind::NotFound => {},
            Err(e) => return Err(format!("Cannot remove launcher settings {}: {e}", file.display())),
        }
    }
    Ok(())
}

pub fn forget_environment(id: &str) -> Result<(), String> {
    forget_in(&directory()?, id)
}

fn forget_in(folder: &Path, id: &str) -> Result<(), String> {
    let entries = match fs::read_dir(folder) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("Cannot read launcher settings: {e}")),
    };
    let mut errors = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let key = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if path.extension().and_then(|s| s.to_str()) != Some("json")
            || key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit())
            || !entry.file_type().map_err(|e| e.to_string())?.is_file() {
            continue;
        }
        let data = match fs::read(&path) {
            Ok(data) => data,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => { errors.push(format!("Cannot read {}: {e}", path.display())); continue; },
        };
        let Ok(saved) = serde_json::from_slice::<Value>(&data) else { continue };
        if saved["version"] == 1 && saved["environment"].as_str() == Some(id) {
            if let Err(error) = clear(&path) { errors.push(error); }
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn deletion_removes_only_bound_settings_and_sync_but_keeps_lock_and_project() {
        let folder = tempfile::tempdir().unwrap();
        let target = folder.path().join(format!("{}.json", "a".repeat(64)));
        let other = folder.path().join(format!("{}.json", "b".repeat(64)));
        for (path, id) in [(&target, "deleted"), (&other, "survives")] {
            fs::write(path, json!({"version":1,"environment":id,"directory":"never-follow-this-path"}).to_string()).unwrap();
            fs::write(path.with_extension("sync.json"), "sync").unwrap();
            fs::write(path.with_extension("lock"), "lock").unwrap();
        }
        let unrelated = folder.path().join("project.json");
        fs::write(&unrelated, json!({"version":1,"environment":"deleted"}).to_string()).unwrap();
        forget_in(folder.path(), "deleted").unwrap();
        assert!(!target.exists());
        assert!(!target.with_extension("sync.json").exists());
        assert!(target.with_extension("lock").exists());
        assert!(other.exists());
        assert!(other.with_extension("sync.json").exists());
        assert!(unrelated.exists());
        forget_in(folder.path(), "deleted").unwrap();
    }
}
