//! Baseline comparison of explicitly shared PC folders. Never scans the rest of the PC.
use crate::{
    models::*, runtime::RuntimeManager, store::PlatformStore, workspace::WorkspaceManager,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{Duration, Instant},
};
use tauri::Manager;
use crate::AppHandle;
static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
const MAX_FILES: usize = 100_000;
const MAX_TEXT: usize = 256 * 1024;
const MAX_TOTAL_TEXT: usize = 32 * 1024 * 1024;
const MAX_HASH_BYTES: u64 = 2 * 1024 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
struct File {
    hash: String,
    bytes: u64,
    #[serde(default)]
    text: Option<String>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
struct Baseline {
    at: String,
    folders: BTreeMap<String, BTreeMap<String, File>>,
    #[serde(default)]
    config: Value,
    #[serde(default)]
    variables: BTreeMap<String, String>,
    #[serde(default)]
    packages: BTreeMap<String, String>,
    #[serde(default)]
    guest_captured: bool,
}
fn path(runtime: &RuntimeManager, id: &str) -> Result<PathBuf, String> {
    if !id.starts_with("env-") || !id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
        return Err("Invalid environment ID".into());
    }
    Ok(runtime
        .environment_storage_root(id)?
        .join("changes")
        .join(format!("{id}.json")))
}
/// The environment's baseline file, resolved before deletion removes its storage route.
pub(crate) fn baseline_path(runtime: &RuntimeManager, id: &str) -> Result<PathBuf, String> {
    path(runtime, id)
}

/// Baselines hold copies of shared-folder text, so none may outlive its environment.
/// Files written in the last ten minutes are left for an environment still being created.
/// Returns the bytes freed and any files that could not be removed.
pub(crate) fn remove_orphans(runtime: &RuntimeManager, live: &BTreeSet<String>) -> (u64, Vec<String>) {
    let (mut freed, mut warnings) = (0, Vec::new());
    for root in runtime.storage_pool_roots() {
        let Ok(entries) = std::fs::read_dir(root.join("changes")) else { continue };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(id) = name.strip_suffix(".json").filter(|id| id.starts_with("env-")) else { continue };
            let Ok(metadata) = entry.metadata() else { continue };
            let fresh = metadata.modified().ok().and_then(|at| at.elapsed().ok()).is_none_or(|age| age < Duration::from_secs(600));
            if live.contains(id) || !metadata.is_file() || fresh { continue; }
            match std::fs::remove_file(entry.path()) {
                Ok(()) => freed += metadata.len(),
                Err(error) => warnings.push(format!("Remove the change baseline of deleted {id}: {error}")),
            }
        }
    }
    (freed, warnings)
}

/// The largest baseline kept: saving refuses what loading would refuse.
const MAX_BASELINE_BYTES: usize = 96 * 1024 * 1024;

/// Baselines key folders by their canonical path, as ensure_folder_baseline records them, so a
/// folder given as a relative path or in another spelling finds its baseline.
fn folder_keys(folders: BTreeSet<String>) -> BTreeSet<String> {
    folders
        .into_iter()
        .map(|folder| std::fs::canonicalize(&folder).map(|path| path.to_string_lossy().into_owned()).unwrap_or(folder))
        .collect()
}

fn load(path: &Path) -> Result<Option<Baseline>, String> {
    if !path.try_exists().map_err(|e| e.to_string())? {
        return Ok(None);
    }
    if std::fs::metadata(path).map_err(|e| e.to_string())?.len() > MAX_BASELINE_BYTES as u64 {
        return Err("Change baseline is too large. Start a new baseline after disconnecting a large My PC folder.".into());
    }
    serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?)
        .map(Some)
        .map_err(|e| e.to_string())
}
fn save(path: &Path, b: &Baseline) -> Result<(), String> {
    save_within(path, b, MAX_BASELINE_BYTES)
}
fn save_within(path: &Path, b: &Baseline, limit: usize) -> Result<(), String> {
    let root = path.parent().ok_or("Invalid baseline path")?;
    std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec(b).map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("This change baseline would be larger than 96 MB. Disconnect a large My PC folder, then start a new baseline.".into());
    }
    let mut file = tempfile::NamedTempFile::new_in(root).map_err(|e| e.to_string())?;
    std::io::Write::write_all(&mut file, &bytes).map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist(path).map_err(|e| e.to_string())?;
    Ok(())
}
fn scan(root: &Path) -> Result<BTreeMap<String, File>, String> {
    let root = cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority())
        .map_err(|e| e.to_string())?;
    let started = Instant::now();
    let mut files = BTreeMap::new();
    let mut stack = vec![PathBuf::from(".")];
    let mut visited = 0usize;
    let mut total = 0u64;
    let mut text_bytes = 0;
    while let Some(dir) = stack.pop() {
        for entry in root
            .read_dir(&dir)
            .map_err(|e| format!("Cannot inspect shared folder: {e}"))?
        {
            let entry = entry.map_err(|e| e.to_string())?;
            let relative = dir.join(entry.file_name());
            let m = root
                .symlink_metadata(&relative)
                .map_err(|e| e.to_string())?;
            visited += 1;
            if m.file_type().is_symlink() {
                continue;
            }
            if started.elapsed() > Duration::from_secs(45) || visited >= MAX_FILES {
                return Err("This folder exceeds the bounded Changes scan. Share a smaller project folder to get a complete comparison.".into());
            }
            if m.is_dir() {
                stack.push(relative);
                continue;
            }
            if !m.is_file() {
                continue;
            }
            let resolved = relative;
            total = total.checked_add(m.len()).ok_or("Folder too large")?;
            if total > MAX_HASH_BYTES {
                return Err(
                    "Changes scan exceeds 2 GiB of file contents; select a smaller shared folder"
                        .into(),
                );
            }
            let mut file = root.open(&resolved).map_err(|e| e.to_string())?;
            let before = file.metadata().map_err(|e| e.to_string())?;
            if !before.is_file() {
                return Err("File type changed during scan".into());
            }
            let mut h = Sha256::new();
            let mut buffer = [0u8; 65536];
            let mut text = Vec::new();
            let keep =
                m.len() <= MAX_TEXT as u64 && text_bytes + m.len() as usize <= MAX_TOTAL_TEXT;
            let mut length = 0;
            loop {
                let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                length += n as u64;
                if length > m.len() || started.elapsed() > Duration::from_secs(45) {
                    return Err(
                        "Files changed during the scan or the scan took too long; refresh to retry"
                            .into(),
                    );
                }
                h.update(&buffer[..n]);
                if keep {
                    text.extend_from_slice(&buffer[..n]);
                }
            }
            let after = file.metadata().map_err(|e| e.to_string())?;
            if length != before.len() || before.modified().ok() != after.modified().ok() {
                return Err("A file changed while scanning; refresh to retry".into());
            }
            let text = if keep && !text.contains(&0) {
                String::from_utf8(text).ok()
            } else {
                None
            };
            text_bytes += text.as_ref().map_or(0, String::len);
            files.insert(
                resolved
                    .strip_prefix(".")
                    .unwrap_or(&resolved)
                    .to_string_lossy()
                    .replace('\\', "/"),
                File {
                    hash: format!("{:x}", h.finalize()),
                    bytes: length,
                    text,
                },
            );
        }
    }
    Ok(files)
}
pub async fn ensure_folder_baseline(
    runtime: &RuntimeManager,
    id: &str,
    folder: &Path,
) -> Result<(), String> {
    let _guard = LOCK.get_or_init(Default::default).lock().await;
    let location = path(runtime, id)?;
    let mut b = load(&location)?.unwrap_or_else(|| Baseline {
        at: chrono::Utc::now().to_rfc3339(),
        ..Default::default()
    });
    let folder = folder.canonicalize().map_err(|e| e.to_string())?;
    let key = folder.to_string_lossy().into_owned();
    if b.folders.contains_key(&key) {
        return Ok(());
    }
    let files = tokio::task::spawn_blocking(move || scan(&folder))
        .await
        .map_err(|e| e.to_string())??;
    b.folders.insert(key, files);
    save(&location, &b)
}
fn difference(
    old: &BTreeMap<String, File>,
    new: &BTreeMap<String, File>,
    folder: &str,
) -> Vec<Value> {
    let mut rows = Vec::new();
    let mut deleted = old
        .keys()
        .filter(|p| !new.contains_key(*p))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut removed_by_hash: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for path in &deleted {
        removed_by_hash
            .entry(&old[path].hash)
            .or_default()
            .push(path);
    }
    let mut added_by_hash: BTreeMap<&str, usize> = BTreeMap::new();
    for (path, file) in new {
        if !old.contains_key(path) {
            *added_by_hash.entry(&file.hash).or_default() += 1;
        }
    }
    // Own paths so consuming the rename set never invalidates the lookup.
    let removed_by_hash: BTreeMap<String, Vec<String>> = removed_by_hash
        .into_iter()
        .map(|(h, paths)| (h.into(), paths.into_iter().map(str::to_owned).collect()))
        .collect();
    for (path, file) in new {
        match old.get(path) {
            Some(before) if before.hash == file.hash => {}
            Some(before) => rows.push(row(folder, path, "modified", Some(before), Some(file))),
            None => {
                let candidates = removed_by_hash
                    .get(&file.hash)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                if candidates.len() == 1 && added_by_hash.get(file.hash.as_str()) == Some(&1) {
                    let from = candidates[0].clone();
                    deleted.remove(&from);
                    let mut r = row(folder, path, "renamed", Some(&old[&from]), Some(file));
                    r["from"] = from.into();
                    rows.push(r)
                } else {
                    rows.push(row(folder, path, "created", None, Some(file)))
                }
            }
        }
    }
    for p in deleted {
        rows.push(row(folder, &p, "deleted", Some(&old[&p]), None))
    }
    rows
}
fn row(folder: &str, path: &str, kind: &str, old: Option<&File>, new: Option<&File>) -> Value {
    let old_text = old.map(|f| f.text.as_deref());
    let new_text = new.map(|f| f.text.as_deref());
    let text_available = old_text.flatten().is_some() || new_text.flatten().is_some();
    let diff = if text_available
        && old_text.is_none_or(|t| t.is_some())
        && new_text.is_none_or(|t| t.is_some())
    {
        let a = old_text.flatten().unwrap_or("");
        let b = new_text.flatten().unwrap_or("");
        if a.lines().count() > 4000 || b.lines().count() > 4000 {
            None
        } else {
            Some(
                similar::TextDiff::from_lines(a, b)
                    .unified_diff()
                    .context_radius(3)
                    .header(&format!("a/{path}"), &format!("b/{path}"))
                    .to_string(),
            )
        }
    } else {
        None
    };
    json!({"folder":folder,"path":path,"kind":kind,"beforeBytes":old.map(|f|f.bytes),"afterBytes":new.map(|f|f.bytes),"beforeHash":old.map(|f|f.hash.clone()),"afterHash":new.map(|f|f.hash.clone()),"diff":diff,"contentAvailable":text_available})
}
async fn guest(
    app: &AppHandle,
    id: &str,
) -> Result<(BTreeMap<String, String>, BTreeMap<String, String>), String> {
    let cmd="printf '__YOUGORI_ENV__\\n'; env -0; printf '\\n__YOUGORI_PACKAGES__\\n'; if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${Package}=${Version}\\n'; elif command -v apk >/dev/null 2>&1; then awk -F: '/^P:/{p=$2} /^V:/{print p \"=\" $2}' /lib/apk/db/installed; elif command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME}=%{VERSION}-%{RELEASE}\\n'; else printf '__UNAVAILABLE__\\n'; fi";
    let r = crate::automation::dispatch::dispatch(
        app,
        "execute_environment_command",
        &json!({"request":{"environmentId":id,"command":cmd}}),
    )
    .await?;
    if r["exitCode"] != 0 {
        return Err("Guest package/environment inventory unavailable".into());
    }
    let text = r["stdout"].as_str().ok_or("Invalid guest inventory")?;
    let (env, packages) = text
        .split_once("\n__YOUGORI_PACKAGES__\n")
        .ok_or("Incomplete guest inventory")?;
    let vars = env
        .strip_prefix("__YOUGORI_ENV__\n")
        .ok_or("Invalid guest inventory")?
        .split('\0')
        .filter_map(|s| s.split_once('='))
        .map(|(k, v)| (k.into(), format!("{:x}", Sha256::digest(v.as_bytes()))))
        .collect();
    if packages.lines().any(|s| s == "__UNAVAILABLE__") {
        return Err("Guest has no supported package manager; package and process-variable comparison is unavailable.".into());
    }
    let packages = packages
        .lines()
        .map(|s| {
            let (k, v) = s.split_once('=').unwrap_or((s, "installed"));
            (k.to_owned(), v.to_owned())
        })
        .collect();
    Ok((vars, packages))
}
fn map_changes(
    old: &BTreeMap<String, String>,
    new: &BTreeMap<String, String>,
    redact: bool,
) -> Vec<Value> {
    let keys = old.keys().chain(new.keys()).collect::<BTreeSet<_>>();
    keys.into_iter().filter(|k|old.get(*k)!=new.get(*k)).map(|k|json!({"name":k,"kind":if !old.contains_key(k){"created"}else if !new.contains_key(k){"deleted"}else{"modified"},"before":if redact{old.get(k).map(|_|"[redacted]")}else{old.get(k).map(String::as_str)},"after":if redact{new.get(k).map(|_|"[redacted]")}else{new.get(k).map(String::as_str)}})).collect()
}

#[tauri::command]
pub async fn environment_changes(
    environment_id: String,
    baseline: bool,
    offset: Option<usize>,
    app: AppHandle,
) -> Result<Value, String> {
    let runtime = app.state::<RuntimeManager>();
    let env = app
        .state::<PlatformStore>()
        .snapshot()?
        .environments
        .into_iter()
        .find(|e| e.id == environment_id)
        .ok_or("Environment not found")?;
    let mut folders = app
        .state::<WorkspaceManager>()
        .host_shares_for(&environment_id)
        .await
        .into_iter()
        .map(|s| s.path)
        .collect::<BTreeSet<_>>();
    for bind in runtime
        .workload_options(env.runtime_id.as_deref().unwrap_or(&env.id))?
        .binds
    {
        folders.insert(bind.source);
    }
    let folders = folder_keys(folders);
    let location = path(&runtime, &environment_id)?;
    let _guard = LOCK.get_or_init(Default::default).lock().await;
    // Starting a new baseline must work even when the old one can no longer be read.
    let existing = if baseline { load(&location).ok().flatten() } else { load(&location)? };
    if folders.is_empty() && existing.is_none() {
        return Ok(json!({"available":false,"notice":"Connect a My PC folder to track changes."}));
    }
    let previous = existing.unwrap_or_default();
    let mut next = Baseline {
        at: chrono::Utc::now().to_rfc3339(),
        ..Default::default()
    };
    let mut warnings = vec![];
    for folder in &folders {
        let path = PathBuf::from(folder);
        let files = tokio::task::spawn_blocking(move || scan(&path))
            .await
            .map_err(|e| e.to_string())??;
        next.folders.insert(folder.clone(), files);
    }
    // Disconnected folders are retained in the baseline but no longer read or labelled deleted.
    for folder in previous.folders.keys().filter(|p| !folders.contains(*p)) {
        warnings.push(format!(
            "{folder}: disconnected; changes are not currently scanned"
        ));
    }
    let mut policy = serde_json::to_value(&env.resource_policy).map_err(|e| e.to_string())?;
    policy["cpu"].as_object_mut().unwrap().remove("current");
    policy["memoryGb"]
        .as_object_mut()
        .unwrap()
        .remove("current");
    next.config = json!({"image":env.runtime,"kind":env.kind,"startup":env.container_command,"internet":env.network_access,"gpu":env.gpu_access,"resources":policy,"storageGb":env.storage_limit_gb,"storageDrive":env.storage_drive});
    if env.status == EnvironmentStatus::Running {
        match guest(&app, &env.id).await {
            Ok((v, p)) => {
                next.variables = v;
                next.packages = p;
                next.guest_captured = true
            }
            Err(e) => warnings.push(e),
        }
    } else {
        warnings.push("Start the environment to compare installed packages and process environment variables.".into())
    }
    let first = previous.at.is_empty();
    let guest_first = !previous.guest_captured && next.guest_captured;
    if baseline || first {
        save(&location, &next)?;
        return Ok(
            json!({"available":true,"baselineAt":next.at,"baselineCreated":true,"files":[],"variables":[],"packages":[],"configuration":[],"warnings":warnings}),
        );
    }
    let mut rows = Vec::new();
    for (folder, files) in &next.folders {
        if let Some(old) = previous.folders.get(folder) {
            rows.extend(difference(old, files, folder))
        } else {
            warnings.push(format!(
                "{folder}: no baseline exists; start a new baseline to include it"
            ))
        }
    }
    let variables = if previous.guest_captured && next.guest_captured {
        map_changes(&previous.variables, &next.variables, true)
    } else {
        vec![]
    };
    let packages = if previous.guest_captured && next.guest_captured {
        map_changes(&previous.packages, &next.packages, false)
    } else {
        vec![]
    };
    let configuration = next
        .config
        .as_object()
        .unwrap()
        .iter()
        .filter(|(k, v)| !previous.config.is_null() && previous.config.get(*k) != Some(*v))
        .map(|(k, v)| json!({"name":k,"before":previous.config[k],"after":v}))
        .collect::<Vec<_>>();
    if guest_first || previous.config.is_null() {
        let mut initialized = previous.clone();
        if guest_first {
            initialized.variables = next.variables;
            initialized.packages = next.packages;
            initialized.guest_captured = true
        }
        if initialized.config.is_null() {
            initialized.config = next.config
        }
        save(&location, &initialized)?;
        warnings.push("Guest/configuration baseline captured now; earlier guest changes cannot be reconstructed.".into())
    }
    let counts = |kind: &str| rows.iter().filter(|v| v["kind"] == kind).count();
    let summary = json!({"modified":counts("modified"),"created":counts("created"),"deleted":counts("deleted"),"renamed":counts("renamed"),"variables":variables.len(),"packagesInstalled":packages.iter().filter(|p|p["kind"]=="created").count(),"packagesChanged":packages.len(),"configuration":configuration.len()});
    let offset = offset.unwrap_or(0);
    let total = rows.len();
    let mut size = 0;
    let mut page = Vec::new();
    for mut row in rows.into_iter().skip(offset).take(200) {
        let bytes = row["diff"].as_str().map_or(0, str::len);
        if size + bytes > 2 * 1024 * 1024 {
            row["diff"] = Value::Null;
            row["diffOmitted"] = json!(true);
        } else {
            size += bytes;
        }
        page.push(row);
    }
    let next_offset = (offset + page.len() < total).then_some(offset + page.len());
    if page.iter().any(|r| r["diffOmitted"] == true) {
        warnings.push("Some text diffs exceed this page's 2 MiB display budget; file hashes and sizes remain available.".into());
    }
    Ok(
        json!({"available":true,"baselineAt":previous.at,"summary":summary,"totalFiles":total,"offset":offset,"nextOffset":next_offset,"files":page,"variables":variables,"packages":packages,"configuration":configuration,"warnings":warnings,"notice":"Compared with the baseline. Changes may come from this environment, you, or other applications. Symlinks/special files are not followed. Binary or large files show hashes and sizes; text diffs are bounded."}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn changes_reports_content_create_delete_and_unique_renames() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("old.txt"), "before\n").unwrap();
        std::fs::write(dir.path().join("move.txt"), "same\n").unwrap();
        std::fs::write(dir.path().join("gone"), "delete\n").unwrap();
        let old = scan(dir.path()).unwrap();
        std::fs::write(dir.path().join("old.txt"), "after\n").unwrap();
        std::fs::rename(dir.path().join("move.txt"), dir.path().join("moved.txt")).unwrap();
        std::fs::remove_file(dir.path().join("gone")).unwrap();
        std::fs::write(dir.path().join("new"), "created").unwrap();
        let rows = difference(&old, &scan(dir.path()).unwrap(), "project");
        for kind in ["created", "deleted", "modified", "renamed"] {
            assert_eq!(rows.iter().filter(|v| v["kind"] == kind).count(), 1)
        }
        assert!(
            rows.iter().find(|v| v["kind"] == "modified").unwrap()["diff"]
                .as_str()
                .unwrap()
                .contains("-before")
        );
    }
    #[test]
    fn variable_diff_never_exposes_values() {
        let a = BTreeMap::from([("TOKEN".into(), "old-secret".into())]);
        let b = BTreeMap::from([("TOKEN".into(), "new-secret".into())]);
        let diff = map_changes(&a, &b, true);
        assert!(!serde_json::to_string(&diff).unwrap().contains("secret"));
    }

    #[test]
    fn a_folder_finds_its_baseline_whatever_spelling_names_it() {
        let root = tempfile::tempdir().unwrap();
        let folder = root.path().join("data");
        std::fs::create_dir(&folder).unwrap();
        let canonical = folder.canonicalize().unwrap().to_string_lossy().into_owned();
        let spelled = root.path().join("data").join("..").join("data").to_string_lossy().into_owned();
        assert_eq!(folder_keys(BTreeSet::from([spelled])), BTreeSet::from([canonical]));
        let gone = root.path().join("gone").to_string_lossy().into_owned();
        assert_eq!(folder_keys(BTreeSet::from([gone.clone()])), BTreeSet::from([gone]), "a disconnected folder keeps its recorded name");
    }

    #[test]
    fn a_baseline_too_large_to_load_again_is_never_saved() {
        let root = tempfile::tempdir().unwrap();
        let location = root.path().join("env.json");
        let small = Baseline { at: "now".into(), ..Default::default() };
        save_within(&location, &small, 4096).unwrap();
        let mut large = small.clone();
        large.config = json!({"padding": "x".repeat(8192)});
        assert!(save_within(&location, &large, 4096).unwrap_err().contains("larger than"));
        assert_eq!(load(&location).unwrap().unwrap().at, "now", "the old baseline is kept");
    }

    #[test]
    fn baselines_of_deleted_environments_are_removed() {
        let data = tempfile::tempdir().unwrap();
        let runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), data.path()).unwrap();
        let changes = runtime.storage_root().join("changes");
        std::fs::create_dir_all(&changes).unwrap();
        let old = std::time::SystemTime::now() - Duration::from_secs(3600);
        for name in ["env-live.json", "env-gone.json", "env-new.json", "notes.txt"] {
            std::fs::write(changes.join(name), b"{}").unwrap();
            if name != "env-new.json" {
                std::fs::File::options().write(true).open(changes.join(name)).unwrap().set_modified(old).unwrap();
            }
        }
        let live = BTreeSet::from(["env-live".to_string()]);
        let (freed, warnings) = remove_orphans(&runtime, &live);
        assert_eq!((freed, warnings.len()), (2, 0));
        assert!(!changes.join("env-gone.json").exists(), "deleted environment's copy of folder text is gone");
        assert!(changes.join("env-live.json").exists() && changes.join("env-new.json").exists() && changes.join("notes.txt").exists());
        assert_eq!(baseline_path(&runtime, "env-live").unwrap(), changes.join("env-live.json"));
    }
}
