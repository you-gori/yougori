//! Copying files out of environments to this PC. Every source speaks the same read-only file API
//! (list/stat/read in 64 KiB chunks), so one walker serves containers, microVMs, cloud servers and
//! environments shared with you. Existing local files are never overwritten.
use crate::{models::*, runtime::RuntimeManager, store::PlatformStore};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cap_std::fs::{Dir, OpenOptions};
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use tauri::State;
use crate::file_import::{transfers, CopyProgress};
use std::{sync::Arc,time::{Duration, Instant}};
use tokio_util::sync::CancellationToken;

const MAX_ENTRIES: usize = 50_000;
const MAX_BYTES: u64 = 100 * 1024 * 1024 * 1024;

struct ExportControl {
    leases: Vec<transfers::Lease>,
    cancellation: CancellationToken,
    operation: Option<crate::automation::context::OperationContext>,
    started: Instant,
    inactivity: Duration,
    total_limit: Duration,
    temporary_staging: bool,
    cleanup_grace: Duration,
    staging: Option<Arc<crate::temporary_storage::Staging>>,
}

impl ExportControl {
    fn begin(source: &Source<'_>, target: Option<&str>) -> Result<Self, String> {
        let source_id = match source { Source::Shared(environment) | Source::Guest(_, environment) => Some(environment.id.as_str()), #[cfg(test)] Source::Fake(_) | Source::Stalled { .. } => None };
        let mut leases = Vec::new();
        for id in source_id.into_iter().chain(target) {
            let lease = transfers::begin(id)?;
            if target.is_some() { lease.transfer.use_host_staging_export(); } else { lease.transfer.use_host_export(); }
            leases.push(lease);
        }
        let operation = crate::automation::context::current();
        let cancellation = operation.as_ref().map(|operation| operation.cancellation.child_token()).unwrap_or_default();
        Ok(Self { leases, cancellation, operation, started:Instant::now(), inactivity:Duration::from_secs(90), total_limit:Duration::from_secs(12 * 60 * 60), temporary_staging:target.is_some(), cleanup_grace:Duration::from_secs(3), staging:None })
    }
    fn check(&self) -> Result<(), String> {
        if self.cancellation.is_cancelled() || self.leases.iter().any(|lease| lease.transfer.cancellation.is_cancelled()) {
            return Err(format!("YOUGORI_OPERATION_CANCELLED: file export cancelled; originals are unchanged; partialCopyPolicy={}", self.partial_policy()));
        }
        if self.started.elapsed() >= self.total_limit { return Err("YOUGORI_TRANSFER_DEADLINE: file export exceeded its 12-hour total limit; completed host files are retained and the incomplete current file is removed".into()); }
        Ok(())
    }
    fn partial_policy(&self) -> &'static str {
        if self.temporary_staging { "remove_unpublished_host_staging_preserve_originals" } else { "preserve_completed_unique_host_files_remove_incomplete_file" }
    }
    fn take_target_lease(&mut self, target:&str) -> Result<transfers::Lease,String> {
        self.check()?;
        let index = self.leases.iter().position(|lease|lease.transfer.environment_id == target).ok_or("The destination transfer lease is missing")?;
        Ok(self.leases.remove(index))
    }
    /// Blocking OS disk I/O cannot be force-cancelled. Keep its file/cleanup
    /// guard on that worker until the OS releases it, and report that outcome.
    async fn host_work<T: Send + 'static>(&self, work: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
        self.check()?;
        let mut task = tokio::task::spawn_blocking(work);
        let remaining = self.total_limit.saturating_sub(self.started.elapsed());
        let interrupted = tokio::select! {
            biased;
            _ = self.cancelled() => "cancelled",
            result = tokio::time::timeout(self.inactivity.min(remaining), &mut task) => match result {
                Ok(result) => return result.map_err(|_| "Host disk worker stopped unexpectedly".to_string())?,
                Err(_) => "inactive",
            },
        };
        // Reclaim an already finishing worker before returning. Dropping a
        // pending JoinHandle leaves its private cleanup guard with the worker.
        match tokio::time::timeout(self.cleanup_grace, task).await {
            Ok(_) => Err(format!("{}: host disk worker released its handle; incomplete-file cleanup was attempted. Inspect the unique destination if a file remains; originals are unchanged", if interrupted == "cancelled" { "YOUGORI_OPERATION_CANCELLED" } else { "YOUGORI_TRANSFER_INACTIVE" })),
            Err(_) => Err(format!("YOUGORI_OPERATION_INTERRUPTED: host disk work {interrupted}, but OS I/O is still pending; incomplete file cleanup will run when its handle closes. Reconciliation required: inspect the unique destination before retrying; originals are unchanged")),
        }
    }
    async fn cancelled(&self) {
        let mut tokens = vec![self.cancellation.clone()];
        tokens.extend(self.leases.iter().map(|lease| lease.transfer.cancellation.clone()));
        futures_util::future::select_all(tokens.into_iter().map(|token| Box::pin(token.cancelled_owned()))).await;
    }
    fn report(&self, phase: &'static str, completed: u64, total: u64, entries: usize) {
        let mut event = CopyProgress { phase, completed_bytes:completed, total_bytes:total, scanned_entries:Some(entries), sent_bytes:Some(completed), confirmed_bytes:Some(completed), ..Default::default() };
        for lease in &self.leases { event = lease.transfer.report(event); }
        if let Some(operation) = &self.operation { (operation.progress)(json!({"phase":phase,"completedBytes":completed,"totalBytes":total,"scannedEntries":entries,"sentBytes":completed,"confirmedBytes":completed,"lastProgressAt":event.last_progress_at.unwrap_or_else(||chrono::Utc::now().to_rfc3339()),"partialCopyPolicy":self.partial_policy(),"transferId":self.leases.first().map(|lease|lease.transfer.id.clone())})); }
    }
    async fn request(&self, source: &Source<'_>, operation: &str, path: &str, offset: u64, length: u64) -> Result<Value, String> {
        self.check()?;
        let remaining = self.total_limit.saturating_sub(self.started.elapsed());
        tokio::select! {
            biased;
            _ = self.cancelled() => { self.check()?; unreachable!() },
            result = tokio::time::timeout(self.inactivity.min(remaining), source.request(operation, path, offset, length)) => result.map_err(|_| format!("YOUGORI_TRANSFER_INACTIVE: file export made no progress for {} seconds while {operation}; completed host files remain, incomplete current file is removed", self.inactivity.as_secs()))?,
        }
    }
}

async fn with_source_cancellation<T>(control:&ExportControl,target:CancellationToken,import:impl std::future::Future<Output=Result<T,String>>) -> Result<T,String> {
    tokio::pin!(import);
    tokio::select! {
        biased;
        _ = control.cancelled() => {
            target.cancel();
            // Keep both environment registrations and private staging alive
            // until the import cooperatively closes its streams/workers.
            import.await
        },
        result = &mut import => result,
    }
}

pub(crate) enum Source<'a> {
    /// Someone else's environment reached through its sharing link and permissions.
    Shared(&'a Environment),
    /// A local container/microVM agent or a connected cloud server's agent.
    Guest(&'a RuntimeManager, &'a Environment),
    /// In-memory tree for tests: path -> file bytes, or None for a folder.
    #[cfg(test)]
    Fake(std::collections::BTreeMap<String, Option<Vec<u8>>>),
    #[cfg(test)]
    Stalled { size: u64, sent: Arc<std::sync::atomic::AtomicU64> },
}

impl Source<'_> {
    async fn request(&self, operation: &str, path: &str, offset: u64, length: u64) -> Result<Value, String> {
        match self {
            Source::Shared(env) => crate::remote_access::client::request_saved(env, "files", json!({"operation":operation,"path":path,"offset":offset,"length":length})).await,
            Source::Guest(runtime, env) => runtime.workspace_request(env, "/v1/remote/files", json!({
                "id": env.runtime_id.as_deref().unwrap_or(&env.id), "root": "/", "path": path,
                "operation": operation, "offset": offset, "length": length, "readOnly": true,
            })).await,
            #[cfg(test)]
            Source::Fake(tree) => {
                let node = tree.get(path).ok_or("No such file")?;
                match (operation, node) {
                    ("stat", node) => Ok(json!({"info":{"directory":node.is_none(),"size":node.as_ref().map_or(0, Vec::len)}})),
                    ("list", None) => Ok(json!({"entries": tree.iter()
                        .filter(|(p, _)| p.rsplit_once('/').map_or(!p.is_empty() && path.is_empty(), |(parent, _)| parent == path))
                        .map(|(p, n)| json!({"name":p.rsplit('/').next(),"directory":n.is_none(),"size":n.as_ref().map_or(0, Vec::len)}))
                        .collect::<Vec<_>>()})),
                    ("read", Some(bytes)) => {
                        let start = (offset as usize).min(bytes.len());
                        let end = (start + length as usize).min(bytes.len());
                        Ok(json!({"data": B64.encode(&bytes[start..end])}))
                    }
                    _ => Err("Unsupported".into()),
                }
            }
            #[cfg(test)]
            Source::Stalled { size, sent } => match operation {
                "stat" => Ok(json!({"info":{"directory":false,"size":size}})),
                "read" if offset == 0 => { sent.store(length, std::sync::atomic::Ordering::SeqCst); Ok(json!({"data":B64.encode(vec![7u8; length as usize])})) },
                _ => std::future::pending().await,
            },
        }
    }
}

pub(crate) fn valid_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    !name.is_empty()
        && name.len() <= 255
        && !name.chars().any(|c| c.is_control() || "/\\:<>\"|?*".contains(c))
        && !name.ends_with(['.', ' '])
        && !matches!(name, "." | "..")
        && !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !(stem.len() == 4 && (stem.starts_with("COM") || stem.starts_with("LPT")) && stem.as_bytes()[3].is_ascii_digit())
}

/// Creates `name`, or `name (2)`, `name (3)` … so nothing existing is replaced. Returns the name used.
fn fresh_folder(parent: &Dir, name: &str) -> Result<String, String> {
    for attempt in 1..1000 {
        let candidate = if attempt == 1 { name.to_owned() } else { format!("{name} ({attempt})") };
        match parent.create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err("Cannot create the destination folder".into()),
        }
    }
    Err("Too many folders with this name already exist".into())
}

/// `report.pdf`, then `report (2).pdf`, `report (3).pdf` … for a file that must not replace an existing one.
fn numbered(name: &str, attempt: u32) -> String {
    if attempt == 1 { return name.to_owned(); }
    match name.rsplit_once('.').filter(|(stem, _)| !stem.is_empty()) {
        Some((stem, extension)) => format!("{stem} ({attempt}).{extension}"),
        None => format!("{name} ({attempt})"),
    }
}

/// The guard follows the owned file onto blocking workers. Even if its async
/// caller is cancelled while a write/fsync is pending, cleanup waits for that
/// handle to close rather than claiming that Windows removed an open file.
struct HostFile {
    file: Option<cap_std::fs::File>,
    directory: Dir,
    path: PathBuf,
    complete: bool,
    staging: Option<Arc<crate::temporary_storage::Staging>>,
}
impl Drop for HostFile {
    fn drop(&mut self) {
        self.file.take();
        if !self.complete { if let Err(error) = self.directory.remove_file(&self.path) { eprintln!("Incomplete host copy needs cleanup: {}",crate::lifecycle::safe_diagnostic(&error.to_string())); } }
    }
}
impl HostFile {
    fn new(file: cap_std::fs::File, directory: &Dir, path: &std::path::Path) -> Result<Self, String> {
        let directory = directory.try_clone().map_err(|_| "Cannot retain the copied-file cleanup directory")?;
        Ok(Self { file:Some(file), directory, path:path.to_owned(), complete:false, staging:None })
    }
}

async fn copy_file(source: &Source<'_>, output: &Dir, remote: &str, local: &std::path::Path, size: u64, control: &ExportControl, completed: &mut u64, total: u64, entries: usize) -> Result<(), String> {
    let directory = output.try_clone().map_err(|_| "Cannot retain the destination directory")?;
    let local = local.to_owned();
    let staging = control.staging.clone();
    let file = control.host_work(move|| {
        let file = directory.open_with(&local,OpenOptions::new().write(true).create_new(true)).map_err(|_| "Cannot create a copied file")?;
        let mut file = HostFile::new(file,&directory,&local)?;
        file.staging = staging;
        Ok(file)
    }).await?;
    write_file(source, file, remote, size, control, completed, total, entries).await
}

async fn write_file(source: &Source<'_>, mut file: HostFile, remote: &str, size: u64, control: &ExportControl, completed: &mut u64, total: u64, entries: usize) -> Result<(), String> {
    let mut offset = 0;
    while offset < size {
        let length = (size - offset).min(65536);
        let value = control.request(source, "read", remote, offset, length).await?;
        let data = B64.decode(value["data"].as_str().unwrap_or("")).map_err(|_| "Invalid file data")?;
        if data.len() as u64 != length {
            return Err("A source file changed while copying; copy it again".into());
        }
        file = control.host_work(move || {
            file.file.as_mut().expect("owned output file").write_all(&data).map_err(|_| "Cannot write a copied file; check free disk space")?;
            Ok(file)
        }).await?;
        offset += length;
        *completed += length;
        control.report("receiving", *completed, total, entries);
    }
    control.check()?;
    control.report("verifying", *completed, total, entries);
    file = control.host_work(move || {
        file.file.as_mut().expect("owned output file").sync_all().map_err(|_| "Cannot finish a copied file".to_string())?;
        Ok(file)
    }).await?;
    control.check()?;
    file.complete = true;
    drop(file);
    Ok(())
}

/// Copies `path` (a file or folder, relative to the source root) into a fresh folder named `folder` inside `destination`.
pub(crate) async fn copy_out(source: Source<'_>, path: &str, destination: &str, folder: &str) -> Result<Value, String> {
    let control = ExportControl::begin(&source, None)?;
    copy_out_controlled(source, path, destination, folder, &control).await
}

async fn copy_out_controlled(source: Source<'_>, path: &str, destination: &str, folder: &str, control: &ExportControl) -> Result<Value, String> {
    control.check()?;
    let destination = PathBuf::from(destination);
    if !destination.is_absolute() {
        return Err("Choose an existing folder on this PC".into());
    }
    let location = destination.clone();
    let parent = control.host_work(move|| {
        if !location.is_dir() { return Err("Choose an existing folder on this PC".into()); }
        Dir::open_ambient_dir(&location,cap_std::ambient_authority()).map_err(|_| "Cannot open the destination folder".into())
    }).await?;
    control.report("scanning", 0, 0, 0);
    let info = control.request(&source, "stat", path, 0, 0).await?;
    if info["info"]["directory"] != true {
        // A single file goes straight into the destination under its own name.
        let size = info["info"]["size"].as_u64().ok_or("Invalid file size")?;
        if size > MAX_BYTES { return Err("Copy exceeds 100 GiB".into()); }
        let file_name = path.rsplit('/').next().filter(|n| valid_name(n)).ok_or("The file name is not valid on this PC")?;
        let directory = parent.try_clone().map_err(|_| "Cannot retain the destination directory")?;
        let file_name = file_name.to_owned();
        let staging = control.staging.clone();
        let (name,file) = control.host_work(move|| {
            let (name,file) = (1..1000).find_map(|attempt| {
                let name = numbered(&file_name,attempt);
                match directory.open_with(&name,OpenOptions::new().write(true).create_new(true)) {
                    Ok(file)=>Some(Ok((name,file))),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists=>None,
                    Err(_)=>Some(Err("Cannot create the copied file".to_string())),
                }
            }).ok_or("Too many files with this name already exist")??;
            let mut file = HostFile::new(file,&directory,std::path::Path::new(&name))?;
            file.staging = staging;
            Ok((name,file))
        }).await?;
        let copied = destination.join(&name).to_string_lossy().into_owned();
        control.report("receiving", 0, size, 1);
        let mut completed = 0;
        write_file(&source, file, path, size, control, &mut completed, size, 1).await?;
        control.report("complete", size, size, 1);
        return Ok(json!({"file": copied, "entries": 1, "bytes": size,"partialCopyPolicy":"preserve_completed_unique_host_files_remove_incomplete_file"}));
    }
    let directory = parent.try_clone().map_err(|_| "Cannot retain the destination directory")?;
    let folder = folder.to_owned();
    let retained_staging = control.staging.clone();
    let (name,output) = control.host_work(move|| {
        let name = fresh_folder(&directory,&folder)?;
        let output = directory.open_dir(&name).map_err(|_| "Cannot open the destination folder")?;
        // Retain private staging while any blocked directory operation runs.
        drop(directory);
        drop(retained_staging);
        Ok((name,output))
    }).await?;
    let mut count = 0usize;
    let mut total = 0u64;
    let mut completed = 0u64;
    let result: Result<(), String> = async {
        let mut pending = vec![(path.to_owned(), PathBuf::new(), 0)];
        let mut files = Vec::new();
        while let Some((remote, local, depth)) = pending.pop() {
            control.check()?;
            if depth > 64 { return Err("Folder nesting exceeds 64 levels".into()); }
            let listing = control.request(&source, "list", &remote, 0, 0).await?;
            let entries = listing["entries"].as_array().filter(|e| e.len() <= 5000).ok_or("Invalid folder listing")?;
            for item in entries {
                control.check()?;
                count += 1;
                if count > MAX_ENTRIES { return Err("Copy exceeds 50,000 entries; copy smaller folders separately".into()); }
                let name = item["name"].as_str().filter(|n| valid_name(n)).ok_or("The folder contains a name that is not valid on this PC")?;
                let child = local.join(name);
                let remote_child = if remote.is_empty() { name.to_owned() } else { format!("{remote}/{name}") };
                if item["directory"] == true {
                    let directory = output.try_clone().map_err(|_| "Cannot retain the destination directory")?;
                    let relative = child.clone();
                    let retained_staging = control.staging.clone();
                    control.host_work(move|| {
                        let result = directory.create_dir(&relative).map_err(|_| "Cannot create a copied folder".to_string());
                        drop(directory);
                        drop(retained_staging);
                        result
                    }).await?;
                    pending.push((remote_child, child, depth + 1));
                    control.report("scanning", 0, total, count);
                    continue;
                }
                let size = item["size"].as_u64().ok_or("Invalid file size")?;
                total = total.checked_add(size).ok_or("Copy too large")?;
                if total > MAX_BYTES { return Err("Copy exceeds 100 GiB; copy smaller folders separately".into()); }
                files.push((remote_child, child, size));
                control.report("scanning", 0, total, count);
            }
        }
        control.report("receiving", 0, total, count);
        for (remote, local, size) in files {
            copy_file(&source, &output, &remote, &local, size, control, &mut completed, total, count).await?;
        }
        Ok(())
    }
    .await;
    let folder = destination.join(name).to_string_lossy().into_owned();
    result.map_err(|error| format!("{error}. Unique destination: {folder}; {completed}/{total} bytes received. Completed files are preserved; an incomplete file is removed after its disk handle closes."))?;
    control.report("complete", completed, total, count);
    Ok(json!({"folder": folder, "entries": count, "bytes": total,"partialCopyPolicy":"preserve_completed_unique_host_files_remove_incomplete_file"}))
}

/// Copies a file or folder out of a running environment into a new folder on this PC.
#[tauri::command]
pub async fn copy_files_from_environment(
    environment_id: String,
    path: String,
    destination: String,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<Value, String> {
    let env = store.environment(&environment_id)?;
    let shared = env.runtime.starts_with("shared://tunnel/");
    if !shared && env.status != EnvironmentStatus::Running {
        return Err("Start or connect this environment first".into());
    }
    if env.kind == EnvironmentKind::FullVm {
        return Err("Full VMs have no Yougori file agent. Copy files out over the VM's own SSH, or place them on its imported-files drive while it is shut down.".into());
    }
    if env.provider == Some(RuntimeProviderKind::NativeSandbox) || env.kind == EnvironmentKind::ComputerBranch {
        return Err("This environment type does not support copying files out".into());
    }
    let trimmed = path.trim();
    let parts = trimmed.split('/').filter(|p| !p.is_empty() && *p != ".").collect::<Vec<_>>();
    if (!shared && !trimmed.starts_with('/')) || parts.is_empty() || trimmed.len() > 4096
        || trimmed.contains(['\0', '\\']) || parts.contains(&"..") {
        return Err("Give an absolute file or folder path inside the environment, for example /app/data".into());
    }
    let relative = parts.join("/");
    let relative = relative.as_str();
    let folder = relative.rsplit('/').next().filter(|n| valid_name(n)).unwrap_or("Yougori copy").to_owned();
    let source = if shared { Source::Shared(&env) } else { Source::Guest(&runtime, &env) };
    copy_out(source, relative, &destination, &folder).await
}

/// Copy a source file or folder into another environment using a temporary,
/// automatically removed host staging directory. The destination's normal
/// import path creates a new folder, so an existing guest file is not replaced.
#[tauri::command]
pub async fn copy_files_between_environments(
    source_id: String,
    target_id: String,
    path: String,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<Value, String> {
    if source_id == target_id { return Err("Choose two different environments".into()); }
    let state = store.snapshot()?;
    let source_env = state.environments.iter().find(|e| e.id == source_id).ok_or("Source environment not found")?;
    let target_env = state.environments.iter().find(|e| e.id == target_id).ok_or("Destination environment not found")?;
    if target_env.status != EnvironmentStatus::Running {
        return Err("Start or connect the destination environment first".into());
    }
    if !matches!(target_env.kind, EnvironmentKind::Container | EnvironmentKind::MicroVm | EnvironmentKind::FullVm | EnvironmentKind::Cloud)
        || target_env.runtime.starts_with("shared://") || target_env.provider == Some(RuntimeProviderKind::NativeSandbox) {
        return Err("This destination does not support imported files".into());
    }
    if source_env.status != EnvironmentStatus::Running && !source_env.runtime.starts_with("shared://tunnel/") {
        return Err("Start or connect the source environment first".into());
    }
    if source_env.kind == EnvironmentKind::FullVm || source_env.provider == Some(RuntimeProviderKind::NativeSandbox) {
        return Err("This source has no readable Yougori file service. Use its own SSH file transfer or export from its guest OS first.".into());
    }
    let trimmed = path.trim();
    let parts = trimmed.split('/').filter(|part| !part.is_empty() && *part != ".").collect::<Vec<_>>();
    if !trimmed.starts_with('/') || parts.is_empty() || trimmed.len() > 4096
        || trimmed.contains(['\0', '\\']) || parts.contains(&"..") {
        return Err("Choose an absolute source file or folder path, such as /app/data".into());
    }
    let relative = parts.join("/");
    let folder = parts.last().filter(|name| valid_name(name)).ok_or("The source name is not valid on this PC")?;
    let shared = source_env.runtime.starts_with("shared://tunnel/");
    let source = if shared { Source::Shared(source_env) } else { Source::Guest(&runtime, source_env) };
    let mut control = ExportControl::begin(&source, Some(&target_id))?;
    let staging_root = runtime.storage_root().join("cross-environment-transfers");
    let staging = control.host_work(move|| {
        std::fs::create_dir_all(&staging_root).map_err(|_| "Cannot prepare temporary transfer storage")?;
        Ok(Arc::new(crate::temporary_storage::Staging::new(&staging_root)?))
    }).await?;
    control.staging = Some(staging.clone());
    let copied = copy_out_controlled(source, &relative, &staging.path().to_string_lossy(), folder, &control).await?;
    // Retain the same target lease across phases. Stop can cancel the target
    // even between export completion and the first import operation.
    let target_lease = control.take_target_lease(&target_id)?;
    let target_cancellation = target_lease.transfer.cancellation.clone();
    let local = copied["file"].as_str().or(copied["folder"].as_str()).ok_or("The source copy did not produce a file or folder")?;
    let operation = crate::automation::context::current();
    let import = Box::pin(crate::file_import::copy_files_into_reusing_lease(&target_id, vec![local.to_owned()], None, &store, &runtime, move |event| { if let Some(operation) = &operation { (operation.progress)(serde_json::to_value(event).unwrap_or(Value::Null)); } }, target_lease));
    let imported = with_source_cancellation(&control,target_cancellation,import).await?;
    Ok(json!({"source": trimmed, "sourceEnvironment":source_env.name, "destination": imported.destination,
        "files": imported.files, "bytes": imported.bytes}))
}

pub(crate) fn valid_volume_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=80).contains(&bytes.len()) && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// Environments whose settings mount each named volume: name -> [{environmentId, environment, target, readOnly, running}].
fn volume_mounts(state: &PlatformState, runtime: &RuntimeManager) -> std::collections::BTreeMap<String, Vec<Value>> {
    let mut mounts = std::collections::BTreeMap::<String, Vec<Value>>::new();
    for env in &state.environments {
        if !matches!(env.kind, EnvironmentKind::Container | EnvironmentKind::MicroVm) || env.runtime.starts_with("shared://") {
            continue;
        }
        let Ok(options) = runtime.workload_options(env.runtime_id.as_deref().unwrap_or(&env.id)) else { continue };
        for volume in options.volumes {
            mounts.entry(volume.source).or_default().push(json!({
                "environmentId": env.id, "environment": env.name, "target": volume.target,
                "readOnly": volume.read_only, "running": env.status == EnvironmentStatus::Running,
            }));
        }
    }
    mounts
}

/// Named volumes: where environments mount them, and what each container runtime actually stores,
/// including volumes left behind by deleted environments. Only running runtimes are asked unless
/// `scan` is set, which starts stopped ones. `size` adds up each volume's files.
pub(crate) async fn volumes(store: &PlatformStore, runtime: &RuntimeManager, scan: bool, size: bool) -> Result<Value, String> {
    let state = store.snapshot()?;
    let names: std::collections::HashMap<String, String> = state.environments.iter()
        .flat_map(|env| [(env.id.clone(), env.name.clone()), (env.runtime_id.clone().unwrap_or_default(), env.name.clone())])
        .filter(|(id, _)| !id.is_empty()).collect();
    let mut volumes: std::collections::BTreeMap<String, Value> = volume_mounts(&state, runtime).into_iter()
        .map(|(name, mounts)| (name.clone(), json!({"name": name, "mounts": mounts, "stored": []}))).collect();
    let (stores, unavailable) = runtime.volume_stores(scan).await;
    let gpu = stores.iter().any(|place| place.provider == RuntimeProviderKind::YougoriCuda);
    let mut checked = Vec::new();
    let mut problems: Vec<String> = unavailable;
    for listing in runtime.list_named_volumes(&stores, size).await {
        let Some(list) = listing["volumes"].as_array() else {
            problems.push(format!("{}: {}", listing["location"].as_str().unwrap_or("?"), outdated_agent(listing["error"].as_str().unwrap_or("unavailable"), listing["runtime"] == "gpu")));
            continue;
        };
        checked.push(listing["location"].clone());
        for volume in list {
            let Some(name) = volume["name"].as_str() else { continue };
            let used_by: Vec<Value> = volume["usedBy"].as_array().into_iter().flatten()
                .filter_map(|c| c.as_str()).map(|c| Value::from(names.get(c).cloned().unwrap_or_else(|| c.to_owned()))).collect();
            let entry = volumes.entry(name.to_owned()).or_insert_with(|| json!({"name": name, "mounts": [], "stored": []}));
            if let Some(stored) = entry["stored"].as_array_mut() {
                stored.push(json!({
                    "location": listing["location"], "runtime": listing["runtime"], "usedBy": used_by,
                    "sizeBytes": volume["sizeBytes"], "sizeComplete": volume["sizeComplete"],
                }));
            }
        }
    }
    let volumes: Vec<Value> = volumes.into_values().map(|mut volume| {
        let used = volume["mounts"].as_array().is_some_and(|m| !m.is_empty())
            || volume["stored"].as_array().into_iter().flatten().any(|s| s["usedBy"].as_array().is_some_and(|u| !u.is_empty()));
        volume["inUse"] = used.into();
        volume
    }).collect();
    Ok(json!({
        "volumes": volumes, "checked": checked, "problems": problems,
        "note": match (scan, gpu) {
            (true, true) => "Every container runtime was checked.",
            (true, false) => "Every container runtime was checked except the GPU runtime, which is checked while a GPU environment runs.",
            _ => "Only running container runtimes were checked; scan to find volumes kept by stopped ones.",
        },
    }))
}

fn outdated_agent(error: &str, gpu: bool) -> String {
    if error.ends_with(": Not Found") && gpu {
        "the GPU runtime runs an older Yougori agent; run GPU setup again (`yougori gpu setup --yes`) to update it".into()
    } else if error.ends_with(": Not Found") {
        "this runtime runs an older Yougori agent; stop its environments and start them again to update it".into()
    } else {
        error.to_owned()
    }
}

/// Removes a named volume and its data from every container runtime that keeps it. Refuses while
/// an environment mounts it. The GPU runtime is included only while it runs.
pub(crate) async fn remove_named_volume(name: &str, store: &PlatformStore, runtime: &RuntimeManager) -> Result<Value, String> {
    if !valid_volume_name(name) {
        return Err("Volume names use up to 80 letters, numbers, dots, dashes or underscores".into());
    }
    let state = store.snapshot()?;
    if let Some(mounts) = volume_mounts(&state, runtime).get(name) {
        let users = mounts.iter().filter_map(|m| m["environment"].as_str()).collect::<Vec<_>>().join(", ");
        return Err(format!("{name} is used by {users}. Delete those environments first; the volume and its data stay until then."));
    }
    let (stores, unavailable) = runtime.volume_stores(true).await;
    let mut removed = Vec::new();
    let mut failures = Vec::new();
    for place in &stores {
        match runtime.volume_request(place, &json!({"action": "remove", "name": name})).await {
            Ok(_) => removed.push(place.location.clone()),
            Err(error) if error.contains("no volume named") => {}
            Err(error) => failures.push(format!("{}: {}", place.location, outdated_agent(&error, place.provider == RuntimeProviderKind::YougoriCuda))),
        }
    }
    if !failures.is_empty() {
        let done = if removed.is_empty() { String::new() } else { format!(" Removed from {}.", removed.join(", ")) };
        return Err(format!("Could not remove {name}: {}.{done}", failures.join("; ")));
    }
    if removed.is_empty() {
        let skipped = if unavailable.is_empty() { String::new() } else { format!(" Not checked: {}.", unavailable.join("; ")) };
        return Err(format!("No volume named {name}.{skipped}"));
    }
    Ok(json!({"removed": name, "from": removed, "notChecked": unavailable}))
}

#[tauri::command]
pub async fn list_volumes(scan: Option<bool>, size: Option<bool>, store: State<'_, PlatformStore>, runtime: State<'_, RuntimeManager>) -> Result<Value, String> {
    volumes(&store, &runtime, scan.unwrap_or(false), size.unwrap_or(false)).await
}

#[tauri::command]
pub async fn remove_volume(name: String, store: State<'_, PlatformStore>, runtime: State<'_, RuntimeManager>) -> Result<Value, String> {
    remove_named_volume(&name, &store, &runtime).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn volume_names_match_the_guest_rules() {
        for good in ["data", "db.cache", "a_b-1", &"x".repeat(80)] { assert!(valid_volume_name(good), "{good}"); }
        for bad in ["", "-data", ".x", "a/b", "a b", "a:b", &"x".repeat(81)] { assert!(!valid_volume_name(bad), "{bad}"); }
        assert!(outdated_agent("runtime operation failed: Not Found", false).contains("start them again"));
        assert!(outdated_agent("runtime operation failed: Not Found", true).contains("gpu setup"));
        assert_eq!(outdated_agent("disk full", true), "disk full");
    }
    #[test]
    fn copied_names_are_safe_on_windows() {
        for good in ["data", "report.pdf", "a b", ".env"] { assert!(valid_name(good), "{good}"); }
        for bad in ["", ".", "..", "a/b", "a\\b", "con", "COM1.txt", "name.", "x:y", "tab\t"] { assert!(!valid_name(bad), "{bad}"); }
    }
    #[tokio::test]
    async fn folders_and_large_files_are_copied_in_chunks_without_overwriting() {
        let big = (0..200_000u32).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let tree = || std::collections::BTreeMap::from([
            ("app".to_owned(), None),
            ("app/data".to_owned(), None),
            ("app/data/big.bin".to_owned(), Some(big.clone())),
            ("app/data/notes".to_owned(), None),
            ("app/data/notes/a.txt".to_owned(), Some(b"hello".to_vec())),
        ]);
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().to_string_lossy().into_owned();
        let first = copy_out(Source::Fake(tree()), "app/data", &destination, "data").await.unwrap();
        assert_eq!((first["entries"].as_u64(), first["bytes"].as_u64()), (Some(3), Some(200_005)));
        assert_eq!(std::fs::read(root.path().join("data/big.bin")).unwrap(), big);
        assert_eq!(std::fs::read(root.path().join("data/notes/a.txt")).unwrap(), b"hello");
        copy_out(Source::Fake(tree()), "app/data", &destination, "data").await.unwrap();
        assert!(root.path().join("data (2)/big.bin").exists());
        for expected in ["a.txt", "a (2).txt"] {
            let copied = copy_out(Source::Fake(tree()), "app/data/notes/a.txt", &destination, "a.txt").await.unwrap();
            assert_eq!(copied["file"].as_str().unwrap(), root.path().join(expected).to_string_lossy());
            assert_eq!(std::fs::read(root.path().join(expected)).unwrap(), b"hello");
        }
        assert_eq!(numbered("archive.tar.gz", 2), "archive.tar (2).gz");
        assert_eq!(numbered(".env", 3), ".env (3)");
    }
    #[tokio::test]
    async fn a_stalled_export_times_out_and_removes_only_its_incomplete_file() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("blob.bin"), b"existing file").unwrap();
        let source = Source::Stalled {size:131072,sent:Default::default()};
        let mut control = ExportControl::begin(&source,None).unwrap();
        control.inactivity = Duration::from_millis(40);
        let error = copy_out_controlled(source,"blob.bin",&root.path().to_string_lossy(),"blob",&control).await.unwrap_err();
        assert!(error.starts_with("YOUGORI_TRANSFER_INACTIVE"),"{error}");
        assert_eq!(std::fs::read(root.path().join("blob.bin")).unwrap(),b"existing file");
        assert!(!root.path().join("blob (2).bin").exists());
    }
    #[tokio::test]
    async fn stopping_either_side_cancels_between_export_and_reports_confirmed_bytes() {
        for stop_target in [false,true] {
            let root = tempfile::tempdir().unwrap();
            let source = Source::Stalled {size:131072,sent:Default::default()};
            let source_id = format!("export-source-{}",uuid::Uuid::new_v4());
            let target_id = format!("export-target-{}",uuid::Uuid::new_v4());
            let mut control = ExportControl::begin(&source,Some(&target_id)).unwrap();
            let source_lease = transfers::begin(&source_id).unwrap();
            source_lease.transfer.use_host_export();
            control.leases.push(source_lease);
            let transfers = control.leases.iter().map(|lease|lease.transfer.id.clone()).collect::<Vec<_>>();
            let progress = Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
            let recorded = progress.clone();
            control.operation = Some(crate::automation::context::OperationContext {id:"export-test".into(),cancellation:control.cancellation.clone(),progress:Arc::new(move|event|recorded.lock().unwrap().push(event))});
            let destination = root.path().to_string_lossy().into_owned();
            let task = tokio::spawn(async move {copy_out_controlled(source,"blob.bin",&destination,"blob",&control).await});
            tokio::time::timeout(Duration::from_secs(2),async {
                loop {
                    if progress.lock().unwrap().iter().any(|event|event["confirmedBytes"] == 65536) {break;}
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }).await.unwrap();
            let result = transfers::cancel(Some(if stop_target {&target_id} else {&source_id}),None);
            assert_eq!(result["cancelRequested"],true);
            let error = tokio::time::timeout(Duration::from_secs(2),task).await.unwrap().unwrap().unwrap_err();
            assert!(error.starts_with("YOUGORI_OPERATION_CANCELLED"),"{error}");
            assert!(!root.path().join("blob.bin").exists());
            assert!(transfers.iter().all(|id|transfers::find(id).is_none()));
            assert!(progress.lock().unwrap().iter().any(|event|event["partialCopyPolicy"] == "remove_unpublished_host_staging_preserve_originals"));
        }
    }
    #[tokio::test]
    async fn target_stop_remains_registered_across_the_export_import_handoff() {
        let root = tempfile::tempdir().unwrap();
        let target = format!("handoff-target-{}",uuid::Uuid::new_v4());
        let source = Source::Fake(std::collections::BTreeMap::from([("file".into(),Some(b"exported".to_vec()))]));
        let mut control = ExportControl::begin(&source,Some(&target)).unwrap();
        let copied = copy_out_controlled(source,"file",&root.path().to_string_lossy(),"file",&control).await.unwrap();
        let lease = control.take_target_lease(&target).unwrap();
        let transfer = lease.transfer.id.clone();
        drop(control);
        assert!(transfers::find(&transfer).is_some());
        assert_eq!(transfers::cancel(Some(&target),None)["cancelRequested"],true);
        let store = PlatformStore::load(root.path().join("state.json")).unwrap();
        let resources = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources");
        let runtime = RuntimeManager::new(&resources,&root.path().join("runtime-fixture")).unwrap();
        // The helper must check the retained token before even inspecting the
        // environment or beginning archive preparation/import.
        let error = crate::file_import::copy_files_into_reusing_lease(&target,vec![copied["file"].as_str().unwrap().to_owned()],None,&store,&runtime,|_|{},lease).await.err().unwrap();
        assert!(error.starts_with("YOUGORI_OPERATION_CANCELLED"),"{error}");
        assert!(transfers::find(&transfer).is_none());
        assert_eq!(std::fs::read(root.path().join("file")).unwrap(),b"exported");
    }
    #[tokio::test]
    async fn source_stop_cancels_the_target_after_export_has_finished() {
        let source_id = format!("import-phase-source-{}",uuid::Uuid::new_v4());
        let target_id = format!("import-phase-target-{}",uuid::Uuid::new_v4());
        let source = Source::Fake(Default::default());
        let mut control = ExportControl::begin(&source,Some(&target_id)).unwrap();
        control.leases.push(transfers::begin(&source_id).unwrap());
        let target = control.take_target_lease(&target_id).unwrap();
        let target_token = target.transfer.cancellation.clone();
        let source_transfer = control.leases[0].transfer.id.clone();
        let target_transfer = target.transfer.id.clone();
        let importing = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let began = importing.clone();
        let task = tokio::spawn(async move {
            let waiter = target_token.clone();
            let import = async move {
                target.transfer.use_guest_import();
                began.store(true,std::sync::atomic::Ordering::SeqCst);
                waiter.cancelled().await;
                target.transfer.check()
            };
            with_source_cancellation(&control,target_token,import).await
        });
        tokio::time::timeout(Duration::from_secs(2),async {while !importing.load(std::sync::atomic::Ordering::SeqCst) {tokio::time::sleep(Duration::from_millis(5)).await;}}).await.unwrap();
        assert!(transfers::find(&source_transfer).is_some());
        assert!(transfers::find(&target_transfer).is_some());
        assert_eq!(transfers::cancel(Some(&source_id),None)["cancelRequested"],true);
        let error = tokio::time::timeout(Duration::from_secs(2),task).await.unwrap().unwrap().unwrap_err();
        assert!(error.starts_with("YOUGORI_OPERATION_CANCELLED"),"{error}");
        assert!(transfers::find(&source_transfer).is_none());
        assert!(transfers::find(&target_transfer).is_none());
    }
    #[tokio::test]
    async fn blocked_host_io_reports_pending_cleanup_and_removes_the_file_after_release() {
        let root = tempfile::tempdir().unwrap();
        let directory = Dir::open_ambient_dir(root.path(),cap_std::ambient_authority()).unwrap();
        let file = directory.open_with("incomplete",OpenOptions::new().create_new(true).write(true)).unwrap();
        let output = HostFile::new(file,&directory,std::path::Path::new("incomplete")).unwrap();
        let source = Source::Fake(Default::default());
        let mut control = ExportControl::begin(&source,None).unwrap();
        control.inactivity = Duration::from_millis(10);
        control.cleanup_grace = Duration::from_millis(10);
        let error = control.host_work(move|| {std::thread::sleep(Duration::from_millis(150));Ok(output)}).await.err().unwrap();
        assert!(error.starts_with("YOUGORI_OPERATION_INTERRUPTED"),"{error}");
        assert!(error.contains("OS I/O is still pending"));
        assert!(root.path().join("incomplete").exists());
        tokio::time::timeout(Duration::from_secs(2),async {while root.path().join("incomplete").exists() {tokio::time::sleep(Duration::from_millis(5)).await;}}).await.unwrap();
    }
    #[test]
    fn existing_folders_are_never_reused() {
        let root = tempfile::tempdir().unwrap();
        let dir = Dir::open_ambient_dir(root.path(), cap_std::ambient_authority()).unwrap();
        assert_eq!(fresh_folder(&dir, "data").unwrap(), "data");
        assert_eq!(fresh_folder(&dir, "data").unwrap(), "data (2)");
        assert_eq!(fresh_folder(&dir, "data").unwrap(), "data (3)");
    }
}
