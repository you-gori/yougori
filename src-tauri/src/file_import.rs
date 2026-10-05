//! One-time copies only. Source paths are opened read-only, never shared with a guest.
use crate::{
    models::{Connection, EnforcementStatus, EnvironmentKind, EnvironmentStatus, PermissionKind},
    runtime::RuntimeManager,
    store::PlatformStore,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tauri::{ipc::Channel, State};
use crate::WebviewWindow;

mod drive;
pub(crate) mod transfers;

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CopyProgress {
    pub phase: &'static str,
    pub completed_bytes: u64,
    pub total_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanned_entries: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmed_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_progress_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waiting_for: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CopyResult {
    pub destination: String,
    pub files: usize,
    pub bytes: u64,
    pub skipped_links: usize,
    /// Files and folders left out by the copied folder's `.yougoriignore`.
    pub skipped_ignored: usize,
    pub delivery: &'static str,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct CopyEntry {
    pub source: PathBuf,
    pub resolved: PathBuf,
    pub relative: PathBuf,
    pub directory: bool,
    pub bytes: u64,
    pub modified: Option<SystemTime>,
    pub mode: u32,
}
pub(crate) struct CopyPlan {
    // Keep source identities on disk: a large node_modules tree must not require
    // holding every path and Metadata value in the desktop's memory.
    manifest: tempfile::NamedTempFile,
    pub entry_count: usize,
    pub bytes: u64,
    pub files: usize,
    pub skipped_links: usize,
    pub skipped_ignored: usize,
}

impl CopyPlan {
    pub fn entries(&self) -> Result<impl Iterator<Item = Result<CopyEntry, String>>, String> {
        let reader = BufReader::new(self.manifest.reopen().map_err(|e| e.to_string())?);
        Ok(serde_json::Deserializer::from_reader(reader)
            .into_iter::<CopyEntry>()
            .map(|entry| entry.map_err(|e| format!("Read copy file list: {e}"))))
    }
}

fn linked(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    metadata.file_type().is_symlink()
}

// The importing owner can use the copy. Other users never gain access that
// the source did not grant; privilege bits and group/other writes are removed.
#[cfg(any(unix, test))]
fn unix_copy_mode(source_mode: u32, directory: bool) -> u32 {
    if directory {
        0o700 | (source_mode & 0o055)
    } else {
        0o600 | (source_mode & 0o155)
    }
}

fn safe_name(path: &Path) -> Result<&std::ffi::OsStr, String> {
    let name = path
        .file_name()
        .ok_or("Choose a file or folder, not a drive root")?;
    let text = name.to_str().ok_or("A filename is not valid Unicode")?;
    if text.is_empty() || text == "." || text == ".." || text.contains(['\\', '/', ':', '\0']) {
        return Err("A filename cannot be copied safely between operating systems".into());
    }
    Ok(name)
}

#[cfg(test)]
pub(crate) fn plan_copy(paths: &[String]) -> Result<CopyPlan, String> {
    scan_copy(
        paths,
        tempfile::NamedTempFile::new().map_err(|e| e.to_string())?,
        |_| {},
    )
}

#[cfg(test)]
fn scan_copy(
    paths: &[String],
    manifest: tempfile::NamedTempFile,
    progress: impl Fn(CopyProgress),
) -> Result<CopyPlan, String> {
    scan_copy_cancellable(paths, manifest, progress, None)
}

fn scan_copy_cancellable(
    paths: &[String],
    manifest: tempfile::NamedTempFile,
    progress: impl Fn(CopyProgress),
    operation: Option<std::sync::Arc<transfers::Transfer>>,
) -> Result<CopyPlan, String> {
    if paths.is_empty() || paths.len() > 256 {
        return Err("Drop between 1 and 256 files or folders at a time".into());
    }
    let mut plan = CopyPlan {
        manifest,
        entry_count: 0,
        bytes: 0,
        files: 0,
        skipped_links: 0,
        skipped_ignored: 0,
    };
    let mut writer = BufWriter::new(plan.manifest.reopen().map_err(|e| e.to_string())?);
    let mut last = Instant::now();
    let mut names = HashSet::new();
    for source in paths {
        if let Some(operation) = &operation { operation.check()?; }
        let source = PathBuf::from(source);
        if !source.is_absolute() {
            return Err("Dropped files must have an absolute path".into());
        }
        let name = safe_name(&source)?.to_owned();
        if !names.insert(name.to_string_lossy().to_lowercase()) {
            return Err(
                "These items have matching names. Drop them separately to keep both copies.".into(),
            );
        }
        let boundary = source.canonicalize().map_err(|e| e.to_string())?;
        // A folder's own .yougoriignore decides what it leaves behind (1 MiB at most).
        let rules = fs::File::open(source.join(crate::ignore_rules::FILE_NAME)).ok().and_then(|file| {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut std::io::Read::take(file, 1024 * 1024), &mut text).ok().map(|_| crate::ignore_rules::Rules::parse(&text))
        });
        let mut ignored = 0usize;
        visit(&source, Path::new(&name), &boundary, 0, rules.as_ref(), &mut ignored, operation.as_deref(), &mut |entry| {
            if let Some(operation) = &operation { operation.check()?; }
            let Some(entry) = entry else {
                plan.skipped_links += 1;
                return Ok(());
            };
            if !entry.directory {
                plan.bytes = plan
                    .bytes
                    .checked_add(entry.bytes)
                    .filter(|size| *size <= i64::MAX as u64)
                    .ok_or("The selected data exceeds the filesystem's supported size")?;
                plan.files += 1;
            }
            serde_json::to_writer(&mut writer, &entry)
                .map_err(|e| format!("Prepare copy file list: {e}"))?;
            writer.write_all(b"\n").map_err(|e| e.to_string())?;
            plan.entry_count += 1;
            if last.elapsed().as_millis() >= 150 {
                progress(CopyProgress {
                    phase: "scanning",
                    completed_bytes: 0,
                    total_bytes: 0,
                    scanned_entries: Some(plan.entry_count),
                    ..Default::default()
                });
                last = Instant::now();
            }
            Ok(())
        })?;
        plan.skipped_ignored += ignored;
    }
    writer.flush().map_err(|e| e.to_string())?;
    if plan.entry_count == 0 {
        return Err("No ordinary files or folders to copy. Links and shortcuts to folders are not followed.".into());
    }
    Ok(plan)
}

fn visit(
    source: &Path,
    relative: &Path,
    boundary: &Path,
    depth: usize,
    rules: Option<&crate::ignore_rules::Rules>,
    ignored: &mut usize,
    operation: Option<&transfers::Transfer>,
    emit: &mut impl FnMut(Option<CopyEntry>) -> Result<(), String>,
) -> Result<(), String> {
    if let Some(operation)=operation {operation.check()?;}
    if depth > 128 {
        return Err(
            "A folder is nested more than 128 levels deep. Shorten that path before copying."
                .into(),
        );
    }
    let metadata = fs::symlink_metadata(source)
        .map_err(|e| format!("Cannot read {}: {e}", source.display()))?;
    if linked(&metadata) {
        return emit(None);
    }
    let resolved = source.canonicalize().map_err(|e| e.to_string())?;
    if !resolved.starts_with(boundary) {
        return Err("A source folder changed while preparing the copy. Drop it again.".into());
    }
    if !metadata.is_dir() && !metadata.is_file() {
        return Err(format!(
            "Not an ordinary file or folder: {}",
            source.display()
        ));
    }
    let directory = metadata.is_dir();
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        unix_copy_mode(metadata.permissions().mode(), directory)
    };
    // Windows has no execute bit; keep shell scripts runnable in the guest.
    #[cfg(not(unix))]
    let mode = if directory { 0o755 } else if source.extension().is_some_and(|e| e == "sh") { 0o755 } else { 0o644 };
    emit(Some(CopyEntry {
        source: source.into(),
        resolved,
        relative: relative.into(),
        directory,
        bytes: if directory { 0 } else { metadata.len() },
        modified: metadata.modified().ok(),
        mode,
    }))?;
    if directory {
        // Enumerate incrementally, including directories with hundreds of
        // thousands of immediate children. Only the ancestry is kept in RAM.
        let children =
            fs::read_dir(source).map_err(|e| format!("Cannot read {}: {e}", source.display()))?;
        for child in children {
            if let Some(operation)=operation {operation.check()?;}
            let path = child.map_err(|e| e.to_string())?.path();
            let child_relative = relative.join(safe_name(&path)?);
            if let Some(rules) = rules {
                let within = child_relative.components().skip(1).map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/");
                if rules.ignored(&within, fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir())) {
                    *ignored += 1;
                    continue;
                }
            }
            visit(
                &path,
                &child_relative,
                boundary,
                depth + 1,
                rules,
                ignored,
                operation,
                emit,
            )?;
        }
    }
    Ok(())
}

pub(crate) fn open_source(entry: &CopyEntry) -> Result<fs::File, String> {
    let current = fs::symlink_metadata(&entry.source).map_err(|e| e.to_string())?;
    if linked(&current) || !current.is_file() {
        return Err("A source file changed into a link or special file. Drop it again.".into());
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT; never follow a swapped link.
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(&entry.source)
        .map_err(|e| format!("Cannot read {}: {e}", entry.source.display()))?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    // Inspect the open handle, not just the path checked before open: a folder
    // may have been replaced by a junction/symlink between those two operations.
    if opened_path(&file)? != entry.resolved {
        return Err("A source path changed during the copy. Drop it again.".into());
    }
    if linked(&opened)
        || !opened.is_file()
        || opened.len() != entry.bytes
        || opened.modified().ok() != entry.modified
    {
        return Err(format!(
            "{} changed while preparing the copy. Drop it again when it has finished saving.",
            entry.source.display()
        ));
    }
    Ok(file)
}

fn opened_path(file: &fs::File) -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        use std::os::windows::{ffi::OsStringExt, io::AsRawHandle};
        let mut buffer = vec![0_u16; 32768];
        let length = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                0,
            )
        } as usize;
        if length == 0 || length >= buffer.len() {
            return Err("Could not verify the open source file".into());
        }
        Ok(PathBuf::from(std::ffi::OsString::from_wide(
            &buffer[..length],
        )))
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(|e| e.to_string())
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::{fd::AsRawFd, unix::ffi::OsStrExt};
        let mut buffer = [0_i8; libc::PATH_MAX as usize];
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buffer.as_mut_ptr()) } == -1 {
            return Err("Could not verify the open source file".into());
        }
        let name = unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) };
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(name.to_bytes())))
    }
}

struct CopyReader<'a, F> {
    file: fs::File,
    completed: &'a mut u64,
    last: &'a mut Instant,
    total: u64,
    progress: &'a F,
    operation: Option<&'a transfers::Transfer>,
}
impl<F: Fn(CopyProgress)> Read for CopyReader<'_, F> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if let Some(operation) = self.operation { operation.check().map_err(io::Error::other)?; }
        let count = self.file.read(buffer)?;
        *self.completed += count as u64;
        if self.last.elapsed().as_millis() >= 150 {
            (self.progress)(CopyProgress {
                phase: "archiving",
                completed_bytes: *self.completed,
                total_bytes: self.total,
                scanned_entries: None,
                ..Default::default()
            });
            *self.last = Instant::now();
        }
        Ok(count)
    }
}

#[cfg(test)]
pub(crate) fn write_archive(
    plan: &CopyPlan,
    destination: &Path,
    progress: impl Fn(CopyProgress),
) -> Result<(), String> {
    write_archive_cancellable(plan, destination, progress, None)
}

fn write_archive_cancellable(
    plan: &CopyPlan,
    destination: &Path,
    progress: impl Fn(CopyProgress),
    operation: Option<std::sync::Arc<transfers::Transfer>>,
) -> Result<(), String> {
    let mut archive = tar::Builder::new(BufWriter::with_capacity(
        1024 * 1024,
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .map_err(|e| e.to_string())?,
    ));
    let mut completed = 0;
    let mut last = Instant::now();
    progress(CopyProgress { phase: "archiving", completed_bytes: 0, total_bytes: plan.bytes, ..Default::default() });
    for entry in plan.entries()? {
        if let Some(operation) = &operation { operation.check()?; }
        let entry = entry?;
        let mut header = tar::Header::new_gnu();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(
            entry
                .modified
                .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        if entry.directory {
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(entry.mode);
            archive
                .append_data(&mut header, &entry.relative, io::empty())
                .map_err(|e| e.to_string())?;
        } else {
            let file = open_source(&entry)?;
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(entry.bytes);
            header.set_mode(entry.mode);
            archive
                .append_data(
                    &mut header,
                    &entry.relative,
                    CopyReader {
                        file,
                        completed: &mut completed,
                        last: &mut last,
                        total: plan.bytes,
                        progress: &progress,
                        operation: operation.as_deref(),
                    }
                    .take(entry.bytes),
                )
                .map_err(|e| format!("Copy could not read {}: {e}", entry.source.display()))?;
        }
    }
    archive.finish().map_err(|e| e.to_string())?;
    archive
        .into_inner()
        .map_err(|e| e.to_string())?
        .flush()
        .map_err(|e| e.to_string())?;
    progress(CopyProgress { phase: "archiving", completed_bytes: completed, total_bytes: plan.bytes, ..Default::default() });
    Ok(())
}

pub(crate) fn cancel_transfers(environment_id: &str, transfer_id: Option<&str>) -> serde_json::Value {
    transfers::cancel(Some(environment_id), transfer_id)
}
pub(crate) fn cancel_all_transfers() -> serde_json::Value { transfers::cancel(None, None) }

#[tauri::command]
pub fn cancel_file_transfer(environment_id: String, transfer_id: Option<String>, window: WebviewWindow) -> Result<serde_json::Value, String> {
    if window.label() != "main" { return Err("Cancel file copies from the main Yougori window".into()); }
    Ok(cancel_transfers(&environment_id, transfer_id.as_deref()))
}

#[tauri::command]
pub async fn copy_files_to_environment(
    environment_id: String,
    paths: Vec<String>,
    on_progress: Channel<CopyProgress>,
    window: WebviewWindow,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<CopyResult, String> {
    if window.label() != "main" {
        return Err("Drop files onto a node in the main Yougori window".into());
    }
    copy_files(&environment_id, paths, &store, &runtime, move |progress| {
        let _ = on_progress.send(progress);
    })
    .await
}

#[tauri::command]
pub fn list_imported_drives(
    environment_id: String,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<Vec<crate::runtime::ImportedDrive>, String> {
    let environment = store.environment(&environment_id)?;
    runtime.imported_drives(&environment)
}

#[tauri::command]
pub async fn set_imported_drive_attached(
    environment_id: String,
    transfer_id: String,
    attached: bool,
    window: WebviewWindow,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<Vec<crate::runtime::ImportedDrive>, String> {
    if window.label() != "main" {
        return Err("Manage imported drives in the main Yougori window".into());
    }
    set_drive_attached(&environment_id, &transfer_id, attached, &store, &runtime).await
}

pub(crate) async fn set_drive_attached(
    environment_id: &str,
    transfer_id: &str,
    attached: bool,
    store: &PlatformStore,
    runtime: &RuntimeManager,
) -> Result<Vec<crate::runtime::ImportedDrive>, String> {
    let lock = crate::commands::environment_network_lock(environment_id).await;
    let _guard = lock
        .try_lock()
        .map_err(|_| "This environment is busy. Wait for its current action to finish.")?;
    let environment = store.environment(&environment_id)?;
    runtime
        .set_import_drive_attached(&environment, transfer_id, attached)
        .await
}

pub(crate) async fn copy_files(
    environment_id: &str,
    paths: Vec<String>,
    store: &PlatformStore,
    runtime: &RuntimeManager,
    progress: impl Fn(CopyProgress) + Send + Sync + 'static,
) -> Result<CopyResult, String> {
    copy_files_into(environment_id, paths, None, store, runtime, progress).await
}

/// Like `copy_files`, optionally into a chosen folder of a container or microVM (a new `yougori-import-…`
/// subfolder is still created there, so nothing is overwritten). The folder must be on the guest's own
/// disk or a named volume.
pub(crate) async fn copy_files_into(
    environment_id: &str,
    paths: Vec<String>,
    destination_folder: Option<String>,
    store: &PlatformStore,
    runtime: &RuntimeManager,
    progress: impl Fn(CopyProgress) + Send + Sync + 'static,
) -> Result<CopyResult, String> {
    let lease=transfers::begin(environment_id)?;
    Box::pin(copy_files_into_reusing_lease(environment_id,paths,destination_folder,store,runtime,progress,lease)).await
}

/// Keep a between-copy target's cancellation lease registered across the export/import handoff.
pub(crate) async fn copy_files_into_reusing_lease(
    environment_id:&str, paths:Vec<String>, destination_folder:Option<String>,
    store:&PlatformStore, runtime:&RuntimeManager,
    progress:impl Fn(CopyProgress)+Send+Sync+'static, lease:transfers::Lease,
)->Result<CopyResult,String>{
    if lease.transfer.environment_id!=environment_id{return Err("The transfer lease belongs to another environment".into());}
    let operation = lease.transfer.clone();
    operation.use_guest_import();
    operation.check()?;
    let state = store.snapshot()?;
    let environment = state
        .environments
        .iter()
        .find(|env| env.id == environment_id)
        .ok_or("Environment not found")?;
    if !matches!(
        environment.kind,
        EnvironmentKind::Container | EnvironmentKind::MicroVm | EnvironmentKind::FullVm | EnvironmentKind::Cloud
    ) || environment.provider == Some(crate::models::RuntimeProviderKind::NativeSandbox)
        || environment.runtime.starts_with("shared://")
    {
        return Err("Drop files onto a local environment or a connected SSH cloud server".into());
    }
    if environment.status != EnvironmentStatus::Running {
        return Err(if environment.kind == EnvironmentKind::Cloud {
            "Connect this cloud server before copying files into it"
        } else {
            "Start this environment before copying files into it"
        }.into());
    }
    let measurement = operation.clone();
    let progress = std::sync::Arc::new(move |event| progress(measurement.report(event)));
    progress(CopyProgress {
        phase: "scanning",
        completed_bytes: 0,
        total_bytes: 0,
        scanned_entries: None,
        ..Default::default()
    });
    let cloud = environment.kind == EnvironmentKind::Cloud;
    if cloud{operation.use_cloud_staging();}
    if destination_folder.is_some() && !matches!(environment.kind, EnvironmentKind::Container | EnvironmentKind::MicroVm) {
        return Err("Choosing a destination folder works for containers and microVMs. Copy without a folder for VMs and cloud servers.".into());
    }
    if destination_folder.as_deref().is_some_and(|folder| !yougori_cli::workload::guest_path(folder)) {
        return Err("Choose an absolute guest folder such as /data".into());
    }
    let shared_destination = destination_folder.as_deref().or_else(|| selected_drop_folder(&state.connections, &environment.id));
    let root = if cloud {
        runtime.storage_root().join("cloud-imports").join(&environment.id)
    } else {
        runtime.environment_storage_root(environment.runtime_id.as_deref().unwrap_or(&environment.id))?.join("file-imports")
    };
    let full_vm = environment.kind == EnvironmentKind::FullVm;
    let report = progress.clone();
    let cancel = operation.clone();
    let mut preparation = tokio::task::spawn_blocking(move || -> Result<_, String> {
        fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        let staging = tempfile::Builder::new().prefix("copy-").tempdir_in(&root).map_err(|e| e.to_string())?;
        let manifest = tempfile::Builder::new().prefix("files-").tempfile_in(&root).map_err(|e| e.to_string())?;
        let plan = scan_copy_cancellable(&paths, manifest, |p| report(p), Some(cancel.clone()))?;
        let disks = sysinfo::Disks::new_with_refreshed_list();
        let disk = crate::runtime::storage::runtime_disk(&disks, &root).ok_or("Could not check free space for the copy")?;
        let required = if full_vm { drive::capacity(&plan) } else { plan.bytes.saturating_mul(2).saturating_add((plan.entry_count as u64).saturating_mul(8192)) };
        if disk.available_space() < required.saturating_add(2 * 1024 * 1024 * 1024) { return Err("Not enough free space for this copy while keeping 2 GB free for your computer. Copy a smaller folder or free some space.".into()); }
        if full_vm { drive::write_drive_cancellable(&plan, &staging.path().join("copy.img"), |p| report(p), Some(cancel.clone()))?; }
        else { write_archive_cancellable(&plan, &staging.path().join("copy.tar"), |p| report(p), Some(cancel.clone()))?; }
        cancel.check()?;
        Ok((plan, staging))
    });
    let mut tick=tokio::time::interval(std::time::Duration::from_secs(1));
    let (plan,staging)=loop {tokio::select! {
        result=&mut preparation=>break result.map_err(|e|e.to_string())??,
        _=operation.cancellation.cancelled()=>{
            match tokio::time::timeout(std::time::Duration::from_secs(3),&mut preparation).await {
                Ok(_)=>return operation.check().and_then(|_|Err("YOUGORI_OPERATION_CANCELLED: copy preparation cancelled".into())),
                Err(_)=>return Err("YOUGORI_OPERATION_INTERRUPTED: host file read did not stop within three seconds; its staging data remains private and will be removed when the read returns. No new guest copy was published.".into())
            }
        },
        _=tick.tick()=>{
            if operation.idle_for()>std::time::Duration::from_secs(90){operation.cancellation.cancel();return Err("YOUGORI_TRANSFER_INACTIVE: scan or archive made no progress for 90 seconds; staged host files will be removed when pending reads finish, originals unchanged".into());}
            operation.check()?;
        }
    }};
    operation.check()?;
    let transfer = operation.id.clone();
    let destination = if cloud {
        runtime.cloud.import_file_archive(&environment.id, &staging.path().join("copy.tar"), &transfer, plan.bytes, plan.files, progress.clone()).await?
    } else if full_vm {
        progress(CopyProgress {
            phase: "finishing",
            completed_bytes: plan.bytes,
            total_bytes: plan.bytes,
            scanned_entries: None,
            ..Default::default()
        });
        runtime
            .attach_import_drive(&environment, &staging.path().join("copy.img"), &transfer)
            .await?
    } else {
        runtime
            .import_file_archive(
                &environment,
                &staging.path().join("copy.tar"),
                &transfer,
                plan.bytes,
                shared_destination,
                progress,
            )
            .await?
    };
    Ok(CopyResult {
        destination,
        bytes: plan.bytes,
        files: plan.files,
        skipped_links: plan.skipped_links,
        skipped_ignored: plan.skipped_ignored,
        delivery: if full_vm { "drive" } else { "directory" },
    })
}

// A drop goes into the guest's shared data only when there is exactly one
// eligible destination. Never choose arbitrarily between several folders.
fn selected_drop_folder<'a>(connections: &'a [Connection], environment_id: &str) -> Option<&'a str> {
    let shared_folders: HashSet<&str> = connections.iter()
        .filter(|connection| connection.active
            && matches!(connection.enforcement_status, Some(EnforcementStatus::Enforced))
            && connection.permissions.iter().any(|permission| matches!(permission, PermissionKind::Data | PermissionKind::Files | PermissionKind::Volumes)))
        .flat_map(|connection| connection.selected_folders.iter())
        .filter(|folder| folder.environment_id == environment_id
            && crate::runtime::connection_files::validate_selected_folder_path(&folder.path).is_ok())
        .map(|folder| folder.path.as_str())
        .collect();
    if shared_folders.len() == 1 { shared_folders.into_iter().next() } else { None }
}

#[cfg(test)]
mod tests;
