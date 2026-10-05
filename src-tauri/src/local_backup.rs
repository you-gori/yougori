//! Portable local backups: a small manifest and a streamed, checksummed disk artifact.
//! Download archives accept only two fixed regular-file entries. No paths from
//! the manifest are used as host destinations.
use crate::{
    backup::{BackupManager, BackupRestore},
    models::*,
    runtime::RuntimeManager,
    store::PlatformStore,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use tauri::State;
use uuid::Uuid;

const MANIFEST: &str = "backup.yougori";
const PAYLOAD: &str = "disk.data";
const MAX_MANIFEST: u64 = 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    version: u32,
    environment: Environment,
    snapshot: Snapshot,
    size: u64,
    sha256: String,
}

fn supported(env: &Environment) -> Result<(), String> {
    let valid = matches!(
        (&env.kind, &env.provider),
        (
            EnvironmentKind::Container,
            Some(RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda)
        ) | (EnvironmentKind::FullVm, Some(RuntimeProviderKind::Qemu))
    ) || (env.kind == EnvironmentKind::MicroVm
        && env.provider == Some(RuntimeProviderKind::Qemu)
        && env.runtime == "builtin:alpine");
    if !valid {
        return Err("Portable backups support managed containers, full VMs and built-in Alpine microVMs. Native branches and custom microVMs are not supported yet.".into());
    }
    crate::commands::validate_policy(&env.resource_policy)
}

fn regular_file(path: &Path) -> Result<File, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.file_type().is_file() {
        return Err("Backup files must be regular files, not links or directories".into());
    }
    File::open(path).map_err(|e| e.to_string())
}

fn validate_standalone_vm(path: &Path) -> Result<(), String> {
    let mut header = [0u8; 104];
    regular_file(path)?
        .read_exact(&mut header)
        .map_err(|e| format!("Invalid VM backup header: {e}"))?;
    let version = u32::from_be_bytes(header[4..8].try_into().unwrap());
    let backing_offset = u64::from_be_bytes(header[8..16].try_into().unwrap());
    let backing_size = u32::from_be_bytes(header[16..20].try_into().unwrap());
    let encryption = u32::from_be_bytes(header[32..36].try_into().unwrap());
    let features = u64::from_be_bytes(header[72..80].try_into().unwrap());
    if &header[..4] != b"QFI\xfb"
        || !matches!(version, 2 | 3)
        || backing_offset != 0
        || backing_size != 0
        || encryption != 0
        || (version == 3 && features & 4 != 0)
    {
        return Err("VM backups must be standalone, unencrypted QCOW2 disks without backing files or external data files".into());
    }
    Ok(())
}

// OCI/Docker archives embed their snapshot tag. Rewrite only the small root
// metadata documents, streaming every layer unchanged; never unpack guest files.
fn retag_container(
    source: &Path,
    destination: &Path,
    old_id: &str,
    new_id: &str,
) -> Result<(u64, String), String> {
    fn replace(
        value: &mut serde_json::Value,
        old: &str,
        new: &str,
        old_id: &str,
        new_id: &str,
    ) -> bool {
        match value {
            serde_json::Value::String(s) if s == old => {
                *s = new.into();
                true
            }
            serde_json::Value::String(s) if s == old_id => {
                *s = new_id.into();
                false
            }
            serde_json::Value::Array(items) => items.iter_mut().fold(false, |found, item| {
                replace(item, old, new, old_id, new_id) || found
            }),
            serde_json::Value::Object(items) => items.values_mut().fold(false, |found, item| {
                replace(item, old, new, old_id, new_id) || found
            }),
            _ => false,
        }
    }
    let input = regular_file(source)?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|e| e.to_string())?;
    let result = (|| {
        let mut archive = tar::Archive::new(input);
        let mut output = tar::Builder::new(file);
        let mut found = false;
        let mut metadata_seen = std::collections::HashSet::new();
        for entry in archive.entries().map_err(|e| e.to_string())? {
            let mut entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path().map_err(|e| e.to_string())?;
            let path = container_archive_path(&path)?;
            let mut header = entry.header().clone();
            // The outer OCI/Docker archive contains metadata and layer blobs,
            // not guest filesystem objects. Links/devices belong inside the
            // opaque layer blobs and must never become archive load targets.
            if !header.entry_type().is_file() && !header.entry_type().is_dir() {
                return Err("Container backups may only contain regular metadata, layer files and directories".into());
            }
            if path == "index.json" || path == "manifest.json" {
                if !metadata_seen.insert(path)
                    || entry.size() > MAX_MANIFEST
                    || !header.entry_type().is_file()
                {
                    return Err("Invalid container backup metadata".into());
                }
                let mut json: serde_json::Value =
                    serde_json::from_reader(&mut entry).map_err(|e| e.to_string())?;
                found |= replace(
                    &mut json,
                    &format!("opendock.local/snapshots:{}", old_id.to_lowercase()),
                    &format!("opendock.local/snapshots:{}", new_id.to_lowercase()),
                    old_id,
                    new_id,
                );
                let bytes = serde_json::to_vec(&json).map_err(|e| e.to_string())?;
                header.set_size(bytes.len() as u64);
                header.set_cksum();
                output
                    .append(&header, bytes.as_slice())
                    .map_err(|e| e.to_string())?;
            } else {
                output
                    .append(&header, &mut entry)
                    .map_err(|e| e.to_string())?;
            }
        }
        if !found {
            return Err("Container backup is missing its original snapshot tag".into());
        }
        let file = output.into_inner().map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        drop(file);
        let mut file = File::open(destination).map_err(|e| e.to_string())?;
        let size = file.metadata().map_err(|e| e.to_string())?.len();
        let mut hash = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        Ok((size, hex::encode(hash.finalize())))
    })();
    if result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result
}

fn container_archive_path(path: &Path) -> Result<String, String> {
    let value = path.to_str().ok_or("Container backup contains a non-UTF-8 archive path")?;
    if value.contains(['\\', ':', '\0'])
        || path.components().any(|part| !matches!(part, std::path::Component::Normal(_) | std::path::Component::CurDir))
    {
        return Err("Container backup contains an unsafe archive path".into());
    }
    // Strip literal ./ components, never arbitrary dots/slashes: ../index.json
    // is traversal, not another spelling of root metadata.
    Ok(path.components().filter_map(|part| match part {
        std::path::Component::Normal(value) => value.to_str(),
        _ => None,
    }).collect::<Vec<_>>().join("/"))
}

// Fixed memory usage even for large VM disks; never overwrite an existing file.
fn copy_checked(source: &Path, target: &Path, size: u64, checksum: &str) -> Result<(), String> {
    let mut input = regular_file(source)?;
    if input.metadata().map_err(|e| e.to_string())?.len() != size {
        return Err("Backup size does not match its manifest".into());
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(|e| e.to_string())?;
    let result = (|| {
        let mut hash = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        let mut total = 0u64;
        loop {
            let count = input.read(&mut buffer).map_err(|e| e.to_string())?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .ok_or("Backup is too large")?;
            if total > size {
                return Err("Backup changed while it was being copied".into());
            }
            hash.update(&buffer[..count]);
            output
                .write_all(&buffer[..count])
                .map_err(|e| e.to_string())?;
        }
        if total != size || hex::encode(hash.finalize()) != checksum {
            return Err("Backup checksum verification failed".into());
        }
        output.sync_all().map_err(|e| e.to_string())
    })();
    drop(output);
    if result.is_err() {
        let _ = fs::remove_file(target);
    }
    result
}

fn write_backup(parent: &Path, manifest: &Manifest, artifact: &Path) -> Result<PathBuf, String> {
    let parent = parent.canonicalize().map_err(|e| e.to_string())?;
    if !parent.is_dir() {
        return Err("Choose a backup destination folder".into());
    }
    let folder = parent.join(format!("Yougori-backup-{}", Uuid::new_v4()));
    fs::create_dir(&folder).map_err(|e| e.to_string())?;
    let result = (|| {
        copy_checked(
            artifact,
            &folder.join(PAYLOAD),
            manifest.size,
            &manifest.sha256,
        )?;
        // Manifest appears only after the entire disk has been verified and flushed.
        let data = serde_json::to_vec_pretty(manifest).map_err(|e| e.to_string())?;
        if data.len() as u64 > MAX_MANIFEST {
            return Err("Backup metadata is too large".into());
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(folder.join(MANIFEST))
            .map_err(|e| e.to_string())?;
        file.write_all(&data)
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        Ok(folder.join(MANIFEST))
    })();
    if result.is_err() {
        // Only our newly created files, never recursive deletion of the selected folder.
        let _ = fs::remove_file(folder.join(MANIFEST));
        let _ = fs::remove_file(folder.join(PAYLOAD));
        let _ = fs::remove_dir(&folder);
    }
    result
}

fn read_backup(path: &Path, staging: &Path) -> Result<BackupRestore, String> {
    use std::io::{Seek, SeekFrom};
    let mut source = regular_file(path)?;
    let mut prefix = [0u8; 512];
    let count = source.read(&mut prefix).map_err(|e| e.to_string())?;
    source.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    // Single-file downloads are a strict two-entry tar, never a general archive
    // extraction. Existing JSON backup manifests keep their original format.
    if count == 512 && &prefix[257..262] == b"ustar" {
        let temporary = tempfile::tempdir_in(staging).map_err(|e| e.to_string())?;
        unpack_download(source, temporary.path())?;
        return read_backup_manifest(&temporary.path().join(MANIFEST), staging);
    }
    read_backup_manifest(path, staging)
}

pub(crate) fn pack_download(manifest: &Path, destination: &Path) -> Result<u64, String> {
    let payload_size = regular_file(&manifest.parent().ok_or("Missing backup folder")?.join(PAYLOAD))?.metadata().map_err(|e| e.to_string())?.len();
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let disk = crate::runtime::storage::runtime_disk(&disks, destination.parent().ok_or("Missing download folder")?).ok_or("Cannot determine available download storage")?;
    if disk.available_space() < payload_size.saturating_add(2 * 1024 * 1024 * 1024) { return Err("Not enough free space to prepare this download. Yougori keeps 2 GB available for your computer.".into()); }
    let output = OpenOptions::new().write(true).create_new(true).open(destination).map_err(|e| e.to_string())?;
    let result = (|| {
        let mut archive = tar::Builder::new(output);
        for name in [MANIFEST, PAYLOAD] {
            let mut input = regular_file(&manifest.parent().ok_or("Missing backup folder")?.join(name))?;
            let size = input.metadata().map_err(|e| e.to_string())?.len();
            if name == MANIFEST && size > MAX_MANIFEST { return Err("Backup manifest is too large".into()); }
            let mut header = tar::Header::new_ustar();
            header.set_size(size);
            header.set_mode(0o600);
            header.set_cksum();
            archive.append_data(&mut header, name, &mut input).map_err(|e| e.to_string())?;
        }
        let output = archive.into_inner().map_err(|e| e.to_string())?;
        output.sync_all().map_err(|e| e.to_string())?;
        output.metadata().map(|m| m.len()).map_err(|e| e.to_string())
    })();
    if result.is_err() { let _ = fs::remove_file(destination); }
    result
}

fn unpack_download(source: File, destination: &Path) -> Result<(), String> {
    let mut archive = tar::Archive::new(source);
    let mut seen = std::collections::HashSet::new();
    let mut expected_payload = None;
    for entry in archive.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let name = entry.path().map_err(|e| e.to_string())?.to_str().ok_or("Invalid download archive path")?.to_owned();
        if ![MANIFEST, PAYLOAD].contains(&name.as_str()) || !entry.header().entry_type().is_file() || !seen.insert(name.clone()) {
            return Err("A Yougori download must contain exactly backup.yougori and disk.data, without links or other paths".into());
        }
        let limit = if name == MANIFEST { MAX_MANIFEST } else { 2 * 1024 * 1024 * 1024 * 1024 };
        if entry.size() == 0 || entry.size() > limit { return Err("Invalid download archive size".into()); }
        if name == MANIFEST {
            if seen.len() != 1 { return Err("The backup manifest must be the first download entry".into()); }
            let mut bytes = Vec::new(); entry.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
            let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| format!("Invalid download manifest: {e}"))?;
            supported(&manifest.environment)?;
            if !matches!(manifest.version, 1 | 2) || manifest.size == 0 || manifest.size > 2 * 1024 * 1024 * 1024 * 1024
                || manifest.sha256.len() != 64 || !manifest.sha256.bytes().all(|b| b.is_ascii_hexdigit()) { return Err("Invalid download manifest".into()); }
            expected_payload = Some(manifest.size);
            fs::write(destination.join(MANIFEST), bytes).map_err(|e| e.to_string())?;
            continue;
        }
        if expected_payload != Some(entry.size()) { return Err("Download payload size does not match its manifest".into()); }
        let mut output = OpenOptions::new().write(true).create_new(true).open(destination.join(name)).map_err(|e| e.to_string())?;
        let mut bytes = vec![0; 256 * 1024]; let mut since_check = 64 * 1024 * 1024;
        loop {
            if since_check >= 64 * 1024 * 1024 {
                let disks = sysinfo::Disks::new_with_refreshed_list();
                let disk = crate::runtime::storage::runtime_disk(&disks, destination).ok_or("Cannot determine available download storage")?;
                if disk.available_space() < 2 * 1024 * 1024 * 1024 { return Err("Not enough free space to import this environment. Yougori keeps 2 GB available for your computer.".into()); }
                since_check = 0;
            }
            let count = entry.read(&mut bytes).map_err(|e| format!("Incomplete download: {e}"))?;
            if count == 0 { break; }
            output.write_all(&bytes[..count]).map_err(|e| e.to_string())?;
            since_check += count;
        }
        output.sync_all().map_err(|e| e.to_string())?;
    }
    if seen.len() != 2 { return Err("The environment download is incomplete".into()); }
    Ok(())
}

fn read_backup_manifest(path: &Path, staging: &Path) -> Result<BackupRestore, String> {
    let mut bytes = Vec::new();
    regular_file(path)?
        .take(MAX_MANIFEST + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_MANIFEST {
        return Err("Backup manifest is too large".into());
    }
    let mut manifest: Manifest =
        serde_json::from_slice(&bytes).map_err(|e| format!("Invalid Yougori backup: {e}"))?;
    if !matches!(manifest.version, 1 | 2) {
        return Err("Unsupported Yougori backup version".into());
    }
    supported(&manifest.environment)?;
    if manifest.size == 0
        || manifest.size > 2 * 1024 * 1024 * 1024 * 1024
        || manifest.sha256.len() != 64
        || !manifest.sha256.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("Invalid backup size or checksum".into());
    }
    let mut artifact = staging.join(format!("local-{}.data", Uuid::new_v4()));
    copy_checked(
        &path.parent().ok_or("Missing backup folder")?.join(PAYLOAD),
        &artifact,
        manifest.size,
        &manifest.sha256,
    )?;
    if manifest.environment.provider == Some(RuntimeProviderKind::Qemu) {
        // Every validation failure must discard our staged copy, including
        // malformed TPM/firmware extensions (which return Err, not false).
        let validation = (|| {
            validate_standalone_vm(&artifact)?;
            if manifest.version == 2 && !crate::runtime::backup_has_vm_security(&artifact)? {
                return Err("This secure VM backup is missing its TPM and firmware state".into());
            }
            Ok::<(), String>(())
        })();
        if let Err(error) = validation {
            let _ = fs::remove_file(&artifact);
            return Err(error);
        }
    }
    let snapshot_id = format!("snap-{}", Uuid::new_v4());
    if manifest.environment.provider.as_ref().is_some_and(RuntimeProviderKind::is_container) {
        let retagged = staging.join(format!("local-{}.data", Uuid::new_v4()));
        let result = retag_container(&artifact, &retagged, &manifest.snapshot.id, &snapshot_id);
        let _ = fs::remove_file(&artifact);
        let (size, checksum) = result?;
        manifest.size = size;
        manifest.sha256 = checksum;
        artifact = retagged;
    }
    let env = &mut manifest.environment;
    env.id = format!("env-{}", Uuid::new_v4());
    env.name = format!(
        "{} (restored)",
        env.name.chars().take(70).collect::<String>()
    );
    env.status = EnvironmentStatus::Stopped;
    env.runtime_id = None;
    env.runtime_path = None;
    env.console_endpoint = None;
    env.control_endpoint = None;
    env.sandbox_policy = None;
    env.branch_type = None;
    env.last_opened_at = None;
    env.created_at = chrono::Utc::now().to_rfc3339();
    let snapshot = &mut manifest.snapshot;
    snapshot.id = snapshot_id;
    snapshot.environment_id = env.id.clone();
    snapshot.environment_state = None;
    snapshot.connections = None;
    snapshot.artifact_path = None;
    snapshot.provider_snapshot_id = None;
    snapshot.checksum_sha256 = Some(manifest.sha256);
    snapshot.artifact_size_bytes = Some(manifest.size);
    Ok(BackupRestore {
        environment: manifest.environment,
        snapshot: manifest.snapshot,
        connections: vec![],
        artifact_path: artifact,
    })
}

#[tauri::command]
pub async fn export_local_backup(
    environment_id: String,
    folder: String,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<String, String> {
    export_backup(environment_id, folder, &store, &runtime).await
}

pub(crate) async fn export_backup(
    environment_id: String,
    folder: String,
    store: &PlatformStore,
    runtime: &RuntimeManager,
) -> Result<String, String> {
    let lock = crate::commands::environment_network_lock(&environment_id).await;
    let _guard = lock.lock().await;
    crate::commands::factory_reset::ensure_complete(&store.snapshot()?, &environment_id)?;
    let environment = store.environment(&environment_id)?;
    supported(&environment)?;
    if environment.status != EnvironmentStatus::Stopped {
        return Err("Stop the environment before creating a consistent local backup".into());
    }
    let id = format!("snap-{}", Uuid::new_v4());
    let runtime_id = environment.runtime_id.as_deref().unwrap_or(&environment.id);
    let (path, size, checksum) = if environment.provider.as_ref().is_some_and(RuntimeProviderKind::is_container) {
        let artifact = runtime
            .create_container_snapshot(
                runtime_id,
                &id,
                &environment.runtime,
                environment.container_command.as_deref().unwrap_or_default(),
            )
            .await?;
        (artifact.path, artifact.size_bytes, artifact.checksum_sha256)
    } else {
        let disk = PathBuf::from(
            environment
                .runtime_path
                .as_deref()
                .ok_or("Missing environment disk")?,
        );
        let artifact = runtime
            .export_vm_disk(runtime_id, &disk, Path::new(&environment.runtime), &id)
            .await?;
        (artifact.path, artifact.size_bytes, artifact.checksum_sha256)
    };
    let snapshot = Snapshot {
        id: id.clone(),
        environment_id: environment.id.clone(),
        name: "Local backup".into(),
        created_at: chrono::Utc::now().to_rfc3339(),
        size_gb: size as f64 / 1_073_741_824.0,
        delta_gb: size as f64 / 1_073_741_824.0,
        encrypted: false,
        status: SnapshotStatus::Ready,
        provider_snapshot_id: None,
        artifact_path: None,
        artifact_size_bytes: Some(size),
        checksum_sha256: Some(checksum.clone()),
        environment_state: None,
        connections: None,
    };
    let mut portable = environment.clone();
    portable.runtime_id = None;
    portable.runtime_path = None;
    portable.control_endpoint = None;
    portable.console_endpoint = None;
    portable.sandbox_policy = None;
    let manifest = Manifest {
        // Older Yougori versions must reject secure backups rather than
        // quietly dropping TPM state while converting their disk payload.
        version: if environment.provider == Some(RuntimeProviderKind::Qemu)
            && crate::runtime::backup_has_vm_security(&path)? { 2 } else { 1 },
        environment: portable,
        snapshot,
        size,
        sha256: checksum,
    };
    let source = path.clone();
    let result =
        tokio::task::spawn_blocking(move || write_backup(Path::new(&folder), &manifest, &source))
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r);
    let cleanup = if environment.provider.as_ref().is_some_and(RuntimeProviderKind::is_container) {
        runtime.delete_container_snapshot(runtime_id, &id).await
    } else {
        runtime.remove_snapshot_artifact(&path).await
    };
    match (result, cleanup) {
        (Ok(path), Ok(())) => Ok(path.to_string_lossy().into_owned()),
        (Ok(path), Err(error)) => Err(format!(
            "Backup saved at {} but temporary snapshot cleanup failed: {error}",
            path.display()
        )),
        (Err(error), _) => Err(error),
    }
}

#[tauri::command]
pub async fn import_local_backup(
    path: String,
    target_provider: Option<RuntimeProviderKind>,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
    backup: State<'_, BackupManager>,
) -> Result<PlatformState, String> {
    import_backup_with_provider(path, target_provider, &store, &runtime, &backup).await
}

#[cfg(test)]
async fn import_backup(
    path: String,
    store: &PlatformStore,
    runtime: &RuntimeManager,
    backup: &BackupManager,
) -> Result<PlatformState, String> {
    import_backup_with_provider(path, None, store, runtime, backup).await
}

pub(crate) async fn import_backup_with_provider(
    path: String,
    target_provider: Option<RuntimeProviderKind>,
    store: &PlatformStore,
    runtime: &RuntimeManager,
    backup: &BackupManager,
) -> Result<PlatformState, String> {
    import_backup_options(path, target_provider, None, store, runtime, backup).await
}

async fn import_backup_options(
    path: String,
    target_provider: Option<RuntimeProviderKind>,
    copy: Option<(String, Option<String>)>,
    store: &PlatformStore,
    runtime: &RuntimeManager,
    backup: &BackupManager,
) -> Result<PlatformState, String> {
    if target_provider.as_ref().is_some_and(|p| !p.is_container()) {
        return Err("Backup engine conversion is only supported between the two container engines.".into());
    }
    if target_provider == Some(RuntimeProviderKind::YougoriCuda) {
        runtime.require_cuda_installation().await?;
    }
    let staging = backup.restore_root.clone();
    let mut restored = tokio::task::spawn_blocking(move || read_backup(Path::new(&path), &staging))
        .await
        .map_err(|e| e.to_string())??;
    if let Some((name, drive)) = copy {
        restored.environment.name = name;
        restored.environment.storage_drive = drive.clone();
        if let Err(error) = runtime.select_storage_drive(&restored.environment.id, drive.as_deref())
            .and_then(|()| runtime.inherit_storage(&restored.snapshot.id, &restored.environment.id)) {
            let _ = backup.delete_restore_artifact(&restored.artifact_path).await;
            return Err(error);
        }
    }
    if let Some(provider) = target_provider {
        if restored.environment.kind != EnvironmentKind::Container || !restored.environment.provider.as_ref().is_some_and(RuntimeProviderKind::is_container) {
            let _ = backup.delete_restore_artifact(&restored.artifact_path).await;
            return Err("A VM disk cannot be loaded into a container engine. Keep its original engine.".into());
        }
        restored.environment.provider = Some(provider);
        // A new engine grants no hardware or network access automatically.
        restored.environment.gpu_access = false;
        restored.environment.network_access = false;
    }
    let artifact = restored.artifact_path.clone();
    let environment_id = restored.environment.id.clone();
    let snapshot_id = restored.snapshot.id.clone();
    let is_container = restored.environment.provider.as_ref().is_some_and(RuntimeProviderKind::is_container);
    let preparation = async {
        if restored.environment.provider == Some(RuntimeProviderKind::YougoriCuda) {
            runtime.require_cuda_installation().await?;
        }
        if is_container {
            let provider = restored.environment.provider.as_ref().unwrap();
            runtime.register_container_provider(&environment_id, provider)?;
            runtime.register_snapshot_provider(&snapshot_id, provider)?;
        }
        Ok::<(), String>(())
    }.await;
    if let Err(error) = preparation {
        let cleanup = backup.delete_restore_artifact(&artifact).await;
        return Err(match cleanup { Ok(()) => error, Err(cleanup) => format!("{error}; {cleanup}") });
    }
    let result =
        crate::commands::install_restored_backup(restored, &store, &runtime, &backup).await;
    if let Err(error) = result {
        let state = store.snapshot()?;
        if state
            .environments
            .iter()
            .any(|env| env.id == environment_id)
        {
            return Err(format!(
                "The restored environment was saved, but follow-up maintenance failed: {error}"
            ));
        }
        let mut errors = vec![error];
        if is_container {
            if let Err(error) = runtime.delete_container(&environment_id).await {
                errors.push(format!("Clean up incomplete restored container: {error}"));
            }
            if let Err(error) = runtime
                .delete_container_snapshot(&environment_id, &snapshot_id)
                .await
            {
                errors.push(format!("Clean up imported snapshot: {error}"));
            }
        }
        if let Err(error) = backup.delete_restore_artifact(&artifact).await {
            errors.push(error);
        }
        return Err(errors.join("; "));
    }
    result
}

fn validate_copy_name(name: &str, state: &PlatformState) -> Result<(), String> {
    if name.trim().is_empty() || name.chars().count() > 80 || name.chars().any(char::is_control) {
        return Err("Enter a name of 1–80 characters without control characters".into());
    }
    if state.environments.iter().any(|environment| environment.name.eq_ignore_ascii_case(name)) {
        return Err("An environment with this name already exists".into());
    }
    Ok(())
}

#[tauri::command]
pub async fn duplicate_local_environment(
    environment_id: String,
    name: String,
    storage_drive: Option<String>,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
    backup: State<'_, BackupManager>,
) -> Result<PlatformState, String> {
    duplicate_local(&environment_id, name, storage_drive, &store, &runtime, &backup).await
}

pub(crate) async fn duplicate_local(
    environment_id: &str,
    name: String,
    storage_drive: Option<String>,
    store: &PlatformStore,
    runtime: &RuntimeManager,
    backup: &BackupManager,
) -> Result<PlatformState, String> {
    let state = store.snapshot()?;
    validate_copy_name(&name, &state)?;
    let source = state.environments.iter().find(|environment| environment.id == environment_id)
        .ok_or("Environment not found")?;
    supported(source)?;
    if source.status != EnvironmentStatus::Stopped {
        return Err("Stop the source environment before duplicating its disk and files".into());
    }
    // Keep the verified portable backup private and scoped to this operation.
    // The normal restore pipeline assigns independent disk, runtime and snapshot IDs.
    let root = runtime.environment_storage_root(source.runtime_id.as_deref().unwrap_or(environment_id))?;
    let temporary = tempfile::Builder::new().prefix("duplicate-").tempdir_in(root)
        .map_err(|error| format!("Prepare duplication: {error}"))?;
    let manifest = export_backup(environment_id.to_owned(), temporary.path().to_string_lossy().into_owned(), store, runtime).await?;
    import_backup_options(manifest, None, Some((name, storage_drive)), store, runtime, backup).await
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Manifest {
        let mut env: Environment = serde_json::from_value(serde_json::json!({
            "id":"env-original","name":"Original","kind":"container","provider":"yougoriOci",
            "status":"stopped","runtime":"alpine:latest","description":"test","createdAt":"2026-01-01T00:00:00Z",
            "cpuUsage":0,"memoryUsageGb":0,"storageDeltaGb":0,"networkRxMbps":0,
            "resourcePolicy":{"cpu":{"min":0.1,"preferred":1,"max":1,"current":0},"memoryGb":{"min":0.125,"preferred":0.25,"max":0.5,"current":0},"priority":"normal","dynamic":true}
        })).unwrap();
        env.kind = EnvironmentKind::Container;
        env.provider = Some(RuntimeProviderKind::YougoriOci);
        env.runtime = "alpine:latest".into();
        let snapshot = Snapshot {
            id: "old-snapshot".into(),
            environment_id: env.id.clone(),
            name: "Test".into(),
            created_at: "2026-01-01".into(),
            size_gb: 0.0,
            delta_gb: 0.0,
            encrypted: false,
            status: SnapshotStatus::Ready,
            provider_snapshot_id: None,
            artifact_path: Some("C:\\unsafe\\path".into()),
            artifact_size_bytes: Some(4),
            checksum_sha256: None,
            environment_state: None,
            connections: None,
        };
        Manifest {
            version: 1,
            environment: env,
            snapshot,
            size: 4,
            sha256: hex::encode(Sha256::digest(b"disk")),
        }
    }
    #[test]
    fn duplication_rejects_invalid_and_existing_names() {
        let temp = tempfile::tempdir().unwrap();
        let store = PlatformStore::load(temp.path().join("state.json")).unwrap();
        let mut state = store.snapshot().unwrap();
        state.environments = vec![fixture().environment];
        for name in ["", "  ", "Original", "ORIGINAL", "bad\nname"] {
            assert!(validate_copy_name(name, &state).is_err(), "{name:?}");
        }
        assert!(validate_copy_name(&"x".repeat(81), &state).is_err());
        assert!(validate_copy_name("Original copy", &state).is_ok());
    }

    #[test]
    fn local_round_trip_creates_independent_ids_and_preserves_settings() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let mut archive = tar::Builder::new(File::create(&source).unwrap());
        let json = br#"{"manifests":[{"annotations":{"io.containerd.image.name":"opendock.local/snapshots:old-snapshot"}}]}"#;
        for (name, bytes) in [
            ("index.json", json.as_slice()),
            ("blobs/sha256/test", b"disk".as_slice()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            archive.append_data(&mut header, name, bytes).unwrap();
        }
        archive.finish().unwrap();
        drop(archive);
        let mut manifest = fixture();
        let bytes = fs::read(&source).unwrap();
        manifest.size = bytes.len() as u64;
        manifest.sha256 = hex::encode(Sha256::digest(&bytes));
        let path = write_backup(temp.path(), &manifest, &source).unwrap();
        assert_eq!(path.file_name().unwrap(), "backup.yougori");
        // A backup made before the product rename is still a valid import.
        let legacy = path.with_file_name("backup.opendock");
        fs::copy(&path, &legacy).unwrap();
        let legacy_restored = read_backup(&legacy, temp.path()).unwrap();
        assert_eq!(legacy_restored.environment.runtime, manifest.environment.runtime);
        let restored = read_backup(&path, temp.path()).unwrap();
        let download = temp.path().join("complete-environment.yougori");
        let size = pack_download(&path, &download).unwrap();
        assert_eq!(size, fs::metadata(&download).unwrap().len());
        let downloaded_copy = read_backup(&download, temp.path()).unwrap();
        assert_ne!(downloaded_copy.environment.id, restored.environment.id);
        assert_eq!(downloaded_copy.environment.runtime, restored.environment.runtime);
        assert_eq!(downloaded_copy.environment.status, EnvironmentStatus::Stopped);
        assert!(downloaded_copy.connections.is_empty());
        assert_ne!(restored.environment.id, manifest.environment.id);
        assert_ne!(restored.snapshot.id, manifest.snapshot.id);
        assert_eq!(restored.environment.status, EnvironmentStatus::Stopped);
        assert_eq!(restored.environment.runtime, manifest.environment.runtime);
        assert_eq!(
            restored.environment.resource_policy.cpu.max,
            manifest.environment.resource_policy.cpu.max
        );
        assert!(restored.environment.runtime_path.is_none());
        assert!(restored.snapshot.artifact_path.is_none());
        assert!(restored.connections.is_empty());
        let mut restored_archive = tar::Archive::new(File::open(restored.artifact_path).unwrap());
        let mut entries = restored_archive.entries().unwrap();
        let mut metadata = String::new();
        entries
            .next()
            .unwrap()
            .unwrap()
            .read_to_string(&mut metadata)
            .unwrap();
        assert!(metadata.contains(&restored.snapshot.id));
        assert!(!metadata.contains("old-snapshot"));
        let mut layer = String::new();
        entries
            .next()
            .unwrap()
            .unwrap()
            .read_to_string(&mut layer)
            .unwrap();
        assert_eq!(layer, "disk");
        // Export again creates a separate folder, never replaces an existing backup.
        assert_ne!(write_backup(temp.path(), &manifest, &source).unwrap(), path);
    }
    #[test]
    fn download_archives_reject_links_duplicates_extra_paths_and_missing_payloads() {
        for mode in ["link", "duplicate", "extra", "missing", "bad-size"] {
            let directory = tempfile::tempdir().unwrap();
            let archive_path = directory.path().join("environment.yougori");
            let mut writer = tar::Builder::new(File::create(&archive_path).unwrap());
            let metadata = serde_json::to_vec(&fixture()).unwrap();
            let mut append = |name: &str, data: &[u8], link: bool| {
                let mut header = tar::Header::new_ustar(); header.set_mode(0o600);
                header.set_entry_type(if link { tar::EntryType::Symlink } else { tar::EntryType::Regular });
                if link { header.set_link_name("/private/secret").unwrap(); }
                header.set_size(data.len() as u64); header.set_cksum();
                writer.append_data(&mut header, name, data).unwrap();
            };
            append(MANIFEST, &metadata, false);
            if mode != "missing" { append(PAYLOAD, if mode == "bad-size" { b"bad" } else { b"disk" }, mode == "link"); }
            if mode == "duplicate" { append(MANIFEST, &metadata, false); }
            if mode == "extra" { append("untrusted-file", b"must not extract", false); }
            drop(append); writer.finish().unwrap(); drop(writer);
            assert!(read_backup(&archive_path, directory.path()).is_err(), "{mode}");
            assert!(!directory.path().join("untrusted-file").exists());
            assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1, "partial files were kept: {mode}");
        }
    }
    #[test]
    fn rejects_corruption_unknown_versions_and_unsupported_runtimes() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        fs::write(&source, b"disk").unwrap();
        let mut manifest = fixture();
        let path = write_backup(temp.path(), &manifest, &source).unwrap();
        fs::write(path.parent().unwrap().join(PAYLOAD), b"oops").unwrap();
        assert!(read_backup(&path, temp.path())
            .err()
            .unwrap()
            .contains("checksum"));
        assert!(!fs::read_dir(temp.path())
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with("local-")));
        manifest.version = 99;
        fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(read_backup(&path, temp.path())
            .err()
            .unwrap()
            .contains("version"));
        manifest.version = 1;
        manifest.environment.kind = EnvironmentKind::ComputerBranch;
        fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(read_backup(&path, temp.path()).is_err());
    }
    #[test]
    fn container_archive_paths_do_not_normalize_traversal_into_metadata() {
        for unsafe_path in ["../index.json", "./../../manifest.json", "/index.json", "C:/index.json", "dir\\index.json"] {
            assert!(container_archive_path(Path::new(unsafe_path)).is_err(), "{unsafe_path}");
        }
        assert_eq!(container_archive_path(Path::new("././index.json")).unwrap(), "index.json");
        assert_eq!(container_archive_path(Path::new("blobs/sha256/layer")).unwrap(), "blobs/sha256/layer");
        assert_eq!(container_archive_path(Path::new(".metadata")).unwrap(), ".metadata");
    }

    #[test]
    fn container_archive_rejects_outer_links_and_cleans_partial_output() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source.tar");
        let target = temp.path().join("retagged.tar");
        let mut archive = tar::Builder::new(File::create(&source).unwrap());
        let mut link = tar::Header::new_gnu();
        link.set_size(0);
        link.set_entry_type(tar::EntryType::Symlink);
        link.set_link_name("/outside").unwrap();
        link.set_cksum();
        archive.append_data(&mut link, "index.json", std::io::empty()).unwrap();
        archive.finish().unwrap();
        drop(archive);
        assert!(retag_container(&source, &target, "old", "new").is_err());
        assert!(!target.exists());
        assert!(source.exists());
    }
    #[test]
    fn failed_export_leaves_existing_files_untouched() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        fs::write(&source, b"bad!").unwrap();
        assert!(write_backup(temp.path(), &fixture(), &source).is_err());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
        assert_eq!(fs::read(source).unwrap(), b"bad!");
    }

    #[test]
    fn vm_headers_reject_external_backing_and_data_files() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vm");
        let mut header = [0u8; 104];
        header[..4].copy_from_slice(b"QFI\xfb");
        header[4..8].copy_from_slice(&3u32.to_be_bytes());
        fs::write(&path, header).unwrap();
        assert!(validate_standalone_vm(&path).is_ok());
        header[8..16].copy_from_slice(&104u64.to_be_bytes());
        fs::write(&path, header).unwrap();
        assert!(validate_standalone_vm(&path).is_err());
        header[8..16].fill(0);
        header[72..80].copy_from_slice(&4u64.to_be_bytes());
        fs::write(&path, header).unwrap();
        assert!(validate_standalone_vm(&path).is_err());
    }

    #[test]
    fn invalid_secure_vm_backup_removes_staged_disk_and_preserves_source() {
        let temp = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        // Pass the standalone-disk checks, but fail extension validation:
        // cluster_bits=0 is not a valid QCOW2 security extension area.
        let mut bytes = vec![0u8; 104];
        bytes[..4].copy_from_slice(b"QFI\xfb");
        bytes[4..8].copy_from_slice(&3u32.to_be_bytes());
        fs::write(&source, &bytes).unwrap();
        let mut manifest = fixture();
        manifest.version = 2;
        manifest.environment.kind = EnvironmentKind::FullVm;
        manifest.environment.provider = Some(RuntimeProviderKind::Qemu);
        manifest.size = bytes.len() as u64;
        manifest.sha256 = hex::encode(Sha256::digest(&bytes));
        let path = write_backup(temp.path(), &manifest, &source).unwrap();

        assert!(read_backup(&path, staging.path()).is_err());
        assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
        assert_eq!(fs::read(source).unwrap(), bytes);
        assert_eq!(fs::read(path.parent().unwrap().join(PAYLOAD)).unwrap(), bytes);
    }

    #[tokio::test]
    #[ignore = "boots an isolated microVM and verifies portable standalone disk backup/restore"]
    async fn real_micro_vm_local_backup_round_trip() -> Result<(), String> {
        let temp = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), temp.path())?;
        let store = PlatformStore::load(temp.path().join("platform-state.json"))?;
        let backup = BackupManager::new(temp.path())?;
        let mut env = fixture().environment;
        env.id = "env-local-vm-test".into();
        env.runtime_id = Some(env.id.clone());
        env.kind = EnvironmentKind::MicroVm;
        env.provider = Some(RuntimeProviderKind::Qemu);
        env.runtime = "builtin:alpine".into();
        let result = async {
            let vm = runtime.provision_micro_vm(&env.id, &env.runtime).await?;
            env.runtime_path = Some(vm.disk_path.to_string_lossy().into_owned());
            runtime.start_micro_vm(&env.id, &vm.disk_path, &vm.source_path, &env.resource_policy).await?;
            // Workspace request waits for the guest agent health endpoint after boot.
            runtime.workspace_request(&env, "/v1/terminal/create", serde_json::json!({"id":env.id,"sessionId":"backup-test","cols":80,"rows":24})).await?;
            let output = runtime.execute_micro_vm_command(&env.id, "printf portable-vm-backup > /root/backup-marker; sync").await?;
            if output.exit_code != 0 { return Err(output.stderr); }
            runtime.vm_action(&env.id, "stop").await?;
            store.mutate(|s| { s.environments = vec![env.clone()]; s.snapshots.clear(); s.connections.clear(); Ok(()) })?;
            let path = export_backup(env.id.clone(), destination.path().to_string_lossy().into_owned(), &store, &runtime).await?;
            let state = import_backup(path, &store, &runtime, &backup).await?;
            let restored = state.environments.iter().find(|e| e.id != env.id).ok_or("Missing restored VM")?;
            let manifest = runtime.restore_builtin_micro_vm_manifest(&restored.id).await?;
            runtime.start_micro_vm(&restored.id, Path::new(restored.runtime_path.as_deref().unwrap()), &manifest, &restored.resource_policy).await?;
            runtime.workspace_request(restored, "/v1/terminal/create", serde_json::json!({"id":restored.id,"sessionId":"backup-restored-test","cols":80,"rows":24})).await?;
            let output = runtime.execute_micro_vm_command(&restored.id, "cat /root/backup-marker").await?;
            if output.exit_code != 0 || output.stdout.trim() != "portable-vm-backup" { return Err(format!("Restored VM file mismatch: {} {}", output.stdout, output.stderr)); }
            Ok(())
        }.await;
        runtime.shutdown_all().await;
        result
    }

    #[tokio::test]
    #[ignore = "boots an isolated managed container and verifies portable disk backup/restore"]
    async fn real_container_local_backup_round_trip() -> Result<(), String> {
        let temp = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), temp.path())?;
        let store = PlatformStore::load(temp.path().join("platform-state.json"))?;
        let backup = BackupManager::new(temp.path())?;
        let mut env = fixture().environment;
        env.id = "env-local-backup-test".into();
        env.runtime_id = Some(env.id.clone());
        env.runtime = "quay.io/libpod/alpine:latest".into();
        env.container_command = Some("sleep 2147483647".into());
        env.status = EnvironmentStatus::Stopped;
        env.resource_policy.cpu.max = 1.0;
        env.resource_policy.cpu.preferred = 1.0;
        env.resource_policy.cpu.min = 0.1;
        env.resource_policy.memory_gb.max = 0.5;
        env.resource_policy.memory_gb.preferred = 0.25;
        env.resource_policy.memory_gb.min = 0.125;
        let result = async {
            runtime
                .provision_container(
                    &env.id,
                    &env.runtime,
                    env.container_command.as_deref().unwrap(),
                    &env.resource_policy,
                    true,
                    false,
                )
                .await?;
            runtime.container_action(&env.id, "start", true).await?;
            let output = runtime
                .execute_container_command(
                    &env.id,
                    "printf portable-backup-test > /root/backup-marker",
                )
                .await?;
            if output.exit_code != 0 {
                return Err(output.stderr);
            }
            runtime.container_action(&env.id, "stop", true).await?;
            store.mutate(|s| {
                s.environments = vec![env.clone()];
                s.snapshots.clear();
                s.connections.clear();
                Ok(())
            })?;
            let path = export_backup(
                env.id.clone(),
                destination.path().to_string_lossy().into_owned(),
                &store,
                &runtime,
            )
            .await?;
            let state = import_backup(path, &store, &runtime, &backup).await?;
            assert_eq!(state.environments.len(), 2);
            let restored = state.environments.iter().find(|e| e.id != env.id).unwrap();
            assert_eq!(restored.status, EnvironmentStatus::Stopped);
            runtime
                .container_action(&restored.id, "start", true)
                .await?;
            let output = runtime
                .execute_container_command(&restored.id, "cat /root/backup-marker")
                .await?;
            assert_eq!(output.stdout.trim(), "portable-backup-test");
            assert_eq!(output.exit_code, 0);
            let state = duplicate_local(&env.id, "Independent copy".into(), None, &store, &runtime, &backup).await?;
            let copy = state.environments.iter().find(|item| item.name == "Independent copy").unwrap();
            assert_ne!(copy.id, env.id);
            assert_ne!(copy.runtime_id, env.runtime_id);
            assert_eq!(copy.status, EnvironmentStatus::Stopped);
            assert_eq!(copy.container_command, env.container_command);
            runtime.container_action(&copy.id, "start", true).await?;
            let output = runtime.execute_container_command(&copy.id, "cat /root/backup-marker; printf copy-only > /root/backup-marker").await?;
            assert_eq!(output.exit_code, 0);
            assert_eq!(output.stdout.trim(), "portable-backup-test");
            runtime.container_action(&env.id, "start", true).await?;
            let output = runtime.execute_container_command(&env.id, "cat /root/backup-marker").await?;
            assert_eq!(output.stdout.trim(), "portable-backup-test");
            assert!(!std::fs::read_dir(runtime.environment_storage_root(&env.id)?).unwrap().any(|entry| entry.unwrap().file_name().to_string_lossy().starts_with("duplicate-")));
            Ok(())
        }
        .await;
        runtime.shutdown_all().await;
        result
    }
}
