use std::{
    fs,
    io,
    path::{Path, PathBuf},
};
#[cfg(target_os = "windows")]
use std::{
    ffi::OsStr,
    fs::File,
    io::{Read, Write},
    process::Stdio,
    sync::Arc,
};

#[cfg(target_os = "windows")]
use std::os::windows::fs::FileExt;

use serde::{Deserialize, Serialize};
#[cfg(target_os = "windows")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "windows")]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
#[cfg(target_os = "windows")]
use uuid::Uuid;

use super::{vm::VmProvisionResult, BranchBlockServer, RuntimeManager};
#[cfg(target_os = "windows")]
use super::{command_output, configure_background_process, path_string};
use crate::models::BranchType;

const BRANCH_METADATA_VERSION: u32 = 1;
#[cfg(any(target_os = "windows", test))]
const BRANCH_BOOT_LABEL: &str = "YougoriEFI";
#[cfg(target_os = "windows")]
const SECTOR_SIZE: u64 = 512;
#[cfg(target_os = "windows")]
const MIN_PARTITION_START_LBA: u64 = 2048;
#[cfg(target_os = "windows")]
const GPT_ENTRY_COUNT: u32 = 128;
#[cfg(target_os = "windows")]
const GPT_ENTRY_SIZE: u32 = 128;
#[cfg(target_os = "windows")]
const GPT_ENTRY_SECTORS: u64 = (GPT_ENTRY_COUNT as u64 * GPT_ENTRY_SIZE as u64) / SECTOR_SIZE;
const MAX_BRANCH_METADATA_BYTES: u64 = 64 * 1024;

#[cfg(target_os = "windows")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShadowInfo {
    shadow_id: String,
    device_object: String,
    volume_size: u64,
    partition_start_lba: u64,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SystemPartitionInfo {
    volume_size: u64,
    partition_start_lba: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BranchMetadata {
    version: u32,
    shadow_id: String,
    shadow_device: String,
    source_volume: String,
    branch_type: BranchType,
    #[serde(default)]
    volume_size: u64,
    #[serde(default)]
    partition_start_lba: u64,
}

#[cfg(target_os = "windows")]
struct HostBootstrap {
    task_name: String,
    script_path: PathBuf,
}

#[cfg(target_os = "windows")]
struct SnapshotDisk {
    source: Arc<File>,
    volume_size: u64,
    partition_offset: u64,
    disk_size: u64,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
}

impl RuntimeManager {
    #[cfg(not(target_os = "windows"))]
    pub(super) async fn start_computer_branch_block_server(&self, _id: &str) -> Result<BranchBlockServer, String> {
        Err("Computer branches are available on Windows only".into())
    }
    #[cfg(target_os = "windows")]
    pub(super) async fn start_computer_branch_block_server(
        &self,
        id: &str,
    ) -> Result<BranchBlockServer, String> {
        let metadata_path = self
            .data_root
            .join("environments")
            .join(id)
            .join("branch.json");
        let metadata = read_branch_metadata(&metadata_path)?;
        let source = Arc::new(File::open(&metadata.shadow_device).map_err(|error| {
            format!(
                "open immutable Windows snapshot {}: {error}",
                metadata.shadow_device
            )
        })?);
        if metadata.volume_size == 0 || metadata.partition_start_lba == 0 {
            return Err(
                "computer branch metadata has not been migrated to a partitioned disk".into(),
            );
        }
        start_read_only_block_server(
            source,
            metadata.volume_size,
            metadata.partition_start_lba,
            &metadata.shadow_id,
        )
        .await
    }

    #[cfg(target_os = "windows")]
    pub(super) async fn prepare_computer_branch_overlay(
        &self,
        id: &str,
        disk_path: &Path,
    ) -> Result<(), String> {
        let metadata_path = self
            .data_root
            .join("environments")
            .join(id)
            .join("branch.json");
        let mut metadata = read_branch_metadata(&metadata_path)?;
        let current_size = read_qcow2_virtual_size(disk_path)?;
        let legacy_layout = metadata.partition_start_lba == 0;
        if metadata.volume_size == 0 {
            metadata.volume_size = current_size;
        }
        if legacy_layout {
            let partition = system_partition_info().await?;
            metadata.volume_size = partition.volume_size;
            metadata.partition_start_lba = partition.partition_start_lba;
        }
        let expected_size = snapshot_disk_size(metadata.volume_size, metadata.partition_start_lba)?;
        if current_size == expected_size {
            write_json_atomic(&metadata_path, &metadata)?;
            command_output(
                &self.layout.qemu_img,
                &[
                    "rebase".into(),
                    "-u".into(),
                    "-b".into(),
                    String::new(),
                    path_string(disk_path),
                ],
                "verify current-computer branch backing metadata",
            )
            .await?;
            return Ok(());
        }
        if !legacy_layout && current_size != metadata.volume_size {
            return Err(format!(
                "computer branch disk has an unsupported virtual size: expected {expected_size} bytes, found {current_size}"
            ));
        }

        // Layout version 1 exposed the NTFS volume as an unpartitioned fixed
        // disk, which Windows Boot Manager cannot use reliably. Those branches
        // never reached Windows, so retain the old sparse overlay for recovery
        // and activate a correctly partitioned empty overlay.
        let default_legacy = disk_path.with_file_name("system.volume-layout-v1.qcow2");
        let legacy = if default_legacy.exists() {
            disk_path.with_file_name(format!(
                "system.volume-layout-v1-{}.qcow2",
                Uuid::new_v4().simple()
            ))
        } else {
            default_legacy
        };
        fs::rename(disk_path, &legacy)
            .map_err(|error| format!("preserve legacy computer branch overlay: {error}"))?;
        let create = command_output(
            &self.layout.qemu_img,
            &[
                "create".into(),
                "-f".into(),
                "qcow2".into(),
                path_string(disk_path),
                expected_size.to_string(),
            ],
            "migrate computer branch to a partitioned disk",
        )
        .await;
        if let Err(error) = create {
            let _ = fs::remove_file(disk_path);
            let _ = fs::rename(&legacy, disk_path);
            return Err(error);
        }
        if let Err(error) = write_json_atomic(&metadata_path, &metadata) {
            let _ = fs::remove_file(disk_path);
            let _ = fs::rename(&legacy, disk_path);
            return Err(error);
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub(super) async fn prepare_computer_branch_overlay(
        &self,
        _id: &str,
        _disk_path: &Path,
    ) -> Result<(), String> {
        Err("Current-computer branches are currently supported on Windows hosts".into())
    }

    #[cfg(target_os = "windows")]
    pub async fn provision_computer_branch(
        &self,
        id: &str,
        branch_type: &BranchType,
    ) -> Result<VmProvisionResult, String> {
        let _branch_operation = self.branch_operations.lock().await;
        if branch_type == &BranchType::CleanOs {
            return Err("Clean OS branches require Windows installation media".into());
        }
        ensure_windows_administrator().await?;
        self.cleanup_orphan_branch_boot_disks().await?;
        let environment_root = self.data_root.join("environments");
        let environment_directory = environment_root.join(id);
        if environment_directory.exists() {
            return Err("environment storage already exists".into());
        }
        fs::create_dir(&environment_directory).map_err(|error| {
            format!(
                "create computer branch storage {}: {error}",
                environment_directory.display()
            )
        })?;

        let bootstrap = match prepare_host_bootstrap(id, branch_type).await {
            Ok(bootstrap) => bootstrap,
            Err(error) => {
                let _ = fs::remove_dir(&environment_directory);
                return Err(error);
            }
        };
        let shadow_result = create_shadow_copy().await;
        let cleanup_result = match bootstrap {
            Some(bootstrap) => cleanup_host_bootstrap(&bootstrap).await,
            None => Ok(()),
        };
        let shadow = match (shadow_result, cleanup_result) {
            (Ok(shadow), Ok(())) => shadow,
            (Ok(shadow), Err(cleanup_error)) => {
                let _ = delete_shadow_copy(&shadow.shadow_id).await;
                let _ = fs::remove_dir(&environment_directory);
                return Err(format!(
                    "remove temporary host branch bootstrap: {cleanup_error}"
                ));
            }
            (Err(error), _) => {
                let _ = fs::remove_dir(&environment_directory);
                return Err(error);
            }
        };

        let disk_path = environment_directory.join("system.qcow2");
        let provision = async {
            command_output(
                &self.layout.qemu_img,
                &[
                    "create".into(),
                    "-f".into(),
                    "qcow2".into(),
                    path_string(&disk_path),
                    snapshot_disk_size(shadow.volume_size, shadow.partition_start_lba)?.to_string(),
                ],
                "create current-computer copy-on-write disk",
            )
            .await?;
            self.ensure_computer_branch_boot(id).await?;
            let firmware_vars = environment_directory.join("uefi-vars.fd");
            fs::copy(&self.layout.uefi_vars, &firmware_vars)
                .map_err(|error| format!("create branch firmware state: {error}"))?;
            let metadata = BranchMetadata {
                version: BRANCH_METADATA_VERSION,
                shadow_id: shadow.shadow_id.clone(),
                shadow_device: shadow.device_object.clone(),
                source_volume: system_drive(),
                branch_type: branch_type.clone(),
                volume_size: shadow.volume_size,
                partition_start_lba: shadow.partition_start_lba,
            };
            write_json_atomic(&environment_directory.join("branch.json"), &metadata)?;
            Ok::<(), String>(())
        }
        .await;
        if let Err(error) = provision {
            let _ = delete_shadow_copy(&shadow.shadow_id).await;
            if environment_directory.starts_with(&environment_root)
                && environment_directory != environment_root
            {
                let _ = fs::remove_dir_all(&environment_directory);
            }
            return Err(error);
        }
        Ok(VmProvisionResult {
            disk_path,
            source_path: PathBuf::from("current-computer"),
        })
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn provision_computer_branch(
        &self,
        _id: &str,
        _branch_type: &BranchType,
    ) -> Result<VmProvisionResult, String> {
        Err("Current-computer branches are currently supported on Windows hosts".into())
    }

    #[cfg(target_os = "windows")]
    pub async fn cleanup_orphan_branch_boot_disks(&self) -> Result<(), String> {
        let environments = self.data_root.join("environments");
        let canonical_environments = fs::canonicalize(&environments)
            .map_err(|error| format!("resolve computer branch storage: {error}"))?;
        let entries = fs::read_dir(&environments)
            .map_err(|error| format!("scan computer branch storage: {error}"))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| format!("inspect computer branch storage: {error}"))?;
            let file_type = entry
                .file_type()
                .map_err(|error| format!("inspect computer branch storage entry type: {error}"))?;
            if !file_type.is_dir() || file_type.is_symlink() {
                continue;
            }
            let directory = entry.path();
            let canonical_directory = fs::canonicalize(&directory).map_err(|error| {
                format!(
                    "resolve computer branch storage {}: {error}",
                    directory.display()
                )
            })?;
            if canonical_directory.parent() != Some(canonical_environments.as_path()) {
                return Err(format!(
                    "refusing orphan cleanup through redirected computer branch storage {}",
                    directory.display()
                ));
            }
            let temporary_vhdx = canonical_directory.join("branch-boot.vhdx");
            let temporary_metadata = match fs::symlink_metadata(&temporary_vhdx) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(format!(
                        "inspect orphaned computer branch boot disk: {error}"
                    ));
                }
            };
            if !temporary_metadata.is_file() || temporary_metadata.file_type().is_symlink() {
                return Err(format!(
                    "refusing to clean an unsafe computer branch boot disk {}",
                    temporary_vhdx.display()
                ));
            }
            if fs::canonicalize(&temporary_vhdx)
                .ok()
                .and_then(|path| path.parent().map(Path::to_path_buf))
                .as_deref()
                != Some(canonical_directory.as_path())
            {
                return Err("refusing to clean a redirected computer branch boot disk".into());
            }
            if !temporary_vhdx.exists() {
                continue;
            }
            detach_virtual_disk(&temporary_vhdx).await?;
            match fs::remove_file(&temporary_vhdx) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "remove orphaned computer branch boot disk {}: {error}",
                        temporary_vhdx.display()
                    ));
                }
            }
            for temporary_name in [
                "create-branch-boot.diskpart",
                "detach-branch-boot.diskpart",
                "branch-boot.qcow2.part",
            ] {
                let temporary = canonical_directory.join(temporary_name);
                match fs::symlink_metadata(&temporary) {
                    Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                        fs::remove_file(&temporary).map_err(|error| {
                            format!("remove orphaned branch temporary file: {error}")
                        })?;
                    }
                    Ok(_) => {
                        return Err(format!(
                            "refusing to remove unsafe branch temporary path {}",
                            temporary.display()
                        ));
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(format!("inspect branch temporary file: {error}"));
                    }
                }
            }
            match fs::remove_dir(&canonical_directory) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => {}
                Err(error) => {
                    return Err(format!("remove empty orphan branch directory: {error}"));
                }
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn cleanup_orphan_branch_boot_disks(&self) -> Result<(), String> {
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub async fn ensure_computer_branch_boot(&self, id: &str) -> Result<PathBuf, String> {
        let directory = self.data_root.join("environments").join(id);
        let output = directory.join("branch-boot.qcow2");
        if output.is_file() {
            return Ok(output);
        }
        fs::create_dir_all(&directory)
            .map_err(|error| format!("create computer branch directory: {error}"))?;
        // Earlier versions staged the temporary disk next to the environment.
        let legacy_vhdx = directory.join("branch-boot.vhdx");
        detach_virtual_disk(&legacy_vhdx).await?;
        match fs::remove_file(&legacy_vhdx) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("remove previous branch boot disk: {error}")),
        }
        // diskpart runs elevated and reads its script in a legacy code page.
        // Stage the script and temporary disk in a fresh, ASCII-only folder that
        // only SYSTEM and Administrators can change, instead of this user-writable
        // (possibly non-ASCII) profile path where another process could swap it.
        let program_data = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .ok_or("Windows ProgramData directory is unavailable")?;
        remove_stale_branch_boot_folders(&program_data).await;
        let work = program_data.join(format!("YougoriBranchBoot-{}", Uuid::new_v4().simple()));
        if !work.to_str().is_some_and(str::is_ascii) {
            return Err("Branch boot media needs an ASCII Windows ProgramData path".into());
        }
        create_protected_directory(&work)?;
        let temporary_vhdx = work.join("branch-boot.vhdx");
        let result = self.build_computer_branch_boot(&work, &temporary_vhdx, &output).await;
        let _ = fs::remove_file(&temporary_vhdx);
        let _ = fs::remove_dir(&work);
        result
    }

    #[cfg(target_os = "windows")]
    async fn build_computer_branch_boot(&self, work: &Path, temporary_vhdx: &Path, output: &Path) -> Result<PathBuf, String> {
        let create_script = format!(
            "create vdisk file=\"{}\" maximum=260 type=expandable\r\nselect vdisk file=\"{}\"\r\nattach vdisk\r\nconvert gpt\r\ncreate partition efi size=200\r\nformat quick fs=fat32 label=\"{}\"\r\nexit\r\n",
            temporary_vhdx.display(),
            temporary_vhdx.display(),
            BRANCH_BOOT_LABEL
        );
        let create_result = run_diskpart(work, "create-branch-boot", &create_script).await;
        if let Err(error) = create_result {
            let _ = detach_virtual_disk(&temporary_vhdx).await;
            return Err(error);
        }
        let drive_letter = match mount_vhd_drive_letter(&temporary_vhdx).await {
            Ok(letter) => letter,
            Err(error) => {
                return Err(match detach_virtual_disk(&temporary_vhdx).await {
                    Ok(()) => error,
                    Err(cleanup_error) => {
                        format!("{error}; cleanup branch boot disk: {cleanup_error}")
                    }
                });
            }
        };
        let mounted_root = PathBuf::from(format!("{drive_letter}:\\"));
        let prepare_result = async {
            command_output(
                &system_executable("bcdboot.exe")?,
                &[
                    format!("{}\\Windows", system_drive()),
                    "/s".into(),
                    format!("{drive_letter}:"),
                    "/f".into(),
                    "UEFI".into(),
                ],
                "write computer branch boot files",
            )
            .await?;
            let store = mounted_root.join("EFI/Microsoft/Boot/BCD");
            for (entry, key, value) in [
                ("{bootmgr}", "device", format!("partition={drive_letter}:")),
                ("{default}", "device", "locate=\\Windows".into()),
                ("{default}", "osdevice", "locate=\\Windows".into()),
                ("{default}", "detecthal", "Yes".into()),
            ] {
                command_output(
                    &system_executable("bcdedit.exe")?,
                    &[
                        "/store".into(),
                        path_string(&store),
                        "/set".into(),
                        entry.into(),
                        key.into(),
                        value,
                    ],
                    "configure computer branch boot entry",
                )
                .await?;
            }
            let fallback_directory = mounted_root.join("EFI/Boot");
            fs::create_dir_all(&fallback_directory)
                .map_err(|error| format!("create UEFI fallback directory: {error}"))?;
            fs::copy(
                mounted_root.join("EFI/Microsoft/Boot/bootmgfw.efi"),
                fallback_directory.join("bootx64.efi"),
            )
            .map_err(|error| format!("create UEFI fallback loader: {error}"))?;
            Ok::<(), String>(())
        }
        .await;
        let detach_result = detach_virtual_disk(&temporary_vhdx).await;
        if let Err(error) = prepare_result {
            let _ = fs::remove_file(&temporary_vhdx);
            return Err(match detach_result {
                Ok(()) => error,
                Err(detach_error) => format!("{error}; detach branch boot disk: {detach_error}"),
            });
        }
        detach_result?;
        let partial = output.with_extension("qcow2.part");
        let _ = fs::remove_file(&partial);
        command_output(
            &self.layout.qemu_img,
            &[
                "convert".into(),
                "-p".into(),
                "-f".into(),
                "vhdx".into(),
                "-O".into(),
                "qcow2".into(),
                "-c".into(),
                path_string(&temporary_vhdx),
                path_string(&partial),
            ],
            "convert computer branch boot disk",
        )
        .await?;
        command_output(
            &self.layout.qemu_img,
            &["check".into(), "-q".into(), path_string(&partial)],
            "verify computer branch boot disk",
        )
        .await?;
        fs::rename(&partial, output)
            .map_err(|error| format!("finalize computer branch boot disk: {error}"))?;
        let _ = fs::remove_file(temporary_vhdx);
        Ok(output.to_path_buf())
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn ensure_computer_branch_boot(&self, _id: &str) -> Result<PathBuf, String> {
        Err("Computer branch boot media can only be generated on Windows".into())
    }

    pub async fn delete_computer_branch_shadow(&self, id: &str) -> Result<(), String> {
        let Some(metadata_path) = verified_branch_metadata_path(&self.data_root, id)? else {
            return Ok(());
        };
        let metadata = read_branch_metadata(&metadata_path)?;
        delete_shadow_copy(&metadata.shadow_id).await
    }
}

fn verified_branch_metadata_path(data_root: &Path, id: &str) -> Result<Option<PathBuf>, String> {
    if id.is_empty()
        || matches!(id, "." | "..")
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("invalid computer branch identifier".into());
    }
    let environments_root = data_root.join("environments");
    let environment_directory = environments_root.join(id);
    let environment_metadata = match fs::symlink_metadata(&environment_directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("inspect computer branch storage: {error}")),
    };
    if !environment_metadata.is_dir() || environment_metadata.file_type().is_symlink() {
        return Err("refusing computer branch cleanup through an unsafe directory".into());
    }
    let canonical_root = fs::canonicalize(&environments_root)
        .map_err(|error| format!("resolve computer branch storage root: {error}"))?;
    let canonical_environment = fs::canonicalize(&environment_directory)
        .map_err(|error| format!("resolve computer branch storage: {error}"))?;
    if canonical_environment.parent() != Some(canonical_root.as_path()) {
        return Err("refusing computer branch cleanup outside runtime storage".into());
    }
    let metadata_path = canonical_environment.join("branch.json");
    match fs::symlink_metadata(&metadata_path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            Ok(Some(metadata_path))
        }
        Ok(_) => Err("refusing to read unsafe computer branch metadata".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("inspect computer branch metadata: {error}")),
    }
}

fn read_branch_metadata(path: &Path) -> Result<BranchMetadata, String> {
    let parent = path
        .parent()
        .ok_or("computer branch metadata has no parent directory")?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("inspect computer branch metadata directory: {error}"))?;
    let file_metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect computer branch metadata: {error}"))?;
    if !parent_metadata.is_dir()
        || parent_metadata.file_type().is_symlink()
        || !file_metadata.is_file()
        || file_metadata.file_type().is_symlink()
        || file_metadata.len() > MAX_BRANCH_METADATA_BYTES
    {
        return Err("computer branch metadata is not a safe bounded file".into());
    }
    let metadata: BranchMetadata = serde_json::from_slice(
        &fs::read(path).map_err(|error| format!("read computer branch metadata: {error}"))?,
    )
    .map_err(|error| format!("decode computer branch metadata: {error}"))?;
    if metadata.version != BRANCH_METADATA_VERSION {
        return Err("computer branch metadata version is unsupported".into());
    }
    Ok(metadata)
}

#[cfg(target_os = "windows")]
fn read_qcow2_virtual_size(path: &Path) -> Result<u64, String> {
    let mut file = File::open(path)
        .map_err(|error| format!("open computer branch overlay metadata: {error}"))?;
    let mut header = [0_u8; 32];
    file.read_exact(&mut header)
        .map_err(|error| format!("read computer branch overlay metadata: {error}"))?;
    if header[0..4] != [b'Q', b'F', b'I', 0xfb] {
        return Err("computer branch overlay is not a valid QCOW2 image".into());
    }
    let size = u64::from_be_bytes(header[24..32].try_into().unwrap());
    if size == 0 || !size.is_multiple_of(512) {
        return Err("computer branch overlay has an invalid virtual size".into());
    }
    Ok(size)
}

#[cfg(target_os = "windows")]
fn snapshot_disk_size(volume_size: u64, partition_start_lba: u64) -> Result<u64, String> {
    if volume_size == 0 || !volume_size.is_multiple_of(SECTOR_SIZE) {
        return Err("Windows snapshot has an invalid block size".into());
    }
    if partition_start_lba < MIN_PARTITION_START_LBA {
        return Err("Windows system partition has an invalid starting sector".into());
    }
    let volume_sectors = volume_size / SECTOR_SIZE;
    partition_start_lba
        .checked_add(volume_sectors)
        .and_then(|sectors| sectors.checked_add(GPT_ENTRY_SECTORS + 1))
        .and_then(|sectors| sectors.checked_mul(SECTOR_SIZE))
        .ok_or_else(|| "Windows snapshot is too large to expose as a virtual disk".into())
}

#[cfg(target_os = "windows")]
fn build_snapshot_disk(
    source: Arc<File>,
    volume_size: u64,
    partition_start_lba: u64,
    identity: &str,
) -> Result<SnapshotDisk, String> {
    let disk_size = snapshot_disk_size(volume_size, partition_start_lba)?;
    let volume_sectors = volume_size / SECTOR_SIZE;
    let last_lba = disk_size / SECTOR_SIZE - 1;
    let partition_last_lba = partition_start_lba + volume_sectors - 1;
    let backup_entries_lba = last_lba - GPT_ENTRY_SECTORS;
    let partition_offset = partition_start_lba * SECTOR_SIZE;
    let mut entries = vec![0_u8; (GPT_ENTRY_COUNT * GPT_ENTRY_SIZE) as usize];

    // Microsoft Basic Data partition type, encoded in GPT's mixed-endian GUID
    // byte order: EBD0A0A2-B9E5-4433-87C0-68B6B72699C7.
    entries[0..16].copy_from_slice(&[
        0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44, 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99,
        0xc7,
    ]);
    entries[16..32].copy_from_slice(&stable_disk_id(identity, b"partition"));
    entries[32..40].copy_from_slice(&partition_start_lba.to_le_bytes());
    entries[40..48].copy_from_slice(&partition_last_lba.to_le_bytes());
    for (index, unit) in "Windows".encode_utf16().enumerate() {
        let offset = 56 + index * 2;
        entries[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
    let entries_crc = crc32fast::hash(&entries);
    let disk_id = stable_disk_id(identity, b"disk");

    let mut prefix = vec![0_u8; 34 * SECTOR_SIZE as usize];
    // Protective MBR prevents legacy tools from treating the GPT disk as empty.
    prefix[446 + 1..446 + 4].fill(0xff);
    prefix[446 + 4] = 0xee;
    prefix[446 + 5..446 + 8].fill(0xff);
    prefix[446 + 8..446 + 12].copy_from_slice(&1_u32.to_le_bytes());
    prefix[446 + 12..446 + 16]
        .copy_from_slice(&u32::try_from(last_lba).unwrap_or(u32::MAX).to_le_bytes());
    prefix[510..512].copy_from_slice(&[0x55, 0xaa]);
    let primary_header = gpt_header(
        1,
        last_lba,
        backup_entries_lba - 1,
        &disk_id,
        2,
        entries_crc,
    );
    prefix[SECTOR_SIZE as usize..SECTOR_SIZE as usize * 2].copy_from_slice(&primary_header);
    let entries_start = SECTOR_SIZE as usize * 2;
    prefix[entries_start..entries_start + entries.len()].copy_from_slice(&entries);

    let mut suffix = vec![0_u8; ((GPT_ENTRY_SECTORS + 1) * SECTOR_SIZE) as usize];
    suffix[..entries.len()].copy_from_slice(&entries);
    let backup_header = gpt_header(
        last_lba,
        1,
        backup_entries_lba - 1,
        &disk_id,
        backup_entries_lba,
        entries_crc,
    );
    let header_start = GPT_ENTRY_SECTORS as usize * SECTOR_SIZE as usize;
    suffix[header_start..header_start + SECTOR_SIZE as usize].copy_from_slice(&backup_header);

    Ok(SnapshotDisk {
        source,
        volume_size,
        partition_offset,
        disk_size,
        prefix,
        suffix,
    })
}

#[cfg(target_os = "windows")]
fn stable_disk_id(identity: &str, purpose: &[u8]) -> [u8; 16] {
    let mut hash = Sha256::new();
    // Part of the stored disk identity; see legacy_names::SNAPSHOT_DISK_HASH_DOMAIN.
    hash.update(yougori_cli::legacy_names::SNAPSHOT_DISK_HASH_DOMAIN);
    hash.update(purpose);
    hash.update(b"\0");
    hash.update(identity.as_bytes());
    let digest = hash.finalize();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

#[cfg(target_os = "windows")]
fn gpt_header(
    current_lba: u64,
    backup_lba: u64,
    last_usable_lba: u64,
    disk_id: &[u8; 16],
    entries_lba: u64,
    entries_crc: u32,
) -> [u8; SECTOR_SIZE as usize] {
    let mut header = [0_u8; SECTOR_SIZE as usize];
    header[0..8].copy_from_slice(b"EFI PART");
    header[8..12].copy_from_slice(&0x0001_0000_u32.to_le_bytes());
    header[12..16].copy_from_slice(&92_u32.to_le_bytes());
    header[24..32].copy_from_slice(&current_lba.to_le_bytes());
    header[32..40].copy_from_slice(&backup_lba.to_le_bytes());
    header[40..48].copy_from_slice(&34_u64.to_le_bytes());
    header[48..56].copy_from_slice(&last_usable_lba.to_le_bytes());
    header[56..72].copy_from_slice(disk_id);
    header[72..80].copy_from_slice(&entries_lba.to_le_bytes());
    header[80..84].copy_from_slice(&GPT_ENTRY_COUNT.to_le_bytes());
    header[84..88].copy_from_slice(&GPT_ENTRY_SIZE.to_le_bytes());
    header[88..92].copy_from_slice(&entries_crc.to_le_bytes());
    let crc = crc32fast::hash(&header[..92]);
    header[16..20].copy_from_slice(&crc.to_le_bytes());
    header
}

#[cfg(target_os = "windows")]
fn read_snapshot_disk(disk: &SnapshotDisk, offset: u64, output: &mut [u8]) -> io::Result<()> {
    output.fill(0);
    let request_end = offset
        .checked_add(output.len() as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "block request overflow"))?;
    if request_end > disk.disk_size {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "block request exceeds synthetic snapshot disk",
        ));
    }
    copy_disk_segment(output, offset, &disk.prefix, 0);
    let volume_end = disk.partition_offset + disk.volume_size;
    let read_start = offset.max(disk.partition_offset);
    let read_end = request_end.min(volume_end);
    if read_start < read_end {
        let destination_start = (read_start - offset) as usize;
        let destination_end = (read_end - offset) as usize;
        let source_offset = read_start - disk.partition_offset;
        let mut completed = 0_usize;
        let destination = &mut output[destination_start..destination_end];
        while completed < destination.len() {
            let count = disk.source.seek_read(
                &mut destination[completed..],
                source_offset + completed as u64,
            )?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Windows snapshot ended before its advertised volume size",
                ));
            }
            completed += count;
        }
    }
    copy_disk_segment(output, offset, &disk.suffix, volume_end);
    Ok(())
}

#[cfg(target_os = "windows")]
fn copy_disk_segment(output: &mut [u8], request_offset: u64, segment: &[u8], segment_offset: u64) {
    let request_end = request_offset + output.len() as u64;
    let segment_end = segment_offset + segment.len() as u64;
    let copy_start = request_offset.max(segment_offset);
    let copy_end = request_end.min(segment_end);
    if copy_start >= copy_end {
        return;
    }
    let output_start = (copy_start - request_offset) as usize;
    let output_end = (copy_end - request_offset) as usize;
    let segment_start = (copy_start - segment_offset) as usize;
    let segment_end = (copy_end - segment_offset) as usize;
    output[output_start..output_end].copy_from_slice(&segment[segment_start..segment_end]);
}

#[cfg(target_os = "windows")]
async fn start_read_only_block_server(
    source: Arc<File>,
    volume_size: u64,
    partition_start_lba: u64,
    identity: &str,
) -> Result<BranchBlockServer, String> {
    let disk = Arc::new(build_snapshot_disk(
        source,
        volume_size,
        partition_start_lba,
        identity,
    )?);
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|error| format!("bind Windows snapshot block bridge: {error}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("read Windows snapshot block bridge address: {error}"))?
        .port();
    let export_name = Uuid::new_v4().simple().to_string();
    let expected_export = export_name.clone();
    let task = tokio::spawn(async move {
        // Serve clients independently so one idle or stalled local connection
        // cannot block QEMU from reconnecting. Dropping the set (when the
        // server task is aborted) also ends every client connection.
        const MAX_CLIENTS: usize = 8;
        let mut clients = tokio::task::JoinSet::new();
        while let Ok((stream, _)) = listener.accept().await {
            while clients.try_join_next().is_some() {}
            if clients.len() >= MAX_CLIENTS {
                continue;
            }
            let disk = Arc::clone(&disk);
            let expected_export = expected_export.clone();
            clients.spawn(async move {
                let _ = serve_read_only_nbd(stream, disk, &expected_export).await;
            });
        }
    });
    Ok(BranchBlockServer {
        port,
        export_name,
        task,
    })
}

#[cfg(target_os = "windows")]
async fn serve_read_only_nbd(
    mut stream: TcpStream,
    disk: Arc<SnapshotDisk>,
    expected_export: &str,
) -> Result<(), String> {
    const NBD_OPT_MAGIC: u64 = 0x4948_4156_454f_5054;
    const NBD_REQUEST_MAGIC: u32 = 0x2560_9513;
    const NBD_REPLY_MAGIC: u32 = 0x6744_6698;
    const NBD_FLAG_HAS_FLAGS: u16 = 1;
    const NBD_FLAG_READ_ONLY: u16 = 2;
    const NBD_OPT_EXPORT_NAME: u32 = 1;
    const NBD_CMD_READ: u16 = 0;
    const NBD_CMD_DISC: u16 = 2;
    const NBD_CMD_FLUSH: u16 = 3;
    const NBD_EIO: u32 = 5;
    const NBD_EINVAL: u32 = 22;
    const NBD_EROFS: u32 = 30;
    const MAX_READ_SIZE: u32 = 32 * 1024 * 1024;

    let negotiation = async {
        stream
            .write_all(b"NBDMAGIC")
            .await
            .map_err(|error| format!("write block bridge handshake: {error}"))?;
        stream
            .write_u64(NBD_OPT_MAGIC)
            .await
            .map_err(|error| format!("write block bridge version: {error}"))?;
        stream
            .write_u16(0)
            .await
            .map_err(|error| format!("write block bridge flags: {error}"))?;
        let _client_flags = stream
            .read_u32()
            .await
            .map_err(|error| format!("read block bridge client flags: {error}"))?;
        let option_magic = stream
            .read_u64()
            .await
            .map_err(|error| format!("read block bridge option magic: {error}"))?;
        let option = stream
            .read_u32()
            .await
            .map_err(|error| format!("read block bridge option: {error}"))?;
        let export_length = stream
            .read_u32()
            .await
            .map_err(|error| format!("read block bridge export length: {error}"))?;
        if option_magic != NBD_OPT_MAGIC || option != NBD_OPT_EXPORT_NAME || export_length > 4096 {
            return Err("snapshot block bridge received an invalid negotiation request".into());
        }
        let mut export = vec![0_u8; export_length as usize];
        stream
            .read_exact(&mut export)
            .await
            .map_err(|error| format!("read block bridge export name: {error}"))?;
        if export != expected_export.as_bytes() {
            return Err("snapshot block bridge rejected an unknown export".into());
        }
        stream
            .write_u64(disk.disk_size)
            .await
            .map_err(|error| format!("write block bridge size: {error}"))?;
        stream
            .write_u16(NBD_FLAG_HAS_FLAGS | NBD_FLAG_READ_ONLY)
            .await
            .map_err(|error| format!("write block bridge transmission flags: {error}"))?;
        stream
            .write_all(&[0_u8; 124])
            .await
            .map_err(|error| format!("finish block bridge handshake: {error}"))?;
        Ok::<(), String>(())
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), negotiation)
        .await
        .map_err(|_| "snapshot block bridge negotiation timed out".to_string())??;

    loop {
        let mut request = [0_u8; 28];
        match stream.read_exact(&mut request).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(format!("read block bridge request: {error}")),
        }
        let magic = u32::from_be_bytes(request[0..4].try_into().unwrap());
        let command = u16::from_be_bytes(request[6..8].try_into().unwrap());
        let handle: [u8; 8] = request[8..16].try_into().unwrap();
        let offset = u64::from_be_bytes(request[16..24].try_into().unwrap());
        let length = u32::from_be_bytes(request[24..28].try_into().unwrap());
        if magic != NBD_REQUEST_MAGIC {
            return Err("snapshot block bridge received an invalid request magic".into());
        }
        if command == NBD_CMD_DISC {
            return Ok(());
        }
        let mut reply = Vec::with_capacity(16 + length as usize);
        reply.extend_from_slice(&NBD_REPLY_MAGIC.to_be_bytes());
        let mut error_code = 0_u32;
        let mut payload = Vec::new();
        if command == NBD_CMD_READ {
            let valid_range = length <= MAX_READ_SIZE
                && offset
                    .checked_add(u64::from(length))
                    .is_some_and(|end| end <= disk.disk_size);
            if valid_range {
                let read_disk = Arc::clone(&disk);
                let read_result = tokio::task::spawn_blocking(move || {
                    let mut data = vec![0_u8; length as usize];
                    read_snapshot_disk(&read_disk, offset, &mut data)?;
                    Ok::<Vec<u8>, std::io::Error>(data)
                })
                .await;
                match read_result {
                    Ok(Ok(data)) => payload = data,
                    _ => error_code = NBD_EIO,
                }
            } else {
                error_code = NBD_EINVAL;
            }
        } else if command != NBD_CMD_FLUSH {
            error_code = NBD_EROFS;
            if command == 1 && length > 0 {
                if length > MAX_READ_SIZE {
                    return Err("snapshot block bridge rejected an oversized write".into());
                }
                let mut discarded = vec![0_u8; length as usize];
                stream
                    .read_exact(&mut discarded)
                    .await
                    .map_err(|error| format!("discard block bridge write: {error}"))?;
            }
        }
        reply.extend_from_slice(&error_code.to_be_bytes());
        reply.extend_from_slice(&handle);
        reply.extend_from_slice(&payload);
        stream
            .write_all(&reply)
            .await
            .map_err(|error| format!("write block bridge reply: {error}"))?;
    }
}

#[cfg(target_os = "windows")]
async fn ensure_windows_administrator() -> Result<(), String> {
    let script = r#"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { 'true' } else { 'false' }
"#;
    let output = run_powershell(script).await?;
    if String::from_utf8_lossy(&output).trim() == "true" {
        Ok(())
    } else {
        Err("Current-computer branches require administrator access. Close Yougori, open PowerShell as Administrator, then run `npm run desktop:dev` again.".into())
    }
}

#[cfg(target_os = "windows")]
async fn system_partition_info() -> Result<SystemPartitionInfo, String> {
    let script = r#"
$ErrorActionPreference = 'Stop'
$driveLetter = $env:SystemDrive.TrimEnd(':')
$partition = Get-Partition -DriveLetter $driveLetter
if ($null -eq $partition) { throw 'The Windows system partition could not be found' }
if (([uint64]$partition.Offset % 512) -ne 0) { throw 'The Windows system partition is not sector aligned' }
[pscustomobject]@{ volumeSize = [uint64]$partition.Size; partitionStartLba = [uint64]([uint64]$partition.Offset / 512) } | ConvertTo-Json -Compress
"#;
    let output = run_powershell(script).await?;
    let partition = serde_json::from_slice::<SystemPartitionInfo>(&output)
        .map_err(|error| format!("decode Windows system partition geometry: {error}"))?;
    if partition.partition_start_lba < MIN_PARTITION_START_LBA
        || partition.volume_size == 0
        || !partition.volume_size.is_multiple_of(SECTOR_SIZE)
    {
        return Err("The Windows system partition has an invalid starting sector".into());
    }
    Ok(partition)
}

#[cfg(target_os = "windows")]
async fn create_shadow_copy() -> Result<ShadowInfo, String> {
    let script = r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Creating a current-computer branch requires administrator access. Restart Yougori as administrator.'
}
$volume = "$env:SystemDrive\"
$driveLetter = $env:SystemDrive.TrimEnd(':')
$partition = Get-Partition -DriveLetter $driveLetter
if ($null -eq $partition) { throw 'The Windows system partition could not be found' }
if (([uint64]$partition.Offset % 512) -ne 0) { throw 'The Windows system partition is not sector aligned' }
$created = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{ Volume = $volume; Context = 'ClientAccessible' }
if ([int]$created.ReturnValue -ne 0) { throw "Volume Shadow Copy failed with code $($created.ReturnValue)" }
$shadow = Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object { $_.ID -eq $created.ShadowID } | Select-Object -First 1
if ($null -eq $shadow) { throw 'The new Volume Shadow Copy could not be found' }
[pscustomobject]@{ shadowId = [string]$shadow.ID; deviceObject = [string]$shadow.DeviceObject; volumeSize = [uint64]$partition.Size; partitionStartLba = [uint64]([uint64]$partition.Offset / 512) } | ConvertTo-Json -Compress
"#;
    let output = run_powershell(script).await?;
    serde_json::from_slice::<ShadowInfo>(&output)
        .map_err(|error| format!("decode Volume Shadow Copy result: {error}"))
}

#[cfg(target_os = "windows")]
async fn delete_shadow_copy(shadow_id: &str) -> Result<(), String> {
    let script = r#"
$ErrorActionPreference = 'Stop'
$shadow = Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object { $_.ID -eq $env:YOUGORI_SHADOW_ID } | Select-Object -First 1
if ($null -ne $shadow) { $shadow | Remove-CimInstance }
"#;
    run_powershell_with_env(script, [("YOUGORI_SHADOW_ID", OsStr::new(shadow_id))])
        .await
        .map(|_| ())
}

#[cfg(not(target_os = "windows"))]
async fn delete_shadow_copy(_shadow_id: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "windows")]
async fn prepare_host_bootstrap(
    id: &str,
    branch_type: &BranchType,
) -> Result<Option<HostBootstrap>, String> {
    let mode = match branch_type {
        BranchType::ExactCopy => return Ok(None),
        BranchType::AppsSettings => "apps-settings",
        BranchType::AppsOnly => "apps-only",
        BranchType::CleanOs => return Ok(None),
    };
    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .ok_or("Windows ProgramData directory is unavailable")?;
    // A SYSTEM ONSTART task runs this script. Standard users may create
    // entries under ProgramData (and own what they create there), so never
    // reuse a predictable path: create a fresh directory that only SYSTEM and
    // Administrators can change, and refuse anything that already exists.
    let directory = program_data.join(format!("YougoriBranch-{}", Uuid::new_v4().simple()));
    create_protected_directory(&directory)?;
    let compact_id = id.replace(|character: char| !character.is_ascii_alphanumeric(), "");
    let suffix = compact_id.chars().take(48).collect::<String>();
    let task_name = format!("YougoriBranch_{suffix}");
    let script_path = directory.join(format!("branch-{suffix}.ps1"));
    let script = branch_bootstrap_script(mode, &task_name);
    if let Err(error) = write_new_file_synced(&script_path, script.as_bytes()) {
        let _ = fs::remove_dir(&directory);
        return Err(error);
    }
    let task_command = format!(
        "\"{}\" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{}\"",
        system_executable("WindowsPowerShell/v1.0/powershell.exe")?.display(),
        script_path.display()
    );
    let create = command_output(
        &system_executable("schtasks.exe")?,
        &[
            "/Create".into(),
            "/TN".into(),
            task_name.clone(),
            "/SC".into(),
            "ONSTART".into(),
            "/RU".into(),
            "SYSTEM".into(),
            "/RL".into(),
            "HIGHEST".into(),
            "/TR".into(),
            task_command,
            "/F".into(),
        ],
        "register VM-only computer branch preparation",
    )
    .await;
    if let Err(error) = create {
        let _ = fs::remove_file(&script_path);
        let _ = fs::remove_dir(&directory);
        return Err(error);
    }
    Ok(Some(HostBootstrap {
        task_name,
        script_path,
    }))
}

#[cfg(target_os = "windows")]
async fn cleanup_host_bootstrap(bootstrap: &HostBootstrap) -> Result<(), String> {
    let deletion = command_output(
        &system_executable("schtasks.exe")?,
        &[
            "/Delete".into(),
            "/TN".into(),
            bootstrap.task_name.clone(),
            "/F".into(),
        ],
        "remove temporary host branch task",
    )
    .await;
    let file_deletion = match fs::remove_file(&bootstrap.script_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove temporary branch script: {error}")),
    };
    if let Some(directory) = bootstrap.script_path.parent() {
        let _ = fs::remove_dir(directory);
    }
    deletion.and(file_deletion)
}

/// Creates a new directory whose protected ACL grants access only to SYSTEM
/// and Administrators; files created inside inherit it. Fails if it exists.
#[cfg(target_os = "windows")]
fn create_protected_directory(path: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW, SECURITY_ATTRIBUTES},
        Storage::FileSystem::CreateDirectoryW,
    };
    let sddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)\0".encode_utf16().collect::<Vec<_>>();
    let wide = path.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<_>>();
    // SAFETY: the descriptor is produced and freed here; both strings are NUL-terminated.
    unsafe {
        let mut descriptor = std::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut descriptor, std::ptr::null_mut()) == 0 {
            return Err(format!("prepare protected branch bootstrap directory: {}", io::Error::last_os_error()));
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let created = CreateDirectoryW(wide.as_ptr(), &attributes);
        let error = io::Error::last_os_error();
        LocalFree(descriptor);
        if created == 0 {
            return Err(format!("create protected branch bootstrap directory {}: {error}", path.display()));
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn write_new_file_synced(path: &Path, contents: &[u8]) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    file.write_all(contents)
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("flush {}: {error}", path.display()))
}

#[cfg(target_os = "windows")]
fn branch_bootstrap_script(mode: &str, task_name: &str) -> String {
    let preparation = if mode == "apps-only" {
        r#"
$profiles = Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and $_.LocalPath -like "$env:SystemDrive\Users\*" }
foreach ($profile in $profiles) {
  try { $profile | Remove-CimInstance -ErrorAction Stop } catch {
    if (Test-Path -LiteralPath $profile.LocalPath) { Remove-Item -LiteralPath $profile.LocalPath -Recurse -Force -ErrorAction Stop }
  }
}
"#
    } else {
        r#"
$profiles = Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and $_.LocalPath -like "$env:SystemDrive\Users\*" }
$keep = @('AppData', 'NTUSER.DAT', 'NTUSER.DAT.LOG1', 'NTUSER.DAT.LOG2', 'NTUSER.INI', 'ntuser.dat{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf', 'ntuser.dat{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms', 'ntuser.dat{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms')
foreach ($profile in $profiles) {
  if (-not (Test-Path -LiteralPath $profile.LocalPath)) { continue }
  Get-ChildItem -LiteralPath $profile.LocalPath -Force | Where-Object { $keep -notcontains $_.Name } | Remove-Item -Recurse -Force -ErrorAction Stop
}
"#
    };
    format!(
        r#"$ErrorActionPreference = 'Stop'
$taskName = '{task_name}'
try {{
  $manufacturer = [string](Get-CimInstance Win32_ComputerSystem).Manufacturer
  if ($manufacturer -notmatch 'QEMU|Red Hat') {{ throw 'Yougori branch preparation refused to run outside the virtual machine' }}
{preparation}
  New-Item -ItemType Directory -Path "$env:ProgramData\Yougori" -Force | Out-Null
  Set-Content -LiteralPath "$env:ProgramData\Yougori\branch-preparation-complete.txt" -Value ([DateTimeOffset]::UtcNow.ToString('O')) -Encoding UTF8
}} finally {{
  & "$env:SystemRoot\System32\schtasks.exe" /Delete /TN $taskName /F | Out-Null
  Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue
}}
"#
    )
}

#[cfg(target_os = "windows")]
async fn run_powershell(script: &str) -> Result<Vec<u8>, String> {
    run_powershell_with_env(script, std::iter::empty::<(&str, &OsStr)>()).await
}

#[cfg(target_os = "windows")]
async fn run_powershell_with_env<'a, I>(script: &str, environment: I) -> Result<Vec<u8>, String>
where
    I: IntoIterator<Item = (&'a str, &'a OsStr)>,
{
    let executable = system_executable("WindowsPowerShell/v1.0/powershell.exe")?;
    let wrapped_script = format!(
        "$ErrorActionPreference = 'Stop'\ntry {{\n{script}\n}} catch {{\n[Console]::Error.Write($_.Exception.Message)\nexit 1\n}}"
    );
    let mut command = tokio::process::Command::new(&executable);
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
        ])
        .arg(&wrapped_script)
        .envs(environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_background_process(&mut command);
    let output = command
        .output()
        .await
        .map_err(|error| format!("start Windows branch operation: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if detail.is_empty() {
            format!("Windows branch operation failed with {}", output.status)
        } else {
            format!("Windows branch operation failed: {detail}")
        });
    }
    Ok(output.stdout)
}

#[cfg(target_os = "windows")]
fn system_executable(name: &str) -> Result<PathBuf, String> {
    let path = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .ok_or("Windows system directory is unavailable")?
        .join("System32")
        .join(name);
    if !path.is_file() {
        return Err(format!(
            "required Windows component is missing: {}",
            path.display()
        ));
    }
    Ok(path)
}

#[cfg(target_os = "windows")]
fn system_drive() -> String {
    std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into())
}

#[cfg(target_os = "windows")]
async fn mount_vhd_drive_letter(disk: &Path) -> Result<char, String> {
    let script = r#"
$ErrorActionPreference = 'Stop'
$disk = Get-DiskImage -ImagePath $env:YOUGORI_VHDX | Get-Disk
$partition = $disk | Get-Partition | Where-Object { [string]$_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' } | Select-Object -First 1
if ($null -eq $partition) { throw 'Windows could not find the EFI partition in the branch boot disk' }
if (-not $partition.DriveLetter) {
  $partition | Add-PartitionAccessPath -AssignDriveLetter
}
for ($attempt = 0; $attempt -lt 50; $attempt++) {
  Update-HostStorageCache
  $partition = Get-Partition -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber
  if ($partition.DriveLetter) {
    [Console]::Out.Write([string]$partition.DriveLetter)
    exit 0
  }
  Start-Sleep -Milliseconds 100
}
throw 'Windows did not expose a drive letter for the branch boot volume after 5 seconds'
"#;
    let output = run_powershell_with_env(script, [("YOUGORI_VHDX", disk.as_os_str())]).await?;
    let value = String::from_utf8_lossy(&output).trim().to_ascii_uppercase();
    let mut characters = value.chars();
    match (characters.next(), characters.next()) {
        (Some(letter @ 'D'..='Z'), None) => Ok(letter),
        _ => Err(format!(
            "Windows returned an invalid branch boot drive letter: {value}"
        )),
    }
}

/// Staging folders a crash left behind. Builds take minutes, so only folders untouched for a
/// day are removed: their disk is detached first, then only plain files inside are deleted.
#[cfg(target_os = "windows")]
async fn remove_stale_branch_boot_folders(program_data: &Path) {
    let Ok(entries) = fs::read_dir(program_data) else { return };
    for entry in entries.flatten() {
        let ours = entry.file_name().to_str().and_then(|name| name.strip_prefix("YougoriBranchBoot-"))
            .is_some_and(|id| id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let stale = entry.metadata().ok().filter(|meta| meta.is_dir())
            .and_then(|meta| meta.modified().ok()).and_then(|time| time.elapsed().ok())
            .is_some_and(|age| age > std::time::Duration::from_secs(86_400));
        if !ours || !stale || !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let work = entry.path();
        if detach_virtual_disk(&work.join("branch-boot.vhdx")).await.is_err() {
            continue;
        }
        for file in fs::read_dir(&work).into_iter().flatten().flatten() {
            if file.file_type().is_ok_and(|kind| kind.is_file()) {
                let _ = fs::remove_file(file.path());
            }
        }
        let _ = fs::remove_dir(&work);
    }
}

#[cfg(target_os = "windows")]
async fn run_diskpart(directory: &Path, name: &str, contents: &str) -> Result<(), String> {
    if !contents.is_ascii() {
        return Err("prepare computer branch boot disk: diskpart scripts must be ASCII".into());
    }
    let script_path = directory.join(format!("{name}.diskpart"));
    write_new_file_synced(&script_path, contents.as_bytes())?;
    let result = command_output(
        &system_executable("diskpart.exe")?,
        &["/s".into(), path_string(&script_path)],
        "prepare computer branch boot disk",
    )
    .await
    .map(|_| ())
    .map_err(compact_diskpart_error);
    let _ = fs::remove_file(script_path);
    result
}

#[cfg(any(target_os = "windows", test))]
fn compact_diskpart_error(error: String) -> String {
    let lower = error.to_ascii_lowercase();
    let marker = [
        "virtual disk service error:",
        "diskpart has encountered an error:",
    ]
    .iter()
    .filter_map(|marker| lower.find(marker))
    .min();
    match marker {
        Some(index) => format!(
            "prepare computer branch boot disk: {}",
            error[index..]
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        ),
        None => error,
    }
}

#[cfg(target_os = "windows")]
async fn detach_virtual_disk(disk: &Path) -> Result<(), String> {
    if !disk.is_file() {
        return Ok(());
    }
    let script = r#"
$image = Get-DiskImage -ImagePath $env:YOUGORI_VHDX
if ($image.Attached) {
  Dismount-DiskImage -ImagePath $env:YOUGORI_VHDX
}
"#;
    run_powershell_with_env(script, [("YOUGORI_VHDX", disk.as_os_str())])
        .await
        .map(|_| ())
}

#[cfg(target_os = "windows")]
fn write_file_synced(path: &Path, contents: &[u8]) -> Result<(), String> {
    let mut file =
        File::create(path).map_err(|error| format!("create {}: {error}", path.display()))?;
    file.write_all(contents)
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("flush {}: {error}", path.display()))
}

#[cfg(target_os = "windows")]
fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let temporary = path.with_extension("json.part");
    let contents = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("encode computer branch metadata: {error}"))?;
    write_file_synced(&temporary, &contents)?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("finalize computer branch metadata: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "windows")]
    fn vm_only_bootstrap_checks_virtual_hardware_and_cleans_itself() {
        let script = branch_bootstrap_script("apps-only", "YougoriBranch_test");
        assert!(script.contains("QEMU|Red Hat"));
        assert!(script.contains("Remove-CimInstance"));
        assert!(script.contains("Remove-Item -LiteralPath $PSCommandPath"));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn settings_bootstrap_preserves_profile_configuration_only() {
        let script = branch_bootstrap_script("apps-settings", "YougoriBranch_test");
        assert!(script.contains("'AppData'"));
        assert!(script.contains("$keep -notcontains $_.Name"));
    }

    #[test]
    fn branch_boot_label_fits_fat_volume_label_limit() {
        assert!(BRANCH_BOOT_LABEL.is_ascii());
        assert!(BRANCH_BOOT_LABEL.len() <= 11);
    }

    #[test]
    fn diskpart_errors_only_surface_the_actionable_failure() {
        let error = "prepare computer branch boot disk: Microsoft DiskPart version 10.0\r\n100 percent completed\r\nVirtual Disk Service error:\r\nThe specified drive letter is not free to be assigned.";
        assert_eq!(
            compact_diskpart_error(error.into()),
            "prepare computer branch boot disk: Virtual Disk Service error: The specified drive letter is not free to be assigned."
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn bundled_qemu_reads_the_loopback_snapshot_bridge() {
        let mut source = tempfile::NamedTempFile::new().unwrap();
        let contents = (0..1024_u32).flat_map(u32::to_be_bytes).collect::<Vec<_>>();
        source.write_all(&contents).unwrap();
        source.as_file().sync_all().unwrap();
        let read_handle = Arc::new(File::open(source.path()).unwrap());
        let partition_start_lba = 4096;
        let layout = build_snapshot_disk(
            Arc::clone(&read_handle),
            contents.len() as u64,
            partition_start_lba,
            "test",
        )
        .unwrap();
        let mut expected = tempfile::NamedTempFile::new().unwrap();
        let mut expected_contents = vec![0_u8; layout.disk_size as usize];
        read_snapshot_disk(&layout, 0, &mut expected_contents).unwrap();
        assert_eq!(&expected_contents[512..520], b"EFI PART");
        assert_eq!(
            &expected_contents[layout.partition_offset as usize
                ..layout.partition_offset as usize + contents.len()],
            &contents
        );
        expected.write_all(&expected_contents).unwrap();
        expected.as_file().sync_all().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let server = runtime
            .block_on(start_read_only_block_server(
                read_handle,
                contents.len() as u64,
                partition_start_lba,
                "test",
            ))
            .unwrap();
        let endpoint = format!("nbd://127.0.0.1:{}/{}", server.port, server.export_name);
        let qemu_img =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("resources/runtime/qemu/qemu-img.exe");
        let output = std::process::Command::new(&qemu_img)
            .args([
                "compare",
                "-f",
                "raw",
                "-F",
                "raw",
                &expected.path().to_string_lossy(),
                &endpoint,
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );

        let overlay_directory = tempfile::tempdir().unwrap();
        let overlay = overlay_directory.path().join("overlay.qcow2");
        let created = std::process::Command::new(&qemu_img)
            .args([
                "create",
                "-f",
                "qcow2",
                "-F",
                "raw",
                "-b",
                "unusable-embedded-backing-device",
                "-u",
                &overlay.to_string_lossy(),
                &layout.disk_size.to_string(),
            ])
            .output()
            .unwrap();
        assert!(
            created.status.success(),
            "{}",
            String::from_utf8_lossy(&created.stderr)
        );
        let rebased = std::process::Command::new(&qemu_img)
            .args(["rebase", "-u", "-b", "", &overlay.to_string_lossy()])
            .output()
            .unwrap();
        assert!(
            rebased.status.success(),
            "{}",
            String::from_utf8_lossy(&rebased.stderr)
        );
        let blockdev = serde_json::json!({
            "driver": "qcow2",
            "file": {
                "driver": "file",
                "filename": overlay.to_string_lossy()
            },
            "backing": {
                "driver": "nbd",
                "server": {
                    "type": "inet",
                    "host": "127.0.0.1",
                    "port": server.port.to_string()
                },
                "export": server.export_name,
                "read-only": true
            },
            "node-name": "test-overlay"
        })
        .to_string();
        let qemu_system = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("resources/runtime/qemu/qemu-system-x86_64.exe");
        let mut qemu = std::process::Command::new(qemu_system)
            .args([
                "-machine",
                "none",
                "-nodefaults",
                "-display",
                "none",
                "-blockdev",
                &blockdev,
                "-S",
            ])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(700));
        if let Some(status) = qemu.try_wait().unwrap() {
            let mut detail = String::new();
            qemu.stderr
                .take()
                .unwrap()
                .read_to_string(&mut detail)
                .unwrap();
            panic!("QEMU rejected the bridged backing graph with {status}: {detail}");
        }
        qemu.kill().unwrap();
        qemu.wait().unwrap();

        let backup = overlay_directory.path().join("standalone-backup.qcow2");
        let backup_source = format!(
            "json:{}",
            super::super::vm::branch_disk_graph(&overlay, &server, "test-backup-source")
        );
        let converted = std::process::Command::new(&qemu_img)
            .args([
                "convert",
                "-O",
                "qcow2",
                &backup_source,
                &backup.to_string_lossy(),
            ])
            .output()
            .unwrap();
        assert!(
            converted.status.success(),
            "{}",
            String::from_utf8_lossy(&converted.stderr)
        );
        let compared = std::process::Command::new(&qemu_img)
            .args([
                "compare",
                "-f",
                "raw",
                "-F",
                "qcow2",
                &expected.path().to_string_lossy(),
                &backup.to_string_lossy(),
            ])
            .output()
            .unwrap();
        assert!(
            compared.status.success(),
            "{}",
            String::from_utf8_lossy(&compared.stderr)
        );
    }
}
