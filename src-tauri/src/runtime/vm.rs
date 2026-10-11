use std::{
    collections::HashSet,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sysinfo::{Pid, ProcessesToUpdate};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use uuid::Uuid;

use super::{
    available_port, command_output, configure_background_process, path_string, AgentEndpoint,
    PerfSpan, RuntimeManager, VmProcess,
};
use crate::models::{CommandResult, ResourcePolicy};

#[derive(Debug, Clone)]
pub struct VmProvisionResult {
    pub disk_path: PathBuf,
    pub source_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct VmConsole {
    pub websocket_url: String,
    pub password: String,
    pub headless: bool,
    pub serial_log_path: Option<PathBuf>,
    pub guest_control_available: bool,
}

const SOURCE_CACHE_VERSION: u8 = 1;
const MICRO_VM_MANIFEST_VERSION: u8 = 1;
const VM_RESTORE_TRANSACTION_VERSION: u8 = 2;
const SOURCE_SAMPLE_BYTES: usize = 64 * 1024;
const MAX_MICRO_VM_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_RUNTIME_IDENTIFIER_BYTES: usize = 160;
const VM_STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const WHPX_STARTUP_TIMEOUT: Duration = Duration::from_secs(25);
static VM_BASE_OPERATIONS: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
static VM_PORT_RESERVATIONS: OnceLock<std::sync::Mutex<HashSet<u16>>> = OnceLock::new();

pub(super) struct VmPortReservations {
    ports: Vec<u16>,
}

impl VmPortReservations {
    pub(super) fn new() -> Self {
        Self { ports: Vec::new() }
    }

    pub(super) fn reserve_available(&mut self, excluded: &[u16]) -> Result<u16, String> {
        let mut reserved = vm_port_reservations()
            .lock()
            .map_err(|_| "virtual machine port reservation state is poisoned".to_string())?;
        for _ in 0..32 {
            let port = available_port()?;
            if excluded.contains(&port) || reserved.contains(&port) {
                continue;
            }
            reserved.insert(port);
            self.ports.push(port);
            return Ok(port);
        }
        Err("could not allocate a distinct local virtual machine port".into())
    }

    fn reserve_vnc_display(&mut self, excluded: &[u16]) -> Result<(u16, u16), String> {
        let mut reserved = vm_port_reservations()
            .lock()
            .map_err(|_| "virtual machine port reservation state is poisoned".to_string())?;
        for display in 100_u16..1000 {
            let port = 5900 + display;
            if excluded.contains(&port) || reserved.contains(&port) {
                continue;
            }
            if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
                reserved.insert(port);
                self.ports.push(port);
                return Ok((display, port));
            }
        }
        Err("could not allocate a local VNC port".into())
    }
}

impl Drop for VmPortReservations {
    fn drop(&mut self) {
        if let Ok(mut reserved) = vm_port_reservations().lock() {
            for port in self.ports.drain(..) {
                reserved.remove(&port);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct SourceIdentity {
    canonical_path: String,
    size_bytes: u64,
    modified_unix_nanos: Option<u64>,
    created_unix_nanos: Option<u64>,
    sample_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SourceChecksumCacheEntry {
    version: u8,
    identity: SourceIdentity,
    checksum_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VmRestoreTransaction {
    version: u8,
    had_previous_disk: bool,
    created_environment_directory: bool,
    #[serde(default)]
    security_changed: bool,
    #[serde(default)]
    previous_security: Option<super::vm_security::Profile>,
    #[serde(default)]
    next_security: Option<super::vm_security::Profile>,
}

#[derive(Debug, Serialize)]
struct MicroVmExecRequest<'a> {
    command: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MicroVmCommandOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

/// Guest agents that can retire their boot credential report it as "boot"
/// until the host replaces it; older agents omit the field.
#[derive(Debug, Default, Deserialize)]
struct MicroVmHealth {
    #[serde(default)]
    credential: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MicroVmSourceManifest {
    kernel: PathBuf,
    #[serde(default)]
    initrd: Option<PathBuf>,
    disk: PathBuf,
    #[serde(default = "default_micro_vm_cmdline")]
    cmdline: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManagedMicroVmManifest {
    version: u8,
    #[serde(default)]
    builtin: bool,
    kernel: PathBuf,
    #[serde(default)]
    initrd: Option<PathBuf>,
    cmdline: String,
}

#[derive(Debug, Clone)]
enum VmLaunchProfile {
    Full {
        source_path: PathBuf,
        gpu_access: bool,
        network_access: bool,
    },
    Micro(ManagedMicroVmManifest, bool),
}

#[derive(Debug, Clone)]
pub struct VmArtifact {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub checksum_sha256: String,
}

#[derive(Debug, Deserialize)]
struct ImageInfo {
    format: String,
    #[serde(default, rename = "virtual-size")]
    virtual_size: u64,
    #[serde(default, rename = "actual-size")]
    actual_size: u64,
}

#[derive(Debug, Deserialize)]
struct BackingImageInfo {
    #[serde(default, rename = "full-backing-filename")]
    full_backing_filename: Option<PathBuf>,
    #[serde(default, rename = "backing-filename")]
    backing_filename: Option<PathBuf>,
    #[serde(default, rename = "backing-filename-format")]
    backing_format: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct VmStorageUsage {
    pub physical_bytes: u64,
    pub logical_bytes: u64,
}

#[derive(Debug, Clone, Default)]
pub struct VmStats {
    pub cpu_percent: f64,
    pub memory_bytes: u64,
}

impl RuntimeManager {
    pub async fn vm_storage_allocation(&self, id: &str, disk: &Path) -> Result<super::storage::StorageAllocation, String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.vm_storage_allocation(id, disk)).await; }

        validate_runtime_identifier("virtual machine", id)?;
        let lock = self.vm_lifecycle_mutex(id).await;
        let _guard = lock.lock().await;
        verify_environment_artifact(&self.data_root, id, disk, "virtual machine disk")?;
        self.inspect_storage(disk, false).await
    }

    pub async fn grow_vm_storage(&self, id: &str, disk: &Path, capacity_gb: f64) -> Result<super::storage::StorageAllocation, String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.grow_vm_storage(id, disk, capacity_gb)).await; }

        validate_runtime_identifier("virtual machine", id)?;
        let lock = self.vm_lifecycle_mutex(id).await;
        let _guard = lock.lock().await;
        verify_environment_artifact(&self.data_root, id, disk, "virtual machine disk")?;
        ensure_no_pending_vm_restore(&self.data_root, id)?;
        if let Some(process) = self.vms.lock().await.get_mut(id) {
            if process.child.try_wait().map_err(|e| e.to_string())?.is_none() {
                return Err("Stop the VM before expanding storage.".into());
            }
        }
        self.grow_disk(disk, capacity_gb, false).await
    }

    async fn live_vm_qmp_port(&self, id: &str) -> Option<u16> {
        let mut processes = self.vms.lock().await;
        processes.get_mut(id).and_then(|process| {
            if process.child.try_wait().ok().flatten().is_none() {
                Some(process.qmp_port)
            } else {
                None
            }
        })
    }

    pub(super) async fn vm_lifecycle_mutex(&self, id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut lifecycle = self.vm_lifecycle.lock().await;
        lifecycle.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = lifecycle.get(id).and_then(std::sync::Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        lifecycle.insert(id.to_owned(), Arc::downgrade(&lock));
        lock
    }

    pub async fn vm_process_stats(&self, id: &str) -> Result<VmStats, String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.vm_process_stats(id)).await; }

        validate_runtime_identifier("virtual machine", id)?;
        let (process_id, allocated_cpus) = {
            let processes = self.vms.lock().await;
            let process = processes
                .get(id)
                .ok_or_else(|| "virtual machine is not running".to_string())?;
            (process.process_id, process.allocated_cpus.max(1))
        };
        let pid = Pid::from_u32(process_id);
        let mut system = self.process_metrics.lock().await;
        system.refresh_processes(ProcessesToUpdate::Some(&[pid]), false);
        let process = system
            .process(pid)
            .ok_or_else(|| "virtual machine process metrics are unavailable".to_string())?;
        Ok(VmStats {
            cpu_percent: f64::from(process.cpu_usage()) / allocated_cpus as f64,
            memory_bytes: process.memory(),
        })
    }

    pub async fn vm_storage_usage(&self, disk_path: &Path) -> Result<VmStorageUsage, String> {
        if let Some(engine) = self.storage_runtime_for_path(disk_path)? { return Box::pin(engine.vm_storage_usage(disk_path)).await; }

        let mut paths = vec![(disk_path.to_path_buf(), false)];
        if let Some(directory) = disk_path.parent() {
            let branch_boot = directory.join("branch-boot.qcow2");
            if branch_boot.is_file() {
                paths.push((branch_boot, false));
            }
            paths.extend(super::import_drive::storage_paths(directory)?.into_iter().map(|path| (path, true)));
        }
        let mut usage = VmStorageUsage::default();
        for (path, raw) in paths {
            let mut arguments = vec!["info".into(), "--force-share".into(), "--output=json".into()];
            if raw { arguments.extend(["-f".into(), "raw".into()]); }
            arguments.push(path_string(&path));
            let output = command_output(
                &self.layout.qemu_img,
                &arguments,
                "inspect virtual machine storage",
            )
            .await?;
            let info = serde_json::from_slice::<ImageInfo>(&output.stdout)
                .map_err(|error| format!("decode virtual machine storage information: {error}"))?;
            usage.physical_bytes = usage.physical_bytes.saturating_add(info.actual_size);
            usage.logical_bytes = usage.logical_bytes.saturating_add(info.virtual_size);
        }
        Ok(usage)
    }

    pub async fn provision_vm(&self, id: &str, source: &str) -> Result<VmProvisionResult, String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.provision_vm(id, source)).await; }

        self.provision_vm_with_storage(id, source, None).await
    }

    /// Create a fresh generation from a microVM's immutable base, never its writable disk.
    pub async fn provision_reset_micro_vm(&self, old_id: &str, new_id: &str, disk: &Path) -> Result<VmProvisionResult, String> {
        self.inherit_storage(new_id, old_id)?;
        if let Some(engine) = self.storage_runtime(old_id)? { return Box::pin(engine.provision_reset_micro_vm(old_id, new_id, disk)).await; }

        validate_runtime_identifier("microVM", old_id)?;
        validate_runtime_identifier("microVM", new_id)?;
        if old_id == new_id { return Err("Factory reset needs a separate disk generation".into()); }
        let old_lock = self.vm_lifecycle_mutex(old_id).await;
        let _old_guard = old_lock.lock().await;
        ensure_no_pending_vm_restore(&self.data_root, old_id)?;
        if self.vm_is_running(old_id).await? { return Err("Stop the microVM before factory reset".into()); }
        let root = verified_runtime_subdirectory(&self.data_root, "environments", "environment storage root")?;
        let old = checked_runtime_child(&root, old_id, "microVM")?;
        require_verified_direct_child(&old, disk, PathKind::File, "microVM reset disk")?;
        let manifest = read_managed_micro_vm_manifest(&old.join("microvm.json")).await?;
        let capacity = self.inspect_storage(disk, false).await?.capacity_gb;
        let output = command_output(&self.layout.qemu_img, &["info".into(), "--output=json".into(), path_string(disk)], "inspect microVM original base").await?;
        let info: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
        let base = match info["full-backing-filename"].as_str().or_else(|| info["backing-filename"].as_str()) {
            Some(path) => { let path = PathBuf::from(path); if path.is_absolute() { path } else { old.join(path) } },
            None if manifest.builtin => self.layout.appliance_base.clone(),
            None => return Err("This imported microVM backup has no original base disk. Import its original image to create a fresh microVM; the current disk was not changed.".into()),
        };
        let _bases = vm_base_operations().lock().await;
        let canonical = fs::canonicalize(&base).map_err(|e| format!("Find original microVM base: {e}"))?;
        if canonical != fs::canonicalize(&self.layout.appliance_base).map_err(|e| e.to_string())? {
            let bases = verified_runtime_subdirectory(&self.data_root, "bases", "VM base storage")?;
            require_verified_direct_child(&bases, &base, PathKind::File, "original microVM base")?;
        }
        let lock = self.vm_lifecycle_mutex(new_id).await;
        let _guard = lock.lock().await;
        let directory = checked_runtime_child(&root, new_id, "fresh microVM")?;
        fs::create_dir(&directory).map_err(|e| format!("Create fresh microVM: {e}"))?;
        let result = async {
            let disk_path = directory.join("system.qcow2");
            command_output(&self.layout.qemu_img, &["create".into(), "-f".into(), "qcow2".into(), "-F".into(), "qcow2".into(), "-b".into(), path_string(&canonical), path_string(&disk_path)], "create fresh microVM disk").await?;
            if capacity > self.inspect_storage(&disk_path, false).await?.capacity_gb { self.grow_disk(&disk_path, capacity, false).await?; }
            let source_path = directory.join("microvm.json");
            write_durable_file(source_path.clone(), serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?).await?;
            Ok(VmProvisionResult { disk_path, source_path })
        }.await;
        if result.is_err() { let _ = remove_verified_directory(&root, &directory, "failed fresh microVM").await; }
        result
    }

    pub async fn provision_reset_full_vm(&self, old_id: &str, new_id: &str, source: &str, disk: &Path) -> Result<VmProvisionResult, String> {
        self.inherit_storage(new_id, old_id)?;
        if let Some(engine) = self.storage_runtime(old_id)? { return Box::pin(engine.provision_reset_full_vm(old_id, new_id, source, disk)).await; }

        validate_runtime_identifier("virtual machine", old_id)?;
        validate_runtime_identifier("virtual machine", new_id)?;
        if old_id == new_id { return Err("Factory reset needs a separate disk generation".into()); }
        let lock = self.vm_lifecycle_mutex(old_id).await;
        let _guard = lock.lock().await;
        ensure_no_pending_vm_restore(&self.data_root, old_id)?;
        if self.vm_is_running(old_id).await? { return Err("Stop the VM before factory reset".into()); }
        let root = verified_runtime_subdirectory(&self.data_root, "environments", "environment storage root")?;
        let old = checked_runtime_child(&root, old_id, "virtual machine")?;
        require_verified_direct_child(&old, disk, PathKind::File, "VM reset disk")?;
        let secure = super::vm_security::profile(&old)?.is_some();
        let capacity = self.inspect_storage(disk, false).await?.capacity_gb.ceil();
        let fresh = self.provision_vm_with_storage(new_id, source, Some(capacity)).await?;
        // Managed media have hash filenames; retain the original security choice
        // even when custom media were initially detected by their filename only.
        let directory = fresh.disk_path.parent().ok_or("Fresh VM disk has no directory")?;
        if let Err(error) = super::vm_security::prepare_required(&self.layout, directory, Path::new(source), secure).await {
            self.delete_vm(new_id).await?;
            return Err(error);
        }
        Ok(fresh)
    }

    pub async fn provision_vm_with_storage(&self, id: &str, source: &str, storage_gb: Option<f64>) -> Result<VmProvisionResult, String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.provision_vm_with_storage(id, source, storage_gb)).await; }

        let disk_bytes = super::storage::storage_bytes(storage_gb.unwrap_or(64.0))?;
        if let Some(gb) = storage_gb {
            let maximum = self.new_vm_storage()?.maximum_gb;
            if gb > maximum {
                return Err(format!("Requested {gb:.0} GB, but only {maximum:.0} GB is available for a new VM on the Yougori drive (2 GB is kept free for the host). Choose a smaller disk or free space on that drive."));
            }
        }
        validate_runtime_identifier("virtual machine", id)?;
        let lifecycle_lock = self.vm_lifecycle_mutex(id).await;
        let _lifecycle_guard = lifecycle_lock.lock().await;
        let _trace = PerfSpan::new("full VM provision");
        let _base_operation = vm_base_operations().lock().await;
        let source_path = PathBuf::from(source);
        if !source_path.is_file() {
            return Err(format!(
                "select an existing bootable ISO or virtual disk: {}",
                source_path.display()
            ));
        }
        let environments_root = verified_runtime_subdirectory(
            &self.data_root,
            "environments",
            "environment storage root",
        )?;
        let environment_directory =
            checked_runtime_child(&environments_root, id, "virtual machine")?;
        if environment_directory.exists() {
            return Err("environment storage already exists".into());
        }
        fs::create_dir(&environment_directory).map_err(|error| {
            format!(
                "create environment storage {}: {error}",
                environment_directory.display()
            )
        })?;
        let disk_path = environment_directory.join("system.qcow2");
        let extension = source_path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if extension == "qcow2" {
            let inspection = super::vm_security::read_backup(&source_path);
            if !matches!(&inspection, Ok(None)) {
                let _ = remove_verified_directory(&environments_root, &environment_directory, "unused new VM storage").await;
                return Err(inspection.err().unwrap_or_else(|| "Use Load local backup for a secure VM backup so its TPM identity is restored with its disk.".into()));
            }
        }
        let managed_source = self.import_vm_source(&source_path, &extension).await;
        let managed_source = match managed_source {
            Ok(path) => path,
            Err(error) => {
                let _ = remove_verified_directory(
                    &environments_root,
                    &environment_directory,
                    "failed virtual machine storage",
                )
                .await;
                return Err(error);
            }
        };
        let result = if extension == "iso" {
            command_output(
                &self.layout.qemu_img,
                &[
                    "create".into(),
                    "-f".into(),
                    "qcow2".into(),
                    path_string(&disk_path),
                    disk_bytes.to_string(),
                ],
                "create virtual machine disk",
            )
            .await
            .map(|_| ())
        } else {
            command_output(
                &self.layout.qemu_img,
                &[
                    "create".into(),
                    "-f".into(),
                    "qcow2".into(),
                    "-F".into(),
                    "qcow2".into(),
                    "-b".into(),
                    path_string(&managed_source),
                    path_string(&disk_path),
                ],
                "create copy-on-write virtual machine branch",
            )
            .await
            .map(|_| ())
        };
        if let Err(error) = result {
            let _ = remove_verified_directory(
                &environments_root,
                &environment_directory,
                "failed virtual machine storage",
            )
            .await;
            return Err(error);
        }
        let uefi_vars = environment_directory.join("uefi-vars.fd");
        if extension != "iso" {
            if let Some(gb) = storage_gb {
                let grow = async {
                    let before = self.inspect_storage(&disk_path, false).await?;
                    if gb > before.capacity_gb { self.grow_disk(&disk_path, gb, false).await?; }
                    Ok::<(), String>(())
                }.await;
                if let Err(error) = grow {
                    let _ = remove_verified_directory(&environments_root, &environment_directory, "failed new VM disk expansion").await;
                    return Err(error);
                }
            }
        }
        if let Err(error) = fs::copy(&self.layout.uefi_vars, &uefi_vars) {
            let _ = remove_verified_directory(
                &environments_root,
                &environment_directory,
                "failed virtual machine storage",
            )
            .await;
            return Err(format!(
                "create persistent virtual machine firmware state: {error}"
            ));
        }
        if let Err(error) = super::vm_security::prepare(&self.layout, &environment_directory, &source_path).await {
            let _ = remove_verified_directory(&environments_root, &environment_directory, "failed new VM security preparation").await;
            return Err(error);
        }
        Ok(VmProvisionResult {
            disk_path,
            source_path: managed_source,
        })
    }

    /// Provisions a direct-kernel microVM without UEFI or emulated display hardware.
    ///
    /// `source` may be `builtin:alpine`, which reuses the verified bundled appliance
    /// kernel, initramfs, and base disk, or a JSON manifest with this shape:
    /// `{ "kernel": "vmlinuz", "initrd": "initrd", "disk": "root.qcow2",
    ///    "cmdline": "root=/dev/vda rw console=ttyS0" }`.
    /// Relative manifest paths are resolved beside the manifest. Custom artifacts are
    /// imported into the content-addressed base store once and reused by later microVMs.
    pub async fn provision_micro_vm(
        &self,
        id: &str,
        source: &str,
    ) -> Result<VmProvisionResult, String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.provision_micro_vm(id, source)).await; }

        validate_runtime_identifier("microVM", id)?;
        let lifecycle_lock = self.vm_lifecycle_mutex(id).await;
        let _lifecycle_guard = lifecycle_lock.lock().await;
        let _trace = PerfSpan::new("microVM provision");
        let _base_operation = vm_base_operations().lock().await;
        let environments_root = verified_runtime_subdirectory(
            &self.data_root,
            "environments",
            "environment storage root",
        )?;
        let environment_directory = checked_runtime_child(&environments_root, id, "microVM")?;
        if environment_directory.exists() {
            return Err("environment storage already exists".into());
        }
        fs::create_dir(&environment_directory).map_err(|error| {
            format!(
                "create microVM storage {}: {error}",
                environment_directory.display()
            )
        })?;

        let result = self
            .provision_micro_vm_inner(&environment_directory, source)
            .await;
        if result.is_err() {
            let _ = remove_verified_directory(
                &environments_root,
                &environment_directory,
                "failed microVM storage",
            )
            .await;
        }
        result
    }

    async fn provision_micro_vm_inner(
        &self,
        environment_directory: &Path,
        source: &str,
    ) -> Result<VmProvisionResult, String> {
        let (kernel, initrd, backing_disk, cmdline) = if source == "builtin:alpine" {
            (
                self.layout.appliance_kernel.clone(),
                Some(self.layout.appliance_initramfs.clone()),
                self.layout.appliance_base.clone(),
                default_builtin_micro_vm_cmdline(),
            )
        } else {
            let source_manifest_path = PathBuf::from(source);
            let metadata = tokio::fs::metadata(&source_manifest_path)
                .await
                .map_err(|error| format!("read microVM source manifest metadata: {error}"))?;
            if !metadata.is_file() {
                return Err(format!(
                    "select an existing microVM JSON manifest: {}",
                    source_manifest_path.display()
                ));
            }
            if metadata.len() > MAX_MICRO_VM_MANIFEST_BYTES {
                return Err("microVM source manifest exceeds the 1 MiB safety limit".into());
            }
            let file = tokio::fs::File::open(&source_manifest_path)
                .await
                .map_err(|error| format!("open microVM source manifest: {error}"))?;
            let mut limited = file.take(MAX_MICRO_VM_MANIFEST_BYTES + 1);
            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            limited
                .read_to_end(&mut bytes)
                .await
                .map_err(|error| format!("read microVM source manifest: {error}"))?;
            if bytes.len() as u64 > MAX_MICRO_VM_MANIFEST_BYTES {
                return Err("microVM source manifest changed beyond the 1 MiB safety limit".into());
            }
            let manifest = serde_json::from_slice::<MicroVmSourceManifest>(&bytes)
                .map_err(|error| format!("decode microVM source manifest: {error}"))?;
            validate_micro_vm_cmdline(&manifest.cmdline)?;
            let manifest_directory = source_manifest_path
                .parent()
                .unwrap_or_else(|| Path::new("."));
            let kernel_source = resolve_manifest_path(manifest_directory, &manifest.kernel);
            let initrd_source = manifest
                .initrd
                .as_ref()
                .map(|path| resolve_manifest_path(manifest_directory, path));
            let disk_source = resolve_manifest_path(manifest_directory, &manifest.disk);
            let disk_extension = disk_source
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            if disk_extension == "iso" {
                return Err(
                    "microVMs require a bootable root disk; ISO installation media needs a full VM"
                        .into(),
                );
            }
            let managed_kernel = self
                .import_vm_blob(&kernel_source, "kernel", "microVM kernel")
                .await?;
            let managed_initrd = match initrd_source {
                Some(path) => Some(
                    self.import_vm_blob(&path, "initrd", "microVM initramfs")
                        .await?,
                ),
                None => None,
            };
            let managed_disk = self.import_vm_source(&disk_source, &disk_extension).await?;
            (
                managed_kernel,
                managed_initrd,
                managed_disk,
                manifest.cmdline,
            )
        };

        validate_micro_vm_cmdline(&cmdline)?;
        for (label, path) in [
            ("kernel", Some(kernel.as_path())),
            ("initramfs", initrd.as_deref()),
            ("root disk", Some(backing_disk.as_path())),
        ] {
            if let Some(path) = path {
                if !path.is_file() {
                    return Err(format!("microVM {label} is missing: {}", path.display()));
                }
            }
        }

        let disk_path = environment_directory.join("system.qcow2");
        command_output(
            &self.layout.qemu_img,
            &[
                "create".into(),
                "-f".into(),
                "qcow2".into(),
                "-F".into(),
                "qcow2".into(),
                "-b".into(),
                path_string(&backing_disk),
                path_string(&disk_path),
            ],
            "create copy-on-write microVM root disk",
        )
        .await?;

        let managed_manifest = ManagedMicroVmManifest {
            version: MICRO_VM_MANIFEST_VERSION,
            builtin: source == "builtin:alpine",
            kernel,
            initrd,
            cmdline,
        };
        let manifest_path = environment_directory.join("microvm.json");
        let manifest_bytes = serde_json::to_vec_pretty(&managed_manifest)
            .map_err(|error| format!("encode managed microVM manifest: {error}"))?;
        write_durable_file(manifest_path.clone(), manifest_bytes).await?;
        Ok(VmProvisionResult {
            disk_path,
            source_path: manifest_path,
        })
    }

    /// Recreates the boot metadata for a restored `builtin:alpine` microVM disk.
    /// Custom profiles intentionally cannot use this helper because their kernel and
    /// initramfs must be packaged with the backup before they can be restored safely.
    pub async fn restore_builtin_micro_vm_manifest(&self, id: &str) -> Result<PathBuf, String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.restore_builtin_micro_vm_manifest(id)).await; }

        validate_runtime_identifier("microVM", id)?;
        let lifecycle_lock = self.vm_lifecycle_mutex(id).await;
        let _lifecycle_guard = lifecycle_lock.lock().await;
        let environments_root = verified_runtime_subdirectory(
            &self.data_root,
            "environments",
            "environment storage root",
        )?;
        let environment_directory = checked_runtime_child(&environments_root, id, "microVM")?;
        require_verified_direct_child(
            &environments_root,
            &environment_directory,
            PathKind::Directory,
            "restored microVM storage",
        )?;
        let disk_path = environment_directory.join("system.qcow2");
        require_verified_direct_child(
            &environment_directory,
            &disk_path,
            PathKind::File,
            "restored microVM disk",
        )?;
        let managed_manifest = ManagedMicroVmManifest {
            version: MICRO_VM_MANIFEST_VERSION,
            builtin: true,
            kernel: self.layout.appliance_kernel.clone(),
            initrd: Some(self.layout.appliance_initramfs.clone()),
            cmdline: default_builtin_micro_vm_cmdline(),
        };
        let manifest_path = environment_directory.join("microvm.json");
        if manifest_path.exists() {
            require_verified_direct_child(
                &environment_directory,
                &manifest_path,
                PathKind::File,
                "managed microVM manifest",
            )?;
        }
        let manifest_bytes = serde_json::to_vec_pretty(&managed_manifest)
            .map_err(|error| format!("encode restored microVM manifest: {error}"))?;
        write_durable_file(manifest_path.clone(), manifest_bytes).await?;
        Ok(manifest_path)
    }

    /// Removes imported VM base artifacts which are no longer reachable.
    ///
    /// The sweep is deliberately conservative: it resolves explicit environment runtime
    /// sources, every surviving managed microVM manifest, and every surviving environment
    /// QCOW2 backing chain before removing anything. Only direct, content-addressed files in
    /// `runtime/bases` are eligible; runtime resources, directories, arbitrary filenames,
    /// and source-cache metadata are never removed here.
    pub async fn garbage_collect_vm_bases(
        &self,
        referenced_sources: &[PathBuf],
    ) -> Result<u64, String> {
        let mut reclaimed = 0u64;
        for engine in self.registered_storage_runtimes() {
            reclaimed = reclaimed.saturating_add(Box::pin(engine?.garbage_collect_vm_bases(referenced_sources)).await?);
        }
        Ok(reclaimed.saturating_add(self.garbage_collect_local_vm_bases(referenced_sources).await?))
    }

    async fn garbage_collect_local_vm_bases(&self, referenced_sources: &[PathBuf]) -> Result<u64, String> {
        let _trace = PerfSpan::new("VM base garbage collection");
        let _base_operation = vm_base_operations().lock().await;
        let bases = self.data_root.join("bases");
        tokio::fs::create_dir_all(&bases)
            .await
            .map_err(|error| format!("create VM base directory before cleanup: {error}"))?;
        let bases_metadata = tokio::fs::symlink_metadata(&bases)
            .await
            .map_err(|error| format!("inspect VM base directory before cleanup: {error}"))?;
        if !bases_metadata.is_dir() || bases_metadata.file_type().is_symlink() {
            return Err("refusing to clean a VM base path that is not a real directory".into());
        }
        let canonical_data_root = fs::canonicalize(&self.data_root).map_err(|error| {
            format!(
                "resolve runtime data directory {}: {error}",
                self.data_root.display()
            )
        })?;
        let canonical_bases = fs::canonicalize(&bases)
            .map_err(|error| format!("resolve VM base directory {}: {error}", bases.display()))?;
        if canonical_bases.parent() != Some(canonical_data_root.as_path()) {
            return Err("refusing to clean a VM base directory outside runtime data".into());
        }
        let mut referenced = HashSet::new();

        for source in referenced_sources {
            if source == Path::new("builtin:alpine") {
                continue;
            }
            if source
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
                && source.is_file()
            {
                let manifest = read_managed_micro_vm_manifest(source).await?;
                preserve_managed_base(&canonical_bases, &manifest.kernel, &mut referenced);
                if let Some(initrd) = manifest.initrd.as_ref() {
                    preserve_managed_base(&canonical_bases, initrd, &mut referenced);
                }
            }
            preserve_managed_base(&canonical_bases, source, &mut referenced);
            if is_qcow2_path(source) && source.is_file() {
                self.collect_qcow2_backing_references(source, &canonical_bases, &mut referenced)
                    .await?;
            }
        }

        let environments_root = verified_runtime_subdirectory(
            &self.data_root,
            "environments",
            "environment storage root",
        )?;
        let mut environments = match tokio::fs::read_dir(&environments_root).await {
            Ok(entries) => Some(entries),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(format!("scan VM environments before cleanup: {error}")),
        };
        if let Some(environments) = environments.as_mut() {
            while let Some(environment) = environments
                .next_entry()
                .await
                .map_err(|error| format!("scan VM environment entry: {error}"))?
            {
                let file_type = environment
                    .file_type()
                    .await
                    .map_err(|error| format!("inspect VM environment entry: {error}"))?;
                if file_type.is_symlink() {
                    return Err(format!(
                        "refusing VM base cleanup while an environment path is a symlink: {}",
                        environment.path().display()
                    ));
                }
                if !file_type.is_dir() {
                    continue;
                }
                let environment_path = environment.path();
                let manifest_path = environment_path.join("microvm.json");
                if manifest_path.is_file() {
                    let manifest = read_managed_micro_vm_manifest(&manifest_path).await?;
                    preserve_managed_base(&canonical_bases, &manifest.kernel, &mut referenced);
                    if let Some(initrd) = manifest.initrd.as_ref() {
                        preserve_managed_base(&canonical_bases, initrd, &mut referenced);
                    }
                }
                let mut files = tokio::fs::read_dir(&environment_path)
                    .await
                    .map_err(|error| {
                        format!(
                            "scan surviving VM storage {}: {error}",
                            environment_path.display()
                        )
                    })?;
                while let Some(file) = files
                    .next_entry()
                    .await
                    .map_err(|error| format!("scan surviving VM storage entry: {error}"))?
                {
                    let file_type = file
                        .file_type()
                        .await
                        .map_err(|error| format!("inspect surviving VM storage entry: {error}"))?;
                    if file_type.is_symlink() && is_qcow2_path(&file.path()) {
                        return Err(format!(
                            "refusing VM base cleanup while a VM disk is a symlink: {}",
                            file.path().display()
                        ));
                    }
                    if file_type.is_file() && is_qcow2_path(&file.path()) {
                        self.collect_qcow2_backing_references(
                            &file.path(),
                            &canonical_bases,
                            &mut referenced,
                        )
                        .await?;
                    }
                }
            }
        }

        sweep_unreferenced_vm_bases(&canonical_bases, &referenced).await
    }

    async fn collect_qcow2_backing_references(
        &self,
        disk_path: &Path,
        canonical_bases: &Path,
        referenced: &mut HashSet<PathBuf>,
    ) -> Result<(), String> {
        // Inspect one header at a time. --backing-chain tries to open raw leaf
        // devices too, so an expired VSS shadow used by an old computer branch
        // used to prevent *all* cache cleanup. A declared raw leaf has no further
        // dependencies: preserve its path without requiring it to be readable.
        let mut path = disk_path.to_path_buf();
        let mut visited = HashSet::new();
        for _ in 0..64 {
            let identity = fs::canonicalize(&path)
                .map_err(|error| format!("inspect VM backing image {}: {error}", path.display()))?;
            if !visited.insert(identity) {
                return Err("VM backing chain contains a cycle; cached images were kept for safety".into());
            }
            preserve_managed_base(canonical_bases, &path, referenced);
            let output = command_output(
                &self.layout.qemu_img,
                &["info".into(), "--force-share".into(), "--output=json".into(), path_string(&path)],
                "inspect surviving virtual machine backing image",
            ).await?;
            let info: BackingImageInfo = serde_json::from_slice(&output.stdout)
                .map_err(|error| format!("decode VM backing image: {error}"))?;
            let Some(backing) = info.full_backing_filename.or(info.backing_filename) else {
                return Ok(());
            };
            let backing = if backing.is_absolute() { backing } else {
                path.parent().unwrap_or_else(|| Path::new(".")).join(backing)
            };
            preserve_managed_base(canonical_bases, &backing, referenced);
            if info.backing_format.as_deref() == Some("raw") { return Ok(()); }
            path = backing;
        }
        Err("VM backing chain is too deep; cached images were kept for safety".into())
    }

    async fn import_vm_source(
        &self,
        source_path: &Path,
        extension: &str,
    ) -> Result<PathBuf, String> {
        let _trace = PerfSpan::new("VM source import");
        let bases =
            verified_runtime_subdirectory(&self.data_root, "bases", "VM base storage root")?;
        if extension == "iso" {
            return self.import_vm_blob(source_path, "iso", "boot media").await;
        }

        let identity = inspect_source_identity(source_path.to_path_buf()).await?;
        if let Some(checksum) = read_cached_source_checksum(&bases, &identity, "qcow2").await {
            let destination = bases.join(format!("{checksum}.qcow2"));
            match safe_regular_file_size(&destination, "cached managed VM base")? {
                Some(size) if size > 0 => return Ok(destination),
                Some(_) => return Err("cached managed VM base is empty".into()),
                None => {}
            }
        }
        let (_, checksum) = hash_file(source_path.to_path_buf()).await?;
        ensure_source_unchanged(source_path, &identity).await?;
        let destination = bases.join(format!("{checksum}.qcow2"));
        match safe_regular_file_size(&destination, "managed VM base")? {
            Some(size) if size > 0 => {
                write_source_checksum_cache(&bases, &identity, "qcow2", &checksum).await?;
                return Ok(destination);
            }
            Some(_) => return Err("managed VM base is empty".into()),
            None => {}
        }
        let info = command_output(
            &self.layout.qemu_img,
            &[
                "info".into(),
                "--output=json".into(),
                path_string(source_path),
            ],
            "inspect source virtual disk",
        )
        .await
        .and_then(|output| {
            serde_json::from_slice::<ImageInfo>(&output.stdout)
                .map_err(|error| format!("decode virtual disk information: {error}"))
        })?;
        let temporary = bases.join(format!(".{}.qcow2.part", Uuid::new_v4().simple()));
        if let Err(error) = command_output(
            &self.layout.qemu_img,
            &[
                "convert".into(),
                "-f".into(),
                info.format,
                "-O".into(),
                "qcow2".into(),
                "-c".into(),
                path_string(source_path),
                path_string(&temporary),
            ],
            "import virtual disk into managed storage",
        )
        .await
        {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(error);
        }
        if let Err(error) = ensure_source_unchanged(source_path, &identity).await {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(error);
        }
        if let Err(error) = command_output(
            &self.layout.qemu_img,
            &["check".into(), "-q".into(), path_string(&temporary)],
            "verify imported virtual disk",
        )
        .await
        {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(error);
        }
        finalize_content_addressed_import(&temporary, &destination).await?;
        write_source_checksum_cache(&bases, &identity, "qcow2", &checksum).await?;
        Ok(destination)
    }

    async fn import_vm_blob(
        &self,
        source_path: &Path,
        artifact_extension: &str,
        description: &str,
    ) -> Result<PathBuf, String> {
        let bases =
            verified_runtime_subdirectory(&self.data_root, "bases", "VM base storage root")?;
        let identity = inspect_source_identity(source_path.to_path_buf()).await?;
        if let Some(checksum) =
            read_cached_source_checksum(&bases, &identity, artifact_extension).await
        {
            let destination = bases.join(format!("{checksum}.{artifact_extension}"));
            match safe_regular_file_size(&destination, "cached managed VM artifact")? {
                Some(size) if size == identity.size_bytes => return Ok(destination),
                Some(_) => {
                    return Err(format!(
                        "cached managed {description} has an unexpected size"
                    ));
                }
                None => {}
            }
        }

        let temporary = bases.join(format!(
            ".{}.{}.part",
            Uuid::new_v4().simple(),
            artifact_extension
        ));
        let imported = copy_and_hash(
            source_path.to_path_buf(),
            temporary.clone(),
            description.to_owned(),
        )
        .await;
        let (size_bytes, checksum) = match imported {
            Ok(imported) => imported,
            Err(error) => {
                let _ = tokio::fs::remove_file(&temporary).await;
                return Err(error);
            }
        };
        if size_bytes != identity.size_bytes {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(format!("{description} changed while it was being imported"));
        }
        if let Err(error) = ensure_source_unchanged(source_path, &identity).await {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(error);
        }
        let destination = bases.join(format!("{checksum}.{artifact_extension}"));
        if let Some(size) = safe_regular_file_size(&destination, "managed VM artifact")? {
            if size != identity.size_bytes {
                let _ = tokio::fs::remove_file(&temporary).await;
                return Err(format!(
                    "managed {description} has an unexpected size: {}",
                    destination.display()
                ));
            }
            let _ = tokio::fs::remove_file(&temporary).await;
            write_source_checksum_cache(&bases, &identity, artifact_extension, &checksum).await?;
            return Ok(destination);
        }
        finalize_content_addressed_import(&temporary, &destination).await?;
        write_source_checksum_cache(&bases, &identity, artifact_extension, &checksum).await?;
        Ok(destination)
    }

    #[cfg(test)]
    pub async fn start_vm(
        &self,
        id: &str,
        disk_path: &Path,
        source_path: &Path,
        resource_policy: &ResourcePolicy,
        gpu_access: bool,
    ) -> Result<VmConsole, String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.start_vm(id, disk_path, source_path, resource_policy, gpu_access)).await; }

        self.start_vm_with_network(id, disk_path, source_path, resource_policy, gpu_access, true).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn start_vm_with_network(
        &self,
        id: &str,
        disk_path: &Path,
        source_path: &Path,
        resource_policy: &ResourcePolicy,
        gpu_access: bool,
        network_access: bool,
    ) -> Result<VmConsole, String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.start_vm_with_network(id, disk_path, source_path, resource_policy, gpu_access, network_access)).await; }

        validate_runtime_identifier("virtual machine", id)?;
        self.start_vm_with_profile(
            id,
            disk_path,
            resource_policy,
            VmLaunchProfile::Full {
                source_path: source_path.to_path_buf(),
                gpu_access,
                network_access,
            },
        )
        .await
    }

    /// Admission and state reporting use the same allocation as QEMU. A live
    /// microVM retains its fixed RAM even when preferences change for next boot.
    pub async fn micro_vm_startup_memory_gb(
        &self, id: &str, manifest_path: &Path, policy: &ResourcePolicy,
    ) -> Result<f64, String> {
        if let Some(engine) = self.storage_runtime(id)? {
            return Box::pin(engine.micro_vm_startup_memory_gb(id, manifest_path, policy)).await;
        }
        validate_runtime_identifier("microVM", id)?;
        {
            let mut processes = self.vms.lock().await;
            if let Some(process) = processes.get_mut(id) {
                if process.child.try_wait().map_err(|error| format!("inspect microVM allocation: {error}"))?.is_none() {
                    return process.allocated_micro_memory_gb.ok_or_else(|| "The running environment is not a direct-kernel microVM".into());
                }
            }
        }
        verify_environment_artifact(&self.data_root, id, manifest_path, "managed microVM manifest")?;
        let manifest = read_managed_micro_vm_manifest(manifest_path).await?;
        super::vm_memory::microvm_startup_gb(policy.memory_gb.preferred, policy.memory_gb.max, manifest.builtin)
    }

    /// Starts a provisioned direct-kernel microVM. The `manifest_path` must be the
    /// managed manifest returned by [`RuntimeManager::provision_micro_vm`].
    #[cfg(test)]
    pub async fn start_micro_vm(
        &self,
        id: &str,
        disk_path: &Path,
        manifest_path: &Path,
        resource_policy: &ResourcePolicy,
    ) -> Result<VmConsole, String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.start_micro_vm(id, disk_path, manifest_path, resource_policy)).await; }

        self.start_micro_vm_with_network(id, disk_path, manifest_path, resource_policy, true).await
    }

    pub async fn start_micro_vm_with_network(
        &self, id: &str, disk_path: &Path, manifest_path: &Path,
        resource_policy: &ResourcePolicy, network_access: bool,
    ) -> Result<VmConsole, String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.start_micro_vm_with_network(id, disk_path, manifest_path, resource_policy, network_access)).await; }

        validate_runtime_identifier("microVM", id)?;
        verify_environment_artifact(&self.data_root, id, disk_path, "microVM disk")?;
        verify_environment_artifact(
            &self.data_root,
            id,
            manifest_path,
            "managed microVM manifest",
        )?;
        let manifest = read_managed_micro_vm_manifest(manifest_path).await?;
        let console=self.start_vm_with_profile(
            id, disk_path, resource_policy, VmLaunchProfile::Micro(manifest, network_access),
        ).await?;
        if let Err(error) = self.start_micro_workload(id).await {
            // The environment is reported as failed; do not leave its VM running
            // and holding CPU, memory and its disk behind that status.
            if let Err(stop) = self.vm_action(id, "stop").await {
                return Err(format!("{error}. Stopping the microVM also failed: {stop}"));
            }
            return Err(error);
        }
        Ok(console)
    }

    async fn start_vm_with_profile(
        &self,
        id: &str,
        disk_path: &Path,
        resource_policy: &ResourcePolicy,
        profile: VmLaunchProfile,
    ) -> Result<VmConsole, String> {
        let _gpu_lease = self.gpu_launches.read().await;
        validate_runtime_identifier("virtual machine", id)?;
        verify_environment_artifact(&self.data_root, id, disk_path, "virtual machine disk")?;
        let _trace = PerfSpan::new(match &profile {
            VmLaunchProfile::Full { .. } => "full VM start",
            VmLaunchProfile::Micro(_, _) => "microVM start",
        });
        let lifecycle_lock = self.vm_lifecycle_mutex(id).await;
        let _lifecycle_guard = lifecycle_lock.lock().await;
        ensure_no_pending_vm_restore(&self.data_root, id)?;
        let min_cpus = resource_policy.cpu.min;
        let cpus = resource_policy.cpu.preferred;
        let max_cpus = resource_policy.cpu.max;
        let max_memory_gb = resource_policy.memory_gb.max;
        let full_source_path = match &profile {
            VmLaunchProfile::Full { source_path, .. } => Some(source_path.as_path()),
            VmLaunchProfile::Micro(_, _) => None,
        };
        if full_source_path == Some(Path::new("current-computer")) {
            self.ensure_computer_branch_boot(id).await?;
        }
        {
            let mut processes = self.vms.lock().await;
            if let Some(process) = processes.get_mut(id) {
                match process.child.try_wait() {
                    Ok(None) => {
                        let headless = process.is_micro_vm;
                        return Ok(VmConsole {
                            websocket_url: if headless {
                                String::new()
                            } else {
                                format!("ws://127.0.0.1:{}", process.websocket_port)
                            },
                            password: process.console_password.clone(),
                            headless,
                            serial_log_path: headless.then(|| {
                                self.data_root
                                    .join("environments")
                                    .join(id)
                                    .join("serial.log")
                            }),
                            guest_control_available: process.micro_endpoint.is_some(),
                        });
                    }
                    Ok(Some(_)) => {
                        processes.remove(id);
                    }
                    Err(error) => return Err(format!("inspect virtual machine process: {error}")),
                }
            }
        }
        self.check_external_vm(id, false).await?;
        let memory_gb = match &profile {
            VmLaunchProfile::Micro(manifest, _) => super::vm_memory::microvm_startup_gb(
                resource_policy.memory_gb.preferred, resource_policy.memory_gb.max, manifest.builtin,
            )?,
            VmLaunchProfile::Full { .. } => resource_policy.memory_gb.preferred,
        };
        // macOS has no equivalent of our Windows/Linux hard CPU affinity.
        // Start at the requested footprint; never boot at the policy maximum
        // and pretend that a host CPU limiter later reduced it.
        let (min_cpus, max_cpus, max_memory_gb) = if cfg!(target_os = "macos") {
            (cpus, cpus, memory_gb)
        } else { (min_cpus, max_cpus, max_memory_gb) };
        let full_vm = matches!(&profile, VmLaunchProfile::Full { .. });
        let startup_memory = super::vm_memory::startup_bytes(if full_vm { max_memory_gb } else { memory_gb }, full_vm);
        super::vm_memory::check_available(startup_memory, super::vm_memory::available_commit_bytes(), full_vm)?;
        if !disk_path.is_file() {
            return Err(format!(
                "virtual machine disk is missing: {}",
                disk_path.display()
            ));
        }
        if let Some(source) = full_source_path {
            super::vm_security::prepare(&self.layout, &self.data_root.join("environments").join(id), source).await?;
        }
        if full_source_path == Some(Path::new("current-computer")) {
            self.prepare_computer_branch_overlay(id, disk_path).await?;
        }
        let mut branch_block_server = if full_source_path == Some(Path::new("current-computer")) {
            Some(self.start_computer_branch_block_server(id).await?)
        } else {
            None
        };
        let mut port_reservations = VmPortReservations::new();
        let (websocket_port, qmp_port, display, console_password, headless, micro_endpoint) =
            match &profile {
                VmLaunchProfile::Full { .. } => {
                    let websocket_port = port_reservations.reserve_available(&[])?;
                    let qmp_port = port_reservations.reserve_available(&[websocket_port])?;
                    let (display, _rfb_port) =
                        port_reservations.reserve_vnc_display(&[websocket_port, qmp_port])?;
                    (
                        websocket_port,
                        qmp_port,
                        display,
                        vnc_console_password(),
                        false,
                        None,
                    )
                }
                VmLaunchProfile::Micro(manifest, _) => {
                    let qmp_port = port_reservations.reserve_available(&[])?;
                    let endpoint = if manifest.builtin {
                        let control_port = port_reservations.reserve_available(&[qmp_port])?;
                        Some(AgentEndpoint {
                            base_url: format!("http://127.0.0.1:{control_port}"),
                            // Two independent UUIDs provide the guest agent's required
                            // 256-bit bearer secret. The endpoint itself is never exposed
                            // through console metadata or written to a log.
                            token: format!(
                                "{}{}",
                                Uuid::new_v4().simple(),
                                Uuid::new_v4().simple()
                            ),
                        })
                    } else {
                        None
                    };
                    (0, qmp_port, 0, String::new(), true, endpoint)
                }
            };
        let private_port = port_reservations.reserve_available(&[qmp_port, websocket_port])?;
        let guest_control_available = micro_endpoint.is_some();
        let accelerators = super::host_platform::x86_accelerators(std::env::consts::OS, std::env::consts::ARCH, headless);
        let mut last_error = String::new();
        let gpu_enabled = matches!(&profile, VmLaunchProfile::Full { gpu_access: true, .. });
        let gpu_launch = if gpu_enabled { Some(self.prepare_gpu_launch(&self.data_root.join("environments").join(id)).await?) } else { None };
        for accelerator in accelerators {
            super::vm_memory::check_available(startup_memory, super::vm_memory::available_commit_bytes(), full_vm)?;
            let internet = match &profile {
                VmLaunchProfile::Micro(_, enabled) => Some(super::microvm_network::MicroVmNetwork::new(*enabled, qmp_port).await?),
                VmLaunchProfile::Full { network_access, .. } => Some(super::microvm_network::MicroVmNetwork::new(*network_access, qmp_port).await?),
            };
            let mut child = match &profile {
                VmLaunchProfile::Full {
                    source_path,
                    gpu_access,
                    ..
                } => self.spawn_full_vm(
                    id,
                    disk_path,
                    source_path,
                    min_cpus,
                    max_cpus,
                    max_memory_gb,
                    qmp_port,
                    websocket_port,
                    display,
                    accelerator,
                    *gpu_access,
                    gpu_launch.as_ref(),
                    branch_block_server.as_ref(),
                    private_port,
                    internet.as_ref().map(|network| network.arguments()).unwrap_or(&[]),
                ),
                VmLaunchProfile::Micro(manifest, _) => self.spawn_micro_vm(
                    id,
                    disk_path,
                    manifest,
                    min_cpus,
                    max_cpus,
                    memory_gb,
                    qmp_port,
                    accelerator,
                    micro_endpoint.as_ref(),
                    private_port,
                    internet.as_ref().map(|network| network.arguments()).unwrap_or(&[]),
                ),
            }?;
            let error_path = self
                .data_root
                .join("environments")
                .join(id)
                .join("qemu.log");
            let is_whpx = *accelerator == "whpx";
            if let Err(error) = wait_for_vm_startup(
                &mut child,
                qmp_port,
                (!headless).then_some(websocket_port),
                &error_path,
                is_whpx,
                // The host packet filter enforces Internet access. Keep the
                // cable up for explicitly authorized local service connections.
                match &profile { VmLaunchProfile::Full { .. } => Some(true), _ => None },
            )
            .await
            {
                let _ = child.kill().await;
                let _ = child.wait().await;
                if let Some(message) = super::vm_memory::allocation_failure(&error, startup_memory, super::vm_memory::available_commit_bytes(), full_vm) {
                    return Err(message);
                }
                #[cfg(test)]
                eprintln!("VM accelerator {accelerator} failed: {error}");
                last_error = error;
                continue;
            }
            if let Some(network) = &internet {
                let enabled = match &profile {
                    VmLaunchProfile::Micro(_, enabled) => *enabled,
                    VmLaunchProfile::Full { network_access, .. } => *network_access,
                };
                if let Err(error) = network.set_enabled(enabled).await {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    return Err(error);
                }
            }
            let process_id = child
                .id()
                .ok_or_else(|| "virtual machine process has no identifier".to_string())?;
            let gpu = if let Some(launch) = &gpu_launch {
                match launch.verify(process_id) {
                    Ok(gpu) => gpu,
                    Err(error) => { let _ = child.kill().await; let _ = child.wait().await; return Err(error); }
                }
            } else { None };
            let private_socket = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, private_port))).await;
            let private_result = match private_socket {
                Ok(Ok(socket)) => self.fabric.attach(id, socket),
                _ => Err("Could not connect the VM private network adapter".into()),
            };
            if let Err(error) = private_result { let _ = child.kill().await; let _ = child.wait().await; return Err(error); }
            self.vms.lock().await.insert(
                id.to_owned(),
                VmProcess {
                    internet,
                    child,
                    _branch_block_server: branch_block_server.take(),
                    _port_reservations: port_reservations,
                    is_micro_vm: headless,
                    gpu_enabled,
                    gpu,
                    micro_endpoint: micro_endpoint.clone(),
                    process_id,
                    allocated_cpus: cpus.round().max(1.0) as usize,
                    allocated_micro_memory_gb: headless.then_some(memory_gb),
                    qmp_port,
                    websocket_port,
                    console_password: console_password.clone(),
                },
            );
            let resource_result = if cfg!(target_os = "macos") {
                // -smp and -m already enforce the fixed boot allocation.
                Ok(())
            } else if headless {
                // A microVM starts at its preferred footprint. Ballooning a larger maximum
                // down on WHPX is both slower and extremely noisy, and microvm deliberately
                // omits ACPI DIMM hotplug. CPU affinity remains dynamically adjustable.
                apply_process_cpu_limit(process_id, cpus)
            } else {
                apply_vm_resource_limits(process_id, qmp_port, cpus, memory_gb).await
            };
            if let Err(error) = resource_result {
                let detail = read_log_tail(&error_path);
                let _ = self.vm_action_locked(id, "stop").await;
                return Err(if detail.is_empty() {
                    format!("configure dynamic virtual machine resources: {error}")
                } else {
                    format!("configure dynamic virtual machine resources: {error}; {detail}")
                });
            }
            if !headless {
                if let Err(error) = qmp_execute(
                    qmp_port,
                    "set_password",
                    Some(json!({ "protocol": "vnc", "password": console_password })),
                )
                .await
                {
                    let _ = self.vm_action_locked(id, "stop").await;
                    return Err(format!("secure virtual machine display: {error}"));
                }
            }
            return Ok(VmConsole {
                websocket_url: if headless {
                    String::new()
                } else {
                    format!("ws://127.0.0.1:{websocket_port}")
                },
                password: console_password,
                headless,
                serial_log_path: headless.then(|| {
                    self.data_root
                        .join("environments")
                        .join(id)
                        .join("serial.log")
                }),
                guest_control_available,
            });
        }
        Err(last_error)
    }

    async fn micro_vm_agent(&self, id: &str) -> Result<AgentEndpoint, String> {
        let mut processes = self.vms.lock().await;
        let process = processes
            .get_mut(id)
            .ok_or_else(|| "microVM is not running".to_string())?;
        if process
            .child
            .try_wait()
            .map_err(|error| format!("inspect microVM: {error}"))?
            .is_some()
        {
            return Err("microVM is not running".into());
        }
        if !process.is_micro_vm {
            return Err("commands through the microVM guest agent require a microVM".into());
        }
        process
            .micro_endpoint
            .clone()
            .ok_or_else(|| "this custom microVM has no Yougori guest agent".to_string())
    }

    /// Wait for a built-in microVM's guest agent and retire its boot credential.
    ///
    /// The boot credential is on the guest kernel command line, which every
    /// process in the microVM, including its OCI workload, can read from
    /// /proc/cmdline. Before the first command, terminal or workload, replace it
    /// with a fresh credential known only to this process and the guest agent.
    /// Older guest agents report no credential state and keep their boot one.
    pub(super) async fn ready_micro_vm_agent(
        &self,
        id: &str,
        unavailable: &str,
    ) -> Result<AgentEndpoint, String> {
        // QMP reports the machine before Alpine finishes booting, so a request
        // sent right after start would reach a port with nothing listening yet.
        let deadline = tokio::time::Instant::now() + super::host_platform::guest_boot_timeout();
        loop {
            let endpoint = self.micro_vm_agent(id).await?;
            let reply = self
                .client
                .get(format!("{}/v1/health", endpoint.base_url))
                .bearer_auth(&endpoint.token)
                .timeout(Duration::from_secs(2))
                .send()
                .await;
            if let Ok(reply) = reply.and_then(|reply| reply.error_for_status()) {
                let health = reply.json::<MicroVmHealth>().await.unwrap_or_default();
                if health.credential.as_deref() != Some("boot") {
                    return Ok(endpoint);
                }
                if let Some(endpoint) = self.rotate_micro_vm_credential(id, &endpoint).await? {
                    return Ok(endpoint);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(unavailable.into());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Returns the endpoint to use, or None when a concurrent request replaced
    /// the credential first and the caller must reload it.
    async fn rotate_micro_vm_credential(
        &self,
        id: &str,
        endpoint: &AgentEndpoint,
    ) -> Result<Option<AgentEndpoint>, String> {
        let rotated = AgentEndpoint {
            base_url: endpoint.base_url.clone(),
            token: format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()),
        };
        let reply = self
            .client
            .post(format!("{}/v1/system/token", endpoint.base_url))
            .bearer_auth(&endpoint.token)
            .json(&json!({ "token": rotated.token }))
            .timeout(Duration::from_secs(10))
            .send()
            .await;
        match reply {
            Ok(reply) if reply.status().is_success() => {}
            Ok(reply) if reply.status() == reqwest::StatusCode::UNAUTHORIZED => return Ok(None),
            Ok(reply)
                if matches!(
                    reply.status(),
                    reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::METHOD_NOT_ALLOWED
                ) =>
            {
                return Ok(Some(endpoint.clone()))
            }
            Ok(reply) => {
                let status = reply.status();
                let detail = reply.text().await.unwrap_or_default();
                return Err(format!(
                    "secure microVM guest agent credential ({status}): {}",
                    detail.trim()
                ));
            }
            Err(error) => {
                // The guest saves the replacement before replying, so a lost
                // reply may still have switched it.
                let mut switched = false;
                for _ in 0..3 {
                    switched = self
                        .client
                        .get(format!("{}/v1/health", rotated.base_url))
                        .bearer_auth(&rotated.token)
                        .timeout(Duration::from_secs(2))
                        .send()
                        .await
                        .is_ok_and(|reply| reply.status().is_success());
                    if switched {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                if !switched {
                    return Err(format!("secure microVM guest agent credential: {error}"));
                }
            }
        }
        let mut processes = self.vms.lock().await;
        if let Some(current) = processes
            .get_mut(id)
            .and_then(|process| process.micro_endpoint.as_mut())
        {
            // Never overwrite the endpoint of a newer launch of this VM.
            if current.base_url == endpoint.base_url && current.token == endpoint.token {
                current.token = rotated.token.clone();
            }
        }
        Ok(Some(rotated))
    }

    pub async fn execute_micro_vm_command(
        &self,
        id: &str,
        command: &str,
    ) -> Result<CommandResult, String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.execute_micro_vm_command(id, command)).await; }

        validate_runtime_identifier("microVM", id)?;
        if command.trim().is_empty() {
            return Err("microVM command cannot be empty".into());
        }
        if command.len() > 32 * 1024 {
            return Err("microVM command exceeds the 32 KiB safety limit".into());
        }
        let endpoint = self
            .ready_micro_vm_agent(
                id,
                "The microVM guest agent is still booting or unavailable. Try the command again in a moment.",
            )
            .await?;
        let response = self
            .client
            .post(format!("{}/v1/system/exec", endpoint.base_url))
            .bearer_auth(&endpoint.token)
            .json(&MicroVmExecRequest { command })
            .timeout(Duration::from_secs(120))
            .send()
            .await
            .map_err(|error| format!("contact microVM guest agent: {error}"))?;
        let status = response.status();
        if !status.is_success() {
            let detail = response.text().await.unwrap_or_default();
            return Err(format!(
                "microVM guest agent rejected the command ({status}): {}",
                detail.trim()
            ));
        }
        let output = response
            .json::<MicroVmCommandOutput>()
            .await
            .map_err(|error| format!("decode microVM command response: {error}"))?;
        Ok(CommandResult {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
        })
    }

    pub async fn update_vm_internet(&self, id: &str, enabled: bool) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.update_vm_internet(id, enabled)).await; }

        validate_runtime_identifier("virtual machine", id)?;
        let lock = self.vm_lifecycle_mutex(id).await;
        let _guard = lock.lock().await;
        {
            let mut processes = self.vms.lock().await;
            let process = processes.get_mut(id).ok_or("Virtual machine is not running")?;
            if process.child.try_wait().map_err(|e| e.to_string())?.is_some() {
                return Err("Virtual machine is no longer running".into());
            }
            process.internet.as_ref().ok_or("Restart this VM to enable host network filtering")?.set_enabled(enabled).await
        }
    }

    pub(super) async fn request_micro_vm_shutdown(
        &self,
        endpoint: &AgentEndpoint,
    ) -> Result<(), String> {
        let response = self
            .client
            .post(format!("{}/v1/system/shutdown", endpoint.base_url))
            .bearer_auth(&endpoint.token)
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .map_err(|error| format!("request clean microVM shutdown: {error}"))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!(
                "microVM guest rejected clean shutdown ({})",
                response.status()
            ))
        }
    }

    pub async fn vm_action(&self, id: &str, action: &str) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.vm_action(id, action)).await; }

        validate_runtime_identifier("virtual machine", id)?;
        let lifecycle_lock = self.vm_lifecycle_mutex(id).await;
        let _lifecycle_guard = lifecycle_lock.lock().await;
        self.vm_action_locked(id, action).await
    }

    async fn vm_action_locked(&self, id: &str, action: &str) -> Result<(), String> {
        if action == "stop" && !self.vm_is_running(id).await? {
            // A crashed app may have left QEMU alive outside this manager's map.
            // Only report success once no matching external runtime holds the disk.
            self.check_external_vm(id, false).await?;
            self.vms.lock().await.remove(id);
            return Ok(());
        }
        let (qmp_port, is_micro_vm, micro_endpoint) = {
            let mut processes = self.vms.lock().await;
            let process = processes
                .get_mut(id)
                .ok_or_else(|| "virtual machine is not running".to_string())?;
            if process
                .child
                .try_wait()
                .map_err(|error| format!("inspect virtual machine: {error}"))?
                .is_some()
            {
                return Err("virtual machine is not running".into());
            }
            (
                process.qmp_port,
                process.is_micro_vm,
                process.micro_endpoint.clone(),
            )
        };
        match action {
            "pause" => return qmp_execute(qmp_port, "stop", None).await,
            "resume" => return qmp_execute(qmp_port, "cont", None).await,
            "restart" => return qmp_execute(qmp_port, "system_reset", None).await,
            "stop" => {}
            _ => return Err("unsupported virtual machine lifecycle action".into()),
        }

        if is_micro_vm {
            if let Some(endpoint) = micro_endpoint.as_ref() {
                if self.request_micro_vm_shutdown(endpoint).await.is_ok()
                    && self
                        .wait_for_registered_vm_exit(id, Duration::from_secs(8))
                        .await?
                {
                    return Ok(());
                }
            }
            // Custom guests have no standard power channel, and a built-in guest may
            // fail before its agent is ready. Flush the host block graph before a bounded
            // VMM quit so QCOW2 metadata is consistent; the guest filesystem journal
            // performs recovery on its next boot.
        } else if qmp_execute_bounded(qmp_port, "system_powerdown", None, Duration::from_secs(3))
            .await
            .is_ok()
            && self
                .wait_for_registered_vm_exit(id, Duration::from_secs(30))
                .await?
        {
            return Ok(());
        }

        quiesce_and_flush_vm(qmp_port, is_micro_vm).await;
        let _ = qmp_execute_bounded(qmp_port, "quit", None, Duration::from_secs(2)).await;
        if self
            .wait_for_registered_vm_exit(id, Duration::from_secs(3))
            .await?
        {
            return Ok(());
        }

        let mut process = self.vms.lock().await.remove(id);
        if let Some(process) = process.as_mut() {
            process
                .child
                .kill()
                .await
                .map_err(|error| format!("force virtual machine shutdown: {error}"))?;
            let _ = process.child.wait().await;
        }
        Ok(())
    }

    async fn wait_for_registered_vm_exit(
        &self,
        id: &str,
        timeout: Duration,
    ) -> Result<bool, String> {
        let deadline = Instant::now() + timeout;
        loop {
            let exited = {
                let mut processes = self.vms.lock().await;
                let Some(process) = processes.get_mut(id) else {
                    return Ok(true);
                };
                match process.child.try_wait() {
                    Ok(Some(_)) => {
                        processes.remove(id);
                        true
                    }
                    Ok(None) => false,
                    Err(error) => {
                        return Err(format!("wait for virtual machine shutdown: {error}"));
                    }
                }
            };
            if exited {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub async fn delete_vm(&self, id: &str) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.delete_vm(id)).await; }

        validate_runtime_identifier("virtual machine", id)?;
        let lifecycle_lock = self.vm_lifecycle_mutex(id).await;
        let _lifecycle_guard = lifecycle_lock.lock().await;
        let parent = verified_runtime_subdirectory(
            &self.data_root,
            "environments",
            "environment storage root",
        )?;
        let directory = checked_runtime_child(&parent, id, "virtual machine")?;
        let storage_exists = verified_direct_child(
            &parent,
            &directory,
            PathKind::Directory,
            "virtual machine storage",
        )?;
        let running = {
            let mut processes = self.vms.lock().await;
            processes
                .get_mut(id)
                .is_some_and(|process| process.child.try_wait().ok().flatten().is_none())
        };
        if running {
            self.vm_action_locked(id, "stop").await?;
        }
        if !storage_exists {
            return Ok(());
        }
        self.delete_computer_branch_shadow(id).await?;
        require_verified_direct_child(
            &parent,
            &directory,
            PathKind::Directory,
            "virtual machine storage",
        )?;
        match tokio::fs::remove_dir_all(&directory).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("remove virtual machine storage: {error}")),
        }
    }

    pub fn vm_security_enabled(&self, id: &str) -> Result<bool, String> {
        if let Some(engine) = self.storage_runtime(id)? { return engine.vm_security_enabled(id); }

        validate_runtime_identifier("virtual machine", id)?;
        let root = verified_runtime_subdirectory(&self.data_root, "environments", "environment storage root")?;
        let directory = checked_runtime_child(&root, id, "virtual machine")?;
        if !verified_direct_child(&root, &directory, PathKind::Directory, "VM security storage")? { return Ok(false); }
        Ok(super::vm_security::profile(&directory)?.is_some())
    }

    pub async fn create_vm_snapshot(
        &self,
        id: &str,
        disk_path: &Path,
        snapshot_id: &str,
    ) -> Result<u64, String> {
        self.inherit_storage(snapshot_id, id)?;
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.create_vm_snapshot(id, disk_path, snapshot_id)).await; }

        validate_runtime_identifier("virtual machine", id)?;
        validate_runtime_identifier("snapshot", snapshot_id)?;
        let lifecycle_lock = self.vm_lifecycle_mutex(id).await;
        let _lifecycle_guard = lifecycle_lock.lock().await;
        ensure_no_pending_vm_restore(&self.data_root, id)?;
        verify_environment_artifact(&self.data_root, id, disk_path, "virtual machine disk")?;
        if super::vm_security::profile(disk_path.parent().ok_or("Missing VM directory")?)?.is_some() {
            return Err("This VM has a virtual TPM. Use a stopped-VM local or cloud backup, which includes its disk, TPM identity and Secure Boot state. Disk-only snapshots are not safe for encrypted VMs.".into());
        }
        let qmp_port = self.live_vm_qmp_port(id).await;
        if let Some(port) = qmp_port {
            live_vm_snapshot(port, LiveSnapshot::Save, snapshot_id).await?;
        } else {
            command_output(
                &self.layout.qemu_img,
                &[
                    "snapshot".into(),
                    "-c".into(),
                    snapshot_id.into(),
                    path_string(disk_path),
                ],
                "create virtual machine snapshot",
            )
            .await?;
        }
        fs::metadata(disk_path)
            .map(|metadata| metadata.len())
            .map_err(|error| format!("read virtual machine snapshot size: {error}"))
    }

    pub async fn restore_vm_snapshot(
        &self,
        id: &str,
        disk_path: &Path,
        snapshot_id: &str,
    ) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.restore_vm_snapshot(id, disk_path, snapshot_id)).await; }

        validate_runtime_identifier("virtual machine", id)?;
        validate_runtime_identifier("snapshot", snapshot_id)?;
        let lifecycle_lock = self.vm_lifecycle_mutex(id).await;
        let _lifecycle_guard = lifecycle_lock.lock().await;
        ensure_no_pending_vm_restore(&self.data_root, id)?;
        verify_environment_artifact(&self.data_root, id, disk_path, "virtual machine disk")?;
        if super::vm_security::profile(disk_path.parent().ok_or("Missing VM directory")?)?.is_some() {
            return Err("Restore a complete local or cloud backup for this TPM-enabled VM; a disk-only snapshot cannot restore its security identity.".into());
        }
        let qmp_port = self.live_vm_qmp_port(id).await;
        if let Some(port) = qmp_port {
            live_vm_snapshot(port, LiveSnapshot::Load, snapshot_id).await
        } else {
            command_output(
                &self.layout.qemu_img,
                &[
                    "snapshot".into(),
                    "-a".into(),
                    snapshot_id.into(),
                    path_string(disk_path),
                ],
                "restore virtual machine snapshot",
            )
            .await
            .map(|_| ())
        }
    }

    pub async fn delete_vm_snapshot(
        &self,
        id: &str,
        disk_path: &Path,
        snapshot_id: &str,
    ) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.delete_vm_snapshot(id, disk_path, snapshot_id)).await; }

        validate_runtime_identifier("virtual machine", id)?;
        validate_runtime_identifier("snapshot", snapshot_id)?;
        let lifecycle_lock = self.vm_lifecycle_mutex(id).await;
        let _lifecycle_guard = lifecycle_lock.lock().await;
        ensure_no_pending_vm_restore(&self.data_root, id)?;
        verify_environment_artifact(&self.data_root, id, disk_path, "virtual machine disk")?;
        let qmp_port = self.live_vm_qmp_port(id).await;
        if let Some(port) = qmp_port {
            live_vm_snapshot(port, LiveSnapshot::Delete, snapshot_id).await
        } else {
            match command_output(
                &self.layout.qemu_img,
                &[
                    "snapshot".into(),
                    "-d".into(),
                    snapshot_id.into(),
                    path_string(disk_path),
                ],
                "delete virtual machine snapshot",
            )
            .await
            {
                // Older versions recorded running full-VM snapshots that QEMU
                // had rejected. Deleting such a record must still succeed.
                Err(error) if error.contains("snapshot not found") => Ok(()),
                result => result.map(|_| ()),
            }
        }
    }

    pub async fn export_vm_disk(
        &self,
        id: &str,
        disk_path: &Path,
        source_path: &Path,
        snapshot_id: &str,
    ) -> Result<VmArtifact, String> {
        self.inherit_storage(snapshot_id, id)?;
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.export_vm_disk(id, disk_path, source_path, snapshot_id)).await; }

        validate_runtime_identifier("virtual machine", id)?;
        validate_runtime_identifier("snapshot", snapshot_id)?;
        let lifecycle_lock = self.vm_lifecycle_mutex(id).await;
        let _lifecycle_guard = lifecycle_lock.lock().await;
        ensure_no_pending_vm_restore(&self.data_root, id)?;
        verify_environment_artifact(&self.data_root, id, disk_path, "virtual machine disk")?;
        if self.vm_is_running(id).await? {
            return Err("stop the virtual machine before exporting a consistent backup".into());
        }
        let security = super::vm_security::capture(disk_path.parent().ok_or("Missing VM directory")?)?;
        let snapshot_root =
            verified_runtime_subdirectory(&self.data_root, "snapshots", "snapshot storage root")?;
        let destination = snapshot_root.join(format!("{snapshot_id}.vm.qcow2"));
        let temporary = destination.with_extension("qcow2.part");
        let _ = tokio::fs::remove_file(&temporary).await;
        #[cfg(not(target_os = "windows"))]
        let _ = (id, source_path);
        #[cfg(target_os = "windows")]
        let branch_server = if source_path == Path::new("current-computer") {
            Some(self.start_computer_branch_block_server(id).await?)
        } else {
            None
        };
        #[cfg(not(target_os = "windows"))]
        let branch_server: Option<&super::BranchBlockServer> = None;
        let source = match branch_server.as_ref() {
            Some(server) => format!(
                "json:{}",
                branch_disk_graph(disk_path, server, "yougori-backup-source")
            ),
            None => path_string(disk_path),
        };
        let mut arguments = vec!["convert".into()];
        if security.is_some() {
            arguments.extend(["-o".into(), "cluster_size=2097152".into()]);
        }
        if branch_server.is_none() {
            arguments.extend(["-f".into(), "qcow2".into()]);
        }
        arguments.extend([
            "-O".into(),
            "qcow2".into(),
            "-c".into(),
            source,
            path_string(&temporary),
        ]);
        let conversion = command_output(
            &self.layout.qemu_img,
            &arguments,
            "export a standalone virtual machine backup",
        )
        .await;
        if let Err(error) = conversion {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(error);
        }
        if let Some(security) = &security {
            if let Err(error) = super::vm_security::embed_backup(&temporary, security) {
                let _ = tokio::fs::remove_file(&temporary).await;
                return Err(error);
            }
        }
        if let Err(error) = command_output(
            &self.layout.qemu_img,
            &["check".into(), "-q".into(), path_string(&temporary)],
            "verify exported virtual machine backup",
        )
        .await
        {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(error);
        }
        let _ = tokio::fs::remove_file(&destination).await;
        tokio::fs::rename(&temporary, &destination)
            .await
            .map_err(|error| format!("finalize virtual machine backup: {error}"))?;
        let (size_bytes, checksum_sha256) = hash_file(destination.clone()).await?;
        Ok(VmArtifact {
            path: destination,
            size_bytes,
            checksum_sha256,
        })
    }

    pub async fn install_vm_backup(
        &self,
        id: &str,
        artifact_path: &Path,
    ) -> Result<PathBuf, String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.install_vm_backup(id, artifact_path)).await; }

        validate_runtime_identifier("virtual machine", id)?;
        let lifecycle_lock = self.vm_lifecycle_mutex(id).await;
        let _lifecycle_guard = lifecycle_lock.lock().await;
        ensure_no_pending_vm_restore(&self.data_root, id)?;
        if self.vm_is_running(id).await? {
            return Err("stop the virtual machine before restoring its disk".into());
        }
        // Before qemu-img opens it: a backing or external data file would make
        // the restored disk read another host file or a remote share.
        ensure_standalone_qcow2(artifact_path)?;
        let security = super::vm_security::read_backup(artifact_path)?;
        command_output(
            &self.layout.qemu_img,
            &["check".into(), "-q".into(), path_string(artifact_path)],
            "verify restored virtual machine backup",
        )
        .await?;
        let environments_root = verified_runtime_subdirectory(
            &self.data_root,
            "environments",
            "environment storage root",
        )?;
        let environment_directory =
            checked_runtime_child(&environments_root, id, "virtual machine")?;
        let created_environment_directory = !environment_directory.exists();
        if !created_environment_directory {
            require_verified_direct_child(
                &environments_root,
                &environment_directory,
                PathKind::Directory,
                "restored virtual machine storage",
            )?;
        }
        tokio::fs::create_dir_all(&environment_directory)
            .await
            .map_err(|error| format!("create restored environment storage: {error}"))?;
        require_verified_direct_child(
            &environments_root,
            &environment_directory,
            PathKind::Directory,
            "restored virtual machine storage",
        )?;
        let previous_security = super::vm_security::profile(&environment_directory)?;
        if previous_security.is_some() && security.is_none() {
            return Err("This disk-only backup has no TPM identity. Restore it as a separate environment instead of replacing a TPM-enabled VM.".into());
        }
        let next_security = security.as_ref().map(|backup| backup.stage(&environment_directory)).transpose()?;
        let uefi_vars = environment_directory.join("uefi-vars.fd");
        match tokio::fs::symlink_metadata(&uefi_vars).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(
                    "refusing restored virtual machine firmware state that is not a real file"
                        .into(),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if let Err(error) = tokio::fs::copy(&self.layout.uefi_vars, &uefi_vars).await {
                    if created_environment_directory {
                        let _ = remove_verified_directory(
                            &environments_root,
                            &environment_directory,
                            "failed restored virtual machine storage",
                        )
                        .await;
                    }
                    return Err(format!(
                        "create restored virtual machine firmware state: {error}"
                    ));
                }
            }
            Err(error) => {
                return Err(format!(
                    "inspect restored virtual machine firmware state: {error}"
                ));
            }
        }
        let disk_path = environment_directory.join("system.qcow2");
        let (transaction_path, previous, temporary) =
            vm_restore_transaction_paths(&environment_directory);
        let had_previous_disk = match tokio::fs::symlink_metadata(&disk_path).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => true,
            Ok(_) => {
                return Err("refusing to replace a VM disk that is not a real file".into());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(format!("inspect current virtual machine disk: {error}")),
        };
        let _ = tokio::fs::remove_file(&temporary).await;
        let conversion = command_output(
            &self.layout.qemu_img,
            &[
                "convert".into(),
                "-f".into(),
                "qcow2".into(),
                "-O".into(),
                "qcow2".into(),
                "-c".into(),
                path_string(artifact_path),
                path_string(&temporary),
            ],
            "install restored virtual machine backup",
        )
        .await;
        if let Err(error) = conversion {
            let _ = tokio::fs::remove_file(&temporary).await;
            if created_environment_directory {
                let _ = remove_verified_directory(
                    &environments_root,
                    &environment_directory,
                    "failed restored virtual machine storage",
                )
                .await;
            }
            return Err(error);
        }
        if let Err(error) = command_output(
            &self.layout.qemu_img,
            &["check".into(), "-q".into(), path_string(&temporary)],
            "verify installed virtual machine disk",
        )
        .await
        {
            let _ = tokio::fs::remove_file(&temporary).await;
            if created_environment_directory {
                let _ = remove_verified_directory(
                    &environments_root,
                    &environment_directory,
                    "failed restored virtual machine storage",
                )
                .await;
            }
            return Err(error);
        }
        let transaction = VmRestoreTransaction {
            version: VM_RESTORE_TRANSACTION_VERSION,
            had_previous_disk,
            created_environment_directory,
            security_changed: next_security.is_some(),
            previous_security,
            next_security,
        };
        let transaction_bytes = match serde_json::to_vec(&transaction) {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = tokio::fs::remove_file(&temporary).await;
                return Err(format!("encode VM restore transaction: {error}"));
            }
        };
        if let Err(error) = write_durable_file(transaction_path.clone(), transaction_bytes).await {
            let _ = tokio::fs::remove_file(&temporary).await;
            if created_environment_directory {
                let _ = remove_verified_directory(
                    &environments_root,
                    &environment_directory,
                    "failed restored virtual machine storage",
                )
                .await;
            }
            return Err(error);
        }
        if had_previous_disk {
            if let Err(error) = tokio::fs::rename(&disk_path, &previous).await {
                let _ = tokio::fs::remove_file(&transaction_path).await;
                let _ = tokio::fs::remove_file(&temporary).await;
                return Err(format!("preserve current virtual machine disk: {error}"));
            }
        }
        if let Err(error) = tokio::fs::rename(&temporary, &disk_path).await {
            if had_previous_disk {
                if let Err(rollback_error) = tokio::fs::rename(&previous, &disk_path).await {
                    return Err(format!(
                        "activate restored virtual machine disk: {error}; preserving rollback transaction after previous disk reactivation failed: {rollback_error}"
                    ));
                }
            }
            let _ = tokio::fs::remove_file(&transaction_path).await;
            let _ = tokio::fs::remove_file(&temporary).await;
            if created_environment_directory {
                let _ = remove_verified_directory(
                    &environments_root,
                    &environment_directory,
                    "failed restored virtual machine storage",
                )
                .await;
            }
            return Err(format!("activate restored virtual machine disk: {error}"));
        }
        if transaction.security_changed {
            super::vm_security::activate(&environment_directory, transaction.next_security.as_ref()).await
                .map_err(|e| format!("Restore security state: {e}. Disk and security rollback information were preserved; resolve the pending restore before starting."))?;
        }
        Ok(disk_path)
    }

    /// Commits a disk restore only after the caller has durably persisted the
    /// corresponding environment state. Until this is called, starts and snapshot
    /// mutations are rejected and the old disk remains available for rollback.
    pub fn has_pending_vm_backup_install(&self, id: &str) -> Result<bool, String> {
        if let Some(engine) = self.storage_runtime(id)? { return engine.has_pending_vm_backup_install(id); }

        validate_runtime_identifier("virtual machine", id)?;
        let environments_root = verified_runtime_subdirectory(
            &self.data_root,
            "environments",
            "environment storage root",
        )?;
        let environment_directory =
            checked_runtime_child(&environments_root, id, "virtual machine")?;
        if !verified_direct_child(
            &environments_root,
            &environment_directory,
            PathKind::Directory,
            "restored virtual machine storage",
        )? {
            return Ok(false);
        }
        let (transaction, previous, temporary) =
            vm_restore_transaction_paths(&environment_directory);
        if read_vm_restore_transaction(&transaction)?.is_some() {
            return Ok(true);
        }
        for path in [previous, temporary] {
            if verified_direct_child(
                &environment_directory,
                &path,
                PathKind::File,
                "VM restore transaction artifact",
            )? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub async fn finalize_vm_backup_install(&self, id: &str) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.finalize_vm_backup_install(id)).await; }

        validate_runtime_identifier("virtual machine", id)?;
        let lifecycle_lock = self.vm_lifecycle_mutex(id).await;
        let _lifecycle_guard = lifecycle_lock.lock().await;
        let environments_root = verified_runtime_subdirectory(
            &self.data_root,
            "environments",
            "environment storage root",
        )?;
        let environment_directory =
            checked_runtime_child(&environments_root, id, "virtual machine")?;
        if !verified_direct_child(
            &environments_root,
            &environment_directory,
            PathKind::Directory,
            "restored virtual machine storage",
        )? {
            return Ok(());
        }
        let (transaction, previous, temporary) =
            vm_restore_transaction_paths(&environment_directory);
        if self.vm_is_running(id).await? { return Err("Stop the VM before finalizing a restore".into()); }
        if let Some(state) = read_vm_restore_transaction(&transaction)? {
            if state.security_changed {
                // Also covers a crash after the disk rename but before profile activation.
                super::vm_security::activate(&environment_directory, state.next_security.as_ref()).await?;
            }
        }
        remove_verified_file(
            &environment_directory,
            &temporary,
            "temporary restored virtual machine disk",
        )
        .await?;
        remove_verified_file(
            &environment_directory,
            &previous,
            "previous virtual machine disk",
        )
        .await?;
        remove_verified_file(
            &environment_directory,
            &transaction,
            "VM restore transaction",
        )
        .await
    }

    /// Restores the pre-install disk when the caller cannot persist restored state.
    /// This method is idempotent across the intermediate phases recorded on disk.
    pub async fn rollback_vm_backup_install(&self, id: &str) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.rollback_vm_backup_install(id)).await; }

        validate_runtime_identifier("virtual machine", id)?;
        let lifecycle_lock = self.vm_lifecycle_mutex(id).await;
        let _lifecycle_guard = lifecycle_lock.lock().await;
        if self.vm_is_running(id).await? {
            return Err("stop the virtual machine before rolling back its disk restore".into());
        }
        let environments_root = verified_runtime_subdirectory(
            &self.data_root,
            "environments",
            "environment storage root",
        )?;
        let environment_directory =
            checked_runtime_child(&environments_root, id, "virtual machine")?;
        require_verified_direct_child(
            &environments_root,
            &environment_directory,
            PathKind::Directory,
            "restored virtual machine storage",
        )?;
        let disk_path = environment_directory.join("system.qcow2");
        let (transaction_path, previous, temporary) =
            vm_restore_transaction_paths(&environment_directory);
        let transaction = read_vm_restore_transaction(&transaction_path)?;
        let previous_exists = verified_direct_child(
            &environment_directory,
            &previous,
            PathKind::File,
            "previous virtual machine disk",
        )?;
        if transaction.is_none() && !previous_exists {
            if verified_direct_child(
                &environment_directory,
                &temporary,
                PathKind::File,
                "temporary restored virtual machine disk",
            )? {
                return remove_verified_file(
                    &environment_directory,
                    &temporary,
                    "temporary restored virtual machine disk",
                )
                .await;
            }
            return Err("virtual machine has no pending disk restore to roll back".into());
        }
        let had_previous_disk = transaction
            .as_ref()
            .map_or(previous_exists, |value| value.had_previous_disk);
        let created_environment_directory = transaction
            .as_ref()
            .is_some_and(|value| value.created_environment_directory);
        let disk_exists = verified_direct_child(
            &environment_directory,
            &disk_path,
            PathKind::File,
            "restored virtual machine disk",
        )?;

        if had_previous_disk && previous_exists {
            let displaced = environment_directory.join(format!(
                ".system.failed-restore.{}.qcow2",
                Uuid::new_v4().simple()
            ));
            if disk_exists {
                tokio::fs::rename(&disk_path, &displaced)
                    .await
                    .map_err(|error| format!("stage restored VM disk for rollback: {error}"))?;
            }
            if let Err(error) = tokio::fs::rename(&previous, &disk_path).await {
                if disk_exists {
                    let _ = tokio::fs::rename(&displaced, &disk_path).await;
                }
                return Err(format!("reactivate previous virtual machine disk: {error}"));
            }
            if disk_exists {
                let _ = tokio::fs::remove_file(&displaced).await;
            }
        } else if !had_previous_disk && disk_exists {
            remove_verified_file(
                &environment_directory,
                &disk_path,
                "restored virtual machine disk",
            )
            .await?;
        }

        if let Some(state) = &transaction {
            if state.security_changed {
                super::vm_security::activate(&environment_directory, state.previous_security.as_ref()).await?;
            }
        }
        if created_environment_directory {
            return remove_verified_directory(
                &environments_root,
                &environment_directory,
                "rolled-back virtual machine storage",
            )
            .await;
        }
        remove_verified_file(
            &environment_directory,
            &temporary,
            "temporary restored virtual machine disk",
        )
        .await?;
        remove_verified_file(
            &environment_directory,
            &transaction_path,
            "VM restore transaction",
        )
        .await
    }

    pub async fn remove_snapshot_artifact(&self, artifact_path: &Path) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime_for_path(artifact_path)? { return Box::pin(engine.remove_snapshot_artifact(artifact_path)).await; }

        let snapshot_root =
            verified_runtime_subdirectory(&self.data_root, "snapshots", "snapshot storage root")?;
        if !verified_direct_child(
            &snapshot_root,
            artifact_path,
            PathKind::File,
            "virtual machine snapshot artifact",
        )? {
            return Ok(());
        }
        match tokio::fs::remove_file(artifact_path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("remove virtual machine snapshot artifact: {error}")),
        }
    }

    pub async fn vm_is_running(&self, id: &str) -> Result<bool, String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.vm_is_running(id)).await; }

        validate_runtime_identifier("virtual machine", id)?;
        let mut processes = self.vms.lock().await;
        let Some(process) = processes.get_mut(id) else {
            return Ok(false);
        };
        // A boolean probe must not consume the exit status before telemetry can
        // distinguish a normal shutdown from a crash.
        process.child.try_wait()
            .map(|status| status.is_none())
            .map_err(|error| format!("inspect virtual machine process: {error}"))
    }

    /// Guest resets keep QEMU alive. A successful exit is a guest shutdown,
    /// while panic=exit-failure and process failures must still surface as errors.
    pub async fn vm_power_state(&self, id: &str) -> Result<super::VmPowerState, String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.vm_power_state(id)).await; }

        validate_runtime_identifier("virtual machine", id)?;
        let mut processes = self.vms.lock().await;
        let Some(process) = processes.get_mut(id) else {
            return Ok(super::VmPowerState::Failed);
        };
        match process.child.try_wait() {
            Ok(None) => {
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    let port = process.qmp_port;
                    drop(processes);
                    // Older distro QEMU cannot exit-failure on panic. Keep the
                    // disk open/inspectable, but report the QMP failure honestly.
                    if let Ok(Ok(status)) = tokio::time::timeout(Duration::from_millis(500), qmp_request(port, "query-status", None)).await {
                        if matches!(status["status"].as_str(), Some("guest-panicked" | "internal-error" | "io-error")) {
                            return Ok(super::VmPowerState::Failed);
                        }
                    }
                }
                Ok(super::VmPowerState::Running)
            },
            Ok(Some(status)) => {
                processes.remove(id);
                Ok(if status.success() {
                    super::VmPowerState::Stopped
                } else {
                    super::VmPowerState::Failed
                })
            }
            Err(error) => Err(format!("inspect virtual machine process: {error}")),
        }
    }

    pub async fn vm_console(&self, id: &str) -> Result<VmConsole, String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.vm_console(id)).await; }

        validate_runtime_identifier("virtual machine", id)?;
        let mut processes = self.vms.lock().await;
        let process = processes
            .get_mut(id)
            .ok_or_else(|| "virtual machine is not running".to_string())?;
        if process
            .child
            .try_wait()
            .map_err(|error| format!("inspect virtual machine: {error}"))?
            .is_some()
        {
            // Leave the exit code for vm_power_state: opening a viewer must
            // not turn a normal shutdown into an apparent missing-process crash.
            return Err("virtual machine is not running".into());
        }
        let headless = process.is_micro_vm;
        Ok(VmConsole {
            websocket_url: if headless {
                String::new()
            } else {
                format!("ws://127.0.0.1:{}", process.websocket_port)
            },
            password: process.console_password.clone(),
            headless,
            serial_log_path: headless.then(|| {
                self.data_root
                    .join("environments")
                    .join(id)
                    .join("serial.log")
            }),
            guest_control_available: process.micro_endpoint.is_some(),
        })
    }

    pub async fn update_vm_resources(
        &self,
        id: &str,
        cpus: f64,
        memory_gb: f64,
    ) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.update_vm_resources(id, cpus, memory_gb)).await; }

        validate_runtime_identifier("virtual machine", id)?;
        if cfg!(target_os = "macos") {
            return Err("macOS VM CPU and memory changes apply after shutdown and restart; no live CPU limit was applied.".into());
        }
        let lifecycle_lock = self.vm_lifecycle_mutex(id).await;
        let _lifecycle_guard = lifecycle_lock.lock().await;
        let (process_id, qmp_port, headless) = {
            let mut processes = self.vms.lock().await;
            let process = processes
                .get_mut(id)
                .ok_or_else(|| "virtual machine is not running".to_string())?;
            if process
                .child
                .try_wait()
                .map_err(|error| format!("inspect virtual machine: {error}"))?
                .is_some()
            {
                return Err("virtual machine is not running".into());
            }
            (process.process_id, process.qmp_port, process.is_micro_vm)
        };
        if headless {
            // The direct-kernel microVM profile has a fixed, minimal memory footprint.
            // It deliberately omits ACPI memory hotplug and does not preallocate the
            // policy maximum merely to balloon most of it away. Memory policy changes
            // therefore take effect on the next microVM start; live CPU changes still apply.
            let _ = memory_gb;
            apply_process_cpu_limit(process_id, cpus)?;
        } else {
            apply_vm_resource_limits(process_id, qmp_port, cpus, memory_gb).await?;
        }
        if let Some(process) = self.vms.lock().await.get_mut(id) {
            process.allocated_cpus = cpus.round().max(1.0) as usize;
        }
        Ok(())
    }


    #[allow(clippy::too_many_arguments)]
    fn spawn_full_vm(
        &self,
        id: &str,
        disk_path: &Path,
        source_path: &Path,
        cpus: f64,
        max_cpus: f64,
        memory_gb: f64,
        qmp_port: u16,
        websocket_port: u16,
        display: u16,
        accelerator: &str,
        gpu_access: bool,
        gpu_launch: Option<&super::gpu::GpuLaunch>,
        branch_block_server: Option<&super::BranchBlockServer>,
        private_port: u16,
        network_arguments: &[String],
    ) -> Result<tokio::process::Child, String> {
        let environment_directory = self.data_root.join("environments").join(id);
        let secure_profile = super::vm_security::profile(&environment_directory)?;
        let branch_boot_path = environment_directory.join("branch-boot.qcow2");
        let has_branch_boot = match fs::symlink_metadata(&branch_boot_path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => true,
            Ok(_) => {
                return Err("computer branch boot disk is not a safe regular file".into());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(format!("inspect computer branch boot disk: {error}")),
        };
        let has_install_media = source_path
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("iso"))
            && source_path.is_file();
        let error_path = environment_directory.join("qemu.log");
        let error_log = create_managed_output_file(&error_path, "virtual machine log")?;
        let minimum_cpus = cpus.round().clamp(1.0, 255.0) as u16;
        let maximum_cpus = max_cpus.ceil().clamp(f64::from(minimum_cpus), 255.0) as u16;
        let memory_mib = super::vm_memory::startup_bytes(memory_gb, true) / (1024 * 1024);
        let disk_file = json!({
            "driver": "file",
            "filename": path_string(disk_path),
            "node-name": "yougori-vm-file"
        })
        .to_string();
        let disk = match branch_block_server {
            Some(server) => {
                let mut graph = branch_disk_graph(disk_path, server, "yougori-vm-disk");
                graph["file"] = json!("yougori-vm-file");
                graph
            }
            None => json!({
                "driver": "qcow2",
                "file": "yougori-vm-file",
                "node-name": "yougori-vm-disk"
            }),
        }
        .to_string();
        let firmware_code_file = json!({
            "driver": "file",
            "filename": path_string(&self.layout.uefi_code),
            "node-name": "yougori-uefi-code-file",
            "read-only": true
        })
        .to_string();
        let firmware_code = json!({
            "driver": "raw",
            "file": "yougori-uefi-code-file",
            "node-name": "yougori-uefi-code",
            "read-only": true
        })
        .to_string();
        let firmware_vars_path = environment_directory.join("uefi-vars.fd");
        match fs::symlink_metadata(&firmware_vars_path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(
                    "persistent virtual machine firmware state is not a safe regular file".into(),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::copy(&self.layout.uefi_vars, &firmware_vars_path).map_err(|error| {
                    format!("create persistent virtual machine firmware state: {error}")
                })?;
            }
            Err(error) => {
                return Err(format!(
                    "inspect persistent virtual machine firmware state: {error}"
                ));
            }
        }
        let firmware_vars_file = json!({
            "driver": "file",
            "filename": path_string(&firmware_vars_path),
            "node-name": "yougori-uefi-vars-file"
        })
        .to_string();
        let firmware_vars = json!({
            "driver": "raw",
            "file": "yougori-uefi-vars-file",
            "node-name": "yougori-uefi-vars"
        })
        .to_string();
        let graphics = full_vm_graphics_arguments(gpu_access);
        let mut arguments = vec![
            "-name".into(),
            format!("Yougori {id}"),
            "-machine".into(),
            // Let WHPX choose its supported interrupt controller. Forcing the
            // userspace APIC hangs Windows during multiprocessor initialization.
            if secure_profile.is_some() { "q35".into() } else { "q35,pflash0=yougori-uefi-code,pflash1=yougori-uefi-vars".into() },
            "-accel".into(),
            accelerator.into(),
            // Like the OCI runtime, expose modern instructions instead of
            // qemu64's legacy feature baseline (insufficient for current OSes).
            "-cpu".into(),
            full_vm_cpu_model(accelerator).into(),
            "-smp".into(),
            format!(
                "cpus={maximum_cpus},maxcpus={maximum_cpus},sockets=1,cores={maximum_cpus},threads=1"
            ),
            "-m".into(),
            memory_mib.to_string(),
            "-no-user-config".into(),
            "-nodefaults".into(),
            "-blockdev".into(),
            disk_file,
            "-blockdev".into(),
            disk,
            "-device".into(),
            format!(
                "ide-hd,drive=yougori-vm-disk,bus=ide.0,bootindex={}",
                if has_branch_boot { 2 } else { 1 }
            ),
            // Preserve the primary adapter's original PCI enumeration position
            // so enabling graphics does not move the NIC or other devices.
            graphics[0].into(),
            graphics[1].into(),
            "-device".into(),
            "qemu-xhci,p2=15,p3=15".into(),
            "-device".into(),
            "usb-tablet".into(),
            "-device".into(),
            "usb-kbd".into(),
            "-netdev".into(),
            "user,id=net0".into(),
            "-device".into(),
            "e1000e,netdev=net0".into(),
            "-S".into(),
            "-device".into(),
            "virtio-rng-pci".into(),
            "-device".into(),
            "virtio-balloon-pci,id=yougori-balloon".into(),
            "-vnc".into(),
            format!(
                "127.0.0.1:{display},websocket=127.0.0.1:{websocket_port},share=force-shared,password=on"
            ),
            "-qmp".into(),
            format!("tcp:127.0.0.1:{qmp_port},server=on,wait=off"),
            "-monitor".into(),
            "none".into(),
            "-action".into(),
            // Windows Setup and OS updates reboot repeatedly. Reset inside the
            // same process/display; never turn a guest reboot into host shutdown.
            if cfg!(any(target_os = "linux", target_os = "macos")) { "reboot=reset,shutdown=poweroff,panic=pause" } else { "reboot=reset,shutdown=poweroff,panic=exit-failure" }.into(),
            "-rtc".into(),
            "base=localtime".into(),
            "-boot".into(),
            "menu=on".into(),
            "-L".into(),
            path_string(&self.layout.qemu_data()),
        ];
        arguments.extend(graphics.into_iter().skip(2).map(String::from));
        arguments.extend(super::import_drive::drive_arguments(&environment_directory)?);
        if has_branch_boot {
            let boot_file = json!({
                "driver": "file",
                "filename": path_string(&branch_boot_path),
                "node-name": "yougori-branch-boot-file"
            })
            .to_string();
            let boot_disk = json!({
                "driver": "qcow2",
                "file": "yougori-branch-boot-file",
                "node-name": "yougori-branch-boot-disk"
            })
            .to_string();
            arguments.extend([
                "-blockdev".into(),
                boot_file,
                "-blockdev".into(),
                boot_disk,
                "-device".into(),
                "ide-hd,drive=yougori-branch-boot-disk,bus=ide.1,bootindex=1".into(),
            ]);
        }
        if has_install_media {
            // Boot an installed disk first. An empty disk falls through to our
            // read-only helper, which starts Windows Setup without a key race.
            let helper = super::boot_media::prepare(&environment_directory)?;
            arguments.extend([
                "-blockdev".into(),
                json!({"driver":"file","filename":path_string(&helper),"node-name":"yougori-boot-file","read-only":true}).to_string(),
                "-blockdev".into(),
                json!({"driver":"raw","file":"yougori-boot-file","node-name":"yougori-boot-disk","read-only":true}).to_string(),
                "-device".into(), "usb-storage,drive=yougori-boot-disk,bootindex=2".into(),
                "-chardev".into(), "ringbuf,id=yougori-boot-log,size=4096".into(),
                "-device".into(), "isa-debugcon,iobase=0xe9,chardev=yougori-boot-log".into(),
            ]);
            let media_file = json!({
                "driver": "file",
                "filename": path_string(source_path),
                "node-name": "yougori-install-media-file",
                "read-only": true
            })
            .to_string();
            let media = json!({
                "driver": "raw",
                "file": "yougori-install-media-file",
                "node-name": "yougori-install-media",
                "read-only": true
            })
            .to_string();
            arguments.extend([
                "-blockdev".into(),
                media_file,
                "-blockdev".into(),
                media,
                "-device".into(),
                "ide-cd,drive=yougori-install-media,bus=ide.1,bootindex=3".into(),
            ]);
        }
        let executable = if let Some(profile) = secure_profile {
            let root = self.layout.root.join("qemu-secure");
            let state = profile.directory(&environment_directory)?;
            arguments.extend([
                "-bios".into(), path_string(&profile.firmware(&root)?),
                "-device".into(), format!("uefi-vars-x64,jsonfile={},force-secure-boot=on,disable-custom-mode=on", path_string(&state.join("uefi-vars.json")).replace(',', ",,")),
                "-tpmdev".into(), format!("yougori,id=yougori-tpm,state={}", path_string(&state.join("tpm.nv")).replace(',', ",,")),
                // TIS transports TPM 2.0 too. CRB's sub-page command RAM cannot
                // be mapped by WHPX and otherwise forces slow TCG fallback.
                "-device".into(), "tpm-tis,tpmdev=yougori-tpm".into(),
            ]);
            root.join("qemu-system-x86_64.exe")
        } else {
            arguments.extend(["-blockdev".into(), firmware_code_file, "-blockdev".into(), firmware_code,
                "-blockdev".into(), firmware_vars_file, "-blockdev".into(), firmware_vars]);
            // All Windows full VMs need the native runtime's WHPX partition
            // reset fix, including guests that do not use Secure Boot/TPM.
            // Keep their existing firmware and identity unchanged.
            if cfg!(target_os = "windows") {
                self.layout.root.join("qemu-secure/qemu-system-x86_64.exe")
            } else {
                self.layout.qemu_system.clone()
            }
        };
        #[cfg(test)]
        arguments.extend(["-serial".into(), format!("file:{}", environment_directory.join("firmware-serial.log").display())]);
        let mut command = tokio::process::Command::new(&executable);
        arguments.extend_from_slice(network_arguments);
        arguments.extend(super::fabric::qemu_args(id, private_port, false));
        command
            .current_dir(executable.parent().unwrap_or(&self.layout.root))
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(error_log));
        configure_background_process(&mut command);
        super::configure_qemu_sandbox(&mut command);
        if let Some(launch) = gpu_launch { launch.configure(&mut command)?; }
        let child = command
            .spawn()
            .map_err(|error| format!("start bundled virtual machine: {error}"))?;
        super::guest_job::contain(&child)?;
        Ok(child)
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_micro_vm(
        &self,
        id: &str,
        disk_path: &Path,
        manifest: &ManagedMicroVmManifest,
        cpus: f64,
        max_cpus: f64,
        memory_gb: f64,
        qmp_port: u16,
        accelerator: &str,
        endpoint: Option<&AgentEndpoint>,
        private_port: u16,
        network_arguments: &[String],
    ) -> Result<tokio::process::Child, String> {
        let environment_directory = self.data_root.join("environments").join(id);
        let error_path = environment_directory.join("qemu.log");
        let error_log = create_managed_output_file(&error_path, "microVM log")?;
        let serial_path = environment_directory.join("serial.log");
        drop(create_managed_output_file(
            &serial_path,
            "microVM serial log",
        )?);
        let minimum_cpus = cpus.round().clamp(1.0, 255.0) as u16;
        let maximum_cpus = max_cpus.ceil().clamp(f64::from(minimum_cpus), 255.0) as u16;
        let memory_mib = super::vm_memory::startup_bytes(memory_gb, false) / (1024 * 1024);
        let machine_accelerator_options = if accelerator == "whpx" {
            ",kernel-irqchip=off"
        } else {
            ""
        };
        let (kernel, initrd) = micro_vm_boot_files(
            manifest, &self.layout.appliance_kernel, &self.layout.appliance_initramfs,
        )?;
        let disk_file = json!({
            "driver": "file",
            "filename": path_string(disk_path),
            "node-name": "yougori-microvm-file"
        })
        .to_string();
        let disk = json!({
            "driver": "qcow2",
            "file": "yougori-microvm-file",
            "node-name": "yougori-microvm-disk"
        })
        .to_string();
        // Apply host compatibility to existing built-in guests at launch,
        // without rewriting their saved manifests or custom kernel settings.
        let kernel_cmdline = if manifest.builtin {
            format!("{}{}", manifest.cmdline, super::host_platform::micro_vm_kernel_options(
                std::env::consts::OS, std::env::consts::ARCH, accelerator,
            ))
        } else {
            manifest.cmdline.clone()
        };
        let cmdline = match endpoint {
            Some(endpoint) => format!(
                "{} softlevel=microvm yougori.mode=microvm yougori.token={} yougori.time={}",
                kernel_cmdline, endpoint.token,
                SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs()
            ),
            None => kernel_cmdline,
        };
        let netdev = match endpoint {
            Some(endpoint) => {
                let port = endpoint
                    .base_url
                    .rsplit(':')
                    .next()
                    .ok_or_else(|| "microVM guest control endpoint has no port".to_string())?;
                format!("user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:7443")
            }
            None => "user,id=net0".into(),
        };
        let mut arguments = vec![
            "-name".into(),
            format!("Yougori microVM {id}"),
            "-machine".into(),
            format!(
                "microvm{machine_accelerator_options},graphics=off,acpi=off,pcie=off,usb=off,{},x-option-roms=off",
                // Nested KVM and older CPUs may not expose TSC_DEADLINE. Keep
                // legacy timers so boot does not silently stall on these hosts.
                if cfg!(any(target_os = "linux", target_os = "macos")) { "pic=on,pit=on,rtc=on" } else { "pic=off,pit=off,rtc=off" }
            ),
            "-accel".into(),
            accelerator.into(),
            "-smp".into(),
            format!(
                "cpus={maximum_cpus},maxcpus={maximum_cpus},sockets=1,cores={maximum_cpus},threads=1"
            ),
            "-m".into(),
            memory_mib.to_string(),
            "-no-user-config".into(),
            "-nodefaults".into(),
            "-kernel".into(),
            path_string(kernel),
            "-append".into(),
            cmdline,
            "-blockdev".into(),
            disk_file,
            "-blockdev".into(),
            disk,
            "-device".into(),
            "virtio-blk-device,drive=yougori-microvm-disk".into(),
            "-netdev".into(),
            netdev,
            "-device".into(),
            "virtio-net-device,netdev=net0".into(),
            "-device".into(),
            "virtio-rng-device".into(),
            "-device".into(),
            "virtio-balloon-device,id=yougori-balloon".into(),
            "-display".into(),
            "none".into(),
            "-serial".into(),
            format!("file:{}", path_string(&serial_path)),
            "-qmp".into(),
            format!("tcp:127.0.0.1:{qmp_port},server=on,wait=off"),
            "-monitor".into(),
            "none".into(),
            "-action".into(),
            if cfg!(any(target_os = "linux", target_os = "macos")) { "panic=pause" } else { "panic=exit-failure" }.into(),
            "-no-reboot".into(),
        ];
        if let Some(initrd) = initrd {
            arguments.extend(["-initrd".into(), path_string(initrd)]);
        }
        arguments.extend(["-cpu".into(), full_vm_cpu_model(accelerator).into()]);
        arguments.extend(["-L".into(), path_string(&self.layout.qemu_data())]);
        arguments.extend_from_slice(network_arguments);
        arguments.extend(super::fabric::qemu_args(id, private_port, true));
        let mut command = tokio::process::Command::new(&self.layout.qemu_system);
        command
            .current_dir(
                self.layout
                    .qemu_system
                    .parent()
                    .unwrap_or(&self.layout.root),
            )
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(error_log));
        configure_background_process(&mut command);
        super::configure_qemu_sandbox(&mut command);
        let child = command
            .spawn()
            .map_err(|error| format!("start bundled microVM: {error}"))?;
        super::guest_job::contain(&child)?;
        Ok(child)
    }
}

#[derive(Clone, Copy)]
enum PathKind {
    File,
    Directory,
}

/// VNC authentication uses at most eight characters. Draw each from 64
/// symbols (48 random bits) instead of eight hex digits (32 bits).
fn vnc_console_password() -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let random = Uuid::new_v4();
    let bits = random.as_bytes()[..6]
        .iter()
        .fold(0_u64, |value, byte| value << 8 | u64::from(*byte));
    (0..8)
        .map(|index| ALPHABET[((bits >> (index * 6)) & 63) as usize] as char)
        .collect()
}

pub(super) fn validate_runtime_identifier(kind: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{kind} identifier cannot be empty"));
    }
    if value.len() > MAX_RUNTIME_IDENTIFIER_BYTES {
        return Err(format!(
            "{kind} identifier exceeds {MAX_RUNTIME_IDENTIFIER_BYTES} bytes"
        ));
    }
    if matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return Err(format!(
            "{kind} identifier may contain only ASCII letters, numbers, '_', '.', and '-'"
        ));
    }
    Ok(())
}

fn checked_runtime_child(root: &Path, id: &str, kind: &str) -> Result<PathBuf, String> {
    validate_runtime_identifier(kind, id)?;
    let child = root.join(id);
    if child.parent() != Some(root) || child == root {
        return Err(format!("refusing an unsafe {kind} storage path"));
    }
    Ok(child)
}

/// Verifies both the lexical and resolved parent immediately before a sensitive
/// filesystem operation. This rejects persisted `..`, symlink, and junction escapes
/// instead of relying on lexical `starts_with`, which is not a security boundary.
fn verified_direct_child(
    root: &Path,
    child: &Path,
    expected_kind: PathKind,
    description: &str,
) -> Result<bool, String> {
    if child.parent() != Some(root) || child == root {
        return Err(format!("refusing an unsafe {description} path"));
    }
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("inspect {description} root {}: {error}", root.display()))?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing a {description} root that is not a real directory"
        ));
    }
    let canonical_root = fs::canonicalize(root)
        .map_err(|error| format!("resolve {description} root {}: {error}", root.display()))?;
    let metadata = match fs::symlink_metadata(child) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(format!(
                "inspect {description} {}: {error}",
                child.display()
            ));
        }
    };
    if metadata.file_type().is_symlink()
        || match expected_kind {
            PathKind::File => !metadata.is_file(),
            PathKind::Directory => !metadata.is_dir(),
        }
    {
        return Err(format!(
            "refusing a {description} that is not a real {}",
            match expected_kind {
                PathKind::File => "file",
                PathKind::Directory => "directory",
            }
        ));
    }
    let canonical_child = fs::canonicalize(child)
        .map_err(|error| format!("resolve {description} {}: {error}", child.display()))?;
    if canonical_child.parent() != Some(canonical_root.as_path()) {
        return Err(format!(
            "refusing a {description} outside its managed directory"
        ));
    }
    Ok(true)
}

fn create_managed_output_file(path: &Path, description: &str) -> Result<File, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            // Unlink first so a hard-linked log cannot cause truncation outside the
            // managed environment. create_new also fails safely if a path is raced in.
            fs::remove_file(path)
                .map_err(|error| format!("replace {description} {}: {error}", path.display()))?;
        }
        Ok(_) => {
            return Err(format!(
                "refusing {description} that is not a safe regular file: {}",
                path.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!("inspect {description} {}: {error}", path.display()));
        }
    }
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("create {description} {}: {error}", path.display()))
}

fn safe_regular_file_size(path: &Path, description: &str) -> Result<Option<u64>, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            Ok(Some(metadata.len()))
        }
        Ok(_) => Err(format!(
            "{description} is not a safe regular file: {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("inspect {description} {}: {error}", path.display())),
    }
}

fn require_verified_direct_child(
    root: &Path,
    child: &Path,
    expected_kind: PathKind,
    description: &str,
) -> Result<(), String> {
    if verified_direct_child(root, child, expected_kind, description)? {
        Ok(())
    } else {
        Err(format!("{description} is missing: {}", child.display()))
    }
}

async fn remove_verified_directory(
    root: &Path,
    directory: &Path,
    description: &str,
) -> Result<(), String> {
    if !verified_direct_child(root, directory, PathKind::Directory, description)? {
        return Ok(());
    }
    match tokio::fs::remove_dir_all(directory).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove {description}: {error}")),
    }
}

async fn remove_verified_file(root: &Path, file: &Path, description: &str) -> Result<(), String> {
    if !verified_direct_child(root, file, PathKind::File, description)? {
        return Ok(());
    }
    match tokio::fs::remove_file(file).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove {description}: {error}")),
    }
}

fn verified_runtime_subdirectory(
    data_root: &Path,
    name: &str,
    description: &str,
) -> Result<PathBuf, String> {
    let directory = data_root.join(name);
    require_verified_direct_child(data_root, &directory, PathKind::Directory, description)?;
    Ok(directory)
}

fn verify_environment_artifact(
    data_root: &Path,
    id: &str,
    artifact: &Path,
    description: &str,
) -> Result<(), String> {
    let environments_root =
        verified_runtime_subdirectory(data_root, "environments", "environment storage root")?;
    let environment_directory = checked_runtime_child(&environments_root, id, "virtual machine")?;
    require_verified_direct_child(
        &environments_root,
        &environment_directory,
        PathKind::Directory,
        "virtual machine storage",
    )?;
    require_verified_direct_child(
        &environment_directory,
        artifact,
        PathKind::File,
        description,
    )
}

fn vm_restore_transaction_paths(environment_directory: &Path) -> (PathBuf, PathBuf, PathBuf) {
    (
        environment_directory.join("restore-transaction.json"),
        environment_directory.join("system.before-restore.qcow2"),
        environment_directory.join("system.restore.part.qcow2"),
    )
}

fn ensure_no_pending_vm_restore(data_root: &Path, id: &str) -> Result<(), String> {
    let environments_root =
        verified_runtime_subdirectory(data_root, "environments", "environment storage root")?;
    let environment_directory = checked_runtime_child(&environments_root, id, "virtual machine")?;
    if !verified_direct_child(
        &environments_root,
        &environment_directory,
        PathKind::Directory,
        "virtual machine storage",
    )? {
        return Ok(());
    }
    let (transaction, previous, _) = vm_restore_transaction_paths(&environment_directory);
    for path in [transaction, previous] {
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(
                    "virtual machine restore is awaiting persisted-state finalize or rollback"
                        .into(),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "inspect pending VM restore state {}: {error}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

fn read_vm_restore_transaction(path: &Path) -> Result<Option<VmRestoreTransaction>, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("inspect VM restore transaction: {error}")),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 4096 {
        return Err("VM restore transaction metadata is not a safe regular file".into());
    }
    let transaction = serde_json::from_slice::<VmRestoreTransaction>(
        &fs::read(path).map_err(|error| format!("read VM restore transaction: {error}"))?,
    )
    .map_err(|error| format!("decode VM restore transaction: {error}"))?;
    if !matches!(transaction.version, 1 | VM_RESTORE_TRANSACTION_VERSION) {
        return Err(format!(
            "unsupported VM restore transaction version {}",
            transaction.version
        ));
    }
    if transaction.security_changed && transaction.next_security.is_none() {
        return Err("Incomplete VM security restore transaction".into());
    }
    Ok(Some(transaction))
}

fn vm_base_operations() -> &'static tokio::sync::Mutex<()> {
    VM_BASE_OPERATIONS.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn vm_port_reservations() -> &'static std::sync::Mutex<HashSet<u16>> {
    VM_PORT_RESERVATIONS.get_or_init(|| std::sync::Mutex::new(HashSet::new()))
}

fn is_qcow2_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("qcow2"))
}

fn preserve_managed_base(canonical_bases: &Path, path: &Path, referenced: &mut HashSet<PathBuf>) {
    let Ok(canonical) = fs::canonicalize(path) else {
        return;
    };
    if canonical.parent() == Some(canonical_bases) && is_content_addressed_vm_base(&canonical) {
        referenced.insert(canonical);
    }
}

fn is_content_addressed_vm_base(path: &Path) -> bool {
    let Some(extension) = path.extension().and_then(|extension| extension.to_str()) else {
        return false;
    };
    if !matches!(
        extension.to_ascii_lowercase().as_str(),
        "iso" | "qcow2" | "kernel" | "initrd"
    ) {
        return false;
    }
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(is_sha256_hex)
}

async fn sweep_unreferenced_vm_bases(
    canonical_bases: &Path,
    referenced: &HashSet<PathBuf>,
) -> Result<u64, String> {
    let mut entries = tokio::fs::read_dir(canonical_bases)
        .await
        .map_err(|error| format!("scan content-addressed VM bases: {error}"))?;
    let mut removable = Vec::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|error| format!("scan VM base entry: {error}"))?
    {
        let file_type = entry
            .file_type()
            .await
            .map_err(|error| format!("inspect VM base entry: {error}"))?;
        if !file_type.is_file() || file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if !is_content_addressed_vm_base(&path) {
            continue;
        }
        let canonical = fs::canonicalize(&path)
            .map_err(|error| format!("resolve VM base candidate {}: {error}", path.display()))?;
        if canonical.parent() != Some(canonical_bases) || referenced.contains(&canonical) {
            continue;
        }
        let size = entry
            .metadata()
            .await
            .map_err(|error| format!("inspect VM base candidate {}: {error}", path.display()))?
            .len();
        removable.push((path, size));
    }

    let mut reclaimed = 0_u64;
    for (path, size) in removable {
        let metadata = match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "recheck VM base candidate {}: {error}",
                    path.display()
                ));
            }
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            continue;
        }
        tokio::fs::remove_file(&path)
            .await
            .map_err(|error| format!("remove unreferenced VM base {}: {error}", path.display()))?;
        reclaimed = reclaimed.saturating_add(size);
    }
    Ok(reclaimed)
}

pub(super) fn full_vm_graphics_arguments(gpu_access: bool) -> Vec<&'static str> {
    if gpu_access {
        // The VNC console must display the accelerated adapter, not a separate
        // basic VGA device while an unused render-only GPU sits beside it.
        // virtio-vga retains VGA/firmware fallback for driver installation; 3D
        // still requires a supported guest driver (currently Linux/Mesa).
        vec!["-device", "virtio-vga-gl,id=yougori-display,max_outputs=1", "-display", "egl-headless"]
    } else {
        vec!["-device", "VGA,id=yougori-display"]
    }
}

pub(super) fn full_vm_cpu_model(accelerator: &str) -> &'static str {
    match accelerator {
        // Nested virtualization expands the host kernel attack surface and is
        // unnecessary for branch workloads. Mask it on every accelerator.
        "kvm" | "hvf" => "host,vmx=off,svm=off",
        // WHPX cannot provide nested VMX/SVM to this guest. Exposing VMX with
        // `max` makes OVMF fault on IA32_FEATURE_CONTROL (MSR 0x3a). Keep the
        // remaining supported modern instructions and hardware acceleration.
        "whpx" => "max,vmx=off,svm=off",
        // Keep software emulation on the verified 48-bit paging profile.
        // The bundled Linux 6.18 kernel and older QEMU TCG can corrupt procfs
        // paths with LA57.
        _ => "max,vmx=off,svm=off,la57=off",
    }
}

fn default_micro_vm_cmdline() -> String {
    "root=/dev/vda rw console=ttyS0,115200n8 reboot=t panic=1".into()
}

fn default_builtin_micro_vm_cmdline() -> String {
    "root=/dev/vda rw rootfstype=ext4 console=ttyS0,115200n8 reboot=t panic=1 quiet modules=virtio_mmio,virtio_blk,virtio_net,virtio_rng,virtio_balloon,ext4"
        .into()
}

fn validate_micro_vm_cmdline(cmdline: &str) -> Result<(), String> {
    if cmdline.trim().is_empty() {
        return Err("microVM kernel command line cannot be empty".into());
    }
    if cmdline.len() > 16 * 1024 {
        return Err("microVM kernel command line exceeds the 16 KiB safety limit".into());
    }
    if cmdline.contains(['\0', '\n', '\r']) {
        return Err("microVM kernel command line contains an invalid control character".into());
    }
    Ok(())
}

fn resolve_manifest_path(manifest_directory: &Path, value: &Path) -> PathBuf {
    if value.is_absolute() {
        value.to_path_buf()
    } else {
        manifest_directory.join(value)
    }
}

async fn read_managed_micro_vm_manifest(path: &Path) -> Result<ManagedMicroVmManifest, String> {
    if !path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
    {
        return Err(format!(
            "microVM runtime metadata must be a JSON manifest, not {}",
            path.display()
        ));
    }
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|error| format!("read managed microVM manifest metadata: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "managed microVM manifest is not a real file: {}",
            path.display()
        ));
    }
    if metadata.len() > MAX_MICRO_VM_MANIFEST_BYTES {
        return Err("managed microVM manifest exceeds the 1 MiB safety limit".into());
    }
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|error| format!("open managed microVM manifest {}: {error}", path.display()))?;
    let mut limited = file.take(MAX_MICRO_VM_MANIFEST_BYTES + 1);
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    limited
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| format!("read managed microVM manifest {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_MICRO_VM_MANIFEST_BYTES {
        return Err("managed microVM manifest changed beyond the 1 MiB safety limit".into());
    }
    let manifest = serde_json::from_slice::<ManagedMicroVmManifest>(&bytes)
        .map_err(|error| format!("decode managed microVM manifest: {error}"))?;
    if manifest.version != MICRO_VM_MANIFEST_VERSION {
        return Err(format!(
            "unsupported managed microVM manifest version {}",
            manifest.version
        ));
    }
    validate_micro_vm_cmdline(&manifest.cmdline)?;
    if !manifest.builtin && !manifest.kernel.is_file() {
        return Err(format!(
            "managed microVM kernel is missing: {}",
            manifest.kernel.display()
        ));
    }
    if let Some(initrd) = manifest.initrd.as_ref().filter(|_| !manifest.builtin) {
        if !initrd.is_file() {
            return Err(format!(
                "managed microVM initramfs is missing: {}",
                initrd.display()
            ));
        }
    }
    Ok(manifest)
}

fn micro_vm_boot_files<'a>(
    manifest: &'a ManagedMicroVmManifest,
    current_kernel: &'a Path,
    current_initrd: &'a Path,
) -> Result<(&'a Path, Option<&'a Path>), String> {
    // Built-in disks use this installation's verified boot upgrade, even if
    // their metadata came from an older/source installation. Custom guests
    // retain their selected kernel and optional initramfs without mutation.
    let (kernel, initrd) = if manifest.builtin {
        (current_kernel, Some(current_initrd))
    } else {
        (manifest.kernel.as_path(), manifest.initrd.as_deref())
    };
    for (label, file) in [("kernel", Some(kernel)), ("initramfs", initrd)] {
        if file.is_some_and(|path| !path.is_file()) {
            return Err(format!("Selected microVM {label} is missing; no older boot fallback was attempted"));
        }
    }
    Ok((kernel, initrd))
}

pub(super) async fn write_durable_file(path: PathBuf, bytes: Vec<u8>) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let parent = path
            .parent()
            .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("runtime-metadata");
        let temporary = parent.join(format!(".{name}.{}.part", Uuid::new_v4().simple()));
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| format!("create {}: {error}", temporary.display()))?;
        file.write_all(&bytes)
            .map_err(|error| format!("write {}: {error}", temporary.display()))?;
        file.sync_all()
            .map_err(|error| format!("flush {}: {error}", temporary.display()))?;
        drop(file);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
                let _ = fs::remove_file(&temporary);
                return Err(format!(
                    "refusing to replace runtime metadata that is not a real file: {}",
                    path.display()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                let _ = fs::remove_file(&temporary);
                return Err(format!(
                    "inspect {} before replacement: {error}",
                    path.display()
                ));
            }
        }
        if let Err(error) = fs::rename(&temporary, &path) {
            let _ = fs::remove_file(&temporary);
            return Err(format!("finalize {}: {error}", path.display()));
        }
        #[cfg(not(target_os = "windows"))]
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("flush directory {}: {error}", parent.display()))?;
        Ok(())
    })
    .await
    .map_err(|error| format!("join durable file write task: {error}"))?
}

async fn inspect_source_identity(path: PathBuf) -> Result<SourceIdentity, String> {
    tokio::task::spawn_blocking(move || inspect_source_identity_blocking(&path))
        .await
        .map_err(|error| format!("join source fingerprint task: {error}"))?
}

fn inspect_source_identity_blocking(path: &Path) -> Result<SourceIdentity, String> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("resolve source {}: {error}", path.display()))?;
    let mut file = File::open(&canonical)
        .map_err(|error| format!("open source {}: {error}", canonical.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect source {}: {error}", canonical.display()))?;
    if !metadata.is_file() {
        return Err(format!("source is not a file: {}", canonical.display()));
    }

    let mut sample_digest = Sha256::new();
    sample_digest.update(metadata.len().to_le_bytes());
    let sample_size = SOURCE_SAMPLE_BYTES.min(metadata.len() as usize);
    let mut offsets = vec![0_u64];
    if metadata.len() > sample_size as u64 {
        offsets.push(metadata.len().saturating_sub(sample_size as u64) / 2);
        offsets.push(metadata.len().saturating_sub(sample_size as u64));
    }
    offsets.sort_unstable();
    offsets.dedup();
    let mut buffer = vec![0_u8; sample_size];
    for offset in offsets {
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| format!("seek source sample {}: {error}", canonical.display()))?;
        let mut count = 0;
        while count < buffer.len() {
            let read = file
                .read(&mut buffer[count..])
                .map_err(|error| format!("read source sample {}: {error}", canonical.display()))?;
            if read == 0 {
                break;
            }
            count += read;
        }
        sample_digest.update(offset.to_le_bytes());
        sample_digest.update((count as u64).to_le_bytes());
        sample_digest.update(&buffer[..count]);
    }

    Ok(SourceIdentity {
        canonical_path: canonical.to_string_lossy().into_owned(),
        size_bytes: metadata.len(),
        modified_unix_nanos: metadata.modified().ok().and_then(system_time_nanos),
        created_unix_nanos: metadata.created().ok().and_then(system_time_nanos),
        sample_sha256: hex::encode(sample_digest.finalize()),
    })
}

fn system_time_nanos(value: SystemTime) -> Option<u64> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_nanos()).ok())
}

async fn ensure_source_unchanged(path: &Path, expected: &SourceIdentity) -> Result<(), String> {
    let actual = inspect_source_identity(path.to_path_buf()).await?;
    if &actual == expected {
        Ok(())
    } else {
        Err(format!(
            "source changed while it was being imported: {}",
            path.display()
        ))
    }
}

fn source_cache_path(
    bases: &Path,
    identity: &SourceIdentity,
    artifact_extension: &str,
) -> Result<PathBuf, String> {
    let mut digest = Sha256::new();
    digest.update(
        serde_json::to_vec(identity)
            .map_err(|error| format!("encode source fingerprint: {error}"))?,
    );
    digest.update([0]);
    digest.update(artifact_extension.as_bytes());
    Ok(bases
        .join("source-cache")
        .join(format!("{}.json", hex::encode(digest.finalize()))))
}

async fn read_cached_source_checksum(
    bases: &Path,
    identity: &SourceIdentity,
    artifact_extension: &str,
) -> Option<String> {
    let path = source_cache_path(bases, identity, artifact_extension).ok()?;
    let bytes = tokio::fs::read(path).await.ok()?;
    let entry = serde_json::from_slice::<SourceChecksumCacheEntry>(&bytes).ok()?;
    (entry.version == SOURCE_CACHE_VERSION
        && entry.identity == *identity
        && is_sha256_hex(&entry.checksum_sha256))
    .then_some(entry.checksum_sha256)
}

async fn write_source_checksum_cache(
    bases: &Path,
    identity: &SourceIdentity,
    artifact_extension: &str,
    checksum: &str,
) -> Result<(), String> {
    if !is_sha256_hex(checksum) {
        return Err("refusing to cache an invalid source checksum".into());
    }
    let cache_path = source_cache_path(bases, identity, artifact_extension)?;
    let cache_directory = cache_path
        .parent()
        .ok_or_else(|| "source checksum cache has no parent directory".to_string())?;
    tokio::fs::create_dir_all(cache_directory)
        .await
        .map_err(|error| format!("create source checksum cache: {error}"))?;
    if cache_path.is_file() {
        return Ok(());
    }
    let entry = SourceChecksumCacheEntry {
        version: SOURCE_CACHE_VERSION,
        identity: identity.clone(),
        checksum_sha256: checksum.to_owned(),
    };
    let bytes = serde_json::to_vec(&entry)
        .map_err(|error| format!("encode source checksum cache: {error}"))?;
    let temporary = cache_directory.join(format!(".{}.json.part", Uuid::new_v4().simple()));
    write_durable_file(temporary.clone(), bytes).await?;
    match tokio::fs::rename(&temporary, &cache_path).await {
        Ok(()) => Ok(()),
        Err(_) if cache_path.is_file() => {
            let _ = tokio::fs::remove_file(&temporary).await;
            Ok(())
        }
        Err(error) => {
            let _ = tokio::fs::remove_file(&temporary).await;
            Err(format!("finalize source checksum cache: {error}"))
        }
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

async fn copy_and_hash(
    source: PathBuf,
    destination: PathBuf,
    description: String,
) -> Result<(u64, String), String> {
    tokio::task::spawn_blocking(move || {
        let mut source_file = File::open(&source)
            .map_err(|error| format!("open {description} {}: {error}", source.display()))?;
        let mut destination_file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&destination)
            .map_err(|error| {
                format!(
                    "create managed {description} {}: {error}",
                    destination.display()
                )
            })?;
        let mut digest = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            let count = source_file
                .read(&mut buffer)
                .map_err(|error| format!("read {description} {}: {error}", source.display()))?;
            if count == 0 {
                break;
            }
            destination_file
                .write_all(&buffer[..count])
                .map_err(|error| {
                    format!(
                        "write managed {description} {}: {error}",
                        destination.display()
                    )
                })?;
            digest.update(&buffer[..count]);
            total = total.saturating_add(count as u64);
        }
        destination_file.sync_all().map_err(|error| {
            format!(
                "flush managed {description} {}: {error}",
                destination.display()
            )
        })?;
        Ok((total, hex::encode(digest.finalize())))
    })
    .await
    .map_err(|error| format!("join managed artifact import task: {error}"))?
}

async fn finalize_content_addressed_import(
    temporary: &Path,
    destination: &Path,
) -> Result<(), String> {
    match tokio::fs::rename(temporary, destination).await {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = tokio::fs::remove_file(temporary).await;
            match safe_regular_file_size(destination, "concurrent managed VM artifact") {
                Ok(Some(_)) => Ok(()),
                Ok(None) => Err(format!(
                    "finalize managed artifact {}: {error}",
                    destination.display()
                )),
                Err(safety_error) => Err(safety_error),
            }
        }
    }
}

async fn wait_for_vm_startup(
    child: &mut tokio::process::Child,
    qmp_port: u16,
    websocket_port: Option<u16>,
    error_path: &Path,
    is_whpx: bool,
    mut initial_network: Option<bool>,
) -> Result<(), String> {
    let timeout = if cfg!(target_os = "macos") {
        super::host_platform::guest_boot_timeout()
    } else if is_whpx {
        WHPX_STARTUP_TIMEOUT
    } else {
        VM_STARTUP_TIMEOUT
    };
    let deadline = Instant::now() + timeout;
    let mut retry_delay = Duration::from_millis(20);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(format!(
                    "virtual machine exited during startup with {status}: {}",
                    read_log_tail(error_path)
                ));
            }
            Ok(None) => {}
            Err(error) => return Err(format!("inspect virtual machine startup: {error}")),
        }
        if is_whpx && whpx_failed(error_path) {
            return Err(format!(
                "Windows Hypervisor Platform failed during guest startup: {}",
                read_log_tail(error_path)
            ));
        }

        // A full VM starts with -S. Set its cable before running the first
        // instruction, then use the normal accelerator stability checks.
        if let Some(enabled) = initial_network {
            if tokio::time::timeout(Duration::from_millis(250), qmp_request(qmp_port, "query-status", None)).await.is_ok_and(|result| result.is_ok()) {
                qmp_execute_bounded(qmp_port, "set_link", Some(json!({ "name": "net0", "up": enabled })), Duration::from_secs(5)).await?;
                qmp_execute_bounded(qmp_port, "cont", None, Duration::from_secs(5)).await?;
                initial_network = None;
            }
        }
        let qmp_ready = initial_network.is_none() && qmp_reports_running(qmp_port).await;
        let console_ready = match websocket_port {
            Some(port) if qmp_ready => tokio::time::timeout(
                Duration::from_millis(250),
                TcpStream::connect(("127.0.0.1", port)),
            )
            .await
            .is_ok_and(|result| result.is_ok()),
            Some(_) => false,
            None => true,
        };
        if qmp_ready && console_ready {
            // QMP begins listening before an accelerator has necessarily run a vCPU.
            // WHPX can therefore report a delayed VP failure after the first successful
            // query. Keep the launch fast, but require the child to survive a short
            // stability window and confirm a second running-state guest signal.
            let stability_window = if is_whpx {
                Duration::from_millis(600)
            } else {
                Duration::from_millis(250)
            };
            let stability_deadline = Instant::now() + stability_window;
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        return Err(format!(
                            "virtual machine exited after control readiness with {status}: {}",
                            read_log_tail(error_path)
                        ));
                    }
                    Ok(None) => {}
                    Err(error) => {
                        return Err(format!("confirm virtual machine startup: {error}"));
                    }
                }
                if is_whpx && whpx_failed(error_path) {
                    return Err(format!(
                        "Windows Hypervisor Platform failed after control readiness: {}",
                        read_log_tail(error_path)
                    ));
                }
                if Instant::now() >= stability_deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            if qmp_reports_running(qmp_port).await {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            let detail = read_log_tail(error_path);
            return Err(if detail.is_empty() {
                format!(
                    "virtual machine control socket was not ready within {} seconds",
                    timeout.as_secs()
                )
            } else {
                format!(
                    "virtual machine control socket was not ready within {} seconds: {detail}",
                    timeout.as_secs()
                )
            });
        }
        tokio::time::sleep(retry_delay).await;
        retry_delay = (retry_delay * 2).min(Duration::from_millis(200));
    }
}

async fn qmp_reports_running(port: u16) -> bool {
    tokio::time::timeout(
        Duration::from_millis(500),
        qmp_request(port, "query-status", None),
    )
    .await
    .is_ok_and(|result| {
        result.is_ok_and(|status| {
            status.get("status").and_then(|value| value.as_str()) == Some("running")
        })
    })
}

pub(super) fn branch_disk_graph(
    disk_path: &Path,
    server: &super::BranchBlockServer,
    node_name: &str,
) -> serde_json::Value {
    json!({
        "driver": "qcow2",
        "file": {
            "driver": "file",
            "filename": path_string(disk_path)
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
        "node-name": node_name
    })
}

/// Restored VM disks must be self-contained, unencrypted QCOW2 images.
pub(super) fn ensure_standalone_qcow2(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| format!("inspect virtual machine backup: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("Virtual machine backups must be regular files".into());
    }
    let mut header = [0_u8; 104];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut header))
        .map_err(|error| format!("Invalid virtual machine backup header: {error}"))?;
    let version = u32::from_be_bytes(header[4..8].try_into().unwrap());
    let backing_offset = u64::from_be_bytes(header[8..16].try_into().unwrap());
    let backing_size = u32::from_be_bytes(header[16..20].try_into().unwrap());
    let encryption = u32::from_be_bytes(header[32..36].try_into().unwrap());
    let incompatible_features = u64::from_be_bytes(header[72..80].try_into().unwrap());
    if &header[..4] != b"QFI\xfb"
        || !matches!(version, 2 | 3)
        || backing_offset != 0
        || backing_size != 0
        || encryption != 0
        || (version == 3 && incompatible_features & 4 != 0)
    {
        return Err("Virtual machine backups must be standalone, unencrypted QCOW2 disks without backing files or external data files".into());
    }
    Ok(())
}

pub(super) async fn hash_file(path: PathBuf) -> Result<(u64, String), String> {
    tokio::task::spawn_blocking(move || {
        let mut file = File::open(&path).map_err(|error| {
            format!(
                "open {} for integrity verification: {error}",
                path.display()
            )
        })?;
        let mut digest = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|error| format!("hash {}: {error}", path.display()))?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
            total = total.saturating_add(count as u64);
        }
        Ok((total, hex::encode(digest.finalize())))
    })
    .await
    .map_err(|error| format!("join virtual machine integrity task: {error}"))?
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LiveSnapshot {
    Save,
    Load,
    Delete,
}

/// Writable qcow2 system disks captured by live snapshots, vmstate first.
const LIVE_SNAPSHOT_NODES: [&str; 3] = ["yougori-vm-disk", "yougori-microvm-disk", "yougori-branch-boot-disk"];
const LIVE_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// HMP savevm/loadvm/delvm require every writable drive to support internal
/// snapshots. Full VMs keep UEFI variables and imported drives in raw files, so
/// those commands always failed, and HMP reports failures only as text. Use
/// QMP snapshot jobs limited to the qcow2 system disks instead. The pflash
/// variables travel in the VM state and are written back after a load.
async fn live_vm_snapshot(port: u16, action: LiveSnapshot, tag: &str) -> Result<(), String> {
    let nodes = qmp_request(port, "query-named-block-nodes", Some(json!({ "flat": true }))).await?;
    let nodes = nodes.as_array().ok_or("virtual machine returned an invalid block device list")?;
    let devices: Vec<&str> = LIVE_SNAPSHOT_NODES
        .into_iter()
        .filter(|name| nodes.iter().any(|node| node["node-name"] == *name && node["ro"] == false && node["drv"] == "qcow2"))
        .collect();
    let Some((command, arguments)) = live_snapshot_plan(action, tag, nodes, &devices)? else { return Ok(()) };
    match qmp_snapshot_job(port, command, arguments).await {
        Err(error) if error.contains("CommandNotFound") => {
            let verb = match action { LiveSnapshot::Save => "savevm", LiveSnapshot::Load => "loadvm", LiveSnapshot::Delete => "delvm" };
            qmp_human_command(port, &format!("{verb} {tag}")).await
        }
        // WHPX and GPU acceleration cannot save a running VM's state. Take an
        // atomic, crash-consistent snapshot of the disks instead; restoring
        // one (like a snapshot of a stopped VM) requires stopping the VM.
        Err(error) if action == LiveSnapshot::Save && live_state_blocked(&error) => {
            let actions: Vec<_> = devices
                .iter()
                .map(|device| json!({ "type": "blockdev-snapshot-internal-sync", "data": { "device": device, "name": tag } }))
                .collect();
            qmp_request(port, "transaction", Some(json!({ "actions": actions }))).await.map(|_| ())
        }
        Err(error) if action == LiveSnapshot::Load && live_state_blocked(&error) => Err(format!(
            "Stop the virtual machine to restore this snapshot; its running state cannot be replaced live. {error}"
        )),
        Err(error) if action == LiveSnapshot::Load => Err(format!("{error}. The virtual machine may be paused; restart it if it does not respond.")),
        result => result,
    }
}

/// QEMU migration blockers (WHPX dirty tracking, virgl) prevent saving or
/// loading running VM state.
fn live_state_blocked(error: &str) -> bool {
    error.contains("migratab") || error.contains("State blocked")
}

fn live_snapshot_plan(
    action: LiveSnapshot,
    tag: &str,
    nodes: &[serde_json::Value],
    devices: &[&str],
) -> Result<Option<(&'static str, serde_json::Value)>, String> {
    if devices.is_empty() {
        return Err("This virtual machine has no snapshot-capable system disk".into());
    }
    let saved = |name: &str| {
        nodes.iter()
            .find(|node| node["node-name"] == name)
            .and_then(|node| node["image"]["snapshots"].as_array())
            .and_then(|snapshots| snapshots.iter().find(|item| item["name"] == tag))
    };
    let job_id = format!("yougori-snapshot-{}", Uuid::new_v4().simple());
    Ok(Some(match action {
        LiveSnapshot::Save => {
            if devices.iter().any(|name| saved(name).is_some()) {
                return Err(format!("Snapshot {tag} already exists on this virtual machine disk"));
            }
            ("snapshot-save", json!({ "job-id": job_id, "tag": tag, "vmstate": devices[0], "devices": devices }))
        }
        LiveSnapshot::Load => {
            if devices.iter().any(|name| saved(name).is_none()) {
                return Err("This snapshot is not stored in the virtual machine disk. Older Yougori versions could record live full-VM snapshots that QEMU had rejected; delete it and create a new snapshot.".into());
            }
            let Some(vmstate) = devices.iter().find(|name| saved(name).and_then(|item| item["vm-state-size"].as_u64()).unwrap_or(0) > 0) else {
                return Err("This snapshot has no saved memory state. Stop the virtual machine, then restore it.".into());
            };
            if nodes.iter().any(|node| node["node-name"].as_str().is_some_and(|name| name.starts_with("import-")) && node["ro"] == false) {
                return Err("Imported drives are not part of snapshots. Stop the virtual machine before restoring so their contents stay consistent.".into());
            }
            ("snapshot-load", json!({ "job-id": job_id, "tag": tag, "vmstate": vmstate, "devices": devices }))
        }
        LiveSnapshot::Delete => {
            let devices: Vec<&str> = devices.iter().copied().filter(|name| saved(name).is_some()).collect();
            if devices.is_empty() {
                return Ok(None);
            }
            ("snapshot-delete", json!({ "job-id": job_id, "tag": tag, "devices": devices }))
        }
    }))
}

async fn qmp_snapshot_job(port: u16, command: &str, arguments: serde_json::Value) -> Result<(), String> {
    let id = arguments["job-id"].as_str().unwrap_or_default().to_owned();
    // QEMU saves/loads VM state in its main loop, so the monitor may not answer the
    // command or a poll until a multi-GB state transfer completes.
    qmp_request_until(port, command, Some(arguments), LIVE_SNAPSHOT_TIMEOUT).await?;
    let started = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let jobs = qmp_request_until(port, "query-jobs", None, LIVE_SNAPSHOT_TIMEOUT).await?;
        let job = jobs
            .as_array()
            .and_then(|jobs| jobs.iter().find(|job| job["id"] == id.as_str()))
            .cloned()
            .ok_or_else(|| format!("virtual machine {command} job ended without a result"))?;
        if job["status"] == "concluded" {
            let _ = qmp_request(port, "job-dismiss", Some(json!({ "id": id }))).await;
            return match job["error"].as_str() {
                Some(error) => Err(format!("virtual machine {command} failed: {error}")),
                None => Ok(()),
            };
        }
        if started.elapsed() > LIVE_SNAPSHOT_TIMEOUT {
            return Err(format!("virtual machine {command} did not finish within {} minutes", LIVE_SNAPSHOT_TIMEOUT.as_secs() / 60));
        }
    }
}

/// QEMU builds without snapshot jobs. HMP reports failures only in its text.
async fn qmp_human_command(port: u16, command: &str) -> Result<(), String> {
    let reply = qmp_request_until(
        port,
        "human-monitor-command",
        Some(json!({ "command-line": command })),
        LIVE_SNAPSHOT_TIMEOUT,
    )
    .await?;
    human_command_result(command, &reply)
}

fn human_command_result(command: &str, reply: &serde_json::Value) -> Result<(), String> {
    let failure = reply
        .as_str()
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.to_ascii_lowercase().starts_with("warning:"))
        .collect::<Vec<_>>()
        .join(" ");
    if failure.is_empty() {
        Ok(())
    } else {
        let verb = command.split_whitespace().next().unwrap_or(command);
        Err(format!("virtual machine rejected {verb}: {failure}"))
    }
}

pub(super) async fn qmp_execute(
    port: u16,
    command: &str,
    arguments: Option<serde_json::Value>,
) -> Result<(), String> {
    qmp_request(port, command, arguments).await.map(|_| ())
}

pub(super) async fn qmp_execute_bounded(
    port: u16,
    command: &str,
    arguments: Option<serde_json::Value>,
    timeout: Duration,
) -> Result<(), String> {
    tokio::time::timeout(timeout, qmp_execute(port, command, arguments))
        .await
        .map_err(|_| format!("virtual machine control command '{command}' timed out"))?
}

pub(super) async fn quiesce_and_flush_vm(port: u16, is_micro_vm: bool) {
    // Once vCPUs are stopped, no guest write can race the final host block flush.
    // Optional full-VM nodes are best-effort because install media/branch disks vary,
    // while the primary writable system node is present in every launch profile.
    let _ = qmp_execute_bounded(port, "stop", None, Duration::from_secs(2)).await;
    let nodes: &[&str] = if is_micro_vm {
        &["yougori-microvm-disk"]
    } else {
        &[
            "yougori-vm-disk",
            "yougori-branch-boot-disk",
            "yougori-uefi-vars",
        ]
    };
    for node in nodes {
        let _ = qmp_execute_bounded(
            port,
            "blockdev-flush",
            Some(json!({ "node-name": node })),
            Duration::from_secs(2),
        )
        .await;
    }
}

pub(super) async fn qmp_request(
    port: u16,
    command: &str,
    arguments: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    qmp_request_until(port, command, arguments, Duration::from_secs(10)).await
}

async fn qmp_request_until(
    port: u16,
    command: &str,
    arguments: Option<serde_json::Value>,
    timeout: Duration,
) -> Result<serde_json::Value, String> {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|error| format!("connect to virtual machine control socket: {error}"))?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    // A long operation (VM state save/load) also delays the monitor's handshake.
    let handshake = if timeout > Duration::from_secs(10) { timeout } else { Duration::from_secs(5) };
    tokio::time::timeout(handshake, reader.read_line(&mut line))
        .await
        .map_err(|_| "virtual machine control greeting timed out".to_string())?
        .map_err(|error| format!("read virtual machine control greeting: {error}"))?;
    write_qmp(&mut writer, json!({ "execute": "qmp_capabilities" })).await?;
    read_qmp_result_until(&mut reader, handshake.max(Duration::from_secs(10))).await?;
    let mut request = json!({ "execute": command });
    if let Some(arguments) = arguments {
        request["arguments"] = arguments;
    }
    write_qmp(&mut writer, request).await?;
    read_qmp_result_until(&mut reader, timeout).await
}

async fn write_qmp(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    value: serde_json::Value,
) -> Result<(), String> {
    let mut bytes = serde_json::to_vec(&value)
        .map_err(|error| format!("encode virtual machine command: {error}"))?;
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .await
        .map_err(|error| format!("write virtual machine command: {error}"))
}

async fn read_qmp_result_until(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    timeout: Duration,
) -> Result<serde_json::Value, String> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("virtual machine control command timed out".into());
        }
        let mut line = String::new();
        let count = tokio::time::timeout(remaining, reader.read_line(&mut line))
            .await
            .map_err(|_| "virtual machine control command timed out".to_string())?
            .map_err(|error| format!("read virtual machine response: {error}"))?;
        if count == 0 {
            return Err("virtual machine control connection closed".into());
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        if let Some(error) = value.get("error") {
            return Err(format!("virtual machine rejected the command: {error}"));
        }
        if let Some(result) = value.get("return") {
            return Ok(result.clone());
        }
    }
}

async fn apply_vm_resource_limits(
    process_id: u32,
    qmp_port: u16,
    desired_cpus: f64,
    desired_memory_gb: f64,
) -> Result<(), String> {
    apply_process_cpu_limit(process_id, desired_cpus)?;
    let memory_bytes = (desired_memory_gb * 1_073_741_824.0)
        .round()
        .clamp(256.0 * 1024.0 * 1024.0, u64::MAX as f64) as u64;
    qmp_execute(qmp_port, "balloon", Some(json!({ "value": memory_bytes }))).await
}

/// Indexes of the host CPUs a VM process may use. Each VM gets a contiguous
/// window (SMT siblings stay together) at an offset derived from its process,
/// stable across live resizes, so VMs no longer all stack on the first CPUs.
#[cfg_attr(not(any(target_os = "windows", target_os = "linux", test)), allow(dead_code))]
fn cpu_window(process_id: u32, available: usize, requested: usize) -> Vec<usize> {
    if available == 0 {
        return Vec::new();
    }
    let requested = requested.clamp(1, available);
    if requested == available {
        return (0..available).collect();
    }
    let spread = (u64::from(process_id).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32) as usize;
    let start = (spread % available) & !1;
    (0..requested).map(|offset| (start + offset) % available).collect()
}

#[cfg(target_os = "windows")]
fn apply_process_cpu_limit(process_id: u32, desired_cpus: f64) -> Result<(), String> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, GetLastError},
        System::Threading::{
            OpenProcess, SetProcessAffinityMask, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_SET_INFORMATION,
        },
    };

    let available = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .min(usize::BITS as usize);
    let requested = (desired_cpus.round().clamp(1.0, available as f64) as usize).min(available);
    let mask = cpu_window(process_id, available, requested)
        .into_iter()
        .fold(0_usize, |mask, cpu| mask | (1_usize << cpu));

    // SAFETY: the handle is opened for this known child process, used once, and closed below.
    unsafe {
        let handle = OpenProcess(
            PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            process_id,
        );
        if handle.is_null() {
            return Err(format!(
                "open virtual machine process {process_id} for CPU allocation: Windows error {}",
                GetLastError()
            ));
        }
        let applied = SetProcessAffinityMask(handle, mask);
        let error = (applied == 0).then(|| GetLastError());
        let _ = CloseHandle(handle);
        if let Some(error) = error {
            return Err(format!(
                "apply virtual machine CPU allocation to process {process_id}: Windows error {error}"
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_process_cpu_limit(process_id: u32, desired_cpus: f64) -> Result<(), String> {
    // Respect the app's cpuset; apply the limit to QEMU's vCPU threads too.
    unsafe {
        let mut allowed: libc::cpu_set_t = std::mem::zeroed();
        let mut selected: libc::cpu_set_t = std::mem::zeroed();
        let size = std::mem::size_of::<libc::cpu_set_t>();
        if libc::sched_getaffinity(0, size, &mut allowed) != 0 {
            return Err(format!("Read available CPU affinity: {}", std::io::Error::last_os_error()));
        }
        let usable: Vec<usize> = (0..libc::CPU_SETSIZE as usize).filter(|cpu| libc::CPU_ISSET(*cpu, &allowed)).collect();
        let requested = (desired_cpus.ceil().max(1.0) as usize).min(usable.len());
        for index in cpu_window(process_id, usable.len(), requested) {
            libc::CPU_SET(usable[index], &mut selected);
        }
        let threads = std::fs::read_dir(format!("/proc/{process_id}/task")).map_err(|e| format!("Read VM threads: {e}"))?;
        for thread in threads {
            let entry = thread.map_err(|e| e.to_string())?;
            let tid: libc::pid_t = entry.file_name().to_string_lossy().parse().map_err(|_| "Invalid VM thread ID")?;
            if libc::sched_setaffinity(tid, size, &selected) != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) { return Err(format!("Set VM CPU affinity: {error}")); }
            }
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn apply_process_cpu_limit(_process_id: u32, _desired_cpus: f64) -> Result<(), String> {
    Err("dynamic virtual machine CPU allocation is currently supported on Windows".into())
}

fn read_log_tail(path: &Path) -> String {
    String::from_utf8_lossy(&read_file_tail(path, 8 * 1024))
        .trim()
        .to_string()
}

fn whpx_failed(path: &Path) -> bool {
    let bytes = read_file_tail(path, 16 * 1024);
    let tail = String::from_utf8_lossy(&bytes);
    tail.contains("WHPX: Unexpected VP exit code")
        || tail.contains("WHPX: Failed to emulate MMIO access")
        || tail.contains("whpx: injection failed")
}

fn read_file_tail(path: &Path, maximum_bytes: u64) -> Vec<u8> {
    let Ok(mut file) = File::open(path) else {
        return Vec::new();
    };
    let Ok(length) = file.metadata().map(|metadata| metadata.len()) else {
        return Vec::new();
    };
    let count = length.min(maximum_bytes);
    if file
        .seek(SeekFrom::Start(length.saturating_sub(count)))
        .is_err()
    {
        return Vec::new();
    }
    let mut bytes = Vec::with_capacity(count as usize);
    match file.take(count).read_to_end(&mut bytes) {
        Ok(_) => bytes,
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn vm_stop_is_idempotent_without_a_live_runtime() {
        let data = tempfile::tempdir().unwrap();
        let manager = super::RuntimeManager::new(std::path::Path::new(env!("CARGO_MANIFEST_DIR")), data.path()).unwrap();
        manager.vm_action("env-stopped-test", "stop").await.unwrap();
        manager.vm_action("env-stopped-test", "stop").await.unwrap();
        assert!(manager.vm_action("env-stopped-test", "pause").await.is_err());
        assert!(manager.vm_action("../outside", "stop").await.is_err());
    }

    /// A minimal guest agent: health reports the credential state, and with
    /// rotation /v1/system/token replaces the credential like the real agent.
    async fn fake_micro_agent(
        boot: String,
        rotation: bool,
    ) -> (String, std::sync::Arc<std::sync::Mutex<(String, usize)>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let state = std::sync::Arc::new(std::sync::Mutex::new((boot.clone(), 0_usize)));
        let shared = state.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let (state, boot) = (shared.clone(), boot.clone());
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0_u8; 4096];
                    let (head, body) = loop {
                        let count = socket.read(&mut buffer).await.unwrap_or(0);
                        if count == 0 {
                            return;
                        }
                        request.extend_from_slice(&buffer[..count]);
                        let text = String::from_utf8_lossy(&request).into_owned();
                        if let Some((head, body)) = text.split_once("\r\n\r\n") {
                            let length = head
                                .lines()
                                .find_map(|line| line.to_ascii_lowercase().strip_prefix("content-length:").map(|value| value.trim().parse::<usize>().unwrap_or(0)))
                                .unwrap_or(0);
                            if body.len() >= length {
                                break (head.to_owned(), body.to_owned());
                            }
                        }
                    };
                    let (status, reply) = {
                        let mut state = state.lock().unwrap();
                        let expected = format!("authorization: bearer {}", state.0);
                        if !head.lines().any(|line| line.to_ascii_lowercase() == expected) {
                            ("401 Unauthorized", json!({ "error": "unauthorized" }))
                        } else if head.starts_with("GET /v1/health ") {
                            let mut health = json!({ "status": "ready", "runtime": "microvm" });
                            if rotation {
                                health["credential"] = json!(if state.0 == boot { "boot" } else { "rotated" });
                            }
                            ("200 OK", health)
                        } else if rotation && head.starts_with("POST /v1/system/token ") {
                            let request: serde_json::Value = serde_json::from_str(&body).unwrap();
                            state.0 = request["token"].as_str().unwrap().to_owned();
                            state.1 += 1;
                            ("200 OK", json!({ "credential": "rotated" }))
                        } else {
                            ("404 Not Found", json!({ "error": "not found" }))
                        }
                    };
                    let reply = reply.to_string();
                    let _ = socket
                        .write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}", reply.len()).as_bytes())
                        .await;
                });
            }
        });
        (address, state)
    }

    #[tokio::test]
    async fn micro_vm_boot_credential_is_retired_before_guest_use() {
        let data = tempfile::tempdir().unwrap();
        let manager = super::RuntimeManager::new(std::path::Path::new(env!("CARGO_MANIFEST_DIR")), data.path()).unwrap();
        for (id, rotation) in [("env-rotating-agent", true), ("env-legacy-agent", false)] {
            let boot = "a".repeat(64);
            let (address, state) = fake_micro_agent(boot.clone(), rotation).await;
            // Any long-running process stands in for QEMU.
            let mut command = tokio::process::Command::new(if cfg!(windows) { "ping" } else { "sleep" });
            if cfg!(windows) {
                command.args(["-n", "30", "127.0.0.1"]);
            } else {
                command.arg("30");
            }
            let child = command
                .stdout(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let process_id = child.id().unwrap();
            manager.vms.lock().await.insert(
                id.into(),
                super::VmProcess {
                    internet: None,
                    child,
                    _branch_block_server: None,
                    _port_reservations: VmPortReservations::new(),
                    is_micro_vm: true,
                    gpu_enabled: false,
                    gpu: None,
                    micro_endpoint: Some(AgentEndpoint { base_url: address, token: boot.clone() }),
                    process_id,
                    allocated_cpus: 1,
                    allocated_micro_memory_gb: Some(1.0),
                    qmp_port: 0,
                    websocket_port: 0,
                    console_password: String::new(),
                },
            );
            let first = manager.ready_micro_vm_agent(id, "unavailable").await.unwrap();
            let second = manager.ready_micro_vm_agent(id, "unavailable").await.unwrap();
            let stored = manager.vms.lock().await.get(id).unwrap().micro_endpoint.clone().unwrap();
            let (current, rotations) = state.lock().unwrap().clone();
            if rotation {
                // The command-line credential is dead and the host uses the replacement.
                assert_ne!(first.token, boot);
                assert!(first.token.len() == 64 && first.token.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
                assert_eq!((current.as_str(), rotations), (first.token.as_str(), 1));
                assert_eq!(second.token, first.token);
                assert_eq!(stored.token, first.token);
            } else {
                // Older guest agents keep working with their boot credential.
                assert_eq!((first.token.as_str(), stored.token.as_str(), rotations), (boot.as_str(), boot.as_str(), 0));
            }
            manager.vms.lock().await.remove(id);
        }
    }

    #[test]
    fn vm_graphics_uses_one_primary_adapter_with_a_vga_fallback() {
        let enabled = super::full_vm_graphics_arguments(true);
        assert_eq!(enabled.iter().filter(|arg| **arg == "-device").count(), 1);
        assert!(enabled.contains(&"virtio-vga-gl,id=yougori-display,max_outputs=1"));
        assert!(enabled.contains(&"egl-headless"));
        assert!(!enabled.iter().any(|arg| arg.starts_with("VGA,")));
        assert_eq!(super::full_vm_graphics_arguments(false), vec!["-device", "VGA,id=yougori-display"]);
    }
    #[test]
    fn full_vm_cpu_profile_does_not_advertise_nested_virtualization_on_whpx() {
        assert_eq!(super::full_vm_cpu_model("whpx"), "max,vmx=off,svm=off");
        assert_eq!(super::full_vm_cpu_model("kvm"), "host,vmx=off,svm=off");
        assert_eq!(super::full_vm_cpu_model("hvf"), "host,vmx=off,svm=off");
        assert_eq!(super::full_vm_cpu_model("tcg,thread=multi"), "max,vmx=off,svm=off,la57=off");
        assert_eq!(super::full_vm_cpu_model("tcg"), "max,vmx=off,svm=off,la57=off");
    }
    use super::*;

    #[test]
    fn vm_cpu_windows_spread_processes_and_stay_stable() {
        assert_eq!(cpu_window(4, 24, 24), (0..24).collect::<Vec<_>>());
        assert_eq!(cpu_window(4, 1, 4), vec![0]);
        assert!(cpu_window(4, 0, 1).is_empty());
        let window = cpu_window(9_876, 24, 4);
        assert_eq!(window.len(), 4);
        assert_eq!(window, cpu_window(9_876, 24, 4), "live resizes keep the same cores");
        assert!(window.iter().all(|cpu| *cpu < 24));
        assert_eq!(window[0] % 2, 0, "SMT sibling pairs stay together");
        let starts: std::collections::HashSet<_> = (1..=32_u32).map(|pid| cpu_window(pid * 4, 24, 2)[0]).collect();
        assert!(starts.len() > 4, "VMs must not all start on the same CPUs: {starts:?}");
    }

    #[test]
    fn vnc_console_passwords_use_the_full_eight_character_space() {
        let first = vnc_console_password();
        assert_eq!(first.len(), 8);
        assert!(first.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')));
        assert_ne!(first, vnc_console_password());
    }

    #[test]
    fn hmp_text_failures_are_errors() {
        assert!(human_command_result("savevm snap", &json!("")).is_ok());
        assert!(human_command_result("savevm snap", &json!("warning: slow storage\r\n")).is_ok());
        let error = human_command_result("savevm snap", &json!("Error: Device 'yougori-uefi-vars' is writable but does not support snapshots\r\n")).unwrap_err();
        assert!(error.contains("savevm") && error.contains("does not support snapshots"));
    }

    #[test]
    fn live_snapshots_cover_qcow2_system_disks_and_reject_phantom_restores() {
        let disk = |snapshots: serde_json::Value| json!({"node-name": "yougori-vm-disk", "drv": "qcow2", "ro": false, "image": {"snapshots": snapshots}});
        let vars = json!({"node-name": "yougori-uefi-vars", "drv": "raw", "ro": false, "image": {}});
        let devices = ["yougori-vm-disk"];
        let empty = [disk(json!([])), vars.clone()];
        let (command, arguments) = live_snapshot_plan(LiveSnapshot::Save, "snap-a", &empty, &devices).unwrap().unwrap();
        assert_eq!(command, "snapshot-save");
        assert_eq!(arguments["devices"], json!(["yougori-vm-disk"]));
        assert_eq!(arguments["vmstate"], "yougori-vm-disk");
        // A record that QEMU never stored cannot report a successful restore.
        assert!(live_snapshot_plan(LiveSnapshot::Load, "snap-a", &empty, &devices).unwrap_err().contains("not stored"));
        assert!(live_snapshot_plan(LiveSnapshot::Delete, "snap-a", &empty, &devices).unwrap().is_none());
        let offline = [disk(json!([{"name": "snap-a", "vm-state-size": 0}])), vars.clone()];
        assert!(live_snapshot_plan(LiveSnapshot::Load, "snap-a", &offline, &devices).unwrap_err().contains("no saved memory state"));
        let live = [disk(json!([{"name": "snap-a", "vm-state-size": 4096}])), vars.clone()];
        assert!(live_snapshot_plan(LiveSnapshot::Save, "snap-a", &live, &devices).unwrap_err().contains("already exists"));
        let (command, arguments) = live_snapshot_plan(LiveSnapshot::Load, "snap-a", &live, &devices).unwrap().unwrap();
        assert_eq!((command, arguments["vmstate"].as_str()), ("snapshot-load", Some("yougori-vm-disk")));
        let (command, _) = live_snapshot_plan(LiveSnapshot::Delete, "snap-a", &live, &devices).unwrap().unwrap();
        assert_eq!(command, "snapshot-delete");
        let imported = [live[0].clone(), vars, json!({"node-name": "import-0123456789abcdef", "drv": "raw", "ro": false})];
        assert!(live_snapshot_plan(LiveSnapshot::Load, "snap-a", &imported, &devices).unwrap_err().contains("Imported drives"));
        assert!(live_snapshot_plan(LiveSnapshot::Save, "snap-b", &imported, &[]).is_err());
    }

    #[test]
    fn runtime_identifiers_reject_path_and_hmp_injection() {
        for value in [
            "",
            ".",
            "..",
            "../escape",
            "..\\escape",
            "nested/path",
            "nested\\path",
            "snapshot\nquit",
            "snapshot\rquit",
            "snapshot;quit",
            "snapshot quit",
            "żółw",
        ] {
            assert!(
                validate_runtime_identifier("snapshot", value).is_err(),
                "accepted unsafe identifier {value:?}"
            );
        }
        assert!(validate_runtime_identifier("snapshot", &"a".repeat(161)).is_err());
        assert!(validate_runtime_identifier("snapshot", &"a".repeat(160)).is_ok());
        assert!(validate_runtime_identifier("snapshot", "env-01.snapshot_2").is_ok());
    }

    #[test]
    fn direct_child_verification_rejects_lexical_parent_traversal() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("root");
        fs::create_dir(&root).unwrap();
        let outside = directory.path().join("outside.qcow2");
        fs::write(&outside, b"outside").unwrap();
        let escaped = root
            .join("child")
            .join("..")
            .join("..")
            .join("outside.qcow2");
        assert!(verified_direct_child(&root, &escaped, PathKind::File, "test artifact").is_err());
    }

    #[test]
    fn restore_transaction_marker_blocks_vm_use_until_resolution() {
        let directory = tempfile::tempdir().unwrap();
        let data_root = directory.path().join("runtime");
        let environment = data_root.join("environments/env-1");
        fs::create_dir_all(&environment).unwrap();
        assert!(ensure_no_pending_vm_restore(&data_root, "env-1").is_ok());

        let (transaction_path, previous, _) = vm_restore_transaction_paths(&environment);
        let transaction = VmRestoreTransaction {
            version: VM_RESTORE_TRANSACTION_VERSION,
            had_previous_disk: true,
            created_environment_directory: false,
            security_changed: false,
            previous_security: None,
            next_security: None,
        };
        fs::write(&transaction_path, serde_json::to_vec(&transaction).unwrap()).unwrap();
        assert!(ensure_no_pending_vm_restore(&data_root, "env-1").is_err());
        let decoded = read_vm_restore_transaction(&transaction_path)
            .unwrap()
            .unwrap();
        assert!(decoded.had_previous_disk);

        fs::remove_file(transaction_path).unwrap();
        fs::write(previous, b"old disk").unwrap();
        assert!(ensure_no_pending_vm_restore(&data_root, "env-1").is_err());
    }

    #[tokio::test]
    async fn source_fingerprint_cache_reuses_only_unchanged_sources() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.img");
        let mut bytes = vec![0_u8; SOURCE_SAMPLE_BYTES * 4];
        bytes[SOURCE_SAMPLE_BYTES * 2] = 7;
        fs::write(&source, &bytes).unwrap();
        let identity = inspect_source_identity(source.clone()).await.unwrap();
        let checksum = "ab".repeat(32);
        write_source_checksum_cache(directory.path(), &identity, "qcow2", &checksum)
            .await
            .unwrap();
        assert_eq!(
            read_cached_source_checksum(directory.path(), &identity, "qcow2").await,
            Some(checksum)
        );

        bytes[SOURCE_SAMPLE_BYTES * 2] = 9;
        fs::write(&source, &bytes).unwrap();
        let changed = inspect_source_identity(source).await.unwrap();
        assert_ne!(changed, identity);
        assert_eq!(
            read_cached_source_checksum(directory.path(), &changed, "qcow2").await,
            None
        );
    }

    #[tokio::test]
    async fn blob_import_copies_and_hashes_in_one_pass() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.iso");
        let destination = directory.path().join("managed.part");
        let bytes = (0_u32..300_000)
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        fs::write(&source, &bytes).unwrap();
        let (size, checksum) = copy_and_hash(source, destination.clone(), "test boot media".into())
            .await
            .unwrap();
        assert_eq!(size, bytes.len() as u64);
        assert_eq!(fs::read(destination).unwrap(), bytes);
        assert_eq!(checksum, hex::encode(Sha256::digest(&bytes)));
    }

    #[tokio::test]
    async fn durable_metadata_write_replaces_a_regular_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("microvm.json");
        fs::write(&path, b"old").unwrap();
        write_durable_file(path.clone(), b"new".to_vec())
            .await
            .unwrap();
        assert_eq!(fs::read(path).unwrap(), b"new");
    }

    #[tokio::test]
    async fn managed_micro_vm_manifest_rejects_disks_and_oversized_json_before_parsing() {
        let directory = tempfile::tempdir().unwrap();
        let disk = directory.path().join("legacy.qcow2");
        fs::write(&disk, b"not json").unwrap();
        assert!(read_managed_micro_vm_manifest(&disk)
            .await
            .unwrap_err()
            .contains("must be a JSON manifest"));

        let oversized = directory.path().join("microvm.json");
        File::create(&oversized)
            .unwrap()
            .set_len(1024 * 1024 + 1)
            .unwrap();
        assert!(read_managed_micro_vm_manifest(&oversized)
            .await
            .unwrap_err()
            .contains("1 MiB safety limit"));
    }

    #[tokio::test]
    async fn builtin_micro_vm_uses_current_boot_upgrade_without_rewriting_custom_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let current_kernel = directory.path().join("current-kernel");
        let current_initrd = directory.path().join("current-initrd");
        fs::write(&current_kernel, b"current").unwrap();
        fs::write(&current_initrd, b"trusted upgrade").unwrap();
        let path = directory.path().join("microvm.json");
        let saved = ManagedMicroVmManifest {
            version: MICRO_VM_MANIFEST_VERSION,
            builtin: true,
            kernel: directory.path().join("removed-install/kernel"),
            initrd: Some(directory.path().join("removed-install/initrd")),
            cmdline: "root=/dev/vda rw console=ttyS0 custom-option=keep".into(),
        };
        let original = serde_json::to_vec(&saved).unwrap();
        fs::write(&path, &original).unwrap();
        let manifest = read_managed_micro_vm_manifest(&path).await.unwrap();
        let (kernel, initrd) = micro_vm_boot_files(&manifest, &current_kernel, &current_initrd).unwrap();
        assert_eq!(kernel, current_kernel);
        assert_eq!(initrd, Some(current_initrd.as_path()));
        assert_eq!(manifest.cmdline, saved.cmdline);
        assert_eq!(fs::read(&path).unwrap(), original);
        fs::remove_file(&current_initrd).unwrap();
        assert!(micro_vm_boot_files(&manifest, &current_kernel, &current_initrd).is_err());

        let custom_kernel = directory.path().join("custom-kernel");
        fs::write(&custom_kernel, b"custom").unwrap();
        let mut custom = saved.clone();
        custom.builtin = false;
        custom.kernel = custom_kernel.clone();
        custom.initrd = None;
        fs::write(&path, serde_json::to_vec(&custom).unwrap()).unwrap();
        let custom = read_managed_micro_vm_manifest(&path).await.unwrap();
        let (kernel, initrd) = micro_vm_boot_files(&custom, &current_kernel, &current_initrd).unwrap();
        assert_eq!(kernel, custom_kernel);
        assert!(initrd.is_none());
        fs::remove_file(&custom_kernel).unwrap();
        assert!(read_managed_micro_vm_manifest(&path).await.is_err());
    }

    #[tokio::test]
    async fn vm_base_sweep_preserves_references_and_only_removes_content_addresses() {
        let directory = tempfile::tempdir().unwrap();
        let bases = directory.path().join("bases");
        fs::create_dir(&bases).unwrap();
        let preserved = bases.join(format!("{}.iso", "11".repeat(32)));
        let removable_disk = bases.join(format!("{}.qcow2", "22".repeat(32)));
        let removable_kernel = bases.join(format!("{}.kernel", "33".repeat(32)));
        let arbitrary = bases.join("user-file.iso");
        fs::write(&preserved, b"keep").unwrap();
        fs::write(&removable_disk, b"remove-disk").unwrap();
        fs::write(&removable_kernel, b"remove-kernel").unwrap();
        fs::write(&arbitrary, b"never-touch").unwrap();
        fs::create_dir(bases.join("source-cache")).unwrap();
        fs::write(bases.join("source-cache/cache.json"), b"{}").unwrap();

        let canonical_bases = fs::canonicalize(&bases).unwrap();
        let referenced = HashSet::from([fs::canonicalize(&preserved).unwrap()]);
        let reclaimed = sweep_unreferenced_vm_bases(&canonical_bases, &referenced)
            .await
            .unwrap();
        assert_eq!(
            reclaimed,
            b"remove-disk".len() as u64 + b"remove-kernel".len() as u64
        );
        assert!(preserved.is_file());
        assert!(!removable_disk.exists());
        assert!(!removable_kernel.exists());
        assert_eq!(fs::read(arbitrary).unwrap(), b"never-touch");
        assert!(bases.join("source-cache/cache.json").is_file());
    }

    #[tokio::test]
    #[ignore = "uses bundled qemu-img on disposable disks; does not boot any VM"]
    async fn vm_cache_cleanup_handles_missing_raw_leaf_and_preserves_backing_images() {
        let data = tempfile::tempdir().unwrap();
        let manager = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), data.path()).unwrap();
        let bases = manager.data_root.join("bases");
        let envs = manager.data_root.join("environments");
        let referenced_iso = bases.join(format!("{}.iso", "11".repeat(32)));
        let unused_iso = bases.join(format!("{}.iso", "22".repeat(32)));
        let raw_base = bases.join(format!("{}.iso", "33".repeat(32)));
        let qcow_base = bases.join(format!("{}.qcow2", "44".repeat(32)));
        fs::write(&referenced_iso, b"shared installer").unwrap();
        fs::write(&unused_iso, b"unused installer").unwrap();
        fs::write(&raw_base, vec![0_u8; 4096]).unwrap();
        command_output(&manager.layout.qemu_img, &["create".into(), "-f".into(), "qcow2".into(), path_string(&qcow_base), "1M".into()], "test base").await.unwrap();
        // Both a missing raw leaf (like an expired VSS snapshot) and valid raw /
        // qcow2 dependencies must be handled without deleting surviving bases.
        for (id, format, backing) in [
            ("expired-branch", "raw", data.path().join("missing-shadow-copy")),
            ("raw-backed", "raw", raw_base.clone()),
            ("qcow-backed", "qcow2", qcow_base.clone()),
        ] {
            let directory = envs.join(id);
            fs::create_dir(&directory).unwrap();
            command_output(&manager.layout.qemu_img, &["create".into(), "-u".into(), "-f".into(), "qcow2".into(), "-F".into(), format.into(), "-b".into(), path_string(&backing), path_string(&directory.join("system.qcow2")), "1M".into()], "test overlay").await.unwrap();
        }
        let reclaimed = manager.garbage_collect_vm_bases(&[referenced_iso.clone()]).await.unwrap();
        assert_eq!(reclaimed, b"unused installer".len() as u64);
        assert!(!unused_iso.exists());
        assert!(referenced_iso.exists());
        assert!(raw_base.exists());
        assert!(qcow_base.exists());
        assert!(envs.join("expired-branch/system.qcow2").exists());

        // Unknown/corrupt dependencies still fail closed before any sweep.
        fs::write(&unused_iso, b"keep while unsafe").unwrap();
        let broken = envs.join("unreadable-chain");
        fs::create_dir(&broken).unwrap();
        command_output(&manager.layout.qemu_img, &["create".into(), "-u".into(), "-f".into(), "qcow2".into(), "-F".into(), "qcow2".into(), "-b".into(), path_string(&data.path().join("missing.qcow2")), path_string(&broken.join("system.qcow2")), "1M".into()], "test missing qcow dependency").await.unwrap();
        assert!(manager.garbage_collect_vm_bases(&[]).await.is_err());
        assert!(unused_iso.exists());
        manager.delete_vm("unreadable-chain").await.unwrap();
        assert!(!broken.exists());
        assert!(envs.join("qcow-backed/system.qcow2").exists());
    }

    #[test]
    fn log_tail_reads_only_the_requested_suffix() {
        let log = tempfile::NamedTempFile::new().unwrap();
        let bytes = (0_u32..10_000)
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        fs::write(log.path(), &bytes).unwrap();
        assert_eq!(read_file_tail(log.path(), 257), bytes[bytes.len() - 257..]);
    }

    #[test]
    fn custom_micro_vm_manifest_defaults_to_a_serial_root_disk() {
        let manifest = serde_json::from_str::<MicroVmSourceManifest>(
            r#"{"kernel":"vmlinuz","disk":"root.qcow2"}"#,
        )
        .unwrap();
        assert_eq!(manifest.cmdline, default_micro_vm_cmdline());
        assert!(manifest.initrd.is_none());
    }

    #[test]
    fn recognizes_delayed_whpx_guest_panic() {
        let log = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            log.path(),
            "whpx: injection failed, vector: 0\nWHPX: Unexpected VP exit code 4\n",
        )
        .unwrap();
        assert!(whpx_failed(log.path()));
    }


    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "launches the bundled QEMU runtime"]
    async fn bundled_qemu_exposes_qmp_and_vnc_websocket() {
        use tokio::io::AsyncReadExt;

        let app_data = tempfile::tempdir().unwrap();
        let manifest_directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let manager = RuntimeManager::new(&manifest_directory, app_data.path()).unwrap();
        let source = app_data.path().join("source.qcow2");
        command_output(
            &manager.layout.qemu_img,
            &[
                "create".into(),
                "-f".into(),
                "qcow2".into(),
                path_string(&source),
                "128M".into(),
            ],
            "create test virtual disk",
        )
        .await
        .unwrap();
        let provisioned = manager
            .provision_vm("env-runtime-test", source.to_str().unwrap())
            .await
            .unwrap();
        let console = manager
            .start_vm(
                "env-runtime-test",
                &provisioned.disk_path,
                &provisioned.source_path,
                &crate::models::ResourcePolicy {
                    cpu: crate::models::ResourceRange {
                        min: 1.0,
                        preferred: 2.0,
                        max: 2.0,
                        current: 0.0,
                    },
                    memory_gb: crate::models::ResourceRange {
                        min: 0.5,
                        preferred: 0.5,
                        max: 1.0,
                        current: 0.0,
                    },
                    priority: crate::models::Priority::Normal,
                    dynamic: true,
                },
                cfg!(target_os = "windows"),
            )
            .await
            .unwrap();
        let port = console
            .websocket_url
            .rsplit(':')
            .next()
            .unwrap()
            .parse::<u16>()
            .unwrap();
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
            .await
            .unwrap();
        let mut response = vec![0_u8; 1024];
        let count = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&response[..count]).contains("101 Switching Protocols"));
        // GPU (virgl) state cannot be saved live; the disks are still captured.
        manager.create_vm_snapshot("env-runtime-test", &provisioned.disk_path, "live-gpu").await.unwrap();
        manager.delete_vm_snapshot("env-runtime-test", &provisioned.disk_path, "live-gpu").await.unwrap();
        let orphan = manager
            .data_root
            .join("bases")
            .join(format!("{}.iso", "ff".repeat(32)));
        fs::write(&orphan, b"unreferenced").unwrap();
        let reclaimed = manager.garbage_collect_vm_bases(&[]).await.unwrap();
        assert!(reclaimed >= b"unreferenced".len() as u64);
        assert!(!orphan.exists());
        assert!(provisioned.source_path.is_file());
        manager.shutdown_all().await;

        let original_disk = hash_file(provisioned.disk_path.clone()).await.unwrap();
        let backup = manager
            .export_vm_disk(
                "env-runtime-test",
                &provisioned.disk_path,
                &provisioned.source_path,
                "transaction-test",
            )
            .await
            .unwrap();
        manager
            .install_vm_backup("env-runtime-test", &backup.path)
            .await
            .unwrap();
        let environment_directory = provisioned.disk_path.parent().unwrap();
        let (transaction, previous, _) = vm_restore_transaction_paths(environment_directory);
        assert!(transaction.is_file());
        assert!(previous.is_file());
        let pending_start = manager
            .start_vm(
                "env-runtime-test",
                &provisioned.disk_path,
                &provisioned.source_path,
                &crate::models::ResourcePolicy {
                    cpu: crate::models::ResourceRange {
                        min: 1.0,
                        preferred: 1.0,
                        max: 1.0,
                        current: 0.0,
                    },
                    memory_gb: crate::models::ResourceRange {
                        min: 0.5,
                        preferred: 0.5,
                        max: 0.5,
                        current: 0.0,
                    },
                    priority: crate::models::Priority::Normal,
                    dynamic: true,
                },
                false,
            )
            .await
            .unwrap_err();
        assert!(pending_start.contains("awaiting persisted-state"));
        manager
            .rollback_vm_backup_install("env-runtime-test")
            .await
            .unwrap();
        assert_eq!(
            hash_file(provisioned.disk_path.clone()).await.unwrap(),
            original_disk
        );
        manager
            .install_vm_backup("env-runtime-test", &backup.path)
            .await
            .unwrap();
        manager
            .finalize_vm_backup_install("env-runtime-test")
            .await
            .unwrap();
        assert!(!transaction.exists());
        assert!(!previous.exists());
        manager
            .remove_snapshot_artifact(&backup.path)
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "launches the bundled QEMU runtime"]
    async fn bundled_full_vm_live_snapshots_exclude_raw_firmware_state() {
        let app_data = tempfile::tempdir().unwrap();
        let manifest_directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let manager = RuntimeManager::new(&manifest_directory, app_data.path()).unwrap();
        let source = app_data.path().join("source.qcow2");
        command_output(&manager.layout.qemu_img, &["create".into(), "-f".into(), "qcow2".into(), path_string(&source), "128M".into()], "create test virtual disk").await.unwrap();
        let provisioned = manager.provision_vm("env-live-snapshot", source.to_str().unwrap()).await.unwrap();
        let range = |value: f64| crate::models::ResourceRange { min: value, preferred: value, max: value, current: 0.0 };
        let policy = crate::models::ResourcePolicy { cpu: range(1.0), memory_gb: range(0.5), priority: crate::models::Priority::Normal, dynamic: true };
        manager.start_vm("env-live-snapshot", &provisioned.disk_path, &provisioned.source_path, &policy, false).await.unwrap();
        let disk = &provisioned.disk_path;
        // HMP savevm refused the raw UEFI variables, so these used to be phantoms.
        manager.create_vm_snapshot("env-live-snapshot", disk, "live-a").await.unwrap();
        assert!(manager.create_vm_snapshot("env-live-snapshot", disk, "live-a").await.unwrap_err().contains("already exists"));
        assert!(manager.restore_vm_snapshot("env-live-snapshot", disk, "never-saved").await.unwrap_err().contains("not stored"));
        manager.create_vm_snapshot("env-live-snapshot", disk, "live-b").await.unwrap();
        manager.delete_vm_snapshot("env-live-snapshot", disk, "live-b").await.unwrap();
        manager.delete_vm_snapshot("env-live-snapshot", disk, "live-b").await.unwrap();
        match manager.restore_vm_snapshot("env-live-snapshot", disk, "live-a").await {
            // Hosts that can save VM state restore it in place.
            Ok(()) => assert!(manager.vm_is_running("env-live-snapshot").await.unwrap()),
            // WHPX keeps a crash-consistent disk snapshot instead.
            Err(error) => assert!(error.contains("Stop the virtual machine"), "{error}"),
        }
        assert!(manager.vm_is_running("env-live-snapshot").await.unwrap());
        manager.shutdown_all().await;
        manager.restore_vm_snapshot("env-live-snapshot", disk, "live-a").await.unwrap();
        manager.delete_vm_snapshot("env-live-snapshot", disk, "live-a").await.unwrap();
        // Stopped VMs use qemu-img; deleting a missing snapshot stays idempotent.
        manager.delete_vm_snapshot("env-live-snapshot", disk, "live-a").await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "launches the bundled direct-kernel microVM runtime"]
    async fn bundled_alpine_micro_vm_exposes_qmp_without_a_display() {
        let app_data = tempfile::tempdir().unwrap();
        let manifest_directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let manager = RuntimeManager::new(&manifest_directory, app_data.path()).unwrap();
        let provisioned = manager
            .provision_micro_vm("micro-runtime-test", "builtin:alpine")
            .await
            .unwrap();
        fs::remove_file(&provisioned.source_path).unwrap();
        let restored_manifest = manager
            .restore_builtin_micro_vm_manifest("micro-runtime-test")
            .await
            .unwrap();
        assert_eq!(restored_manifest, provisioned.source_path);
        let policy = crate::models::ResourcePolicy {
            cpu: crate::models::ResourceRange { min: 1.0, preferred: 1.0, max: 1.0, current: 0.0 },
            memory_gb: crate::models::ResourceRange { min: 0.125, preferred: 0.25, max: 0.5, current: 0.0 },
            priority: crate::models::Priority::Normal,
            dynamic: true,
        };
        assert_eq!(manager.micro_vm_startup_memory_gb("micro-runtime-test", &restored_manifest, &policy).await.unwrap(), 0.5);
        let mut capped = policy.clone();
        capped.memory_gb.max = 0.25;
        assert!(manager.start_micro_vm("micro-runtime-test", &provisioned.disk_path, &restored_manifest, &capped).await.unwrap_err().contains("512 MiB"));
        assert!(!manager.vm_is_running("micro-runtime-test").await.unwrap());
        let console = manager
            .start_micro_vm(
                "micro-runtime-test",
                &provisioned.disk_path,
                &restored_manifest,
                &policy,
            )
            .await
            .unwrap();
        assert!(console.headless);
        assert!(console.websocket_url.is_empty());
        assert!(console.guest_control_available);
        let qmp_port = manager.vms.lock().await.get("micro-runtime-test").unwrap().qmp_port;
        let memory = qmp_request(qmp_port, "query-memory-size-summary", None).await.unwrap();
        assert_eq!(memory["base-memory"].as_u64(), Some(512 * 1024 * 1024));
        assert_eq!(manager.micro_vm_startup_memory_gb("micro-runtime-test", &restored_manifest, &policy).await.unwrap(), 0.5);
        let serial_path = console.serial_log_path.as_ref().unwrap();
        assert!(serial_path.is_file());
        // QMP readiness precedes kernel/initramfs/userspace startup. Use the
        // maintained host boot budget, and fail immediately on a kernel panic.
        let userspace_started = Instant::now();
        let deadline = userspace_started + super::super::host_platform::guest_boot_timeout();
        let serial_output = loop {
            let output = fs::read_to_string(serial_path).unwrap_or_default();
            assert!(!output.contains("Kernel panic"), "microVM kernel panicked before userspace:\n{output}");
            if output.contains("OpenRC") || Instant::now() >= deadline || !manager.vm_is_running("micro-runtime-test").await.unwrap() {
                break output;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert!(
            serial_output.contains("OpenRC"),
            "microVM guest did not reach Alpine userspace:\n{serial_output}\nQEMU:\n{}",
            fs::read_to_string(
                app_data
                    .path()
                    .join("runtime/environments/micro-runtime-test/qemu.log")
            )
            .unwrap_or_default()
        );
        eprintln!("microVM OpenRC ready after {:.3}s following QMP; actual boot RAM512MiB", userspace_started.elapsed().as_secs_f64());
        let command_output = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let response = tokio::time::timeout(remaining, manager.execute_micro_vm_command("micro-runtime-test", "printf yougori-agent-ready")).await;
            match response {
                Ok(Ok(output)) => break output,
                Ok(Err(error)) if Instant::now() >= deadline => {
                    panic!("microVM guest agent did not become ready: {error}\n{serial_output}")
                }
                Err(_) => panic!("microVM guest agent exceeded its maintained boot budget:\n{serial_output}"),
                Ok(Err(_)) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        };
        assert_eq!(command_output.exit_code, 0);
        assert_eq!(command_output.stdout, "yougori-agent-ready");
        assert!(command_output.stderr.is_empty());
        eprintln!("microVM authenticated command ready after {:.3}s following QMP", userspace_started.elapsed().as_secs_f64());
        // Saving a smaller next-boot policy cannot make the live allocation
        // disappear from admission/reporting or start a second guest.
        manager.start_micro_vm("micro-runtime-test", &provisioned.disk_path, &restored_manifest, &capped).await.unwrap();
        assert_eq!(manager.micro_vm_startup_memory_gb("micro-runtime-test", &restored_manifest, &capped).await.unwrap(), 0.5);
        let shutdown_started = Instant::now();
        manager
            .vm_action("micro-runtime-test", "stop")
            .await
            .unwrap();
        assert!(shutdown_started.elapsed() < Duration::from_secs(9));
        assert!(!manager.vm_is_running("micro-runtime-test").await.unwrap());
        manager.shutdown_all().await;
    }
}
