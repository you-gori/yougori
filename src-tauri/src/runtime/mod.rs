mod appliance;
mod boot_token;
mod host_platform;
pub(crate) mod cloud;
pub(crate) mod cuda;
mod host_relay;
mod microvm_network;
#[cfg(test)]
mod cuda_tests;
pub(crate) mod fabric;
mod remote_bridge;
pub(crate) mod connection_files;
mod appliance_capacity;
pub(crate) mod gpu;
mod branch;
mod native_sandbox;
mod guest_job;
pub(crate) mod recovery;
mod shutdown;
#[cfg(test)]
mod container_smoke_tests;
mod vm;
mod vm_memory;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmPowerState {
    Running,
    Stopped,
    Failed,
}
mod boot_media;
mod vm_security;
pub(crate) mod storage;
mod volumes;
pub(crate) mod named_volumes;
mod workload;
mod container_storage;
mod storage_reclaim;

pub(crate) fn backup_has_vm_security(path: &Path) -> Result<bool, String> {
    vm_security::read_backup(path).map(|state| state.is_some())
}
#[cfg(test)]
mod internet_tests;
#[cfg(test)]
mod windows_setup_tests;
mod workspace;
pub(crate) mod guest_ssh;
mod file_import;
mod snapshot_export;
#[cfg(test)]
pub(crate) use snapshot_export::SnapshotExports;
mod duplication_disk;
mod import_drive;
pub use import_drive::ImportedDrive;

use std::{
    collections::HashMap,
    fs,
    io::{BufReader, Read},
    path::{Path, PathBuf},
    sync::Weak,
    time::{Instant, UNIX_EPOCH},
};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sysinfo::System;
use tokio::{
    process::Child,
    sync::{Mutex, OnceCell, RwLock},
};

use crate::models::{ProviderAvailability, ProviderKind, ProviderStatus};

pub(super) struct PerfSpan {
    name: &'static str,
    started: Instant,
    enabled: bool,
}

impl PerfSpan {
    pub(super) fn new(name: &'static str) -> Self {
        Self {
            name,
            started: Instant::now(),
            enabled: std::env::var_os("YOUGORI_PERF_TRACE").is_some()
                || std::env::var_os("OPENDOCK_PERF_TRACE").is_some(),
        }
    }
}

impl Drop for PerfSpan {
    fn drop(&mut self) {
        if self.enabled {
            eprintln!(
                "[yougori-perf] {}: {:.3} ms",
                self.name,
                self.started.elapsed().as_secs_f64() * 1_000.0
            );
        }
    }
}

#[derive(Debug, Clone)]
struct RuntimeLayout {
    root: PathBuf,
    qemu_system: PathBuf,
    qemu_img: PathBuf,
    appliance_base: PathBuf,
    appliance_kernel: PathBuf,
    appliance_initramfs: PathBuf,
    uefi_code: PathBuf,
    uefi_vars: PathBuf,
}

struct ApplianceProcess {
    // Fields drop in declaration order. Request child termination before
    // releasing packet redirectors or deleting the private boot token, even
    // when a shutdown future is cancelled after taking this process owner.
    child: Child,
    internet: microvm_network::MicroVmNetwork,
    _boot_token: boot_token::BootTokenFile,
    endpoint: AgentEndpoint,
    qmp_port: u16,
    max_memory_mib: usize,
    _port_reservations: vm::VmPortReservations,
    capacity: appliance_capacity::ApplianceCapacity,
    active_containers: std::collections::HashSet<String>,
    gpu: Option<gpu::GpuAdapter>,
}

#[derive(Debug, Clone)]
struct AgentEndpoint {
    base_url: String,
    token: String,
}

struct VmProcess {
    child: Child,
    internet: Option<microvm_network::MicroVmNetwork>,
    _branch_block_server: Option<BranchBlockServer>,
    _port_reservations: vm::VmPortReservations,
    is_micro_vm: bool,
    gpu_enabled: bool,
    gpu: Option<gpu::GpuAdapter>,
    micro_endpoint: Option<AgentEndpoint>,
    process_id: u32,
    allocated_cpus: usize,
    // Direct-kernel guests have fixed boot RAM; full VMs retain balloon control.
    allocated_micro_memory_gb: Option<f64>,
    qmp_port: u16,
    websocket_port: u16,
    console_password: String,
}

#[cfg(target_os = "windows")]
struct NativeSandboxProcess {
    process_handle: usize,
    job_handle: usize,
    process_id: u32,
}

#[cfg(not(target_os = "windows"))]
struct NativeSandboxProcess { process_id: u32 }

struct BranchBlockServer {
    port: u16,
    export_name: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for BranchBlockServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub struct RuntimeManager {
    resource_directory: PathBuf,
    settings_root: PathBuf,
    volumes: volumes::Volumes,
    workload_shares: Mutex<HashMap<String, (String, Vec<crate::host_files::HostFolderServer>)>>,
    pub cloud: cloud::Cloud,
    cuda: yougori_cuda_runtime::CudaRuntime,
    fabric: fabric::Fabric,
    remote_bridges: Mutex<HashMap<String, remote_bridge::BridgeHandle>>,
    shared_files: connection_files::SharedFiles,
    layout: RuntimeLayout,
    data_root: PathBuf,
    appliance_overlay_source: PathBuf,
    appliance_overlay_base: PathBuf,
    appliance_overlay_base_digest: String,
    client: Client,
    appliance: Mutex<Option<ApplianceProcess>>,
    appliance_operations: RwLock<()>,
    snapshot_exports: snapshot_export::SnapshotExports,
    gpu_launches: std::sync::Arc<RwLock<()>>,
    appliance_capacity: std::sync::Mutex<appliance_capacity::ApplianceCapacity>,
    appliance_preparation: OnceCell<bool>,
    vms: Mutex<HashMap<String, VmProcess>>,
    vm_lifecycle: Mutex<HashMap<String, Weak<Mutex<()>>>>,
    sandboxes: Mutex<HashMap<String, NativeSandboxProcess>>,
    #[cfg(target_os = "windows")]
    branch_operations: Mutex<()>,
    network_samples: Mutex<HashMap<String, (u64, std::time::Instant)>>,
    process_metrics: Mutex<System>,
}

impl RuntimeManager {
    #[cfg(all(test, windows))]
    pub(crate) fn use_dedicated_cuda_test_runtime(&mut self) -> Result<(), String> {
        let path=Path::new(env!("CARGO_MANIFEST_DIR")).join("../build/cuda/integration-runtime").canonicalize().map_err(|e|e.to_string())?;
        if !path.join("installed.json").is_file(){return Err("Install the dedicated CUDA test runtime first".into())}
        self.cuda=yougori_cuda_runtime::CudaRuntime::new(path)?;
        Ok(())
    }
    pub async fn connect_cloud(&self, id: &str) -> Result<serde_json::Value,String> {
        self.cloud.connect(id,self.fabric.clone(),self.shared_files.clone()).await
    }
    pub async fn desktop_connected_files_request(&self, environment_id: &str, request: serde_json::Value) -> Result<serde_json::Value, String> {
        self.shared_files.desktop_request(environment_id, request).await
    }
    pub fn storage_root(&self) -> &Path { &self.data_root }

    pub fn new(resource_directory: &Path, app_data_directory: &Path) -> Result<Self, String> {
        let layout = RuntimeLayout::discover(resource_directory)?;
        Self::new_with_layout(resource_directory, app_data_directory, layout)
    }

    #[cfg(test)]
    fn new_with_fixture_resources(resource_directory: &Path, app_data_directory: &Path) -> Result<Self, String> {
        let layout = RuntimeLayout::from_candidates(resource_directory, vec![
            resource_directory.join("runtime"),
            resource_directory.join("resources/runtime"),
        ])?;
        Self::new_with_layout(resource_directory, app_data_directory, layout)
    }

    fn new_with_layout(resource_directory: &Path, app_data_directory: &Path, layout: RuntimeLayout) -> Result<Self, String> {
        let data_root = app_data_directory.join("runtime");
        fs::create_dir_all(&data_root)
            .map_err(|error| format!("create Yougori runtime data directory: {error}"))?;
        let appliance_base_digest = {
            let _trace = PerfSpan::new("runtime verification");
            layout.verify(&data_root.join("integrity-cache-v1.json"))?
        };
        let (appliance_overlay_source, appliance_overlay_base_digest) =
            appliance::existing_overlay_base(&data_root, &layout.appliance_base, &appliance_base_digest)
                .unwrap_or_else(|| (layout.appliance_base.clone(), appliance_base_digest.clone()));
        let appliance_overlay_base = appliance::archive_overlay_path(&data_root, &appliance_overlay_base_digest);
        fs::create_dir_all(data_root.join("appliance"))
            .map_err(|error| format!("create Yougori appliance data directory: {error}"))?;
        fs::create_dir_all(data_root.join("environments"))
            .map_err(|error| format!("create Yougori environment data directory: {error}"))?;
        fs::create_dir_all(data_root.join("snapshots"))
            .map_err(|error| format!("create Yougori snapshot directory: {error}"))?;
        fs::create_dir_all(data_root.join("bases"))
            .map_err(|error| format!("create Yougori base image directory: {error}"))?;
        let client = Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(35 * 60))
            .user_agent(concat!("Yougori/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| format!("initialize Yougori control client: {error}"))?;
        Ok(Self {
            resource_directory: resource_directory.to_owned(),
            settings_root: data_root.clone(),
            volumes: volumes::Volumes::new(&data_root)?,
            workload_shares: Mutex::new(HashMap::new()),
            cloud: cloud::Cloud::new(data_root.join("cloud")),
            cuda: yougori_cuda_runtime::CudaRuntime::new(cuda::cuda_directory(&data_root)?)?,
            fabric: fabric::Fabric::default(),
            remote_bridges: Mutex::new(HashMap::new()),
            shared_files: connection_files::SharedFiles::default(),
            layout,
            data_root,
            appliance_overlay_source,
            appliance_overlay_base,
            appliance_overlay_base_digest,
            client,
            appliance: Mutex::new(None),
            appliance_operations: RwLock::new(()),
            snapshot_exports: snapshot_export::SnapshotExports::default(),
            gpu_launches: std::sync::Arc::new(RwLock::new(())),
            appliance_capacity: std::sync::Mutex::new(appliance_capacity::ApplianceCapacity::default()),
            appliance_preparation: OnceCell::new(),
            vms: Mutex::new(HashMap::new()),
            vm_lifecycle: Mutex::new(HashMap::new()),
            sandboxes: Mutex::new(HashMap::new()),
            #[cfg(target_os = "windows")]
            branch_operations: Mutex::new(()),
            network_samples: Mutex::new(HashMap::new()),
            process_metrics: Mutex::new(System::new()),
        })
    }

    pub fn provider_statuses(&self) -> Vec<ProviderStatus> {
        vec![
            ProviderStatus {
                id: "provider-yougori-oci".into(),
                name: "Yougori OCI Runtime".into(),
                kind: ProviderKind::Container,
                status: ProviderAvailability::Ready,
                detail: if cfg!(target_os = "macos") { "macOS preview · x86-64 container appliance · Homebrew QEMU required; no GPU/CUDA" } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) { "Linux ARM64 · x86-64 container appliance through QEMU software emulation; no GPU/CUDA" } else if cfg!(target_os = "linux") { "Bundled containerd appliance · Linux QEMU/KVM" } else { "Bundled containerd appliance · no external runtime required" }.into(),
            },
            ProviderStatus {
                id: "provider-yougori-qemu".into(),
                name: "Yougori Virtualization".into(),
                kind: ProviderKind::Virtualization,
                status: ProviderAvailability::Ready,
                detail: if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
                    "Apple Silicon preview: x86-64 guests use slow software emulation, not ARM virtualization. Use amd64/x86-64 images, not ARM64. VM CPU and RAM changes require shutdown and restart. GPU/CUDA and Windows secure guests are unavailable."
                } else if cfg!(target_os = "macos") {
                    "Intel Mac preview: HVF acceleration for containers/full VMs with software fallback; microVMs use software emulation. VM CPU and RAM changes require shutdown and restart. GPU/CUDA and Windows secure guests are unavailable."
                } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
                    "Linux ARM64: x86-64 guests use software emulation. Use amd64/x86-64 guest images. ARM KVM cannot accelerate these guests; GPU/CUDA and Windows secure guests are unavailable."
                } else if cfg!(target_os = "linux") {
                    if std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").is_ok() {
                        "Linux QEMU · KVM hardware acceleration available"
                    } else {
                        "KVM is unavailable to this user; software emulation will be slower. Enable virtualization and grant your user access to /dev/kvm (kvm group), then log in again. Do not run Yougori as root."
                    }
                } else { "Bundled QEMU with hardware acceleration and software fallback" }.into(),
            },
            ProviderStatus {
                id: "provider-storage".into(),
                name: "Yougori CoW Storage".into(),
                kind: ProviderKind::Storage,
                status: ProviderAvailability::Ready,
                detail: "QCOW2 overlays and immutable OCI snapshot artifacts".into(),
            },
        ]
    }

    pub async fn shutdown_all(&self) {
        let report = self.shutdown_all_report().await;
        if report["complete"] != true {
            eprintln!("Runtime shutdown needs reconciliation: {}", report);
        }
    }
}

impl Drop for RuntimeManager {
    fn drop(&mut self) {
        if let Ok(mut appliance) = self.appliance.try_lock() {
            if let Some(process) = appliance.as_mut() {
                let _ = process.child.start_kill();
            }
        }
        if let Ok(mut vms) = self.vms.try_lock() {
            for process in vms.values_mut() {
                let _ = process.child.start_kill();
            }
        }
        if let Ok(mut sandboxes) = self.sandboxes.try_lock() {
            for process in sandboxes.values_mut() {
                native_sandbox::terminate_native_process(process);
            }
            sandboxes.clear();
        }
    }
}

impl RuntimeLayout {
    fn qemu_data(&self) -> PathBuf {
        if cfg!(target_os = "linux") { PathBuf::from("/usr/share/qemu") }
        else if cfg!(target_os = "macos") { host_platform::macos_qemu_prefix(std::env::consts::ARCH).join("share/qemu") }
        else { self.root.join("qemu/share") }
    }

    fn discover(resource_directory: &Path) -> Result<Self, String> {
        let mut candidates = vec![
            resource_directory.join("runtime"),
            resource_directory.join("resources").join("runtime"),
        ];
        if cfg!(yougori_source_runtime) {
            // Prefer current source assets over stale copies left in target/debug.
            candidates.insert(
                0,
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/runtime"),
            );
        }
        Self::from_candidates(resource_directory, candidates)
    }

    fn from_candidates(resource_directory: &Path, candidates: Vec<PathBuf>) -> Result<Self, String> {
        let root = candidates
            .into_iter()
            .find(|candidate| candidate.join("appliance/appliance-base.qcow2").is_file())
            .ok_or_else(|| {
                format!(
                    "bundled Yougori runtime was not found under {}",
                    resource_directory.display()
                )
            })?;
        let executable_suffix = if cfg!(target_os = "windows") {
            ".exe"
        } else {
            ""
        };
        let mut layout = Self {
            qemu_system: root
                .join("qemu")
                .join(format!("qemu-system-x86_64{executable_suffix}")),
            qemu_img: root
                .join("qemu")
                .join(format!("qemu-img{executable_suffix}")),
            appliance_base: root.join("appliance/appliance-base.qcow2"),
            appliance_kernel: root.join("appliance/vmlinuz-virt"),
            appliance_initramfs: root.join("appliance/initramfs-virt"),
            uefi_code: root.join("qemu/share/edk2-x86_64-code.fd"),
            uefi_vars: root.join("qemu/share/edk2-i386-vars.fd"),
            root,
        };
        if cfg!(target_os = "linux") {
            // Distribution packages own updates; never search PATH/the working directory.
            layout.qemu_system = PathBuf::from("/usr/bin/qemu-system-x86_64");
            layout.qemu_img = PathBuf::from("/usr/bin/qemu-img");
            layout.uefi_code = PathBuf::from("/usr/share/OVMF/OVMF_CODE_4M.fd");
            layout.uefi_vars = PathBuf::from("/usr/share/OVMF/OVMF_VARS_4M.fd");
        }
        if cfg!(target_os = "macos") {
            let prefix = host_platform::macos_qemu_prefix(std::env::consts::ARCH);
            layout.qemu_system = prefix.join("bin/qemu-system-x86_64");
            layout.qemu_img = prefix.join("bin/qemu-img");
            layout.uefi_code = prefix.join("share/qemu/edk2-x86_64-code.fd");
            layout.uefi_vars = prefix.join("share/qemu/edk2-i386-vars.fd");
        }
        Ok(layout)
    }

    fn verify(&self, cache_path: &Path) -> Result<String, String> {
        for path in [
            &self.qemu_system,
            &self.qemu_img,
            &self.appliance_base,
            &self.appliance_kernel,
            &self.appliance_initramfs,
            &self.uefi_code,
            &self.uefi_vars,
        ] {
            if !path.is_file() {
                let help = if cfg!(target_os = "macos") {
                    "On macOS, install native Homebrew QEMU with 'brew install qemu' (not under Rosetta), then reopen Yougori. See docs/macos.md."
                } else if cfg!(target_os = "linux") {
                    "On Linux, install qemu-system-x86, qemu-utils and ovmf using your package manager."
                } else { "Reinstall Yougori to restore its runtime files." };
                return Err(format!(
                    "Runtime file is missing: {}. {help}",
                    path.display()
                ));
            }
        }

        let runtime_root = canonical_path_key(&self.root);
        let previous = read_verification_cache(cache_path).filter(|cache| {
            cache.schema_version == RUNTIME_VERIFICATION_CACHE_VERSION
                && cache.runtime_root == runtime_root
        });
        let appliance_cache = previous.as_ref().and_then(|cache| {
            cache
                .manifests
                .iter()
                .find(|entry| entry.scope == "appliance")
        });
        let qemu_cache = previous
            .as_ref()
            .and_then(|cache| cache.manifests.iter().find(|entry| entry.scope == "qemu"));
        let appliance = verify_checksum_manifest(
            &self.root.join("appliance"),
            &self.root.join("appliance/SHA256SUMS"),
            "appliance",
            appliance_cache,
        )?;
        let qemu = if cfg!(any(target_os = "linux", target_os = "macos")) { None } else { Some(verify_checksum_manifest(
            &self.root.join("qemu"),
            &self.root.join("qemu/SHA256SUMS"),
            "qemu",
            qemu_cache,
        )?) };
        let appliance_base_digest = appliance
            .files
            .iter()
            .find(|entry| entry.relative_path == "appliance-base.qcow2")
            .map(|entry| entry.expected_sha256.clone())
            .ok_or_else(|| {
                format!(
                    "{} does not identify appliance-base.qcow2",
                    self.root.join("appliance/SHA256SUMS").display()
                )
            })?;
        let mut manifests = vec![appliance];
        if let Some(qemu) = qemu { manifests.push(qemu); }
        if cfg!(target_os = "windows") && self.root.join("qemu-secure").exists() {
            let secure_cache = previous.as_ref().and_then(|cache| cache.manifests.iter().find(|entry| entry.scope == "qemu-secure"));
            manifests.push(verify_checksum_manifest(
                &self.root.join("qemu-secure"), &self.root.join("qemu-secure/SHA256SUMS"), "qemu-secure", secure_cache,
            )?);
        }
        let current = RuntimeVerificationCache {
            schema_version: RUNTIME_VERIFICATION_CACHE_VERSION,
            runtime_root,
            manifests,
        };
        if previous.as_ref() != Some(&current) {
            // Cache persistence is an optimization. A read-only application-data folder must
            // not turn a successfully verified runtime into an application startup failure.
            let _ = write_verification_cache(cache_path, &current);
        }
        Ok(appliance_base_digest)
    }
}

const RUNTIME_VERIFICATION_CACHE_VERSION: u32 = 1;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RuntimeVerificationCache {
    schema_version: u32,
    runtime_root: String,
    manifests: Vec<ManifestVerification>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ManifestVerification {
    scope: String,
    manifest_sha256: String,
    files: Vec<VerifiedRuntimeFile>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct VerifiedRuntimeFile {
    relative_path: String,
    canonical_path: String,
    expected_sha256: String,
    length: u64,
    modified_unix_nanos: u64,
    created_unix_nanos: Option<u64>,
}

fn verify_checksum_manifest(
    root: &Path,
    manifest: &Path,
    scope: &str,
    cached: Option<&ManifestVerification>,
) -> Result<ManifestVerification, String> {
    let canonical_root = fs::canonicalize(root)
        .map_err(|error| format!("resolve runtime directory {}: {error}", root.display()))?;
    let checksums =
        fs::read(manifest).map_err(|error| format!("read {}: {error}", manifest.display()))?;
    let manifest_sha256 = hex::encode(Sha256::digest(&checksums));
    let checksums = std::str::from_utf8(&checksums)
        .map_err(|error| format!("decode {}: {error}", manifest.display()))?;
    let mut files = Vec::new();
    for line in checksums.lines().filter(|line| !line.trim().is_empty()) {
        let (expected, name) = line
            .split_once(char::is_whitespace)
            .ok_or_else(|| format!("invalid checksum line in {}", manifest.display()))?;
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("invalid checksum in {}", manifest.display()));
        }
        let relative = Path::new(name.trim().trim_start_matches('*'));
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(format!("unsafe runtime path in {}", manifest.display()));
        }
        let path = root.join(relative);
        let canonical_file = fs::canonicalize(&path)
            .map_err(|error| format!("resolve runtime file {}: {error}", path.display()))?;
        if !canonical_file.starts_with(&canonical_root) {
            return Err(format!(
                "runtime manifest entry resolves outside {}: {}",
                root.display(),
                path.display()
            ));
        }
        let metadata = fs::metadata(&path)
            .map_err(|error| format!("inspect runtime file {}: {error}", path.display()))?;
        if !metadata.is_file() {
            return Err(format!(
                "bundled runtime file is missing: {}",
                path.display()
            ));
        }
        files.push(VerifiedRuntimeFile {
            relative_path: relative.to_string_lossy().replace('\\', "/"),
            canonical_path: canonical_file.to_string_lossy().into_owned(),
            expected_sha256: expected.to_ascii_lowercase(),
            length: metadata.len(),
            modified_unix_nanos: system_time_nanos(metadata.modified().ok()),
            created_unix_nanos: metadata
                .created()
                .ok()
                .map(|time| system_time_nanos(Some(time))),
        });
    }
    if files.is_empty() {
        return Err(format!(
            "runtime checksum manifest is empty: {}",
            manifest.display()
        ));
    }

    let current = ManifestVerification {
        scope: scope.to_owned(),
        manifest_sha256,
        files,
    };
    if cached == Some(&current) {
        return Ok(current);
    }

    // The manifest or at least one identity tuple changed. Re-establish trust for the entire
    // manifest once; subsequent launches only read the small manifest and file metadata.
    for entry in &current.files {
        let path = root.join(&entry.relative_path);
        let actual = file_sha256(&path)?;
        if !actual.eq_ignore_ascii_case(&entry.expected_sha256) {
            return Err(format!(
                "bundled runtime checksum mismatch: {}",
                path.display()
            ));
        }
    }
    Ok(current)
}

fn file_sha256(path: &Path) -> Result<String, String> {
    let file =
        fs::File::open(path).map_err(|error| format!("verify {}: {error}", path.display()))?;
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("verify {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn system_time_nanos(time: Option<std::time::SystemTime>) -> u64 {
    time.and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or_default()
}

fn canonical_path_key(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn read_verification_cache(path: &Path) -> Option<RuntimeVerificationCache> {
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

fn write_verification_cache(path: &Path, cache: &RuntimeVerificationCache) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| {
        format!(
            "invalid runtime verification cache path: {}",
            path.display()
        )
    })?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("create runtime verification cache directory: {error}"))?;
    let temporary = parent.join(format!(
        ".integrity-cache-{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let contents = serde_json::to_vec(cache)
        .map_err(|error| format!("encode runtime verification cache: {error}"))?;
    fs::write(&temporary, contents)
        .map_err(|error| format!("write runtime verification cache: {error}"))?;
    if path.exists() {
        fs::remove_file(path)
            .map_err(|error| format!("replace runtime verification cache: {error}"))?;
    }
    fs::rename(&temporary, path)
        .map_err(|error| format!("commit runtime verification cache: {error}"))
}

fn available_port() -> Result<u16, String> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|error| format!("allocate a local control port: {error}"))?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|error| format!("read local control port: {error}"))
}

fn configure_background_process(command: &mut tokio::process::Command) {
    command.kill_on_drop(true);
    #[cfg(target_os = "linux")]
    unsafe {
        let parent = libc::getpid();
        command.pre_exec(move || {
            // Never gain new privilege from setuid binaries or file capabilities
            // after a compromise of a native runtime helper.
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // QEMU handles SIGTERM by closing disks. Do not leave disk holders
            // running after the app crashes; never terminate unrelated processes.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(std::io::Error::other("Yougori exited during runtime startup"));
            }
            Ok(())
        });
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.as_std_mut().creation_flags(CREATE_NO_WINDOW);
    }
}

fn configure_qemu_sandbox(command: &mut tokio::process::Command) {
    // A compromised VMM should not receive host API keys or bearer secrets.
    // Preserve only OS paths, locale and the desktop display/runtime hints that
    // QEMU needs. Explicit GPU variables are configured after this function.
    let environment = std::env::vars_os().filter(|(name, _)| {
        name.to_str().is_some_and(|name| qemu_environment_name_allowed(name))
    }).collect::<Vec<_>>();
    command.env_clear().envs(environment);
    #[cfg(target_os = "linux")]
    // QEMU's maintained seccomp policy permits vCPU/IO threads while denying
    // obsolete syscalls, privilege changes, new programs and scheduler changes.
    // An unsupported QEMU fails startup instead of silently dropping the filter.
    command.args(["-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"]);
    #[cfg(not(target_os = "linux"))]
    let _ = command;
}

fn qemu_environment_name_allowed(name: &str) -> bool {
    matches!(name.to_ascii_uppercase().as_str(),
        "SYSTEMROOT" | "WINDIR" | "SYSTEMDRIVE" | "PATH" | "TEMP" | "TMP"
        | "PROGRAMFILES" | "PROGRAMFILES(X86)" | "PROGRAMW6432" | "PROGRAMDATA"
        | "HOME" | "USERPROFILE" | "LANG" | "LANGUAGE" | "LC_ALL" | "LC_CTYPE"
        | "DISPLAY" | "WAYLAND_DISPLAY" | "XAUTHORITY" | "XDG_RUNTIME_DIR"
        | "DBUS_SESSION_BUS_ADDRESS" | "FONTCONFIG_PATH" | "FONTCONFIG_FILE")
}

async fn command_output(
    executable: &Path,
    arguments: &[String],
    operation: &str,
) -> Result<std::process::Output, String> {
    let mut command = tokio::process::Command::new(executable);
    command.args(arguments);
    configure_background_process(&mut command);
    let output = command
        .output()
        .await
        .map_err(|error| format!("{operation}: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = match (stderr.is_empty(), stdout.is_empty()) {
            (false, false) => format!("{stderr}\n{stdout}"),
            (false, true) => stderr,
            (true, false) => stdout,
            (true, true) => String::new(),
        };
        return Err(if detail.is_empty() {
            format!("{operation} failed with {}", output.status)
        } else {
            format!("{operation}: {detail}")
        });
    }
    Ok(output)
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(yougori_source_runtime)]
    fn development_runtime_prefers_source_over_stale_build_resources() {
        let directory = tempfile::tempdir().unwrap();
        let stale = directory.path().join("runtime/appliance");
        fs::create_dir_all(&stale).unwrap();
        fs::write(stale.join("appliance-base.qcow2"), b"stale").unwrap();

        let layout = RuntimeLayout::discover(directory.path()).unwrap();
        assert_eq!(
            layout.root,
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/runtime")
        );
    }

    #[test]
    fn allocated_port_is_loopback_bindable() {
        let port = available_port().unwrap();
        assert!(port > 0);
    }

    #[test]
    fn qemu_environment_excludes_host_secrets_and_loader_overrides() {
        for name in ["OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "HTTP_PROXY",
            "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "QEMU_AUDIO_DRV"] {
            assert!(!qemu_environment_name_allowed(name));
        }
        for name in ["SystemRoot", "PATH", "LANG", "DISPLAY", "XDG_RUNTIME_DIR"] {
            assert!(qemu_environment_name_allowed(name));
        }
    }

    #[test]
    fn verification_cache_invalidates_changed_runtime_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("runtime-part");
        fs::create_dir_all(&root).unwrap();
        let payload = root.join("payload.bin");
        fs::write(&payload, b"trusted-runtime").unwrap();
        let expected = file_sha256(&payload).unwrap();
        let manifest = root.join("SHA256SUMS");
        fs::write(&manifest, format!("{expected}  payload.bin\n")).unwrap();

        let verified =
            verify_checksum_manifest(&root, &manifest, "test", None).expect("initial verification");
        verify_checksum_manifest(&root, &manifest, "test", Some(&verified))
            .expect("unchanged metadata should reuse the cache");

        fs::write(&payload, b"tampered-runtime-with-a-new-length").unwrap();
        let error = verify_checksum_manifest(&root, &manifest, "test", Some(&verified))
            .expect_err("changed metadata must force a fresh content hash");
        assert!(error.contains("checksum mismatch"));
    }

    #[test]
    fn verification_cache_round_trips() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.json");
        let cache = RuntimeVerificationCache {
            schema_version: RUNTIME_VERIFICATION_CACHE_VERSION,
            runtime_root: canonical_path_key(directory.path()),
            manifests: vec![ManifestVerification {
                scope: "test".into(),
                manifest_sha256: "abc".into(),
                files: vec![VerifiedRuntimeFile {
                    relative_path: "runtime.bin".into(),
                    canonical_path: "C:/runtime/runtime.bin".into(),
                    expected_sha256: "def".into(),
                    length: 42,
                    modified_unix_nanos: 10,
                    created_unix_nanos: Some(5),
                }],
            }],
        };
        write_verification_cache(&path, &cache).unwrap();
        assert_eq!(read_verification_cache(&path), Some(cache));
    }

    #[test]
    #[ignore = "hashes the complete bundled runtime to compare cold and warm verification"]
    fn bundled_runtime_warm_verification_uses_the_metadata_cache() {
        let app_data = tempfile::tempdir().unwrap();
        let manifest_directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let cold_started = Instant::now();
        let cold = RuntimeManager::new(&manifest_directory, app_data.path()).unwrap();
        let cold_elapsed = cold_started.elapsed();
        drop(cold);

        let warm_started = Instant::now();
        let warm = RuntimeManager::new(&manifest_directory, app_data.path()).unwrap();
        let warm_elapsed = warm_started.elapsed();
        drop(warm);

        eprintln!(
            "bundled runtime verification: cold={:.3}ms warm={:.3}ms",
            cold_elapsed.as_secs_f64() * 1_000.0,
            warm_elapsed.as_secs_f64() * 1_000.0
        );
        assert!(
            warm_elapsed < cold_elapsed,
            "the metadata cache should be faster than hashing every runtime byte"
        );
    }
}
