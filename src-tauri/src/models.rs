use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum EnvironmentKind {
    Cloud,
    Container,
    MicroVm,
    FullVm,
    ComputerBranch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum EnvironmentStatus {
    Running,
    Stopped,
    Paused,
    Provisioning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum RuntimeProviderKind {
    CloudSsh,
    #[serde(alias = "openDockOci")]
    YougoriOci,
    #[serde(alias = "openDockCuda")]
    YougoriCuda,
    Qemu,
    NativeSandbox,
}

impl RuntimeProviderKind {
    pub fn is_container(&self) -> bool {
        matches!(self, Self::YougoriOci | Self::YougoriCuda)
    }
}

#[cfg(test)]
mod provider_name_tests {
    use super::RuntimeProviderKind;

    #[test]
    fn old_provider_values_load_and_new_values_are_written() {
        for (previous, current, provider) in [
            ("openDockOci", "yougoriOci", RuntimeProviderKind::YougoriOci),
            ("openDockCuda", "yougoriCuda", RuntimeProviderKind::YougoriCuda),
        ] {
            assert_eq!(serde_json::from_str::<RuntimeProviderKind>(&format!("\"{previous}\"")).unwrap(), provider);
            assert_eq!(serde_json::to_string(&provider).unwrap(), format!("\"{current}\""));
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum BranchType {
    ExactCopy,
    AppsSettings,
    AppsOnly,
    CleanOs,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum SandboxFileAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SandboxShare {
    pub path: String,
    pub access: SandboxFileAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SandboxPolicy {
    pub executable: String,
    #[serde(default)]
    pub arguments: String,
    #[serde(default)]
    pub shares: Vec<SandboxShare>,
    #[serde(default)]
    pub network_access: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum Priority {
    Low,
    Normal,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceRange {
    pub min: f64,
    pub preferred: f64,
    pub max: f64,
    pub current: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourcePolicy {
    pub cpu: ResourceRange,
    pub memory_gb: ResourceRange,
    pub priority: Priority,
    // Compatibility with old state, snapshots, backups and API clients. The
    // allocation mode is no longer configurable, even if they send false.
    #[serde(skip_deserializing, default = "allocation_always_enabled")]
    pub dynamic: bool,
}

fn allocation_always_enabled() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Environment {
    pub id: String,
    pub name: String,
    pub kind: EnvironmentKind,
    pub status: EnvironmentStatus,
    pub runtime: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<RuntimeProviderKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub console_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_command: Option<String>,
    #[serde(default)]
    pub network_access: bool,
    #[serde(default)]
    pub gpu_access: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_policy: Option<SandboxPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch_type: Option<BranchType>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_opened_at: Option<String>,
    pub cpu_usage: f64,
    pub memory_usage_gb: f64,
    pub storage_delta_gb: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_limit_gb: Option<f64>,
    #[serde(default)]
    pub storage_drive: Option<String>,
    pub network_rx_mbps: f64,
    pub resource_policy: ResourcePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum PermissionKind {
    Network,
    Ports,
    Files,
    Volumes,
    Data,
    Secrets,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum ConnectionDirection {
    OneWay,
    Bidirectional,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum EnforcementStatus {
    Enforced,
    Pending,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SelectedConnectionFolder {
    pub environment_id: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Connection {
    pub id: String,
    pub source_id: String,
    pub target_id: String,
    pub direction: ConnectionDirection,
    pub permissions: Vec<PermissionKind>,
    pub ports: Vec<String>,
    #[serde(default)]
    pub commands: bool,
    #[serde(default)]
    pub selected_folders: Vec<SelectedConnectionFolder>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume: Option<String>,
    pub active: bool,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement_status: Option<EnforcementStatus>,
    #[serde(default)]
    pub provider_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SnapshotStatus {
    Ready,
    Creating,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotEnvironmentState {
    pub runtime: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<RuntimeProviderKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_command: Option<String>,
    #[serde(default)]
    pub network_access: bool,
    #[serde(default)]
    pub gpu_access: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_policy: Option<SandboxPolicy>,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch_type: Option<BranchType>,
    pub resource_policy: ResourcePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub id: String,
    pub environment_id: String,
    pub name: String,
    pub created_at: String,
    pub size_gb: f64,
    pub delta_gb: f64,
    pub encrypted: bool,
    pub status: SnapshotStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_snapshot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_state: Option<SnapshotEnvironmentState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connections: Option<Vec<Connection>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum BackupProvider {
    AwsS3,
    AzureBlob,
    GoogleCloud,
    S3Compatible,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupDestination {
    pub id: String,
    pub name: String,
    pub provider: BackupProvider,
    pub location: String,
    pub encrypted: bool,
    pub connected: bool,
    pub last_verified_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum BackupRunStatus {
    Complete,
    Running,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupRun {
    pub id: String,
    pub environment_id: String,
    pub destination_id: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    pub transferred_gb: f64,
    pub deduplicated_gb: f64,
    pub status: BackupRunStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_object: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HostPressure {
    Low,
    Moderate,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostMetrics {
    pub hostname: String,
    pub os: String,
    pub cpu_model: String,
    pub total_cpu: usize,
    pub used_cpu_percent: f64,
    #[serde(default)]
    pub gpu_usage_percent: Option<f64>,
    pub total_memory_gb: f64,
    pub used_memory_gb: f64,
    pub total_storage_gb: f64,
    pub used_storage_gb: f64,
    /// Mount point of the volume holding runtime data (not all host drives).
    #[serde(default)]
    pub storage_drive: Option<String>,
    #[serde(default)]
    pub storage_drives: Vec<HostStorageDrive>,
    pub storage_saved_gb: f64,
    pub pressure: HostPressure,
    pub cpu_history: Vec<f64>,
    #[serde(default)]
    pub gpu_history: Vec<f64>,
    pub memory_history: Vec<f64>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostStorageDrive {
    pub path: String,
    pub name: String,
    pub file_system: String,
    pub total_gb: f64,
    pub free_gb: f64,
    pub read_only: bool,
    pub removable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderKind {
    Container,
    Virtualization,
    Storage,
    Backup,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderAvailability {
    Ready,
    Unavailable,
    NeedsSetup,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderStatus {
    pub id: String,
    pub name: String,
    pub kind: ProviderKind,
    pub status: ProviderAvailability,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum ThemePreference {
    Light,
    Dark,
    System,
    Theme1,
    Theme2,
    Theme3,
    Theme4,
    Theme5,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CustomThemeColors {
    pub background: String,
    pub surface: String,
    pub accent: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    #[serde(default)]
    pub auto_start_environment_ids: Vec<String>,
    #[serde(default)]
    pub keep_awake: bool,
    pub theme: ThemePreference,
    #[serde(default)]
    pub custom_theme_colors: Option<CustomThemeColors>,
    pub launch_at_startup: bool,
    /// Start at login as a background engine (no dashboard), for CLI-first use.
    #[serde(default)]
    pub startup_headless: bool,
    pub minimize_to_tray: bool,
    pub pause_on_battery: bool,
    pub telemetry_enabled: bool,
    pub data_directory: String,
    pub snapshot_retention: usize,
    pub bandwidth_limit_mbps: usize,
}

/// A saved domain: the metadata of a reusable Cloudflare account tunnel. Its token is only in the OS vault.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SavedDomain {
    pub id: String,
    /// Vault scope the token is stored under (normally "public-presets").
    pub credential_environment_id: String,
    /// App port the token was saved for; part of its vault key.
    pub port: u16,
    pub hostname: String,
    /// Local port the Cloudflare route points at (http://127.0.0.1:host_port).
    pub host_port: u16,
}

/// A non-secret service publication that should be restored when its node starts.
/// Cloudflare tokens remain in the OS credential vault; this record stores only
/// the selected saved setup and listener settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedEnvironmentService {
    pub id: String,
    pub environment_id: String,
    pub port: u16,
    pub kind: crate::workspace::PublicationKind,
    pub host_port: u16,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub cloudflare_hostname: Option<String>,
    #[serde(default)]
    pub remembered_account: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformState {
    /// Changes only when settings change, so narrow updates can reject stale writers.
    #[serde(default)]
    pub settings_revision: u64,
    /// Last native startup outcome. Credentials and request payloads are never retained.
    #[serde(default)]
    pub startup_report: Option<crate::lifecycle::StartupReport>,
    /// Completed environment-copy downloads across every temporary link.
    #[serde(default)]
    pub environment_downloads: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    pub cloud_copy_sources: std::collections::BTreeMap<String, crate::duplication::VerifiedSource>,
    #[serde(default)]
    pub duplication_jobs: std::collections::BTreeMap<String, crate::duplication::Job>,
    #[serde(default)]
    pub cli_environment_id: Option<String>,
    #[serde(default)]
    pub cloud_deployments: std::collections::BTreeMap<String,crate::cloud_deployment::Deployment>,
    #[serde(default)]
    pub neocloud_deployments: std::collections::BTreeMap<String,crate::neocloud::Deployment>,
    /// User-declared graph service ports shared by desktop and CLI. A declaration
    /// never opens a listener or grants network access by itself.
    #[serde(default)]
    pub manual_service_ports: std::collections::BTreeMap<String, Vec<u16>>,
    /// Reusable Cloudflare account tunnels, shared by the app and the CLI. Tokens stay in the OS vault.
    #[serde(default)]
    pub saved_domains: Vec<SavedDomain>,
    /// Service routes are restored from these non-secret settings when a node starts.
    #[serde(default)]
    pub saved_environment_services: Vec<SavedEnvironmentService>,
    /// Retired/staged reset generations awaiting deletion. Never erase the active generation.
    #[serde(default)]
    pub pending_factory_resets: Vec<FactoryResetCleanup>,
    #[serde(default)]
    pub schema_version: u32,
    pub environments: Vec<Environment>,
    pub connections: Vec<Connection>,
    pub snapshots: Vec<Snapshot>,
    pub destinations: Vec<BackupDestination>,
    pub backup_runs: Vec<BackupRun>,
    /// Durable intent records distinguish a crash before a VM restore state
    /// commit (roll back the disk) from a crash after it (finalize the disk).
    #[serde(default)]
    pub pending_vm_restores: Vec<String>,
    pub host: HostMetrics,
    pub providers: Vec<ProviderStatus>,
    pub settings: AppSettings,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentDeletionResult {
    #[serde(flatten)]
    pub state: PlatformState,
    pub storage_cleanup: StorageCleanupResult,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageCleanupResult {
    pub reclaimed_cache_bytes: u64,
    pub reclaimed_disk_bytes: u64,
    pub notes: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FactoryResetCleanup {
    pub environment: Environment,
    pub snapshots: Vec<Snapshot>,
    pub committed: bool,
}

impl PlatformState {
    pub fn seeded() -> Result<Self, serde_json::Error> {
        serde_json::from_str(include_str!("../../src/data/seed.json"))
    }

    pub fn empty() -> Result<Self, serde_json::Error> {
        let mut state = Self::seeded()?;
        state.schema_version = 7;
        state.environments.clear();
        state.duplication_jobs.clear();
        state.cloud_copy_sources.clear();
        state.neocloud_deployments.clear();
        state.saved_environment_services.clear();
        state.connections.clear();
        state.snapshots.clear();
        state.destinations.clear();
        state.backup_runs.clear();
        state.pending_vm_restores.clear();
        Ok(state)
    }

    pub fn migrate(mut self) -> Result<Self, serde_json::Error> {
        if self.schema_version < 2 {
            let settings = self.settings;
            self = Self::empty()?;
            self.settings = settings;
        }
        if self.schema_version < 3 {
            for environment in &mut self.environments {
                if environment.kind == EnvironmentKind::ComputerBranch {
                    environment.provider = Some(RuntimeProviderKind::NativeSandbox);
                    environment.status = EnvironmentStatus::Stopped;
                    environment.console_endpoint = None;
                    if environment.sandbox_policy.is_none() {
                        environment.last_error = Some(
                            "This branch used the retired virtual-machine engine. Create a new Computer Branch and choose the application and folders it may access."
                                .into(),
                        );
                    }
                }
            }
        }
        if self.schema_version < 4 {
            // Before schema 4, "microVm" used the same UEFI/q35 launch path as a
            // full VM. Keep those existing disks bootable instead of feeding their
            // ISO/QCOW2 source to the new direct-kernel manifest loader.
            for environment in &mut self.environments {
                if environment.kind == EnvironmentKind::MicroVm {
                    environment.kind = EnvironmentKind::FullVm;
                }
            }
        }
        if self.schema_version < 7 {
            // Full VMs previously always had an uplink; their unused false
            // network_access field must not unplug them during this upgrade.
            for environment in &mut self.environments {
                if environment.kind == EnvironmentKind::FullVm {
                    environment.network_access = true;
                }
            }
            for snapshot in &mut self.snapshots {
                if self.environments.iter().any(|environment| environment.id == snapshot.environment_id && environment.kind == EnvironmentKind::FullVm) {
                    if let Some(saved) = &mut snapshot.environment_state { saved.network_access = true; }
                }
            }
        }
        self.schema_version = 7;
        Ok(self)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateResourceRange {
    pub min: f64,
    pub preferred: f64,
    pub max: f64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateResourcePolicy {
    pub cpu: CreateResourceRange,
    pub memory_gb: CreateResourceRange,
    pub priority: Priority,
    #[serde(skip_deserializing, default = "allocation_always_enabled")]
    pub dynamic: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateEnvironmentRequest {
    #[serde(default)]
    pub auto_setup_cuda: bool,
    #[serde(default)]
    pub workload: Option<yougori_cli::workload::Options>,
    #[serde(default)]
    pub storage_drive: Option<String>,
    #[serde(default)]
    pub storage_gb: Option<f64>,
    pub name: String,
    pub kind: EnvironmentKind,
    pub runtime: String,
    pub provider: RuntimeProviderKind,
    #[serde(default)]
    pub container_command: Option<String>,
    #[serde(default = "allocation_always_enabled")]
    pub network_access: bool,
    #[serde(default)]
    pub gpu_access: bool,
    #[serde(default)]
    pub sandbox_policy: Option<SandboxPolicy>,
    pub description: String,
    pub branch_type: Option<BranchType>,
    pub resource_policy: CreateResourcePolicy,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateConnectionRequest {
    pub source_id: String,
    pub target_id: String,
    pub direction: ConnectionDirection,
    pub permissions: Vec<PermissionKind>,
    pub ports: Vec<String>,
    #[serde(default)]
    pub commands: bool,
    #[serde(default)]
    pub selected_folders: Vec<SelectedConnectionFolder>,
    #[serde(default)]
    pub ssh_port: Option<u16>,
    pub volume: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddDestinationRequest {
    pub name: String,
    pub provider: BackupProvider,
    pub location: String,
    pub access_key: String,
    pub secret_key: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum GuestSessionKind {
    ContainerTerminal,
    EmbeddedVnc,
    HeadlessTerminal,
    HeadlessSerial,
    NativeApplication,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestSession {
    pub kind: GuestSessionKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub websocket_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecuteCommandRequest {
    pub environment_id: String,
    pub command: String,
    #[serde(default)]
    pub ssh: Option<crate::runtime::guest_ssh::GuestSsh>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecuteConnectedCommandRequest {
    pub connection_id: String,
    pub source_id: String,
    pub command: String,
    #[serde(default)]
    pub ssh: Option<crate::runtime::guest_ssh::GuestSsh>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creation_defaults_to_internet_on_and_preserves_explicit_off() {
        let mut value=serde_json::json!({
            "name":"Network default", "kind":"container", "runtime":"alpine:3.24",
            "provider":"yougoriOci", "description":"",
            "resourcePolicy":{"cpu":{"min":1,"preferred":1,"max":1},
                "memoryGb":{"min":1,"preferred":1,"max":1},"priority":"normal"}
        });
        let request:CreateEnvironmentRequest=serde_json::from_value(value.clone()).unwrap();
        assert!(request.network_access);
        value["networkAccess"]=false.into();
        let request:CreateEnvironmentRequest=serde_json::from_value(value).unwrap();
        assert!(!request.network_access);
    }

    #[test]
    fn allocation_is_enabled_for_legacy_policies_and_creation_requests() {
        for legacy_flag in [Some(false), Some(true), None] {
            let mut saved = serde_json::json!({
                "cpu": { "min": 1, "preferred": 2, "max": 4, "current": 0 },
                "memoryGb": { "min": 1, "preferred": 2, "max": 4, "current": 0 },
                "priority": "normal"
            });
            if let Some(flag) = legacy_flag { saved["dynamic"] = flag.into(); }
            let policy: ResourcePolicy = serde_json::from_value(saved.clone()).unwrap();
            assert!(policy.dynamic);
            assert_eq!(policy.cpu.preferred, 2.0);
            assert_eq!(serde_json::to_value(&policy).unwrap()["dynamic"], true);
            let request: CreateResourcePolicy = serde_json::from_value(saved).unwrap();
            assert!(request.dynamic);
        }
    }

    #[test]
    fn legacy_q35_micro_vm_is_migrated_to_a_full_vm() {
        let mut state = PlatformState::empty().unwrap();
        state.schema_version = 3;
        state.environments.push(Environment {
            id: "legacy-microvm".into(),
            name: "Legacy microVM".into(),
            kind: EnvironmentKind::MicroVm,
            status: EnvironmentStatus::Stopped,
            runtime: "C:\\managed\\installer.iso".into(),
            provider: Some(RuntimeProviderKind::Qemu),
            runtime_id: Some("legacy-microvm".into()),
            runtime_path: Some("C:\\managed\\system.qcow2".into()),
            control_endpoint: None,
            console_endpoint: None,
            container_command: None,
            network_access: false,
            gpu_access: false,
            sandbox_policy: None,
            last_error: None,
            description: "Created before direct-kernel profiles".into(),
            branch_type: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            last_opened_at: None,
            cpu_usage: 0.0,
            memory_usage_gb: 0.0,
            storage_delta_gb: 0.0,
            storage_limit_gb: None,
            storage_drive: None,
            network_rx_mbps: 0.0,
            resource_policy: ResourcePolicy {
                cpu: ResourceRange {
                    min: 1.0,
                    preferred: 1.0,
                    max: 2.0,
                    current: 0.0,
                },
                memory_gb: ResourceRange {
                    min: 1.0,
                    preferred: 2.0,
                    max: 4.0,
                    current: 0.0,
                },
                priority: Priority::Normal,
                dynamic: true,
            },
        });

        let migrated = state.migrate().unwrap();
        assert_eq!(migrated.schema_version, 7);
        assert_eq!(migrated.environments[0].kind, EnvironmentKind::FullVm);
        assert!(migrated.environments[0].network_access);
        let mut disconnected = migrated.clone();
        disconnected.environments[0].network_access = false;
        assert!(!disconnected.migrate().unwrap().environments[0].network_access);
        assert_eq!(
            migrated.environments[0].runtime,
            "C:\\managed\\installer.iso"
        );
    }
}
