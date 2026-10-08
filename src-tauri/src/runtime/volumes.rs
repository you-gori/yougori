//! Durable drive routing. A missing volume never falls back to the default disk.
use super::RuntimeManager;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, io::Write, path::{Path, PathBuf}, sync::{Arc, Mutex}};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Volume {
    directory: PathBuf,
    identity: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recovery_environment(id: &str) -> crate::models::Environment {
        serde_json::from_value(serde_json::json!({
            "id":id,"name":"Recovery fixture","kind":"container","provider":"yougoriCuda","status":"stopped",
            "runtime":"docker.io/library/ubuntu:24.04","description":"Disposable recovery routing test","createdAt":"test",
            "cpuUsage":0,"memoryUsageGb":0,"storageDeltaGb":0,"networkRxMbps":0,
            "resourcePolicy":{"cpu":{"min":1,"preferred":1,"max":1,"current":0},"memoryGb":{"min":1,"preferred":1,"max":1,"current":0},"priority":"normal","dynamic":true}
        })).unwrap()
    }

    fn assign(manager: &RuntimeManager, parent: &Path, id: &str) -> Result<PathBuf, String> {
        let identity = uuid::Uuid::new_v4().to_string();
        let directory = parent.canonicalize().map_err(|e| e.to_string())?.join(&identity);
        fs::create_dir(&directory).map_err(|e| e.to_string())?;
        fs::write(directory.join("yougori-volume.json"), serde_json::to_vec(&identity).unwrap()).map_err(|e| e.to_string())?;
        let mut routes = manager.volumes.routes.lock().unwrap();
        routes.entries.insert(id.into(), Volume { directory: directory.clone(), identity });
        save(&manager.data_root.join("storage-routes.json"), &routes)?;
        Ok(directory)
    }

    #[test]
    fn storage_routes_persist_and_never_fall_back_when_a_drive_disappears() -> Result<(), String> {
        let local = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let resources = Path::new(env!("CARGO_MANIFEST_DIR"));
        let manager = RuntimeManager::new(resources, local.path())?;
        let directory = assign(&manager, second.path(), "env-other")?;
        manager.inherit_storage("snapshot-other", "env-other")?;
        manager.inherit_storage("reset-other", "env-other")?;
        assert!(manager.same_storage("env-other", "reset-other")?);
        assert!(!manager.same_storage("env-other", "env-default")?);
        let engine = manager.storage_runtime("env-other")?.unwrap();
        assert_eq!(engine.storage_root(), directory.join("runtime"));
        assert!(!manager.data_root.join("environments/env-other").exists());
        let absent = directory.with_extension("offline");
        fs::rename(&directory, &absent).map_err(|e| e.to_string())?;
        assert!(manager.storage_runtime("env-other").is_err());
        fs::rename(&absent, &directory).map_err(|e| e.to_string())?;
        let original = fs::read(directory.join("yougori-volume.json")).unwrap();
        fs::write(directory.join("yougori-volume.json"), b"\"wrong-volume\"").unwrap();
        assert!(manager.storage_runtime("env-other").is_err());
        fs::write(directory.join("yougori-volume.json"), original).unwrap();
        let restored = RuntimeManager::new(resources, local.path())?;
        assert_eq!(restored.environment_storage_root("snapshot-other")?, directory.join("runtime"));
        assert!(restored.new_storage_on_drive(Some(second.path().to_str().unwrap())).is_err());
        let disks = sysinfo::Disks::new_with_refreshed_list();
        assert_eq!(super::super::storage::host_drives(&disks).len(), disks.list().iter().filter(|d| d.total_space() > 0).count());
        Ok(())
    }

    #[tokio::test]
    async fn recovery_uses_saved_provider_on_the_original_drive_and_never_falls_back() -> Result<(), String> {
        let local = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let resources = Path::new(env!("CARGO_MANIFEST_DIR"));
        let manager = RuntimeManager::new(resources, local.path())?;
        let directory = assign(&manager, second.path(), "env-recovery-routing")?;
        let mut environment = recovery_environment("env-recovery-routing");
        environment.id = "env-recovery-routing".into();
        environment.runtime_id = None;
        environment.kind = crate::models::EnvironmentKind::Container;
        environment.provider = Some(crate::models::RuntimeProviderKind::YougoriCuda);
        manager.register_container_provider(&environment.id, &crate::models::RuntimeProviderKind::YougoriCuda)?;
        let report = manager.recover_environment_report(&environment).await?;
        assert_eq!(report.provider, crate::models::RuntimeProviderKind::YougoriCuda);
        assert_eq!(report.storage_root, directory.join("runtime").display().to_string());
        assert!(report.disk_path.starts_with(&directory.display().to_string()));
        assert!(!report.ready_to_start); // no CUDA installation; never report fake success.
        environment.provider = Some(crate::models::RuntimeProviderKind::YougoriOci);
        let report = manager.recover_environment_report(&environment).await?;
        assert!(!report.ready_to_start);
        assert!(report.error.unwrap().contains("runtime route differ"));
        let absent = directory.with_extension("offline");
        fs::rename(&directory, &absent).map_err(|e|e.to_string())?;
        assert!(manager.recover_environment_report(&environment).await.unwrap_err().contains("Storage drive is unavailable"));
        assert!(!local.path().join("runtime/appliance/system.qcow2").exists());
        Ok(())
    }

    #[cfg(windows)]
    #[tokio::test]
    #[ignore = "uses a fresh disposable volume on D: to verify CUDA recovery routing; does not install or stop WSL"]
    async fn cuda_recovery_on_d_reports_the_original_provider_and_storage() -> Result<(), String> {
        let local = tempfile::tempdir().unwrap();
        let drive = tempfile::Builder::new().prefix("yougori-recovery-test-").tempdir_in("D:/").map_err(|e|e.to_string())?;
        let manager = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), local.path())?;
        let directory = assign(&manager, drive.path(), "env-d-recovery")?;
        let mut environment = recovery_environment("env-d-recovery");
        environment.id = "env-d-recovery".into();
        environment.runtime_id = None;
        environment.kind = crate::models::EnvironmentKind::Container;
        environment.provider = Some(crate::models::RuntimeProviderKind::YougoriCuda);
        manager.register_container_provider(&environment.id, &crate::models::RuntimeProviderKind::YougoriCuda)?;
        let report = manager.recover_environment_report(&environment).await?;
        assert_eq!(report.provider, crate::models::RuntimeProviderKind::YougoriCuda);
        assert_eq!(report.storage_root, directory.join("runtime").display().to_string());
        assert!(report.storage_root.trim_start_matches("\\\\?\\").to_ascii_lowercase().starts_with("d:"));
        assert!(!report.ready_to_start);
        assert!(!report.ownership_released);
        assert!(!local.path().join("runtime/cuda/runtime-owner.lock").exists());
        assert!(!directory.join("runtime/cuda/distribution/ext4.vhdx").exists());
        Ok(())
    }

    #[tokio::test]
    #[ignore = "downloads Alpine into a disposable OCI pool on another storage root and verifies restart and cleanup"]
    async fn storage_drive_container_uses_its_own_pool() -> Result<(), String> {
        let local = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let resources = Path::new(env!("CARGO_MANIFEST_DIR"));
        let manager = RuntimeManager::new(resources, local.path())?;
        let directory = assign(&manager, second.path(), "drive-container")?;
        let policy = serde_json::from_value(serde_json::json!({"cpu":{"min":1,"preferred":1,"max":1,"current":1},"memoryGb":{"min":0.5,"preferred":0.5,"max":0.5,"current":0.5},"priority":"normal","dynamic":false})).unwrap();
        let result = async {
            manager.provision_container_with_storage("drive-container", "quay.io/libpod/alpine:latest", "sleep 2147483647", &policy, false, false, 6.0).await?;
            manager.container_action("drive-container", "start", false).await?;
            let result = manager.execute_container_command("drive-container", "echo drive-container-survives > /root/marker; sync").await?;
            if result.exit_code != 0 { return Err(result.stderr); }
            assert!(directory.join("runtime/appliance/system.qcow2").exists());
            assert!(!manager.data_root.join("appliance/system.qcow2").exists());
            manager.container_action("drive-container", "stop", false).await?;
            manager.shutdown_all().await;
            let restored = RuntimeManager::new(resources, local.path())?;
            let verified = async {
                restored.container_action("drive-container", "start", false).await?;
                let result = restored.execute_container_command("drive-container", "cat /root/marker").await?;
                if result.exit_code != 0 || !result.stdout.contains("drive-container-survives") { return Err("Selected-drive container lost its data".into()); }
                assert_eq!(restored.container_telemetry(&["drive-container".into()]).await?.len(), 1);
                restored.container_action("drive-container", "stop", false).await?;
                restored.delete_container("drive-container").await?;
                Ok(())
            }.await;
            restored.shutdown_all().await;
            verified
        }.await;
        manager.shutdown_all().await;
        result
    }

    #[tokio::test]
    #[ignore = "boots a disposable MicroVM on another managed storage root and verifies restart, snapshots and deletion"]
    async fn storage_drive_microvm_lifecycle_preserves_its_disk() -> Result<(), String> {
        let local = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let resources = Path::new(env!("CARGO_MANIFEST_DIR"));
        let manager = RuntimeManager::new(resources, local.path())?;
        let directory = assign(&manager, second.path(), "drive-micro")?;
        let policy = serde_json::from_value(serde_json::json!({"cpu":{"min":1,"preferred":1,"max":1,"current":1},"memoryGb":{"min":0.5,"preferred":0.5,"max":1,"current":0.5},"priority":"normal","dynamic":false})).unwrap();
        let result = async {
            let vm = manager.provision_micro_vm("drive-micro", "builtin:alpine").await?;
            assert!(vm.disk_path.starts_with(&directory));
            manager.start_micro_vm_with_network("drive-micro", &vm.disk_path, &vm.source_path, &policy, false).await?;
            let written = manager.execute_micro_vm_command("drive-micro", "echo drive-survives > /root/storage-marker; sync").await?;
            if written.exit_code != 0 { return Err(written.stderr); }
            manager.vm_action("drive-micro", "stop").await?;
            manager.create_vm_snapshot("drive-micro", &vm.disk_path, "drive-snapshot").await?;
            manager.shutdown_all().await;
            let restored = RuntimeManager::new(resources, local.path())?;
            let verify = async {
                restored.start_micro_vm_with_network("drive-micro", &vm.disk_path, &vm.source_path, &policy, false).await?;
                let read = restored.execute_micro_vm_command("drive-micro", "cat /root/storage-marker").await?;
                if read.exit_code != 0 || !read.stdout.contains("drive-survives") { return Err("Selected-drive restart lost its marker".into()); }
                restored.vm_action("drive-micro", "stop").await?;
                restored.delete_vm_snapshot("drive-micro", &vm.disk_path, "drive-snapshot").await?;
                restored.delete_vm("drive-micro").await?;
                assert!(!vm.disk_path.exists());
                assert!(!restored.data_root.join("environments/drive-micro").exists());
                Ok(())
            }.await;
            restored.shutdown_all().await;
            verify
        }.await;
        manager.shutdown_all().await;
        result
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Routes {
    installation: String,
    entries: BTreeMap<String, Volume>,
}

pub(super) struct Volumes {
    routes: Mutex<Routes>,
    engines: Mutex<BTreeMap<PathBuf, Arc<RuntimeManager>>>,
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("Read storage routing: {e}"))?;
    if !metadata.is_file() || metadata.len() > 8 * 1024 * 1024 { return Err("Invalid storage routing file".into()); }
    serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| format!("Read storage routing: {e}"))
}

fn save(path: &Path, value: &Routes) -> Result<(), String> {
    let mut file = tempfile::NamedTempFile::new_in(path.parent().ok_or("Invalid storage path")?).map_err(|e| e.to_string())?;
    serde_json::to_writer(&mut file, value).map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist(path).map_err(|e| format!("Save drive selection: {e}"))?;
    Ok(())
}

impl Volumes {
    pub(super) fn new(root: &Path) -> Result<Self, String> {
        let path = root.join("storage-routes.json");
        let routes = if path.try_exists().map_err(|e| e.to_string())? { read_json(&path)? } else {
            Routes { installation: uuid::Uuid::new_v4().to_string(), entries: BTreeMap::new() }
        };
        uuid::Uuid::parse_str(&routes.installation).map_err(|_| "Invalid storage installation identity")?;
        Ok(Self { routes: Mutex::new(routes), engines: Mutex::new(BTreeMap::new()) })
    }
}

impl RuntimeManager {
    /// Coordination keys for all registered pools, including an unavailable
    /// drive. Listing these paths does not load a runtime or redirect storage.
    pub(crate) fn storage_pool_roots(&self) -> Vec<PathBuf> {
        let mut roots = std::collections::BTreeSet::from([self.data_root.clone()]);
        roots.extend(self.volumes.routes.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).entries.values().map(|volume| volume.directory.join("runtime")));
        roots.into_iter().collect()
    }

    fn volume(&self, id: &str) -> Result<Option<Volume>, String> {
        super::vm::validate_runtime_identifier("storage route", id)?;
        Ok(self.volumes.routes.lock().map_err(|_| "Storage routing lock unavailable")?.entries.get(id).cloned())
    }

    pub fn same_storage(&self, left: &str, right: &str) -> Result<bool, String> { Ok(self.volume(left)? == self.volume(right)?) }
    pub fn volume_is_assigned(&self, id: &str) -> Result<bool, String> { Ok(self.volume(id)?.is_some()) }

    pub fn environment_storage_root(&self, id: &str) -> Result<PathBuf, String> {
        match self.volume(id)? {
            Some(volume) => { self.verify_volume(&volume)?; Ok(volume.directory.join("runtime")) }
            None => Ok(self.data_root.clone()),
        }
    }

    fn verify_volume(&self, volume: &Volume) -> Result<(), String> {
        uuid::Uuid::parse_str(&volume.identity).map_err(|_| "Invalid storage volume identity")?;
        if volume.directory.file_name().and_then(|s| s.to_str()) != Some(volume.identity.as_str()) { return Err("Invalid managed storage directory".into()); }
        let directory = volume.directory.canonicalize().map_err(|_| format!("Storage drive is unavailable: {}. Reconnect the original drive and retry.", volume.directory.display()))?;
        if directory != volume.directory { return Err("The environment storage folder was redirected. Reconnect its original drive.".into()); }
        let identity: String = read_json(&directory.join("yougori-volume.json"))?;
        if identity != volume.identity { return Err("This is not the environment's original storage drive. Reconnect the original drive.".into()); }
        Ok(())
    }

    pub fn storage_runtime(&self, id: &str) -> Result<Option<Arc<Self>>, String> {
        self.volume(id)?.map(|volume| self.volume_runtime(&volume)).transpose()
    }

    pub fn storage_runtime_on_drive(&self, drive: Option<&str>) -> Result<Option<Arc<Self>>, String> {
        use sha2::Digest;
        let Some(drive) = drive.filter(|s| !s.is_empty()) else { return Ok(None); };
        let key = format!("storage-{:x}", sha2::Sha256::digest(drive.as_bytes()));
        self.select_storage_drive(&key, Some(drive))?;
        self.storage_runtime(&key)
    }

    pub(crate) fn registered_storage_runtimes(&self) -> Vec<Result<Arc<Self>, String>> {
        let volumes: BTreeMap<_, _> = self.volumes.routes.lock().unwrap_or_else(|p| p.into_inner()).entries.values().map(|v| (v.directory.clone(), v.clone())).collect();
        volumes.values().map(|volume| self.volume_runtime(volume)).collect()
    }

    fn volume_runtime(&self, volume: &Volume) -> Result<Arc<Self>, String> {
        self.verify_volume(volume)?;
        let mut engines = self.volumes.engines.lock().map_err(|_| "Storage engine lock unavailable")?;
        if let Some(engine) = engines.get(&volume.directory) { return Ok(engine.clone()); }
        let mut engine = Self::new(&self.resource_directory, &volume.directory)?;
        engine.fabric = self.fabric.clone();
        engine.shared_files = self.shared_files.clone();
        engine.gpu_launches = self.gpu_launches.clone();
        engine.snapshot_exports = self.snapshot_exports.clone();
        engine.settings_root = self.settings_root.clone();
        let engine = Arc::new(engine);
        engines.insert(volume.directory.clone(), engine.clone());
        Ok(engine)
    }

    /// Copy the drive binding for snapshots and replacement runtime IDs.
    pub fn inherit_storage(&self, id: &str, source: &str) -> Result<(), String> {
        super::vm::validate_runtime_identifier("storage route", id)?;
        let Some(volume) = self.volume(source)? else { return Ok(()); };
        let mut routes = self.volumes.routes.lock().map_err(|_| "Storage routing lock unavailable")?;
        if let Some(existing) = routes.entries.get(id) {
            return if existing == &volume { Ok(()) } else { Err("The existing environment belongs to a different drive".into()) };
        }
        let mut next = routes.clone();
        next.entries.insert(id.into(), volume);
        save(&self.data_root.join("storage-routes.json"), &next)?;
        *routes = next;
        Ok(())
    }

    /// Selection is a mount point returned by the OS, never an arbitrary path.
    pub fn select_storage_drive(&self, id: &str, selected: Option<&str>) -> Result<(), String> {
        super::vm::validate_runtime_identifier("storage route", id)?;
        let Some(selected) = selected.filter(|value| !value.is_empty()) else { return Ok(()); };
        let mount = Path::new(selected).canonicalize().map_err(|_| "The selected storage drive is unavailable")?;
        let disks = sysinfo::Disks::new_with_refreshed_list();
        let disk = disks.list().iter().find(|disk| disk.mount_point().canonicalize().is_ok_and(|path| path == mount)).ok_or("Choose an available storage drive")?;
        if disk.is_read_only() { return Err("The selected drive is read-only".into()); }
        if disk.available_space() < 2 * 1024 * 1024 * 1024 { return Err("The selected drive needs at least 2 GB free".into()); }
        if super::storage::runtime_disk(&disks, &self.data_root).is_some_and(|current| current.mount_point() == disk.mount_point()) { return Ok(()); }
        let mut routes = self.volumes.routes.lock().map_err(|_| "Storage routing lock unavailable")?;
        let parent = mount.join("Yougori");
        fs::create_dir_all(&parent).map_err(|e| format!("Cannot use this storage drive: {e}"))?;
        if parent.canonicalize().map_err(|e| e.to_string())? != parent { return Err("The Yougori storage folder is redirected".into()); }
        let directory = parent.join(&routes.installation);
        let identity_file = directory.join("yougori-volume.json");
        if !directory.try_exists().map_err(|e| e.to_string())? {
            fs::create_dir(&directory).map_err(|e| e.to_string())?;
            let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&identity_file).map_err(|e| e.to_string())?;
            file.write_all(serde_json::to_string(&routes.installation).map_err(|e| e.to_string())?.as_bytes()).and_then(|_| file.sync_all()).map_err(|e| e.to_string())?;
        }
        let volume = Volume { directory, identity: routes.installation.clone() };
        self.verify_volume(&volume)?;
        let probe = tempfile::NamedTempFile::new_in(&volume.directory).map_err(|e| format!("This drive is not writable: {e}"))?;
        drop(probe);
        if let Some(existing) = routes.entries.get(id) {
            return if existing == &volume { Ok(()) } else { Err("An existing environment cannot change drives through creation".into()) };
        }
        let mut next = routes.clone();
        next.entries.insert(id.into(), volume);
        save(&self.data_root.join("storage-routes.json"), &next)?;
        *routes = next;
        Ok(())
    }

    pub fn storage_runtime_for_path(&self, path: &Path) -> Result<Option<Arc<Self>>, String> {
        let volumes: Vec<_> = self.volumes.routes.lock().map_err(|_| "Storage routing lock unavailable")?.entries.values().cloned().collect();
        for volume in volumes {
            if path.starts_with(volume.directory.join("runtime")) { return self.volume_runtime(&volume).map(Some); }
        }
        Ok(None)
    }

    pub fn storage_groups(&self, ids: &[String]) -> Result<Vec<(Option<Arc<Self>>, Vec<String>)>, String> {
        let mut groups: BTreeMap<PathBuf, (Option<Arc<Self>>, Vec<String>)> = BTreeMap::new();
        for id in ids {
            let engine = self.storage_runtime(id)?;
            let root = engine.as_ref().map(|engine| engine.data_root.clone()).unwrap_or_else(|| self.data_root.clone());
            groups.entry(root).or_insert_with(|| (engine, Vec::new())).1.push(id.clone());
        }
        Ok(groups.into_values().collect())
    }

    pub(super) fn loaded_storage_runtimes(&self) -> Vec<Arc<Self>> {
        self.volumes.engines.lock().unwrap_or_else(|p| p.into_inner()).values().cloned().collect()
    }
}
