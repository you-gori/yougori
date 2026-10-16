use super::{command_output, path_string, RuntimeManager};
use serde::Serialize;
use std::{path::Path, time::Duration};

const GB: f64 = 1_073_741_824.0;

pub(crate) fn host_drives(disks: &sysinfo::Disks) -> Vec<crate::models::HostStorageDrive> {
    let mut drives: Vec<_> = disks.list().iter().filter(|disk| disk.total_space() > 0).map(|disk| crate::models::HostStorageDrive {
        path: disk.mount_point().to_string_lossy().into_owned(),
        name: disk.name().to_string_lossy().into_owned(),
        file_system: disk.file_system().to_string_lossy().into_owned(),
        total_gb: disk.total_space() as f64 / GB,
        free_gb: disk.available_space() as f64 / GB,
        read_only: disk.is_read_only(),
        removable: disk.is_removable(),
    }).collect();
    drives.sort_by(|a, b| a.path.cmp(&b.path));
    drives.dedup_by(|a, b| a.path == b.path);
    drives
}

/// Resolve the actual data volume, including nested mount points / relocated data.
pub(crate) fn runtime_disk<'a>(disks: &'a sysinfo::Disks, root: &Path) -> Option<&'a sysinfo::Disk> {
    let root = root.canonicalize().ok()?;
    disks.list().iter().filter_map(|disk| {
        let mount = disk.mount_point().canonicalize().ok()?;
        root.starts_with(&mount).then_some((mount.components().count(), disk))
    }).max_by_key(|(depth, _)| *depth).map(|(_, disk)| disk)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageAllocation {
    pub capacity_gb: f64,
    pub physical_gb: f64,
    pub maximum_gb: f64,
    pub shared: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_enforced: Option<bool>,
}

pub(crate) fn storage_bytes(gb: f64) -> Result<u64, String> {
    if !gb.is_finite() || gb < 1.0 || gb > 16384.0 || gb.fract() != 0.0 {
        return Err("Storage must be a whole number between 1 and 16384 GB".into());
    }
    Ok((gb * GB) as u64)
}

impl RuntimeManager {
    pub fn new_storage_on_drive(&self, selected: Option<&str>) -> Result<StorageAllocation, String> {
        let Some(selected) = selected.filter(|s| !s.is_empty()) else { return self.new_vm_storage(); };
        let selected = Path::new(selected).canonicalize().map_err(|_| "The selected drive is unavailable")?;
        let disks = sysinfo::Disks::new_with_refreshed_list();
        let disk = disks.list().iter().find(|disk| disk.mount_point().canonicalize().is_ok_and(|p| p == selected)).ok_or("Choose an available storage drive")?;
        if disk.is_read_only() { return Err("The selected drive is read-only".into()); }
        let maximum = (disk.available_space().saturating_sub(2 * GB as u64) as f64 / GB).floor().min(16384.0);
        Ok(StorageAllocation { capacity_gb: 0.0, physical_gb: 0.0, maximum_gb: maximum, shared: false, limit_enforced: None })
    }
    pub(super) async fn prepare_container_pool_capacity(&self) -> Result<(), String> {
        // This backing filesystem is an implementation detail, not a node's
        // storage limit. Keep its sparse capacity aligned with the actual host
        // volume so an old 6/15 GB pool cannot hide available host disk space.
        let path = self.data_root.join("appliance/system.qcow2");
        let before = self.inspect_storage(&path, true).await?;
        if before.maximum_gb > before.capacity_gb {
            self.grow_disk(&path, before.maximum_gb, true).await?;
            self.record_appliance_overlay_state()?;
        }
        Ok(())
    }

    pub(super) async fn grow_live_container_pool(&self) -> Result<(), String> {
        let mut guard = self.appliance.lock().await;
        let Some(process) = guard.as_mut() else { return Ok(()); };
        if process.child.try_wait().map_err(|e| e.to_string())?.is_some() { return Ok(()); }
        let path = self.data_root.join("appliance/system.qcow2");
        let before = self.inspect_storage(&path, true).await?;
        if before.maximum_gb > before.capacity_gb {
            super::vm::qmp_execute(&process.qmp, "block_resize", Some(serde_json::json!({
                "node-name": "yougori-appliance-disk", "size": storage_bytes(before.maximum_gb)?
            }))).await?;
        }
        let response = self.client.post(format!("{}/v1/storage/grow", process.endpoint.base_url))
            .bearer_auth(&process.endpoint.token).timeout(Duration::from_secs(120))
            .json(&serde_json::json!({})).send().await.map_err(|e| e.to_string())?;
        super::appliance::successful_response(response).await?;
        Ok(())
    }

    pub fn new_vm_storage(&self) -> Result<StorageAllocation, String> {
        let disks = sysinfo::Disks::new_with_refreshed_list();
        let disk = runtime_disk(&disks, &self.data_root).ok_or("Cannot determine free space on the Yougori drive")?;
        // A new VM cannot reuse bytes already occupied by the container pool.
        let maximum = (disk.available_space().saturating_sub(2 * GB as u64) as f64 / GB).floor().min(16384.0);
        Ok(StorageAllocation { capacity_gb: 0.0, physical_gb: 0.0, maximum_gb: maximum, shared: false, limit_enforced: None })
    }

    // Read-only shared access is needed while QEMU owns the image. Never use
    // --force-share for writes: resize must acquire QEMU's exclusive disk lock.
    pub(super) async fn inspect_storage(&self, path: &Path, shared: bool) -> Result<StorageAllocation, String> {
        let output = command_output(&self.layout.qemu_img,
            &["info".into(), "--force-share".into(), "--output=json".into(), path_string(path)],
            "inspect storage capacity").await?;
        let info: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
        let capacity = info["virtual-size"].as_u64().ok_or("Disk capacity is missing")?;
        let physical = info["actual-size"].as_u64().ok_or("Physical disk size is missing")?;
        let disks = sysinfo::Disks::new_with_refreshed_list();
        let disk = runtime_disk(&disks, &self.data_root).ok_or("Cannot determine free space on the runtime drive")?;
        // Reserve 2 GB on the actual runtime volume, not the sum of other drives.
        let maximum = ((disk.available_space().saturating_add(physical).saturating_sub(2 * GB as u64)) as f64 / GB).floor();
        Ok(StorageAllocation { capacity_gb: capacity as f64 / GB, physical_gb: physical as f64 / GB,
            maximum_gb: maximum.min(16384.0).max((capacity as f64 / GB).ceil()), shared, limit_enforced: None })
    }

    pub(super) async fn grow_disk(&self, path: &Path, capacity_gb: f64, shared: bool) -> Result<StorageAllocation, String> {
        let bytes = storage_bytes(capacity_gb)?;
        let before = self.inspect_storage(path, shared).await?;
        if capacity_gb < before.capacity_gb { return Err("Storage cannot be reduced. Shrinking could destroy files.".into()); }
        if capacity_gb == before.capacity_gb { return Ok(before); }
        if capacity_gb > before.maximum_gb { return Err(format!("Not enough space on the runtime drive. Maximum available capacity is {:.0} GB.", before.maximum_gb)); }
        command_output(&self.layout.qemu_img,
            &["resize".into(), "-f".into(), "qcow2".into(), path_string(path), bytes.to_string()],
            "expand storage (no files are removed)").await?;
        self.inspect_storage(path, shared).await
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_storage_reports_only_the_volume_holding_its_directory() {
        let root = tempfile::tempdir().unwrap();
        let disks = sysinfo::Disks::new_with_refreshed_list();
        let disk = runtime_disk(&disks, root.path()).expect("temporary directory has a storage volume");
        assert!(root.path().canonicalize().unwrap().starts_with(disk.mount_point().canonicalize().unwrap()));
        assert!(disk.total_space() > 0);
        assert!(runtime_disk(&disks, &root.path().join("does-not-exist")).is_none());
    }
    #[test]
    fn storage_capacity_rejects_invalid_or_fractional_values() {
        for value in [0.0, -1.0, 0.5, 1.1, f64::NAN, f64::INFINITY, 16385.0] { assert!(storage_bytes(value).is_err()); }
        assert_eq!(storage_bytes(64.0).unwrap(), 64 * 1_073_741_824);
    }

    fn policy() -> crate::models::ResourcePolicy {
        use crate::models::*;
        ResourcePolicy { cpu: ResourceRange { min: 1.0, preferred: 1.0, max: 1.0, current: 0.0 },
            memory_gb: ResourceRange { min: 0.5, preferred: 0.5, max: 0.5, current: 0.0 }, priority: Priority::Normal, dynamic: false }
    }

    #[tokio::test]
    #[ignore = "boots disposable guests to verify storage expansion and file preservation"]
    async fn storage_expansion_preserves_microvm_files() -> Result<(), String> {
        let data = tempfile::tempdir().unwrap();
        let runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), data.path())?;
        let result = async {
            let vm = runtime.provision_micro_vm("storage-micro", "builtin:alpine").await?;
            for gb in [8.0, 10.0] {
                let allocation = runtime.grow_vm_storage("storage-micro", &vm.disk_path, gb).await?;
                assert_eq!(allocation.capacity_gb, gb);
                assert!(runtime.grow_vm_storage("storage-micro", &vm.disk_path, gb - 1.0).await.unwrap_err().contains("cannot be reduced"));
                runtime.start_micro_vm("storage-micro", &vm.disk_path, &vm.source_path, &policy()).await?;
                let deadline = std::time::Instant::now() + Duration::from_secs(60);
                let output = loop {
                    match runtime.execute_micro_vm_command("storage-micro", "df -k /; cat /root/storage-marker 2>/dev/null; echo storage-survives > /root/storage-marker; sync").await {
                        Ok(output) => break output,
                        Err(error) if std::time::Instant::now() >= deadline => {
                            let serial = std::fs::read_to_string(data.path().join("runtime/environments/storage-micro/serial.log")).unwrap_or_default();
                            return Err(format!("{error}\n{serial}"));
                        },
                        Err(_) => tokio::time::sleep(Duration::from_millis(250)).await,
                    }
                };
                assert_eq!(output.exit_code, 0, "{}", output.stderr);
                let blocks: u64 = output.stdout.lines().find(|line| line.starts_with("/dev/vda")).unwrap().split_whitespace().nth(1).unwrap().parse().unwrap();
                assert!(blocks > ((gb - 1.0) * 1048576.0) as u64, "{}", output.stdout);
                if gb == 10.0 { assert!(output.stdout.contains("storage-survives")); }
                assert!(runtime.grow_vm_storage("storage-micro", &vm.disk_path, gb + 1.0).await.unwrap_err().contains("Stop"));
                eprintln!("MicroVM {gb} GB verified: {}", output.stdout);
                runtime.vm_action("storage-micro", "stop").await?;
            }

            Ok(())
        }.await;
        runtime.shutdown_all().await;
        result
    }

    #[tokio::test]
    #[ignore = "uses bundled qemu-img on disposable images, without booting a VM"]
    async fn storage_vm_creation_uses_selected_capacity_and_never_shrinks_imports() -> Result<(), String> {
        let data = tempfile::tempdir().unwrap();
        let runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), data.path())?;
        let image = data.path().join("source.qcow2");
        command_output(&runtime.layout.qemu_img, &["create".into(), "-f".into(), "qcow2".into(), path_string(&image), "4G".into()], "test disk").await?;
        let original = std::fs::read(&image).map_err(|e| e.to_string())?;
        for (id, requested, actual) in [("storage-small", 2.0, 4.0), ("storage-large", 8.0, 8.0)] {
            let vm = runtime.provision_vm_with_storage(id, image.to_str().unwrap(), Some(requested)).await?;
            assert_eq!(runtime.vm_storage_allocation(id, &vm.disk_path).await?.capacity_gb, actual);
        }
        assert_eq!(std::fs::read(image).map_err(|e| e.to_string())?, original);
        // This is only a provisioning fixture, never booted as an installer.
        let iso = data.path().join("empty-fixture.iso");
        std::fs::write(&iso, vec![0_u8; 65536]).map_err(|e| e.to_string())?;
        let vm = runtime.provision_vm_with_storage("storage-iso", iso.to_str().unwrap(), Some(12.0)).await?;
        assert_eq!(runtime.vm_storage_allocation("storage-iso", &vm.disk_path).await?.capacity_gb, 12.0);
        Ok(())
    }
}
