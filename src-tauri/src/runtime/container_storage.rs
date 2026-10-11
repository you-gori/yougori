use super::{appliance::successful_response, storage::{storage_bytes, StorageAllocation}, RuntimeManager};
use serde::Deserialize;
use std::time::Duration;

const GB: f64 = 1_073_741_824.0;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContainerStorageInfo {
    limit_bytes: u64,
    used_bytes: u64,
    enforced: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::*;
    use std::path::Path;

    #[tokio::test]
    #[ignore = "requires YOUGORI_LEGACY_INITRAMFS; migrates real legacy root, volume, and metadata in a disposable appliance"]
    async fn container_storage_migrates_legacy_files_and_private_volumes() -> Result<(), String> {
        let old = std::env::var_os("YOUGORI_LEGACY_INITRAMFS").ok_or("Set YOUGORI_LEGACY_INITRAMFS to the previous release's initramfs")?;
        let data = tempfile::tempdir().unwrap();
        let mut runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), data.path())?;
        let updated = runtime.layout.appliance_initramfs.clone();
        runtime.layout.appliance_initramfs = std::path::PathBuf::from(old).canonicalize().map_err(|e| e.to_string())?;
        if runtime.layout.appliance_initramfs == updated { return Err("Legacy and updated payloads must differ".into()); }
        let result = async {
            let endpoint = runtime.appliance_endpoint().await?;
            let response = runtime.client.post(format!("{}/v1/containers/provision", endpoint.base_url))
                .bearer_auth(&endpoint.token).json(&serde_json::json!({
                    "id":"legacy-quota","image":"docker.io/library/redis:7-alpine","command":"sleep 2147483647",
                    "cpus":1,"memoryBytes":536870912,"networkAccess":false,"gpuAccess":false
                })).send().await.map_err(|e| e.to_string())?;
            successful_response(response).await?;
            runtime.container_action("legacy-quota", "start", false).await?;
            let created = runtime.execute_container_command("legacy-quota",
                "mkdir -p /root/project/sub; echo root-survives > /root/project/sub/marker; chmod 640 /root/project/sub/marker; ln /root/project/sub/marker /root/hardlink; ln -s /root/project/sub/marker /root/symlink; echo volume-survives > /data/marker; dd if=/dev/zero of=/data/database-fixture bs=1048576 count=32; sync").await?;
            if created.exit_code != 0 { return Err(created.stderr); }
            runtime.container_action("legacy-quota", "stop", false).await?;
            runtime.shutdown_all().await;
            runtime.layout.appliance_initramfs = updated;
            let before = runtime.container_storage_allocation("legacy-quota").await?;
            if before.limit_enforced != Some(false) || before.physical_gb < 0.03 { return Err(format!("legacy allocation: {before:?}")); }
            runtime.set_container_storage("legacy-quota", 1.0).await?;
            runtime.container_action("legacy-quota", "start", false).await?;
            let verified = runtime.execute_container_command("legacy-quota",
                "cat /root/project/sub/marker /root/hardlink /root/symlink /data/marker; test $(stat -c %a /root/hardlink) = 640 && test $(stat -c %i /root/hardlink) = $(stat -c %i /root/project/sub/marker) && test $(wc -c < /data/database-fixture) = 33554432").await?;
            if verified.exit_code != 0 || !verified.stdout.contains("root-survives") || !verified.stdout.contains("volume-survives") {
                return Err(format!("migration verification: {} {}", verified.stdout, verified.stderr));
            }
            eprintln!("Legacy migration preserved root files, private volume, hardlinks, symlinks and permissions: {}", verified.stdout);
            Ok(())
        }.await;
        runtime.shutdown_all().await;
        result
    }

    #[tokio::test]
    #[ignore = "fills private quotas in two disposable containers, then grows one online and verifies restart persistence"]
    async fn container_storage_limits_are_independent_and_enforced() -> Result<(), String> {
        let data = tempfile::tempdir().unwrap();
        let runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), data.path())?;
        let policy: ResourcePolicy = serde_json::from_value(serde_json::json!({
            "cpu":{"min":1,"preferred":1,"max":1,"current":0},
            "memoryGb":{"min":0.5,"preferred":0.5,"max":0.5,"current":0},"priority":"normal","dynamic":true
        })).unwrap();
        let result = async {
            // Redis declares a private /data volume. Both it and the writable
            // root must share one quota, while the second node remains usable.
            runtime.provision_container_with_storage("quota-one", "docker.io/library/redis:7-alpine", "sleep 2147483647", &policy, false, false, 1.0).await?;
            runtime.provision_container_with_storage("quota-peer", "quay.io/libpod/alpine:latest", "sleep 2147483647", &policy, false, false, 2.0).await?;
            for id in ["quota-one", "quota-peer"] { runtime.container_action(id, "start", false).await?; }
            let pid = runtime.appliance.lock().await.as_ref().unwrap().child.id();
            let root = runtime.execute_container_command("quota-one", "dd if=/dev/zero of=/root/quota-fill bs=1048576 count=512 && echo quota-survives > /root/marker").await?;
            if root.exit_code != 0 { return Err(format!("root write: {}", root.stderr)); }
            let full = runtime.execute_container_command("quota-one", "dd if=/dev/zero of=/data/quota-fill bs=1048576 count=600").await?;
            if full.exit_code == 0 || !full.stderr.to_lowercase().contains("quota") {
                return Err(format!("container root and volume exceeded their combined limit: {} {}", full.stdout, full.stderr));
            }
            let first = runtime.container_storage_allocation("quota-one").await?;
            if first.limit_enforced != Some(true) || first.shared || first.capacity_gb != 1.0 || first.physical_gb < 0.9 || first.physical_gb > 1.001 {
                return Err(format!("invalid first-node allocation: {first:?}"));
            }
            let peer = runtime.execute_container_command("quota-peer", "echo peer-survives > /root/marker; dd if=/dev/zero of=/root/peer-data bs=1048576 count=16").await?;
            if peer.exit_code != 0 { return Err(format!("peer affected by another node's limit: {}", peer.stderr)); }
            runtime.set_container_storage("quota-one", 2.0).await?;
            if pid != runtime.appliance.lock().await.as_ref().unwrap().child.id() { return Err("quota change restarted the runtime".into()); }
            let expanded = runtime.execute_container_command("quota-one", "cat /root/marker; dd if=/dev/zero of=/data/after-expansion bs=1048576 count=64 && df -k / /data").await?;
            if expanded.exit_code != 0 || !expanded.stdout.contains("quota-survives") { return Err(format!("live quota increase: {} {}", expanded.stdout, expanded.stderr)); }
            eprintln!("Private root/volume limit enforced, live expansion: {}", expanded.stdout);
            if runtime.container_storage_allocation("quota-peer").await?.capacity_gb != 2.0 { return Err("peer allocation changed".into()); }
            if runtime.set_container_storage("quota-one", 1.0).await.is_ok() { return Err("limit below current usage unexpectedly succeeded".into()); }
            let freed = runtime.execute_container_command("quota-one", "rm /root/quota-fill /data/quota-fill; sync").await?;
            if freed.exit_code != 0 { return Err(freed.stderr); }
            let reduced = runtime.set_container_storage("quota-one", 1.0).await?;
            if reduced.capacity_gb != 1.0 || reduced.limit_enforced != Some(true) || pid != runtime.appliance.lock().await.as_ref().unwrap().child.id() {
                return Err("live storage reduction did not keep the runtime and enforced limit".into());
            }
            let retained = runtime.execute_container_command("quota-one", "cat /root/marker; test $(wc -c < /data/after-expansion) = 67108864; df -k / /data").await?;
            if retained.exit_code != 0 || !retained.stdout.contains("quota-survives") { return Err("storage reduction lost a file".into()); }
            if runtime.container_storage_allocation("quota-peer").await?.capacity_gb != 2.0 { return Err("storage reduction changed the peer".into()); }
            eprintln!("Live reduction preserved files and the other container: {}", retained.stdout);
            runtime.set_container_storage("quota-one", 2.0).await?;
            for id in ["quota-one", "quota-peer"] { runtime.container_action(id, "stop", false).await?; }
            runtime.shutdown_all().await;
            for id in ["quota-one", "quota-peer"] {
                runtime.container_action(id, "start", false).await?;
                let contents = runtime.execute_container_command(id, "cat /root/marker").await?;
                if contents.exit_code != 0 || !contents.stdout.contains("survives") { return Err("quota restart lost a file".into()); }
                let allocation = runtime.container_storage_allocation(id).await?;
                if allocation.capacity_gb != 2.0 || allocation.limit_enforced != Some(true) { return Err("quota did not survive restart".into()); }
            }
            Ok(())
        }.await;
        runtime.shutdown_all().await;
        result
    }
}

impl RuntimeManager {
    pub async fn container_storage_allocation(&self, id: &str) -> Result<StorageAllocation, String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.container_storage_allocation(id)).await; }

        self.container_storage_request(id, None).await
    }

    pub async fn set_container_storage(&self, id: &str, capacity_gb: f64) -> Result<StorageAllocation, String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.set_container_storage(id, capacity_gb)).await; }

        storage_bytes(capacity_gb)?;
        let before = self.container_storage_allocation(id).await?;
        if capacity_gb <= before.physical_gb && (before.limit_enforced != Some(true) || capacity_gb != before.capacity_gb) {
            return Err(format!("This container already uses {:.2} GB. Choose a storage limit above its current usage.", before.physical_gb));
        }
        if capacity_gb > before.maximum_gb {
            return Err(format!("Not enough free space on the Yougori drive. Maximum available limit is {:.0} GB.", before.maximum_gb));
        }
        self.container_storage_request(id, Some(capacity_gb)).await
    }

    async fn container_storage_request(&self, id: &str, capacity_gb: Option<f64>) -> Result<StorageAllocation, String> {
        let _lease = self.appliance_operations.read().await;
        let endpoint = self.container_endpoint(id).await?;
        if capacity_gb.is_some() && self.container_provider(id)? == crate::models::RuntimeProviderKind::YougoriOci {
            self.grow_live_container_pool().await?;
        }
        let response = self.client.post(format!("{}/v1/containers/storage", endpoint.base_url))
            .bearer_auth(&endpoint.token).timeout(Duration::from_secs(300))
            .json(&serde_json::json!({"id": id, "limitBytes": capacity_gb.map(storage_bytes).transpose()?.unwrap_or(0)}))
            .send().await.map_err(|e| format!("read or update this container's storage: {e}"))?;
        let info: ContainerStorageInfo = successful_response(response).await?.json().await.map_err(|e| e.to_string())?;
        let capacity = info.limit_bytes as f64 / GB;
        let used = info.used_bytes as f64 / GB;
        let host = self.new_vm_storage()?;
        Ok(StorageAllocation {
            capacity_gb: capacity, physical_gb: used,
            maximum_gb: (host.maximum_gb + used).floor().max(capacity).min(16380.0),
            shared: false, limit_enforced: Some(info.enforced),
        })
    }
}
